#![allow(warnings)]
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{DkgMessage, IpcMessage, SigningMessage};
use crate::capnp_gen::{serialize_message, deserialize_message};
use frost_secp256k1::Identifier;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Maximum message size in bytes (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
/// Message header size in bytes (4 bytes for message length)
const HEADER_SIZE: usize = 4;

/// IPC channel for communication between processes
pub struct IpcChannel<T> {
    /// Sender for outgoing messages
    pub tx: Sender<T>,
    /// Receiver for incoming messages
    pub rx: Receiver<T>,
}

impl<T> IpcChannel<T> {
    /// Create a new IPC channel
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = channel(capacity);
        Self { tx, rx }
    }

    /// Get a clone of the sender
    pub fn sender(&self) -> Sender<T> {
        self.tx.clone()
    }

    /// Get the receiver (consumes self)
    pub fn into_receiver(self) -> Receiver<T> {
        self.rx
    }
}


/// TCP-based IPC server acting as the coordinator in ChillDKG
///
/// The server (coordinator) acts as a central message hub in ChillDKG:
/// 1. All participants connect to the coordinator
/// 2. The coordinator collects messages from participants
/// 3. The coordinator routes/broadcasts messages to relevant participants
/// 4. The coordinator helps manage the protocol flow across its rounds
pub struct IpcServer {
    /// Local participant ID
    local_id: Identifier,
    /// Socket address
    socket_addr: SocketAddr,
    /// Connected clients
    clients: Arc<Mutex<HashMap<Identifier, Sender<IpcMessage>>>>,
    /// Channel for incoming messages
    incoming: IpcChannel<(Identifier, IpcMessage)>,
}

impl IpcServer {
    /// Create a new IPC server
    pub async fn new(local_id: Identifier, ip: IpAddr, port: u16) -> Result<Self> {
        let socket_addr = SocketAddr::new(ip, port);

        let server = Self {
            local_id,
            socket_addr,
            clients: Arc::new(Mutex::new(HashMap::new())),
            incoming: IpcChannel::new(100),
        };

        Ok(server)
    }

    /// Create a new IPC server bound to localhost with the specified port
    pub async fn new_localhost(local_id: Identifier, port: u16) -> Result<Self> {
        Self::new(local_id, IpAddr::V4(Ipv4Addr::LOCALHOST), port).await
    }

    /// Start listening for connections
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.socket_addr)
            .await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to bind to {}: {}", self.socket_addr, e)))?;

        let clients = self.clients.clone();
        let incoming_tx = self.incoming.sender();

        // Spawn a task to accept connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        log::info!("New TCP connection from {}", addr);

                        let clients = clients.clone();
                        let incoming_tx = incoming_tx.clone();

                        // Handle connection in a separate task
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, clients, incoming_tx).await {
                                log::error!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Error accepting connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Send a message to a specific participant
    pub async fn send(&self, participant_id: Identifier, message: IpcMessage) -> Result<()> {
        let clients = self.clients.lock().await;

        if let Some(tx) = clients.get(&participant_id) {
            tx.send(message).await
                .map_err(|e| FrostWalletError::IpcError(format!("Failed to send message: {}", e)))?;
            Ok(())
        } else {
            Err(FrostWalletError::IpcError(format!("No connection to participant {:?}", participant_id)))
        }
    }

    /// Broadcast a message to all participants
    pub async fn broadcast(&self, message: IpcMessage) -> Result<()> {
        let clients = self.clients.lock().await;

        for (id, tx) in clients.iter() {
            if let Err(e) = tx.send(message.clone()).await {
                log::error!("Failed to send to participant {:?}: {}", id, e);
            }
        }

        Ok(())
    }

    /// Forward a message from one participant to another
    pub async fn forward(&self, from_id: Identifier, to_id: Identifier, message: IpcMessage) -> Result<()> {
        self.send(to_id, message).await
    }

    /// Broadcast a message to all participants except the sender
    pub async fn broadcast_except(&self, sender_id: Identifier, message: IpcMessage) -> Result<()> {
        let clients = self.clients.lock().await;

        for (id, tx) in clients.iter() {
            if *id != sender_id {
                if let Err(e) = tx.send(message.clone()).await {
                    log::error!("Failed to send to participant {:?}: {}", id, e);
                }
            }
        }

        Ok(())
    }

    /// Receive the next message
    pub async fn receive(&mut self) -> Result<(Identifier, IpcMessage)> {
        self.incoming.rx.recv().await
            .ok_or_else(|| FrostWalletError::IpcError("Channel closed".to_string()))
    }

    /// Get the server's socket address
    pub fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    /// Get a list of all connected participants
    pub async fn connected_participants(&self) -> Vec<Identifier> {
        let clients = self.clients.lock().await;
        clients.keys().cloned().collect()
    }

    /// Check if a specific participant is connected
    pub async fn is_participant_connected(&self, participant_id: Identifier) -> bool {
        let clients = self.clients.lock().await;
        clients.contains_key(&participant_id)
    }
}

/// TCP-based IPC client that connects to the coordinator
///
/// In ChillDKG, all participants act as clients that connect to the coordinator.
/// Participants only communicate with the coordinator, not directly with each other.
pub struct IpcClient {
    /// Local participant ID
    local_id: Identifier,
    /// Remote participant ID (usually the coordinator's ID)
    remote_id: Identifier,
    /// TCP stream
    stream: Option<TcpStream>,
    /// Channel for outgoing messages
    outgoing: Sender<IpcMessage>,
    /// Channel for incoming messages
    incoming: Receiver<IpcMessage>,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(local_id: Identifier, remote_id: Identifier) -> Self {
        let (outgoing_tx, _) = channel::<IpcMessage>(100);
        let (_, incoming_rx) = channel::<IpcMessage>(100);

        Self {
            local_id,
            remote_id,
            stream: None,
            outgoing: outgoing_tx,
            incoming: incoming_rx,
        }
    }

    /// Connect to the coordinator server
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<()> {
        log::info!("Connecting to coordinator at {}", addr);
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to connect to coordinator at {}: {}", addr, e)))?;

        // Set TCP_NODELAY to disable Nagle's algorithm for better latency
        stream.set_nodelay(true)
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to set TCP_NODELAY: {}", e)))?;

        let (read_half, mut write_half) = stream.into_split();

        let (outgoing_tx, mut outgoing_rx) = channel::<IpcMessage>(100);
        let (incoming_tx, incoming_rx) = channel::<IpcMessage>(100);

        self.outgoing = outgoing_tx;
        self.incoming = incoming_rx;

        // Spawn task to read incoming messages
        let incoming_tx_clone = incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = read_messages(read_half, incoming_tx_clone).await {
                log::error!("Error reading messages: {}", e);
            }
        });

        // Spawn task to write outgoing messages
        tokio::spawn(async move {
            while let Some(message) = outgoing_rx.recv().await {
                if let Err(e) = write_message(&mut write_half, &message).await {
                    log::error!("Error writing message: {}", e);
                    break;
                }
            }
        });

        // println!("Before Handshake");

        // Send initial handshake with our ID
        self.send(IpcMessage::Handshake(self.local_id)).await?;

        // println!("After Handshake");

        Ok(())
    }

    /// Send a message to the coordinator
    pub async fn send(&self, message: IpcMessage) -> Result<()> {
        println!("Sending message: {:?}", message);
        self.outgoing.send(message).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to send message to coordinator: {}", e)))
    }

    pub async fn send_to_participant(&self, participant_id: Identifier, message: IpcMessage) -> Result<()> {
        self.send(message).await
    }

    /// Receive the next message
    pub async fn receive(&mut self) -> Result<IpcMessage> {
        self.incoming.recv().await
            .ok_or_else(|| FrostWalletError::IpcError("Channel closed".to_string()))
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            // Close the stream gracefully
            stream.shutdown().await
                .map_err(|e| FrostWalletError::IpcError(format!("Failed to close connection: {}", e)))?;
        }

        Ok(())
    }
}

// Helper function to handle a new connection
async fn handle_connection(
    stream: TcpStream,
    clients: Arc<Mutex<HashMap<Identifier, Sender<IpcMessage>>>>,
    incoming_tx: Sender<(Identifier, IpcMessage)>,
) -> Result<()> {
    // Set TCP_NODELAY to disable Nagle's algorithm for better latency
    stream.set_nodelay(true)
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to set TCP_NODELAY: {}", e)))?;

    let (mut read_half, mut write_half) = stream.into_split();

    // Create a channel for messages to send to this client
    let (client_tx, mut client_rx) = channel::<IpcMessage>(100);

    // Wait for handshake message to get client ID
    let mut message_buf = Vec::new();
    let mut len_buf = [0u8; HEADER_SIZE];

    read_half.read_exact(&mut len_buf).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to read message header: {}", e)))?;

    let message_len = u32::from_be_bytes(len_buf) as usize;

    if message_len > MAX_MESSAGE_SIZE {
        return Err(FrostWalletError::IpcError(format!(
            "Message too large: {} bytes (max {})",
            message_len,
            MAX_MESSAGE_SIZE
        )));
    }

    message_buf.resize(message_len, 0);
    read_half.read_exact(&mut message_buf).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to read message body: {}", e)))?;

    let message: IpcMessage = bincode::deserialize(&message_buf)
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;

    let client_id = match &message {
        IpcMessage::Handshake(id) => *id,
        _ => return Err(FrostWalletError::IpcError("Expected handshake message".to_string())),
    };

    log::info!("Client {:?} connected", client_id);

    // Add client to the map
    {
        let mut clients = clients.lock().await;
        clients.insert(client_id, client_tx.clone());
    }

    // Forward the handshake to the application
    incoming_tx.send((client_id, message)).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to forward handshake: {}", e)))?;

    // Spawn task to read incoming messages
    let incoming_tx = incoming_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = read_messages_with_sender(read_half, incoming_tx, client_id).await {
            log::error!("Error reading messages from client {:?}: {}", client_id, e);
        }

        // Remove client when done
        let mut clients = clients.lock().await;
        clients.remove(&client_id);
        log::info!("Client {:?} disconnected", client_id);
    });

    // Spawn task to write outgoing messages
    tokio::spawn(async move {
        while let Some(message) = client_rx.recv().await {
            if let Err(e) = write_message(&mut write_half, &message).await {
                log::error!("Error writing message to client {:?}: {}", client_id, e);
                break;
            }
        }
    });

    Ok(())
}

// Helper function to read messages from a stream
async fn read_messages<R: AsyncRead + Unpin>(
    mut stream: R,
    tx: Sender<IpcMessage>,
) -> Result<()> {
    let mut message_buf = Vec::new();
    let mut len_buf = [0u8; HEADER_SIZE];

    while stream.read_exact(&mut len_buf).await.is_ok() {
        let message_len = u32::from_be_bytes(len_buf) as usize;

        if message_len > MAX_MESSAGE_SIZE {
            return Err(FrostWalletError::IpcError(format!(
                "Message too large: {} bytes (max {})",
                message_len,
                MAX_MESSAGE_SIZE
            )));
        }

        message_buf.resize(message_len, 0);
        stream.read_exact(&mut message_buf).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to read message body: {}", e)))?;

        let message: IpcMessage = bincode::deserialize(&message_buf)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;

        tx.send(message).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to forward message: {}", e)))?;
    }

    Ok(())
}

// Helper function to read messages from a stream with sender ID
async fn read_messages_with_sender<R: AsyncRead + Unpin>(
    mut stream: R,
    tx: Sender<(Identifier, IpcMessage)>,
    sender_id: Identifier,
) -> Result<()> {
    let mut message_buf = Vec::new();
    let mut len_buf = [0u8; HEADER_SIZE];

    while stream.read_exact(&mut len_buf).await.is_ok() {
        let message_len = u32::from_be_bytes(len_buf) as usize;

        if message_len > MAX_MESSAGE_SIZE {
            return Err(FrostWalletError::IpcError(format!(
                "Message too large: {} bytes (max {})",
                message_len,
                MAX_MESSAGE_SIZE
            )));
        }

        message_buf.resize(message_len, 0);
        stream.read_exact(&mut message_buf).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to read message body: {}", e)))?;

        let message: IpcMessage = bincode::deserialize(&message_buf)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;

        tx.send((sender_id, message)).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to forward message: {}", e)))?;
    }

    Ok(())
}

// Helper function to write a message to a stream
async fn write_message<W: AsyncWrite + Unpin, T: serde::Serialize>(
    stream: &mut W,
    message: &T,
) -> Result<()> {
    let data = bincode::serialize(message)
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize message: {}", e)))?;

    if data.len() > MAX_MESSAGE_SIZE {
        return Err(FrostWalletError::IpcError(format!(
            "Message too large: {} bytes (max {})",
            data.len(),
            MAX_MESSAGE_SIZE
        )));
    }

    let len = (data.len() as u32).to_be_bytes();

    stream.write_all(&len).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to write message header: {}", e)))?;

    stream.write_all(&data).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to write message body: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;
    use crate::common::types::ThresholdConfig;
    use tempfile::tempdir;
    use tokio_test::block_on;

    #[test]
    fn test_ipc_serialization() {
        // Create a test message
        let message = IpcMessage::Dkg(DkgMessage::Start(ThresholdConfig::new(2, 3)));

        // Serialize
        let data = bincode::serialize(&message).unwrap();

        // Deserialize
        let deserialized: IpcMessage = bincode::deserialize(&data).unwrap();

        // Verify
        match deserialized {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[tokio::test]
    async fn test_tcp_communication() {
        // Use a high port number to avoid conflicts
        let port = 34567;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create server and client IDs
        let server_id = Identifier::try_from(1).unwrap();
        let client_id = Identifier::try_from(2).unwrap();

        // Create and start server
        let mut server = IpcServer::new_localhost(server_id, port).await.unwrap();
        server.start().await.unwrap();

        // Create and connect client
        let mut client = IpcClient::new(client_id, server_id);
        client.connect(server_addr).await.unwrap();

        // First, receive the handshake message that is automatically sent when connecting
        let (handshake_sender_id, handshake_message) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.receive()
        ).await.unwrap().unwrap();

        // Verify it's a handshake with the correct ID
        assert_eq!(handshake_sender_id, client_id);
        match handshake_message {
            IpcMessage::Handshake(id) => {
                assert_eq!(id, client_id);
            },
            _ => panic!("Expected handshake message"),
        }

        // Now send the test message
        let test_message = IpcMessage::Dkg(DkgMessage::Start(ThresholdConfig::new(2, 3)));
        client.send(test_message.clone()).await.unwrap();

        // Receive the test message
        let (sender_id, received_message) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.receive()
        ).await.unwrap().unwrap();

        // Verify the message
        assert_eq!(sender_id, client_id);
        match received_message {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type"),
        }

        // Send a message from server to client
        let response_message = IpcMessage::Dkg(DkgMessage::Finish);
        server.send(client_id, response_message.clone()).await.unwrap();

        // Receive the message on the client
        let received_response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.receive()
        ).await.unwrap().unwrap();

        // Verify the response
        match received_response {
            IpcMessage::Dkg(DkgMessage::Finish) => {},
            _ => panic!("Wrong message type"),
        }

        // Clean up
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_to_multiple_clients() {
        // Use a high port number to avoid conflicts
        let port = 34568;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create server and client IDs
        let server_id = Identifier::try_from(1).unwrap();
        let client1_id = Identifier::try_from(2).unwrap();
        let client2_id = Identifier::try_from(3).unwrap();
        let client3_id = Identifier::try_from(4).unwrap();

        // Create and start server
        let mut server = IpcServer::new_localhost(server_id, port).await.unwrap();
        server.start().await.unwrap();

        // Create and connect multiple clients
        let mut client1 = IpcClient::new(client1_id, server_id);
        let mut client2 = IpcClient::new(client2_id, server_id);
        let mut client3 = IpcClient::new(client3_id, server_id);

        client1.connect(server_addr).await.unwrap();
        client2.connect(server_addr).await.unwrap();
        client3.connect(server_addr).await.unwrap();

        // Consume all handshake messages
        for _ in 0..3 {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                server.receive()
            ).await.unwrap();
        }

        // Check connected participants
        let connected = server.connected_participants().await;
        assert_eq!(connected.len(), 3);
        assert!(connected.contains(&client1_id));
        assert!(connected.contains(&client2_id));
        assert!(connected.contains(&client3_id));

        // Test individual participant connection check
        assert!(server.is_participant_connected(client1_id).await);
        assert!(server.is_participant_connected(client2_id).await);
        assert!(server.is_participant_connected(client3_id).await);

        // Non-existent participant should not be connected
        let non_existent_id = Identifier::try_from(99).unwrap();
        assert!(!server.is_participant_connected(non_existent_id).await);

        // Broadcast a message to all clients
        let broadcast_message = IpcMessage::Dkg(DkgMessage::Start(ThresholdConfig::new(2, 3)));
        server.broadcast(broadcast_message.clone()).await.unwrap();

        // Verify all clients receive the broadcast
        let received1 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client1.receive()
        ).await.unwrap().unwrap();

        let received2 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client2.receive()
        ).await.unwrap().unwrap();

        let received3 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client3.receive()
        ).await.unwrap().unwrap();

        // Verify all received messages match the broadcast
        match received1 {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type received by client 1"),
        }

        match received2 {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type received by client 2"),
        }

        match received3 {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type received by client 3"),
        }

        // Clean up
        client1.close().await.unwrap();
        client2.close().await.unwrap();
        client3.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_broadcast_except_sender() {
        // Use a high port number to avoid conflicts
        let port = 34569;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create server and client IDs
        let server_id = Identifier::try_from(1).unwrap();
        let client1_id = Identifier::try_from(2).unwrap();
        let client2_id = Identifier::try_from(3).unwrap();
        let client3_id = Identifier::try_from(4).unwrap();

        // Create and start server
        let mut server = IpcServer::new_localhost(server_id, port).await.unwrap();
        server.start().await.unwrap();

        // Create and connect multiple clients
        let mut client1 = IpcClient::new(client1_id, server_id);
        let mut client2 = IpcClient::new(client2_id, server_id);
        let mut client3 = IpcClient::new(client3_id, server_id);

        client1.connect(server_addr).await.unwrap();
        client2.connect(server_addr).await.unwrap();
        client3.connect(server_addr).await.unwrap();

        // Consume all handshake messages
        for _ in 0..3 {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                server.receive()
            ).await.unwrap();
        }

        // Broadcast a message to all clients except client1
        let broadcast_message = IpcMessage::Dkg(DkgMessage::Start(ThresholdConfig::new(2, 3)));
        server.broadcast_except(client1_id, broadcast_message.clone()).await.unwrap();

        // Set up timeouts for receiving - client1 should timeout, others should receive
        let timeout_duration = Duration::from_millis(500);

        // Client 1 should NOT receive the message (timeout)
        let result1 = tokio::time::timeout(
            timeout_duration,
            client1.receive()
        ).await;

        // Client 2 and 3 should receive the message
        let received2 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client2.receive()
        ).await.unwrap().unwrap();

        let received3 = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client3.receive()
        ).await.unwrap().unwrap();

        // Client 1 should have timed out
        assert!(result1.is_err(), "Client 1 should not have received the broadcast_except message");

        // Verify other clients received the message
        match received2 {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type received by client 2"),
        }

        match received3 {
            IpcMessage::Dkg(DkgMessage::Start(config)) => {
                assert_eq!(config.threshold, 2);
                assert_eq!(config.total_participants, 3);
            }
            _ => panic!("Wrong message type received by client 3"),
        }

        // Clean up
        client1.close().await.unwrap();
        client2.close().await.unwrap();
        client3.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_message_forwarding() {
        // Use a high port number to avoid conflicts
        let port = 34570;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create server and client IDs
        let server_id = Identifier::try_from(1).unwrap();
        let client1_id = Identifier::try_from(2).unwrap();
        let client2_id = Identifier::try_from(3).unwrap();

        // Create and start server
        let mut server = IpcServer::new_localhost(server_id, port).await.unwrap();
        server.start().await.unwrap();

        // Create and connect multiple clients
        let mut client1 = IpcClient::new(client1_id, server_id);
        let mut client2 = IpcClient::new(client2_id, server_id);

        client1.connect(server_addr).await.unwrap();
        client2.connect(server_addr).await.unwrap();

        // Consume all handshake messages
        for _ in 0..2 {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                server.receive()
            ).await.unwrap();
        }

        // Client 1 sends a message intended for client 2
        let message_to_forward = IpcMessage::Dkg(DkgMessage::KeyShare(
            client1_id, client2_id, Vec::new()
        ));

        // Using the send_to_participant method (which in this implementation just sends to coordinator)
        client1.send_to_participant(client2_id, message_to_forward.clone()).await.unwrap();

        // Server receives the message
        let (sender_id, received_message) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.receive()
        ).await.unwrap().unwrap();

        // Verify the sender
        assert_eq!(sender_id, client1_id);

        // Server forwards the message to client2
        server.forward(client1_id, client2_id, received_message).await.unwrap();

        // Client 2 receives the forwarded message
        let forwarded_message = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client2.receive()
        ).await.unwrap().unwrap();

        // Verify the forwarded message
        match forwarded_message {
            IpcMessage::Dkg(DkgMessage::KeyShare(from_id, to_id, _)) => {
                assert_eq!(from_id, client1_id);
                assert_eq!(to_id, client2_id);
            }
            _ => panic!("Wrong message type forwarded"),
        }

        // Clean up
        client1.close().await.unwrap();
        client2.close().await.unwrap();
    }
}