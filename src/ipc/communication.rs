#![allow(warnings)]
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{DkgMessage, IpcMessage, SigningMessage};
use crate::capnp_gen::{serialize_message, deserialize_message};
use frost_secp256k1::Identifier;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixListener;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::fs;

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

/// Unix socket-based IPC server
pub struct IpcServer {
    /// Local participant ID
    local_id: Identifier,
    /// Socket path
    socket_path: PathBuf,
    /// Connected clients
    clients: Arc<Mutex<HashMap<Identifier, Sender<IpcMessage>>>>,
    /// Channel for incoming messages
    incoming: IpcChannel<(Identifier, IpcMessage)>,
}

impl IpcServer {
    /// Create a new IPC server
    pub async fn new(local_id: Identifier, socket_path: impl AsRef<Path>) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Create parent directory if it doesn't exist
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        // Remove the socket file if it already exists
        if socket_path.exists() {
            fs::remove_file(&socket_path)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        let server = Self {
            local_id,
            socket_path,
            clients: Arc::new(Mutex::new(HashMap::new())),
            incoming: IpcChannel::new(100),
        };

        Ok(server)
    }

    /// Start listening for connections
    pub async fn start(&self) -> Result<()> {
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to bind to {:?}: {}", self.socket_path, e)))?;

        // Set socket permissions (important for security)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600); // Only owner can read/write
            fs::set_permissions(&self.socket_path, perms)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }

        let clients = self.clients.clone();
        let incoming_tx = self.incoming.sender();

        // Spawn a task to accept connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        log::info!("New connection on Unix socket");

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

    /// Receive the next message
    pub async fn receive(&mut self) -> Result<(Identifier, IpcMessage)> {
        self.incoming.rx.recv().await
            .ok_or_else(|| FrostWalletError::IpcError("Channel closed".to_string()))
    }

    /// Clean up socket file
    pub fn cleanup(&self) -> Result<()> {
        if self.socket_path.exists() {
            fs::remove_file(&self.socket_path)
                .map_err(|e| FrostWalletError::IoError(e))?;
        }
        Ok(())
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Unix socket-based IPC client
pub struct IpcClient {
    /// Local participant ID
    local_id: Identifier,
    /// Remote participant ID
    remote_id: Identifier,
    /// Unix stream
    stream: Option<UnixStream>,
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

    /// Connect to a server
    pub async fn connect(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to connect to socket: {}", e)))?;

        // self.stream = Option::from(stream);

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

        // Send initial handshake with our ID
        self.send(IpcMessage::Handshake(self.local_id)).await?;

        Ok(())
    }

    /// Send a message
    pub async fn send(&self, message: IpcMessage) -> Result<()> {
        self.outgoing.send(message).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to send message: {}", e)))
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
    stream: UnixStream,
    clients: Arc<Mutex<HashMap<Identifier, Sender<IpcMessage>>>>,
    incoming_tx: Sender<(Identifier, IpcMessage)>,
) -> Result<()> {
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
    async fn test_unix_socket_communication() {
        // Create a temporary directory for the socket
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Create server and client IDs
        let server_id = Identifier::try_from(1).unwrap();
        let client_id = Identifier::try_from(2).unwrap();

        // Create and start server
        let mut server = IpcServer::new(server_id, &socket_path).await.unwrap();
        server.start().await.unwrap();

        // Create and connect client
        let mut client = IpcClient::new(client_id, server_id);
        client.connect(&socket_path).await.unwrap();

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

        println!("Sender ID: {:?}", sender_id);
        println!("Received message: {:?}", received_message);

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
        server.cleanup().unwrap();
    }
}