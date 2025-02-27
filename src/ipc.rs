use crate::error::{FrostWalletError, Result};
use crate::types::{DkgMessage, IpcMessage, SigningMessage, ThresholdConfig};
use frost_core::Identifier;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};


/// Maximum message size in bytes (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
/// Message header size in bytes (4 bytes for message length)
const HEADER_SIZE: usize = 4;

/// IPC channel for communication between processes
pub struct IpcChannel<T> {
    /// Sender for outgoing messages
    tx: Sender<T>,
    /// Receiver for incoming messages
    rx: Receiver<T>,
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

/// TCP-based IPC server
pub struct IpcServer {
    /// Local participant ID
    local_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
    /// Listening address
    address: SocketAddr,
    /// Connected clients
    clients: Arc<Mutex<HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Sender<IpcMessage>>>>,
    /// Channel for incoming messages
    incoming: IpcChannel<(Identifier<frost_secp256k1::Secp256K1Sha256>, IpcMessage)>,
}

impl IpcServer {
    /// Create a new IPC server
    pub async fn new(local_id: Identifier<frost_secp256k1::Secp256K1Sha256>, address: SocketAddr) -> Result<Self> {
        let server = Self {
            local_id,
            address,
            clients: Arc::new(Mutex::new(HashMap::new())),
            incoming: IpcChannel::new(100),
        };

        Ok(server)
    }

    /// Start listening for connections
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.address).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to bind to {}: {}", self.address, e)))?;

        let clients = self.clients.clone();
        let incoming_tx = self.incoming.sender();

        // Spawn a task to accept connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        log::info!("New connection from {}", addr);

                        let clients = clients.clone();
                        let incoming_tx = incoming_tx.clone();

                        // Handle connection in a separate task
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, addr, clients, incoming_tx).await {
                                log::error!("Error handling connection from {}: {}", addr, e);
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
    pub async fn send(&self, participant_id: Identifier<frost_secp256k1::Secp256K1Sha256>, message: IpcMessage) -> Result<()> {
        let clients = self.clients.lock().unwrap();

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
        let clients = self.clients.lock().unwrap();

        for (id, tx) in clients.iter() {
            if let Err(e) = tx.send(message.clone()).await {
                log::error!("Failed to send to participant {:?}: {}", id, e);
            }
        }

        Ok(())
    }

    /// Receive the next message
    pub async fn receive(&mut self) -> Result<(Identifier<frost_secp256k1::Secp256K1Sha256>, IpcMessage)> {
        self.incoming.rx.recv().await
            .ok_or_else(|| FrostWalletError::IpcError("Channel closed".to_string()))
    }
}

/// TCP-based IPC client
pub struct IpcClient {
    /// Local participant ID
    local_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
    /// Remote participant ID
    remote_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
    /// TCP stream
    stream: Option<TcpStream>,
    /// Channel for outgoing messages
    outgoing: Sender<IpcMessage>,
    /// Channel for incoming messages
    incoming: Receiver<IpcMessage>,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(local_id: Identifier<frost_secp256k1::Secp256K1Sha256>, remote_id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Self {
        let (outgoing_tx, mut outgoing_rx) = channel::<IpcMessage>(100);
        let (incoming_tx, mut incoming_rx) = channel::<IpcMessage>(100);

        Self {
            local_id,
            remote_id,
            stream: None,
            outgoing: outgoing_tx,
            incoming: incoming_rx,
        }
    }

    /// Connect to a server
    pub async fn connect(&mut self, address: SocketAddr) -> Result<()> {
        let stream = TcpStream::connect(address).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to connect to {}: {}", address, e)))?;

        // self.stream = Some(stream);

        let (read_half, mut write_half) = stream.into_split();

        // Wrap the write_half in an Arc<Mutex<>> so it can be shared
        // let write_half = Arc::new(Mutex::new(write_half));

        // Clone for the task
        // let write_half_clone = write_half.clone();

        let (outgoing_tx, mut outgoing_rx) = channel::<IpcMessage>(100);
        let (incoming_tx, incoming_rx) = channel::<IpcMessage>(100);

        // Spawn task to read incoming messages
        // let incoming_tx = incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = read_messages(read_half, incoming_tx).await {
                log::error!("Error reading messages: {}", e);
            }
        });

        // Spawn task to write outgoing messages
        // let mut outgoing_rx = self.outgoing.clone();
        tokio::spawn(async move {
            while let Some(message) = outgoing_rx.recv().await {
                if let Err(e) = write_message(&mut write_half, &message).await {
                    log::error!("Error writing message: {}", e);
                    break;
                }
            }
        });

        // Store the sender end in self to allow sending messages
        self.outgoing = outgoing_tx;
        self.incoming = incoming_rx;

        // Send initial handshake with our ID
        self.send(IpcMessage::Handshake(self.local_id)).await?;

        // Store None since we've already consumed the stream
        self.stream = None;

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
    mut stream: TcpStream,
    addr: SocketAddr,
    clients: Arc<Mutex<HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Sender<IpcMessage>>>>,
    incoming_tx: Sender<(Identifier<frost_secp256k1::Secp256K1Sha256>, IpcMessage)>,
) -> Result<()> {
    // Wait for handshake message to get client ID
    let mut message_buf = Vec::new();
    let mut len_buf = [0u8; HEADER_SIZE];

    stream.read_exact(&mut len_buf).await
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
    stream.read_exact(&mut message_buf).await
        .map_err(|e| FrostWalletError::IpcError(format!("Failed to read message body: {}", e)))?;

    let message: IpcMessage = bincode::deserialize(&message_buf)
        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))?;

    let client_id = match &message {
        IpcMessage::Handshake(id) => *id,
        _ => return Err(FrostWalletError::IpcError("Expected handshake message".to_string())),
    };

    log::info!("Client {:?} connected from {}", client_id, addr);

    // Create a channel for messages to send to this client
    let (client_tx, mut client_rx) = channel::<IpcMessage>(100);

    // Add client to the map
    {
        let mut clients = clients.lock().unwrap();
        clients.insert(client_id, client_tx.clone());
    }

    // Now split the stream and spawn tasks inside an async block to manage ownership properly
    let (read_half, mut write_half) = stream.into_split();

    // Create adapter for read_messages
    let (adapter_tx, mut adapter_rx) = channel::<IpcMessage>(100);

    // Spawn a task to forward messages with client_id
    let forward_tx = incoming_tx.clone();
    tokio::spawn(async move {
        while let Some(msg) = adapter_rx.recv().await {
            if let Err(e) = forward_tx.send((client_id, msg)).await {
                log::error!("Failed to forward message: {}", e);
                break;
            }
        }
    });

    // Spawn task to read incoming messages
    tokio::spawn(async move {
        if let Err(e) = read_messages(read_half, adapter_tx).await {
            log::error!("Error reading messages from client {:?}: {}", client_id, e);
        }

        // Remove client when done
        let mut clients = clients.lock().unwrap();
        clients.remove(&client_id);
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

// Helper function to write a message to a stream
async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(
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
}