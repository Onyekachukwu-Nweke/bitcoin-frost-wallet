use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{DkgMessage, IpcMessage, Participant, ProcessState, ThresholdConfig};
use crate::frost_dkg::chilldkg::{DkgCoordinator, DkgRoundState};
use crate::ipc::{IpcServer, IpcClient, ParticipantProcess, ProcessCoordinator};
use frost_secp256k1::keys::{Identifier, KeyPackage, PublicKeyPackage};
use std::collections::HashMap;
// use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

/// Timeout for DKG operations in seconds
const DKG_TIMEOUT_SECONDS: u64 = 60;

/// DKG process controller - coordinates DKG across multiple processes
pub struct DkgProcessController {
    /// Local participant ID
    local_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// DKG coordinator
    coordinator: DkgCoordinator,
    /// Process coordinator
    processes: ProcessCoordinator,
    /// IPC server
    ipc_server: Option<IpcServer>,
    /// IPC clients
    ipc_clients: HashMap<Identifier, IpcClient>,
    /// Path to participant binary
    binary_path: PathBuf,
}

impl DkgProcessController {
    /// Create a new DKG process controller
    pub fn new(
        local_id: Identifier,
        config: ThresholdConfig,
        binary_path: PathBuf,
    ) -> Self {
        let coordinator = DkgCoordinator::new(config.clone());
        let processes = ProcessCoordinator::new();

        Self {
            local_id,
            config,
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            binary_path,
        }
    }

    /// Start the IPC server
    pub async fn start_server(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let server = IpcServer::new(self.local_id, socket_path).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to a remote participant
    pub async fn connect_to_participant(
        &mut self,
        participant_id: Identifier,
        socket_path: impl AsRef<Path>,
    ) -> Result<()> {
        let mut client = IpcClient::new(self.local_id, participant_id);
        client.connect(socket_path).await?;
        self.ipc_clients.insert(participant_id, client);
        Ok(())
    }

    /// Spawn a new participant process
    pub async fn spawn_participant(
        &mut self,
        participant_id: Identifier,
        args: Vec<String>,
    ) -> Result<()> {
        let mut process = ParticipantProcess::new(participant_id, self.binary_path.clone());
        process.spawn(args).await?;

        self.processes.add_process(process);
        Ok(())
    }

    /// Run DKG with the local participant
    pub async fn run_dkg(&mut self) -> Result<KeyPackage> {
        // Initialize DKG
        self.coordinator.start()?;

        // Make sure we have a local participant
        let local_participant = Participant::new(self.local_id);
        self.coordinator.add_participant(local_participant)?;

        // Start DKG with all remote participants
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Start(self.config.clone()))).await?;

        // Run DKG rounds
        self.run_dkg_round1().await?;
        self.run_dkg_round2().await?;
        self.run_dkg_round3().await?;

        // Get local key package
        self.coordinator.get_key_package(self.local_id)
    }

    /// Run DKG Round 1: Generate and share commitments
    async fn run_dkg_round1(&mut self) -> Result<()> {
        log::info!("Starting DKG Round 1");

        // Check current state
        match self.coordinator.get_round_state() {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(
                "Invalid state for Round 1".to_string()
            )),
        }

        // Generate local commitment
        let round1_package = self.coordinator.generate_round1(self.local_id)?;

        // Process local commitment
        self.coordinator.process_round1_package(self.local_id, round1_package.clone())?;

        // Broadcast commitment to all participants
        let commitment_bytes = bincode::serialize(&round1_package)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize commitment: {}", e)))?;

        self.broadcast_message(IpcMessage::Dkg(
            DkgMessage::Commitment(self.local_id, commitment_bytes)
        )).await?;

        // Wait for commitments from all participants
        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(DKG_TIMEOUT_SECONDS);

        while !matches!(self.coordinator.get_round_state(), DkgRoundState::Round2) {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError("Timed out waiting for commitments".to_string()));
            }

            // Process any incoming messages
            if let Some(server) = &mut self.ipc_server {
                // Try to receive with a short timeout
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        self.handle_dkg_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            // Short sleep to avoid busy waiting
            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Completed DKG Round 1");
        Ok(())
    }

    /// Run DKG Round 2: Exchange key shares
    async fn run_dkg_round2(&mut self) -> Result<()> {
        log::info!("Starting DKG Round 2");

        // Check current state
        match self.coordinator.get_round_state() {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(
                "Invalid state for Round 2".to_string()
            )),
        }

        // Generate and send key shares to each participant
        for &participant_id in self.coordinator.get_participants().keys() {
            if participant_id != self.local_id {
                // Generate key share for this participant
                let round2_package = self.coordinator.generate_round2(self.local_id)?;

                // Serialize the key share
                let key_share_bytes = bincode::serialize(&round2_package)
                    .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize key share: {}", e)))?;

                // Send key share
                self.send_message(
                    participant_id,
                    IpcMessage::Dkg(DkgMessage::KeyShare(
                        self.local_id,
                        participant_id,
                        key_share_bytes,
                    )),
                ).await?;

                // Process key share locally
                self.coordinator.process_round2_package(
                    participant_id,
                    round2_package,
                )?;
            }
        }

        // Wait for key shares from all participants
        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(DKG_TIMEOUT_SECONDS);

        while !matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError("Timed out waiting for key shares".to_string()));
            }

            // Process any incoming messages
            if let Some(server) = &mut self.ipc_server {
                // Try to receive with a short timeout
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        self.handle_dkg_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            // Short sleep to avoid busy waiting
            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Completed DKG Round 2");
        Ok(())
    }

    /// Run DKG Round 3: Verify and finalize
    async fn run_dkg_round3(&mut self) -> Result<PublicKeyPackage> {
        log::info!("Starting DKG Round 3");

        // Check current state
        match self.coordinator.get_round_state() {
            DkgRoundState::Round3 => {},
            _ => return Err(FrostWalletError::DkgError(
                "Invalid state for Round 3".to_string()
            )),
        }

        // Finalize DKG
        let key_package = self.coordinator.finalize(self.local_id)?;
        let pub_key_package = self.coordinator.get_public_key_package()?;

        // Broadcast completion
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Finish)).await?;

        log::info!("Completed DKG Round 3");
        Ok(pub_key_package)
    }

    /// Handle a DKG message from a participant
    async fn handle_dkg_message(
        &mut self,
        sender_id: Identifier,
        message: IpcMessage,
    ) -> Result<()> {
        match message {
            IpcMessage::Dkg(dkg_message) => {
                match dkg_message {
                    DkgMessage::Start(config) => {
                        // Verify config matches ours
                        if config.threshold != self.config.threshold ||
                            config.total_participants != self.config.total_participants {
                            return Err(FrostWalletError::DkgError(
                                "Threshold config mismatch".to_string()
                            ));
                        }

                        // Add participant if not already present
                        let participant = Participant::new(sender_id);
                        let _ = self.coordinator.add_participant(participant);
                    },
                    DkgMessage::Commitment(participant_id, commitment_bytes) => {
                        // Deserialize the commitment
                        let round1_package = bincode::deserialize(&commitment_bytes)
                            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize commitment: {}", e)))?;

                        // Process commitment
                        self.coordinator.process_round1_package(participant_id, round1_package)?;
                    },
                    DkgMessage::KeyShare(from_id, to_id, key_share_bytes) => {
                        // Process key share if it's for us
                        if to_id == self.local_id {
                            // Deserialize the key share
                            let round2_package = bincode::deserialize(&key_share_bytes)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize key share: {}", e)))?;

                            self.coordinator.process_round2_package(from_id, round2_package)?;
                        }
                    },
                    DkgMessage::Finish => {
                        // Nothing to do, we'll detect completion from state
                    },
                }
            },
            _ => {
                return Err(FrostWalletError::DkgError(
                    "Unexpected message type during DKG".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Send a message to a specific participant
    async fn send_message(
        &self,
        participant_id: Identifier,
        message: IpcMessage,
    ) -> Result<()> {
        if let Some(client) = self.ipc_clients.get(&participant_id) {
            client.send(message).await?;
            Ok(())
        } else if let Some(server) = &self.ipc_server {
            server.send(participant_id, message).await
        } else {
            Err(FrostWalletError::IpcError(format!(
                "No connection to participant {:?}",
                participant_id
            )))
        }
    }

    /// Broadcast a message to all participants
    async fn broadcast_message(&self, message: IpcMessage) -> Result<()> {
        // Send to all IPC clients
        for (id, client) in &self.ipc_clients {
            if let Err(e) = client.send(message.clone()).await {
                log::error!("Failed to send to participant {}: {}", id, e);
            }
        }

        // Send to all IPC server clients
        if let Some(server) = &self.ipc_server {
            server.broadcast(message).await?;
        }

        Ok(())
    }
}

/// DKG participant process - runs on each participant
pub struct DkgParticipantProcess {
    /// Local participant ID
    local_id: Identifier,
    /// DKG coordinator
    coordinator: DkgCoordinator,
    /// IPC client for connection to coordinator
    coordinator_client: Option<IpcClient>,
}

impl DkgParticipantProcess {
    /// Create a new DKG participant process
    pub fn new(local_id: Identifier) -> Self {
        let config = ThresholdConfig::new(2, 3); // Default config, will be overridden by coordinator
        let coordinator = DkgCoordinator::new(config);

        Self {
            local_id,
            coordinator,
            coordinator_client: None,
        }
    }

    /// Connect to the DKG coordinator
    pub async fn connect_to_coordinator(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let mut client = IpcClient::new(self.local_id, Identifier::try_from(1).unwrap());
        client.connect(socket_path).await?;
        self.coordinator_client = Some(client);
        Ok(())
    }

    /// Run the DKG process
    pub async fn run(&mut self) -> Result<KeyPackage> {
        // Wait for Start message from coordinator
        let client = self.coordinator_client.as_mut()
            .ok_or_else(|| FrostWalletError::InvalidState("Not connected to coordinator".to_string()))?;

        // Send handshake
        client.send(IpcMessage::Handshake(self.local_id)).await?;

        // Wait for initial DKG message
        let message = client.receive().await?;

        let config = match message {
            IpcMessage::Dkg(DkgMessage::Start(config)) => config,
            _ => return Err(FrostWalletError::DkgError("Expected Start message from coordinator".to_string())),
        };

        // Initialize DKG with the received config
        self.coordinator = DkgCoordinator::new(config);
        self.coordinator.start()?;

        // Add ourselves as a participant
        let local_participant = Participant::new(self.local_id);
        self.coordinator.add_participant(local_participant)?;

        // Run DKG rounds
        let key_package = self.run_dkg_rounds(client).await?;

        Ok(key_package)
    }

    /// Run the DKG rounds
    async fn run_dkg_rounds(&mut self, client: &mut IpcClient) -> Result<KeyPackage> {
        // Process messages until DKG is complete
        loop {
            let message = client.receive().await?;

            match message {
                IpcMessage::Dkg(dkg_message) => {
                    match dkg_message {
                        DkgMessage::Commitment(participant_id, commitment_bytes) => {
                            // Deserialize the commitment
                            let round1_package = bincode::deserialize(&commitment_bytes)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize commitment: {}", e)))?;

                            // Process the commitment
                            self.coordinator.process_round1_package(participant_id, round1_package)?;

                            // If we're in Round 1, generate and send our commitment
                            if matches!(self.coordinator.get_round_state(), DkgRoundState::Round1) {
                                let round1_package = self.coordinator.generate_round1(self.local_id)?;

                                // Process our own commitment
                                self.coordinator.process_round1_package(self.local_id, round1_package.clone())?;

                                // Serialize and send the commitment
                                let commitment_bytes = bincode::serialize(&round1_package)
                                    .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize commitment: {}", e)))?;

                                client.send(IpcMessage::Dkg(
                                    DkgMessage::Commitment(self.local_id, commitment_bytes)
                                )).await?;
                            }
                        },
                        DkgMessage::KeyShare(from_id, to_id, key_share_bytes) => {
                            // Process key share if it's for us
                            if to_id == self.local_id {
                                // Deserialize the key share
                                let round2_package = bincode::deserialize(&key_share_bytes)
                                    .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize key share: {}", e)))?;

                                self.coordinator.process_round2_package(from_id, round2_package)?;
                            }

                            // If we're in Round 2, generate and send our key shares
                            if matches!(self.coordinator.get_round_state(), DkgRoundState::Round2) {
                                // Generate our round 2 package
                                let round2_package = self.coordinator.generate_round2(self.local_id)?;

                                // Serialize the package
                                let key_share_bytes = bincode::serialize(&round2_package)
                                    .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize key share: {}", e)))?;

                                // Send to all participants
                                for &participant_id in self.coordinator.get_participants().keys() {
                                    if participant_id != self.local_id {
                                        client.send(IpcMessage::Dkg(
                                            DkgMessage::KeyShare(self.local_id, participant_id, key_share_bytes.clone())
                                        )).await?;
                                    }
                                }
                            }
                        },
                        DkgMessage::Finish => {
                            // Finalize DKG
                            if matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
                                let key_package = self.coordinator.finalize(self.local_id)?;
                                return Ok(key_package);
                            }
                        },
                        _ => {}
                    }
                },
                _ => {}
            }

            // Check if we've advanced to Round 3
            if matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
                // Send Finish message
                client.send(IpcMessage::Dkg(DkgMessage::Finish)).await?;

                // Wait for Finish message from coordinator
                loop {
                    let message = client.receive().await?;
                    if let IpcMessage::Dkg(DkgMessage::Finish) = message {
                        break;
                    }
                }

                // Finalize and return key package
                let key_package = self.coordinator.finalize(self.local_id)?;
                return Ok(key_package);
            }
        }
    }
}