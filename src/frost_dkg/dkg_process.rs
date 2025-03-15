use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use crate::common::errors::{FrostWalletError, Result};
use crate::frost_dkg::chilldkg::{DkgCoordinator, DkgRoundState};
use crate::ipc::{IpcServer, IpcClient};
use crate::ipc::process::{ParticipantProcess, ProcessCoordinator};
use crate::common::types::{
    DkgMessage, IpcMessage, Participant, ProcessState, ThresholdConfig,
};
use frost_secp256k1::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage},
};

/// Timeout for DKG operations in seconds
const DKG_TIMEOUT_SECONDS: u64 = 60;
/// Timeout for participant connections in seconds
const CONNECTION_TIMEOUT_SECONDS: u64 = 30;
/// Default poll interval in milliseconds
const POLL_INTERVAL_MS: u64 = 100;

/// Enum to track the state of the DKG process
#[derive(Debug, Clone, PartialEq)]
pub enum DkgProcessState {
    /// Waiting for participants to connect
    WaitingForConnections {
        /// Number of participants connected so far
        connected: usize,
        /// Total number of participants expected
        expected: usize,
    },
    /// Running DKG Round 1
    Round1,
    /// Running DKG Round 2
    Round2,
    /// Running DKG Round 3
    Round3,
    /// DKG completed successfully
    Completed,
    /// DKG failed
    Failed(String),
}

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
    /// Current state of the DKG process
    state: DkgProcessState,
    /// Participants that have sent their round 1 commitments
    round1_participants: HashSet<Identifier>,
    /// Participants that have sent their round 2 key shares
    round2_participants: HashSet<Identifier>,
    /// Connected participants
    connected_participants: HashSet<Identifier>,
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

        let expected = config.total_participants as usize;

        Self {
            local_id,
            config: config.clone(),
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            binary_path,
            state: DkgProcessState::WaitingForConnections { connected: 1, expected }, // Start with 1 (self)
            round1_participants: HashSet::new(),
            round2_participants: HashSet::new(),
            connected_participants: HashSet::from([local_id]), // Start with self connected
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

    /// Check if a participant is connected
    pub fn is_participant_connected(&self, id: Identifier) -> bool {
        self.connected_participants.contains(&id)
    }

    /// Add a participant to the coordinator
    pub fn add_participant(&mut self, id: Identifier) -> Result<bool> {
        if self.is_participant_connected(id) {
            return Ok(false); // Already connected
        }

        let participant = Participant::new(id);
        self.coordinator.add_participant(participant)?;
        self.connected_participants.insert(id);

        // Update the connection state
        if let DkgProcessState::WaitingForConnections { connected, expected } = &mut self.state {
            *connected += 1;
            log::info!("Participant {:?} connected. Now have {}/{} participants.",
                id, *connected, *expected);

            if *connected == *expected {
                // All participants connected, ready to start DKG
                self.state = DkgProcessState::Round1;
            }
        }

        Ok(true) // Successfully added
    }

    /// Run DKG with the local participant
    pub async fn run_dkg(&mut self) -> Result<KeyPackage> {
        // Initialize DKG
        self.coordinator.start()?;

        // Make sure we have a local participant
        let local_participant = Participant::new(self.local_id);
        self.coordinator.add_participant(local_participant)?;

        // Wait for all participants to connect
        self.wait_for_connections().await?;

        // Start DKG with all remote participants
        log::info!("All participants connected. Starting DKG process.");
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Start(self.config.clone()))).await?;

        // Run DKG rounds
        self.run_dkg_round1().await?;
        self.run_dkg_round2().await?;
        self.run_dkg_round3().await?;

        // Update state to completed
        self.state = DkgProcessState::Completed;

        // Get local key package
        self.coordinator.get_key_package(self.local_id)
    }

    /// Wait for all participants to connect
    async fn wait_for_connections(&mut self) -> Result<()> {
        log::info!("Waiting for participants to connect... (expecting {} total)",
                  self.config.total_participants);

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(CONNECTION_TIMEOUT_SECONDS);

        while let DkgProcessState::WaitingForConnections { connected, expected } = self.state {
            if connected == expected {
                log::info!("All {} participants connected", connected);
                self.state = DkgProcessState::Round1;
                return Ok(());
            }

            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError(
                    format!("Timed out waiting for participants to connect. Have {}, need {}",
                            connected, expected)
                ));
            }

            // Process any incoming messages to handle handshakes
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(POLL_INTERVAL_MS), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        log::info!("Received message from participant {:?}: {:?}",
                                  sender_id,
                                  if let IpcMessage::Handshake(_) = &message {
                                      "Handshake".to_string()
                                  } else {
                                      format!("{:?}", message)
                                  });
                        self.process_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue waiting
                }
            }

            // Short sleep to avoid busy waiting
            sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Process an incoming message
    async fn process_message(&mut self, sender_id: Identifier, message: IpcMessage) -> Result<()> {
        match message {
            IpcMessage::Handshake(id) => {
                log::info!("Received handshake from participant: {:?}", id);
                let was_added = self.add_participant(id)?;

                // Send acknowledgment
                log::info!("Sending acknowledgment to participant: {:?}", id);
                match self.send_message(id, IpcMessage::Success(None)).await {
                    Ok(_) => log::info!("Successfully sent acknowledgment to participant: {:?}", id),
                    Err(e) => log::error!("Failed to send acknowledgment to participant {:?}: {}", id, e),
                }
            },
            IpcMessage::Dkg(dkg_message) => {
                self.handle_dkg_message(sender_id, dkg_message).await?;
            },
            _ => {
                log::debug!("Ignoring unexpected message type: {:?}", message);
            }
        }

        Ok(())
    }

    /// Run DKG Round 1: Generate and share commitments
    async fn run_dkg_round1(&mut self) -> Result<()> {
        log::info!("Starting DKG Round 1");
        self.state = DkgProcessState::Round1;

        // Check current state
        match self.coordinator.get_round_state() {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(
                "Invalid state for Round 1".to_string()
            )),
        }

        // Generate local Round 1 package
        let round1_package = self.coordinator.generate_round1(self.local_id)?;

        // Add self to the round1 participants
        self.round1_participants.insert(self.local_id);

        // Broadcast round1 package to all participants
        self.broadcast_message(IpcMessage::Dkg(
            DkgMessage::Commitment(self.local_id, bincode::serialize(&round1_package)?)
        )).await?;

        // Wait for commitments from all participants
        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(DKG_TIMEOUT_SECONDS);

        while self.round1_participants.len() < self.connected_participants.len() {
            if start_time.elapsed() > timeout_duration {
                self.state = DkgProcessState::Failed("Timed out waiting for commitments".to_string());
                return Err(FrostWalletError::TimeoutError("Timed out waiting for commitments".to_string()));
            }

            // Process any incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(POLL_INTERVAL_MS), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        self.process_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            // Short sleep to avoid busy waiting
            sleep(Duration::from_millis(10)).await;
        }

        // Verify that we transitioned to Round 2
        if !matches!(self.coordinator.get_round_state(), DkgRoundState::Round2) {
            self.state = DkgProcessState::Failed("Failed to transition to Round 2".to_string());
            return Err(FrostWalletError::DkgError("Failed to transition to Round 2".to_string()));
        }

        log::info!("Completed DKG Round 1");
        self.state = DkgProcessState::Round2;
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

        // Generate Round 2 packages for this participant
        let round2_packages = self.coordinator.generate_round2(self.local_id)?;

        // Add self to round2 participants
        self.round2_participants.insert(self.local_id);

        // Send each package to the corresponding participant
        for (recipient_id, package) in &round2_packages {
            self.send_message(
                *recipient_id,
                IpcMessage::Dkg(DkgMessage::KeyShare(
                    self.local_id,
                    *recipient_id,
                    bincode::serialize(package)?,
                )),
            ).await?;
        }

        // Wait for key shares from all participants
        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(DKG_TIMEOUT_SECONDS);

        while self.round2_participants.len() < self.connected_participants.len() {
            if start_time.elapsed() > timeout_duration {
                self.state = DkgProcessState::Failed("Timed out waiting for key shares".to_string());
                return Err(FrostWalletError::TimeoutError("Timed out waiting for key shares".to_string()));
            }

            // Process any incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(POLL_INTERVAL_MS), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        self.process_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            // Short sleep to avoid busy waiting
            sleep(Duration::from_millis(10)).await;
        }

        // Verify that we transitioned to Round 3
        if !matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
            self.state = DkgProcessState::Failed("Failed to transition to Round 3".to_string());
            return Err(FrostWalletError::DkgError("Failed to transition to Round 3".to_string()));
        }

        log::info!("Completed DKG Round 2");
        self.state = DkgProcessState::Round3;
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

        // Finalize DKG for the local participant
        let key_package = self.coordinator.finalize(self.local_id)?;

        // Get public key package
        let pub_key_package = self.coordinator.get_public_key_package()?;

        // Broadcast completion
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Finish)).await?;

        log::info!("Completed DKG Round 3");
        self.state = DkgProcessState::Completed;
        Ok(pub_key_package)
    }

    /// Handle a DKG message from a participant
    async fn handle_dkg_message(
        &mut self,
        sender_id: Identifier,
        dkg_message: DkgMessage,
    ) -> Result<()> {
        log::debug!("Received DKG message from {:?}: {:?}",
            sender_id,
            match &dkg_message {
                DkgMessage::Start(_) => "Start".to_string(),
                DkgMessage::Commitment(_, _) => "Commitment".to_string(),
                DkgMessage::KeyShare(_, _, _) => "KeyShare".to_string(),
                DkgMessage::Finish => "Finish".to_string(),
            }
        );

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
                self.add_participant(sender_id)?;
            },
            DkgMessage::Commitment(participant_id, commitment_data) => {
                // Ensure the participant is registered
                if !self.is_participant_connected(participant_id) {
                    let _ = self.add_participant(participant_id);
                }

                // Deserialize commitment data
                let round1_package = bincode::deserialize(&commitment_data)?;

                // Process commitment
                self.coordinator.process_round1_package(participant_id, round1_package)?;

                // Mark participant as having sent round1 commitment
                self.round1_participants.insert(participant_id);

                log::debug!("Processed commitment from participant {:?} ({}/{} received)",
                    participant_id,
                    self.round1_participants.len(),
                    self.connected_participants.len());
            },
            DkgMessage::KeyShare(from_id, to_id, key_share_data) => {
                // Process key share if it's for us
                if to_id == self.local_id {
                    // Deserialize key share data
                    let round2_package = bincode::deserialize(&key_share_data)?;

                    // Collect all packages for this sender
                    let mut packages = BTreeMap::new();
                    packages.insert(self.local_id, round2_package);

                    // Process the round 2 package
                    self.coordinator.process_round2_package(from_id, packages)?;

                    // Mark participant as having sent round2 key share
                    self.round2_participants.insert(from_id);

                    log::debug!("Processed key share from participant {:?} ({}/{} received)",
                        from_id,
                        self.round2_participants.len(),
                        self.connected_participants.len());
                }
            },
            DkgMessage::Finish => {
                // Nothing to do, we'll detect completion from state
                log::debug!("Received finish message from participant {:?}", sender_id);
            },
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
        if let Some(server) = &self.ipc_server {
            server.broadcast(message).await
        } else {
            // If no server, send to each client individually
            for (id, client) in &self.ipc_clients {
                client.send(message.clone()).await?;
            }
            Ok(())
        }
    }

    /// Get the current DKG process state
    pub fn get_state(&self) -> &DkgProcessState {
        &self.state
    }

    /// Clean up resources
    pub async fn cleanup(&mut self) -> Result<()> {
        // Terminate all spawned processes
        self.processes.terminate_all().await?;

        // Clean up IPC server
        if let Some(server) = &self.ipc_server {
            server.cleanup()?;
        }

        Ok(())
    }
}

/// DKG participant process - runs as a separate process
pub struct DkgParticipantProcess {
    /// Local participant ID
    local_id: Identifier,
    /// DKG coordinator
    coordinator: DkgCoordinator,
    /// IPC client for communication with the coordinator
    client: Option<IpcClient>,
    /// Received key package
    key_package: Option<KeyPackage>,
    /// IPC server for incoming connections
    ipc_server: Option<IpcServer>,
    /// Current state of the DKG process
    state: DkgProcessState,
}

impl DkgParticipantProcess {
    /// Create a new DKG participant process
    pub fn new(local_id: Identifier) -> Self {
        let config = ThresholdConfig::new(0, 0); // Will be replaced with actual config from coordinator
        let coordinator = DkgCoordinator::new(config);

        Self {
            local_id,
            coordinator,
            client: None,
            key_package: None,
            ipc_server: None,
            state: DkgProcessState::WaitingForConnections { connected: 0, expected: 0 },
        }
    }

    /// Start the IPC server
    pub async fn start_server(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let server = IpcServer::new(self.local_id, socket_path).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to the coordinator
    pub async fn connect_to_coordinator(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let coordinator_id = Identifier::try_from(1u16).unwrap(); // Assuming coordinator has ID 1
        println!("Connecting to participant {:?}", self.local_id);
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(socket_path).await?;
        self.client = Some(client);

        // Send handshake to coordinator
        if let Some(client) = &mut self.client {
            client.send(IpcMessage::Handshake(self.local_id)).await?;

            // Wait for acknowledgment
            let start_time = Instant::now();
            let timeout_duration = Duration::from_secs(10);

            while start_time.elapsed() < timeout_duration {
                match timeout(Duration::from_millis(500), client.receive()).await {
                    Ok(Ok(message)) => {
                        if let IpcMessage::Success(_) = message {
                            log::info!("Handshake with coordinator successful");
                            return Ok(());
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => continue, // Timeout, keep waiting
                }
            }

            // If we got here, we timed out waiting for acknowledgment
            Err(FrostWalletError::TimeoutError("Timed out waiting for handshake acknowledgment".to_string()))
        } else {
            Err(FrostWalletError::InvalidState("Failed to initialize client".to_string()))
        }
    }

    /// Run the DKG protocol as a participant
    pub async fn run(&mut self) -> Result<KeyPackage> {
        // Verify we have a connection to the coordinator
        let client = self.client.as_mut()
            .ok_or_else(|| FrostWalletError::InvalidState("Not connected to coordinator".to_string()))?;

        let mut round_state = DkgRoundState::Round1;
        let mut received_config = false;

        log::info!("Starting DKG as participant {:?}", self.local_id);

        // Wait for coordinator to start DKG
        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(CONNECTION_TIMEOUT_SECONDS);

        while !received_config {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError("Timed out waiting for DKG start".to_string()));
            }

            // Receive a message from the coordinator
            match timeout(Duration::from_secs(1), client.receive()).await {
                Ok(Ok(message)) => {
                    match message {
                        IpcMessage::Dkg(DkgMessage::Start(config)) => {
                            log::info!("Received DKG start: {:?}", config);

                            // Initialize coordinator with the received config
                            self.coordinator = DkgCoordinator::new(config.clone());

                            // Add ourselves as a participant
                            let participant = Participant::new(self.local_id);
                            self.coordinator.add_participant(participant)?;

                            // Start the DKG process
                            self.coordinator.start()?;
                            received_config = true;
                            self.state = DkgProcessState::Round1;
                            break;
                        },
                        _ => {
                            // Ignore other messages until we receive the DKG start
                            log::debug!("Ignoring message while waiting for DKG start");
                            continue;
                        }
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout, continue waiting
                    continue;
                }
            }
        }

        if !received_config {
            return Err(FrostWalletError::TimeoutError("Timed out waiting for DKG start".to_string()));
        }

        // Process DKG rounds
        log::info!("Starting DKG rounds");

        // Round 1: Generate commitment
        round_state = DkgRoundState::Round1;
        let round1_package = self.coordinator.generate_round1(self.local_id)?;

        // Send commitment to coordinator
        client.send(IpcMessage::Dkg(
            DkgMessage::Commitment(self.local_id, bincode::serialize(&round1_package)?)
        )).await?;

        // Process incoming messages and advance through rounds
        let timeout_duration = Duration::from_secs(DKG_TIMEOUT_SECONDS * 3); // 3 minutes total timeout
        let start_time = Instant::now();

        while start_time.elapsed() < timeout_duration {
            match timeout(Duration::from_millis(POLL_INTERVAL_MS), client.receive()).await {
                Ok(Ok(message)) => {
                    match message {
                        IpcMessage::Dkg(dkg_message) => {
                            match dkg_message {
                                DkgMessage::Commitment(participant_id, commitment_data) => {
                                    // Process commitment
                                    log::debug!("Received commitment from participant {:?}", participant_id);
                                    let round1_package = bincode::deserialize(&commitment_data)?;
                                    self.coordinator.process_round1_package(participant_id, round1_package)?;
                                },
                                DkgMessage::KeyShare(from_id, to_id, key_share_data) => {
                                    // Process key share if it's for us
                                    if to_id == self.local_id {
                                        log::debug!("Received key share from participant {:?}", from_id);
                                        // Deserialize key share data
                                        let round2_package = bincode::deserialize(&key_share_data)?;

                                        // Collect all packages for this sender
                                        let mut packages = BTreeMap::new();
                                        packages.insert(self.local_id, round2_package);

                                        // Process the round 2 package
                                        self.coordinator.process_round2_package(from_id, packages)?;

                                        // If we're now in Round 2, generate and send our Round 2 packages
                                        if matches!(self.coordinator.get_round_state(), DkgRoundState::Round2)
                                            && round_state != DkgRoundState::Round2 {
                                            round_state = DkgRoundState::Round2;
                                            self.state = DkgProcessState::Round2;
                                            log::debug!("Advancing to Round 2");

                                            // Generate Round 2 packages
                                            let round2_packages = self.coordinator.generate_round2(self.local_id)?;

                                            // Send each package to the coordinator (it will forward to the right participant)
                                            for (recipient_id, package) in &round2_packages {
                                                log::debug!("Sending key share to participant {:?}", recipient_id);
                                                client.send(IpcMessage::Dkg(DkgMessage::KeyShare(
                                                    self.local_id,
                                                    *recipient_id,
                                                    bincode::serialize(package)?,
                                                ))).await?;
                                            }
                                        }
                                    }
                                },
                                DkgMessage::Finish => {
                                    // Finalize the DKG process if we have all data
                                    log::debug!("Received DKG finish message");
                                    if matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
                                        log::info!("Finalizing DKG");
                                        let key_package = self.coordinator.finalize(self.local_id)?;
                                        self.key_package = Some(key_package.clone());
                                        self.state = DkgProcessState::Completed;
                                        return Ok(key_package);
                                    }
                                },
                                _ => {
                                    // Ignore other DKG messages
                                    log::debug!("Ignoring unexpected DKG message");
                                }
                            }
                        },
                        _ => {
                            // Ignore non-DKG messages
                            log::debug!("Ignoring non-DKG message");
                        }
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Timeout, check round state and take actions if needed
                    match self.coordinator.get_round_state() {
                        DkgRoundState::Round3 if round_state != DkgRoundState::Round3 => {
                            // If we reached Round 3 but haven't yet finalized
                            round_state = DkgRoundState::Round3;
                            self.state = DkgProcessState::Round3;
                            log::info!("Advancing to Round 3");
                            let key_package = self.coordinator.finalize(self.local_id)?;
                            self.key_package = Some(key_package.clone());

                            // Send completion back to coordinator
                            client.send(IpcMessage::Dkg(DkgMessage::Finish)).await?;
                            log::info!("Sent DKG finish message");

                            self.state = DkgProcessState::Completed;
                            return Ok(key_package);
                        },
                        _ => {
                            // Continue waiting
                            log::debug!("Waiting for messages, current state: {:?}", self.coordinator.get_round_state());
                        }
                    }
                }
            }
        }

        self.state = DkgProcessState::Failed("DKG process timed out".to_string());
        Err(FrostWalletError::TimeoutError("DKG process timed out".to_string()))
    }

    /// Get the key package
    pub fn get_key_package(&self) -> Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }

    /// Get the current DKG process state
    pub fn get_state(&self) -> &DkgProcessState {
        &self.state
    }

    /// Clean up resources
    pub fn cleanup(&self) -> Result<()> {
        // Clean up IPC server
        if let Some(server) = &self.ipc_server {
            server.cleanup()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::task;
    use std::time::Duration;
    use std::thread;

    /// Create socket paths for a test with n participants
    pub fn create_socket_paths(dir: &Path, n: u16) -> Vec<PathBuf> {
        (0..n).map(|i| dir.join(format!("participant_{}.sock", i))).collect()
    }

    /// Create test participants with unique IDs starting from 1
    pub fn create_test_participants(count: u16) -> Vec<Identifier> {
        (1..=count).map(|i| Identifier::try_from(i).unwrap()).collect()
    }

    /// Wait for a condition to become true with timeout
    pub async fn wait_for_condition<F>(mut condition: F, timeout_ms: u64) -> Result<()>
    where
        F: FnMut() -> bool,
    {
        let start = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);

        while !condition() {
            if start.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError("Condition timed out".to_string()));
            }
            sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    /// Basic multi-process DKG test
    #[tokio::test]
    async fn test_multiprocess_dkg_basic() -> Result<()> {
        // Enable logging for tests
        let _ = env_logger::builder().filter_level(log::LevelFilter::Debug).try_init();

        println!("Setting up test environment");
        // Setup test environment
        let dir = tempdir().unwrap();
        let socket_paths = create_socket_paths(dir.path(), 3); // 3 participants
        let participants = create_test_participants(3);
        let binary_path = PathBuf::from("target/debug/bitcoin-frost-wallet");
        let config = ThresholdConfig::new(2, 3); // 2-of-3

        println!("Creating coordinator");
        // Create coordinator (participant 1)
        let coordinator_id = participants[0];
        let mut controller = DkgProcessController::new(
            coordinator_id,
            config.clone(),
            binary_path.clone(),
        );

        println!("Starting coordinator's IPC server");
        // Start coordinator's IPC server
        controller.start_server(&socket_paths[0]).await?;

        // Create participant processes
        let participant2_id = participants[1];
        let participant3_id = participants[2];

        println!("Creating participant processes");
        // Create and initialize participant processes
        let mut participant2 = DkgParticipantProcess::new(participant2_id);
        let mut participant3 = DkgParticipantProcess::new(participant3_id);

        println!("Starting participant IPC servers");
        // Start participant IPC servers
        participant2.start_server(&socket_paths[1]).await?;
        participant3.start_server(&socket_paths[2]).await?;

        // Give server time to start
        sleep(Duration::from_millis(200)).await;

        println!("Connecting coordinator to participants");
        // Connect coordinator to participants
        controller.connect_to_participant(participant2_id, &socket_paths[1]).await?;
        controller.connect_to_participant(participant3_id, &socket_paths[2]).await?;

        println!("Connecting participants to coordinator");
        // Connect participants to coordinator

        // Extract the paths needed for each participant
        let coordinator_socket = socket_paths[0].clone();

        let p2_connect = task::spawn(async move {
            match participant2.connect_to_coordinator(&coordinator_socket).await {
                Ok(_) => {
                    println!("Participant 2 connected successfully");
                    Ok(participant2)
                },
                Err(e) => {
                    println!("Participant 2 failed to connect: {}", e);
                    Err(e)
                }
            }
        });

        // Extract the paths needed for each participant
        let coordinator_socket = socket_paths[0].clone();

        let p3_connect = task::spawn(async move {
            match participant3.connect_to_coordinator(&coordinator_socket).await {
                Ok(_) => {
                    println!("Participant 3 connected successfully");
                    Ok(participant3)
                },
                Err(e) => {
                    println!("Participant 3 failed to connect: {}", e);
                    Err(e)
                }
            }
        });

        // Wait for connections to complete
        let mut participant2 = timeout(Duration::from_secs(30), p2_connect).await.unwrap().unwrap().unwrap();
        let mut participant3 = timeout(Duration::from_secs(30), p3_connect).await.unwrap().unwrap().unwrap();

        // Give connections time to stabilize
        println!("Giving connections time to stabilize");
        sleep(Duration::from_millis(1000)).await;

        println!("Running DKG process");
        // Run DKG in separate tasks
        let coordinator_task = task::spawn(async move {
            println!("Coordinator starting DKG process");
            let result = controller.run_dkg().await;
            println!("Coordinator DKG process completed: {:?}", result.is_ok());
            result
        });

        let participant2_task = task::spawn(async move {
            println!("Participant 2 starting DKG process");
            let result = participant2.run().await;
            println!("Participant 2 DKG process completed: {:?}", result.is_ok());
            result
        });

        let participant3_task = task::spawn(async move {
            println!("Participant 3 starting DKG process");
            let result = participant3.run().await;
            println!("Participant 3 DKG process completed: {:?}", result.is_ok());
            result
        });

        println!("Waiting for DKG tasks to complete");
        // Wait for all tasks with timeout (increased timeout for debugging)
        let coordinator_result = timeout(Duration::from_secs(120), coordinator_task).await.unwrap().unwrap().unwrap();
        let participant2_result = timeout(Duration::from_secs(120), participant2_task).await.unwrap().unwrap().unwrap();
        let participant3_result = timeout(Duration::from_secs(120), participant3_task).await.unwrap().unwrap().unwrap();

        // Verify all participants have consistent key packages
        println!("Verifying key packages");
        let coordinator_key = coordinator_result.verifying_key();
        let participant2_key = participant2_result.verifying_key();
        let participant3_key = participant3_result.verifying_key();

        assert_eq!(coordinator_key, participant2_key);
        assert_eq!(coordinator_key, participant3_key);

        println!("Test completed successfully");
        Ok(())
    }

    #[tokio::test]
    async fn test_dkg_single_process() {
        // Create a DKG coordinator with a 2-of-3 threshold configuration
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let config = ThresholdConfig::new(2, 3);
        let binary_path = PathBuf::from("target/debug/bitcoin-frost");

        let mut controller = DkgProcessController::new(
            coordinator_id,
            config,
            binary_path,
        );

        // Add coordinator as a participant first
        let coordinator_participant = Participant::new(coordinator_id);
        controller.coordinator.add_participant(coordinator_participant).unwrap();

        // Add participants directly to the coordinator
        for i in 2..=3 {
            let participant_id = Identifier::try_from(i).unwrap();
            let participant = Participant::new(participant_id);
            controller.coordinator.add_participant(participant).unwrap();
        }

        // Start DKG
        controller.coordinator.start().unwrap();

        // Generate and process Round 1 packages
        for i in 1..=3 {
            let id = Identifier::try_from(i).unwrap();
            let package = controller.coordinator.generate_round1(id).unwrap();
            controller.coordinator.process_round1_package(id, package).unwrap();
        }

        // Generate and process Round 2 packages
        for i in 1..=3 {
            let id = Identifier::try_from(i).unwrap();
            let packages = controller.coordinator.generate_round2(id).unwrap();
            controller.coordinator.process_round2_package(id, packages).unwrap();
        }

        // Finalize DKG for all participants
        for i in 1..=3 {
            let id = Identifier::try_from(i).unwrap();
            controller.coordinator.finalize(id).unwrap();
        }

        // Verify we have key packages and they're all for the same group key
        let key_package1 = controller.coordinator.get_key_package(Identifier::try_from(1u16).unwrap()).unwrap();
        let key_package2 = controller.coordinator.get_key_package(Identifier::try_from(2u16).unwrap()).unwrap();
        let key_package3 = controller.coordinator.get_key_package(Identifier::try_from(3u16).unwrap()).unwrap();

        let pubkey1 = key_package1.verifying_key();
        let pubkey2 = key_package2.verifying_key();
        let pubkey3 = key_package3.verifying_key();

        assert_eq!(pubkey1, pubkey2);
        assert_eq!(pubkey2, pubkey3);
    }
}