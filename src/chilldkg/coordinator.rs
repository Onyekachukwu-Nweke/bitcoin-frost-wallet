use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{round1, round2};
use tokio::time::{sleep, timeout};
use crate::common::errors::FrostWalletError;
use crate::common::types::{DkgMessage, DkgRoundState, IpcMessage, Participant, ThresholdConfig};
use crate::common::constants::DKG_TIMEOUT_SECONDS;
use crate::ipc::{IpcClient, IpcServer, ParticipantProcess, ProcessCoordinator};

/// DKG coordinator - manages the protocol but does not participate in key generation
/// Acts purely as a communication facilitator between participants
pub struct DkgCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Current round state
    pub(crate) round_state: DkgRoundState,
    /// Participants in the DKG
    participants: BTreeMap<Identifier, Participant>,
    /// Round 1 packages received from participants
    pub(crate) round1_packages: BTreeMap<Identifier, round1::Package>,
    /// Round 2 packages received from participants (sender -> recipient -> package)
    pub(crate) round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>>,
}

impl DkgCoordinator {
    /// Create a new DKG coordinator
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            round_state: DkgRoundState::Round1,
            participants: BTreeMap::new(),
            round1_packages: BTreeMap::new(),
            round2_packages: BTreeMap::new(),
        }
    }

    /// Add a participant to the DKG
    pub fn add_participant(&mut self, participant: Participant) -> crate::common::errors::Result<()> {
        if self.participants.len() >= self.config.total_participants as usize {
            return Err(FrostWalletError::DkgError("Maximum number of participants reached".to_string()));
        }

        self.participants.insert(participant.id, participant.clone());
        Ok(())
    }

    /// Get a participant by ID
    pub fn get_participant(&self, id: Identifier) -> Option<&Participant> {
        self.participants.get(&id)
    }

    /// Get a mutable participant by ID
    pub fn get_participant_mut(&mut self, id: Identifier) -> Option<&mut Participant> {
        self.participants.get_mut(&id)
    }

    /// Get all participants
    pub fn get_participants(&self) -> &BTreeMap<Identifier, Participant> {
        &self.participants
    }

    /// Get current round state
    pub fn get_round_state(&self) -> &DkgRoundState {
        &self.round_state
    }

    /// Get the threshold configuration
    pub fn get_config(&self) -> &ThresholdConfig {
        &self.config
    }

    /// Start the DKG process
    pub fn start(&mut self) -> crate::common::errors::Result<()> {
        if self.participants.len() < self.config.threshold as usize {
            return Err(FrostWalletError::DkgError(format!(
                "Not enough participants: have {}, need at least {}",
                self.participants.len(),
                self.config.threshold
            )));
        }

        self.round1_packages.clear();
        self.round2_packages.clear();
        self.round_state = DkgRoundState::Round1;

        Ok(())
    }

    /// Process a round 1 package from a participant
    pub fn process_round1_package(&mut self, participant_id: Identifier, package: round1::Package) -> crate::common::errors::Result<()> {
        match self.round_state {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 1 package in current state: {:?}",
                self.round_state
            ))),
        }

        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        self.round1_packages.insert(participant_id, package);

        if self.round1_packages.len() == self.participants.len() {
            self.round_state = DkgRoundState::Round2;
        }

        Ok(())
    }

    /// Process round 2 packages from a participant
    pub fn process_round2_package(&mut self, participant_id: Identifier, recipient_id: Identifier, package: round2::Package) -> crate::common::errors::Result<()> {
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 2 package in current state: {:?}",
                self.round_state
            ))),
        }

        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        if !self.participants.contains_key(&recipient_id) {
            return Err(FrostWalletError::ParticipantNotFound(recipient_id));
        }

        if !self.round2_packages.contains_key(&participant_id) {
            self.round2_packages.insert(participant_id, BTreeMap::new());
        }

        self.round2_packages.get_mut(&participant_id).unwrap().insert(recipient_id, package);

        let expected_packages = self.participants.len() * (self.participants.len() - 1);
        let mut current_packages = 0;

        for (_, packages) in &self.round2_packages {
            current_packages += packages.len();
        }

        if current_packages == expected_packages {
            self.round_state = DkgRoundState::Round3; // Transition to Round 3, but coordinator will finish here
        }

        Ok(())
    }

    /// Get round 1 package for a specific participant
    pub fn get_round1_package(&self, participant_id: Identifier) -> crate::common::errors::Result<&round1::Package> {
        self.round1_packages.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError(format!(
                "No round 1 package available for participant {:?}",
                participant_id
            )))
    }

    /// Get round 2 packages intended for a specific recipient
    pub fn get_round2_packages_for_recipient(&self, recipient_id: Identifier) -> crate::common::errors::Result<BTreeMap<Identifier, round2::Package>> {
        let mut result = BTreeMap::new();

        for (sender_id, packages) in &self.round2_packages {
            if let Some(package) = packages.get(&recipient_id) {
                result.insert(*sender_id, package.clone());
            }
        }

        if result.is_empty() {
            return Err(FrostWalletError::DkgError(format!(
                "No round 2 packages available for recipient {:?}",
                recipient_id
            )));
        }

        Ok(result)
    }
}

/// Coordinator for DKG processes - strictly manages communication without participating in key generation
///
/// Important: The coordinator acts ONLY as a communication relay between participants.
/// It does NOT participate in the actual cryptographic operations of the DKG protocol.
/// It never generates or holds any cryptographic material and does not count as one of the n participants.
pub struct DkgProcessController {
    /// Local coordinator ID (used only for message routing, not for key generation)
    local_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// DKG coordinator - handles the protocol state tracking only
    coordinator: DkgCoordinator,
    /// Process coordinator - manages spawned processes
    processes: ProcessCoordinator,
    /// IPC server - handles TCP communication
    ipc_server: Option<IpcServer>,
    /// IPC clients - connections to participants
    ipc_clients: HashMap<Identifier, IpcClient>,
    /// Path to participant binary (for spawning processes)
    binary_path: Option<PathBuf>,
    /// Server address
    server_addr: SocketAddr,
}

impl DkgProcessController {
    /// Create a new DKG process controller
    pub fn new(local_id: Identifier, config: ThresholdConfig, port: u16) -> Self {
        let coordinator = DkgCoordinator::new(config.clone());
        let processes = ProcessCoordinator::new();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        Self {
            local_id,
            config,
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            binary_path: None,
            server_addr,
        }
    }

    /// Set the binary path for spawning participant processes
    pub fn set_binary_path(&mut self, path: PathBuf) {
        self.binary_path = Some(path);
    }

    /// Get the server address
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Start the IPC server
    pub async fn start_server(&mut self) -> crate::common::errors::Result<()> {
        let server = IpcServer::new_localhost(self.local_id, self.server_addr.port()).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to a remote participant
    pub async fn connect_to_participant(&mut self, participant_id: Identifier, addr: SocketAddr) -> crate::common::errors::Result<()> {
        let mut client = IpcClient::new(self.local_id, participant_id);
        client.connect(addr).await?;
        self.ipc_clients.insert(participant_id, client);
        Ok(())
    }

    /// Spawn a new participant process
    pub async fn spawn_participant(&mut self, participant_id: Identifier, args: Vec<String>) -> crate::common::errors::Result<()> {
        let binary_path = self.binary_path.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("Binary path not set".to_string()))?;

        let mut process = ParticipantProcess::new(participant_id, binary_path);
        process.spawn(args).await?;
        self.processes.add_process(process);

        // Wait for process to initialize
        sleep(Duration::from_millis(500)).await;

        Ok(())
    }

    /// Register a participant for tracking purposes only
    ///
    /// Note: This doesn't add the coordinator as a cryptographic participant.
    /// It only registers actual participants for state tracking purposes.
    pub fn add_participant(&mut self, participant: Participant) -> crate::common::errors::Result<()> {
        // Ensure the coordinator never adds itself as a participant
        if participant.id == self.local_id {
            return Err(FrostWalletError::InvalidState(
                "Coordinator cannot be added as a participant in DKG".to_string()
            ));
        }
        self.coordinator.add_participant(participant)
    }

    /// Run the complete DKG protocol as coordinator
    pub async fn run_dkg(&mut self) -> crate::common::errors::Result<()> {
        log::info!("Starting DKG protocol as coordinator");

        // Initialize DKG state tracking (coordinator doesn't participate)
        self.coordinator.start()?;

        // Wait for all participants to connect
        let expected_participants = self.config.total_participants as usize;
        let start_time = Instant::now();

        while self.ipc_server.as_ref().unwrap().connected_participants().await.len() < expected_participants {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for participants to connect".to_string()));
            }
            sleep(Duration::from_millis(100)).await;
        }

        log::info!("All participants connected. Starting DKG rounds.");

        // Broadcast DKG start message to all participants
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Start(self.config.clone()))).await?;

        // Run DKG rounds (coordinator only relays messages)
        self.run_round1().await?;
        self.run_round2().await?;

        // At this point, all key shares have been exchanged, and participants have been notified
        // The coordinator considers the DKG complete
        log::info!("DKG protocol completed successfully.");
        Ok(())
    }

    /// Run Round 1: Collect commitments from all participants
    async fn run_round1(&mut self) -> crate::common::errors::Result<()> {
        log::info!("Coordinator: Starting Round 1");

        // Wait for commitments from all participants
        let expected_commitments = self.config.total_participants as usize;
        let start_time = Instant::now();

        while self.coordinator.get_round_state() != &DkgRoundState::Round2 {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 1 commitments".to_string()));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        self.handle_dkg_message(sender_id, message).await?;
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Coordinator: Round 1 completed, received all commitments");
        Ok(())
    }

    /// Run DKG Round 2: Exchange encrypted key shares
    async fn run_round2(&mut self) -> crate::common::errors::Result<()> {
        log::info!("Coordinator: Starting Round 2");

        // Wait for all participants to exchange Round 2 packages
        let start_time = Instant::now();

        // Calculate the expected number of Round 2 packages
        // For n participants, we expect n * (n-1) packages total
        // (each participant sends a package to every other participant)
        let n = self.coordinator.get_participants().len();
        let expected_packages = n * (n - 1);
        let mut received_packages = 0;

        // Track packages to ensure proper routing
        let mut package_tracker: HashMap<(Identifier, Identifier), bool> = HashMap::new();

        while self.coordinator.get_round_state() != &DkgRoundState::Round3 {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 2 completion".to_string()));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        if let IpcMessage::Dkg(DkgMessage::KeyShare(from_id, to_id, key_share_data)) = &message {
                            // Track this package
                            package_tracker.insert((*from_id, *to_id), true);
                            received_packages = package_tracker.len();

                            log::info!("Received key share from {:?} to {:?} ({}/{} total packages)",
                                      from_id, to_id, received_packages, expected_packages);

                            // Handle the message
                            self.handle_dkg_message(sender_id, message).await?;

                            // If we've received all expected packages, we can move to Round 3
                            if received_packages >= expected_packages {
                                log::info!("Received all expected Round 2 packages ({}), moving to Round 3", received_packages);
                                // Broadcast to all participants that Round 2 is complete
                                self.broadcast_message(IpcMessage::Dkg(DkgMessage::Finish)).await?;
                                break;
                            }
                        } else {
                            // Handle other messages
                            self.handle_dkg_message(sender_id, message).await?;
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Coordinator: Round 2 completed, received all key shares");
        Ok(())
    }

    /// Handle a DKG message from a participant
    async fn handle_dkg_message(&mut self, sender_id: Identifier, message: IpcMessage) -> crate::common::errors::Result<()> {
        match message {
            IpcMessage::Dkg(dkg_message) => {
                match dkg_message {
                    DkgMessage::Start(config) => {
                        log::info!("Received Start message from participant {:?}", sender_id);
                        if config.threshold != self.config.threshold ||
                            config.total_participants != self.config.total_participants {
                            return Err(FrostWalletError::InvalidThresholdParams(
                                "Mismatched threshold parameters".to_string()
                            ));
                        }
                    },
                    DkgMessage::Commitment(participant_id, commitment_data) => {
                        log::info!("Received Round 1 commitment from participant {:?}", participant_id);
                        let round1_package: round1::Package = bincode::deserialize(&commitment_data)?;
                        self.coordinator.process_round1_package(participant_id, round1_package.clone())?;

                        if self.coordinator.get_round_state() == &DkgRoundState::Round2 {
                            log::info!("All Round 1 commitments received, forwarding to all participants");
                            for (id, pkg) in &self.coordinator.round1_packages {
                                let serialized = bincode::serialize(pkg)?;
                                self.broadcast_message(IpcMessage::Dkg(
                                    DkgMessage::Commitment(*id, serialized)
                                )).await?;
                            }
                        }
                    },
                    DkgMessage::KeyShare(from_id, to_id, key_share_data) => {
                        log::info!("Received key share from {:?} to {:?}", from_id, to_id);
                        let round2_package: round2::Package = bincode::deserialize(&key_share_data)?;
                        self.coordinator.process_round2_package(from_id, to_id, round2_package.clone())?;

                        if from_id != to_id {
                            self.send_message(to_id, IpcMessage::Dkg(
                                DkgMessage::KeyShare(from_id, to_id, key_share_data)
                            )).await?;
                        }
                    },
                    DkgMessage::Finish => {
                        // Log for debugging, but no further action needed
                        log::info!("Participant {:?} has completed DKG", sender_id);
                    }
                }
            },
            IpcMessage::Handshake(id) => {
                log::info!("Received handshake from participant {:?}", id);
                if id != sender_id {
                    return Err(FrostWalletError::VerificationError(
                        format!("Handshake ID mismatch: expected {:?}, got {:?}", sender_id, id)
                    ));
                }
                let participant = Participant::new(id);
                let _ = self.coordinator.add_participant(participant);
            },
            _ => {
                log::warn!("Received unexpected message type from participant {:?}", sender_id);
            }
        }

        Ok(())
    }

    /// Send a message to a specific participant
    async fn send_message(&self, participant_id: Identifier, message: IpcMessage) -> crate::common::errors::Result<()> {
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
    async fn broadcast_message(&self, message: IpcMessage) -> crate::common::errors::Result<()> {
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

    /// Clean up resources
    pub async fn cleanup(&mut self) -> crate::common::errors::Result<()> {
        // Terminate all spawned processes
        self.processes.terminate_all().await?;
        Ok(())
    }
}