use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use frost_secp256k1::{
    Identifier,
    keys::{dkg::round1, dkg::round2, KeyPackage, PublicKeyPackage},
};
use tokio::time::{sleep, timeout};

use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{DkgMessage, IpcMessage, Participant, ProcessState, ThresholdConfig};
use crate::frost_dkg::chilldkg::{DkgCoordinator, DkgParticipant, DkgRoundState};
use crate::ipc::communication::{IpcClient, IpcServer};
use crate::ipc::process::{ParticipantProcess, ProcessCoordinator};

/// Timeout for DKG operations in seconds
const DKG_TIMEOUT_SECONDS: u64 = 120;

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
    pub async fn start_server(&mut self) -> Result<()> {
        let server = IpcServer::new_localhost(self.local_id, self.server_addr.port()).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to a remote participant
    pub async fn connect_to_participant(&mut self, participant_id: Identifier, addr: SocketAddr) -> Result<()> {
        let mut client = IpcClient::new(self.local_id, participant_id);
        client.connect(addr).await?;
        self.ipc_clients.insert(participant_id, client);
        Ok(())
    }

    /// Spawn a new participant process
    pub async fn spawn_participant(&mut self, participant_id: Identifier, args: Vec<String>) -> Result<()> {
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
    pub fn add_participant(&mut self, participant: Participant) -> Result<()> {
        // Ensure the coordinator never adds itself as a participant
        if participant.id == self.local_id {
            return Err(FrostWalletError::InvalidState(
                "Coordinator cannot be added as a participant in DKG".to_string()
            ));
        }
        self.coordinator.add_participant(participant)
    }

    /// Run the complete DKG protocol as coordinator
    pub async fn run_dkg(&mut self) -> Result<PublicKeyPackage> {
        log::info!("Starting DKG protocol as coordinator");

        // Initialize DKG state tracking (coordinator doesn't participate)
        self.coordinator.start()?;

        // Wait for all participants to connect
        // Note: The coordinator is NOT counted as a participant
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
        self.run_round3().await?;

        // Get public key package from the state tracker
        let pub_key_package = self.coordinator.get_public_key_package()?;

        log::info!("DKG protocol completed successfully.");
        Ok(pub_key_package)
    }

    /// Run Round 1: Collect commitments from all participants
    async fn run_round1(&mut self) -> Result<()> {
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

    /// Run Round 2: Exchange encrypted key shares
    async fn run_round2(&mut self) -> Result<()> {
        log::info!("Coordinator: Starting Round 2");

        // Wait for all participants to complete Round 2
        let start_time = Instant::now();

        while self.coordinator.get_round_state() != &DkgRoundState::Round3 {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 2 completion".to_string()));
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

        log::info!("Coordinator: Round 2 completed, received all key shares");
        Ok(())
    }

    /// Run Round 3: Collect public key packages
    async fn run_round3(&mut self) -> Result<()> {
        log::info!("Coordinator: Starting Round 3");

        // Notify participants that all key shares have been exchanged
        self.broadcast_message(IpcMessage::Dkg(DkgMessage::Finish)).await?;

        // Wait for all participants to submit their public key packages
        let start_time = Instant::now();

        while self.coordinator.get_round_state() != &DkgRoundState::Complete {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for public key packages".to_string()));
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

        log::info!("Coordinator: Round 3 completed, DKG protocol finished");
        Ok(())
    }

    /// Handle a DKG message from a participant
    async fn handle_dkg_message(&mut self, sender_id: Identifier, message: IpcMessage) -> Result<()> {
        match message {
            IpcMessage::Dkg(dkg_message) => {
                match dkg_message {
                    DkgMessage::Start(config) => {
                        // Usually only coordinator sends this, but handle it anyway
                        log::info!("Received Start message from participant {:?}", sender_id);

                        // Verify config matches ours
                        if config.threshold != self.config.threshold ||
                            config.total_participants != self.config.total_participants {
                            return Err(FrostWalletError::InvalidThresholdParams(
                                "Mismatched threshold parameters".to_string()
                            ));
                        }
                    },
                    DkgMessage::Commitment(participant_id, commitment_data) => {
                        log::info!("Received Round 1 commitment from participant {:?}", participant_id);

                        // Deserialize and process the commitment
                        let round1_package: round1::Package = bincode::deserialize(&commitment_data)?;
                        self.coordinator.process_round1_package(participant_id, round1_package)?;

                        // If we're in Round 2, we need to forward all Round 1 packages to all participants
                        if self.coordinator.get_round_state() == &DkgRoundState::Round2 {
                            log::info!("All Round 1 commitments received, notifying participants");

                            // Forward each commitment to all participants
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

                        // Deserialize the key share
                        let round2_package: round2::Package = bincode::deserialize(&key_share_data)?;

                        // Store in coordinator (for monitoring only, not for actual use)
                        self.coordinator.process_round2_package(from_id, to_id, round2_package.clone())?;

                        // Forward the key share to the intended recipient
                        if let Some(client) = self.ipc_clients.get(&to_id) {
                            client.send(IpcMessage::Dkg(
                                DkgMessage::KeyShare(from_id, to_id, key_share_data)
                            )).await?;
                        }

                        // Check if this completes Round 2
                        if self.coordinator.get_round_state() == &DkgRoundState::Round3 {
                            log::info!("All Round 2 key shares exchanged, moving to Round 3");
                        }
                    },
                    DkgMessage::Finish => {
                        // A participant has finished DKG and is submitting their public key package
                        log::info!("Participant {:?} has completed DKG", sender_id);

                        // Update our state tracker to mark this participant as finished
                        // This is purely for coordinator bookkeeping
                        // if let Some(pub_key_package) = self.coordinator.pub_key_package.clone() {
                        //     self.coordinator.process_public_key_package(sender_id, pub_key_package)?;
                        // }
                    }
                }
            },
            IpcMessage::Handshake(id) => {
                log::info!("Received handshake from participant {:?}", id);

                // Verify the ID matches what we expect
                if id != sender_id {
                    return Err(FrostWalletError::VerificationError(
                        format!("Handshake ID mismatch: expected {:?}, got {:?}", sender_id, id)
                    ));
                }

                // Add the participant if not already present
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
    async fn send_message(&self, participant_id: Identifier, message: IpcMessage) -> Result<()> {
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

    /// Clean up resources
    pub async fn cleanup(&mut self) -> Result<()> {
        // Terminate all spawned processes
        self.processes.terminate_all().await?;
        Ok(())
    }
}

/// Participant in the DKG protocol - performs cryptographic operations
pub struct DkgParticipantProcess {
    /// Local participant ID
    local_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// DKG participant - handles cryptographic operations
    participant: DkgParticipant,
    /// Connection to the coordinator
    coordinator_client: Option<IpcClient>,
    /// Received round 1 packages from other participants
    round1_packages: BTreeMap<Identifier, round1::Package>,
    /// Received round 2 packages intended for this participant
    round2_packages: BTreeMap<Identifier, round2::Package>,
    /// Final key package after DKG completion
    key_package: Option<KeyPackage>,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// Current round state
    round_state: DkgRoundState,
}

impl DkgParticipantProcess {
    /// Create a new DKG participant process
    pub fn new(local_id: Identifier, config: ThresholdConfig) -> Self {
        Self {
            local_id,
            config: config.clone(),
            participant: DkgParticipant::new(local_id, config),
            coordinator_client: None,
            round1_packages: BTreeMap::new(),
            round2_packages: BTreeMap::new(),
            key_package: None,
            pub_key_package: None,
            round_state: DkgRoundState::Round1,
        }
    }

    /// Connect to the coordinator
    pub async fn connect_to_coordinator(&mut self, addr: SocketAddr) -> Result<()> {
        let coordinator_id = Identifier::try_from(1u16).unwrap(); // Coordinator ID is typically 1
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(addr).await?;
        self.coordinator_client = Some(client);
        Ok(())
    }

    /// Run the DKG protocol as a participant
    pub async fn run_dkg(&mut self) -> Result<KeyPackage> {
        log::info!("Starting DKG protocol as participant {:?}", self.local_id);

        let client = self.coordinator_client.as_mut()
            .ok_or_else(|| FrostWalletError::InvalidState("Not connected to coordinator".to_string()))?;

        // Send handshake to coordinator
        client.send(IpcMessage::Handshake(self.local_id)).await?;

        // Wait for start message from coordinator
        let start_time = Instant::now();
        let mut dkg_started = false;

        while !dkg_started {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for DKG start".to_string()));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    if let IpcMessage::Dkg(DkgMessage::Start(config)) = message {
                        log::info!("Received DKG start from coordinator with config: {:?}", config);

                        // Verify config matches ours
                        if config.threshold != self.config.threshold ||
                            config.total_participants != self.config.total_participants {
                            return Err(FrostWalletError::InvalidThresholdParams(
                                "Mismatched threshold parameters".to_string()
                            ));
                        }

                        dkg_started = true;
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {}, // Timeout, continue
            }

            sleep(Duration::from_millis(10)).await;
        }

        // Generate and send Round 1 package (commitment)
        self.round_state = DkgRoundState::Round1;
        let round1_package = self.participant.generate_round1()?;

        // Store our own package
        self.round1_packages.insert(self.local_id, round1_package.clone());

        // Send to coordinator
        client.send(IpcMessage::Dkg(
            DkgMessage::Commitment(self.local_id, bincode::serialize(&round1_package)?)
        )).await?;

        log::info!("Sent Round 1 commitment to coordinator");

        // Wait for all commitments from other participants via coordinator
        let start_time = Instant::now();
        while self.round1_packages.len() < self.config.total_participants as usize {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 1 commitments".to_string()));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    if let IpcMessage::Dkg(DkgMessage::Commitment(id, commitment_data)) = message {
                        if id != self.local_id { // Skip our own commitments
                            let round1_package: round1::Package = bincode::deserialize(&commitment_data)?;
                            self.round1_packages.insert(id, round1_package);
                            log::info!("Received Round 1 commitment from participant {:?}", id);
                        }
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {}, // Timeout, continue
            }

            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Received all Round 1 commitments, moving to Round 2");
        self.round_state = DkgRoundState::Round2;

        // Generate Round 2 packages (key shares)
        let round2_packages = self.participant.generate_round2(&self.round1_packages)?;

        // Send each key share to its intended recipient via the coordinator
        for (recipient_id, package) in &round2_packages {
            client.send(IpcMessage::Dkg(
                DkgMessage::KeyShare(self.local_id, *recipient_id, bincode::serialize(package)?)
            )).await?;
            log::info!("Sent Round 2 key share to participant {:?}", recipient_id);
        }

        // Wait for key shares from other participants
        let start_time = Instant::now();
        let expected_shares = self.config.total_participants as usize - 1; // Exclude self

        while self.round2_packages.len() < expected_shares {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 2 key shares".to_string()));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    if let IpcMessage::Dkg(DkgMessage::KeyShare(from_id, to_id, key_share_data)) = message {
                        if to_id == self.local_id && from_id != self.local_id {
                            let round2_package: round2::Package = bincode::deserialize(&key_share_data)?;
                            self.round2_packages.insert(from_id, round2_package);
                            log::info!("Received Round 2 key share from participant {:?}", from_id);
                        }
                    } else if let IpcMessage::Dkg(DkgMessage::Finish) = message {
                        log::info!("Received finish message from coordinator");
                        break; // Coordinator indicates all shares have been exchanged
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {}, // Timeout, continue
            }

            sleep(Duration::from_millis(10)).await;
        }

        log::info!("Received necessary Round 2 key shares, finalizing DKG");
        self.round_state = DkgRoundState::Round3;

        // Finalize DKG and create key package
        let (key_package, public_key_package) = self.participant.finalize(
            &self.round1_packages,
            &self.round2_packages
        )?;

        // Store key materials
        self.key_package = Some(key_package.clone());
        self.pub_key_package = Some(public_key_package.clone());

        // Notify coordinator we're done
        client.send(IpcMessage::Dkg(DkgMessage::Finish)).await?;

        log::info!("DKG protocol completed successfully");
        self.round_state = DkgRoundState::Complete;

        Ok(key_package)
    }

    /// Wait for key shares from other participants
    async fn receive_round2_packages(&mut self, client: &mut IpcClient) -> Result<()> {
        let start_time = Instant::now();

        // Calculate expected number of shares
        // We should receive one package from each other participant
        let expected_shares = self.config.total_participants as usize - 1; // Exclude self

        log::info!("Waiting for {} Round 2 key shares from other participants", expected_shares);

        // Create a set to track which participants we've received packages from
        let mut received_from: std::collections::HashSet<Identifier> = std::collections::HashSet::new();

        // Loop until we receive enough packages or timeout
        while received_from.len() < expected_shares {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(
                    format!("Timeout waiting for Round 2 key shares. Got {}/{} expected shares.",
                            received_from.len(), expected_shares)
                ));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    if let IpcMessage::Dkg(DkgMessage::KeyShare(from_id, to_id, key_share_data)) = message {
                        if to_id == self.local_id && from_id != self.local_id {
                            let round2_package: round2::Package = bincode::deserialize(&key_share_data)?;
                            self.round2_packages.insert(from_id, round2_package);
                            received_from.insert(from_id);
                            log::info!("Received Round 2 key share from participant {:?} ({}/{})",
                                      from_id, received_from.len(), expected_shares);
                        }
                    } else if let IpcMessage::Dkg(DkgMessage::Finish) = message {
                        log::info!("Received finish message from coordinator");
                        // Only break if we have received enough packages
                        if received_from.len() >= expected_shares {
                            log::info!("All Round 2 packages received, proceeding to finalization");
                            break;
                        } else {
                            log::warn!("Received finish message but only have {}/{} packages, continuing to wait",
                                     received_from.len(), expected_shares);
                        }
                    }
                },
                Ok(Err(e)) => return Err(e),
                Err(_) => {}, // Timeout, continue
            }

            sleep(Duration::from_millis(10)).await;
        }

        // Verify we have the right number of packages
        if received_from.len() < expected_shares {
            return Err(FrostWalletError::DkgError(
                format!("Failed to receive all Round 2 key shares. Got {}/{}",
                        received_from.len(), expected_shares)
            ));
        }

        Ok(())
    }

    /// Get the key package
    pub fn get_key_package(&self) -> Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> Result<PublicKeyPackage> {
        self.pub_key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_dkg_coordinator_and_participants() {
        // Use different port for each test to avoid conflicts
        let port = 35000;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create coordinator and participants
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant1_id = Identifier::try_from(2u16).unwrap();
        let participant2_id = Identifier::try_from(3u16).unwrap();
        let participant3_id = Identifier::try_from(4u16).unwrap();

        // Create a 2-of-3 threshold configuration
        // Note: This is for 3 actual participants, the coordinator is NOT a participant
        let config = ThresholdConfig::new(2, 3);

        // Initialize coordinator
        let mut coordinator = DkgProcessController::new(coordinator_id, config.clone(), port);
        coordinator.start_server().await.unwrap();

        // Initialize participants
        let mut participant1 = DkgParticipantProcess::new(participant1_id, config.clone());
        let mut participant2 = DkgParticipantProcess::new(participant2_id, config.clone());
        let mut participant3 = DkgParticipantProcess::new(participant3_id, config.clone());

        // Register participants with coordinator (for tracking only)
        // Note: The coordinator does NOT add itself as a participant
        coordinator.add_participant(Participant::new(participant1_id)).unwrap();
        coordinator.add_participant(Participant::new(participant2_id)).unwrap();
        coordinator.add_participant(Participant::new(participant3_id)).unwrap();

        // Connect participants to coordinator
        participant1.connect_to_coordinator(server_addr).await.unwrap();
        participant2.connect_to_coordinator(server_addr).await.unwrap();
        participant3.connect_to_coordinator(server_addr).await.unwrap();

        // Wait for connections to be established
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run participants in separate tasks
        let participant1_task = tokio::spawn(async move {
            participant1.run_dkg().await.unwrap()
        });

        let participant2_task = tokio::spawn(async move {
            participant2.run_dkg().await.unwrap()
        });

        let participant3_task = tokio::spawn(async move {
            participant3.run_dkg().await.unwrap()
        });

        // Run coordinator (which only facilitates communication)
        let pub_key_package = coordinator.run_dkg().await.unwrap();

        // Wait for participants to complete
        let key_package1 = participant1_task.await.unwrap();
        let key_package2 = participant2_task.await.unwrap();
        let key_package3 = participant3_task.await.unwrap();

        // Verify that all participants derived the same public key
        assert_eq!(key_package1.verifying_key(), key_package2.verifying_key());
        assert_eq!(key_package2.verifying_key(), key_package3.verifying_key());
        assert_eq!(key_package3.verifying_key(), pub_key_package.verifying_key());

        // Clean up
        coordinator.cleanup().await.unwrap();
    }

    #[tokio::test]
    async fn test_dkg_with_different_threshold() {
        // Use different port for each test to avoid conflicts
        let port = 35001;
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        // Create a 3-of-5 threshold configuration for this test
        // Note: This means 5 actual participants, not including the coordinator
        let config = ThresholdConfig::new(3, 5);

        // Initialize coordinator (not a participant)
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let mut coordinator = DkgProcessController::new(coordinator_id, config.clone(), port);
        coordinator.start_server().await.unwrap();

        // Initialize 5 participants (coordinator is NOT counted as a participant)
        let mut participants = Vec::new();
        let mut participant_tasks = Vec::new();

        for i in 2..=6 { // Creating 5 participants with IDs 2-6
            let id = Identifier::try_from(i).unwrap();
            let mut participant = DkgParticipantProcess::new(id, config.clone());

            // Connect to coordinator
            participant.connect_to_coordinator(server_addr).await.unwrap();

            // Add to coordinator's list (for tracking only)
            coordinator.add_participant(Participant::new(id)).unwrap();

            participants.push(participant);
        }

        // Wait for connections to be established
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start participant processes in separate tasks
        for mut participant in participants {
            let task = tokio::spawn(async move {
                participant.run_dkg().await.unwrap()
            });
            participant_tasks.push(task);
        }

        // Run coordinator (only facilitates communication)
        let pub_key_package = coordinator.run_dkg().await.unwrap();

        // Wait for all participants to complete
        let mut key_packages = Vec::new();
        for task in participant_tasks {
            key_packages.push(task.await.unwrap());
        }

        // Verify all participants derived the same public key
        let first_key = &key_packages[0].verifying_key();
        for key_package in &key_packages {
            assert_eq!(key_package.verifying_key(), *first_key);
        }
        assert_eq!(*first_key, pub_key_package.verifying_key());

        // Clean up
        coordinator.cleanup().await.unwrap();
    }
}