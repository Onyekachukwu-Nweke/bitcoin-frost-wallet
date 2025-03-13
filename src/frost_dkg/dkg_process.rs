use tokio::sync::Mutex;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use std::collections::{BTreeMap, HashMap};
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

/// DKG process controller - coordinates DKG across multiple processes
pub struct DkgProcessController {
    /// Local participant ID
    local_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// DKG coordinator
    pub(crate) coordinator: DkgCoordinator,
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

    /// Run DKG with the local participan
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

        // Generate local Round 1 package
        let round1_package = self.coordinator.generate_round1(self.local_id)?;

        // Broadcast round1 package to all participants
        self.broadcast_message(IpcMessage::Dkg(
            DkgMessage::Commitment(self.local_id, bincode::serialize(&round1_package)?)
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

        // Generate Round 2 packages for this participant
        let round2_packages = self.coordinator.generate_round2(self.local_id)?;

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

        // Finalize DKG for the local participant
        let key_package = self.coordinator.finalize(self.local_id)?;

        // Get public key package
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
        println!("Message from participant {:?}: {:?}", sender_id, message);
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
                    DkgMessage::Commitment(participant_id, commitment_data) => {
                        // Deserialize commitment data
                        let round1_package = bincode::deserialize(&commitment_data)?;

                        // Process commitment
                        self.coordinator.process_round1_package(participant_id, round1_package)?;
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
        }
    }

    /// Connect to the coordinator
    pub async fn connect_to_coordinator(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let coordinator_id = Identifier::try_from(1u16).unwrap(); // Assuming coordinator has ID 1
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(socket_path).await?;
        self.client = Some(client);
        Ok(())
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
        loop {
            // Receive a message from the coordinator
            let message = client.receive().await?;

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
                    break;
                },
                _ => {
                    // Ignore other messages until we receive the DKG start
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
            match timeout(Duration::from_millis(200), client.receive()).await {
                Ok(Ok(message)) => {
                    match message {
                        IpcMessage::Dkg(dkg_message) => {
                            match dkg_message {
                                DkgMessage::Commitment(participant_id, commitment_data) => {
                                    // Process commitment if we're in Round 1
                                    let round1_package = bincode::deserialize(&commitment_data)?;
                                    self.coordinator.process_round1_package(participant_id, round1_package)?;
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

                                        // If we're now in Round 2, generate and send our Round 2 packages
                                        if matches!(self.coordinator.get_round_state(), DkgRoundState::Round2)
                                            && round_state != DkgRoundState::Round2 {
                                            round_state = DkgRoundState::Round2;

                                            // Generate Round 2 packages
                                            let round2_packages = self.coordinator.generate_round2(self.local_id)?;

                                            // Send each package to the coordinator (it will forward to the right participant)
                                            for (recipient_id, package) in &round2_packages {
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
                                    if matches!(self.coordinator.get_round_state(), DkgRoundState::Round3) {
                                        let key_package = self.coordinator.finalize(self.local_id)?;
                                        self.key_package = Some(key_package.clone());
                                        return Ok(key_package);
                                    }
                                },
                                _ => {
                                    // Ignore other DKG messages
                                }
                            }
                        },
                        _ => {
                            // Ignore non-DKG messages
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
                            let key_package = self.coordinator.finalize(self.local_id)?;
                            self.key_package = Some(key_package.clone());

                            // Send completion back to coordinator
                            client.send(IpcMessage::Dkg(DkgMessage::Finish)).await?;

                            return Ok(key_package);
                        },
                        _ => {
                            // Continue waiting
                        }
                    }
                }
            }
        }

        Err(FrostWalletError::TimeoutError("DKG process timed out".to_string()))
    }

    /// Get the key package
    pub fn get_key_package(&self) -> Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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

    #[tokio::test]
    async fn test_dkg_different_thresholds() {
        // Test with different threshold configurations to ensure correctness
        for (threshold, total) in [(2, 3), (3, 5), (4, 7)] {
            let coordinator_id = Identifier::try_from(1u16).unwrap();
            let config = ThresholdConfig::new(threshold, total);
            let binary_path = PathBuf::from("target/debug/bitcoin-frost");

            let mut controller = DkgProcessController::new(
                coordinator_id,
                config,
                binary_path,
            );

            // Add all participants including coordinator
            for i in 1..=total {
                let participant_id = Identifier::try_from(i).unwrap();
                let participant = Participant::new(participant_id);
                controller.coordinator.add_participant(participant).unwrap();
            }

            // Start DKG
            controller.coordinator.start().unwrap();

            // Generate and process Round 1 packages
            for i in 1..=total {
                let id = Identifier::try_from(i).unwrap();
                let package = controller.coordinator.generate_round1(id).unwrap();
                controller.coordinator.process_round1_package(id, package).unwrap();
            }

            // Generate and process Round 2 packages
            for i in 1..=total {
                let id = Identifier::try_from(i).unwrap();
                let packages = controller.coordinator.generate_round2(id).unwrap();
                controller.coordinator.process_round2_package(id, packages).unwrap();
            }

            // Finalize DKG for all participants
            let mut key_packages = Vec::new();
            for i in 1..=total {
                let id = Identifier::try_from(i).unwrap();
                let key_package = controller.coordinator.finalize(id).unwrap();
                key_packages.push(key_package);
            }

            // Verify all participants share the same group key
            let first_verifying_key = key_packages[0].verifying_key();
            for key_package in &key_packages[1..] {
                assert_eq!(first_verifying_key, key_package.verifying_key());
            }

            // Verify we get the same public key package from the coordinator
            let pub_key_package = controller.coordinator.get_public_key_package().unwrap();
            assert_eq!(first_verifying_key, pub_key_package.verifying_key());
        }
    }

    #[tokio::test]
    async fn test_dkg_message_handling() {
        // Create a temporary directory for the socket
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Create coordinator and participant IDs
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant_id = Identifier::try_from(2u16).unwrap();

        // Create coordinator controller
        let config = ThresholdConfig::new(2, 2);
        let binary_path = PathBuf::from("target/debug/bitcoin-frost");

        let mut controller = DkgProcessController::new(
            coordinator_id,
            config.clone(),
            binary_path,
        );

        // Start the coordinator's IPC server
        controller.start_server(&socket_path).await.unwrap();

        // Add coordinator as participant
        let coordinator_participant = Participant::new(coordinator_id);
        controller.coordinator.add_participant(coordinator_participant).unwrap();

        // Create participant process
        let mut participant = DkgParticipantProcess::new(participant_id);

        // Test handling of Start message
        let start_message = IpcMessage::Dkg(DkgMessage::Start(config.clone()));
        controller.handle_dkg_message(participant_id, start_message).await.unwrap();

        // Verify the participant was added
        assert!(controller.coordinator.get_participant(participant_id).is_some());

        // Generate a Round 1 package for the participant
        controller.coordinator.start().unwrap();
        let round1_package = controller.coordinator.generate_round1(coordinator_id).unwrap();

        // Serialize the Round 1 package
        let commitment_data = bincode::serialize(&round1_package).unwrap();

        // Test handling of Commitment message
        let commitment_message = IpcMessage::Dkg(DkgMessage::Commitment(
            coordinator_id, commitment_data
        ));

        // Test that we can handle our own commitment properly
        controller.handle_dkg_message(coordinator_id, commitment_message).await.unwrap();

        // Create a dummy Round 2 package for testing KeyShare message handling
        // In a real scenario, this would be generated properly based on Round 1 results
        // let mut dummy_round2_package: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> = BTreeMap::new();

        // Test handling of Finish message
        let finish_message = IpcMessage::Dkg(DkgMessage::Finish);
        controller.handle_dkg_message(participant_id, finish_message).await.unwrap();

        // Clean up
        if let Some(server) = &controller.ipc_server {
            let _ = server.cleanup();
        }
    }
}

