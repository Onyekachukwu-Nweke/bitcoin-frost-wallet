use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{IpcMessage, Participant, SigningMessage, ThresholdConfig};
use crate::frost_dkg::frost::FrostCoordinator;
use crate::ipc::{IpcServer, IpcClient, ProcessCoordinator};
use frost_secp256k1::{
    Identifier,
    Signature, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};

/// Timeout for signing operations in seconds
const SIGNING_TIMEOUT_SECONDS: u64 = 30;

/// Signing process controller - coordinates threshold signing across multiple processes
pub struct SigningProcessController {
    /// Local participant ID
    local_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// FROST coordinator
    coordinator: FrostCoordinator,
    /// Process coordinator
    processes: ProcessCoordinator,
    /// IPC server
    ipc_server: Option<IpcServer>,
    /// IPC clients
    ipc_clients: HashMap<Identifier, IpcClient>,
    /// Local key package
    key_package: Option<KeyPackage>,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// Path to participant binary
    binary_path: Option<PathBuf>,
}

impl SigningProcessController {
    /// Create a new signing process controller
    pub fn new(
        local_id: Identifier,
        config: ThresholdConfig,
    ) -> Self {
        let coordinator = FrostCoordinator::new(config.clone());
        let processes = ProcessCoordinator::new();

        Self {
            local_id,
            config,
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            key_package: None,
            pub_key_package: None,
            binary_path: None,
        }
    }

    /// Set the binary path for spawning participant processes
    pub fn set_binary_path(&mut self, path: PathBuf) {
        self.binary_path = Some(path);
    }

    /// Set the key package and public key package
    pub fn set_key_package(&mut self, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Result<()> {
        self.key_package = Some(key_package);
        self.pub_key_package = Some(pub_key_package.clone());
        self.coordinator.set_public_key_package(pub_key_package);
        Ok(())
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
        let binary_path = self.binary_path.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("Binary path not set".to_string()))?;

        let mut process = crate::ipc::process::ParticipantProcess::new(participant_id, binary_path);
        process.spawn(args).await?;
        self.processes.add_process(process);
        Ok(())
    }

    /// Sign a message using t-of-n threshold FROST signature
    pub async fn sign_message(
        &mut self,
        message: Vec<u8>,
        signers: Vec<Identifier>,
    ) -> Result<Signature> {
        // Verify we have enough signers
        if signers.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: signers.len() as u16,
            });
        }

        // Verify local participant is included
        if !signers.contains(&self.local_id) {
            return Err(FrostWalletError::InvalidState(
                "Local participant must be included in signers".to_string()
            ));
        }

        // Verify we have a key package
        if self.key_package.is_none() {
            return Err(FrostWalletError::InvalidState(
                "No key package available for signing".to_string()
            ));
        }

        // Start signing session
        self.coordinator.start_signing(message.clone())?;

        // Start signing with remote participants
        for signer_id in &signers {
            if *signer_id != self.local_id {
                if let Some(client) = self.ipc_clients.get(signer_id) {
                    client.send(IpcMessage::Signing(SigningMessage::Start {
                        message: message.clone(),
                        signers: signers.clone(),
                    })).await?;
                }
            }
        }

        // Run signing rounds
        let (commitments_map, nonces) = self.run_round1(&signers).await?;
        let signing_package = self.create_signing_package(commitments_map).await?;
        let signature_shares = self.run_round2(signing_package.clone(), nonces, &signers).await?;

        // Aggregate signature shares
        let signature = self.coordinator.aggregate_signatures(
            &signing_package,
            &signature_shares,
        )?;

        // Verify the signature
        let valid = self.coordinator.verify_signature(&message, &signature)?;

        if !valid {
            return Err(FrostWalletError::VerificationError(
                "Generated signature failed verification".to_string()
            ));
        }

        // Reset signing session
        self.coordinator.clear_signing_session();

        Ok(signature)
    }

    /// Run Round 1: Generate and collect commitments
    async fn run_round1(
        &mut self,
        signers: &[Identifier],
    ) -> Result<(BTreeMap<Identifier, SigningCommitments>, SigningNonces)> {
        // Generate local commitments
        let (commitments, nonces) = self.coordinator.generate_commitments(self.local_id)?;

        // Store local commitments
        self.coordinator.add_commitments(self.local_id, commitments.clone())?;

        // Broadcast commitments
        let serialized_commitments = bincode::serialize(&commitments)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize commitments: {}", e)))?;

        for &signer_id in signers {
            if signer_id != self.local_id {
                if let Some(client) = self.ipc_clients.get(&signer_id) {
                    client.send(IpcMessage::Signing(SigningMessage::Round1 {
                        id: self.local_id,
                        commitment: serialized_commitments.clone(),
                    })).await?;
                }
            }
        }

        // Collect commitments from other participants
        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(self.local_id, commitments);

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(SIGNING_TIMEOUT_SECONDS);

        while commitments_map.len() < signers.len() {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError(
                    "Timed out waiting for commitments".to_string()
                ));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        if let IpcMessage::Signing(SigningMessage::Round1 { id, commitment }) = message {
                            let deserialized_commitment = bincode::deserialize(&commitment)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize commitment: {}", e)))?;

                            commitments_map.insert(id, deserialized_commitment);
                            self.coordinator.add_commitments(id, *commitments_map.get(&id).unwrap())?;
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            sleep(Duration::from_millis(10)).await;
        }

        Ok((commitments_map, nonces))
    }

    /// Create signing package from collected commitments
    async fn create_signing_package(
        &mut self,
        commitments_map: BTreeMap<Identifier, SigningCommitments>,
    ) -> Result<SigningPackage> {
        Ok(self.coordinator.create_signing_package()?)
    }

    /// Run Round 2: Generate and collect signature shares
    async fn run_round2(
        &mut self,
        signing_package: SigningPackage,
        nonces: SigningNonces,
        signers: &[Identifier],
    ) -> Result<BTreeMap<Identifier, SignatureShare>> {
        // Generate local signature share
        let signature_share = self.coordinator.generate_signature_share(
            self.local_id,
            &nonces,
            &signing_package,
        )?;

        // Broadcast signature share
        let serialized_share = bincode::serialize(&signature_share)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize signature share: {}", e)))?;

        for &signer_id in signers {
            if signer_id != self.local_id {
                if let Some(client) = self.ipc_clients.get(&signer_id) {
                    client.send(IpcMessage::Signing(SigningMessage::Round2 {
                        id: self.local_id,
                        signature_share: serialized_share.clone(),
                    })).await?;
                }
            }
        }

        // Collect signature shares from other participants
        let mut signature_shares = BTreeMap::new();
        signature_shares.insert(self.local_id, signature_share);

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(SIGNING_TIMEOUT_SECONDS);

        while signature_shares.len() < signers.len() {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError(
                    "Timed out waiting for signature shares".to_string()
                ));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        if let IpcMessage::Signing(SigningMessage::Round2 { id, signature_share }) = message {
                            let deserialized_share = bincode::deserialize(&signature_share)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize signature share: {}", e)))?;

                            signature_shares.insert(id, deserialized_share);
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            sleep(Duration::from_millis(10)).await;
        }

        Ok(signature_shares)
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

impl Drop for SigningProcessController {
    fn drop(&mut self) {
        // Try to clean up resources when dropped
        let _ = self.processes.terminate_all();
    }
}

/// Signing participant process - runs on each participant
pub struct SigningParticipantProcess {
    /// Local participant ID
    local_id: Identifier,
    /// FROST coordinator
    coordinator: FrostCoordinator,
    /// IPC client for connection to coordinator
    coordinator_client: Option<IpcClient>,
    /// Local key package
    key_package: Option<KeyPackage>,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// IPC server for incoming connections
    ipc_server: Option<IpcServer>,
}

impl SigningParticipantProcess {
    /// Create a new signing participant process
    pub fn new(local_id: Identifier) -> Self {
        let config = ThresholdConfig::new(2, 3); // Default config
        let coordinator = FrostCoordinator::new(config);

        Self {
            local_id,
            coordinator,
            coordinator_client: None,
            key_package: None,
            pub_key_package: None,
            ipc_server: None,
        }
    }

    /// Set the key package and public key package
    pub fn set_key_package(&mut self, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Result<()> {
        self.key_package = Some(key_package);
        self.pub_key_package = Some(pub_key_package.clone());
        self.coordinator.set_public_key_package(pub_key_package);
        Ok(())
    }

    /// Start the IPC server for incoming connections
    pub async fn start_server(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let server = IpcServer::new(self.local_id, socket_path).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to the signing coordinator
    pub async fn connect_to_coordinator(&mut self, socket_path: impl AsRef<Path>) -> Result<()> {
        let coordinator_id = Identifier::try_from(1u16).unwrap(); // Assuming coordinator has ID 1
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(socket_path).await?;
        self.coordinator_client = Some(client);
        Ok(())
    }

    /// Wait for signing requests and process them
    pub async fn run(&mut self) -> Result<()> {
        let client = self.coordinator_client.as_mut()
            .ok_or_else(|| FrostWalletError::InvalidState("Not connected to coordinator".to_string()))?;

        // Verify we have a key package
        if self.key_package.is_none() {
            return Err(FrostWalletError::InvalidState("No key package available for signing".to_string()));
        }

        // Send handshake
        client.send(IpcMessage::Handshake(self.local_id)).await?;

        // Process signing requests
        loop {
            let message = client.receive().await?;

            match message {
                IpcMessage::Signing(SigningMessage::Start { message, signers }) => {
                    // Start a new signing session
                    self.coordinator.start_signing(message.clone())?;

                    // Generate our commitment
                    let (commitments, nonces) = self.coordinator.generate_commitments(self.local_id)?;

                    // Store local commitment
                    self.coordinator.add_commitments(self.local_id, commitments.clone())?;

                    // Send commitment to coordinator
                    let serialized_commitments = bincode::serialize(&commitments)
                        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize commitments: {}", e)))?;

                    client.send(IpcMessage::Signing(SigningMessage::Round1 {
                        id: self.local_id,
                        commitment: serialized_commitments,
                    })).await?;

                    // Wait for all commitments to be shared via Round1 messages from other signers
                    let mut received_commitments = BTreeMap::new();
                    received_commitments.insert(self.local_id, commitments);

                    for _ in 1..signers.len() {
                        let message = client.receive().await?;

                        if let IpcMessage::Signing(SigningMessage::Round1 { id, commitment }) = message {
                            let deserialized_commitment = bincode::deserialize(&commitment)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize commitment: {}", e)))?;

                            received_commitments.insert(id, deserialized_commitment);
                            self.coordinator.add_commitments(id, *received_commitments.get(&id).unwrap())?;
                        }
                    }

                    // Create signing package
                    let signing_package = self.coordinator.create_signing_package()?;

                    // Generate signature share
                    let signature_share = self.coordinator.generate_signature_share(
                        self.local_id,
                        &nonces,
                        &signing_package,
                    )?;

                    // Send signature share
                    let serialized_share = bincode::serialize(&signature_share)
                        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize signature share: {}", e)))?;

                    client.send(IpcMessage::Signing(SigningMessage::Round2 {
                        id: self.local_id,
                        signature_share: serialized_share,
                    })).await?;

                    // Reset signing session
                    self.coordinator.clear_signing_session();
                },
                _ => {
                    log::warn!("Unexpected message type: {:?}", message);
                }
            }
        }
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

impl Drop for SigningParticipantProcess {
    fn drop(&mut self) {
        // Try to clean up resources when dropped
        if let Some(server) = &self.ipc_server {
            let _ = server.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_dkg::{chilldkg::DkgCoordinator, frost::FrostSigner};
    use frost_secp256k1::VerifyingKey;
    use tempfile::tempdir;

    // Helper function to generate test key packages
    fn generate_test_key_packages(threshold: u16, total: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
        // Create a DKG coordinator
        let config = ThresholdConfig::new(threshold, total);
        let mut coordinator = DkgCoordinator::new(config.clone());

        // Add participants
        for i in 1..=total {
            let participant_id = Identifier::try_from(i).unwrap();
            let participant = Participant::new(participant_id);
            coordinator.add_participant(participant).unwrap();
        }

        // Start DKG
        coordinator.start().unwrap();

        // Execute DKG
        for i in 1..=total {
            let id = Identifier::try_from(i).unwrap();
            let package = coordinator.generate_round1(id).unwrap();
            coordinator.process_round1_package(id, package).unwrap();
        }

        for i in 1..=total {
            let id = Identifier::try_from(i).unwrap();
            let packages = coordinator.generate_round2(id).unwrap();
            coordinator.process_round2_package(id, packages).unwrap();
        }

        // Get key packages
        let mut key_packages = BTreeMap::new();
        for i in 1..=total {
            let id = Identifier::try_from(i).unwrap();
            let key_package = coordinator.finalize(id).unwrap();
            key_packages.insert(id, key_package);
        }

        // Get public key package
        let pub_key_package = coordinator.get_public_key_package().unwrap();

        (key_packages, pub_key_package)
    }

    #[tokio::test]
    async fn test_signing_single_process() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create coordinator ID and participant IDs
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant_ids = vec![
            coordinator_id,
            Identifier::try_from(2u16).unwrap(),
        ];

        // Create signing controller
        let config = ThresholdConfig::new(2, 3);
        let mut controller = SigningProcessController::new(coordinator_id, config);

        // Set key packages
        controller.set_key_package(
            key_packages.get(&coordinator_id).unwrap().clone(),
            pub_key_package.clone(),
        ).unwrap();

        // Add coordinator to its own participant list first
        let coordinator_participant = Participant::with_key_package(
            coordinator_id,
            key_packages.get(&coordinator_id).unwrap().clone(),
        );
        controller.coordinator.add_participant(coordinator_participant);

        // Add participants directly to the coordinator
        for &id in &participant_ids {
            if id != coordinator_id {
                let participant = Participant::with_key_package(
                    id,
                    key_packages.get(&id).unwrap().clone(),
                );
                controller.coordinator.add_participant(participant);
            }
        }

        // Create a message to sign
        let message = b"Test message".to_vec();

        controller.coordinator.start_signing(message.clone()).unwrap();

        // Mock signature shares for participants other than coordinator
        // In a real scenario, these would come from the participant processes
        let result = tokio::task::spawn_blocking(move || {
            // Simulate signing process by manually creating commitments
            let (commitments, nonces) = controller.coordinator.generate_commitments(coordinator_id).unwrap();
            controller.coordinator.add_commitments(coordinator_id, commitments.clone()).unwrap();

            // Add commitments for other participants
            for &id in &participant_ids {
                if id != coordinator_id {
                    let (other_commitments, _) = controller.coordinator.generate_commitments(id).unwrap();
                    controller.coordinator.add_commitments(id, other_commitments).unwrap();
                }
            }

            // Create signing package
            let signing_package = controller.coordinator.create_signing_package().unwrap();

            // Generate signature share for coordinator
            let signature_share = controller.coordinator.generate_signature_share(
                coordinator_id,
                &nonces,
                &signing_package,
            ).unwrap();

            // Generate signature shares for other participants
            let mut signature_shares = BTreeMap::new();
            signature_shares.insert(coordinator_id, signature_share);

            for &id in &participant_ids {
                if id != coordinator_id {
                    // In a real scenario, these would come from the participants
                    let key_package = key_packages.get(&id).unwrap();

                    // Generate nonces for this participant
                    let (other_commitment, other_nonces) = controller.coordinator.generate_commitments(id).unwrap();

                    // Generate signature share
                    let other_share = controller.coordinator.generate_signature_share(
                        id,
                        &other_nonces,
                        &signing_package,
                    ).unwrap();

                    signature_shares.insert(id, other_share);
                }
            }

            // Aggregate signature shares
            let signature = controller.coordinator.aggregate_signatures(
                &signing_package,
                &signature_shares,
            ).unwrap();

            // Verify signature
            let valid = controller.coordinator.verify_signature(&message, &signature).unwrap();
            assert!(valid, "Generated signature failed verification");

            valid
        }).await.unwrap();

        // Verify we got a valid signature
        assert!(result, "true");
    }

//     #[tokio::test]
//     async fn test_signing_controller_process() {
//         // Generate key packages
//         let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
//
//         // Create temporary directory for socket
//         let dir = tempdir().unwrap();
//         let coordinator_socket = dir.path().join("coordinator.sock");
//         let participant_socket = dir.path().join("participant.sock");
//
//         // Create coordinator and participant IDs
//         let coordinator_id = Identifier::try_from(1u16).unwrap();
//         let participant_id = Identifier::try_from(2u16).unwrap();
//
//         // Create signing controller
//         let config = ThresholdConfig::new(2, 3);
//         let mut controller = SigningProcessController::new(coordinator_id, config);
//
//         // Set key packages
//         controller.set_key_package(
//             key_packages.get(&coordinator_id).unwrap().clone(),
//             pub_key_package.clone(),
//         ).unwrap();
//
//         // Start the coordinator's IPC server
//         controller.start_server(&coordinator_socket).await.unwrap();
//
//         // Create participant process
//         let mut participant = SigningParticipantProcess::new(participant_id);
//
//         // Set participant key package
//         participant.set_key_package(
//             key_packages.get(&participant_id).unwrap().clone(),
//             pub_key_package.clone(),
//         ).unwrap();
//
//         // Start participant server
//         participant.start_server(&participant_socket).await.unwrap();
//
//         // Connect participant to coordinator
//         participant.connect_to_coordinator(&coordinator_socket).await.unwrap();
//
//         // Connect coordinator to participant
//         controller.connect_to_participant(participant_id, &participant_socket).await.unwrap();
//
//         // Add participant to coordinator's list
//         let participant_obj = Participant::with_key_package(
//             participant_id,
//             key_packages.get(&participant_id).unwrap().clone(),
//         );
//         controller.coordinator.add_participant(participant_obj);
//
//         // Now let's run a signing session in the background
//         let message = b"Test message".to_vec();
//         let participant_clone = participant;
//
//         // Spawn participant process to handle signing requests
//         let participant_handle = tokio::spawn(async move {
//             // This simulates what the participant would do
//             // In a real scenario, this would be a separate process
//             let client = participant_clone.coordinator_client.as_ref().unwrap();
//
//             // Wait for signing request
//             let msg = client.receive().await.unwrap();
//
//             if let IpcMessage::Signing(SigningMessage::Start { message, signers }) = msg {
//                 // Start signing session
//                 participant_clone.coordinator.start_signing(message.clone()).unwrap();
//
//                 // Generate commitment
//                 let (commitments, nonces) = participant_clone.coordinator.generate_commitments(participant_id).unwrap();
//
//                 // Add commitment locally
//                 participant_clone.coordinator.add_commitments(participant_id, commitments.clone()).unwrap();
//
//                 // Send commitment to coordinator
//                 let serialized = bincode::serialize(&commitments).unwrap();
//                 client.send(IpcMessage::Signing(SigningMessage::Round1 {
//                     id: participant_id,
//                     commitment: serialized,
//                 })).await.unwrap();
//
//                 // Wait for coordinator's commitment
//                 let msg = client.receive().await.unwrap();
//
//                 if let IpcMessage::Signing(SigningMessage::Round1 { id, commitment }) = msg {
//                     // Deserialize coordinator's commitment
//                     let coordinator_commitments: SigningCommitments = bincode::deserialize(&commitment).unwrap();
//
//                     // Add coordinator's commitment
//                     participant_clone.coordinator.add_commitments(id, coordinator_commitments).unwrap();
//
//                     // Create signing package
//                     let signing_package = participant_clone.coordinator.create_signing_package().unwrap();
//
//                     // Generate signature share
//                     let signature_share = participant_clone.coordinator.generate_signature_share(
//                         participant_id,
//                         &nonces,
//                         &signing_package,
//                     ).unwrap();
//
//                     // Send signature share to coordinator
//                     let serialized = bincode::serialize(&signature_share).unwrap();
//                     client.send(IpcMessage::Signing(SigningMessage::Round2 {
//                         id: participant_id,
//                         signature_share: serialized,
//                     })).await.unwrap();
//                 }
//             }
//         });
//
//         // Now have the coordinator run a signing session
//         let signers = vec![coordinator_id, participant_id];
//         let signature = controller.sign_message(message.clone(), signers).await;
//
//         // Await the participant process to complete
//         let _ = tokio::time::timeout(Duration::from_secs(5), participant_handle).await;
//
//         // Verify we got a valid signature
//         assert!(signature.is_ok());
//
//         // Verify signature against the original message
//         let result = controller.coordinator.verify_signature(&message, &signature.unwrap()).unwrap();
//         assert!(result, "Signature verification failed");
//
//         // Clean up
//         controller.cleanup().await.unwrap();
//     }
//
//     #[tokio::test]
//     #[ignore] // Requires binary to be built first - run with: cargo test -- --ignored
//     async fn test_multi_process_signing() {
//         // This test simulates a real multi-process signing session with spawned processes
//
//         // Create a temporary directory for socket and key files
//         let dir = tempdir().unwrap();
//         let coordinator_socket = dir.path().join("coordinator.sock");
//         let key_dir = dir.path().join("keys");
//         std::fs::create_dir_all(&key_dir).unwrap();
//
//         // Generate key packages
//         let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
//
//         // Set up coordinator
//         let coordinator_id = Identifier::try_from(1u16).unwrap();
//         let config = ThresholdConfig::new(2, 3);
//
//         // Find the path to the binary
//         let current_exe = std::env::current_exe().unwrap();
//         let binary_dir = current_exe.parent().unwrap();
//         let binary_path = binary_dir.join("bitcoin-frost-wallet");
//
//         // Make sure the binary exists
//         if !binary_path.exists() {
//             println!("Binary not found at {:?}, skipping test", binary_path);
//             return;
//         }
//
//         // Create signing controller
//         let mut controller = SigningProcessController::new(coordinator_id, config);
//         controller.set_binary_path(binary_path.clone());
//
//         // Set coordinator key package
//         controller.set_key_package(
//             key_packages.get(&coordinator_id).unwrap().clone(),
//             pub_key_package.clone(),
//         ).unwrap();
//
//         // Start the coordinator's IPC server
//         controller.start_server(&coordinator_socket).await.unwrap();
//
//         // Save key packages to files for participants to load
//         for (id, key_package) in &key_packages {
//             let key_file = key_dir.join(format!("key_{}.json", id.0));
//             let serialized = serde_json::to_string_pretty(&key_package).unwrap();
//             std::fs::write(&key_file, serialized).unwrap();
//         }
//
//         // Save public key package
//         let pub_key_file = key_dir.join("pubkey.json");
//         let serialized = serde_json::to_string_pretty(&pub_key_package).unwrap();
//         std::fs::write(&pub_key_file, serialized).unwrap();
//
//         // Spawn participant processes
//         let mut participant_processes = Vec::new();
//
//         for i in 2..=3 {
//             let participant_id = Identifier::try_from(i).unwrap();
//             let participant_socket = dir.path().join(format!("participant_{}.sock", i));
//
//             // Build arguments for participant process
//             let args = vec![
//                 "--id".to_string(), i.to_string(),
//                 "--mode".to_string(), "signing-participant".to_string(),
//                 "--coordinator-socket".to_string(), coordinator_socket.to_string_lossy().to_string(),
//                 "--socket".to_string(), participant_socket.to_string_lossy().to_string(),
//                 "--key-file".to_string(), key_dir.join(format!("key_{}.json", i)).to_string_lossy().to_string(),
//                 "--pubkey-file".to_string(), pub_key_file.to_string_lossy().to_string(),
//             ];
//
//             // Spawn the participant process
//             controller.spawn_participant(participant_id, args).await.unwrap();
//
//             // Add participant to signing session
//             let participant = Participant::with_key_package(
//                 participant_id,
//                 key_packages.get(&participant_id).unwrap().clone(),
//             );
//             controller.coordinator.add_participant(participant);
//
//             // Wait for the socket to appear
//             let timeout_duration = Duration::from_secs(5);
//             let start_time = Instant::now();
//
//             while !participant_socket.exists() && start_time.elapsed() < timeout_duration {
//                 sleep(Duration::from_millis(100)).await;
//             }
//
//             if participant_socket.exists() {
//                 // Try connecting to the participant
//                 match controller.connect_to_participant(participant_id, &participant_socket).await {
//                     Ok(_) => {
//                         println!("Connected to participant {}", i);
//                         participant_processes.push(participant_id);
//                     },
//                     Err(e) => {
//                         println!("Failed to connect to participant {}: {}", i, e);
//                     }
//                 }
//             } else {
//                 println!("Participant socket did not appear in time: {:?}", participant_socket);
//             }
//         }
//
//         // Only continue if we connected to at least one participant
//         if !participant_processes.is_empty() {
//             // Create a message to sign
//             let message = b"This is a multi-process signing test".to_vec();
//
//             // Select signers (coordinator + one participant)
//             let mut signers = vec![coordinator_id];
//             signers.push(participant_processes[0]);
//
//             // Sign the message
//             match tokio::time::timeout(
//                 Duration::from_secs(30),
//                 controller.sign_message(message.clone(), signers)
//             ).await {
//                 Ok(result) => match result {
//                     Ok(signature) => {
//                         println!("Signing completed successfully");
//
//                         // Verify the signature
//                         let valid = controller.coordinator.verify_signature(&message, &signature).unwrap();
//                         assert!(valid, "Generated signature failed verification");
//                     },
//                     Err(e) => {
//                         println!("Signing failed: {}", e);
//                         assert!(false, "Signing failed: {}", e);
//                     }
//                 },
//                 Err(_) => {
//                     println!("Signing timed out");
//                     assert!(false, "Signing timed out");
//                 }
//             }
//         } else {
//             println!("No participants connected, skipping actual signing test");
//         }
//
//         // Clean up
//         controller.cleanup().await.unwrap();
//     }
//
//     #[tokio::test]
//     async fn test_signing_threshold_validation() {
//         // Generate key packages
//         let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
//
//         // Create coordinator
//         let coordinator_id = Identifier::try_from(1u16).unwrap();
//         let config = ThresholdConfig::new(2, 3);
//         let mut controller = SigningProcessController::new(coordinator_id, config);
//
//         // Set key packages
//         controller.set_key_package(
//             key_packages.get(&coordinator_id).unwrap().clone(),
//             pub_key_package.clone(),
//         ).unwrap();
//
//         // Try to sign with too few signers (only coordinator)
//         let message = b"Test message".to_vec();
//         let signers = vec![coordinator_id];  // Only one signer
//
//         let result = controller.sign_message(message, signers).await;
//
//         // Verify we get the expected error
//         assert!(result.is_err());
//         match result {
//             Err(FrostWalletError::NotEnoughSigners { required, provided }) => {
//                 assert_eq!(required, 2);
//                 assert_eq!(provided, 1);
//             },
//             _ => panic!("Expected NotEnoughSigners error"),
//         }
//     }
//
//     #[tokio::test]
//     async fn test_frost_signing_validation() {
//         // Test message
//         let message = b"Test message".to_vec();
//
//         // Generate key packages
//         let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
//
//         // Create a signing controller
//         let coordinator_id = Identifier::try_from(1u16).unwrap();
//         let config = ThresholdConfig::new(2, 3);
//         let mut controller = SigningProcessController::new(coordinator_id, config);
//
//         // Set key packages
//         controller.set_key_package(
//             key_packages.get(&coordinator_id).unwrap().clone(),
//             pub_key_package.clone(),
//         ).unwrap();
//
//         // Test FROST signing directly using the FrostSigner utility
//         let signers = vec![
//             Identifier::try_from(1u16).unwrap(),
//             Identifier::try_from(2u16).unwrap(),
//         ];
//
//         let signature = FrostSigner::sign_message(
//             &key_packages,
//             &pub_key_package,
//             &message,
//             &signers,
//         ).unwrap();
//
//         // Verify the signature
//         let verifying_key = pub_key_package.verifying_key();
//
//         let valid = VerifyingKey::verify(
//             verifying_key,
//             &message,
//             &signature,
//         ).is_ok();
//
//         assert!(valid, "FROST signature validation failed");
//     }
}