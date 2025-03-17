use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{IpcMessage, Participant, SigningMessage, ThresholdConfig};
use crate::frost_dkg::frost::{FrostCoordinator, FrostParticipant};
use crate::ipc::{IpcServer, IpcClient, ProcessCoordinator};
use frost_secp256k1::{
    Identifier,
    Signature, SigningPackage,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout};
use std::net::SocketAddr;
use log::{debug, info, warn, error};

/// Timeout for signing operations in seconds
const SIGNING_TIMEOUT_SECONDS: u64 = 30;

/// Coordinator process controller - manages network communication for the protocol
/// The coordinator is a non-signing entity that facilitates message exchange between participants
pub struct CoordinatorController {
    /// Coordinator ID
    coordinator_id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// FROST coordinator for protocol coordination
    coordinator: FrostCoordinator,
    /// Process coordinator for managing subprocesses
    processes: ProcessCoordinator,
    /// IPC server for receiving messages from participants
    ipc_server: Option<IpcServer>,
    /// IPC clients for sending messages to participants
    ipc_clients: HashMap<Identifier, IpcClient>,
    /// Binary path for spawning participant processes
    binary_path: Option<PathBuf>,
    /// Current public key package for verification
    pub_key_package: Option<PublicKeyPackage>,
}

impl CoordinatorController {
    /// Create a new coordinator controller
    pub fn new(
        coordinator_id: Identifier,
        config: ThresholdConfig,
    ) -> Self {
        let coordinator = FrostCoordinator::new(config.clone());
        let processes = ProcessCoordinator::new();

        Self {
            coordinator_id,
            config,
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            binary_path: None,
            pub_key_package: None,
        }
    }

    /// Set the binary path for spawning participant processes
    pub fn set_binary_path(&mut self, path: PathBuf) {
        self.binary_path = Some(path);
    }

    /// Set the public key package for signature verification
    pub fn set_public_key_package(&mut self, pub_key_package: PublicKeyPackage) -> Result<()> {
        self.pub_key_package = Some(pub_key_package.clone());
        self.coordinator.set_public_key_package(pub_key_package);
        Ok(())
    }

    /// Start the IPC server for TCP communication
    pub async fn start_server(&mut self, port: u16) -> Result<()> {
        let server = IpcServer::new_localhost(self.coordinator_id, port).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    /// Connect to a remote participant
    pub async fn connect_to_participant(
        &mut self,
        participant_id: Identifier,
        addr: SocketAddr,
    ) -> Result<()> {
        let mut client = IpcClient::new(self.coordinator_id, participant_id);
        client.connect(addr).await?;

        // Add the participant to the coordinator's known participants
        self.coordinator.add_participant(Participant::new(participant_id));

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

        // Add the participant to the coordinator's known participants
        self.coordinator.add_participant(Participant::new(participant_id));

        Ok(())
    }

    /// Coordinate signing between participants - the coordinator only relays messages
    pub async fn coordinate_signing(
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

        debug!("Starting signing session with {} signers", signers.len());

        // 1. Start signing session in the coordinator
        self.coordinator.start_signing(message.clone())?;

        // 2. Initiate signing with all participants
        for &signer_id in &signers {
            debug!("Sending signing start to participant {:?}", signer_id);
            if let Some(client) = self.ipc_clients.get(&signer_id) {
                client.send(IpcMessage::Signing(SigningMessage::Start {
                    message: message.clone(),
                    signers: signers.clone(),
                })).await?;
            } else {
                return Err(FrostWalletError::IpcError(format!("No connection to participant {:?}", signer_id)));
            }
        }

        // 3. Collect commitments from participants (Round 1)
        let commitments = self.collect_commitments(&signers).await?;
        debug!("Collected all commitments: {:?}", commitments.keys());

        // 4. Create signing package
        let signing_package = self.coordinator.create_signing_package(&signers)?;
        debug!("Created signing package");

        // 5. Distribute signing package to participants
        let serialized_package = bincode::serialize(&signing_package)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize signing package: {}", e)))?;

        for &signer_id in &signers {
            debug!("Sending signing package to participant {:?}", signer_id);
            if let Some(client) = self.ipc_clients.get(&signer_id) {
                client.send(IpcMessage::Signing(SigningMessage::SigningPackage {
                    package: serialized_package.clone(),
                })).await?;
            }
        }

        // 6. Collect signature shares from participants (Round 2)
        let signature_shares = self.collect_signature_shares(&signers).await?;
        debug!("Collected all signature shares: {:?}", signature_shares.keys());

        // 7. Aggregate signature shares into final signature
        debug!("Aggregating signature shares");
        let signature = self.coordinator.aggregate_signature_shares(&signing_package, &signature_shares)?;

        // 8. Verify signature
        if let Some(pub_key_package) = &self.pub_key_package {
            debug!("Verifying signature");
            let verification_result = frost_secp256k1::VerifyingKey::verify(
                pub_key_package.verifying_key(),
                &message,
                &signature,
            );

            if verification_result.is_err() {
                return Err(FrostWalletError::VerificationError("Generated signature failed verification".to_string()));
            }
            debug!("Signature verified successfully");
        }

        // 9. Reset signing session
        self.coordinator.clear_signing_session();

        // 10. Send final signature to all participants (optional)
        let serialized_signature = bincode::serialize(&signature)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize signature: {}", e)))?;

        for &signer_id in &signers {
            if let Some(client) = self.ipc_clients.get(&signer_id) {
                client.send(IpcMessage::Signing(SigningMessage::FinalSignature {
                    signature: serialized_signature.clone(),
                })).await?;
            }
        }

        Ok(signature)
    }

    /// Collect commitments from participants (Round 1)
    async fn collect_commitments(
        &mut self,
        signers: &[Identifier],
    ) -> Result<BTreeMap<Identifier, SigningCommitments>> {
        let required_commitments = signers.len();
        let mut commitments_map = BTreeMap::new();

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(SIGNING_TIMEOUT_SECONDS);

        debug!("Waiting for {} commitments", required_commitments);

        // Collect commitments
        while commitments_map.len() < required_commitments {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError(
                    format!("Timed out waiting for commitments. Received {}/{}",
                            commitments_map.len(), required_commitments)
                ));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        debug!("Received message from {:?}: {:?}", sender_id, message);
                        if let IpcMessage::Signing(SigningMessage::Round1 { id, commitment }) = message {
                            // Verify the sender is a valid signer
                            if !signers.contains(&id) {
                                debug!("Ignoring commitment from non-signer: {:?}", id);
                                continue;
                            }

                            // Deserialize and store commitment
                            let deserialized_commitment: SigningCommitments = bincode::deserialize(&commitment)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize commitment: {}", e)))?;

                            debug!("Adding commitment from participant {:?}", id);
                            self.coordinator.add_commitment(id, deserialized_commitment.clone())?;
                            commitments_map.insert(id, deserialized_commitment);
                            debug!("Now have {}/{} commitments", commitments_map.len(), required_commitments);
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {}, // Timeout, continue
                }
            }

            sleep(Duration::from_millis(10)).await;
        }

        Ok(commitments_map)
    }

    /// Collect signature shares from participants (Round 2)
    async fn collect_signature_shares(
        &mut self,
        signers: &[Identifier],
    ) -> Result<BTreeMap<Identifier, SignatureShare>> {
        let required_shares = signers.len();
        let mut signature_shares = BTreeMap::new();

        let start_time = Instant::now();
        let timeout_duration = Duration::from_secs(SIGNING_TIMEOUT_SECONDS);

        debug!("Waiting for {} signature shares", required_shares);

        // Collect signature shares
        while signature_shares.len() < required_shares {
            if start_time.elapsed() > timeout_duration {
                return Err(FrostWalletError::TimeoutError(
                    format!("Timed out waiting for signature shares. Received {}/{}",
                            signature_shares.len(), required_shares)
                ));
            }

            // Process incoming messages
            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        debug!("Received message from {:?}: {:?}", sender_id, message);
                        if let IpcMessage::Signing(SigningMessage::Round2 { id, signature_share }) = message {
                            // Verify the sender is a valid signer
                            if !signers.contains(&id) {
                                debug!("Ignoring signature share from non-signer: {:?}", id);
                                continue;
                            }

                            // Deserialize signature share
                            let deserialized_share: SignatureShare = bincode::deserialize(&signature_share)
                                .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize signature share: {}", e)))?;

                            debug!("Adding signature share from participant {:?}", id);
                            signature_shares.insert(id, deserialized_share);
                            debug!("Now have {}/{} signature shares", signature_shares.len(), required_shares);
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

        Ok(())
    }

    /// Get server address for others to connect to
    pub fn get_server_addr(&self) -> Option<SocketAddr> {
        self.ipc_server.as_ref().map(|server| server.socket_addr())
    }
}

impl Drop for CoordinatorController {
    fn drop(&mut self) {
        // Try to clean up resources when dropped
        let _ = self.processes.terminate_all();
    }
}

/// Signing participant - handles cryptographic operations for signing
/// Each participant communicates only with the coordinator
pub struct SigningParticipant {
    /// Local participant ID
    local_id: Identifier,
    /// FROST participant for cryptographic operations
    frost_participant: FrostParticipant,
    /// IPC client for connection to the coordinator
    coordinator_client: Option<IpcClient>,
    /// Current message being signed
    current_message: Option<Vec<u8>>,
    /// Signers involved in the current signing session
    current_signers: Vec<Identifier>,
    /// Current signing nonces (round 1 secrets)
    current_nonces: Option<SigningNonces>,
}

impl SigningParticipant {
    /// Create a new signing participant
    pub fn new(
        local_id: Identifier,
        key_package: KeyPackage,
        pub_key_package: PublicKeyPackage
    ) -> Self {
        Self {
            local_id,
            frost_participant: FrostParticipant::new(local_id, key_package, pub_key_package),
            coordinator_client: None,
            current_message: None,
            current_signers: Vec::new(),
            current_nonces: None,
        }
    }

    /// Connect to the coordinator
    pub async fn connect_to_coordinator(
        &mut self,
        coordinator_id: Identifier,
        addr: SocketAddr
    ) -> Result<()> {
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(addr).await?;

        self.coordinator_client = Some(client);

        // Send handshake message to identify ourselves to the coordinator
        self.coordinator_client.as_ref().unwrap()
            .send(IpcMessage::Handshake(self.local_id)).await?;

        Ok(())
    }

    /// Run signing process, participating in threshold signatures as instructed by coordinator
    pub async fn run(&mut self) -> Result<()> {
        // Ensure we have a client, but don't hold the reference yet
        if self.coordinator_client.is_none() {
            return Err(FrostWalletError::InvalidState("Not connected to coordinator".to_string()));
        }

        info!("Participant {:?} starting", self.local_id);

        // Process signing requests in a loop
        loop {
            // Borrow client mutably only for the receive operation
            let message = {
                let client = self.coordinator_client.as_mut().unwrap(); // Safe due to prior check
                match client.receive().await {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Error receiving message: {:?}", e);
                        return Err(e);
                    }
                }
            };

            match message {
                IpcMessage::Signing(SigningMessage::Start { message, signers }) => {
                    info!("Received signing request for {} signers", signers.len());
                    debug!("Signers: {:?}", signers);

                    if !signers.contains(&self.local_id) {
                        debug!("I'm not a signer in this session, ignoring");
                        continue;
                    }

                    // Now we can safely modify self since no other mutable borrow exists
                    self.current_message = Some(message);
                    self.current_signers = signers;

                    // Generate commitment for Round 1
                    debug!("Generating commitment");
                    let (commitment, nonces) = self.frost_participant.generate_commitment()?;
                    self.current_nonces = Some(nonces);

                    // Serialize and send commitment to coordinator
                    let serialized_commitment = bincode::serialize(&commitment)
                        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize commitment: {}", e)))?;

                    debug!("Sending commitment to coordinator");
                    // Borrow client mutably again for sending
                    let client = self.coordinator_client.as_mut().unwrap();
                    client.send(IpcMessage::Signing(SigningMessage::Round1 {
                        id: self.local_id,
                        commitment: serialized_commitment,
                    })).await?;
                    debug!("Commitment sent successfully");
                },

                IpcMessage::Signing(SigningMessage::SigningPackage { package }) => {
                    info!("Received signing package from coordinator");

                    // Deserialize the signing package
                    let signing_package: SigningPackage = bincode::deserialize(&package)
                        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize signing package: {}", e)))?;

                    // Get nonces from Round 1
                    let nonces = self.current_nonces.as_ref()
                        .ok_or_else(|| FrostWalletError::InvalidState("No signing nonces available".to_string()))?;

                    // Generate signature share for Round 2
                    debug!("Generating signature share");
                    let signature_share = self.frost_participant.generate_signature_share(nonces, &signing_package)?;

                    // Serialize and send signature share to coordinator
                    let serialized_share = bincode::serialize(&signature_share)
                        .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize signature share: {}", e)))?;

                    debug!("Sending signature share to coordinator");
                    let client = self.coordinator_client.as_mut().unwrap();
                    client.send(IpcMessage::Signing(SigningMessage::Round2 {
                        id: self.local_id,
                        signature_share: serialized_share,
                    })).await?;
                    debug!("Signature share sent successfully");

                    self.reset_signing_state();
                },

                IpcMessage::Signing(SigningMessage::FinalSignature { signature }) => {
                    info!("Received final signature from coordinator");
                    // Optionally verify the signature here
                },

                IpcMessage::Handshake(id) => {
                    debug!("Received handshake from {:?}", id);
                },

                _ => {
                    warn!("Unexpected message type: {:?}", message);
                }
            }
        }
    }

    /// Reset signing state between sessions
    fn reset_signing_state(&mut self) {
        self.current_message = None;
        self.current_signers.clear();
        self.current_nonces = None;
    }
}

impl Drop for SigningParticipant {
    fn drop(&mut self) {
        // Clean up resources if needed
        self.reset_signing_state();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost_dkg::chilldkg::DkgCoordinator;
    use frost_secp256k1::VerifyingKey;
    use frost_secp256k1::keys::IdentifierList;
    use rand_core::OsRng;
    use tempfile::tempdir;

    // Helper function to generate test key packages
    fn generate_test_key_packages(threshold: u16, total: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
        let (secret_shares, pub_key_package) = frost_secp256k1::keys::generate_with_dealer(
            total,
            threshold,
            IdentifierList::Default,
            &mut OsRng,
        ).expect("Failed to generate key packages");

        let key_packages: BTreeMap<_, _> = secret_shares.into_iter()
            .map(|(id, ss)| {
                let key_package = KeyPackage::try_from(ss)
                    .map_err(|e| FrostWalletError::FrostError("Failed to convert to KeyPackage".to_string()))
                    .unwrap();
                (id, key_package)
            })
            .collect();

        (key_packages, pub_key_package)
    }

    #[tokio::test]
    async fn test_signing_coordinator_architecture() {
        // Set up logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant1_id = Identifier::try_from(2u16).unwrap();
        let participant2_id = Identifier::try_from(3u16).unwrap();

        let coordinator_port = 36000;

        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = CoordinatorController::new(coordinator_id, config.clone());
        coordinator.set_public_key_package(pub_key_package.clone()).unwrap();

        // Start server and get socket address
        coordinator.start_server(coordinator_port).await.unwrap();
        let coordinator_addr = coordinator.get_server_addr().unwrap();

        println!("Coordinator server started at {:?}", coordinator_addr);

        // Create participants with their key packages
        let mut participant1 = SigningParticipant::new(
            participant1_id,
            key_packages.get(&participant1_id).unwrap().clone(),
            pub_key_package.clone(),
        );

        let mut participant2 = SigningParticipant::new(
            participant2_id,
            key_packages.get(&participant2_id).unwrap().clone(),
            pub_key_package.clone(),
        );

        // Connect participants to coordinator
        participant1.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 1 connected to coordinator");

        participant2.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 2 connected to coordinator");

        // Give time for connections to be established
        sleep(Duration::from_millis(200)).await;

        // Connect coordinator to participants (so it can send messages to them)
        coordinator.connect_to_participant(participant1_id, coordinator_addr).await.unwrap();
        coordinator.connect_to_participant(participant2_id, coordinator_addr).await.unwrap();

        // Give more time for connections to be fully established
        sleep(Duration::from_millis(500)).await;

        println!("All connections established");

        // Start participant tasks
        let p1_handle = tokio::spawn(async move {
            participant1.run().await
        });

        let p2_handle = tokio::spawn(async move {
            participant2.run().await
        });

        // Give participants time to start their loops
        sleep(Duration::from_millis(500)).await;

        println!("Participants started, beginning signing process");

        // Create test message and signers list
        let message = b"Test message with coordinator architecture".to_vec();
        let signers = vec![participant1_id, participant2_id];

        // Coordinate signing process
        let signature = coordinator.coordinate_signing(message.clone(), signers).await.unwrap();

        println!("Signing completed, verifying signature");

        // Verify the signature
        let verification_result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            &message,
            &signature,
        );

        assert!(verification_result.is_ok(), "Signature verification failed");

        println!("Signature verified successfully!");

        // Clean up
        p1_handle.abort();
        p2_handle.abort();
        coordinator.cleanup().await.unwrap();
    }
}