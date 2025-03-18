use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{IpcMessage, Participant, SigningMessage, ThresholdConfig};
use frost_secp256k1::{
    Identifier, SigningPackage, VerifyingKey, Signature,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand_core::OsRng;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use log::{debug, info};
use tokio::time::{sleep, timeout};
use crate::ipc::{IpcClient, IpcServer, ProcessCoordinator};

/// FROST Coordinator - A non-signing entity that facilitates the threshold signing protocol
/// The coordinator handles communication flow and aggregates results without having signing capability
pub struct FrostCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Participants in the signing session
    participants: HashMap<Identifier, Participant>,
    /// Current round commitments (Round 1)
    commitments: Option<BTreeMap<Identifier, SigningCommitments>>,
    /// Current message being signed
    message: Option<Vec<u8>>,
    /// Public key package for verification
    pub_key_package: Option<PublicKeyPackage>,
}

impl FrostCoordinator {
    /// Create a new FROST coordinator for signing
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            participants: HashMap::new(),
            commitments: None,
            message: None,
            pub_key_package: None,
        }
    }

    /// Set the public key package for signature verification
    pub fn set_public_key_package(&mut self, pkg: PublicKeyPackage) {
        self.pub_key_package = Some(pkg);
    }

    /// Add a participant
    pub fn add_participant(&mut self, participant: Participant) {
        self.participants.insert(participant.id, participant);
    }

    /// Get a participant by ID
    pub fn get_participant(&self, id: Identifier) -> Option<&Participant> {
        self.participants.get(&id)
    }

    /// Get all participants
    pub fn get_participants(&self) -> &HashMap<Identifier, Participant> {
        &self.participants
    }

    /// Get the count of commitments in the current signing session
    pub fn get_commitments_count(&self) -> usize {
        match &self.commitments {
            Some(commitments) => commitments.len(),
            None => 0,
        }
    }

    /// Start a new signing session
    /// This is called by the coordinator to initiate a signing session with a specific message
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<()> {
        // Ensure we have enough participants to meet the threshold
        if self.participants.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: self.participants.len() as u16,
            });
        }

        // Initialize commitments collection and store message
        self.commitments = Some(BTreeMap::new());
        self.message = Some(message);
        Ok(())
    }

    /// Add a commitment from a participant (Round 1)
    /// Called when the coordinator receives a commitment from a participant
    pub fn add_commitment(&mut self, participant_id: Identifier, commitment: SigningCommitments) -> Result<()> {
        // Ensure the participant is registered
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Store the commitment
        if let Some(commitments_map) = &mut self.commitments {
            commitments_map.insert(participant_id, commitment);
            Ok(())
        } else {
            Err(FrostWalletError::InvalidState("No signing session in progress".to_string()))
        }
    }

    /// Check if all required commitments have been received
    pub fn has_all_commitments(&self, required_signers: &[Identifier]) -> bool {
        if let Some(commitments) = &self.commitments {
            required_signers.iter().all(|id| commitments.contains_key(id))
        } else {
            false
        }
    }

    /// Create a signing package for Round 2
    /// Called after all required commitments have been collected
    pub fn create_signing_package(&self, signers: &[Identifier]) -> Result<SigningPackage> {
        // Ensure we have commitments and a message
        let commitments = self.commitments.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No commitments available".to_string()))?;

        let message = self.message.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No message to sign".to_string()))?;

        // Filter commitments to only include the specified signers
        let filtered_commitments: BTreeMap<_, _> = commitments.iter()
            .filter(|(id, _)| signers.contains(id))
            .map(|(id, commitment)| (*id, commitment.clone()))
            .collect();

        // Ensure we have enough signers
        if filtered_commitments.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: filtered_commitments.len() as u16,
            });
        }

        // Create signing package
        Ok(SigningPackage::new(filtered_commitments, message))
    }

    /// Aggregate signature shares into a complete signature (coordinator's final step)
    /// Called after all signature shares have been collected
    pub fn aggregate_signature_shares(
        &self,
        signing_package: &SigningPackage,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<Signature> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package available for verification".to_string()))?;

        // Aggregate the signature shares
        let signature = frost_secp256k1::aggregate(
            signing_package,
            signature_shares,
            pub_key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature)
    }

    /// Verify a signature (optional step for the coordinator)
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package available for verification".to_string()))?;

        // Verify the signature
        let result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            message,
            signature,
        ).map(|()| true)
            .unwrap_or(false);

        Ok(result)
    }

    /// Clear the current signing session
    /// Called to reset the coordinator state after signing completes
    pub fn clear_signing_session(&mut self) {
        self.commitments = None;
        self.message = None;
    }
}

/// Coordinator process controller - manages network communication for signing
pub struct CoordinatorController {
    coordinator_id: Identifier,
    config: ThresholdConfig,
    coordinator: FrostCoordinator,
    processes: ProcessCoordinator,
    ipc_server: Option<IpcServer>,
    ipc_clients: HashMap<Identifier, IpcClient>,
    binary_path: Option<PathBuf>,
    pub_key_package: Option<PublicKeyPackage>,
    server_addr: SocketAddr,
    round_state: crate::frost::tests::SigningRoundState,
}

impl CoordinatorController {
    pub fn new(coordinator_id: Identifier, config: ThresholdConfig, port: u16) -> Self {
        let coordinator = FrostCoordinator::new(config.clone());
        let processes = ProcessCoordinator::new();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        Self {
            coordinator_id,
            config,
            coordinator,
            processes,
            ipc_server: None,
            ipc_clients: HashMap::new(),
            binary_path: None,
            pub_key_package: None,
            server_addr,
            round_state: crate::frost::tests::SigningRoundState::WaitingForParticipants,
        }
    }

    pub fn set_binary_path(&mut self, path: PathBuf) {
        self.binary_path = Some(path);
    }

    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub fn set_public_key_package(&mut self, pub_key_package: PublicKeyPackage) -> Result<()> {
        self.pub_key_package = Some(pub_key_package.clone());
        self.coordinator.set_public_key_package(pub_key_package);
        Ok(())
    }

    pub async fn start_server(&mut self) -> Result<()> {
        let server = IpcServer::new_localhost(self.coordinator_id, self.server_addr.port()).await?;
        server.start().await?;
        self.ipc_server = Some(server);
        Ok(())
    }

    pub async fn connect_to_participant(&mut self, participant_id: Identifier, addr: SocketAddr) -> Result<()> {
        let mut client = IpcClient::new(self.coordinator_id, participant_id);
        client.connect(addr).await?;
        self.coordinator.add_participant(Participant::new(participant_id));
        self.ipc_clients.insert(participant_id, client);
        Ok(())
    }

    pub async fn spawn_participant(&mut self, participant_id: Identifier, args: Vec<String>) -> Result<()> {
        let binary_path = self.binary_path.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("Binary path not set".to_string()))?;
        let mut process = crate::ipc::process::ParticipantProcess::new(participant_id, binary_path);
        process.spawn(args).await?;
        self.processes.add_process(process);
        sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    pub async fn coordinate_signing(&mut self, message: Vec<u8>, signers: Vec<Identifier>) -> Result<Signature> {
        info!("Starting signing protocol as coordinator with {} signers", signers.len());

        // Verify we have enough signers
        if signers.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: signers.len() as u16,
            });
        }

        // Wait for all signers to connect
        let start_time = Instant::now();
        while self.ipc_clients.len() < signers.len() {
            if start_time.elapsed() > Duration::from_secs(crate::frost::tests::SIGNING_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(format!(
                    "Timeout waiting for participants to connect. Connected {}/{}",
                    self.ipc_clients.len(), signers.len()
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }

        self.round_state = crate::frost::tests::SigningRoundState::Round1;
        self.coordinator.start_signing(message.clone())?;

        // Broadcast start message
        self.broadcast_message(IpcMessage::Signing(SigningMessage::Start {
            message: message.clone(),
            signers: signers.clone(),
        })).await?;

        // Round 1: Collect commitments
        let commitments = self.run_round1(&signers).await?;
        debug!("Collected all commitments: {:?}", commitments.keys());

        // Round 2: Distribute signing package and collect shares
        let (signing_package, signature_shares) = self.run_round2(&signers).await?;
        debug!("Collected all signature shares: {:?}", signature_shares.keys());

        // Aggregate and finalize
        let signature = self.coordinator.aggregate_signature_shares(&signing_package, &signature_shares)?;
        info!("Signature aggregated successfully");

        // Verify signature
        if let Some(pub_key_package) = &self.pub_key_package {
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

        // Send final signature to participants
        let serialized_signature = bincode::serialize(&signature)?;
        self.broadcast_message(IpcMessage::Signing(SigningMessage::FinalSignature {
            signature: serialized_signature,
        })).await?;

        self.round_state = crate::frost::tests::SigningRoundState::Complete;
        self.coordinator.clear_signing_session();

        Ok(signature)
    }

    async fn run_round1(&mut self, signers: &[Identifier]) -> Result<BTreeMap<Identifier, SigningCommitments>> {
        info!("Coordinator: Starting Round 1");
        let expected_commitments = signers.len();
        let mut commitments_map = BTreeMap::new();
        let start_time = Instant::now();

        while commitments_map.len() < expected_commitments {
            if start_time.elapsed() > Duration::from_secs(crate::frost::tests::SIGNING_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(format!(
                    "Timed out waiting for commitments. Received {}/{}",
                    commitments_map.len(), expected_commitments
                )));
            }

            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        debug!("Received message from {:?}: {:?}", sender_id, message);
                        if let IpcMessage::Signing(SigningMessage::Round1 { id, commitment }) = message {
                            if !signers.contains(&id) {
                                debug!("Ignoring commitment from non-signer: {:?}", id);
                                continue;
                            }
                            let deserialized_commitment: SigningCommitments = bincode::deserialize(&commitment)?;
                            self.coordinator.add_commitment(id, deserialized_commitment.clone())?;
                            commitments_map.insert(id, deserialized_commitment);
                            info!("Received commitment from {:?} ({}/{})", id, commitments_map.len(), expected_commitments);
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {},
                }
            }
            sleep(Duration::from_millis(10)).await;
        }

        info!("Coordinator: Round 1 completed, received all commitments");
        self.round_state = crate::frost::tests::SigningRoundState::Round2;
        Ok(commitments_map)
    }

    async fn run_round2(&mut self, signers: &[Identifier]) -> Result<(SigningPackage, BTreeMap<Identifier, SignatureShare>)> {
        info!("Coordinator: Starting Round 2");
        let signing_package = self.coordinator.create_signing_package(signers)?;
        let serialized_package = bincode::serialize(&signing_package)?;

        // Broadcast signing package
        self.broadcast_message(IpcMessage::Signing(SigningMessage::SigningPackage {
            package: serialized_package,
        })).await?;

        let expected_shares = signers.len();
        let mut signature_shares = BTreeMap::new();
        let start_time = Instant::now();

        while signature_shares.len() < expected_shares {
            if start_time.elapsed() > Duration::from_secs(crate::frost::tests::SIGNING_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(format!(
                    "Timed out waiting for signature shares. Received {}/{}",
                    signature_shares.len(), expected_shares
                )));
            }

            if let Some(server) = &mut self.ipc_server {
                match timeout(Duration::from_millis(100), server.receive()).await {
                    Ok(Ok((sender_id, message))) => {
                        debug!("Received message from {:?}: {:?}", sender_id, message);
                        if let IpcMessage::Signing(SigningMessage::Round2 { id, signature_share }) = message {
                            if !signers.contains(&id) {
                                debug!("Ignoring signature share from non-signer: {:?}", id);
                                continue;
                            }
                            let deserialized_share: SignatureShare = bincode::deserialize(&signature_share)?;
                            signature_shares.insert(id, deserialized_share);
                            info!("Received signature share from {:?} ({}/{})", id, signature_shares.len(), expected_shares);
                        }
                    },
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {},
                }
            }
            sleep(Duration::from_millis(10)).await;
        }

        info!("Coordinator: Round 2 completed, received all signature shares");
        Ok((signing_package, signature_shares))
    }

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

    async fn broadcast_message(&self, message: IpcMessage) -> Result<()> {
        if let Some(server) = &self.ipc_server {
            server.broadcast(message).await
        } else {
            for (id, client) in &self.ipc_clients {
                client.send(message.clone()).await?;
            }
            Ok(())
        }
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        self.processes.terminate_all().await?;
        Ok(())
    }

    pub fn get_server_addr(&self) -> Option<SocketAddr> {
        self.ipc_server.as_ref().map(|server| server.socket_addr())
    }
}

impl Drop for CoordinatorController {
    fn drop(&mut self) {
        let _ = self.processes.terminate_all();
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::Identifier;
    use frost_secp256k1::keys::IdentifierList;



    // #[test]
    // fn test_participant_operations() {
    //     // Generate key packages
    //     let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
    //
    //     // Create a single participant
    //     let participant_id = *key_packages.keys().next().unwrap();
    //     let participant = FrostParticipant::new(
    //         participant_id,
    //         key_packages.get(&participant_id).unwrap().clone(),
    //         pub_key_package.clone()
    //     );
    //
    //     // Test generating commitment
    //     let (commitment, nonces) = participant.generate_commitment().unwrap();
    //     assert!(commitment);
    //
    //     // Create a fake signing package (normally provided by coordinator)
    //     let mut commitments_map = BTreeMap::new();
    //     commitments_map.insert(participant_id, commitment);
    //     let message = b"Test participant operations";
    //     let signing_package = SigningPackage::new(commitments_map, message);
    //
    //     // Test generating signature share
    //     let signature_share = participant.generate_signature_share(&nonces, &signing_package).unwrap();
    //     assert!(signature_share);
    // }
}