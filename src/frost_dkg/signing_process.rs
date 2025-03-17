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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use log::{debug, info, warn, error};

/// Timeout for signing operations in seconds
const SIGNING_TIMEOUT_SECONDS: u64 = 30;

#[derive(Debug, PartialEq)]
enum SigningRoundState {
    WaitingForParticipants,
    Round1,
    Round2,
    Complete,
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
    round_state: SigningRoundState,
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
            round_state: SigningRoundState::WaitingForParticipants,
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
            if start_time.elapsed() > Duration::from_secs(SIGNING_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(format!(
                    "Timeout waiting for participants to connect. Connected {}/{}",
                    self.ipc_clients.len(), signers.len()
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }

        self.round_state = SigningRoundState::Round1;
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

        self.round_state = SigningRoundState::Complete;
        self.coordinator.clear_signing_session();

        Ok(signature)
    }

    async fn run_round1(&mut self, signers: &[Identifier]) -> Result<BTreeMap<Identifier, SigningCommitments>> {
        info!("Coordinator: Starting Round 1");
        let expected_commitments = signers.len();
        let mut commitments_map = BTreeMap::new();
        let start_time = Instant::now();

        while commitments_map.len() < expected_commitments {
            if start_time.elapsed() > Duration::from_secs(SIGNING_TIMEOUT_SECONDS) {
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
        self.round_state = SigningRoundState::Round2;
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
            if start_time.elapsed() > Duration::from_secs(SIGNING_TIMEOUT_SECONDS) {
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

pub struct SigningParticipant {
    local_id: Identifier,
    frost_participant: FrostParticipant,
    coordinator_client: Option<IpcClient>,
    current_message: Option<Vec<u8>>,
    current_signers: Vec<Identifier>,
    current_nonces: Option<SigningNonces>,
}

impl SigningParticipant {
    pub fn new(local_id: Identifier, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Self {
        Self {
            local_id,
            frost_participant: FrostParticipant::new(local_id, key_package, pub_key_package),
            coordinator_client: None,
            current_message: None,
            current_signers: Vec::new(),
            current_nonces: None,
        }
    }

    pub async fn connect_to_coordinator(&mut self, coordinator_id: Identifier, addr: SocketAddr) -> Result<()> {
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(addr).await?;
        self.coordinator_client = Some(client);
        self.coordinator_client.as_ref().unwrap()
            .send(IpcMessage::Handshake(self.local_id)).await?;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.coordinator_client.is_none() {
            return Err(FrostWalletError::InvalidState("Not connected to coordinator".to_string()));
        }

        info!("Participant {:?} starting", self.local_id);

        loop {
            let message = {
                let client = self.coordinator_client.as_mut().unwrap();
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

                    self.current_message = Some(message);
                    self.current_signers = signers;

                    debug!("Generating commitment");
                    let (commitment, nonces) = self.frost_participant.generate_commitment()?;
                    self.current_nonces = Some(nonces);

                    let serialized_commitment = bincode::serialize(&commitment)?;
                    debug!("Sending commitment to coordinator");
                    let client = self.coordinator_client.as_mut().unwrap();
                    client.send(IpcMessage::Signing(SigningMessage::Round1 {
                        id: self.local_id,
                        commitment: serialized_commitment,
                    })).await?;
                    debug!("Commitment sent successfully");
                },

                IpcMessage::Signing(SigningMessage::SigningPackage { package }) => {
                    info!("Received signing package from coordinator");
                    let signing_package: SigningPackage = bincode::deserialize(&package)?;

                    let nonces = self.current_nonces.as_ref()
                        .ok_or_else(|| FrostWalletError::InvalidState("No signing nonces available".to_string()))?;

                    debug!("Generating signature share");
                    let signature_share = self.frost_participant.generate_signature_share(nonces, &signing_package)?;

                    let serialized_share = bincode::serialize(&signature_share)?;
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

    fn reset_signing_state(&mut self) {
        self.current_message = None;
        self.current_signers.clear();
        self.current_nonces = None;
    }
}

impl Drop for SigningParticipant {
    fn drop(&mut self) {
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
        let _ = env_logger::builder().is_test(true).try_init();

        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);
        let coordinator_id = Identifier::try_from(1u16).unwrap();
        let participant1_id = Identifier::try_from(2u16).unwrap();
        let participant2_id = Identifier::try_from(3u16).unwrap();
        let coordinator_port = 36000;

        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = CoordinatorController::new(coordinator_id, config.clone(), coordinator_port);
        coordinator.set_public_key_package(pub_key_package.clone()).unwrap();

        coordinator.start_server().await.unwrap();
        let coordinator_addr = coordinator.get_server_addr().unwrap();
        println!("Coordinator server started at {:?}", coordinator_addr);

        let mut participant1 = SigningParticipant::new(
            participant1_id,
            key_packages.get(&participant1_id).unwrap().clone(),
            pub_key_package.clone(),
        );
        participant1.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 1 connected to coordinator");

        let mut participant2 = SigningParticipant::new(
            participant2_id,
            key_packages.get(&participant2_id).unwrap().clone(),
            pub_key_package.clone(),
        );
        participant2.connect_to_coordinator(coordinator_id, coordinator_addr).await.unwrap();
        println!("Participant 2 connected to coordinator");

        sleep(Duration::from_millis(200)).await;

        coordinator.connect_to_participant(participant1_id, coordinator_addr).await.unwrap();
        coordinator.connect_to_participant(participant2_id, coordinator_addr).await.unwrap();

        sleep(Duration::from_millis(500)).await;
        println!("All connections established");

        let p1_handle = tokio::spawn(async move {
            participant1.run().await
        });
        let p2_handle = tokio::spawn(async move {
            participant2.run().await
        });

        sleep(Duration::from_millis(500)).await;
        println!("Participants started, beginning signing process");

        let message = b"Test message with coordinator architecture".to_vec();
        let signers = vec![participant1_id, participant2_id];

        let signature = coordinator.coordinate_signing(message.clone(), signers).await.unwrap();
        println!("Signing completed, verifying signature");

        let verification_result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            &message,
            &signature,
        );
        assert!(verification_result.is_ok(), "Signature verification failed");

        println!("Signature verified successfully!");
        p1_handle.abort();
        p2_handle.abort();
        coordinator.cleanup().await.unwrap();
    }
}