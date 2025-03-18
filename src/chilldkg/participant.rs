use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{part1, part2, part3, round1, round2};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use rand_core::OsRng;
use tokio::time::{sleep, timeout};
use crate::common::errors::FrostWalletError;
use crate::common::types::{DkgMessage, DkgRoundState, IpcMessage, ThresholdConfig};
use crate::common::constants::DKG_TIMEOUT_SECONDS;
use crate::ipc::IpcClient;

/// DKG Participant - handles the cryptographic operations for a single participant
pub struct DkgParticipant {
    /// Participant identifier
    id: Identifier,
    /// Threshold configuration
    config: ThresholdConfig,
    /// Round 1 secret package (generated during round 1)
    round1_secret: Option<round1::SecretPackage>,
    /// Round 2 secret package (generated during round 2)
    round2_secret: Option<round2::SecretPackage>,
    /// Final key package after DKG completion
    key_package: Option<KeyPackage>,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
}

impl DkgParticipant {
    /// Create a new DKG participant
    pub fn new(id: Identifier, config: ThresholdConfig) -> Self {
        Self {
            id,
            config,
            round1_secret: None,
            round2_secret: None,
            key_package: None,
            pub_key_package: None,
        }
    }

    /// Generate round 1 package
    pub fn generate_round1(&mut self) -> crate::common::errors::Result<round1::Package> {
        // Generate Round 1 data
        let (round1_secret, round1_package) = part1(
            self.id,
            self.config.total_participants,
            self.config.threshold,
            &mut OsRng,
        ).map_err(|e| FrostWalletError::DkgError(format!("Round 1 generation error: {}", e)))?;

        // Store the secret
        self.round1_secret = Some(round1_secret);

        Ok(round1_package)
    }

    /// Generate round 2 packages for all other participants
    pub fn generate_round2(&mut self, round1_packages: &BTreeMap<Identifier, round1::Package>) -> crate::common::errors::Result<BTreeMap<Identifier, round2::Package>> {
        let round1_secret = self.round1_secret.take()
            .ok_or_else(|| FrostWalletError::DkgError("No round 1 secret available".to_string()))?;

        // Filter to exclude own package
        let other_round1_packages: BTreeMap<Identifier, round1::Package> = round1_packages
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        let (round2_secret, round2_packages) = part2(
            round1_secret,
            &other_round1_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("Round 2 generation error: {}", e)))?;

        self.round2_secret = Some(round2_secret);

        Ok(round2_packages)
    }

    /// Finalize DKG and create key package
    pub fn finalize(&mut self,
                    round1_packages: &BTreeMap<Identifier, round1::Package>,
                    round2_packages: &BTreeMap<Identifier, round2::Package>) -> crate::common::errors::Result<(KeyPackage, PublicKeyPackage)> {
        let round2_secret = self.round2_secret.take()
            .ok_or_else(|| FrostWalletError::DkgError("No round 2 secret available".to_string()))?;

        // Filter round1 packages to exclude own package
        let other_round1_packages: BTreeMap<Identifier, round1::Package> = round1_packages
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        println!("round 2 packages len: {}", round2_packages.len());
        println!("other_round1_packages len: {}", other_round1_packages.len());

        let (key_package, public_key_package) = part3(
            &round2_secret,
            &other_round1_packages,
            round2_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("DKG finalization error: {}", e)))?;

        self.key_package = Some(key_package.clone());
        self.pub_key_package = Some(public_key_package.clone());

        Ok((key_package, public_key_package))
    }

    /// Get the key package
    pub fn get_key_package(&self) -> crate::common::errors::Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::DkgError("DKG not yet complete".to_string()))
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> crate::common::errors::Result<PublicKeyPackage> {
        self.pub_key_package.clone()
            .ok_or_else(|| FrostWalletError::DkgError("DKG not yet complete".to_string()))
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
    pub async fn connect_to_coordinator(&mut self, addr: SocketAddr) -> crate::common::errors::Result<()> {
        let coordinator_id = Identifier::try_from(1u16).unwrap(); // Coordinator ID is typically 1
        let mut client = IpcClient::new(self.local_id, coordinator_id);
        client.connect(addr).await?;
        self.coordinator_client = Some(client);
        Ok(())
    }

    /// Run the DKG protocol as a participant
    pub async fn run_dkg(&mut self) -> crate::common::errors::Result<KeyPackage> {
        log::info!("Starting DKG protocol as participant {:?}", self.local_id);

        // Take ownership of the client to avoid holding a mutable borrow
        let mut client = self.coordinator_client
            .take()
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
                }
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
        let expected_commitments = self.config.total_participants as usize;

        while self.round1_packages.len() < expected_commitments {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError("Timeout waiting for Round 1 commitments".to_string()));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    if let IpcMessage::Dkg(DkgMessage::Commitment(id, commitment_data)) = message {
                        if id != self.local_id { // We already stored our own commitment
                            let round1_package: round1::Package = bincode::deserialize(&commitment_data)?;
                            self.round1_packages.insert(id, round1_package);
                            log::info!("Received Round 1 commitment from participant {:?} ({}/{})",
                                      id, self.round1_packages.len(), expected_commitments);
                        }
                    }
                }
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

        // Receive Round 2 packages
        {
            // Scope to ensure client borrow is released before mutating self again
            self.receive_round2_packages(&mut client).await?;
        }

        log::info!("Received necessary Round 2 key shares, finalizing DKG");
        self.round_state = DkgRoundState::Round3;

        // Create a map containing only the Round 2 packages sent to this participant
        let my_round2_packages = self.round2_packages.clone();

        // Finalize DKG and create key package
        let (key_package, public_key_package) = self.participant.finalize(
            &self.round1_packages,
            &my_round2_packages
        )?;

        // Store key materials
        self.key_package = Some(key_package.clone());
        self.pub_key_package = Some(public_key_package.clone());

        // Notify coordinator we're done
        client.send(IpcMessage::Dkg(DkgMessage::Finish)).await?;

        log::info!("DKG protocol completed successfully");
        self.round_state = DkgRoundState::Complete;

        // Restore the client back to self
        self.coordinator_client = Some(client);

        Ok(key_package)
    }

    /// Wait for key shares from other participants
    async fn receive_round2_packages(
        &mut self,
        client: &mut IpcClient,
    ) -> crate::common::errors::Result<()> {
        let start_time = Instant::now();

        // Calculate expected number of shares
        let expected_shares = self.config.total_participants as usize - 1; // Exclude self

        log::info!("Waiting for {} Round 2 key shares from other participants", expected_shares);

        let mut received_from: std::collections::HashSet<Identifier> = std::collections::HashSet::new();

        while received_from.len() < expected_shares {
            if start_time.elapsed() > Duration::from_secs(DKG_TIMEOUT_SECONDS) {
                return Err(FrostWalletError::TimeoutError(
                    format!("Timeout waiting for Round 2 key shares. Got {}/{} expected shares. Participants: {:?}",
                            received_from.len(), expected_shares, received_from)
                ));
            }

            match timeout(Duration::from_millis(100), client.receive()).await {
                Ok(Ok(message)) => {
                    log::info!("Received message: {:?}", message);
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

        if received_from.len() < expected_shares {
            return Err(FrostWalletError::DkgError(
                format!("Failed to receive all Round 2 key shares. Got {}/{}",
                        received_from.len(), expected_shares)
            ));
        }

        Ok(())
    }

    /// Get the key package
    pub fn get_key_package(&self) -> crate::common::errors::Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> crate::common::errors::Result<PublicKeyPackage> {
        self.pub_key_package.clone()
            .ok_or_else(|| FrostWalletError::InvalidState("DKG not yet complete".to_string()))
    }
}