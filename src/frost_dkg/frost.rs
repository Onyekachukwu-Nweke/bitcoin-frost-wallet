use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ThresholdConfig};
use frost_secp256k1::{
    Identifier, SigningPackage, VerifyingKey, Signature,
    keys::{KeyPackage, PublicKeyPackage},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand_core::OsRng;
use std::collections::{BTreeMap, HashMap};

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

/// FROST Participant - Each signer in the threshold signature scheme
/// Handles cryptographic operations specific to a single participant
pub struct FrostParticipant {
    /// Participant identifier
    id: Identifier,
    /// Key package containing the participant's signing key
    key_package: KeyPackage,
    /// Public key package for verification
    pub_key_package: PublicKeyPackage,
}

impl FrostParticipant {
    /// Create a new FROST participant
    pub fn new(id: Identifier, key_package: KeyPackage, pub_key_package: PublicKeyPackage) -> Self {
        Self {
            id,
            key_package,
            pub_key_package,
        }
    }

    /// Get the participant's ID
    pub fn get_id(&self) -> Identifier {
        self.id
    }

    /// Generate signing commitments (Round 1)
    /// Called when the participant is asked to participate in signing
    pub fn generate_commitment(&self) -> Result<(SigningCommitments, SigningNonces)> {
        let signing_share = self.key_package.signing_share();
        let (nonces, commitments) = frost_secp256k1::round1::commit(signing_share, &mut OsRng);
        Ok((commitments, nonces))
    }

    /// Generate a signature share (Round 2)
    /// Called after receiving the signing package from the coordinator
    pub fn generate_signature_share(
        &self,
        nonces: &SigningNonces,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare> {
        let signature_share = frost_secp256k1::round2::sign(
            signing_package,
            nonces,
            &self.key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature_share)
    }

    /// Verify a signature (for participants to verify the final result)
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let result = VerifyingKey::verify(
            self.pub_key_package.verifying_key(),
            message,
            signature,
        ).map(|()| true)
            .unwrap_or(false);

        Ok(result)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::Identifier;
    use frost_secp256k1::keys::IdentifierList;

    // Helper function to generate key packages for testing
    fn generate_test_key_packages(threshold: u16, participants: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
        let (secret_shares, pub_key_package) = frost_secp256k1::keys::generate_with_dealer(
            participants,
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

    // Helper function to create a set of frost participants
    fn create_frost_participants(
        key_packages: &BTreeMap<Identifier, KeyPackage>,
        pub_key_package: &PublicKeyPackage
    ) -> BTreeMap<Identifier, FrostParticipant> {
        key_packages.iter()
            .map(|(id, key_package)| {
                (*id, FrostParticipant::new(*id, key_package.clone(), pub_key_package.clone()))
            })
            .collect()
    }

    #[test]
    fn test_coordinator_based_frost_signing() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants with their respective key packages
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for coordinator-based signing";

        // Define the signers for this session
        let signer_ids: Vec<Identifier> = participants.keys().copied().take(2).collect();

        // Create a coordinator (doesn't have signing capability)
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // Register participants with the coordinator
        for &id in &signer_ids {
            coordinator.add_participant(Participant::new(id));
        }

        // 1. Coordinator initiates signing session
        coordinator.start_signing(message.to_vec()).unwrap();

        // 2. Participants generate and send commitments to coordinator (Round 1)
        let mut nonces_map = HashMap::new();

        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let (commitment, nonces) = participant.generate_commitment().unwrap();

            // Send commitment to coordinator (simulated)
            coordinator.add_commitment(id, commitment).unwrap();

            // Participant stores their nonces for later use
            nonces_map.insert(id, nonces);
        }

        // 3. Coordinator creates signing package and distributes to participants
        assert!(coordinator.has_all_commitments(&signer_ids));
        let signing_package = coordinator.create_signing_package(&signer_ids).unwrap();

        // 4. Participants generate signature shares and send to coordinator (Round 2)
        let mut signature_shares = BTreeMap::new();

        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();

            // Generate signature share
            let signature_share = participant
                .generate_signature_share(nonces, &signing_package)
                .unwrap();

            // Send signature share to coordinator (simulated)
            signature_shares.insert(id, signature_share);
        }

        // 5. Coordinator aggregates signature shares to form final signature
        let signature = coordinator
            .aggregate_signature_shares(&signing_package, &signature_shares)
            .unwrap();

        // 6. Coordinator verifies the signature
        let valid = coordinator.verify_signature(message, &signature).unwrap();
        assert!(valid, "Signature verification failed");

        // 7. Reset for next signing session
        coordinator.clear_signing_session();
    }

    #[test]
    fn test_complete_signing_flow() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants with their respective key packages
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for complete signing flow";

        // Define signers for this session
        let signer_ids: Vec<Identifier> = participants.keys().copied().take(2).collect();

        // Create coordinator
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // 1. Coordinator setup - register all participants
        for &id in &signer_ids {
            coordinator.add_participant(Participant::new(id));
        }

        // 2. Initialize signing session
        coordinator.start_signing(message.to_vec()).unwrap();

        // 3. Participants generate commitments
        let mut nonces_map = HashMap::new();
        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let (commitment, nonces) = participant.generate_commitment().unwrap();
            coordinator.add_commitment(id, commitment).unwrap();
            nonces_map.insert(id, nonces);
        }

        // 4. Coordinator creates and distributes signing package
        let signing_package = coordinator.create_signing_package(&signer_ids).unwrap();

        // 5. Participants generate signature shares
        let mut signature_shares = BTreeMap::new();
        for &id in &signer_ids {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = participant.generate_signature_share(nonces, &signing_package).unwrap();
            signature_shares.insert(id, signature_share);
        }

        // 6. Coordinator aggregates shares into final signature
        let signature = coordinator.aggregate_signature_shares(&signing_package, &signature_shares).unwrap();

        // 7. Verify signature
        let verification_result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            message,
            &signature,
        );

        assert!(verification_result.is_ok(), "Signature verification failed");
    }

    #[test]
    fn test_not_enough_signers() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create participants
        let participants = create_frost_participants(&key_packages, &pub_key_package);

        // Create a message to sign
        let message = b"Test message for threshold validation";

        // Try to sign with only one signer (below threshold)
        let signers: Vec<Identifier> = participants.keys().copied().take(1).collect();

        // Create a coordinator with threshold 2
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);

        // Register just one participant
        for &id in &signers {
            coordinator.add_participant(Participant::new(id));
        }

        // Attempt to start signing session
        let result = coordinator.start_signing(message.to_vec());
        assert!(result.is_err());

        if let Err(FrostWalletError::NotEnoughSigners { required, provided }) = result {
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        } else {
            panic!("Expected NotEnoughSigners error");
        }
    }

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