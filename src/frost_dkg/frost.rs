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

/// FROST signing coordinator for threshold signing
/// Acts as a communication facilitator, does not handle cryptographic material
pub struct FrostCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Participants in the signing session
    participants: HashMap<Identifier, Participant>,
    /// Current round commitments (Round 1)
    commitments: Option<BTreeMap<Identifier, SigningCommitments>>,
    /// Current message being signed
    message: Option<Vec<u8>>,
}

impl FrostCoordinator {
    /// Create a new FROST coordinator for signing
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            participants: HashMap::new(),
            commitments: None,
            message: None,
        }
    }

    /// Add a participant
    pub fn add_participant(&mut self, participant: Participant) {
        self.participants.insert(participant.id, participant);
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
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<()> {
        if self.participants.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: self.participants.len() as u16,
            });
        }
        self.commitments = Some(BTreeMap::new());
        self.message = Some(message);
        Ok(())
    }

    /// Add commitments from a participant (Round 1)
    pub fn add_commitments(&mut self, participant_id: Identifier, commitments: SigningCommitments) -> Result<()> {
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }
        if let Some(commitments_map) = &mut self.commitments {
            commitments_map.insert(participant_id, commitments);
            Ok(())
        } else {
            Err(FrostWalletError::InvalidState("No signing session in progress".to_string()))
        }
    }

    /// Create a signing package for Round 2
    pub fn create_signing_package(&self) -> Result<SigningPackage> {
        let commitments = self.commitments.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No commitments available".to_string()))?;

        let message = self.message.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No message to sign".to_string()))?;

        if commitments.len() < self.config.threshold as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: self.config.threshold,
                provided: commitments.len() as u16,
            });
        }

        Ok(SigningPackage::new(commitments.clone(), message))
    }

    /// Clear the current signing session
    pub fn clear_signing_session(&mut self) {
        self.commitments = None;
        self.message = None;
    }
}

/// FROST signing participant - handles cryptographic operations for a single participant
pub struct FrostParticipant {
    /// Participant identifier
    id: Identifier,
    /// Key package for signing
    key_package: KeyPackage,
    /// Public key package (for verification)
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

    /// Generate signing commitments (Round 1)
    pub fn generate_commitments(&self) -> Result<(SigningCommitments, SigningNonces)> {
        let signing_share = self.key_package.signing_share();
        let (nonces, commitments) = frost_secp256k1::round1::commit(signing_share, &mut OsRng);
        Ok((commitments, nonces))
    }

    /// Generate a signature share (Round 2)
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

    /// Aggregate signature shares into a complete signature
    pub fn aggregate_signatures(
        &self,
        signing_package: &SigningPackage,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<Signature> {
        let signature = frost_secp256k1::aggregate(
            signing_package,
            signature_shares,
            &self.pub_key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;
        Ok(signature)
    }

    /// Verify a signature
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
    fn generate_test_key_packages(threshold: u16, participants: u16) -> (BTreeMap<Identifier, FrostParticipant>, PublicKeyPackage) {
        let (secret_shares, pub_key_package) = frost_secp256k1::keys::generate_with_dealer(
            participants,
            threshold,
            IdentifierList::Default,
            &mut OsRng,
        ).expect("Failed to generate key packages");

        let participants: BTreeMap<_, _> = secret_shares.into_iter()
            .map(|(id, ss)| {
                let key_package = KeyPackage::try_from(ss)
                    .map_err(|e| FrostWalletError::FrostError("Failed to convert to KeyPackage".to_string()))
                    .unwrap();
                let participant = FrostParticipant::new(id, key_package, pub_key_package.clone());
                (id, participant)
            })
            .collect();

        (participants, pub_key_package)
    }

    #[test]
    fn test_frost_signing() {
        // Generate key packages
        let (participants, _) = generate_test_key_packages(2, 3);

        // Create a message to sign
        let message = b"Test message";

        // Select signers
        let signers: Vec<Identifier> = participants.keys().copied().take(2).collect();

        // Start a coordinator (for testing facilitation)
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        for id in signers.iter().copied() {
            coordinator.add_participant(Participant::new(id));
        }
        coordinator.start_signing(message.to_vec()).unwrap();

        // Generate and collect commitments
        let mut nonces_map = HashMap::new();
        for &id in &signers {
            let participant = participants.get(&id).unwrap();
            let (commitments, nonces) = participant.generate_commitments().unwrap();
            coordinator.add_commitments(id, commitments).unwrap();
            nonces_map.insert(id, nonces);
        }

        // Create signing package
        let signing_package = coordinator.create_signing_package().unwrap();

        // Generate signature shares
        let mut signature_shares = BTreeMap::new();
        for &id in &signers {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = participant.generate_signature_share(nonces, &signing_package).unwrap();
            signature_shares.insert(id, signature_share);
        }

        // Aggregate signature shares
        let first_participant = participants.get(&signers[0]).unwrap();
        let signature = first_participant.aggregate_signatures(&signing_package, &signature_shares).unwrap();

        // Verify signature
        let valid = first_participant.verify_signature(message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_coordinator_signing() {
        // Generate key packages
        let (participants, _) = generate_test_key_packages(2, 3);

        // Create a coordinator
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);

        // Add participants (without key packages, since coordinator doesn't need them)
        let signers: Vec<Identifier> = participants.keys().copied().take(2).collect();
        for &id in &signers {
            coordinator.add_participant(Participant::new(id));
        }

        // Create a message to sign
        let message = b"Test message".to_vec();

        // Start signing session
        coordinator.start_signing(message.clone()).unwrap();

        // Generate and collect commitments
        let mut nonces_map = HashMap::new();
        for &id in &signers {
            let participant = participants.get(&id).unwrap();
            let (commitments, nonces) = participant.generate_commitments().unwrap();
            coordinator.add_commitments(id, commitments).unwrap();
            nonces_map.insert(id, nonces);
        }

        // Create signing package
        let signing_package = coordinator.create_signing_package().unwrap();

        // Generate signature shares
        let mut signature_shares = BTreeMap::new();
        for &id in &signers {
            let participant = participants.get(&id).unwrap();
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = participant.generate_signature_share(nonces, &signing_package).unwrap();
            signature_shares.insert(id, signature_share);
        }

        // Aggregate signature shares using a participant's logic
        let first_participant = participants.get(&signers[0]).unwrap();
        let signature = first_participant.aggregate_signatures(&signing_package, &signature_shares).unwrap();

        // Verify signature using a participant's logic
        let valid = first_participant.verify_signature(&message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_not_enough_signers() {
        // Generate key packages
        let (participants, _) = generate_test_key_packages(2, 3);

        // Create a message to sign
        let message = b"Test message";

        // Try to sign with only one signer (below threshold)
        let signers: Vec<Identifier> = participants.keys().copied().take(1).collect();

        // Start a coordinator (for testing facilitation)
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        for &id in &signers {
            coordinator.add_participant(Participant::new(id));
        }
        let result = coordinator.start_signing(message.to_vec());
        assert!(result.is_err());

        if let Err(FrostWalletError::NotEnoughSigners { required, provided }) = result {
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        } else {
            panic!("Expected NotEnoughSigners error");
        }
    }
}