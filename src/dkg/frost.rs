use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ThresholdConfig};
use frost_secp256k1::{
    Identifier, SigningPackage, VerifyingKey, Signature,
    keys::{KeyPackage, PublicKeyPackage, SecretShare, SigningShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand_core::OsRng;
use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};

/// FROST signing coordinator for threshold signing
pub struct FrostCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// Participants in the signing session
    participants: HashMap<Identifier, Participant>,
    /// Current round commitments
    commitments: Option<BTreeMap<Identifier, SigningCommitments>>,
    /// Current message being signed
    message: Option<Vec<u8>>,
}

impl FrostCoordinator {
    /// Create a new FROST coordinator for signing
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            pub_key_package: None,
            participants: HashMap::new(),
            commitments: None,
            message: None,
        }
    }

    /// Set the public key package
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

    /// Get a mutable participant by ID
    pub fn get_participant_mut(&mut self, id: Identifier) -> Option<&mut Participant> {
        self.participants.get_mut(&id)
    }

    /// Get all participants
    pub fn get_participants(&self) -> &HashMap<Identifier, Participant> {
        &self.participants
    }

    /// Start a new signing session
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<()> {
        self.commitments = Some(BTreeMap::new());
        self.message = Some(message);
        Ok(())
    }

    /// Generate signing commitments (Round 1)
    pub fn generate_commitments(&self, participant_id: Identifier) -> Result<(SigningCommitments, SigningNonces)> {
        let participant = self.get_participant(participant_id)
            .ok_or_else(|| FrostWalletError::ParticipantNotFound(participant_id))?;

        let key_package = participant.key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("Participant has no key package".to_string()))?;

        // Use frost_secp256k1::round1::commit to generate commitments
        let signing_share = key_package.secret_share().signing_share();

        let (nonces, commitments) = frost_secp256k1::round1::commit(
            signing_share,
            &mut OsRng,
        );

        Ok((commitments, nonces))
    }

    /// Add commitments from a participant (Round 1)
    pub fn add_commitments(&mut self, participant_id: Identifier, commitments: SigningCommitments) -> Result<()> {
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

        Ok(SigningPackage::new(commitments.clone(), message))
    }

    /// Generate a signature share (Round 2)
    pub fn generate_signature_share(
        &self,
        participant_id: Identifier,
        nonces: &SigningNonces,
        signing_package: &SigningPackage
    ) -> Result<SignatureShare> {
        let participant = self.get_participant(participant_id)
            .ok_or_else(|| FrostWalletError::ParticipantNotFound(participant_id))?;

        let key_package = participant.key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("Participant has no key package".to_string()))?;

        // Use frost_secp256k1::round2::sign to generate the signature share
        let signature_share = frost_secp256k1::round2::sign(
            signing_package,
            nonces,
            key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature_share)
    }

    /// Aggregate signature shares into a complete signature
    pub fn aggregate_signatures(
        &self,
        signing_package: &SigningPackage,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
    ) -> Result<Signature> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package available".to_string()))?;

        // Use frost_secp256k1::aggregate to combine the signature shares
        let signature = frost_secp256k1::aggregate(
            signing_package,
            signature_shares,
            pub_key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature)
    }

    /// Verify a signature
    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package available".to_string()))?;

        // Use frost_secp256k1::verify to check the signature
        let result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            message,
            signature,
        ).map(|()| true) // If verification succeeds, return true
         .unwrap_or(false); // If verification fails, return false

        Ok(result)
    }

    /// Clear the current signing session
    pub fn clear_signing_session(&mut self) {
        self.commitments = None;
        self.message = None;
    }
}

/// Utility functions for FROST signing
pub struct FrostSigner;

impl FrostSigner {
    /// Sign a message using a complete signing workflow
    pub fn sign_message(
        key_packages: &BTreeMap<Identifier, KeyPackage>,
        pub_key_package: &PublicKeyPackage,
        message: &[u8],
        signers: &[Identifier],
    ) -> Result<Signature> {
        // Verify we have enough signers
        let min_signers = key_packages.values().next()
            .map(|kp| kp.parameters().min_signers())
            .unwrap_or(0);

        if signers.len() < min_signers as usize {
            return Err(FrostWalletError::NotEnoughSigners {
                required: min_signers,
                provided: signers.len() as u16,
            });
        }

        // Round 1: Generate commitments
        let mut commitments_map = BTreeMap::new();
        let mut nonces_map = HashMap::new();

        for &signer_id in signers {
            let key_package = key_packages.get(&signer_id)
                .ok_or_else(|| FrostWalletError::ParticipantNotFound(signer_id))?;

            let signing_share = key_package.secret_share().signing_share();

            // Generate commitments using frost_secp256k1::round1::commit
            let (nonces, commitments) = frost_secp256k1::round1::commit(
                signing_share,
                &mut OsRng,
            );

            commitments_map.insert(signer_id, commitments);
            nonces_map.insert(signer_id, nonces);
        }

        // Create signing package
        let signing_package = SigningPackage::new(commitments_map, message);

        // Round 2: Generate signature shares
        let mut signature_shares = BTreeMap::new();

        for &signer_id in signers {
            let key_package = key_packages.get(&signer_id)
                .ok_or_else(|| FrostWalletError::ParticipantNotFound(signer_id))?;

            let nonces = nonces_map.get(&signer_id)
                .ok_or_else(|| FrostWalletError::InvalidState("Missing nonces".to_string()))?;

            // Generate signature share using frost_secp256k1::round2::sign
            let signature_share = frost_secp256k1::round2::sign(
                &signing_package,
                nonces,
                key_package,
            ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

            signature_shares.insert(signer_id, signature_share);
        }

        // Aggregate signature shares
        let signature = frost_secp256k1::aggregate(
            &signing_package,
            &signature_shares,
            pub_key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature)
    }

    /// Verify a signature
    pub fn verify_signature(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool> {
        // Verify signature using frost_secp256k1::verify
        let result = VerifyingKey::verify(
            verifying_key,
            message,
            signature,
        ).map(|()| true) // If verification succeeds, return true
         .unwrap_or(false); // If verification fails, return false

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::Identifier;
    use frost_secp256k1::keys::{KeyGenOptions, ThresholdParameters};
    use frost_secp256k1::keys::dkg::{self, round1, round2};

    // Helper function to generate key packages for testing
    fn generate_test_key_packages(threshold: u16, participants: u16) -> (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage) {
        let params = ThresholdParameters::new(threshold, participants)
            .expect("Failed to create threshold parameters");

        let (key_packages, _) = frost_secp256k1::keys::generate_with_dealer(
            params,
            KeyGenOptions::default(),
            &mut OsRng,
        ).expect("Failed to generate key packages");

        let pub_key_package = key_packages.values().next().unwrap().public_key_package().clone();

        (key_packages, pub_key_package)
    }

    #[test]
    fn test_frost_signing() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create a message to sign
        let message = b"Test message";

        // Select signers
        let signers: Vec<Identifier> = key_packages.keys().copied().take(2).collect();

        // Sign the message
        let signature = FrostSigner::sign_message(
            &key_packages,
            &pub_key_package,
            message,
            &signers,
        ).unwrap();

        // Verify the signature
        let valid = FrostSigner::verify_signature(
            pub_key_package.verifying_key(),
            message,
            &signature,
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_coordinator_signing() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create a coordinator
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // Add participants
        for (id, key_package) in &key_packages {
            let participant = Participant::with_key_package(*id, key_package.clone());
            coordinator.add_participant(participant);
        }

        // Create a message to sign
        let message = b"Test message".to_vec();

        // Start signing session
        coordinator.start_signing(message.clone()).unwrap();

        // Generate and collect commitments
        let mut nonces_map = HashMap::new();
        let participants: Vec<Identifier> = key_packages.keys().copied().take(2).collect();

        for &id in &participants {
            let (commitments, nonces) = coordinator.generate_commitments(id).unwrap();
            coordinator.add_commitments(id, commitments).unwrap();
            nonces_map.insert(id, nonces);
        }

        // Create signing package
        let signing_package = coordinator.create_signing_package().unwrap();

        // Generate signature shares
        let mut signature_shares = BTreeMap::new();

        for &id in &participants {
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = coordinator.generate_signature_share(
                id,
                nonces,
                &signing_package,
            ).unwrap();

            signature_shares.insert(id, signature_share);
        }

        // Aggregate signature shares
        let signature = coordinator.aggregate_signatures(
            &signing_package,
            &signature_shares,
        ).unwrap();

        // Verify signature
        let valid = coordinator.verify_signature(&message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_not_enough_signers() {
        // Generate key packages
        let (key_packages, pub_key_package) = generate_test_key_packages(2, 3);

        // Create a message to sign
        let message = b"Test message";

        // Try to sign with only one signer (below threshold)
        let signers: Vec<Identifier> = key_packages.keys().copied().take(1).collect();

        // This should fail because we need at least 2 signers
        let result = FrostSigner::sign_message(
            &key_packages,
            &pub_key_package,
            message,
            &signers,
        );

        assert!(result.is_err());

        if let Err(FrostWalletError::NotEnoughSigners { required, provided }) = result {
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        } else {
            panic!("Expected NotEnoughSigners error");
        }
    }
}