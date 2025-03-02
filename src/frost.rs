#![allow(warnings)]
use crate::error::{FrostWalletError, Result};
use crate::types::{Participant, ThresholdConfig};
use frost_core::{
    Identifier, SigningPackage, VerifyingKey
};
use frost_secp256k1::{
    keys::{IdentifierList, KeyPackage, PublicKeyPackage, SigningShare, SecretShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
    Signature,
};
use rand_core::{OsRng};
use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};

/// FROST signing coordinator
pub struct FrostCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Public key package
    pub_key_package: Option<PublicKeyPackage>,
    /// Participants in the signing session
    participants: HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Participant>,
    /// Current round commitments
    commitments: Option<BTreeMap<Identifier<frost_secp256k1::Secp256K1Sha256>, SigningCommitments>>,
    /// Current message being signed
    message: Option<Vec<u8>>,
}

impl FrostCoordinator {
    /// Create a new FROST coordinator
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
    pub fn get_participant(&self, id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Option<&Participant> {
        self.participants.get(&id)
    }

    /// Get a mutable participant by ID
    pub fn get_participant_mut(&mut self, id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Option<&mut Participant> {
        self.participants.get_mut(&id)
    }

    /// Get all participants
    pub fn get_participants(&self) -> &HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Participant> {
        &self.participants
    }

    /// Start a new signing session
    pub fn start_signing(&mut self, message: Vec<u8>) -> Result<()> {
        self.commitments = Some(BTreeMap::new());
        self.message = Some(message);
        Ok(())
    }

    /// Generate signing commitments (Round 1)
    pub fn generate_commitments(&self, participant_id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Result<(SigningCommitments, SigningNonces)> {
        // let mut rng = thread_rng();

        let participant = self.get_participant(participant_id)
            .ok_or_else(|| FrostWalletError::ParticipantNotFound(participant_id))?;

        let key_package = participant.key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("Participant has no key package".to_string()))?;

        // key_package = key_package.secret_share();

        let signing_share = key_package.signing_share();

        let (nonces, commitments) = frost_secp256k1::round1::commit(
            &signing_share,
            &mut OsRng,
        );

        Ok((commitments, nonces))
    }

    /// Add commitments from a participant (Round 1)
    pub fn add_commitments(&mut self, participant_id: Identifier<frost_secp256k1::Secp256K1Sha256>, commitments: SigningCommitments) -> Result<()> {
        if let Some(commitments_map) = &mut self.commitments {
            commitments_map.insert(participant_id, commitments);
            Ok(())
        } else {
            Err(FrostWalletError::InvalidState("No signing session in progress".to_string()))
        }
    }

    /// Create a signing package for Round 2
    pub fn create_signing_package(&self) -> Result<SigningPackage<frost_secp256k1::Secp256K1Sha256>> {
        let commitments = self.commitments.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No commitments available".to_string()))?;

        let message = self.message.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No message to sign".to_string()))?;

        Ok(SigningPackage::new(commitments.clone(), message))
    }

    /// Generate a signature share (Round 2)
    pub fn generate_signature_share(
        &self,
        participant_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        nonces: &SigningNonces,
        signing_package: &SigningPackage<frost_secp256k1::Secp256K1Sha256>,
    ) -> Result<SignatureShare> {
        let participant = self.get_participant(participant_id)
            .ok_or_else(|| FrostWalletError::ParticipantNotFound(participant_id))?;

        let key_package = participant.key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("Participant has no key package".to_string()))?;

        let signature_share = frost_secp256k1::round2::sign(
            signing_package,
            nonces,
            key_package,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        Ok(signature_share)
    }

    /// Aggregate signature shares
    pub fn aggregate_signatures(
        &self,
        signing_package: &SigningPackage<frost_secp256k1::Secp256K1Sha256>,
        signature_shares: &BTreeMap<Identifier<frost_secp256k1::Secp256K1Sha256>, SignatureShare>,
    ) -> Result<Signature> {
        let pub_key_package = self.pub_key_package.as_ref()
            .ok_or_else(|| FrostWalletError::InvalidState("No public key package available".to_string()))?;

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

        let is_valid = VerifyingKey::verify(
            pub_key_package.verifying_key(),
            message,
            signature,
        ).map(|()| true) // If verification succeeds, return true
         .unwrap_or(false); // If verification fails, return false

        Ok(is_valid)
    }

    /// Clear the current signing session
    pub fn clear_signing_session(&mut self) {
        self.commitments = None;
        self.message = None;
    }
}

/// FROST utilities for single-process testing
pub struct FrostUtil;

impl FrostUtil {
    /// Generate key packages using the dealer-based keygen
    pub fn generate_keys(config: &ThresholdConfig) -> Result<(BTreeMap<Identifier<frost_secp256k1::Secp256K1Sha256>, KeyPackage>, PublicKeyPackage)> {
        let min_signers = config.threshold;
        let max_signers = config.total_participants;

        let (secret_shares, public_key_package) = frost_secp256k1::keys::generate_with_dealer(
            max_signers,
            min_signers,
            IdentifierList::Default,
            &mut OsRng,
        ).map_err(|e| FrostWalletError::FrostError(e.to_string()))?;

        let key_packages: BTreeMap<_, _> = secret_shares.into_iter()
            .map(|(id, ss)| {
                let key_package = KeyPackage::try_from(ss)
                    .map_err(|e| FrostWalletError::FrostError("Failed to convert to KeyPackage".to_string()))
                    .unwrap();
                (id, key_package)
            })
            .collect();

        Ok((key_packages, public_key_package))
    }

    /// Sign a message using a single-process workflow (for testing)
    pub fn sign_message(
        key_packages: &BTreeMap<Identifier<frost_secp256k1::Secp256K1Sha256>, KeyPackage>,
        pub_key_package: &PublicKeyPackage,
        message: &[u8],
        signers: &[Identifier<frost_secp256k1::Secp256K1Sha256>],
    ) -> Result<Signature> {
        if signers.len() < key_packages.len() / 2 + 1 {
            return Err(FrostWalletError::NotEnoughSigners {
                required: (key_packages.len() / 2 + 1) as u16,
                provided: signers.len() as u16,
            });
        }

        // Round 1: Generate commitments
        let mut commitments_map = BTreeMap::new();
        let mut nonces_map = HashMap::new();

        for &signer_id in signers {
            let key_package = key_packages.get(&signer_id)
                .ok_or_else(|| FrostWalletError::ParticipantNotFound(signer_id))?;

            let signing_share = key_package.signing_share();

            let (nonces, commitments) = frost_secp256k1::round1::commit(
                &signing_share,
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

            // key_package = KeyPackage::try_from(key_package).unwrap_or();

            let nonces = nonces_map.get(&signer_id)
                .ok_or_else(|| FrostWalletError::InvalidState("Missing nonces".to_string()))?;

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
        pub_key_package: &PublicKeyPackage,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool> {
        let result = VerifyingKey::verify(
            pub_key_package.verifying_key(),
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

    #[test]
    fn test_generate_and_sign() {
        // Create a 2-of-3 threshold configuration
        let config = ThresholdConfig::new(2, 3);

        // Generate key packages
        let (key_packages, pub_key_package) = FrostUtil::generate_keys(&config).unwrap();

        // Verify we have 3 key packages
        assert_eq!(key_packages.len(), 3);

        // Sign a message with 2 signers
        let message = b"Test message";
        let signers: Vec<Identifier<frost_secp256k1::Secp256K1Sha256>> = key_packages.keys().copied().take(2).collect();

        let signature = FrostUtil::sign_message(&key_packages, &pub_key_package, message, &signers).unwrap();

        // Verify the signature
        let result = FrostUtil::verify_signature(
            &pub_key_package,
            message,
            &signature,
        ).unwrap();

        assert!(result);
    }

    #[test]
    fn test_not_enough_signers() {
        // Create a 2-of-3 threshold configuration
        let config = ThresholdConfig::new(2, 3);

        // Generate key packages
        let (key_packages, pub_key_package) = FrostUtil::generate_keys(&config).unwrap();

        // Try to sign with only 1 signer (below threshold)
        let message = b"Test message";
        let signers: Vec<Identifier<frost_secp256k1::Secp256K1Sha256>> = key_packages.keys().copied().take(1).collect();

        let result = FrostUtil::sign_message(&key_packages, &pub_key_package, message, &signers);

        assert!(result.is_err());
    }

    #[test]
    fn test_coordinator() {
        // Create a 2-of-3 threshold configuration
        let config = ThresholdConfig::new(2, 3);

        // Generate key packages
        let (key_packages, pub_key_package) = FrostUtil::generate_keys(&config).unwrap();

        // Create coordinator
        let mut coordinator = FrostCoordinator::new(config);
        coordinator.set_public_key_package(pub_key_package.clone());

        // Add participants
        for (id, key_package) in &key_packages {
            let participant = Participant::with_key_package(*id, key_package.clone());
            coordinator.add_participant(participant);
        }

        // Start signing session
        let message = b"Test message".to_vec();
        coordinator.start_signing(message.clone()).unwrap();

        // Get participant IDs
        let participant_ids: Vec<Identifier<frost_secp256k1::Secp256K1Sha256>> = coordinator.get_participants().keys().copied().take(2).collect();

        // Round 1: Generate and collect commitments
        let mut nonces_map = HashMap::new();

        for &id in &participant_ids {
            let (commitments, nonces) = coordinator.generate_commitments(id).unwrap();
            coordinator.add_commitments(id, commitments).unwrap();
            nonces_map.insert(id, nonces);
        }

        // Create signing package
        let signing_package = coordinator.create_signing_package().unwrap();

        // Round 2: Generate signature shares
        let mut signature_shares = BTreeMap::new();

        for &id in &participant_ids {
            let nonces = nonces_map.get(&id).unwrap();
            let signature_share = coordinator.generate_signature_share(id, nonces, &signing_package).unwrap();
            signature_shares.insert(id, signature_share);
        }

        // Aggregate signatures
        let signature = coordinator.aggregate_signatures(&signing_package, &signature_shares).unwrap();

        // Verify signature
        let result = coordinator.verify_signature(&message, &signature).unwrap();
        assert!(result);
    }
}