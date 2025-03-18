use std::collections::BTreeMap;
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{part1, part2, part3, round1, round2};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use rand_core::OsRng;
use crate::common::errors::FrostWalletError;
use crate::common::types::ThresholdConfig;

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