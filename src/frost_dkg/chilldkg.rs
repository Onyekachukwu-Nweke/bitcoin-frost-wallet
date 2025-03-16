#![allow(warnings)]
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ThresholdConfig};
use frost_secp256k1::{
    keys::{dkg::{part1, part2, part3, round1, round2}, KeyPackage, PublicKeyPackage},
    Identifier,
};
use rand_core::OsRng;
use std::collections::BTreeMap;

/// State for a ChillDKG round
#[derive(Debug, Clone, PartialOrd, PartialEq)]
pub enum DkgRoundState {
    /// Round 1: Generate and share commitments
    Round1,
    /// Round 2: Generate and exchange encrypted secret shares
    Round2,
    /// Round 3: Verify and finalize
    Round3,
    /// DKG complete
    Complete,
    /// DKG failed
    Failed(String),
}

/// DKG coordinator - manages the protocol but does not participate in key generation
/// Acts purely as a communication facilitator between participants
pub struct DkgCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Current round state
    pub(crate) round_state: DkgRoundState,
    /// Participants in the DKG
    participants: BTreeMap<Identifier, Participant>,
    /// Round 1 packages received from participants
    pub(crate) round1_packages: BTreeMap<Identifier, round1::Package>,
    /// Round 2 packages received from participants (sender -> recipient -> package)
    pub(crate) round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>>,
    /// Final public key package (after DKG completion)
    pub_key_package: Option<PublicKeyPackage>,
    /// Tracks which participants have finalized (submitted their public key package)
    finalized_participants: BTreeMap<Identifier, bool>,
}

impl DkgCoordinator {
    /// Create a new DKG coordinator
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            round_state: DkgRoundState::Round1,
            participants: BTreeMap::new(),
            round1_packages: BTreeMap::new(),
            round2_packages: BTreeMap::new(),
            pub_key_package: None,
            finalized_participants: BTreeMap::new(),
        }
    }

    /// Add a participant to the DKG
    pub fn add_participant(&mut self, participant: Participant) -> Result<()> {
        if self.participants.len() >= self.config.total_participants as usize {
            return Err(FrostWalletError::DkgError("Maximum number of participants reached".to_string()));
        }

        self.participants.insert(participant.id, participant.clone());
        self.finalized_participants.insert(participant.id, false);
        Ok(())
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
    pub fn get_participants(&self) -> &BTreeMap<Identifier, Participant> {
        &self.participants
    }

    /// Get current round state
    pub fn get_round_state(&self) -> &DkgRoundState {
        &self.round_state
    }

    /// Get the threshold configuration
    pub fn get_config(&self) -> &ThresholdConfig {
        &self.config
    }

    /// Start the DKG process
    pub fn start(&mut self) -> Result<()> {
        // Verify we have enough participants
        if self.participants.len() < self.config.threshold as usize {
            return Err(FrostWalletError::DkgError(format!(
                "Not enough participants: have {}, need at least {}",
                self.participants.len(),
                self.config.threshold
            )));
        }

        // Reset state
        self.round1_packages.clear();
        self.round2_packages.clear();
        self.pub_key_package = None;

        // Reset finalization status
        for (_, status) in self.finalized_participants.iter_mut() {
            *status = false;
        }

        // Set initial state to Round 1
        self.round_state = DkgRoundState::Round1;

        Ok(())
    }

    /// Process a round 1 package from a participant
    pub fn process_round1_package(&mut self, participant_id: Identifier, package: round1::Package) -> Result<()> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 1 package in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Store the package
        self.round1_packages.insert(participant_id, package);

        // Check if we have all round 1 packages
        if self.round1_packages.len() == self.participants.len() {
            // Advance to Round 2
            self.round_state = DkgRoundState::Round2;
        }

        Ok(())
    }

    /// Process round 2 packages from a participant
    pub fn process_round2_package(&mut self, participant_id: Identifier, recipient_id: Identifier, package: round2::Package) -> Result<()> {
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 2 package in current state: {:?}",
                self.round_state
            ))),
        }

        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        if !self.participants.contains_key(&recipient_id) {
            return Err(FrostWalletError::ParticipantNotFound(recipient_id));
        }

        // Create entry for this sender if it doesn't exist
        if !self.round2_packages.contains_key(&participant_id) {
            self.round2_packages.insert(participant_id, BTreeMap::new());
        }

        // Store the package
        self.round2_packages.get_mut(&participant_id).unwrap().insert(recipient_id, package);

        // Check if we have all round 2 packages
        let expected_packages = self.participants.len() * (self.participants.len() - 1);
        let mut current_packages = 0;

        for (_, packages) in &self.round2_packages {
            current_packages += packages.len();
        }

        if current_packages == expected_packages {
            self.round_state = DkgRoundState::Round3;
        }

        Ok(())
    }

    /// Process a finalized public key package from a participant
    pub fn process_public_key_package(&mut self, participant_id: Identifier, public_key_package: PublicKeyPackage) -> Result<()> {
        // We should accept public key packages in either Round3 or Complete state
        // as participants might submit them at different times
        match self.round_state {
            DkgRoundState::Round3 | DkgRoundState::Complete => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process public key package in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Store the first public key package we receive
        if self.pub_key_package.is_none() {
            self.pub_key_package = Some(public_key_package.clone());
        } else {
            // Verify that the public key package matches previously submitted ones
            let existing_pk = self.pub_key_package.as_ref().unwrap().verifying_key();
            let new_pk = public_key_package.verifying_key();

            if existing_pk != new_pk {
                return Err(FrostWalletError::VerificationError(
                    "Public key package doesn't match previously submitted ones".to_string()
                ));
            }
        }

        // Mark this participant as finalized
        if let Some(status) = self.finalized_participants.get_mut(&participant_id) {
            *status = true;
        }

        // Check if all participants have finalized
        let all_finalized = self.finalized_participants.values().all(|&status| status);

        if all_finalized {
            self.round_state = DkgRoundState::Complete;
        }

        Ok(())
    }

    /// Check if a participant has finalized
    pub fn is_participant_finalized(&self, participant_id: Identifier) -> bool {
        self.finalized_participants.get(&participant_id).copied().unwrap_or(false)
    }

    /// Check if all participants have finalized
    pub fn all_participants_finalized(&self) -> bool {
        self.finalized_participants.values().all(|&status| status)
    }

    /// Get round 1 package for a specific participant
    pub fn get_round1_package(&self, participant_id: Identifier) -> Result<&round1::Package> {
        self.round1_packages.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError(format!(
                "No round 1 package available for participant {:?}",
                participant_id
            )))
    }

    /// Get round 2 packages intended for a specific recipient
    pub fn get_round2_packages_for_recipient(&self, recipient_id: Identifier) -> Result<BTreeMap<Identifier, round2::Package>> {
        let mut result = BTreeMap::new();

        for (sender_id, packages) in &self.round2_packages {
            if let Some(package) = packages.get(&recipient_id) {
                result.insert(*sender_id, package.clone());
            }
        }

        if result.is_empty() {
            return Err(FrostWalletError::DkgError(format!(
                "No round 2 packages available for recipient {:?}",
                recipient_id
            )));
        }

        Ok(result)
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> Result<PublicKeyPackage> {
        self.pub_key_package.clone()
            .ok_or_else(|| FrostWalletError::DkgError("DKG not yet complete".to_string()))
    }
}

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
    pub fn generate_round1(&mut self) -> Result<round1::Package> {
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
    pub fn generate_round2(&mut self, round1_packages: &BTreeMap<Identifier, round1::Package>) -> Result<BTreeMap<Identifier, round2::Package>> {
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
                    round2_packages: &BTreeMap<Identifier, round2::Package>) -> Result<(KeyPackage, PublicKeyPackage)> {
        let round2_secret = self.round2_secret.take()
            .ok_or_else(|| FrostWalletError::DkgError("No round 2 secret available".to_string()))?;

        // Filter round1 packages to exclude own package
        let other_round1_packages: BTreeMap<Identifier, round1::Package> = round1_packages
            .iter()
            .filter(|(id, _)| **id != self.id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

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
    pub fn get_key_package(&self) -> Result<KeyPackage> {
        self.key_package.clone()
            .ok_or_else(|| FrostWalletError::DkgError("DKG not yet complete".to_string()))
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> Result<PublicKeyPackage> {
        self.pub_key_package.clone()
            .ok_or_else(|| FrostWalletError::DkgError("DKG not yet complete".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::Identifier;

    #[test]
    fn test_dkg_with_separate_coordinator_and_participants() {
        // Create a coordinator and participants
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = DkgCoordinator::new(config.clone());

        // Create participants
        let mut participants = BTreeMap::new();
        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            let participant = Participant::new(id);
            coordinator.add_participant(participant).unwrap();

            participants.insert(id, DkgParticipant::new(id, config.clone()));
        }

        // Start DKG
        coordinator.start().unwrap();
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round1));

        // Round 1: Generate and share commitments
        let mut round1_packages = BTreeMap::new();
        for (&id, participant) in &mut participants {
            let package = participant.generate_round1().unwrap();
            round1_packages.insert(id, package.clone());
            coordinator.process_round1_package(id, package).unwrap();
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round2));

        // Round 2: Generate and exchange encrypted key shares
        for (&sender_id, participant) in &mut participants {
            let packages = participant.generate_round2(&round1_packages).unwrap();

            // Send each package to the coordinator
            for (recipient_id, package) in &packages {
                coordinator.process_round2_package(sender_id, *recipient_id, package.clone()).unwrap();
            }
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round3));

        // Round 3: Finalize and verify
        let mut pub_key_packages = Vec::new();

        for (&id, participant) in &mut participants {
            // Get round 2 packages intended for this participant
            let round2_packages_for_me = coordinator.get_round2_packages_for_recipient(id).unwrap();

            // Finalize
            let (key_package, public_key_package) = participant.finalize(
                &round1_packages,
                &round2_packages_for_me
            ).unwrap();

            // Share public key package with coordinator
            coordinator.process_public_key_package(id, public_key_package.clone()).unwrap();
            pub_key_packages.push(public_key_package);
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Complete));

        // Verify all participants have the same public key
        let first_pub_key = pub_key_packages[0].verifying_key();
        for pkg in &pub_key_packages[1..] {
            assert_eq!(first_pub_key, pkg.verifying_key());
        }

        // Verify coordinator has the same public key
        let coordinator_pub_key = coordinator.get_public_key_package().unwrap();
        assert_eq!(first_pub_key, coordinator_pub_key.verifying_key());
    }
}