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

/// DKG coordinator using frost_secp256k1::keys::frost_dkg
pub struct DkgCoordinator {
    /// Threshold configuration
    config: ThresholdConfig,
    /// Current round state
    round_state: DkgRoundState,
    /// Participants in the DKG
    participants: BTreeMap<Identifier, Participant>,
    /// Round 1 packages received from participants
    round1_packages: BTreeMap<Identifier, round1::Package>,
    /// Round 2 packages received from participants
    round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>>,
    /// Final key packages after DKG
    key_packages: Option<BTreeMap<Identifier, KeyPackage>>,
    /// Final public key package
    pub_key_package: Option<BTreeMap<Identifier, PublicKeyPackage>>,
    /// Local round1 secret for the local participant
    local_round1_secret: BTreeMap<Identifier, round1::SecretPackage>,
    /// Local round2 secret for the local participant
    local_round2_secret: BTreeMap<Identifier, round2::SecretPackage>,
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
            key_packages: None,
            pub_key_package: None,
            local_round1_secret: BTreeMap::new(),
            local_round2_secret: BTreeMap::new(),
        }
    }

    /// Add a participant to the DKG
    pub fn add_participant(&mut self, participant: Participant) -> Result<()> {
        if self.participants.len() >= self.config.total_participants as usize {
            return Err(FrostWalletError::DkgError("Maximum number of participants reached".to_string()));
        }

        self.participants.insert(participant.id, participant);
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
        self.key_packages = None;
        self.pub_key_package = None;
        self.local_round1_secret.clear();
        self.local_round2_secret.clear();

        // Set initial state to Round 1
        self.round_state = DkgRoundState::Round1;

        Ok(())
    }

    /// Generate round 1 package for the specified participant
    pub fn generate_round1(&mut self, participant_id: Identifier) -> Result<round1::Package> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot generate round 1 package in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Generate Round 1 data
        let (round1_secret, round1_package) = part1(
            participant_id,
            self.config.total_participants,
            self.config.threshold,
            &mut OsRng,
        ).map_err(|e| FrostWalletError::DkgError(format!("Round 1 generation error: {}", e)))?;

        // Store the secret if this is the local participant
        if self.participants.contains_key(&participant_id) {
            // println!("here");
            self.local_round1_secret.insert(participant_id, round1_secret.clone());
        }

        // // Store the package
        self.round1_packages.insert(participant_id, round1_package.clone());

        Ok(round1_package)
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

    /// Generate round 2 packages for the specified participant
    pub fn generate_round2(&mut self, participant_id: Identifier) -> Result<BTreeMap<Identifier, round2::Package>> {
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot generate round 2 package in current state: {:?}",
                self.round_state
            ))),
        }

        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        let round1_secret = self.local_round1_secret.remove(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError("No local round 1 secret".to_string()))?;

        if self.round1_packages.len() != self.participants.len() {
            return Err(FrostWalletError::DkgError(format!(
                "Not enough round 1 packages: have {}, need {}",
                self.round1_packages.len(),
                self.participants.len()
            )));
        }

        let round1_packages: BTreeMap<Identifier, round1::Package> = self.round1_packages
            .iter()
            .filter(|(id, _)| **id != participant_id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        let (round2_secret, round2_packages) = part2(
            round1_secret,
            &round1_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("Round 2 generation error: {}", e)))?;

        self.local_round2_secret.insert(participant_id, round2_secret);

        Ok(round2_packages)
    }

    /// Process round 2 packages from a participant
    pub fn process_round2_package(&mut self, participant_id: Identifier, packages: BTreeMap<Identifier, round2::Package>) -> Result<()> {
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

        self.round2_packages.insert(participant_id, packages);

        if self.round2_packages.len() == self.participants.len() {
            self.round_state = DkgRoundState::Round3;
        }

        Ok(())
    }

    /// Finalize the DKG process and create key packages
    pub fn finalize(&mut self, participant_id: Identifier) -> Result<KeyPackage> {
        match self.round_state {
            DkgRoundState::Round3 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot finalize DKG in current state: {:?}",
                self.round_state
            ))),
        }

        let round2_secret = self.local_round2_secret.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError("No local round 2 secret".to_string()))?;

        let round1_packages: BTreeMap<Identifier, round1::Package> = self.round1_packages
            .iter()
            .filter(|(id, _)| **id != participant_id)
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        // Collect round2 packages intended for this participant from all other senders
        let round2_packages: BTreeMap<Identifier, round2::Package> = self.round2_packages
            .iter()
            .filter_map(|(sender_id, packages)| {
                if *sender_id != participant_id {
                    packages.get(&participant_id).map(|pkg| (*sender_id, pkg.clone()))
                } else {
                    None
                }
            })
            .collect();

        let (key_package, public_key_package) = part3(
            round2_secret,
            &round1_packages,
            &round2_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("DKG finalization error: {}", e)))?;

        if self.pub_key_package.is_none() {
            self.pub_key_package = Some(BTreeMap::new());
        }
        self.pub_key_package.as_mut().unwrap().insert(participant_id, public_key_package.clone());

        if self.key_packages.is_none() {
            self.key_packages = Some(BTreeMap::new());
        }
        self.key_packages.as_mut().unwrap().insert(participant_id, key_package.clone());

        if self.key_packages.as_ref().unwrap().len() == self.participants.len() {
            self.round_state = DkgRoundState::Complete;
        }

        Ok(key_package)
    }

    /// Get the key package for a participant
    pub fn get_key_package(&self, participant_id: Identifier) -> Result<KeyPackage> {
        match &self.key_packages {
            Some(key_packages) => {
                key_packages.get(&participant_id)
                    .cloned()
                    .ok_or_else(|| FrostWalletError::ParticipantNotFound(participant_id))
            },
            None => Err(FrostWalletError::DkgError("DKG not yet complete".to_string())),
        }
    }

    /// Get the public key package
    pub fn get_public_key_package(&self) -> Result<PublicKeyPackage> {
        match &self.pub_key_package {
            Some(pkg) => Ok(pkg.get(&self.participants.iter().next().unwrap().0).ok_or_else(|| {
                FrostWalletError::DkgError("Public key package not found".to_string())
            }).unwrap().clone()),
            None => Err(FrostWalletError::DkgError("DKG not yet complete".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1::Identifier;

    #[test]
    fn test_dkg_coordinator() {
        let config = ThresholdConfig::new(2, 3);
        let mut coordinator = DkgCoordinator::new(config);

        for i in 1..=3 {
            let participant = Participant::new(Identifier::try_from(i as u16).unwrap());
            coordinator.add_participant(participant).unwrap();
        }

        coordinator.start().unwrap();
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round1));

        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            let package = coordinator.generate_round1(id).unwrap();
            coordinator.process_round1_package(id, package).unwrap();
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round2));

        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            let packages = coordinator.generate_round2(id).unwrap();
            coordinator.process_round2_package(id, packages).unwrap();
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round3));

        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            coordinator.finalize(id).unwrap();
        }

        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Complete));

        let pub_key_package = coordinator.get_public_key_package().unwrap();
        for i in 1..=3 {
            let id = Identifier::try_from(i as u16).unwrap();
            let key_package = coordinator.get_key_package(id).unwrap();
            assert_eq!(key_package.verifying_key(), pub_key_package.verifying_key());
        }
    }
}


