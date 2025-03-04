use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{DkgMessage, ThresholdConfig, Participant};
use frost_secp256k1::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage, SecretShare, dkg::{self, round1, round2, part1, part2, part3}},
};
use rand_core::OsRng;
use std::collections::{BTreeMap};

/// State for a ChillDKG round
#[derive(Debug, Clone)]
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
    round2_packages: BTreeMap<Identifier, round2::Package>,
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
        if participant_id == self.participants.iter().next().unwrap().0.clone() {
            self.local_round1_secret.insert(participant_id, round1_secret);
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

    /// Generate round 2 package for the specified participant
    pub fn generate_round2(&mut self, participant_id: Identifier) -> Result<round2::Package> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot generate round 2 package in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Get the local round 1 secret
        let round1_secret = self.local_round1_secret.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError("No local round 1 secret".to_string()))?.clone();

        println!("Found local round1 secret for {:?}", round1_secret);

        // Ensure we have the right number of round1 packages
        if self.round1_packages.len() != self.participants.len() {
            return Err(FrostWalletError::DkgError(format!(
                "Not enough round 1 packages: have {}, need {}",
                self.round1_packages.len(),
                self.participants.len()
            )));
        }

        // println!("round1_secret:{}, participants:{}", self.round1_packages.len(), self.participants.len());

        // println!("{:?}", round1_secret);

        // Get all round 1 packages
        // let round1_packages: BTreeMap<Identifier, round1::Package> = self.round1_packages.clone();
        //
        // print

        println!("I am here");

        // println!("Number of round1 packages: {}", self.round1_packages.len());
        // println!("Expected participants: {}", self.participants.len());
        // println!("Round1 packages: {:?}", self.round1_packages.values());
        // println!("Current participant: {:?}", participant_id);
        // println!("Round1 secret exists: {:?}", round1_secret);

        let round1_packages: BTreeMap<Identifier, round1::Package> = self.round1_packages
            .iter()
            .filter(|(id, _)| **id != participant_id)  // Only include other participants' packages
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();

        // println!("Round1 packages content:");
        // for (id, pkg) in &round1_packages {
        //     println!("ID: {:?}", id);
        //     println!("Min signers: {}", round1_secret.min_signers());
        //     println!("Max signers: {}", round1_secret.max_signers());
        //     println!("Package commitment values: {:?}", pkg.commitment());
        // }

        // println!("Round1 secret details:");
        // println!("Identifier: {:?}", round1_secret.identifier());
        // println!("Min signers from secret: {}", round1_secret.min_signers());
        // println!("Max signers from secret: {}", round1_secret.max_signers());

        // Generate Round 2 data
        let (round2_secret, round2_packages) = part2(
            round1_secret,
            &round1_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("Round 2 generation error: {}", e)))?;

        println!("I am here 2");

        println!("Round2 Packages: {:?}", round2_packages);

        self.local_round2_secret.insert(participant_id, round2_secret);

        // Store the package
        self.round2_packages = round2_packages.clone();

        let round2_package = round2_packages.get(&participant_id).ok_or_else(|| {
            FrostWalletError::DkgError("Round 2 package not found".to_string())
        }).unwrap().clone();

        Ok(round2_package)
    }

    /// Process a round 2 package from a participant
    pub fn process_round2_package(&mut self, participant_id: Identifier, package: round2::Package) -> Result<()> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 2 package in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Store the package
        self.round2_packages.insert(participant_id, package);

        // Check if we have all round 2 packages
        if self.round2_packages.len() == self.participants.len() {
            // Advance to Round 3
            self.round_state = DkgRoundState::Round3;
        }

        Ok(())
    }

    /// Finalize the DKG process and create key packages
    pub fn finalize(&mut self, participant_id: Identifier) -> Result<KeyPackage> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round3 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot finalize DKG in current state: {:?}",
                self.round_state
            ))),
        }

        // Get the local round 2 secret
        let round2_secret = self.local_round2_secret.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError("No local round 2 secret".to_string()))?;

        // Get all round 1 packages
        let round1_packages: BTreeMap<Identifier, round1::Package> = self.round1_packages.clone().into_iter().collect();

        // Get all round 2 packages
        let round2_packages: BTreeMap<Identifier, round2::Package> = self.round2_packages.clone().into_iter().collect();

        // Verify and finalize
        let (key_package, public_key_package) = part3(
            round2_secret,
            &round1_packages,
            &round2_packages,
        ).map_err(|e| FrostWalletError::DkgError(format!("DKG finalization error: {}", e)))?;

        // Store the public key package
        if self.pub_key_package.is_none() {
            self.pub_key_package = Some(BTreeMap::new());
        }

        // Add the public key package to the map
        self.pub_key_package.as_mut().unwrap().insert(participant_id, public_key_package.clone());

        // self.pub_key_package = Some(public_key_package);

        // Create the key packages map if it doesn't exist
        if self.key_packages.is_none() {
            self.key_packages = Some(BTreeMap::new());
        }

        // Add the key package to the map
        self.key_packages.as_mut().unwrap().insert(participant_id, key_package.clone());

        // Set state to Complete
        self.round_state = DkgRoundState::Complete;

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
        // Create a 2-of-3 threshold configuration
        let config = ThresholdConfig::new(2, 3);

        // Create coordinator
        let mut coordinator = DkgCoordinator::new(config);

        // Add participants
        for i in 1..=3 {
            let participant = Participant::new(Identifier::try_from(i as u16).unwrap());
            coordinator.add_participant(participant).unwrap();
        }

        // Start DKG
        coordinator.start().unwrap();

        // Verify initial state
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round1));

        // Generate and process round 1 packages
        for i in 1..=3 {
            let id = Identifier::from(Identifier::try_from(i as u16).unwrap());
            let package = coordinator.generate_round1(id).unwrap();
            coordinator.process_round1_package(id, package).unwrap();
        }

        // Verify state advanced to Round 2
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round2));

        // Generate and process round 2 packages
        for i in 1..=3 {
            let id = Identifier::from(Identifier::try_from(i as u16).unwrap());
            let package = coordinator.generate_round2(id).unwrap();
            coordinator.process_round2_package(id, package).unwrap();
        }

        // Verify state advanced to Round 3
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Round3));

        // Finalize DKG for each participant
        for i in 1..=3 {
            let id = Identifier::from(Identifier::try_from(i as u16).unwrap());
            coordinator.finalize(id).unwrap();
        }

        // Verify state is Complete
        assert!(matches!(coordinator.get_round_state(), DkgRoundState::Complete));

        // Get the public key package
        let pub_key_package = coordinator.get_public_key_package().unwrap();

        // Verify key packages are available
        for i in 1..=3 {
            let id = Identifier::from(Identifier::try_from(i as u16).unwrap());
            let key_package = coordinator.get_key_package(id).unwrap();
            assert_eq!(key_package.verifying_key(), pub_key_package.verifying_key());
        }
    }
}


