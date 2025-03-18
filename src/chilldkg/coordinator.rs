use std::collections::BTreeMap;
use frost_secp256k1::Identifier;
use frost_secp256k1::keys::dkg::{round1, round2};
use crate::chilldkg::chilldkg::DkgRoundState;
use crate::common::errors::FrostWalletError;
use crate::common::types::{Participant, ThresholdConfig};

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
        }
    }

    /// Add a participant to the DKG
    pub fn add_participant(&mut self, participant: Participant) -> crate::common::errors::Result<()> {
        if self.participants.len() >= self.config.total_participants as usize {
            return Err(FrostWalletError::DkgError("Maximum number of participants reached".to_string()));
        }

        self.participants.insert(participant.id, participant.clone());
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
    pub fn start(&mut self) -> crate::common::errors::Result<()> {
        if self.participants.len() < self.config.threshold as usize {
            return Err(FrostWalletError::DkgError(format!(
                "Not enough participants: have {}, need at least {}",
                self.participants.len(),
                self.config.threshold
            )));
        }

        self.round1_packages.clear();
        self.round2_packages.clear();
        self.round_state = DkgRoundState::Round1;

        Ok(())
    }

    /// Process a round 1 package from a participant
    pub fn process_round1_package(&mut self, participant_id: Identifier, package: round1::Package) -> crate::common::errors::Result<()> {
        match self.round_state {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process round 1 package in current state: {:?}",
                self.round_state
            ))),
        }

        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        self.round1_packages.insert(participant_id, package);

        if self.round1_packages.len() == self.participants.len() {
            self.round_state = DkgRoundState::Round2;
        }

        Ok(())
    }

    /// Process round 2 packages from a participant
    pub fn process_round2_package(&mut self, participant_id: Identifier, recipient_id: Identifier, package: round2::Package) -> crate::common::errors::Result<()> {
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

        if !self.round2_packages.contains_key(&participant_id) {
            self.round2_packages.insert(participant_id, BTreeMap::new());
        }

        self.round2_packages.get_mut(&participant_id).unwrap().insert(recipient_id, package);

        let expected_packages = self.participants.len() * (self.participants.len() - 1);
        let mut current_packages = 0;

        for (_, packages) in &self.round2_packages {
            current_packages += packages.len();
        }

        if current_packages == expected_packages {
            self.round_state = DkgRoundState::Round3; // Transition to Round 3, but coordinator will finish here
        }

        Ok(())
    }

    /// Get round 1 package for a specific participant
    pub fn get_round1_package(&self, participant_id: Identifier) -> crate::common::errors::Result<&round1::Package> {
        self.round1_packages.get(&participant_id)
            .ok_or_else(|| FrostWalletError::DkgError(format!(
                "No round 1 package available for participant {:?}",
                participant_id
            )))
    }

    /// Get round 2 packages intended for a specific recipient
    pub fn get_round2_packages_for_recipient(&self, recipient_id: Identifier) -> crate::common::errors::Result<BTreeMap<Identifier, round2::Package>> {
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
}