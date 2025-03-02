use crate::error::{FrostWalletError, Result};
use crate::types::{DkgMessage, ThresholdConfig, Participant};
use frost_core::{Identifier, Ciphersuite, Field, Group};
use frost_secp256k1::{
    keys::{KeyPackage, PublicKeyPackage, SecretShare},
    Secp256K1Sha256
};
use secp256k1::{SecretKey, PublicKey, Secp256k1, Scalar};
use sha2::{Sha256, Digest};
use rand_core::{OsRng};
use std::collections::{HashMap, BTreeMap};

/// State for a ChillDKG round
#[derive(Debug, Clone)]
pub enum DkgRoundState {
    /// Round 1: Generate and share commitments
    Round1,
    /// Round 2: Exchange key shares
    Round2,
    /// Round 3: Verify and finalize
    Round3,
    /// DKG complete
    Complete,
    /// DKG failed
    Failed(String),
}

/// Polynomial representation for DKG
struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Create a new random polynomial of specified degree
    pub fn random(degree: usize) -> Self {
        let coefficients = (0..=degree)
            .map(|_| <Secp256K1Sha256 as Ciphersuite>::::random(&mut OsRng))
            .collect();
        Self { coefficients }
    }

    /// Evaluate polynomial at point x (Identifier or u16)
    pub fn evaluate(&self, x: u16) -> Scalar {
        let mut result = <Secp256K1Sha256 as Ciphersuite>::F::zero();
        let x_scalar = Scalar::from_bytes([x as u8; 32]).unwrap_or(Scalar::one());

        // Compute polynomial evaluation using Horner's method:
        // f(x) = a_0 + x(a_1 + x(a_2 + ... + x*a_n))
        for coeff in self.coefficients.iter().rev() {
            result = result * x_scalar + *coeff;
        }

        result
    }

    /// Generate commitment to this polynomial (coefficients in G)
    pub fn commitment(&self) -> Vec<PublicKey> {
        let secp = Secp256k1::new();
        self.coefficients.iter()
            .map(|scalar| {
                let secret = SecretKey::from_slice(&scalar.to_bytes()).unwrap();
                PublicKey::from_secret_key(&secp, &secret)
            })
            .collect()
    }
}

/// DKG coordinator for ChillDKG implementation
pub struct DkgCoordinator {
    config: ThresholdConfig,
    round_state: DkgRoundState,
    participants: HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Participant>,
    commitments: HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Vec<u8>>,
    key_shares: HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, HashMap<Identifier<frost_secp256k1::Secp256K1Sha256>, Vec<u8>>>,
    key_packages: Option<BTreeMap<Identifier<frost_secp256k1::Secp256K1Sha256>, KeyPackage>>,
    pub_key_package: Option<PublicKeyPackage>,
}

impl DkgCoordinator {
    /// Create a new DKG coordinator
    pub fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            round_state: DkgRoundState::Round1,
            participants: HashMap::new(),
            commitments: HashMap::new(),
            key_shares: HashMap::new(),
            key_packages: None,
            pub_key_package: None,
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
        self.commitments.clear();
        self.key_shares.clear();
        self.key_packages = None;
        self.pub_key_package = None;

        // Set initial state to Round 1
        self.round_state = DkgRoundState::Round1;

        Ok(())
    }

    /// Process commitment from a participant (Round 1)
    pub fn process_commitment(&mut self, participant_id: Identifier<frost_secp256k1::Secp256K1Sha256>, commitment: Vec<u8>) -> Result<()> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round1 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process commitment in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify the participant exists
        if !self.participants.contains_key(&participant_id) {
            return Err(FrostWalletError::ParticipantNotFound(participant_id));
        }

        // Store the commitment
        self.commitments.insert(participant_id, commitment);

        // Check if we have all commitments
        if self.commitments.len() == self.participants.len() {
            // Advance to Round 2
            self.round_state = DkgRoundState::Round2;
        }

        Ok(())
    }

    /// Process key share from a participant (Round 2)
    pub fn process_key_share(
        &mut self,
        from_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        to_id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        key_share: Vec<u8>,
    ) -> Result<()> {
        // Verify we're in the right round
        match self.round_state {
            DkgRoundState::Round2 => {},
            _ => return Err(FrostWalletError::DkgError(format!(
                "Cannot process key share in current state: {:?}",
                self.round_state
            ))),
        }

        // Verify both participants exist
        if !self.participants.contains_key(&from_id) {
            return Err(FrostWalletError::ParticipantNotFound(from_id));
        }

        if !self.participants.contains_key(&to_id) {
            return Err(FrostWalletError::ParticipantNotFound(to_id));
        }

        // Store the key share
        self.key_shares
            .entry(to_id)
            .or_insert_with(HashMap::new)
            .insert(from_id, key_share);

        // Check if all key shares have been exchanged
        let all_shares_received = self.participants.keys().all(|&id| {
            let shares = self.key_shares.get(&id).unwrap_or(&HashMap::new());
            shares.len() == self.participants.len() - 1 // Exclude self-share
        });

        if all_shares_received {
            // Advance to Round 3
            self.round_state = DkgRoundState::Round3;
        }

        Ok(())
    }
}