use bitcoin::{Address, Network, Transaction};
use frost_core::{Identifier, Scalar};
use frost_secp256k1::{
    keys::{KeyPackage, PublicKeyPackage, SecretShare, SigningShare},
    Signature
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the threshold parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of participants required to sign
    pub threshold: u16,
    /// Total number of participants
    pub total_participants: u16,
}

impl ThresholdConfig {
    pub fn new(threshold: u16, total_participants: u16) -> Self {
        Self {
            threshold,
            total_participants,
        }
    }

    pub fn validate(&self) -> bool {
        self.threshold > 0 && self.threshold <= self.total_participants
    }
}

/// Participant identifier with local state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Unique participant identifier
    pub id: Identifier<frost_secp256k1::Secp256K1Sha256>,
    /// Key material (None if this is a remote participant)
    pub key_package: Option<KeyPackage>,
    /// Process ID if running in a separate process
    pub process_id: Option<u32>,
}

impl Participant {
    pub fn new(id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Self {
        Self {
            id,
            key_package: None,
            process_id: None,
        }
    }

    pub fn with_key_package(id: Identifier<frost_secp256k1::Secp256K1Sha256>, key_package: KeyPackage) -> Self {
        Self {
            id,
            key_package: Some(key_package),
            process_id: None,
        }
    }

    pub fn is_local(&self) -> bool {
        self.key_package.is_some()
    }
}

/// Message types for inter-process communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// DKG-related messages
    Dkg(DkgMessage),
    /// Signing-related messages
    Signing(SigningMessage),
    /// Error message
    Error(String),
    /// Success message with optional data
    Success(Option<Vec<u8>>),
}

/// Messages for distributed key generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DkgMessage {
    /// Start a new DKG round
    Start(ThresholdConfig),
    /// Share a commitment with all participants
    Commitment(Identifier<frost_secp256k1::Secp256K1Sha256>, Vec<u8>),
    /// Share a key with a specific participant
    KeyShare(Identifier<frost_secp256k1::Secp256K1Sha256>, Identifier<frost_secp256k1::Secp256K1Sha256>, Vec<u8>),
    /// Finish the DKG process
    Finish,
}

/// Messages for distributed signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningMessage {
    /// Start a new signing round for a message
    Start {
        /// The message to sign
        message: Vec<u8>,
        /// Participants involved in signing
        signers: Vec<Identifier<frost_secp256k1::Secp256K1Sha256>>,
    },
    /// Nonce/commitment for round 1
    Round1 {
        /// Participant ID
        id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        /// Commitment data
        commitment: Vec<u8>,
    },
    /// Signature share for round 2
    Round2 {
        /// Participant ID
        id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        /// Signature share data
        signature_share: Vec<u8>,
    },
    /// Finalize signing by aggregating signature shares
    Finalize {
        /// All signature shares to aggregate
        shares: Vec<(Identifier<frost_secp256k1::Secp256K1Sha256>, Vec<u8>)>,
    },
}

/// Wallet configuration and state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Threshold parameters
    pub threshold: ThresholdConfig,
    /// Network (mainnet, testnet, etc.)
    pub network: Network,
    /// Storage location for keys and data
    pub storage_path: Option<PathBuf>,
    /// Public key package
    pub public_key_package: Option<PublicKeyPackage>,
}

impl WalletConfig {
    pub fn new(threshold: u16, total_participants: u16, network: Network) -> Self {
        Self {
            threshold: ThresholdConfig::new(threshold, total_participants),
            network,
            storage_path: None,
            public_key_package: None,
        }
    }

    pub fn with_storage(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(path);
        self
    }
}

/// Process state for a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessState {
    /// Process is initializing
    Initializing,
    /// Process is ready for DKG
    ReadyForDkg,
    /// DKG is in progress
    DkgInProgress {
        /// Current round number
        round: u8,
    },
    /// DKG is complete
    DkgComplete,
    /// Process is ready for signing
    ReadyForSigning,
    /// Signing is in progress
    SigningInProgress {
        /// Current round number
        round: u8,
    },
    /// Process has encountered an error
    Error(String),
}

/// Transaction signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    /// Transaction to sign
    pub transaction: Transaction,
    /// Input index to sign
    pub input_index: usize,
    /// Input value in satoshis
    pub input_value: u64,
    /// Participants that will sign
    pub signers: Vec<Identifier<frost_secp256k1::Secp256K1Sha256>>,
}

/// Transaction signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    /// Final signature
    pub signature: Signature,
    /// Public key that can verify this signature
    pub public_key: Vec<u8>,
}