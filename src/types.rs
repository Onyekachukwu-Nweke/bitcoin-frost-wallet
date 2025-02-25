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
