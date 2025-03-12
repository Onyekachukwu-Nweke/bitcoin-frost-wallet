#![allow(warnings)]
use frost_core::{Identifier, Error as FrostError};
use thiserror::Error;
use std::io;
use std::sync::mpsc;

#[derive(Error, Debug)]
pub enum FrostWalletError {
    #[error("Invalid threshold parameters: {0}")]
    InvalidThresholdParams(String),

    #[error("FROST error: {0}")]
    FrostError(String),

    #[error("DKG error: {0}")]
    DkgError(String),

    #[error("Participant not found: {:?}",  0)]
    ParticipantNotFound(Identifier<frost_secp256k1::Secp256K1Sha256>),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("IPC error: {0}")]
    IpcError(String),

    #[error("Process error: {0}")]
    ProcessError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Not enough signers: need {required}, got {provided}")]
    NotEnoughSigners { required: u16, provided: u16 },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    /// Bitcoin error
    #[error("Bitcoin error: {0}")]
    BitcoinError(String),

    /// Bitcoin RPC error
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),

    /// CapnProto RPC error
    #[error("CapnProto RPC error: {0}")]
    CapnProtoError(String),

    /// Wallet connection error
    #[error("Wallet connection error: {0}")]
    ConnectionError(String),

    /// Insufficient funds error
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),
}

impl From<mpsc::RecvError> for FrostWalletError {
    fn from(e: mpsc::RecvError) -> Self {
        Self::IpcError(format!("Channel receive error: {}", e))
    }
}

impl From<mpsc::SendError<Vec<u8>>> for FrostWalletError {
    fn from(e: mpsc::SendError<Vec<u8>>) -> Self {
        Self::IpcError(format!("Channel send error: {}", e))
    }
}

impl From<serde_json::Error> for FrostWalletError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(format!("JSON error: {}", e))
    }
}

impl From<bincode::Error> for FrostWalletError {
    fn from(e: bincode::Error) -> Self {
        Self::SerializationError(format!("Bincode error: {}", e))
    }
}

impl From<bitcoin::address::Error> for FrostWalletError {
    fn from(err: bitcoin::address::Error) -> Self {
        Self::BitcoinError(format!("Address error: {}", err))
    }
}

impl From<bitcoin::consensus::encode::Error> for FrostWalletError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Self::BitcoinError(format!("Encoding error: {}", err))
    }
}

// impl From<bitcoin::hashes::Error> for FrostWalletError {
//     fn from(err: bitcoin::hashes::Error) -> Self {
//         Self::BitcoinError(format!("Hash error: {}", err))
//     }
// }

/// Result type for the bitcoin-frost-wallet library
pub type Result<T> = std::result::Result<T, FrostWalletError>;