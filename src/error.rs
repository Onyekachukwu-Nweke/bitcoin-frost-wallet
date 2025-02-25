use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid threshold value")]
    InvalidThreshold,

    #[error("Invalid number of signing parties")]
    InvalidSigningParties,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid share")]
    InvalidShare,

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}