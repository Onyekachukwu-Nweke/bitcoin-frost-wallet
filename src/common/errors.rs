use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid key generation: {0}")]
    KeyGenerationError(String),

    #[error("IPC communication error: {0}")]
    IPCError(String),

    #[error("DKG protocol error: {0}")]
    DKGError(String),

    #[error("General error: {0}")]
    GeneralError(String),
}