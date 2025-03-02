// src/common/types.rs

use crate::common::errors::WalletError;

/// A convenient alias for results in our wallet application.
pub type Result<T> = std::result::Result<T, WalletError>;

/// Represents the status of a DKG participant.
#[derive(Debug, Clone)]
pub enum ParticipantStatus {
    Initialized,
    ShareDistributed,
    Verified,
    Aggregated,
}

/// A simple IPC message type used for inter-process communication.
// #[derive(Debug, Clone)]
// pub struct IPCMessage {
//     /// Identifier of the sender participant.
//     pub sender: usize,
//     /// Message content as a string.
//     pub content: String,
// }
