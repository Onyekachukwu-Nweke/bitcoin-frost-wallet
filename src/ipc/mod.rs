pub mod process;
pub mod communication;

// Re-export commonly used types
pub use process::{ParticipantProcess, ProcessCoordinator};
pub use communication::{IpcChannel, IpcClient, IpcServer};