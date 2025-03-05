pub mod capnp_gen;
pub mod process;
pub mod communication;
// mod capnp_gen;
// mod process;
// mod communication;

// Re-export commonly used types
pub use process::{ParticipantProcess, ProcessCoordinator};
pub use communication::{IpcClient, IpcServer, IpcChannel};