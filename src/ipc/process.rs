use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ProcessState};
use frost_core::Identifier;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tokio::process::Command as TokioCommand;

/// Represents a participant process
pub struct ParticipantProcess {
    /// Participant ID
    pub id: Identifier,
    /// Process handle
    pub process: Option<Child>,
    /// Path to the executable
    pub binary_path: PathBuf,
    /// Process state
    pub state: ProcessState,
}

impl ParticipantProcess {
    /// Create a new participant process
    pub fn new(id: Identifier, binary_path: PathBuf) -> Self {
        Self {
            id,
            process: None,
            binary_path,
            state: ProcessState::Initializing,
        }
    }

    /// Spawn a participant process
    pub async fn spawn(&mut self, args: Vec<String>) -> Result<()> {
        // Prepare command
        let mut command = TokioCommand::new(&self.binary_path);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn process
        let process = command
            .spawn()
            .map_err(|e| FrostWalletError::ProcessError(format!("Failed to spawn process: {}", e)))?;

        // Store process handle
        let process = process.into_std();
        self.process = Some(process);
        self.state = ProcessState::Initializing;

        Ok(())
    }

    /// Check if the process is running
    pub fn is_running(&mut self) -> bool {
        if let Some(process) = &mut self.process {
            match process.try_wait() {
                Ok(None) => true,        // Process is running
                Ok(Some(_)) => false,    // Process has exited
                Err(_) => false,         // Error checking process status
            }
        } else {
            false
        }
    }

    /// Terminate the process
    pub fn terminate(&mut self) -> Result<()> {
        if let Some(process) = &mut self.process {
            process
                .kill()
                .map_err(|e| FrostWalletError::ProcessError(format!("Failed to terminate process: {}", e)))?;

            process
                .wait()
                .map_err(|e| FrostWalletError::ProcessError(format!("Failed to wait for process: {}", e)))?;

            self.process = None;
            self.state = ProcessState::Error("Process terminated".to_string());
        }

        Ok(())
    }
}

/// Coordinator for multiple participant processes
pub struct ProcessCoordinator {
    /// Map of participant ID to process
    processes: HashMap<Identifier, ParticipantProcess>,
}

impl ProcessCoordinator {
    /// Create a new process coordinator
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    /// Add a process to the coordinator
    pub fn add_process(&mut self, process: ParticipantProcess) {
        self.processes.insert(process.id, process);
    }

    /// Get a process by ID
    pub fn get_process(&self, id: Identifier) -> Option<&ParticipantProcess> {
        self.processes.get(&id)
    }

    /// Get a mutable process by ID
    pub fn get_process_mut(&mut self, id: Identifier) -> Option<&mut ParticipantProcess> {
        self.processes.get_mut(&id)
    }

    /// Get all processes
    pub fn get_processes(&self) -> &HashMap<Identifier, ParticipantProcess> {
        &self.processes
    }

    /// Check if all processes are running
    pub fn all_running(&mut self) -> bool {
        self.processes
            .values_mut()
            .all(|process| process.is_running())
    }

    /// Terminate all processes
    pub fn terminate_all(&mut self) -> Result<()> {
        for (_, process) in self.processes.iter_mut() {
            process.terminate()?;
        }

        Ok(())
    }
}