#![allow(warnings)]
use crate::common::errors::{FrostWalletError, Result};
use crate::common::types::{Participant, ProcessState};
use frost_secp256k1::Identifier;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use tokio::process::{Child as TokioChild, Command as TokioCommand};

/// Represents a participant process
pub struct ParticipantProcess {
    /// Participant ID
    pub id: Identifier,
    /// Process handle (using tokio Child)
    pub process: Option<TokioChild>,
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
        self.process = Some(process);
        self.state = ProcessState::Initializing;

        Ok(())
    }

    /// Check if the process is running
    pub async fn is_running(&mut self) -> bool {
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
    pub async fn terminate(&mut self) -> Result<()> {
        if let Some(process) = &mut self.process {
            process
                .kill()
                .await
                .map_err(|e| FrostWalletError::ProcessError(format!("Failed to terminate process: {}", e)))?;

            process
                .wait()
                .await
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
    pub async fn all_running(&mut self) -> bool {
        for process in self.processes.values_mut() {
            if !process.is_running().await {
                return false;
            }
        }
        true
    }

    /// Terminate all processes
    pub async fn terminate_all(&mut self) -> Result<()> {
        for (_, process) in self.processes.iter_mut() {
            process.terminate().await?;
        }

        Ok(())
    }
}