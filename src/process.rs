#![allow(warnings)]
use crate::error::{FrostWalletError, Result};
use crate::types::{IpcMessage, Participant, ProcessState};
use frost_core::Identifier;
use serde::{Serialize, de::DeserializeOwned};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child as TokioChild, Command as TokioCommand};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use std::io::Write;

/// Maximum message size in bytes (10MB)
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Process handle for participant
pub struct ParticipantProcess {
    /// Participant identifier
    pub id: Identifier<frost_secp256k1::Secp256K1Sha256>,
    /// Process handle
    process: Arc<Mutex<Option<TokioChild>>>,
    /// Sender for messages to the process
    tx: Sender<Vec<u8>>,
    /// Receiver for messages from the process
    rx: Receiver<Vec<u8>>,
    /// Current process state
    state: Arc<Mutex<ProcessState>>,
}

impl ParticipantProcess {
    /// Spawn a new participant process
    pub async fn spawn(
        id: Identifier<frost_secp256k1::Secp256K1Sha256>,
        executable: PathBuf,
        args: Vec<String>,
    ) -> Result<Self> {
        // Create channels for IPC
        let (parent_tx, mut child_rx) = channel::<Vec<u8>>(100);
        let (mut child_tx, parent_rx) = channel::<Vec<u8>>(100);

        // Spawn child process
        let mut child = TokioCommand::new(executable)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| FrostWalletError::ProcessError(format!("Failed to spawn process: {}", e)))?;

        // Get stdin/stdout handles
        let mut stdin = child.stdin.take()
            .ok_or_else(|| FrostWalletError::ProcessError("Failed to open stdin".to_string()))?;
        let mut stdout = child.stdout.take()
            .ok_or_else(|| FrostWalletError::ProcessError("Failed to open stdout".to_string()))?;

        // Spawn tasks to handle stdin/stdout communication
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];

            loop {
                match stdout.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        if let Err(e) = child_tx.send(buffer[..n].to_vec()).await {
                            eprintln!("Failed to send message to parent: {}", e);
                            break;
                        }
                    }
                    Ok(_) => break, // EOF
                    Err(e) => {
                        eprintln!("Error reading from child stdout: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(msg) = child_rx.recv().await {
                if let Err(e) = stdin.write_all(&msg).await {
                    eprintln!("Failed to write to child stdin: {}", e);
                    break;
                }

                if let Err(e) = stdin.flush().await {
                    eprintln!("Failed to flush child stdin: {}", e);
                    break;
                }
            }
        });

        Ok(Self {
            id,
            process: Arc::new(Mutex::new(Some(child))),
            tx: parent_tx,
            rx: parent_rx,
            state: Arc::new(Mutex::new(ProcessState::Initializing)),
        })
    }

    /// Send a message to the participant process
    pub async fn send<T: Serialize>(&self, message: T) -> Result<()> {
        let serialized = bincode::serialize(&message)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to serialize message: {}", e)))?;

        if serialized.len() > MAX_MESSAGE_SIZE {
            return Err(FrostWalletError::IpcError(format!(
                "Message too large: {} bytes (max {})",
                serialized.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        self.tx.send(serialized).await
            .map_err(|e| FrostWalletError::IpcError(format!("Failed to send message: {}", e)))?;

        Ok(())
    }

    /// Receive a message from the participant process
    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let data = self.rx.recv().await
            .ok_or_else(|| FrostWalletError::IpcError("Channel closed".to_string()))?;

        bincode::deserialize(&data)
            .map_err(|e| FrostWalletError::SerializationError(format!("Failed to deserialize message: {}", e)))
    }

    /// Update the process state
    pub fn update_state(&self, state: ProcessState) {
        let mut current = self.state.lock().unwrap();
        *current = state;
    }

    /// Get the current process state
    pub fn get_state(&self) -> ProcessState {
        self.state.lock().unwrap().clone()
    }

    /// Check if the process is still running
    pub fn is_running(&self) -> bool {
        let mut process_guard = self.process.lock().unwrap();

        match &mut *process_guard {
            Some(child) => {
                // try_wait() requires a mutable reference
                match child.try_wait() {
                    Ok(None) => true,    // No exit status = still running
                    Ok(Some(_)) => false, // Has exit status = not running
                    Err(_) => false,     // Error = assume not running
                }
            },
            None => false, // No process = not running
        }
    }

    /// Terminate the process
    pub async fn terminate(&self) -> Result<()> {
        let mut process = self.process.lock().unwrap();

        if let Some(mut child) = process.take() {
            let _ = child.kill().await;
        }

        Ok(())
    }
}

impl Drop for ParticipantProcess {
    fn drop(&mut self) {
        let mut process = self.process.lock().unwrap();

        // Changed to mutable
        if let Some(mut child) = process.take() {
            let _ = child.start_kill();
        }
    }
}

/// Participant process coordinator
pub struct ProcessCoordinator {
    /// Participant processes
    processes: Vec<ParticipantProcess>,
    /// Local participant ID
    local_id: Option<Identifier<frost_secp256k1::Secp256K1Sha256>>,
}

impl ProcessCoordinator {
    /// Create a new process coordinator
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            local_id: None,
        }
    }

    /// Set the local participant ID
    pub fn set_local_id(&mut self, id: Identifier<frost_secp256k1::Secp256K1Sha256>) {
        self.local_id = Some(id);
    }

    /// Add a participant process
    pub fn add_process(&mut self, process: ParticipantProcess) {
        self.processes.push(process);
    }

    /// Get a participant process by ID
    pub fn get_process(&mut self, id: Identifier<frost_secp256k1::Secp256K1Sha256>) -> Option<&mut ParticipantProcess> {
        self.processes.iter_mut().find(|p| p.id == id)
    }

    /// Broadcast a message to all participant processes
    pub async fn broadcast<T: Serialize + Clone>(&self, message: T) -> Result<()> {
        for process in &self.processes {
            process.send(message.clone()).await?;
        }

        Ok(())
    }

    /// Terminate all processes
    pub async fn terminate_all(&self) -> Result<()> {
        for process in &self.processes {
            process.terminate().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_core::{Identifier, Scalar};
    use std::path::PathBuf;
    use tempfile::tempdir;
    use tokio_test::block_on;

    #[test]
    fn test_process_lifecycle() {
        // Create a more persistent temporary directory
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path().to_owned();

        // Create mock executable with absolute path
        let executable = create_mock_executable(&temp_path);
        println!("Created executable at: {:?}", executable);

        // Make sure the file exists
        assert!(executable.exists(), "Mock executable does not exist");

        // Create a valid identifier
        let id = Identifier::<frost_secp256k1::Secp256K1Sha256>::try_from(1).unwrap();

        block_on(async {
            // Spawn a participant process
            let mut process = ParticipantProcess::spawn(
                id,
                executable,
                vec![],
            ).await.unwrap();

            // Check initial state
            assert!(matches!(process.get_state(), ProcessState::Initializing));

            // Update state
            process.update_state(ProcessState::ReadyForDkg);
            assert!(matches!(process.get_state(), ProcessState::ReadyForDkg));

            // Verify the process is running
            assert!(process.is_running());

            // Terminate the process
            process.terminate().await.unwrap();

            // Verify the process is no longer running
            assert!(!process.is_running());
        });

        // Keep the temp_dir variable alive until the end of the test
        drop(temp_dir);
    }

    // Modified helper to create a mock executable for testing
    fn create_mock_executable(dir_path: &PathBuf) -> PathBuf {
        // Use the provided directory path
        let path = dir_path.join("mock_executable");

        #[cfg(target_os = "windows")]
        {
            let path = path.with_extension("exe");

            // For Windows, create a simple batch file
            let script = "@echo off\n:loop\nset /p line=\necho %line%\ngoto loop";
            std::fs::write(&path, script).unwrap();

            path
        }

        #[cfg(not(target_os = "windows"))]
        {
            // For Unix, create a simple shell script
            let script = "#!/bin/sh\nwhile read line; do\n  echo \"$line\"\ndone\n";
            std::fs::write(&path, script).unwrap();

            // Make it executable
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();

            path
        }
    }
}

