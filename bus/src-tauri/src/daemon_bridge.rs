//! Daemon Bridge Module
//!
//! This module manages the lifecycle of the Go daemon process and provides
//! communication between the Tauri frontend and the daemon via JSON-over-stdio.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// Errors that can occur in the daemon bridge
#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("daemon not running")]
    NotRunning,
    #[error("daemon already running")]
    AlreadyRunning,
    #[error("failed to spawn daemon: {0}")]
    SpawnError(#[from] std::io::Error),
    #[error("daemon binary not found: {0}")]
    BinaryNotFound(String),
    #[error("failed to send command: {0}")]
    SendError(String),
    #[error("failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("command timeout")]
    Timeout,
    #[error("daemon error: {0}")]
    DaemonError(String),
}

/// Command sent to the daemon
#[derive(Debug, Clone, Serialize)]
pub struct DaemonCommand {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub cmd: String,
    pub id: String,
    pub params: serde_json::Value,
}

impl DaemonCommand {
    pub fn new(cmd: &str, params: serde_json::Value) -> Self {
        Self {
            msg_type: "cmd".to_string(),
            cmd: cmd.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            params,
        }
    }
}

/// Event received from the daemon
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonEvent {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub evt: String,
    #[serde(default)]
    pub id: Option<String>,
    pub data: serde_json::Value,
}

/// Pending command awaiting response
type PendingResponse = oneshot::Sender<Result<DaemonEvent, DaemonError>>;

/// The daemon bridge manages communication with the Go daemon process
pub struct DaemonBridge {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    pending_responses: Arc<RwLock<HashMap<String, PendingResponse>>>,
    event_tx: Option<mpsc::UnboundedSender<DaemonEvent>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl DaemonBridge {
    /// Create a new daemon bridge instance
    pub fn new() -> Self {
        Self {
            child: None,
            stdin: None,
            pending_responses: Arc::new(RwLock::new(HashMap::new())),
            event_tx: None,
            shutdown_tx: None,
        }
    }

    /// Find the daemon binary path
    pub fn find_daemon_binary(resource_dir: Option<PathBuf>) -> Result<PathBuf, DaemonError> {
        // Try multiple locations in order of priority
        let candidates = Self::get_binary_candidates(resource_dir);

        for path in candidates {
            if path.exists() {
                info!("Found daemon binary at: {:?}", path);
                return Ok(path);
            }
        }

        Err(DaemonError::BinaryNotFound(
            "daemon binary not found in any expected location".to_string(),
        ))
    }

    fn get_binary_candidates(resource_dir: Option<PathBuf>) -> Vec<PathBuf> {
        let mut candidates = Vec::new();

        // Platform-specific binary name
        #[cfg(target_os = "windows")]
        let binary_name = "daemon.exe";
        #[cfg(not(target_os = "windows"))]
        let binary_name = "daemon";

        // Platform-specific binary with arch suffix
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let arch_binary = "daemon-darwin-arm64";
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        let arch_binary = "daemon-darwin-amd64";
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        let arch_binary = "daemon-linux-amd64";
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        let arch_binary = "daemon-linux-arm64";
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let arch_binary = "daemon-windows-amd64.exe";
        #[cfg(not(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "windows", target_arch = "x86_64"),
        )))]
        let arch_binary = binary_name;

        // 1. Resource directory (bundled app)
        if let Some(ref res_dir) = resource_dir {
            candidates.push(res_dir.join(binary_name));
            candidates.push(res_dir.join(arch_binary));
            candidates.push(res_dir.join("binaries").join(binary_name));
            candidates.push(res_dir.join("binaries").join(arch_binary));
        }

        // 2. Current executable directory
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                candidates.push(exe_dir.join(binary_name));
                candidates.push(exe_dir.join(arch_binary));
            }
        }

        // 3. Current working directory (development)
        candidates.push(PathBuf::from(binary_name));
        candidates.push(PathBuf::from(arch_binary));

        // 4. Project dist directory (development)
        candidates.push(PathBuf::from("../../dist").join(arch_binary));
        candidates.push(PathBuf::from("../dist").join(arch_binary));
        candidates.push(PathBuf::from("dist").join(arch_binary));

        candidates
    }

    /// Spawn the daemon process
    pub fn spawn(
        &mut self,
        daemon_path: PathBuf,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) -> Result<(), DaemonError> {
        if self.child.is_some() {
            return Err(DaemonError::AlreadyRunning);
        }

        info!("Spawning daemon from: {:?}", daemon_path);

        let mut child = Command::new(&daemon_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                error!("Failed to spawn daemon: {}", e);
                DaemonError::SpawnError(e)
            })?;

        let stdin = child.stdin.take().expect("stdin should be available");
        let stdout = child.stdout.take().expect("stdout should be available");
        let stderr = child.stderr.take().expect("stderr should be available");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);
        self.stdin = Some(stdin);
        self.event_tx = Some(event_tx.clone());
        self.child = Some(child);

        // Spawn stdout reader task
        let pending = Arc::clone(&self.pending_responses);
        let event_tx_clone = event_tx.clone();
        std::thread::spawn(move || {
            Self::read_stdout(stdout, pending, event_tx_clone);
        });

        // Spawn stderr reader task (for logging)
        std::thread::spawn(move || {
            Self::read_stderr(stderr);
        });

        // Spawn shutdown monitor
        let pending_shutdown = Arc::clone(&self.pending_responses);
        std::thread::spawn(move || {
            let _ = shutdown_rx;
            // When shutdown_rx is dropped, this will complete
            // Clean up pending responses
            if let Ok(mut pending) = pending_shutdown.try_write() {
                for (_, sender) in pending.drain() {
                    let _ = sender.send(Err(DaemonError::NotRunning));
                }
            }
        });

        info!("Daemon spawned successfully");
        Ok(())
    }

    fn read_stdout(
        stdout: ChildStdout,
        pending: Arc<RwLock<HashMap<String, PendingResponse>>>,
        event_tx: mpsc::UnboundedSender<DaemonEvent>,
    ) {
        let reader = BufReader::new(stdout);

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if line.is_empty() {
                        continue;
                    }

                    debug!("Daemon stdout: {}", line);

                    match serde_json::from_str::<DaemonEvent>(&line) {
                        Ok(event) => {
                            // Check if this is a response to a pending command
                            if let Some(id) = &event.id {
                                if !id.is_empty() {
                                    // Use blocking approach for thread
                                    let sender = {
                                        if let Ok(mut pending_guard) = pending.try_write() {
                                            pending_guard.remove(id)
                                        } else {
                                            None
                                        }
                                    };

                                    if let Some(sender) = sender {
                                        let _ = sender.send(Ok(event.clone()));
                                    }
                                }
                            }

                            // Always forward events to the event channel
                            if event_tx.send(event).is_err() {
                                warn!("Event channel closed");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse daemon event: {} - line: {}", e, line);
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading daemon stdout: {}", e);
                    break;
                }
            }
        }

        info!("Daemon stdout reader exiting");
    }

    fn read_stderr(stderr: std::process::ChildStderr) {
        let reader = BufReader::new(stderr);

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if !line.is_empty() {
                        debug!("Daemon stderr: {}", line);
                    }
                }
                Err(e) => {
                    error!("Error reading daemon stderr: {}", e);
                    break;
                }
            }
        }

        info!("Daemon stderr reader exiting");
    }

    /// Send a command to the daemon
    pub fn send_command(&mut self, command: DaemonCommand) -> Result<String, DaemonError> {
        let stdin = self.stdin.as_mut().ok_or(DaemonError::NotRunning)?;

        let json = serde_json::to_string(&command)?;
        debug!("Sending command: {}", json);

        writeln!(stdin, "{}", json)
            .map_err(|e| DaemonError::SendError(format!("failed to write to stdin: {}", e)))?;
        stdin
            .flush()
            .map_err(|e| DaemonError::SendError(format!("failed to flush stdin: {}", e)))?;

        Ok(command.id)
    }

    /// Send a command and wait for a response
    pub async fn send_command_async(
        bridge: Arc<Mutex<DaemonBridge>>,
        command: DaemonCommand,
    ) -> Result<DaemonEvent, DaemonError> {
        let (tx, rx) = oneshot::channel();
        let cmd_id = command.id.clone();

        {
            let mut bridge_guard = bridge.lock().await;

            // Register pending response
            {
                let mut pending = bridge_guard.pending_responses.write().await;
                pending.insert(cmd_id.clone(), tx);
            }

            // Send the command
            bridge_guard.send_command(command)?;
        }

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(DaemonError::SendError("response channel closed".to_string())),
            Err(_) => {
                // Remove from pending on timeout
                let bridge_guard = bridge.lock().await;
                let mut pending = bridge_guard.pending_responses.write().await;
                pending.remove(&cmd_id);
                Err(DaemonError::Timeout)
            }
        }
    }

    /// Check if the daemon is running
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // Process has exited
                    self.child = None;
                    self.stdin = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Stop the daemon
    pub fn stop(&mut self) -> Result<(), DaemonError> {
        // Send shutdown command first
        if self.stdin.is_some() {
            let shutdown_cmd = DaemonCommand::new("shutdown", serde_json::json!({}));
            let _ = self.send_command(shutdown_cmd);
        }

        // Give the daemon a moment to shut down gracefully
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Force kill if still running
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Clean up
        self.child = None;
        self.stdin = None;
        self.shutdown_tx = None;

        info!("Daemon stopped");
        Ok(())
    }
}

impl Default for DaemonBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DaemonBridge {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Thread-safe wrapper for the daemon bridge
pub type SharedDaemonBridge = Arc<Mutex<DaemonBridge>>;

/// Create a new shared daemon bridge
pub fn create_shared_bridge() -> SharedDaemonBridge {
    Arc::new(Mutex::new(DaemonBridge::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_command_serialization() {
        let cmd = DaemonCommand::new("dial", serde_json::json!({"addr": "127.0.0.1:9000"}));
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"cmd\""));
        assert!(json.contains("\"cmd\":\"dial\""));
    }

    #[test]
    fn test_daemon_event_deserialization() {
        let json = r#"{"type":"evt","evt":"ready","data":{"version":"1.0.0"}}"#;
        let event: DaemonEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.msg_type, "evt");
        assert_eq!(event.evt, "ready");
    }
}
