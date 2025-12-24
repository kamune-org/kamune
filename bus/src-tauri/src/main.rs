//! Kamune Desktop Application
//!
//! This is the main entry point for the Tauri application that provides
//! a GUI for the kamune secure messaging protocol.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod daemon_bridge;

use daemon_bridge::{create_shared_bridge, DaemonBridge, DaemonCommand, DaemonEvent, SharedDaemonBridge};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

/// Global daemon bridge instance
static DAEMON_BRIDGE: OnceCell<SharedDaemonBridge> = OnceCell::new();

/// Event receiver for forwarding daemon events to the frontend
static EVENT_RECEIVER: OnceCell<Arc<Mutex<Option<mpsc::UnboundedReceiver<DaemonEvent>>>>> =
    OnceCell::new();

/// Application state
pub struct AppState {
    bridge: SharedDaemonBridge,
    resource_dir: Option<PathBuf>,
}

/// Response type for Tauri commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl CommandResponse {
    pub fn success(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }
    }
}

/// Start the daemon process
#[tauri::command]
async fn start_daemon(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CommandResponse, String> {
    let mut bridge = state.bridge.lock().await;

    if bridge.is_running() {
        return Ok(CommandResponse::error("Daemon is already running"));
    }

    // Find daemon binary
    let daemon_path = match DaemonBridge::find_daemon_binary(state.resource_dir.clone()) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to find daemon binary: {}", e);
            return Ok(CommandResponse::error(&format!(
                "Daemon binary not found: {}",
                e
            )));
        }
    };

    // Create event channel
    let (tx, rx) = mpsc::unbounded_channel();

    // Store receiver for the event forwarder
    if let Some(receiver) = EVENT_RECEIVER.get() {
        *receiver.lock().await = Some(rx);
    }

    // Spawn daemon
    if let Err(e) = bridge.spawn(daemon_path.clone(), tx) {
        error!("Failed to spawn daemon: {}", e);
        return Ok(CommandResponse::error(&format!(
            "Failed to spawn daemon: {}",
            e
        )));
    }

    // Start event forwarder task
    let app_handle = app.clone();
    tokio::spawn(async move {
        forward_daemon_events(app_handle).await;
    });

    info!("Daemon started from: {:?}", daemon_path);
    Ok(CommandResponse::success(serde_json::json!({
        "status": "started",
        "path": daemon_path.to_string_lossy()
    })))
}

/// Stop the daemon process
#[tauri::command]
async fn stop_daemon(state: State<'_, AppState>) -> Result<CommandResponse, String> {
    let mut bridge = state.bridge.lock().await;

    if !bridge.is_running() {
        return Ok(CommandResponse::error("Daemon is not running"));
    }

    if let Err(e) = bridge.stop() {
        error!("Failed to stop daemon: {}", e);
        return Ok(CommandResponse::error(&format!(
            "Failed to stop daemon: {}",
            e
        )));
    }

    info!("Daemon stopped");
    Ok(CommandResponse::success(serde_json::json!({
        "status": "stopped"
    })))
}

/// Check if the daemon is running
#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<CommandResponse, String> {
    let mut bridge = state.bridge.lock().await;
    let running = bridge.is_running();

    Ok(CommandResponse::success(serde_json::json!({
        "running": running
    })))
}

/// Start a kamune server
#[tauri::command]
async fn start_server(
    state: State<'_, AppState>,
    addr: String,
    storage_path: Option<String>,
    no_passphrase: Option<bool>,
) -> Result<CommandResponse, String> {
    let bridge = Arc::clone(&state.bridge);

    let cmd = DaemonCommand::new(
        "start_server",
        serde_json::json!({
            "addr": addr,
            "storage_path": storage_path.unwrap_or_default(),
            "db_no_passphrase": no_passphrase.unwrap_or(true)
        }),
    );

    match DaemonBridge::send_command_async(bridge, cmd).await {
        Ok(event) => Ok(CommandResponse::success(event.data)),
        Err(e) => {
            error!("Failed to start server: {}", e);
            Ok(CommandResponse::error(&format!(
                "Failed to start server: {}",
                e
            )))
        }
    }
}

/// Dial a remote server
#[tauri::command]
async fn dial(
    state: State<'_, AppState>,
    addr: String,
    storage_path: Option<String>,
    no_passphrase: Option<bool>,
) -> Result<CommandResponse, String> {
    let bridge = Arc::clone(&state.bridge);

    let cmd = DaemonCommand::new(
        "dial",
        serde_json::json!({
            "addr": addr,
            "storage_path": storage_path.unwrap_or_default(),
            "db_no_passphrase": no_passphrase.unwrap_or(true)
        }),
    );

    match DaemonBridge::send_command_async(bridge, cmd).await {
        Ok(event) => Ok(CommandResponse::success(event.data)),
        Err(e) => {
            error!("Failed to dial: {}", e);
            Ok(CommandResponse::error(&format!("Failed to dial: {}", e)))
        }
    }
}

/// Send a message on a session
#[tauri::command]
async fn send_message(
    state: State<'_, AppState>,
    session_id: String,
    message: String,
) -> Result<CommandResponse, String> {
    let bridge = Arc::clone(&state.bridge);

    // Base64 encode the message
    let data_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        message.as_bytes(),
    );

    let cmd = DaemonCommand::new(
        "send_message",
        serde_json::json!({
            "session_id": session_id,
            "data_base64": data_base64
        }),
    );

    match DaemonBridge::send_command_async(bridge, cmd).await {
        Ok(event) => Ok(CommandResponse::success(event.data)),
        Err(e) => {
            error!("Failed to send message: {}", e);
            Ok(CommandResponse::error(&format!(
                "Failed to send message: {}",
                e
            )))
        }
    }
}

/// List active sessions
#[tauri::command]
async fn list_sessions(state: State<'_, AppState>) -> Result<CommandResponse, String> {
    let bridge = Arc::clone(&state.bridge);

    let cmd = DaemonCommand::new("list_sessions", serde_json::json!({}));

    match DaemonBridge::send_command_async(bridge, cmd).await {
        Ok(event) => Ok(CommandResponse::success(event.data)),
        Err(e) => {
            error!("Failed to list sessions: {}", e);
            Ok(CommandResponse::error(&format!(
                "Failed to list sessions: {}",
                e
            )))
        }
    }
}

/// Close a session
#[tauri::command]
async fn close_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<CommandResponse, String> {
    let bridge = Arc::clone(&state.bridge);

    let cmd = DaemonCommand::new(
        "close_session",
        serde_json::json!({
            "session_id": session_id
        }),
    );

    match DaemonBridge::send_command_async(bridge, cmd).await {
        Ok(event) => Ok(CommandResponse::success(event.data)),
        Err(e) => {
            error!("Failed to close session: {}", e);
            Ok(CommandResponse::error(&format!(
                "Failed to close session: {}",
                e
            )))
        }
    }
}

/// Forward daemon events to the frontend
async fn forward_daemon_events(app: AppHandle) {
    let receiver = match EVENT_RECEIVER.get() {
        Some(r) => r,
        None => {
            warn!("Event receiver not initialized");
            return;
        }
    };

    let mut rx = match receiver.lock().await.take() {
        Some(rx) => rx,
        None => {
            warn!("No event receiver available");
            return;
        }
    };

    info!("Starting daemon event forwarder");

    while let Some(event) = rx.recv().await {
        // Map daemon events to Tauri events
        let event_name = format!("daemon:{}", event.evt);

        if let Err(e) = app.emit(&event_name, &event) {
            error!("Failed to emit event {}: {}", event_name, e);
        }

        // Also emit a generic daemon event for catch-all handlers
        if let Err(e) = app.emit("daemon:event", &event) {
            error!("Failed to emit generic daemon event: {}", e);
        }
    }

    info!("Daemon event forwarder exiting");
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("kamune_app=info".parse().unwrap()),
        )
        .init();

    info!("Starting Kamune Desktop Application");

    // Create shared bridge
    let bridge = create_shared_bridge();
    DAEMON_BRIDGE.set(Arc::clone(&bridge)).ok();

    // Initialize event receiver holder
    EVENT_RECEIVER
        .set(Arc::new(Mutex::new(None)))
        .ok();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Get resource directory for finding bundled binaries
            let resource_dir = app.path().resource_dir().ok();

            info!("Resource directory: {:?}", resource_dir);

            // Initialize app state
            let state = AppState {
                bridge: DAEMON_BRIDGE.get().unwrap().clone(),
                resource_dir,
            };

            app.manage(state);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_daemon,
            stop_daemon,
            daemon_status,
            start_server,
            dial,
            send_message,
            list_sessions,
            close_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
