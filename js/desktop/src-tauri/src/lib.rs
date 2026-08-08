use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use llm_notary_core::vault::{CHILD_KEY_STDIN_ENV, Vault};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tauri::{
    Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_shell::{ShellExt, process::CommandChild};

const ADMIN_ORIGIN: &str = "http://127.0.0.1:8788";
const CONVENIENCE_MARKER: &str = "desktop-convenience-v1";
const ONBOARDING_MARKER: &str = "desktop-onboarding-v1";

#[derive(Default)]
struct DaemonProcess(Mutex<Option<CommandChild>>);

#[derive(Debug, Default, Deserialize, Serialize)]
struct CaptureCounts {
    total_captures: u64,
    capturing: u64,
    ready_to_finalize: u64,
    finalized: u64,
    failed: u64,
    active_operations: u64,
}

#[derive(Debug, Deserialize)]
struct AdminStatus {
    version: String,
    proxy_listener: String,
    admin_listener: String,
    vault: String,
    notary: String,
    counts: CaptureCounts,
}

#[derive(Debug, Serialize)]
struct DesktopState {
    running: bool,
    managed_by_desktop: bool,
    vault_configured: bool,
    agent_configured: bool,
    onboarding_complete: bool,
    vault_mode: String,
    version: Option<String>,
    proxy_listener: String,
    admin_listener: String,
    notary: Option<String>,
    counts: CaptureCounts,
    message: Option<String>,
}

fn local_vault_mode() -> (bool, String) {
    match Vault::status() {
        Ok("OS vault") => (true, "keychain".into()),
        Ok("passphrase vault") if convenience_marker_path().is_ok_and(|path| path.exists()) => {
            (true, "convenience".into())
        }
        Ok("passphrase vault") => (true, "passphrase".into()),
        Ok(other) => (true, other.to_lowercase()),
        Err(_) => (false, "not configured".into()),
    }
}

fn local_marker_path(name: &str) -> Result<PathBuf, String> {
    Vault::configuration_path()
        .map_err(|error| format!("Could not locate the local vault: {error}"))?
        .parent()
        .map(|directory| directory.join(name))
        .ok_or_else(|| "the local vault path has no parent directory".into())
}

fn convenience_marker_path() -> Result<PathBuf, String> {
    local_marker_path(CONVENIENCE_MARKER)
}

fn onboarding_marker_path() -> Result<PathBuf, String> {
    local_marker_path(ONBOARDING_MARKER)
}

fn agent_config_path() -> Result<PathBuf, String> {
    let base = if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("APPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("HOME") {
        let home = PathBuf::from(path);
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join(".config")
        }
    } else {
        return Err("Could not determine the local configuration directory.".into());
    };
    Ok(base.join("llm-notary").join("config.toml"))
}

fn write_private_marker(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create the desktop settings directory: {error}"))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => file
            .write_all(contents)
            .map_err(|error| format!("Could not save the desktop setup state: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!(
            "Could not save the desktop setup state at {}: {error}",
            path.display()
        )),
    }
}

fn mark_convenience_vault() -> Result<(), String> {
    let path = convenience_marker_path()?;
    write_private_marker(&path, b"LLM Notary desktop convenience vault\n")
}

fn open_vault_for_child() -> Result<Vault, String> {
    match Vault::status() {
        Ok("OS vault") => Vault::open(None).map_err(|error| {
            format!("Could not unlock the capture key with the OS credential vault: {error}")
        }),
        Ok("passphrase vault") => {
            let vault = Vault::open(Some("")).map_err(|error| {
                format!("Could not open the desktop convenience vault: {error}")
            })?;
            if !convenience_marker_path()?.exists() {
                return Err(
                    "This passphrase vault was configured outside the desktop app. Desktop passphrase entry is not implemented yet."
                        .into(),
                );
            }
            Ok(vault)
        }
        Ok(other) => Err(format!("Unsupported local vault mode: {other}")),
        Err(_) => Err("Choose how to protect private captures before starting the service.".into()),
    }
}

async fn read_admin_status() -> Result<AdminStatus, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(350))
        .timeout(Duration::from_millis(900))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(format!("{ADMIN_ORIGIN}/v1/status"))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(
            "The local service is running, but dashboard authentication is enabled.".into(),
        );
    }
    response
        .error_for_status()
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())
}

async fn daemon_is_healthy() -> bool {
    let Ok(client) = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(250))
        .timeout(Duration::from_millis(500))
        .build()
    else {
        return false;
    };
    client
        .get(format!("{ADMIN_ORIGIN}/healthz"))
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

#[tauri::command]
async fn get_desktop_state(
    process: tauri::State<'_, DaemonProcess>,
) -> Result<DesktopState, String> {
    let (vault_configured, local_mode) = local_vault_mode();
    let agent_configured = agent_config_path().is_ok_and(|path| path.exists());
    let onboarding_complete = onboarding_marker_path().is_ok_and(|path| path.exists());
    let managed_by_desktop = process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some();

    match read_admin_status().await {
        Ok(status) => Ok(DesktopState {
            running: true,
            managed_by_desktop,
            vault_configured,
            agent_configured,
            onboarding_complete,
            vault_mode: match status.vault.as_str() {
                "OS vault" => "keychain".into(),
                "passphrase vault" => local_mode,
                _ => status.vault,
            },
            version: Some(status.version),
            proxy_listener: status.proxy_listener,
            admin_listener: status.admin_listener,
            notary: Some(status.notary),
            counts: status.counts,
            message: None,
        }),
        Err(error) => {
            let running = daemon_is_healthy().await;
            Ok(DesktopState {
                running,
                managed_by_desktop,
                vault_configured,
                agent_configured,
                onboarding_complete,
                vault_mode: local_mode,
                version: None,
                proxy_listener: "127.0.0.1:8787".into(),
                admin_listener: "127.0.0.1:8788".into(),
                notary: None,
                counts: CaptureCounts::default(),
                message: if running { Some(error) } else { None },
            })
        }
    }
}

#[tauri::command]
fn complete_onboarding() -> Result<(), String> {
    if !local_vault_mode().0 {
        return Err("Choose how to protect private captures before finishing setup.".into());
    }
    let path = onboarding_marker_path()?;
    write_private_marker(&path, b"LLM Notary desktop onboarding complete\n")
}

#[tauri::command]
fn configure_vault(mode: String) -> Result<(), String> {
    if Vault::status().is_ok() {
        return Ok(());
    }

    match mode.as_str() {
        "keychain" => Vault::init_os().map(|_| ()).map_err(|error| {
            format!("Could not store the capture key in the OS credential vault: {error}")
        }),
        "convenience" => {
            Vault::init_passphrase("").map_err(|error| {
                format!("Could not initialize the local capture vault: {error}")
            })?;
            mark_convenience_vault()
        }
        _ => Err("Choose Keychain protection or convenience mode.".into()),
    }
}

fn spawn_daemon(app: &tauri::AppHandle, process: &DaemonProcess) -> Result<(), String> {
    let vault = open_vault_for_child()?;
    let unlock_key = vault.child_unlock_key_line();
    let (mut events, mut child) = app
        .shell()
        .sidecar("llm-notaryd")
        .map_err(|error| format!("Could not locate the bundled llm-notaryd service: {error}"))?
        .env(CHILD_KEY_STDIN_ENV, "1")
        .spawn()
        .map_err(|error| format!("Could not start the bundled llm-notaryd service: {error}"))?;

    if let Err(error) = child.write(&unlock_key) {
        let _ = child.kill();
        return Err(format!(
            "Could not send the unlocked capture key to the local service: {error}"
        ));
    }
    drop(unlock_key);

    *process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")? = Some(child);

    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            if matches!(
                event,
                tauri_plugin_shell::process::CommandEvent::Terminated(_)
            ) {
                if let Ok(mut guard) = app_handle.state::<DaemonProcess>().0.lock() {
                    *guard = None;
                }
                break;
            }
        }
    });
    Ok(())
}

#[tauri::command]
async fn start_daemon(
    app: tauri::AppHandle,
    process: tauri::State<'_, DaemonProcess>,
) -> Result<(), String> {
    if daemon_is_healthy().await {
        return Ok(());
    }
    if !local_vault_mode().0 {
        return Err("Choose how to protect private captures before starting the service.".into());
    }
    let already_starting = process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some();
    if !already_starting {
        spawn_daemon(&app, &process)?;
    }
    for _ in 0..50 {
        if daemon_is_healthy().await {
            return Ok(());
        }
        let still_running = process
            .0
            .lock()
            .map_err(|_| "daemon process state is unavailable")?
            .is_some();
        if !still_running {
            return Err("The bundled local service exited before becoming ready.".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("The bundled local service did not become ready within five seconds.".into())
}

#[tauri::command]
async fn stop_daemon(process: tauri::State<'_, DaemonProcess>) -> Result<(), String> {
    let child = process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .take();
    match child {
        Some(child) => child
            .kill()
            .map_err(|error| format!("Could not stop the local service: {error}")),
        None if daemon_is_healthy().await => Err(
            "This service was started outside the desktop app. Stop it from the process that launched it."
                .into(),
        ),
        None => Ok(()),
    }
}

#[tauri::command]
async fn restart_daemon(
    app: tauri::AppHandle,
    process: tauri::State<'_, DaemonProcess>,
) -> Result<(), String> {
    let child = process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .take();
    if let Some(child) = child {
        child
            .kill()
            .map_err(|error| format!("Could not stop the local service: {error}"))?;
        tokio::time::sleep(Duration::from_millis(300)).await;
    } else if daemon_is_healthy().await {
        return Err(
            "This service was started outside the desktop app. Restart it from the process that launched it."
                .into(),
        );
    }
    spawn_daemon(&app, &process)
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn create_tray(app: &tauri::App) -> tauri::Result<()> {
    let open_app = MenuItem::with_id(app, "open_app", "Open LLM Notary", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit LLM Notary", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_app, &separator, &quit])?;

    #[cfg(target_os = "macos")]
    let tray_icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-icon.png"))?;
    #[cfg(not(target_os = "macos"))]
    let tray_icon = app.default_window_icon().expect("application icon").clone();

    TrayIconBuilder::with_id("llm-notary")
        .icon(tray_icon)
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("LLM Notary")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open_app" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(DaemonProcess::default())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .invoke_handler(tauri::generate_handler![
            get_desktop_state,
            configure_vault,
            complete_onboarding,
            start_daemon,
            stop_daemon,
            restart_daemon,
        ])
        .setup(|app| {
            create_tray(app)?;
            if local_vault_mode().0 && onboarding_marker_path().is_ok_and(|path| path.exists()) {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let process = app_handle.state::<DaemonProcess>();
                    let _ = start_daemon(app_handle.clone(), process).await;
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building LLM Notary desktop");

    app.run(|app, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            let child = app
                .state::<DaemonProcess>()
                .0
                .lock()
                .ok()
                .and_then(|mut process| process.take());
            if let Some(child) = child {
                let _ = child.kill();
            }
        }
    });
}
