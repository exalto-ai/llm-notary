use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use llm_notary_core::vault::{CHILD_KEY_STDIN_ENV, Vault};
use llm_notary_updater::{self as update, ReleaseArtifact};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tauri::{
    Manager,
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_shell::{ShellExt, process::CommandChild};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::{Host, Url};
use zeroize::Zeroizing;

const ADMIN_ORIGIN: &str = "http://127.0.0.1:8788";
const CONVENIENCE_MARKER: &str = "desktop-convenience-v1";
const ONBOARDING_MARKER: &str = "desktop-onboarding-v1";
const DESKTOP_CONTROL_STDIN_ENV: &str = "LLM_NOTARY_DESKTOP_CONTROL_STDIN";

#[derive(Default)]
struct DaemonProcess(Mutex<Option<CommandChild>>);

#[derive(Default)]
struct VaultSession(Mutex<Option<Vault>>);

#[derive(Default)]
struct ExitState {
    allowed: AtomicBool,
    draining: AtomicBool,
}

struct PendingDesktopUpdate {
    build_id: String,
    channel_revision: u64,
    update: Update,
    bytes: Vec<u8>,
}

struct DesktopUpdaterState {
    view: Mutex<DesktopUpdateView>,
    pending: Mutex<Option<PendingDesktopUpdate>>,
    busy: AtomicBool,
}

impl Default for DesktopUpdaterState {
    fn default() -> Self {
        let enabled = desktop_updates_enabled(
            env!("LLM_NOTARY_BUILD_ID"),
            env!("LLM_NOTARY_UPDATES_ENABLED"),
        );
        Self {
            view: Mutex::new(DesktopUpdateView {
                enabled,
                phase: if enabled { "idle" } else { "disabled" }.into(),
                current_build_id: env!("LLM_NOTARY_BUILD_ID").into(),
                latest_build_id: None,
                downloaded_bytes: 0,
                total_bytes: None,
                message: (!enabled)
                    .then(|| "Automatic updates are available in signed release builds.".into()),
            }),
            pending: Mutex::new(None),
            busy: AtomicBool::new(false),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct DesktopUpdateView {
    enabled: bool,
    phase: String,
    current_build_id: String,
    latest_build_id: Option<String>,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    message: Option<String>,
}

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
    build_id: String,
    proxy_listener: String,
    admin_listener: String,
    vault: String,
    notary: String,
    capture_enabled: bool,
    counts: CaptureCounts,
}

#[derive(Debug, Deserialize, Serialize)]
struct CaptureSetting {
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct DesktopState {
    running: bool,
    managed_by_desktop: bool,
    vault_configured: bool,
    agent_configured: bool,
    onboarding_complete: bool,
    vault_mode: String,
    vault_locked: bool,
    version: Option<String>,
    app_build_id: String,
    daemon_build_id: Option<String>,
    proxy_listener: String,
    admin_listener: String,
    notary: Option<String>,
    capture_enabled: bool,
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

fn passphrase_vault_is_locked(mode: &str, session: &VaultSession) -> bool {
    mode == "passphrase" && !session.0.lock().is_ok_and(|vault| vault.as_ref().is_some())
}

fn should_auto_start(vault_configured: bool, mode: &str, onboarding_complete: bool) -> bool {
    vault_configured && mode != "passphrase" && onboarding_complete
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

fn vault_unlock_key_for_child(session: &VaultSession) -> Result<Zeroizing<Vec<u8>>, String> {
    match Vault::status() {
        Ok("OS vault") => Vault::open(None)
            .map(|vault| vault.child_unlock_key_line())
            .map_err(|error| {
                format!("Could not unlock the capture key with the OS credential vault: {error}")
            }),
        Ok("passphrase vault") => {
            if convenience_marker_path()?.exists() {
                return Vault::open(Some(""))
                    .map(|vault| vault.child_unlock_key_line())
                    .map_err(|error| {
                        format!("Could not open the unprotected local capture vault: {error}")
                    });
            }
            session
                .0
                .lock()
                .map_err(|_| "capture vault session is unavailable".to_string())?
                .as_ref()
                .map(Vault::child_unlock_key_line)
                .ok_or_else(|| {
                    "Enter the capture vault passphrase before starting the service.".into()
                })
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

async fn account_request(
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(350))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?;
    let mut request = client.request(method, format!("{ADMIN_ORIGIN}{path}"));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    let status = response.status();
    let payload = response
        .json::<Value>()
        .await
        .map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(payload
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("The local account request failed.")
            .to_owned());
    }
    Ok(payload)
}

fn valid_account_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[tauri::command]
async fn get_account_connection() -> Result<Value, String> {
    account_request(reqwest::Method::GET, "/v1/account", None).await
}

#[tauri::command]
async fn start_account_connection() -> Result<Value, String> {
    account_request(reqwest::Method::POST, "/v1/account", Some(json!({}))).await
}

#[tauri::command]
async fn poll_account_connection(request_id: String) -> Result<Value, String> {
    if !valid_account_request_id(&request_id) {
        return Err("Invalid account authorization request.".into());
    }
    account_request(
        reqwest::Method::GET,
        &format!("/v1/account/{request_id}"),
        None,
    )
    .await
}

#[tauri::command]
async fn disconnect_account() -> Result<(), String> {
    account_request(reqwest::Method::DELETE, "/v1/account", None)
        .await
        .map(|_| ())
}

fn validate_account_link(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "The account link is not a valid URL.".to_string())?;
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host().is_some_and(|host| match host {
            Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        });
    let fragment = url.fragment().unwrap_or_default();
    let route = fragment
        .split_once('?')
        .map_or(fragment, |(route, _)| route);
    let authorization_query = fragment.strip_prefix("/authorize?").is_some_and(|query| {
        let mut request_id = false;
        let mut approval_secret = false;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                return false;
            };
            if value.is_empty()
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'#')
            {
                return false;
            }
            match key {
                "request_id" if !request_id => request_id = true,
                "approval_secret" if !approval_secret => approval_secret = true,
                _ => return false,
            }
        }
        request_id && approval_secret
    });
    let allowed_route = matches!(
        route,
        "/dashboard" | "/dashboard/credits" | "/pricing" | "/dashboard/settings"
    ) || authorization_query;
    if (!secure && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || !allowed_route
    {
        return Err(
            "The account link was rejected because it is not a trusted hosted route.".into(),
        );
    }
    Ok(url)
}

#[tauri::command]
fn open_account_link(url: String) -> Result<(), String> {
    let url = validate_account_link(&url)?;
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url.as_str()).spawn();
    #[cfg(target_os = "windows")]
    let result = Command::new("explorer.exe").arg(url.as_str()).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = Command::new("xdg-open").arg(url.as_str()).spawn();
    result
        .map(|_| ())
        .map_err(|error| format!("Could not open the account page: {error}"))
}

async fn write_capture_setting(enabled: bool) -> Result<bool, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .put(format!("{ADMIN_ORIGIN}/v1/settings/capture"))
        .json(&CaptureSetting { enabled })
        .send()
        .await
        .map_err(|_| {
            "The local service is unreachable; capture mode did not change.".to_string()
        })?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(
            "The local service requires dashboard authentication; capture mode did not change."
                .into(),
        );
    }
    response
        .error_for_status()
        .map_err(|_| {
            "The local service could not change capture mode. Capture remains unchanged."
                .to_string()
        })?
        .json::<CaptureSetting>()
        .await
        .map(|setting| setting.enabled)
        .map_err(|_| "The local service returned an invalid capture setting.".to_string())
}

#[tauri::command]
async fn set_capture_enabled(enabled: bool) -> Result<bool, String> {
    write_capture_setting(enabled).await
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

fn desktop_updates_enabled(build_id: &str, enabled: &str) -> bool {
    cfg!(target_os = "macos") && build_id != "dev" && enabled == "1"
}

fn build_ids_require_update(current: &str, latest: &str) -> bool {
    current != latest
}

fn pending_build_is_latest(pending: Option<&str>, latest: &str) -> bool {
    pending.is_some_and(|pending| pending == latest)
}

fn restart_block_reason(
    counts: &CaptureCounts,
    running: bool,
    managed_by_desktop: bool,
) -> Option<&'static str> {
    if counts.capturing > 0 {
        Some("Wait for the active capture to finish before restarting to update.")
    } else if counts.active_operations > 0 {
        Some("Wait for the active finalization to finish before restarting to update.")
    } else if running && !managed_by_desktop {
        Some(
            "The running local service was started outside this app. Stop or update it from the process that launched it before restarting the app.",
        )
    } else {
        None
    }
}

fn set_update_view(
    state: &DesktopUpdaterState,
    update: impl FnOnce(&mut DesktopUpdateView),
) -> Result<DesktopUpdateView, String> {
    let mut view = state
        .view
        .lock()
        .map_err(|_| "desktop update state is unavailable")?;
    update(&mut view);
    Ok(view.clone())
}

#[tauri::command]
fn get_update_state(
    state: tauri::State<'_, DesktopUpdaterState>,
) -> Result<DesktopUpdateView, String> {
    state
        .view
        .lock()
        .map_err(|_| "desktop update state is unavailable".to_string())
        .map(|view| view.clone())
}

async fn check_and_download_update_inner(
    app: &tauri::AppHandle,
) -> Result<DesktopUpdateView, String> {
    let state = app.state::<DesktopUpdaterState>();
    if !desktop_updates_enabled(
        env!("LLM_NOTARY_BUILD_ID"),
        env!("LLM_NOTARY_UPDATES_ENABLED"),
    ) {
        return get_update_state(state);
    }

    set_update_view(&state, |view| {
        view.phase = "checking".into();
        view.message = Some("Checking the signed latest release…".into());
        view.downloaded_bytes = 0;
        view.total_bytes = None;
    })?;

    let check = update::check_latest()
        .await
        .map_err(|error| format!("Could not check for updates: {error}"))?;
    if check.current_build_id != env!("LLM_NOTARY_BUILD_ID") {
        return Err("The desktop app and release checker disagree about this build.".into());
    }
    if check.update_available
        != build_ids_require_update(env!("LLM_NOTARY_BUILD_ID"), &check.latest_build_id)
    {
        return Err("The signed release returned an inconsistent build identity.".into());
    }
    if !check.update_available {
        state
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")?
            .take();
        return set_update_view(&state, |view| {
            view.phase = "current".into();
            view.latest_build_id = Some(check.latest_build_id);
            view.message = Some("This is the latest signed release.".into());
        });
    }
    let pending_build = state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .as_ref()
        .map(|pending| pending.build_id.clone());
    let pending_matches_latest =
        pending_build_is_latest(pending_build.as_deref(), &check.latest_build_id);
    if pending_matches_latest {
        return set_update_view(&state, |view| {
            view.phase = "ready".into();
            view.latest_build_id = Some(check.latest_build_id);
            view.message =
                Some("The latest release is ready. Restart when local work is idle.".into());
        });
    }
    // A newer channel revision may withdraw or replace a previously
    // downloaded build. Discard it before selecting the new signed release.
    state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .take();

    let release = check
        .release
        .ok_or_else(|| "The verified desktop release is unavailable.".to_string())?;
    let desktop = release
        .manifest
        .desktop
        .get("darwin-aarch64")
        .ok_or_else(|| "The signed release has no macOS app.".to_string())?;
    let expected_artifact: ReleaseArtifact = desktop.updater.artifact.clone();
    let expected_signature = desktop.updater.signature.clone();
    let expected_version = release.manifest.version.clone();

    let updater = app
        .updater_builder()
        .target("darwin-aarch64")
        .endpoints(vec![release.manifest_url.clone()])
        .map_err(|error| format!("Could not configure the desktop updater: {error}"))?
        .header("Cache-Control", "no-cache, no-store")
        .map_err(|error| format!("Could not configure update caching: {error}"))?
        .timeout(Duration::from_secs(10 * 60))
        // The authenticated build-ID comparison above is the only version
        // decision. This comparator lets the latest channel intentionally
        // roll back to a different signed build with the same app version.
        .version_comparator(|_, _| true)
        .build()
        .map_err(|error| format!("Could not start the desktop updater: {error}"))?;
    let pending = updater
        .check()
        .await
        .map_err(|error| format!("Could not read the verified desktop release: {error}"))?
        .ok_or_else(|| "The updater did not return the selected signed release.".to_string())?;

    if pending.version != expected_version
        || pending.download_url.as_str() != expected_artifact.url
        || pending.signature != expected_signature
    {
        return Err("The desktop updater response does not match the signed release.".into());
    }

    set_update_view(&state, |view| {
        view.phase = "downloading".into();
        view.latest_build_id = Some(check.latest_build_id.clone());
        view.downloaded_bytes = 0;
        view.total_bytes = Some(expected_artifact.size_bytes);
        view.message = Some("Downloading the signed update…".into());
    })?;
    let mut downloaded = 0_u64;
    let bytes = pending
        .download(
            |chunk, _| {
                downloaded = downloaded.saturating_add(chunk as u64);
                let _ = set_update_view(&state, |view| {
                    view.downloaded_bytes = downloaded;
                });
            },
            || {},
        )
        .await
        .map_err(|error| format!("Could not download or verify the desktop update: {error}"))?;
    update::verify_artifact_bytes(&expected_artifact, &bytes)
        .map_err(|error| format!("The desktop update failed release verification: {error}"))?;

    *state
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")? = Some(PendingDesktopUpdate {
        build_id: check.latest_build_id,
        channel_revision: check.channel_revision,
        update: pending,
        bytes,
    });
    set_update_view(&state, |view| {
        view.phase = "ready".into();
        view.downloaded_bytes = expected_artifact.size_bytes;
        view.total_bytes = Some(expected_artifact.size_bytes);
        view.message = Some("The latest release is ready. Restart when local work is idle.".into());
    })
}

async fn check_and_download_update(app: &tauri::AppHandle) -> Result<DesktopUpdateView, String> {
    let state = app.state::<DesktopUpdaterState>();
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An update operation is already in progress.".into());
    }
    let result = check_and_download_update_inner(app).await;
    state.busy.store(false, Ordering::Release);
    if let Err(error) = &result {
        let update_is_still_ready = state.pending.lock().is_ok_and(|pending| pending.is_some());
        let _ = set_update_view(&state, |view| {
            view.phase = if update_is_still_ready {
                "ready"
            } else {
                "error"
            }
            .into();
            view.message = Some(error.clone());
        });
    }
    result
}

#[tauri::command]
async fn check_for_updates(app: tauri::AppHandle) -> Result<DesktopUpdateView, String> {
    check_and_download_update(&app).await
}

#[tauri::command]
async fn install_update_and_restart(app: tauri::AppHandle) -> Result<(), String> {
    let updates = app.state::<DesktopUpdaterState>();
    if updates
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("An update operation is already in progress.".into());
    }

    let result = install_update_and_restart_inner(&app).await;
    updates.busy.store(false, Ordering::Release);
    if let Err(error) = &result {
        let update_is_still_ready = updates
            .pending
            .lock()
            .is_ok_and(|pending| pending.is_some());
        let _ = set_update_view(&updates, |view| {
            view.phase = if update_is_still_ready {
                "ready"
            } else {
                "error"
            }
            .into();
            view.message = Some(error.clone());
        });
    }
    result
}

async fn install_update_and_restart_inner(app: &tauri::AppHandle) -> Result<(), String> {
    let updates = app.state::<DesktopUpdaterState>();
    let (pending_build_id, pending_revision) = updates
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .as_ref()
        .map(|pending| (pending.build_id.clone(), pending.channel_revision))
        .ok_or_else(|| "No verified desktop update is ready.".to_string())?;

    // Authenticate once before disrupting local work, and again after the
    // daemon has drained. A withdrawn download always stays inert.
    confirm_pending_is_latest(&updates, &pending_build_id, pending_revision).await?;

    let process = app.state::<DaemonProcess>();
    let managed = process
        .0
        .lock()
        .map_err(|_| "daemon process state is unavailable")?
        .is_some();
    match read_admin_status().await {
        Ok(status) => {
            if let Some(reason) = restart_block_reason(&status.counts, true, managed) {
                return Err(reason.into());
            }
        }
        Err(_) if daemon_is_healthy().await && !managed => {
            return Err(restart_block_reason(&CaptureCounts::default(), true, false)
                .expect("an external running service has a block reason")
                .into());
        }
        Err(_) => {}
    }

    if managed {
        request_managed_daemon_shutdown(&process).await?;
    }
    if let Err(error) =
        confirm_pending_is_latest(&updates, &pending_build_id, pending_revision).await
    {
        if managed && let Err(restart_error) = spawn_daemon(app, &process) {
            return Err(format!(
                "{error} The local service could not be restarted: {restart_error}"
            ));
        }
        return Err(error);
    }
    set_update_view(&updates, |view| {
        view.phase = "installing".into();
        view.message = Some("Installing the update and reopening LLM Notary…".into());
    })?;
    let pending = updates
        .pending
        .lock()
        .map_err(|_| "desktop update state is unavailable")?
        .take()
        .ok_or_else(|| "No verified desktop update is ready.".to_string())?;

    if let Err(error) = pending.update.install(&pending.bytes) {
        *updates
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")? = Some(pending);
        if managed {
            let _ = spawn_daemon(app, &process);
        }
        return Err(format!("Could not install the desktop update: {error}"));
    }
    app.restart()
}

async fn confirm_pending_is_latest(
    updates: &DesktopUpdaterState,
    pending_build_id: &str,
    pending_revision: u64,
) -> Result<(), String> {
    let latest = update::check_latest()
        .await
        .map_err(|error| format!("Could not confirm the latest release; try again: {error}"))?;
    if !latest.update_available || latest.latest_build_id != pending_build_id {
        updates
            .pending
            .lock()
            .map_err(|_| "desktop update state is unavailable")?
            .take();
        return Err(
            "The downloaded release is no longer latest. Check again for the current release."
                .into(),
        );
    }
    if latest.channel_revision < pending_revision {
        return Err(
            "The latest release revision moved backward; the update was not installed.".into(),
        );
    }
    Ok(())
}

fn schedule_update_checks(app: tauri::AppHandle) {
    if !desktop_updates_enabled(
        env!("LLM_NOTARY_BUILD_ID"),
        env!("LLM_NOTARY_UPDATES_ENABLED"),
    ) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let _ = check_and_download_update(&app).await;
            let jitter = env!("LLM_NOTARY_BUILD_ID")
                .bytes()
                .fold(0_u64, |value, byte| value.wrapping_add(byte as u64))
                % (15 * 60);
            tokio::time::sleep(Duration::from_secs(6 * 60 * 60 + jitter)).await;
        }
    });
}

#[tauri::command]
async fn get_desktop_state(
    process: tauri::State<'_, DaemonProcess>,
    vault_session: tauri::State<'_, VaultSession>,
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
        Ok(status) => {
            let daemon_build_id = status.build_id.clone();
            let message = (daemon_build_id != env!("LLM_NOTARY_BUILD_ID")).then(|| {
                "The app and running local service are different builds. Update or restart the separately installed service before relying on new client behavior."
                    .into()
            });
            Ok(DesktopState {
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
                vault_locked: false,
                version: Some(status.version),
                app_build_id: env!("LLM_NOTARY_BUILD_ID").into(),
                daemon_build_id: Some(daemon_build_id),
                proxy_listener: status.proxy_listener,
                admin_listener: status.admin_listener,
                notary: Some(status.notary),
                capture_enabled: status.capture_enabled,
                counts: status.counts,
                message,
            })
        }
        Err(error) => {
            let running = daemon_is_healthy().await;
            Ok(DesktopState {
                running,
                managed_by_desktop,
                vault_configured,
                agent_configured,
                onboarding_complete,
                vault_locked: passphrase_vault_is_locked(&local_mode, &vault_session),
                vault_mode: local_mode,
                version: None,
                app_build_id: env!("LLM_NOTARY_BUILD_ID").into(),
                daemon_build_id: None,
                proxy_listener: "127.0.0.1:8787".into(),
                admin_listener: "127.0.0.1:8788".into(),
                notary: None,
                capture_enabled: false,
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
fn configure_vault(
    mode: String,
    passphrase: Option<String>,
    vault_session: tauri::State<'_, VaultSession>,
) -> Result<(), String> {
    if Vault::status().is_ok() {
        return Ok(());
    }

    match mode.as_str() {
        "keychain" => Vault::init_os().map(|_| ()).map_err(|error| {
            format!("Could not store the capture key in the OS credential vault: {error}")
        }),
        "passphrase" => {
            let passphrase = Zeroizing::new(
                passphrase.ok_or_else(|| "Enter and confirm a vault passphrase.".to_string())?,
            );
            let vault = Vault::init_passphrase(&passphrase).map_err(|error| {
                format!("Could not initialize the local capture vault: {error}")
            })?;
            if passphrase.is_empty() {
                mark_convenience_vault()?;
            }
            *vault_session
                .0
                .lock()
                .map_err(|_| "capture vault session is unavailable".to_string())? = Some(vault);
            Ok(())
        }
        _ => Err("Choose Keychain protection or a passphrase.".into()),
    }
}

#[tauri::command]
fn unlock_vault(
    passphrase: String,
    vault_session: tauri::State<'_, VaultSession>,
) -> Result<(), String> {
    if local_vault_mode().1 != "passphrase" {
        return Err("This capture vault does not require a passphrase.".into());
    }
    if !Vault::passphrase_unlock_is_verifiable()
        .map_err(|error| format!("Could not inspect the capture vault: {error}"))?
    {
        return Err(
            "This passphrase vault predates verified desktop unlock. Continue using it with the CLI; desktop migration is not available yet."
                .into(),
        );
    }
    let passphrase = Zeroizing::new(passphrase);
    let vault = Vault::open(Some(&passphrase))
        .map_err(|error| format!("Could not unlock the capture vault: {error}"))?;
    *vault_session
        .0
        .lock()
        .map_err(|_| "capture vault session is unavailable".to_string())? = Some(vault);
    Ok(())
}

fn spawn_daemon(app: &tauri::AppHandle, process: &DaemonProcess) -> Result<(), String> {
    let vault_session = app.state::<VaultSession>();
    let unlock_key = vault_unlock_key_for_child(&vault_session)?;
    let (mut events, mut child) = app
        .shell()
        .sidecar("llm-notaryd")
        .map_err(|error| format!("Could not locate the bundled llm-notaryd service: {error}"))?
        .env(CHILD_KEY_STDIN_ENV, "1")
        .env(DESKTOP_CONTROL_STDIN_ENV, "1")
        .spawn()
        .map_err(|error| format!("Could not start the bundled llm-notaryd service: {error}"))?;

    if let Err(error) = child.write(&unlock_key) {
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

async fn request_managed_daemon_shutdown(process: &DaemonProcess) -> Result<bool, String> {
    {
        let mut guard = process
            .0
            .lock()
            .map_err(|_| "daemon process state is unavailable")?;
        let Some(child) = guard.as_mut() else {
            return Ok(false);
        };
        child
            .write(b"shutdown\n")
            .map_err(|error| format!("Could not request a safe local-service shutdown: {error}"))?;
    }
    for _ in 0..6_000 {
        let stopped = process
            .0
            .lock()
            .map_err(|_| "daemon process state is unavailable")?
            .is_none();
        if stopped {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(
        "The local service is still draining work after ten minutes. It was left running; try again after active work finishes."
            .into(),
    )
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
    match request_managed_daemon_shutdown(&process).await? {
        true => Ok(()),
        false if daemon_is_healthy().await => Err(
            "This service was started outside the desktop app. Stop it from the process that launched it."
                .into(),
        ),
        false => Ok(()),
    }
}

#[tauri::command]
async fn restart_daemon(
    app: tauri::AppHandle,
    process: tauri::State<'_, DaemonProcess>,
) -> Result<(), String> {
    let stopped = request_managed_daemon_shutdown(&process).await?;
    if !stopped && daemon_is_healthy().await {
        return Err(
            "This service was started outside the desktop app. Restart it from the process that launched it."
                .into(),
        );
    }
    spawn_daemon(&app, &process)
}

fn show_main_window(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn create_tray(app: &tauri::App) -> tauri::Result<CheckMenuItem<tauri::Wry>> {
    let open_app = MenuItem::with_id(app, "open_app", "Open LLM Notary", true, None::<&str>)?;
    let capture_requests = CheckMenuItem::with_id(
        app,
        "capture_requests",
        "Capture requests — service stopped",
        false,
        false,
        None::<&str>,
    )?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit LLM Notary", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_app, &capture_requests, &separator, &quit])?;

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
        .on_menu_event({
            let capture_requests = capture_requests.clone();
            move |app, event| match event.id().as_ref() {
                "open_app" => show_main_window(app),
                "capture_requests" => {
                    let requested = capture_requests.is_checked().unwrap_or(false);
                    let capture_requests = capture_requests.clone();
                    tauri::async_runtime::spawn(async move {
                        match write_capture_setting(requested).await {
                            Ok(enabled) => {
                                let _ = capture_requests.set_checked(enabled);
                                let _ = capture_requests.set_text("Capture requests");
                                let _ = capture_requests.set_enabled(true);
                            }
                            Err(_) => {
                                let _ = capture_requests.set_checked(!requested);
                                let _ = capture_requests.set_text("Capture requests — unavailable");
                                let _ = capture_requests.set_enabled(false);
                            }
                        }
                    });
                }
                "quit" => app.exit(0),
                _ => {}
            }
        })
        .build(app)?;
    Ok(capture_requests)
}

fn schedule_capture_menu_updates(capture_requests: CheckMenuItem<tauri::Wry>) {
    tauri::async_runtime::spawn(async move {
        loop {
            match read_admin_status().await {
                Ok(status) => {
                    let _ = capture_requests.set_checked(status.capture_enabled);
                    let _ = capture_requests.set_text("Capture requests");
                    let _ = capture_requests.set_enabled(true);
                }
                Err(_) => {
                    let _ = capture_requests.set_text("Capture requests — service stopped");
                    let _ = capture_requests.set_enabled(false);
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(DaemonProcess::default())
        .manage(VaultSession::default())
        .manage(ExitState::default())
        .manage(DesktopUpdaterState::default())
        .plugin(tauri_plugin_shell::init())
        .plugin(
            tauri_plugin_updater::Builder::new()
                .pubkey(include_str!("../../../../runtime/config/updater-public-key.txt").trim())
                .build(),
        )
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .invoke_handler(tauri::generate_handler![
            get_desktop_state,
            get_account_connection,
            start_account_connection,
            poll_account_connection,
            disconnect_account,
            open_account_link,
            configure_vault,
            unlock_vault,
            complete_onboarding,
            start_daemon,
            stop_daemon,
            restart_daemon,
            set_capture_enabled,
            get_update_state,
            check_for_updates,
            install_update_and_restart,
        ])
        .setup(|app| {
            let capture_requests = create_tray(app)?;
            schedule_capture_menu_updates(capture_requests);
            schedule_update_checks(app.handle().clone());
            let (vault_configured, vault_mode) = local_vault_mode();
            let onboarding_complete = onboarding_marker_path().is_ok_and(|path| path.exists());
            if should_auto_start(vault_configured, &vault_mode, onboarding_complete) {
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
                #[cfg(target_os = "macos")]
                let _ = window
                    .app_handle()
                    .set_activation_policy(tauri::ActivationPolicy::Accessory);
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building LLM Notary desktop");

    app.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            let exit = app.state::<ExitState>();
            if exit.allowed.load(Ordering::Acquire) {
                return;
            }
            let managed = app
                .state::<DaemonProcess>()
                .0
                .lock()
                .is_ok_and(|process| process.is_some());
            if !managed {
                return;
            }
            api.prevent_exit();
            if exit
                .draining
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let process = app_handle.state::<DaemonProcess>();
                match request_managed_daemon_shutdown(&process).await {
                    Ok(_) => {
                        app_handle
                            .state::<ExitState>()
                            .allowed
                            .store(true, Ordering::Release);
                        app_handle.exit(code.unwrap_or(0));
                    }
                    Err(error) => {
                        eprintln!("Could not drain the local service before exit: {error}");
                        app_handle
                            .state::<ExitState>()
                            .draining
                            .store(false, Ordering::Release);
                        show_main_window(&app_handle);
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_build_identity_controls_desktop_updates() {
        assert!(!desktop_updates_enabled("dev", "1"));
        assert!(!desktop_updates_enabled("signed-preview", "0"));
        assert!(!build_ids_require_update("build-a", "build-a"));
        assert!(build_ids_require_update("build-a", "build-b"));
        assert!(build_ids_require_update("newer-build", "older-build"));
        assert!(pending_build_is_latest(Some("build-b"), "build-b"));
        assert!(!pending_build_is_latest(Some("build-b"), "build-a"));
    }

    #[test]
    fn active_local_work_and_external_services_block_restart() {
        let mut counts = CaptureCounts {
            capturing: 1,
            ..CaptureCounts::default()
        };
        assert!(restart_block_reason(&counts, true, true).is_some());
        counts.capturing = 0;
        counts.active_operations = 1;
        assert!(restart_block_reason(&counts, true, true).is_some());
        counts.active_operations = 0;
        assert!(restart_block_reason(&counts, true, false).is_some());
        assert!(restart_block_reason(&counts, true, true).is_none());
        assert!(restart_block_reason(&counts, false, false).is_none());
    }

    #[test]
    fn passphrase_vaults_wait_for_an_in_memory_unlock() {
        let session = VaultSession::default();
        assert!(passphrase_vault_is_locked("passphrase", &session));
        assert!(!passphrase_vault_is_locked("keychain", &session));
        assert!(!passphrase_vault_is_locked("convenience", &session));
        assert!(!should_auto_start(true, "passphrase", true));
        assert!(should_auto_start(true, "keychain", true));
        assert!(should_auto_start(true, "convenience", true));
        assert!(!should_auto_start(false, "keychain", true));
        assert!(!should_auto_start(true, "keychain", false));
    }

    #[test]
    fn account_links_allow_only_known_routes_and_device_authorization_parameters() {
        assert!(
            validate_account_link(
                "https://notary.example/#/authorize?request_id=abc&approval_secret=xyz"
            )
            .is_ok()
        );
        assert!(validate_account_link("https://notary.example/#/dashboard/credits").is_ok());
        assert!(
            validate_account_link("https://notary.example/#/authorize?request_id=abc").is_err()
        );
        assert!(
            validate_account_link("https://notary.example/#/authorize?request_id=abc&evil=xyz")
                .is_err()
        );
        assert!(validate_account_link("http://example.com/#/dashboard").is_err());
    }
}
