//! Authenticated release checks shared by the CLI, daemon, and desktop shell.

use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fs2::FileExt as _;
use minisign_verify::{PublicKey, Signature};
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::AsyncWriteExt as _,
    sync::{RwLock, watch},
};

mod storage;

/// Public release origin compiled into official distributions.
pub const DEFAULT_PUBLIC_ORIGIN: &str = env!("LLM_NOTARY_PUBLIC_ORIGIN");
/// Exact source/release identity compiled into this updater.
pub const BUILD_ID: &str = env!("LLM_NOTARY_BUILD_ID");
/// Whether this build may replace installed release artifacts.
pub const UPDATES_ENABLED: bool = env!("LLM_NOTARY_UPDATES_ENABLED").as_bytes()[0] == b'1';

/// Writes a private release-adjacent file without exposing partial contents.
pub fn write_private_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    storage::write_private_file_atomically(path, contents)
}

const CHANNEL_ENVELOPE_SCHEMA: &str = "llm-notary/release-channel-envelope/v1";
const CHANNEL_SCHEMA: &str = "llm-notary/release-channel/v1";
const RELEASE_SCHEMA: &str = "llm-notary/release/v1";
const CHANNEL: &str = "latest";
const MANIFEST_LIMIT: usize = 512 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const PUBLIC_KEY: &str = include_str!("../../../config/updater-public-key.txt");
const JOURNAL_NAME: &str = ".llm-notary-update.json";
const CLI_BACKUP_NAME: &str = ".llm-notary.update-backup";
const DAEMON_BACKUP_NAME: &str = ".notaryd.update-backup";
const CHANNEL_STATE_NAME: &str = "update-channel.json";
const CHANNEL_LOCK_NAME: &str = ".update-channel.lock";
#[cfg(windows)]
const WINDOWS_RESULT_NAME: &str = ".llm-notary-update-result.json";

/// Finds the shared local configuration directory without depending on the
/// daemon's full configuration model.
pub fn default_config_path() -> Result<PathBuf> {
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
        bail!("could not determine a configuration directory")
    };
    Ok(base.join("llm-notary").join("config.toml"))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelEnvelope {
    schema_version: String,
    signed: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelPointer {
    schema_version: String,
    channel: String,
    channel_revision: u64,
    build_id: String,
    manifest_url: String,
    manifest_sha256: String,
    manifest_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelState {
    schema_version: String,
    channel: String,
    channel_revision: u64,
    signed_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub name: String,
    pub url: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlatform {
    pub archive: ReleaseArtifact,
    pub llm_notary: ReleaseArtifact,
    pub notaryd: ReleaseArtifact,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopUpdaterArtifact {
    #[serde(flatten)]
    pub artifact: ReleaseArtifact,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopRelease {
    pub dmg: ReleaseArtifact,
    pub updater: DesktopUpdaterArtifact,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TauriPlatform {
    pub url: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub build_id: String,
    pub commit_sha: String,
    pub version: String,
    pub published_at: String,
    pub artifacts: BTreeMap<String, ReleasePlatform>,
    pub desktop: BTreeMap<String, DesktopRelease>,
    pub platforms: BTreeMap<String, TauriPlatform>,
}

#[derive(Clone, Debug)]
pub struct VerifiedRelease {
    pub channel: String,
    pub channel_revision: u64,
    pub manifest_url: Url,
    pub manifest: ReleaseManifest,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCheck {
    pub channel: String,
    pub channel_revision: u64,
    pub current_build_id: String,
    pub latest_build_id: String,
    pub version: String,
    pub published_at: String,
    pub update_available: bool,
    pub official_build: bool,
    #[serde(skip)]
    pub release: Option<VerifiedRelease>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InstallOutcome {
    pub state: String,
    pub previous_build_id: String,
    pub new_build_id: String,
    pub updated_on_disk: bool,
    pub daemon_restart_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsUpdateResult {
    pub state: String,
    pub build_id: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct BackgroundUpdateStatus {
    pub enabled: bool,
    pub current_build_id: String,
    pub latest_build_id: Option<String>,
    pub update_available: bool,
    pub last_checked_unix_ms: Option<u64>,
    pub error_code: Option<String>,
}

pub type SharedUpdateStatus = Arc<RwLock<BackgroundUpdateStatus>>;

pub fn background_status() -> SharedUpdateStatus {
    Arc::new(RwLock::new(BackgroundUpdateStatus {
        enabled: is_official_build(),
        current_build_id: BUILD_ID.into(),
        latest_build_id: None,
        update_available: false,
        last_checked_unix_ms: None,
        error_code: None,
    }))
}

pub fn background_status_disabled(reason: &str) -> SharedUpdateStatus {
    Arc::new(RwLock::new(BackgroundUpdateStatus {
        enabled: false,
        current_build_id: BUILD_ID.into(),
        latest_build_id: None,
        update_available: false,
        last_checked_unix_ms: None,
        error_code: Some(reason.into()),
    }))
}

pub fn spawn_background_checker(
    status: SharedUpdateStatus,
    mut shutdown: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !is_official_build() {
        return None;
    }
    Some(tokio::spawn(async move {
        if wait_or_shutdown(Duration::from_secs(15), &mut shutdown).await {
            return;
        }
        loop {
            let checked_at = current_unix_ms();
            match check_latest().await {
                Ok(check) => {
                    let mut status = status.write().await;
                    status.latest_build_id = Some(check.latest_build_id);
                    status.update_available = check.update_available;
                    status.last_checked_unix_ms = checked_at;
                    status.error_code = None;
                }
                Err(_) => {
                    let mut status = status.write().await;
                    status.last_checked_unix_ms = checked_at;
                    status.error_code = Some("check_failed".into());
                }
            }
            let jitter = checked_at.unwrap_or(0) % (30 * 60 * 1_000);
            if wait_or_shutdown(
                Duration::from_millis(6 * 60 * 60 * 1_000 + jitter),
                &mut shutdown,
            )
            .await
            {
                return;
            }
        }
    }))
}

async fn wait_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
    }
}

fn current_unix_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateJournal {
    schema_version: String,
    build_id: String,
    phase: JournalPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    ReplacingDaemon,
    DaemonReplaced,
    ReplacingCli,
    CliReplaced,
}

pub fn is_official_build() -> bool {
    BUILD_ID != "dev" && UPDATES_ENABLED
}

pub fn channel_url() -> Result<Url> {
    Url::parse(&format!(
        "{DEFAULT_PUBLIC_ORIGIN}/downloads/cli/channels/{CHANNEL}.json"
    ))
    .context("the compiled update channel URL is invalid")
}

pub async fn check_latest() -> Result<UpdateCheck> {
    let channel_state = if is_official_build() {
        Some(channel_state_path()?)
    } else {
        None
    };
    check_from_url_with_state(channel_url()?, channel_state).await
}

async fn check_from_url_with_state(
    channel_url: Url,
    channel_state: Option<PathBuf>,
) -> Result<UpdateCheck> {
    require_https_url(&channel_url, "update channel")?;
    let client = update_http_client()?;
    let envelope_bytes = fetch_small(&client, channel_url, MANIFEST_LIMIT).await?;
    let envelope: ChannelEnvelope =
        serde_json::from_slice(&envelope_bytes).context("the update channel is malformed")?;
    ensure!(
        envelope.schema_version == CHANNEL_ENVELOPE_SCHEMA,
        "the update channel envelope schema is unsupported"
    );
    let pointer_bytes = BASE64_STANDARD
        .decode(envelope.signed.trim())
        .context("the signed update channel payload is not base64")?;
    ensure!(
        pointer_bytes.len() <= MANIFEST_LIMIT,
        "the signed update channel payload is too large"
    );
    verify_manifest_signature(&pointer_bytes, &envelope.signature, PUBLIC_KEY)
        .context("the update channel signature is invalid")?;
    let pointer: ChannelPointer = serde_json::from_slice(&pointer_bytes)
        .context("the signed update channel payload is malformed")?;
    validate_identifier(&pointer.build_id, "channel build ID")?;
    ensure!(
        pointer.schema_version == CHANNEL_SCHEMA,
        "the update channel schema is unsupported"
    );
    ensure!(
        pointer.channel == CHANNEL,
        "the update channel name is unexpected"
    );
    ensure!(
        pointer.channel_revision > 0,
        "the update channel revision is invalid"
    );
    validate_sha256(&pointer.manifest_sha256, "manifest SHA-256")?;
    let manifest_url = Url::parse(&pointer.manifest_url).context("the manifest URL is invalid")?;
    require_https_url(&manifest_url, "release manifest")?;
    require_build_url(&manifest_url, &pointer.build_id, "release.json")?;
    let manifest_bytes = fetch_small(&client, manifest_url.clone(), MANIFEST_LIMIT).await?;
    let actual_hash = hex::encode(Sha256::digest(&manifest_bytes));
    ensure!(
        actual_hash == pointer.manifest_sha256,
        "the release manifest hash does not match the channel pointer"
    );
    verify_manifest_signature(&manifest_bytes, &pointer.manifest_signature, PUBLIC_KEY)?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .context("the signed release manifest is malformed")?;
    validate_manifest(&manifest)?;
    ensure!(
        manifest.build_id == pointer.build_id,
        "the channel and manifest build IDs do not match"
    );
    if let Some(path) = channel_state {
        accept_channel_revision(&path, &pointer, &pointer_bytes)?;
    }
    let update_available = build_ids_differ(BUILD_ID, &manifest.build_id);
    Ok(UpdateCheck {
        channel: pointer.channel.clone(),
        channel_revision: pointer.channel_revision,
        current_build_id: BUILD_ID.into(),
        latest_build_id: manifest.build_id.clone(),
        version: manifest.version.clone(),
        published_at: manifest.published_at.clone(),
        update_available,
        official_build: is_official_build(),
        release: Some(VerifiedRelease {
            channel: pointer.channel,
            channel_revision: pointer.channel_revision,
            manifest_url,
            manifest,
        }),
    })
}

fn channel_state_path() -> Result<PathBuf> {
    let config = default_config_path()?;
    Ok(config
        .parent()
        .context("the configuration path has no parent directory")?
        .join(CHANNEL_STATE_NAME))
}

fn accept_channel_revision(
    path: &Path,
    pointer: &ChannelPointer,
    signed_bytes: &[u8],
) -> Result<()> {
    let parent = path
        .parent()
        .context("the update channel state has no parent directory")?;
    let mut directory = fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let existed = parent.try_exists().context("inspecting update state")?;
        directory.mode(0o700);
        directory.create(parent).context("creating update state")?;
        if !existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("restricting update state")?;
        }
    }
    #[cfg(not(unix))]
    directory.create(parent).context("creating update state")?;

    let lock_path = parent.join(CHANNEL_LOCK_NAME);
    let mut lock_options = fs::OpenOptions::new();
    lock_options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        lock_options.mode(0o600);
    }
    let lock = lock_options
        .open(&lock_path)
        .context("opening the update channel state lock")?;
    lock.lock_exclusive()
        .context("locking the update channel state")?;

    let signed_sha256 = hex::encode(Sha256::digest(signed_bytes));
    if path.exists() {
        let state: ChannelState =
            serde_json::from_slice(&fs::read(path).context("reading the update channel state")?)
                .context("the update channel state is malformed")?;
        ensure!(
            state.schema_version == "llm-notary/update-channel-state/v1"
                && state.channel == CHANNEL,
            "the update channel state is unsupported"
        );
        ensure!(
            pointer.channel_revision >= state.channel_revision,
            "the signed update channel revision was replayed"
        );
        if pointer.channel_revision == state.channel_revision {
            ensure!(
                signed_sha256 == state.signed_sha256,
                "the signed update channel revision conflicts with the accepted revision"
            );
            return Ok(());
        }
    }
    let bytes = serde_json::to_vec(&ChannelState {
        schema_version: "llm-notary/update-channel-state/v1".into(),
        channel: pointer.channel.clone(),
        channel_revision: pointer.channel_revision,
        signed_sha256,
    })?;
    storage::write_private_file_atomically(path, &bytes)
        .context("persisting the authenticated update channel revision")
}

fn build_ids_differ(current: &str, latest: &str) -> bool {
    current != latest
}

pub fn verify_manifest_signature(bytes: &[u8], signature: &str, public_key: &str) -> Result<()> {
    let public_key = decode_wrapped_text(public_key, "updater public key")?;
    let signature = decode_wrapped_text(signature, "release manifest signature")?;
    PublicKey::decode(&public_key)
        .context("the updater public key is malformed")?
        .verify(
            bytes,
            &Signature::decode(&signature)
                .context("the release manifest signature is malformed")?,
            true,
        )
        .context("the release manifest signature is invalid")
}

fn decode_wrapped_text(value: &str, name: &str) -> Result<String> {
    let bytes = BASE64_STANDARD
        .decode(value.trim())
        .with_context(|| format!("the {name} is not base64"))?;
    String::from_utf8(bytes).with_context(|| format!("the {name} is not UTF-8"))
}

fn update_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("llm-notary-updater/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("initializing the update client")
}

async fn fetch_small(client: &reqwest::Client, url: Url, maximum: usize) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .header(header::CACHE_CONTROL, "no-cache, no-store")
        .header(header::PRAGMA, "no-cache")
        .send()
        .await
        .context("requesting update metadata")?;
    ensure!(
        response.status() == StatusCode::OK,
        "the update server did not return update metadata"
    );
    require_https_url(response.url(), "update response")?;
    if let Some(length) = response.content_length() {
        ensure!(length <= maximum as u64, "the update metadata is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("reading update metadata")? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= maximum,
            "the update metadata is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<()> {
    ensure!(
        manifest.schema_version == RELEASE_SCHEMA,
        "the release manifest schema is unsupported"
    );
    validate_identifier(&manifest.build_id, "manifest build ID")?;
    ensure!(
        manifest.commit_sha.len() == 40
            && manifest
                .commit_sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the release commit SHA is invalid"
    );
    validate_identifier(&manifest.version, "release version")?;
    ensure!(
        manifest.published_at.ends_with('Z') && manifest.published_at.contains('T'),
        "the release timestamp is invalid"
    );
    let expected = [
        ("linux-x86_64", ""),
        ("linux-aarch64", ""),
        ("darwin-aarch64", ""),
        ("windows-x86_64", ".exe"),
    ];
    ensure!(
        manifest.artifacts.len() == expected.len(),
        "the release manifest has an unexpected platform set"
    );
    for (platform, suffix) in expected {
        let artifacts = manifest
            .artifacts
            .get(platform)
            .with_context(|| format!("the release is missing {platform}"))?;
        validate_artifact(&artifacts.archive, &manifest.build_id, None)?;
        validate_artifact(
            &artifacts.llm_notary,
            &manifest.build_id,
            Some(&format!("llm-notary-{platform}{suffix}")),
        )?;
        validate_artifact(
            &artifacts.notaryd,
            &manifest.build_id,
            Some(&format!("notaryd-{platform}{suffix}")),
        )?;
    }
    ensure!(
        manifest.desktop.len() == 1 && manifest.platforms.len() == 1,
        "the desktop release platform set is unexpected"
    );
    let desktop = manifest
        .desktop
        .get("darwin-aarch64")
        .context("the macOS desktop release is missing")?;
    validate_artifact(
        &desktop.dmg,
        &manifest.build_id,
        Some("LLM-Notary-macos-arm64.dmg"),
    )?;
    validate_artifact(
        &desktop.updater.artifact,
        &manifest.build_id,
        Some("LLM-Notary-macos-arm64.app.tar.gz"),
    )?;
    decode_wrapped_text(&desktop.updater.signature, "desktop updater signature")?;
    let tauri = manifest
        .platforms
        .get("darwin-aarch64")
        .context("the Tauri macOS platform is missing")?;
    ensure!(
        tauri.url == desktop.updater.artifact.url && tauri.signature == desktop.updater.signature,
        "the desktop updater entries do not match"
    );
    Ok(())
}

fn validate_artifact(
    artifact: &ReleaseArtifact,
    build_id: &str,
    expected_name: Option<&str>,
) -> Result<()> {
    if let Some(expected_name) = expected_name {
        ensure!(
            artifact.name == expected_name,
            "the release artifact name is unexpected"
        );
    } else {
        validate_identifier(&artifact.name, "release artifact name")?;
    }
    ensure!(
        artifact.size_bytes > 0 && artifact.size_bytes <= MAX_ARTIFACT_BYTES,
        "the release artifact size is invalid"
    );
    validate_sha256(&artifact.sha256, "release artifact SHA-256")?;
    let url = Url::parse(&artifact.url).context("a release artifact URL is invalid")?;
    require_https_url(&url, "release artifact")?;
    require_build_url(&url, build_id, &artifact.name)
}

fn require_https_url(url: &Url, name: &str) -> Result<()> {
    ensure!(url.scheme() == "https", "the {name} URL must use HTTPS");
    ensure!(
        url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
        "the {name} URL authority is invalid"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "the {name} URL must not have a query or fragment"
    );
    Ok(())
}

fn require_build_url(url: &Url, build_id: &str, name: &str) -> Result<()> {
    let expected = format!("/cli/builds/{build_id}/{name}");
    ensure!(
        url.path().ends_with(&expected),
        "the release URL is not inside its immutable build directory"
    );
    Ok(())
}

fn validate_identifier(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value.starts_with('.')
            && !value.contains("..")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "the {name} is invalid"
    );
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the {name} is invalid"
    );
    Ok(())
}

fn platform_name() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        ("macos", "aarch64") => Ok("darwin-aarch64"),
        ("windows", "x86_64") => Ok("windows-x86_64"),
        (os, arch) => bail!("automatic updates are not available for {os}-{arch}"),
    }
}

pub async fn install_latest() -> Result<InstallOutcome> {
    ensure!(
        is_official_build(),
        "source and development builds cannot replace themselves; install an official build first"
    );
    let install = InstallPaths::discover()?;
    recover_interrupted_update(&install)?;
    ensure_current_pair(&install)?;
    let check = check_latest().await?;
    if !check.update_available {
        return Ok(InstallOutcome {
            state: "current".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: BUILD_ID.into(),
            updated_on_disk: false,
            daemon_restart_required: false,
        });
    }
    let release = check
        .release
        .context("the verified release is unavailable")?;
    install_verified_release(&install, &release).await
}

async fn install_verified_release(
    install: &InstallPaths,
    release: &VerifiedRelease,
) -> Result<InstallOutcome> {
    #[cfg(windows)]
    ensure_windows_daemon_stopped(install)?;
    let platform = platform_name()?;
    let artifacts = release
        .manifest
        .artifacts
        .get(platform)
        .with_context(|| format!("the release has no payloads for {platform}"))?;
    let staging = tempfile::Builder::new()
        .prefix(".llm-notary-update-")
        .tempdir_in(&install.directory)
        .with_context(|| {
            format!(
                "creating an update staging directory in {}",
                install.directory.display()
            )
        })?;
    let cli_candidate = staging.path().join(cli_file_name());
    let daemon_candidate = staging.path().join(daemon_file_name());
    let client = update_http_client()?;
    download_artifact(&client, &artifacts.llm_notary, &cli_candidate).await?;
    download_artifact(&client, &artifacts.notaryd, &daemon_candidate).await?;
    make_executable(&cli_candidate)?;
    make_executable(&daemon_candidate)?;
    ensure_candidate_build(&cli_candidate, &release.manifest.build_id, "llm-notary")?;
    ensure_candidate_build(&daemon_candidate, &release.manifest.build_id, "notaryd")?;

    #[cfg(unix)]
    {
        apply_update_transaction(
            install,
            &cli_candidate,
            &daemon_candidate,
            &release.manifest.build_id,
        )?;
        Ok(InstallOutcome {
            state: "updated".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: release.manifest.build_id.clone(),
            updated_on_disk: true,
            daemon_restart_required: true,
        })
    }
    #[cfg(windows)]
    {
        let staging = staging.keep();
        let helper = staging.join("llm-notary-update-helper.exe");
        fs::copy(&cli_candidate, &helper).context("creating the Windows update helper")?;
        let mut command = Command::new(&helper);
        command
            .arg("__apply-update")
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .arg("--install-directory")
            .arg(&install.directory)
            .arg("--staging-directory")
            .arg(&staging)
            .arg("--build-id")
            .arg(&release.manifest.build_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x08000000);
        command
            .spawn()
            .context("starting the Windows update helper")?;
        Ok(InstallOutcome {
            state: "staged".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: release.manifest.build_id.clone(),
            updated_on_disk: false,
            daemon_restart_required: true,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("automatic installation is not implemented on this operating system")
    }
}

async fn download_artifact(
    client: &reqwest::Client,
    artifact: &ReleaseArtifact,
    destination: &Path,
) -> Result<()> {
    let url = Url::parse(&artifact.url).context("the artifact URL is invalid")?;
    let mut response = client
        .get(url)
        .send()
        .await
        .context("downloading the update")?;
    ensure!(
        response.status() == StatusCode::OK,
        "the update server did not return an artifact"
    );
    require_https_url(response.url(), "artifact response")?;
    if let Some(length) = response.content_length() {
        ensure!(
            length == artifact.size_bytes,
            "the update download size does not match its manifest"
        );
    }
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .await
        .context("creating the staged update")?;
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading the update download")?
    {
        size = size
            .checked_add(chunk.len() as u64)
            .context("the update size overflowed")?;
        ensure!(
            size <= artifact.size_bytes,
            "the update download is larger than its manifest"
        );
        hash.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .context("writing the staged update")?;
    }
    output
        .sync_all()
        .await
        .context("syncing the staged update")?;
    ensure!(
        size == artifact.size_bytes,
        "the update download ended before its declared size"
    );
    ensure!(
        hex::encode(hash.finalize()) == artifact.sha256,
        "the update download hash does not match its signed manifest"
    );
    Ok(())
}

/// Verifies bytes selected by the authenticated release manifest.
///
/// The desktop updater uses this in addition to Tauri's bundle signature so
/// both update paths enforce the same signed size and SHA-256 contract.
pub fn verify_artifact_bytes(artifact: &ReleaseArtifact, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() as u64 == artifact.size_bytes,
        "the update download size does not match its signed manifest"
    );
    ensure!(
        hex::encode(Sha256::digest(bytes)) == artifact.sha256,
        "the update download hash does not match its signed manifest"
    );
    Ok(())
}

#[derive(Debug)]
struct InstallPaths {
    directory: PathBuf,
    cli: PathBuf,
    daemon: PathBuf,
    journal: PathBuf,
    cli_backup: PathBuf,
    daemon_backup: PathBuf,
}

impl InstallPaths {
    fn discover() -> Result<Self> {
        let cli = std::env::current_exe().context("locating the running llm-notary executable")?;
        let directory = cli
            .parent()
            .context("the running executable has no parent directory")?
            .to_owned();
        ensure!(
            cli.file_name().and_then(|name| name.to_str()) == Some(cli_file_name()),
            "automatic updates require an executable named {}",
            cli_file_name()
        );
        let display = cli.to_string_lossy().to_ascii_lowercase();
        ensure!(
            !display.contains(".app/contents/macos/"),
            "the desktop app must update its bundled service as part of the whole app"
        );
        ensure!(
            !display.contains("/cellar/")
                && !display.contains("/nix/store/")
                && !display.starts_with("/usr/bin/")
                && !display.contains("/opt/local/"),
            "this installation is managed by a package manager; update it with that package manager"
        );
        let daemon = directory.join(daemon_file_name());
        for path in [&cli, &daemon] {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspecting {}", path.display()))?;
            ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "{} is not a regular installed file",
                path.display()
            );
        }
        Ok(Self {
            journal: directory.join(JOURNAL_NAME),
            cli_backup: directory.join(CLI_BACKUP_NAME),
            daemon_backup: directory.join(DAEMON_BACKUP_NAME),
            directory,
            cli,
            daemon,
        })
    }

    #[cfg(any(test, windows))]
    fn from_directory(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
            cli: directory.join(cli_file_name()),
            daemon: directory.join(daemon_file_name()),
            journal: directory.join(JOURNAL_NAME),
            cli_backup: directory.join(CLI_BACKUP_NAME),
            daemon_backup: directory.join(DAEMON_BACKUP_NAME),
        }
    }
}

fn cli_file_name() -> &'static str {
    if cfg!(windows) {
        "llm-notary.exe"
    } else {
        "llm-notary"
    }
}

fn daemon_file_name() -> &'static str {
    if cfg!(windows) {
        "notaryd.exe"
    } else {
        "notaryd"
    }
}

#[cfg(windows)]
fn ensure_windows_daemon_stopped(install: &InstallPaths) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
    };

    let path = install
        .daemon
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        handle != INVALID_HANDLE_VALUE,
        "notaryd.exe is running, locked, or cannot be replaced; stop the local service before updating"
    );
    unsafe { CloseHandle(handle) };
    Ok(())
}

fn ensure_current_pair(install: &InstallPaths) -> Result<()> {
    ensure_candidate_build(&install.cli, BUILD_ID, "llm-notary")?;
    ensure_candidate_build(&install.daemon, BUILD_ID, "notaryd")
}

fn ensure_candidate_build(path: &Path, build_id: &str, program: &str) -> Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running staged {program}"))?;
    ensure!(
        output.status.success(),
        "the staged {program} did not report its version"
    );
    let stdout =
        String::from_utf8(output.stdout).context("the staged program version is not UTF-8")?;
    ensure!(
        stdout.contains(&format!("({build_id})")),
        "the staged {program} build ID does not match the signed release"
    );
    Ok(())
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("marking {} executable", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn apply_update_transaction(
    install: &InstallPaths,
    cli_candidate: &Path,
    daemon_candidate: &Path,
    build_id: &str,
) -> Result<()> {
    ensure!(
        path_is_absent(&install.cli_backup)?
            && path_is_absent(&install.daemon_backup)?
            && path_is_absent(&install.journal)?,
        "a previous update has not been recovered"
    );
    write_journal(install, build_id, JournalPhase::Prepared)?;
    hard_link_backup(&install.daemon, &install.daemon_backup)?;
    write_journal(install, build_id, JournalPhase::ReplacingDaemon)?;
    if let Err(error) = replace_file(daemon_candidate, &install.daemon) {
        let _ = recover_interrupted_update(install);
        return Err(error).context("installing the new notaryd");
    }
    sync_directory(&install.directory)?;
    write_journal(install, build_id, JournalPhase::DaemonReplaced)?;
    hard_link_backup(&install.cli, &install.cli_backup)?;
    write_journal(install, build_id, JournalPhase::ReplacingCli)?;
    if let Err(error) = replace_file(cli_candidate, &install.cli) {
        let _ = recover_interrupted_update(install);
        return Err(error).context("installing the new llm-notary");
    }
    sync_directory(&install.directory)?;
    write_journal(install, build_id, JournalPhase::CliReplaced)?;
    if let Err(error) = ensure_candidate_build(&install.cli, build_id, "llm-notary")
        .and_then(|_| ensure_candidate_build(&install.daemon, build_id, "notaryd"))
    {
        let rollback = rollback_to_backups(install);
        return match rollback {
            Ok(()) => Err(error).context("validating the installed update; restored the old pair"),
            Err(rollback_error) => Err(error).context(format!(
                "validating the installed update; rollback also failed: {rollback_error:#}"
            )),
        };
    }
    finish_transaction(install)
}

fn hard_link_backup(source: &Path, backup: &Path) -> Result<()> {
    ensure!(
        path_is_absent(backup)?,
        "the rollback path {} already exists",
        backup.display()
    );
    if let Err(link_error) = fs::hard_link(source, backup) {
        let mut input = fs::File::open(source)
            .with_context(|| format!("opening installed file {}", source.display()))?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o700);
        }
        let mut output = options.open(backup).with_context(|| {
            format!(
                "creating rollback copy {} after hard-link failure: {link_error}",
                backup.display()
            )
        })?;
        std::io::copy(&mut input, &mut output)
            .with_context(|| format!("writing rollback copy {}", backup.display()))?;
        output
            .sync_all()
            .with_context(|| format!("syncing rollback copy {}", backup.display()))?;
    }
    sync_directory(
        source
            .parent()
            .context("installed file has no parent directory")?,
    )
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn rollback_to_backups(install: &InstallPaths) -> Result<()> {
    restore_backup(&install.cli_backup, &install.cli)?;
    restore_backup(&install.daemon_backup, &install.daemon)?;
    remove_if_exists(&install.cli_backup)?;
    remove_if_exists(&install.daemon_backup)?;
    remove_if_exists(&install.journal)?;
    sync_directory(&install.directory)
}

fn write_journal(install: &InstallPaths, build_id: &str, phase: JournalPhase) -> Result<()> {
    let bytes = serde_json::to_vec(&UpdateJournal {
        schema_version: "llm-notary/update-journal/v1".into(),
        build_id: build_id.into(),
        phase,
    })?;
    storage::write_private_file_atomically(&install.journal, &bytes)?;
    sync_directory(&install.directory)
}

fn recover_interrupted_update(install: &InstallPaths) -> Result<()> {
    if path_is_absent(&install.journal)? {
        ensure!(
            path_is_absent(&install.cli_backup)? && path_is_absent(&install.daemon_backup)?,
            "orphaned update rollback files require manual inspection"
        );
        return Ok(());
    }
    let journal: UpdateJournal =
        serde_json::from_slice(&fs::read(&install.journal).context("reading the update journal")?)
            .context("the update journal is malformed")?;
    ensure!(
        journal.schema_version == "llm-notary/update-journal/v1",
        "the update journal schema is unsupported"
    );
    validate_identifier(&journal.build_id, "journal build ID")?;
    match journal.phase {
        JournalPhase::Prepared => {}
        JournalPhase::ReplacingDaemon | JournalPhase::DaemonReplaced => {
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
        JournalPhase::ReplacingCli => {
            restore_backup(&install.cli_backup, &install.cli)?;
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
        JournalPhase::CliReplaced => {
            if ensure_candidate_build(&install.cli, &journal.build_id, "llm-notary").is_ok()
                && ensure_candidate_build(&install.daemon, &journal.build_id, "notaryd").is_ok()
            {
                return finish_transaction(install);
            }
            restore_backup(&install.cli_backup, &install.cli)?;
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
    }
    remove_if_exists(&install.cli_backup)?;
    remove_if_exists(&install.daemon_backup)?;
    remove_if_exists(&install.journal)?;
    sync_directory(&install.directory)
}

fn restore_backup(backup: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(backup)
        .with_context(|| format!("inspecting update rollback copy {}", backup.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "the update rollback copy {} is missing",
        backup.display()
    );
    if target.is_file() && files_match(backup, target)? {
        return remove_if_exists(backup);
    }
    replace_file(backup, target).with_context(|| format!("restoring {}", target.display()))
}

fn files_match(left: &Path, right: &Path) -> Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = fs::metadata(right)?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }
    Ok(file_sha256(left)? == file_sha256(right)?)
}

fn file_sha256(path: &Path) -> Result<[u8; 32]> {
    let mut input = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

fn finish_transaction(install: &InstallPaths) -> Result<()> {
    remove_if_exists(&install.cli_backup)?;
    remove_if_exists(&install.daemon_backup)?;
    remove_if_exists(&install.journal)?;
    sync_directory(&install.directory)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("opening {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn run_windows_apply_helper(
    parent_pid: u32,
    install_directory: &Path,
    staging_directory: &Path,
    build_id: &str,
) -> Result<()> {
    let result =
        run_windows_apply_helper_inner(parent_pid, install_directory, staging_directory, build_id);
    let report = WindowsUpdateResult {
        state: if result.is_ok() { "updated" } else { "failed" }.into(),
        build_id: build_id.into(),
        message: if result.is_ok() {
            "The staged Windows update completed.".into()
        } else {
            "The staged Windows update failed safely. Run llm-notary update again after stopping notaryd.".into()
        },
    };
    let report_path = install_directory.join(WINDOWS_RESULT_NAME);
    if let Ok(bytes) = serde_json::to_vec(&report) {
        let _ = storage::write_private_file_atomically(&report_path, &bytes);
    }
    result
}

#[cfg(windows)]
fn run_windows_apply_helper_inner(
    parent_pid: u32,
    install_directory: &Path,
    staging_directory: &Path,
    build_id: &str,
) -> Result<()> {
    wait_for_process(parent_pid);
    validate_identifier(build_id, "helper build ID")?;
    let install = InstallPaths::from_directory(install_directory);
    ensure!(
        staging_directory.parent() == Some(install_directory),
        "the helper staging directory is outside the installation directory"
    );
    recover_interrupted_update(&install)?;
    ensure_windows_daemon_stopped(&install)?;
    apply_update_transaction(
        &install,
        &staging_directory.join(cli_file_name()),
        &staging_directory.join(daemon_file_name()),
        build_id,
    )?;
    schedule_windows_helper_cleanup(staging_directory);
    Ok(())
}

#[cfg(windows)]
pub fn windows_update_result() -> Option<WindowsUpdateResult> {
    let executable = std::env::current_exe().ok()?;
    let path = executable.parent()?.join(WINDOWS_RESULT_NAME);
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[cfg(not(windows))]
pub fn windows_update_result() -> Option<WindowsUpdateResult> {
    None
}

#[cfg(not(windows))]
pub fn run_windows_apply_helper(
    _parent_pid: u32,
    _install_directory: &Path,
    _staging_directory: &Path,
    _build_id: &str,
) -> Result<()> {
    bail!("the Windows update helper is unavailable on this operating system")
}

#[cfg(windows)]
fn wait_for_process(pid: u32) {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{INFINITE, OpenProcess, WaitForSingleObject},
    };
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, pid) };
    if !handle.is_null() {
        unsafe {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
fn schedule_windows_helper_cleanup(staging_directory: &Path) {
    fn schedule(path: &Path) {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
        let path = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            MoveFileExW(path.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
    if let Ok(helper) = std::env::current_exe() {
        schedule(&helper);
    }
    schedule(staging_directory);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = "untrusted comment: minisign public key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n";
    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1555779966\tfile:test\nQtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==\n";

    #[test]
    fn exact_build_identity_drives_update_availability() {
        assert!(!build_ids_differ("same", "same"));
        assert!(build_ids_differ("new", "old"));
        assert!(build_ids_differ("old", "new"));
    }

    #[test]
    fn authenticates_exact_manifest_bytes() {
        let public_key = BASE64_STANDARD.encode(TEST_PUBLIC_KEY);
        let signature = BASE64_STANDARD.encode(TEST_SIGNATURE);
        verify_manifest_signature(b"test", &signature, &public_key).unwrap();
        assert!(verify_manifest_signature(b"tampered", &signature, &public_key).is_err());
        assert!(verify_manifest_signature(b"test", "not-base64", &public_key).is_err());
    }

    fn channel_pointer(revision: u64) -> ChannelPointer {
        ChannelPointer {
            schema_version: CHANNEL_SCHEMA.into(),
            channel: CHANNEL.into(),
            channel_revision: revision,
            build_id: "build".into(),
            manifest_url: "https://example.com/downloads/cli/builds/build/release.json".into(),
            manifest_sha256: "a".repeat(64),
            manifest_signature: "signature".into(),
        }
    }

    #[test]
    fn channel_revision_rejects_replay_and_conflicting_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(CHANNEL_STATE_NAME);
        accept_channel_revision(&path, &channel_pointer(20), b"revision-20").unwrap();
        accept_channel_revision(&path, &channel_pointer(20), b"revision-20").unwrap();
        assert!(accept_channel_revision(&path, &channel_pointer(19), b"revision-19").is_err());
        assert!(accept_channel_revision(&path, &channel_pointer(20), b"conflict").is_err());
        accept_channel_revision(&path, &channel_pointer(21), b"authorized-rollback").unwrap();
    }

    #[test]
    fn rejects_unsafe_release_urls_and_identifiers() {
        assert!(validate_identifier("../latest", "test").is_err());
        assert!(validate_sha256(&"a".repeat(64), "test").is_ok());
        assert!(
            require_build_url(
                &Url::parse(
                    "https://example.com/downloads/cli/builds/build/llm-notary-linux-x86_64"
                )
                .unwrap(),
                "build",
                "llm-notary-linux-x86_64",
            )
            .is_ok()
        );
        assert!(
            require_build_url(
                &Url::parse("https://example.com/downloads/cli/latest").unwrap(),
                "build",
                "llm-notary-linux-x86_64",
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    fn executable(path: &Path, program: &str, build_id: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(
            path,
            format!("#!/bin/sh\necho '{program} 0.1.0 ({build_id})'\n"),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaces_both_programs_and_removes_the_journal() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "llm-notary", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        let cli_candidate = directory.path().join("new-cli");
        let daemon_candidate = directory.path().join("new-daemon");
        executable(&cli_candidate, "llm-notary", "new-build");
        executable(&daemon_candidate, "notaryd", "new-build");

        apply_update_transaction(&install, &cli_candidate, &daemon_candidate, "new-build").unwrap();

        ensure_candidate_build(&install.cli, "new-build", "llm-notary").unwrap();
        ensure_candidate_build(&install.daemon, "new-build", "notaryd").unwrap();
        assert!(!install.journal.exists());
        assert!(!install.cli_backup.exists());
        assert!(!install.daemon_backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn restores_the_old_pair_when_the_second_replace_fails() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "llm-notary", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        let missing_cli_candidate = directory.path().join("missing-cli");
        let daemon_candidate = directory.path().join("new-daemon");
        executable(&daemon_candidate, "notaryd", "new-build");

        assert!(
            apply_update_transaction(
                &install,
                &missing_cli_candidate,
                &daemon_candidate,
                "new-build",
            )
            .is_err()
        );

        ensure_candidate_build(&install.cli, "old-build", "llm-notary").unwrap();
        ensure_candidate_build(&install.daemon, "old-build", "notaryd").unwrap();
        assert!(!install.journal.exists());
        assert!(!install.cli_backup.exists());
        assert!(!install.daemon_backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovers_a_crash_between_pair_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "llm-notary", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        hard_link_backup(&install.cli, &install.cli_backup).unwrap();
        hard_link_backup(&install.daemon, &install.daemon_backup).unwrap();
        let new_cli = directory.path().join("new-cli");
        let new_daemon = directory.path().join("new-daemon");
        executable(&new_cli, "llm-notary", "new-build");
        executable(&new_daemon, "notaryd", "new-build");
        replace_file(&new_cli, &install.cli).unwrap();
        replace_file(&new_daemon, &install.daemon).unwrap();
        write_journal(&install, "new-build", JournalPhase::ReplacingCli).unwrap();

        recover_interrupted_update(&install).unwrap();

        ensure_candidate_build(&install.cli, "old-build", "llm-notary").unwrap();
        ensure_candidate_build(&install.daemon, "old-build", "notaryd").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recovery_finishes_a_fully_replaced_current_pair() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "llm-notary", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        hard_link_backup(&install.cli, &install.cli_backup).unwrap();
        hard_link_backup(&install.daemon, &install.daemon_backup).unwrap();
        let new_cli = directory.path().join("new-cli");
        let new_daemon = directory.path().join("new-daemon");
        executable(&new_cli, "llm-notary", "new-build");
        executable(&new_daemon, "notaryd", "new-build");
        replace_file(&new_cli, &install.cli).unwrap();
        replace_file(&new_daemon, &install.daemon).unwrap();
        write_journal(&install, "new-build", JournalPhase::CliReplaced).unwrap();

        recover_interrupted_update(&install).unwrap();

        ensure_candidate_build(&install.cli, "new-build", "llm-notary").unwrap();
        ensure_candidate_build(&install.daemon, "new-build", "notaryd").unwrap();
        assert!(path_is_absent(&install.journal).unwrap());
        assert!(path_is_absent(&install.cli_backup).unwrap());
        assert!(path_is_absent(&install.daemon_backup).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn backup_creation_never_follows_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let backup = directory.path().join("backup");
        let outside = directory.path().join("outside");
        fs::write(&source, b"installed").unwrap();
        symlink(&outside, &backup).unwrap();

        assert!(hard_link_backup(&source, &backup).is_err());
        assert!(!outside.exists());
        assert_eq!(fs::read(&source).unwrap(), b"installed");
    }

    #[cfg(windows)]
    #[test]
    fn windows_preflight_requires_the_daemon_file_to_be_unlocked() {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
            Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
        };

        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        fs::write(&install.daemon, b"daemon fixture").unwrap();
        ensure_windows_daemon_stopped(&install).unwrap();

        let path = install
            .daemon
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert!(ensure_windows_daemon_stopped(&install).is_err());
        unsafe { CloseHandle(handle) };
        ensure_windows_daemon_stopped(&install).unwrap();
    }
}
