use std::{
    collections::HashSet,
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use tokio_stream::wrappers::ReceiverStream;

use super::{
    api_origin::ApiOrigin,
    auth,
    config::load_agent_config,
    http_client_builder,
    notary::{parse_directory, pin},
};
use crate::{
    DeferredBundle, DeferredCaptureConfig,
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{
        ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore, ArtifactStoreError,
    },
    attestable_request_header_bytes, chunked_request_body,
    config::{AgentConfig, ProviderConfig},
    deferred_streaming_request_to, deferred_streaming_request_to_admitted,
    metadata::{CaptureCompletion, NewCapture},
    metadata_store::{CaptureClaim, MetadataStoreError},
    notary_admission_error,
    notary_directory::{NotaryDirectory, NotaryDirectoryRecord, NotaryEndpoint},
    persistence::Persistence,
    server_runtime::{Lifecycle, ServerRuntime},
    vault::Vault,
};

#[cfg(test)]
use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    artifact_router::RoutedArtifactStore, artifact_store::FileSystemArtifactStore,
    sqlite_catalog::SqliteCatalog, sqlite_metadata_store::SqliteMetadataStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Provider {
    Openai,
    OpenaiCodex,
    Anthropic,
    Deepseek,
    Openrouter,
}

impl Provider {
    const ALL: [Self; 5] = [
        Self::Openai,
        Self::OpenaiCodex,
        Self::Anthropic,
        Self::Deepseek,
        Self::Openrouter,
    ];

    fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::OpenaiCodex => "chatgpt.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Deepseek => "api.deepseek.com",
            Self::Openrouter => "openrouter.ai",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Openai | Self::OpenaiCodex => "openai",
            Self::Anthropic => "anthropic",
            Self::Deepseek => "deepseek",
            Self::Openrouter => "openrouter",
        }
    }

    #[cfg(test)]
    fn default_path_prefix(self) -> &'static str {
        match self {
            Self::Openai => "/openai",
            Self::OpenaiCodex => "/codex",
            Self::Anthropic => "/anthropic",
            Self::Deepseek => "/deepseek",
            Self::Openrouter => "/openrouter",
        }
    }

    fn config(self, config: &AgentConfig) -> &ProviderConfig {
        match self {
            Self::Openai => &config.providers.openai,
            Self::OpenaiCodex => &config.providers.codex,
            Self::Anthropic => &config.providers.anthropic,
            Self::Deepseek => &config.providers.deepseek,
            Self::Openrouter => &config.providers.openrouter,
        }
    }

    fn upstream_path_prefix(self) -> &'static str {
        match self {
            Self::OpenaiCodex => "/backend-api/codex",
            _ => "",
        }
    }
}

#[derive(Debug)]
pub struct ProxyArgs {
    /// Versioned local agent configuration file. Defaults to the standard
    /// path, creating an editable default there on first use.
    pub(crate) config: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    capture_mode: Arc<CaptureMode>,
    direct_upstream: Arc<dyn DirectUpstreamConnector>,
    max_frame_bytes: usize,
    max_attestable_http_bytes: usize,
    pub(crate) vault: Arc<Vault>,
    pub(crate) persistence: Persistence,
    pub(crate) config: Arc<AgentConfig>,
    config_fingerprint: Arc<str>,
    serial: Arc<Mutex<u64>>,
    hosted_admission: bool,
    capture_tasks: CaptureTasks,
    server_runtime: Option<Arc<ServerRuntime>>,
}

pub(crate) struct CaptureMode {
    enabled: AtomicBool,
    notary: RwLock<Option<NotaryEndpoint>>,
    transition: Mutex<()>,
    config: Arc<AgentConfig>,
    persistence: Persistence,
    server_runtime: Option<Arc<ServerRuntime>>,
    #[cfg(test)]
    fail_notary_initialization: AtomicBool,
}

impl CaptureMode {
    pub(crate) fn new(
        enabled: bool,
        notary: Option<NotaryEndpoint>,
        config: Arc<AgentConfig>,
        persistence: Persistence,
        server_runtime: Option<Arc<ServerRuntime>>,
    ) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            notary: RwLock::new(notary),
            transition: Mutex::new(()),
            config,
            persistence,
            server_runtime,
            #[cfg(test)]
            fail_notary_initialization: AtomicBool::new(false),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    async fn snapshot(&self) -> Result<bool> {
        // PostgreSQL is the shared daemon setting. Refreshing at admission
        // lets replicas converge without keeping a competing process-local
        // preference or letting a stale value execute the wrong request path.
        if self.server_runtime.is_some() {
            let persisted = self.persistence.metadata.capture_enabled().await?;
            if persisted != self.enabled() {
                if persisted {
                    self.ensure_notary().await?;
                }
                self.enabled.store(persisted, Ordering::Release);
            }
        }
        Ok(self.enabled())
    }

    async fn notary(&self) -> Result<NotaryEndpoint> {
        self.notary
            .read()
            .await
            .clone()
            .context("capture mode has no initialized trusted notary")
    }

    async fn ensure_notary(&self) -> Result<NotaryEndpoint> {
        #[cfg(test)]
        if self.fail_notary_initialization.load(Ordering::Acquire) {
            bail!("injected trusted notary initialization failure");
        }
        if let Some(notary) = self.notary.read().await.clone() {
            return Ok(notary);
        }
        let notary = initialize_notary(
            &self.config,
            &self.persistence,
            self.server_runtime.as_deref(),
        )
        .await?;
        *self.notary.write().await = Some(notary.clone());
        Ok(notary)
    }

    pub(crate) async fn set_enabled(&self, enabled: bool) -> Result<bool> {
        let _transition = self.transition.lock().await;
        let persisted = self.persistence.metadata.capture_enabled().await?;
        if persisted == enabled {
            if enabled {
                self.ensure_notary().await?;
            }
            self.enabled.store(persisted, Ordering::Release);
            return Ok(persisted);
        }
        // Enabling is prepared before the durable transition. A discovery or
        // trust failure therefore cannot leave the selected mode half-on.
        if enabled {
            self.ensure_notary().await?;
        }
        let authoritative = self
            .persistence
            .metadata
            .set_capture_enabled(enabled, current_unix_ms()?)
            .await?;
        self.enabled.store(authoritative, Ordering::Release);
        Ok(authoritative)
    }
}

struct DirectUpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

#[async_trait::async_trait]
trait DirectUpstreamConnector: Send + Sync {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse>;
}

struct ReqwestDirectUpstreamConnector {
    client: reqwest::Client,
}

impl ReqwestDirectUpstreamConnector {
    fn new() -> Result<Self> {
        Ok(Self {
            client: http_client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        })
    }
}

#[async_trait::async_trait]
impl DirectUpstreamConnector for ReqwestDirectUpstreamConnector {
    async fn send(&self, provider: Provider, request: Request) -> Result<DirectUpstreamResponse> {
        let (parts, body) = request.into_parts();
        let url = format!("https://{}{}", provider.host(), parts.uri);
        let response = self
            .client
            .request(parts.method, url)
            .headers(parts.headers)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
            .context("sending direct provider request")?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(DirectUpstreamResponse {
            status,
            headers,
            body: Body::from_stream(response.bytes_stream()),
        })
    }
}

#[derive(Clone, Default)]
struct CaptureTasks {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

struct CaptureTaskGuard(CaptureTasks);

impl CaptureTasks {
    fn track(&self) -> CaptureTaskGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CaptureTaskGuard(self.clone())
    }

    async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for CaptureTaskGuard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let (config, config_path) = load_agent_config(args.config.as_deref())?;
    auth::validate_credential_configuration()?;
    let listen = config.proxy.listen;
    let max_frame_bytes = config.notary.max_frame_bytes;
    let max_attestable_http_bytes = config.proxy.max_attestable_http_bytes;
    if max_frame_bytes == 0 || max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    if max_attestable_http_bytes == 0 {
        bail!("maximum attestable HTTP bytes must be non-zero");
    }
    // Open and validate persistence before notary discovery or interactive
    // vault initialization. A PostgreSQL outage or unmigrated schema therefore
    // fails startup directly and never causes a fallback or unrelated prompt.
    let server_runtime = config
        .server
        .is_some()
        .then(ServerRuntime::from_environment)
        .transpose()?
        .map(Arc::new);
    if server_runtime.is_some() && !auth::api_key_mode_active()? {
        bail!("server mode requires LLM_NOTARY_API_KEY or LLM_NOTARY_API_KEY_FILE");
    }
    if server_runtime.is_some() && std::env::var_os("LLM_NOTARY_DESKTOP_CONTROL_STDIN").is_some() {
        bail!("desktop child-process control is unavailable in server mode");
    }
    let persistence = Persistence::open(&config).await?;
    let vault = if server_runtime.is_some() {
        Vault::open_server().context("opening the shared server vault")?
    } else {
        Vault::open_or_init_interactive().context(
            "opening the local bundle vault (set LLM_NOTARY_VAULT_PASSPHRASE_FILE before first start when an OS vault is unavailable)",
        )?
    };
    if let Some(server_runtime) = &server_runtime {
        let api_origin = auth::configured_api_origin()?;
        let vault_identity = vault.server_identity_sha256()?;
        persistence
            .metadata
            .register_replica(
                server_runtime.identity(),
                &config.server_compatibility_sha256_for_api_origin(
                    &api_origin.to_string(),
                    &vault_identity,
                )?,
                server_runtime.lease_seconds(),
            )
            .await?;
    } else {
        let recovery = persistence.reconcile_incomplete_captures().await?;
        if recovery.recovered_bundles > 0
            || recovery.interrupted_captures > 0
            || recovery.pending_publications > 0
        {
            tracing::warn!(
                recovered_bundles = recovery.recovered_bundles,
                interrupted_captures = recovery.interrupted_captures,
                pending_publications = recovery.pending_publications,
                "reconciled captures left incomplete by an earlier proxy process"
            );
        }
    }
    let hosted_admission = hosted_admission_required(&config);
    let capture_enabled = persistence.metadata.capture_enabled().await?;
    let config = Arc::new(config);
    let notary = if capture_enabled {
        Some(initialize_notary(&config, &persistence, server_runtime.as_deref()).await?)
    } else {
        None
    };
    let capture_mode = Arc::new(CaptureMode::new(
        capture_enabled,
        notary.clone(),
        config.clone(),
        persistence.clone(),
        server_runtime.clone(),
    ));
    let state = AppState {
        capture_mode: capture_mode.clone(),
        direct_upstream: Arc::new(ReqwestDirectUpstreamConnector::new()?),
        max_frame_bytes,
        max_attestable_http_bytes,
        vault: Arc::new(vault),
        persistence,
        config_fingerprint: Arc::from(config.fingerprint()?),
        config,
        serial: Arc::new(Mutex::new(0)),
        hosted_admission,
        capture_tasks: CaptureTasks::default(),
        server_runtime: server_runtime.clone(),
    };
    let app = router(state.clone());
    let admin_state = crate::admin::AdminState::new(
        state.persistence.clone(),
        state.config.clone(),
        server_runtime.clone(),
        server_runtime
            .as_ref()
            .map(|_| state.vault.server_identity_sha256())
            .transpose()?,
        Some(capture_mode),
    )
    .await?;
    let admin = crate::admin::router(admin_state.clone())?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let admin_listener = tokio::net::TcpListener::bind(state.config.admin.listen).await?;
    tracing::info!(
        address = %listen,
        notary = notary.as_ref().map(ToString::to_string).as_deref().unwrap_or("capture disabled"),
        capture_enabled,
        config = %config_path.display(),
        providers = ?Provider::ALL,
        "LLM Notary daemon proxy listening"
    );
    tracing::info!(address = %state.config.admin.listen, "LLM Notary daemon admin API listening");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = watch::channel(false);
    if let Some(server_runtime) = &server_runtime {
        server_runtime.mark_ready();
    }
    let mut heartbeat = spawn_server_heartbeat(
        state.persistence.clone(),
        server_runtime.clone(),
        heartbeat_shutdown_rx,
    );
    let capture_recovery = spawn_capture_recovery_worker(
        state.persistence.clone(),
        server_runtime.clone(),
        shutdown_rx.clone(),
    );
    let update_checker = if server_runtime.is_none() {
        crate::update::spawn_background_checker(
            admin_state.update_status.clone(),
            shutdown_rx.clone(),
        )
    } else {
        None
    };
    let mut worker = crate::admin::spawn_finalization_worker(
        state.persistence.clone(),
        state.config.clone(),
        state.vault.clone(),
        admin_state.work_available.clone(),
        server_runtime.clone(),
        shutdown_rx.clone(),
    );
    let proxy_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let admin_shutdown = wait_for_shutdown(shutdown_rx);
    let mut proxy_server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(proxy_shutdown)
            .await
            .context("proxy listener exited")
    });
    let mut admin_server = tokio::spawn(async move {
        axum::serve(admin_listener, admin)
            .with_graceful_shutdown(admin_shutdown)
            .await
            .context("admin listener exited")
    });
    enum Exit {
        Requested,
        Proxy(Result<()>),
        Admin(Result<()>),
        Worker(Result<()>),
        Heartbeat(Result<()>),
    }
    let exit = tokio::select! {
        result = &mut proxy_server => Exit::Proxy(joined(result, "proxy server")),
        result = &mut admin_server => Exit::Admin(joined(result, "admin server")),
        result = &mut worker => Exit::Worker(joined(result, "finalization worker")),
        result = &mut heartbeat => Exit::Heartbeat(joined(result, "server replica heartbeat")),
        () = shutdown_signal() => Exit::Requested,
    };
    if let Some(server_runtime) = &server_runtime {
        server_runtime.mark_draining();
        if matches!(&exit, Exit::Requested) {
            tokio::time::sleep(std::time::Duration::from_secs(
                server_runtime.withdrawal_delay_seconds(),
            ))
            .await;
        }
    }
    tracing::info!("LLM Notary daemon draining before shutdown");
    let _ = shutdown_tx.send(true);
    let mut forced_server_shutdown = false;
    match exit {
        Exit::Requested => {
            if let Some(server_runtime) = &server_runtime {
                let graceful = tokio::time::timeout(
                    std::time::Duration::from_secs(server_runtime.shutdown_grace_seconds()),
                    async {
                        joined((&mut proxy_server).await, "proxy server")?;
                        joined((&mut admin_server).await, "admin server")?;
                        joined((&mut worker).await, "finalization worker")?;
                        Ok::<_, anyhow::Error>(())
                    },
                )
                .await;
                match graceful {
                    Ok(result) => result?,
                    Err(_) => {
                        forced_server_shutdown = true;
                        tracing::warn!(
                            shutdown_grace_seconds = server_runtime.shutdown_grace_seconds(),
                            "server shutdown grace expired; stopping remaining local tasks"
                        );
                        proxy_server.abort();
                        admin_server.abort();
                        worker.abort();
                    }
                }
            } else {
                joined(proxy_server.await, "proxy server")?;
                joined(admin_server.await, "admin server")?;
                joined(worker.await, "finalization worker")?;
            }
        }
        Exit::Proxy(result) => {
            result?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "finalization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "server replica heartbeat")?;
            bail!("proxy server stopped unexpectedly");
        }
        Exit::Admin(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(worker.await, "finalization worker")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "server replica heartbeat")?;
            bail!("admin server stopped unexpectedly");
        }
        Exit::Worker(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            let _ = heartbeat_shutdown_tx.send(true);
            joined(heartbeat.await, "server replica heartbeat")?;
            bail!("finalization worker stopped unexpectedly");
        }
        Exit::Heartbeat(result) => {
            result?;
            joined(proxy_server.await, "proxy server")?;
            joined(admin_server.await, "admin server")?;
            joined(worker.await, "finalization worker")?;
            bail!("server replica heartbeat stopped unexpectedly");
        }
    }
    if let Some(update_checker) = update_checker {
        update_checker.await.context("update checker task exited")?;
    }
    if forced_server_shutdown {
        capture_recovery.abort();
    } else {
        capture_recovery
            .await
            .context("capture recovery worker exited")?;
        state.capture_tasks.wait_idle().await;
    }
    let _ = heartbeat_shutdown_tx.send(true);
    if forced_server_shutdown {
        heartbeat.abort();
    } else {
        joined(heartbeat.await, "server replica heartbeat")?;
    }
    if let (Some(server_runtime), false) = (&server_runtime, forced_server_shutdown) {
        state
            .persistence
            .metadata
            .release_replica(server_runtime.identity())
            .await?;
    }
    tracing::info!("LLM Notary daemon shut down cleanly");
    Ok(())
}

pub(crate) fn hosted_admission_required(config: &AgentConfig) -> bool {
    config.notary.endpoint.is_none()
}

fn spawn_capture_recovery_worker(
    persistence: Persistence,
    server_runtime: Option<Arc<ServerRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            }
            if server_runtime
                .as_ref()
                .is_some_and(|server_runtime| server_runtime.lifecycle() != Lifecycle::Ready)
            {
                continue;
            }
            let recovery = if let Some(server_runtime) = &server_runtime {
                persistence.reconcile_server_capture(server_runtime).await
            } else {
                persistence.reconcile_pending_publications().await
            };
            match recovery {
                Ok(summary) if summary.recovered_bundles > 0 => {
                    tracing::info!(
                        recovered_bundles = summary.recovered_bundles,
                        pending_publications = summary.pending_publications,
                        "attached delayed immutable capture artifacts"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "capture artifact recovery is temporarily unavailable");
                }
            }
        }
    })
}

fn spawn_server_heartbeat(
    persistence: Persistence,
    server_runtime: Option<Arc<ServerRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let Some(server_runtime) = server_runtime else {
            while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
            return Ok(());
        };
        loop {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() { return Ok(()); }
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(server_runtime.heartbeat_interval_seconds())) => {}
            }
            match persistence
                .metadata
                .heartbeat_replica(server_runtime.identity(), server_runtime.lease_seconds())
                .await
            {
                Ok(()) => {}
                Err(MetadataStoreError::Fenced) => {
                    server_runtime.mark_draining();
                    return Err(MetadataStoreError::Fenced.into());
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "server replica heartbeat could not reach the metadata backend; retrying"
                    );
                }
            }
        }
    })
}

fn joined(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    name: &str,
) -> Result<()> {
    result.with_context(|| format!("{name} task exited"))?
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new().fallback(any(proxy)).with_state(state)
}

async fn shutdown_signal() {
    if std::env::var_os("LLM_NOTARY_DESKTOP_CONTROL_STDIN").is_some() {
        tokio::select! {
            () = system_shutdown_signal() => unblock_desktop_control_stdin(),
            () = desktop_shutdown_signal() => {},
        }
    } else {
        system_shutdown_signal().await;
    }
}

async fn system_shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing Ctrl-C signal handler failed");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing termination signal handler failed")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

async fn desktop_shutdown_signal() {
    let command = tokio::task::spawn_blocking(|| {
        use std::io::BufRead as _;
        let mut line = String::new();
        let read = std::io::stdin().lock().read_line(&mut line)?;
        Ok::<_, std::io::Error>((read, line))
    })
    .await;
    match command {
        Ok(Ok((0, _))) => tracing::info!("desktop control pipe closed"),
        Ok(Ok((_, line))) if line.trim_end_matches(['\r', '\n']) == "shutdown" => {
            tracing::info!("desktop requested graceful shutdown");
        }
        Ok(Ok(_)) => {
            tracing::warn!("ignoring an invalid desktop control command");
            std::future::pending::<()>().await;
        }
        Ok(Err(_)) | Err(_) => {
            tracing::warn!("desktop control pipe failed");
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(unix)]
fn unblock_desktop_control_stdin() {
    // SAFETY: the process is already shutting down. Closing its private
    // desktop-control pipe releases the one blocking reader so the Tokio
    // runtime cannot wait on that thread during teardown.
    unsafe {
        libc::close(libc::STDIN_FILENO);
    }
}

#[cfg(windows)]
fn unblock_desktop_control_stdin() {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Console::{GetStdHandle, STD_INPUT_HANDLE},
    };
    // SAFETY: the process is already shutting down and no further stdin reads
    // are attempted after the desktop-control reader is released.
    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if !handle.is_null() {
            CloseHandle(handle);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn unblock_desktop_control_stdin() {}

pub(crate) async fn discover_notary() -> Result<NotaryEndpoint> {
    let directory = refresh_notary_directory().await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")?;
    resolve_notary(directory.active_at(now)?).await
}

async fn initialize_notary(
    config: &AgentConfig,
    persistence: &Persistence,
    server_runtime: Option<&ServerRuntime>,
) -> Result<NotaryEndpoint> {
    match config.notary_endpoint()? {
        Some(notary) => Ok(notary),
        None if server_runtime.is_some() => {
            let (directory, directory_url) =
                fetch_notary_directory_from(&super::auth::configured_api_origin()?).await?;
            let trust = persistence
                .metadata
                .pin_notary_directory(directory, directory_url.as_str())
                .await?;
            let active = trust
                .records
                .iter()
                .find(|record| record.key_id == trust.active_key_id)
                .context("shared notary trust is missing its active endpoint")?;
            resolve_notary(active).await
        }
        None => discover_notary().await,
    }
}

pub(crate) async fn refresh_notary_directory() -> Result<NotaryDirectory> {
    refresh_notary_directory_from(&super::auth::configured_api_origin()?).await
}

pub(crate) async fn refresh_notary_directory_from(
    api_origin: &ApiOrigin,
) -> Result<NotaryDirectory> {
    let (directory, directory_url) = fetch_notary_directory_from(api_origin).await?;
    pin(directory.clone(), directory_url.as_str())?;
    tracing::info!(
        key_id = %directory.active_key_id,
        key_count = directory.notaries.len(),
        "pinned trusted notary directory"
    );
    Ok(directory)
}

pub(crate) async fn fetch_notary_directory_from(
    api_origin: &ApiOrigin,
) -> Result<(NotaryDirectory, url::Url)> {
    let directory_url = notary_directory_url(api_origin);
    let bytes = http_client_builder()
        .build()?
        .get(directory_url.clone())
        .send()
        .await
        .with_context(|| format!("fetching notary endpoint from {directory_url}"))?
        .error_for_status()
        .with_context(|| format!("fetching notary endpoint from {directory_url}"))?
        .bytes()
        .await
        .context("reading notary directory from LLM Notary API")?;
    let directory = parse_directory(&bytes)?;
    Ok((directory, directory_url))
}

fn notary_directory_url(api_origin: &ApiOrigin) -> url::Url {
    api_origin.api_url("/api/notary")
}

pub(crate) async fn resolve_notary(record: &NotaryDirectoryRecord) -> Result<NotaryEndpoint> {
    record.endpoint()
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    if state
        .server_runtime
        .as_ref()
        .is_some_and(|server_runtime| server_runtime.lifecycle() != Lifecycle::Ready)
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "application/json")],
            r#"{"error":{"message":"LLM Notary proxy is draining"}}"#,
        )
            .into_response();
    }
    match proxy_inner(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                kind = if auth::hosted_admission_failure(&error).is_some() {
                    "hosted_admission"
                } else if notary_admission_error(&error).is_some() {
                    "notary_capacity"
                } else {
                    "proxy_error"
                },
                "proxy request failed"
            );
            proxy_error_response(&error)
        }
    }
}

fn proxy_error_response(error: &anyhow::Error) -> Response {
    if let Some(admission) = auth::hosted_admission_failure(error) {
        let body = serde_json::json!({
            "error": {
                "type": "hosted_admission",
                "code": admission.code(),
                "message": admission.message(),
            }
        });
        return (
            admission.status(),
            [("content-type", "application/json")],
            body.to_string(),
        )
            .into_response();
    }
    let Some(admission) = notary_admission_error(error) else {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "application/json")],
            r#"{"error":{"message":"LLM Notary proxy request failed"}}"#,
        )
            .into_response();
    };
    let retry_after_seconds = admission.retry_after().as_secs().max(1);
    let message = match admission.rejection() {
        crate::NotaryAdmissionRejection::CaptureAtCapacity => {
            "LLM Notary capture capacity is temporarily full; retry shortly."
        }
        crate::NotaryAdmissionRejection::CaptureDisabled => {
            "LLM Notary is temporarily not accepting new captures."
        }
        crate::NotaryAdmissionRejection::FinalizeAtCapacity => {
            "LLM Notary returned an unexpected finalization-capacity rejection. Retry shortly."
        }
        crate::NotaryAdmissionRejection::AdmissionDenied
        | crate::NotaryAdmissionRejection::AdmissionExpired
        | crate::NotaryAdmissionRejection::CoordinatorUnavailable
        | crate::NotaryAdmissionRejection::CaptureCreditsExhausted
        | crate::NotaryAdmissionRejection::FinalizationCreditsExhausted => {
            unreachable!("hosted admission failures are rendered before capacity responses")
        }
    };
    let body = serde_json::json!({
        "error": {
            "type": "notary_capacity",
            "code": admission.rejection().code(),
            "message": message,
            "retry_after_seconds": retry_after_seconds,
        }
    });
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a u64 retry-after value is always a valid header"),
    );
    response
}

/// Selects a fixed provider adapter from the first local path segment and
/// removes that segment before the authenticated upstream request is formed.
/// This keeps the caller from choosing an arbitrary destination while letting
/// one local listener serve every supported provider.
fn provider_route(uri: &http::Uri, config: &AgentConfig) -> Option<(Provider, http::Uri)> {
    for provider in Provider::ALL {
        let provider_config = provider.config(config);
        if !provider_config.enabled {
            continue;
        }
        let prefix = provider_config.route_prefix.as_str();
        let Some(remainder) = uri.path().strip_prefix(prefix) else {
            continue;
        };
        if !remainder.is_empty() && !remainder.starts_with('/') {
            continue;
        }
        if provider == Provider::OpenaiCodex
            && !matches!(remainder, "/responses" | "/responses/compact")
        {
            continue;
        }
        let upstream_path = match (provider.upstream_path_prefix(), remainder) {
            ("", "") => "/".to_owned(),
            ("", remainder) => remainder.to_owned(),
            (base, "") => format!("{base}/"),
            (base, remainder) => format!("{base}{remainder}"),
        };
        let path_and_query = match uri.query() {
            Some(query) => format!("{upstream_path}?{query}"),
            None => upstream_path,
        };
        let upstream_uri = path_and_query
            .parse()
            .expect("a path and query taken from a parsed URI remain valid");
        return Some((provider, upstream_uri));
    }
    None
}

fn provider_route_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/json")],
        r#"{"error":{"message":"an enabled LLM Notary provider path is required"}}"#,
    )
        .into_response()
}

async fn proxy_inner(state: AppState, request: Request) -> Result<Response> {
    let (mut parts, body) = request.into_parts();
    for name in [
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("chatgpt-account-id"),
        HeaderName::from_static("x-openai-fedramp"),
        HeaderName::from_static("anthropic-beta"),
        HeaderName::from_static("anthropic-version"),
    ] {
        if let Some(value) = parts.headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    if (parts.method == http::Method::GET || parts.method == http::Method::HEAD)
        && matches!(parts.uri.path(), "/" | "/healthz")
    {
        let mut response = if parts.method == http::Method::HEAD {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(format!(
                r#"{{"service":"llm-notary-proxy","status":"ok","build_id":"{}"}}"#,
                crate::cli::BUILD_ID
            )))
        };
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    if parts.method == http::Method::GET || parts.method == http::Method::HEAD {
        return Ok(provider_route_not_found_response());
    }
    if parts.method != http::Method::POST {
        let mut response =
            Response::new(Body::from(r#"{"error":{"message":"method not allowed"}}"#));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            http::header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST"),
        );
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    let Some((provider, upstream_uri)) = provider_route(&parts.uri, &state.config) else {
        return Ok(provider_route_not_found_response());
    };
    let host = provider.host();
    let mut outbound_headers = end_to_end_headers(&parts.headers);
    // The provider hostname is selected by the local adapter, never by the
    // caller. `Host` is connection-specific here because we create a new
    // upstream connection rather than forwarding the caller's one.
    outbound_headers.remove(http::header::HOST);
    let capture_enabled = state.capture_mode.snapshot().await?;
    if !capture_enabled {
        tracing::info!(
            provider = host,
            "forwarding provider request without capture"
        );
        return direct_provider_request(
            &state,
            provider,
            parts.method,
            upstream_uri,
            outbound_headers,
            body,
        )
        .await;
    }
    let notary = state.capture_mode.notary().await?;
    outbound_headers.remove(http::header::ACCEPT_ENCODING);
    outbound_headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host).expect("provider host is a valid HTTP header value"),
    );
    outbound_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let request_header_bytes =
        attestable_request_header_bytes(&parts.method, &upstream_uri, &outbound_headers)?;
    let (input, admission, effective_attestable_http_bytes, effective_frame_bytes) =
        collect_request_then_admit(
            body,
            request_header_bytes,
            state.max_attestable_http_bytes,
            state.max_frame_bytes,
            || async {
                if state.hosted_admission {
                    auth::issue_capture_admission().await.map(Some)
                } else {
                    Ok(None)
                }
            },
        )
        .await?;
    let streaming = wants_stream(&parts.headers, &input);
    let request_metadata =
        request_catalog_metadata(provider, &input, state.config.catalog.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for notarization"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder()
        .method(parts.method)
        .uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (capture_id, created_at_unix_ms) = next_capture_metadata(&state).await?;
    let capture_claim = state
        .server_runtime
        .as_ref()
        .map(|server_runtime| server_runtime.capture_claim(capture_id.clone()));
    let new_capture = NewCapture {
        capture_id: capture_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: state.config_fingerprint.to_string(),
    };
    if let (Some(server_runtime), Some(claim)) = (&state.server_runtime, &capture_claim) {
        state
            .persistence
            .metadata
            .begin_capture_claimed(new_capture, claim, server_runtime.lease_seconds())
            .await?;
    } else {
        state
            .persistence
            .metadata
            .begin_capture(new_capture)
            .await?;
    }
    let mut capture_claim_lease = match (&state.server_runtime, &capture_claim) {
        (Some(server_runtime), Some(claim)) => Some(
            server_runtime
                .keep_capture_claim_alive(state.persistence.metadata.clone(), claim.clone()),
        ),
        _ => None,
    };
    let started = Instant::now();
    let capture = DeferredCaptureConfig {
        capture_id: capture_id.clone(),
        provider_name: provider.name().to_owned(),
        created_at_unix_ms,
        request_body_bytes,
        max_attestable_http_bytes: effective_attestable_http_bytes,
        max_frame_bytes: effective_frame_bytes,
    };
    let upstream = match admission {
        Some(admission) => {
            deferred_streaming_request_to_admitted(
                &notary,
                host,
                capture,
                outbound,
                &admission.ticket,
            )
            .await
        }
        None => deferred_streaming_request_to(&notary, host, capture, outbound).await,
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &capture_id,
                "notary_error",
            )
            .await;
            return Err(error);
        }
    };

    if streaming {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let trace_state = state.clone();
        let capture_id_for_task = capture_id.clone();
        let capture_claim_for_task = capture_claim.clone();
        let capture_claim_lease_for_task = capture_claim_lease.take();
        let response_preview_limit = state.config.catalog.output_preview_chars;
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        // Register before detaching. Once both graceful servers have stopped,
        // no new task can register and daemon shutdown can safely wait for
        // every admitted stream to seal, save, and reach the catalog.
        let capture_task = state.capture_tasks.track();
        tokio::spawn(async move {
            let _capture_task = capture_task;
            let _capture_claim_lease = capture_claim_lease_for_task;
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            let mut client_connected = true;
            let mut output_preview = StreamingOutputPreview::new(provider, response_preview_limit);
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if let Ok(bytes) = &chunk {
                    output_preview.push(bytes);
                }
                if client_connected && body_sender.send(chunk).await.is_err() {
                    // Keep draining the provider stream so a caller
                    // disconnect does not prevent the bundle from sealing.
                    client_connected = false;
                }
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; sealing deferred bundle"
            );
            let bundle = upstream.bundle;
            drop(body_sender);
            match bundle.await {
                Ok(Ok(bundle)) => {
                    let response_bytes = match u64::try_from(output_preview.response_bytes) {
                        Ok(response_bytes) => response_bytes,
                        Err(_) => {
                            let _ = fail_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                &capture_id_for_task,
                                "response_size_overflow",
                            )
                            .await;
                            tracing::warn!(capture_id = %capture_id_for_task, "provider response size does not fit durable metadata");
                            return;
                        }
                    };
                    let preview = output_preview.finish();
                    let encrypted = match encrypt_bundle(
                        bundle,
                        trace_state.vault.clone(),
                        &capture_id_for_task,
                    )
                    .await
                    {
                        Ok(encrypted) => encrypted,
                        Err(error) => {
                            let _ = fail_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                &capture_id_for_task,
                                "bundle_store_error",
                            )
                            .await;
                            tracing::warn!(%error, "could not encrypt deferred streaming bundle");
                            return;
                        }
                    };
                    let (expected_artifact_size_bytes, expected_artifact_sha256) =
                        artifact_expectation(&encrypted);
                    let completion = CaptureCompletion {
                        capture_id: capture_id_for_task.clone(),
                        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
                        duration_ms: elapsed_ms(started),
                        http_status: status.as_u16(),
                        response_bytes,
                        response_model: preview.response_model,
                        output_preview: preview.text,
                        output_preview_truncated: preview.truncated,
                        expected_artifact_size_bytes,
                        expected_artifact_sha256,
                    };
                    if let Err(error) = prepare_capture(
                        &trace_state.persistence,
                        trace_state.server_runtime.as_deref(),
                        capture_claim_for_task.as_ref(),
                        completion.clone(),
                    )
                    .await
                    {
                        let _ = fail_capture(
                            &trace_state.persistence,
                            capture_claim_for_task.as_ref(),
                            &capture_id_for_task,
                            "metadata_prepare_error",
                        )
                        .await;
                        tracing::warn!(capture_id = %capture_id_for_task, %error, "could not stage streaming capture completion");
                        return;
                    }
                    match store_bundle(
                        &trace_state.persistence,
                        &capture_id_for_task,
                        capture_claim_for_task.as_ref(),
                        encrypted,
                    )
                    .await
                    {
                        Ok(artifact) => {
                            if complete_capture(
                                &trace_state.persistence,
                                capture_claim_for_task.as_ref(),
                                completion,
                                artifact,
                            )
                            .await
                            .is_err()
                            {
                                tracing::warn!(capture_id = %capture_id_for_task, "could not index deferred streaming bundle");
                            }
                            tracing::info!(capture_id = %capture_id_for_task, provider = provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote deferred streaming bundle")
                        }
                        Err(error) => {
                            let failure_code =
                                artifact_failure_code(&error).unwrap_or("bundle_store_error");
                            if !recoverable_artifact_publication_failure(failure_code) {
                                let _ = fail_capture(
                                    &trace_state.persistence,
                                    capture_claim_for_task.as_ref(),
                                    &capture_id_for_task,
                                    failure_code,
                                )
                                .await;
                            }
                            tracing::warn!(%error, "could not save deferred streaming bundle")
                        }
                    }
                }
                Ok(Err(error)) => {
                    let _ = fail_capture(
                        &trace_state.persistence,
                        capture_claim_for_task.as_ref(),
                        &capture_id_for_task,
                        "capture_error",
                    )
                    .await;
                    tracing::warn!(%error, "stream ended without an LLM Notary deferred bundle")
                }
                Err(error) => {
                    let _ = fail_capture(
                        &trace_state.persistence,
                        capture_claim_for_task.as_ref(),
                        &capture_id_for_task,
                        "capture_task_error",
                    )
                    .await;
                    tracing::warn!(%error, "stream deferred capture task exited")
                }
            }
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_end_to_end_headers(response.headers_mut(), &headers);
        response.headers_mut().insert(
            "x-llm-notary-capture-id",
            HeaderValue::from_str(&capture_id)?,
        );
        return Ok(response);
    }

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = upstream.body.recv().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(error) => {
                let _ = fail_capture(
                    &state.persistence,
                    capture_claim.as_ref(),
                    &capture_id,
                    "response_error",
                )
                .await;
                return Err(error.into());
            }
        }
    }
    let bundle = match upstream.bundle.await {
        Ok(Ok(bundle)) => bundle,
        Ok(Err(error)) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &capture_id,
                "capture_error",
            )
            .await;
            return Err(error);
        }
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &capture_id,
                "capture_task_error",
            )
            .await;
            return Err(error).context("deferred bundle task exited");
        }
    };
    let response_metadata =
        response_catalog_metadata(provider, &body, state.config.catalog.output_preview_chars);
    let encrypted = match encrypt_bundle(bundle, state.vault.clone(), &capture_id).await {
        Ok(encrypted) => encrypted,
        Err(error) => {
            let _ = fail_capture(
                &state.persistence,
                capture_claim.as_ref(),
                &capture_id,
                "bundle_store_error",
            )
            .await;
            return Err(error);
        }
    };
    let (expected_artifact_size_bytes, expected_artifact_sha256) = artifact_expectation(&encrypted);
    let completion = CaptureCompletion {
        capture_id: capture_id.clone(),
        completed_at_unix_ms: current_unix_ms().unwrap_or(created_at_unix_ms),
        duration_ms: elapsed_ms(started),
        http_status: status.as_u16(),
        response_bytes: u64::try_from(body.len())?,
        response_model: response_metadata.response_model,
        output_preview: response_metadata.output_preview,
        output_preview_truncated: response_metadata.output_preview_truncated,
        expected_artifact_size_bytes,
        expected_artifact_sha256,
    };
    if let Err(error) = prepare_capture(
        &state.persistence,
        state.server_runtime.as_deref(),
        capture_claim.as_ref(),
        completion.clone(),
    )
    .await
    {
        let _ = fail_capture(
            &state.persistence,
            capture_claim.as_ref(),
            &capture_id,
            "metadata_prepare_error",
        )
        .await;
        tracing::warn!(capture_id = %capture_id, %error, "could not stage capture completion");
    } else {
        let artifact = match store_bundle(
            &state.persistence,
            &capture_id,
            capture_claim.as_ref(),
            encrypted,
        )
        .await
        {
            Ok(artifact) => artifact,
            Err(error) => {
                let failure_code = artifact_failure_code(&error).unwrap_or("bundle_store_error");
                if !recoverable_artifact_publication_failure(failure_code) {
                    let _ = fail_capture(
                        &state.persistence,
                        capture_claim.as_ref(),
                        &capture_id,
                        failure_code,
                    )
                    .await;
                }
                return Err(error);
            }
        };
        if complete_capture(
            &state.persistence,
            capture_claim.as_ref(),
            completion,
            artifact,
        )
        .await
        .is_err()
        {
            tracing::warn!(capture_id = %capture_id, "could not index deferred bundle");
        }
    }
    tracing::info!(capture_id = %capture_id, provider = host, "wrote deferred bundle");

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response.headers_mut().insert(
        "x-llm-notary-capture-id",
        HeaderValue::from_str(&capture_id)?,
    );
    Ok(response)
}

async fn direct_provider_request(
    state: &AppState,
    provider: Provider,
    method: http::Method,
    upstream_uri: http::Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response> {
    let mut outbound = http::Request::builder().method(method).uri(upstream_uri);
    for (name, value) in &headers {
        outbound = outbound.header(name, value);
    }
    let upstream = state
        .direct_upstream
        .send(provider, outbound.body(body)?)
        .await?;
    let mut response = Response::new(upstream.body);
    *response.status_mut() = upstream.status;
    copy_end_to_end_headers(response.headers_mut(), &upstream.headers);
    Ok(response)
}

async fn collect_request_body(mut body: Body, maximum: usize) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            let length = collected
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow::anyhow!("request body byte count overflow"))?;
            if length > maximum {
                bail!(
                    "provider request body exceeds the {maximum}-byte maximum attestable HTTP budget"
                );
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected.freeze())
}

async fn collect_request_then_admit<F, Fut>(
    body: Body,
    request_header_bytes: usize,
    local_max_attestable_http_bytes: usize,
    local_max_frame_bytes: usize,
    issue_admission: F,
) -> Result<(Bytes, Option<auth::AdmissionTicket>, usize, usize)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<auth::AdmissionTicket>>>,
{
    let local_body_limit = local_max_attestable_http_bytes
        .checked_sub(request_header_bytes)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider request headers exceed the {local_max_attestable_http_bytes}-byte maximum attestable HTTP budget"
            )
        })?;
    let input = collect_request_body(body, local_body_limit).await?;
    let admission = issue_admission().await?;
    let effective_attestable_http_bytes = admission
        .as_ref()
        .map(|admission| admission.max_attestable_http_bytes)
        .unwrap_or(local_max_attestable_http_bytes)
        .min(local_max_attestable_http_bytes);
    let effective_frame_bytes = admission
        .as_ref()
        .map(|admission| admission.max_frame_bytes)
        .unwrap_or(local_max_frame_bytes)
        .min(local_max_frame_bytes);
    let request_bytes = request_header_bytes
        .checked_add(input.len())
        .ok_or_else(|| anyhow::anyhow!("provider request byte count overflow"))?;
    if request_bytes > effective_attestable_http_bytes {
        bail!(
            "provider request exceeds the {effective_attestable_http_bytes}-byte maximum attestable HTTP budget"
        );
    }
    Ok((
        input,
        admission,
        effective_attestable_http_bytes,
        effective_frame_bytes,
    ))
}

async fn encrypt_bundle(
    bundle: DeferredBundle,
    vault: Arc<Vault>,
    expected_capture_id: &str,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        bundle.capture_id() == expected_capture_id,
        "deferred bundle capture does not match the active request"
    );
    tokio::task::spawn_blocking(move || bundle.to_encrypted_bytes(&vault))
        .await
        .context("deferred bundle encryption task failed")?
}

fn artifact_expectation(encrypted: &[u8]) -> (u64, String) {
    let size = u64::try_from(encrypted.len()).expect("artifact bytes fit in u64");
    (size, hex::encode(Sha256::digest(encrypted)))
}

async fn store_bundle(
    persistence: &Persistence,
    capture_id: &str,
    claim: Option<&CaptureClaim>,
    encrypted: Vec<u8>,
) -> Result<crate::artifact_store::ArtifactRecord> {
    let key = ArtifactKey::new(capture_id, ArtifactKind::DeferredBundle)?;
    if let Some(claim) = claim {
        persistence
            .artifacts
            .put_scoped(
                &key,
                &claim.publication_id,
                ArtifactSource::from_bytes(encrypted),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .map_err(Into::into)
    } else {
        persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(encrypted),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .map_err(Into::into)
    }
}

async fn fail_capture(
    persistence: &Persistence,
    claim: Option<&CaptureClaim>,
    capture_id: &str,
    failure_code: &str,
) -> Result<()> {
    if let Some(claim) = claim {
        persistence
            .metadata
            .fail_capture_claimed(claim, failure_code)
            .await?;
    } else {
        persistence
            .metadata
            .mark_capture_failed(capture_id, failure_code)
            .await?;
    }
    Ok(())
}

async fn prepare_capture(
    persistence: &Persistence,
    server_runtime: Option<&ServerRuntime>,
    claim: Option<&CaptureClaim>,
    completion: CaptureCompletion,
) -> Result<()> {
    if let (Some(server_runtime), Some(claim)) = (server_runtime, claim) {
        persistence
            .metadata
            .prepare_capture_completion_claimed(completion, claim, server_runtime.lease_seconds())
            .await?;
    } else {
        persistence
            .metadata
            .prepare_capture_completion(completion)
            .await?;
    }
    Ok(())
}

async fn complete_capture(
    persistence: &Persistence,
    claim: Option<&CaptureClaim>,
    completion: CaptureCompletion,
    artifact: crate::artifact_store::ArtifactRecord,
) -> Result<()> {
    if let Some(claim) = claim {
        persistence
            .metadata
            .complete_capture_claimed(completion, artifact, claim)
            .await?;
    } else {
        persistence
            .metadata
            .complete_capture(completion, artifact)
            .await?;
    }
    Ok(())
}

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

fn recoverable_artifact_publication_failure(code: &str) -> bool {
    code == "artifact_backend_unavailable"
}

async fn next_capture_metadata(state: &AppState) -> Result<(String, u64)> {
    let mut serial = state.serial.lock().await;
    *serial += 1;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_millis();
    let created_at_unix_ms: u64 = created_at_unix_ms
        .try_into()
        .map_err(|_| anyhow::anyhow!("capture timestamp does not fit in u64"))?;
    Ok((
        format!(
            "cap-{created_at_unix_ms}-{serial:04}-{}",
            uuid::Uuid::new_v4().simple()
        ),
        created_at_unix_ms,
    ))
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Default)]
struct RequestCatalogMetadata {
    requested_model: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
}

#[derive(Default)]
struct ResponseCatalogMetadata {
    response_model: Option<String>,
    output_preview: String,
    output_preview_truncated: bool,
}

struct Preview {
    text: String,
    truncated: bool,
}

/// Pulls only known textual message fields from a supported request shape. It
/// intentionally never indexes raw HTTP, headers, or tool-call arguments.
fn request_catalog_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> RequestCatalogMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return RequestCatalogMetadata::default();
    };
    let requested_model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut preview = LimitedText::new(maximum_preview_chars);
    match provider {
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            append_messages(&mut preview, value.get("messages"));
            append_messages(&mut preview, value.get("input"));
        }
        Provider::Anthropic => {
            append_text_value(&mut preview, value.get("system"));
            append_messages(&mut preview, value.get("messages"));
        }
    }
    let preview = preview.finish();
    RequestCatalogMetadata {
        requested_model,
        prompt_preview: preview.text,
        prompt_preview_truncated: preview.truncated,
    }
}

/// Pulls visible assistant text from a complete non-streaming response.
fn response_catalog_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> ResponseCatalogMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return ResponseCatalogMetadata::default();
    };
    let mut preview = LimitedText::new(maximum_preview_chars);
    append_response_text(provider, &mut preview, &value, false);
    let preview = preview.finish();
    ResponseCatalogMetadata {
        response_model: value
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        output_preview: preview.text,
        output_preview_truncated: preview.truncated,
    }
}

/// Incrementally extracts text from provider SSE events without retaining the
/// raw stream in the catalog.
struct StreamingOutputPreview {
    provider: Provider,
    preview: LimitedText,
    pending: Vec<u8>,
    response_bytes: usize,
    response_model: Option<String>,
}

struct StreamingResponseMetadata {
    text: String,
    truncated: bool,
    response_model: Option<String>,
}

impl StreamingOutputPreview {
    fn new(provider: Provider, maximum_preview_chars: usize) -> Self {
        Self {
            provider,
            preview: LimitedText::new(maximum_preview_chars),
            pending: Vec::new(),
            response_bytes: 0,
            response_model: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.response_bytes = self.response_bytes.saturating_add(bytes.len());
        self.pending.extend_from_slice(bytes);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=newline).collect::<Vec<_>>();
            let line = line.strip_suffix(b"\n").unwrap_or(&line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let data = trim_ascii(data);
            if data == b"[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                if self.response_model.is_none() {
                    self.response_model = response_model_from_stream_event(&value);
                }
                append_response_text(self.provider, &mut self.preview, &value, true);
            }
        }
    }

    fn finish(mut self) -> StreamingResponseMetadata {
        // Some providers send a final JSON body rather than SSE. It is safe to
        // ignore an incomplete event rather than index raw bytes.
        self.pending.clear();
        let preview = self.preview.finish();
        StreamingResponseMetadata {
            text: preview.text,
            truncated: preview.truncated,
            response_model: self.response_model,
        }
    }
}

fn response_model_from_stream_event(value: &serde_json::Value) -> Option<String> {
    value
        .get("model")
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("model"))
        })
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("model"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

struct LimitedText {
    maximum_chars: usize,
    text: String,
    truncated: bool,
}

impl LimitedText {
    fn new(maximum_chars: usize) -> Self {
        Self {
            maximum_chars,
            text: String::new(),
            truncated: false,
        }
    }

    fn push(&mut self, text: &str) {
        if text.is_empty() || self.truncated || self.maximum_chars == 0 {
            return;
        }
        let used = self.text.chars().count();
        let available = self.maximum_chars.saturating_sub(used);
        if available == 0 {
            self.truncated = true;
            return;
        }
        let mut characters = text.chars();
        let prefix = characters.by_ref().take(available).collect::<String>();
        self.text.push_str(&prefix);
        if characters.next().is_some() {
            self.truncated = true;
        }
    }

    fn separator(&mut self) {
        if !self.text.is_empty() {
            self.push("\n");
        }
    }

    fn finish(self) -> Preview {
        Preview {
            text: self.text,
            truncated: self.truncated,
        }
    }
}

fn append_messages(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(messages) = value.and_then(serde_json::Value::as_array) else {
        append_text_value(preview, value);
        return;
    };
    for message in messages {
        let Some(message) = message.as_object() else {
            append_text_value(preview, Some(message));
            continue;
        };
        let content = message.get("content").or_else(|| message.get("text"));
        let mut message_preview = LimitedText::new(usize::MAX);
        append_text_value(&mut message_preview, content);
        let message_preview = message_preview.finish();
        if message_preview.text.is_empty() {
            continue;
        }
        preview.separator();
        if let Some(role) = message.get("role").and_then(serde_json::Value::as_str) {
            preview.push(role);
            preview.push(": ");
        }
        preview.push(&message_preview.text);
    }
}

fn append_text_value(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        preview.push(text);
        return;
    }
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        if let Some(text) = item.as_str() {
            preview.push(text);
            continue;
        }
        let Some(item) = item.as_object() else {
            continue;
        };
        let kind = item.get("type").and_then(serde_json::Value::as_str);
        if matches!(kind, Some("text" | "input_text" | "output_text"))
            && let Some(text) = item.get("text").and_then(serde_json::Value::as_str)
        {
            preview.push(text);
        }
    }
}

fn append_response_text(
    provider: Provider,
    preview: &mut LimitedText,
    value: &serde_json::Value,
    streaming: bool,
) {
    match provider {
        Provider::Anthropic => {
            if streaming {
                if let Some(text) = value
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(serde_json::Value::as_str)
                {
                    preview.push(text);
                }
            } else {
                append_text_value(preview, value.get("content"));
            }
        }
        Provider::Openai | Provider::OpenaiCodex | Provider::Deepseek | Provider::Openrouter => {
            if streaming {
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        if let Some(text) = choice
                            .get("delta")
                            .and_then(|delta| delta.get("content"))
                            .and_then(serde_json::Value::as_str)
                        {
                            preview.push(text);
                        }
                    }
                }
                if let Some(text) = value.get("delta").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
            } else {
                if let Some(text) = value.get("output_text").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        append_text_value(
                            preview,
                            choice
                                .get("message")
                                .and_then(|message| message.get("content")),
                        );
                    }
                }
                if let Some(output) = value.get("output").and_then(serde_json::Value::as_array) {
                    for item in output {
                        append_text_value(preview, item.get("content"));
                    }
                }
            }
        }
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn wants_stream(headers: &HeaderMap, input: &[u8]) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"))
        || serde_json::from_slice::<serde_json::Value>(input)
            .ok()
            .and_then(|json| json.get("stream").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
}

/// Returns headers that remain meaningful after the proxy opens a fresh HTTP
/// connection. RFC 9110 hop-by-hop fields must not cross that boundary,
/// including extension fields named by a `Connection` header.
fn end_to_end_headers(source: &HeaderMap) -> HeaderMap {
    let mut target = HeaderMap::new();
    copy_end_to_end_headers(&mut target, source);
    target
}

fn copy_end_to_end_headers(target: &mut HeaderMap, source: &HeaderMap) {
    let hop_by_hop = hop_by_hop_header_names(source);
    for (name, value) in source {
        if !hop_by_hop.contains(name) {
            target.append(name, value.clone());
        }
    }
}

fn hop_by_hop_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut names = [
        http::header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        http::header::PROXY_AUTHENTICATE,
        http::header::PROXY_AUTHORIZATION,
        http::header::TE,
        http::header::TRAILER,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                names.insert(name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone)]
    struct DirectObservation {
        provider: Provider,
        uri: http::Uri,
        headers: HeaderMap,
    }

    struct StubDirectUpstream {
        observations: Arc<StdMutex<Vec<DirectObservation>>>,
        response: StdMutex<Option<DirectUpstreamResponse>>,
    }

    #[async_trait::async_trait]
    impl DirectUpstreamConnector for StubDirectUpstream {
        async fn send(
            &self,
            provider: Provider,
            request: Request,
        ) -> Result<DirectUpstreamResponse> {
            let (parts, _body) = request.into_parts();
            self.observations.lock().unwrap().push(DirectObservation {
                provider,
                uri: parts.uri,
                headers: parts.headers,
            });
            self.response
                .lock()
                .unwrap()
                .take()
                .context("stub direct response was already used")
        }
    }

    fn state() -> AppState {
        let config = AgentConfig::default();
        let artifacts = RoutedArtifactStore::new(
            config.storage.backend,
            FileSystemArtifactStore::new("bundles", "traces"),
            None,
        )
        .unwrap();
        let persistence = Persistence {
            metadata: Arc::new(SqliteMetadataStore::from_catalog(
                SqliteCatalog::open(std::path::Path::new(":memory:"), true).unwrap(),
                true,
            )),
            artifacts: Arc::new(artifacts),
        };
        let config = Arc::new(config);
        let capture_mode = Arc::new(CaptureMode::new(
            true,
            Some("127.0.0.1:7047".parse().unwrap()),
            config.clone(),
            persistence.clone(),
            None,
        ));
        AppState {
            capture_mode,
            direct_upstream: Arc::new(ReqwestDirectUpstreamConnector::new().unwrap()),
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            vault: Arc::new(Vault::test_only()),
            persistence,
            config_fingerprint: Arc::from(config.fingerprint().unwrap()),
            config,
            serial: Arc::new(Mutex::new(0)),
            hosted_admission: false,
            capture_tasks: CaptureTasks::default(),
            server_runtime: None,
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_every_detached_capture_task() {
        let tasks = CaptureTasks::default();
        let guard = tasks.track();
        let waiting = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.wait_idle().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("capture drain timed out")
            .expect("capture drain task failed");
    }

    #[test]
    fn ambiguous_backend_publication_remains_recoverable() {
        assert!(recoverable_artifact_publication_failure(
            "artifact_backend_unavailable"
        ));
        for terminal in [
            "artifact_collision",
            "artifact_corrupt",
            "artifact_invalid",
            "bundle_store_error",
        ] {
            assert!(!recoverable_artifact_publication_failure(terminal));
        }
    }

    #[test]
    fn explicit_self_hosted_notaries_never_require_admission_tickets() {
        let mut config = AgentConfig::default();
        assert!(hosted_admission_required(&config));

        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        config.notary.public_key = Some("02".to_owned() + &"ab".repeat(32));
        assert!(!hosted_admission_required(&config));
    }

    #[test]
    fn detects_streaming_from_accept_or_request_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(wants_stream(&headers, b"{}"));
        assert!(wants_stream(&HeaderMap::new(), br#"{"stream":true}"#));
        assert!(!wants_stream(&HeaderMap::new(), br#"{"stream":false}"#));
    }

    #[tokio::test]
    async fn request_collection_enforces_the_attestable_byte_budget() {
        assert_eq!(
            collect_request_body(Body::from("abc"), 3).await.unwrap(),
            Bytes::from_static(b"abc")
        );
        let error = collect_request_body(Body::from("abcd"), 3)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("maximum attestable HTTP budget"));
    }

    #[tokio::test]
    async fn direct_mode_streams_without_capture_and_preserves_end_to_end_response() {
        let mut state = state();
        state.capture_mode.set_enabled(false).await.unwrap();
        let before = state.persistence.metadata.counts().await.unwrap();
        let observations = Arc::new(StdMutex::new(Vec::new()));
        let (response_sender, response_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        response_headers.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        response_headers.insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://api.openai.com/redirect-target"),
        );
        response_headers.insert(
            "x-provider-request-id",
            HeaderValue::from_static("req-safe"),
        );
        state.direct_upstream = Arc::new(StubDirectUpstream {
            observations: observations.clone(),
            response: StdMutex::new(Some(DirectUpstreamResponse {
                status: StatusCode::TEMPORARY_REDIRECT,
                headers: response_headers,
                body: Body::from_stream(ReceiverStream::new(response_receiver)),
            })),
        });

        let (request_sender, request_receiver) =
            tokio::sync::mpsc::channel::<std::result::Result<Bytes, std::io::Error>>(1);
        let request = Request::post("/openai/v1/responses?stream=true")
            .header(http::header::AUTHORIZATION, "Bearer provider-secret")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .header(http::header::CONNECTION, "x-request-scoped")
            .header("x-request-scoped", "must-not-forward")
            .body(Body::from_stream(ReceiverStream::new(request_receiver)))
            .unwrap();
        // Keeping the sender open proves admission and response headers do not
        // wait for the whole request body. The stub deliberately never reads
        // that body, matching a connector which begins its HTTPS exchange as
        // chunks arrive.
        let mut response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            proxy_inner(state.clone(), request),
        )
        .await
        .expect("direct request waited for its complete body")
        .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "https://api.openai.com/redirect-target"
        );
        assert_eq!(
            response.headers().get("x-provider-request-id").unwrap(),
            "req-safe"
        );
        assert!(response.headers().get(http::header::CONNECTION).is_none());
        assert!(response.headers().get("x-response-scoped").is_none());
        assert!(response.headers().get("x-llm-notary-capture-id").is_none());

        response_sender
            .send(Ok(Bytes::from_static(b"data: direct\n\n")))
            .await
            .unwrap();
        let frame = response.body_mut().frame().await.unwrap().unwrap();
        assert_eq!(
            frame.into_data().unwrap(),
            Bytes::from_static(b"data: direct\n\n")
        );
        drop(response_sender);
        drop(request_sender);

        {
            let seen = observations.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].provider, Provider::Openai);
            assert_eq!(seen[0].uri, "/v1/responses?stream=true");
            assert_eq!(
                seen[0].headers.get(http::header::AUTHORIZATION).unwrap(),
                "Bearer provider-secret"
            );
            assert_eq!(
                seen[0].headers.get(http::header::ACCEPT_ENCODING).unwrap(),
                "gzip"
            );
            assert!(seen[0].headers.get("x-request-scoped").is_none());
        }
        assert_eq!(state.persistence.metadata.counts().await.unwrap(), before);
    }

    #[tokio::test]
    async fn failed_enable_is_atomic_and_leaves_capture_off() {
        let config = Arc::new(AgentConfig::default());
        let artifacts = RoutedArtifactStore::new(
            config.storage.backend,
            FileSystemArtifactStore::new("bundles", "traces"),
            None,
        )
        .unwrap();
        let persistence = Persistence {
            metadata: Arc::new(SqliteMetadataStore::from_catalog(
                SqliteCatalog::open(std::path::Path::new(":memory:"), true).unwrap(),
                true,
            )),
            artifacts: Arc::new(artifacts),
        };
        persistence
            .metadata
            .set_capture_enabled(false, 1)
            .await
            .unwrap();
        let mode = CaptureMode::new(false, None, config, persistence.clone(), None);
        mode.fail_notary_initialization
            .store(true, Ordering::Release);
        assert!(mode.set_enabled(true).await.is_err());
        assert!(!mode.enabled());
        assert!(!persistence.metadata.capture_enabled().await.unwrap());
    }

    #[test]
    fn provider_adapters_pin_their_authenticated_hosts() {
        assert_eq!(Provider::Openrouter.host(), "openrouter.ai");
        assert_eq!(Provider::Openrouter.name(), "openrouter");
        assert_eq!(Provider::Openrouter.default_path_prefix(), "/openrouter");
        assert_eq!(Provider::OpenaiCodex.host(), "chatgpt.com");
        assert_eq!(Provider::OpenaiCodex.name(), "openai");
        assert_eq!(Provider::OpenaiCodex.default_path_prefix(), "/codex");
        assert_eq!(
            Provider::OpenaiCodex.upstream_path_prefix(),
            "/backend-api/codex"
        );
    }

    #[test]
    fn provider_routes_select_the_adapter_and_strip_its_prefix() {
        let config = AgentConfig::default();
        let uri = "/openai/v1/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Openai);
        assert_eq!(upstream_uri, "/v1/responses?stream=true");

        let uri = "/codex/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::OpenaiCodex);
        assert_eq!(upstream_uri, "/backend-api/codex/responses?stream=true");

        let uri = "/deepseek/chat/completions".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Deepseek);
        assert_eq!(upstream_uri, "/chat/completions");

        let uri = "/anthropic/v1/messages?beta=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri, "/v1/messages?beta=true");

        for unsupported in ["/codex", "/codex/../unrelated", "/codex/v1/responses"] {
            let uri = unsupported.parse().unwrap();
            assert!(
                provider_route(&uri, &config).is_none(),
                "Codex route accepted {unsupported}"
            );
        }
    }

    #[test]
    fn provider_routes_only_match_a_complete_first_path_segment() {
        let config = AgentConfig::default();
        let uri = "/openaiish/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());

        let uri = "/anthropic".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri.to_string(), "/");
    }

    #[test]
    fn disabled_provider_routes_are_not_available() {
        let mut config = AgentConfig::default();
        config.providers.openai.enabled = false;
        let uri = "/openai/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());
    }

    #[test]
    fn catalog_previews_extract_textual_messages_without_headers() {
        let request = request_catalog_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Explain pricing"}]}"#,
            1_000,
        );
        assert_eq!(request.requested_model.as_deref(), Some("gpt-5"));
        assert_eq!(
            request.prompt_preview,
            "system: Be concise\nuser: Explain pricing"
        );

        let response = response_catalog_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","choices":[{"message":{"content":"Pricing is usage based."}}]}"#,
            1_000,
        );
        assert_eq!(response.response_model.as_deref(), Some("gpt-5"));
        assert_eq!(response.output_preview, "Pricing is usage based.");

        let anthropic = request_catalog_metadata(
            Provider::Anthropic,
            br#"{"model":"claude-sonnet","system":"Be concise","messages":[{"role":"user","content":[{"type":"text","text":"Use the weather tool"},{"type":"tool_result","tool_use_id":"toolu_1","content":"private tool result"}]}],"tools":[{"name":"weather","input_schema":{"type":"object"}}]}"#,
            1_000,
        );
        assert_eq!(
            anthropic.prompt_preview,
            "Be concise\nuser: Use the weather tool"
        );
        assert!(!anthropic.prompt_preview.contains("private tool result"));
    }

    #[test]
    fn streaming_preview_handles_split_sse_events() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        let first = br#"data: {"model":"gpt-5","choices":[{"delta":{"content":"Price"}}]}"#;
        let second = br#"data: {"choices":[{"delta":{"content":"d"}}]}"#;
        preview.push(first);
        preview.push(b"\n\n");
        preview.push(second);
        preview.push(b"\n\n");
        assert_eq!(preview.response_bytes, first.len() + second.len() + 4);
        let preview = preview.finish();
        assert_eq!(preview.text, "Priced");
        assert_eq!(preview.response_model.as_deref(), Some("gpt-5"));
    }

    #[test]
    fn streaming_preview_reads_the_openai_responses_model() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        preview.push(
            b"data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-5-mini\"}}\n\n",
        );
        assert_eq!(
            preview.finish().response_model.as_deref(),
            Some("gpt-5-mini")
        );
    }

    #[test]
    fn streaming_preview_accepts_claude_messages_events_and_ignores_pings() {
        let mut preview = StreamingOutputPreview::new(Provider::Anthropic, 1_000);
        preview.push(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet\"}}\n\n",
        );
        preview.push(b"event: ping\ndata: {\"type\":\"ping\"}\n\n");
        preview.push(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        );
        let preview = preview.finish();
        assert_eq!(preview.response_model.as_deref(), Some("claude-sonnet"));
        assert_eq!(preview.text, "hello");
    }

    #[test]
    fn zero_preview_limit_omits_text_without_marking_it_truncated() {
        let request = request_catalog_metadata(
            Provider::Openai,
            br#"{"messages":[{"role":"user","content":"Do not store this preview"}]}"#,
            0,
        );
        assert!(request.prompt_preview.is_empty());
        assert!(!request.prompt_preview_truncated);
    }

    #[test]
    fn strips_fixed_and_connection_nominated_hop_by_hop_headers() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-request-scoped"),
        );
        source.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        source.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic proxy-secret"),
        );
        source.insert(http::header::TE, HeaderValue::from_static("trailers"));
        source.insert(
            http::header::TRAILER,
            HeaderValue::from_static("x-checksum"),
        );
        source.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        source.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        source.insert(
            "x-request-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer provider-credential"),
        );
        source.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("account-routing-value"),
        );
        source.insert(
            "x-openai-fedramp",
            HeaderValue::from_static("fedramp-routing-value"),
        );
        source.insert(
            "anthropic-beta",
            HeaderValue::from_static("oauth-2025-04-20,interleaved-thinking"),
        );
        source.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        source.insert("x-end-to-end", HeaderValue::from_static("keep"));

        let forwarded = end_to_end_headers(&source);
        for name in [
            http::header::CONNECTION,
            HeaderName::from_static("keep-alive"),
            http::header::PROXY_AUTHORIZATION,
            http::header::TE,
            http::header::TRAILER,
            http::header::TRANSFER_ENCODING,
            http::header::UPGRADE,
            HeaderName::from_static("x-request-scoped"),
        ] {
            assert!(forwarded.get(name).is_none());
        }
        assert_eq!(
            forwarded.get(http::header::AUTHORIZATION).unwrap(),
            "Bearer provider-credential"
        );
        assert_eq!(
            forwarded.get("chatgpt-account-id").unwrap(),
            "account-routing-value"
        );
        assert_eq!(
            forwarded.get("x-openai-fedramp").unwrap(),
            "fedramp-routing-value"
        );
        assert_eq!(
            forwarded.get("anthropic-beta").unwrap(),
            "oauth-2025-04-20,interleaved-thinking"
        );
        assert_eq!(forwarded.get("anthropic-version").unwrap(), "2023-06-01");
        assert_eq!(forwarded.get("x-end-to-end").unwrap(), "keep");
    }

    #[test]
    fn strips_response_only_hop_by_hop_headers_and_connection_tokens() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        source.insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=proxy"),
        );
        source.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert("x-request-id", HeaderValue::from_static("provider-id"));

        let mut target = HeaderMap::new();
        copy_end_to_end_headers(&mut target, &source);
        assert!(target.get(http::header::CONNECTION).is_none());
        assert!(target.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(target.get("x-response-scoped").is_none());
        assert_eq!(target.get("x-request-id").unwrap(), "provider-id");
    }

    #[test]
    fn directory_discovery_stays_on_the_configured_api_origin() {
        assert_eq!(
            notary_directory_url(&ApiOrigin::parse("https://self-hosted.example").unwrap())
                .as_str(),
            "https://self-hosted.example/api/notary"
        );
        assert!(ApiOrigin::parse("file:///tmp/notary").is_err());
    }

    #[tokio::test]
    async fn admin_paths_are_not_reachable_from_the_proxy_listener() {
        for (method, path) in [
            (http::Method::GET, "/openapi.json"),
            (http::Method::GET, "/v1/status"),
            (http::Method::GET, "/v1/captures"),
            (http::Method::POST, "/v1/captures/cap-example/finalizations"),
            (http::Method::GET, "/v1/operations/op-example"),
            (http::Method::POST, "/v1/operations/op-example/retry"),
            (http::Method::GET, "/v1/captures/cap-example/package"),
            (http::Method::POST, "/v1/captures/cap-example/trace:verify"),
            (http::Method::GET, "/v1/events"),
            (http::Method::POST, "/v1/session"),
            (http::Method::GET, "/v1/account"),
            (http::Method::POST, "/v1/captures/cap-example/shares"),
            (http::Method::GET, "/v1/shares/share-example"),
        ] {
            let state = state();
            let serial = state.serial.clone();
            let response = proxy_inner(
                state,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(response.headers().get("x-llm-notary-bundle").is_none());
            assert_eq!(*serial.lock().await, 0);
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_methods_locally_without_a_bundle() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(http::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
        assert!(response.headers().get("x-llm-notary-bundle").is_none());
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn rejects_posts_outside_the_fixed_provider_paths_without_a_bundle() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/v1/responses")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("x-llm-notary-bundle").is_none());
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn maps_capture_capacity_to_a_retryable_service_unavailable_response() {
        let response =
            proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                crate::NotaryAdmissionRejection::CaptureAtCapacity,
                std::time::Duration::from_secs(7),
            )));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER).unwrap(),
            "7"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": {
                    "type": "notary_capacity",
                    "code": "capture_at_capacity",
                    "message": "LLM Notary capture capacity is temporarily full; retry shortly.",
                    "retry_after_seconds": 7,
                }
            })
        );
    }

    #[tokio::test]
    async fn capture_admission_waits_for_the_complete_locally_bounded_body() {
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(1);
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::from_static(b"body")))
            .await
            .unwrap();
        let (admitted_sender, mut admitted_receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(collect_request_then_admit(
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_receiver)),
            2,
            64,
            128,
            move || async move {
                let _ = admitted_sender.send(());
                Ok(None)
            },
        ));

        // Filling the one-slot channel again proves the collector consumed the
        // first frame and is now waiting for EOF, not acquiring a ticket.
        body_sender
            .send(Ok::<_, std::io::Error>(Bytes::new()))
            .await
            .unwrap();
        assert!(matches!(
            admitted_receiver.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(body_sender);

        let (body, admission, http_limit, frame_limit) = task.await.unwrap().unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_none());
        assert_eq!((http_limit, frame_limit), (64, 128));
        assert!(admitted_receiver.await.is_ok());
    }

    #[tokio::test]
    async fn capture_revalidates_the_collected_request_against_ticket_limits() {
        let result = collect_request_then_admit(
            Body::from(Bytes::from_static(b"request-body")),
            8,
            128,
            256,
            || async {
                Ok(Some(auth::AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 16,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await;
        assert!(
            result
                .err()
                .expect("the ticket limit must reject the collected request")
                .to_string()
                .contains("16-byte maximum attestable HTTP budget")
        );

        let (body, admission, http_limit, frame_limit) = collect_request_then_admit(
            Body::from(Bytes::from_static(b"body")),
            8,
            128,
            256,
            || async {
                Ok(Some(auth::AdmissionTicket {
                    ticket: "redacted-one-operation-ticket".to_owned(),
                    max_attestable_http_bytes: 80,
                    max_frame_bytes: 64,
                }))
            },
        )
        .await
        .unwrap();
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(admission.is_some());
        assert_eq!((http_limit, frame_limit), (80, 64));
    }

    #[tokio::test]
    async fn hosted_redemption_failures_use_stable_bounded_json_errors() {
        for (rejection, status, code) in [
            (
                crate::NotaryAdmissionRejection::AdmissionDenied,
                StatusCode::BAD_GATEWAY,
                "hosted_admission_denied",
            ),
            (
                crate::NotaryAdmissionRejection::AdmissionExpired,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_expired",
            ),
            (
                crate::NotaryAdmissionRejection::CoordinatorUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "hosted_admission_unavailable",
            ),
            (
                crate::NotaryAdmissionRejection::CaptureCreditsExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "capture_credits_exhausted",
            ),
            (
                crate::NotaryAdmissionRejection::FinalizationCreditsExhausted,
                StatusCode::PAYMENT_REQUIRED,
                "finalization_credits_exhausted",
            ),
        ] {
            let response =
                proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                    rejection,
                    std::time::Duration::from_secs(5),
                )));
            assert_eq!(response.status(), status);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
            assert_eq!(body["error"]["type"], "hosted_admission");
            assert_eq!(body["error"]["code"], code);
            assert!(body.to_string().len() < 512);
        }

        let response = proxy_error_response(&anyhow::anyhow!(
            "wrong digest for secret-ticket-and-provider-payload"
        ));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(br#"{"error":{"message":"LLM Notary proxy request failed"}}"#)
        );
    }
}
