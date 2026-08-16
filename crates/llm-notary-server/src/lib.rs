use std::{
    env, fs,
    fs::OpenOptions,
    future::Future,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use axum::{Router, http::header, response::IntoResponse, routing::get};
use clap::Parser;
use k256::ecdsa::SigningKey;
use llm_notary_core::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    HostedCaptureSettlementRecorder, HostedNotarySessionLimits, NotaryAdmissionRejection,
    NotarySessionMode, read_hosted_notary_session_prelude, run_hosted_notary_session_after_prelude,
    write_notary_admission,
};
use metrics::{counter, gauge, histogram};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
    time::{MissedTickBehavior, timeout},
};
use tracing::Instrument as _;
use url::Url;

const DEFAULT_LEASE_RENEW_INTERVAL_SECS: u64 = 10;
const RELEASE_OUTBOX_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct AdmissionCoordinator {
    http: reqwest::Client,
    origin: Url,
    service_token: Arc<str>,
    instance_id: Arc<str>,
    directory_generation: u64,
    renew_interval: Duration,
    release_outbox: ReleaseOutbox,
}

#[derive(Clone)]
struct ReleaseOutbox {
    directory: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
    next_temp_id: Arc<AtomicU64>,
}

#[derive(Serialize)]
struct RedeemRequest<'a> {
    ticket: &'a str,
    notary_instance_id: &'a str,
    mode: &'static str,
    directory_generation: u64,
    contract: &'static str,
}

#[derive(Deserialize)]
struct RedeemedLease {
    lease_id: String,
    lease_expires_at: i64,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    record_digest: Option<String>,
    authorized_allowance_bytes: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemedOperation {
    #[serde(default, rename = "operation_id")]
    _operation_id: Option<String>,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    record_digest: Option<String>,
    authenticated_allowance_bytes: Option<i64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RedeemedAdmission {
    Operation(RedeemedOperation),
    Lease(RedeemedLease),
}

#[derive(Serialize)]
struct LeaseRequest<'a> {
    lease_id: &'a str,
    notary_instance_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<LeaseCompletionOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    used_allowance_bytes: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LeaseCompletionOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PendingLeaseRelease {
    lease_id: String,
    notary_instance_id: String,
    outcome: LeaseCompletionOutcome,
    used_allowance_bytes: Option<i64>,
}

#[derive(Deserialize)]
struct LeaseRenewed {
    lease_expires_at: i64,
}

#[derive(Deserialize)]
struct CoordinatorErrorResponse {
    error: String,
}

enum CoordinatorRejection {
    Capacity,
    Denied,
    CaptureCreditsExhausted,
    FinalizationCreditsExhausted,
    Unavailable(anyhow::Error),
}

#[derive(Parser, Debug)]
#[command(about = "LLM Notary TLSNotary service")]
struct Args {
    /// Print the signing key's SEC1 public key and exit. Used by deployment
    /// health checks without exposing the private key.
    #[arg(long)]
    print_public_key: bool,
    #[arg(long, default_value = "127.0.0.1:7047")]
    listen: SocketAddr,

    /// A file containing exactly 32 hexadecimal bytes. This key is the trust
    /// root for receipts, so use an HSM/KMS in a real deployment.
    #[arg(long)]
    signing_key: PathBuf,

    /// Reject new capture sessions while continuing to finalize bundles that
    /// were captured before a planned key handoff.
    #[arg(long)]
    finalize_only: bool,

    /// Exact provider hostnames this notary may connect to in Proxy-TLS mode.
    /// Supplying this explicitly is required in production; the development
    /// defaults cover the supported provider adapters.
    #[arg(long, default_values_t = [
        "api.openai.com".to_owned(),
        "chatgpt.com".to_owned(),
        "api.anthropic.com".to_owned(),
        "api.deepseek.com".to_owned(),
        "openrouter.ai".to_owned(),
    ])]
    allow_host: Vec<String>,

    /// Largest private-proof chunk accepted from a client. This is a service
    /// resource limit; clients cannot raise it in their proof request.
    #[arg(long, default_value_t = 128 * 1024)]
    max_private_chunk_bytes: usize,

    /// Largest total private transcript commitment set accepted in one proof.
    /// This bounds transcript bytes when every individual chunk is valid.
    #[arg(long, default_value_t = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)]
    max_total_private_chunk_bytes: usize,

    /// Largest number of private commitments accepted in one proof. Each
    /// commitment creates a child proof VM, so this bounds fixed proof work.
    #[arg(long, default_value_t = 128)]
    max_private_chunk_commitments: usize,

    /// Largest serialized proof or attestation frame accepted from a paired
    /// proxy. This must match the proxy's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,

    /// Maximum number of simultaneous live Proxy-TLS capture sessions.
    ///
    /// This is independent from --max-concurrent-finalizations so deferred
    /// proofs cannot consume all capacity needed for live provider traffic.
    #[arg(long, default_value_t = 8)]
    max_concurrent_captures: usize,

    /// Maximum number of simultaneous deferred private-proof finalizations.
    ///
    /// This is independent from --max-concurrent-captures. Finalization is
    /// the CPU- and memory-intensive phase, while capture prioritizes live
    /// request latency.
    #[arg(long, default_value_t = 1)]
    max_concurrent_finalizations: usize,

    /// Maximum number of sockets waiting to send a valid protocol prelude.
    #[arg(long, default_value_t = 128)]
    max_pending_connections: usize,

    /// Time allowed for a new socket to send its complete protocol prelude.
    #[arg(long, default_value_t = 10)]
    prelude_timeout_secs: u64,

    /// Hard wall-clock limit for one notary protocol session.
    #[arg(long, default_value_t = 30 * 60)]
    session_timeout_secs: u64,

    /// Emit per-session cgroup CPU and memory measurements in structured logs.
    ///
    /// This is intended for one-session-at-a-time Linux container profiling.
    /// The metrics are unavailable outside cgroup v2 environments.
    #[arg(long)]
    profile_sessions: bool,
}

impl ReleaseOutbox {
    fn open(directory: PathBuf) -> Result<Self> {
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating release outbox {}", directory.display()))?;
        if !fs::metadata(&directory)
            .with_context(|| format!("reading release outbox {}", directory.display()))?
            .is_dir()
        {
            bail!("release outbox path must be a directory");
        }
        let outbox = Self {
            directory: Arc::new(directory),
            write_lock: Arc::new(Mutex::new(())),
            next_temp_id: Arc::new(AtomicU64::new(0)),
        };
        outbox.remove_stale_temporary_files()?;
        // No session from the previous process can still be writing its
        // receipt. Promote every valid staged record so restart recovery can
        // replay it, including a process that died immediately after sending
        // the receipt.
        for release in outbox.all_releases()? {
            outbox.mark_ready(&release)?;
        }
        Ok(outbox)
    }

    fn remove_stale_temporary_files(&self) -> Result<()> {
        for entry in fs::read_dir(self.directory.as_ref())
            .with_context(|| format!("reading release outbox {}", self.directory.display()))?
        {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if file_name.starts_with(".release-") && file_name.ends_with(".tmp") {
                fs::remove_file(&path).with_context(|| {
                    format!("removing stale release outbox file {}", path.display())
                })?;
            }
        }
        Ok(())
    }

    fn persist_or_existing(&self, release: PendingLeaseRelease) -> Result<PendingLeaseRelease> {
        validate_pending_release(&release)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("release outbox lock was poisoned"))?;
        let path = self.release_path(&release.lease_id);
        if path.exists() {
            return self.read_release(&path);
        }

        let bytes = serde_json::to_vec(&release).context("serializing pending lease release")?;
        let temp_id = self.next_temp_id.fetch_add(1, Ordering::Relaxed);
        let temp_path = self
            .directory
            .join(format!(".release-{}-{temp_id}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .with_context(|| format!("creating release outbox file {}", temp_path.display()))?;
        let persist = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp_path, &path)?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if persist.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        persist.with_context(|| format!("persisting release outbox file {}", path.display()))?;
        Ok(release)
    }

    fn prepare_for_release(&self, release: PendingLeaseRelease) -> Result<PendingLeaseRelease> {
        let persisted = self.persist_or_existing(release)?;
        self.mark_ready(&persisted)?;
        Ok(persisted)
    }

    fn mark_ready(&self, release: &PendingLeaseRelease) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("release outbox lock was poisoned"))?;
        let stored = self.read_release(&self.release_path(&release.lease_id))?;
        if stored != *release {
            bail!("pending lease release changed before becoming replayable");
        }
        let path = self.ready_path(&release.lease_id);
        if path.exists() {
            return Ok(());
        }
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("creating release-ready marker {}", path.display()))?;
        file.sync_all()?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn pending(&self) -> Result<Vec<PendingLeaseRelease>> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("release outbox lock was poisoned"))?;
        Ok(self
            .read_all_releases()?
            .into_iter()
            .filter(|release| self.ready_path(&release.lease_id).exists())
            .collect())
    }

    fn all_releases(&self) -> Result<Vec<PendingLeaseRelease>> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("release outbox lock was poisoned"))?;
        self.read_all_releases()
    }

    fn read_all_releases(&self) -> Result<Vec<PendingLeaseRelease>> {
        let mut pending = Vec::new();
        for entry in fs::read_dir(self.directory.as_ref())
            .with_context(|| format!("reading release outbox {}", self.directory.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            pending.push(self.read_release(&path)?);
        }
        pending.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        Ok(pending)
    }

    fn complete(&self, release: &PendingLeaseRelease) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("release outbox lock was poisoned"))?;
        let path = self.release_path(&release.lease_id);
        if !path.exists() {
            return Ok(());
        }
        let stored = self.read_release(&path)?;
        if stored != *release {
            bail!("pending lease release changed before completion");
        }
        let ready_path = self.ready_path(&release.lease_id);
        if ready_path.exists() {
            fs::remove_file(&ready_path).with_context(|| {
                format!("removing release-ready marker {}", ready_path.display())
            })?;
        }
        fs::remove_file(&path)
            .with_context(|| format!("removing release outbox file {}", path.display()))?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    fn release_path(&self, lease_id: &str) -> PathBuf {
        self.directory.join(format!("{lease_id}.json"))
    }

    fn ready_path(&self, lease_id: &str) -> PathBuf {
        self.directory.join(format!("{lease_id}.ready"))
    }

    fn read_release(&self, path: &Path) -> Result<PendingLeaseRelease> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading release outbox file {}", path.display()))?;
        let release: PendingLeaseRelease = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing release outbox file {}", path.display()))?;
        validate_pending_release(&release)?;
        if path.file_name().and_then(|value| value.to_str())
            != Some(&format!("{}.json", release.lease_id))
        {
            bail!("release outbox filename does not match its lease ID");
        }
        Ok(release)
    }
}

fn validate_pending_release(release: &PendingLeaseRelease) -> Result<()> {
    let safe_identifier = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    if !safe_identifier(&release.lease_id) {
        bail!("pending release lease ID is not a safe identifier");
    }
    if !safe_identifier(&release.notary_instance_id) {
        bail!("pending release notary instance ID is not a safe identifier");
    }
    if release.used_allowance_bytes.is_some_and(|value| value < 0) {
        bail!("pending release allowance cannot be negative");
    }
    if release.outcome != LeaseCompletionOutcome::Completed
        && release.used_allowance_bytes.is_some()
    {
        bail!("only completed leases may include exact allowance usage");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

impl AdmissionCoordinator {
    fn from_env() -> Result<Self> {
        let origin = env::var("LLM_NOTARY_ADMISSION_API_ORIGIN")
            .context("LLM_NOTARY_ADMISSION_API_ORIGIN must be set")?;
        let origin = Url::parse(&origin)
            .context("LLM_NOTARY_ADMISSION_API_ORIGIN must be an absolute URL")?;
        if origin.cannot_be_a_base() || origin.query().is_some() || origin.fragment().is_some() {
            bail!("LLM_NOTARY_ADMISSION_API_ORIGIN must be a base URL without query or fragment");
        }
        if origin.scheme() != "https"
            && !(origin.scheme() == "http"
                && origin.host_str().is_some_and(|host| {
                    host == "localhost"
                        || host == "127.0.0.1"
                        || host == "::1"
                        || host.ends_with(".flycast")
                }))
        {
            bail!("admission API origin must use HTTPS, loopback HTTP, or private Flycast HTTP");
        }
        let token_file = env::var("LLM_NOTARY_ADMISSION_SERVICE_TOKEN_FILE")
            .context("LLM_NOTARY_ADMISSION_SERVICE_TOKEN_FILE must be set")?;
        let service_token = fs::read_to_string(&token_file)
            .with_context(|| format!("reading admission service token file {token_file}"))?;
        let service_token = service_token.trim();
        if !(32..=512).contains(&service_token.len()) {
            bail!("admission service token must contain between 32 and 512 bytes");
        }
        let instance_id = env::var("LLM_NOTARY_INSTANCE_ID")
            .or_else(|_| env::var("FLY_MACHINE_ID"))
            .unwrap_or_else(|_| format!("notary-{}", std::process::id()));
        if instance_id.is_empty()
            || instance_id.len() > 128
            || !instance_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("LLM_NOTARY_INSTANCE_ID must be a safe identifier of at most 128 bytes");
        }
        let directory_generation = env::var("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .context("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION must be a u64")?;
        let renew_interval_secs = env::var("LLM_NOTARY_ADMISSION_RENEW_INTERVAL_SECS")
            .unwrap_or_else(|_| DEFAULT_LEASE_RENEW_INTERVAL_SECS.to_string())
            .parse::<u64>()
            .context("LLM_NOTARY_ADMISSION_RENEW_INTERVAL_SECS must be a u64")?;
        if renew_interval_secs == 0 || renew_interval_secs > 60 {
            bail!("LLM_NOTARY_ADMISSION_RENEW_INTERVAL_SECS must be between 1 and 60");
        }
        let release_outbox = env::var("LLM_NOTARY_RELEASE_OUTBOX_DIR")
            .context("LLM_NOTARY_RELEASE_OUTBOX_DIR must be set")?;
        if release_outbox.is_empty() {
            bail!("LLM_NOTARY_RELEASE_OUTBOX_DIR must not be empty");
        }
        let release_outbox = ReleaseOutbox::open(PathBuf::from(release_outbox))?;
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent("LLM-Notary-Service/0.1")
                .timeout(Duration::from_secs(5))
                .build()
                .context("building admission coordinator client")?,
            origin,
            service_token: Arc::from(service_token),
            instance_id: Arc::from(instance_id),
            directory_generation,
            renew_interval: Duration::from_secs(renew_interval_secs),
            release_outbox,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.origin
            .join(path)
            .with_context(|| format!("building admission coordinator URL for {path}"))
    }

    async fn redeem(
        &self,
        ticket: &str,
        mode: NotarySessionMode,
    ) -> std::result::Result<RedeemedAdmission, CoordinatorRejection> {
        let url = self
            .endpoint("/api/internal/notary/admissions/redeem")
            .map_err(CoordinatorRejection::Unavailable)?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.service_token.as_ref())
            .json(&RedeemRequest {
                ticket,
                notary_instance_id: self.instance_id.as_ref(),
                mode: session_mode_label(mode),
                directory_generation: self.directory_generation,
                contract: "one_operation_v1",
            })
            .send()
            .await
            .map_err(|error| CoordinatorRejection::Unavailable(error.into()))?;
        match response.status() {
            reqwest::StatusCode::OK => response
                .json()
                .await
                .map_err(|error| CoordinatorRejection::Unavailable(error.into())),
            status => {
                let error_code = response
                    .json::<CoordinatorErrorResponse>()
                    .await
                    .ok()
                    .map(|error| error.error);
                Err(coordinator_rejection(status, error_code.as_deref()))
            }
        }
    }

    async fn renew(&self, lease_id: &str) -> Result<i64> {
        let response = self
            .http
            .post(self.endpoint("/api/internal/notary/leases/renew")?)
            .bearer_auth(self.service_token.as_ref())
            .json(&LeaseRequest {
                lease_id,
                notary_instance_id: self.instance_id.as_ref(),
                outcome: None,
                used_allowance_bytes: None,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json::<LeaseRenewed>().await?.lease_expires_at)
    }

    async fn release(&self, release: &PendingLeaseRelease) -> Result<()> {
        self.http
            .post(self.endpoint("/api/internal/notary/leases/release")?)
            .bearer_auth(self.service_token.as_ref())
            .json(&LeaseRequest {
                lease_id: &release.lease_id,
                notary_instance_id: &release.notary_instance_id,
                outcome: Some(release.outcome),
                used_allowance_bytes: release.used_allowance_bytes,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn pending_release(
        &self,
        lease_id: &str,
        outcome: LeaseCompletionOutcome,
        used_allowance_bytes: Option<i64>,
    ) -> PendingLeaseRelease {
        PendingLeaseRelease {
            lease_id: lease_id.to_owned(),
            notary_instance_id: self.instance_id.to_string(),
            outcome,
            used_allowance_bytes,
        }
    }

    fn persist_release(
        &self,
        lease_id: &str,
        outcome: LeaseCompletionOutcome,
        used_allowance_bytes: Option<i64>,
    ) -> Result<PendingLeaseRelease> {
        let requested = self.pending_release(lease_id, outcome, used_allowance_bytes);
        let persisted = self.release_outbox.persist_or_existing(requested.clone())?;
        if persisted != requested {
            bail!("lease already has a different pending release");
        }
        Ok(persisted)
    }

    async fn settle(
        &self,
        lease_id: &str,
        outcome: LeaseCompletionOutcome,
        used_allowance_bytes: Option<i64>,
    ) -> Result<()> {
        // A completed capture is recorded before its receipt is sent. If the
        // receipt write later fails, preserve that earlier exact settlement
        // instead of replacing it with a transport-failure outcome.
        let release = self
            .release_outbox
            .prepare_for_release(self.pending_release(lease_id, outcome, used_allowance_bytes))?;
        self.release(&release).await?;
        self.release_outbox.complete(&release)
    }

    async fn replay_pending_releases(self) {
        loop {
            match self.release_outbox.pending() {
                Ok(pending) => {
                    gauge!("llm_notary_notary_pending_lease_releases").set(pending.len() as f64);
                    for release in pending {
                        match self.release(&release).await {
                            Ok(()) => {
                                if let Err(error) = self.release_outbox.complete(&release) {
                                    tracing::error!(%error, "removing replayed lease release from outbox failed");
                                }
                            }
                            Err(error) => {
                                tracing::warn!(%error, "pending lease release still awaiting coordinator");
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "reading release outbox failed");
                }
            }
            tokio::time::sleep(RELEASE_OUTBOX_RETRY_INTERVAL).await;
        }
    }
}

fn coordinator_rejection(
    status: reqwest::StatusCode,
    error_code: Option<&str>,
) -> CoordinatorRejection {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => CoordinatorRejection::Capacity,
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("capture_credits_exhausted") =>
        {
            CoordinatorRejection::CaptureCreditsExhausted
        }
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("finalization_credits_exhausted") =>
        {
            CoordinatorRejection::FinalizationCreditsExhausted
        }
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            CoordinatorRejection::Unavailable(anyhow::anyhow!(
                "admission coordinator rejected service authentication"
            ))
        }
        status if status.is_client_error() => CoordinatorRejection::Denied,
        status => CoordinatorRejection::Unavailable(anyhow::anyhow!(
            "admission coordinator returned {status}"
        )),
    }
}

#[derive(Clone)]
struct SessionBudgets {
    captures: Arc<Semaphore>,
    finalizations: Arc<Semaphore>,
}

impl SessionBudgets {
    fn new(captures: usize, finalizations: usize) -> Self {
        Self {
            captures: Arc::new(Semaphore::new(captures)),
            finalizations: Arc::new(Semaphore::new(finalizations)),
        }
    }

    fn try_acquire(
        &self,
        mode: NotarySessionMode,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        match mode {
            NotarySessionMode::Capture => Arc::clone(&self.captures).try_acquire_owned(),
            NotarySessionMode::Finalize => Arc::clone(&self.finalizations).try_acquire_owned(),
        }
    }

    fn available_permits(&self, mode: NotarySessionMode) -> usize {
        match mode {
            NotarySessionMode::Capture => self.captures.available_permits(),
            NotarySessionMode::Finalize => self.finalizations.available_permits(),
        }
    }
}

struct SessionProfile {
    mode: NotarySessionMode,
    started: Instant,
    cgroup: Option<Cgroup>,
    cpu_start: Option<CgroupCpuStat>,
    memory_current_start_bytes: Option<u64>,
    memory_peak_start_bytes: Option<u64>,
    memory_events_start: Option<CgroupMemoryEvents>,
    sampled_memory_peak_bytes: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
    sampler: tokio::task::JoinHandle<()>,
}

impl SessionProfile {
    fn start(mode: NotarySessionMode) -> Self {
        let cgroup = Cgroup::for_current_process();
        let sampled_memory_peak_bytes = Arc::new(AtomicU64::new(
            cgroup
                .as_ref()
                .and_then(Cgroup::memory_current_bytes)
                .unwrap_or_default(),
        ));
        let peak = Arc::clone(&sampled_memory_peak_bytes);
        let (stop, mut stopped) = watch::channel(false);
        let sampler_cgroup = cgroup.clone();
        let sampler = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(10));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        if let Some(current) = sampler_cgroup
                            .as_ref()
                            .and_then(Cgroup::memory_current_bytes)
                        {
                            peak.fetch_max(current, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        Self {
            mode,
            started: Instant::now(),
            cpu_start: cgroup.as_ref().and_then(Cgroup::cpu_stat),
            memory_current_start_bytes: cgroup.as_ref().and_then(Cgroup::memory_current_bytes),
            memory_peak_start_bytes: cgroup.as_ref().and_then(Cgroup::memory_peak_bytes),
            memory_events_start: cgroup.as_ref().and_then(Cgroup::memory_events),
            cgroup,
            sampled_memory_peak_bytes,
            stop,
            sampler,
        }
    }

    async fn finish(self, outcome: &'static str) {
        let _ = self.stop.send(true);
        let _ = self.sampler.await;
        let sampled_memory_peak_bytes = self.sampled_memory_peak_bytes.load(Ordering::Relaxed);
        let cpu_end = self.cgroup.as_ref().and_then(Cgroup::cpu_stat);
        let memory_current_end_bytes = self.cgroup.as_ref().and_then(Cgroup::memory_current_bytes);
        let memory_peak_end_bytes = self.cgroup.as_ref().and_then(Cgroup::memory_peak_bytes);
        let memory_events_end = self.cgroup.as_ref().and_then(Cgroup::memory_events);
        tracing::info!(
            mode = session_mode_label(self.mode),
            outcome,
            elapsed_ms = self.started.elapsed().as_millis(),
            cgroup_path = ?self.cgroup.as_ref().map(Cgroup::path_display),
            cgroup_cpu_usage_usec = ?CgroupCpuStat::usage_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_user_usec = ?CgroupCpuStat::user_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_system_usec = ?CgroupCpuStat::system_delta_usec(self.cpu_start, cpu_end),
            cgroup_cpu_throttled_usec = ?CgroupCpuStat::throttled_delta_usec(self.cpu_start, cpu_end),
            cgroup_memory_current_start_bytes = ?self.memory_current_start_bytes,
            cgroup_memory_current_end_bytes = ?memory_current_end_bytes,
            cgroup_memory_sampled_peak_bytes = ?(sampled_memory_peak_bytes != 0).then_some(sampled_memory_peak_bytes),
            cgroup_memory_peak_start_bytes = ?self.memory_peak_start_bytes,
            cgroup_memory_peak_end_bytes = ?memory_peak_end_bytes,
            cgroup_memory_peak_increase_bytes = ?delta(self.memory_peak_start_bytes, memory_peak_end_bytes),
            cgroup_memory_max_bytes = ?self.cgroup.as_ref().and_then(Cgroup::memory_max_bytes),
            cgroup_memory_events_oom = ?CgroupMemoryEvents::oom_delta(self.memory_events_start, memory_events_end),
            cgroup_memory_events_oom_kill = ?CgroupMemoryEvents::oom_kill_delta(self.memory_events_start, memory_events_end),
            "notary session resource profile"
        );
    }
}

#[derive(Clone, Debug)]
enum Cgroup {
    V2(CgroupV2),
    V1(CgroupV1),
}

impl Cgroup {
    fn for_current_process() -> Option<Self> {
        CgroupV2::for_current_process()
            .map(Self::V2)
            .or_else(|| CgroupV1::for_current_process().map(Self::V1))
    }

    fn path_display(&self) -> String {
        match self {
            Self::V2(cgroup) => cgroup.path.display().to_string(),
            Self::V1(cgroup) => cgroup.path_display(),
        }
    }

    fn cpu_stat(&self) -> Option<CgroupCpuStat> {
        match self {
            Self::V2(cgroup) => cgroup.cpu_stat(),
            Self::V1(cgroup) => cgroup.cpu_stat(),
        }
    }

    fn memory_current_bytes(&self) -> Option<u64> {
        match self {
            Self::V2(cgroup) => cgroup.memory_current_bytes(),
            Self::V1(cgroup) => cgroup.memory_current_bytes(),
        }
    }

    fn memory_peak_bytes(&self) -> Option<u64> {
        match self {
            Self::V2(cgroup) => cgroup.memory_peak_bytes(),
            Self::V1(cgroup) => cgroup.memory_peak_bytes(),
        }
    }

    fn memory_max_bytes(&self) -> Option<u64> {
        match self {
            Self::V2(cgroup) => cgroup.memory_max_bytes(),
            Self::V1(cgroup) => cgroup.memory_max_bytes(),
        }
    }

    fn memory_events(&self) -> Option<CgroupMemoryEvents> {
        match self {
            Self::V2(cgroup) => cgroup.memory_events(),
            Self::V1(cgroup) => cgroup.memory_events(),
        }
    }
}

#[derive(Clone, Debug)]
struct CgroupV2 {
    path: PathBuf,
}

impl CgroupV2 {
    fn for_current_process() -> Option<Self> {
        let memberships = fs::read_to_string("/proc/self/cgroup").ok()?;
        let relative = memberships
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?;
        let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        path.join("cgroup.controllers")
            .is_file()
            .then_some(Self { path })
    }

    fn number(&self, file: &str) -> Option<u64> {
        fs::read_to_string(self.path.join(file))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn memory_current_bytes(&self) -> Option<u64> {
        self.number("memory.current")
    }

    fn memory_peak_bytes(&self) -> Option<u64> {
        self.number("memory.peak")
    }

    fn memory_max_bytes(&self) -> Option<u64> {
        self.number("memory.max")
    }

    fn cpu_stat(&self) -> Option<CgroupCpuStat> {
        parse_cgroup_cpu_stat(&fs::read_to_string(self.path.join("cpu.stat")).ok()?)
    }

    fn memory_events(&self) -> Option<CgroupMemoryEvents> {
        parse_cgroup_memory_events(&fs::read_to_string(self.path.join("memory.events")).ok()?)
    }
}

#[derive(Clone, Debug)]
struct CgroupV1 {
    cpuacct_path: Option<PathBuf>,
    cpu_path: Option<PathBuf>,
    memory_path: Option<PathBuf>,
}

impl CgroupV1 {
    fn for_current_process() -> Option<Self> {
        let memberships = fs::read_to_string("/proc/self/cgroup").ok()?;
        let mut cpuacct_path = None;
        let mut cpu_path = None;
        let mut memory_path = None;

        for membership in memberships.lines() {
            let mut fields = membership.splitn(3, ':');
            let (Some(_hierarchy), Some(controllers), Some(relative_path)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if controllers.is_empty() {
                continue;
            }
            let path = Path::new("/sys/fs/cgroup")
                .join(controllers)
                .join(relative_path.trim_start_matches('/'));
            if !path.is_dir() {
                continue;
            }
            if controllers
                .split(',')
                .any(|controller| controller == "cpuacct")
            {
                cpuacct_path = Some(path.clone());
            }
            if controllers.split(',').any(|controller| controller == "cpu") {
                cpu_path = Some(path.clone());
            }
            if controllers
                .split(',')
                .any(|controller| controller == "memory")
            {
                memory_path = Some(path);
            }
        }

        (cpuacct_path.is_some() || memory_path.is_some()).then_some(Self {
            cpuacct_path,
            cpu_path,
            memory_path,
        })
    }

    fn path_display(&self) -> String {
        self.cpuacct_path
            .as_ref()
            .or(self.memory_path.as_ref())
            .or(self.cpu_path.as_ref())
            .map(|path| path.display().to_string())
            .unwrap_or_default()
    }

    fn number(path: Option<&PathBuf>, file: &str) -> Option<u64> {
        fs::read_to_string(path?.join(file))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn cpu_stat(&self) -> Option<CgroupCpuStat> {
        let usage_usec = Self::number(self.cpuacct_path.as_ref(), "cpuacct.usage")? / 1_000;
        let throttled_usec = self
            .cpu_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path.join("cpu.stat")).ok())
            .and_then(|stat| parse_cgroup_v1_throttled_usec(&stat));
        Some(CgroupCpuStat {
            usage_usec,
            user_usec: None,
            system_usec: None,
            throttled_usec,
        })
    }

    fn memory_current_bytes(&self) -> Option<u64> {
        Self::number(self.memory_path.as_ref(), "memory.usage_in_bytes")
    }

    fn memory_peak_bytes(&self) -> Option<u64> {
        Self::number(self.memory_path.as_ref(), "memory.max_usage_in_bytes")
    }

    fn memory_max_bytes(&self) -> Option<u64> {
        Self::number(self.memory_path.as_ref(), "memory.limit_in_bytes")
    }

    fn memory_events(&self) -> Option<CgroupMemoryEvents> {
        // cgroup v1 exposes only a limit-charge failure counter. It is not an
        // OOM/OOM-kill counter, so leave these v2-specific fields absent.
        None
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupCpuStat {
    usage_usec: u64,
    user_usec: Option<u64>,
    system_usec: Option<u64>,
    throttled_usec: Option<u64>,
}

impl CgroupCpuStat {
    fn usage_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|stat| stat.usage_usec),
            end.map(|stat| stat.usage_usec),
        )
    }

    fn user_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.user_usec),
            end.and_then(|stat| stat.user_usec),
        )
    }

    fn system_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.system_usec),
            end.and_then(|stat| stat.system_usec),
        )
    }

    fn throttled_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.and_then(|stat| stat.throttled_usec),
            end.and_then(|stat| stat.throttled_usec),
        )
    }
}

fn parse_cgroup_cpu_stat(stat: &str) -> Option<CgroupCpuStat> {
    let mut parsed = CgroupCpuStat::default();
    for line in stat.lines() {
        let (name, value) = line.split_once(' ')?;
        let value = value.parse().ok()?;
        match name {
            "usage_usec" => parsed.usage_usec = value,
            "user_usec" => parsed.user_usec = Some(value),
            "system_usec" => parsed.system_usec = Some(value),
            "throttled_usec" => parsed.throttled_usec = Some(value),
            _ => {}
        }
    }
    (parsed.usage_usec != 0).then_some(parsed)
}

fn parse_cgroup_v1_throttled_usec(stat: &str) -> Option<u64> {
    stat.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == "throttled_time")
            .then(|| value.parse::<u64>().ok().map(|value| value / 1_000))
            .flatten()
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupMemoryEvents {
    oom: u64,
    oom_kill: u64,
}

impl CgroupMemoryEvents {
    fn oom_delta(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(start.map(|events| events.oom), end.map(|events| events.oom))
    }

    fn oom_kill_delta(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|events| events.oom_kill),
            end.map(|events| events.oom_kill),
        )
    }
}

fn parse_cgroup_memory_events(events: &str) -> Option<CgroupMemoryEvents> {
    let mut parsed = CgroupMemoryEvents::default();
    for line in events.lines() {
        let (name, value) = line.split_once(' ')?;
        let value = value.parse().ok()?;
        match name {
            "oom" => parsed.oom = value,
            "oom_kill" => parsed.oom_kill = value,
            _ => {}
        }
    }
    Some(parsed)
}

fn delta(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    end.and_then(|end| start.and_then(|start| end.checked_sub(start)))
}

/// Runs the remote Proxy-TLS notary service.
pub async fn run() -> Result<()> {
    let _telemetry = llm_notary_core::telemetry::init("llm-notary-server")?;
    let args = Args::parse();
    if args.max_private_chunk_bytes == 0
        || args.max_total_private_chunk_bytes == 0
        || args.max_private_chunk_commitments == 0
        || args.max_concurrent_captures == 0
        || args.max_concurrent_finalizations == 0
        || args.max_pending_connections == 0
        || args.prelude_timeout_secs == 0
        || args.session_timeout_secs == 0
    {
        bail!("notary resource limits must be non-zero");
    }
    if args.max_frame_bytes == 0 || args.max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    let key_text = std::fs::read_to_string(&args.signing_key)
        .with_context(|| format!("reading {}", args.signing_key.display()))?;
    let bytes = hex::decode(key_text.trim()).context("signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    let key = Arc::new(SigningKey::from_slice(&bytes).context("invalid secp256k1 key")?);
    let public_key = hex::encode(key.verifying_key().to_sec1_bytes());
    if args.print_public_key {
        println!("{public_key}");
        return Ok(());
    }
    let admission = AdmissionCoordinator::from_env()?;
    tokio::spawn(admission.clone().replay_pending_releases());
    let allowed_hosts = Arc::new(
        args.allow_host
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    );
    let listener = TcpListener::bind(args.listen).await?;
    let session_budgets = SessionBudgets::new(
        args.max_concurrent_captures,
        args.max_concurrent_finalizations,
    );
    let connection_permits = Arc::new(Semaphore::new(args.max_pending_connections));
    gauge!("llm_notary_notary_active_sessions", "mode" => "capture").set(0.0);
    gauge!("llm_notary_notary_active_sessions", "mode" => "finalize").set(0.0);
    gauge!("llm_notary_notary_pending_connections").set(0.0);
    if let Some(metrics_listen) = env::var("LLM_NOTARY_METRICS_LISTEN")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .context("LLM_NOTARY_METRICS_LISTEN must be a socket address")?
    {
        tokio::spawn(async move {
            let listener = match TcpListener::bind(metrics_listen).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::error!(%error, %metrics_listen, "binding notary metrics listener failed");
                    return;
                }
            };
            tracing::info!(%metrics_listen, "notary metrics listener active");
            if let Err(error) =
                axum::serve(listener, Router::new().route("/metrics", get(metrics))).await
            {
                tracing::error!(%error, "notary metrics listener stopped");
            }
        });
    }
    tracing::info!(
        address = %args.listen,
        public_key,
        max_concurrent_captures = args.max_concurrent_captures,
        max_concurrent_finalizations = args.max_concurrent_finalizations,
        "LLM Notary service listening"
    );
    println!("LLM Notary public key: {public_key}");

    loop {
        let (mut stream, _address) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let Ok(connection_permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            counter!("llm_notary_notary_sessions_total", "mode" => "unknown", "outcome" => "rejected_pending_limit").increment(1);
            tracing::warn!("notary connection rejected at pending-connection limit");
            continue;
        };
        gauge!("llm_notary_notary_pending_connections")
            .set((args.max_pending_connections - connection_permits.available_permits()) as f64);
        tracing::info!("notary client connected");
        let key = Arc::clone(&key);
        let allowed_hosts = Arc::clone(&allowed_hosts);
        let max_private_chunk_bytes = args.max_private_chunk_bytes;
        let max_total_private_chunk_bytes = args.max_total_private_chunk_bytes;
        let max_private_chunk_commitments = args.max_private_chunk_commitments;
        let max_frame_bytes = args.max_frame_bytes;
        let prelude_timeout = std::time::Duration::from_secs(args.prelude_timeout_secs);
        let session_timeout = std::time::Duration::from_secs(args.session_timeout_secs);
        let connection_permits = Arc::clone(&connection_permits);
        let session_budgets = session_budgets.clone();
        let finalize_only = args.finalize_only;
        let profile_sessions = args.profile_sessions;
        let max_pending_connections = args.max_pending_connections;
        let max_concurrent_captures = args.max_concurrent_captures;
        let max_concurrent_finalizations = args.max_concurrent_finalizations;
        let admission = admission.clone();
        tokio::spawn(async move {
            let prelude = match timeout(
                prelude_timeout,
                read_hosted_notary_session_prelude(&mut stream),
            )
            .await
            {
                Ok(Ok(prelude)) => prelude,
                Ok(Err(error)) => {
                    drop(connection_permit);
                    gauge!("llm_notary_notary_pending_connections").set(
                        (max_pending_connections - connection_permits.available_permits()) as f64,
                    );
                    counter!("llm_notary_notary_sessions_total", "mode" => "unknown", "outcome" => "invalid_prelude").increment(1);
                    tracing::warn!(%error, "invalid notary session prelude");
                    return;
                }
                Err(_) => {
                    drop(connection_permit);
                    gauge!("llm_notary_notary_pending_connections").set(
                        (max_pending_connections - connection_permits.available_permits()) as f64,
                    );
                    counter!("llm_notary_notary_sessions_total", "mode" => "unknown", "outcome" => "prelude_timed_out").increment(1);
                    tracing::warn!("notary session prelude timed out");
                    return;
                }
            };
            drop(connection_permit);
            gauge!("llm_notary_notary_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            let mode = prelude.mode();
            if !session_mode_allowed(finalize_only, mode) {
                counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_finalize_only").increment(1);
                tracing::warn!("capture rejected by finalize-only notary");
                if let Err(error) = write_notary_admission(
                    &mut stream,
                    &prelude,
                    Err(NotaryAdmissionRejection::CaptureDisabled),
                )
                .await
                {
                    tracing::debug!(%error, "could not send notary admission rejection");
                }
                return;
            }
            let Ok(session_permit) = session_budgets.try_acquire(mode) else {
                counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_concurrency_limit").increment(1);
                tracing::warn!(
                    mode = session_mode_label(mode),
                    "notary session rejected at mode concurrency limit"
                );
                let rejection = match mode {
                    NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
                    NotarySessionMode::Finalize => NotaryAdmissionRejection::FinalizeAtCapacity,
                };
                if let Err(error) =
                    write_notary_admission(&mut stream, &prelude, Err(rejection)).await
                {
                    tracing::debug!(%error, "could not send notary admission rejection");
                }
                return;
            };
            let ticket = prelude
                .admission_ticket()
                .expect("hosted prelude always has a ticket");
            let redeemed = match admission.redeem(ticket, mode).await {
                Ok(redeemed) => redeemed,
                Err(rejection) => {
                    let rejection = match rejection {
                        CoordinatorRejection::Capacity => match mode {
                            NotarySessionMode::Capture => {
                                NotaryAdmissionRejection::CaptureAtCapacity
                            }
                            NotarySessionMode::Finalize => {
                                NotaryAdmissionRejection::FinalizeAtCapacity
                            }
                        },
                        CoordinatorRejection::Denied => NotaryAdmissionRejection::AdmissionDenied,
                        CoordinatorRejection::CaptureCreditsExhausted => {
                            NotaryAdmissionRejection::CaptureCreditsExhausted
                        }
                        CoordinatorRejection::FinalizationCreditsExhausted => {
                            NotaryAdmissionRejection::FinalizationCreditsExhausted
                        }
                        CoordinatorRejection::Unavailable(error) => {
                            tracing::error!(%error, "admission coordinator request failed");
                            NotaryAdmissionRejection::CoordinatorUnavailable
                        }
                    };
                    counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_coordinator").increment(1);
                    if let Err(error) =
                        write_notary_admission(&mut stream, &prelude, Err(rejection)).await
                    {
                        tracing::debug!(%error, "could not send notary admission rejection");
                    }
                    return;
                }
            };
            let (operation, legacy_lease) = match redeemed {
                RedeemedAdmission::Operation(operation) => (operation, None),
                RedeemedAdmission::Lease(lease) => {
                    let operation = RedeemedOperation {
                        _operation_id: None,
                        max_attestable_http_bytes: lease.max_attestable_http_bytes,
                        max_frame_bytes: lease.max_frame_bytes,
                        max_private_chunk_bytes: lease.max_private_chunk_bytes,
                        max_private_chunk_commitments: lease.max_private_chunk_commitments,
                        record_digest: lease.record_digest.clone(),
                        authenticated_allowance_bytes: Some(lease.authorized_allowance_bytes),
                    };
                    (operation, Some(lease))
                }
            };
            let limits = match effective_hosted_limits(
                mode,
                &operation,
                session_timeout,
                max_private_chunk_bytes,
                max_total_private_chunk_bytes,
                max_private_chunk_commitments,
                max_frame_bytes,
            ) {
                Ok(limits) => limits,
                Err(error) => {
                    tracing::error!(%error, "coordinator returned invalid notary limits");
                    if let Some(lease) = legacy_lease.as_ref() {
                        let _ = admission
                            .settle(&lease.lease_id, LeaseCompletionOutcome::ServiceFailed, None)
                            .await;
                    }
                    let _ = write_notary_admission(
                        &mut stream,
                        &prelude,
                        Err(NotaryAdmissionRejection::CoordinatorUnavailable),
                    )
                    .await;
                    return;
                }
            };
            let effective_session_timeout = limits.session_timeout;
            let legacy_lease_deadline = match legacy_lease.as_ref() {
                Some(lease) => match lease_deadline(lease.lease_expires_at) {
                    Ok(deadline) => Some(deadline),
                    Err(error) => {
                        tracing::error!(%error, "coordinator returned an expired notary lease");
                        let _ = admission
                            .settle(&lease.lease_id, LeaseCompletionOutcome::ServiceFailed, None)
                            .await;
                        let _ = write_notary_admission(
                            &mut stream,
                            &prelude,
                            Err(NotaryAdmissionRejection::CoordinatorUnavailable),
                        )
                        .await;
                        return;
                    }
                },
                None => None,
            };
            if let Err(error) = write_notary_admission(&mut stream, &prelude, Ok(())).await {
                tracing::debug!(%error, "could not send notary admission acceptance");
                if let Some(lease) = legacy_lease.as_ref() {
                    let _ = admission
                        .settle(&lease.lease_id, LeaseCompletionOutcome::ClientFailed, None)
                        .await;
                }
                return;
            }
            let max_concurrent_sessions = match mode {
                NotarySessionMode::Capture => max_concurrent_captures,
                NotarySessionMode::Finalize => max_concurrent_finalizations,
            };
            gauge!("llm_notary_notary_active_sessions", "mode" => session_mode_label(mode))
                .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
            let started = Instant::now();
            let session_span = tracing::info_span!(
                "notary.session",
                otel.name = "notary.session",
                notary.session.mode = session_mode_label(mode),
            );
            let profile = profile_sessions.then(|| SessionProfile::start(mode));
            let capture_settlement_recorder: Option<HostedCaptureSettlementRecorder> =
                match (mode, legacy_lease.as_ref()) {
                    (NotarySessionMode::Capture, Some(lease)) => {
                        let admission = admission.clone();
                        let lease_id = lease.lease_id.clone();
                        Some(Box::new(move |authenticated_transcript_bytes| {
                            let used_allowance_bytes =
                                i64::try_from(authenticated_transcript_bytes)
                                    .context("hosted transcript byte count exceeds i64")?;
                            admission.persist_release(
                                &lease_id,
                                LeaseCompletionOutcome::Completed,
                                Some(used_allowance_bytes),
                            )?;
                            Ok(())
                        })
                            as HostedCaptureSettlementRecorder)
                    }
                    _ => None,
                };
            let session = run_hosted_notary_session_after_prelude(
                stream,
                mode,
                key,
                allowed_hosts,
                limits,
                capture_settlement_recorder,
            );
            let session_and_lease = async {
                tokio::pin!(session);
                if let (Some(lease), Some(deadline)) =
                    (legacy_lease.as_ref(), legacy_lease_deadline)
                {
                    let lease_guard = maintain_lease(admission.clone(), &lease.lease_id, deadline);
                    tokio::pin!(lease_guard);
                    tokio::select! {
                        result = &mut session => result,
                        result = &mut lease_guard => {
                            result?;
                            bail!("admission lease guard stopped unexpectedly")
                        }
                    }
                } else {
                    session.await
                }
            };
            let result = timeout(effective_session_timeout, session_and_lease)
                .instrument(session_span)
                .await;
            let (outcome, lease_outcome, used_allowance_bytes) = match result {
                Ok(Ok(session_result)) => {
                    let used_allowance_bytes = match mode {
                        NotarySessionMode::Capture => Some(
                            i64::try_from(session_result.authenticated_transcript_bytes)
                                .expect("hosted transcript limit fits in i64"),
                        ),
                        NotarySessionMode::Finalize => None,
                    };
                    (
                        "completed",
                        LeaseCompletionOutcome::Completed,
                        used_allowance_bytes,
                    )
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "notary session failed");
                    // Once the client-controlled proof stream begins, protocol,
                    // validation, and transport errors cannot safely be called a
                    // service failure. Do not mint a restoration for them.
                    ("failed", LeaseCompletionOutcome::ClientFailed, None)
                }
                Err(_) => {
                    tracing::warn!("notary session timed out");
                    ("timed_out", LeaseCompletionOutcome::ClientFailed, None)
                }
            };
            if let Some(profile) = profile {
                profile.finish(outcome).await;
            }
            if let Some(lease) = legacy_lease.as_ref()
                && let Err(error) = admission
                    .settle(&lease.lease_id, lease_outcome, used_allowance_bytes)
                    .await
            {
                counter!("llm_notary_notary_lease_release_failures_total", "mode" => session_mode_label(mode)).increment(1);
                tracing::warn!(%error, "admission lease release queued for durable retry");
            }
            counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => outcome).increment(1);
            histogram!("llm_notary_notary_session_duration_seconds", "mode" => session_mode_label(mode), "outcome" => outcome).record(started.elapsed().as_secs_f64());
            drop(session_permit);
            gauge!("llm_notary_notary_active_sessions", "mode" => session_mode_label(mode))
                .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
        });
    }
}

async fn metrics() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        llm_notary_core::telemetry::prometheus_metrics(),
    )
}

fn effective_hosted_limits(
    mode: NotarySessionMode,
    operation: &RedeemedOperation,
    local_session_timeout: Duration,
    local_max_private_chunk_bytes: usize,
    local_max_total_private_chunk_bytes: usize,
    local_max_private_chunk_commitments: usize,
    local_max_frame_bytes: usize,
) -> Result<HostedNotarySessionLimits> {
    let positive = |name: &str, value: i64| -> Result<usize> {
        if value <= 0 {
            bail!("coordinator {name} must be positive");
        }
        value
            .try_into()
            .with_context(|| format!("coordinator {name} does not fit in usize"))
    };
    let max_private_chunk_bytes =
        positive("max_private_chunk_bytes", operation.max_private_chunk_bytes)?
            .min(local_max_private_chunk_bytes);
    let policy_attestable = positive(
        "max_attestable_http_bytes",
        operation.max_attestable_http_bytes,
    )?;
    let (expected_record_digest, authenticated_allowance) =
        match (
            mode,
            operation.record_digest.as_deref(),
            operation.authenticated_allowance_bytes,
        ) {
            // A legacy API includes its balance-bounded lease allowance here. The
            // bridge honors it only while that API is active; one-operation capture
            // responses carry no authenticated byte grant.
            (NotarySessionMode::Capture, None, legacy_allowance) => (
                None,
                legacy_allowance
                    .map(|allowance| positive("authorized_allowance_bytes", allowance))
                    .transpose()?
                    .unwrap_or(policy_attestable),
            ),
            (NotarySessionMode::Finalize, Some(digest), Some(allowance)) => {
                let bytes = hex::decode(digest).context("coordinator record digest is not hex")?;
                let allowance = positive("authenticated_allowance_bytes", allowance)?;
                (
                    Some(bytes.try_into().map_err(|_| {
                        anyhow::anyhow!("coordinator record digest is not 32 bytes")
                    })?),
                    allowance,
                )
            }
            _ => bail!("coordinator record digest does not match the session mode"),
        };
    if authenticated_allowance > policy_attestable {
        bail!("coordinator allowance exceeds its per-session ceiling");
    }
    Ok(HostedNotarySessionLimits {
        expected_record_digest,
        expected_transcript_bytes: (mode == NotarySessionMode::Finalize)
            .then_some(authenticated_allowance),
        session_timeout: local_session_timeout,
        max_private_chunk_bytes,
        max_total_private_chunk_bytes: authenticated_allowance
            .min(policy_attestable)
            .min(local_max_total_private_chunk_bytes),
        max_private_chunk_commitments: positive(
            "max_private_chunk_commitments",
            operation.max_private_chunk_commitments,
        )?
        .min(local_max_private_chunk_commitments),
        max_frame_bytes: positive("max_frame_bytes", operation.max_frame_bytes)?
            .min(local_max_frame_bytes),
    })
}

async fn maintain_lease(
    coordinator: AdmissionCoordinator,
    lease_id: &str,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let lease_id = lease_id.to_owned();
    let renew_interval = coordinator.renew_interval;
    maintain_lease_until(renew_interval, deadline, move || {
        let coordinator = coordinator.clone();
        let lease_id = lease_id.clone();
        async move {
            let expires_at = coordinator.renew(&lease_id).await?;
            lease_deadline(expires_at)
        }
    })
    .await
}

fn lease_deadline(expires_at: i64) -> Result<tokio::time::Instant> {
    let expires_at = u64::try_from(expires_at).context("admission lease deadline is negative")?;
    let wall_deadline = std::time::UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at))
        .context("admission lease deadline is too large")?;
    let remaining = wall_deadline
        .duration_since(std::time::SystemTime::now())
        .context("admission lease has already expired")?;
    Ok(tokio::time::Instant::now() + remaining)
}

async fn maintain_lease_until<F, Fut>(
    renew_interval: Duration,
    mut deadline: tokio::time::Instant,
    mut renew: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<tokio::time::Instant>>,
{
    loop {
        let now = tokio::time::Instant::now();
        let remaining = deadline
            .checked_duration_since(now)
            .context("admission lease renewal deadline passed")?;
        let renew_after = renew_interval.min(remaining);
        tokio::time::sleep_until(now + renew_after).await;
        if tokio::time::Instant::now() >= deadline {
            bail!("admission lease renewal deadline passed");
        }
        match tokio::time::timeout_at(deadline, renew()).await {
            Ok(Ok(renewed_deadline)) => {
                if renewed_deadline <= tokio::time::Instant::now() {
                    bail!("admission coordinator returned an expired lease");
                }
                deadline = renewed_deadline;
            }
            Err(_) => bail!("admission lease renewal deadline passed"),
            Ok(Err(_error)) => {
                tracing::warn!("admission lease renewal failed; retrying before its deadline");
            }
        }
    }
}

fn session_mode_label(mode: NotarySessionMode) -> &'static str {
    match mode {
        NotarySessionMode::Capture => "capture",
        NotarySessionMode::Finalize => "finalize",
    }
}

fn session_mode_allowed(finalize_only: bool, mode: NotarySessionMode) -> bool {
    !finalize_only || mode == NotarySessionMode::Finalize
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_OUTBOX_ID: AtomicU64 = AtomicU64::new(0);

    fn test_outbox() -> (ReleaseOutbox, PathBuf) {
        let id = TEST_OUTBOX_ID.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "llm-notary-release-outbox-test-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        (ReleaseOutbox::open(directory.clone()).unwrap(), directory)
    }

    #[test]
    fn finalize_only_rejects_capture_before_protocol_admission() {
        assert!(!session_mode_allowed(true, NotarySessionMode::Capture));
        assert!(session_mode_allowed(true, NotarySessionMode::Finalize));
        assert!(session_mode_allowed(false, NotarySessionMode::Capture));
    }

    #[test]
    fn capture_and_finalize_budgets_are_independent() {
        let budgets = SessionBudgets::new(1, 1);
        let capture = budgets.try_acquire(NotarySessionMode::Capture).unwrap();
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_err());

        let finalize = budgets.try_acquire(NotarySessionMode::Finalize).unwrap();
        assert!(budgets.try_acquire(NotarySessionMode::Finalize).is_err());

        drop(capture);
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_ok());
        drop(finalize);
        assert!(budgets.try_acquire(NotarySessionMode::Finalize).is_ok());
    }

    #[test]
    fn redemption_bridge_requests_one_operation_and_accepts_both_contracts() {
        let request = serde_json::to_value(RedeemRequest {
            ticket: "opaque-ticket",
            notary_instance_id: "notary-test",
            mode: "capture",
            directory_generation: 1,
            contract: "one_operation_v1",
        })
        .unwrap();
        assert_eq!(request["contract"], "one_operation_v1");

        let operation: RedeemedAdmission = serde_json::from_value(serde_json::json!({
            "max_attestable_http_bytes": 1024,
            "max_frame_bytes": 2048,
            "max_private_chunk_bytes": 512,
            "max_private_chunk_commitments": 4,
            "record_digest": null,
            "authenticated_allowance_bytes": null
        }))
        .unwrap();
        assert!(matches!(operation, RedeemedAdmission::Operation(_)));

        let lease: RedeemedAdmission = serde_json::from_value(serde_json::json!({
            "lease_id": "legacy-lease",
            "lease_expires_at": 1,
            "access_pool": "free",
            "max_attestable_http_bytes": 1024,
            "max_frame_bytes": 2048,
            "max_private_chunk_bytes": 512,
            "max_private_chunk_commitments": 4,
            "record_digest": null,
            "authorized_allowance_bytes": 512
        }))
        .unwrap();
        assert!(matches!(lease, RedeemedAdmission::Lease(_)));
    }

    #[test]
    fn coordinator_policy_can_only_reduce_local_size_limits() {
        let operation = RedeemedOperation {
            _operation_id: None,
            max_attestable_http_bytes: 8 << 20,
            max_frame_bytes: 64 << 20,
            max_private_chunk_bytes: 256 << 10,
            max_private_chunk_commitments: 256,
            record_digest: Some("ab".repeat(32)),
            authenticated_allowance_bytes: Some(8 << 20),
        };
        let limits = effective_hosted_limits(
            NotarySessionMode::Finalize,
            &operation,
            Duration::from_secs(30),
            128 << 10,
            4 << 20,
            64,
            32 << 20,
        )
        .expect("valid limits");
        assert_eq!(limits.max_private_chunk_bytes, 128 << 10);
        assert_eq!(limits.max_total_private_chunk_bytes, 4 << 20);
        assert_eq!(limits.max_private_chunk_commitments, 64);
        assert_eq!(limits.max_frame_bytes, 32 << 20);
        assert_eq!(limits.expected_record_digest, Some([0xab; 32]));
        assert_eq!(limits.expected_transcript_bytes, Some(8 << 20));
        assert_eq!(limits.session_timeout, Duration::from_secs(30));
    }

    #[test]
    fn capture_policy_rejects_a_finalization_digest() {
        let operation = RedeemedOperation {
            _operation_id: None,
            max_attestable_http_bytes: 1024,
            max_frame_bytes: 1024,
            max_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 1,
            record_digest: Some("ab".repeat(32)),
            authenticated_allowance_bytes: Some(1024),
        };
        assert!(
            effective_hosted_limits(
                NotarySessionMode::Capture,
                &operation,
                Duration::from_secs(30),
                1024,
                1024,
                1,
                1024,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn coordinator_outage_fails_closed() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let (release_outbox, release_outbox_directory) = test_outbox();
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(250))
                .build()
                .unwrap(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            directory_generation: 1,
            renew_interval: Duration::from_secs(1),
            release_outbox,
        };

        assert!(matches!(
            coordinator
                .redeem("opaque-ticket", NotarySessionMode::Capture)
                .await,
            Err(CoordinatorRejection::Unavailable(_))
        ));
        fs::remove_dir_all(release_outbox_directory).unwrap();
    }

    #[test]
    fn coordinator_authentication_failure_is_not_a_user_denial() {
        assert!(matches!(
            coordinator_rejection(reqwest::StatusCode::UNAUTHORIZED, None),
            CoordinatorRejection::Unavailable(_)
        ));
        assert!(matches!(
            coordinator_rejection(reqwest::StatusCode::FORBIDDEN, None),
            CoordinatorRejection::Unavailable(_)
        ));
        assert!(matches!(
            coordinator_rejection(reqwest::StatusCode::CONFLICT, None),
            CoordinatorRejection::Denied
        ));
        assert!(matches!(
            coordinator_rejection(reqwest::StatusCode::TOO_MANY_REQUESTS, None),
            CoordinatorRejection::Capacity
        ));
        assert!(matches!(
            coordinator_rejection(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                Some("service_capacity"),
            ),
            CoordinatorRejection::Capacity
        ));
        assert!(matches!(
            coordinator_rejection(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                Some("capture_credits_exhausted"),
            ),
            CoordinatorRejection::CaptureCreditsExhausted
        ));
        assert!(matches!(
            coordinator_rejection(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                Some("finalization_credits_exhausted"),
            ),
            CoordinatorRejection::FinalizationCreditsExhausted
        ));
    }

    #[tokio::test]
    async fn lease_guard_stops_at_deadline_after_failures_and_a_hung_renewal() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(80);
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let result = maintain_lease_until(Duration::from_millis(10), deadline, {
            let attempts = Arc::clone(&attempts);
            move || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt < 2 {
                        bail!("immediate renewal failure");
                    }
                    std::future::pending::<Result<tokio::time::Instant>>().await
                }
            }
        })
        .await;

        assert!(result.is_err());
        assert!(attempts.load(Ordering::Relaxed) >= 3);
        assert!(tokio::time::Instant::now() <= deadline + Duration::from_millis(50));
    }

    #[test]
    fn release_outbox_survives_reopen_and_removes_completed_entries() {
        let (outbox, directory) = test_outbox();
        let release = PendingLeaseRelease {
            lease_id: "lease-123".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            outcome: LeaseCompletionOutcome::Completed,
            used_allowance_bytes: Some(42),
        };
        outbox.persist_or_existing(release.clone()).unwrap();
        assert!(outbox.pending().unwrap().is_empty());
        drop(outbox);

        let reopened = ReleaseOutbox::open(directory.clone()).unwrap();
        assert_eq!(reopened.pending().unwrap(), vec![release.clone()]);
        reopened.complete(&release).unwrap();
        assert!(reopened.pending().unwrap().is_empty());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exact_capture_settlement_wins_over_later_transport_failure() {
        let (outbox, directory) = test_outbox();
        let completed = PendingLeaseRelease {
            lease_id: "lease-456".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            outcome: LeaseCompletionOutcome::Completed,
            used_allowance_bytes: Some(512),
        };
        outbox.persist_or_existing(completed.clone()).unwrap();
        assert!(
            outbox.pending().unwrap().is_empty(),
            "pre-receipt records must not be replayable while the session is active"
        );
        let existing = outbox
            .prepare_for_release(PendingLeaseRelease {
                outcome: LeaseCompletionOutcome::ClientFailed,
                used_allowance_bytes: None,
                ..completed.clone()
            })
            .unwrap();

        assert_eq!(existing, completed);
        assert_eq!(outbox.pending().unwrap(), vec![completed]);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn parses_cgroup_cpu_stat() {
        let stat = "usage_usec 42\nuser_usec 21\nsystem_usec 21\nthrottled_usec 3\n";
        assert_eq!(
            parse_cgroup_cpu_stat(stat),
            Some(CgroupCpuStat {
                usage_usec: 42,
                user_usec: Some(21),
                system_usec: Some(21),
                throttled_usec: Some(3),
            })
        );
    }

    #[test]
    fn parses_cgroup_v1_throttled_time() {
        assert_eq!(
            parse_cgroup_v1_throttled_usec("nr_periods 2\nnr_throttled 1\nthrottled_time 4500\n"),
            Some(4)
        );
    }

    #[test]
    fn parses_cgroup_memory_events() {
        assert_eq!(
            parse_cgroup_memory_events("low 0\nhigh 2\nmax 3\noom 4\noom_kill 5\n"),
            Some(CgroupMemoryEvents {
                oom: 4,
                oom_kill: 5,
            })
        );
    }
}
