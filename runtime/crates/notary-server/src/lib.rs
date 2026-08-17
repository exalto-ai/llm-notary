use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use axum::{Router, http::header, response::IntoResponse, routing::get};
use clap::{Args as ClapArgs, Parser, Subcommand};
use k256::ecdsa::SigningKey;
use metrics::{counter, gauge, histogram};
use notary_core::{
    AuthenticatedBytesRecorder, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    NotaryAdmissionRejection, NotarySessionFailureKind, NotarySessionLimits, NotarySessionMode,
    read_notary_session_prelude, run_notary_session_with_limits_after_prelude,
    write_notary_admission,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
    task::JoinSet,
    time::{MissedTickBehavior, timeout},
};
use tracing::Instrument as _;

#[derive(Parser, Debug)]
#[command(
    name = "notary-server",
    about = "Notary remote Proxy-TLS server",
    version
)]
pub struct NotaryServerArgs {
    #[command(subcommand)]
    pub command: NotaryServerCommand,
}

impl NotaryServerArgs {
    pub fn parse_env() -> Self {
        Self::parse()
    }
}

#[derive(Debug, Subcommand)]
pub enum NotaryServerCommand {
    /// Serve Capture and Notarization protocol sessions.
    Serve(NotaryServerServeArgs),
    /// Print the signing key's SEC1 public key and exit.
    PublicKey(NotaryServerPublicKeyArgs),
}

#[derive(Clone, Debug, ClapArgs)]
pub struct NotaryServerPublicKeyArgs {
    /// File containing exactly 32 hexadecimal signing-key bytes.
    #[arg(long, env = "NOTARY_SERVER_SIGNING_KEY_FILE")]
    pub signing_key_file: PathBuf,
}

#[derive(Clone, Debug, ClapArgs)]
pub struct NotaryServerServeArgs {
    /// Public protocol listener.
    #[arg(long, env = "NOTARY_SERVER_LISTEN", default_value = "127.0.0.1:7047")]
    pub listen: SocketAddr,

    /// File containing exactly 32 hexadecimal signing-key bytes.
    #[arg(long, env = "NOTARY_SERVER_SIGNING_KEY_FILE")]
    pub signing_key_file: PathBuf,

    /// Reject Capture sessions while continuing Notarization sessions.
    #[arg(long, env = "NOTARY_SERVER_NOTARIZATION_ONLY")]
    pub notarization_only: bool,

    /// Exact provider hostname the server may resolve and connect to.
    #[arg(
        long = "allow-host",
        env = "NOTARY_SERVER_ALLOW_HOSTS",
        value_delimiter = ',',
        action = clap::ArgAction::Append
    )]
    pub allow_hosts: Vec<String>,

    /// Largest private-proof chunk accepted from a client. This is a service
    /// resource limit; clients cannot raise it in their proof request.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_PRIVATE_CHUNK_BYTES",
        default_value_t = 128 * 1024
    )]
    pub max_private_chunk_bytes: usize,

    /// Largest total private transcript commitment set accepted in one proof.
    /// This bounds transcript bytes when every individual chunk is valid.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_TOTAL_PRIVATE_CHUNK_BYTES",
        default_value_t = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES
    )]
    pub max_total_private_chunk_bytes: usize,

    /// Largest number of private commitments accepted in one proof. Each
    /// commitment creates a child proof VM, so this bounds fixed proof work.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_PRIVATE_CHUNK_COMMITMENTS",
        default_value_t = 128
    )]
    pub max_private_chunk_commitments: usize,

    /// Largest serialized proof or attestation frame accepted from a paired
    /// proxy. This must match the proxy's --max-frame-bytes setting.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_FRAME_BYTES",
        default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES
    )]
    pub max_frame_bytes: usize,

    /// Maximum number of simultaneous live Proxy-TLS capture sessions.
    ///
    /// This is independent from --max-concurrent-notarizations so deferred
    /// proofs cannot consume all capacity needed for live provider traffic.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_CONCURRENT_CAPTURES",
        default_value_t = 8
    )]
    pub max_concurrent_captures: usize,

    /// Maximum number of simultaneous deferred private-proof notarizations.
    ///
    /// This is independent from --max-concurrent-captures. Notarization is
    /// the CPU- and memory-intensive phase, while capture prioritizes live
    /// request latency.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_CONCURRENT_NOTARIZATIONS",
        default_value_t = 1
    )]
    pub max_concurrent_notarizations: usize,

    /// Maximum number of sockets waiting to send a valid protocol prelude.
    #[arg(
        long,
        env = "NOTARY_SERVER_MAX_PENDING_CONNECTIONS",
        default_value_t = 128
    )]
    pub max_pending_connections: usize,

    /// Time allowed for a new socket to send its complete protocol prelude.
    #[arg(long, env = "NOTARY_SERVER_PRELUDE_TIMEOUT_SECS", default_value_t = 10)]
    pub prelude_timeout_secs: u64,

    /// Hard wall-clock limit for one notary protocol session.
    #[arg(
        long,
        env = "NOTARY_SERVER_SESSION_TIMEOUT_SECS",
        default_value_t = 30 * 60
    )]
    pub session_timeout_secs: u64,

    /// Internal-only Prometheus listener.
    #[arg(long, env = "NOTARY_SERVER_METRICS_LISTEN")]
    pub metrics_listen: Option<SocketAddr>,

    /// Emit per-session cgroup CPU and memory measurements in structured logs.
    ///
    /// This is intended for one-session-at-a-time Linux container profiling.
    /// The metrics are unavailable outside cgroup v2 environments.
    #[arg(long, env = "NOTARY_SERVER_PROFILE_SESSIONS")]
    pub profile_sessions: bool,
}

#[derive(Clone)]
pub struct NotaryServerConfig {
    listen: SocketAddr,
    metrics_listen: Option<SocketAddr>,
    signing_key: Arc<SigningKey>,
    public_key: String,
    allowed_hosts: Arc<Vec<String>>,
    notarization_only: bool,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
    max_concurrent_captures: usize,
    max_concurrent_notarizations: usize,
    max_pending_connections: usize,
    prelude_timeout: Duration,
    session_timeout: Duration,
    profile_sessions: bool,
}

impl NotaryServerConfig {
    pub fn from_args(args: NotaryServerServeArgs) -> Result<Self> {
        validate_positive_limits(&args)?;
        let signing_key = Arc::new(read_signing_key(&args.signing_key_file)?);
        let public_key = hex::encode(signing_key.verifying_key().to_sec1_bytes());
        let allowed_hosts = Arc::new(validate_allowed_hosts(args.allow_hosts)?);
        Ok(Self {
            listen: args.listen,
            metrics_listen: args.metrics_listen,
            signing_key,
            public_key,
            allowed_hosts,
            notarization_only: args.notarization_only,
            max_private_chunk_bytes: args.max_private_chunk_bytes,
            max_total_private_chunk_bytes: args.max_total_private_chunk_bytes,
            max_private_chunk_commitments: args.max_private_chunk_commitments,
            max_frame_bytes: args.max_frame_bytes,
            max_concurrent_captures: args.max_concurrent_captures,
            max_concurrent_notarizations: args.max_concurrent_notarizations,
            max_pending_connections: args.max_pending_connections,
            prelude_timeout: Duration::from_secs(args.prelude_timeout_secs),
            session_timeout: Duration::from_secs(args.session_timeout_secs),
            profile_sessions: args.profile_sessions,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

fn validate_positive_limits(args: &NotaryServerServeArgs) -> Result<()> {
    if args.max_private_chunk_bytes == 0
        || args.max_total_private_chunk_bytes == 0
        || args.max_private_chunk_commitments == 0
        || args.max_concurrent_captures == 0
        || args.max_concurrent_notarizations == 0
        || args.max_pending_connections == 0
        || args.prelude_timeout_secs == 0
        || args.session_timeout_secs == 0
    {
        bail!("Notary server resource limits must be non-zero");
    }
    if args.max_total_private_chunk_bytes < args.max_private_chunk_bytes {
        bail!("total private-chunk bytes must be at least one private chunk");
    }
    if args.max_frame_bytes == 0 || args.max_frame_bytes > u32::MAX as usize {
        bail!(
            "Notary server frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    Ok(())
}

fn validate_allowed_hosts(hosts: Vec<String>) -> Result<Vec<String>> {
    let mut hosts = hosts
        .into_iter()
        .map(|host| host.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        bail!("at least one explicit --allow-host is required");
    }
    for host in &hosts {
        if host.is_empty()
            || host.len() > 253
            || host.parse::<std::net::IpAddr>().is_ok()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
        {
            bail!("allowed provider host is not a valid explicit hostname");
        }
    }
    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let key_text =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key_text = key_text
        .strip_suffix("\r\n")
        .or_else(|| key_text.strip_suffix('\n'))
        .unwrap_or(&key_text);
    let bytes = hex::decode(key_text).context("signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    SigningKey::from_slice(&bytes).context("invalid secp256k1 key")
}

pub fn print_public_key(args: &NotaryServerPublicKeyArgs) -> Result<()> {
    let key = read_signing_key(&args.signing_key_file)?;
    println!("{}", hex::encode(key.verifying_key().to_sec1_bytes()));
    Ok(())
}

/// The bounded, opaque value supplied in a versioned notary prelude.
///
/// Public protocol code deliberately assigns no account, credit, or ticket
/// semantics to this value. An injected admission policy may interpret it,
/// but it must not expose reusable credentials to the notary runtime.
#[derive(Clone, Copy)]
pub struct AdmissionRequest<'a> {
    pub mode: NotarySessionMode,
    pub admission_value: Option<&'a str>,
}

impl std::fmt::Debug for AdmissionRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionRequest")
            .field("mode", &self.mode)
            .field(
                "admission_value",
                &self.admission_value.map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Optional policy constraints for one admitted session.
///
/// Every numeric value is intersected with the process-local hard maximum;
/// an injected policy can tighten a limit but can never relax it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionConstraints {
    pub expected_record_digest: Option<[u8; 32]>,
    pub expected_transcript_bytes: Option<usize>,
    pub session_timeout: Option<Duration>,
    pub max_private_chunk_bytes: Option<usize>,
    pub max_total_private_chunk_bytes: Option<usize>,
    pub max_private_chunk_commitments: Option<usize>,
    pub max_frame_bytes: Option<usize>,
}

/// Terminal result reported after an admitted cryptographic session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

/// Optional durable lifecycle hook owned by an injected admission adapter.
///
/// Implementations should persist locally and return promptly. In particular,
/// reporting an admitted session must not depend on an external policy service remaining
/// reachable while the cryptographic protocol is running.
pub trait SessionLifecycle: Send + Sync {
    fn record_authenticated_bytes(&self, bytes: usize) -> Result<()>;
    fn finish(&self, outcome: SessionOutcome, fallback_bytes: usize) -> Result<()>;
}

/// The result of admission policy evaluation before acceptance is sent.
pub struct AdmissionGrant {
    pub constraints: AdmissionConstraints,
    pub lifecycle: Option<Arc<dyn SessionLifecycle>>,
}

impl AdmissionGrant {
    pub fn unrestricted() -> Self {
        Self {
            constraints: AdmissionConstraints::default(),
            lifecycle: None,
        }
    }
}

/// Small generic seam between the public protocol runtime and an optional
/// deployment-specific admission implementation.
#[async_trait]
pub trait AdmissionPolicy: Send + Sync {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection>;
}

/// Public ticketless policy. Ticketless v1/v2 sessions are accepted;
/// any unexpected opaque admission value fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct TicketlessAdmissionPolicy;

#[async_trait]
impl AdmissionPolicy for TicketlessAdmissionPolicy {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
        if request.admission_value.is_some() {
            return Err(NotaryAdmissionRejection::AdmissionDenied);
        }
        Ok(AdmissionGrant::unrestricted())
    }
}

#[derive(Clone, Copy)]
struct LocalSessionLimits {
    session_timeout: Duration,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
}

#[derive(Clone)]
struct SessionBudgets {
    captures: Arc<Semaphore>,
    notarizations: Arc<Semaphore>,
}

impl SessionBudgets {
    fn new(captures: usize, notarizations: usize) -> Self {
        Self {
            captures: Arc::new(Semaphore::new(captures)),
            notarizations: Arc::new(Semaphore::new(notarizations)),
        }
    }

    fn try_acquire(
        &self,
        mode: NotarySessionMode,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        match mode {
            NotarySessionMode::Capture => Arc::clone(&self.captures).try_acquire_owned(),
            NotarySessionMode::Notarization => Arc::clone(&self.notarizations).try_acquire_owned(),
        }
    }

    fn available_permits(&self, mode: NotarySessionMode) -> usize {
        match mode {
            NotarySessionMode::Capture => self.captures.available_permits(),
            NotarySessionMode::Notarization => self.notarizations.available_permits(),
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

/// Parses the public executable command and runs the ticketless server.
pub async fn run() -> Result<()> {
    match NotaryServerArgs::parse_env().command {
        NotaryServerCommand::PublicKey(args) => print_public_key(&args),
        NotaryServerCommand::Serve(args) => {
            let config = NotaryServerConfig::from_args(args)?;
            let _telemetry = notary_core::telemetry::init("notary-server")?;
            serve(
                config,
                Arc::new(TicketlessAdmissionPolicy),
                shutdown_signal(),
            )
            .await
        }
    }
}

/// Installs the process termination signal used by executable composition.
pub fn shutdown_signal() -> watch::Receiver<bool> {
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
            match terminate {
                Ok(mut terminate) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = terminate.recv() => {}
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = sender.send(true);
    });
    receiver
}

/// Binds the configured listeners and serves until shutdown.
pub async fn serve(
    config: NotaryServerConfig,
    admission: Arc<dyn AdmissionPolicy>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding Notary server listener {}", config.listen))?;
    serve_on_listener(config, listener, admission, shutdown).await
}

/// Serves on a caller-supplied listener for deterministic integration tests.
pub async fn serve_on_listener(
    config: NotaryServerConfig,
    listener: TcpListener,
    admission: Arc<dyn AdmissionPolicy>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let address = listener
        .local_addr()
        .context("reading Notary server address")?;
    let metrics_listener = match config.metrics_listen {
        Some(metrics_address) => Some(
            TcpListener::bind(metrics_address)
                .await
                .with_context(|| format!("binding Notary metrics listener {metrics_address}"))?,
        ),
        None => None,
    };
    let session_budgets = SessionBudgets::new(
        config.max_concurrent_captures,
        config.max_concurrent_notarizations,
    );
    let connection_permits = Arc::new(Semaphore::new(config.max_pending_connections));
    gauge!("notary_server_active_sessions", "mode" => "capture").set(0.0);
    gauge!("notary_server_active_sessions", "mode" => "notarization").set(0.0);
    gauge!("notary_server_pending_connections").set(0.0);

    let (internal_stop, internal_shutdown) = watch::channel(false);
    let metrics_task = metrics_listener.map(|metrics_listener| {
        let metrics_address = metrics_listener
            .local_addr()
            .expect("bound metrics listener has an address");
        let mut internal_shutdown = internal_shutdown.clone();
        tracing::info!(%metrics_address, "Notary server metrics listener active");
        tokio::spawn(async move {
            axum::serve(
                metrics_listener,
                Router::new().route("/metrics", get(metrics)),
            )
            .with_graceful_shutdown(async move {
                while !*internal_shutdown.borrow() {
                    if internal_shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .context("Notary server metrics listener stopped")
        })
    });
    tracing::info!(
        %address,
        public_key = %config.public_key,
        max_concurrent_captures = config.max_concurrent_captures,
        max_concurrent_notarizations = config.max_concurrent_notarizations,
        "Notary server listening"
    );
    println!("Notary server public key: {}", config.public_key);

    enum ServeEvent {
        Shutdown,
        ConnectionFinished(Option<std::result::Result<(), tokio::task::JoinError>>),
        Accepted(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
    }
    let mut connections = JoinSet::new();
    let mut result = Ok(());
    loop {
        if *shutdown.borrow() {
            break;
        }
        let event = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    ServeEvent::Shutdown
                } else {
                    continue;
                }
            }
            connection = connections.join_next(), if !connections.is_empty() => {
                ServeEvent::ConnectionFinished(connection)
            }
            accepted = listener.accept() => ServeEvent::Accepted(accepted),
        };
        let accepted = match event {
            ServeEvent::Shutdown => break,
            ServeEvent::ConnectionFinished(Some(Ok(()))) | ServeEvent::ConnectionFinished(None) => {
                continue;
            }
            ServeEvent::ConnectionFinished(Some(Err(error))) => {
                result = Err(anyhow::Error::new(error));
                break;
            }
            ServeEvent::Accepted(accepted) => accepted,
        };
        let (stream, _peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                result = Err(error).context("accepting Notary server connection");
                break;
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(%error, "configuring Notary client socket failed");
            continue;
        }
        let Ok(connection_permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            counter!("notary_server_sessions_total", "mode" => "unknown", "outcome" => "rejected_pending_limit").increment(1);
            tracing::warn!("Notary connection rejected at pending-connection limit");
            continue;
        };
        gauge!("notary_server_pending_connections")
            .set((config.max_pending_connections - connection_permits.available_permits()) as f64);
        tracing::info!("Notary client connected");
        connections.spawn(handle_connection(ConnectionTask {
            stream,
            connection_permit,
            key: Arc::clone(&config.signing_key),
            allowed_hosts: Arc::clone(&config.allowed_hosts),
            max_private_chunk_bytes: config.max_private_chunk_bytes,
            max_total_private_chunk_bytes: config.max_total_private_chunk_bytes,
            max_private_chunk_commitments: config.max_private_chunk_commitments,
            max_frame_bytes: config.max_frame_bytes,
            prelude_timeout: config.prelude_timeout,
            session_timeout: config.session_timeout,
            connection_permits: Arc::clone(&connection_permits),
            session_budgets: session_budgets.clone(),
            notarization_only: config.notarization_only,
            profile_sessions: config.profile_sessions,
            max_pending_connections: config.max_pending_connections,
            max_concurrent_captures: config.max_concurrent_captures,
            max_concurrent_notarizations: config.max_concurrent_notarizations,
            admission: Arc::clone(&admission),
        }));
    }

    let _ = internal_stop.send(true);
    while let Some(connection) = connections.join_next().await {
        if let Err(error) = connection {
            tracing::error!(%error, "Notary connection task failed");
            if result.is_ok() {
                result = Err(anyhow::Error::new(error));
            }
        }
    }
    if let Some(metrics_task) = metrics_task {
        match metrics_task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if result.is_ok() => result = Err(error),
            Ok(Err(error)) => tracing::error!(%error, "Notary metrics shutdown failed"),
            Err(error) if result.is_ok() => result = Err(anyhow::Error::new(error)),
            Err(error) => tracing::error!(%error, "Notary metrics task failed"),
        }
    }
    result
}

struct ConnectionTask {
    stream: tokio::net::TcpStream,
    connection_permit: OwnedSemaphorePermit,
    key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
    prelude_timeout: Duration,
    session_timeout: Duration,
    connection_permits: Arc<Semaphore>,
    session_budgets: SessionBudgets,
    notarization_only: bool,
    profile_sessions: bool,
    max_pending_connections: usize,
    max_concurrent_captures: usize,
    max_concurrent_notarizations: usize,
    admission: Arc<dyn AdmissionPolicy>,
}

async fn handle_connection(task: ConnectionTask) {
    let ConnectionTask {
        mut stream,
        connection_permit,
        key,
        allowed_hosts,
        max_private_chunk_bytes,
        max_total_private_chunk_bytes,
        max_private_chunk_commitments,
        max_frame_bytes,
        prelude_timeout,
        session_timeout,
        connection_permits,
        session_budgets,
        notarization_only,
        profile_sessions,
        max_pending_connections,
        max_concurrent_captures,
        max_concurrent_notarizations,
        admission,
    } = task;
    let prelude = match timeout(prelude_timeout, read_notary_session_prelude(&mut stream)).await {
        Ok(Ok(prelude)) => prelude,
        Ok(Err(error)) => {
            drop(connection_permit);
            gauge!("notary_server_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("notary_server_sessions_total", "mode" => "unknown", "outcome" => "invalid_prelude").increment(1);
            tracing::warn!(%error, "invalid Notary session prelude");
            return;
        }
        Err(_) => {
            drop(connection_permit);
            gauge!("notary_server_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("notary_server_sessions_total", "mode" => "unknown", "outcome" => "prelude_timed_out").increment(1);
            tracing::warn!("Notary session prelude timed out");
            return;
        }
    };
    drop(connection_permit);
    gauge!("notary_server_pending_connections")
        .set((max_pending_connections - connection_permits.available_permits()) as f64);
    let mode = prelude.mode();
    if !session_mode_allowed(notarization_only, mode) {
        counter!("notary_server_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_notarization_only").increment(1);
        tracing::warn!("Capture rejected by notarization-only Notary server");
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
        counter!("notary_server_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_concurrency_limit").increment(1);
        tracing::warn!(
            mode = session_mode_label(mode),
            "Notary session rejected at mode concurrency limit"
        );
        let rejection = match mode {
            NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
            NotarySessionMode::Notarization => NotaryAdmissionRejection::NotarizationAtCapacity,
        };
        if let Err(error) = write_notary_admission(&mut stream, &prelude, Err(rejection)).await {
            tracing::debug!(%error, "could not send notary admission rejection");
        }
        return;
    };
    let grant = match admission
        .admit(AdmissionRequest {
            mode,
            admission_value: prelude.admission_value(),
        })
        .await
    {
        Ok(grant) => grant,
        Err(rejection) => {
            counter!("notary_server_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_policy").increment(1);
            if let Err(error) = write_notary_admission(&mut stream, &prelude, Err(rejection)).await
            {
                tracing::debug!(%error, "could not send notary admission rejection");
            }
            return;
        }
    };
    let lifecycle = grant.lifecycle;
    let limits = match effective_session_limits(
        LocalSessionLimits {
            session_timeout,
            max_private_chunk_bytes,
            max_total_private_chunk_bytes,
            max_private_chunk_commitments,
            max_frame_bytes,
        },
        grant.constraints,
    ) {
        Ok(limits) => limits,
        Err(error) => {
            tracing::error!(%error, "admission policy returned invalid notary limits");
            if let Some(lifecycle) = &lifecycle
                && lifecycle.finish(SessionOutcome::ServiceFailed, 0).is_err()
            {
                tracing::error!("recording invalid admission outcome failed");
            }
            let _ = write_notary_admission(
                &mut stream,
                &prelude,
                Err(NotaryAdmissionRejection::AdmissionServiceUnavailable),
            )
            .await;
            return;
        }
    };
    let effective_session_timeout = limits.session_timeout;
    if let Err(error) = write_notary_admission(&mut stream, &prelude, Ok(())).await {
        tracing::debug!(%error, "could not send notary admission acceptance");
        if let Some(lifecycle) = &lifecycle
            && lifecycle.finish(SessionOutcome::ClientFailed, 0).is_err()
        {
            tracing::error!("recording disconnected admission outcome failed");
        }
        return;
    }
    let max_concurrent_sessions = match mode {
        NotarySessionMode::Capture => max_concurrent_captures,
        NotarySessionMode::Notarization => max_concurrent_notarizations,
    };
    gauge!("notary_server_active_sessions", "mode" => session_mode_label(mode))
        .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
    let started = Instant::now();
    let session_span = tracing::info_span!(
        "notary.session",
        otel.name = "notary.session",
        notary.session.mode = session_mode_label(mode),
    );
    let profile = profile_sessions.then(|| SessionProfile::start(mode));
    let usage_recorder: Option<AuthenticatedBytesRecorder> =
        lifecycle.as_ref().map(Arc::clone).map(|lifecycle| {
            Box::new(move |bytes| lifecycle.record_authenticated_bytes(bytes))
                as AuthenticatedBytesRecorder
        });
    let session = run_notary_session_with_limits_after_prelude(
        stream,
        mode,
        key,
        allowed_hosts,
        limits,
        usage_recorder,
    );
    let session = async {
        session.await.map_err(|error| {
            let outcome = match error.kind() {
                NotarySessionFailureKind::Client => SessionOutcome::ClientFailed,
                NotarySessionFailureKind::Service => SessionOutcome::ServiceFailed,
            };
            (outcome, anyhow::Error::new(error))
        })
    };
    let result = timeout(effective_session_timeout, session)
        .instrument(session_span)
        .await;
    let (outcome, settlement_outcome, authenticated_bytes) = match result {
        Ok(Ok(result)) => (
            "completed",
            SessionOutcome::Completed,
            result.authenticated_transcript_bytes,
        ),
        Ok(Err((settlement_outcome, error))) => {
            tracing::warn!(%error, "Notary session failed");
            ("failed", settlement_outcome, 0)
        }
        Err(_) => {
            tracing::warn!("Notary session timed out");
            ("timed_out", SessionOutcome::ClientFailed, 0)
        }
    };
    if let Some(lifecycle) = &lifecycle
        && lifecycle
            .finish(settlement_outcome, authenticated_bytes)
            .is_err()
    {
        tracing::error!("recording terminal session outcome failed");
    }
    if let Some(profile) = profile {
        profile.finish(outcome).await;
    }
    counter!("notary_server_sessions_total", "mode" => session_mode_label(mode), "outcome" => outcome).increment(1);
    histogram!("notary_server_session_duration_seconds", "mode" => session_mode_label(mode), "outcome" => outcome).record(started.elapsed().as_secs_f64());
    drop(session_permit);
    gauge!("notary_server_active_sessions", "mode" => session_mode_label(mode))
        .set((max_concurrent_sessions - session_budgets.available_permits(mode)) as f64);
}

async fn metrics() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        notary_core::telemetry::prometheus_metrics(),
    )
}

fn effective_session_limits(
    local: LocalSessionLimits,
    policy: AdmissionConstraints,
) -> Result<NotarySessionLimits> {
    let cap = |name: &str, requested: Option<usize>, hard: usize| -> Result<usize> {
        match requested {
            Some(0) => bail!("admission policy {name} must be positive"),
            Some(requested) => Ok(requested.min(hard)),
            None => Ok(hard),
        }
    };
    let session_timeout = match policy.session_timeout {
        Some(value) if value.is_zero() => {
            bail!("admission policy session_timeout must be positive")
        }
        Some(value) => value.min(local.session_timeout),
        None => local.session_timeout,
    };
    Ok(NotarySessionLimits {
        expected_record_digest: policy.expected_record_digest,
        expected_transcript_bytes: policy.expected_transcript_bytes,
        session_timeout,
        max_private_chunk_bytes: cap(
            "max_private_chunk_bytes",
            policy.max_private_chunk_bytes,
            local.max_private_chunk_bytes,
        )?,
        max_total_private_chunk_bytes: cap(
            "max_total_private_chunk_bytes",
            policy.max_total_private_chunk_bytes,
            local.max_total_private_chunk_bytes,
        )?,
        max_private_chunk_commitments: cap(
            "max_private_chunk_commitments",
            policy.max_private_chunk_commitments,
            local.max_private_chunk_commitments,
        )?,
        max_frame_bytes: cap(
            "max_frame_bytes",
            policy.max_frame_bytes,
            local.max_frame_bytes,
        )?,
    })
}

fn session_mode_label(mode: NotarySessionMode) -> &'static str {
    match mode {
        NotarySessionMode::Capture => "capture",
        NotarySessionMode::Notarization => "notarization",
    }
}

fn session_mode_allowed(notarization_only: bool, mode: NotarySessionMode) -> bool {
    !notarization_only || mode == NotarySessionMode::Notarization
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn test_server_args(signing_key_file: PathBuf) -> NotaryServerServeArgs {
        NotaryServerServeArgs {
            listen: "127.0.0.1:0".parse().unwrap(),
            signing_key_file,
            notarization_only: false,
            allow_hosts: vec!["api.openai.com".to_owned()],
            max_private_chunk_bytes: 1024,
            max_total_private_chunk_bytes: 2048,
            max_private_chunk_commitments: 2,
            max_frame_bytes: 4096,
            max_concurrent_captures: 2,
            max_concurrent_notarizations: 1,
            max_pending_connections: 2,
            prelude_timeout_secs: 1,
            session_timeout_secs: 2,
            metrics_listen: None,
            profile_sessions: false,
        }
    }

    fn test_server_config() -> (tempfile::TempDir, NotaryServerConfig) {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        fs::write(&signing_key_file, format!("{}\n", "01".repeat(32))).unwrap();
        let config = NotaryServerConfig::from_args(test_server_args(signing_key_file)).unwrap();
        (directory, config)
    }

    #[derive(Clone)]
    struct RecordingLifecycle {
        outcomes: Arc<Mutex<Vec<SessionOutcome>>>,
    }

    impl SessionLifecycle for RecordingLifecycle {
        fn record_authenticated_bytes(&self, _bytes: usize) -> Result<()> {
            Ok(())
        }

        fn finish(&self, outcome: SessionOutcome, _fallback_bytes: usize) -> Result<()> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }
    }

    struct TestAdmissionPolicy {
        reject: bool,
        constraints: AdmissionConstraints,
        lifecycle: RecordingLifecycle,
    }

    #[async_trait]
    impl AdmissionPolicy for TestAdmissionPolicy {
        async fn admit(
            &self,
            _request: AdmissionRequest<'_>,
        ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
            if self.reject {
                return Err(NotaryAdmissionRejection::AdmissionDenied);
            }
            Ok(AdmissionGrant {
                constraints: self.constraints.clone(),
                lifecycle: Some(Arc::new(self.lifecycle.clone())),
            })
        }
    }

    async fn test_connection(
        reject: bool,
        constraints: AdmissionConstraints,
        session_timeout: Duration,
    ) -> (
        tokio::net::TcpStream,
        tokio::task::JoinHandle<()>,
        Arc<Mutex<Vec<SessionOutcome>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let connection_permits = Arc::new(Semaphore::new(1));
        let connection_permit = Arc::clone(&connection_permits).try_acquire_owned().unwrap();
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let admission = Arc::new(TestAdmissionPolicy {
            reject,
            constraints,
            lifecycle: RecordingLifecycle {
                outcomes: Arc::clone(&outcomes),
            },
        });
        let task = tokio::spawn(handle_connection(ConnectionTask {
            stream,
            connection_permit,
            key: Arc::new(SigningKey::from_slice(&[1; 32]).unwrap()),
            allowed_hosts: Arc::new(Vec::new()),
            max_private_chunk_bytes: 1024,
            max_total_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 1,
            max_frame_bytes: 1024,
            prelude_timeout: Duration::from_secs(1),
            session_timeout,
            connection_permits,
            session_budgets: SessionBudgets::new(1, 1),
            notarization_only: false,
            profile_sessions: false,
            max_pending_connections: 1,
            max_concurrent_captures: 1,
            max_concurrent_notarizations: 1,
            admission,
        }));
        (client, task, outcomes)
    }

    async fn write_capture_prelude(client: &mut tokio::net::TcpStream) {
        write_capture_prelude_with_admission(client, Some("opaque-ticket")).await;
    }

    async fn write_capture_prelude_with_admission(
        client: &mut tokio::net::TcpStream,
        admission_value: Option<&str>,
    ) {
        let admission_value = admission_value.unwrap_or_default().as_bytes();
        client.write_all(b"NTRY\0\0\0\x01").await.unwrap();
        client.write_all(&[2]).await.unwrap();
        client
            .write_all(&(admission_value.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(admission_value).await.unwrap();
        client.flush().await.unwrap();
    }

    async fn wait_for_connection(task: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("connection handler timed out")
            .expect("connection handler panicked");
    }

    #[test]
    fn canonical_cli_requires_an_explicit_subcommand_and_allowlist() {
        let parsed = NotaryServerArgs::try_parse_from([
            "notary-server",
            "serve",
            "--signing-key-file",
            "signing-key",
            "--allow-host",
            "api.openai.com",
            "--allow-host",
            "api.anthropic.com",
        ])
        .unwrap();
        let NotaryServerCommand::Serve(args) = parsed.command else {
            panic!("expected serve command");
        };
        assert_eq!(args.allow_hosts, ["api.openai.com", "api.anthropic.com"]);

        let parsed = NotaryServerArgs::try_parse_from([
            "notary-server",
            "public-key",
            "--signing-key-file",
            "signing-key",
        ])
        .unwrap();
        assert!(matches!(parsed.command, NotaryServerCommand::PublicKey(_)));

        assert!(NotaryServerArgs::try_parse_from(["notary-server"]).is_err());
        assert!(
            NotaryServerArgs::try_parse_from([
                "notary-server",
                "--signing-key-file",
                "signing-key"
            ])
            .is_err()
        );
        assert!(
            NotaryServerArgs::try_parse_from([
                "notary-server",
                "serve",
                "--signing-key",
                "signing-key"
            ])
            .is_err()
        );
    }

    #[test]
    fn validated_config_rejects_implicit_or_invalid_provider_access() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        fs::write(&signing_key_file, "01".repeat(32)).unwrap();

        let mut args = test_server_args(signing_key_file.clone());
        args.allow_hosts.clear();
        assert!(NotaryServerConfig::from_args(args).is_err());

        for invalid_host in ["*", "127.0.0.1", "https://api.openai.com", "-bad.test"] {
            let mut args = test_server_args(signing_key_file.clone());
            args.allow_hosts = vec![invalid_host.to_owned()];
            assert!(
                NotaryServerConfig::from_args(args).is_err(),
                "accepted invalid provider host {invalid_host}"
            );
        }

        let mut args = test_server_args(signing_key_file);
        args.allow_hosts = vec![
            "API.OPENAI.COM".to_owned(),
            "api.anthropic.com".to_owned(),
            "api.openai.com".to_owned(),
        ];
        let config = NotaryServerConfig::from_args(args).unwrap();
        assert_eq!(
            config.allowed_hosts.as_slice(),
            ["api.anthropic.com", "api.openai.com"]
        );
    }

    #[test]
    fn validated_config_rejects_zero_or_inconsistent_limits() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        fs::write(&signing_key_file, "01".repeat(32)).unwrap();

        let mut args = test_server_args(signing_key_file.clone());
        args.max_pending_connections = 0;
        assert!(NotaryServerConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file.clone());
        args.max_total_private_chunk_bytes = args.max_private_chunk_bytes - 1;
        assert!(NotaryServerConfig::from_args(args).is_err());

        let mut args = test_server_args(signing_key_file);
        args.max_frame_bytes = u32::MAX as usize + 1;
        assert!(NotaryServerConfig::from_args(args).is_err());
    }

    #[test]
    fn signing_key_file_allows_one_line_ending_but_no_other_whitespace() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing-key");
        fs::write(&path, format!("{}\r\n", "01".repeat(32))).unwrap();
        assert!(read_signing_key(&path).is_ok());
        fs::write(&path, format!(" {}\n", "01".repeat(32))).unwrap();
        assert!(read_signing_key(&path).is_err());
        fs::write(&path, format!("{}\n\n", "01".repeat(32))).unwrap();
        assert!(read_signing_key(&path).is_err());
    }

    #[tokio::test]
    async fn injected_shutdown_stops_accepting_and_waits_for_connection_tasks() {
        let (_directory, mut config) = test_server_config();
        config.prelude_timeout = Duration::from_millis(150);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let mut server = tokio::spawn(serve_on_listener(
            config,
            listener,
            Arc::new(TicketlessAdmissionPolicy),
            shutdown,
        ));
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(b"NTRY").await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        shutdown_sender.send(true).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut server)
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server ignored injected shutdown")
            .expect("server task panicked")
            .expect("server failed during shutdown");
    }

    #[test]
    fn notarization_only_rejects_capture_before_protocol_admission() {
        assert!(!session_mode_allowed(true, NotarySessionMode::Capture));
        assert!(session_mode_allowed(true, NotarySessionMode::Notarization));
        assert!(session_mode_allowed(false, NotarySessionMode::Capture));
    }

    #[test]
    fn capture_and_notarize_budgets_are_independent() {
        let budgets = SessionBudgets::new(1, 1);
        let capture = budgets.try_acquire(NotarySessionMode::Capture).unwrap();
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_err());

        let notarize = budgets
            .try_acquire(NotarySessionMode::Notarization)
            .unwrap();
        assert!(
            budgets
                .try_acquire(NotarySessionMode::Notarization)
                .is_err()
        );

        drop(capture);
        assert!(budgets.try_acquire(NotarySessionMode::Capture).is_ok());
        drop(notarize);
        assert!(budgets.try_acquire(NotarySessionMode::Notarization).is_ok());
    }

    #[tokio::test]
    async fn ticketless_policy_accepts_only_ticketless_sessions() {
        let policy = TicketlessAdmissionPolicy;
        assert!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: None,
                })
                .await
                .is_ok()
        );
        assert!(matches!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: Some("unexpected-opaque-value"),
                })
                .await,
            Err(NotaryAdmissionRejection::AdmissionDenied)
        ));
    }

    #[tokio::test]
    async fn ticketless_policy_runs_through_the_shared_session_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let connection_permits = Arc::new(Semaphore::new(1));
        let connection_permit = Arc::clone(&connection_permits).try_acquire_owned().unwrap();
        let task = tokio::spawn(handle_connection(ConnectionTask {
            stream,
            connection_permit,
            key: Arc::new(SigningKey::from_slice(&[1; 32]).unwrap()),
            allowed_hosts: Arc::new(vec!["api.openai.com".to_owned()]),
            max_private_chunk_bytes: 1024,
            max_total_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 1,
            max_frame_bytes: 1024,
            prelude_timeout: Duration::from_secs(1),
            session_timeout: Duration::from_secs(1),
            connection_permits,
            session_budgets: SessionBudgets::new(1, 1),
            notarization_only: false,
            profile_sessions: false,
            max_pending_connections: 1,
            max_concurrent_captures: 1,
            max_concurrent_notarizations: 1,
            admission: Arc::new(TicketlessAdmissionPolicy),
        }));
        let mut client = client;
        write_capture_prelude_with_admission(&mut client, None).await;
        let mut response = [0; 1];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        drop(client);
        wait_for_connection(task).await;
    }

    #[test]
    fn admission_request_debug_redacts_the_opaque_value() {
        let request = AdmissionRequest {
            mode: NotarySessionMode::Capture,
            admission_value: Some("one-time-secret-ticket"),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("one-time-secret-ticket"));
    }

    #[tokio::test]
    async fn connection_policy_rejection_is_sent_without_a_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            true,
            AdmissionConstraints::default(),
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 6];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 2);
        wait_for_connection(task).await;
        assert!(outcomes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn accepted_connection_disconnect_finishes_the_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints::default(),
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 1];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        drop(client);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ClientFailed]);
    }

    #[tokio::test]
    async fn accepted_connection_timeout_finishes_the_lifecycle() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints::default(),
            Duration::from_millis(20),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 1];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ClientFailed]);
    }

    #[tokio::test]
    async fn invalid_policy_limits_finish_before_rejection() {
        let (mut client, task, outcomes) = test_connection(
            false,
            AdmissionConstraints {
                max_frame_bytes: Some(0),
                ..AdmissionConstraints::default()
            },
            Duration::from_secs(1),
        )
        .await;
        write_capture_prelude(&mut client).await;
        let mut response = [0; 6];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 2);
        wait_for_connection(task).await;
        assert_eq!(*outcomes.lock().unwrap(), [SessionOutcome::ServiceFailed]);
    }

    #[test]
    fn injected_policy_can_only_reduce_local_limits() {
        let limits = effective_session_limits(
            LocalSessionLimits {
                session_timeout: Duration::from_secs(30),
                max_private_chunk_bytes: 128 << 10,
                max_total_private_chunk_bytes: 4 << 20,
                max_private_chunk_commitments: 64,
                max_frame_bytes: 32 << 20,
            },
            AdmissionConstraints {
                expected_record_digest: Some([0xab; 32]),
                expected_transcript_bytes: Some(1024),
                session_timeout: Some(Duration::from_secs(60)),
                max_private_chunk_bytes: Some(256 << 10),
                max_total_private_chunk_bytes: Some(8 << 20),
                max_private_chunk_commitments: Some(128),
                max_frame_bytes: Some(64 << 20),
            },
        )
        .unwrap();
        assert_eq!(limits.session_timeout, Duration::from_secs(30));
        assert_eq!(limits.max_private_chunk_bytes, 128 << 10);
        assert_eq!(limits.max_total_private_chunk_bytes, 4 << 20);
        assert_eq!(limits.max_private_chunk_commitments, 64);
        assert_eq!(limits.max_frame_bytes, 32 << 20);
        assert_eq!(limits.expected_record_digest, Some([0xab; 32]));
        assert_eq!(limits.expected_transcript_bytes, Some(1024));
    }

    #[test]
    fn injected_policy_zero_limit_fails_closed() {
        assert!(
            effective_session_limits(
                LocalSessionLimits {
                    session_timeout: Duration::from_secs(30),
                    max_private_chunk_bytes: 1024,
                    max_total_private_chunk_bytes: 1024,
                    max_private_chunk_commitments: 1,
                    max_frame_bytes: 1024,
                },
                AdmissionConstraints {
                    max_frame_bytes: Some(0),
                    ..AdmissionConstraints::default()
                },
            )
            .is_err()
        );
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
