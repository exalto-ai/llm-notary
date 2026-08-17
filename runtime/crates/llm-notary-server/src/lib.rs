use std::{
    env, fs,
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
use clap::Parser;
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
    time::{MissedTickBehavior, timeout},
};
use tracing::Instrument as _;

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

    /// Reject new capture sessions while continuing to notarize bundles that
    /// were captured before a planned key handoff.
    #[arg(long)]
    notarize_only: bool,

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
    /// This is independent from --max-concurrent-notarizations so deferred
    /// proofs cannot consume all capacity needed for live provider traffic.
    #[arg(long, default_value_t = 8)]
    max_concurrent_captures: usize,

    /// Maximum number of simultaneous deferred private-proof notarizations.
    ///
    /// This is independent from --max-concurrent-captures. Notarization is
    /// the CPU- and memory-intensive phase, while capture prioritizes live
    /// request latency.
    #[arg(long, default_value_t = 1)]
    max_concurrent_notarizations: usize,

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
/// reporting an admitted session must not depend on a coordinator remaining
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

/// Coordinator-free public policy. Ticketless v1/v2 sessions are accepted;
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

/// Runs the remote Proxy-TLS notary service.
pub async fn run() -> Result<()> {
    run_with_policy_factory(|| Ok(Arc::new(TicketlessAdmissionPolicy))).await
}

/// Runs the remote Proxy-TLS notary service with an injected admission policy.
pub async fn run_with_policy(admission: Arc<dyn AdmissionPolicy>) -> Result<()> {
    run_with_policy_factory(|| Ok(admission)).await
}

/// Runs the remote Proxy-TLS notary service with a lazily initialized admission policy.
pub async fn run_with_policy_factory<F>(admission: F) -> Result<()>
where
    F: FnOnce() -> Result<Arc<dyn AdmissionPolicy>>,
{
    let _telemetry = notary_core::telemetry::init("llm-notary-server")?;
    let args = Args::parse();
    if args.max_private_chunk_bytes == 0
        || args.max_total_private_chunk_bytes == 0
        || args.max_private_chunk_commitments == 0
        || args.max_concurrent_captures == 0
        || args.max_concurrent_notarizations == 0
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
    let admission = admission()?;
    let allowed_hosts = Arc::new(
        args.allow_host
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    );
    let listener = TcpListener::bind(args.listen).await?;
    let session_budgets = SessionBudgets::new(
        args.max_concurrent_captures,
        args.max_concurrent_notarizations,
    );
    let connection_permits = Arc::new(Semaphore::new(args.max_pending_connections));
    gauge!("llm_notary_notary_active_sessions", "mode" => "capture").set(0.0);
    gauge!("llm_notary_notary_active_sessions", "mode" => "notarization").set(0.0);
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
        max_concurrent_notarizations = args.max_concurrent_notarizations,
        "LLM Notary service listening"
    );
    println!("LLM Notary public key: {public_key}");

    loop {
        let (stream, _address) = listener.accept().await?;
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
        let notarize_only = args.notarize_only;
        let profile_sessions = args.profile_sessions;
        let max_pending_connections = args.max_pending_connections;
        let max_concurrent_captures = args.max_concurrent_captures;
        let max_concurrent_notarizations = args.max_concurrent_notarizations;
        let admission = admission.clone();
        tokio::spawn(handle_connection(ConnectionTask {
            stream,
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
            notarize_only,
            profile_sessions,
            max_pending_connections,
            max_concurrent_captures,
            max_concurrent_notarizations,
            admission,
        }));
    }
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
    notarize_only: bool,
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
        notarize_only,
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
            gauge!("llm_notary_notary_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("llm_notary_notary_sessions_total", "mode" => "unknown", "outcome" => "invalid_prelude").increment(1);
            tracing::warn!(%error, "invalid notary session prelude");
            return;
        }
        Err(_) => {
            drop(connection_permit);
            gauge!("llm_notary_notary_pending_connections")
                .set((max_pending_connections - connection_permits.available_permits()) as f64);
            counter!("llm_notary_notary_sessions_total", "mode" => "unknown", "outcome" => "prelude_timed_out").increment(1);
            tracing::warn!("notary session prelude timed out");
            return;
        }
    };
    drop(connection_permit);
    gauge!("llm_notary_notary_pending_connections")
        .set((max_pending_connections - connection_permits.available_permits()) as f64);
    let mode = prelude.mode();
    if !session_mode_allowed(notarize_only, mode) {
        counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_notarize_only").increment(1);
        tracing::warn!("capture rejected by notarize-only notary");
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
            counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => "rejected_policy").increment(1);
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
    gauge!("llm_notary_notary_active_sessions", "mode" => session_mode_label(mode))
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
            tracing::warn!(%error, "notary session failed");
            ("failed", settlement_outcome, 0)
        }
        Err(_) => {
            tracing::warn!("notary session timed out");
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
    counter!("llm_notary_notary_sessions_total", "mode" => session_mode_label(mode), "outcome" => outcome).increment(1);
    histogram!("llm_notary_notary_session_duration_seconds", "mode" => session_mode_label(mode), "outcome" => outcome).record(started.elapsed().as_secs_f64());
    drop(session_permit);
    gauge!("llm_notary_notary_active_sessions", "mode" => session_mode_label(mode))
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

fn session_mode_allowed(notarize_only: bool, mode: NotarySessionMode) -> bool {
    !notarize_only || mode == NotarySessionMode::Notarization
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
            notarize_only: false,
            profile_sessions: false,
            max_pending_connections: 1,
            max_concurrent_captures: 1,
            max_concurrent_notarizations: 1,
            admission,
        }));
        (client, task, outcomes)
    }

    async fn write_capture_prelude(client: &mut tokio::net::TcpStream) {
        let ticket = b"opaque-ticket";
        client.write_all(b"LLMN\0\0\0\x03").await.unwrap();
        client.write_all(&[2]).await.unwrap();
        client
            .write_all(&(ticket.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(ticket).await.unwrap();
        client.flush().await.unwrap();
    }

    async fn wait_for_connection(task: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("connection handler timed out")
            .expect("connection handler panicked");
    }

    #[test]
    fn notarize_only_rejects_capture_before_protocol_admission() {
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
    async fn coordinator_free_policy_accepts_only_ticketless_sessions() {
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
