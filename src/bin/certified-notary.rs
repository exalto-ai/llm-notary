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
use certified::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES, NotaryAdmissionRejection,
    NotarySessionMode, read_notary_session_prelude, run_notary_session_after_prelude,
    write_notary_admission,
};
use clap::Parser;
use k256::ecdsa::SigningKey;
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, watch},
    time::{MissedTickBehavior, timeout},
};

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
}

struct SessionProfile {
    mode: NotarySessionMode,
    started: Instant,
    cgroup: Option<CgroupV2>,
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
        let cgroup = CgroupV2::for_current_process();
        let sampled_memory_peak_bytes = Arc::new(AtomicU64::new(
            cgroup
                .as_ref()
                .and_then(CgroupV2::memory_current_bytes)
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
                            .and_then(CgroupV2::memory_current_bytes)
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
            cpu_start: cgroup.as_ref().and_then(CgroupV2::cpu_stat),
            memory_current_start_bytes: cgroup.as_ref().and_then(CgroupV2::memory_current_bytes),
            memory_peak_start_bytes: cgroup.as_ref().and_then(CgroupV2::memory_peak_bytes),
            memory_events_start: cgroup.as_ref().and_then(CgroupV2::memory_events),
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
        let cpu_end = self.cgroup.as_ref().and_then(CgroupV2::cpu_stat);
        let memory_current_end_bytes = self
            .cgroup
            .as_ref()
            .and_then(CgroupV2::memory_current_bytes);
        let memory_peak_end_bytes = self.cgroup.as_ref().and_then(CgroupV2::memory_peak_bytes);
        let memory_events_end = self.cgroup.as_ref().and_then(CgroupV2::memory_events);
        tracing::info!(
            mode = session_mode_name(self.mode),
            outcome,
            elapsed_ms = self.started.elapsed().as_millis(),
            cgroup_path = ?self.cgroup.as_ref().map(|cgroup| cgroup.path.display().to_string()),
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
            cgroup_memory_max_bytes = ?self.cgroup.as_ref().and_then(CgroupV2::memory_max_bytes),
            cgroup_memory_events_oom = ?CgroupMemoryEvents::oom_delta(self.memory_events_start, memory_events_end),
            cgroup_memory_events_oom_kill = ?CgroupMemoryEvents::oom_kill_delta(self.memory_events_start, memory_events_end),
            "notary session resource profile"
        );
    }
}

fn session_mode_name(mode: NotarySessionMode) -> &'static str {
    match mode {
        NotarySessionMode::Capture => "capture",
        NotarySessionMode::Finalize => "finalize",
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupCpuStat {
    usage_usec: u64,
    user_usec: u64,
    system_usec: u64,
    throttled_usec: u64,
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
            start.map(|stat| stat.user_usec),
            end.map(|stat| stat.user_usec),
        )
    }

    fn system_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|stat| stat.system_usec),
            end.map(|stat| stat.system_usec),
        )
    }

    fn throttled_delta_usec(start: Option<Self>, end: Option<Self>) -> Option<u64> {
        delta(
            start.map(|stat| stat.throttled_usec),
            end.map(|stat| stat.throttled_usec),
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
            "user_usec" => parsed.user_usec = value,
            "system_usec" => parsed.system_usec = value,
            "throttled_usec" => parsed.throttled_usec = value,
            _ => {}
        }
    }
    (parsed.usage_usec != 0).then_some(parsed)
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
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
    tracing::info!(
        address = %args.listen,
        public_key,
        max_concurrent_captures = args.max_concurrent_captures,
        max_concurrent_finalizations = args.max_concurrent_finalizations,
        "LLM Notary service listening"
    );
    println!("LLM Notary public key: {public_key}");

    loop {
        let (mut stream, address) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let Ok(connection_permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            tracing::warn!(%address, "notary connection rejected at pending-connection limit");
            continue;
        };
        tracing::info!(%address, "notary client connected");
        let key = Arc::clone(&key);
        let allowed_hosts = Arc::clone(&allowed_hosts);
        let max_private_chunk_bytes = args.max_private_chunk_bytes;
        let max_total_private_chunk_bytes = args.max_total_private_chunk_bytes;
        let max_private_chunk_commitments = args.max_private_chunk_commitments;
        let max_frame_bytes = args.max_frame_bytes;
        let prelude_timeout = std::time::Duration::from_secs(args.prelude_timeout_secs);
        let session_timeout = std::time::Duration::from_secs(args.session_timeout_secs);
        let session_budgets = session_budgets.clone();
        let finalize_only = args.finalize_only;
        let profile_sessions = args.profile_sessions;
        tokio::spawn(async move {
            let prelude =
                match timeout(prelude_timeout, read_notary_session_prelude(&mut stream)).await {
                    Ok(Ok(prelude)) => prelude,
                    Ok(Err(error)) => {
                        tracing::warn!(%address, %error, "invalid notary session prelude");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(%address, "notary session prelude timed out");
                        return;
                    }
                };
            drop(connection_permit);
            let mode = prelude.mode();
            if !session_mode_allowed(finalize_only, mode) {
                tracing::warn!(%address, "capture rejected by finalize-only notary");
                if let Err(error) = write_notary_admission(
                    &mut stream,
                    prelude,
                    Err(NotaryAdmissionRejection::CaptureDisabled),
                )
                .await
                {
                    tracing::debug!(%address, %error, "could not send notary admission rejection");
                }
                return;
            }
            let Ok(session_permit) = session_budgets.try_acquire(mode) else {
                tracing::warn!(
                    %address,
                    mode = session_mode_name(mode),
                    "notary session rejected at mode concurrency limit"
                );
                let rejection = match mode {
                    NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
                    NotarySessionMode::Finalize => NotaryAdmissionRejection::FinalizeAtCapacity,
                };
                if let Err(error) =
                    write_notary_admission(&mut stream, prelude, Err(rejection)).await
                {
                    tracing::debug!(%address, %error, "could not send notary admission rejection");
                }
                return;
            };
            if let Err(error) = write_notary_admission(&mut stream, prelude, Ok(())).await {
                tracing::debug!(%address, %error, "could not send notary admission acceptance");
                return;
            }
            let profile = profile_sessions.then(|| SessionProfile::start(mode));
            let result = timeout(
                session_timeout,
                run_notary_session_after_prelude(
                    stream,
                    mode,
                    key,
                    allowed_hosts,
                    max_private_chunk_bytes,
                    max_total_private_chunk_bytes,
                    max_private_chunk_commitments,
                    max_frame_bytes,
                ),
            )
            .await;
            let outcome = match result {
                Ok(Ok(())) => "completed",
                Ok(Err(error)) => {
                    tracing::warn!(%address, %error, "notary session failed");
                    "failed"
                }
                Err(_) => {
                    tracing::warn!(%address, "notary session timed out");
                    "timed_out"
                }
            };
            if let Some(profile) = profile {
                profile.finish(outcome).await;
            }
            drop(session_permit);
        });
    }
}

fn session_mode_allowed(finalize_only: bool, mode: NotarySessionMode) -> bool {
    !finalize_only || mode == NotarySessionMode::Finalize
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parses_cgroup_cpu_stat() {
        let stat = "usage_usec 42\nuser_usec 21\nsystem_usec 21\nthrottled_usec 3\n";
        assert_eq!(
            parse_cgroup_cpu_stat(stat),
            Some(CgroupCpuStat {
                usage_usec: 42,
                user_usec: 21,
                system_usec: 21,
                throttled_usec: 3,
            })
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
