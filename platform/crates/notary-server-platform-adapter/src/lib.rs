use std::{
    collections::HashMap,
    env,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use metrics::{counter, gauge};
use notary_core::{NotaryAdmissionRejection, NotarySessionMode};
use notary_server::{
    AdmissionConstraints, AdmissionGrant, AdmissionPolicy, AdmissionRequest, NotaryServerArgs,
    NotaryServerCommand, NotaryServerConfig, SessionLifecycle, SessionOutcome, print_public_key,
    read_private_file, serve, shutdown_signal,
};
use serde::{Deserialize, Serialize};
use url::Url;

mod settlement_outbox;

use settlement_outbox::{
    PendingUsageSettlement, UsageMode, UsageSettlementOutbox, UsageSettlementOutcome,
};

const USAGE_OUTBOX_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const USAGE_OUTBOX_BATCH_SIZE: usize = 16;
const USAGE_OUTBOX_MAX_BACKOFF: Duration = Duration::from_secs(60);
const USAGE_OUTBOX_SHUTDOWN_FLUSH: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
struct SettlementRetry {
    failures: u32,
    not_before: Instant,
}

#[derive(Clone)]
struct PlatformAdmissionPolicy {
    http: reqwest::Client,
    origin: Url,
    service_token: Arc<str>,
    instance_id: Arc<str>,
    registry_generation: u64,
    usage_outbox: UsageSettlementOutbox,
}

#[derive(Serialize)]
struct RedeemRequest<'a> {
    ticket: &'a str,
    notary_instance_id: &'a str,
    mode: &'static str,
    registry_generation: u64,
    contract: &'static str,
    usage_settlement: bool,
}

#[derive(Deserialize)]
struct RedeemedOperation {
    operation_id: String,
    activation_deadline: i64,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    record_digest: Option<String>,
    notarization_allowance_bytes: Option<i64>,
}

#[derive(Serialize)]
struct ActivateOperationRequest<'a> {
    operation_id: &'a str,
    notary_instance_id: &'a str,
    mode: &'static str,
}

#[derive(Serialize)]
struct UsageSettlementRequest<'a> {
    operation_id: &'a str,
    notary_instance_id: &'a str,
    mode: UsageMode,
    authenticated_bytes: i64,
    outcome: UsageSettlementOutcome,
}

#[derive(Deserialize)]
struct PlatformErrorResponse {
    error: String,
}

enum PlatformPolicyRejection {
    Capacity,
    Denied,
    Expired,
    CaptureAllowanceExhausted,
    NotarizationAllowanceExhausted,
    Unavailable(anyhow::Error),
}

impl PlatformAdmissionPolicy {
    fn from_env() -> Result<Self> {
        let origin = env::var("NOTARY_SERVER_PLATFORM_API_ORIGIN")
            .context("NOTARY_SERVER_PLATFORM_API_ORIGIN must be set")?;
        let origin = validate_platform_origin(&origin)?;
        let token_file = env::var("NOTARY_SERVER_PLATFORM_SERVICE_TOKEN_FILE")
            .context("NOTARY_SERVER_PLATFORM_SERVICE_TOKEN_FILE must be set")?;
        let service_token = read_service_token(&token_file)?;
        let instance_id = env::var("NOTARY_SERVER_INSTANCE_ID")
            .context("NOTARY_SERVER_INSTANCE_ID must be set")?;
        if instance_id.is_empty()
            || instance_id.len() > 128
            || !instance_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("NOTARY_SERVER_INSTANCE_ID must be a safe identifier of at most 128 bytes");
        }
        let registry_generation = env::var("NOTARY_SERVER_REGISTRY_GENERATION")
            .context("NOTARY_SERVER_REGISTRY_GENERATION must be set")?
            .parse()
            .context("NOTARY_SERVER_REGISTRY_GENERATION must be a u64")?;
        let usage_outbox = UsageSettlementOutbox::open(
            env::var("NOTARY_SERVER_USAGE_OUTBOX_DIR")
                .context("NOTARY_SERVER_USAGE_OUTBOX_DIR must be set")?,
        )?;
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent("notary-server/0.1")
                .timeout(Duration::from_secs(5))
                .build()
                .context("building platform API client")?,
            origin,
            service_token,
            instance_id: Arc::from(instance_id),
            registry_generation,
            usage_outbox,
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.origin
            .join(path)
            .with_context(|| format!("building platform API URL for {path}"))
    }

    async fn redeem(
        &self,
        ticket: &str,
        mode: NotarySessionMode,
    ) -> std::result::Result<RedeemedOperation, PlatformPolicyRejection> {
        let url = self
            .endpoint("/api/internal/notary/admissions/redeem")
            .map_err(PlatformPolicyRejection::Unavailable)?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.service_token.as_ref())
            .json(&RedeemRequest {
                ticket,
                notary_instance_id: self.instance_id.as_ref(),
                mode: session_mode_label(mode),
                registry_generation: self.registry_generation,
                contract: "one_operation_v2",
                usage_settlement: true,
            })
            .send()
            .await
            .map_err(|error| PlatformPolicyRejection::Unavailable(error.into()))?;
        match response.status() {
            reqwest::StatusCode::OK => response
                .json()
                .await
                .map_err(|error| PlatformPolicyRejection::Unavailable(error.into())),
            status => {
                let error_code = response
                    .json::<PlatformErrorResponse>()
                    .await
                    .ok()
                    .map(|error| error.error);
                Err(platform_rejection(status, error_code.as_deref()))
            }
        }
    }

    async fn activate(&self, operation_id: &str, mode: NotarySessionMode) -> Result<()> {
        let url = self.endpoint("/api/internal/notary/operations/activate")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.service_token.as_ref())
            .json(&ActivateOperationRequest {
                operation_id,
                notary_instance_id: self.instance_id.as_ref(),
                mode: session_mode_label(mode),
            })
            .send()
            .await
            .context("activating admitted operation")?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            bail!("operation activation API returned {}", response.status());
        }
        Ok(())
    }
}

impl PlatformAdmissionPolicy {
    async fn settle_usage(&self, pending: &PendingUsageSettlement) -> Result<()> {
        let outcome = pending
            .outcome
            .context("usage settlement is not terminal")?;
        let url = self.endpoint("/api/internal/notary/operations/settle")?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.service_token.as_ref())
            .json(&UsageSettlementRequest {
                operation_id: &pending.operation_id,
                notary_instance_id: &pending.notary_instance_id,
                mode: pending.mode,
                authenticated_bytes: pending.authenticated_bytes,
                outcome,
            })
            .send()
            .await
            .context("sending usage settlement")?;
        if !matches!(
            response.status(),
            reqwest::StatusCode::NO_CONTENT | reqwest::StatusCode::GONE
        ) {
            bail!("usage settlement API returned {}", response.status());
        }
        Ok(())
    }

    #[cfg(test)]
    async fn replay_usage_outbox(&self) {
        self.replay_usage_outbox_batch(&mut HashMap::new(), USAGE_OUTBOX_BATCH_SIZE, None)
            .await;
    }

    async fn replay_usage_outbox_batch(
        &self,
        retries: &mut HashMap<String, SettlementRetry>,
        batch_size: usize,
        deadline: Option<Instant>,
    ) {
        match self.usage_outbox.retry_terminal_writes() {
            Ok(0) => {}
            Ok(remaining) => tracing::warn!(
                remaining,
                "terminal usage outbox writes remain queued for retry"
            ),
            Err(error) => tracing::error!(%error, "retrying terminal usage outbox writes failed"),
        }
        let pending = match self.usage_outbox.ready() {
            Ok(pending) => pending,
            Err(error) => {
                tracing::error!(%error, "reading usage settlement outbox failed");
                return;
            }
        };
        gauge!("notary_server_usage_settlement_outbox_pending").set(pending.len() as f64);
        let now = Instant::now();
        let due = pending
            .into_iter()
            .filter(|entry| {
                retries
                    .get(&entry.operation_id)
                    .is_none_or(|retry| retry.not_before <= now)
            })
            .take(batch_size)
            .collect::<Vec<_>>();
        for entry in due {
            let delivery = match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, self.settle_usage(&entry)).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow::anyhow!("usage settlement flush deadline elapsed")),
                    }
                }
                None => self.settle_usage(&entry).await,
            };
            match delivery {
                Ok(()) => {
                    if self.usage_outbox.remove(&entry.operation_id).is_err() {
                        tracing::error!("removing settled usage outbox entry failed");
                    } else {
                        retries.remove(&entry.operation_id);
                        counter!("notary_server_usage_settlement_deliveries_total", "outcome" => "delivered")
                            .increment(1);
                    }
                }
                Err(error) => {
                    let failures = retries
                        .get(&entry.operation_id)
                        .map_or(1, |retry| retry.failures.saturating_add(1));
                    retries.insert(
                        entry.operation_id.clone(),
                        SettlementRetry {
                            failures,
                            not_before: Instant::now()
                                + settlement_retry_delay(&entry.operation_id, failures),
                        },
                    );
                    counter!("notary_server_usage_settlement_deliveries_total", "outcome" => "retry")
                        .increment(1);
                    tracing::warn!(%error, "usage settlement delivery will be retried");
                }
            }
        }
    }

    async fn run_usage_settlement_worker(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut ticker = tokio::time::interval(USAGE_OUTBOX_RETRY_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut retries = HashMap::new();
        loop {
            if *shutdown.borrow() {
                retries.clear();
                self.replay_usage_outbox_batch(
                    &mut retries,
                    usize::MAX,
                    Some(Instant::now() + USAGE_OUTBOX_SHUTDOWN_FLUSH),
                )
                .await;
                return Ok(());
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        retries.clear();
                        self.replay_usage_outbox_batch(
                            &mut retries,
                            usize::MAX,
                            Some(Instant::now() + USAGE_OUTBOX_SHUTDOWN_FLUSH),
                        ).await;
                        return Ok(());
                    }
                }
                _ = ticker.tick() => {
                    self.replay_usage_outbox_batch(
                        &mut retries,
                        USAGE_OUTBOX_BATCH_SIZE,
                        None,
                    ).await
                },
            }
        }
    }
}

fn settlement_retry_delay(operation_id: &str, failures: u32) -> Duration {
    let exponential = 1_u64 << failures.saturating_sub(1).min(5);
    let base = USAGE_OUTBOX_RETRY_INTERVAL
        .saturating_mul(u32::try_from(exponential).unwrap_or(u32::MAX))
        .min(USAGE_OUTBOX_MAX_BACKOFF);
    let jitter_millis = operation_id.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(byte.into())
    }) % 500;
    base.saturating_add(Duration::from_millis(jitter_millis))
        .min(USAGE_OUTBOX_MAX_BACKOFF)
}

fn platform_rejection(
    status: reqwest::StatusCode,
    error_code: Option<&str>,
) -> PlatformPolicyRejection {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => PlatformPolicyRejection::Capacity,
        reqwest::StatusCode::GONE if error_code == Some("admission_ticket_expired") => {
            PlatformPolicyRejection::Expired
        }
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("capture_credits_exhausted") =>
        {
            PlatformPolicyRejection::CaptureAllowanceExhausted
        }
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("notarization_credits_exhausted") =>
        {
            PlatformPolicyRejection::NotarizationAllowanceExhausted
        }
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            PlatformPolicyRejection::Unavailable(anyhow::anyhow!(
                "platform API rejected service authentication"
            ))
        }
        status if status.is_client_error() => PlatformPolicyRejection::Denied,
        status => {
            PlatformPolicyRejection::Unavailable(anyhow::anyhow!("platform API returned {status}"))
        }
    }
}

struct PlatformSessionLifecycle {
    operation_id: String,
    usage_outbox: UsageSettlementOutbox,
}

impl SessionLifecycle for PlatformSessionLifecycle {
    fn record_authenticated_bytes(&self, bytes: usize) -> Result<()> {
        self.usage_outbox
            .record_authenticated_bytes(&self.operation_id, bytes)
    }

    fn finish(&self, outcome: SessionOutcome, fallback_bytes: usize) -> Result<()> {
        let outcome = match outcome {
            SessionOutcome::Completed => UsageSettlementOutcome::Completed,
            SessionOutcome::ClientFailed => UsageSettlementOutcome::ClientFailed,
            SessionOutcome::ServiceFailed => UsageSettlementOutcome::ServiceFailed,
        };
        self.usage_outbox
            .finish(&self.operation_id, outcome, fallback_bytes)
    }
}

#[async_trait]
impl AdmissionPolicy for PlatformAdmissionPolicy {
    async fn admit(
        &self,
        request: AdmissionRequest<'_>,
    ) -> std::result::Result<AdmissionGrant, NotaryAdmissionRejection> {
        let Some(ticket) = request.admission_value else {
            return Err(NotaryAdmissionRejection::AdmissionDenied);
        };
        let operation = self
            .redeem(ticket, request.mode)
            .await
            .map_err(|rejection| platform_admission_rejection(request.mode, rejection))?;
        let pending = PendingUsageSettlement {
            operation_id: operation.operation_id.clone(),
            notary_instance_id: self.instance_id.to_string(),
            mode: UsageMode::for_session(request.mode),
            authenticated_bytes: 0,
            outcome: None,
        };
        if self.usage_outbox.stage(&pending).is_err() {
            tracing::error!("staging admitted operation usage failed");
            let mut failed = pending;
            failed.outcome = Some(UsageSettlementOutcome::ServiceFailed);
            if let Err(error) = self.settle_usage(&failed).await {
                tracing::error!(%error, "direct settlement after outbox failure failed");
            }
            return Err(NotaryAdmissionRejection::AdmissionServiceUnavailable);
        }
        let constraints = match operation_constraints(request.mode, &operation) {
            Ok(constraints) => constraints,
            Err(error) => {
                tracing::error!(%error, "platform API returned invalid Notary limits");
                if self
                    .usage_outbox
                    .finish(
                        &operation.operation_id,
                        UsageSettlementOutcome::ServiceFailed,
                        0,
                    )
                    .is_err()
                {
                    tracing::error!("recording invalid admitted operation for settlement failed");
                }
                return Err(NotaryAdmissionRejection::AdmissionServiceUnavailable);
            }
        };
        if let Err(error) = self.activate(&operation.operation_id, request.mode).await {
            tracing::error!(%error, "activating admitted operation failed");
            if self
                .usage_outbox
                .finish(
                    &operation.operation_id,
                    UsageSettlementOutcome::ServiceFailed,
                    0,
                )
                .is_err()
            {
                tracing::error!("recording unactivated operation for settlement failed");
            }
            return Err(NotaryAdmissionRejection::AdmissionServiceUnavailable);
        }
        Ok(AdmissionGrant {
            constraints,
            lifecycle: Some(Arc::new(PlatformSessionLifecycle {
                operation_id: operation.operation_id,
                usage_outbox: self.usage_outbox.clone(),
            })),
        })
    }
}

fn platform_admission_rejection(
    mode: NotarySessionMode,
    rejection: PlatformPolicyRejection,
) -> NotaryAdmissionRejection {
    match rejection {
        PlatformPolicyRejection::Capacity => match mode {
            NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
            NotarySessionMode::Notarization => NotaryAdmissionRejection::NotarizationAtCapacity,
        },
        PlatformPolicyRejection::Denied => NotaryAdmissionRejection::AdmissionDenied,
        PlatformPolicyRejection::Expired => NotaryAdmissionRejection::AdmissionExpired,
        PlatformPolicyRejection::CaptureAllowanceExhausted => {
            NotaryAdmissionRejection::CaptureAllowanceExhausted
        }
        PlatformPolicyRejection::NotarizationAllowanceExhausted => {
            NotaryAdmissionRejection::NotarizationAllowanceExhausted
        }
        PlatformPolicyRejection::Unavailable(error) => {
            tracing::error!(%error, "platform API admission request failed");
            NotaryAdmissionRejection::AdmissionServiceUnavailable
        }
    }
}

/// Runs Exalto's platform policy around the shared Notary server runtime.
pub async fn run() -> Result<()> {
    run_command(NotaryServerArgs::parse_env().command).await
}

async fn run_command(command: NotaryServerCommand) -> Result<()> {
    match command {
        NotaryServerCommand::PublicKey(args) => print_public_key(&args),
        NotaryServerCommand::Serve(args) => {
            let config = NotaryServerConfig::from_args(args)?;
            let policy = Arc::new(PlatformAdmissionPolicy::from_env()?);
            policy.usage_outbox.recover_after_restart()?;
            let _telemetry = notary_core::telemetry::init("notary-server")?;
            serve_with_platform_policy(config, policy, shutdown_signal()).await
        }
    }
}

async fn serve_with_platform_policy(
    config: NotaryServerConfig,
    policy: Arc<PlatformAdmissionPolicy>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    // Stop settlement only after the shared server has drained its tracked
    // sessions. A session that finishes during graceful shutdown can therefore
    // stage its terminal usage before the worker's final replay.
    let (worker_stop, worker_shutdown) = tokio::sync::watch::channel(false);
    let server_policy = Arc::clone(&policy);
    let server = async move {
        let result = serve(config, server_policy as Arc<dyn AdmissionPolicy>, shutdown).await;
        let _ = worker_stop.send(true);
        result
    };
    let (server_result, worker_result) =
        tokio::join!(server, policy.run_usage_settlement_worker(worker_shutdown));
    server_result?;
    worker_result
}

fn validate_platform_origin(value: &str) -> Result<Url> {
    let origin =
        Url::parse(value).context("NOTARY_SERVER_PLATFORM_API_ORIGIN must be an absolute URL")?;
    if origin.cannot_be_a_base()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
    {
        bail!(
            "NOTARY_SERVER_PLATFORM_API_ORIGIN must be an origin without credentials, path, query, or fragment"
        );
    }
    if origin.scheme() != "https"
        && !(origin.scheme() == "http"
            && origin.host_str().is_some_and(|host| {
                host == "localhost"
                    || host == "127.0.0.1"
                    || host == "::1"
                    || host == "notary-api.internal"
                    || host.ends_with(".flycast")
            }))
    {
        bail!("platform API origin must use HTTPS, loopback HTTP, or explicitly private HTTP");
    }
    Ok(origin)
}

fn read_service_token(path: &str) -> Result<Arc<str>> {
    let token_bytes = read_private_file(Path::new(path), "platform service token")?;
    let token =
        std::str::from_utf8(&token_bytes).context("platform service token must be UTF-8")?;
    let token = token
        .strip_suffix("\r\n")
        .or_else(|| token.strip_suffix('\n'))
        .unwrap_or(token);
    if !(32..=512).contains(&token.len()) || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("platform service token must contain 32 to 512 non-whitespace bytes");
    }
    Ok(Arc::from(token))
}

fn operation_constraints(
    mode: NotarySessionMode,
    operation: &RedeemedOperation,
) -> Result<AdmissionConstraints> {
    if operation.activation_deadline <= 0 {
        bail!("platform activation deadline must be positive");
    }
    let positive = |name: &str, value: i64| -> Result<usize> {
        if value <= 0 {
            bail!("platform {name} must be positive");
        }
        value
            .try_into()
            .with_context(|| format!("platform {name} does not fit in usize"))
    };
    let max_private_chunk_bytes =
        positive("max_private_chunk_bytes", operation.max_private_chunk_bytes)?;
    let policy_attestable = positive(
        "max_attestable_http_bytes",
        operation.max_attestable_http_bytes,
    )?;
    let (expected_record_digest, authenticated_allowance) = match (
        mode,
        operation.record_digest.as_deref(),
        operation.notarization_allowance_bytes,
    ) {
        (NotarySessionMode::Capture, None, None) => (None, policy_attestable),
        (NotarySessionMode::Notarization, Some(digest), Some(allowance)) => {
            let bytes = hex::decode(digest).context("platform record digest is not hex")?;
            let allowance = positive("notarization_allowance_bytes", allowance)?;
            (
                Some(
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("platform record digest is not 32 bytes"))?,
                ),
                allowance,
            )
        }
        _ => bail!("platform record digest does not match the session mode"),
    };
    if authenticated_allowance > policy_attestable {
        bail!("platform allowance exceeds its per-session ceiling");
    }
    Ok(AdmissionConstraints {
        expected_record_digest,
        expected_transcript_bytes: (mode == NotarySessionMode::Notarization)
            .then_some(authenticated_allowance),
        session_timeout: None,
        max_private_chunk_bytes: Some(max_private_chunk_bytes),
        max_total_private_chunk_bytes: Some(authenticated_allowance.min(policy_attestable)),
        max_private_chunk_commitments: Some(positive(
            "max_private_chunk_commitments",
            operation.max_private_chunk_commitments,
        )?),
        max_frame_bytes: Some(positive("max_frame_bytes", operation.max_frame_bytes)?),
    })
}

fn session_mode_label(mode: NotarySessionMode) -> &'static str {
    match mode {
        NotarySessionMode::Capture => "capture",
        NotarySessionMode::Notarization => "notarization",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use std::fs;

    fn write_private_test_file(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn platform_origin_is_an_origin_and_never_carries_credentials() {
        for valid in [
            "https://platform.example.com",
            "http://localhost:8080",
            "http://notary-api.internal:8080",
            "http://notary-api.internal.flycast",
        ] {
            assert!(
                validate_platform_origin(valid).is_ok(),
                "rejected valid platform origin {valid}"
            );
        }
        for invalid in [
            "http://platform.example.com",
            "https://user:secret@platform.example.com",
            "https://platform.example.com/api",
            "https://platform.example.com?query=1",
            "https://platform.example.com#fragment",
        ] {
            assert!(
                validate_platform_origin(invalid).is_err(),
                "accepted invalid platform origin {invalid}"
            );
        }
    }

    #[test]
    fn platform_service_token_allows_one_line_ending_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service-token");
        write_private_test_file(&path, format!("{}\r\n", "x".repeat(32)));
        assert_eq!(
            read_service_token(path.to_str().unwrap()).unwrap().as_ref(),
            "x".repeat(32)
        );
        write_private_test_file(&path, format!(" {}\n", "x".repeat(32)));
        assert!(read_service_token(path.to_str().unwrap()).is_err());
        write_private_test_file(&path, format!("{}\n\n", "x".repeat(32)));
        assert!(read_service_token(path.to_str().unwrap()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn platform_service_token_rejects_insecure_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("service-token");
        write_private_test_file(&path, "x".repeat(32));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o604)).unwrap();
        assert!(read_service_token(path.to_str().unwrap()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("service-token-link");
        symlink(&path, &link).unwrap();
        assert!(read_service_token(link.to_str().unwrap()).is_err());
    }

    #[test]
    fn usage_mode_uses_the_canonical_notarization_wire_value() {
        assert_eq!(
            serde_json::to_value(UsageMode::Notarization).unwrap(),
            "notarization"
        );
    }

    #[tokio::test]
    async fn public_key_command_is_isolated_from_platform_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        write_private_test_file(&signing_key_file, format!("{}\n", "01".repeat(32)));
        run_command(NotaryServerCommand::PublicKey(
            notary_server::NotaryServerPublicKeyArgs { signing_key_file },
        ))
        .await
        .unwrap();
    }

    #[test]
    fn redemption_requires_two_phase_operation_activation() {
        let request = serde_json::to_value(RedeemRequest {
            ticket: "opaque-ticket",
            notary_instance_id: "notary-test",
            mode: "capture",
            registry_generation: 1,
            contract: "one_operation_v2",
            usage_settlement: true,
        })
        .unwrap();
        assert_eq!(request["contract"], "one_operation_v2");
        assert_eq!(request["usage_settlement"], true);

        let operation: RedeemedOperation = serde_json::from_value(serde_json::json!({
            "operation_id": "operation-test",
            "activation_deadline": 1234,
            "max_attestable_http_bytes": 1024,
            "max_frame_bytes": 2048,
            "max_private_chunk_bytes": 512,
            "max_private_chunk_commitments": 4,
            "record_digest": null,
            "notarization_allowance_bytes": null,
            "future_additive_field": "accepted"
        }))
        .unwrap();
        assert_eq!(operation.operation_id, "operation-test");
    }

    #[test]
    fn platform_policy_returns_only_tighter_candidate_limits() {
        let operation = RedeemedOperation {
            operation_id: "operation-notarization".to_owned(),
            activation_deadline: 1234,
            max_attestable_http_bytes: 8 << 20,
            max_frame_bytes: 64 << 20,
            max_private_chunk_bytes: 256 << 10,
            max_private_chunk_commitments: 256,
            record_digest: Some("ab".repeat(32)),
            notarization_allowance_bytes: Some(8 << 20),
        };
        let limits = operation_constraints(NotarySessionMode::Notarization, &operation)
            .expect("valid limits");
        assert_eq!(limits.max_private_chunk_bytes, Some(256 << 10));
        assert_eq!(limits.max_total_private_chunk_bytes, Some(8 << 20));
        assert_eq!(limits.max_private_chunk_commitments, Some(256));
        assert_eq!(limits.max_frame_bytes, Some(64 << 20));
        assert_eq!(limits.expected_record_digest, Some([0xab; 32]));
        assert_eq!(limits.expected_transcript_bytes, Some(8 << 20));
        assert_eq!(limits.session_timeout, None);
    }

    #[test]
    fn capture_policy_rejects_a_notarization_digest() {
        let operation = RedeemedOperation {
            operation_id: "operation-capture".to_owned(),
            activation_deadline: 1234,
            max_attestable_http_bytes: 1024,
            max_frame_bytes: 1024,
            max_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 1,
            record_digest: Some("ab".repeat(32)),
            notarization_allowance_bytes: Some(1024),
        };
        assert!(operation_constraints(NotarySessionMode::Capture, &operation).is_err());
    }

    #[tokio::test]
    async fn platform_outage_fails_closed() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(250))
                .build()
                .unwrap(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageSettlementOutbox::open(outbox_directory.path()).unwrap(),
        };

        assert!(matches!(
            policy
                .redeem("opaque-ticket", NotarySessionMode::Capture)
                .await,
            Err(PlatformPolicyRejection::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn admitted_operation_needs_no_platform_liveness() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/api/internal/notary/admissions/redeem",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "operation_id": "operation-capture",
                        "activation_deadline": 1234,
                        "max_attestable_http_bytes": 1024,
                        "max_frame_bytes": 2048,
                        "max_private_chunk_bytes": 512,
                        "max_private_chunk_commitments": 4,
                        "record_digest": null,
                        "notarization_allowance_bytes": null
                    }))
                }),
            )
            .route(
                "/api/internal/notary/operations/activate",
                axum::routing::post(|| async { axum::http::StatusCode::NO_CONTENT }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageSettlementOutbox::open(outbox_directory.path()).unwrap(),
        };
        let grant = policy
            .admit(AdmissionRequest {
                mode: NotarySessionMode::Capture,
                admission_value: Some("opaque-ticket"),
            })
            .await
            .expect("one-operation admission should be accepted");
        server.abort();
        let lifecycle = grant.lifecycle.expect("platform lifecycle");
        lifecycle.record_authenticated_bytes(321).unwrap();
        lifecycle.finish(SessionOutcome::Completed, 321).unwrap();
        assert_eq!(grant.constraints.max_total_private_chunk_bytes, Some(1024));
        assert_eq!(grant.constraints.session_timeout, None);
        assert_eq!(policy.usage_outbox.ready().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn platform_policy_runs_through_the_shared_server_contract() {
        let directory = tempfile::tempdir().unwrap();
        let signing_key_file = directory.path().join("signing-key");
        write_private_test_file(&signing_key_file, format!("{}\n", "01".repeat(32)));

        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_address = api_listener.local_addr().unwrap();
        let api = Router::new()
            .route(
                "/api/internal/notary/admissions/redeem",
                axum::routing::post(
                    |axum::Json(request): axum::Json<serde_json::Value>| async move {
                        let notarization = request.get("mode").and_then(|mode| mode.as_str())
                            == Some("notarization");
                        axum::Json(serde_json::json!({
                            "operation_id": if notarization {
                                "operation-shared-notarization"
                            } else {
                                "operation-shared-capture"
                            },
                            "activation_deadline": 1234,
                            "max_attestable_http_bytes": 1024,
                            "max_frame_bytes": 2048,
                            "max_private_chunk_bytes": 512,
                            "max_private_chunk_commitments": 4,
                            "record_digest": notarization.then(|| "11".repeat(32)),
                            "notarization_allowance_bytes": notarization.then_some(1024)
                        }))
                    },
                ),
            )
            .route(
                "/api/internal/notary/operations/activate",
                axum::routing::post(|| async { axum::http::StatusCode::NO_CONTENT }),
            );
        let api_server = tokio::spawn(async move { axum::serve(api_listener, api).await.unwrap() });
        let policy = Arc::new(PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{api_address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageSettlementOutbox::open(directory.path().join("outbox")).unwrap(),
        });
        let server_config = NotaryServerConfig::from_args(notary_server::NotaryServerServeArgs {
            listen: "127.0.0.1:0".parse().unwrap(),
            signing_key_file,
            notarization_only: false,
            allow_hosts: vec!["api.openai.com".to_owned()],
            max_private_chunk_bytes: 1024,
            max_total_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 4,
            max_frame_bytes: 2048,
            max_concurrent_captures: 1,
            max_concurrent_notarizations: 1,
            max_pending_connections: 1,
            prelude_timeout_secs: 1,
            session_timeout_secs: 1,
            shutdown_grace_secs: 1,
            metrics_listen: None,
            profile_sessions: false,
        })
        .unwrap();
        let server_policy: Arc<dyn AdmissionPolicy> = policy.clone();
        for (mode, ticket) in [
            (NotarySessionMode::Capture, "opaque-capture-ticket"),
            (
                NotarySessionMode::Notarization,
                "opaque-notarization-ticket",
            ),
        ] {
            notary_server::test_support::exercise_admission_policy_contract(
                server_config.clone(),
                Arc::clone(&server_policy),
                mode,
                Some(ticket),
            )
            .await
            .unwrap();
        }

        let settled = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let ready = policy.usage_outbox.ready().unwrap();
                if ready.len() == 2 {
                    break ready;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("shared server did not finish the platform lifecycle");
        assert_eq!(settled[0].operation_id, "operation-shared-capture");
        assert_eq!(settled[1].operation_id, "operation-shared-notarization");
        assert!(
            settled
                .iter()
                .all(|entry| { entry.outcome == Some(UsageSettlementOutcome::ClientFailed) })
        );
        api_server.abort();
        let _ = api_server.await;
    }

    #[tokio::test]
    async fn invalid_redeemed_limits_are_staged_for_service_failed_settlement() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/internal/notary/admissions/redeem",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "operation_id": "operation-invalid-limits",
                    "activation_deadline": 1234,
                    "max_attestable_http_bytes": 0,
                    "max_frame_bytes": 2048,
                    "max_private_chunk_bytes": 512,
                    "max_private_chunk_commitments": 4,
                    "record_digest": null,
                    "notarization_allowance_bytes": null
                }))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageSettlementOutbox::open(outbox_directory.path()).unwrap(),
        };

        assert!(matches!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: Some("opaque-ticket"),
                })
                .await,
            Err(NotaryAdmissionRejection::AdmissionServiceUnavailable)
        ));
        let pending = policy.usage_outbox.ready().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].operation_id, "operation-invalid-limits");
        assert_eq!(
            pending[0].outcome,
            Some(UsageSettlementOutcome::ServiceFailed)
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn activation_failure_leaves_a_durable_service_failed_settlement() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/api/internal/notary/admissions/redeem",
                axum::routing::post(|| async {
                    axum::Json(serde_json::json!({
                        "operation_id": "operation-activation-outage",
                        "activation_deadline": 1234,
                        "max_attestable_http_bytes": 1024,
                        "max_frame_bytes": 2048,
                        "max_private_chunk_bytes": 512,
                        "max_private_chunk_commitments": 4,
                        "record_digest": null,
                        "notarization_allowance_bytes": null
                    }))
                }),
            )
            .route(
                "/api/internal/notary/operations/activate",
                axum::routing::post(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageSettlementOutbox::open(outbox_directory.path()).unwrap(),
        };

        assert!(matches!(
            policy
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: Some("opaque-ticket"),
                })
                .await,
            Err(NotaryAdmissionRejection::AdmissionServiceUnavailable)
        ));
        assert_eq!(
            policy.usage_outbox.ready().unwrap(),
            vec![PendingUsageSettlement {
                operation_id: "operation-activation-outage".to_owned(),
                notary_instance_id: "notary-test".to_owned(),
                mode: UsageMode::Capture,
                authenticated_bytes: 0,
                outcome: Some(UsageSettlementOutcome::ServiceFailed),
            }]
        );
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn usage_outbox_recovers_measured_bytes_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-restart".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Capture,
            authenticated_bytes: 0,
            outcome: None,
        };
        let outbox = UsageSettlementOutbox::open(directory.path()).unwrap();
        outbox.stage(&pending).unwrap();
        outbox
            .record_authenticated_bytes(&pending.operation_id, 321)
            .unwrap();
        drop(outbox);

        let restarted = UsageSettlementOutbox::open(directory.path()).unwrap();
        restarted.recover_after_restart().unwrap();
        assert_eq!(
            restarted.ready().unwrap(),
            vec![PendingUsageSettlement {
                authenticated_bytes: 321,
                outcome: Some(UsageSettlementOutcome::ServiceFailed),
                ..pending
            }]
        );
    }

    #[test]
    fn usage_outbox_rejects_conflicting_local_reports() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = UsageSettlementOutbox::open(directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-conflict".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Notarization,
            authenticated_bytes: 0,
            outcome: None,
        };
        outbox.stage(&pending).unwrap();
        outbox
            .record_authenticated_bytes(&pending.operation_id, 42)
            .unwrap();
        outbox
            .record_authenticated_bytes(&pending.operation_id, 42)
            .unwrap();
        assert!(
            outbox
                .record_authenticated_bytes(&pending.operation_id, 41)
                .is_err()
        );
        outbox
            .finish(&pending.operation_id, UsageSettlementOutcome::Completed, 42)
            .unwrap();
        outbox
            .finish(&pending.operation_id, UsageSettlementOutcome::Completed, 42)
            .unwrap();
        assert!(
            outbox
                .finish(
                    &pending.operation_id,
                    UsageSettlementOutcome::ClientFailed,
                    42,
                )
                .is_err()
        );
    }

    #[test]
    fn usage_outbox_retries_a_transient_terminal_write() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = UsageSettlementOutbox::open(directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-terminal-retry".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Capture,
            authenticated_bytes: 0,
            outcome: None,
        };
        outbox.stage(&pending).unwrap();

        let displaced = directory.path().with_extension("displaced");
        fs::rename(directory.path(), &displaced).unwrap();
        fs::write(directory.path(), b"temporarily unavailable").unwrap();
        assert!(
            outbox
                .finish(
                    &pending.operation_id,
                    UsageSettlementOutcome::ServiceFailed,
                    31,
                )
                .is_err()
        );
        fs::remove_file(directory.path()).unwrap();
        fs::rename(&displaced, directory.path()).unwrap();

        assert_eq!(outbox.retry_terminal_writes().unwrap(), 0);
        assert_eq!(
            outbox.ready().unwrap(),
            vec![PendingUsageSettlement {
                authenticated_bytes: 31,
                outcome: Some(UsageSettlementOutcome::ServiceFailed),
                ..pending
            }]
        );
    }

    #[test]
    fn settlement_retry_backoff_is_bounded_and_stable() {
        assert_eq!(
            settlement_retry_delay("operation-stable", 1),
            settlement_retry_delay("operation-stable", 1)
        );
        assert!(settlement_retry_delay("operation-stable", 1) >= USAGE_OUTBOX_RETRY_INTERVAL);
        assert_eq!(
            settlement_retry_delay("operation-stable", u32::MAX),
            USAGE_OUTBOX_MAX_BACKOFF
        );
    }

    #[tokio::test]
    async fn successful_usage_replay_removes_only_delivered_entries() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = UsageSettlementOutbox::open(directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-delivery".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Capture,
            authenticated_bytes: 0,
            outcome: None,
        };
        outbox.stage(&pending).unwrap();
        outbox
            .finish(
                &pending.operation_id,
                UsageSettlementOutcome::ClientFailed,
                17,
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/internal/notary/operations/settle",
            axum::routing::post(|| async { reqwest::StatusCode::NO_CONTENT }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: outbox,
        };

        policy.replay_usage_outbox().await;
        assert!(policy.usage_outbox.ready().unwrap().is_empty());
        server.abort();
        let _ = server.await;

        let retry = PendingUsageSettlement {
            operation_id: "operation-retry".to_owned(),
            ..pending
        };
        policy.usage_outbox.stage(&retry).unwrap();
        policy
            .usage_outbox
            .finish(
                &retry.operation_id,
                UsageSettlementOutcome::ClientFailed,
                19,
            )
            .unwrap();
        policy.replay_usage_outbox().await;
        assert_eq!(policy.usage_outbox.ready().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn settlement_worker_flushes_ready_usage_during_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let usage_outbox = UsageSettlementOutbox::open(directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-shutdown".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Notarization,
            authenticated_bytes: 0,
            outcome: None,
        };
        usage_outbox.stage(&pending).unwrap();
        usage_outbox
            .finish(&pending.operation_id, UsageSettlementOutcome::Completed, 29)
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/internal/notary/operations/settle",
            axum::routing::post(|| async { reqwest::StatusCode::NO_CONTENT }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox,
        };
        let (shutdown_sender, shutdown) = tokio::sync::watch::channel(false);
        let worker_policy = policy.clone();
        let worker =
            tokio::spawn(async move { worker_policy.run_usage_settlement_worker(shutdown).await });
        shutdown_sender.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("settlement worker ignored shutdown")
            .expect("settlement worker panicked")
            .expect("settlement worker failed");
        assert!(policy.usage_outbox.ready().unwrap().is_empty());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn gone_operation_acknowledgement_removes_usage_entry() {
        let usage_directory = tempfile::tempdir().unwrap();
        let usage_outbox = UsageSettlementOutbox::open(usage_directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-deleted-account".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Capture,
            authenticated_bytes: 0,
            outcome: None,
        };
        usage_outbox.stage(&pending).unwrap();
        usage_outbox
            .finish(
                &pending.operation_id,
                UsageSettlementOutcome::ServiceFailed,
                23,
            )
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/internal/notary/operations/settle",
            axum::routing::post(|| async { reqwest::StatusCode::GONE }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let policy = PlatformAdmissionPolicy {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox,
        };

        policy.replay_usage_outbox().await;
        assert!(policy.usage_outbox.ready().unwrap().is_empty());
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn platform_authentication_failure_is_not_a_user_denial() {
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::UNAUTHORIZED, None),
            PlatformPolicyRejection::Unavailable(_)
        ));
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::FORBIDDEN, None),
            PlatformPolicyRejection::Unavailable(_)
        ));
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::CONFLICT, None),
            PlatformPolicyRejection::Denied
        ));
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::GONE, Some("admission_ticket_expired"),),
            PlatformPolicyRejection::Expired
        ));
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::GONE, None),
            PlatformPolicyRejection::Denied
        ));
        assert!(matches!(
            platform_rejection(reqwest::StatusCode::TOO_MANY_REQUESTS, None),
            PlatformPolicyRejection::Capacity
        ));
        assert!(matches!(
            platform_rejection(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                Some("service_capacity"),
            ),
            PlatformPolicyRejection::Capacity
        ));
        assert!(matches!(
            platform_rejection(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                Some("capture_credits_exhausted"),
            ),
            PlatformPolicyRejection::CaptureAllowanceExhausted
        ));
        assert!(matches!(
            platform_rejection(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                Some("notarization_credits_exhausted"),
            ),
            PlatformPolicyRejection::NotarizationAllowanceExhausted
        ));
    }
}
