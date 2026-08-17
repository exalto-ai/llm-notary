use std::{env, fs, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use llm_notary_server::{
    AdmissionConstraints, AdmissionGrant, AdmissionPolicy, AdmissionRequest, SessionLifecycle,
    SessionOutcome,
};
use metrics::{counter, gauge};
use notary_core::{NotaryAdmissionRejection, NotarySessionMode};
use serde::{Deserialize, Serialize};
use url::Url;

mod outbox;

use outbox::{PendingUsageSettlement, UsageMode, UsageOutbox, UsageSettlementOutcome};

const USAGE_OUTBOX_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct AdmissionCoordinator {
    http: reqwest::Client,
    origin: Url,
    service_token: Arc<str>,
    instance_id: Arc<str>,
    registry_generation: u64,
    usage_outbox: UsageOutbox,
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
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    record_digest: Option<String>,
    notarization_allowance_bytes: Option<i64>,
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
struct CoordinatorErrorResponse {
    error: String,
}

enum CoordinatorRejection {
    Capacity,
    Denied,
    Expired,
    CaptureAllowanceExhausted,
    NotarizationAllowanceExhausted,
    Unavailable(anyhow::Error),
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
        let registry_generation = env::var("LLM_NOTARY_REGISTRY_GENERATION")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .context("LLM_NOTARY_REGISTRY_GENERATION must be a u64")?;
        let usage_outbox = UsageOutbox::open(
            env::var("LLM_NOTARY_USAGE_OUTBOX_DIR")
                .context("LLM_NOTARY_USAGE_OUTBOX_DIR must be set")?,
        )?;
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent("LLM-Notary-Service/0.1")
                .timeout(Duration::from_secs(5))
                .build()
                .context("building admission coordinator client")?,
            origin,
            service_token: Arc::from(service_token),
            instance_id: Arc::from(instance_id),
            registry_generation,
            usage_outbox,
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
    ) -> std::result::Result<RedeemedOperation, CoordinatorRejection> {
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
                registry_generation: self.registry_generation,
                contract: "one_operation_v1",
                usage_settlement: true,
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
}

impl AdmissionCoordinator {
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
            bail!("usage coordinator returned {}", response.status());
        }
        Ok(())
    }

    async fn replay_usage_outbox(&self) {
        let pending = match self.usage_outbox.ready() {
            Ok(pending) => pending,
            Err(_) => {
                tracing::error!("reading usage settlement outbox failed");
                return;
            }
        };
        gauge!("llm_notary_usage_outbox_pending").set(pending.len() as f64);
        for entry in pending {
            match self.settle_usage(&entry).await {
                Ok(()) => {
                    if self.usage_outbox.remove(&entry.operation_id).is_err() {
                        tracing::error!("removing settled usage outbox entry failed");
                    } else {
                        counter!("llm_notary_usage_outbox_deliveries_total", "outcome" => "delivered")
                            .increment(1);
                    }
                }
                Err(error) => {
                    counter!("llm_notary_usage_outbox_deliveries_total", "outcome" => "retry")
                        .increment(1);
                    tracing::warn!(%error, "usage settlement delivery will be retried");
                }
            }
        }
    }
}

fn coordinator_rejection(
    status: reqwest::StatusCode,
    error_code: Option<&str>,
) -> CoordinatorRejection {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => CoordinatorRejection::Capacity,
        reqwest::StatusCode::GONE if error_code == Some("admission_ticket_expired") => {
            CoordinatorRejection::Expired
        }
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("capture_credits_exhausted") =>
        {
            CoordinatorRejection::CaptureAllowanceExhausted
        }
        reqwest::StatusCode::PAYMENT_REQUIRED
            if error_code == Some("notarization_credits_exhausted") =>
        {
            CoordinatorRejection::NotarizationAllowanceExhausted
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

struct HostedLifecycle {
    operation_id: String,
    usage_outbox: UsageOutbox,
}

impl SessionLifecycle for HostedLifecycle {
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
impl AdmissionPolicy for AdmissionCoordinator {
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
            .map_err(|rejection| coordinator_admission_rejection(request.mode, rejection))?;
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
                tracing::error!(%error, "admission coordinator returned invalid notary limits");
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
        Ok(AdmissionGrant {
            constraints,
            lifecycle: Some(Arc::new(HostedLifecycle {
                operation_id: operation.operation_id,
                usage_outbox: self.usage_outbox.clone(),
            })),
        })
    }
}

fn coordinator_admission_rejection(
    mode: NotarySessionMode,
    rejection: CoordinatorRejection,
) -> NotaryAdmissionRejection {
    match rejection {
        CoordinatorRejection::Capacity => match mode {
            NotarySessionMode::Capture => NotaryAdmissionRejection::CaptureAtCapacity,
            NotarySessionMode::Notarization => NotaryAdmissionRejection::NotarizationAtCapacity,
        },
        CoordinatorRejection::Denied => NotaryAdmissionRejection::AdmissionDenied,
        CoordinatorRejection::Expired => NotaryAdmissionRejection::AdmissionExpired,
        CoordinatorRejection::CaptureAllowanceExhausted => {
            NotaryAdmissionRejection::CaptureAllowanceExhausted
        }
        CoordinatorRejection::NotarizationAllowanceExhausted => {
            NotaryAdmissionRejection::NotarizationAllowanceExhausted
        }
        CoordinatorRejection::Unavailable(error) => {
            tracing::error!(%error, "admission coordinator request failed");
            NotaryAdmissionRejection::AdmissionServiceUnavailable
        }
    }
}

/// Runs Exalto's hosted adapter around the public remote notary runtime.
pub async fn run() -> Result<()> {
    llm_notary_server::run_with_policy_factory(|| {
        let admission = AdmissionCoordinator::from_env()?;
        admission.usage_outbox.recover_after_restart()?;
        let usage_replayer = admission.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(USAGE_OUTBOX_RETRY_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                usage_replayer.replay_usage_outbox().await;
            }
        });
        Ok(Arc::new(admission) as Arc<dyn AdmissionPolicy>)
    })
    .await
}

fn operation_constraints(
    mode: NotarySessionMode,
    operation: &RedeemedOperation,
) -> Result<AdmissionConstraints> {
    let positive = |name: &str, value: i64| -> Result<usize> {
        if value <= 0 {
            bail!("coordinator {name} must be positive");
        }
        value
            .try_into()
            .with_context(|| format!("coordinator {name} does not fit in usize"))
    };
    let max_private_chunk_bytes =
        positive("max_private_chunk_bytes", operation.max_private_chunk_bytes)?;
    let policy_attestable = positive(
        "max_attestable_http_bytes",
        operation.max_attestable_http_bytes,
    )?;
    let (expected_record_digest, authenticated_allowance) =
        match (
            mode,
            operation.record_digest.as_deref(),
            operation.notarization_allowance_bytes,
        ) {
            (NotarySessionMode::Capture, None, None) => (None, policy_attestable),
            (NotarySessionMode::Notarization, Some(digest), Some(allowance)) => {
                let bytes = hex::decode(digest).context("coordinator record digest is not hex")?;
                let allowance = positive("notarization_allowance_bytes", allowance)?;
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

    #[test]
    fn redemption_requires_one_operation_with_durable_settlement() {
        let request = serde_json::to_value(RedeemRequest {
            ticket: "opaque-ticket",
            notary_instance_id: "notary-test",
            mode: "capture",
            registry_generation: 1,
            contract: "one_operation_v1",
            usage_settlement: true,
        })
        .unwrap();
        assert_eq!(request["contract"], "one_operation_v1");
        assert_eq!(request["usage_settlement"], true);

        let operation: RedeemedOperation = serde_json::from_value(serde_json::json!({
            "operation_id": "operation-test",
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
    fn coordinator_policy_returns_only_tighter_candidate_limits() {
        let operation = RedeemedOperation {
            operation_id: "operation-notarization".to_owned(),
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
    async fn coordinator_outage_fails_closed() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(250))
                .build()
                .unwrap(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageOutbox::open(outbox_directory.path()).unwrap(),
        };

        assert!(matches!(
            coordinator
                .redeem("opaque-ticket", NotarySessionMode::Capture)
                .await,
            Err(CoordinatorRejection::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn admitted_operation_needs_no_coordinator_liveness() {
        let outbox_directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/api/internal/notary/admissions/redeem",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "operation_id": "operation-capture",
                    "max_attestable_http_bytes": 1024,
                    "max_frame_bytes": 2048,
                    "max_private_chunk_bytes": 512,
                    "max_private_chunk_commitments": 4,
                    "record_digest": null,
                    "notarization_allowance_bytes": null
                }))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageOutbox::open(outbox_directory.path()).unwrap(),
        };
        let grant = coordinator
            .admit(AdmissionRequest {
                mode: NotarySessionMode::Capture,
                admission_value: Some("opaque-ticket"),
            })
            .await
            .expect("one-operation admission should be accepted");
        server.abort();
        let lifecycle = grant.lifecycle.expect("hosted lifecycle");
        lifecycle.record_authenticated_bytes(321).unwrap();
        lifecycle.finish(SessionOutcome::Completed, 321).unwrap();
        assert_eq!(grant.constraints.max_total_private_chunk_bytes, Some(1024));
        assert_eq!(grant.constraints.session_timeout, None);
        assert_eq!(coordinator.usage_outbox.ready().unwrap().len(), 1);
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
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: UsageOutbox::open(outbox_directory.path()).unwrap(),
        };

        assert!(matches!(
            coordinator
                .admit(AdmissionRequest {
                    mode: NotarySessionMode::Capture,
                    admission_value: Some("opaque-ticket"),
                })
                .await,
            Err(NotaryAdmissionRejection::AdmissionServiceUnavailable)
        ));
        let pending = coordinator.usage_outbox.ready().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].operation_id, "operation-invalid-limits");
        assert_eq!(
            pending[0].outcome,
            Some(UsageSettlementOutcome::ServiceFailed)
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
        let outbox = UsageOutbox::open(directory.path()).unwrap();
        outbox.stage(&pending).unwrap();
        outbox
            .record_authenticated_bytes(&pending.operation_id, 321)
            .unwrap();
        drop(outbox);

        let restarted = UsageOutbox::open(directory.path()).unwrap();
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
        let outbox = UsageOutbox::open(directory.path()).unwrap();
        let pending = PendingUsageSettlement {
            operation_id: "operation-conflict".to_owned(),
            notary_instance_id: "notary-test".to_owned(),
            mode: UsageMode::Finalize,
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

    #[tokio::test]
    async fn successful_usage_replay_removes_only_delivered_entries() {
        let directory = tempfile::tempdir().unwrap();
        let outbox = UsageOutbox::open(directory.path()).unwrap();
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
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox: outbox,
        };

        coordinator.replay_usage_outbox().await;
        assert!(coordinator.usage_outbox.ready().unwrap().is_empty());
        server.abort();
        let _ = server.await;

        let retry = PendingUsageSettlement {
            operation_id: "operation-retry".to_owned(),
            ..pending
        };
        coordinator.usage_outbox.stage(&retry).unwrap();
        coordinator
            .usage_outbox
            .finish(
                &retry.operation_id,
                UsageSettlementOutcome::ClientFailed,
                19,
            )
            .unwrap();
        coordinator.replay_usage_outbox().await;
        assert_eq!(coordinator.usage_outbox.ready().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn gone_operation_acknowledgement_removes_usage_entry() {
        let usage_directory = tempfile::tempdir().unwrap();
        let usage_outbox = UsageOutbox::open(usage_directory.path()).unwrap();
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
        let coordinator = AdmissionCoordinator {
            http: reqwest::Client::new(),
            origin: Url::parse(&format!("http://{address}/")).unwrap(),
            service_token: Arc::from("x".repeat(32)),
            instance_id: Arc::from("notary-test"),
            registry_generation: 1,
            usage_outbox,
        };

        coordinator.replay_usage_outbox().await;
        assert!(coordinator.usage_outbox.ready().unwrap().is_empty());
        server.abort();
        let _ = server.await;
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
            coordinator_rejection(reqwest::StatusCode::GONE, Some("admission_ticket_expired"),),
            CoordinatorRejection::Expired
        ));
        assert!(matches!(
            coordinator_rejection(reqwest::StatusCode::GONE, None),
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
            CoordinatorRejection::CaptureAllowanceExhausted
        ));
        assert!(matches!(
            coordinator_rejection(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                Some("notarization_credits_exhausted"),
            ),
            CoordinatorRejection::NotarizationAllowanceExhausted
        ));
    }
}
