//! Durable hosted Trace verification worker lifecycle.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::sync::watch;
use tracing::Span;
use uuid::Uuid;

use notary_core::{public_safety::PUBLIC_PACKAGE_SAFETY_VERSION, sha256_hex};

use crate::{
    NotaryApiState,
    traces::owner::{HostedTraceRow, cleanup_object, enqueue_cleanup_direct},
    unix_timestamp,
    verification::{
        process::{TRUST_SOURCE, VerificationError, VerifiedPackage, verify_hosted},
        worker::acquire_verification_capacity,
    },
};

use super::public::purge_expired_trace_rate_limits;

const CLAIM_TIMEOUT_SECS: i64 = 15 * 60;
const LISTING_PREVIEW_CHARS: usize = 180;
const VERIFICATION_INTERVAL_SECS: u64 = 2;
const MAX_JOBS_PER_TICK: usize = 4;
const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 10 * 60;

struct VerifiedArtifacts {
    verified: VerifiedPackage,
    archive: Vec<u8>,
    model: String,
    input_preview: Option<String>,
    output_preview: Option<String>,
    safety_override_applied: bool,
}

struct StoredPublicArtifacts {
    content_object_key: String,
    content_size_bytes: i64,
    content_sha256: String,
    package_object_key: String,
    package_size_bytes: i64,
    package_sha256: String,
}

#[derive(sqlx::FromRow)]
struct ExistingPublicArtifacts {
    content_object_key: String,
    content_size_bytes: i64,
    content_sha256: String,
    package_object_key: Option<String>,
    package_size_bytes: Option<i64>,
    package_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionUpdateState {
    Applied,
    NotApplied,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactReconciliation {
    MatchesPublicTrace,
    DoesNotMatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactDisposition {
    Admit,
    CleanUp,
    Retain,
}

fn artifact_disposition(
    update: AdmissionUpdateState,
    reconciliation: ArtifactReconciliation,
) -> ArtifactDisposition {
    if update == AdmissionUpdateState::Applied
        || reconciliation == ArtifactReconciliation::MatchesPublicTrace
    {
        ArtifactDisposition::Admit
    } else if reconciliation == ArtifactReconciliation::DoesNotMatch {
        ArtifactDisposition::CleanUp
    } else {
        ArtifactDisposition::Retain
    }
}

impl ExistingPublicArtifacts {
    fn matches(&self, stored: &StoredPublicArtifacts) -> bool {
        self.content_object_key == stored.content_object_key
            && self.content_size_bytes == stored.content_size_bytes
            && self.content_sha256 == stored.content_sha256
            && self.package_object_key.as_deref() == Some(stored.package_object_key.as_str())
            && self.package_size_bytes == Some(stored.package_size_bytes)
            && self.package_sha256.as_deref() == Some(stored.package_sha256.as_str())
    }
}

enum AdmissionFailure {
    Reject(String, anyhow::Error),
    Retry(anyhow::Error),
}

pub(crate) async fn run_worker(state: NotaryApiState, mut shutdown: watch::Receiver<bool>) {
    if !state.traces.enabled() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(VERIFICATION_INTERVAL_SECS));
    let mut next_rate_limit_cleanup = Instant::now();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {}
        }
        if let Err(error) = recover_stale_claims(&state).await {
            tracing::error!(%error, "recovering stale Trace verification claims failed");
        }
        for _ in 0..MAX_JOBS_PER_TICK {
            match claim_next_job(&state).await {
                Ok(Some((job, claim))) => process_claim(&state, job, claim).await,
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "claiming a Trace verification failed");
                    break;
                }
            }
        }
        if let Err(error) = purge_verified_private_objects(&state).await {
            tracing::error!(%error, "purging shared Trace intake objects failed");
        }
        if let Err(error) = update_queue_metrics(&state).await {
            tracing::error!(%error, "updating Trace verification metrics failed");
        }
        if Instant::now() >= next_rate_limit_cleanup {
            if let Err(error) = purge_expired_trace_rate_limits(&state).await {
                tracing::error!(%error, "purging expired Trace rate limits failed");
            }
            next_rate_limit_cleanup =
                Instant::now() + Duration::from_secs(RATE_LIMIT_CLEANUP_INTERVAL_SECS);
        }
    }
}

async fn claim_next_job(state: &NotaryApiState) -> Result<Option<(HostedTraceRow, String)>> {
    let claim = Uuid::new_v4().to_string();
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let job = sqlx::query_as::<_, HostedTraceRow>(
        "WITH next_job AS (
                 SELECT trace_id FROM traces
                 WHERE status = 'queued'
                 ORDER BY queued_at, trace_id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
             UPDATE traces
             SET status = 'verifying', verification_claim = $1, verification_started_at = $2,
                 updated_at = $3, failure_code = NULL
             FROM next_job
             WHERE traces.trace_id = next_job.trace_id
             RETURNING traces.*",
    )
    .bind(&claim)
    .bind(now)
    .bind(now)
    .fetch_optional(&state.database)
    .await?;
    Ok(job.map(|job| (job, claim)))
}

#[tracing::instrument(
    name = "trace.verification",
    skip_all,
    fields(trace.id = %job.trace_id, archive.size_bytes = tracing::field::Empty)
)]
async fn process_claim(state: &NotaryApiState, job: HostedTraceRow, claim: String) {
    let started = Instant::now();
    let _capacity = acquire_verification_capacity().await;
    let archive = match state
        .traces
        .storage
        .get_object(
            &job.committed_staging_object_key,
            state
                .traces
                .max_package_bytes
                .min(notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64) as usize,
        )
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            reject_claim(state, &job, &claim, "object_missing", None).await;
            finish_admission_metric("rejected", started);
            return;
        }
        Err(error) => {
            retry_claim(state, &job, &claim, error).await;
            finish_admission_metric("retry", started);
            return;
        }
    };
    let actual_size = archive.len() as i64;
    Span::current().record("archive.size_bytes", actual_size);
    metrics::histogram!("notary_api_trace_package_bytes").record(actual_size as f64);
    let admitted_package_sha256 = sha256_hex(&archive);
    if actual_size != job.declared_package_size_bytes {
        reject_claim(
            state,
            &job,
            &claim,
            "object_size_mismatch",
            Some((actual_size, admitted_package_sha256)),
        )
        .await;
        finish_admission_metric("rejected", started);
        return;
    }
    if admitted_package_sha256 != job.declared_package_sha256 {
        reject_claim(
            state,
            &job,
            &claim,
            "object_sha256_mismatch",
            Some((actual_size, admitted_package_sha256)),
        )
        .await;
        finish_admission_metric("rejected", started);
        return;
    }

    let registry = state.registry.clone();
    let allow_high_entropy = job.allow_high_entropy;
    let result = verify_for_admission(archive, registry, allow_high_entropy).await;
    match result {
        Ok(artifacts) => {
            if artifacts.verified.source_trace_id != job.source_trace_id {
                reject_claim(
                    state,
                    &job,
                    &claim,
                    "source_trace_id_mismatch",
                    Some((actual_size, admitted_package_sha256)),
                )
                .await;
                finish_admission_metric("rejected", started);
                return;
            }
            if let Err(error) = admit_claim(
                state,
                &job,
                &claim,
                actual_size,
                &admitted_package_sha256,
                artifacts,
            )
            .await
            {
                retry_claim(state, &job, &claim, error).await;
                finish_admission_metric("retry", started);
            } else {
                finish_admission_metric("shared", started);
            }
        }
        Err(AdmissionFailure::Reject(code, error)) => {
            tracing::info!(trace_id = %job.trace_id, failure_code = %code, %error, "hosted Trace rejected");
            reject_claim(
                state,
                &job,
                &claim,
                &code,
                Some((actual_size, admitted_package_sha256)),
            )
            .await;
            finish_admission_metric("rejected", started);
        }
        Err(AdmissionFailure::Retry(error)) => {
            retry_claim(state, &job, &claim, error).await;
            finish_admission_metric("retry", started);
        }
    }
}

fn finish_admission_metric(outcome: &'static str, started: Instant) {
    metrics::counter!("notary_api_trace_verifications_total", "outcome" => outcome).increment(1);
    metrics::histogram!("notary_api_trace_verification_duration_seconds", "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
}

async fn verify_for_admission(
    archive: Vec<u8>,
    registry: notary_core::registry::Registry,
    allow_high_entropy: bool,
) -> std::result::Result<VerifiedArtifacts, AdmissionFailure> {
    verify_for_admission_with(archive, registry, allow_high_entropy, verify_hosted).await
}

async fn verify_for_admission_with<F, Fut>(
    archive: Vec<u8>,
    registry: notary_core::registry::Registry,
    allow_high_entropy: bool,
    run_verifier: F,
) -> std::result::Result<VerifiedArtifacts, AdmissionFailure>
where
    F: FnOnce(Vec<u8>, notary_core::registry::Registry, bool) -> Fut,
    Fut: std::future::Future<Output = Result<VerifiedPackage, VerificationError>>,
{
    let verified = run_verifier(archive.clone(), registry, allow_high_entropy)
        .await
        .map_err(map_verification_error)?;
    finish_trace_verification(archive, verified)
}

fn map_verification_error(error: VerificationError) -> AdmissionFailure {
    match error {
        VerificationError::Rejected(code) if code == "verification_unavailable" => {
            AdmissionFailure::Retry(anyhow::anyhow!(code))
        }
        VerificationError::Rejected(code) => {
            AdmissionFailure::Reject(code.clone(), anyhow::anyhow!(code))
        }
        VerificationError::Timeout => {
            AdmissionFailure::Retry(anyhow::anyhow!("verification subprocess timed out"))
        }
        VerificationError::Cancelled => {
            AdmissionFailure::Retry(anyhow::anyhow!("verification subprocess was cancelled"))
        }
        VerificationError::Unavailable => {
            AdmissionFailure::Retry(anyhow::anyhow!("verification subprocess is unavailable"))
        }
    }
}

fn finish_trace_verification(
    archive: Vec<u8>,
    verified: VerifiedPackage,
) -> std::result::Result<VerifiedArtifacts, AdmissionFailure> {
    let safety_override_applied = verified.safety_override_applied.ok_or_else(|| {
        AdmissionFailure::Retry(anyhow::anyhow!(
            "hosted verifier omitted its public-safety decision"
        ))
    })?;
    let model = trace_model(&verified.trace)
        .map_err(|error| AdmissionFailure::Reject("package_invalid".to_owned(), error))?;
    let (input_preview, output_preview) = trace_previews(&verified.trace)
        .map_err(|error| AdmissionFailure::Reject("package_invalid".to_owned(), error))?;
    Ok(VerifiedArtifacts {
        verified,
        archive,
        model,
        input_preview,
        output_preview,
        safety_override_applied,
    })
}

fn trace_model(trace: &[u8]) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(trace)?;
    let spans = value
        .pointer("/resourceSpans/0/scopeSpans/0/spans")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("public trace has no span array"))?;
    let attributes = spans
        .first()
        .and_then(|span| span.get("attributes"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("public trace has no span attributes"))?;
    attributes
        .iter()
        .find(|attribute| {
            attribute.get("key").and_then(serde_json::Value::as_str) == Some("gen_ai.request.model")
        })
        .and_then(|attribute| attribute.pointer("/value/stringValue"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("public trace has no request model"))
}

fn trace_previews(trace: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let value: serde_json::Value = serde_json::from_slice(trace)?;
    Ok((
        trace_message_preview(&value, "gen_ai.input.messages", "user"),
        trace_message_preview(&value, "gen_ai.output.messages", "assistant"),
    ))
}

fn trace_message_preview(
    trace: &serde_json::Value,
    attribute_key: &str,
    preferred_role: &str,
) -> Option<String> {
    let resources = trace.get("resourceSpans")?.as_array()?;
    for resource in resources {
        let Some(scopes) = resource
            .get("scopeSpans")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for scope in scopes {
            let Some(spans) = scope.get("spans").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for span in spans {
                let Some(attributes) = span.get("attributes").and_then(serde_json::Value::as_array)
                else {
                    continue;
                };
                let Some(serialized_messages) = attributes.iter().find_map(|attribute| {
                    (attribute.get("key").and_then(serde_json::Value::as_str)
                        == Some(attribute_key))
                    .then(|| attribute.pointer("/value/stringValue"))
                    .flatten()
                    .and_then(serde_json::Value::as_str)
                }) else {
                    continue;
                };
                let Ok(messages) = serde_json::from_str::<serde_json::Value>(serialized_messages)
                else {
                    continue;
                };
                let Some(messages) = messages.as_array() else {
                    continue;
                };
                let preferred = messages.iter().find(|message| {
                    message.get("role").and_then(serde_json::Value::as_str) == Some(preferred_role)
                });
                if let Some(preview) = preferred
                    .and_then(message_text)
                    .or_else(|| messages.iter().find_map(message_text))
                    .and_then(compact_preview)
                {
                    return Some(preview);
                }
            }
        }
    }
    None
}

fn message_text(message: &serde_json::Value) -> Option<&str> {
    message
        .get("parts")?
        .as_array()?
        .iter()
        .find(|part| {
            part.get("type").and_then(serde_json::Value::as_str) == Some("text")
                && part
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })
        .and_then(|part| part.get("content"))
        .and_then(serde_json::Value::as_str)
}

fn compact_preview(value: &str) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    let mut characters = normalized.chars();
    let mut preview = characters
        .by_ref()
        .take(LISTING_PREVIEW_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        preview.push('…');
    }
    Some(preview)
}

async fn admit_claim(
    state: &NotaryApiState,
    job: &HostedTraceRow,
    claim: &str,
    actual_size: i64,
    admitted_package_sha256: &str,
    artifacts: VerifiedArtifacts,
) -> Result<()> {
    if artifacts.verified.package_sha256 != admitted_package_sha256 {
        bail!("verified package hash changed before admission");
    }
    let stored = store_committed_artifacts(state, &job.trace_id, &artifacts).await?;
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let update = sqlx::query(
        "UPDATE traces
         SET status = 'shared', admitted_package_size_bytes = $1, admitted_package_sha256 = $2,
             verified_at = $3, updated_at = $4,
             content_object_key = $5, content_size_bytes = $6,
             content_sha256 = $7, package_object_key = $8,
             package_size_bytes = $9, package_sha256 = $10,
             disclosure_safety_version = $11,
             disclosure_safety_override = $12,
             provider = $13, provider_host = $14, model = $15,
             input_preview = $16, output_preview = $17,
             listing_search_text = LOWER(CONCAT_WS(
                ' ', $13, $15,
                (SELECT display_name FROM accounts WHERE account_id = traces.account_id),
                $16, $17
             )),
             authenticated_provider_connection_unix_ms = $18,
             verified_notary_key_id = $19,
             verified_registry_generation = $20, verified_trust_source = $21,
             verification_claim = NULL
         WHERE trace_id = $22 AND status = 'verifying' AND verification_claim = $23
           AND content_object_key IS NULL AND package_object_key IS NULL",
    )
    .bind(actual_size)
    .bind(admitted_package_sha256)
    .bind(now)
    .bind(now)
    .bind(&stored.content_object_key)
    .bind(stored.content_size_bytes)
    .bind(&stored.content_sha256)
    .bind(&stored.package_object_key)
    .bind(stored.package_size_bytes)
    .bind(&stored.package_sha256)
    .bind(PUBLIC_PACKAGE_SAFETY_VERSION)
    .bind(artifacts.safety_override_applied)
    .bind(&artifacts.verified.provider_name)
    .bind(&artifacts.verified.provider_host)
    .bind(&artifacts.model)
    .bind(&artifacts.input_preview)
    .bind(&artifacts.output_preview)
    .bind(i64::try_from(artifacts.verified.authenticated_at_unix_ms)?)
    .bind(&artifacts.verified.notary_key_id)
    .bind(i64::try_from(artifacts.verified.registry_generation)?)
    .bind(TRUST_SOURCE)
    .bind(&job.trace_id)
    .bind(claim)
    .execute(&state.database)
    .await;
    let (update_state, update_error) = match update {
        Ok(result) if result.rows_affected() == 1 => (AdmissionUpdateState::Applied, None),
        Ok(_) => (AdmissionUpdateState::NotApplied, None),
        Err(error) => (AdmissionUpdateState::Ambiguous, Some(error)),
    };
    let reconciliation_result = if update_state == AdmissionUpdateState::Applied {
        None
    } else {
        Some(existing_public_artifacts_match(state, &job.trace_id, &stored).await)
    };
    let reconciliation = match reconciliation_result.as_ref() {
        None => ArtifactReconciliation::Unknown,
        Some(Ok(true)) => ArtifactReconciliation::MatchesPublicTrace,
        Some(Ok(false)) => ArtifactReconciliation::DoesNotMatch,
        Some(Err(_)) => ArtifactReconciliation::Unknown,
    };
    match artifact_disposition(update_state, reconciliation) {
        ArtifactDisposition::Admit => {}
        ArtifactDisposition::CleanUp => {
            cleanup_committed_artifacts(state, &job.trace_id, &stored).await?;
            if let Some(error) = update_error {
                return Err(error.into());
            }
            bail!("hosted Trace verification claim was lost before admission");
        }
        ArtifactDisposition::Retain => {
            // A connection loss can arrive after PostgreSQL committed the
            // admission. Deleting while both writes are ambiguous could remove
            // the public artifacts referenced by that committed row.
            if let Some(error) = update_error {
                return Err(error.into());
            }
            let error = reconciliation_result
                .expect("a non-applied update must be reconciled")
                .expect_err("unknown reconciliation must contain an error");
            return Err(error.context(
                "hosted Trace verification claim was lost and committed artifacts could not be reconciled",
            ));
        }
    }
    purge_private_object(state, job).await;
    Ok(())
}

async fn existing_public_artifacts_match(
    state: &NotaryApiState,
    trace_id: &str,
    stored: &StoredPublicArtifacts,
) -> Result<bool> {
    Ok(load_existing_public_artifacts(state, trace_id)
        .await?
        .as_ref()
        .is_some_and(|current| current.matches(stored)))
}

async fn load_existing_public_artifacts(
    state: &NotaryApiState,
    trace_id: &str,
) -> Result<Option<ExistingPublicArtifacts>> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    sqlx::query_as(
        "SELECT traces.content_object_key, traces.content_size_bytes,
                traces.content_sha256, traces.package_object_key,
                traces.package_size_bytes, traces.package_sha256
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.trace_id = $1 AND traces.status = 'shared'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $2)
           AND traces.content_object_key IS NOT NULL",
    )
    .bind(trace_id)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(Into::into)
}

async fn store_committed_artifacts(
    state: &NotaryApiState,
    trace_id: &str,
    artifacts: &VerifiedArtifacts,
) -> Result<StoredPublicArtifacts> {
    let content_sha256 = sha256_hex(&artifacts.verified.trace);
    let package_sha256 = sha256_hex(&artifacts.archive);
    if content_sha256 != artifacts.verified.content_sha256
        || package_sha256 != artifacts.verified.package_sha256
    {
        bail!("verified artifacts changed before public storage");
    }
    let stored = StoredPublicArtifacts {
        content_object_key: state.traces.storage.committed_artifact_key(
            trace_id,
            "content",
            &content_sha256,
        )?,
        content_size_bytes: artifacts.verified.trace.len().try_into()?,
        content_sha256,
        package_object_key: state.traces.storage.committed_artifact_key(
            trace_id,
            "package",
            &package_sha256,
        )?,
        package_size_bytes: artifacts.archive.len().try_into()?,
        package_sha256,
    };
    let result = async {
        write_public_artifact(
            state,
            &stored.content_object_key,
            "content",
            &stored.content_sha256,
            &artifacts.verified.trace,
        )
        .await?;
        write_public_artifact(
            state,
            &stored.package_object_key,
            "package",
            &stored.package_sha256,
            &artifacts.archive,
        )
        .await?;

        // Read through the same storage path used by recipients, then repeat
        // size/hash, safety, and cryptographic verification before the row can
        // atomically become reachable.
        let downloaded = state
            .traces
            .storage
            .get_object(&stored.package_object_key, artifacts.archive.len())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stored package disappeared before admission"))?;
        if downloaded.len() as i64 != stored.package_size_bytes
            || sha256_hex(&downloaded) != stored.package_sha256
            || downloaded != artifacts.archive
        {
            bail!("stored package failed its pre-commit integrity check");
        }
        reverify_stored_package(downloaded, state.registry.clone(), &artifacts.verified).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        cleanup_committed_artifacts(state, trace_id, &stored)
            .await
            .context("queueing incomplete committed artifacts for cleanup")?;
        return Err(error);
    }
    Ok(stored)
}

async fn reverify_stored_package(
    archive: Vec<u8>,
    registry: notary_core::registry::Registry,
    expected: &VerifiedPackage,
) -> Result<()> {
    reverify_stored_package_with(archive, registry, expected, verify_hosted).await
}

async fn reverify_stored_package_with<F, Fut>(
    archive: Vec<u8>,
    registry: notary_core::registry::Registry,
    expected: &VerifiedPackage,
    run_verifier: F,
) -> Result<()>
where
    F: FnOnce(Vec<u8>, notary_core::registry::Registry, bool) -> Fut,
    Fut: std::future::Future<Output = Result<VerifiedPackage, VerificationError>>,
{
    let allow_high_entropy = expected.safety_override_applied.ok_or_else(|| {
        anyhow::anyhow!("initial hosted verification omitted its public-safety decision")
    })?;
    let verified = run_verifier(archive, registry, allow_high_entropy)
        .await
        .map_err(|error| anyhow::anyhow!("stored package verifier failed: {error:?}"))?;
    if &verified != expected {
        bail!("stored package verification metadata changed");
    }
    Ok(())
}

async fn write_public_artifact(
    state: &NotaryApiState,
    object_key: &str,
    kind: &str,
    sha256: &str,
    bytes: &[u8],
) -> Result<()> {
    state
        .traces
        .storage
        .put_public_artifact(object_key, kind, sha256, bytes)
        .await?;
    let stored = state
        .traces
        .storage
        .head_object(object_key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("public artifact disappeared after upload"))?;
    if !super::storage::TraceStorage::has_expected_public_metadata(
        &stored,
        kind,
        sha256,
        bytes.len().try_into()?,
    ) {
        bail!("public artifact metadata changed after upload");
    }
    Ok(())
}

async fn cleanup_committed_artifacts(
    state: &NotaryApiState,
    trace_id: &str,
    artifacts: &StoredPublicArtifacts,
) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    for (object_key, artifact_kind) in [
        (&artifacts.content_object_key, "content"),
        (&artifacts.package_object_key, "package"),
    ] {
        enqueue_cleanup_direct(state, trace_id, object_key, artifact_kind, now).await?;
    }
    for object_key in [&artifacts.content_object_key, &artifacts.package_object_key] {
        let _ = cleanup_object(state, object_key).await?;
    }
    Ok(())
}

async fn reject_claim(
    state: &NotaryApiState,
    job: &HostedTraceRow,
    claim: &str,
    code: &str,
    actual: Option<(i64, String)>,
) {
    let now = unix_timestamp().unwrap_or(job.updated_at);
    let (actual_size, admitted_package_sha256) = actual
        .map(|(size, sha256)| (Some(size), Some(sha256)))
        .unwrap_or((None, None));
    match sqlx::query(
        "UPDATE traces
         SET status = 'rejected', failure_code = $1, admitted_package_size_bytes = $2,
             admitted_package_sha256 = $3, updated_at = $4, verification_claim = NULL
         WHERE trace_id = $5 AND status = 'verifying' AND verification_claim = $6",
    )
    .bind(code)
    .bind(actual_size)
    .bind(admitted_package_sha256)
    .bind(now)
    .bind(&job.trace_id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => purge_private_object(state, job).await,
        Ok(_) => tracing::warn!(trace_id = %job.trace_id, "hosted Trace rejection lost its claim"),
        Err(error) => {
            tracing::error!(trace_id = %job.trace_id, %error, "recording hosted Trace rejection failed")
        }
    }
}

async fn retry_claim(
    state: &NotaryApiState,
    job: &HostedTraceRow,
    claim: &str,
    error: anyhow::Error,
) {
    tracing::error!(trace_id = %job.trace_id, %error, "hosted Trace verification will retry");
    let now = unix_timestamp().unwrap_or(job.updated_at);
    if let Err(update_error) = sqlx::query(
        "UPDATE traces
         SET status = 'queued', updated_at = $1, verification_claim = NULL,
             verification_started_at = NULL
         WHERE trace_id = $2 AND status = 'verifying' AND verification_claim = $3",
    )
    .bind(now)
    .bind(&job.trace_id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        tracing::error!(trace_id = %job.trace_id, %update_error, "requeueing hosted Trace failed");
    }
}

async fn purge_private_object(state: &NotaryApiState, job: &HostedTraceRow) {
    match super::owner::purge_private_objects(state, job).await {
        Ok(true) => {
            let now = unix_timestamp().unwrap_or(job.updated_at);
            if let Err(error) = sqlx::query(
                "UPDATE traces SET staging_purged_at = $1, updated_at = $2
                 WHERE trace_id = $3 AND staging_purged_at IS NULL",
            )
            .bind(now)
            .bind(now)
            .bind(&job.trace_id)
            .execute(&state.database)
            .await
            {
                tracing::error!(trace_id = %job.trace_id, %error, "recording private purge failed");
            }
        }
        Ok(false) => {
            tracing::warn!(trace_id = %job.trace_id, "private object purge remains queued")
        }
        Err(error) => {
            tracing::error!(trace_id = %job.trace_id, %error, "private object purge failed")
        }
    }
}

async fn purge_verified_private_objects(state: &NotaryApiState) -> Result<()> {
    let jobs = sqlx::query_as::<_, HostedTraceRow>(
        "SELECT * FROM traces
         WHERE status IN ('shared', 'rejected') AND staging_purged_at IS NULL
         ORDER BY updated_at LIMIT 100",
    )
    .fetch_all(&state.database)
    .await?;
    for job in jobs {
        purge_private_object(state, &job).await;
    }
    Ok(())
}

async fn recover_stale_claims(state: &NotaryApiState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    sqlx::query(
        "UPDATE traces
         SET status = 'queued', verification_claim = NULL,
             verification_started_at = NULL, updated_at = $1
         WHERE status = 'verifying' AND verification_started_at < $2
           AND content_object_key IS NULL AND package_object_key IS NULL",
    )
    .bind(now)
    .bind(now - CLAIM_TIMEOUT_SECS)
    .execute(&state.database)
    .await?;
    Ok(())
}

async fn update_queue_metrics(state: &NotaryApiState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let (depth, oldest): (i64, Option<i64>) =
        sqlx::query_as("SELECT COUNT(*), MIN(queued_at) FROM traces WHERE status = 'queued'")
            .fetch_one(&state.database)
            .await?;
    metrics::gauge!("notary_api_trace_verification_queue_depth").set(depth as f64);
    metrics::gauge!("notary_api_trace_verification_oldest_queued_seconds")
        .set(oldest.map_or(0, |queued| now.saturating_sub(queued)) as f64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::traces::{
        owner::TraceService,
        storage::{MockTraceStorage, StoredObject},
    };

    #[test]
    fn ambiguous_admission_updates_never_delete_artifacts_without_database_truth() {
        use AdmissionUpdateState::{Ambiguous, Applied, NotApplied};
        use ArtifactDisposition::{Admit, CleanUp, Retain};
        use ArtifactReconciliation::{DoesNotMatch, MatchesPublicTrace, Unknown};

        for (update, reconciliation, expected) in [
            (Applied, Unknown, Admit),
            (Applied, DoesNotMatch, Admit),
            (NotApplied, MatchesPublicTrace, Admit),
            (NotApplied, DoesNotMatch, CleanUp),
            (NotApplied, Unknown, Retain),
            (Ambiguous, MatchesPublicTrace, Admit),
            (Ambiguous, DoesNotMatch, CleanUp),
            (Ambiguous, Unknown, Retain),
        ] {
            assert_eq!(artifact_disposition(update, reconciliation), expected);
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn incomplete_committed_artifacts_are_durably_queued() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "listed-user", 1, "publisher").await;
        let storage = MockTraceStorage::new();
        let stored = StoredPublicArtifacts {
            content_object_key: "test/content/trc-cleanup-committed/content.json".to_owned(),
            content_size_bytes: 7,
            content_sha256: "b".repeat(64),
            package_object_key: "test/packages/trc-cleanup-committed/package.llmtrace".to_owned(),
            package_size_bytes: 7,
            package_sha256: "c".repeat(64),
        };
        for (object_key, sha256) in [
            (&stored.content_object_key, &stored.content_sha256),
            (&stored.package_object_key, &stored.package_sha256),
        ] {
            storage.objects.lock().unwrap().insert(
                object_key.clone(),
                StoredObject {
                    size_bytes: 7,
                    metadata: Default::default(),
                },
            );
            storage.fail_delete(object_key);
            assert_eq!(sha256.len(), 64);
        }
        let state = NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: String::new(),
            github_client_secret: String::new(),
            github_callback_url: Url::parse("https://example.test/auth/github").unwrap(),
            google_client_id: String::new(),
            google_client_secret: String::new(),
            google_callback_url: Url::parse("https://example.test/auth/google").unwrap(),
            public_origin: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            registry: crate::tests::test_registry(),
            traces: TraceService::mock(storage),
            admission: std::sync::Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        };

        cleanup_committed_artifacts(&state, "trc-cleanup-committed", &stored)
            .await
            .unwrap();
        let queued: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT object_key, artifact_kind, attempts
             FROM storage_cleanup_queue ORDER BY artifact_kind",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            queued,
            vec![
                (stored.content_object_key, "content".to_owned(), 1),
                (stored.package_object_key, "package".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn extracts_the_model_without_materialized_listing_fields() {
        let trace = serde_json::to_vec(&serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-test"}}
            ]}]}]}]
        }))
        .unwrap();
        assert_eq!(trace_model(&trace).unwrap(), "gpt-test");
    }

    #[test]
    fn extracts_short_listing_previews_from_disclosed_messages() {
        let long_output = "answer ".repeat(50);
        let trace = serde_json::to_vec(&serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [
                {
                    "key": "gen_ai.input.messages",
                    "value": {"stringValue": serde_json::to_string(&serde_json::json!([
                        {"role": "system", "parts": [{"type": "text", "content": "instructions"}]},
                        {"role": "user", "parts": [{"type": "text", "content": "  Compare\nthese traces.  "}]}
                    ])).unwrap()}
                },
                {
                    "key": "gen_ai.output.messages",
                    "value": {"stringValue": serde_json::to_string(&serde_json::json!([
                        {"role": "assistant", "parts": [{"type": "text", "content": long_output}]}
                    ])).unwrap()}
                }
            ]}]}]}]
        }))
        .unwrap();
        let (input, output) = trace_previews(&trace).unwrap();
        assert_eq!(input.as_deref(), Some("Compare these traces."));
        let output = output.unwrap();
        assert!(output.ends_with('…'));
        assert_eq!(output.chars().count(), LISTING_PREVIEW_CHARS + 1);
    }

    fn verified_package(archive: &[u8]) -> VerifiedPackage {
        let trace = serde_json::to_vec(&serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-test"}}
            ]}]}]}]
        }))
        .unwrap();
        VerifiedPackage {
            source_trace_id: "trc-test".to_owned(),
            authenticated_at_unix_ms: 1_700_000_000_000,
            provider_name: "openai".to_owned(),
            provider_host: "api.openai.com".to_owned(),
            request_path: "/v1/chat/completions".to_owned(),
            notary_key_id: "sha256:test".to_owned(),
            registry_generation: 7,
            package_sha256: sha256_hex(archive),
            content_sha256: sha256_hex(&trace),
            trace,
            safety_override_applied: Some(false),
        }
    }

    #[tokio::test]
    async fn hosted_admission_uses_the_typed_isolated_verifier() {
        let archive = b"exact uploaded package".to_vec();
        let expected_archive = archive.clone();
        let verified = verified_package(&archive);
        let expected_verified = verified.clone();
        let registry = crate::tests::test_registry();
        let expected_generation = registry.generation;
        let admitted = verify_for_admission_with(
            archive,
            registry,
            false,
            move |actual_archive, actual_registry, allow_high_entropy| async move {
                assert_eq!(actual_archive, expected_archive);
                assert_eq!(actual_registry.generation, expected_generation);
                assert!(!allow_high_entropy);
                Ok(expected_verified)
            },
        )
        .await
        .unwrap_or_else(|failure| match failure {
            AdmissionFailure::Reject(code, error) => {
                panic!("hosted Trace verification rejected {code}: {error}")
            }
            AdmissionFailure::Retry(error) => {
                panic!("hosted Trace verification requested a retry: {error}")
            }
        });
        assert_eq!(admitted.model, "gpt-test");
        assert_eq!(admitted.verified, verified);
    }

    #[tokio::test]
    async fn post_storage_recheck_rejects_changed_verification_metadata() {
        let archive = b"exact stored package".to_vec();
        let expected = verified_package(&archive);
        let mut changed = expected.clone();
        changed.provider_host = "unexpected.example".to_owned();
        let result = reverify_stored_package_with(
            archive,
            crate::tests::test_registry(),
            &expected,
            move |_, _, _| async move { Ok(changed) },
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "stored package verification metadata changed"
        );
    }
}
