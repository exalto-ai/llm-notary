use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::FromRow;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tracing::Span;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use notary_core::{
    pagination::{CursorScope, Page, PageQuery, decode_cursor},
    public_safety::{
        PUBLIC_PACKAGE_SAFETY_VERSION, PublicPackageSafetyContext,
        validate_public_trace_package_with_context_and_force,
    },
    sha256_hex,
};

use crate::{
    ApiError, ApiResult, NotaryApiState, database_error, pagination,
    traces::owner::{
        HostedTraceRow, MAX_SHARE_PASSWORD_BYTES, cleanup_object, enqueue_cleanup_direct,
        run_share_password_work,
    },
    unix_timestamp,
    verification::worker::{
        HostedVerificationError, HostedVerifiedPackage, TRUST_SOURCE,
        acquire_verification_capacity, verify_package,
    },
};

const ADMISSION_INTERVAL_SECS: u64 = 2;
const CLAIM_TIMEOUT_SECS: i64 = 15 * 60;
const MAX_JOBS_PER_TICK: usize = 4;
const LIBRARY_PREVIEW_CHARS: usize = 180;
const SHARE_PASSWORD_HEADER: &str = "x-share-password";
const MAX_REPORT_MESSAGE_CHARS: usize = 500;
const SHARE_RATE_LIMIT_KEY_PURPOSE: &[u8] = b"llm-notary/share-rate-limit/v1";
const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 10 * 60;
const RATE_LIMIT_RETENTION_SECS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy)]
struct ShareRateLimit {
    action: &'static str,
    max_requests: i64,
    window_secs: i64,
    error_code: &'static str,
    error_message: &'static str,
}

const SHARE_PASSWORD_RATE_LIMIT: ShareRateLimit = ShareRateLimit {
    action: "password",
    max_requests: 10,
    window_secs: 60,
    error_code: "share_password_rate_limited",
    error_message: "Too many password attempts were made from this network",
};

const SHARE_REPORT_RATE_LIMIT: ShareRateLimit = ShareRateLimit {
    action: "report",
    max_requests: 5,
    window_secs: 60 * 60,
    error_code: "share_report_rate_limited",
    error_message: "Too many reports were submitted from this network",
};

#[derive(FromRow)]
struct PublicShareRow {
    id: String,
    visibility: String,
    access_expires_at: Option<i64>,
    access_password_hash: Option<String>,
    publisher: String,
    verified_at: i64,
    provider: String,
    provider_host: String,
    model: String,
    authenticated_provider_connection_unix_ms: Option<i64>,
    verified_notary_key_id: Option<String>,
    verified_registry_generation: Option<i64>,
    verified_trust_source: Option<String>,
    content_object_key: String,
    content_size_bytes: i64,
    content_sha256: String,
    package_object_key: Option<String>,
    package_size_bytes: Option<i64>,
    package_sha256: Option<String>,
    disclosure_safety_version: Option<String>,
    disclosure_safety_override: bool,
}

fn public_package_metadata(share: &PublicShareRow) -> ApiResult<(&str, i64, &str, &str)> {
    match (
        share.package_object_key.as_deref(),
        share.package_size_bytes,
        share.package_sha256.as_deref(),
        share.disclosure_safety_version.as_deref(),
    ) {
        (Some(key), Some(size), Some(sha256), Some(safety_version)) if size > 0 => {
            Ok((key, size, sha256, safety_version))
        }
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "shared Trace {} is missing retained package metadata",
            share.id
        ))),
    }
}

#[derive(FromRow)]
struct ListedShareRow {
    id: String,
    publisher: String,
    provider: String,
    model: String,
    authenticated_provider_connection_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    page_authenticated_at_unix_ms: i64,
}

#[derive(Deserialize, ToSchema)]
struct ListedSharesQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    search: Option<String>,
    provider: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ListedSharePagePosition {
    authenticated_at_unix_ms: i64,
    id: String,
}

#[derive(Serialize, ToSchema)]
struct ListedShareSummary {
    id: String,
    provider: String,
    model: String,
    publisher: String,
    authenticated_at_unix_ms: Option<i64>,
    input_preview: Option<String>,
    output_preview: Option<String>,
    password_protected: bool,
    share_url: String,
}

#[derive(Serialize, ToSchema)]
struct PublicShareDetail {
    id: String,
    visibility: String,
    password_protected: bool,
    expires_at: Option<i64>,
    publisher: String,
    verified_at: i64,
    authenticated_at_unix_ms: Option<i64>,
    provider: String,
    host: String,
    model: String,
    verification_state: &'static str,
    notary_key_id: Option<String>,
    registry_generation: Option<i64>,
    trust_source: Option<String>,
    content_sha256: String,
    package_size_bytes: i64,
    package_sha256: String,
    disclosure_safety_version: String,
    disclosure_safety_override: bool,
    trace_url: String,
    package_url: String,
    share_url: String,
}

#[derive(Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum ShareReportReason {
    SensitiveInformation,
    Harassment,
    IllegalContent,
    Spam,
    Other,
}

impl ShareReportReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::SensitiveInformation => "sensitive_information",
            Self::Harassment => "harassment",
            Self::IllegalContent => "illegal_content",
            Self::Spam => "spam",
            Self::Other => "other",
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateShareReport {
    reason: ShareReportReason,
    #[schema(max_length = 500)]
    message: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ShareReportReceipt {
    received: bool,
}

struct VerifiedArtifacts {
    verified: HostedVerifiedPackage,
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

enum AdmissionFailure {
    Reject(String, anyhow::Error),
    Retry(anyhow::Error),
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(listed_shares))
        .routes(routes!(public_share_detail))
        .routes(routes!(public_share_trace))
        .routes(routes!(public_share_package))
        .routes(routes!(create_share_report))
}

#[utoipa::path(
    get,
    path = "/api/public/shares",
    summary = "List Listed verified-session shares",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query), ("search" = Option<String>, Query), ("provider" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<ListedShareSummary>),
        (status = 400, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "library"
)]
async fn listed_shares(
    State(state): State<NotaryApiState>,
    query: Result<Query<ListedSharesQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<ListedShareSummary>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let search = normalize_library_search(query.search)?;
    let search_pattern = search.as_deref().map(library_search_regex);
    let provider = normalize_library_filter(query.provider, 100, "provider is too long")?;
    let page_query = PageQuery {
        limit: query.limit,
        cursor: query.cursor,
    };
    let limit = page_query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new(
        "/api/public/shares",
        &(&search, &provider),
        "authenticated_provider_connection_unix_ms desc nulls last, trace_id desc",
    )
    .map_err(pagination::api_error)?;
    let position = page_query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<ListedSharePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let rows: Vec<ListedShareRow> = sqlx::query_as(
        "SELECT traces.trace_id AS id, accounts.display_name AS publisher, traces.provider,
                traces.model,
                traces.authenticated_provider_connection_unix_ms,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.input_preview END AS input_preview,
                CASE WHEN traces.access_password_hash IS NULL
                     THEN traces.output_preview END AS output_preview,
                traces.access_password_hash IS NOT NULL AS password_protected,
                COALESCE(
                    traces.authenticated_provider_connection_unix_ms,
                    '-9223372036854775808'::BIGINT
                ) AS page_authenticated_at_unix_ms
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.status = 'shared'
           AND traces.visibility = 'listed'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $6)
           AND traces.content_object_key IS NOT NULL
           AND traces.package_object_key IS NOT NULL
           AND ($1::TEXT IS NULL OR traces.provider = $1)
           AND ($2::TEXT IS NULL OR (
                traces.access_password_hash IS NULL
                AND traces.listing_search_text ~* $2
           ) OR (
                traces.access_password_hash IS NOT NULL
                AND LOWER(CONCAT_WS(
                    ' ', traces.provider, traces.model, accounts.display_name
                )) ~* $2
           ))
           AND ($3::TEXT IS NULL OR (
                COALESCE(
                    traces.authenticated_provider_connection_unix_ms,
                    '-9223372036854775808'::BIGINT
                ), traces.trace_id
           ) < ($4, $3))
         ORDER BY traces.authenticated_provider_connection_unix_ms DESC NULLS LAST,
                  traces.trace_id DESC
         LIMIT $5",
    )
    .bind(&provider)
    .bind(&search_pattern)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(
        position
            .as_ref()
            .map(|position| position.authenticated_at_unix_ms),
    )
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .bind(unix_timestamp()?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    let page = Page::from_limit_plus_one(rows, limit, &scope, |share| ListedSharePagePosition {
        authenticated_at_unix_ms: share.page_authenticated_at_unix_ms,
        id: share.id.clone(),
    })
    .map_err(pagination::api_error)?;
    let items = page
        .items
        .into_iter()
        .map(|share| ListedShareSummary {
            share_url: canonical_share_url(&state, &share.id),
            id: share.id,
            provider: share.provider,
            model: share.model,
            publisher: share.publisher,
            authenticated_at_unix_ms: share.authenticated_provider_connection_unix_ms,
            input_preview: share.input_preview,
            output_preview: share.output_preview,
            password_protected: share.password_protected,
        })
        .collect();
    Ok(Json(Page {
        items,
        next_cursor: page.next_cursor,
    }))
}

fn normalize_library_filter(
    value: Option<String>,
    maximum: usize,
    error: &'static str,
) -> ApiResult<Option<String>> {
    let value = value.map(|value| value.trim().to_lowercase());
    match value {
        Some(value) if value.len() > maximum => Err(ApiError::bad_request(error)),
        Some(value) if value.is_empty() => Ok(None),
        value => Ok(value),
    }
}

fn normalize_library_search(value: Option<String>) -> ApiResult<Option<String>> {
    let value = normalize_library_filter(value, 200, "search is too long")?;
    match value {
        Some(value) if !has_indexable_search_trigram(&value) => Err(ApiError::bad_request(
            "search must include 3 consecutive letters or numbers",
        )),
        value => Ok(value),
    }
}

fn has_indexable_search_trigram(value: &str) -> bool {
    let mut run = 0;
    for character in value.chars() {
        if character.is_alphanumeric() {
            run += 1;
            if run == 3 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn library_search_regex(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern
}

#[utoipa::path(
    get,
    path = "/api/public/shares/{share_id}",
    summary = "Get one verified-session share by its stable ID",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = PublicShareDetail),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_detail(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let (package_size_bytes, package_sha256, safety_version) = {
        let (_, size, sha256, safety_version) = public_package_metadata(&share)?;
        (size, sha256.to_owned(), safety_version.to_owned())
    };
    let detail = PublicShareDetail {
        id: share.id.clone(),
        visibility: share.visibility.clone(),
        password_protected: share.access_password_hash.is_some(),
        expires_at: share.access_expires_at,
        publisher: share.publisher,
        verified_at: share.verified_at,
        authenticated_at_unix_ms: share.authenticated_provider_connection_unix_ms,
        provider: share.provider,
        host: share.provider_host,
        model: share.model,
        verification_state: "verified",
        notary_key_id: share.verified_notary_key_id,
        registry_generation: share.verified_registry_generation,
        trust_source: share.verified_trust_source,
        content_sha256: share.content_sha256,
        package_size_bytes,
        package_sha256,
        disclosure_safety_version: safety_version,
        disclosure_safety_override: share.disclosure_safety_override,
        trace_url: format!("/api/public/shares/{}/trace.otlp.json", share.id),
        package_url: format!("/api/public/shares/{}/package.llmtrace", share.id),
        share_url: canonical_share_url(&state, &share.id),
    };
    let mut response = Json(detail).into_response();
    add_discovery_headers(&mut response, &share.visibility);
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/api/public/shares/{share_id}/trace.otlp.json",
    summary = "Download the verified canonical OpenTelemetry trace",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = serde_json::Value, content_type = "application/json"),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_trace(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let bytes = load_public_bytes(
        &state,
        &share.content_object_key,
        share.content_size_bytes,
        &share.content_sha256,
    )
    .await?;
    Ok(public_bytes(
        bytes,
        "application/json; charset=utf-8",
        &share.content_sha256,
        None,
        &share.visibility,
    ))
}

#[utoipa::path(
    get,
    path = "/api/public/shares/{share_id}/package.llmtrace",
    summary = "Download the exact verified portable proof package",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn public_share_package(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Response> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let (object_key, size_bytes, sha256, _) = public_package_metadata(&share)?;
    let bytes = load_public_bytes(&state, object_key, size_bytes, sha256).await?;
    Ok(public_bytes(
        bytes,
        super::storage::ARCHIVE_CONTENT_TYPE,
        sha256,
        Some(&format!("llm-notary-{share_id}.llmtrace")),
        &share.visibility,
    ))
}

#[utoipa::path(
    post,
    path = "/api/public/shares/{share_id}/reports",
    summary = "Report a published share",
    params(("share_id" = String, Path), ("X-Share-Password" = Option<String>, Header, description = "Base64url-encoded UTF-8 password for a protected share")),
    request_body = CreateShareReport,
    responses(
        (status = 200, body = ShareReportReceipt),
        (status = 400, body = crate::ErrorResponse),
        (status = 401, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    tag = "sharing"
)]
async fn create_share_report(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
    Json(request): Json<CreateShareReport>,
) -> ApiResult<Json<ShareReportReceipt>> {
    let share = load_public_share(&state, &headers, &share_id, peer).await?;
    let message = normalize_report_message(request.message)?;
    let now = unix_timestamp()?;
    enforce_share_request_limit(
        &state,
        &headers,
        peer,
        &share.id,
        now,
        SHARE_REPORT_RATE_LIMIT,
    )
    .await?;
    sqlx::query(
        "INSERT INTO trace_reports
             (report_id, trace_id, reason, message, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(share.id)
    .bind(request.reason.as_str())
    .bind(message)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(ShareReportReceipt { received: true }))
}

pub(crate) async fn run_worker(state: NotaryApiState, mut shutdown: watch::Receiver<bool>) {
    if !state.traces.enabled() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(ADMISSION_INTERVAL_SECS));
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
            if let Err(error) = purge_expired_share_rate_limits(&state).await {
                tracing::error!(%error, "purging expired share rate limits failed");
            }
            next_rate_limit_cleanup =
                Instant::now() + Duration::from_secs(RATE_LIMIT_CLEANUP_INTERVAL_SECS);
        }
    }
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
    name = "share.admission",
    skip_all,
    fields(share.id = %job.trace_id, archive.size_bytes = tracing::field::Empty)
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

    let directory = state.registry.clone();
    let allow_high_entropy = job.allow_high_entropy;
    let parent = Span::current();
    let result = tokio::task::spawn_blocking(move || {
        parent.in_scope(|| verify_for_admission(archive, &directory, allow_high_entropy))
    })
    .await;
    match result {
        Ok(Ok(artifacts)) => {
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
        Ok(Err(AdmissionFailure::Reject(code, error))) => {
            tracing::info!(share_id = %job.trace_id, failure_code = %code, %error, "share rejected");
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
        Ok(Err(AdmissionFailure::Retry(error))) => {
            retry_claim(state, &job, &claim, error).await;
            finish_admission_metric("retry", started);
        }
        Err(error) => {
            retry_claim(state, &job, &claim, anyhow::anyhow!(error)).await;
            finish_admission_metric("retry", started);
        }
    }
}

fn finish_admission_metric(outcome: &'static str, started: Instant) {
    metrics::counter!("notary_api_trace_verifications_total", "outcome" => outcome).increment(1);
    metrics::histogram!("notary_api_trace_verification_duration_seconds", "outcome" => outcome)
        .record(started.elapsed().as_secs_f64());
}

fn verify_for_admission(
    archive: Vec<u8>,
    directory: &notary_core::registry::Registry,
    allow_high_entropy: bool,
) -> std::result::Result<VerifiedArtifacts, AdmissionFailure> {
    let verified = verify_package(&archive, directory).map_err(|error| match error {
        HostedVerificationError::Service(error) => AdmissionFailure::Retry(error),
        error => AdmissionFailure::Reject(
            error
                .admission_code()
                .expect("non-service errors have an admission code")
                .to_owned(),
            anyhow::anyhow!(error.public_code()),
        ),
    })?;
    finish_trace_verification(archive, verified, allow_high_entropy)
}

fn finish_trace_verification(
    archive: Vec<u8>,
    verified: HostedVerifiedPackage,
    allow_high_entropy: bool,
) -> std::result::Result<VerifiedArtifacts, AdmissionFailure> {
    let safety = validate_public_trace_package_with_context_and_force(
        &archive,
        PublicPackageSafetyContext {
            provider_host: &verified.provider_host,
            request_path: &verified.request_path,
        },
        allow_high_entropy,
    )
    .map_err(|error| AdmissionFailure::Reject(error.admission_code(), anyhow::anyhow!(error)))?;
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
        safety_override_applied: safety.high_entropy_override_applied,
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
        .take(LIBRARY_PREVIEW_CHARS)
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
    match update {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            let current = load_public_share_optional(state, &job.trace_id)
                .await
                .ok()
                .flatten();
            if !current
                .as_ref()
                .is_some_and(|current| current.matches(&stored))
            {
                cleanup_committed_artifacts(state, &job.trace_id, &stored).await?;
                bail!("share claim was lost before admission");
            }
        }
        Err(error) => {
            cleanup_committed_artifacts(state, &job.trace_id, &stored).await?;
            return Err(error.into());
        }
    }
    purge_private_object(state, job).await;
    Ok(())
}

async fn store_committed_artifacts(
    state: &NotaryApiState,
    share_id: &str,
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
            share_id,
            "content",
            &content_sha256,
        )?,
        content_size_bytes: artifacts.verified.trace.len().try_into()?,
        content_sha256,
        package_object_key: state.traces.storage.committed_artifact_key(
            share_id,
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
        let directory = state.registry.clone();
        let expected_trace = stored.content_sha256.clone();
        let expected_package = stored.package_sha256.clone();
        let expected_safety_override = artifacts.safety_override_applied;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let verified = verify_package(&downloaded, &directory)
                .map_err(|_| anyhow::anyhow!("stored package failed cryptographic verification"))?;
            let safety = validate_public_trace_package_with_context_and_force(
                &downloaded,
                PublicPackageSafetyContext {
                    provider_host: &verified.provider_host,
                    request_path: &verified.request_path,
                },
                expected_safety_override,
            )
            .map_err(|error| anyhow::anyhow!(error))?;
            if safety.high_entropy_override_applied != expected_safety_override {
                bail!("stored package safety decision changed");
            }
            if verified.content_sha256 != expected_trace
                || verified.package_sha256 != expected_package
            {
                bail!("stored package verification metadata changed");
            }
            Ok(())
        })
        .await??;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        cleanup_committed_artifacts(state, share_id, &stored)
            .await
            .context("queueing incomplete committed artifacts for cleanup")?;
        return Err(error);
    }
    Ok(stored)
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

impl PublicShareRow {
    fn matches(&self, stored: &StoredPublicArtifacts) -> bool {
        self.content_object_key == stored.content_object_key
            && self.content_size_bytes == stored.content_size_bytes
            && self.content_sha256 == stored.content_sha256
            && self.package_object_key.as_deref() == Some(stored.package_object_key.as_str())
            && self.package_size_bytes == Some(stored.package_size_bytes)
            && self.package_sha256.as_deref() == Some(stored.package_sha256.as_str())
    }
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
        Ok(_) => tracing::warn!(share_id = %job.trace_id, "share rejection lost its claim"),
        Err(error) => {
            tracing::error!(share_id = %job.trace_id, %error, "recording rejection failed")
        }
    }
}

async fn retry_claim(
    state: &NotaryApiState,
    job: &HostedTraceRow,
    claim: &str,
    error: anyhow::Error,
) {
    tracing::error!(share_id = %job.trace_id, %error, "share admission will retry");
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
        tracing::error!(share_id = %job.trace_id, %update_error, "requeueing share failed");
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
                tracing::error!(share_id = %job.trace_id, %error, "recording private purge failed");
            }
        }
        Ok(false) => {
            tracing::warn!(share_id = %job.trace_id, "private object purge remains queued")
        }
        Err(error) => {
            tracing::error!(share_id = %job.trace_id, %error, "private object purge failed")
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

async fn load_public_share(
    state: &NotaryApiState,
    headers: &HeaderMap,
    share_id: &str,
    peer: SocketAddr,
) -> ApiResult<PublicShareRow> {
    let share = load_public_share_optional(state, share_id)
        .await?
        .ok_or_else(|| ApiError::not_found("share was not found"))?;
    require_share_password(
        state,
        headers,
        share_id,
        peer,
        share.access_password_hash.as_deref(),
    )
    .await?;
    public_package_metadata(&share)?;
    Ok(share)
}

async fn load_public_share_optional(
    state: &NotaryApiState,
    share_id: &str,
) -> ApiResult<Option<PublicShareRow>> {
    let now = unix_timestamp()?;
    sqlx::query_as(
        "SELECT traces.trace_id AS id, traces.visibility,
                traces.access_expires_at, traces.access_password_hash,
                accounts.display_name AS publisher,
                traces.verified_at, traces.provider,
                traces.provider_host, traces.model,
                traces.authenticated_provider_connection_unix_ms,
                traces.verified_notary_key_id,
                traces.verified_registry_generation,
                traces.verified_trust_source,
                traces.content_object_key,
                traces.content_size_bytes,
                traces.content_sha256,
                traces.package_object_key, traces.package_size_bytes,
                traces.package_sha256,
                traces.disclosure_safety_version,
                traces.disclosure_safety_override
         FROM traces
         JOIN accounts ON accounts.account_id = traces.account_id
         WHERE traces.trace_id = $1 AND traces.status = 'shared'
           AND (traces.access_expires_at IS NULL OR traces.access_expires_at > $2)
           AND traces.content_object_key IS NOT NULL",
    )
    .bind(share_id)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)
}

async fn require_share_password(
    state: &NotaryApiState,
    headers: &HeaderMap,
    share_id: &str,
    peer: SocketAddr,
    password_hash: Option<&str>,
) -> ApiResult<()> {
    let Some(password_hash) = password_hash else {
        return Ok(());
    };
    let encoded_password = headers.get(SHARE_PASSWORD_HEADER).ok_or_else(|| {
        ApiError::coded(
            StatusCode::UNAUTHORIZED,
            "share_password_required",
            "This share requires a password",
        )
    })?;
    let now = unix_timestamp()?;
    enforce_share_request_limit(
        state,
        headers,
        peer,
        share_id,
        now,
        SHARE_PASSWORD_RATE_LIMIT,
    )
    .await?;
    let password =
        decode_share_password(encoded_password).map_err(|()| invalid_share_password())?;
    let valid = verify_share_password(password, password_hash.to_owned()).await?;
    if !valid {
        return Err(invalid_share_password());
    }
    Ok(())
}

fn decode_share_password(value: &HeaderValue) -> Result<Vec<u8>, ()> {
    let encoded = value.to_str().map_err(|_| ())?;
    if encoded.len() > MAX_SHARE_PASSWORD_BYTES.div_ceil(3) * 4 {
        return Err(());
    }
    let password = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?;
    if password.len() > MAX_SHARE_PASSWORD_BYTES {
        return Err(());
    }
    Ok(password)
}

async fn verify_share_password(password: Vec<u8>, password_hash: String) -> ApiResult<bool> {
    run_share_password_work(move || {
        PasswordHash::new(&password_hash)
            .ok()
            .is_some_and(|parsed| {
                Argon2::default()
                    .verify_password(&password, &parsed)
                    .is_ok()
            })
    })
    .await
}

fn invalid_share_password() -> ApiError {
    ApiError::coded(
        StatusCode::UNAUTHORIZED,
        "share_password_invalid",
        "The share password is incorrect",
    )
}

async fn enforce_share_request_limit(
    state: &NotaryApiState,
    headers: &HeaderMap,
    peer: SocketAddr,
    share_id: &str,
    now: i64,
    rate_limit: ShareRateLimit,
) -> ApiResult<()> {
    let subject_key = share_rate_limit_subject_key(state, headers, peer, rate_limit.action)?;
    let window_reset_before = now - rate_limit.window_secs;
    let request_count = sqlx::query_scalar::<_, i64>(
        "INSERT INTO public_trace_rate_limits
             (trace_id, subject_key_sha256, action, window_started_at, request_count, updated_at)
         VALUES ($1, $2, $3, $4, 1, $4)
         ON CONFLICT (trace_id, subject_key_sha256, action) DO UPDATE
         SET window_started_at = CASE
                 WHEN public_trace_rate_limits.window_started_at <= $5 THEN $4
                 ELSE public_trace_rate_limits.window_started_at
             END,
             request_count = CASE
                 WHEN public_trace_rate_limits.window_started_at <= $5 THEN 1
                 ELSE public_trace_rate_limits.request_count + 1
             END,
             updated_at = $4
         WHERE public_trace_rate_limits.window_started_at <= $5
            OR public_trace_rate_limits.request_count < $6
         RETURNING request_count",
    )
    .bind(share_id)
    .bind(subject_key)
    .bind(rate_limit.action)
    .bind(now)
    .bind(window_reset_before)
    .bind(rate_limit.max_requests)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    if request_count.is_none() {
        return Err(ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            rate_limit.error_code,
            rate_limit.error_message,
        ));
    }
    Ok(())
}

async fn purge_expired_share_rate_limits(state: &NotaryApiState) -> Result<()> {
    let cutoff = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?
        - RATE_LIMIT_RETENTION_SECS;
    sqlx::query("DELETE FROM public_trace_rate_limits WHERE updated_at < $1")
        .bind(cutoff)
        .execute(&state.database)
        .await?;
    sqlx::query("DELETE FROM trace_access_change_limits WHERE updated_at < $1")
        .bind(cutoff)
        .execute(&state.database)
        .await?;
    Ok(())
}

fn share_rate_limit_subject_key(
    state: &NotaryApiState,
    headers: &HeaderMap,
    peer: SocketAddr,
    action: &str,
) -> ApiResult<String> {
    let client_ip = crate::admissions::resolve_client_ip(headers, Some(peer), &state.admission)?;
    let client = crate::admissions::normalized_client_address(client_ip);
    let version = state.admission.anonymous_subject_key_version.to_string();
    let mut hmac = Hmac::<Sha256>::new_from_slice(&state.admission.anonymous_subject_hmac_key)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid anonymous subject key")))?;
    for value in [
        SHARE_RATE_LIMIT_KEY_PURPOSE,
        version.as_bytes(),
        action.as_bytes(),
        client.as_bytes(),
    ] {
        hmac.update(&(value.len() as u64).to_be_bytes());
        hmac.update(value);
    }
    Ok(format!(
        "v{}:{}",
        state.admission.anonymous_subject_key_version,
        hex::encode(hmac.finalize().into_bytes())
    ))
}

fn normalize_report_message(message: Option<String>) -> ApiResult<Option<String>> {
    let message = message.map(|message| message.trim().to_owned());
    match message {
        Some(message) if message.chars().count() > MAX_REPORT_MESSAGE_CHARS => Err(
            ApiError::bad_request("report message must contain at most 500 characters"),
        ),
        Some(message) if message.is_empty() => Ok(None),
        message => Ok(message),
    }
}

async fn load_public_bytes(
    state: &NotaryApiState,
    object_key: &str,
    size_bytes: i64,
    sha256: &str,
) -> ApiResult<Vec<u8>> {
    let limit: usize = size_bytes
        .try_into()
        .map_err(|_| ApiError::service_unavailable("public artifact metadata is invalid"))?;
    let bytes = state
        .traces
        .storage
        .get_object(object_key, limit)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::service_unavailable("public artifact is temporarily unavailable")
        })?;
    if bytes.len() != limit || sha256_hex(&bytes) != sha256 {
        return Err(ApiError::service_unavailable(
            "public artifact failed its integrity check",
        ));
    }
    Ok(bytes)
}

fn canonical_share_url(state: &NotaryApiState, share_id: &str) -> String {
    state
        .public_origin
        .join(&format!("/s/{share_id}"))
        .expect("share path is a valid same-origin URL")
        .to_string()
}

fn add_discovery_headers(response: &mut Response, visibility: &str) {
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static(SHARE_PASSWORD_HEADER),
    );
    if visibility == "unlisted" {
        response.headers_mut().insert(
            "x-robots-tag",
            HeaderValue::from_static("noindex, nofollow, noarchive"),
        );
    }
}

fn public_bytes(
    bytes: Vec<u8>,
    content_type: &'static str,
    sha256: &str,
    filename: Option<&str>,
    visibility: &str,
) -> Response {
    let mut response = (StatusCode::OK, Body::from(bytes)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        "x-content-sha256",
        HeaderValue::from_str(sha256).expect("SHA-256 is a valid header value"),
    );
    if let Some(filename) = filename {
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .expect("safe share ID makes a valid filename"),
        );
    }
    add_discovery_headers(&mut response, visibility);
    response
}

#[cfg(test)]
mod tests {
    use std::fs;

    use notary_core::archive::{PACKAGE_FILES, build_trace_package_archive};
    use url::Url;

    use super::*;
    use crate::traces::{
        owner::TraceService,
        storage::{MockTraceStorage, StoredObject},
    };

    #[test]
    fn library_filters_are_normalized_and_bounded() {
        assert_eq!(
            normalize_library_filter(Some("  OpenAI  ".to_owned()), 100, "too long").unwrap(),
            Some("openai".to_owned())
        );
        assert_eq!(
            normalize_library_filter(Some("   ".to_owned()), 100, "too long").unwrap(),
            None
        );
        assert!(normalize_library_filter(Some("x".repeat(101)), 100, "too long").is_err());
        assert!(normalize_library_search(Some("ai".to_owned())).is_err());
        assert!(normalize_library_search(Some("%%%".to_owned())).is_err());
        assert!(normalize_library_search(Some("a-b-c".to_owned())).is_err());
        assert_eq!(
            normalize_library_search(Some("  GPT  ".to_owned())).unwrap(),
            Some("gpt".to_owned())
        );
        assert_eq!(library_search_regex("100%_safe!"), "100%_safe!");
        assert_eq!(library_search_regex("a.b[c]"), "a\\.b\\[c\\]");
    }

    async fn insert_library_share(
        pool: &sqlx::PgPool,
        id: &str,
        visibility: &str,
        provider: &str,
        authenticated_at: Option<i64>,
        search_text: &str,
    ) {
        sqlx::query(
            "INSERT INTO traces (
                 trace_id, account_id, source_trace_id, idempotency_key, status, package_format,
                 declared_package_size_bytes, declared_package_sha256, staging_object_key,
                 committed_staging_object_key, upload_expires_at, created_at, updated_at,
                 verified_at, admitted_package_size_bytes, admitted_package_sha256,
                 content_object_key, content_size_bytes, content_sha256,
                 visibility, package_object_key, package_size_bytes, package_sha256,
                 disclosure_safety_version, provider, provider_host, model,
                 authenticated_provider_connection_unix_ms,
                 input_preview, output_preview, listing_search_text
             ) VALUES (
                 $1, 'library-user', $1 || '-source', $1 || '-key', 'shared', $2,
                 1, $3, $1 || '-upload', $1 || '-intake', 10, 1, 1,
                 1, 1, $3, $1 || '-trace', 1, $4, $5,
                 $1 || '-package', 1, $6, 'notary/public-package-safety/v1',
                 $7, $7 || '.example.com', 'model-' || $1, $8,
                 'input ' || $1, 'output ' || $1, $9
             )",
        )
        .bind(id)
        .bind(crate::traces::storage::PACKAGE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind(visibility)
        .bind("c".repeat(64))
        .bind(provider)
        .bind(authenticated_at)
        .bind(search_text)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn incomplete_committed_artifacts_are_durably_queued() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "library-user", 1, "publisher").await;
        insert_library_share(
            &database.pool,
            "trc-cleanup-committed",
            "unlisted",
            "openai",
            Some(100),
            "openai cleanup",
        )
        .await;
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
            registry: crate::tests::directory_key(),
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

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn listed_share_route_pages_ties_nulls_filters_and_concurrent_inserts() {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "library-user", 1, "publisher").await;
        insert_library_share(
            &database.pool,
            "share-c",
            "listed",
            "openai",
            Some(100),
            "openai publisher 100%_safe! prompt",
        )
        .await;
        insert_library_share(
            &database.pool,
            "share-b",
            "listed",
            "openai",
            Some(100),
            "openai publisher 100xxsafe prompt",
        )
        .await;
        insert_library_share(
            &database.pool,
            "share-a",
            "listed",
            "anthropic",
            Some(90),
            "anthropic publisher",
        )
        .await;
        insert_library_share(
            &database.pool,
            "share-null",
            "listed",
            "openai",
            None,
            "openai publisher without timestamp",
        )
        .await;
        insert_library_share(
            &database.pool,
            "hidden",
            "unlisted",
            "openai",
            Some(95),
            "openai publisher hidden",
        )
        .await;
        let state = NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: url::Url::parse(
                "https://notary.exalto.ai/api/auth/github/callback",
            )
            .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: url::Url::parse(
                "https://notary.exalto.ai/api/auth/google/callback",
            )
            .unwrap(),
            public_origin: url::Url::parse("https://notary.exalto.ai").unwrap(),
            secure_cookies: true,
            registry: crate::tests::directory_key(),
            traces: crate::traces::owner::TraceService::disabled_for_test(),
            admission: std::sync::Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        };

        let first = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: Some(2),
                cursor: None,
                search: None,
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            first
                .items
                .iter()
                .map(|share| share.id.as_str())
                .collect::<Vec<_>>(),
            ["share-c", "share-b"]
        );
        let cursor = first.next_cursor.unwrap();

        insert_library_share(
            &state.database,
            "share-new",
            "listed",
            "openai",
            Some(200),
            "openai publisher inserted later",
        )
        .await;
        let second = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: Some(2),
                cursor: Some(cursor),
                search: None,
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            second
                .items
                .iter()
                .map(|share| share.id.as_str())
                .collect::<Vec<_>>(),
            ["share-a", "share-null"]
        );
        assert!(second.next_cursor.is_none());

        let literal_search = listed_shares(
            State(state.clone()),
            Ok(Query(ListedSharesQuery {
                limit: None,
                cursor: None,
                search: Some("100%_safe!".to_owned()),
                provider: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(literal_search.items.len(), 1);
        assert_eq!(literal_search.items[0].id, "share-c");

        let provider_filter = listed_shares(
            State(state),
            Ok(Query(ListedSharesQuery {
                limit: None,
                cursor: None,
                search: None,
                provider: Some("ANTHROPIC".to_owned()),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(provider_filter.items.len(), 1);
        assert_eq!(provider_filter.items[0].id, "share-a");
    }

    fn package_with_openai_response_id(trace: &[u8]) -> Vec<u8> {
        let directory = std::env::temp_dir().join(format!(
            "llm-notary-hosted-admission-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => {
                    br#"{"format":"notary/trace-evidence/v1"}"#.to_vec()
                }
                "request.disclosed.http" => b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: \0\0\0\0\r\n\r\n{\"model\":\"gpt-test\"}".to_vec(),
                "response.disclosed.http" => b"HTTP/1.1 200 OK\r\nContent-Type: \0\0\0\r\n\r\n{\"id\":\"chatcmpl-7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np\",\"choices\":[]}".to_vec(),
                "trace.otlp.json" => trace.to_vec(),
                _ => b"public TLSNotary evidence".to_vec(),
            };
            fs::write(directory.join(name), bytes).unwrap();
        }
        let archive = build_trace_package_archive(&directory).unwrap();
        fs::remove_dir_all(directory).unwrap();
        archive
    }

    #[test]
    fn extracts_the_model_without_materialized_library_fields() {
        let trace = serde_json::to_vec(&serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-test"}}
            ]}]}]}]
        }))
        .unwrap();
        assert_eq!(trace_model(&trace).unwrap(), "gpt-test");
    }

    #[test]
    fn extracts_short_library_previews_from_disclosed_messages() {
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
        assert_eq!(output.chars().count(), LIBRARY_PREVIEW_CHARS + 1);
    }

    #[test]
    fn hosted_admission_accepts_a_verified_openai_root_response_id() {
        let trace = serde_json::to_vec(&serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{"attributes": [
                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-test"}}
            ]}]}]}]
        }))
        .unwrap();
        let archive = package_with_openai_response_id(&trace);
        let verified = HostedVerifiedPackage {
            source_trace_id: "trc-test".to_owned(),
            authenticated_at_unix_ms: 1_700_000_000_000,
            provider_name: "openai".to_owned(),
            provider_host: "api.openai.com".to_owned(),
            request_path: "/v1/chat/completions".to_owned(),
            notary_key_id: "sha256:test".to_owned(),
            registry_generation: 7,
            package_sha256: sha256_hex(&archive),
            content_sha256: sha256_hex(&trace),
            trace,
        };

        let admitted = match finish_trace_verification(archive, verified, false) {
            Ok(admitted) => admitted,
            Err(AdmissionFailure::Reject(code, error)) => {
                panic!("hosted Trace verification rejected {code}: {error}")
            }
            Err(AdmissionFailure::Retry(error)) => {
                panic!("hosted Trace verification requested a retry: {error}")
            }
        };
        assert_eq!(admitted.model, "gpt-test");
        assert_eq!(admitted.verified.request_path, "/v1/chat/completions");
        assert!(!admitted.safety_override_applied);
    }

    #[test]
    fn unlisted_artifacts_are_noindex_but_still_downloadable() {
        let response = public_bytes(
            b"package".to_vec(),
            crate::traces::storage::ARCHIVE_CONTENT_TYPE,
            &"a".repeat(64),
            Some("llm-notary-share.llmtrace"),
            "unlisted",
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-robots-tag").unwrap(),
            "noindex, nofollow, noarchive"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"llm-notary-share.llmtrace\""
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
    }

    #[test]
    fn listed_artifacts_do_not_receive_a_noindex_header() {
        let response = public_bytes(
            b"trace".to_vec(),
            "application/json; charset=utf-8",
            &"b".repeat(64),
            None,
            "listed",
        );
        assert!(!response.headers().contains_key("x-robots-tag"));
    }

    #[test]
    fn report_messages_are_trimmed_and_bounded() {
        assert_eq!(
            normalize_report_message(Some("  concise reason  ".to_owned())).unwrap(),
            Some("concise reason".to_owned())
        );
        assert_eq!(
            normalize_report_message(Some("   ".to_owned())).unwrap(),
            None
        );
        assert!(normalize_report_message(Some("x".repeat(501))).is_err());
    }

    #[tokio::test]
    async fn protected_share_passwords_round_trip_utf8_and_bound_verification() {
        use argon2::{
            PasswordHasher,
            password_hash::{SaltString, rand_core::OsRng},
        };

        let password = "пароль\n🔐123";
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        let encoded = URL_SAFE_NO_PAD.encode(password.as_bytes());
        let header = HeaderValue::from_str(&encoded).unwrap();
        let decoded = decode_share_password(&header).unwrap();
        assert_eq!(decoded, password.as_bytes());
        assert!(verify_share_password(decoded, hash.clone()).await.unwrap());

        let wrong = URL_SAFE_NO_PAD.encode("wrong-password".as_bytes());
        let wrong = decode_share_password(&HeaderValue::from_str(&wrong).unwrap()).unwrap();
        assert!(!verify_share_password(wrong, hash.clone()).await.unwrap());

        let capacity = Arc::new(Semaphore::new(1));
        let _held = capacity.clone().acquire_owned().await.unwrap();
        let saturated =
            crate::traces::owner::run_share_password_work_with_capacity(capacity, || true).await;
        assert!(matches!(
            saturated,
            Err(ApiError {
                code: "share_password_capacity",
                ..
            })
        ));

        let oversized = URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_SHARE_PASSWORD_BYTES + 1]);
        assert!(decode_share_password(&HeaderValue::from_str(&oversized).unwrap()).is_err());
        assert!(decode_share_password(&HeaderValue::from_static("not base64")).is_err());
        assert!(
            !verify_share_password(password.as_bytes().to_vec(), "invalid-hash".to_owned())
                .await
                .unwrap()
        );
    }
}
