use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock},
    time::Duration,
};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use tokio::sync::{Semaphore, watch};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    ApiError, ApiResult, NotaryApiState,
    auth::{ApiScope, authenticated_principal, authenticated_web_user},
    config::TraceStorageConfig,
    database_error, pagination,
    traces::storage::{PACKAGE_FORMAT, TraceStorage},
    typed_id, unix_timestamp,
};
use notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};

#[cfg(test)]
use crate::config::{DEFAULT_MAX_PACKAGE_BYTES, DEFAULT_UPLOAD_TTL_SECS};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const CLEANUP_INTERVAL_SECS: u64 = 10 * 60;
const OBJECTS_PER_CLEANUP: i64 = 32;
const MAX_TRACE_ACCESS_EXPIRY_DAYS: u32 = 365;
const MIN_TRACE_PASSWORD_BYTES: usize = 8;
pub(super) const MAX_TRACE_PASSWORD_BYTES: usize = 128;
const TRACE_PASSWORD_CHANGE_LIMIT: i64 = 5;
const TRACE_PASSWORD_CHANGE_WINDOW_SECS: i64 = 60;
const TRACE_PASSWORD_WORK_CAPACITY: usize = 4;

static TRACE_PASSWORD_CAPACITY: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(TRACE_PASSWORD_WORK_CAPACITY)));

#[derive(Clone)]
pub struct TraceService {
    pub(super) storage: TraceStorage,
    pub(crate) max_package_bytes: i64,
    upload_ttl_secs: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateHostedTraceRequest {
    source_trace_id: String,
    package_format: String,
    package_size_bytes: i64,
    package_sha256: String,
    visibility: TraceVisibility,
    /// Optional initial access password. The value is accepted only in this body.
    password: Option<String>,
    /// Optional initial access expiry in days.
    #[schema(maximum = 365)]
    expires_in_days: Option<u32>,
    /// Accept unexplained high-entropy values after reviewing the disclosure.
    #[serde(default)]
    allow_high_entropy: bool,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CompleteHostedTraceUploadRequest {
    package_size_bytes: i64,
    package_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraceVisibility {
    Unlisted,
    Listed,
}

impl TraceVisibility {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
}

#[derive(Serialize, ToSchema)]
struct CreateHostedTraceResponse {
    trace: HostedTrace,
    upload: Option<HostedTraceUpload>,
}

#[derive(Deserialize, Serialize)]
struct HostedTracePagePosition {
    created_at: i64,
    id: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct UpdateTraceAccessSettings {
    visibility: Option<TraceVisibility>,
    /// A new password, or an empty string to remove the current password.
    password: Option<String>,
    /// Days from now until expiry. Zero removes the current expiry.
    #[schema(maximum = 365)]
    expires_in_days: Option<u32>,
}

#[derive(Serialize, ToSchema)]
struct HostedTraceUpload {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    expires_at: i64,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HostedTraceStatus {
    Verifying,
    Shared,
    Stopped,
    Rejected,
    Failed,
}

#[derive(Serialize, ToSchema)]
struct TraceAccessSettings {
    visibility: TraceVisibility,
    password_protected: bool,
    expires_at: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct HostedTracePackage {
    format: String,
    declared_size_bytes: i64,
    declared_sha256: String,
    admitted_size_bytes: Option<i64>,
    admitted_sha256: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct HostedTraceVerification {
    verified_at: Option<i64>,
    failure_code: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct HostedTrace {
    trace_id: String,
    source_trace_id: String,
    status: HostedTraceStatus,
    access: TraceAccessSettings,
    package: HostedTracePackage,
    verification: HostedTraceVerification,
    allow_high_entropy: bool,
    created_at: i64,
    updated_at: i64,
    status_url: String,
    public_url: Option<String>,
    package_url: Option<String>,
    owner_package_url: Option<String>,
}

#[derive(FromRow)]
pub(super) struct HostedTraceRow {
    pub(super) trace_id: String,
    pub(super) account_id: String,
    pub(super) source_trace_id: String,
    pub(super) status: String,
    pub(super) visibility: String,
    pub(super) access_expires_at: Option<i64>,
    pub(super) access_password_hash: Option<String>,
    pub(super) allow_high_entropy: bool,
    pub(super) package_format: String,
    pub(super) declared_package_size_bytes: i64,
    pub(super) declared_package_sha256: String,
    pub(super) staging_object_key: String,
    pub(super) committed_staging_object_key: String,
    pub(super) upload_expires_at: i64,
    pub(super) upload_generation: i64,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) failure_code: Option<String>,
    pub(super) verified_at: Option<i64>,
    pub(super) package_object_key: Option<String>,
    pub(super) admitted_package_size_bytes: Option<i64>,
    pub(super) admitted_package_sha256: Option<String>,
}

impl TraceService {
    pub fn from_config(config: &TraceStorageConfig) -> anyhow::Result<Self> {
        let storage = TraceStorage::from_config(config)?;
        Ok(Self {
            storage,
            max_package_bytes: config.max_package_bytes,
            upload_ttl_secs: config.upload_ttl_secs,
        })
    }

    pub fn enabled(&self) -> bool {
        self.storage.is_enabled()
    }

    pub async fn validate(&self) -> anyhow::Result<()> {
        self.storage.validate().await
    }

    #[cfg(test)]
    pub(super) fn mock(storage: super::storage::MockTraceStorage) -> Self {
        Self {
            storage: TraceStorage::Mock(storage),
            max_package_bytes: DEFAULT_MAX_PACKAGE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
        }
    }

    #[cfg(test)]
    pub fn disabled_for_test() -> Self {
        Self {
            storage: TraceStorage::Disabled,
            max_package_bytes: DEFAULT_MAX_PACKAGE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
        }
    }
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(create_hosted_trace))
        .routes(routes!(get_hosted_trace, update_trace_access))
        .routes(routes!(download_owned_trace_package))
        .routes(routes!(list_web_traces))
        .routes(routes!(complete_hosted_trace_upload))
        .routes(routes!(stop_hosted_trace_sharing))
}

#[utoipa::path(
    get,
    path = "/api/traces/{trace_id}/package.llmtrace",
    summary = "Download an owned exact verified portable proof package",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = Vec<u8>, content_type = "application/vnd.exalto.notary.trace-package+zip"),
        (status = 401, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 409, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:read"]), ("browserSession" = [])),
    tag = "traces"
)]
async fn download_owned_trace_package(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Response> {
    require_enabled(&state)?;
    let account_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::TracesRead)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let trace = load_owned_trace(&state, &account_id, &trace_id).await?;
    let (object_key, size_bytes, sha256) = match (
        trace.package_object_key.as_deref(),
        trace.admitted_package_size_bytes,
        trace.admitted_package_sha256.as_deref(),
    ) {
        (Some(key), Some(size), Some(sha256)) if size > 0 => (key, size, sha256),
        _ => {
            return Err(ApiError::conflict(
                "hosted Trace package is not ready for export",
            ));
        }
    };
    let bytes = super::public::load_public_bytes(&state, object_key, size_bytes, sha256).await?;
    Ok(super::public::public_bytes(
        bytes,
        super::storage::ARCHIVE_CONTENT_TYPE,
        sha256,
        Some(&format!("{trace_id}.llmtrace")),
        "unlisted",
    ))
}

pub(crate) async fn run_cleanup_worker(state: NotaryApiState, mut shutdown: watch::Receiver<bool>) {
    if !state.traces.enabled() {
        tracing::warn!("hosted Trace storage is disabled; hosted Trace endpoints will return 503");
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {}
        }
        if let Err(error) = cleanup_expired_uploads(&state).await {
            tracing::error!(
                status = %error.status,
                error = error.message,
                "cleaning up expired Trace uploads failed"
            );
        }
        if let Err(error) = cleanup_storage_objects(&state).await {
            tracing::error!(
                status = %error.status,
                error = error.message,
                "cleaning up Trace objects failed"
            );
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/traces",
    summary = "Create, resume, or safely re-share one hosted Trace",
    params(("Idempotency-Key" = String, Header, description = "Stable key for this hosted Trace request")),
    request_body = CreateHostedTraceRequest,
    responses(
        (status = 200, body = CreateHostedTraceResponse, description = "Existing hosted Trace"),
        (status = 201, body = CreateHostedTraceResponse, description = "New or reopened hosted Trace"),
        (status = 400, body = crate::ErrorResponse),
        (status = 401, body = crate::ErrorResponse),
        (status = 402, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 409, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:share"])),
    tag = "traces"
)]
async fn create_hosted_trace(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    Json(request): Json<CreateHostedTraceRequest>,
) -> ApiResult<Response> {
    require_enabled(&state)?;
    validate_request(&state.traces, &request)?;
    let account_id = authenticated_principal(&state, &headers, ApiScope::TracesShare)
        .await?
        .account_id;
    let billing = crate::credits::account_billing_state(&state.database, &account_id).await?;
    if billing.billing_status == crate::credits::BillingStatus::Review {
        return Err(ApiError::coded(
            axum::http::StatusCode::PAYMENT_REQUIRED,
            "billing_review",
            "Trace uploads are unavailable while billing is under review",
        ));
    }
    let storage_limit =
        crate::credits::plan_entitlements(&state.admission, billing.plan).trace_storage_bytes;
    let idempotency_key = idempotency_key(&headers)?;
    let now = unix_timestamp()?;
    let expires_at_changed = request.expires_in_days.is_some();
    let access_expires_at = expires_at_from_days(request.expires_in_days, now)?;
    let password_changed = request.password.is_some();
    if password_changed {
        enforce_password_change_limit(&state, &account_id, now).await?;
    }
    let access_password_hash = match request.password.as_deref() {
        Some("") | None => None,
        Some(_) => Some(hash_trace_access_password(request.password.clone().unwrap()).await?),
    };
    let job_id = typed_id("trc-");
    let staging_object_key = state
        .traces
        .storage
        .staging_object_key(&account_id, &job_id, 0)
        .map_err(ApiError::internal)?;
    let committed_staging_object_key = state
        .traces
        .storage
        .committed_staging_object_key(&account_id, &job_id, 0)
        .map_err(ApiError::internal)?;
    let upload_expires_at = now + state.traces.upload_ttl_secs;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&account_id)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    let idempotent_source: Option<String> = sqlx::query_scalar(
        "SELECT source_trace_id FROM traces
         WHERE account_id = $1 AND idempotency_key = $2",
    )
    .bind(&account_id)
    .bind(&idempotency_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?;
    if idempotent_source
        .as_deref()
        .is_some_and(|source| source != request.source_trace_id.as_str())
    {
        return Err(ApiError::conflict(
            "idempotency key was already used for a different hosted Trace",
        ));
    }
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM traces WHERE account_id = $1 AND source_trace_id = $2
         )",
    )
    .bind(&account_id)
    .bind(&request.source_trace_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database_error)?;
    if !existing && let Some(storage_limit) = storage_limit {
        let stored_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(declared_package_size_bytes), 0)::BIGINT FROM traces
             WHERE account_id = $1
               AND status IN ('uploading', 'queued', 'verifying', 'shared', 'stopped')",
        )
        .bind(&account_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?;
        if !trace_storage_allows(
            Some(storage_limit),
            stored_bytes,
            request.package_size_bytes,
        ) {
            return Err(trace_storage_quota_error());
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO traces
         (trace_id, account_id, source_trace_id, idempotency_key, status, visibility,
          access_expires_at, access_password_hash, allow_high_entropy,
          package_format, declared_package_size_bytes,
          declared_package_sha256, staging_object_key, committed_staging_object_key, upload_expires_at,
          created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'uploading', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         ON CONFLICT (account_id, source_trace_id) DO NOTHING",
    )
    .bind(&job_id)
    .bind(&account_id)
    .bind(&request.source_trace_id)
    .bind(&idempotency_key)
    .bind(request.visibility.as_str())
    .bind(access_expires_at)
    .bind(&access_password_hash)
    .bind(request.allow_high_entropy)
    .bind(&request.package_format)
    .bind(request.package_size_bytes)
    .bind(&request.package_sha256)
    .bind(staging_object_key)
    .bind(committed_staging_object_key)
    .bind(upload_expires_at)
    .bind(now)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;

    let mut job = load_trace_by_source(&state, &account_id, &request.source_trace_id).await?;
    let entropy_override_retry = job.status == "rejected"
        && !job.allow_high_entropy
        && request.allow_high_entropy
        && job
            .failure_code
            .as_deref()
            .is_some_and(|code| code.starts_with("high_entropy_value_"));
    if job.package_format != request.package_format
        || job.declared_package_size_bytes != request.package_size_bytes
        || job.declared_package_sha256 != request.package_sha256
        || (job.allow_high_entropy != request.allow_high_entropy && !entropy_override_retry)
    {
        return Err(ApiError::conflict(
            "idempotency key was already used with different package metadata",
        ));
    }
    if job.status == "uploading" && job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        job = load_trace_by_source(&state, &account_id, &request.source_trace_id).await?;
    }
    if job.status == "stopped" && job.package_object_key.is_some() {
        sqlx::query(
            "UPDATE traces
             SET status = 'shared', visibility = $1,
                 access_expires_at = CASE WHEN $2 THEN $3 ELSE access_expires_at END,
                 access_password_hash = CASE WHEN $4 THEN $5 ELSE access_password_hash END,
                 updated_at = $6
             WHERE trace_id = $7 AND account_id = $8 AND status = 'stopped'
               AND content_object_key IS NOT NULL AND package_object_key IS NOT NULL",
        )
        .bind(request.visibility.as_str())
        .bind(expires_at_changed)
        .bind(access_expires_at)
        .bind(password_changed)
        .bind(&access_password_hash)
        .bind(now)
        .bind(&job.trace_id)
        .bind(&account_id)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
        job = load_trace_by_source(&state, &account_id, &request.source_trace_id).await?;
    }
    let mut reopened = false;
    if (job.status == "failed" && job.failure_code.as_deref() == Some("upload_expired"))
        || entropy_override_retry
    {
        let retry_upload_key = state
            .traces
            .storage
            .staging_object_key(&account_id, &job.trace_id, job.upload_generation + 1)
            .map_err(ApiError::internal)?;
        let retry_committed_staging_key = state
            .traces
            .storage
            .committed_staging_object_key(&account_id, &job.trace_id, job.upload_generation + 1)
            .map_err(ApiError::internal)?;
        let mut reopen_transaction = state.database.begin().await.map_err(database_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&account_id)
            .execute(&mut *reopen_transaction)
            .await
            .map_err(database_error)?;
        let current = sqlx::query_as::<_, (String, i64, Option<String>, bool)>(
            "SELECT status, upload_generation, failure_code, allow_high_entropy FROM traces
             WHERE trace_id = $1 AND account_id = $2 FOR UPDATE",
        )
        .bind(&job.trace_id)
        .bind(&account_id)
        .fetch_one(&mut *reopen_transaction)
        .await
        .map_err(database_error)?;
        let retryable = (current.0 == "failed" && current.2.as_deref() == Some("upload_expired"))
            || (current.0 == "rejected"
                && !current.3
                && request.allow_high_entropy
                && current
                    .2
                    .as_deref()
                    .is_some_and(|code| code.starts_with("high_entropy_value_")));
        if retryable && let Some(storage_limit) = storage_limit {
            let stored_bytes: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM(declared_package_size_bytes), 0)::BIGINT FROM traces
                 WHERE account_id = $1
                   AND status IN ('uploading', 'queued', 'verifying', 'shared', 'stopped')",
            )
            .bind(&account_id)
            .fetch_one(&mut *reopen_transaction)
            .await
            .map_err(database_error)?;
            if !trace_storage_allows(
                Some(storage_limit),
                stored_bytes,
                job.declared_package_size_bytes,
            ) {
                return Err(trace_storage_quota_error());
            }
        }
        let reset = sqlx::query(
            "UPDATE traces
             SET status = 'uploading', staging_object_key = $1, committed_staging_object_key = $2,
                 upload_expires_at = $3, upload_generation = upload_generation + 1,
                 visibility = $4,
                 access_expires_at = CASE WHEN $5 THEN $6 ELSE access_expires_at END,
                 access_password_hash = CASE WHEN $7 THEN $8 ELSE access_password_hash END,
                 allow_high_entropy = $9,
                 admitted_package_size_bytes = NULL, admitted_package_sha256 = NULL,
                 staging_purged_at = NULL, updated_at = $10, failure_code = NULL
             WHERE trace_id = $11 AND account_id = $12
               AND ((status = 'failed' AND failure_code = 'upload_expired')
                    OR (status = 'rejected' AND failure_code LIKE 'high\\_entropy\\_value\\_%' ESCAPE '\\'
                        AND allow_high_entropy = FALSE AND $9 = TRUE))
               AND upload_generation = $13",
        )
        .bind(retry_upload_key)
        .bind(retry_committed_staging_key)
        .bind(upload_expires_at)
        .bind(request.visibility.as_str())
        .bind(expires_at_changed)
        .bind(access_expires_at)
        .bind(password_changed)
        .bind(&access_password_hash)
        .bind(request.allow_high_entropy)
        .bind(now)
        .bind(&job.trace_id)
        .bind(&account_id)
        .bind(current.1)
        .execute(&mut *reopen_transaction)
        .await
        .map_err(database_error)?;
        reopened = reset.rows_affected() == 1;
        reopen_transaction.commit().await.map_err(database_error)?;
        job = load_trace_by_source(&state, &account_id, &request.source_trace_id).await?;
    }
    let upload = if job.status == "uploading" {
        let presigned = state
            .traces
            .storage
            .presign_upload(
                &job.staging_object_key,
                job.declared_package_size_bytes,
                &job.declared_package_sha256,
                Duration::from_secs((job.upload_expires_at - now) as u64),
            )
            .await
            .map_err(ApiError::internal)?;
        Some(HostedTraceUpload {
            method: presigned.method,
            url: presigned.url,
            headers: presigned.headers,
            expires_at: job.upload_expires_at,
        })
    } else {
        None
    };
    let status = if inserted.rows_affected() == 1 || reopened {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(CreateHostedTraceResponse {
            trace: hosted_trace_response(&job, &state.public_origin),
            upload,
        }),
    )
        .into_response())
}

fn trace_storage_allows(limit: Option<i64>, stored_bytes: i64, requested_bytes: i64) -> bool {
    limit.is_none_or(|limit| stored_bytes.saturating_add(requested_bytes) <= limit)
}

fn trace_storage_quota_error() -> ApiError {
    ApiError::coded(
        axum::http::StatusCode::PAYMENT_REQUIRED,
        "trace_storage_quota_exceeded",
        "This upload would exceed the account's trace storage allowance",
    )
}

#[utoipa::path(
    get,
    path = "/api/traces/{trace_id}",
    summary = "Get one hosted Trace",
    params(("trace_id" = String, Path)),
    responses(
        (status = 200, body = HostedTrace),
        (status = 401, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:read"]), ("browserSession" = [])),
    tag = "traces"
)]
async fn get_hosted_trace(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<Json<HostedTrace>> {
    require_enabled(&state)?;
    let account_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::TracesRead)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let mut job = load_owned_trace(&state, &account_id, &trace_id).await?;
    let now = unix_timestamp()?;
    if job.status == "uploading" && job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        job = load_owned_trace(&state, &account_id, &trace_id).await?;
    }
    Ok(Json(hosted_trace_response(&job, &state.public_origin)))
}

#[utoipa::path(
    patch,
    path = "/api/traces/{trace_id}",
    summary = "Change hosted Trace access settings",
    params(("trace_id" = String, Path)),
    request_body = UpdateTraceAccessSettings,
    responses(
        (status = 200, body = HostedTrace),
        (status = 400, body = crate::ErrorResponse),
        (status = 401, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 429, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:share"]), ("browserSession" = [])),
    tag = "traces"
)]
async fn update_trace_access(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
    Json(request): Json<UpdateTraceAccessSettings>,
) -> ApiResult<Json<HostedTrace>> {
    require_enabled(&state)?;
    let account_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::TracesShare)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let now = unix_timestamp()?;
    if request.visibility.is_none()
        && request.password.is_none()
        && request.expires_in_days.is_none()
    {
        return Err(ApiError::bad_request(
            "at least one access setting is required",
        ));
    }
    // Resolve ownership before accepting any request that can schedule costly
    // password hashing work.
    load_owned_trace(&state, &account_id, &trace_id).await?;
    let visibility = request.visibility.map(TraceVisibility::as_str);
    let expires_at_changed = request.expires_in_days.is_some();
    let expires_at = expires_at_from_days(request.expires_in_days, now)?;
    let password_changed = request.password.is_some();
    if password_changed {
        enforce_password_change_limit(&state, &account_id, now).await?;
    }
    let password_hash = match request.password {
        Some(password) if password.is_empty() => None,
        Some(password) => Some(hash_trace_access_password(password).await?),
        None => None,
    };
    let updated = sqlx::query(
        "UPDATE traces
         SET visibility = COALESCE($1, visibility),
             access_expires_at = CASE WHEN $2 THEN $3 ELSE access_expires_at END,
             access_password_hash = CASE WHEN $4 THEN $5 ELSE access_password_hash END,
             updated_at = $6
         WHERE trace_id = $7 AND account_id = $8",
    )
    .bind(visibility)
    .bind(expires_at_changed)
    .bind(expires_at)
    .bind(password_changed)
    .bind(password_hash)
    .bind(now)
    .bind(&trace_id)
    .bind(&account_id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("hosted Trace was not found"));
    }
    let trace = load_owned_trace(&state, &account_id, &trace_id).await?;
    Ok(Json(hosted_trace_response(&trace, &state.public_origin)))
}

#[utoipa::path(
    get,
    path = "/api/traces",
    summary = "List the current account's hosted Traces",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<HostedTrace>),
        (status = 400, body = crate::ErrorResponse),
        (status = 401, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    security(("browserSession" = []), ("bearerAuth" = ["traces:read"])),
    tag = "traces"
)]
async fn list_web_traces(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<HostedTrace>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let account_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::TracesRead)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let limit = query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new("/api/traces", &account_id, "created_at desc, trace_id desc")
        .map_err(pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<HostedTracePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let traces = sqlx::query_as::<_, HostedTraceRow>(
        "SELECT * FROM traces
         WHERE account_id = $1
           AND ($2::TEXT IS NULL OR (created_at, trace_id) < ($3, $2))
         ORDER BY created_at DESC, trace_id DESC
         LIMIT $4",
    )
    .bind(&account_id)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.created_at))
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(|trace| hosted_trace_response(&trace, &state.public_origin))
    .collect();
    let page = Page::from_limit_plus_one(traces, limit, &scope, |trace| HostedTracePagePosition {
        created_at: trace.created_at,
        id: trace.trace_id.clone(),
    })
    .map_err(pagination::api_error)?;
    Ok(Json(page))
}

#[utoipa::path(
    post,
    path = "/api/traces/{trace_id}/upload-completion",
    summary = "Complete one hosted Trace package upload",
    params(("trace_id" = String, Path)),
    request_body = CompleteHostedTraceUploadRequest,
    responses(
        (status = 200, body = HostedTrace),
        (status = 401, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 409, body = crate::ErrorResponse),
        (status = 410, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse),
        (status = 503, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:share"])),
    tag = "traces"
)]
async fn complete_hosted_trace_upload(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
    Json(request): Json<CompleteHostedTraceUploadRequest>,
) -> ApiResult<Json<HostedTrace>> {
    require_enabled(&state)?;
    let account_id = authenticated_principal(&state, &headers, ApiScope::TracesShare)
        .await?
        .account_id;
    let job = load_owned_trace(&state, &account_id, &trace_id).await?;
    if request.package_size_bytes != job.declared_package_size_bytes
        || request.package_sha256 != job.declared_package_sha256
    {
        return Err(ApiError::conflict(
            "upload completion does not match the declared package",
        ));
    }
    if job.status == "queued" {
        return Ok(Json(hosted_trace_response(&job, &state.public_origin)));
    }
    if job.status != "uploading" {
        return Err(ApiError::conflict(
            "hosted Trace is not accepting an upload",
        ));
    }
    let now = unix_timestamp()?;
    if job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        return Err(ApiError::gone("hosted Trace upload expired"));
    }
    let uploaded = state
        .traces
        .storage
        .head_object(&job.staging_object_key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("hosted Trace upload was not found"))?;
    if uploaded.size_bytes != job.declared_package_size_bytes {
        return Err(ApiError::conflict(
            "uploaded object size does not match the declared size",
        ));
    }
    if !TraceStorage::has_expected_metadata(&uploaded, &job.declared_package_sha256) {
        return Err(ApiError::conflict(
            "uploaded object metadata does not match the hosted Trace",
        ));
    }

    if let Err(error) = state
        .traces
        .storage
        .promote_object(&job.staging_object_key, &job.committed_staging_object_key)
        .await
    {
        let current = load_owned_trace(&state, &account_id, &job.trace_id).await?;
        if current.status == "queued" && current.upload_generation == job.upload_generation {
            return Ok(Json(hosted_trace_response(&current, &state.public_origin)));
        }
        if current.upload_generation != job.upload_generation || current.status != "uploading" {
            return Err(ApiError::conflict(
                "hosted Trace upload attempt was superseded while completing",
            ));
        }
        return Err(ApiError::internal(error));
    }
    let promoted = state
        .traces
        .storage
        .head_object(&job.committed_staging_object_key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!(
                "promoted committed staging object is missing"
            ))
        })?;
    if promoted.size_bytes != job.declared_package_size_bytes
        || !TraceStorage::has_expected_metadata(&promoted, &job.declared_package_sha256)
    {
        enqueue_cleanup_direct(
            &state,
            &job.trace_id,
            &job.committed_staging_object_key,
            "staging",
            now,
        )
        .await
        .map_err(database_error)?;
        let _ = cleanup_object(&state, &job.committed_staging_object_key).await;
        return Err(ApiError::internal(anyhow::anyhow!(
            "promoted committed staging object metadata changed"
        )));
    }

    let job = queue_completed_attempt(&state, &account_id, &job, now).await?;
    Ok(Json(hosted_trace_response(&job, &state.public_origin)))
}

#[utoipa::path(
    delete,
    path = "/api/traces/{trace_id}/share",
    summary = "Stop public access to one hosted Trace",
    params(("trace_id" = String, Path)),
    responses(
        (status = 204, description = "Sharing stopped; the owner record and package remain"),
        (status = 401, body = crate::ErrorResponse),
        (status = 403, body = crate::ErrorResponse),
        (status = 404, body = crate::ErrorResponse),
        (status = 409, body = crate::ErrorResponse),
        (status = 500, body = crate::ErrorResponse)
    ),
    security(("bearerAuth" = ["traces:share"]), ("browserSession" = [])),
    tag = "traces"
)]
async fn stop_hosted_trace_sharing(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(trace_id): Path<String>,
) -> ApiResult<StatusCode> {
    let account_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::TracesShare)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let now = unix_timestamp()?;
    let result = sqlx::query(
        "UPDATE traces SET status = 'stopped', updated_at = $1
         WHERE trace_id = $2 AND account_id = $3 AND status = 'shared'",
    )
    .bind(now)
    .bind(&trace_id)
    .bind(&account_id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if result.rows_affected() == 1 {
        return Ok(StatusCode::NO_CONTENT);
    }
    let trace = load_owned_trace(&state, &account_id, &trace_id).await?;
    if trace.status == "stopped" {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::conflict(
            "hosted Trace sharing can be stopped only after verification",
        ))
    }
}

async fn queue_completed_attempt(
    state: &NotaryApiState,
    account_id: &str,
    job: &HostedTraceRow,
    now: i64,
) -> ApiResult<HostedTraceRow> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    let updated = sqlx::query(
        "UPDATE traces
         SET status = 'queued', queued_at = $1, updated_at = $2
         WHERE trace_id = $3 AND account_id = $4 AND status = 'uploading'
           AND upload_generation = $5 AND staging_object_key = $6
           AND committed_staging_object_key = $7 AND upload_expires_at = $8",
    )
    .bind(now)
    .bind(now)
    .bind(&job.trace_id)
    .bind(account_id)
    .bind(job.upload_generation)
    .bind(&job.staging_object_key)
    .bind(&job.committed_staging_object_key)
    .bind(job.upload_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 1 {
        enqueue_cleanup(
            &mut transaction,
            &job.trace_id,
            &job.staging_object_key,
            "staging",
            now,
        )
        .await
        .map_err(database_error)?;
    }
    transaction.commit().await.map_err(database_error)?;
    if updated.rows_affected() != 1 {
        let current = load_owned_trace(state, account_id, &job.trace_id).await?;
        if current.status != "queued" || current.upload_generation != job.upload_generation {
            enqueue_private_cleanup_pair(state, job, now)
                .await
                .map_err(database_error)?;
            let _ = cleanup_object(state, &job.committed_staging_object_key).await;
            let _ = cleanup_object(state, &job.staging_object_key).await;
            return Err(ApiError::conflict(
                "hosted Trace changed while the upload was completing",
            ));
        }
        return Ok(current);
    }
    let _ = cleanup_object(state, &job.staging_object_key).await;
    load_owned_trace(state, account_id, &job.trace_id).await
}

async fn load_trace_by_source(
    state: &NotaryApiState,
    account_id: &str,
    source_trace_id: &str,
) -> ApiResult<HostedTraceRow> {
    sqlx::query_as("SELECT * FROM traces WHERE account_id = $1 AND source_trace_id = $2")
        .bind(account_id)
        .bind(source_trace_id)
        .fetch_one(&state.database)
        .await
        .map_err(database_error)
}

async fn load_owned_trace(
    state: &NotaryApiState,
    account_id: &str,
    job_id: &str,
) -> ApiResult<HostedTraceRow> {
    sqlx::query_as("SELECT * FROM traces WHERE trace_id = $1 AND account_id = $2")
        .bind(job_id)
        .bind(account_id)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::not_found("hosted Trace was not found"))
}

async fn expire_upload(state: &NotaryApiState, job: &HostedTraceRow, now: i64) -> ApiResult<bool> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    let updated = sqlx::query(
        "UPDATE traces
         SET status = 'failed', failure_code = 'upload_expired', updated_at = $1
         WHERE trace_id = $2 AND account_id = $3 AND status = 'uploading'
           AND upload_generation = $4 AND staging_object_key = $5 AND upload_expires_at = $6
           AND upload_expires_at <= $7",
    )
    .bind(now)
    .bind(&job.trace_id)
    .bind(&job.account_id)
    .bind(job.upload_generation)
    .bind(&job.staging_object_key)
    .bind(job.upload_expires_at)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 0 {
        transaction.rollback().await.map_err(database_error)?;
        return Ok(false);
    }
    enqueue_cleanup(
        &mut transaction,
        &job.trace_id,
        &job.staging_object_key,
        "staging",
        now,
    )
    .await
    .map_err(database_error)?;
    enqueue_cleanup(
        &mut transaction,
        &job.trace_id,
        &job.committed_staging_object_key,
        "staging",
        now,
    )
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    let _ = cleanup_object(state, &job.staging_object_key).await;
    let _ = cleanup_object(state, &job.committed_staging_object_key).await;
    Ok(true)
}

async fn cleanup_expired_uploads(state: &NotaryApiState) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let jobs = sqlx::query_as::<_, HostedTraceRow>(
        "SELECT * FROM traces
         WHERE status = 'uploading' AND upload_expires_at <= $1
         ORDER BY upload_expires_at
         LIMIT 100",
    )
    .bind(now)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    for job in jobs {
        let _ = expire_upload(state, &job, now).await?;
    }
    Ok(())
}

pub(crate) async fn cleanup_storage_objects(state: &NotaryApiState) -> ApiResult<()> {
    let objects: Vec<String> = sqlx::query_scalar(
        "SELECT object_key
         FROM storage_cleanup_queue
         ORDER BY attempts, created_at, object_key
         LIMIT $1",
    )
    .bind(OBJECTS_PER_CLEANUP)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?;
    for object_key in objects {
        cleanup_object(state, &object_key)
            .await
            .map_err(database_error)?;
    }
    Ok(())
}

async fn enqueue_cleanup(
    transaction: &mut Transaction<'_, Postgres>,
    trace_id: &str,
    object_key: &str,
    artifact_kind: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO storage_cleanup_queue
             (object_key, trace_id, artifact_kind, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(object_key)
    .bind(trace_id)
    .bind(artifact_kind)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn enqueue_cleanup_direct(
    state: &NotaryApiState,
    trace_id: &str,
    object_key: &str,
    artifact_kind: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO storage_cleanup_queue
             (object_key, trace_id, artifact_kind, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(object_key)
    .bind(trace_id)
    .bind(artifact_kind)
    .bind(now)
    .execute(&state.database)
    .await?;
    Ok(())
}

async fn enqueue_private_cleanup_pair(
    state: &NotaryApiState,
    job: &HostedTraceRow,
    now: i64,
) -> Result<(), sqlx::Error> {
    let mut transaction = state.database.begin().await?;
    enqueue_cleanup(
        &mut transaction,
        &job.trace_id,
        &job.staging_object_key,
        "staging",
        now,
    )
    .await?;
    enqueue_cleanup(
        &mut transaction,
        &job.trace_id,
        &job.committed_staging_object_key,
        "staging",
        now,
    )
    .await?;
    transaction.commit().await
}

pub(super) async fn cleanup_object(
    state: &NotaryApiState,
    object_key: &str,
) -> Result<bool, sqlx::Error> {
    let now = unix_timestamp().map_err(|error| sqlx::Error::Protocol(error.message.into()))?;
    let mut transaction = state.database.begin().await?;
    let queued: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT trace_id FROM storage_cleanup_queue
         WHERE object_key = $1 FOR UPDATE",
    )
    .bind(object_key)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some((trace_id,)) = queued else {
        transaction.commit().await?;
        return Ok(true);
    };
    if let Some(trace_id) = trace_id {
        let trace: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT status, content_object_key, package_object_key
             FROM traces WHERE trace_id = $1 FOR UPDATE",
        )
        .bind(trace_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((status, content_object_key, package_object_key)) = trace {
            if content_object_key.as_deref() == Some(object_key)
                || package_object_key.as_deref() == Some(object_key)
            {
                sqlx::query("DELETE FROM storage_cleanup_queue WHERE object_key = $1")
                    .bind(object_key)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                return Ok(true);
            }
            if status == "verifying" {
                transaction.commit().await?;
                return Ok(false);
            }
        }
    }
    transaction.commit().await?;
    match state.traces.storage.delete_object(object_key).await {
        Ok(()) => {
            sqlx::query("DELETE FROM storage_cleanup_queue WHERE object_key = $1")
                .bind(object_key)
                .execute(&state.database)
                .await?;
            Ok(true)
        }
        Err(_) => {
            sqlx::query(
                "UPDATE storage_cleanup_queue
                 SET attempts = attempts + 1, last_attempt_at = $1
                 WHERE object_key = $2",
            )
            .bind(now)
            .bind(object_key)
            .execute(&state.database)
            .await?;
            Ok(false)
        }
    }
}

pub(super) async fn purge_private_objects(
    state: &NotaryApiState,
    job: &HostedTraceRow,
) -> anyhow::Result<bool> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    enqueue_private_cleanup_pair(state, job, now).await?;
    let _ = cleanup_object(state, &job.staging_object_key).await?;
    let _ = cleanup_object(state, &job.committed_staging_object_key).await?;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM storage_cleanup_queue
             WHERE trace_id = $1 AND artifact_kind = 'staging'
         )",
    )
    .bind(&job.trace_id)
    .fetch_one(&state.database)
    .await?;
    Ok(!pending)
}

fn require_enabled(state: &NotaryApiState) -> ApiResult<()> {
    if state.traces.enabled() {
        Ok(())
    } else {
        Err(ApiError::service_unavailable(
            "hosted Trace storage is not configured",
        ))
    }
}

fn validate_request(service: &TraceService, request: &CreateHostedTraceRequest) -> ApiResult<()> {
    if !request.source_trace_id.starts_with("trc-")
        || request.source_trace_id.len() > 128
        || !request
            .source_trace_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApiError::bad_request("source_trace_id is invalid"));
    }
    if request.package_format != PACKAGE_FORMAT {
        return Err(ApiError::bad_request(
            "package_format is not supported by this server",
        ));
    }
    let max_package_bytes = service
        .max_package_bytes
        .min(notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64);
    if request.package_size_bytes <= 0 || request.package_size_bytes > max_package_bytes {
        return Err(ApiError::bad_request(
            "package_size_bytes is outside the accepted range",
        ));
    }
    if request.package_sha256.len() != 64
        || !request
            .package_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad_request(
            "package_sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn idempotency_key(headers: &HeaderMap) -> ApiResult<String> {
    let value = headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Idempotency-Key header is required"))?;
    if !(16..=200).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ApiError::bad_request(
            "Idempotency-Key must contain 16 to 200 safe ASCII characters",
        ));
    }
    Ok(value.to_owned())
}

fn hosted_trace_response(job: &HostedTraceRow, public_origin: &url::Url) -> HostedTrace {
    let visibility = match job.visibility.as_str() {
        "listed" => TraceVisibility::Listed,
        _ => TraceVisibility::Unlisted,
    };
    let access_active = job
        .access_expires_at
        .is_none_or(|expires_at| unix_timestamp().is_ok_and(|now| expires_at > now));
    let live = job.status == "shared" && access_active;
    let status = match job.status.as_str() {
        "shared" => HostedTraceStatus::Shared,
        "stopped" => HostedTraceStatus::Stopped,
        "rejected" => HostedTraceStatus::Rejected,
        "failed" => HostedTraceStatus::Failed,
        _ => HostedTraceStatus::Verifying,
    };
    HostedTrace {
        trace_id: job.trace_id.clone(),
        source_trace_id: job.source_trace_id.clone(),
        status,
        access: TraceAccessSettings {
            visibility,
            password_protected: job.access_password_hash.is_some(),
            expires_at: job.access_expires_at,
        },
        package: HostedTracePackage {
            format: job.package_format.clone(),
            declared_size_bytes: job.declared_package_size_bytes,
            declared_sha256: job.declared_package_sha256.clone(),
            admitted_size_bytes: job.admitted_package_size_bytes,
            admitted_sha256: job.admitted_package_sha256.clone(),
        },
        verification: HostedTraceVerification {
            verified_at: job.verified_at,
            failure_code: job.failure_code.clone(),
        },
        allow_high_entropy: job.allow_high_entropy,
        created_at: job.created_at,
        updated_at: job.updated_at,
        status_url: format!("/api/traces/{}", job.trace_id),
        public_url: live.then(|| {
            public_origin
                .join(&format!("/s/{}", job.trace_id))
                .expect("public Trace path is a valid same-origin URL")
                .to_string()
        }),
        package_url: (live && job.package_object_key.is_some())
            .then(|| format!("/api/public/traces/{}/package.llmtrace", job.trace_id)),
        owner_package_url: job
            .package_object_key
            .is_some()
            .then(|| format!("/api/traces/{}/package.llmtrace", job.trace_id)),
    }
}

fn expires_at_from_days(days: Option<u32>, now: i64) -> ApiResult<Option<i64>> {
    match days {
        Some(0) | None => Ok(None),
        Some(days) if days <= MAX_TRACE_ACCESS_EXPIRY_DAYS => now
            .checked_add(i64::from(days) * 24 * 60 * 60)
            .map(Some)
            .ok_or_else(|| ApiError::bad_request("Trace expiry is outside the accepted range")),
        Some(_) => Err(ApiError::bad_request(
            "expires_in_days must be between 0 and 365",
        )),
    }
}

async fn hash_trace_access_password(password: String) -> ApiResult<String> {
    if !(MIN_TRACE_PASSWORD_BYTES..=MAX_TRACE_PASSWORD_BYTES).contains(&password.len()) {
        return Err(ApiError::bad_request(
            "password must contain between 8 and 128 bytes",
        ));
    }
    run_password_work(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| ApiError::internal(anyhow::anyhow!(error)))
    })
    .await?
}

pub(super) async fn run_password_work<T, F>(work: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_password_work_with_capacity(TRACE_PASSWORD_CAPACITY.clone(), work).await
}

pub(super) async fn run_password_work_with_capacity<T, F>(
    capacity: Arc<Semaphore>,
    work: F,
) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let _capacity = capacity.try_acquire_owned().map_err(|_| {
        ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            "trace_password_capacity",
            "Password processing is busy; try again shortly",
        )
    })?;
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| ApiError::internal(error.into()))
}

async fn enforce_password_change_limit(
    state: &NotaryApiState,
    account_id: &str,
    now: i64,
) -> ApiResult<()> {
    let window_reset_before = now - TRACE_PASSWORD_CHANGE_WINDOW_SECS;
    let request_count = sqlx::query_scalar::<_, i64>(
        "INSERT INTO trace_access_change_limits
             (account_id, window_started_at, request_count, updated_at)
         VALUES ($1, $2, 1, $2)
         ON CONFLICT (account_id) DO UPDATE
         SET window_started_at = CASE
                 WHEN trace_access_change_limits.window_started_at <= $3 THEN $2
                 ELSE trace_access_change_limits.window_started_at
             END,
             request_count = CASE
                 WHEN trace_access_change_limits.window_started_at <= $3 THEN 1
                 ELSE trace_access_change_limits.request_count + 1
             END,
             updated_at = $2
         WHERE trace_access_change_limits.window_started_at <= $3
            OR trace_access_change_limits.request_count < $4
         RETURNING request_count",
    )
    .bind(account_id)
    .bind(now)
    .bind(window_reset_before)
    .bind(TRACE_PASSWORD_CHANGE_LIMIT)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    if request_count.is_none() {
        return Err(ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            "trace_password_change_rate_limited",
            "Too many password changes were requested for this account",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::Cookie;
    use url::Url;

    use super::*;
    use crate::traces::storage::{MockTraceStorage, StoredObject};

    const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn trace_storage_quota_accepts_the_boundary_and_unlimited_plan() {
        assert!(trace_storage_allows(Some(1_000), 750, 250));
        assert!(!trace_storage_allows(Some(1_000), 750, 251));
        assert!(trace_storage_allows(None, i64::MAX, i64::MAX));
    }

    async fn test_state() -> (NotaryApiState, MockTraceStorage, HeaderMap, HeaderMap) {
        let database = crate::fresh_database().await;
        crate::insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        crate::insert_test_github_user(&database.pool, "user-2", 2, "two").await;
        let now = unix_timestamp().expect("time");
        let tokens_one = crate::issue_device_session(&database, "user-1", "One", now)
            .await
            .expect("session one");
        let tokens_two = crate::issue_device_session(&database, "user-2", "Two", now)
            .await
            .expect("session two");
        let headers = |token: String| {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("authorization"),
            );
            headers.insert(
                IDEMPOTENCY_KEY_HEADER,
                "01234567-89ab-cdef-0123-456789abcdef"
                    .parse()
                    .expect("idempotency key"),
            );
            headers
        };
        let storage = MockTraceStorage::new();
        let state = NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .expect("callback"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .expect("Google callback"),
            public_origin: Url::parse("https://notary.exalto.ai").expect("app"),
            secure_cookies: true,
            registry: crate::tests::test_registry(),
            traces: TraceService::mock(storage.clone()),
            admission: std::sync::Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        };
        (
            state,
            storage,
            headers(tokens_one.access_token),
            headers(tokens_two.access_token),
        )
    }

    fn request() -> CreateHostedTraceRequest {
        CreateHostedTraceRequest {
            source_trace_id: "trc-source-test".to_owned(),
            package_format: PACKAGE_FORMAT.to_owned(),
            package_size_bytes: 1234,
            package_sha256: SHA256.to_owned(),
            visibility: TraceVisibility::Unlisted,
            password: None,
            expires_in_days: None,
            allow_high_entropy: false,
        }
    }

    fn completion_request(job: &HostedTraceRow) -> CompleteHostedTraceUploadRequest {
        CompleteHostedTraceUploadRequest {
            package_size_bytes: job.declared_package_size_bytes,
            package_sha256: job.declared_package_sha256.clone(),
        }
    }

    #[tokio::test]
    async fn durable_content_cleanup_is_bounded_and_retryable() {
        let (state, storage, _, _) = test_state().await;
        let object_key = "test/content/trc-cleanup/deadbeef.json";
        storage.object_bytes(object_key, b"committed content".to_vec());
        storage.fail_delete(object_key);
        sqlx::query(
            "INSERT INTO storage_cleanup_queue
                 (object_key, trace_id, artifact_kind, created_at)
             VALUES ($1, NULL, 'content', 1)",
        )
        .bind(object_key)
        .execute(&state.database)
        .await
        .unwrap();

        cleanup_storage_objects(&state).await.unwrap();
        let attempts: i64 =
            sqlx::query_scalar("SELECT attempts FROM storage_cleanup_queue WHERE object_key = $1")
                .bind(object_key)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(attempts, 1);

        storage.delete_failures.lock().unwrap().remove(object_key);
        cleanup_storage_objects(&state).await.unwrap();
        assert!(
            storage
                .deleted
                .lock()
                .unwrap()
                .contains(&object_key.to_owned())
        );
    }

    #[tokio::test]
    async fn completed_upload_cleanup_is_durable_across_delete_failures() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(
            &job.staging_object_key,
            job.declared_package_size_bytes,
            SHA256,
        );
        storage.fail_delete(&job.staging_object_key);

        let _ = complete_hosted_trace_upload(
            State(state.clone()),
            headers,
            Path(job.trace_id.clone()),
            Json(completion_request(&job)),
        )
        .await
        .expect("complete despite deferred cleanup");
        let queued: (String, i64) = sqlx::query_as(
            "SELECT artifact_kind, attempts FROM storage_cleanup_queue
             WHERE object_key = $1",
        )
        .bind(&job.staging_object_key)
        .fetch_one(&state.database)
        .await
        .expect("durable upload cleanup");
        assert_eq!(queued, ("staging".to_owned(), 1));
        assert!(
            storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.staging_object_key)
        );

        storage
            .delete_failures
            .lock()
            .unwrap()
            .remove(&job.staging_object_key);
        cleanup_storage_objects(&state).await.unwrap();
        assert!(
            !storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.staging_object_key)
        );
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM storage_cleanup_queue WHERE object_key = $1")
                .bind(&job.staging_object_key)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    async fn expired_upload_cleanup_is_durable_across_delete_failures() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers, Json(request()))
            .await
            .expect("create");
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(
            &job.staging_object_key,
            job.declared_package_size_bytes,
            SHA256,
        );
        storage.fail_delete(&job.staging_object_key);

        assert!(expire_upload(&state, &job, i64::MAX).await.unwrap());
        let attempts: i64 =
            sqlx::query_scalar("SELECT attempts FROM storage_cleanup_queue WHERE object_key = $1")
                .bind(&job.staging_object_key)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(attempts, 1);

        storage
            .delete_failures
            .lock()
            .unwrap()
            .remove(&job.staging_object_key);
        cleanup_storage_objects(&state).await.unwrap();
        assert!(
            !storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.staging_object_key)
        );
    }

    #[tokio::test]
    async fn create_is_idempotent_and_scoped_to_the_device_user() {
        let (state, _storage, headers_one, mut headers_two) = test_state().await;
        let first = create_hosted_trace(State(state.clone()), headers_one.clone(), Json(request()))
            .await
            .expect("first create");
        assert_eq!(first.status(), StatusCode::CREATED);
        let second =
            create_hosted_trace(State(state.clone()), headers_one.clone(), Json(request()))
                .await
                .expect("idempotent create");
        assert_eq!(second.status(), StatusCode::OK);
        let mut different_source = request();
        different_source.source_trace_id = "trc-different-source".to_owned();
        let key_conflict = create_hosted_trace(
            State(state.clone()),
            headers_one.clone(),
            Json(different_source),
        )
        .await;
        assert!(matches!(
            key_conflict,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let mut forced = request();
        forced.allow_high_entropy = true;
        let force_conflict =
            create_hosted_trace(State(state.clone()), headers_one.clone(), Json(forced)).await;
        assert!(matches!(
            force_conflict,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let mut changed = request();
        changed.package_size_bytes += 1;
        let conflict = create_hosted_trace(State(state.clone()), headers_one, Json(changed)).await;
        assert!(matches!(
            conflict,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));

        headers_two.insert(
            IDEMPOTENCY_KEY_HEADER,
            "fedcba98-7654-3210-fedc-ba9876543210"
                .parse()
                .expect("idempotency key"),
        );
        let other = create_hosted_trace(State(state.clone()), headers_two, Json(request()))
            .await
            .expect("other user create");
        assert_eq!(other.status(), StatusCode::CREATED);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job count");
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn web_users_list_only_their_traces() {
        let (state, _storage, headers_one, headers_two) = test_state().await;
        let with_key = |headers: &HeaderMap, key: &'static str| {
            let mut headers = headers.clone();
            headers.insert(
                IDEMPOTENCY_KEY_HEADER,
                key.parse().expect("idempotency key"),
            );
            headers
        };
        create_hosted_trace(State(state.clone()), headers_one.clone(), Json(request()))
            .await
            .expect("own hosted Trace");
        create_hosted_trace(State(state.clone()), headers_two, Json(request()))
            .await
            .expect("other hosted Trace");
        for key in [
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        ] {
            let mut additional = request();
            additional.source_trace_id = format!("trc-source-{key}");
            create_hosted_trace(
                State(state.clone()),
                with_key(&headers_one, key),
                Json(additional),
            )
            .await
            .expect("additional own hosted Trace");
        }
        let expected_ids: std::collections::BTreeSet<String> =
            sqlx::query_scalar("SELECT trace_id FROM traces WHERE account_id = 'user-1'")
                .fetch_all(&state.database)
                .await
                .expect("own hosted Trace IDs")
                .into_iter()
                .collect();

        let now = unix_timestamp().expect("time");
        let web_token = "web-trace-session";
        sqlx::query(
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, $3)",
        )
        .bind(notary_core::sha256_hex(web_token.as_bytes()))
        .bind(now + crate::SESSION_TTL_SECS)
        .bind(now)
        .execute(&state.database)
        .await
        .expect("web session");
        let jar = CookieJar::new().add(Cookie::new(crate::SESSION_COOKIE, web_token.to_owned()));

        let first = list_web_traces(
            State(state.clone()),
            HeaderMap::new(),
            jar.clone(),
            Ok(Query(PageQuery {
                limit: Some(2),
                cursor: None,
            })),
        )
        .await
        .expect("hosted Traces");
        assert_eq!(first.0.items.len(), 2);
        let cursor = first.0.next_cursor.clone().expect("second page cursor");

        let concurrent_key = "44444444-4444-4444-4444-444444444444";
        let mut concurrent = request();
        concurrent.source_trace_id = "trc-source-concurrent".to_owned();
        create_hosted_trace(
            State(state.clone()),
            with_key(&headers_one, concurrent_key),
            Json(concurrent),
        )
        .await
        .expect("concurrent own hosted Trace");
        sqlx::query(
            "UPDATE traces SET created_at = $1
             WHERE account_id = 'user-1' AND idempotency_key = $2",
        )
        .bind(now + 100)
        .bind(concurrent_key)
        .execute(&state.database)
        .await
        .expect("move concurrent job above cursor boundary");

        let second = list_web_traces(
            State(state),
            HeaderMap::new(),
            jar,
            Ok(Query(PageQuery {
                limit: Some(2),
                cursor: Some(cursor),
            })),
        )
        .await
        .expect("second hosted Traces page");
        assert_eq!(second.0.items.len(), 2);
        assert!(second.0.next_cursor.is_none());
        let actual_ids = first
            .0
            .items
            .into_iter()
            .chain(second.0.items)
            .map(|trace| trace.trace_id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_ids, expected_ids);
    }

    #[tokio::test]
    async fn completion_promotes_then_queues_an_immutable_committed_staging_object() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(
            &job.staging_object_key,
            job.declared_package_size_bytes,
            SHA256,
        );

        let completed = complete_hosted_trace_upload(
            State(state.clone()),
            headers.clone(),
            Path(job.trace_id.clone()),
            Json(completion_request(&job)),
        )
        .await
        .expect("complete");
        assert_eq!(completed.0.status, HostedTraceStatus::Verifying);
        assert!(
            storage
                .objects
                .lock()
                .expect("mock lock")
                .contains_key(&job.committed_staging_object_key)
        );
        assert!(
            !storage
                .objects
                .lock()
                .expect("mock lock")
                .contains_key(&job.staging_object_key)
        );

        let completion = completion_request(&job);
        let retried = complete_hosted_trace_upload(
            State(state),
            headers,
            Path(job.trace_id),
            Json(completion),
        )
        .await
        .expect("idempotent complete");
        assert_eq!(retried.0.status, HostedTraceStatus::Verifying);
    }

    #[tokio::test]
    async fn completion_rejects_missing_or_mismatched_objects_without_queueing() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job");
        let missing = complete_hosted_trace_upload(
            State(state.clone()),
            headers.clone(),
            Path(job.trace_id.clone()),
            Json(completion_request(&job)),
        )
        .await;
        assert!(matches!(
            missing,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        storage.objects.lock().expect("mock lock").insert(
            job.staging_object_key.clone(),
            StoredObject {
                size_bytes: job.declared_package_size_bytes + 1,
                metadata: BTreeMap::new(),
            },
        );
        let mismatched = complete_hosted_trace_upload(
            State(state.clone()),
            headers,
            Path(job.trace_id.clone()),
            Json(completion_request(&job)),
        )
        .await;
        assert!(matches!(
            mismatched,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let state_value: String =
            sqlx::query_scalar("SELECT status FROM traces WHERE trace_id = $1")
                .bind(job.trace_id)
                .fetch_one(&state.database)
                .await
                .expect("state");
        assert_eq!(state_value, "uploading");
    }

    #[tokio::test]
    async fn users_cannot_read_or_complete_each_others_jobs() {
        let (state, _storage, headers_one, headers_two) = test_state().await;
        create_hosted_trace(State(state.clone()), headers_one, Json(request()))
            .await
            .expect("create");
        let job_id: String = sqlx::query_scalar("SELECT trace_id FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job ID");
        let read = get_hosted_trace(
            State(state.clone()),
            headers_two.clone(),
            CookieJar::new(),
            Path(job_id.clone()),
        )
        .await;
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces WHERE trace_id = $1")
            .bind(&job_id)
            .fetch_one(&state.database)
            .await
            .expect("hosted Trace");
        let complete = complete_hosted_trace_upload(
            State(state),
            headers_two,
            Path(job_id),
            Json(completion_request(&job)),
        )
        .await;
        assert!(matches!(
            read,
            Err(ApiError {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ));
        assert!(matches!(
            complete,
            Err(ApiError {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn cleanup_expires_jobs_and_removes_staging_objects() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers, Json(request()))
            .await
            .expect("create");
        let job: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(
            &job.staging_object_key,
            job.declared_package_size_bytes,
            SHA256,
        );
        sqlx::query("UPDATE traces SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire job");

        cleanup_expired_uploads(&state).await.expect("cleanup");
        let state_value: String =
            sqlx::query_scalar("SELECT status FROM traces WHERE trace_id = $1")
                .bind(&job.trace_id)
                .fetch_one(&state.database)
                .await
                .expect("state");
        assert_eq!(state_value, "failed");
        assert!(
            storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&job.staging_object_key)
        );
    }

    #[tokio::test]
    async fn identical_trace_request_reopens_an_expired_upload_without_duplicate_jobs() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let first: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("first job");
        storage.object(
            &first.staging_object_key,
            first.declared_package_size_bytes,
            SHA256,
        );
        sqlx::query("UPDATE traces SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");

        let mut retry = request();
        retry.visibility = TraceVisibility::Listed;
        retry.password = Some("replacement-password".to_owned());
        retry.expires_in_days = Some(30);
        let response = create_hosted_trace(State(state.clone()), headers, Json(retry))
            .await
            .expect("retry expired upload");
        assert_eq!(response.status(), StatusCode::CREATED);
        let retried: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("retried job");
        assert_eq!(retried.trace_id, first.trace_id);
        assert_eq!(retried.status, "uploading");
        assert_eq!(retried.visibility, "listed");
        assert!(retried.access_password_hash.is_some());
        assert!(retried.access_expires_at.is_some_and(|expiry| expiry > 1));
        assert_ne!(retried.staging_object_key, first.staging_object_key);
        assert!(retried.upload_expires_at > 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM traces")
                .fetch_one(&state.database)
                .await
                .expect("job count"),
            1
        );
        assert!(
            storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&first.staging_object_key)
        );
    }

    #[tokio::test]
    async fn stopped_reactivation_uses_patch_semantics_for_access_controls() {
        let (state, _storage, headers, _) = test_state().await;
        let mut initial = request();
        initial.visibility = TraceVisibility::Listed;
        initial.password = Some("initial-password".to_owned());
        initial.expires_in_days = Some(7);
        create_hosted_trace(State(state.clone()), headers.clone(), Json(initial))
            .await
            .expect("create protected Trace");
        sqlx::query(
            "UPDATE traces SET status = 'stopped',
             verified_at = 1,
             admitted_package_size_bytes = declared_package_size_bytes,
             admitted_package_sha256 = declared_package_sha256,
             package_object_key = 'package-key',
             package_size_bytes = declared_package_size_bytes,
             package_sha256 = declared_package_sha256,
             content_object_key = 'content-key', content_size_bytes = 1,
             content_sha256 = $1, disclosure_safety_version = $2",
        )
        .bind("b".repeat(64))
        .bind(notary_core::public_safety::PUBLIC_PACKAGE_SAFETY_VERSION)
        .execute(&state.database)
        .await
        .expect("prepare stopped Trace");
        let stopped: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("stopped Trace");

        let mut keep = request();
        keep.visibility = TraceVisibility::Unlisted;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(keep))
            .await
            .expect("reactivate while keeping controls");
        let kept: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("reactivated Trace");
        assert_eq!(kept.trace_id, stopped.trace_id);
        assert_eq!(kept.status, "shared");
        assert_eq!(kept.visibility, "unlisted");
        assert_eq!(kept.access_password_hash, stopped.access_password_hash);
        assert_eq!(kept.access_expires_at, stopped.access_expires_at);

        sqlx::query("UPDATE traces SET status = 'stopped'")
            .execute(&state.database)
            .await
            .expect("stop again");
        let mut clear = request();
        clear.password = Some(String::new());
        clear.expires_in_days = Some(0);
        create_hosted_trace(State(state.clone()), headers, Json(clear))
            .await
            .expect("reactivate with explicit clears");
        let cleared: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("cleared Trace");
        assert_eq!(cleared.status, "shared");
        assert!(cleared.access_password_hash.is_none());
        assert!(cleared.access_expires_at.is_none());
    }

    #[tokio::test]
    async fn reviewed_high_entropy_rejection_can_reopen_one_upload_attempt() {
        let (state, _storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create hosted Trace");
        let original: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("original upload");
        sqlx::query(
            "UPDATE traces
             SET status = 'rejected', failure_code = 'high_entropy_value_trace',
                 admitted_package_size_bytes = declared_package_size_bytes,
                 admitted_package_sha256 = declared_package_sha256,
                 staging_purged_at = 1
             WHERE trace_id = $1",
        )
        .bind(&original.trace_id)
        .execute(&state.database)
        .await
        .expect("reject high-entropy package");

        let mut forced = request();
        forced.allow_high_entropy = true;
        let response = create_hosted_trace(State(state.clone()), headers, Json(forced))
            .await
            .expect("reopen reviewed upload");
        assert_eq!(response.status(), StatusCode::CREATED);
        let reopened: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("reopened upload");
        assert_eq!(reopened.trace_id, original.trace_id);
        assert_eq!(reopened.status, "uploading");
        assert!(reopened.allow_high_entropy);
        assert_eq!(reopened.upload_generation, original.upload_generation + 1);
        assert!(reopened.admitted_package_size_bytes.is_none());
        assert!(reopened.admitted_package_sha256.is_none());
        assert_ne!(reopened.staging_object_key, original.staging_object_key);
    }

    #[tokio::test]
    async fn owner_package_export_returns_exact_bytes_without_public_access() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create hosted Trace");
        let trace: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("hosted Trace row");
        let package = b"exact owner package bytes".to_vec();
        let sha256 = notary_core::sha256_hex(&package);
        let object_key = "account/user-1/packages/owner-package.llmtrace";
        storage.object_bytes(object_key, package.clone());
        sqlx::query(
            "UPDATE traces
             SET status = 'stopped', package_object_key = $1,
                 admitted_package_size_bytes = $2, admitted_package_sha256 = $3,
                 package_size_bytes = $2, package_sha256 = $3,
                 verified_at = 1,
                 content_object_key = 'owner-content', content_size_bytes = 1,
                 content_sha256 = $5, disclosure_safety_version = $6,
                 access_password_hash = 'protected'
             WHERE trace_id = $4",
        )
        .bind(object_key)
        .bind(i64::try_from(package.len()).unwrap())
        .bind(&sha256)
        .bind(&trace.trace_id)
        .bind("b".repeat(64))
        .bind(notary_core::public_safety::PUBLIC_PACKAGE_SAFETY_VERSION)
        .execute(&state.database)
        .await
        .expect("prepare owned package");

        let response = download_owned_trace_package(
            State(state),
            headers,
            CookieJar::new(),
            Path(trace.trace_id.clone()),
        )
        .await
        .expect("download owned package");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-content-sha256"], sha256);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_DISPOSITION],
            format!("attachment; filename=\"{}.llmtrace\"", trace.trace_id)
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("package body"),
            package
        );
    }

    #[tokio::test]
    async fn stale_expiration_cannot_cancel_a_reopened_upload_generation() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        sqlx::query("UPDATE traces SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");
        let stale: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("stale generation");
        assert!(expire_upload(&state, &stale, 2).await.unwrap());

        create_hosted_trace(State(state.clone()), headers, Json(request()))
            .await
            .expect("reopen");
        let reopened: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("reopened generation");
        assert_eq!(reopened.status, "uploading");
        assert_ne!(reopened.staging_object_key, stale.staging_object_key);

        assert!(!expire_upload(&state, &stale, i64::MAX).await.unwrap());
        let current: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("current generation");
        assert_eq!(current.status, "uploading");
        assert_eq!(current.staging_object_key, reopened.staging_object_key);
        assert!(
            !storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&reopened.staging_object_key)
        );
    }

    #[tokio::test]
    async fn stale_completion_cannot_queue_or_overwrite_a_reopened_generation() {
        let (state, storage, headers, _) = test_state().await;
        create_hosted_trace(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        sqlx::query("UPDATE traces SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");
        let stale: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("stale generation");
        assert!(expire_upload(&state, &stale, 2).await.unwrap());
        create_hosted_trace(State(state.clone()), headers, Json(request()))
            .await
            .expect("reopen");
        let current: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("current generation");
        assert_eq!(current.upload_generation, stale.upload_generation + 1);
        assert_ne!(
            current.committed_staging_object_key,
            stale.committed_staging_object_key
        );

        storage.object(
            &stale.committed_staging_object_key,
            stale.declared_package_size_bytes,
            SHA256,
        );
        assert!(
            queue_completed_attempt(&state, &stale.account_id, &stale, 3)
                .await
                .is_err()
        );
        let still_current: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("still current");
        assert_eq!(still_current.status, "uploading");
        assert_eq!(still_current.upload_generation, current.upload_generation);

        storage.object(
            &current.committed_staging_object_key,
            current.declared_package_size_bytes,
            SHA256,
        );
        let queued = queue_completed_attempt(&state, &current.account_id, &current, 4)
            .await
            .expect("queue current generation");
        assert_eq!(queued.status, "queued");

        storage.object(
            &stale.committed_staging_object_key,
            stale.declared_package_size_bytes,
            SHA256,
        );
        assert!(
            queue_completed_attempt(&state, &stale.account_id, &stale, 5)
                .await
                .is_err()
        );
        let remains_queued: HostedTraceRow = sqlx::query_as("SELECT * FROM traces")
            .fetch_one(&state.database)
            .await
            .expect("queued generation");
        assert_eq!(remains_queued.status, "queued");
        assert_eq!(remains_queued.upload_generation, current.upload_generation);
        assert!(
            storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&stale.committed_staging_object_key)
        );
        assert!(
            !storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&current.committed_staging_object_key)
        );
    }

    #[test]
    fn hosted_trace_requests_are_bounded_and_versioned() {
        let storage = MockTraceStorage::new();
        let service = TraceService::mock(storage);
        assert!(validate_request(&service, &request()).is_ok());
        let mut unsupported = request();
        unsupported.package_format = "future/v2".to_owned();
        assert!(validate_request(&service, &unsupported).is_err());
        let mut too_large = request();
        too_large.package_size_bytes = DEFAULT_MAX_PACKAGE_BYTES + 1;
        assert!(validate_request(&service, &too_large).is_err());
        let mut uppercase_hash = request();
        uppercase_hash.package_sha256 = SHA256.to_uppercase();
        assert!(validate_request(&service, &uppercase_hash).is_err());
    }

    #[tokio::test]
    async fn access_password_hashes_are_salted_and_bounded() {
        let first = hash_trace_access_password("long-enough-password".to_owned())
            .await
            .unwrap();
        let second = hash_trace_access_password("long-enough-password".to_owned())
            .await
            .unwrap();
        assert_ne!(first, second);
        assert!(
            hash_trace_access_password("short".to_owned())
                .await
                .is_err()
        );
        assert!(hash_trace_access_password("x".repeat(129)).await.is_err());
    }
}
