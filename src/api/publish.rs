use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, authenticated_web_user, bearer_token, database_error,
    intake::{ARCHIVE_FORMAT, IntakeStorage},
    unix_timestamp,
};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const DEFAULT_MAX_ARCHIVE_BYTES: i64 = 128 * 1024 * 1024;
const DEFAULT_UPLOAD_TTL_SECS: i64 = 15 * 60;
const CLEANUP_INTERVAL_SECS: u64 = 10 * 60;

#[derive(Clone)]
pub struct PublishService {
    pub(super) storage: IntakeStorage,
    pub(super) max_archive_bytes: i64,
    upload_ttl_secs: i64,
    pub(super) platform_signing_key: Option<Arc<SigningKey>>,
    pub(super) stamp_issuer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishJob {
    archive_format: String,
    size_bytes: i64,
    sha256: String,
}

#[derive(Serialize)]
struct CreatePublishJobResponse {
    job: PublishJobResponse,
    upload: Option<UploadInstructions>,
}

#[derive(Serialize)]
struct WebPublishJobsResponse {
    jobs: Vec<PublishJobResponse>,
}

#[derive(Serialize)]
struct UploadInstructions {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    expires_at: i64,
}

#[derive(Serialize)]
struct PublishJobResponse {
    id: String,
    state: String,
    archive_format: String,
    size_bytes: i64,
    sha256: String,
    created_at: i64,
    updated_at: i64,
    upload_expires_at: i64,
    queued_at: Option<i64>,
    admitted_at: Option<i64>,
    private_purged_at: Option<i64>,
    failure_code: Option<String>,
    status_url: String,
    trace_url: Option<String>,
    stamp_url: Option<String>,
}

#[derive(FromRow)]
pub(super) struct PublishJobRow {
    pub(super) id: String,
    pub(super) user_id: String,
    pub(super) state: String,
    pub(super) archive_format: String,
    pub(super) declared_size_bytes: i64,
    pub(super) declared_sha256: String,
    pub(super) upload_object_key: String,
    pub(super) intake_object_key: String,
    pub(super) upload_expires_at: i64,
    pub(super) upload_generation: i64,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) queued_at: Option<i64>,
    pub(super) failure_code: Option<String>,
    pub(super) admitted_at: Option<i64>,
    pub(super) private_purged_at: Option<i64>,
}

impl PublishService {
    pub fn from_env(stamp_issuer: String) -> anyhow::Result<Self> {
        let max_archive_bytes =
            integer_env("LLM_NOTARY_INTAKE_MAX_BYTES")?.unwrap_or(DEFAULT_MAX_ARCHIVE_BYTES);
        if max_archive_bytes <= 0 {
            anyhow::bail!("LLM_NOTARY_INTAKE_MAX_BYTES must be positive");
        }
        let upload_ttl_secs =
            integer_env("LLM_NOTARY_INTAKE_UPLOAD_TTL_SECS")?.unwrap_or(DEFAULT_UPLOAD_TTL_SECS);
        if !(60..=24 * 60 * 60).contains(&upload_ttl_secs) {
            anyhow::bail!("LLM_NOTARY_INTAKE_UPLOAD_TTL_SECS must be between 60 and 86400 seconds");
        }
        let storage = IntakeStorage::from_env()?;
        let (platform_signing_key, stamp_issuer) = if storage.is_enabled() {
            (Some(Arc::new(load_platform_signing_key()?)), stamp_issuer)
        } else {
            (None, String::new())
        };
        Ok(Self {
            storage,
            max_archive_bytes,
            upload_ttl_secs,
            platform_signing_key,
            stamp_issuer,
        })
    }

    pub fn enabled(&self) -> bool {
        self.storage.is_enabled()
    }

    pub async fn validate(&self) -> anyhow::Result<()> {
        self.storage.validate().await
    }

    #[cfg(test)]
    pub(super) fn mock(storage: super::intake::MockIntakeStorage) -> Self {
        Self {
            storage: IntakeStorage::Mock(storage),
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
            platform_signing_key: Some(Arc::new(
                SigningKey::from_slice(&[11; 32]).expect("test platform key"),
            )),
            stamp_issuer: "https://llmnotary.example".to_owned(),
        }
    }

    #[cfg(test)]
    pub fn disabled_for_test() -> Self {
        Self {
            storage: IntakeStorage::Disabled,
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
            platform_signing_key: None,
            stamp_issuer: String::new(),
        }
    }
}

fn load_platform_signing_key() -> anyhow::Result<SigningKey> {
    let path = std::env::var("LLM_NOTARY_PLATFORM_SIGNING_KEY_FILE").map_err(|_| {
        anyhow::anyhow!(
            "LLM_NOTARY_PLATFORM_SIGNING_KEY_FILE is required when publication intake is enabled"
        )
    })?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading platform signing key {path}"))?;
    let bytes = hex::decode(text.trim()).context("platform signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        anyhow::bail!("platform signing key must contain exactly 32 bytes");
    }
    SigningKey::from_slice(&bytes).context("platform signing key is invalid")
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/publish/jobs", post(create_publish_job))
        .route("/api/publish/jobs/{job_id}", get(get_publish_job))
        .route("/api/me/publish-jobs", get(list_web_publish_jobs))
        .route(
            "/api/publish/jobs/{job_id}/complete",
            post(complete_publish_job),
        )
}

pub fn spawn_cleanup(state: AppState) {
    if !state.publish.enabled() {
        tracing::warn!("publication intake is disabled; publish endpoints will return 503");
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(error) = cleanup_expired_uploads(&state).await {
                tracing::error!(
                    status = %error.status,
                    error = error.message,
                    "cleaning up expired publication uploads failed"
                );
            }
        }
    });
}

async fn create_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePublishJob>,
) -> ApiResult<Response> {
    require_enabled(&state)?;
    validate_request(&state.publish, &request)?;
    let user_id = authenticated_cli_user_id(&state, &headers).await?;
    let idempotency_key = idempotency_key(&headers)?;
    let now = unix_timestamp()?;
    let job_id = Uuid::new_v4().to_string();
    let upload_nonce = Uuid::new_v4().simple().to_string();
    let upload_object_key = state
        .publish
        .storage
        .upload_object_key(&user_id, &job_id, &upload_nonce)
        .map_err(ApiError::internal)?;
    let intake_object_key = state
        .publish
        .storage
        .intake_object_key(&user_id, &job_id, 0)
        .map_err(ApiError::internal)?;
    let upload_expires_at = now + state.publish.upload_ttl_secs;
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO publish_jobs
         (id, user_id, idempotency_key, state, archive_format, declared_size_bytes,
          declared_sha256, upload_object_key, intake_object_key, upload_expires_at,
          created_at, updated_at)
         VALUES (?, ?, ?, 'uploading', ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&job_id)
    .bind(&user_id)
    .bind(&idempotency_key)
    .bind(&request.archive_format)
    .bind(request.size_bytes)
    .bind(&request.sha256)
    .bind(upload_object_key)
    .bind(intake_object_key)
    .bind(upload_expires_at)
    .bind(now)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;

    let mut job = load_job_by_idempotency(&state, &user_id, &idempotency_key).await?;
    if job.archive_format != request.archive_format
        || job.declared_size_bytes != request.size_bytes
        || job.declared_sha256 != request.sha256
    {
        return Err(ApiError::conflict(
            "idempotency key was already used with different archive metadata",
        ));
    }
    if job.state == "uploading" && job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        job = load_job_by_idempotency(&state, &user_id, &idempotency_key).await?;
    }
    let mut reopened = false;
    if job.state == "expired" {
        let retry_nonce = Uuid::new_v4().simple().to_string();
        let retry_upload_key = state
            .publish
            .storage
            .upload_object_key(&user_id, &job.id, &retry_nonce)
            .map_err(ApiError::internal)?;
        let retry_intake_key = state
            .publish
            .storage
            .intake_object_key(&user_id, &job.id, job.upload_generation + 1)
            .map_err(ApiError::internal)?;
        let reset = sqlx::query(
            "UPDATE publish_jobs
             SET state = 'uploading', upload_object_key = ?, intake_object_key = ?,
                 upload_expires_at = ?, upload_generation = upload_generation + 1,
                 updated_at = ?, failure_code = NULL
             WHERE id = ? AND user_id = ? AND state = 'expired'
               AND upload_generation = ?",
        )
        .bind(retry_upload_key)
        .bind(retry_intake_key)
        .bind(upload_expires_at)
        .bind(now)
        .bind(&job.id)
        .bind(&user_id)
        .bind(job.upload_generation)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
        reopened = reset.rows_affected() == 1;
        job = load_job_by_idempotency(&state, &user_id, &idempotency_key).await?;
    }
    let upload = if job.state == "uploading" {
        let presigned = state
            .publish
            .storage
            .presign_upload(
                &job.upload_object_key,
                job.declared_size_bytes,
                &job.declared_sha256,
                Duration::from_secs((job.upload_expires_at - now) as u64),
            )
            .await
            .map_err(ApiError::internal)?;
        Some(UploadInstructions {
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
        Json(CreatePublishJobResponse {
            job: job_response(&job),
            upload,
        }),
    )
        .into_response())
}

async fn get_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> ApiResult<Json<PublishJobResponse>> {
    require_enabled(&state)?;
    let user_id = authenticated_cli_user_id(&state, &headers).await?;
    let mut job = load_owned_job(&state, &user_id, &job_id).await?;
    let now = unix_timestamp()?;
    if job.state == "uploading" && job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        job = load_owned_job(&state, &user_id, &job_id).await?;
    }
    Ok(Json(job_response(&job)))
}

async fn list_web_publish_jobs(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<WebPublishJobsResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let jobs = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE user_id = ?
         ORDER BY created_at DESC, id DESC
         LIMIT 100",
    )
    .bind(user.0)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .iter()
    .map(job_response)
    .collect();
    Ok(Json(WebPublishJobsResponse { jobs }))
}

async fn complete_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> ApiResult<Json<PublishJobResponse>> {
    require_enabled(&state)?;
    let user_id = authenticated_cli_user_id(&state, &headers).await?;
    let job = load_owned_job(&state, &user_id, &job_id).await?;
    if job.state == "queued" {
        return Ok(Json(job_response(&job)));
    }
    if job.state != "uploading" {
        return Err(ApiError::conflict(
            "publication job is not accepting an upload",
        ));
    }
    let now = unix_timestamp()?;
    if job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        return Err(ApiError::gone("publication upload expired"));
    }
    let uploaded = state
        .publish
        .storage
        .head_object(&job.upload_object_key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("publication upload was not found"))?;
    if uploaded.size_bytes != job.declared_size_bytes {
        return Err(ApiError::conflict(
            "uploaded object size does not match the declared size",
        ));
    }
    if !IntakeStorage::has_expected_metadata(&uploaded, &job.declared_sha256) {
        return Err(ApiError::conflict(
            "uploaded object metadata does not match the publish job",
        ));
    }

    if let Err(error) = state
        .publish
        .storage
        .promote_object(&job.upload_object_key, &job.intake_object_key)
        .await
    {
        let current = load_owned_job(&state, &user_id, &job.id).await?;
        if current.state == "queued" && current.upload_generation == job.upload_generation {
            return Ok(Json(job_response(&current)));
        }
        if current.upload_generation != job.upload_generation || current.state != "uploading" {
            return Err(ApiError::conflict(
                "publication upload attempt was superseded while completing",
            ));
        }
        return Err(ApiError::internal(error));
    }
    let promoted = state
        .publish
        .storage
        .head_object(&job.intake_object_key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("promoted intake object is missing")))?;
    if promoted.size_bytes != job.declared_size_bytes
        || !IntakeStorage::has_expected_metadata(&promoted, &job.declared_sha256)
    {
        state
            .publish
            .storage
            .delete_object(&job.intake_object_key)
            .await
            .map_err(ApiError::internal)?;
        return Err(ApiError::internal(anyhow::anyhow!(
            "promoted intake object metadata changed"
        )));
    }

    let job = queue_completed_attempt(&state, &user_id, &job, now).await?;
    Ok(Json(job_response(&job)))
}

async fn queue_completed_attempt(
    state: &AppState,
    user_id: &str,
    job: &PublishJobRow,
    now: i64,
) -> ApiResult<PublishJobRow> {
    let updated = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', queued_at = ?, updated_at = ?
         WHERE id = ? AND user_id = ? AND state = 'uploading'
           AND upload_generation = ? AND upload_object_key = ?
           AND intake_object_key = ? AND upload_expires_at = ?",
    )
    .bind(now)
    .bind(now)
    .bind(&job.id)
    .bind(user_id)
    .bind(job.upload_generation)
    .bind(&job.upload_object_key)
    .bind(&job.intake_object_key)
    .bind(job.upload_expires_at)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        let current = load_owned_job(state, user_id, &job.id).await?;
        if current.state != "queued" || current.upload_generation != job.upload_generation {
            if let Err(error) = state
                .publish
                .storage
                .delete_object(&job.intake_object_key)
                .await
            {
                tracing::warn!(
                    job_id = %job.id,
                    %error,
                    "deleting unqueued promoted intake object failed"
                );
            }
            if let Err(error) = state
                .publish
                .storage
                .delete_object(&job.upload_object_key)
                .await
            {
                tracing::warn!(
                    job_id = %job.id,
                    %error,
                    "deleting superseded staging upload failed"
                );
            }
            return Err(ApiError::conflict(
                "publication job changed while the upload was completing",
            ));
        }
        return Ok(current);
    }
    if let Err(error) = state
        .publish
        .storage
        .delete_object(&job.upload_object_key)
        .await
    {
        tracing::warn!(job_id = %job.id, %error, "deleting completed staging upload failed");
    }
    load_owned_job(state, user_id, &job.id).await
}

async fn authenticated_cli_user_id(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let token = bearer_token(headers)?;
    let now = unix_timestamp()?;
    sqlx::query_scalar(
        "SELECT cli_sessions.user_id
         FROM cli_access_tokens
         JOIN cli_sessions ON cli_sessions.id = cli_access_tokens.session_id
         WHERE cli_access_tokens.token_hash = ? AND cli_access_tokens.expires_at > ?
           AND cli_sessions.revoked_at IS NULL AND cli_sessions.expires_at > ?",
    )
    .bind(certified::sha256_hex(token.as_bytes()))
    .bind(now)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)
}

async fn load_job_by_idempotency(
    state: &AppState,
    user_id: &str,
    idempotency_key: &str,
) -> ApiResult<PublishJobRow> {
    sqlx::query_as("SELECT * FROM publish_jobs WHERE user_id = ? AND idempotency_key = ?")
        .bind(user_id)
        .bind(idempotency_key)
        .fetch_one(&state.database)
        .await
        .map_err(database_error)
}

async fn load_owned_job(state: &AppState, user_id: &str, job_id: &str) -> ApiResult<PublishJobRow> {
    sqlx::query_as("SELECT * FROM publish_jobs WHERE id = ? AND user_id = ?")
        .bind(job_id)
        .bind(user_id)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::not_found("publication job was not found"))
}

async fn expire_upload(state: &AppState, job: &PublishJobRow, now: i64) -> ApiResult<bool> {
    let updated = sqlx::query(
        "UPDATE publish_jobs SET state = 'expired', updated_at = ?
         WHERE id = ? AND user_id = ? AND state = 'uploading'
           AND upload_generation = ? AND upload_object_key = ? AND upload_expires_at = ?
           AND upload_expires_at <= ?",
    )
    .bind(now)
    .bind(&job.id)
    .bind(&job.user_id)
    .bind(job.upload_generation)
    .bind(&job.upload_object_key)
    .bind(job.upload_expires_at)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 0 {
        return Ok(false);
    }
    if let Err(error) = state
        .publish
        .storage
        .delete_object(&job.upload_object_key)
        .await
    {
        tracing::warn!(job_id = %job.id, %error, "deleting expired staging upload failed");
    }
    Ok(true)
}

async fn cleanup_expired_uploads(state: &AppState) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let jobs = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE state = 'uploading' AND upload_expires_at <= ?
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

fn require_enabled(state: &AppState) -> ApiResult<()> {
    if state.publish.enabled() {
        Ok(())
    } else {
        Err(ApiError::service_unavailable(
            "publication intake is not configured",
        ))
    }
}

fn validate_request(service: &PublishService, request: &CreatePublishJob) -> ApiResult<()> {
    if request.archive_format != ARCHIVE_FORMAT {
        return Err(ApiError::bad_request(
            "archive_format is not supported by this server",
        ));
    }
    if request.size_bytes <= 0 || request.size_bytes > service.max_archive_bytes {
        return Err(ApiError::bad_request(
            "size_bytes is outside the accepted range",
        ));
    }
    if request.sha256.len() != 64
        || !request
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad_request(
            "sha256 must be 64 lowercase hexadecimal characters",
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

fn job_response(job: &PublishJobRow) -> PublishJobResponse {
    let public = (job.state == "admitted").then(|| {
        (
            format!("/api/public/traces/{}/trace.otlp.json", job.id),
            format!("/api/public/traces/{}/stamp.json", job.id),
        )
    });
    PublishJobResponse {
        id: job.id.clone(),
        state: job.state.clone(),
        archive_format: job.archive_format.clone(),
        size_bytes: job.declared_size_bytes,
        sha256: job.declared_sha256.clone(),
        created_at: job.created_at,
        updated_at: job.updated_at,
        upload_expires_at: job.upload_expires_at,
        queued_at: job.queued_at,
        admitted_at: job.admitted_at,
        private_purged_at: job.private_purged_at,
        failure_code: job.failure_code.clone(),
        status_url: format!("/api/publish/jobs/{}", job.id),
        trace_url: public.as_ref().map(|urls| urls.0.clone()),
        stamp_url: public.map(|urls| urls.1),
    }
}

fn integer_env(name: &str) -> anyhow::Result<Option<i64>> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|error| anyhow::anyhow!("{name} must be an integer: {error}"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::Cookie;
    use sqlx::SqlitePool;
    use url::Url;

    use super::super::intake::{MockIntakeStorage, StoredObject};
    use super::*;

    const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn test_state() -> (AppState, MockIntakeStorage, HeaderMap, HeaderMap) {
        let database = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .expect("migrations");
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'one', 1, 1), ('user-2', 2, 'two', 1, 1)",
        )
        .execute(&database)
        .await
        .expect("users");
        let now = unix_timestamp().expect("time");
        let tokens_one = super::super::issue_cli_session(&database, "user-1", "One", now)
            .await
            .expect("session one");
        let tokens_two = super::super::issue_cli_session(&database, "user-2", "Two", now)
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
        let storage = MockIntakeStorage::new();
        let state = AppState {
            database,
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://llmnotary.exalto.ai/api/auth/github/callback")
                .expect("callback"),
            app_url: Url::parse("https://llmnotary.exalto.ai").expect("app"),
            secure_cookies: true,
            notary_directory: super::super::tests::directory_key(),
            publish: PublishService::mock(storage.clone()),
            library_metadata: super::super::admission::MetadataService::from_env(),
        };
        (
            state,
            storage,
            headers(tokens_one.access_token),
            headers(tokens_two.access_token),
        )
    }

    fn request() -> CreatePublishJob {
        CreatePublishJob {
            archive_format: ARCHIVE_FORMAT.to_owned(),
            size_bytes: 1234,
            sha256: SHA256.to_owned(),
        }
    }

    #[tokio::test]
    async fn create_is_idempotent_and_scoped_to_the_cli_user() {
        let (state, _storage, headers_one, mut headers_two) = test_state().await;
        let first = create_publish_job(State(state.clone()), headers_one.clone(), Json(request()))
            .await
            .expect("first create");
        assert_eq!(first.status(), StatusCode::CREATED);
        let second = create_publish_job(State(state.clone()), headers_one.clone(), Json(request()))
            .await
            .expect("idempotent create");
        assert_eq!(second.status(), StatusCode::OK);
        let mut changed = request();
        changed.size_bytes += 1;
        let conflict = create_publish_job(State(state.clone()), headers_one, Json(changed)).await;
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
        let other = create_publish_job(State(state.clone()), headers_two, Json(request()))
            .await
            .expect("other user create");
        assert_eq!(other.status(), StatusCode::CREATED);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job count");
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn web_users_list_only_their_publish_jobs() {
        let (state, _storage, headers_one, headers_two) = test_state().await;
        create_publish_job(State(state.clone()), headers_one, Json(request()))
            .await
            .expect("own publish job");
        create_publish_job(State(state.clone()), headers_two, Json(request()))
            .await
            .expect("other publish job");

        let now = unix_timestamp().expect("time");
        let web_token = "web-publish-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES (?, 'user-1', ?, ?)",
        )
        .bind(certified::sha256_hex(web_token.as_bytes()))
        .bind(now + super::super::SESSION_TTL_SECS)
        .bind(now)
        .execute(&state.database)
        .await
        .expect("web session");
        let jar = CookieJar::new().add(Cookie::new(
            super::super::SESSION_COOKIE,
            web_token.to_owned(),
        ));

        let response = list_web_publish_jobs(State(state), jar)
            .await
            .expect("publish jobs");
        assert_eq!(response.0.jobs.len(), 1);
    }

    #[tokio::test]
    async fn completion_promotes_then_queues_an_immutable_intake_object() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(&job.upload_object_key, job.declared_size_bytes, SHA256);

        let completed =
            complete_publish_job(State(state.clone()), headers.clone(), Path(job.id.clone()))
                .await
                .expect("complete");
        assert_eq!(completed.0.state, "queued");
        assert!(
            storage
                .objects
                .lock()
                .expect("mock lock")
                .contains_key(&job.intake_object_key)
        );
        assert!(
            !storage
                .objects
                .lock()
                .expect("mock lock")
                .contains_key(&job.upload_object_key)
        );

        let retried = complete_publish_job(State(state), headers, Path(job.id))
            .await
            .expect("idempotent complete");
        assert_eq!(retried.0.state, "queued");
    }

    #[tokio::test]
    async fn completion_rejects_missing_or_mismatched_objects_without_queueing() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job");
        let missing =
            complete_publish_job(State(state.clone()), headers.clone(), Path(job.id.clone())).await;
        assert!(matches!(
            missing,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        storage.objects.lock().expect("mock lock").insert(
            job.upload_object_key.clone(),
            StoredObject {
                size_bytes: job.declared_size_bytes + 1,
                metadata: BTreeMap::new(),
            },
        );
        let mismatched =
            complete_publish_job(State(state.clone()), headers, Path(job.id.clone())).await;
        assert!(matches!(
            mismatched,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let state_value: String = sqlx::query_scalar("SELECT state FROM publish_jobs WHERE id = ?")
            .bind(job.id)
            .fetch_one(&state.database)
            .await
            .expect("state");
        assert_eq!(state_value, "uploading");
    }

    #[tokio::test]
    async fn users_cannot_read_or_complete_each_others_jobs() {
        let (state, _storage, headers_one, headers_two) = test_state().await;
        create_publish_job(State(state.clone()), headers_one, Json(request()))
            .await
            .expect("create");
        let job_id: String = sqlx::query_scalar("SELECT id FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job ID");
        let read = get_publish_job(
            State(state.clone()),
            headers_two.clone(),
            Path(job_id.clone()),
        )
        .await;
        let complete = complete_publish_job(State(state), headers_two, Path(job_id)).await;
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
        create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("create");
        let job: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(&job.upload_object_key, job.declared_size_bytes, SHA256);
        sqlx::query("UPDATE publish_jobs SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire job");

        cleanup_expired_uploads(&state).await.expect("cleanup");
        let state_value: String = sqlx::query_scalar("SELECT state FROM publish_jobs WHERE id = ?")
            .bind(&job.id)
            .fetch_one(&state.database)
            .await
            .expect("state");
        assert_eq!(state_value, "expired");
        assert!(
            storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&job.upload_object_key)
        );
    }

    #[tokio::test]
    async fn identical_publish_reopens_an_expired_upload_without_duplicate_jobs() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let first: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("first job");
        storage.object(&first.upload_object_key, first.declared_size_bytes, SHA256);
        sqlx::query("UPDATE publish_jobs SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");

        let response = create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("retry expired upload");
        assert_eq!(response.status(), StatusCode::CREATED);
        let retried: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("retried job");
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.state, "uploading");
        assert_ne!(retried.upload_object_key, first.upload_object_key);
        assert!(retried.upload_expires_at > 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM publish_jobs")
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
                .contains(&first.upload_object_key)
        );
    }

    #[tokio::test]
    async fn stale_expiration_cannot_cancel_a_reopened_upload_generation() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        sqlx::query("UPDATE publish_jobs SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");
        let stale: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("stale generation");
        assert!(expire_upload(&state, &stale, 2).await.unwrap());

        create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("reopen");
        let reopened: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("reopened generation");
        assert_eq!(reopened.state, "uploading");
        assert_ne!(reopened.upload_object_key, stale.upload_object_key);

        assert!(!expire_upload(&state, &stale, i64::MAX).await.unwrap());
        let current: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("current generation");
        assert_eq!(current.state, "uploading");
        assert_eq!(current.upload_object_key, reopened.upload_object_key);
        assert!(
            !storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&reopened.upload_object_key)
        );
    }

    #[tokio::test]
    async fn stale_completion_cannot_queue_or_overwrite_a_reopened_generation() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        sqlx::query("UPDATE publish_jobs SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");
        let stale: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("stale generation");
        assert!(expire_upload(&state, &stale, 2).await.unwrap());
        create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("reopen");
        let current: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("current generation");
        assert_eq!(current.upload_generation, stale.upload_generation + 1);
        assert_ne!(current.intake_object_key, stale.intake_object_key);

        storage.object(&stale.intake_object_key, stale.declared_size_bytes, SHA256);
        assert!(
            queue_completed_attempt(&state, &stale.user_id, &stale, 3)
                .await
                .is_err()
        );
        let still_current: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("still current");
        assert_eq!(still_current.state, "uploading");
        assert_eq!(still_current.upload_generation, current.upload_generation);

        storage.object(
            &current.intake_object_key,
            current.declared_size_bytes,
            SHA256,
        );
        let queued = queue_completed_attempt(&state, &current.user_id, &current, 4)
            .await
            .expect("queue current generation");
        assert_eq!(queued.state, "queued");

        storage.object(&stale.intake_object_key, stale.declared_size_bytes, SHA256);
        assert!(
            queue_completed_attempt(&state, &stale.user_id, &stale, 5)
                .await
                .is_err()
        );
        let remains_queued: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("queued generation");
        assert_eq!(remains_queued.state, "queued");
        assert_eq!(remains_queued.upload_generation, current.upload_generation);
        assert!(
            storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&stale.intake_object_key)
        );
        assert!(
            !storage
                .deleted
                .lock()
                .expect("mock lock")
                .contains(&current.intake_object_key)
        );
    }

    #[test]
    fn publish_requests_are_bounded_and_versioned() {
        let storage = MockIntakeStorage::new();
        let service = PublishService::mock(storage);
        assert!(validate_request(&service, &request()).is_ok());
        let mut unsupported = request();
        unsupported.archive_format = "future/v2".to_owned();
        assert!(validate_request(&service, &unsupported).is_err());
        let mut too_large = request();
        too_large.size_bytes = DEFAULT_MAX_ARCHIVE_BYTES + 1;
        assert!(validate_request(&service, &too_large).is_err());
        let mut uppercase_hash = request();
        uppercase_hash.sha256 = SHA256.to_uppercase();
        assert!(validate_request(&service, &uppercase_hash).is_err());
    }
}
