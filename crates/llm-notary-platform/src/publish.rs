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
use tokio::sync::Semaphore;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, authenticated_web_user,
    authn::{ApiScope, authenticated_principal},
    config::StorageConfig,
    database_error,
    intake::{ARCHIVE_FORMAT, IntakeStorage},
    pagination, unix_timestamp,
};
use llm_notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};

#[cfg(test)]
use super::config::{DEFAULT_MAX_ARCHIVE_BYTES, DEFAULT_UPLOAD_TTL_SECS};

const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const CLEANUP_INTERVAL_SECS: u64 = 10 * 60;
const OBJECTS_PER_CLEANUP: i64 = 32;
const MAX_SHARE_EXPIRY_DAYS: u32 = 365;
const MIN_SHARE_PASSWORD_BYTES: usize = 8;
pub(super) const MAX_SHARE_PASSWORD_BYTES: usize = 128;
const SHARE_PASSWORD_CHANGE_LIMIT: i64 = 5;
const SHARE_PASSWORD_CHANGE_WINDOW_SECS: i64 = 60;
const SHARE_PASSWORD_WORK_CAPACITY: usize = 4;

static SHARE_PASSWORD_CAPACITY: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(SHARE_PASSWORD_WORK_CAPACITY)));

#[derive(Clone)]
pub struct PublishService {
    pub(super) storage: IntakeStorage,
    pub(super) max_archive_bytes: i64,
    upload_ttl_secs: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePublishJob {
    archive_format: String,
    size_bytes: i64,
    sha256: String,
    visibility: ShareVisibility,
    /// Accept unexplained high-entropy values after reviewing the disclosure.
    #[serde(default)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShareVisibility {
    Unlisted,
    Listed,
}

impl ShareVisibility {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
}

#[derive(Serialize, ToSchema)]
struct CreateShareResponse {
    share: ShareResponse,
    upload: Option<UploadInstructions>,
}

#[derive(Deserialize, Serialize)]
struct SharePagePosition {
    created_at: i64,
    id: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct UpdateShareSettings {
    visibility: Option<ShareVisibility>,
    published: Option<bool>,
    /// A new password, or an empty string to remove the current password.
    password: Option<String>,
    /// Days from now until expiry. Zero removes the current expiry.
    #[schema(maximum = 365)]
    expires_in_days: Option<u32>,
}

#[derive(Serialize, ToSchema)]
struct UploadInstructions {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    expires_at: i64,
}

#[derive(Serialize, ToSchema)]
struct ShareResponse {
    id: String,
    state: String,
    visibility: ShareVisibility,
    published: bool,
    password_protected: bool,
    expires_at: Option<i64>,
    force: bool,
    created_at: i64,
    updated_at: i64,
    admitted_at: Option<i64>,
    failure_code: Option<String>,
    status_url: String,
    share_url: Option<String>,
    package_url: Option<String>,
}

#[derive(FromRow)]
pub(super) struct PublishJobRow {
    pub(super) id: String,
    pub(super) user_id: String,
    pub(super) state: String,
    pub(super) visibility: String,
    pub(super) published: bool,
    pub(super) share_expires_at: Option<i64>,
    pub(super) share_password_hash: Option<String>,
    pub(super) force_publication: bool,
    pub(super) archive_format: String,
    pub(super) declared_size_bytes: i64,
    pub(super) declared_sha256: String,
    pub(super) upload_object_key: String,
    pub(super) intake_object_key: String,
    pub(super) upload_expires_at: i64,
    pub(super) upload_generation: i64,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) failure_code: Option<String>,
    pub(super) admitted_at: Option<i64>,
    pub(super) package_object_key: Option<String>,
}

impl PublishService {
    pub fn from_config(config: &StorageConfig) -> anyhow::Result<Self> {
        let storage = IntakeStorage::from_config(config)?;
        Ok(Self {
            storage,
            max_archive_bytes: config.max_archive_bytes,
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
    pub(super) fn mock(storage: super::intake::MockIntakeStorage) -> Self {
        Self {
            storage: IntakeStorage::Mock(storage),
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
        }
    }

    #[cfg(test)]
    pub fn disabled_for_test() -> Self {
        Self {
            storage: IntakeStorage::Disabled,
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            upload_ttl_secs: DEFAULT_UPLOAD_TTL_SECS,
        }
    }
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_publish_job))
        .routes(routes!(get_publish_job, update_share_settings))
        .routes(routes!(list_web_publish_jobs))
        .routes(routes!(complete_publish_job))
}

pub fn spawn_cleanup(state: AppState) {
    if !state.publish.enabled() {
        tracing::warn!("share intake is disabled; share endpoints will return 503");
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
            if let Err(error) = cleanup_publication_objects(&state).await {
                tracing::error!(
                    status = %error.status,
                    error = error.message,
                    "cleaning up publication objects failed"
                );
            }
        }
    });
}

/// Returns whether expired uploads must be cleaned up before the API can enter
/// its application-managed idle shutdown. Uploads that expire while every API
/// Machine is stopped are cleaned up when the next request wakes a Machine.
pub async fn has_pending_cleanup(state: &AppState) -> ApiResult<bool> {
    let now = unix_timestamp()?;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM publish_jobs
             WHERE state = 'uploading' AND upload_expires_at <= $1
             LIMIT 1
         ) OR EXISTS(
             SELECT 1 FROM publication_object_cleanup
             LIMIT 1
         )",
    )
    .bind(now)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    Ok(pending)
}

#[utoipa::path(
    post,
    path = "/api/shares",
    summary = "Create or resume a share",
    params(("Idempotency-Key" = String, Header, description = "Stable key for this share attempt")),
    request_body = CreatePublishJob,
    responses(
        (status = 200, body = CreateShareResponse, description = "Existing share"),
        (status = 201, body = CreateShareResponse, description = "New or reopened share"),
        (status = 400, body = super::ErrorResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 403, body = super::ErrorResponse),
        (status = 409, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse),
        (status = 503, body = super::ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "sharing"
)]
async fn create_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePublishJob>,
) -> ApiResult<Response> {
    require_enabled(&state)?;
    validate_request(&state.publish, &request)?;
    let user_id = authenticated_principal(&state, &headers, ApiScope::PublishWrite)
        .await?
        .user_id;
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
        "INSERT INTO publish_jobs
         (id, user_id, idempotency_key, state, visibility, force_publication,
          archive_format, declared_size_bytes,
          declared_sha256, upload_object_key, intake_object_key, upload_expires_at,
          created_at, updated_at)
         VALUES ($1, $2, $3, 'uploading', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (user_id, idempotency_key) DO NOTHING",
    )
    .bind(&job_id)
    .bind(&user_id)
    .bind(&idempotency_key)
    .bind(request.visibility.as_str())
    .bind(request.force)
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
        || job.visibility != request.visibility.as_str()
        || job.force_publication != request.force
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
             SET state = 'uploading', upload_object_key = $1, intake_object_key = $2,
                 upload_expires_at = $3, upload_generation = upload_generation + 1,
                 updated_at = $4, failure_code = NULL
             WHERE id = $5 AND user_id = $6 AND state = 'expired'
               AND upload_generation = $7",
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
        Json(CreateShareResponse {
            share: share_response(&job, &state.app_url),
            upload,
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/shares/{share_id}",
    summary = "Get a share's admission state",
    params(("share_id" = String, Path)),
    responses(
        (status = 200, body = ShareResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 403, body = super::ErrorResponse),
        (status = 404, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse),
        (status = 503, body = super::ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "sharing"
)]
async fn get_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ShareResponse>> {
    require_enabled(&state)?;
    let user_id = authenticated_principal(&state, &headers, ApiScope::PublishRead)
        .await?
        .user_id;
    let mut job = load_owned_job(&state, &user_id, &job_id).await?;
    let now = unix_timestamp()?;
    if job.state == "uploading" && job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        job = load_owned_job(&state, &user_id, &job_id).await?;
    }
    Ok(Json(share_response(&job, &state.app_url)))
}

#[utoipa::path(
    patch,
    path = "/api/shares/{share_id}",
    summary = "Change a share's publication access settings",
    params(("share_id" = String, Path)),
    request_body = UpdateShareSettings,
    responses(
        (status = 200, body = ShareResponse),
        (status = 400, body = super::ErrorResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 403, body = super::ErrorResponse),
        (status = 404, body = super::ErrorResponse),
        (status = 429, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse),
        (status = 503, body = super::ErrorResponse)
    ),
    security(("bearerAuth" = []), ("browserSession" = [])),
    tag = "sharing"
)]
async fn update_share_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(share_id): Path<String>,
    Json(request): Json<UpdateShareSettings>,
) -> ApiResult<Json<ShareResponse>> {
    require_enabled(&state)?;
    let user_id = if headers.contains_key(axum::http::header::AUTHORIZATION) {
        authenticated_principal(&state, &headers, ApiScope::PublishWrite)
            .await?
            .user_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let now = unix_timestamp()?;
    if request.visibility.is_none()
        && request.published.is_none()
        && request.password.is_none()
        && request.expires_in_days.is_none()
    {
        return Err(ApiError::bad_request(
            "at least one share setting is required",
        ));
    }
    // Resolve ownership before accepting any request that can schedule costly
    // password hashing work.
    load_owned_job(&state, &user_id, &share_id).await?;
    let visibility = request.visibility.map(ShareVisibility::as_str);
    let expires_at_changed = request.expires_in_days.is_some();
    let expires_at = match request.expires_in_days {
        Some(0) => None,
        Some(days) if days <= MAX_SHARE_EXPIRY_DAYS => Some(
            now.checked_add(i64::from(days) * 24 * 60 * 60)
                .ok_or_else(|| {
                    ApiError::bad_request("share expiry is outside the accepted range")
                })?,
        ),
        Some(_) => {
            return Err(ApiError::bad_request(
                "expires_in_days must be between 0 and 365",
            ));
        }
        None => None,
    };
    let password_changed = request.password.is_some();
    if password_changed {
        enforce_password_change_limit(&state, &user_id, now).await?;
    }
    let password_hash = match request.password {
        Some(password) if password.is_empty() => None,
        Some(password) => Some(hash_share_password(password).await?),
        None => None,
    };
    let updated = sqlx::query(
        "UPDATE publish_jobs
         SET visibility = COALESCE($1, visibility),
             published = COALESCE($2, published),
             share_expires_at = CASE WHEN $3 THEN $4 ELSE share_expires_at END,
             share_password_hash = CASE WHEN $5 THEN $6 ELSE share_password_hash END,
             updated_at = $7
         WHERE id = $8 AND user_id = $9",
    )
    .bind(visibility)
    .bind(request.published)
    .bind(expires_at_changed)
    .bind(expires_at)
    .bind(password_changed)
    .bind(password_hash)
    .bind(now)
    .bind(&share_id)
    .bind(&user_id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("share was not found"));
    }
    let share = load_owned_job(&state, &user_id, &share_id).await?;
    Ok(Json(share_response(&share, &state.app_url)))
}

#[utoipa::path(
    get,
    path = "/api/me/shares",
    summary = "List the browser user's shares",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<ShareResponse>),
        (status = 400, body = super::ErrorResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "sharing"
)]
async fn list_web_publish_jobs(
    State(state): State<AppState>,
    jar: CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<ShareResponse>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let user = authenticated_web_user(&state, &jar).await?;
    let limit = query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new("/api/me/shares", &user.0, "created_at desc, id desc")
        .map_err(pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<SharePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let shares = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE user_id = $1
           AND ($2::TEXT IS NULL OR (created_at, id) < ($3, $2))
         ORDER BY created_at DESC, id DESC
         LIMIT $4",
    )
    .bind(&user.0)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.created_at))
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(error.into()))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(|share| share_response(&share, &state.app_url))
    .collect();
    let page = Page::from_limit_plus_one(shares, limit, &scope, |share| SharePagePosition {
        created_at: share.created_at,
        id: share.id.clone(),
    })
    .map_err(pagination::api_error)?;
    Ok(Json(page))
}

#[utoipa::path(
    post,
    path = "/api/shares/{share_id}/complete",
    summary = "Complete the upload for a share",
    params(("share_id" = String, Path)),
    responses(
        (status = 200, body = ShareResponse),
        (status = 401, body = super::ErrorResponse),
        (status = 403, body = super::ErrorResponse),
        (status = 404, body = super::ErrorResponse),
        (status = 409, body = super::ErrorResponse),
        (status = 410, body = super::ErrorResponse),
        (status = 500, body = super::ErrorResponse),
        (status = 503, body = super::ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "sharing"
)]
async fn complete_publish_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> ApiResult<Json<ShareResponse>> {
    require_enabled(&state)?;
    let user_id = authenticated_principal(&state, &headers, ApiScope::PublishWrite)
        .await?
        .user_id;
    let job = load_owned_job(&state, &user_id, &job_id).await?;
    if job.state == "queued" {
        return Ok(Json(share_response(&job, &state.app_url)));
    }
    if job.state != "uploading" {
        return Err(ApiError::conflict("share is not accepting an upload"));
    }
    let now = unix_timestamp()?;
    if job.upload_expires_at <= now {
        expire_upload(&state, &job, now).await?;
        return Err(ApiError::gone("share upload expired"));
    }
    let uploaded = state
        .publish
        .storage
        .head_object(&job.upload_object_key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::conflict("share upload was not found"))?;
    if uploaded.size_bytes != job.declared_size_bytes {
        return Err(ApiError::conflict(
            "uploaded object size does not match the declared size",
        ));
    }
    if !IntakeStorage::has_expected_metadata(&uploaded, &job.declared_sha256) {
        return Err(ApiError::conflict(
            "uploaded object metadata does not match the share",
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
            return Ok(Json(share_response(&current, &state.app_url)));
        }
        if current.upload_generation != job.upload_generation || current.state != "uploading" {
            return Err(ApiError::conflict(
                "share upload attempt was superseded while completing",
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
        enqueue_cleanup_direct(&state, &job.id, &job.intake_object_key, "intake", now)
            .await
            .map_err(database_error)?;
        let _ = cleanup_object(&state, &job.intake_object_key).await;
        return Err(ApiError::internal(anyhow::anyhow!(
            "promoted intake object metadata changed"
        )));
    }

    let job = queue_completed_attempt(&state, &user_id, &job, now).await?;
    Ok(Json(share_response(&job, &state.app_url)))
}

async fn queue_completed_attempt(
    state: &AppState,
    user_id: &str,
    job: &PublishJobRow,
    now: i64,
) -> ApiResult<PublishJobRow> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    let updated = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', queued_at = $1, updated_at = $2
         WHERE id = $3 AND user_id = $4 AND state = 'uploading'
           AND upload_generation = $5 AND upload_object_key = $6
           AND intake_object_key = $7 AND upload_expires_at = $8",
    )
    .bind(now)
    .bind(now)
    .bind(&job.id)
    .bind(user_id)
    .bind(job.upload_generation)
    .bind(&job.upload_object_key)
    .bind(&job.intake_object_key)
    .bind(job.upload_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() == 1 {
        enqueue_cleanup(
            &mut transaction,
            &job.id,
            &job.upload_object_key,
            "upload",
            now,
        )
        .await
        .map_err(database_error)?;
    }
    transaction.commit().await.map_err(database_error)?;
    if updated.rows_affected() != 1 {
        let current = load_owned_job(state, user_id, &job.id).await?;
        if current.state != "queued" || current.upload_generation != job.upload_generation {
            enqueue_private_cleanup_pair(state, job, now)
                .await
                .map_err(database_error)?;
            let _ = cleanup_object(state, &job.intake_object_key).await;
            let _ = cleanup_object(state, &job.upload_object_key).await;
            return Err(ApiError::conflict(
                "share changed while the upload was completing",
            ));
        }
        return Ok(current);
    }
    let _ = cleanup_object(state, &job.upload_object_key).await;
    load_owned_job(state, user_id, &job.id).await
}

async fn load_job_by_idempotency(
    state: &AppState,
    user_id: &str,
    idempotency_key: &str,
) -> ApiResult<PublishJobRow> {
    sqlx::query_as("SELECT * FROM publish_jobs WHERE user_id = $1 AND idempotency_key = $2")
        .bind(user_id)
        .bind(idempotency_key)
        .fetch_one(&state.database)
        .await
        .map_err(database_error)
}

async fn load_owned_job(state: &AppState, user_id: &str, job_id: &str) -> ApiResult<PublishJobRow> {
    sqlx::query_as("SELECT * FROM publish_jobs WHERE id = $1 AND user_id = $2")
        .bind(job_id)
        .bind(user_id)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::not_found("share was not found"))
}

async fn expire_upload(state: &AppState, job: &PublishJobRow, now: i64) -> ApiResult<bool> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    let updated = sqlx::query(
        "UPDATE publish_jobs SET state = 'expired', updated_at = $1
         WHERE id = $2 AND user_id = $3 AND state = 'uploading'
           AND upload_generation = $4 AND upload_object_key = $5 AND upload_expires_at = $6
           AND upload_expires_at <= $7",
    )
    .bind(now)
    .bind(&job.id)
    .bind(&job.user_id)
    .bind(job.upload_generation)
    .bind(&job.upload_object_key)
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
        &job.id,
        &job.upload_object_key,
        "upload",
        now,
    )
    .await
    .map_err(database_error)?;
    enqueue_cleanup(
        &mut transaction,
        &job.id,
        &job.intake_object_key,
        "intake",
        now,
    )
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    let _ = cleanup_object(state, &job.upload_object_key).await;
    let _ = cleanup_object(state, &job.intake_object_key).await;
    Ok(true)
}

async fn cleanup_expired_uploads(state: &AppState) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let jobs = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE state = 'uploading' AND upload_expires_at <= $1
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

pub(super) async fn cleanup_publication_objects(state: &AppState) -> ApiResult<()> {
    let objects: Vec<String> = sqlx::query_scalar(
        "SELECT object_key
         FROM publication_object_cleanup
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
    publication_id: &str,
    object_key: &str,
    artifact_kind: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO publication_object_cleanup
             (object_key, publication_id, artifact_kind, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(object_key)
    .bind(publication_id)
    .bind(artifact_kind)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn enqueue_cleanup_direct(
    state: &AppState,
    publication_id: &str,
    object_key: &str,
    artifact_kind: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO publication_object_cleanup
             (object_key, publication_id, artifact_kind, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(object_key)
    .bind(publication_id)
    .bind(artifact_kind)
    .bind(now)
    .execute(&state.database)
    .await?;
    Ok(())
}

async fn enqueue_private_cleanup_pair(
    state: &AppState,
    job: &PublishJobRow,
    now: i64,
) -> Result<(), sqlx::Error> {
    let mut transaction = state.database.begin().await?;
    enqueue_cleanup(
        &mut transaction,
        &job.id,
        &job.upload_object_key,
        "upload",
        now,
    )
    .await?;
    enqueue_cleanup(
        &mut transaction,
        &job.id,
        &job.intake_object_key,
        "intake",
        now,
    )
    .await?;
    transaction.commit().await
}

async fn cleanup_object(state: &AppState, object_key: &str) -> Result<bool, sqlx::Error> {
    let now = unix_timestamp().map_err(|error| sqlx::Error::Protocol(error.message.into()))?;
    match state.publish.storage.delete_object(object_key).await {
        Ok(()) => {
            sqlx::query("DELETE FROM publication_object_cleanup WHERE object_key = $1")
                .bind(object_key)
                .execute(&state.database)
                .await?;
            Ok(true)
        }
        Err(_) => {
            sqlx::query(
                "UPDATE publication_object_cleanup
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
    state: &AppState,
    job: &PublishJobRow,
) -> anyhow::Result<bool> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    enqueue_private_cleanup_pair(state, job, now).await?;
    let _ = cleanup_object(state, &job.upload_object_key).await?;
    let _ = cleanup_object(state, &job.intake_object_key).await?;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM publication_object_cleanup
             WHERE publication_id = $1 AND artifact_kind IN ('upload', 'intake')
         )",
    )
    .bind(&job.id)
    .fetch_one(&state.database)
    .await?;
    Ok(!pending)
}

fn require_enabled(state: &AppState) -> ApiResult<()> {
    if state.publish.enabled() {
        Ok(())
    } else {
        Err(ApiError::service_unavailable(
            "share intake is not configured",
        ))
    }
}

fn validate_request(service: &PublishService, request: &CreatePublishJob) -> ApiResult<()> {
    if request.archive_format != ARCHIVE_FORMAT {
        return Err(ApiError::bad_request(
            "archive_format is not supported by this server",
        ));
    }
    let max_archive_bytes = service
        .max_archive_bytes
        .min(llm_notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64);
    if request.size_bytes <= 0 || request.size_bytes > max_archive_bytes {
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

fn share_response(job: &PublishJobRow, app_url: &url::Url) -> ShareResponse {
    let visibility = match job.visibility.as_str() {
        "listed" => ShareVisibility::Listed,
        _ => ShareVisibility::Unlisted,
    };
    let live = job.state == "admitted"
        && job.published
        && job
            .share_expires_at
            .is_none_or(|expires_at| expires_at > unix_timestamp().unwrap_or(i64::MAX));
    ShareResponse {
        id: job.id.clone(),
        state: job.state.clone(),
        visibility,
        published: job.published,
        password_protected: job.share_password_hash.is_some(),
        expires_at: job.share_expires_at,
        force: job.force_publication,
        created_at: job.created_at,
        updated_at: job.updated_at,
        admitted_at: job.admitted_at,
        failure_code: job.failure_code.clone(),
        status_url: format!("/api/shares/{}", job.id),
        share_url: live.then(|| {
            app_url
                .join(&format!("/s/{}", job.id))
                .expect("share path is a valid same-origin URL")
                .to_string()
        }),
        package_url: (live && job.package_object_key.is_some())
            .then(|| format!("/api/public/shares/{}/package.llmtrace", job.id)),
    }
}

async fn hash_share_password(password: String) -> ApiResult<String> {
    if !(MIN_SHARE_PASSWORD_BYTES..=MAX_SHARE_PASSWORD_BYTES).contains(&password.len()) {
        return Err(ApiError::bad_request(
            "password must contain between 8 and 128 bytes",
        ));
    }
    run_share_password_work(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| ApiError::internal(anyhow::anyhow!(error)))
    })
    .await?
}

pub(super) async fn run_share_password_work<T, F>(work: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_share_password_work_with_capacity(SHARE_PASSWORD_CAPACITY.clone(), work).await
}

pub(super) async fn run_share_password_work_with_capacity<T, F>(
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
            "share_password_capacity",
            "Password processing is busy; try again shortly",
        )
    })?;
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| ApiError::internal(error.into()))
}

async fn enforce_password_change_limit(state: &AppState, user_id: &str, now: i64) -> ApiResult<()> {
    let window_reset_before = now - SHARE_PASSWORD_CHANGE_WINDOW_SECS;
    let request_count = sqlx::query_scalar::<_, i64>(
        "INSERT INTO share_password_change_limits
             (user_id, window_started_at, request_count, updated_at)
         VALUES ($1, $2, 1, $2)
         ON CONFLICT (user_id) DO UPDATE
         SET window_started_at = CASE
                 WHEN share_password_change_limits.window_started_at <= $3 THEN $2
                 ELSE share_password_change_limits.window_started_at
             END,
             request_count = CASE
                 WHEN share_password_change_limits.window_started_at <= $3 THEN 1
                 ELSE share_password_change_limits.request_count + 1
             END,
             updated_at = $2
         WHERE share_password_change_limits.window_started_at <= $3
            OR share_password_change_limits.request_count < $4
         RETURNING request_count",
    )
    .bind(user_id)
    .bind(now)
    .bind(window_reset_before)
    .bind(SHARE_PASSWORD_CHANGE_LIMIT)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    if request_count.is_none() {
        return Err(ApiError::coded(
            StatusCode::TOO_MANY_REQUESTS,
            "share_password_change_rate_limited",
            "Too many password changes were requested for this account",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::Cookie;
    use url::Url;

    use super::super::intake::{MockIntakeStorage, StoredObject};
    use super::*;

    const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    async fn test_state() -> (AppState, MockIntakeStorage, HeaderMap, HeaderMap) {
        let database = super::super::fresh_database().await;
        super::super::insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        super::super::insert_test_github_user(&database.pool, "user-2", 2, "two").await;
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
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse(
                "https://llm-notary.exalto.ai/api/auth/github/callback",
            )
            .expect("callback"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse(
                "https://llm-notary.exalto.ai/api/auth/google/callback",
            )
            .expect("Google callback"),
            app_url: Url::parse("https://llm-notary.exalto.ai").expect("app"),
            secure_cookies: true,
            notary_directory: super::super::tests::directory_key(),
            publish: PublishService::mock(storage.clone()),
            admission: std::sync::Arc::new(super::super::config::AdmissionConfig::for_test()),
            billing: super::super::billing::BillingService::disabled_for_test(),
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
            visibility: ShareVisibility::Unlisted,
            force: false,
        }
    }

    #[tokio::test]
    async fn expired_upload_cleanup_prevents_idle_shutdown() {
        let (state, _, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("create");
        assert!(
            !has_pending_cleanup(&state)
                .await
                .expect("no expired uploads")
        );

        sqlx::query("UPDATE publish_jobs SET upload_expires_at = 1")
            .execute(&state.database)
            .await
            .expect("expire upload");
        assert!(has_pending_cleanup(&state).await.expect("expired upload"));
    }

    #[tokio::test]
    async fn obsolete_stamp_cleanup_is_bounded_and_retryable() {
        let (state, storage, _, _) = test_state().await;
        let object_key = "test/public/legacy/stamp-deadbeef.json";
        storage.object_bytes(object_key, b"obsolete stamp".to_vec());
        storage.fail_delete(object_key);
        sqlx::query(
            "INSERT INTO publication_object_cleanup
                 (object_key, publication_id, artifact_kind, created_at)
             VALUES ($1, NULL, 'stamp', 1)",
        )
        .bind(object_key)
        .execute(&state.database)
        .await
        .unwrap();

        assert!(has_pending_cleanup(&state).await.unwrap());
        cleanup_publication_objects(&state).await.unwrap();
        let attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM publication_object_cleanup WHERE object_key = $1",
        )
        .bind(object_key)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(attempts, 1);

        storage.delete_failures.lock().unwrap().remove(object_key);
        cleanup_publication_objects(&state).await.unwrap();
        assert!(!has_pending_cleanup(&state).await.unwrap());
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
        create_publish_job(State(state.clone()), headers.clone(), Json(request()))
            .await
            .expect("create");
        let job: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(&job.upload_object_key, job.declared_size_bytes, SHA256);
        storage.fail_delete(&job.upload_object_key);

        let _ = complete_publish_job(State(state.clone()), headers, Path(job.id.clone()))
            .await
            .expect("complete despite deferred cleanup");
        let queued: (String, i64) = sqlx::query_as(
            "SELECT artifact_kind, attempts FROM publication_object_cleanup
             WHERE object_key = $1",
        )
        .bind(&job.upload_object_key)
        .fetch_one(&state.database)
        .await
        .expect("durable upload cleanup");
        assert_eq!(queued, ("upload".to_owned(), 1));
        assert!(
            storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.upload_object_key)
        );

        storage
            .delete_failures
            .lock()
            .unwrap()
            .remove(&job.upload_object_key);
        cleanup_publication_objects(&state).await.unwrap();
        assert!(
            !storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.upload_object_key)
        );
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM publication_object_cleanup WHERE object_key = $1",
        )
        .bind(&job.upload_object_key)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    async fn expired_upload_cleanup_is_durable_across_delete_failures() {
        let (state, storage, headers, _) = test_state().await;
        create_publish_job(State(state.clone()), headers, Json(request()))
            .await
            .expect("create");
        let job: PublishJobRow = sqlx::query_as("SELECT * FROM publish_jobs")
            .fetch_one(&state.database)
            .await
            .expect("job");
        storage.object(&job.upload_object_key, job.declared_size_bytes, SHA256);
        storage.fail_delete(&job.upload_object_key);

        assert!(expire_upload(&state, &job, i64::MAX).await.unwrap());
        assert!(has_pending_cleanup(&state).await.unwrap());
        let attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM publication_object_cleanup WHERE object_key = $1",
        )
        .bind(&job.upload_object_key)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(attempts, 1);

        storage
            .delete_failures
            .lock()
            .unwrap()
            .remove(&job.upload_object_key);
        cleanup_publication_objects(&state).await.unwrap();
        assert!(!has_pending_cleanup(&state).await.unwrap());
        assert!(
            !storage
                .objects
                .lock()
                .unwrap()
                .contains_key(&job.upload_object_key)
        );
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
        let mut forced = request();
        forced.force = true;
        let force_conflict =
            create_publish_job(State(state.clone()), headers_one.clone(), Json(forced)).await;
        assert!(matches!(
            force_conflict,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
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
        let with_key = |headers: &HeaderMap, key: &'static str| {
            let mut headers = headers.clone();
            headers.insert(
                IDEMPOTENCY_KEY_HEADER,
                key.parse().expect("idempotency key"),
            );
            headers
        };
        create_publish_job(State(state.clone()), headers_one.clone(), Json(request()))
            .await
            .expect("own publish job");
        create_publish_job(State(state.clone()), headers_two, Json(request()))
            .await
            .expect("other publish job");
        for key in [
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
        ] {
            create_publish_job(
                State(state.clone()),
                with_key(&headers_one, key),
                Json(request()),
            )
            .await
            .expect("additional own publish job");
        }
        let expected_ids: std::collections::BTreeSet<String> =
            sqlx::query_scalar("SELECT id FROM publish_jobs WHERE user_id = 'user-1'")
                .fetch_all(&state.database)
                .await
                .expect("own publish job IDs")
                .into_iter()
                .collect();

        let now = unix_timestamp().expect("time");
        let web_token = "web-publish-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, $3)",
        )
        .bind(llm_notary_core::sha256_hex(web_token.as_bytes()))
        .bind(now + super::super::SESSION_TTL_SECS)
        .bind(now)
        .execute(&state.database)
        .await
        .expect("web session");
        let jar = CookieJar::new().add(Cookie::new(
            super::super::SESSION_COOKIE,
            web_token.to_owned(),
        ));

        let first = list_web_publish_jobs(
            State(state.clone()),
            jar.clone(),
            Ok(Query(PageQuery {
                limit: Some(2),
                cursor: None,
            })),
        )
        .await
        .expect("publish jobs");
        assert_eq!(first.0.items.len(), 2);
        let cursor = first.0.next_cursor.clone().expect("second page cursor");

        let concurrent_key = "44444444-4444-4444-4444-444444444444";
        create_publish_job(
            State(state.clone()),
            with_key(&headers_one, concurrent_key),
            Json(request()),
        )
        .await
        .expect("concurrent own publish job");
        sqlx::query(
            "UPDATE publish_jobs SET created_at = $1
             WHERE user_id = 'user-1' AND idempotency_key = $2",
        )
        .bind(now + 100)
        .bind(concurrent_key)
        .execute(&state.database)
        .await
        .expect("move concurrent job above cursor boundary");

        let second = list_web_publish_jobs(
            State(state),
            jar,
            Ok(Query(PageQuery {
                limit: Some(2),
                cursor: Some(cursor),
            })),
        )
        .await
        .expect("second publish jobs page");
        assert_eq!(second.0.items.len(), 2);
        assert!(second.0.next_cursor.is_none());
        let actual_ids = first
            .0
            .items
            .into_iter()
            .chain(second.0.items)
            .map(|share| share.id)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_ids, expected_ids);
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
        let state_value: String =
            sqlx::query_scalar("SELECT state FROM publish_jobs WHERE id = $1")
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
        let state_value: String =
            sqlx::query_scalar("SELECT state FROM publish_jobs WHERE id = $1")
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

    #[tokio::test]
    async fn share_password_hashes_are_salted_and_bounded() {
        let first = hash_share_password("long-enough-password".to_owned())
            .await
            .unwrap();
        let second = hash_share_password("long-enough-password".to_owned())
            .await
            .unwrap();
        assert_ne!(first, second);
        assert!(hash_share_password("short".to_owned()).await.is_err());
        assert!(hash_share_password("x".repeat(129)).await.is_err());
    }
}
