use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use k256::elliptic_curve::subtle::ConstantTimeEq as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, ErrorResponse,
    authn::{ApiScope, optional_authenticated_principal},
    config::{AdmissionConfig, TierPolicy},
    database_error, random_token, unix_timestamp,
};
use llm_notary_core::sha256_hex;

const ADMISSION_LOCK_NAMESPACE: i32 = 151;
const ADMISSION_LOCK_KEY: i32 = 1;
const MAX_TICKET_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const SECS_PER_MINUTE: i64 = 60;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServicePlan {
    Free,
    PaidPreview,
}

impl ServicePlan {
    fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::PaidPreview => "paid_preview",
        }
    }

    fn parse(value: &str) -> ApiResult<Self> {
        match value {
            "free" => Ok(Self::Free),
            "paid_preview" => Ok(Self::PaidPreview),
            _ => Err(ApiError::internal(anyhow::anyhow!(
                "database contains an invalid service plan"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    Capture,
    Finalize,
}

impl AdmissionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessPool {
    Public,
    Free,
    PaidPreview,
}

impl AccessPool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Free => "free",
            Self::PaidPreview => "paid_preview",
        }
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct EffectiveEntitlements {
    pub access_pool: AccessPool,
    pub capture_concurrency: i64,
    pub finalize_concurrency: i64,
    pub account_concurrency: Option<i64>,
    pub starts_per_minute: i64,
    pub session_timeout_secs: i64,
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub monthly_finalization_bytes: i64,
    pub remaining_finalization_bytes: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePlanRequest {
    pub plan: ServicePlan,
}

#[derive(Serialize, ToSchema)]
pub struct PlanResponse {
    pub plan: ServicePlan,
    pub entitlements: EffectiveEntitlements,
}

#[derive(Deserialize, ToSchema)]
pub struct IssueAdmissionRequest {
    pub mode: AdmissionMode,
    pub record_digest: Option<String>,
    pub requested_allowance_bytes: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct AdmissionTicketResponse {
    pub ticket: String,
    pub expires_at: i64,
    pub directory_generation: u64,
    pub entitlements: EffectiveEntitlements,
}

#[derive(Deserialize, ToSchema)]
pub struct RedeemAdmissionRequest {
    pub ticket: String,
    pub notary_instance_id: String,
    pub mode: AdmissionMode,
    pub directory_generation: u64,
}

#[derive(Serialize, ToSchema)]
pub struct RedeemAdmissionResponse {
    pub lease_id: String,
    pub lease_expires_at: i64,
    pub access_pool: AccessPool,
    pub session_timeout_secs: i64,
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub record_digest: Option<String>,
    pub authorized_allowance_bytes: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct LeaseRequest {
    pub lease_id: String,
    pub notary_instance_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct LeaseRenewedResponse {
    pub lease_expires_at: i64,
}

#[derive(FromRow)]
struct TicketRow {
    subject_id: Option<String>,
    access_pool: String,
    mode: String,
    directory_generation: i64,
    record_digest: Option<String>,
    requested_allowance_bytes: i64,
    session_timeout_secs: i64,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(issue_admission))
        .routes(routes!(change_plan))
        .routes(routes!(redeem_admission))
        .routes(routes!(renew_lease))
        .routes(routes!(release_lease))
}

pub async fn account_plan(
    state: &AppState,
    user_id: &str,
) -> ApiResult<(ServicePlan, EffectiveEntitlements)> {
    let plan: String = sqlx::query_scalar("SELECT service_plan FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.database)
        .await
        .map_err(database_error)?;
    let plan = ServicePlan::parse(&plan)?;
    let pool = match plan {
        ServicePlan::Free => AccessPool::Free,
        ServicePlan::PaidPreview => AccessPool::PaidPreview,
    };
    let policy = policy_for_pool(&state.admission, pool);
    let remaining = remaining_budget(
        &state.database,
        &budget_subject(Some(user_id)),
        policy,
        unix_timestamp()?,
    )
    .await?;
    Ok((plan, entitlements(pool, policy, remaining)))
}

#[utoipa::path(
    put,
    path = "/api/me/plan",
    summary = "Switch the signed-in account between free and paid preview",
    request_body = ChangePlanRequest,
    responses(
        (status = 200, body = PlanResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn change_plan(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
    Json(request): Json<ChangePlanRequest>,
) -> ApiResult<Json<PlanResponse>> {
    let user = super::authenticated_web_user(&state, &jar).await?;
    sqlx::query("UPDATE users SET service_plan = $1, updated_at = $2 WHERE id = $3")
        .bind(request.plan.as_str())
        .bind(unix_timestamp()?)
        .bind(&user.0)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let (_, entitlements) = account_plan(&state, &user.0).await?;
    Ok(Json(PlanResponse {
        plan: request.plan,
        entitlements,
    }))
}

#[utoipa::path(
    post,
    path = "/api/notary/admissions",
    summary = "Issue a short-lived one-time hosted notary admission ticket",
    request_body = IssueAdmissionRequest,
    responses(
        (status = 200, body = AdmissionTicketResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 429, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security((), ("bearerAuth" = [])),
    tag = "notary-admission"
)]
async fn issue_admission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssueAdmissionRequest>,
) -> ApiResult<Json<AdmissionTicketResponse>> {
    let identity =
        optional_authenticated_principal(&state, &headers, ApiScope::NotaryAdmit).await?;
    let (subject_id, pool) = match identity {
        Some(principal) => {
            let plan: String = sqlx::query_scalar("SELECT service_plan FROM users WHERE id = $1")
                .bind(&principal.user_id)
                .fetch_one(&state.database)
                .await
                .map_err(database_error)?;
            let plan = ServicePlan::parse(&plan)?;
            let pool = match plan {
                ServicePlan::Free => AccessPool::Free,
                ServicePlan::PaidPreview => AccessPool::PaidPreview,
            };
            (Some(principal.user_id), pool)
        }
        None => (None, AccessPool::Public),
    };
    let policy = policy_for_pool(&state.admission, pool);
    let (record_digest, allowance) = validate_ticket_request(&request, policy)?;
    let now = unix_timestamp()?;
    let token = random_token();
    let directory_generation = i64::try_from(state.notary_directory.generation)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("directory generation is too large")))?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let recent_count: i64 = match subject_id.as_deref() {
        Some(subject_id) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_admission_tickets
             WHERE subject_id = $1 AND issued_at > $2",
        )
        .bind(subject_id)
        .bind(now - SECS_PER_MINUTE)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?,
        None => sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_admission_tickets
             WHERE subject_id IS NULL AND issued_at > $1",
        )
        .bind(now - SECS_PER_MINUTE)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database_error)?,
    };
    if recent_count >= policy.starts_per_minute {
        return Err(ApiError::too_many_requests("admission start rate exceeded"));
    }
    let expires_at = now + state.admission.ticket_ttl_secs;
    sqlx::query(
        "INSERT INTO notary_admission_tickets
         (token_hash, subject_id, access_pool, mode, directory_generation,
          record_digest, requested_allowance_bytes, session_timeout_secs,
          max_attestable_http_bytes, max_frame_bytes, max_private_chunk_bytes,
          max_private_chunk_commitments, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(subject_id.as_deref())
    .bind(pool.as_str())
    .bind(request.mode.as_str())
    .bind(directory_generation)
    .bind(record_digest)
    .bind(allowance)
    .bind(policy.session_timeout_secs)
    .bind(policy.max_attestable_http_bytes)
    .bind(policy.max_frame_bytes)
    .bind(policy.max_private_chunk_bytes)
    .bind(policy.max_private_chunk_commitments)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;

    let budget_subject = budget_subject(subject_id.as_deref());
    let remaining = remaining_budget(&state.database, &budget_subject, policy, now).await?;
    metrics::counter!("llm_notary_admission_tickets_total", "pool" => pool.as_str(), "mode" => request.mode.as_str()).increment(1);
    Ok(Json(AdmissionTicketResponse {
        ticket: token,
        expires_at,
        directory_generation: state.notary_directory.generation,
        entitlements: entitlements(pool, policy, remaining),
    }))
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/admissions/redeem",
    summary = "Consume a ticket and acquire a distributed notary lease",
    request_body = RedeemAdmissionRequest,
    responses(
        (status = 200, body = RedeemAdmissionResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 429, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("serviceBearer" = [])),
    tag = "notary-admission"
)]
async fn redeem_admission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RedeemAdmissionRequest>,
) -> ApiResult<Json<RedeemAdmissionResponse>> {
    authenticate_service(&state, &headers)?;
    validate_opaque(
        &request.ticket,
        MAX_TICKET_BYTES,
        "invalid admission ticket",
    )?;
    validate_opaque(
        &request.notary_instance_id,
        MAX_INSTANCE_ID_BYTES,
        "invalid notary instance identifier",
    )?;
    let now = unix_timestamp()?;
    let requested_generation = i64::try_from(request.directory_generation)
        .map_err(|_| ApiError::bad_request("directory generation is too large"))?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    expire_leases(&mut transaction, now).await?;
    let ticket = sqlx::query_as::<_, TicketRow>(
        "SELECT subject_id, access_pool, mode, directory_generation, record_digest,
                requested_allowance_bytes, session_timeout_secs, max_attestable_http_bytes,
                max_frame_bytes, max_private_chunk_bytes, max_private_chunk_commitments,
                expires_at, consumed_at
         FROM notary_admission_tickets WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(sha256_hex(request.ticket.as_bytes()))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::gone("admission ticket is invalid or expired"))?;
    if ticket.consumed_at.is_some() {
        return Err(ApiError::conflict("admission ticket was already consumed"));
    }
    if ticket.expires_at <= now {
        return Err(ApiError::gone("admission ticket is invalid or expired"));
    }
    if ticket.mode != request.mode.as_str() || ticket.directory_generation != requested_generation {
        return Err(ApiError::conflict(
            "admission ticket audience does not match",
        ));
    }
    let pool = parse_pool(&ticket.access_pool)?;
    let policy = policy_for_pool(&state.admission, pool);
    enforce_concurrency(&mut transaction, &state.admission, policy, &ticket, now).await?;
    if request.mode == AdmissionMode::Finalize {
        debit_finalization_budget(&mut transaction, policy, &ticket, now).await?;
    }
    let lease_id = Uuid::new_v4().to_string();
    let lease_expires_at = now + state.admission.lease_ttl_secs;
    sqlx::query(
        "INSERT INTO notary_admission_leases
         (id, notary_instance_id, subject_id, access_pool, mode, acquired_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&lease_id)
    .bind(&request.notary_instance_id)
    .bind(ticket.subject_id.as_deref())
    .bind(pool.as_str())
    .bind(request.mode.as_str())
    .bind(now)
    .bind(lease_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    sqlx::query(
        "UPDATE notary_admission_tickets
         SET consumed_at = $1, consumed_by_instance = $2, lease_id = $3
         WHERE token_hash = $4 AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(&request.notary_instance_id)
    .bind(&lease_id)
    .bind(sha256_hex(request.ticket.as_bytes()))
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    metrics::counter!("llm_notary_admission_leases_total", "pool" => pool.as_str(), "mode" => request.mode.as_str(), "outcome" => "admitted").increment(1);
    Ok(Json(RedeemAdmissionResponse {
        lease_id,
        lease_expires_at,
        access_pool: pool,
        session_timeout_secs: ticket.session_timeout_secs,
        max_attestable_http_bytes: ticket.max_attestable_http_bytes,
        max_frame_bytes: ticket.max_frame_bytes,
        max_private_chunk_bytes: ticket.max_private_chunk_bytes,
        max_private_chunk_commitments: ticket.max_private_chunk_commitments,
        record_digest: ticket.record_digest,
        authorized_allowance_bytes: ticket.requested_allowance_bytes,
    }))
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/leases/renew",
    summary = "Renew an active distributed notary lease",
    request_body = LeaseRequest,
    responses(
        (status = 200, body = LeaseRenewedResponse),
        (status = 401, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("serviceBearer" = [])),
    tag = "notary-admission"
)]
async fn renew_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> ApiResult<Json<LeaseRenewedResponse>> {
    authenticate_service(&state, &headers)?;
    validate_lease_request(&request)?;
    let now = unix_timestamp()?;
    let expires_at = now + state.admission.lease_ttl_secs;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    expire_leases(&mut transaction, now).await?;
    let renewed = sqlx::query(
        "UPDATE notary_admission_leases SET expires_at = $1
         WHERE id = $2 AND notary_instance_id = $3 AND released_at IS NULL
           AND terminal_state IS NULL AND expires_at > $4",
    )
    .bind(expires_at)
    .bind(&request.lease_id)
    .bind(&request.notary_instance_id)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if renewed.rows_affected() != 1 {
        return Err(ApiError::gone("admission lease is no longer active"));
    }
    transaction.commit().await.map_err(database_error)?;
    Ok(Json(LeaseRenewedResponse {
        lease_expires_at: expires_at,
    }))
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/leases/release",
    summary = "Release an active distributed notary lease",
    request_body = LeaseRequest,
    responses(
        (status = 204, description = "Lease released or already terminal"),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("serviceBearer" = [])),
    tag = "notary-admission"
)]
async fn release_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> ApiResult<StatusCode> {
    authenticate_service(&state, &headers)?;
    validate_lease_request(&request)?;
    let now = unix_timestamp()?;
    sqlx::query(
        "UPDATE notary_admission_leases
         SET released_at = COALESCE(released_at, $1), terminal_state = COALESCE(terminal_state, 'released')
         WHERE id = $2 AND notary_instance_id = $3",
    )
    .bind(now)
    .bind(&request.lease_id)
    .bind(&request.notary_instance_id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_ticket_request(
    request: &IssueAdmissionRequest,
    policy: &TierPolicy,
) -> ApiResult<(Option<String>, i64)> {
    match request.mode {
        AdmissionMode::Capture => {
            if request.record_digest.is_some() || request.requested_allowance_bytes.is_some() {
                return Err(ApiError::bad_request(
                    "capture admission must not include finalization fields",
                ));
            }
            Ok((None, policy.max_attestable_http_bytes))
        }
        AdmissionMode::Finalize => {
            let digest = request
                .record_digest
                .as_deref()
                .filter(|digest| {
                    digest.len() == 64
                        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && digest.bytes().all(|byte| !byte.is_ascii_uppercase())
                })
                .ok_or_else(|| {
                    ApiError::bad_request("record_digest must be 32-byte lowercase hex")
                })?;
            let allowance = request
                .requested_allowance_bytes
                .filter(|allowance| *allowance > 0)
                .ok_or_else(|| {
                    ApiError::bad_request("requested finalization allowance must be positive")
                })?;
            if allowance > policy.max_attestable_http_bytes {
                return Err(ApiError::bad_request(
                    "requested finalization allowance exceeds the per-session limit",
                ));
            }
            Ok((Some(digest.to_owned()), allowance))
        }
    }
}

fn authenticate_service(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(ApiError::unauthorized)?;
    let supplied = Sha256::digest(token.as_bytes());
    let expected = Sha256::digest(state.admission.service_token.as_bytes());
    if !bool::from(supplied.ct_eq(&expected)) {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}

async fn admission_lock(transaction: &mut Transaction<'_, Postgres>) -> ApiResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(ADMISSION_LOCK_NAMESPACE)
        .bind(ADMISSION_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    Ok(())
}

async fn expire_leases(transaction: &mut Transaction<'_, Postgres>, now: i64) -> ApiResult<()> {
    sqlx::query(
        "UPDATE notary_admission_leases
         SET terminal_state = 'expired'
         WHERE released_at IS NULL AND terminal_state IS NULL AND expires_at <= $1",
    )
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn enforce_concurrency(
    transaction: &mut Transaction<'_, Postgres>,
    config: &AdmissionConfig,
    policy: &TierPolicy,
    ticket: &TicketRow,
    now: i64,
) -> ApiResult<()> {
    let global_limit = match ticket.mode.as_str() {
        "capture" => config.global_capture_concurrency,
        "finalize" => config.global_finalize_concurrency,
        _ => return Err(ApiError::internal(anyhow::anyhow!("invalid ticket mode"))),
    };
    let pool_limit = match ticket.mode.as_str() {
        "capture" => policy.capture_concurrency,
        "finalize" => policy.finalize_concurrency,
        _ => unreachable!(),
    };
    let global: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notary_admission_leases
         WHERE mode = $1 AND released_at IS NULL AND expires_at > $2",
    )
    .bind(&ticket.mode)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let pool: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notary_admission_leases
         WHERE mode = $1 AND access_pool = $2 AND released_at IS NULL AND expires_at > $3",
    )
    .bind(&ticket.mode)
    .bind(&ticket.access_pool)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    if global >= global_limit || pool >= pool_limit {
        return Err(ApiError::too_many_requests(
            "notary capacity is temporarily full",
        ));
    }
    if let (Some(subject_id), Some(account_limit)) =
        (ticket.subject_id.as_deref(), policy.account_concurrency)
    {
        let account: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_admission_leases
             WHERE subject_id = $1 AND released_at IS NULL AND expires_at > $2",
        )
        .bind(subject_id)
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(database_error)?;
        if account >= account_limit {
            return Err(ApiError::too_many_requests(
                "account concurrency is temporarily full",
            ));
        }
    }
    Ok(())
}

async fn debit_finalization_budget(
    transaction: &mut Transaction<'_, Postgres>,
    policy: &TierPolicy,
    ticket: &TicketRow,
    now: i64,
) -> ApiResult<()> {
    let digest = ticket
        .record_digest
        .as_deref()
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("finalization ticket has no digest")))?;
    let budget_subject = budget_subject(ticket.subject_id.as_deref());
    let period_start = monthly_period_start(&mut **transaction, now).await?;
    if let Some(previous) = sqlx::query_scalar::<_, i64>(
        "SELECT allowance_bytes FROM notary_finalization_credit_ledger
         WHERE budget_subject = $1 AND record_digest = $2",
    )
    .bind(&budget_subject)
    .bind(digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    {
        if previous != ticket.requested_allowance_bytes {
            return Err(ApiError::conflict(
                "a retry must use the original finalization allowance",
            ));
        }
        return Ok(());
    }
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(allowance_bytes), 0)::BIGINT
         FROM notary_finalization_credit_ledger
         WHERE budget_subject = $1 AND period_start = $2",
    )
    .bind(&budget_subject)
    .bind(period_start)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    if used.saturating_add(ticket.requested_allowance_bytes) > policy.monthly_finalization_bytes {
        return Err(ApiError::payment_required(
            "finalization budget is exhausted",
        ));
    }
    sqlx::query(
        "INSERT INTO notary_finalization_credit_ledger
         (budget_subject, account_id, record_digest, allowance_bytes, period_start, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&budget_subject)
    .bind(ticket.subject_id.as_deref())
    .bind(digest)
    .bind(ticket.requested_allowance_bytes)
    .bind(period_start)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn remaining_budget(
    database: &super::DatabasePool,
    budget_subject: &str,
    policy: &TierPolicy,
    now: i64,
) -> ApiResult<i64> {
    let period_start = monthly_period_start(database, now).await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(allowance_bytes), 0)::BIGINT
         FROM notary_finalization_credit_ledger
         WHERE budget_subject = $1 AND period_start = $2",
    )
    .bind(budget_subject)
    .bind(period_start)
    .fetch_one(database)
    .await
    .map_err(database_error)?;
    Ok(policy.monthly_finalization_bytes.saturating_sub(used))
}

async fn monthly_period_start<'e, E>(executor: E, now: i64) -> ApiResult<i64>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM date_trunc('month', to_timestamp($1)))::BIGINT")
        .bind(now as f64)
        .fetch_one(executor)
        .await
        .map_err(database_error)
}

fn policy_for_pool(config: &AdmissionConfig, pool: AccessPool) -> &TierPolicy {
    match pool {
        AccessPool::Public => &config.public,
        AccessPool::Free => &config.free,
        AccessPool::PaidPreview => &config.paid_preview,
    }
}

fn entitlements(
    pool: AccessPool,
    policy: &TierPolicy,
    remaining_finalization_bytes: i64,
) -> EffectiveEntitlements {
    EffectiveEntitlements {
        access_pool: pool,
        capture_concurrency: policy.capture_concurrency,
        finalize_concurrency: policy.finalize_concurrency,
        account_concurrency: policy.account_concurrency,
        starts_per_minute: policy.starts_per_minute,
        session_timeout_secs: policy.session_timeout_secs,
        max_attestable_http_bytes: policy.max_attestable_http_bytes,
        max_frame_bytes: policy.max_frame_bytes,
        max_private_chunk_bytes: policy.max_private_chunk_bytes,
        max_private_chunk_commitments: policy.max_private_chunk_commitments,
        monthly_finalization_bytes: policy.monthly_finalization_bytes,
        remaining_finalization_bytes,
    }
}

fn budget_subject(subject_id: Option<&str>) -> String {
    subject_id
        .map(|subject_id| format!("user:{subject_id}"))
        .unwrap_or_else(|| "public".to_owned())
}

fn parse_pool(value: &str) -> ApiResult<AccessPool> {
    match value {
        "public" => Ok(AccessPool::Public),
        "free" => Ok(AccessPool::Free),
        "paid_preview" => Ok(AccessPool::PaidPreview),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "invalid admission pool"
        ))),
    }
}

fn validate_opaque(value: &str, maximum: usize, message: &'static str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request(message));
    }
    Ok(())
}

fn validate_lease_request(request: &LeaseRequest) -> ApiResult<()> {
    validate_opaque(&request.lease_id, 128, "invalid lease identifier")?;
    validate_opaque(
        &request.notary_instance_id,
        MAX_INSTANCE_ID_BYTES,
        "invalid notary instance identifier",
    )
}

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use serde::Deserialize;
    use url::Url;

    use super::*;

    async fn test_state() -> AppState {
        let database = super::super::fresh_database().await;
        AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://example.test/api/auth/github/callback").unwrap(),
            app_url: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            notary_directory: super::super::tests::directory_key(),
            publish: super::super::publish::PublishService::disabled_for_test(),
            library_metadata: super::super::admission::MetadataService::disabled(),
            admission: std::sync::Arc::new(AdmissionConfig::for_test()),
        }
    }

    fn service_headers(state: &AppState) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", state.admission.service_token)
                .parse()
                .unwrap(),
        );
        headers
    }

    struct TestNotaryInstance {
        http: reqwest::Client,
        origin: String,
        service_token: String,
        instance_id: &'static str,
        directory_generation: u64,
    }

    #[derive(Deserialize)]
    struct TestTicket {
        ticket: String,
    }

    #[derive(Deserialize)]
    struct TestLease {
        lease_id: String,
    }

    impl TestNotaryInstance {
        async fn redeem(&self, ticket: &str) -> reqwest::Response {
            self.http
                .post(format!(
                    "{}/api/internal/notary/admissions/redeem",
                    self.origin
                ))
                .bearer_auth(&self.service_token)
                .json(&serde_json::json!({
                    "ticket": ticket,
                    "notary_instance_id": self.instance_id,
                    "mode": "capture",
                    "directory_generation": self.directory_generation,
                }))
                .send()
                .await
                .unwrap()
        }

        async fn release(&self, lease_id: &str) -> reqwest::Response {
            self.http
                .post(format!(
                    "{}/api/internal/notary/leases/release",
                    self.origin
                ))
                .bearer_auth(&self.service_token)
                .json(&serde_json::json!({
                    "lease_id": lease_id,
                    "notary_instance_id": self.instance_id,
                }))
                .send()
                .await
                .unwrap()
        }
    }

    #[test]
    fn each_access_pool_has_distinct_limits() {
        let config = AdmissionConfig::for_test();
        assert!(config.public.max_attestable_http_bytes < config.free.max_attestable_http_bytes);
        assert!(
            config.free.max_attestable_http_bytes < config.paid_preview.max_attestable_http_bytes
        );
        assert!(config.public.session_timeout_secs < config.free.session_timeout_secs);
        assert!(config.free.session_timeout_secs < config.paid_preview.session_timeout_secs);
        assert!(config.public.monthly_finalization_bytes < config.free.monthly_finalization_bytes);
        assert!(
            config.free.monthly_finalization_bytes < config.paid_preview.monthly_finalization_bytes
        );
    }

    #[test]
    fn finalization_requires_a_bound_digest_and_allowance() {
        let policy = TierPolicy::free();
        let missing = IssueAdmissionRequest {
            mode: AdmissionMode::Finalize,
            record_digest: None,
            requested_allowance_bytes: Some(1),
        };
        assert!(validate_ticket_request(&missing, &policy).is_err());
        let valid = IssueAdmissionRequest {
            mode: AdmissionMode::Finalize,
            record_digest: Some("ab".repeat(32)),
            requested_allowance_bytes: Some(1024),
        };
        assert_eq!(
            validate_ticket_request(&valid, &policy).expect("valid request"),
            (valid.record_digest.clone(), 1024)
        );
        let oversized = IssueAdmissionRequest {
            mode: AdmissionMode::Finalize,
            record_digest: valid.record_digest,
            requested_allowance_bytes: Some(policy.max_attestable_http_bytes + 1),
        };
        assert!(validate_ticket_request(&oversized, &policy).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn two_instances_share_limits_and_expired_leases_recover_capacity() {
        let state = test_state().await;
        let issue = || {
            issue_admission(
                State(state.clone()),
                HeaderMap::new(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Capture,
                    record_digest: None,
                    requested_allowance_bytes: None,
                }),
            )
        };
        let first = issue().await.expect("first public ticket").0.ticket;
        let second = issue().await.expect("second public ticket").0.ticket;
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&state.database)
            .await
            .unwrap();
        assert_eq!(users, 0, "anonymous admission must not create an account");

        let redeem = |ticket: String, instance: &'static str| {
            redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.to_owned(),
                    mode: AdmissionMode::Capture,
                    directory_generation: state.notary_directory.generation,
                }),
            )
        };
        let lease = redeem(first.clone(), "notary-one")
            .await
            .expect("first instance admitted")
            .0;
        let at_capacity = redeem(second.clone(), "notary-two").await;
        assert!(matches!(
            at_capacity,
            Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
        let replay = redeem(first, "notary-two").await;
        assert!(matches!(
            replay,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));

        sqlx::query("UPDATE notary_admission_leases SET expires_at = 1 WHERE id = $1")
            .bind(&lease.lease_id)
            .execute(&state.database)
            .await
            .unwrap();
        let recovered = redeem(second, "notary-two")
            .await
            .expect("expired first-instance lease releases distributed capacity")
            .0;
        let renewed = renew_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: recovered.lease_id.clone(),
                notary_instance_id: "notary-two".into(),
            }),
        )
        .await
        .expect("active lease renews")
        .0;
        assert!(renewed.lease_expires_at > unix_timestamp().unwrap());
        release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: recovered.lease_id,
                notary_instance_id: "notary-two".into(),
            }),
        )
        .await
        .expect("active lease releases");
        let finalization_debits: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notary_finalization_credit_ledger")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(finalization_debits, 0, "captures must not consume credits");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn global_and_account_concurrency_are_shared_across_instances() {
        let mut state = test_state().await;
        let mut policy = (*state.admission).clone();
        policy.global_capture_concurrency = 1;
        policy.public.capture_concurrency = 2;
        state.admission = std::sync::Arc::new(policy);
        let issue_public = || {
            issue_admission(
                State(state.clone()),
                HeaderMap::new(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Capture,
                    record_digest: None,
                    requested_allowance_bytes: None,
                }),
            )
        };
        let global_first = issue_public().await.unwrap().0.ticket;
        let global_second = issue_public().await.unwrap().0.ticket;
        let global_state = state.clone();
        let global_redeem = move |ticket: String, instance: &'static str| {
            redeem_admission(
                State(global_state.clone()),
                service_headers(&global_state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.into(),
                    mode: AdmissionMode::Capture,
                    directory_generation: global_state.notary_directory.generation,
                }),
            )
        };
        let global_lease = global_redeem(global_first, "notary-global-one")
            .await
            .unwrap()
            .0;
        let global_rejection = global_redeem(global_second, "notary-global-two").await;
        assert!(matches!(
            global_rejection,
            Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "notary capacity is temporarily full",
            })
        ));
        release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: global_lease.lease_id,
                notary_instance_id: "notary-global-one".into(),
            }),
        )
        .await
        .unwrap();

        let mut policy = (*state.admission).clone();
        policy.global_capture_concurrency = 2;
        policy.free.capture_concurrency = 2;
        policy.free.account_concurrency = Some(1);
        state.admission = std::sync::Arc::new(policy);
        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('account-limit-user', 11, 'account-limit', $1, $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cli_sessions
             (id, user_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
             VALUES ('account-limit-session', 'account-limit-user', 'test', 'account-refresh', $1, $1, $2)",
        )
        .bind(now)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        let access_token = "account-limit-access";
        sqlx::query(
            "INSERT INTO cli_access_tokens (token_hash, session_id, expires_at, created_at)
             VALUES ($1, 'account-limit-session', $2, $3)",
        )
        .bind(sha256_hex(access_token.as_bytes()))
        .bind(now + 60)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let mut authenticated = HeaderMap::new();
        authenticated.insert(
            header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let issue_account = || {
            issue_admission(
                State(state.clone()),
                authenticated.clone(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Capture,
                    record_digest: None,
                    requested_allowance_bytes: None,
                }),
            )
        };
        let account_first = issue_account().await.unwrap().0.ticket;
        let account_second = issue_account().await.unwrap().0.ticket;
        let account_state = state.clone();
        let account_redeem = move |ticket: String, instance: &'static str| {
            redeem_admission(
                State(account_state.clone()),
                service_headers(&account_state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.into(),
                    mode: AdmissionMode::Capture,
                    directory_generation: account_state.notary_directory.generation,
                }),
            )
        };
        let _account_lease = account_redeem(account_first, "notary-account-one")
            .await
            .unwrap();
        let account_rejection = account_redeem(account_second, "notary-account-two").await;
        assert!(matches!(
            account_rejection,
            Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "account concurrency is temporarily full",
            })
        ));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn two_notary_clients_share_capacity_through_the_service_boundary() {
        let state = test_state().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app: axum::Router = super::super::hosted_router()
            .with_state(state.clone())
            .into();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let origin = format!("http://{address}");
        let issue_client = reqwest::Client::new();
        let issue = || async {
            issue_client
                .post(format!("{origin}/api/notary/admissions"))
                .json(&serde_json::json!({ "mode": "capture" }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<TestTicket>()
                .await
                .unwrap()
                .ticket
        };
        let first_ticket = issue().await;
        let second_ticket = issue().await;
        let instance = |instance_id| TestNotaryInstance {
            http: reqwest::Client::new(),
            origin: origin.clone(),
            service_token: state.admission.service_token.clone(),
            instance_id,
            directory_generation: state.notary_directory.generation,
        };
        let first = instance("notary-http-one");
        let second = instance("notary-http-two");

        let first_lease = first
            .redeem(&first_ticket)
            .await
            .error_for_status()
            .unwrap()
            .json::<TestLease>()
            .await
            .unwrap();
        assert_eq!(
            second.redeem(&second_ticket).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            first.release(&first_lease.lease_id).await.status(),
            StatusCode::NO_CONTENT
        );
        second
            .redeem(&second_ticket)
            .await
            .error_for_status()
            .unwrap();
        let distinct_instances: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT notary_instance_id) FROM notary_admission_leases",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(distinct_instances, 2);
        server.abort();
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn small_bundle_debits_exactly_once_and_retries_require_its_stable_allowance() {
        let state = test_state().await;
        let digest = "cd".repeat(32);
        let issue = || {
            issue_admission(
                State(state.clone()),
                HeaderMap::new(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Finalize,
                    record_digest: Some(digest.clone()),
                    requested_allowance_bytes: Some(1024),
                }),
            )
        };
        for instance in ["notary-one", "notary-two"] {
            let ticket = issue().await.expect("finalization ticket").0.ticket;
            let lease = redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.into(),
                    mode: AdmissionMode::Finalize,
                    directory_generation: state.notary_directory.generation,
                }),
            )
            .await
            .expect("finalization admitted")
            .0;
            release_lease(
                State(state.clone()),
                service_headers(&state),
                Json(LeaseRequest {
                    lease_id: lease.lease_id,
                    notary_instance_id: instance.into(),
                }),
            )
            .await
            .unwrap();
        }
        let changed_allowance = issue_admission(
            State(state.clone()),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Finalize,
                record_digest: Some(digest.clone()),
                requested_allowance_bytes: Some(2048),
            }),
        )
        .await
        .expect("changed-allowance ticket")
        .0
        .ticket;
        let rejected_retry = redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Json(RedeemAdmissionRequest {
                ticket: changed_allowance,
                notary_instance_id: "notary-three".into(),
                mode: AdmissionMode::Finalize,
                directory_generation: state.notary_directory.generation,
            }),
        )
        .await;
        assert!(matches!(
            rejected_retry,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let ledger: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(allowance_bytes), 0)::BIGINT
             FROM notary_finalization_credit_ledger WHERE record_digest = $1",
        )
        .bind(digest)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(ledger, (1, 1024));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn dashboard_plan_change_is_authoritative_for_new_tickets() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'octo', 1, 1)",
        )
        .execute(&state.database)
        .await
        .unwrap();
        let session = "browser-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, 1)",
        )
        .bind(sha256_hex(session.as_bytes()))
        .bind(unix_timestamp().unwrap() + 60)
        .execute(&state.database)
        .await
        .unwrap();
        let response = change_plan(
            State(state.clone()),
            CookieJar::new().add(Cookie::new(super::super::SESSION_COOKIE, session)),
            Json(ChangePlanRequest {
                plan: ServicePlan::PaidPreview,
            }),
        )
        .await
        .expect("plan update")
        .0;
        assert_eq!(response.plan, ServicePlan::PaidPreview);
        assert_eq!(response.entitlements.access_pool, AccessPool::PaidPreview);
        let stored: String =
            sqlx::query_scalar("SELECT service_plan FROM users WHERE id = 'user-1'")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(stored, "paid_preview");

        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO cli_sessions
             (id, user_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
             VALUES ('cli-session', 'user-1', 'test notary', 'refresh-hash', $1, $1, $2)",
        )
        .bind(now)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        let access_token = "cli-access-token";
        sqlx::query(
            "INSERT INTO cli_access_tokens (token_hash, session_id, expires_at, created_at)
             VALUES ($1, 'cli-session', $2, $3)",
        )
        .bind(sha256_hex(access_token.as_bytes()))
        .bind(now + 60)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let mut cli_headers = HeaderMap::new();
        cli_headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let paid_ticket = issue_admission(
            State(state.clone()),
            cli_headers.clone(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .expect("paid-preview admission")
        .0;
        assert_eq!(
            paid_ticket.entitlements.access_pool,
            AccessPool::PaidPreview
        );

        let free = change_plan(
            State(state.clone()),
            CookieJar::new().add(Cookie::new(super::super::SESSION_COOKIE, session)),
            Json(ChangePlanRequest {
                plan: ServicePlan::Free,
            }),
        )
        .await
        .expect("switch back to free")
        .0;
        assert_eq!(free.entitlements.access_pool, AccessPool::Free);
        let free_ticket = issue_admission(
            State(state),
            cli_headers,
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .expect("free admission")
        .0;
        assert_eq!(free_ticket.entitlements.access_pool, AccessPool::Free);
    }
}
