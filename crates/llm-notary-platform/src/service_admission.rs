use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::subtle::ConstantTimeEq as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, ErrorResponse,
    authn::{ApiScope, optional_authenticated_principal},
    config::{AdmissionConfig, AdmissionPolicy},
    database_error, random_token, unix_timestamp,
};
use llm_notary_core::sha256_hex;

const ADMISSION_LOCK_NAMESPACE: i32 = 151;
const ADMISSION_LOCK_KEY: i32 = 1;
const MAX_TICKET_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const SECS_PER_DAY: i64 = 24 * 60 * 60;
const CLIENT_IP_HEADER: &str = "x-llm-notary-client-ip";
const PUBLIC_SUBJECT_PURPOSE: &str = "hosted-finalization-public-subject";
const ACCOUNT_TESTING_GRANT_ID: &str = "hosted-finalization-testing-v1";
const ACCOUNT_TESTING_GRANT_AMOUNT_BYTES: i64 = 128 << 20;
const PROMOTIONAL_OFFER_ID: &str = "hosted-finalization-bonus-v1";
const PROMOTIONAL_OFFER_AMOUNT_BYTES: i64 = 128 << 20;
const PROMOTIONAL_OFFER_CLAIM_DEADLINE: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z
const PROMOTIONAL_GRANT_TTL_SECS: i64 = 90 * SECS_PER_DAY;
const CREDIT_HISTORY_LIMIT: i64 = 20;

type HmacSha256 = Hmac<Sha256>;

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
}

impl AccessPool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Free => "free",
        }
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct AdmissionLimits {
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CreditHistoryKind {
    Grant,
    Debit,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditHistoryEntry {
    pub id: String,
    pub kind: CreditHistoryKind,
    pub amount_bytes: i64,
    pub source_kind: Option<String>,
    pub display_label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditSummary {
    pub total_remaining_bytes: i64,
    pub included_monthly_remaining_bytes: i64,
    pub supplemental_remaining_bytes: i64,
    pub reset_at: i64,
    pub next_grant_expiration: Option<i64>,
    pub history: Vec<CreditHistoryEntry>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditOffer {
    pub id: String,
    pub title: String,
    pub description: String,
    pub amount_bytes: i64,
    pub claim_expires_at: i64,
    pub credit_expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct CreditOffersResponse {
    pub offers: Vec<CreditOffer>,
}

#[derive(Serialize, ToSchema)]
pub struct ClaimCreditOfferResponse {
    pub offer_id: String,
    pub credits: CreditSummary,
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
    pub limits: AdmissionLimits,
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
    credit_subject: String,
    access_pool: String,
    mode: String,
    directory_generation: i64,
    record_digest: Option<String>,
    requested_allowance_bytes: i64,
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
        .routes(routes!(eligible_credit_offers))
        .routes(routes!(claim_credit_offer))
        .routes(routes!(redeem_admission))
        .routes(routes!(renew_lease))
        .routes(routes!(release_lease))
}

pub async fn account_access(state: &AppState, user_id: &str) -> ApiResult<CreditSummary> {
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let pool = AccessPool::Free;
    let policy = policy_for_pool(&state.admission, pool);
    let credit_subject = account_credit_subject(user_id);
    ensure_credit_grants(
        &mut transaction,
        &credit_subject,
        Some(user_id),
        pool,
        policy,
        now,
    )
    .await?;
    transaction.commit().await.map_err(database_error)?;
    let credits = credit_summary(&state.database, &credit_subject, now).await?;
    Ok(credits)
}

#[utoipa::path(
    get,
    path = "/api/me/credit-offers",
    summary = "List promotional credit offers eligible for the signed-in account",
    responses(
        (status = 200, body = CreditOffersResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn eligible_credit_offers(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> ApiResult<Json<CreditOffersResponse>> {
    let user = super::authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let claimed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM notary_credit_grants
             WHERE credit_subject = $1 AND source_kind = 'promotion'
               AND source_reference = $2
         )",
    )
    .bind(account_credit_subject(&user.0))
    .bind(PROMOTIONAL_OFFER_ID)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    let offers = if promotional_offer_eligible(claimed, now) {
        vec![promotional_offer(now)]
    } else {
        Vec::new()
    };
    Ok(Json(CreditOffersResponse { offers }))
}

#[utoipa::path(
    post,
    path = "/api/me/credit-offers/{offer_id}/claim",
    summary = "Claim one server-defined promotional credit offer",
    params(("offer_id" = String, Path)),
    responses(
        (status = 200, body = ClaimCreditOfferResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn claim_credit_offer(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(offer_id): Path<String>,
) -> ApiResult<Json<ClaimCreditOfferResponse>> {
    let user = super::authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let credit_subject = account_credit_subject(&user.0);
    let pool = AccessPool::Free;
    ensure_credit_grants(
        &mut transaction,
        &credit_subject,
        Some(&user.0),
        pool,
        policy_for_pool(&state.admission, pool),
        now,
    )
    .await?;
    let claimed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM notary_credit_grants
             WHERE credit_subject = $1 AND source_kind = 'promotion'
               AND source_reference = $2
         )",
    )
    .bind(&credit_subject)
    .bind(PROMOTIONAL_OFFER_ID)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database_error)?;
    if offer_id != PROMOTIONAL_OFFER_ID || !promotional_offer_eligible(claimed, now) {
        if offer_id == PROMOTIONAL_OFFER_ID && claimed {
            return Err(ApiError::coded(
                StatusCode::CONFLICT,
                "credit_offer_already_claimed",
                "This credit offer has already been claimed",
            ));
        }
        return Err(ApiError::coded(
            StatusCode::FORBIDDEN,
            "credit_offer_not_eligible",
            "This account is not eligible for the credit offer",
        ));
    }
    create_credit_grant(
        &mut transaction,
        CreditGrantSpec {
            credit_subject: &credit_subject,
            account_id: Some(&user.0),
            amount_bytes: PROMOTIONAL_OFFER_AMOUNT_BYTES,
            source_kind: "promotion",
            source_reference: PROMOTIONAL_OFFER_ID,
            idempotency_key: &format!("promotion:{PROMOTIONAL_OFFER_ID}"),
            period_start: None,
            period_end: None,
            created_at: now,
            available_at: now,
            expires_at: Some(now + PROMOTIONAL_GRANT_TTL_SECS),
            display_label: "Hosted finalization bonus",
        },
    )
    .await?;
    transaction.commit().await.map_err(database_error)?;
    let credits = credit_summary(&state.database, &credit_subject, now).await?;
    Ok(Json(ClaimCreditOfferResponse { offer_id, credits }))
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
        (status = 402, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 429, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security((), ("bearerAuth" = [])),
    tag = "notary-admission"
)]
async fn issue_admission(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<IssueAdmissionRequest>,
) -> ApiResult<Json<AdmissionTicketResponse>> {
    let identity =
        optional_authenticated_principal(&state, &headers, ApiScope::NotaryAdmit).await?;
    let now = unix_timestamp()?;
    let period = monthly_credit_period(&state.database, now).await?;
    let (subject_id, credit_subject, pool) = match identity {
        Some(principal) => {
            let credit_subject = account_credit_subject(&principal.user_id);
            (Some(principal.user_id), credit_subject, AccessPool::Free)
        }
        None => {
            let client_ip = resolve_client_ip(&headers, Some(peer), &state.admission)?;
            let credit_subject = public_credit_subject(
                client_ip,
                period.start,
                &state.admission.anonymous_subject_hmac_key,
                state.admission.anonymous_subject_key_version,
            )?;
            (None, credit_subject, AccessPool::Public)
        }
    };
    let policy = policy_for_pool(&state.admission, pool);
    let (record_digest, allowance) = validate_ticket_request(&request, policy)?;
    let token = random_token();
    let directory_generation = i64::try_from(state.notary_directory.generation)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("directory generation is too large")))?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    ensure_credit_grants(
        &mut transaction,
        &credit_subject,
        subject_id.as_deref(),
        pool,
        policy,
        now,
    )
    .await?;
    if request.mode == AdmissionMode::Finalize {
        preflight_finalization_credits(
            &mut transaction,
            &credit_subject,
            record_digest
                .as_deref()
                .expect("validated finalization digest"),
            allowance,
            now,
        )
        .await?;
    }
    let expires_at = now + state.admission.ticket_ttl_secs;
    sqlx::query(
        "INSERT INTO notary_admission_tickets
         (token_hash, subject_id, credit_subject, access_pool, mode, directory_generation,
          record_digest, requested_allowance_bytes, max_attestable_http_bytes, max_frame_bytes,
          max_private_chunk_bytes, max_private_chunk_commitments, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(subject_id.as_deref())
    .bind(&credit_subject)
    .bind(pool.as_str())
    .bind(request.mode.as_str())
    .bind(directory_generation)
    .bind(record_digest)
    .bind(allowance)
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

    metrics::counter!("llm_notary_admission_tickets_total", "pool" => pool.as_str(), "mode" => request.mode.as_str()).increment(1);
    Ok(Json(AdmissionTicketResponse {
        ticket: token,
        expires_at,
        directory_generation: state.notary_directory.generation,
        limits: admission_limits(policy),
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
        (status = 402, body = ErrorResponse),
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
        "SELECT subject_id, credit_subject, access_pool, mode, directory_generation, record_digest,
                requested_allowance_bytes, max_attestable_http_bytes, max_frame_bytes,
                max_private_chunk_bytes, max_private_chunk_commitments, expires_at, consumed_at
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
    let credit_subject = ticket.credit_subject.clone();
    ensure_credit_grants(
        &mut transaction,
        &credit_subject,
        ticket.subject_id.as_deref(),
        pool,
        policy,
        now,
    )
    .await?;
    enforce_concurrency(&mut transaction, &state.admission, policy, &ticket, now).await?;
    if request.mode == AdmissionMode::Finalize {
        debit_finalization_credits(&mut transaction, &ticket, now).await?;
    }
    let lease_id = Uuid::new_v4().to_string();
    let lease_expires_at = now + state.admission.lease_ttl_secs;
    sqlx::query(
        "INSERT INTO notary_admission_leases
         (id, notary_instance_id, subject_id, credit_subject, access_pool, mode, acquired_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&lease_id)
    .bind(&request.notary_instance_id)
    .bind(ticket.subject_id.as_deref())
    .bind(&ticket.credit_subject)
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
    policy: &AdmissionPolicy,
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
    policy: &AdmissionPolicy,
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
    Ok(())
}

#[derive(Clone, Copy)]
struct CreditPeriod {
    start: i64,
    end: i64,
}

struct CreditGrantSpec<'a> {
    credit_subject: &'a str,
    account_id: Option<&'a str>,
    amount_bytes: i64,
    source_kind: &'a str,
    source_reference: &'a str,
    idempotency_key: &'a str,
    period_start: Option<i64>,
    period_end: Option<i64>,
    created_at: i64,
    available_at: i64,
    expires_at: Option<i64>,
    display_label: &'a str,
}

#[derive(FromRow)]
struct ExistingGrantRow {
    id: String,
    account_id: Option<String>,
    amount_bytes: i64,
    source_kind: String,
    source_reference: String,
    idempotency_key: String,
    period_start: Option<i64>,
    period_end: Option<i64>,
    created_at: i64,
    available_at: i64,
    expires_at: Option<i64>,
    display_label: Option<String>,
}

#[derive(FromRow)]
struct GrantBalanceRow {
    source_kind: String,
    expires_at: Option<i64>,
    remaining_bytes: i64,
}

async fn create_credit_grant(
    transaction: &mut Transaction<'_, Postgres>,
    spec: CreditGrantSpec<'_>,
) -> ApiResult<String> {
    if spec.amount_bytes <= 0
        || spec.credit_subject.is_empty()
        || spec.credit_subject.len() > 160
        || spec.source_reference.is_empty()
        || spec.source_reference.len() > 256
        || spec.idempotency_key.is_empty()
        || spec.idempotency_key.len() > 256
        || spec.display_label.len() > 120
        || spec
            .account_id
            .is_some_and(|account_id| account_credit_subject(account_id) != spec.credit_subject)
        || spec
            .expires_at
            .is_some_and(|expires| expires <= spec.available_at)
    {
        return Err(ApiError::internal(anyhow::anyhow!(
            "invalid server-authored credit grant"
        )));
    }
    let existing = sqlx::query_as::<_, ExistingGrantRow>(
        "SELECT id, account_id, amount_bytes, source_kind, source_reference, idempotency_key,
                period_start, period_end, created_at, available_at, expires_at, display_label
         FROM notary_credit_grants
         WHERE credit_subject = $1
           AND ((source_kind = $2 AND source_reference = $3) OR idempotency_key = $4)
         FOR UPDATE",
    )
    .bind(spec.credit_subject)
    .bind(spec.source_kind)
    .bind(spec.source_reference)
    .bind(spec.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    if let Some(existing) = existing {
        if existing.account_id.as_deref() != spec.account_id
            || existing.amount_bytes != spec.amount_bytes
            || existing.source_kind != spec.source_kind
            || existing.source_reference != spec.source_reference
            || existing.idempotency_key != spec.idempotency_key
            || existing.period_start != spec.period_start
            || existing.period_end != spec.period_end
            || existing.created_at != spec.created_at
            || existing.available_at != spec.available_at
            || existing.expires_at != spec.expires_at
            || existing.display_label.as_deref() != Some(spec.display_label)
        {
            return Err(ApiError::conflict(
                "credit grant idempotency key was already used for different grant data",
            ));
        }
        return Ok(existing.id);
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO notary_credit_grants
         (id, credit_subject, account_id, amount_bytes, source_kind, source_reference,
          idempotency_key, period_start, period_end, created_at, available_at, expires_at,
          display_label)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(&id)
    .bind(spec.credit_subject)
    .bind(spec.account_id)
    .bind(spec.amount_bytes)
    .bind(spec.source_kind)
    .bind(spec.source_reference)
    .bind(spec.idempotency_key)
    .bind(spec.period_start)
    .bind(spec.period_end)
    .bind(spec.created_at)
    .bind(spec.available_at)
    .bind(spec.expires_at)
    .bind(spec.display_label)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(id)
}

async fn ensure_monthly_grant(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    account_id: Option<&str>,
    pool: AccessPool,
    policy: &AdmissionPolicy,
    now: i64,
) -> ApiResult<()> {
    let period = monthly_credit_period(&mut **transaction, now).await?;
    let included: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
         FROM notary_credit_grants
         WHERE credit_subject = $1 AND source_kind = 'included_monthly'
           AND period_start = $2",
    )
    .bind(credit_subject)
    .bind(period.start)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let amount = policy
        .monthly_finalization_bytes
        .saturating_sub(included)
        .max(0);
    if amount == 0 {
        return Ok(());
    }
    let reference = format!("monthly:{}:{}", pool.as_str(), period.start);
    let label = match pool {
        AccessPool::Public => "Monthly Public credits",
        AccessPool::Free => "Monthly Free credits",
    };
    create_credit_grant(
        transaction,
        CreditGrantSpec {
            credit_subject,
            account_id,
            amount_bytes: amount,
            source_kind: "included_monthly",
            source_reference: &reference,
            idempotency_key: &reference,
            period_start: Some(period.start),
            period_end: Some(period.end),
            created_at: now,
            available_at: period.start,
            expires_at: Some(period.end),
            display_label: label,
        },
    )
    .await?;
    Ok(())
}

async fn ensure_credit_grants(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    account_id: Option<&str>,
    pool: AccessPool,
    policy: &AdmissionPolicy,
    now: i64,
) -> ApiResult<()> {
    ensure_monthly_grant(transaction, credit_subject, account_id, pool, policy, now).await?;
    let Some(account_id) = account_id else {
        return Ok(());
    };
    let already_issued: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM notary_credit_grants
             WHERE credit_subject = $1 AND source_kind = 'manual_adjustment'
               AND source_reference = $2
         )",
    )
    .bind(credit_subject)
    .bind(ACCOUNT_TESTING_GRANT_ID)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    if already_issued {
        return Ok(());
    }
    create_credit_grant(
        transaction,
        CreditGrantSpec {
            credit_subject,
            account_id: Some(account_id),
            amount_bytes: ACCOUNT_TESTING_GRANT_AMOUNT_BYTES,
            source_kind: "manual_adjustment",
            source_reference: ACCOUNT_TESTING_GRANT_ID,
            idempotency_key: ACCOUNT_TESTING_GRANT_ID,
            period_start: None,
            period_end: None,
            created_at: now,
            available_at: now,
            expires_at: None,
            display_label: "Automatic testing credits",
        },
    )
    .await?;
    Ok(())
}

async fn debit_finalization_credits(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &TicketRow,
    now: i64,
) -> ApiResult<()> {
    let digest = ticket
        .record_digest
        .as_deref()
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("finalization ticket has no digest")))?;
    let credit_subject = ticket.credit_subject.clone();
    if let Some(previous) = sqlx::query_scalar::<_, i64>(
        "SELECT allowance_bytes FROM notary_credit_debits
         WHERE credit_subject = $1 AND record_digest = $2",
    )
    .bind(&credit_subject)
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
    let grants = available_grants(transaction, &credit_subject, now).await?;
    let available = grants.iter().fold(0_i64, |total, (_, remaining)| {
        total.saturating_add(*remaining)
    });
    if available < ticket.requested_allowance_bytes {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            "finalization_credits_exhausted",
            "There are not enough hosted finalization credits for this capture",
        ));
    }
    let debit_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO notary_credit_debits
         (id, credit_subject, account_id, record_digest, allowance_bytes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&debit_id)
    .bind(&credit_subject)
    .bind(ticket.subject_id.as_deref())
    .bind(digest)
    .bind(ticket.requested_allowance_bytes)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    allocate_debit(
        transaction,
        &debit_id,
        ticket.requested_allowance_bytes,
        &grants,
    )
    .await?;
    Ok(())
}

async fn preflight_finalization_credits(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    digest: &str,
    allowance: i64,
    now: i64,
) -> ApiResult<()> {
    if let Some(previous) = sqlx::query_scalar::<_, i64>(
        "SELECT allowance_bytes FROM notary_credit_debits
         WHERE credit_subject = $1 AND record_digest = $2",
    )
    .bind(credit_subject)
    .bind(digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    {
        return if previous == allowance {
            Ok(())
        } else {
            Err(ApiError::conflict(
                "a retry must use the original finalization allowance",
            ))
        };
    }
    let available = available_grants(transaction, credit_subject, now)
        .await?
        .iter()
        .map(|(_, remaining)| *remaining)
        .sum::<i64>();
    if available < allowance {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            "finalization_credits_exhausted",
            "There are not enough hosted finalization credits for this capture",
        ));
    }
    Ok(())
}

async fn available_grants(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    now: i64,
) -> ApiResult<Vec<(String, i64)>> {
    sqlx::query_as::<_, (String, i64)>(
        "SELECT grants.id,
                grants.amount_bytes - COALESCE((
                    SELECT SUM(allocations.amount_bytes)
                    FROM notary_credit_debit_allocations AS allocations
                    WHERE allocations.grant_id = grants.id
                ), 0)::BIGINT AS remaining_bytes
         FROM notary_credit_grants AS grants
         WHERE grants.credit_subject = $1 AND grants.available_at <= $2
           AND (grants.expires_at IS NULL OR grants.expires_at > $2)
           AND grants.amount_bytes - COALESCE((
                   SELECT SUM(allocations.amount_bytes)
                   FROM notary_credit_debit_allocations AS allocations
                   WHERE allocations.grant_id = grants.id
               ), 0)::BIGINT > 0
         ORDER BY grants.expires_at ASC NULLS LAST, grants.available_at, grants.created_at,
                  grants.id
         FOR UPDATE OF grants",
    )
    .bind(credit_subject)
    .bind(now)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)
}

async fn allocate_debit(
    transaction: &mut Transaction<'_, Postgres>,
    debit_id: &str,
    amount_bytes: i64,
    grants: &[(String, i64)],
) -> ApiResult<()> {
    let mut unallocated = amount_bytes;
    for (order, (grant_id, remaining)) in grants.iter().enumerate() {
        if unallocated == 0 {
            break;
        }
        let allocated = unallocated.min(*remaining);
        sqlx::query(
            "INSERT INTO notary_credit_debit_allocations
             (debit_id, grant_id, amount_bytes, allocation_order)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(debit_id)
        .bind(grant_id)
        .bind(allocated)
        .bind(i32::try_from(order).map_err(|_| {
            ApiError::internal(anyhow::anyhow!("too many credit grant allocations"))
        })?)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
        unallocated -= allocated;
    }
    if unallocated != 0 {
        return Err(ApiError::internal(anyhow::anyhow!(
            "credit allocation did not cover its debit"
        )));
    }
    Ok(())
}

async fn credit_summary(
    database: &super::DatabasePool,
    credit_subject: &str,
    now: i64,
) -> ApiResult<CreditSummary> {
    let period = monthly_credit_period(database, now).await?;
    let balances = sqlx::query_as::<_, GrantBalanceRow>(
        "SELECT grants.source_kind, grants.expires_at,
                grants.amount_bytes - COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT
                    AS remaining_bytes
         FROM notary_credit_grants AS grants
         LEFT JOIN notary_credit_debit_allocations AS allocations
           ON allocations.grant_id = grants.id
         WHERE grants.credit_subject = $1 AND grants.available_at <= $2
           AND (grants.expires_at IS NULL OR grants.expires_at > $2)
         GROUP BY grants.id
         HAVING grants.amount_bytes - COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT > 0
         ORDER BY grants.expires_at ASC NULLS LAST, grants.created_at, grants.id",
    )
    .bind(credit_subject)
    .bind(now)
    .fetch_all(database)
    .await
    .map_err(database_error)?;
    let included_monthly_remaining_bytes = balances
        .iter()
        .filter(|grant| grant.source_kind == "included_monthly")
        .map(|grant| grant.remaining_bytes)
        .sum::<i64>();
    let supplemental_remaining_bytes = balances
        .iter()
        .filter(|grant| grant.source_kind != "included_monthly")
        .map(|grant| grant.remaining_bytes)
        .sum::<i64>();
    let next_grant_expiration = balances.iter().filter_map(|grant| grant.expires_at).min();

    let mut history = sqlx::query_as::<_, (String, String, i64, String, i64, Option<i64>)>(
        "SELECT id, source_kind, amount_bytes,
                COALESCE(display_label, 'Hosted finalization credits'), created_at, expires_at
         FROM notary_credit_grants
         WHERE credit_subject = $1
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(credit_subject)
    .bind(CREDIT_HISTORY_LIMIT)
    .fetch_all(database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(
        |(id, source_kind, amount_bytes, display_label, created_at, expires_at)| {
            CreditHistoryEntry {
                id,
                kind: CreditHistoryKind::Grant,
                amount_bytes,
                source_kind: Some(source_kind),
                display_label,
                created_at,
                expires_at,
            }
        },
    )
    .collect::<Vec<_>>();
    let debits = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT id, allowance_bytes, created_at FROM notary_credit_debits
         WHERE credit_subject = $1
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(credit_subject)
    .bind(CREDIT_HISTORY_LIMIT)
    .fetch_all(database)
    .await
    .map_err(database_error)?;
    history.extend(
        debits
            .into_iter()
            .map(|(id, amount_bytes, created_at)| CreditHistoryEntry {
                id,
                kind: CreditHistoryKind::Debit,
                amount_bytes,
                source_kind: None,
                display_label: "Hosted finalization".to_owned(),
                created_at,
                expires_at: None,
            }),
    );
    history.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.id.cmp(&left.id))
    });
    history.truncate(CREDIT_HISTORY_LIMIT as usize);
    Ok(CreditSummary {
        total_remaining_bytes: included_monthly_remaining_bytes
            .saturating_add(supplemental_remaining_bytes),
        included_monthly_remaining_bytes,
        supplemental_remaining_bytes,
        reset_at: period.end,
        next_grant_expiration,
        history,
    })
}

async fn monthly_credit_period<'e, E>(executor: E, now: i64) -> ApiResult<CreditPeriod>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let (start, end) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT EXTRACT(EPOCH FROM (
                    date_trunc('month', to_timestamp($1) AT TIME ZONE 'UTC')
                    AT TIME ZONE 'UTC'
                ))::BIGINT,
                EXTRACT(EPOCH FROM (
                    (date_trunc('month', to_timestamp($1) AT TIME ZONE 'UTC')
                     + interval '1 month')
                    AT TIME ZONE 'UTC'
                ))::BIGINT",
    )
    .bind(now as f64)
    .fetch_one(executor)
    .await
    .map_err(database_error)?;
    Ok(CreditPeriod { start, end })
}

fn policy_for_pool(config: &AdmissionConfig, pool: AccessPool) -> &AdmissionPolicy {
    match pool {
        AccessPool::Public => &config.public,
        AccessPool::Free => &config.free,
    }
}

fn admission_limits(policy: &AdmissionPolicy) -> AdmissionLimits {
    AdmissionLimits {
        max_attestable_http_bytes: policy.max_attestable_http_bytes,
        max_frame_bytes: policy.max_frame_bytes,
        max_private_chunk_bytes: policy.max_private_chunk_bytes,
        max_private_chunk_commitments: policy.max_private_chunk_commitments,
    }
}

fn account_credit_subject(user_id: &str) -> String {
    format!("user:{user_id}")
}

fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &AdmissionConfig,
) -> ApiResult<IpAddr> {
    let peer = peer.ok_or_else(|| ApiError::bad_request("client address is unavailable"))?;
    let peer_ip = canonical_ip(peer.ip());
    let trusted = config
        .trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&peer_ip));
    if trusted {
        return Ok(headers
            .get(CLIENT_IP_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok())
            .map(canonical_ip)
            .unwrap_or(peer_ip));
    }
    Ok(peer_ip)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn normalized_client_address(ip: IpAddr) -> String {
    match canonical_ip(ip) {
        IpAddr::V4(address) => format!("v4:{address}"),
        IpAddr::V6(address) => {
            let segments = address.segments();
            let prefix = Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            );
            format!("v6:{prefix}/64")
        }
    }
}

fn public_credit_subject(
    ip: IpAddr,
    period_start: i64,
    key: &[u8],
    key_version: u32,
) -> ApiResult<String> {
    let normalized = normalized_client_address(ip);
    let version = key_version.to_string();
    let period = period_start.to_string();
    let mut hmac = HmacSha256::new_from_slice(key)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid anonymous subject key")))?;
    for value in [
        PUBLIC_SUBJECT_PURPOSE.as_bytes(),
        version.as_bytes(),
        period.as_bytes(),
        normalized.as_bytes(),
    ] {
        hmac.update(&(value.len() as u64).to_be_bytes());
        hmac.update(value);
    }
    Ok(format!(
        "public:v{key_version}:{}",
        hex::encode(hmac.finalize().into_bytes())
    ))
}

fn promotional_offer_eligible(claimed: bool, now: i64) -> bool {
    !claimed && now < PROMOTIONAL_OFFER_CLAIM_DEADLINE
}

fn promotional_offer(now: i64) -> CreditOffer {
    CreditOffer {
        id: PROMOTIONAL_OFFER_ID.to_owned(),
        title: "128 MiB hosted finalization bonus".to_owned(),
        description: "Claim once for hosted finalization. The bonus expires after 90 days."
            .to_owned(),
        amount_bytes: PROMOTIONAL_OFFER_AMOUNT_BYTES,
        claim_expires_at: PROMOTIONAL_OFFER_CLAIM_DEADLINE,
        credit_expires_at: now + PROMOTIONAL_GRANT_TTL_SECS,
    }
}

fn parse_pool(value: &str) -> ApiResult<AccessPool> {
    match value {
        "public" => Ok(AccessPool::Public),
        "free" => Ok(AccessPool::Free),
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

    fn test_peer() -> ConnectInfo<SocketAddr> {
        test_peer_at("198.51.100.10")
    }

    fn test_peer_at(address: &str) -> ConnectInfo<SocketAddr> {
        ConnectInfo(SocketAddr::new(
            address.parse().expect("test peer IP"),
            4242,
        ))
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
    fn public_and_free_access_have_distinct_credit_and_capture_limits() {
        let config = AdmissionConfig::for_test();
        assert!(config.public.max_attestable_http_bytes < config.free.max_attestable_http_bytes);
        assert!(config.public.monthly_finalization_bytes < config.free.monthly_finalization_bytes);
    }

    #[test]
    fn trusted_proxy_resolution_cannot_be_spoofed_by_an_untrusted_peer() {
        let config = AdmissionConfig::for_test();
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, "203.0.113.7".parse().unwrap());
        let untrusted: SocketAddr = "198.51.100.9:443".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(untrusted), &config).unwrap(),
            untrusted.ip()
        );

        let trusted: SocketAddr = "127.0.0.2:8080".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(trusted), &config).unwrap(),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn public_subjects_normalize_ipv6_and_scope_hmacs_by_period_and_version() {
        let key = b"deterministic-test-key-that-is-at-least-thirty-two-bytes";
        let first = public_credit_subject(
            "2001:db8:abcd:1234::1".parse().unwrap(),
            1_774_569_600,
            key,
            1,
        )
        .unwrap();
        let temporary = public_credit_subject(
            "2001:db8:abcd:1234:ffff::99".parse().unwrap(),
            1_774_569_600,
            key,
            1,
        )
        .unwrap();
        let outside_prefix = public_credit_subject(
            "2001:db8:abcd:1235::1".parse().unwrap(),
            1_774_569_600,
            key,
            1,
        )
        .unwrap();
        assert_eq!(first, temporary, "one IPv6 /64 shares an allowance");
        assert_ne!(first, outside_prefix);
        assert_ne!(
            first,
            public_credit_subject(
                "2001:db8:abcd:1234::1".parse().unwrap(),
                1_777_248_000,
                key,
                1,
            )
            .unwrap()
        );
        assert_ne!(
            first,
            public_credit_subject(
                "2001:db8:abcd:1234::1".parse().unwrap(),
                1_774_569_600,
                key,
                2,
            )
            .unwrap()
        );
        assert!(!first.contains("2001:db8"));

        let nat_first =
            public_credit_subject("203.0.113.44".parse().unwrap(), 1_774_569_600, key, 1).unwrap();
        let nat_second =
            public_credit_subject("203.0.113.44".parse().unwrap(), 1_774_569_600, key, 1).unwrap();
        assert_eq!(nat_first, nat_second, "one NAT address shares an allowance");
        assert_eq!(
            nat_first,
            public_credit_subject(
                "::ffff:203.0.113.44".parse().unwrap(),
                1_774_569_600,
                key,
                1,
            )
            .unwrap(),
            "IPv4-mapped addresses use the individual IPv4 subject",
        );
    }

    #[test]
    fn promotional_offer_eligibility_is_server_defined() {
        assert!(promotional_offer_eligible(
            false,
            PROMOTIONAL_OFFER_CLAIM_DEADLINE - 1
        ));
        assert!(!promotional_offer_eligible(
            true,
            PROMOTIONAL_OFFER_CLAIM_DEADLINE - 1
        ));
        assert!(!promotional_offer_eligible(
            false,
            PROMOTIONAL_OFFER_CLAIM_DEADLINE
        ));
    }

    #[test]
    fn finalization_requires_a_bound_digest_and_allowance() {
        let policy = AdmissionPolicy::free();
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
    async fn public_ip_subjects_receive_independent_allowances_without_subject_limits() {
        let mut state = test_state().await;
        let mut admission = (*state.admission).clone();
        admission.global_capture_concurrency = 4;
        admission.public.capture_concurrency = 4;
        state.admission = std::sync::Arc::new(admission);

        let issue = |peer| {
            issue_admission(
                State(state.clone()),
                peer,
                HeaderMap::new(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Capture,
                    record_digest: None,
                    requested_allowance_bytes: None,
                }),
            )
        };
        let first = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("first subject ticket")
            .0;
        let same_subject = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("same subject ticket")
            .0;
        let third_same_subject = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("same subject has no separate start limit")
            .0;
        let independent = issue(test_peer_at("198.51.100.11"))
            .await
            .expect("independent subject ticket")
            .0;

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
        let first_lease = redeem(first.ticket, "notary-ip-one")
            .await
            .expect("first subject admitted")
            .0;
        let independent_lease = redeem(independent.ticket, "notary-ip-two")
            .await
            .expect("independent subject admitted concurrently")
            .0;
        let same_subject_lease = redeem(same_subject.ticket, "notary-ip-three")
            .await
            .expect("same subject has no separate session limit")
            .0;
        let third_same_subject_lease = redeem(third_same_subject.ticket, "notary-ip-four")
            .await
            .expect("same subject remains limited only by shared service capacity")
            .0;

        let grant_summary: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT credit_subject), COUNT(*),
                    MIN(amount_bytes), MAX(amount_bytes)
             FROM notary_credit_grants
             WHERE source_kind = 'included_monthly'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(
            grant_summary,
            (
                2,
                2,
                state.admission.public.monthly_finalization_bytes,
                state.admission.public.monthly_finalization_bytes,
            )
        );
        let ticket_counts: Vec<i64> = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_admission_tickets
             GROUP BY credit_subject ORDER BY COUNT(*)",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(ticket_counts, vec![1, 3]);
        let stored_subjects: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT credit_subject FROM notary_admission_tickets
             ORDER BY credit_subject",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(stored_subjects.len(), 2);
        assert!(stored_subjects.iter().all(|subject| {
            subject.starts_with("public:v1:")
                && !subject.contains("198.51.100.10")
                && !subject.contains("198.51.100.11")
        }));
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&state.database)
            .await
            .unwrap();
        assert_eq!(users, 0);

        for (lease_id, instance) in [
            (first_lease.lease_id, "notary-ip-one"),
            (independent_lease.lease_id, "notary-ip-two"),
            (same_subject_lease.lease_id, "notary-ip-three"),
            (third_same_subject_lease.lease_id, "notary-ip-four"),
        ] {
            release_lease(
                State(state.clone()),
                service_headers(&state),
                Json(LeaseRequest {
                    lease_id,
                    notary_instance_id: instance.to_owned(),
                }),
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn two_instances_share_limits_and_expired_leases_recover_capacity() {
        let state = test_state().await;
        let issue = || {
            issue_admission(
                State(state.clone()),
                test_peer(),
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
            sqlx::query_scalar("SELECT COUNT(*) FROM notary_credit_debits")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(finalization_debits, 0, "captures must not consume credits");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn global_concurrency_is_shared_across_instances() {
        let mut state = test_state().await;
        let mut policy = (*state.admission).clone();
        policy.global_capture_concurrency = 1;
        policy.public.capture_concurrency = 2;
        state.admission = std::sync::Arc::new(policy);
        let issue_public = || {
            issue_admission(
                State(state.clone()),
                test_peer(),
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
                ..
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
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
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
                test_peer(),
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
        let rejected_retry = issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Finalize,
                record_digest: Some(digest.clone()),
                requested_allowance_bytes: Some(2048),
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
             FROM notary_credit_debits WHERE record_digest = $1",
        )
        .bind(digest)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(ledger, (1, 1024));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn concurrent_finalizations_cannot_overspend_one_subject() {
        let mut state = test_state().await;
        let mut admission = (*state.admission).clone();
        admission.public.finalize_concurrency = 2;
        admission.public.max_attestable_http_bytes = 64 << 20;
        state.admission = std::sync::Arc::new(admission);
        let allowance = 40_i64 << 20;
        let issue = |digest: String| {
            issue_admission(
                State(state.clone()),
                test_peer(),
                HeaderMap::new(),
                Json(IssueAdmissionRequest {
                    mode: AdmissionMode::Finalize,
                    record_digest: Some(digest),
                    requested_allowance_bytes: Some(allowance),
                }),
            )
        };
        let first = issue("31".repeat(32)).await.unwrap().0.ticket;
        let second = issue("32".repeat(32)).await.unwrap().0.ticket;
        let redeem = |ticket: String, instance: &'static str| {
            redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.to_owned(),
                    mode: AdmissionMode::Finalize,
                    directory_generation: state.notary_directory.generation,
                }),
            )
        };
        let (first, second) = tokio::join!(
            redeem(first, "notary-debit-one"),
            redeem(second, "notary-debit-two")
        );
        assert!(first.is_ok() ^ second.is_ok());
        let rejected = first.err().or_else(|| second.err()).unwrap();
        assert_eq!(rejected.code, "finalization_credits_exhausted");
        let debit: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(allowance_bytes), 0)::BIGINT
             FROM notary_credit_debits",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(debit, (1, allowance));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn monthly_grants_are_idempotent_and_reset_on_utc_boundaries() {
        let state = test_state().await;
        let subject = "public:v1:monthly-grant-test";
        let august = 1_786_797_296;
        let mut transaction = state.database.begin().await.unwrap();
        sqlx::query("SET LOCAL TIME ZONE 'America/Los_Angeles'")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let period = monthly_credit_period(&mut *transaction, august)
            .await
            .unwrap();
        assert_eq!(period.start, 1_785_542_400);
        assert_eq!(period.end, 1_788_220_800);
        let dst_period = monthly_credit_period(&mut *transaction, 1_794_744_000)
            .await
            .unwrap();
        assert_eq!(dst_period.start, 1_793_491_200);
        assert_eq!(dst_period.end, 1_796_083_200);
        for _ in 0..2 {
            ensure_monthly_grant(
                &mut transaction,
                subject,
                None,
                AccessPool::Public,
                &state.admission.public,
                august,
            )
            .await
            .unwrap();
        }
        transaction.commit().await.unwrap();

        let august_grants: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), SUM(amount_bytes)::BIGINT
             FROM notary_credit_grants
             WHERE credit_subject = $1 AND period_start = $2",
        )
        .bind(subject)
        .bind(period.start)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(
            august_grants,
            (1, state.admission.public.monthly_finalization_bytes)
        );

        let september = period.end;
        let mut transaction = state.database.begin().await.unwrap();
        ensure_monthly_grant(
            &mut transaction,
            subject,
            None,
            AccessPool::Public,
            &state.admission.public,
            september,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        let grants: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT period_start, period_end, amount_bytes
             FROM notary_credit_grants WHERE credit_subject = $1
             ORDER BY period_start",
        )
        .bind(subject)
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            grants,
            vec![
                (
                    1_785_542_400,
                    1_788_220_800,
                    state.admission.public.monthly_finalization_bytes,
                ),
                (
                    1_788_220_800,
                    1_790_812_800,
                    state.admission.public.monthly_finalization_bytes,
                ),
            ]
        );
        let credits = credit_summary(&state.database, subject, september)
            .await
            .unwrap();
        assert_eq!(
            credits.total_remaining_bytes,
            state.admission.public.monthly_finalization_bytes
        );
        assert_eq!(credits.reset_at, 1_790_812_800);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn grant_creation_is_idempotent_by_source_reference_and_key() {
        fn grant<'a>(
            source_reference: &'a str,
            idempotency_key: &'a str,
            amount_bytes: i64,
        ) -> CreditGrantSpec<'a> {
            CreditGrantSpec {
                credit_subject: "user:grant-idempotency-test",
                account_id: None,
                amount_bytes,
                source_kind: "external_purchase",
                source_reference,
                idempotency_key,
                period_start: None,
                period_end: None,
                created_at: 1_785_542_400,
                available_at: 1_785_542_400,
                expires_at: None,
                display_label: "External credit grant",
            }
        }

        let state = test_state().await;
        let mut transaction = state.database.begin().await.unwrap();
        let first = create_credit_grant(&mut transaction, grant("source-a", "key-a", 1024))
            .await
            .unwrap();
        let replay = create_credit_grant(&mut transaction, grant("source-a", "key-a", 1024))
            .await
            .unwrap();
        assert_eq!(first, replay);
        let reused_source = create_credit_grant(&mut transaction, grant("source-a", "key-b", 1024))
            .await
            .unwrap_err();
        assert_eq!(reused_source.status, StatusCode::CONFLICT);
        let reused_key = create_credit_grant(&mut transaction, grant("source-b", "key-a", 1024))
            .await
            .unwrap_err();
        assert_eq!(reused_key.status, StatusCode::CONFLICT);
        transaction.commit().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_credit_grants
             WHERE credit_subject = 'user:grant-idempotency-test'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn debits_allocate_expiring_grants_before_non_expiring_grants() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        let subject = "public:v1:test-allocation-subject";
        let mut transaction = state.database.begin().await.unwrap();
        admission_lock(&mut transaction).await.unwrap();
        create_credit_grant(
            &mut transaction,
            CreditGrantSpec {
                credit_subject: subject,
                account_id: None,
                amount_bytes: 1_000,
                source_kind: "manual_adjustment",
                source_reference: "expired",
                idempotency_key: "expired",
                period_start: None,
                period_end: None,
                created_at: now - 200,
                available_at: now - 200,
                expires_at: Some(now - 100),
                display_label: "expired",
            },
        )
        .await
        .unwrap();
        for (reference, amount, expires_at) in [
            ("non-expiring", 100, None),
            ("later", 100, Some(now + 200)),
            ("sooner", 100, Some(now + 100)),
        ] {
            create_credit_grant(
                &mut transaction,
                CreditGrantSpec {
                    credit_subject: subject,
                    account_id: None,
                    amount_bytes: amount,
                    source_kind: "manual_adjustment",
                    source_reference: reference,
                    idempotency_key: reference,
                    period_start: None,
                    period_end: None,
                    created_at: now,
                    available_at: now,
                    expires_at,
                    display_label: reference,
                },
            )
            .await
            .unwrap();
        }
        let ticket = TicketRow {
            subject_id: None,
            credit_subject: subject.to_owned(),
            access_pool: "public".to_owned(),
            mode: "finalize".to_owned(),
            directory_generation: 1,
            record_digest: Some("ef".repeat(32)),
            requested_allowance_bytes: 250,
            max_attestable_http_bytes: 1024,
            max_frame_bytes: 1024,
            max_private_chunk_bytes: 1024,
            max_private_chunk_commitments: 1,
            expires_at: now + 30,
            consumed_at: None,
        };
        debit_finalization_credits(&mut transaction, &ticket, now)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let allocations = sqlx::query_as::<_, (String, i64)>(
            "SELECT grants.source_reference, allocations.amount_bytes
             FROM notary_credit_debit_allocations AS allocations
             JOIN notary_credit_grants AS grants ON grants.id = allocations.grant_id
             JOIN notary_credit_debits AS debits ON debits.id = allocations.debit_id
             WHERE debits.credit_subject = $1
             ORDER BY allocations.allocation_order",
        )
        .bind(subject)
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            allocations,
            vec![
                ("sooner".to_owned(), 100),
                ("later".to_owned(), 100),
                ("non-expiring".to_owned(), 50),
            ]
        );
        let credits = credit_summary(&state.database, subject, now).await.unwrap();
        assert_eq!(credits.total_remaining_bytes, 50);
        assert_eq!(credits.next_grant_expiration, None);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn concurrent_promotional_claims_create_one_server_authored_grant() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('promo-user', 44, 'promo', $1, $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let session = "promo-browser-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'promo-user', $2, $3)",
        )
        .bind(sha256_hex(session.as_bytes()))
        .bind(now + 60)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let jar = CookieJar::new().add(Cookie::new(super::super::SESSION_COOKIE, session));
        let first = claim_credit_offer(
            State(state.clone()),
            jar.clone(),
            Path(PROMOTIONAL_OFFER_ID.to_owned()),
        );
        let second = claim_credit_offer(
            State(state.clone()),
            jar,
            Path(PROMOTIONAL_OFFER_ID.to_owned()),
        );
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok() ^ second.is_ok());
        let successful = first
            .as_ref()
            .ok()
            .or_else(|| second.as_ref().ok())
            .unwrap();
        assert_eq!(
            successful.0.credits.total_remaining_bytes,
            state.admission.free.monthly_finalization_bytes
                + ACCOUNT_TESTING_GRANT_AMOUNT_BYTES
                + PROMOTIONAL_OFFER_AMOUNT_BYTES
        );
        let rejected = first.err().or_else(|| second.err()).unwrap();
        assert_eq!(rejected.code, "credit_offer_already_claimed");
        let grant: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_grants
             WHERE credit_subject = 'user:promo-user' AND source_kind = 'promotion'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(grant, (1, PROMOTIONAL_OFFER_AMOUNT_BYTES));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn signed_in_accounts_always_receive_free_access_and_credits() {
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'octo', 1, 1)",
        )
        .execute(&state.database)
        .await
        .unwrap();
        let free_credits = account_access(&state, "user-1").await.unwrap();
        assert_eq!(free_credits.total_remaining_bytes, 640 << 20);
        assert_eq!(free_credits.included_monthly_remaining_bytes, 512 << 20);
        assert_eq!(free_credits.supplemental_remaining_bytes, 128 << 20);
        let testing_grant: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_grants
             WHERE credit_subject = 'user:user-1' AND source_kind = 'manual_adjustment'
               AND source_reference = $1",
        )
        .bind(ACCOUNT_TESTING_GRANT_ID)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(testing_grant, (1, ACCOUNT_TESTING_GRANT_AMOUNT_BYTES));
        let repeated_access = account_access(&state, "user-1").await.unwrap();
        assert_eq!(repeated_access.total_remaining_bytes, 640 << 20);
        let compatibility_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND ((table_name = 'users' AND column_name = 'service_plan')
                 OR (table_name = 'notary_admission_tickets'
                     AND column_name = 'session_timeout_secs'))",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(compatibility_columns, 2);
        let compatibility_plan: String =
            sqlx::query_scalar("SELECT service_plan FROM users WHERE id = 'user-1'")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(compatibility_plan, "free");
        let legacy_ledger: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('notary_finalization_credit_ledger')::TEXT")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(
            legacy_ledger.as_deref(),
            Some("notary_finalization_credit_ledger")
        );

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
        let free_ticket = issue_admission(
            State(state.clone()),
            test_peer(),
            cli_headers,
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .expect("free account admission")
        .0;
        assert_eq!(
            free_ticket.limits.max_attestable_http_bytes,
            state.admission.free.max_attestable_http_bytes
        );
        let access_pool: String = sqlx::query_scalar(
            "SELECT access_pool FROM notary_admission_tickets WHERE token_hash = $1",
        )
        .bind(sha256_hex(free_ticket.ticket.as_bytes()))
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(access_pool, "free");
    }
}
