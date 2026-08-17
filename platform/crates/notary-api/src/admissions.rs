use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State, rejection::JsonRejection},
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
    ApiError, ApiResult, ErrorResponse, NotaryApiState,
    auth::{ApiScope, authenticated_web_user, optional_authenticated_principal},
    config::{AdmissionTierLimits, NotaryAdmissionConfig},
    database_error, random_secret, typed_id, unix_timestamp,
};
use crate::credits::{
    AccountBillingState, BillingStatus, ClaimCreditOfferResponse, CreditBalanceSummary,
    CreditHistoryEntry, CreditHistoryKind, CreditKind, CreditOffer, CreditOffersResponse,
    CreditSummary, Plan,
};
#[cfg(test)]
use crate::credits::{PlanEntitlements, plan_entitlements};
use notary_core::{
    pagination::{CursorScope, Page, PageQuery, decode_cursor},
    sha256_hex,
};

const ADMISSION_LOCK_NAMESPACE: i32 = 151;
const ADMISSION_LOCK_KEY: i32 = 1;
const MAX_TICKET_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const SECS_PER_DAY: i64 = 24 * 60 * 60;
const CLIENT_IP_HEADER: &str = "x-notary-client-ip";
const PUBLIC_SUBJECT_PURPOSE: &str = "hosted-notarization-public-subject";
const PROMOTIONAL_OFFER_ID: &str = "hosted-notarization-bonus-v1";
const PROMOTIONAL_OFFER_AMOUNT_BYTES: i64 = 128 << 20;
const PROMOTIONAL_OFFER_CLAIM_DEADLINE: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z
const PROMOTIONAL_GRANT_TTL_SECS: i64 = 90 * SECS_PER_DAY;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    Capture,
    Notarization,
}

impl AdmissionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Notarization => "notarization",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionTier {
    Public,
    Free,
    OneGb,
    TenGb,
}

impl AdmissionTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Free => "free",
            Self::OneGb => "one_gb",
            Self::TenGb => "ten_gb",
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

#[derive(Deserialize, Serialize)]
struct CreditHistoryPagePosition {
    created_at: i64,
    id: String,
    kind: String,
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
    pub registry_generation: u64,
    pub limits: AdmissionLimits,
}

#[derive(Deserialize, ToSchema)]
pub struct RedeemAdmissionRequest {
    pub ticket: String,
    pub notary_instance_id: String,
    pub mode: AdmissionMode,
    pub registry_generation: u64,
    pub contract: AdmissionRedemptionContract,
    /// The caller durably settles usage by operation ID. The stop-legacy
    /// contract requires this capability for every admitted operation.
    pub usage_settlement: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRedemptionContract {
    OneOperationV1,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemedOperationResponse {
    pub operation_id: String,
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub record_digest: Option<String>,
    pub notarization_allowance_bytes: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageSettlementOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

impl UsageSettlementOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ClientFailed => "client_failed",
            Self::ServiceFailed => "service_failed",
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UsageSettlementRequest {
    pub operation_id: String,
    pub notary_instance_id: String,
    pub mode: AdmissionMode,
    pub authenticated_bytes: i64,
    pub outcome: UsageSettlementOutcome,
}

#[derive(FromRow)]
struct OperationTicketRow {
    account_id: Option<String>,
    credit_subject: String,
    admission_tier: String,
    mode: String,
    registry_generation: i64,
    record_digest: Option<String>,
    notarization_allowance_bytes: Option<i64>,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
}

#[derive(FromRow)]
struct OperationRow {
    operation_id: String,
    notary_instance_id: String,
    account_id: Option<String>,
    credit_subject: String,
    mode: String,
    notarization_allowance_bytes: Option<i64>,
    max_attestable_http_bytes: i64,
    admitted_at: i64,
    terminal_outcome: Option<String>,
    settled_authenticated_bytes: Option<i64>,
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(issue_admission))
        .routes(routes!(eligible_credit_offers))
        .routes(routes!(credit_history))
        .routes(routes!(claim_credit_offer))
        .routes(routes!(redeem_admission))
        .routes(routes!(settle_usage))
}

#[utoipa::path(
    get,
    path = "/api/me/credits/history",
    summary = "List the signed-in account's credit activity",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<CreditHistoryEntry>),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
async fn credit_history(
    State(state): State<NotaryApiState>,
    jar: axum_extra::extract::cookie::CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<CreditHistoryEntry>>> {
    let Query(query) = query.map_err(super::pagination::query_error)?;
    let user = authenticated_web_user(&state, &jar).await?;
    ensure_account_monthly_grant(&state, &user.0).await?;
    let limit = query
        .limit(
            super::pagination::DEFAULT_PAGE_LIMIT,
            super::pagination::MAX_PAGE_LIMIT,
        )
        .map_err(super::pagination::api_error)?;
    let scope = CursorScope::new(
        "/api/me/credits/history",
        &user.0,
        "created_at desc, id desc, kind desc",
    )
    .map_err(super::pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<CreditHistoryPagePosition>(&scope, cursor))
        .transpose()
        .map_err(super::pagination::api_error)?;
    let credit_subject = account_credit_subject(&user.0);
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            i64,
            Option<String>,
            String,
            i64,
            Option<i64>,
        ),
    >(
        "SELECT id, kind, credit_kind, amount_bytes, source_kind, display_label, created_at, expires_at
         FROM (
             SELECT id, 'grant'::TEXT AS kind, credit_kind, amount_bytes,
                    source_kind::TEXT AS source_kind,
                    COALESCE(display_label, 'Credits') AS display_label,
                    created_at, expires_at
             FROM credit_grants
             WHERE credit_subject = $1 AND source_kind <> 'operation_overage'
             UNION ALL
             SELECT id, 'debit'::TEXT AS kind, credit_kind, allowance_bytes AS amount_bytes,
                    NULL::TEXT AS source_kind,
                    CASE credit_kind WHEN 'capture' THEN 'Hosted capture'
                         ELSE 'Hosted notarization' END AS display_label,
                    created_at, NULL::BIGINT AS expires_at
             FROM credit_debits WHERE credit_subject = $1
             UNION ALL
             SELECT id, 'adjustment'::TEXT AS kind, 'notarization'::TEXT AS credit_kind, amount_bytes,
                    source_kind::TEXT AS source_kind, display_label,
                    created_at, NULL::BIGINT AS expires_at
             FROM credit_adjustments WHERE credit_subject = $1
         ) AS history
         WHERE ($2::TEXT IS NULL OR (created_at, id, kind) < ($3, $2, $4))
         ORDER BY created_at DESC, id DESC, kind DESC
         LIMIT $5",
    )
    .bind(&credit_subject)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.created_at))
    .bind(position.as_ref().map(|position| &position.kind))
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(anyhow::anyhow!(error)))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(
        |(id, kind, credit_kind, amount_bytes, source_kind, display_label, created_at, expires_at)| {
            CreditHistoryEntry {
                id,
                kind: match kind.as_str() {
                    "grant" => CreditHistoryKind::Grant,
                    "debit" => CreditHistoryKind::Debit,
                    "adjustment" => CreditHistoryKind::Adjustment,
                    _ => unreachable!("credit history query emits only known kinds"),
                },
                credit_kind: match credit_kind.as_str() {
                    "capture" => CreditKind::Capture,
                    "notarization" => CreditKind::Notarization,
                    _ => unreachable!("credit history query emits only known credit kinds"),
                },
                amount_bytes,
                source_kind,
                display_label,
                created_at,
                expires_at,
            }
        },
    )
    .collect::<Vec<_>>();
    let page = Page::from_limit_plus_one(rows, limit, &scope, |entry| CreditHistoryPagePosition {
        created_at: entry.created_at,
        id: entry.id.clone(),
        kind: match entry.kind {
            CreditHistoryKind::Grant => "grant",
            CreditHistoryKind::Debit => "debit",
            CreditHistoryKind::Adjustment => "adjustment",
        }
        .to_owned(),
    })
    .map_err(super::pagination::api_error)?;
    Ok(Json(page))
}

pub async fn account_access(state: &NotaryApiState, account_id: &str) -> ApiResult<CreditSummary> {
    ensure_account_monthly_grant(state, account_id).await?;
    let now = unix_timestamp()?;
    credit_summary(&state.database, &account_credit_subject(account_id), now).await
}

pub async fn account_billing_state(
    database: &super::DatabasePool,
    account_id: &str,
) -> ApiResult<AccountBillingState> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT plan, billing_status
         FROM account_billing_profiles WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(database)
    .await
    .map_err(database_error)?;
    match row {
        Some((plan, status)) => Ok(AccountBillingState {
            plan: parse_plan(&plan)?,
            billing_status: parse_billing_status(&status)?,
        }),
        None => Ok(AccountBillingState {
            plan: Plan::Free,
            billing_status: BillingStatus::Active,
        }),
    }
}

async fn account_admission_tier(
    database: &super::DatabasePool,
    account_id: &str,
) -> ApiResult<AdmissionTier> {
    Ok(
        match account_billing_state(database, account_id).await?.plan {
            Plan::Free => AdmissionTier::Free,
            Plan::OneGb => AdmissionTier::OneGb,
            Plan::TenGb => AdmissionTier::TenGb,
        },
    )
}

async fn ensure_account_monthly_grant(state: &NotaryApiState, account_id: &str) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let pool = account_admission_tier(&state.database, account_id).await?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let policy = policy_for_pool(&state.admission, pool);
    let credit_subject = account_credit_subject(account_id);
    for credit_kind in [CreditKind::Capture, CreditKind::Notarization] {
        ensure_monthly_grant(
            &mut transaction,
            &credit_subject,
            Some(account_id),
            pool,
            policy,
            credit_kind,
            now,
        )
        .await?;
    }
    transaction.commit().await.map_err(database_error)?;
    Ok(())
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
    State(state): State<NotaryApiState>,
    jar: axum_extra::extract::cookie::CookieJar,
) -> ApiResult<Json<CreditOffersResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let claimed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM credit_grants
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
    State(state): State<NotaryApiState>,
    jar: axum_extra::extract::cookie::CookieJar,
    Path(offer_id): Path<String>,
) -> ApiResult<Json<ClaimCreditOfferResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let pool = account_admission_tier(&state.database, &user.0).await?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let credit_subject = account_credit_subject(&user.0);
    ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        Some(&user.0),
        pool,
        policy_for_pool(&state.admission, pool),
        CreditKind::Notarization,
        now,
    )
    .await?;
    let claimed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM credit_grants
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
            credit_kind: CreditKind::Notarization,
            amount_bytes: PROMOTIONAL_OFFER_AMOUNT_BYTES,
            source_kind: "promotion",
            source_reference: PROMOTIONAL_OFFER_ID,
            idempotency_key: &format!("promotion:{PROMOTIONAL_OFFER_ID}"),
            period_start: None,
            period_end: None,
            created_at: now,
            available_at: now,
            expires_at: Some(now + PROMOTIONAL_GRANT_TTL_SECS),
            display_label: "Hosted notarization bonus",
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
        (status = 500, body = ErrorResponse)
    ),
    security((), ("bearerAuth" = [])),
    tag = "notary-admission"
)]
async fn issue_admission(
    State(state): State<NotaryApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<IssueAdmissionRequest>,
) -> ApiResult<Json<AdmissionTicketResponse>> {
    let required_scope = match request.mode {
        AdmissionMode::Capture => ApiScope::CaptureRequest,
        AdmissionMode::Notarization => ApiScope::NotarizationRequest,
    };
    let identity = optional_authenticated_principal(&state, &headers, required_scope).await?;
    let now = unix_timestamp()?;
    let period = monthly_credit_period(&state.database, now).await?;
    let (account_id, credit_subject, pool, billing_status) = match identity {
        Some(principal) => {
            let billing = account_billing_state(&state.database, &principal.account_id).await?;
            let credit_subject = account_credit_subject(&principal.account_id);
            let pool = match billing.plan {
                Plan::Free => AdmissionTier::Free,
                Plan::OneGb => AdmissionTier::OneGb,
                Plan::TenGb => AdmissionTier::TenGb,
            };
            (
                Some(principal.account_id),
                credit_subject,
                pool,
                billing.billing_status,
            )
        }
        None => {
            let client_ip = resolve_client_ip(&headers, Some(peer), &state.admission)?;
            let credit_subject = public_credit_subject(
                client_ip,
                period.start,
                &state.admission.anonymous_subject_hmac_key,
                state.admission.anonymous_subject_key_version,
            )?;
            (
                None,
                credit_subject,
                AdmissionTier::Public,
                BillingStatus::Active,
            )
        }
    };
    if billing_status == BillingStatus::Review {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            "billing_review",
            "Hosted capture and notarization are unavailable while billing is under review",
        ));
    }
    let policy = policy_for_pool(&state.admission, pool);
    let (record_digest, requested_allowance) = validate_ticket_request(&request, policy)?;
    let token = random_secret("notary_admission_");
    let registry_generation = i64::try_from(state.registry.generation)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("Registry generation is too large")))?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        account_id.as_deref(),
        pool,
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    let allowance = if request.mode == AdmissionMode::Capture {
        bounded_capture_allowance(
            requested_allowance,
            available_credit_bytes(&mut transaction, &credit_subject, CreditKind::Capture, now)
                .await?,
        )?
    } else {
        requested_allowance
    };
    preflight_credits(
        &mut transaction,
        &credit_subject,
        CreditKind::for_mode(request.mode),
        allowance,
        now,
    )
    .await?;
    let notarization_allowance = (request.mode == AdmissionMode::Notarization).then_some(allowance);
    let expires_at = now + state.admission.ticket_ttl_secs;
    sqlx::query(
        "INSERT INTO admission_tickets
         (token_hash, account_id, credit_subject, admission_tier, mode, registry_generation,
          record_digest, notarization_allowance_bytes, max_attestable_http_bytes, max_frame_bytes,
          max_private_chunk_bytes, max_private_chunk_commitments, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(account_id.as_deref())
    .bind(&credit_subject)
    .bind(pool.as_str())
    .bind(request.mode.as_str())
    .bind(registry_generation)
    .bind(record_digest)
    .bind(notarization_allowance)
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

    metrics::counter!("notary_api_notary_admission_tickets_total", "pool" => pool.as_str(), "mode" => request.mode.as_str()).increment(1);
    Ok(Json(AdmissionTicketResponse {
        ticket: token,
        expires_at,
        registry_generation: state.registry.generation,
        limits: admission_limits(policy),
    }))
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/admissions/redeem",
    summary = "Consume a ticket using the requested notary admission contract",
    request_body = RedeemAdmissionRequest,
    responses(
        (status = 200, body = RedeemedOperationResponse),
        (status = 400, body = ErrorResponse),
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
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    request: Result<Json<RedeemAdmissionRequest>, JsonRejection>,
) -> ApiResult<Json<RedeemedOperationResponse>> {
    authenticate_service(&state, &headers)?;
    let Json(request) =
        request.map_err(|_| ApiError::bad_request("invalid admission redemption request"))?;
    match request.contract {
        AdmissionRedemptionContract::OneOperationV1 => {}
    }
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
    if !request.usage_settlement {
        return Err(ApiError::bad_request(
            "durable operation usage settlement is required",
        ));
    }
    let now = unix_timestamp()?;
    let requested_generation = i64::try_from(request.registry_generation)
        .map_err(|_| ApiError::bad_request("Registry generation is too large"))?;
    redeem_one_operation(&state, &request, now, requested_generation)
        .await
        .map(Json)
}

async fn redeem_one_operation(
    state: &NotaryApiState,
    request: &RedeemAdmissionRequest,
    now: i64,
    requested_generation: i64,
) -> ApiResult<RedeemedOperationResponse> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let ticket = sqlx::query_as::<_, OperationTicketRow>(
        "SELECT account_id, credit_subject, admission_tier, mode, registry_generation,
                record_digest, notarization_allowance_bytes, max_attestable_http_bytes,
                max_frame_bytes, max_private_chunk_bytes, max_private_chunk_commitments,
                expires_at, consumed_at
         FROM admission_tickets WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(sha256_hex(request.ticket.as_bytes()))
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(admission_ticket_expired)?;
    if ticket.consumed_at.is_some() {
        return Err(ApiError::conflict("admission ticket was already consumed"));
    }
    if ticket.expires_at <= now {
        return Err(admission_ticket_expired());
    }
    if ticket.mode != request.mode.as_str() || ticket.registry_generation != requested_generation {
        return Err(ApiError::conflict(
            "admission ticket audience does not match",
        ));
    }
    let pool = parse_pool(&ticket.admission_tier)?;
    let policy = policy_for_pool(&state.admission, pool);
    if let Some(account_id) = ticket.account_id.as_deref() {
        let current_billing = sqlx::query_as::<_, (String, String)>(
            "SELECT plan, billing_status
             FROM account_billing_profiles WHERE account_id = $1
             FOR SHARE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        let (plan, billing_status) = current_billing
            .as_ref()
            .map(|(plan, status)| (plan.as_str(), status.as_str()))
            .unwrap_or(("free", "active"));
        if billing_status == "review" {
            return Err(ApiError::coded(
                StatusCode::PAYMENT_REQUIRED,
                "billing_review",
                "Hosted capture and notarization are unavailable while billing is under review",
            ));
        }
        if (pool == AdmissionTier::OneGb && plan != "one_gb")
            || (pool == AdmissionTier::TenGb && plan != "ten_gb")
        {
            return Err(ApiError::coded(
                StatusCode::PAYMENT_REQUIRED,
                "billing_plan_changed",
                "The account plan changed after this admission ticket was issued",
            ));
        }
    }
    ensure_monthly_grant(
        &mut transaction,
        &ticket.credit_subject,
        ticket.account_id.as_deref(),
        pool,
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    let required_allowance = ticket.notarization_allowance_bytes.unwrap_or(1);
    preflight_credits(
        &mut transaction,
        &ticket.credit_subject,
        CreditKind::for_mode(request.mode),
        required_allowance,
        now,
    )
    .await?;
    let ticket_token_hash = sha256_hex(request.ticket.as_bytes());
    let operation_id = typed_id("op-");
    sqlx::query(
        "INSERT INTO admitted_operations
             (operation_id, ticket_token_hash, notary_instance_id, account_id, credit_subject,
              admission_tier, mode, record_digest, notarization_allowance_bytes,
              max_attestable_http_bytes, admitted_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&operation_id)
    .bind(&ticket_token_hash)
    .bind(&request.notary_instance_id)
    .bind(ticket.account_id.as_deref())
    .bind(&ticket.credit_subject)
    .bind(pool.as_str())
    .bind(request.mode.as_str())
    .bind(ticket.record_digest.as_deref())
    .bind(ticket.notarization_allowance_bytes)
    .bind(ticket.max_attestable_http_bytes)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    let updated = sqlx::query(
        "UPDATE admission_tickets
         SET consumed_at = $1
         WHERE token_hash = $2 AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(ticket_token_hash)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("admission ticket was already consumed"));
    }
    transaction.commit().await.map_err(database_error)?;
    metrics::counter!("notary_api_notary_admissions_total", "pool" => pool.as_str(), "mode" => request.mode.as_str(), "outcome" => "admitted").increment(1);
    Ok(RedeemedOperationResponse {
        operation_id,
        max_attestable_http_bytes: ticket.max_attestable_http_bytes,
        max_frame_bytes: ticket.max_frame_bytes,
        max_private_chunk_bytes: ticket.max_private_chunk_bytes,
        max_private_chunk_commitments: ticket.max_private_chunk_commitments,
        record_digest: ticket.record_digest,
        notarization_allowance_bytes: ticket.notarization_allowance_bytes,
    })
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/operations/settle",
    summary = "Settle authoritative byte usage for one admitted operation",
    request_body = UsageSettlementRequest,
    responses(
        (status = 204, description = "Usage settled or identical report already applied"),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("serviceBearer" = [])),
    tag = "notary-admission"
)]
async fn settle_usage(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    Json(request): Json<UsageSettlementRequest>,
) -> ApiResult<StatusCode> {
    authenticate_service(&state, &headers)?;
    validate_opaque(&request.operation_id, 128, "invalid operation identifier")?;
    validate_opaque(
        &request.notary_instance_id,
        MAX_INSTANCE_ID_BYTES,
        "invalid notary instance identifier",
    )?;
    if request.authenticated_bytes < 0 {
        return Err(ApiError::bad_request(
            "authenticated usage must not be negative",
        ));
    }
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let operation = sqlx::query_as::<_, OperationRow>(
        "SELECT operation_id, notary_instance_id, account_id, credit_subject, mode,
                notarization_allowance_bytes, max_attestable_http_bytes, admitted_at,
                terminal_outcome, settled_authenticated_bytes
         FROM admitted_operations WHERE operation_id = $1 FOR UPDATE",
    )
    .bind(&request.operation_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::gone("admitted operation is unknown"))?;
    if operation.notary_instance_id != request.notary_instance_id
        || operation.mode != request.mode.as_str()
    {
        return Err(ApiError::conflict(
            "usage report does not match the admitted operation",
        ));
    }
    validate_settlement_bytes(&operation, &request)?;
    if let Some(previous_outcome) = operation.terminal_outcome.as_deref() {
        return if previous_outcome == request.outcome.as_str()
            && operation.settled_authenticated_bytes == Some(request.authenticated_bytes)
        {
            transaction.commit().await.map_err(database_error)?;
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(ApiError::conflict(
                "operation usage was already settled with different data",
            ))
        };
    }
    if request.authenticated_bytes > 0 {
        record_operation_debit(&mut transaction, &operation, request.authenticated_bytes).await?;
    }
    sqlx::query(
        "UPDATE admitted_operations
         SET terminal_outcome = $1, settled_authenticated_bytes = $2, settled_at = $3
         WHERE operation_id = $4 AND terminal_outcome IS NULL",
    )
    .bind(request.outcome.as_str())
    .bind(request.authenticated_bytes)
    .bind(now)
    .bind(&operation.operation_id)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    metrics::counter!(
        "notary_api_usage_settlements_total",
        "mode" => request.mode.as_str(),
        "outcome" => request.outcome.as_str()
    )
    .increment(1);
    Ok(StatusCode::NO_CONTENT)
}

fn validate_settlement_bytes(
    operation: &OperationRow,
    request: &UsageSettlementRequest,
) -> ApiResult<()> {
    match request.mode {
        AdmissionMode::Capture => {
            if request.outcome == UsageSettlementOutcome::Completed
                && request.authenticated_bytes > operation.max_attestable_http_bytes
            {
                return Err(ApiError::bad_request(
                    "completed capture usage exceeds the admitted protocol limit",
                ));
            }
        }
        AdmissionMode::Notarization => {
            let allowance = operation.notarization_allowance_bytes.ok_or_else(|| {
                ApiError::internal(anyhow::anyhow!(
                    "notarization operation is missing its authenticated allowance"
                ))
            })?;
            if request.authenticated_bytes != 0 && request.authenticated_bytes != allowance {
                return Err(ApiError::bad_request(
                    "notarization usage does not match its authenticated allowance",
                ));
            }
            if request.outcome == UsageSettlementOutcome::Completed
                && request.authenticated_bytes != allowance
            {
                return Err(ApiError::bad_request(
                    "completed notarization usage must match its authenticated allowance",
                ));
            }
        }
    }
    Ok(())
}

async fn record_operation_debit(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &OperationRow,
    authenticated_bytes: i64,
) -> ApiResult<()> {
    let credit_kind = match operation.mode.as_str() {
        "capture" => CreditKind::Capture,
        "notarization" => CreditKind::Notarization,
        _ => {
            return Err(ApiError::internal(anyhow::anyhow!(
                "invalid operation mode"
            )));
        }
    };
    let grants = settlement_grants(
        transaction,
        &operation.credit_subject,
        credit_kind,
        operation.admitted_at,
    )
    .await?;
    if grants.is_empty() {
        return Err(ApiError::internal(anyhow::anyhow!(
            "admitted operation has no credit grant"
        )));
    }
    let debit_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO credit_debits
             (id, credit_subject, account_id, credit_kind, allowance_bytes,
              created_at, operation_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&debit_id)
    .bind(&operation.credit_subject)
    .bind(operation.account_id.as_deref())
    .bind(credit_kind.as_str())
    .bind(authenticated_bytes)
    .bind(operation.admitted_at)
    .bind(&operation.operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    allocate_settled_usage(
        transaction,
        &debit_id,
        authenticated_bytes,
        &grants,
        operation,
        credit_kind,
    )
    .await
}

async fn settlement_grants(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    credit_kind: CreditKind,
    admitted_at: i64,
) -> ApiResult<Vec<(String, i64, Option<i64>)>> {
    sqlx::query_as::<_, (String, i64, Option<i64>)>(
        "SELECT grants.id,
                grants.amount_bytes - COALESCE((
                    SELECT SUM(allocations.amount_bytes)
                    FROM credit_debit_allocations AS allocations
                    WHERE allocations.grant_id = grants.id
                ), 0)::BIGINT AS remaining_bytes,
                grants.expires_at
         FROM credit_grants AS grants
         WHERE grants.credit_subject = $1 AND grants.credit_kind = $2
           AND grants.source_kind <> 'operation_overage'
           AND grants.available_at <= $3
           AND (grants.expires_at IS NULL OR grants.expires_at > $3)
         ORDER BY grants.expires_at ASC NULLS LAST, grants.available_at,
                  grants.created_at, grants.id
         FOR UPDATE OF grants",
    )
    .bind(credit_subject)
    .bind(credit_kind.as_str())
    .bind(admitted_at)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)
}

async fn allocate_settled_usage(
    transaction: &mut Transaction<'_, Postgres>,
    debit_id: &str,
    authenticated_bytes: i64,
    grants: &[(String, i64, Option<i64>)],
    operation: &OperationRow,
    credit_kind: CreditKind,
) -> ApiResult<()> {
    let mut remaining = authenticated_bytes;
    let mut allocated_grants = Vec::new();
    for (grant_id, available, _) in grants {
        if remaining == 0 {
            break;
        }
        let allocated = remaining.min((*available).max(0));
        if allocated == 0 {
            continue;
        }
        let order = i32::try_from(allocated_grants.len()).map_err(|_| {
            ApiError::internal(anyhow::anyhow!("too many credit grant allocations"))
        })?;
        sqlx::query(
            "INSERT INTO credit_debit_allocations
                 (debit_id, grant_id, amount_bytes, allocation_order)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(debit_id)
        .bind(grant_id)
        .bind(allocated)
        .bind(order)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
        allocated_grants.push(grant_id.clone());
        remaining -= allocated;
    }
    if remaining == 0 {
        return Ok(());
    }
    let overage_expires_at = grants
        .last()
        .map(|(_, _, expires_at)| *expires_at)
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("usage allocation has no grant")))?;
    let overage_grant_id = Uuid::new_v4().to_string();
    let overage_reference = format!("operation-overage:{}", operation.operation_id);
    sqlx::query(
        "INSERT INTO credit_grants
             (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind,
              source_reference, idempotency_key, created_at, available_at, expires_at,
              display_label)
         VALUES ($1, $2, $3, $4, 0, 'operation_overage', $5, $5, $6, $6, $7,
                 'Hosted usage overage')",
    )
    .bind(&overage_grant_id)
    .bind(&operation.credit_subject)
    .bind(operation.account_id.as_deref())
    .bind(credit_kind.as_str())
    .bind(&overage_reference)
    .bind(operation.admitted_at)
    .bind(overage_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    let order = i32::try_from(allocated_grants.len())
        .map_err(|_| ApiError::internal(anyhow::anyhow!("too many credit grant allocations")))?;
    sqlx::query(
        "INSERT INTO credit_debit_allocations
             (debit_id, grant_id, amount_bytes, allocation_order)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(debit_id)
    .bind(overage_grant_id)
    .bind(remaining)
    .bind(order)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

fn validate_ticket_request(
    request: &IssueAdmissionRequest,
    policy: &AdmissionTierLimits,
) -> ApiResult<(Option<String>, i64)> {
    match request.mode {
        AdmissionMode::Capture => {
            if request.record_digest.is_some() || request.requested_allowance_bytes.is_some() {
                return Err(ApiError::bad_request(
                    "capture admission must not include notarization fields",
                ));
            }
            Ok((None, policy.max_attestable_http_bytes))
        }
        AdmissionMode::Notarization => {
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
                    ApiError::bad_request("requested notarization allowance must be positive")
                })?;
            if allowance > policy.max_attestable_http_bytes {
                return Err(ApiError::bad_request(
                    "requested notarization allowance exceeds the per-session limit",
                ));
            }
            Ok((Some(digest.to_owned()), allowance))
        }
    }
}

fn authenticate_service(state: &NotaryApiState, headers: &HeaderMap) -> ApiResult<()> {
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

#[derive(Clone, Copy)]
struct CreditPeriod {
    start: i64,
    end: i64,
}

struct CreditGrantSpec<'a> {
    credit_subject: &'a str,
    account_id: Option<&'a str>,
    credit_kind: CreditKind,
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
    credit_kind: String,
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

#[derive(Clone, Copy)]
pub(crate) struct PurchaseAdjustmentSpec<'a> {
    pub account_id: &'a str,
    pub purchase_id: &'a str,
    pub amount_bytes: i64,
    pub source_kind: &'a str,
    pub source_reference: &'a str,
    pub idempotency_key: &'a str,
    pub display_label: &'a str,
    pub created_at: i64,
}

#[derive(FromRow)]
struct GrantBalanceRow {
    source_kind: String,
    expires_at: Option<i64>,
    granted_bytes: i64,
    used_bytes: i64,
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
        "SELECT id, account_id, credit_kind, amount_bytes, source_kind, source_reference, idempotency_key,
                period_start, period_end, created_at, available_at, expires_at, display_label
         FROM credit_grants
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
            || existing.credit_kind != spec.credit_kind.as_str()
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
        "INSERT INTO credit_grants
         (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind, source_reference,
          idempotency_key, period_start, period_end, created_at, available_at, expires_at,
          display_label)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(&id)
    .bind(spec.credit_subject)
    .bind(spec.account_id)
    .bind(spec.credit_kind.as_str())
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

pub(crate) async fn grant_external_purchase(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: &str,
    payment_reference: &str,
    amount_bytes: i64,
    created_at: i64,
) -> ApiResult<String> {
    let credit_subject = account_credit_subject(account_id);
    let idempotency_key = format!("external-purchase:{payment_reference}");
    create_credit_grant(
        transaction,
        CreditGrantSpec {
            credit_subject: &credit_subject,
            account_id: Some(account_id),
            credit_kind: CreditKind::Notarization,
            amount_bytes,
            source_kind: "external_purchase",
            source_reference: payment_reference,
            idempotency_key: &idempotency_key,
            period_start: None,
            period_end: None,
            created_at,
            available_at: created_at,
            expires_at: None,
            display_label: "Purchased notarization credits",
        },
    )
    .await
}

pub(crate) async fn set_account_billing_state(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: &str,
    plan: Plan,
    billing_status: BillingStatus,
    updated_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO account_billing_profiles
             (account_id, plan, billing_status, updated_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id) DO UPDATE
         SET plan = EXCLUDED.plan,
             billing_status = EXCLUDED.billing_status,
             updated_at = GREATEST(account_billing_profiles.updated_at, EXCLUDED.updated_at)",
    )
    .bind(account_id)
    .bind(plan.as_str())
    .bind(billing_status.as_str())
    .bind(updated_at)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

pub(crate) async fn apply_purchase_adjustment(
    transaction: &mut Transaction<'_, Postgres>,
    spec: PurchaseAdjustmentSpec<'_>,
) -> ApiResult<String> {
    let valid_kind_and_sign = matches!(
        (spec.source_kind, spec.amount_bytes.signum()),
        ("purchase_refund", -1) | ("purchase_dispute", -1) | ("dispute_reinstatement", 1)
    );
    if !valid_kind_and_sign
        || spec.source_reference.is_empty()
        || spec.source_reference.len() > 256
        || spec.idempotency_key.is_empty()
        || spec.idempotency_key.len() > 256
        || spec.display_label.is_empty()
        || spec.display_label.len() > 120
    {
        return Err(ApiError::internal(anyhow::anyhow!(
            "invalid server-authored credit adjustment"
        )));
    }
    let credit_subject = account_credit_subject(spec.account_id);
    let existing = sqlx::query_as::<_, (String, String, i64, String, String, String, String, i64)>(
        "SELECT id, purchase_id, amount_bytes, source_kind, source_reference,
                idempotency_key, display_label, created_at
         FROM credit_adjustments
         WHERE credit_subject = $1
           AND ((source_kind = $2 AND source_reference = $3) OR idempotency_key = $4)
         FOR UPDATE",
    )
    .bind(&credit_subject)
    .bind(spec.source_kind)
    .bind(spec.source_reference)
    .bind(spec.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    if let Some((
        id,
        purchase_id,
        amount_bytes,
        source_kind,
        source_reference,
        idempotency_key,
        label,
        created_at,
    )) = existing
    {
        if purchase_id != spec.purchase_id
            || amount_bytes != spec.amount_bytes
            || source_kind != spec.source_kind
            || source_reference != spec.source_reference
            || idempotency_key != spec.idempotency_key
            || label != spec.display_label
            || created_at != spec.created_at
        {
            return Err(ApiError::conflict(
                "credit adjustment idempotency key was already used for different data",
            ));
        }
        return Ok(id);
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO credit_adjustments
             (id, credit_subject, account_id, purchase_id, amount_bytes, source_kind,
              source_reference, idempotency_key, display_label, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&id)
    .bind(&credit_subject)
    .bind(spec.account_id)
    .bind(spec.purchase_id)
    .bind(spec.amount_bytes)
    .bind(spec.source_kind)
    .bind(spec.source_reference)
    .bind(spec.idempotency_key)
    .bind(spec.display_label)
    .bind(spec.created_at)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(id)
}

async fn ensure_monthly_grant(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    account_id: Option<&str>,
    _pool: AdmissionTier,
    policy: &AdmissionTierLimits,
    credit_kind: CreditKind,
    now: i64,
) -> ApiResult<()> {
    let period = monthly_credit_period(&mut **transaction, now).await?;
    let monthly_bytes = match credit_kind {
        CreditKind::Capture => policy.monthly_capture_bytes,
        CreditKind::Notarization => policy.monthly_notarization_bytes,
    };
    let reference = format!("monthly:{}:{}", credit_kind.as_str(), period.start);
    let existing = sqlx::query_as::<_, (String, i64)>(
        "SELECT id, amount_bytes FROM credit_grants
         WHERE credit_subject = $1 AND credit_kind = $2
           AND source_kind = 'included_monthly' AND period_start = $3
         FOR UPDATE",
    )
    .bind(credit_subject)
    .bind(credit_kind.as_str())
    .bind(period.start)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    if let Some((grant_id, current_amount)) = existing {
        // Settled allocations may exceed a grant because admission does not
        // reserve bytes. Keep the configured allowance authoritative so the
        // resulting negative balance remains visible and blocks new tickets.
        if monthly_bytes != current_amount {
            sqlx::query("UPDATE credit_grants SET amount_bytes = $1 WHERE id = $2")
                .bind(monthly_bytes)
                .bind(grant_id)
                .execute(&mut **transaction)
                .await
                .map_err(database_error)?;
        }
        return Ok(());
    }
    let label = match credit_kind {
        CreditKind::Capture => "Monthly capture allowance",
        CreditKind::Notarization => "Monthly notarization allowance",
    };
    create_credit_grant(
        transaction,
        CreditGrantSpec {
            credit_subject,
            account_id,
            credit_kind,
            amount_bytes: monthly_bytes,
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

async fn preflight_credits(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    credit_kind: CreditKind,
    allowance: i64,
    now: i64,
) -> ApiResult<()> {
    let available = available_credit_bytes(transaction, credit_subject, credit_kind, now).await?;
    if available < allowance {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            credit_exhausted_code(credit_kind),
            credit_exhausted_message(credit_kind),
        ));
    }
    Ok(())
}

async fn available_credit_bytes(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    credit_kind: CreditKind,
    now: i64,
) -> ApiResult<i64> {
    let grant_balance: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(
                    grants.amount_bytes - COALESCE((
                        SELECT SUM(allocations.amount_bytes)
                        FROM credit_debit_allocations AS allocations
                        WHERE allocations.grant_id = grants.id
                    ), 0)
                ), 0)::BIGINT
         FROM credit_grants AS grants
         WHERE grants.credit_subject = $1 AND grants.credit_kind = $2
           AND grants.available_at <= $3
           AND (grants.expires_at IS NULL OR grants.expires_at > $3)",
    )
    .bind(credit_subject)
    .bind(credit_kind.as_str())
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(
        grant_balance.saturating_add(if credit_kind == CreditKind::Notarization {
            credit_adjustment_total(&mut **transaction, credit_subject).await?
        } else {
            0
        }),
    )
}

fn bounded_capture_allowance(session_max: i64, available: i64) -> ApiResult<i64> {
    let allowance = session_max.min(available);
    if allowance <= 0 {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            credit_exhausted_code(CreditKind::Capture),
            credit_exhausted_message(CreditKind::Capture),
        ));
    }
    Ok(allowance)
}

async fn credit_adjustment_total<'e, E>(executor: E, credit_subject: &str) -> ApiResult<i64>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
         FROM credit_adjustments WHERE credit_subject = $1",
    )
    .bind(credit_subject)
    .fetch_one(executor)
    .await
    .map_err(database_error)
}

async fn credit_summary(
    database: &super::DatabasePool,
    credit_subject: &str,
    now: i64,
) -> ApiResult<CreditSummary> {
    let period = monthly_credit_period(database, now).await?;
    Ok(CreditSummary {
        capture: credit_balance_summary(database, credit_subject, CreditKind::Capture, now).await?,
        notarization: credit_balance_summary(
            database,
            credit_subject,
            CreditKind::Notarization,
            now,
        )
        .await?,
        reset_at: period.end,
    })
}

async fn credit_balance_summary(
    database: &super::DatabasePool,
    credit_subject: &str,
    credit_kind: CreditKind,
    now: i64,
) -> ApiResult<CreditBalanceSummary> {
    let balances = sqlx::query_as::<_, GrantBalanceRow>(
        "SELECT grants.source_kind, grants.expires_at,
                grants.amount_bytes AS granted_bytes,
                COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT AS used_bytes,
                grants.amount_bytes - COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT
                    AS remaining_bytes
         FROM credit_grants AS grants
         LEFT JOIN credit_debit_allocations AS allocations
           ON allocations.grant_id = grants.id
         WHERE grants.credit_subject = $1 AND grants.credit_kind = $2
           AND grants.available_at <= $3
           AND (grants.expires_at IS NULL OR grants.expires_at > $3)
         GROUP BY grants.id
         ORDER BY grants.expires_at ASC NULLS LAST, grants.created_at, grants.id",
    )
    .bind(credit_subject)
    .bind(credit_kind.as_str())
    .bind(now)
    .fetch_all(database)
    .await
    .map_err(database_error)?;
    let gross_included_remaining_bytes = balances
        .iter()
        .filter(|grant| grant.source_kind == "included_monthly")
        .map(|grant| grant.remaining_bytes)
        .sum::<i64>();
    let adjustment_bytes = if credit_kind == CreditKind::Notarization {
        credit_adjustment_total(database, credit_subject).await?
    } else {
        0
    };
    let adjusted_supplemental_bytes = balances
        .iter()
        .filter(|grant| grant.source_kind != "included_monthly")
        .map(|grant| grant.remaining_bytes)
        .sum::<i64>()
        .saturating_add(adjustment_bytes);
    let (included_monthly_remaining_bytes, supplemental_remaining_bytes) =
        if adjusted_supplemental_bytes >= 0 {
            (gross_included_remaining_bytes, adjusted_supplemental_bytes)
        } else {
            (
                gross_included_remaining_bytes.saturating_add(adjusted_supplemental_bytes),
                0,
            )
        };
    let total_remaining_bytes =
        included_monthly_remaining_bytes.saturating_add(supplemental_remaining_bytes);
    let next_grant_expiration = if total_remaining_bytes > 0 {
        balances
            .iter()
            .filter(|grant| grant.remaining_bytes > 0)
            .filter_map(|grant| grant.expires_at)
            .min()
    } else {
        None
    };
    let total_granted_bytes = balances
        .iter()
        .map(|grant| grant.granted_bytes)
        .sum::<i64>();
    let total_used_bytes = balances.iter().map(|grant| grant.used_bytes).sum::<i64>();

    Ok(CreditBalanceSummary {
        total_granted_bytes,
        total_used_bytes,
        total_remaining_bytes,
        included_monthly_remaining_bytes,
        supplemental_remaining_bytes,
        next_grant_expiration,
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

fn policy_for_pool(config: &NotaryAdmissionConfig, pool: AdmissionTier) -> &AdmissionTierLimits {
    match pool {
        AdmissionTier::Public => &config.public,
        AdmissionTier::Free => &config.free,
        AdmissionTier::OneGb => &config.one_gb,
        AdmissionTier::TenGb => &config.ten_gb,
    }
}

fn credit_exhausted_code(kind: CreditKind) -> &'static str {
    match kind {
        CreditKind::Capture => "capture_credits_exhausted",
        CreditKind::Notarization => "notarization_credits_exhausted",
    }
}

fn credit_exhausted_message(kind: CreditKind) -> &'static str {
    match kind {
        CreditKind::Capture => "The monthly hosted capture allowance is exhausted",
        CreditKind::Notarization => "There are not enough hosted notarization credits",
    }
}

fn admission_limits(policy: &AdmissionTierLimits) -> AdmissionLimits {
    AdmissionLimits {
        max_attestable_http_bytes: policy.max_attestable_http_bytes,
        max_frame_bytes: policy.max_frame_bytes,
        max_private_chunk_bytes: policy.max_private_chunk_bytes,
        max_private_chunk_commitments: policy.max_private_chunk_commitments,
    }
}

fn account_credit_subject(account_id: &str) -> String {
    format!("account:{account_id}")
}

pub(crate) fn resolve_client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &NotaryAdmissionConfig,
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

pub(crate) fn normalized_client_address(ip: IpAddr) -> String {
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
        title: "128 MiB hosted notarization bonus".to_owned(),
        description: "Claim once for hosted notarization. The bonus expires after 90 days."
            .to_owned(),
        amount_bytes: PROMOTIONAL_OFFER_AMOUNT_BYTES,
        claim_expires_at: PROMOTIONAL_OFFER_CLAIM_DEADLINE,
        credit_expires_at: now + PROMOTIONAL_GRANT_TTL_SECS,
    }
}

fn parse_pool(value: &str) -> ApiResult<AdmissionTier> {
    match value {
        "public" => Ok(AdmissionTier::Public),
        "free" => Ok(AdmissionTier::Free),
        "one_gb" => Ok(AdmissionTier::OneGb),
        "ten_gb" => Ok(AdmissionTier::TenGb),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "invalid admission pool"
        ))),
    }
}

fn parse_plan(value: &str) -> ApiResult<Plan> {
    match value {
        "free" => Ok(Plan::Free),
        "one_gb" => Ok(Plan::OneGb),
        "ten_gb" => Ok(Plan::TenGb),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "invalid account service plan"
        ))),
    }
}

fn parse_billing_status(value: &str) -> ApiResult<BillingStatus> {
    match value {
        "active" => Ok(BillingStatus::Active),
        "review" => Ok(BillingStatus::Review),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "invalid account billing status"
        ))),
    }
}

fn admission_ticket_expired() -> ApiError {
    ApiError::coded(
        StatusCode::GONE,
        "admission_ticket_expired",
        "admission ticket is invalid or expired",
    )
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

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use url::Url;

    use super::*;

    async fn test_state() -> NotaryApiState {
        let database = super::super::fresh_database().await;
        NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://example.test/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://example.test/api/auth/google/callback")
                .unwrap(),
            public_origin: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            registry: super::super::tests::directory_key(),
            traces: super::super::traces::owner::TraceService::disabled_for_test(),
            admission: std::sync::Arc::new(NotaryAdmissionConfig::for_test()),
            billing: super::super::billing::BillingService::disabled_for_test(),
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn credit_kind_columns_require_an_explicit_value() {
        let state = test_state().await;
        let columns: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT table_name, column_default
             FROM information_schema.columns
             WHERE table_schema = 'notary_api'
               AND table_name IN ('credit_grants', 'credit_debits')
               AND column_name = 'credit_kind'
             ORDER BY table_name",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            columns,
            vec![
                ("credit_debits".to_owned(), None),
                ("credit_grants".to_owned(), None),
            ]
        );
    }

    fn service_headers(state: &NotaryApiState) -> HeaderMap {
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

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn credit_history_is_paginated_and_account_scoped() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        super::super::insert_test_github_user(&state.database, "history-1", 101, "history-one")
            .await;
        super::super::insert_test_github_user(&state.database, "history-2", 102, "history-two")
            .await;
        for (token, account_id) in [
            ("history-token-1", "history-1"),
            ("history-token-2", "history-2"),
        ] {
            sqlx::query(
                "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(sha256_hex(token.as_bytes()))
            .bind(account_id)
            .bind(now + 600)
            .bind(now)
            .execute(&state.database)
            .await
            .unwrap();
        }
        let mut transaction = state.database.begin().await.unwrap();
        create_credit_grant(
            &mut transaction,
            CreditGrantSpec {
                credit_subject: "account:history-1",
                account_id: Some("history-1"),
                credit_kind: CreditKind::Notarization,
                amount_bytes: 1,
                source_kind: "manual_adjustment",
                source_reference: "credit-history-pagination-fixture",
                idempotency_key: "credit-history-pagination-fixture",
                period_start: None,
                period_end: None,
                created_at: now - 1,
                available_at: now - 1,
                expires_at: None,
                display_label: "Credit history pagination fixture",
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        let jar = |token| CookieJar::new().add(Cookie::new(super::super::SESSION_COOKIE, token));
        let first = credit_history(
            State(state.clone()),
            jar("history-token-1"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: None,
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first.items.len(), 1);
        let cursor = first.next_cursor.expect("second credit-history page");
        let second = credit_history(
            State(state.clone()),
            jar("history-token-1"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: Some(cursor.clone()),
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0].id, second.items[0].id);

        let cross_account = credit_history(
            State(state),
            jar("history-token-2"),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: Some(cursor),
            })),
        )
        .await;
        assert!(matches!(
            cross_account,
            Err(ApiError {
                code: "cursor_scope_mismatch",
                ..
            })
        ));
    }

    #[test]
    fn plans_have_distinct_limits_and_exact_product_entitlements() {
        let config = NotaryAdmissionConfig::for_test();
        assert!(config.public.max_attestable_http_bytes < config.free.max_attestable_http_bytes);
        assert_eq!(
            config.public.monthly_notarization_bytes,
            config.free.monthly_notarization_bytes
        );
        assert!(config.free.max_attestable_http_bytes < config.one_gb.max_attestable_http_bytes);
        assert_eq!(
            plan_entitlements(&config, Plan::Free),
            PlanEntitlements {
                monthly_capture_bytes: 50_000_000,
                monthly_notarization_bytes: 50_000_000,
                trace_storage_bytes: Some(1_000_000_000),
            }
        );
        assert_eq!(
            plan_entitlements(&config, Plan::OneGb),
            PlanEntitlements {
                monthly_capture_bytes: 1_000_000_000,
                monthly_notarization_bytes: 1_000_000_000,
                trace_storage_bytes: Some(10_000_000_000),
            }
        );
        assert_eq!(
            plan_entitlements(&config, Plan::TenGb),
            PlanEntitlements {
                monthly_capture_bytes: 10_000_000_000,
                monthly_notarization_bytes: 10_000_000_000,
                trace_storage_bytes: None,
            }
        );
    }

    #[test]
    fn capture_tickets_use_the_last_partial_allowance() {
        assert_eq!(
            bounded_capture_allowance(8 << 20, 50_000_000).unwrap(),
            8 << 20
        );
        assert_eq!(bounded_capture_allowance(8 << 20, 1_024).unwrap(), 1_024);
        let exhausted = bounded_capture_allowance(8 << 20, 0).unwrap_err();
        assert_eq!(exhausted.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(exhausted.code, "capture_credits_exhausted");
    }

    #[test]
    fn trusted_proxy_resolution_cannot_be_spoofed_by_an_untrusted_peer() {
        let config = NotaryAdmissionConfig::for_test();
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
    fn notarization_requires_a_bound_digest_and_allowance() {
        let policy = AdmissionTierLimits::free();
        let missing = IssueAdmissionRequest {
            mode: AdmissionMode::Notarization,
            record_digest: None,
            requested_allowance_bytes: Some(1),
        };
        assert!(validate_ticket_request(&missing, &policy).is_err());
        let valid = IssueAdmissionRequest {
            mode: AdmissionMode::Notarization,
            record_digest: Some("ab".repeat(32)),
            requested_allowance_bytes: Some(1024),
        };
        assert_eq!(
            validate_ticket_request(&valid, &policy).expect("valid request"),
            (valid.record_digest.clone(), 1024)
        );
        let oversized = IssueAdmissionRequest {
            mode: AdmissionMode::Notarization,
            record_digest: valid.record_digest,
            requested_allowance_bytes: Some(policy.max_attestable_http_bytes + 1),
        };
        assert!(validate_ticket_request(&oversized, &policy).is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn one_operation_tickets_are_single_use_without_capacity_or_credit_reservations() {
        let state = test_state().await;
        let issue_capture = || {
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
        let first = issue_capture().await.unwrap().0;
        let second = issue_capture().await.unwrap().0;
        let required = issue_capture().await.unwrap().0;
        let redeem = |ticket: String, instance: &'static str, usage_settlement| {
            redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Ok(Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.to_owned(),
                    mode: AdmissionMode::Capture,
                    registry_generation: state.registry.generation,
                    contract: AdmissionRedemptionContract::OneOperationV1,
                    usage_settlement,
                })),
            )
        };

        let Json(admitted) = redeem(first.ticket.clone(), "notary-one", true)
            .await
            .unwrap();
        assert!(!admitted.operation_id.is_empty());
        assert_eq!(admitted.record_digest, None);
        assert_eq!(admitted.notarization_allowance_bytes, None);
        let consumed: Option<i64> =
            sqlx::query_scalar("SELECT consumed_at FROM admission_tickets WHERE token_hash = $1")
                .bind(sha256_hex(first.ticket.as_bytes()))
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert!(consumed.is_some());
        let admitted_instance: String = sqlx::query_scalar(
            "SELECT notary_instance_id FROM admitted_operations WHERE operation_id = $1",
        )
        .bind(&admitted.operation_id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(admitted_instance, "notary-one");
        let _ = redeem(second.ticket, "notary-two", true).await.unwrap();
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
        let endpoint = format!("http://{address}/api/internal/notary/admissions/redeem");
        let client = reqwest::Client::new();
        let missing_contract = client
            .post(&endpoint)
            .bearer_auth(&state.admission.service_token)
            .json(&serde_json::json!({
                "ticket": required.ticket.clone(),
                "notary_instance_id": "notary-old",
                "mode": "capture",
                "registry_generation": state.registry.generation,
                "usage_settlement": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(missing_contract.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            missing_contract
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        let missing_body: serde_json::Value = missing_contract.json().await.unwrap();
        assert_eq!(
            missing_body["error"],
            "invalid admission redemption request"
        );
        let unknown_contract = client
            .post(&endpoint)
            .bearer_auth(&state.admission.service_token)
            .json(&serde_json::json!({
                "ticket": required.ticket.clone(),
                "notary_instance_id": "notary-old",
                "mode": "capture",
                "registry_generation": state.registry.generation,
                "contract": "unsupported",
                "usage_settlement": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(unknown_contract.status(), StatusCode::BAD_REQUEST);
        let unauthenticated = client
            .post(&endpoint)
            .json(&serde_json::json!({"contract": "unsupported"}))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        let missing_settlement =
            match redeem(required.ticket.clone(), "notary-no-settlement", false).await {
                Ok(_) => panic!("redemption without durable settlement was admitted"),
                Err(error) => error,
            };
        assert_eq!(missing_settlement.status, StatusCode::BAD_REQUEST);
        let _ = redeem(required.ticket, "notary-required", true)
            .await
            .unwrap();
        let replay = match redeem(first.ticket, "notary-three", true).await {
            Ok(_) => panic!("one-operation ticket replay was admitted"),
            Err(error) => error,
        };
        assert_eq!(replay.status, StatusCode::CONFLICT);
        server.abort();

        let (debits, operations): (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM credit_debits),
                 (SELECT COUNT(*) FROM admitted_operations)",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!((debits, operations), (0, 3));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn settlement_is_idempotent_and_charges_admitted_capture_overage() {
        let mut state = test_state().await;
        let mut admission = NotaryAdmissionConfig::for_test();
        admission.public.monthly_capture_bytes = 10;
        admission.public.max_attestable_http_bytes = 10;
        state.admission = std::sync::Arc::new(admission);
        let ticket = issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .unwrap()
        .0;
        let Json(operation) = redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(RedeemAdmissionRequest {
                ticket: ticket.ticket,
                notary_instance_id: "notary-overage".to_owned(),
                mode: AdmissionMode::Capture,
                registry_generation: ticket.registry_generation,
                contract: AdmissionRedemptionContract::OneOperationV1,
                usage_settlement: true,
            })),
        )
        .await
        .unwrap();
        let operation_id = operation.operation_id;
        let report = || UsageSettlementRequest {
            operation_id: operation_id.clone(),
            notary_instance_id: "notary-overage".to_owned(),
            mode: AdmissionMode::Capture,
            authenticated_bytes: 11,
            outcome: UsageSettlementOutcome::ClientFailed,
        };

        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(report()),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(report()),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let (debits, charged): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(allowance_bytes), 0)::BIGINT
             FROM credit_debits WHERE operation_id = $1",
        )
        .bind(&operation_id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!((debits, charged), (1, 11));
        let credit_subject: String = sqlx::query_scalar(
            "SELECT credit_subject FROM admitted_operations WHERE operation_id = $1",
        )
        .bind(&operation_id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        let balances: Vec<(String, i64)> = sqlx::query_as(
            "SELECT grants.source_kind,
                    grants.amount_bytes - COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT
             FROM credit_grants AS grants
             LEFT JOIN credit_debit_allocations AS allocations
               ON allocations.grant_id = grants.id
             WHERE grants.credit_subject = $1 AND grants.credit_kind = 'capture'
             GROUP BY grants.id
             ORDER BY grants.source_kind",
        )
        .bind(&credit_subject)
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            balances,
            vec![
                ("included_monthly".to_owned(), 0),
                ("operation_overage".to_owned(), -1),
            ]
        );
        let credits = credit_summary(&state.database, &credit_subject, unix_timestamp().unwrap())
            .await
            .unwrap();
        assert_eq!(credits.capture.total_remaining_bytes, -1);

        let mut conflicting = report();
        conflicting.authenticated_bytes = 10;
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(conflicting),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        let mut conflicting = report();
        conflicting.mode = AdmissionMode::Notarization;
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(conflicting),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        let mut conflicting = report();
        conflicting.outcome = UsageSettlementOutcome::ServiceFailed;
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(conflicting),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        let mut conflicting = report();
        conflicting.notary_instance_id = "different-notary".to_owned();
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(conflicting),
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        let unchanged: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(allowance_bytes), 0)::BIGINT
             FROM credit_debits WHERE operation_id = $1",
        )
        .bind(&operation_id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(unchanged, (1, 11));
        let denied = match issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        {
            Ok(_) => panic!("overdrawn subject must be denied"),
            Err(error) => error,
        };
        assert_eq!(denied.status, StatusCode::PAYMENT_REQUIRED);

        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO credit_grants
                 (id, credit_subject, credit_kind, amount_bytes, source_kind,
                  source_reference, idempotency_key, created_at, available_at, display_label)
             VALUES ('later-insufficient', $1, 'capture', 1, 'manual_adjustment',
                     'later-insufficient', 'later-insufficient', $2, $2, 'Later credit')",
        )
        .bind(&credit_subject)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let still_denied = match issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        {
            Ok(_) => panic!("credit that only repays overage debt must not admit a ticket"),
            Err(error) => error,
        };
        assert_eq!(still_denied.status, StatusCode::PAYMENT_REQUIRED);

        sqlx::query(
            "INSERT INTO credit_grants
                 (id, credit_subject, credit_kind, amount_bytes, source_kind,
                  source_reference, idempotency_key, created_at, available_at, display_label)
             VALUES ('later-sufficient', $1, 'capture', 2, 'manual_adjustment',
                     'later-sufficient', 'later-sufficient', $2, $2, 'More later credit')",
        )
        .bind(&credit_subject)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let _ = issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .expect("credit beyond the outstanding debt admits a new operation");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn notarization_settlement_requires_the_bound_notarization_allowance() {
        let state = test_state().await;
        let digest = "ab".repeat(32);
        let ticket = issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Notarization,
                record_digest: Some(digest.clone()),
                requested_allowance_bytes: Some(42),
            }),
        )
        .await
        .unwrap()
        .0;
        let Json(operation) = redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(RedeemAdmissionRequest {
                ticket: ticket.ticket,
                notary_instance_id: "notary-notarization".to_owned(),
                mode: AdmissionMode::Notarization,
                registry_generation: ticket.registry_generation,
                contract: AdmissionRedemptionContract::OneOperationV1,
                usage_settlement: true,
            })),
        )
        .await
        .unwrap();
        let operation_id = operation.operation_id;
        let invalid = settle_usage(
            State(state.clone()),
            service_headers(&state),
            Json(UsageSettlementRequest {
                operation_id: operation_id.clone(),
                notary_instance_id: "notary-notarization".to_owned(),
                mode: AdmissionMode::Notarization,
                authenticated_bytes: 41,
                outcome: UsageSettlementOutcome::Completed,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);

        settle_usage(
            State(state.clone()),
            service_headers(&state),
            Json(UsageSettlementRequest {
                operation_id: operation_id.clone(),
                notary_instance_id: "notary-notarization".to_owned(),
                mode: AdmissionMode::Notarization,
                authenticated_bytes: 42,
                outcome: UsageSettlementOutcome::ClientFailed,
            }),
        )
        .await
        .unwrap();
        let charged: i64 =
            sqlx::query_scalar("SELECT allowance_bytes FROM credit_debits WHERE operation_id = $1")
                .bind(operation_id)
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(charged, 42, "measured failed operations are still charged");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn one_operation_expiry_and_wrong_mode_fail_before_admission() {
        let state = test_state().await;
        let capture = issue_admission(
            State(state.clone()),
            test_peer(),
            HeaderMap::new(),
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .unwrap()
        .0;
        let request = |ticket, mode, instance| RedeemAdmissionRequest {
            ticket,
            notary_instance_id: instance,
            mode,
            registry_generation: capture.registry_generation,
            contract: AdmissionRedemptionContract::OneOperationV1,
            usage_settlement: true,
        };
        let wrong_mode = match redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(request(
                capture.ticket.clone(),
                AdmissionMode::Notarization,
                "notary-wrong-mode".to_owned(),
            ))),
        )
        .await
        {
            Ok(_) => panic!("wrong-mode ticket was admitted"),
            Err(error) => error,
        };
        assert_eq!(wrong_mode.status, StatusCode::CONFLICT);

        sqlx::query("UPDATE admission_tickets SET expires_at = 1 WHERE token_hash = $1")
            .bind(sha256_hex(capture.ticket.as_bytes()))
            .execute(&state.database)
            .await
            .unwrap();
        let expired = match redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(request(
                capture.ticket,
                AdmissionMode::Capture,
                "notary-expired".to_owned(),
            ))),
        )
        .await
        {
            Ok(_) => panic!("expired ticket was admitted"),
            Err(error) => error,
        };
        assert_eq!(expired.status, StatusCode::GONE);
        assert_eq!(expired.code, "admission_ticket_expired");

        let missing = match redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(request(
                "missing-ticket".to_owned(),
                AdmissionMode::Capture,
                "notary-missing".to_owned(),
            ))),
        )
        .await
        {
            Ok(_) => panic!("missing ticket was admitted"),
            Err(error) => error,
        };
        assert_eq!(
            (missing.status, missing.code, missing.message),
            (expired.status, expired.code, expired.message),
            "missing and expired tickets must not form a validity oracle"
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn public_ip_subjects_receive_independent_allowances_without_subject_limits() {
        let state = test_state().await;

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
        let _first = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("first subject ticket")
            .0;
        let _same_subject = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("same subject ticket")
            .0;
        let _third_same_subject = issue(test_peer_at("198.51.100.10"))
            .await
            .expect("same subject has no separate start limit")
            .0;
        let _independent = issue(test_peer_at("198.51.100.11"))
            .await
            .expect("independent subject ticket")
            .0;

        let grant_summary: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(DISTINCT credit_subject), COUNT(*),
                    MIN(amount_bytes), MAX(amount_bytes)
             FROM credit_grants
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
                state.admission.public.monthly_notarization_bytes,
                state.admission.public.monthly_notarization_bytes,
            )
        );
        let ticket_counts: Vec<i64> = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admission_tickets
             GROUP BY credit_subject ORDER BY COUNT(*)",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(ticket_counts, vec![1, 3]);
        let stored_subjects: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT credit_subject FROM admission_tickets
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
        let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
            .fetch_one(&state.database)
            .await
            .unwrap();
        assert_eq!(accounts, 0);
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
                AdmissionTier::Public,
                &state.admission.public,
                CreditKind::Notarization,
                august,
            )
            .await
            .unwrap();
        }
        transaction.commit().await.unwrap();

        let august_grants: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), SUM(amount_bytes)::BIGINT
             FROM credit_grants
             WHERE credit_subject = $1 AND period_start = $2",
        )
        .bind(subject)
        .bind(period.start)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(
            august_grants,
            (1, state.admission.public.monthly_notarization_bytes)
        );

        let mut transaction = state.database.begin().await.unwrap();
        ensure_monthly_grant(
            &mut transaction,
            subject,
            None,
            AdmissionTier::OneGb,
            &state.admission.one_gb,
            CreditKind::Notarization,
            august,
        )
        .await
        .unwrap();
        let upgraded: i64 = sqlx::query_scalar(
            "SELECT amount_bytes FROM credit_grants
             WHERE credit_subject = $1 AND period_start = $2",
        )
        .bind(subject)
        .bind(period.start)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(upgraded, state.admission.one_gb.monthly_notarization_bytes);
        ensure_monthly_grant(
            &mut transaction,
            subject,
            None,
            AdmissionTier::Public,
            &state.admission.public,
            CreditKind::Notarization,
            august,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        let september = period.end;
        let mut transaction = state.database.begin().await.unwrap();
        ensure_monthly_grant(
            &mut transaction,
            subject,
            None,
            AdmissionTier::Public,
            &state.admission.public,
            CreditKind::Notarization,
            september,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        let grants: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT period_start, period_end, amount_bytes
             FROM credit_grants WHERE credit_subject = $1
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
                    state.admission.public.monthly_notarization_bytes,
                ),
                (
                    1_788_220_800,
                    1_790_812_800,
                    state.admission.public.monthly_notarization_bytes,
                ),
            ]
        );
        let credits = credit_summary(&state.database, subject, september)
            .await
            .unwrap();
        assert_eq!(
            credits.notarization.total_remaining_bytes,
            state.admission.public.monthly_notarization_bytes
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
                credit_subject: "account:grant-idempotency-test",
                account_id: None,
                credit_kind: CreditKind::Notarization,
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
            "SELECT COUNT(*) FROM credit_grants
             WHERE credit_subject = 'account:grant-idempotency-test'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn concurrent_promotional_claims_create_one_server_authored_grant() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        super::super::insert_test_github_user(&state.database, "promo-user", 44, "promo").await;
        let session = "promo-browser-session";
        sqlx::query(
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
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
            successful.0.credits.notarization.total_remaining_bytes,
            state.admission.free.monthly_notarization_bytes + PROMOTIONAL_OFFER_AMOUNT_BYTES
        );
        let rejected = first.err().or_else(|| second.err()).unwrap();
        assert_eq!(rejected.code, "credit_offer_already_claimed");
        let grant: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM credit_grants
             WHERE credit_subject = 'account:promo-user' AND source_kind = 'promotion'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(grant, (1, PROMOTIONAL_OFFER_AMOUNT_BYTES));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn signed_in_accounts_default_to_free_and_subscriptions_select_paid_access() {
        let state = test_state().await;
        super::super::insert_test_github_user(&state.database, "user-1", 1, "octo").await;
        let free_credits = account_access(&state, "user-1").await.unwrap();
        assert_eq!(free_credits.notarization.total_remaining_bytes, 50_000_000);
        assert_eq!(
            free_credits.notarization.included_monthly_remaining_bytes,
            50_000_000
        );
        assert_eq!(free_credits.notarization.supplemental_remaining_bytes, 0);
        let repeated_access = account_access(&state, "user-1").await.unwrap();
        assert_eq!(
            repeated_access.notarization.total_remaining_bytes,
            50_000_000
        );
        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO devices
             (device_id, account_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
             VALUES ('device-test', 'user-1', 'test notary', 'refresh-hash', $1, $1, $2)",
        )
        .bind(now)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        let access_token = "notary_access_test";
        sqlx::query(
            "INSERT INTO device_access_tokens (token_hash, device_id, expires_at, created_at)
             VALUES ($1, 'device-test', $2, $3)",
        )
        .bind(sha256_hex(access_token.as_bytes()))
        .bind(now + 60)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let mut device_headers = HeaderMap::new();
        device_headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let free_ticket = issue_admission(
            State(state.clone()),
            test_peer(),
            device_headers,
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
        let admission_tier: String = sqlx::query_scalar(
            "SELECT admission_tier FROM admission_tickets WHERE token_hash = $1",
        )
        .bind(sha256_hex(free_ticket.ticket.as_bytes()))
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(admission_tier, "free");

        sqlx::query(
            "INSERT INTO account_billing_profiles
                 (account_id, plan, billing_status, updated_at)
             VALUES ('user-1', 'one_gb', 'active', $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        assert_eq!(
            account_billing_state(&state.database, "user-1")
                .await
                .unwrap(),
            AccountBillingState {
                plan: Plan::OneGb,
                billing_status: BillingStatus::Active,
            }
        );
        let mut paid_headers = HeaderMap::new();
        paid_headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {access_token}").parse().unwrap(),
        );
        let paid_ticket = issue_admission(
            State(state.clone()),
            test_peer(),
            paid_headers,
            Json(IssueAdmissionRequest {
                mode: AdmissionMode::Capture,
                record_digest: None,
                requested_allowance_bytes: None,
            }),
        )
        .await
        .expect("paid account admission")
        .0;
        assert_eq!(
            paid_ticket.limits.max_attestable_http_bytes,
            state.admission.one_gb.max_attestable_http_bytes
        );
        let paid_admission_tier: String = sqlx::query_scalar(
            "SELECT admission_tier FROM admission_tickets WHERE token_hash = $1",
        )
        .bind(sha256_hex(paid_ticket.ticket.as_bytes()))
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(paid_admission_tier, "one_gb");

        sqlx::query(
            "UPDATE account_billing_profiles
             SET plan = 'free', updated_at = $1 WHERE account_id = 'user-1'",
        )
        .bind(now + 1)
        .execute(&state.database)
        .await
        .unwrap();
        let stale_paid_ticket = redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(RedeemAdmissionRequest {
                ticket: paid_ticket.ticket,
                notary_instance_id: "notary-stale-plan".to_owned(),
                mode: AdmissionMode::Capture,
                registry_generation: paid_ticket.registry_generation,
                contract: AdmissionRedemptionContract::OneOperationV1,
                usage_settlement: true,
            })),
        )
        .await
        .expect_err("stale paid ticket should be rejected");
        assert_eq!(stale_paid_ticket.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(stale_paid_ticket.code, "billing_plan_changed");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn billing_adjustments_enforce_purchase_ownership_and_signs() {
        let state = test_state().await;
        super::super::insert_test_github_user(&state.database, "buyer", 3, "buyer").await;
        super::super::insert_test_github_user(&state.database, "other", 4, "other").await;
        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO billing_purchases
                 (id, account_id, client_idempotency_key, provider, state, currency,
                  unit_amount_cents, quantity_gb, credit_bytes, expected_amount_cents,
                  provider_price_id, livemode, created_at, updated_at)
             VALUES ('purchase-1', 'buyer', 'checkout-1', 'stripe', 'paid', 'usd',
                     1000, 1, 1000000000, 1000, 'price_test', FALSE, $1, $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();

        let wrong_sign = sqlx::query(
            "INSERT INTO credit_adjustments
                 (id, credit_subject, account_id, purchase_id, amount_bytes, source_kind,
                  source_reference, idempotency_key, display_label, created_at)
             VALUES ('adjustment-sign', 'account:buyer', 'buyer', 'purchase-1', 1,
                     'purchase_refund', 'refund-sign', 'refund-sign', 'Refund', $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await;
        assert!(wrong_sign.is_err());

        let wrong_owner = sqlx::query(
            "INSERT INTO credit_adjustments
                 (id, credit_subject, account_id, purchase_id, amount_bytes, source_kind,
                  source_reference, idempotency_key, display_label, created_at)
             VALUES ('adjustment-owner', 'account:other', 'other', 'purchase-1', -1,
                     'purchase_refund', 'refund-owner', 'refund-owner', 'Refund', $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await;
        assert!(wrong_owner.is_err());
    }
}
