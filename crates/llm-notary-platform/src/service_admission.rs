use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
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
use llm_notary_core::{
    pagination::{CursorScope, Page, PageQuery, decode_cursor},
    sha256_hex,
};

const ADMISSION_LOCK_NAMESPACE: i32 = 151;
const ADMISSION_LOCK_KEY: i32 = 1;
const MAX_TICKET_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const SECS_PER_DAY: i64 = 24 * 60 * 60;
const CLIENT_IP_HEADER: &str = "x-llm-notary-client-ip";
const PUBLIC_SUBJECT_PURPOSE: &str = "hosted-finalization-public-subject";
const PROMOTIONAL_OFFER_ID: &str = "hosted-finalization-bonus-v1";
const PROMOTIONAL_OFFER_AMOUNT_BYTES: i64 = 128 << 20;
const PROMOTIONAL_OFFER_CLAIM_DEADLINE: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z
const PROMOTIONAL_GRANT_TTL_SECS: i64 = 90 * SECS_PER_DAY;

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
    OneGb,
    TenGb,
}

impl AccessPool {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Free => "free",
            Self::OneGb => "one_gb",
            Self::TenGb => "ten_gb",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServicePlan {
    Free,
    OneGb,
    TenGb,
}

impl ServicePlan {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::OneGb => "one_gb",
            Self::TenGb => "ten_gb",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditKind {
    Capture,
    Notarization,
}

impl CreditKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Notarization => "notarization",
        }
    }

    fn for_mode(mode: AdmissionMode) -> Self {
        match mode {
            AdmissionMode::Capture => Self::Capture,
            AdmissionMode::Finalize => Self::Notarization,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingStatus {
    Active,
    Review,
}

impl BillingStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Review => "review",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct AccountBillingState {
    pub service_plan: ServicePlan,
    pub billing_status: BillingStatus,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct PlanEntitlements {
    pub monthly_notarization_bytes: i64,
    pub monthly_capture_bytes: i64,
    /// `None` means there is no fixed plan ceiling; abuse controls still apply.
    pub trace_storage_bytes: Option<i64>,
}

pub(crate) fn plan_entitlements(config: &AdmissionConfig, plan: ServicePlan) -> PlanEntitlements {
    let policy = match plan {
        ServicePlan::Free => &config.free,
        ServicePlan::OneGb => &config.one_gb,
        ServicePlan::TenGb => &config.ten_gb,
    };
    PlanEntitlements {
        monthly_notarization_bytes: policy.monthly_notarization_bytes,
        monthly_capture_bytes: policy.monthly_capture_bytes,
        trace_storage_bytes: match plan {
            ServicePlan::Free => Some(1_000_000_000),
            ServicePlan::OneGb => Some(10_000_000_000),
            ServicePlan::TenGb => None,
        },
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
    Adjustment,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditHistoryEntry {
    pub id: String,
    pub kind: CreditHistoryKind,
    pub credit_kind: CreditKind,
    pub amount_bytes: i64,
    pub source_kind: Option<String>,
    pub display_label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditBalanceSummary {
    pub total_granted_bytes: i64,
    pub total_used_bytes: i64,
    pub total_remaining_bytes: i64,
    pub included_monthly_remaining_bytes: i64,
    pub supplemental_remaining_bytes: i64,
    pub next_grant_expiration: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditSummary {
    pub capture: CreditBalanceSummary,
    pub notarization: CreditBalanceSummary,
    pub reset_at: i64,
}

#[derive(Deserialize, Serialize)]
struct CreditHistoryPagePosition {
    created_at: i64,
    id: String,
    kind: String,
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
    #[serde(default)]
    pub contract: Option<AdmissionRedemptionContract>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRedemptionContract {
    OneOperationV1,
}

#[derive(Serialize, ToSchema)]
pub struct RedeemedLeaseResponse {
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

#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemedOperationResponse {
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub record_digest: Option<String>,
    pub authenticated_allowance_bytes: Option<i64>,
}

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum RedeemAdmissionResponse {
    Lease(RedeemedLeaseResponse),
    Operation(RedeemedOperationResponse),
}

#[cfg(test)]
impl std::ops::Deref for RedeemAdmissionResponse {
    type Target = RedeemedLeaseResponse;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Lease(lease) => lease,
            Self::Operation(_) => panic!("test expected the legacy lease contract"),
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct LeaseRequest {
    pub lease_id: String,
    pub notary_instance_id: String,
    #[serde(default)]
    pub outcome: Option<LeaseCompletionOutcome>,
    #[serde(default)]
    pub used_allowance_bytes: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseCompletionOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

impl LeaseCompletionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ClientFailed => "client_failed",
            Self::ServiceFailed => "service_failed",
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct LeaseRenewedResponse {
    pub lease_expires_at: i64,
}

#[derive(FromRow)]
struct TicketRow {
    token_hash: String,
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

#[derive(FromRow)]
struct OperationTicketRow {
    subject_id: Option<String>,
    credit_subject: String,
    access_pool: String,
    mode: String,
    directory_generation: i64,
    record_digest: Option<String>,
    authenticated_allowance_bytes: Option<i64>,
    max_attestable_http_bytes: i64,
    max_frame_bytes: i64,
    max_private_chunk_bytes: i64,
    max_private_chunk_commitments: i64,
    expires_at: i64,
    consumed_at: Option<i64>,
}

struct DebitReservation {
    id: String,
    restore_on_service_failure: bool,
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(issue_admission))
        .routes(routes!(eligible_credit_offers))
        .routes(routes!(credit_history))
        .routes(routes!(claim_credit_offer))
        .routes(routes!(redeem_admission))
        .routes(routes!(renew_lease))
        .routes(routes!(release_lease))
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
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<CreditHistoryEntry>>> {
    let Query(query) = query.map_err(super::pagination::query_error)?;
    let user = super::authenticated_web_user(&state, &jar).await?;
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
             FROM notary_credit_grants WHERE credit_subject = $1
             UNION ALL
             SELECT id, 'debit'::TEXT AS kind, credit_kind, allowance_bytes AS amount_bytes,
                    NULL::TEXT AS source_kind,
                    CASE credit_kind WHEN 'capture' THEN 'Hosted capture'
                         ELSE 'Hosted notarization' END AS display_label,
                    created_at, NULL::BIGINT AS expires_at
             FROM notary_credit_debits WHERE credit_subject = $1
             UNION ALL
             SELECT id, 'adjustment'::TEXT AS kind, 'notarization'::TEXT AS credit_kind, amount_bytes,
                    source_kind::TEXT AS source_kind, display_label,
                    created_at, NULL::BIGINT AS expires_at
             FROM notary_credit_adjustments WHERE credit_subject = $1
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

pub async fn account_access(state: &AppState, user_id: &str) -> ApiResult<CreditSummary> {
    ensure_account_monthly_grant(state, user_id).await?;
    let now = unix_timestamp()?;
    credit_summary(&state.database, &account_credit_subject(user_id), now).await
}

pub async fn account_billing_state(
    database: &super::DatabasePool,
    user_id: &str,
) -> ApiResult<AccountBillingState> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT service_plan, billing_status
         FROM account_billing_profiles WHERE account_id = $1",
    )
    .bind(user_id)
    .fetch_optional(database)
    .await
    .map_err(database_error)?;
    match row {
        Some((plan, status)) => Ok(AccountBillingState {
            service_plan: parse_service_plan(&plan)?,
            billing_status: parse_billing_status(&status)?,
        }),
        None => Ok(AccountBillingState {
            service_plan: ServicePlan::Free,
            billing_status: BillingStatus::Active,
        }),
    }
}

async fn account_access_pool(
    database: &super::DatabasePool,
    user_id: &str,
) -> ApiResult<AccessPool> {
    Ok(
        match account_billing_state(database, user_id).await?.service_plan {
            ServicePlan::Free => AccessPool::Free,
            ServicePlan::OneGb => AccessPool::OneGb,
            ServicePlan::TenGb => AccessPool::TenGb,
        },
    )
}

async fn ensure_account_monthly_grant(state: &AppState, user_id: &str) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let pool = account_access_pool(&state.database, user_id).await?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let policy = policy_for_pool(&state.admission, pool);
    let credit_subject = account_credit_subject(user_id);
    for credit_kind in [CreditKind::Capture, CreditKind::Notarization] {
        ensure_monthly_grant(
            &mut transaction,
            &credit_subject,
            Some(user_id),
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
    let pool = account_access_pool(&state.database, &user.0).await?;
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
    let (subject_id, credit_subject, pool, billing_status) = match identity {
        Some(principal) => {
            let billing = account_billing_state(&state.database, &principal.user_id).await?;
            let credit_subject = account_credit_subject(&principal.user_id);
            let pool = match billing.service_plan {
                ServicePlan::Free => AccessPool::Free,
                ServicePlan::OneGb => AccessPool::OneGb,
                ServicePlan::TenGb => AccessPool::TenGb,
            };
            (
                Some(principal.user_id),
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
                AccessPool::Public,
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
    let token = random_token();
    let directory_generation = i64::try_from(state.notary_directory.generation)
        .map_err(|_| ApiError::internal(anyhow::anyhow!("directory generation is too large")))?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        subject_id.as_deref(),
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
    {
        preflight_credits(
            &mut transaction,
            &credit_subject,
            CreditKind::for_mode(request.mode),
            record_digest.as_deref(),
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
    // `requested_allowance_bytes` keeps the immediately previous lease
    // contract rollbackable. The one-operation redemption path ignores it.
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
    summary = "Consume a ticket using the requested notary admission contract",
    request_body = RedeemAdmissionRequest,
    responses(
        (status = 200, body = RedeemAdmissionResponse),
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
    if request.contract == Some(AdmissionRedemptionContract::OneOperationV1) {
        return redeem_one_operation(&state, &request, now, requested_generation)
            .await
            .map(|response| Json(RedeemAdmissionResponse::Operation(response)));
    }
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    expire_leases(&mut transaction, now).await?;
    let ticket = sqlx::query_as::<_, TicketRow>(
        "SELECT token_hash, subject_id, credit_subject, access_pool, mode, directory_generation, record_digest,
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
    if let Some(account_id) = ticket.subject_id.as_deref() {
        let current_billing = sqlx::query_as::<_, (String, String)>(
            "SELECT service_plan, billing_status
             FROM account_billing_profiles WHERE account_id = $1
             FOR SHARE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        let (service_plan, billing_status) = current_billing
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
        if (pool == AccessPool::OneGb && service_plan != "one_gb")
            || (pool == AccessPool::TenGb && service_plan != "ten_gb")
        {
            return Err(ApiError::coded(
                StatusCode::PAYMENT_REQUIRED,
                "billing_plan_changed",
                "The account plan changed after this admission ticket was issued",
            ));
        }
    }
    let credit_subject = ticket.credit_subject.clone();
    ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        ticket.subject_id.as_deref(),
        pool,
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    enforce_concurrency(&mut transaction, &state.admission, policy, &ticket, now).await?;
    let credit_debit = Some(debit_credits(&mut transaction, &ticket, now).await?);
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
         SET consumed_at = $1, consumed_by_instance = $2, lease_id = $3,
             credit_debit_id = $4, credit_debit_refundable = $5
         WHERE token_hash = $6 AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(&request.notary_instance_id)
    .bind(&lease_id)
    .bind(credit_debit.as_ref().map(|debit| debit.id.as_str()))
    .bind(
        credit_debit
            .as_ref()
            .is_some_and(|debit| debit.restore_on_service_failure),
    )
    .bind(sha256_hex(request.ticket.as_bytes()))
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    metrics::counter!("llm_notary_admission_leases_total", "pool" => pool.as_str(), "mode" => request.mode.as_str(), "outcome" => "admitted").increment(1);
    Ok(Json(RedeemAdmissionResponse::Lease(
        RedeemedLeaseResponse {
            lease_id,
            lease_expires_at,
            access_pool: pool,
            max_attestable_http_bytes: ticket.max_attestable_http_bytes,
            max_frame_bytes: ticket.max_frame_bytes,
            max_private_chunk_bytes: ticket.max_private_chunk_bytes,
            max_private_chunk_commitments: ticket.max_private_chunk_commitments,
            record_digest: ticket.record_digest,
            authorized_allowance_bytes: ticket.requested_allowance_bytes,
        },
    )))
}

async fn redeem_one_operation(
    state: &AppState,
    request: &RedeemAdmissionRequest,
    now: i64,
    requested_generation: i64,
) -> ApiResult<RedeemedOperationResponse> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let ticket = sqlx::query_as::<_, OperationTicketRow>(
        "SELECT subject_id, credit_subject, access_pool, mode, directory_generation,
                record_digest, authenticated_allowance_bytes, max_attestable_http_bytes,
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
    if let Some(account_id) = ticket.subject_id.as_deref() {
        let current_billing = sqlx::query_as::<_, (String, String)>(
            "SELECT service_plan, billing_status
             FROM account_billing_profiles WHERE account_id = $1
             FOR SHARE",
        )
        .bind(account_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
        let (service_plan, billing_status) = current_billing
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
        if (pool == AccessPool::OneGb && service_plan != "one_gb")
            || (pool == AccessPool::TenGb && service_plan != "ten_gb")
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
        ticket.subject_id.as_deref(),
        pool,
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    let required_allowance = ticket.authenticated_allowance_bytes.unwrap_or(1);
    preflight_credits(
        &mut transaction,
        &ticket.credit_subject,
        CreditKind::for_mode(request.mode),
        ticket.record_digest.as_deref(),
        required_allowance,
        now,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE notary_admission_tickets
         SET consumed_at = $1, consumed_by_instance = $2
         WHERE token_hash = $3 AND consumed_at IS NULL",
    )
    .bind(now)
    .bind(&request.notary_instance_id)
    .bind(sha256_hex(request.ticket.as_bytes()))
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict("admission ticket was already consumed"));
    }
    transaction.commit().await.map_err(database_error)?;
    metrics::counter!("llm_notary_admission_operations_total", "pool" => pool.as_str(), "mode" => request.mode.as_str(), "outcome" => "admitted").increment(1);
    Ok(RedeemedOperationResponse {
        max_attestable_http_bytes: ticket.max_attestable_http_bytes,
        max_frame_bytes: ticket.max_frame_bytes,
        max_private_chunk_bytes: ticket.max_private_chunk_bytes,
        max_private_chunk_commitments: ticket.max_private_chunk_commitments,
        record_digest: ticket.record_digest,
        authenticated_allowance_bytes: ticket.authenticated_allowance_bytes,
    })
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
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
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
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    admission_lock(&mut transaction).await?;
    let lease = sqlx::query_as::<_, (String, Option<String>, Option<i64>)>(
        "SELECT mode, completion_outcome, released_at
         FROM notary_admission_leases
         WHERE id = $1 AND notary_instance_id = $2
         FOR UPDATE",
    )
    .bind(&request.lease_id)
    .bind(&request.notary_instance_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?;
    let Some((mode, previous_outcome, previous_released_at)) = lease else {
        transaction.commit().await.map_err(database_error)?;
        return Ok(StatusCode::NO_CONTENT);
    };
    let requested_outcome = request.outcome.map(LeaseCompletionOutcome::as_str);
    if previous_outcome
        .as_deref()
        .is_some_and(|previous| requested_outcome.is_some_and(|requested| requested != previous))
    {
        return Err(ApiError::conflict(
            "admission lease was already released with a different outcome",
        ));
    }
    let effective_outcome = previous_outcome.as_deref().or(requested_outcome);
    match (mode.as_str(), effective_outcome) {
        ("capture", Some("completed")) => {
            let used = request.used_allowance_bytes.ok_or_else(|| {
                ApiError::bad_request("completed capture release must include used_allowance_bytes")
            })?;
            settle_capture_reservation(&mut transaction, &request.lease_id, used).await?;
        }
        ("capture", Some("service_failed")) => {
            if request.used_allowance_bytes.is_some() {
                return Err(ApiError::bad_request(
                    "failed capture release must not include used_allowance_bytes",
                ));
            }
            settle_capture_reservation(&mut transaction, &request.lease_id, 0).await?;
        }
        (_, _) if request.used_allowance_bytes.is_some() => {
            return Err(ApiError::bad_request(
                "used_allowance_bytes is only valid for a completed capture",
            ));
        }
        _ => {}
    }
    let released_at = previous_released_at.unwrap_or(now);
    sqlx::query(
        "UPDATE notary_admission_leases
         SET released_at = COALESCE(released_at, $1),
             terminal_state = COALESCE(terminal_state, 'released'),
             completion_outcome = COALESCE(completion_outcome, $4)
         WHERE id = $2 AND notary_instance_id = $3",
    )
    .bind(released_at)
    .bind(&request.lease_id)
    .bind(&request.notary_instance_id)
    .bind(requested_outcome)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if mode == AdmissionMode::Finalize.as_str()
        && effective_outcome == Some(LeaseCompletionOutcome::ServiceFailed.as_str())
    {
        restore_purchased_credits_for_service_failure(
            &mut transaction,
            &request.lease_id,
            released_at,
        )
        .await?;
    }
    transaction.commit().await.map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn settle_capture_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    lease_id: &str,
    used_allowance_bytes: i64,
) -> ApiResult<()> {
    let ticket = sqlx::query_as::<_, (String, i64, Option<i64>)>(
        "SELECT credit_debit_id, requested_allowance_bytes, settled_allowance_bytes
         FROM notary_admission_tickets
         WHERE lease_id = $1 AND mode = 'capture' AND credit_debit_id IS NOT NULL
         FOR UPDATE",
    )
    .bind(lease_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| {
        ApiError::internal(anyhow::anyhow!("capture lease has no credit reservation"))
    })?;
    let (debit_id, reserved_allowance_bytes, settled_allowance_bytes) = ticket;
    if used_allowance_bytes < 0 || used_allowance_bytes > reserved_allowance_bytes {
        return Err(ApiError::bad_request(
            "capture usage exceeds its authorized allowance",
        ));
    }
    if let Some(settled) = settled_allowance_bytes {
        return if settled == used_allowance_bytes {
            Ok(())
        } else {
            Err(ApiError::conflict(
                "capture lease was already settled with different usage",
            ))
        };
    }
    let debit = sqlx::query_as::<_, (i64, String)>(
        "SELECT allowance_bytes, credit_kind FROM notary_credit_debits
         WHERE id = $1 FOR UPDATE",
    )
    .bind(&debit_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::internal(anyhow::anyhow!("capture credit reservation is missing")))?;
    if debit.0 != reserved_allowance_bytes || debit.1 != CreditKind::Capture.as_str() {
        return Err(ApiError::internal(anyhow::anyhow!(
            "capture credit reservation does not match its ticket"
        )));
    }
    let allocations = sqlx::query_as::<_, (String, i64)>(
        "SELECT grant_id, amount_bytes
         FROM notary_credit_debit_allocations
         WHERE debit_id = $1 ORDER BY allocation_order
         FOR UPDATE",
    )
    .bind(&debit_id)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)?;
    let mut remaining = used_allowance_bytes;
    for (grant_id, amount_bytes) in allocations {
        if remaining >= amount_bytes {
            remaining -= amount_bytes;
        } else if remaining > 0 {
            sqlx::query(
                "UPDATE notary_credit_debit_allocations
                 SET amount_bytes = $1 WHERE debit_id = $2 AND grant_id = $3",
            )
            .bind(remaining)
            .bind(&debit_id)
            .bind(&grant_id)
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
            remaining = 0;
        } else {
            sqlx::query(
                "DELETE FROM notary_credit_debit_allocations
                 WHERE debit_id = $1 AND grant_id = $2",
            )
            .bind(&debit_id)
            .bind(&grant_id)
            .execute(&mut **transaction)
            .await
            .map_err(database_error)?;
        }
    }
    if remaining != 0 {
        return Err(ApiError::internal(anyhow::anyhow!(
            "capture credit allocations do not cover their reservation"
        )));
    }
    sqlx::query("UPDATE notary_credit_debits SET allowance_bytes = $1 WHERE id = $2")
        .bind(used_allowance_bytes)
        .bind(&debit_id)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    sqlx::query(
        "UPDATE notary_admission_tickets SET settled_allowance_bytes = $1 WHERE lease_id = $2",
    )
    .bind(used_allowance_bytes)
    .bind(lease_id)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn restore_purchased_credits_for_service_failure(
    transaction: &mut Transaction<'_, Postgres>,
    lease_id: &str,
    created_at: i64,
) -> ApiResult<()> {
    let debit = sqlx::query_as::<_, (String, String, String, i64)>(
        "SELECT debits.id, debits.credit_subject, debits.account_id,
                COALESCE(SUM(allocations.amount_bytes) FILTER (
                    WHERE grants.source_kind IN ('external_purchase', 'service_refund')
                ), 0)::BIGINT AS purchased_bytes
         FROM notary_admission_tickets AS tickets
         JOIN notary_credit_debits AS debits ON debits.id = tickets.credit_debit_id
         JOIN notary_credit_debit_allocations AS allocations
           ON allocations.debit_id = debits.id
         JOIN notary_credit_grants AS grants ON grants.id = allocations.grant_id
         WHERE tickets.lease_id = $1 AND tickets.credit_debit_refundable
           AND debits.account_id IS NOT NULL
         GROUP BY debits.id",
    )
    .bind(lease_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    let Some((debit_id, credit_subject, account_id, purchased_bytes)) = debit else {
        return Ok(());
    };
    if purchased_bytes == 0 {
        return Ok(());
    }
    let reference = format!("service-failure:{debit_id}");
    create_credit_grant(
        transaction,
        CreditGrantSpec {
            credit_subject: &credit_subject,
            account_id: Some(&account_id),
            credit_kind: CreditKind::Notarization,
            amount_bytes: purchased_bytes,
            source_kind: "service_refund",
            source_reference: &reference,
            idempotency_key: &reference,
            period_start: None,
            period_end: None,
            created_at,
            available_at: created_at,
            expires_at: None,
            display_label: "Service failure credit restoration",
        },
    )
    .await?;
    Ok(())
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
        "INSERT INTO notary_credit_grants
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
    service_plan: ServicePlan,
    billing_status: BillingStatus,
    updated_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO account_billing_profiles
             (account_id, service_plan, billing_status, updated_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id) DO UPDATE
         SET service_plan = EXCLUDED.service_plan,
             billing_status = EXCLUDED.billing_status,
             updated_at = GREATEST(account_billing_profiles.updated_at, EXCLUDED.updated_at)",
    )
    .bind(account_id)
    .bind(service_plan.as_str())
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
         FROM notary_credit_adjustments
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
        "INSERT INTO notary_credit_adjustments
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
    _pool: AccessPool,
    policy: &AdmissionPolicy,
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
        "SELECT id, amount_bytes FROM notary_credit_grants
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
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_debit_allocations WHERE grant_id = $1",
        )
        .bind(&grant_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(database_error)?;
        let reconciled_amount = monthly_bytes.max(used);
        if reconciled_amount != current_amount {
            sqlx::query("UPDATE notary_credit_grants SET amount_bytes = $1 WHERE id = $2")
                .bind(reconciled_amount)
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

async fn debit_credits(
    transaction: &mut Transaction<'_, Postgres>,
    ticket: &TicketRow,
    now: i64,
) -> ApiResult<DebitReservation> {
    let credit_kind = match ticket.mode.as_str() {
        "capture" => CreditKind::Capture,
        "finalize" => CreditKind::Notarization,
        _ => return Err(ApiError::internal(anyhow::anyhow!("invalid ticket mode"))),
    };
    let digest = ticket
        .record_digest
        .as_deref()
        .unwrap_or(&ticket.token_hash);
    let credit_subject = ticket.credit_subject.clone();
    if let Some((previous_debit_id, previous_allowance)) = sqlx::query_as::<_, (String, i64)>(
        "SELECT id, allowance_bytes FROM notary_credit_debits
         WHERE credit_subject = $1 AND credit_kind = $2 AND record_digest = $3",
    )
    .bind(&credit_subject)
    .bind(credit_kind.as_str())
    .bind(digest)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    {
        if previous_allowance != ticket.requested_allowance_bytes {
            return Err(ApiError::conflict(
                "a retry must use the original finalization allowance",
            ));
        }
        let attempt_active: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                 FROM notary_credit_debits AS attempts
                 JOIN notary_admission_tickets AS tickets
                   ON tickets.credit_debit_id = attempts.id
                 JOIN notary_admission_leases AS leases ON leases.id = tickets.lease_id
                 WHERE (attempts.id = $1 OR attempts.retry_of_debit_id = $1)
                   AND leases.released_at IS NULL AND leases.terminal_state IS NULL
                   AND leases.expires_at > $2
             )",
        )
        .bind(&previous_debit_id)
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(database_error)?;
        if attempt_active {
            return Err(ApiError::conflict(
                "a retry for this finalization is already in progress",
            ));
        }
        let restoration = sqlx::query_as::<_, (String, i64)>(
            "SELECT grants.id,
                    grants.amount_bytes - COALESCE((
                        SELECT SUM(allocations.amount_bytes)
                        FROM notary_credit_debit_allocations AS allocations
                        WHERE allocations.grant_id = grants.id
                    ), 0)::BIGINT AS remaining_bytes
             FROM notary_credit_grants AS grants
             JOIN notary_credit_debits AS attempts
               ON grants.source_reference = 'service-failure:' || attempts.id
             WHERE grants.credit_subject = $1 AND grants.source_kind = 'service_refund'
               AND (attempts.id = $2 OR attempts.retry_of_debit_id = $2)
               AND grants.available_at <= $3
               AND (grants.expires_at IS NULL OR grants.expires_at > $3)
               AND grants.amount_bytes - COALESCE((
                       SELECT SUM(allocations.amount_bytes)
                       FROM notary_credit_debit_allocations AS allocations
                       WHERE allocations.grant_id = grants.id
                   ), 0)::BIGINT > 0
             ORDER BY grants.available_at, grants.created_at, grants.id
             LIMIT 1
             FOR UPDATE OF grants",
        )
        .bind(&credit_subject)
        .bind(&previous_debit_id)
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?;
        let Some((restoration_grant_id, restored_bytes)) = restoration else {
            let latest_retry = sqlx::query_scalar::<_, String>(
                "SELECT retries.id FROM notary_credit_debits AS retries
                 WHERE retries.retry_of_debit_id = $1
                 ORDER BY retries.created_at DESC, retries.id DESC
                 LIMIT 1",
            )
            .bind(&previous_debit_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(database_error)?;
            if let Some(retry_id) = latest_retry {
                return Ok(DebitReservation {
                    id: retry_id,
                    restore_on_service_failure: false,
                });
            }
            return Ok(DebitReservation {
                id: previous_debit_id,
                restore_on_service_failure: false,
            });
        };
        let debit_id = Uuid::new_v4().to_string();
        let retry_digest = sha256_hex(
            format!("service-retry:{previous_debit_id}:{restoration_grant_id}").as_bytes(),
        );
        sqlx::query(
            "INSERT INTO notary_credit_debits
                 (id, credit_subject, account_id, credit_kind, record_digest, allowance_bytes, created_at,
                  retry_of_debit_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&debit_id)
        .bind(&credit_subject)
        .bind(ticket.subject_id.as_deref())
        .bind(credit_kind.as_str())
        .bind(retry_digest)
        .bind(restored_bytes)
        .bind(now)
        .bind(&previous_debit_id)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
        allocate_debit(
            transaction,
            &debit_id,
            restored_bytes,
            &[(restoration_grant_id, restored_bytes)],
        )
        .await?;
        return Ok(DebitReservation {
            id: debit_id,
            restore_on_service_failure: true,
        });
    }
    let grants = available_grants(transaction, &credit_subject, credit_kind, now).await?;
    let available = grants
        .iter()
        .fold(0_i64, |total, (_, remaining)| {
            total.saturating_add(*remaining)
        })
        .saturating_add(if credit_kind == CreditKind::Notarization {
            credit_adjustment_total(&mut **transaction, &credit_subject).await?
        } else {
            0
        });
    if available < ticket.requested_allowance_bytes {
        return Err(ApiError::coded(
            StatusCode::PAYMENT_REQUIRED,
            credit_exhausted_code(credit_kind),
            credit_exhausted_message(credit_kind),
        ));
    }
    let debit_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO notary_credit_debits
         (id, credit_subject, account_id, credit_kind, record_digest, allowance_bytes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&debit_id)
    .bind(&credit_subject)
    .bind(ticket.subject_id.as_deref())
    .bind(credit_kind.as_str())
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
    Ok(DebitReservation {
        id: debit_id,
        restore_on_service_failure: true,
    })
}

async fn preflight_credits(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    credit_kind: CreditKind,
    digest: Option<&str>,
    allowance: i64,
    now: i64,
) -> ApiResult<()> {
    if let Some(digest) = digest {
        let previous = sqlx::query_scalar::<_, i64>(
            "SELECT allowance_bytes FROM notary_credit_debits
             WHERE credit_subject = $1 AND credit_kind = $2 AND record_digest = $3",
        )
        .bind(credit_subject)
        .bind(credit_kind.as_str())
        .bind(digest)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)?;
        if let Some(previous) = previous {
            return if previous == allowance {
                Ok(())
            } else {
                Err(ApiError::conflict(
                    "a retry must use the original notarization allowance",
                ))
            };
        }
    }
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
    Ok(
        available_grants(transaction, credit_subject, credit_kind, now)
            .await?
            .iter()
            .map(|(_, remaining)| *remaining)
            .sum::<i64>()
            .saturating_add(if credit_kind == CreditKind::Notarization {
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

async fn available_grants(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    credit_kind: CreditKind,
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
         WHERE grants.credit_subject = $1 AND grants.credit_kind = $2
           AND grants.available_at <= $3
           AND (grants.expires_at IS NULL OR grants.expires_at > $3)
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
    .bind(credit_kind.as_str())
    .bind(now)
    .fetch_all(&mut **transaction)
    .await
    .map_err(database_error)
}

async fn credit_adjustment_total<'e, E>(executor: E, credit_subject: &str) -> ApiResult<i64>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
         FROM notary_credit_adjustments WHERE credit_subject = $1",
    )
    .bind(credit_subject)
    .fetch_one(executor)
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
         FROM notary_credit_grants AS grants
         LEFT JOIN notary_credit_debit_allocations AS allocations
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
                gross_included_remaining_bytes
                    .saturating_add(adjusted_supplemental_bytes)
                    .max(0),
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

fn policy_for_pool(config: &AdmissionConfig, pool: AccessPool) -> &AdmissionPolicy {
    match pool {
        AccessPool::Public => &config.public,
        AccessPool::Free => &config.free,
        AccessPool::OneGb => &config.one_gb,
        AccessPool::TenGb => &config.ten_gb,
    }
}

fn credit_exhausted_code(kind: CreditKind) -> &'static str {
    match kind {
        CreditKind::Capture => "capture_credits_exhausted",
        CreditKind::Notarization => "finalization_credits_exhausted",
    }
}

fn credit_exhausted_message(kind: CreditKind) -> &'static str {
    match kind {
        CreditKind::Capture => "The monthly hosted capture allowance is exhausted",
        CreditKind::Notarization => "There are not enough hosted notarization credits",
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

pub(crate) fn resolve_client_ip(
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
        "one_gb" => Ok(AccessPool::OneGb),
        "ten_gb" => Ok(AccessPool::TenGb),
        _ => Err(ApiError::internal(anyhow::anyhow!(
            "invalid admission pool"
        ))),
    }
}

fn parse_service_plan(value: &str) -> ApiResult<ServicePlan> {
    match value {
        "free" => Ok(ServicePlan::Free),
        "one_gb" => Ok(ServicePlan::OneGb),
        "ten_gb" => Ok(ServicePlan::TenGb),
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
            github_callback_url: Url::parse("https://example.test/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://example.test/api/auth/google/callback")
                .unwrap(),
            app_url: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            notary_directory: super::super::tests::directory_key(),
            publish: super::super::publish::PublishService::disabled_for_test(),
            admission: std::sync::Arc::new(AdmissionConfig::for_test()),
            billing: super::super::billing::BillingService::disabled_for_test(),
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn credit_kind_columns_have_no_rollback_default() {
        let state = test_state().await;
        let columns: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT table_name, column_default
             FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name IN ('notary_credit_grants', 'notary_credit_debits')
               AND column_name = 'credit_kind'
             ORDER BY table_name",
        )
        .fetch_all(&state.database)
        .await
        .unwrap();
        assert_eq!(
            columns,
            vec![
                ("notary_credit_debits".to_owned(), None),
                ("notary_credit_grants".to_owned(), None),
            ]
        );
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

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn credit_history_is_paginated_and_account_scoped() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        super::super::insert_test_github_user(&state.database, "history-1", 101, "history-one")
            .await;
        super::super::insert_test_github_user(&state.database, "history-2", 102, "history-two")
            .await;
        for (token, user_id) in [
            ("history-token-1", "history-1"),
            ("history-token-2", "history-2"),
        ] {
            sqlx::query(
                "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(sha256_hex(token.as_bytes()))
            .bind(user_id)
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
                credit_subject: "user:history-1",
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
    fn plans_have_distinct_limits_and_exact_product_entitlements() {
        let config = AdmissionConfig::for_test();
        assert!(config.public.max_attestable_http_bytes < config.free.max_attestable_http_bytes);
        assert_eq!(
            config.public.monthly_notarization_bytes,
            config.free.monthly_notarization_bytes
        );
        assert!(config.free.max_attestable_http_bytes < config.one_gb.max_attestable_http_bytes);
        assert!(config.free.capture_concurrency < config.one_gb.capture_concurrency);
        assert_eq!(
            plan_entitlements(&config, ServicePlan::Free),
            PlanEntitlements {
                monthly_capture_bytes: 50_000_000,
                monthly_notarization_bytes: 50_000_000,
                trace_storage_bytes: Some(1_000_000_000),
            }
        );
        assert_eq!(
            plan_entitlements(&config, ServicePlan::OneGb),
            PlanEntitlements {
                monthly_capture_bytes: 1_000_000_000,
                monthly_notarization_bytes: 1_000_000_000,
                trace_storage_bytes: Some(10_000_000_000),
            }
        );
        assert_eq!(
            plan_entitlements(&config, ServicePlan::TenGb),
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
        let redeem = |ticket: String, instance: &'static str| {
            redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.to_owned(),
                    mode: AdmissionMode::Capture,
                    directory_generation: state.notary_directory.generation,
                    contract: Some(AdmissionRedemptionContract::OneOperationV1),
                }),
            )
        };

        let Json(RedeemAdmissionResponse::Operation(admitted)) =
            redeem(first.ticket.clone(), "notary-one").await.unwrap()
        else {
            panic!("one-operation redemption returned a lease");
        };
        assert_eq!(admitted.record_digest, None);
        assert_eq!(admitted.authenticated_allowance_bytes, None);
        assert!(matches!(
            redeem(second.ticket, "notary-two").await.unwrap().0,
            RedeemAdmissionResponse::Operation(_)
        ));
        let replay = match redeem(first.ticket, "notary-three").await {
            Ok(_) => panic!("one-operation ticket replay was admitted"),
            Err(error) => error,
        };
        assert_eq!(replay.status, StatusCode::CONFLICT);

        let (leases, debits): (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM notary_admission_leases),
                 (SELECT COUNT(*) FROM notary_credit_debits)",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!((leases, debits), (0, 0));
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
            directory_generation: capture.directory_generation,
            contract: Some(AdmissionRedemptionContract::OneOperationV1),
        };
        let wrong_mode = match redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Json(request(
                capture.ticket.clone(),
                AdmissionMode::Finalize,
                "notary-wrong-mode".to_owned(),
            )),
        )
        .await
        {
            Ok(_) => panic!("wrong-mode ticket was admitted"),
            Err(error) => error,
        };
        assert_eq!(wrong_mode.status, StatusCode::CONFLICT);

        sqlx::query("UPDATE notary_admission_tickets SET expires_at = 1 WHERE token_hash = $1")
            .bind(sha256_hex(capture.ticket.as_bytes()))
            .execute(&state.database)
            .await
            .unwrap();
        let expired = match redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Json(request(
                capture.ticket,
                AdmissionMode::Capture,
                "notary-expired".to_owned(),
            )),
        )
        .await
        {
            Ok(_) => panic!("expired ticket was admitted"),
            Err(error) => error,
        };
        assert_eq!(expired.status, StatusCode::GONE);
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
                    contract: None,
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
                state.admission.public.monthly_notarization_bytes,
                state.admission.public.monthly_notarization_bytes,
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
            (first_lease.lease_id.clone(), "notary-ip-one"),
            (independent_lease.lease_id.clone(), "notary-ip-two"),
            (same_subject_lease.lease_id.clone(), "notary-ip-three"),
            (third_same_subject_lease.lease_id.clone(), "notary-ip-four"),
        ] {
            release_lease(
                State(state.clone()),
                service_headers(&state),
                Json(LeaseRequest {
                    lease_id,
                    notary_instance_id: instance.to_owned(),
                    outcome: None,
                    used_allowance_bytes: None,
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
                    contract: None,
                }),
            )
        };
        let lease = redeem(first.clone(), "notary-one")
            .await
            .expect("first instance admitted")
            .0;
        let expired_reservation = lease.authorized_allowance_bytes;
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
                outcome: None,
                used_allowance_bytes: None,
            }),
        )
        .await
        .expect("active lease renews")
        .0;
        assert!(renewed.lease_expires_at > unix_timestamp().unwrap());
        let recovered_lease_id = recovered.lease_id.clone();
        release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: recovered_lease_id.clone(),
                notary_instance_id: "notary-two".into(),
                outcome: Some(LeaseCompletionOutcome::Completed),
                used_allowance_bytes: Some(1_024),
            }),
        )
        .await
        .expect("active lease releases");
        release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: recovered_lease_id.clone(),
                notary_instance_id: "notary-two".into(),
                outcome: Some(LeaseCompletionOutcome::Completed),
                used_allowance_bytes: Some(1_024),
            }),
        )
        .await
        .expect("identical capture settlement is idempotent");
        let conflicting_settlement = release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: recovered_lease_id,
                notary_instance_id: "notary-two".into(),
                outcome: Some(LeaseCompletionOutcome::Completed),
                used_allowance_bytes: Some(2_048),
            }),
        )
        .await;
        assert!(matches!(
            conflicting_settlement,
            Err(ApiError {
                status: StatusCode::CONFLICT,
                ..
            })
        ));
        let capture_debits: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(allowance_bytes), 0)::BIGINT
                 FROM notary_credit_debits WHERE credit_kind = 'capture'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(capture_debits, (2, expired_reservation + 1_024));
        let notarization_debits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_credit_debits WHERE credit_kind = 'notarization'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(notarization_debits, 0);
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
                    contract: None,
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
                lease_id: global_lease.lease_id.clone(),
                notary_instance_id: "notary-global-one".into(),
                outcome: None,
                used_allowance_bytes: None,
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
                    contract: None,
                }),
            )
            .await
            .expect("finalization admitted")
            .0;
            release_lease(
                State(state.clone()),
                service_headers(&state),
                Json(LeaseRequest {
                    lease_id: lease.lease_id.clone(),
                    notary_instance_id: instance.into(),
                    outcome: None,
                    used_allowance_bytes: None,
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
                    contract: None,
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
                CreditKind::Notarization,
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
            (1, state.admission.public.monthly_notarization_bytes)
        );

        let mut transaction = state.database.begin().await.unwrap();
        ensure_monthly_grant(
            &mut transaction,
            subject,
            None,
            AccessPool::OneGb,
            &state.admission.one_gb,
            CreditKind::Notarization,
            august,
        )
        .await
        .unwrap();
        let upgraded: i64 = sqlx::query_scalar(
            "SELECT amount_bytes FROM notary_credit_grants
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
            AccessPool::Public,
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
            AccessPool::Public,
            &state.admission.public,
            CreditKind::Notarization,
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
                credit_subject: "user:grant-idempotency-test",
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
                credit_kind: CreditKind::Notarization,
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
                    credit_kind: CreditKind::Notarization,
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
            token_hash: "01".repeat(32),
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
        debit_credits(&mut transaction, &ticket, now).await.unwrap();
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
        assert_eq!(credits.notarization.total_remaining_bytes, 50);
        assert_eq!(credits.notarization.next_grant_expiration, None);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn concurrent_promotional_claims_create_one_server_authored_grant() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        super::super::insert_test_github_user(&state.database, "promo-user", 44, "promo").await;
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
            successful.0.credits.notarization.total_remaining_bytes,
            state.admission.free.monthly_notarization_bytes + PROMOTIONAL_OFFER_AMOUNT_BYTES
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
        assert_eq!(compatibility_columns, 0);
        let legacy_ledger: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('notary_finalization_credit_ledger')::TEXT")
                .fetch_one(&state.database)
                .await
                .unwrap();
        assert_eq!(legacy_ledger, None);

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

        sqlx::query(
            "INSERT INTO account_billing_profiles
                 (account_id, service_plan, billing_status, updated_at)
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
                service_plan: ServicePlan::OneGb,
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
        let paid_access_pool: String = sqlx::query_scalar(
            "SELECT access_pool FROM notary_admission_tickets WHERE token_hash = $1",
        )
        .bind(sha256_hex(paid_ticket.ticket.as_bytes()))
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(paid_access_pool, "one_gb");

        sqlx::query(
            "UPDATE account_billing_profiles
             SET service_plan = 'free', updated_at = $1 WHERE account_id = 'user-1'",
        )
        .bind(now + 1)
        .execute(&state.database)
        .await
        .unwrap();
        let stale_paid_ticket = redeem_admission(
            State(state.clone()),
            service_headers(&state),
            Json(RedeemAdmissionRequest {
                ticket: paid_ticket.ticket,
                notary_instance_id: "notary-stale-plan".to_owned(),
                mode: AdmissionMode::Capture,
                directory_generation: paid_ticket.directory_generation,
                contract: None,
            }),
        )
        .await
        .err()
        .expect("stale paid ticket should be rejected");
        assert_eq!(stale_paid_ticket.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(stale_paid_ticket.code, "billing_plan_changed");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn explicit_service_failures_restore_only_purchased_credit_allocations_once() {
        let state = test_state().await;
        super::super::insert_test_github_user(&state.database, "settlement-user", 2, "settlement")
            .await;
        let now = unix_timestamp().unwrap();
        let digest = "a".repeat(64);
        sqlx::query(
            "INSERT INTO notary_credit_grants
                 (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind,
                  source_reference, idempotency_key, created_at, available_at, display_label)
             VALUES ('purchased-grant', 'user:settlement-user', 'settlement-user', 'notarization', 1000,
                     'external_purchase', 'pi_test', 'purchase:pi_test', $1, $1, 'Purchased')",
        )
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_credit_debits
                 (id, credit_subject, account_id, credit_kind, record_digest, allowance_bytes, created_at)
             VALUES ('settlement-debit', 'user:settlement-user', 'settlement-user', 'notarization', $1, 1000, $2)",
        )
        .bind(&digest)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_credit_debit_allocations
                 (debit_id, grant_id, amount_bytes, allocation_order)
             VALUES ('settlement-debit', 'purchased-grant', 1000, 0)",
        )
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_admission_tickets
                  (token_hash, subject_id, credit_subject, access_pool, mode,
                  directory_generation, record_digest, requested_allowance_bytes,
                  max_attestable_http_bytes, max_frame_bytes,
                  max_private_chunk_bytes, max_private_chunk_commitments, issued_at,
                  expires_at, consumed_at, consumed_by_instance, lease_id, credit_debit_id,
                  credit_debit_refundable)
             VALUES ('settlement-ticket', 'settlement-user', 'user:settlement-user', 'one_gb',
                     'finalize', 1, $1, 1000, 1000, 2000, 1000, 1,
                     $2, $3, $2, 'notary-settlement', 'settlement-lease',
                     'settlement-debit', TRUE)",
        )
        .bind(&digest)
        .bind(now)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_admission_leases
                 (id, notary_instance_id, subject_id, credit_subject, access_pool, mode,
                  acquired_at, expires_at)
             VALUES ('settlement-lease', 'notary-settlement', 'settlement-user',
                     'user:settlement-user', 'one_gb', 'finalize', $1, $2)",
        )
        .bind(now)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();

        for _ in 0..2 {
            release_lease(
                State(state.clone()),
                service_headers(&state),
                Json(LeaseRequest {
                    lease_id: "settlement-lease".to_owned(),
                    notary_instance_id: "notary-settlement".to_owned(),
                    outcome: Some(LeaseCompletionOutcome::ServiceFailed),
                    used_allowance_bytes: None,
                }),
            )
            .await
            .unwrap();
        }
        let conflicting_outcome = release_lease(
            State(state.clone()),
            service_headers(&state),
            Json(LeaseRequest {
                lease_id: "settlement-lease".to_owned(),
                notary_instance_id: "notary-settlement".to_owned(),
                outcome: Some(LeaseCompletionOutcome::ClientFailed),
                used_allowance_bytes: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(conflicting_outcome.status, StatusCode::CONFLICT);
        let restored: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_grants
             WHERE credit_subject = 'user:settlement-user'
               AND source_kind = 'service_refund'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(restored, (1, 1000));
        let outcome: String = sqlx::query_scalar(
            "SELECT completion_outcome FROM notary_admission_leases
             WHERE id = 'settlement-lease'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(outcome, "service_failed");

        sqlx::query(
            "INSERT INTO notary_admission_tickets
                  (token_hash, subject_id, credit_subject, access_pool, mode,
                  directory_generation, record_digest, requested_allowance_bytes,
                  max_attestable_http_bytes, max_frame_bytes,
                  max_private_chunk_bytes, max_private_chunk_commitments, issued_at,
                  expires_at, consumed_at, consumed_by_instance, lease_id, credit_debit_id,
                  credit_debit_refundable)
             VALUES ('root-active-ticket', 'settlement-user', 'user:settlement-user', 'one_gb',
                     'finalize', 1, $1, 1000, 1000, 2000, 1000, 1,
                     $2, $3, $2, 'notary-root-retry', 'root-active-lease',
                     'settlement-debit', FALSE)",
        )
        .bind(&digest)
        .bind(now + 1)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_admission_leases
                 (id, notary_instance_id, subject_id, credit_subject, access_pool, mode,
                  acquired_at, expires_at)
             VALUES ('root-active-lease', 'notary-root-retry', 'settlement-user',
                     'user:settlement-user', 'one_gb', 'finalize', $1, $2)",
        )
        .bind(now + 1)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();
        let mut active_root_transaction = state.database.begin().await.unwrap();
        let active_root_retry = debit_credits(
            &mut active_root_transaction,
            &TicketRow {
                token_hash: "02".repeat(32),
                subject_id: Some("settlement-user".to_owned()),
                credit_subject: "user:settlement-user".to_owned(),
                access_pool: "one_gb".to_owned(),
                mode: "finalize".to_owned(),
                directory_generation: 1,
                record_digest: Some(digest.clone()),
                requested_allowance_bytes: 1000,
                max_attestable_http_bytes: 1000,
                max_frame_bytes: 2000,
                max_private_chunk_bytes: 1000,
                max_private_chunk_commitments: 1,
                expires_at: now + 60,
                consumed_at: None,
            },
            now + 2,
        )
        .await
        .err()
        .expect("an active root-debit attempt must serialize same-digest retries");
        assert_eq!(active_root_retry.status, StatusCode::CONFLICT);
        active_root_transaction.rollback().await.unwrap();
        sqlx::query(
            "UPDATE notary_admission_leases
             SET released_at = $1, terminal_state = 'released',
                 completion_outcome = 'completed'
             WHERE id = 'root-active-lease'",
        )
        .bind(now + 2)
        .execute(&state.database)
        .await
        .unwrap();

        let mut transaction = state.database.begin().await.unwrap();
        let retry_debit = debit_credits(
            &mut transaction,
            &TicketRow {
                token_hash: "03".repeat(32),
                subject_id: Some("settlement-user".to_owned()),
                credit_subject: "user:settlement-user".to_owned(),
                access_pool: "one_gb".to_owned(),
                mode: "finalize".to_owned(),
                directory_generation: 1,
                record_digest: Some(digest),
                requested_allowance_bytes: 1000,
                max_attestable_http_bytes: 1000,
                max_frame_bytes: 2000,
                max_private_chunk_bytes: 1000,
                max_private_chunk_commitments: 1,
                expires_at: now + 60,
                consumed_at: None,
            },
            now + 1,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        assert_ne!(retry_debit.id, "settlement-debit");
        assert!(retry_debit.restore_on_service_failure);
        let retry: (i64, String) = sqlx::query_as(
            "SELECT allowance_bytes, retry_of_debit_id
             FROM notary_credit_debits WHERE id = $1",
        )
        .bind(&retry_debit.id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(retry, (1000, "settlement-debit".to_owned()));
        let restored_remaining: i64 = sqlx::query_scalar(
            "SELECT grants.amount_bytes - COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT
             FROM notary_credit_grants AS grants
             LEFT JOIN notary_credit_debit_allocations AS allocations
               ON allocations.grant_id = grants.id
             WHERE grants.credit_subject = 'user:settlement-user'
               AND grants.source_kind = 'service_refund'
             GROUP BY grants.id",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(restored_remaining, 0);

        sqlx::query(
            "INSERT INTO notary_admission_tickets
                  (token_hash, subject_id, credit_subject, access_pool, mode,
                  directory_generation, record_digest, requested_allowance_bytes,
                  max_attestable_http_bytes, max_frame_bytes,
                  max_private_chunk_bytes, max_private_chunk_commitments, issued_at,
                  expires_at, consumed_at, consumed_by_instance, lease_id, credit_debit_id,
                  credit_debit_refundable)
             VALUES ('retry-active-ticket', 'settlement-user', 'user:settlement-user', 'one_gb',
                     'finalize', 1, $1, 1000, 1000, 2000, 1000, 1,
                     $2, $3, $2, 'notary-retry', 'retry-active-lease', $4, TRUE)",
        )
        .bind("a".repeat(64))
        .bind(now + 1)
        .bind(now + 60)
        .bind(&retry_debit.id)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_admission_leases
                 (id, notary_instance_id, subject_id, credit_subject, access_pool, mode,
                  acquired_at, expires_at)
             VALUES ('retry-active-lease', 'notary-retry', 'settlement-user',
                     'user:settlement-user', 'one_gb', 'finalize', $1, $2)",
        )
        .bind(now + 1)
        .bind(now + 60)
        .execute(&state.database)
        .await
        .unwrap();

        let mut duplicate_transaction = state.database.begin().await.unwrap();
        let duplicate_retry = debit_credits(
            &mut duplicate_transaction,
            &TicketRow {
                token_hash: "04".repeat(32),
                subject_id: Some("settlement-user".to_owned()),
                credit_subject: "user:settlement-user".to_owned(),
                access_pool: "one_gb".to_owned(),
                mode: "finalize".to_owned(),
                directory_generation: 1,
                record_digest: Some("a".repeat(64)),
                requested_allowance_bytes: 1000,
                max_attestable_http_bytes: 1000,
                max_frame_bytes: 2000,
                max_private_chunk_bytes: 1000,
                max_private_chunk_commitments: 1,
                expires_at: now + 60,
                consumed_at: None,
            },
            now + 2,
        )
        .await
        .err()
        .expect("a consumed service-failure retry must not be reused concurrently");
        assert_eq!(duplicate_retry.status, StatusCode::CONFLICT);
        duplicate_transaction.rollback().await.unwrap();

        sqlx::query(
            "UPDATE notary_admission_leases
             SET released_at = $1, terminal_state = 'released',
                 completion_outcome = 'client_failed'
             WHERE id = 'retry-active-lease'",
        )
        .bind(now + 2)
        .execute(&state.database)
        .await
        .unwrap();
        let mut terminal_transaction = state.database.begin().await.unwrap();
        let terminal_retry = debit_credits(
            &mut terminal_transaction,
            &TicketRow {
                token_hash: "05".repeat(32),
                subject_id: Some("settlement-user".to_owned()),
                credit_subject: "user:settlement-user".to_owned(),
                access_pool: "one_gb".to_owned(),
                mode: "finalize".to_owned(),
                directory_generation: 1,
                record_digest: Some("a".repeat(64)),
                requested_allowance_bytes: 1000,
                max_attestable_http_bytes: 1000,
                max_frame_bytes: 2000,
                max_private_chunk_bytes: 1000,
                max_private_chunk_commitments: 1,
                expires_at: now + 60,
                consumed_at: None,
            },
            now + 3,
        )
        .await
        .unwrap();
        assert_eq!(terminal_retry.id, retry_debit.id);
        assert!(!terminal_retry.restore_on_service_failure);
        terminal_transaction.rollback().await.unwrap();
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
            "INSERT INTO notary_credit_adjustments
                 (id, credit_subject, account_id, purchase_id, amount_bytes, source_kind,
                  source_reference, idempotency_key, display_label, created_at)
             VALUES ('adjustment-sign', 'user:buyer', 'buyer', 'purchase-1', 1,
                     'purchase_refund', 'refund-sign', 'refund-sign', 'Refund', $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await;
        assert!(wrong_sign.is_err());

        let wrong_owner = sqlx::query(
            "INSERT INTO notary_credit_adjustments
                 (id, credit_subject, account_id, purchase_id, amount_bytes, source_kind,
                  source_reference, idempotency_key, display_label, created_at)
             VALUES ('adjustment-owner', 'user:other', 'other', 'purchase-1', -1,
                     'purchase_refund', 'refund-owner', 'refund-owner', 'Refund', $1)",
        )
        .bind(now)
        .execute(&state.database)
        .await;
        assert!(wrong_owner.is_err());
    }
}
