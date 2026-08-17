//! Credit plans, balances, history, offers, and entitlement policy.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    ApiError, ApiResult, ErrorResponse, NotaryApiState,
    admissions::AdmissionMode,
    auth::authenticated_web_user,
    config::{AdmissionTierLimits, NotaryAdmissionConfig},
    database_error, unix_timestamp,
};
use notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};

const SECS_PER_DAY: i64 = 24 * 60 * 60;
const LEDGER_LOCK_NAMESPACE: i32 = 151;
const LEDGER_LOCK_KEY: i32 = 1;
const PROMOTIONAL_OFFER_ID: &str = "hosted-notarization-bonus-v1";
const PROMOTIONAL_OFFER_AMOUNT_BYTES: i64 = 128 << 20;
const PROMOTIONAL_OFFER_CLAIM_DEADLINE: i64 = 1_893_456_000; // 2030-01-01T00:00:00Z
const PROMOTIONAL_GRANT_TTL_SECS: i64 = 90 * SECS_PER_DAY;

#[derive(Deserialize, Serialize)]
struct CreditHistoryPagePosition {
    created_at: i64,
    id: String,
    kind: String,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    OneGb,
    TenGb,
}

impl Plan {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::OneGb => "one_gb",
            Self::TenGb => "ten_gb",
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditKind {
    Capture,
    Notarization,
}

impl CreditKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Notarization => "notarization",
        }
    }

    pub(crate) fn for_mode(mode: AdmissionMode) -> Self {
        match mode {
            AdmissionMode::Capture => Self::Capture,
            AdmissionMode::Notarization => Self::Notarization,
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
    pub plan: Plan,
    pub billing_status: BillingStatus,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct PlanEntitlements {
    pub monthly_notarization_bytes: i64,
    pub monthly_capture_bytes: i64,
    /// `None` means there is no fixed plan ceiling; abuse controls still apply.
    pub trace_storage_bytes: Option<i64>,
}

pub(crate) fn plan_entitlements(config: &NotaryAdmissionConfig, plan: Plan) -> PlanEntitlements {
    let policy = match plan {
        Plan::Free => &config.free,
        Plan::OneGb => &config.one_gb,
        Plan::TenGb => &config.ten_gb,
    };
    PlanEntitlements {
        monthly_notarization_bytes: policy.monthly_notarization_bytes,
        monthly_capture_bytes: policy.monthly_capture_bytes,
        trace_storage_bytes: match plan {
            Plan::Free => Some(1_000_000_000),
            Plan::OneGb => Some(10_000_000_000),
            Plan::TenGb => None,
        },
    }
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

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(eligible_credit_offers))
        .routes(routes!(credit_history))
        .routes(routes!(claim_credit_offer))
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
    let Query(query) = query.map_err(crate::pagination::query_error)?;
    let user = authenticated_web_user(&state, &jar).await?;
    ensure_account_monthly_grant(&state, &user.0).await?;
    let limit = query
        .limit(
            crate::pagination::DEFAULT_PAGE_LIMIT,
            crate::pagination::MAX_PAGE_LIMIT,
        )
        .map_err(crate::pagination::api_error)?;
    let scope = CursorScope::new(
        "/api/me/credits/history",
        &user.0,
        "created_at desc, id desc, kind desc",
    )
    .map_err(crate::pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<CreditHistoryPagePosition>(&scope, cursor))
        .transpose()
        .map_err(crate::pagination::api_error)?;
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
    .map_err(crate::pagination::api_error)?;
    Ok(Json(page))
}

pub async fn account_access(state: &NotaryApiState, account_id: &str) -> ApiResult<CreditSummary> {
    ensure_account_monthly_grant(state, account_id).await?;
    let now = unix_timestamp()?;
    credit_summary(&state.database, &account_credit_subject(account_id), now).await
}

pub async fn account_billing_state(
    database: &crate::DatabasePool,
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
    parse_account_billing_state(row)
}

pub(crate) async fn locked_account_billing_state(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: &str,
) -> ApiResult<AccountBillingState> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT plan, billing_status
         FROM account_billing_profiles WHERE account_id = $1
         FOR SHARE",
    )
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    parse_account_billing_state(row)
}

fn parse_account_billing_state(row: Option<(String, String)>) -> ApiResult<AccountBillingState> {
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

async fn ensure_account_monthly_grant(state: &NotaryApiState, account_id: &str) -> ApiResult<()> {
    let now = unix_timestamp()?;
    let billing = account_billing_state(&state.database, account_id).await?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    lock_ledger(&mut transaction).await?;
    let policy = policy_for_plan(&state.admission, billing.plan);
    let credit_subject = account_credit_subject(account_id);
    for credit_kind in [CreditKind::Capture, CreditKind::Notarization] {
        ensure_monthly_grant(
            &mut transaction,
            &credit_subject,
            Some(account_id),
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
    let billing = account_billing_state(&state.database, &user.0).await?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    lock_ledger(&mut transaction).await?;
    let credit_subject = account_credit_subject(&user.0);
    ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        Some(&user.0),
        policy_for_plan(&state.admission, billing.plan),
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

#[derive(Clone, Copy)]
pub(crate) struct CreditPeriod {
    pub start: i64,
    pub end: i64,
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

pub(crate) async fn lock_ledger(transaction: &mut Transaction<'_, Postgres>) -> ApiResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(LEDGER_LOCK_NAMESPACE)
        .bind(LEDGER_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(database_error)?;
    Ok(())
}

pub(crate) async fn record_operation_debit(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    credit_subject: &str,
    account_id: Option<&str>,
    mode: AdmissionMode,
    authenticated_bytes: i64,
    admitted_at: i64,
) -> ApiResult<()> {
    let credit_kind = CreditKind::for_mode(mode);
    let grants = settlement_grants(transaction, credit_subject, credit_kind, admitted_at).await?;
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
    .bind(credit_subject)
    .bind(account_id)
    .bind(credit_kind.as_str())
    .bind(authenticated_bytes)
    .bind(admitted_at)
    .bind(operation_id)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    allocate_settled_usage(
        transaction,
        &debit_id,
        authenticated_bytes,
        &grants,
        operation_id,
        credit_subject,
        account_id,
        credit_kind,
        admitted_at,
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

#[allow(clippy::too_many_arguments)]
async fn allocate_settled_usage(
    transaction: &mut Transaction<'_, Postgres>,
    debit_id: &str,
    authenticated_bytes: i64,
    grants: &[(String, i64, Option<i64>)],
    operation_id: &str,
    credit_subject: &str,
    account_id: Option<&str>,
    credit_kind: CreditKind,
    admitted_at: i64,
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
    let overage_reference = format!("operation-overage:{operation_id}");
    sqlx::query(
        "INSERT INTO credit_grants
             (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind,
              source_reference, idempotency_key, created_at, available_at, expires_at,
              display_label)
         VALUES ($1, $2, $3, $4, 0, 'operation_overage', $5, $5, $6, $6, $7,
                 'Hosted usage overage')",
    )
    .bind(&overage_grant_id)
    .bind(credit_subject)
    .bind(account_id)
    .bind(credit_kind.as_str())
    .bind(&overage_reference)
    .bind(admitted_at)
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

pub(crate) async fn ensure_monthly_grant(
    transaction: &mut Transaction<'_, Postgres>,
    credit_subject: &str,
    account_id: Option<&str>,
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

pub(crate) async fn preflight(
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

pub(crate) async fn available_credit_bytes(
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

pub(crate) fn bounded_capture_allowance(session_max: i64, available: i64) -> ApiResult<i64> {
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

pub(crate) async fn credit_summary(
    database: &crate::DatabasePool,
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
    database: &crate::DatabasePool,
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

pub(crate) async fn monthly_credit_period<'e, E>(executor: E, now: i64) -> ApiResult<CreditPeriod>
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

fn policy_for_plan(config: &NotaryAdmissionConfig, plan: Plan) -> &AdmissionTierLimits {
    match plan {
        Plan::Free => &config.free,
        Plan::OneGb => &config.one_gb,
        Plan::TenGb => &config.ten_gb,
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

pub(crate) fn account_credit_subject(account_id: &str) -> String {
    format!("account:{account_id}")
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

#[cfg(test)]
mod tests {
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use notary_core::sha256_hex;
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
            registry: super::super::tests::test_registry(),
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
