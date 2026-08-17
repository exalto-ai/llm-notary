use axum::{
    Json,
    extract::{ConnectInfo, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::subtle::ConstantTimeEq as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::sync::watch;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::{
    ApiError, ApiResult, ErrorResponse, NotaryApiState,
    auth::{ApiScope, optional_authenticated_principal},
    config::{AdmissionTierLimits, NotaryAdmissionConfig},
    database_error, random_secret, typed_id, unix_timestamp,
};
use crate::credits::{self, BillingStatus, CreditKind, Plan};
use notary_core::sha256_hex;

const MAX_TICKET_BYTES: usize = 512;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const CLIENT_IP_HEADER: &str = "x-notary-client-ip";
const PUBLIC_SUBJECT_PURPOSE: &str = "hosted-notarization-public-subject";
const ACTIVATION_RECOVERY_INTERVAL_SECS: u64 = 15;
const ACTIVATION_WINDOW_SECS: i64 = 60;

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
    OneOperationV2,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemedOperationResponse {
    pub operation_id: String,
    pub activation_deadline: i64,
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub record_digest: Option<String>,
    pub notarization_allowance_bytes: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct ActivateOperationRequest {
    pub operation_id: String,
    pub notary_instance_id: String,
    pub mode: AdmissionMode,
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
    activated_at: Option<i64>,
    terminal_outcome: Option<String>,
    settled_authenticated_bytes: Option<i64>,
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(issue_admission))
        .routes(routes!(redeem_admission))
        .routes(routes!(activate_operation))
        .routes(routes!(settle_usage))
}

/// Settles operations that were redeemed but never activated by a notary-server.
///
/// A short activation lease is distinct from the much longer session lifetime:
/// no protocol session may begin until the adapter has durably staged settlement
/// state and activated the operation.
pub(crate) async fn run_recovery_worker(
    state: NotaryApiState,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(ACTIVATION_RECOVERY_INTERVAL_SECS));
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {}
        }
        if let Err(error) = recover_expired_activations(&state).await {
            tracing::error!(?error, "recovering unactivated admitted operations failed");
        }
    }
}

async fn recover_expired_activations(state: &NotaryApiState) -> ApiResult<u64> {
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    credits::lock_ledger(&mut transaction).await?;
    let recovered = sqlx::query_scalar::<_, String>(
        "UPDATE admitted_operations
         SET terminal_outcome = 'service_failed', settled_authenticated_bytes = 0,
             settled_at = $1
         WHERE activated_at IS NULL AND terminal_outcome IS NULL
           AND activation_deadline <= $1
         RETURNING mode",
    )
    .bind(now)
    .fetch_all(&mut *transaction)
    .await
    .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;
    for mode in &recovered {
        metrics::counter!(
            "notary_api_usage_settlements_total",
            "mode" => mode.clone(),
            "outcome" => "service_failed"
        )
        .increment(1);
    }
    Ok(recovered.len() as u64)
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
    let period = credits::monthly_credit_period(&state.database, now).await?;
    let (account_id, credit_subject, pool, billing_status) = match identity {
        Some(principal) => {
            let billing =
                credits::account_billing_state(&state.database, &principal.account_id).await?;
            let credit_subject = credits::account_credit_subject(&principal.account_id);
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
    credits::lock_ledger(&mut transaction).await?;
    credits::ensure_monthly_grant(
        &mut transaction,
        &credit_subject,
        account_id.as_deref(),
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    let allowance = if request.mode == AdmissionMode::Capture {
        credits::bounded_capture_allowance(
            requested_allowance,
            credits::available_credit_bytes(
                &mut transaction,
                &credit_subject,
                CreditKind::Capture,
                now,
            )
            .await?,
        )?
    } else {
        requested_allowance
    };
    credits::preflight(
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
    credits::lock_ledger(&mut transaction).await?;
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
        let billing = credits::locked_account_billing_state(&mut transaction, account_id).await?;
        if billing.billing_status == BillingStatus::Review {
            return Err(ApiError::coded(
                StatusCode::PAYMENT_REQUIRED,
                "billing_review",
                "Hosted capture and notarization are unavailable while billing is under review",
            ));
        }
        if (pool == AdmissionTier::OneGb && billing.plan != Plan::OneGb)
            || (pool == AdmissionTier::TenGb && billing.plan != Plan::TenGb)
        {
            return Err(ApiError::coded(
                StatusCode::PAYMENT_REQUIRED,
                "billing_plan_changed",
                "The account plan changed after this admission ticket was issued",
            ));
        }
    }
    credits::ensure_monthly_grant(
        &mut transaction,
        &ticket.credit_subject,
        ticket.account_id.as_deref(),
        policy,
        CreditKind::for_mode(request.mode),
        now,
    )
    .await?;
    let required_allowance = ticket.notarization_allowance_bytes.unwrap_or(1);
    credits::preflight(
        &mut transaction,
        &ticket.credit_subject,
        CreditKind::for_mode(request.mode),
        required_allowance,
        now,
    )
    .await?;
    let ticket_token_hash = sha256_hex(request.ticket.as_bytes());
    let operation_id = typed_id("op-");
    let (activation_deadline, activated_at) = match request.contract {
        AdmissionRedemptionContract::OneOperationV1 => (now, Some(now)),
        AdmissionRedemptionContract::OneOperationV2 => (
            now.checked_add(ACTIVATION_WINDOW_SECS).ok_or_else(|| {
                ApiError::internal(anyhow::anyhow!("activation deadline overflow"))
            })?,
            None,
        ),
    };
    sqlx::query(
        "INSERT INTO admitted_operations
             (operation_id, ticket_token_hash, notary_instance_id, account_id, credit_subject,
              admission_tier, mode, record_digest, notarization_allowance_bytes,
              max_attestable_http_bytes, admitted_at, activation_deadline, activated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
    .bind(activation_deadline)
    .bind(activated_at)
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
        activation_deadline,
        max_attestable_http_bytes: ticket.max_attestable_http_bytes,
        max_frame_bytes: ticket.max_frame_bytes,
        max_private_chunk_bytes: ticket.max_private_chunk_bytes,
        max_private_chunk_commitments: ticket.max_private_chunk_commitments,
        record_digest: ticket.record_digest,
        notarization_allowance_bytes: ticket.notarization_allowance_bytes,
    })
}

#[derive(FromRow)]
struct ActivationRow {
    notary_instance_id: String,
    mode: String,
    activation_deadline: i64,
    activated_at: Option<i64>,
    terminal_outcome: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/internal/notary/operations/activate",
    summary = "Activate an admitted operation after settlement state is durable",
    request_body = ActivateOperationRequest,
    responses(
        (status = 204, description = "Operation activated or identical activation already applied"),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("serviceBearer" = [])),
    tag = "notary-admission"
)]
async fn activate_operation(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    request: Result<Json<ActivateOperationRequest>, JsonRejection>,
) -> ApiResult<StatusCode> {
    authenticate_service(&state, &headers)?;
    let Json(request) =
        request.map_err(|_| ApiError::bad_request("invalid operation activation request"))?;
    validate_opaque(&request.operation_id, 128, "invalid operation identifier")?;
    validate_opaque(
        &request.notary_instance_id,
        MAX_INSTANCE_ID_BYTES,
        "invalid notary instance identifier",
    )?;
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    credits::lock_ledger(&mut transaction).await?;
    let operation = sqlx::query_as::<_, ActivationRow>(
        "SELECT notary_instance_id, mode, activation_deadline, activated_at, terminal_outcome
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
            "activation does not match the admitted operation",
        ));
    }
    if operation.activated_at.is_some() {
        transaction.commit().await.map_err(database_error)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    if operation.terminal_outcome.is_some() || operation.activation_deadline <= now {
        return Err(ApiError::gone("operation activation window expired"));
    }
    let updated = sqlx::query(
        "UPDATE admitted_operations SET activated_at = $1
         WHERE operation_id = $2 AND activated_at IS NULL AND terminal_outcome IS NULL",
    )
    .bind(now)
    .bind(&request.operation_id)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::gone("operation activation window expired"));
    }
    transaction.commit().await.map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
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
    credits::lock_ledger(&mut transaction).await?;
    let operation = sqlx::query_as::<_, OperationRow>(
        "SELECT operation_id, notary_instance_id, account_id, credit_subject, mode,
                notarization_allowance_bytes, max_attestable_http_bytes, admitted_at,
                activated_at, terminal_outcome, settled_authenticated_bytes
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
    if operation.activated_at.is_none()
        && (request.outcome != UsageSettlementOutcome::ServiceFailed
            || request.authenticated_bytes != 0)
    {
        return Err(ApiError::conflict("admitted operation is not activated"));
    }
    if request.authenticated_bytes > 0 {
        credits::record_operation_debit(
            &mut transaction,
            &operation.operation_id,
            &operation.credit_subject,
            operation.account_id.as_deref(),
            request.mode,
            request.authenticated_bytes,
            operation.admitted_at,
        )
        .await?;
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

fn policy_for_pool(config: &NotaryAdmissionConfig, pool: AdmissionTier) -> &AdmissionTierLimits {
    match pool {
        AdmissionTier::Public => &config.public,
        AdmissionTier::Free => &config.free,
        AdmissionTier::OneGb => &config.one_gb,
        AdmissionTier::TenGb => &config.ten_gb,
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

        let (debits, operations, activated): (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM credit_debits),
                 (SELECT COUNT(*) FROM admitted_operations),
                 (SELECT COUNT(*) FROM admitted_operations
                  WHERE activated_at IS NOT NULL AND activation_deadline = admitted_at)",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!((debits, operations, activated), (0, 3, 3));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn v2_operations_require_bound_activation_before_billable_settlement() {
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
        let redeem = |ticket: String, instance: &'static str| {
            redeem_admission(
                State(state.clone()),
                service_headers(&state),
                Ok(Json(RedeemAdmissionRequest {
                    ticket,
                    notary_instance_id: instance.to_owned(),
                    mode: AdmissionMode::Capture,
                    registry_generation: state.registry.generation,
                    contract: AdmissionRedemptionContract::OneOperationV2,
                    usage_settlement: true,
                })),
            )
        };

        let ticket = issue_capture().await.unwrap().0;
        let operation = redeem(ticket.ticket, "notary-v2").await.unwrap().0;
        assert!(operation.activation_deadline > unix_timestamp().unwrap());
        let activated_at: Option<i64> = sqlx::query_scalar(
            "SELECT activated_at FROM admitted_operations WHERE operation_id = $1",
        )
        .bind(&operation.operation_id)
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(activated_at, None);

        let pending_settlement = settle_usage(
            State(state.clone()),
            service_headers(&state),
            Json(UsageSettlementRequest {
                operation_id: operation.operation_id.clone(),
                notary_instance_id: "notary-v2".to_owned(),
                mode: AdmissionMode::Capture,
                authenticated_bytes: 1,
                outcome: UsageSettlementOutcome::Completed,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(pending_settlement.status, StatusCode::CONFLICT);

        let wrong_binding = activate_operation(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(ActivateOperationRequest {
                operation_id: operation.operation_id.clone(),
                notary_instance_id: "notary-other".to_owned(),
                mode: AdmissionMode::Capture,
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_binding.status, StatusCode::CONFLICT);

        let activation = ActivateOperationRequest {
            operation_id: operation.operation_id.clone(),
            notary_instance_id: "notary-v2".to_owned(),
            mode: AdmissionMode::Capture,
        };
        assert_eq!(
            activate_operation(
                State(state.clone()),
                service_headers(&state),
                Ok(Json(activation)),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            activate_operation(
                State(state.clone()),
                service_headers(&state),
                Ok(Json(ActivateOperationRequest {
                    operation_id: operation.operation_id.clone(),
                    notary_instance_id: "notary-v2".to_owned(),
                    mode: AdmissionMode::Capture,
                })),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );

        let cleanup_ticket = issue_capture().await.unwrap().0;
        let cleanup = redeem(cleanup_ticket.ticket, "notary-cleanup")
            .await
            .unwrap()
            .0;
        assert_eq!(
            settle_usage(
                State(state.clone()),
                service_headers(&state),
                Json(UsageSettlementRequest {
                    operation_id: cleanup.operation_id.clone(),
                    notary_instance_id: "notary-cleanup".to_owned(),
                    mode: AdmissionMode::Capture,
                    authenticated_bytes: 0,
                    outcome: UsageSettlementOutcome::ServiceFailed,
                }),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        let activation_after_cleanup = activate_operation(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(ActivateOperationRequest {
                operation_id: cleanup.operation_id,
                notary_instance_id: "notary-cleanup".to_owned(),
                mode: AdmissionMode::Capture,
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(activation_after_cleanup.status, StatusCode::GONE);

        let expiring_ticket = issue_capture().await.unwrap().0;
        let expiring = redeem(expiring_ticket.ticket, "notary-expired")
            .await
            .unwrap()
            .0;
        let expired_at = unix_timestamp().unwrap();
        sqlx::query(
            "UPDATE admitted_operations
             SET admitted_at = $1, activation_deadline = $2
             WHERE operation_id = $3",
        )
        .bind(expired_at - 2)
        .bind(expired_at - 1)
        .bind(&expiring.operation_id)
        .execute(&state.database)
        .await
        .unwrap();
        let expired = activate_operation(
            State(state.clone()),
            service_headers(&state),
            Ok(Json(ActivateOperationRequest {
                operation_id: expiring.operation_id,
                notary_instance_id: "notary-expired".to_owned(),
                mode: AdmissionMode::Capture,
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(expired.status, StatusCode::GONE);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn expired_unactivated_operations_are_recovered_without_a_debit() {
        let state = test_state().await;
        let now = unix_timestamp().unwrap();
        sqlx::query(
            "INSERT INTO admitted_operations
                 (operation_id, ticket_token_hash, notary_instance_id, credit_subject,
                  admission_tier, mode, max_attestable_http_bytes, admitted_at,
                  activation_deadline)
             VALUES ('op-pending', 'pending-token-hash', 'notary-recovery', 'public:test',
                     'public', 'capture', 1024, $1, $2)",
        )
        .bind(now - 61)
        .bind(now - 1)
        .execute(&state.database)
        .await
        .unwrap();

        assert_eq!(recover_expired_activations(&state).await.unwrap(), 1);
        let recovered: (Option<String>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT terminal_outcome, settled_authenticated_bytes, activated_at
             FROM admitted_operations WHERE operation_id = 'op-pending'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(
            recovered,
            (Some("service_failed".to_owned()), Some(0), None)
        );
        let debits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_debits")
            .fetch_one(&state.database)
            .await
            .unwrap();
        assert_eq!(debits, 0);
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
        let credits =
            credits::credit_summary(&state.database, &credit_subject, unix_timestamp().unwrap())
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
    async fn signed_in_accounts_default_to_free_and_subscriptions_select_paid_access() {
        let state = test_state().await;
        super::super::insert_test_github_user(&state.database, "user-1", 1, "octo").await;
        let free_credits = credits::account_access(&state, "user-1").await.unwrap();
        assert_eq!(free_credits.notarization.total_remaining_bytes, 50_000_000);
        assert_eq!(
            free_credits.notarization.included_monthly_remaining_bytes,
            50_000_000
        );
        assert_eq!(free_credits.notarization.supplemental_remaining_bytes, 0);
        let repeated_access = credits::account_access(&state, "user-1").await.unwrap();
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
            credits::account_billing_state(&state.database, "user-1")
                .await
                .unwrap(),
            credits::AccountBillingState {
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
}
