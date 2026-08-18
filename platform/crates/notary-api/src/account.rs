//! Account profile, usage summary, and durable deletion behavior.

use super::*;
use crate::auth::authenticated_web_user;
use crate::browser_auth::BrowserAuthProvider;
use serde::Deserialize;

#[derive(Serialize, ToSchema)]
pub(super) struct PublicUser {
    pub(super) id: String,
    pub(super) provider_display_name: String,
    pub(super) avatar_url: Option<String>,
    pub(super) auth_provider: BrowserAuthProvider,
    pub(super) display_name: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct AccountResponse {
    pub(super) account: PublicUser,
    billing: AccountBillingResponse,
    links: AccountLinks,
}

#[derive(Serialize, ToSchema)]
struct AccountLinks {
    usage: &'static str,
    billing: &'static str,
    devices: &'static str,
    api_keys: &'static str,
}

#[derive(Serialize, ToSchema)]
struct UsageResponse {
    credits: credits::CreditSummary,
    operations: NotaryStats,
    hosted_traces: HostedTraceUsage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub(super) struct AccountBillingResponse {
    pub(super) plan: credits::Plan,
    pub(super) billing_status: credits::BillingStatus,
    pub(super) purchase_mode: billing::BillingPurchaseMode,
    pub(super) subscriptions_configured: bool,
    pub(super) entitlements: credits::PlanEntitlements,
}

impl AccountBillingResponse {
    pub(super) fn new(
        state: credits::AccountBillingState,
        purchase_mode: billing::BillingPurchaseMode,
        subscriptions_configured: bool,
        admission: &NotaryAdmissionConfig,
    ) -> Self {
        Self {
            plan: state.plan,
            billing_status: state.billing_status,
            purchase_mode,
            subscriptions_configured,
            entitlements: credits::plan_entitlements(admission, state.plan),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct HostedTraceUsage {
    total: i64,
    shared: i64,
    verifying: i64,
    needs_attention: i64,
    stored_bytes: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteAccountRequest {
    /// Must be exactly `DELETE` after the user confirms local traces remain local.
    pub(super) confirmation: String,
}

#[derive(Debug, Eq, PartialEq, Serialize, ToSchema)]
pub(super) struct NotaryStats {
    /// Successfully completed capture operations.
    pub(super) captures: i64,
    /// Successfully completed notarization operations.
    pub(super) notarizations: i64,
}

pub(super) async fn account_notary_stats(
    database: &DatabasePool,
    account_id: &str,
) -> ApiResult<NotaryStats> {
    let (captures, notarizations) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT
             COUNT(*) FILTER (WHERE operations.mode = 'capture')::BIGINT,
             COUNT(*) FILTER (WHERE operations.mode = 'notarization')::BIGINT
         FROM admitted_operations AS operations
         WHERE operations.account_id = $1
           AND operations.terminal_outcome = 'completed'",
    )
    .bind(account_id)
    .fetch_one(database)
    .await
    .map_err(database_error)?;
    Ok(NotaryStats {
        captures,
        notarizations,
    })
}

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(account, delete_account))
        .routes(routes!(usage))
}

#[utoipa::path(
    get,
    path = "/api/account",
    summary = "Get the current Notary account",
    responses(
        (status = 200, body = AccountResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "account"
)]
pub(super) async fn account(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
) -> ApiResult<Json<AccountResponse>> {
    let session_token = session_token(&jar)?;
    let now = unix_timestamp()?;
    let user = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        "SELECT accounts.account_id, accounts.display_name, identity.provider_display_name,
                identity.provider_avatar_url, identity.provider
         FROM browser_sessions
         JOIN accounts ON accounts.account_id = browser_sessions.account_id
         JOIN LATERAL (
             SELECT provider, provider_display_name, provider_avatar_url
             FROM account_identities
             WHERE account_id = accounts.account_id
             ORDER BY last_used_at DESC, identity_id
             LIMIT 1
         ) AS identity ON TRUE
         WHERE browser_sessions.token_hash = $1 AND browser_sessions.expires_at > $2",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    let billing = credits::account_billing_state(&state.database, &user.0).await?;
    Ok(Json(AccountResponse {
        account: PublicUser {
            id: user.0,
            provider_display_name: user.2,
            avatar_url: user.3,
            auth_provider: BrowserAuthProvider::from_database(&user.4)?,
            display_name: user.1,
        },
        billing: AccountBillingResponse::new(
            billing,
            state.billing.purchase_mode(),
            state.billing.subscriptions_configured(),
            &state.admission,
        ),
        links: AccountLinks {
            usage: "/api/usage",
            billing: "/api/billing/purchases",
            devices: "/api/devices",
            api_keys: "/api/api-keys",
        },
    }))
}

#[utoipa::path(
    get,
    path = "/api/usage",
    summary = "Get capture, notarization, and hosted Trace usage",
    responses(
        (status = 200, body = UsageResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = []), ("bearerAuth" = ["account:read"])),
    tag = "account"
)]
async fn usage(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> ApiResult<Json<UsageResponse>> {
    let account_id = if headers.contains_key(header::AUTHORIZATION) {
        auth::authenticated_principal(&state, &headers, auth::ApiScope::AccountRead)
            .await?
            .account_id
    } else {
        authenticated_web_user(&state, &jar).await?.0
    };
    let credits = credits::account_access(&state, &account_id).await?;
    let operations = account_notary_stats(&state.database, &account_id).await?;
    let (total, shared, in_progress, needs_attention, stored_bytes) =
        sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            "SELECT COUNT(*)::BIGINT,
                COUNT(*) FILTER (WHERE status = 'shared')::BIGINT,
                COUNT(*) FILTER (
                    WHERE status IN ('uploading', 'queued', 'verifying')
                )::BIGINT,
                COUNT(*) FILTER (WHERE status IN ('rejected', 'failed'))::BIGINT,
                COALESCE(SUM(
                    COALESCE(admitted_package_size_bytes, declared_package_size_bytes)
                ) FILTER (
                    WHERE status IN (
                        'uploading', 'queued', 'verifying', 'shared', 'stopped'
                    )
                ), 0)::BIGINT
         FROM traces WHERE account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&state.database)
        .await
        .map_err(database_error)?;
    Ok(Json(UsageResponse {
        credits,
        operations,
        hosted_traces: HostedTraceUsage {
            total,
            shared,
            verifying: in_progress,
            needs_attention,
            stored_bytes,
        },
    }))
}

#[utoipa::path(
    delete,
    path = "/api/account",
    summary = "Delete the current Notary account and hosted data",
    request_body = DeleteAccountRequest,
    responses(
        (status = 204, description = "Account deleted", headers(("Set-Cookie" = String))),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "account"
)]
pub(super) async fn delete_account(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Json(request): Json<DeleteAccountRequest>,
) -> ApiResult<(CookieJar, StatusCode)> {
    if request.confirmation != "DELETE" {
        return Err(ApiError::bad_request(
            "confirmation must be DELETE; local traces on disconnected devices are unaffected",
        ));
    }
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    sqlx::query(
        "INSERT INTO storage_cleanup_queue
             (object_key, trace_id, artifact_kind, created_at)
         SELECT artifact.object_key, jobs.trace_id, artifact.artifact_kind, $2
         FROM traces AS jobs
         CROSS JOIN LATERAL (
             VALUES
                 (jobs.staging_object_key, 'staging'),
                 (jobs.committed_staging_object_key, 'staging'),
                 (jobs.content_object_key, 'content'),
                 (jobs.package_object_key, 'package')
         ) AS artifact(object_key, artifact_kind)
         WHERE jobs.account_id = $1 AND artifact.object_key IS NOT NULL
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(&user.0)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    sqlx::query("DELETE FROM accounts WHERE account_id = $1")
        .bind(&user.0)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;

    Ok((
        jar.remove(state.expired_cookie(SESSION_COOKIE)),
        StatusCode::NO_CONTENT,
    ))
}
