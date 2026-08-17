//! Account profile, usage summary, and durable deletion behavior.

use super::*;
use crate::auth::authenticated_web_user;

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new().routes(routes!(me, delete_account))
}

#[utoipa::path(
    get,
    path = "/api/me",
    summary = "Get the signed-in browser user",
    responses(
        (status = 200, body = MeResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
pub(super) async fn me(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
) -> ApiResult<Json<MeResponse>> {
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
    let credits = admissions::account_access(&state, &user.0).await?;
    let billing = admissions::account_billing_state(&state.database, &user.0).await?;
    let notary_stats = account_notary_stats(&state.database, &user.0).await?;
    let (total, admitted, in_progress, stored_bytes) = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT COUNT(*)::BIGINT,
                COUNT(*) FILTER (WHERE status IN ('shared', 'stopped'))::BIGINT,
                COUNT(*) FILTER (
                    WHERE status IN ('uploading', 'queued', 'verifying')
                )::BIGINT,
                COALESCE(SUM(
                    COALESCE(admitted_package_size_bytes, declared_package_size_bytes)
                ) FILTER (
                    WHERE status IN (
                        'uploading', 'queued', 'verifying', 'shared', 'stopped'
                    )
                ), 0)::BIGINT
         FROM traces WHERE account_id = $1",
    )
    .bind(&user.0)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(MeResponse {
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
        credits,
        notary_stats,
        share_stats: ShareStats {
            total,
            admitted,
            in_progress,
            stored_bytes,
        },
    }))
}

#[utoipa::path(
    delete,
    path = "/api/me",
    summary = "Delete the current account and all associated hosted data",
    responses(
        (status = 204, description = "Account deleted", headers(("Set-Cookie" = String))),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "browser-auth"
)]
pub(super) async fn delete_account(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, StatusCode)> {
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
