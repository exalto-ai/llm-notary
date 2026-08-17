//! Device authorization, token rotation, replay detection, and revocation.

use super::*;
use crate::auth::authenticated_web_user;

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_devices))
        .routes(routes!(revoke_web_device_session))
        .routes(routes!(start_device_authorization))
        .routes(routes!(
            device_approval_details,
            approve_device_authorization
        ))
        .routes(routes!(complete_device_authorization))
        .routes(routes!(refresh_device_tokens))
        .routes(routes!(logout_device_session))
        .routes(routes!(device_me))
}

#[utoipa::path(
    get,
    path = "/api/cli/sessions",
    summary = "List the browser user's active Device sessions",
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<WebDeviceSession>),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
pub(super) async fn list_devices(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<WebDeviceSession>>> {
    let Query(query) = query.map_err(pagination::query_error)?;
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let limit = query
        .limit(pagination::DEFAULT_PAGE_LIMIT, pagination::MAX_PAGE_LIMIT)
        .map_err(pagination::api_error)?;
    let scope = CursorScope::new("/api/cli/sessions", &user.0, "created_at desc, id desc")
        .map_err(pagination::api_error)?;
    let position = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<DeviceSessionPagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let sessions = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT device_id, device_name, created_at, last_used_at, expires_at
         FROM devices
         WHERE account_id = $1 AND revoked_at IS NULL AND expires_at > $2
           AND ($3::TEXT IS NULL OR (created_at, device_id) < ($4, $3))
         ORDER BY created_at DESC, device_id DESC
         LIMIT $5",
    )
    .bind(&user.0)
    .bind(now)
    .bind(position.as_ref().map(|position| &position.id))
    .bind(position.as_ref().map(|position| position.created_at))
    .bind(i64::try_from(limit + 1).map_err(|error| ApiError::internal(anyhow!(error)))?)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(|session| WebDeviceSession {
        id: session.0,
        device_name: session.1,
        created_at: session.2,
        last_used_at: session.3,
        expires_at: session.4,
    })
    .collect();
    let page = Page::from_limit_plus_one(sessions, limit, &scope, |session| {
        DeviceSessionPagePosition {
            created_at: session.created_at,
            id: session.id.clone(),
        }
    })
    .map_err(pagination::api_error)?;
    Ok(Json(page))
}

#[utoipa::path(
    delete,
    path = "/api/cli/sessions/{session_id}",
    summary = "Revoke one of the browser user's Device sessions",
    params(("session_id" = String, Path)),
    responses(
        (status = 204, description = "Device session revoked"),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
pub(super) async fn revoke_web_device_session(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(session_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let revoked = sqlx::query(
        "UPDATE devices SET revoked_at = $1
         WHERE device_id = $2 AND account_id = $3 AND revoked_at IS NULL AND expires_at > $4",
    )
    .bind(now)
    .bind(session_id)
    .bind(user.0)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if revoked.rows_affected() != 1 {
        return Err(ApiError::not_found("Device session was not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/cli/authorizations",
    summary = "Start Device device authorization",
    request_body = CreateDeviceAuthorization,
    responses(
        (status = 200, body = DeviceAuthorizationStarted),
        (status = 400, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
pub(super) async fn start_device_authorization(
    State(state): State<NotaryApiState>,
    Json(request): Json<CreateDeviceAuthorization>,
) -> ApiResult<Json<DeviceAuthorizationStarted>> {
    let device_name = request.device_name.trim();
    if device_name.is_empty() || device_name.len() > 120 {
        return Err(ApiError::bad_request(
            "device_name must be between 1 and 120 characters",
        ));
    }
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM device_authorizations WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;

    // The displayed code is intentionally low-entropy. The browser approval
    // URL and the polling endpoint each also require an independent 256-bit
    // secret, so a guessed code cannot approve or consume an authorization.
    for _ in 0..10 {
        let request_id = typed_id("dva-");
        let user_code = user_code();
        let poll_secret = random_secret("notary_access_");
        let approval_secret = random_secret("notary_access_");
        let inserted = sqlx::query(
            "INSERT INTO device_authorizations
             (authorization_id, user_code, poll_secret_hash, approval_secret_hash, device_name, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT DO NOTHING",
        )
        .bind(&request_id)
        .bind(&user_code)
        .bind(sha256_hex(poll_secret.as_bytes()))
        .bind(sha256_hex(approval_secret.as_bytes()))
        .bind(device_name)
        .bind(now)
        .bind(now + DEVICE_AUTHORIZATION_TTL_SECS)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
        if inserted.rows_affected() == 1 {
            let verification_uri_complete = format!(
                "{}#/authorize?request_id={}&approval_secret={}",
                state.public_origin, request_id, approval_secret
            );
            return Ok(Json(DeviceAuthorizationStarted {
                request_id,
                user_code,
                verification_uri_complete,
                expires_in: DEVICE_AUTHORIZATION_TTL_SECS,
                interval: 3,
                poll_secret,
            }));
        }
    }
    Err(ApiError::internal(anyhow!(
        "could not allocate unique user code"
    )))
}

#[utoipa::path(
    get,
    path = "/api/cli/authorizations/{request_id}/approval",
    summary = "Get browser approval details",
    params(("request_id" = String, Path), ("approval_secret" = String, Query)),
    responses(
        (status = 200, body = ApprovalDetails),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
pub(super) async fn device_approval_details(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(request_id): Path<String>,
    Query(query): Query<ApprovalQuery>,
) -> ApiResult<Json<ApprovalDetails>> {
    authenticated_web_user(&state, &jar).await?;
    let request = approval_request(&state, &request_id, &query.approval_secret).await?;
    Ok(Json(ApprovalDetails {
        user_code: request.0,
        device_name: request.1,
        expires_at: request.2,
    }))
}

#[utoipa::path(
    post,
    path = "/api/cli/authorizations/{request_id}/approval",
    summary = "Approve a Device device authorization",
    params(("request_id" = String, Path), ("approval_secret" = String, Query)),
    responses(
        (status = 204, description = "Device device authorized"),
        (status = 401, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
pub(super) async fn approve_device_authorization(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(request_id): Path<String>,
    Query(query): Query<ApprovalQuery>,
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let approved = sqlx::query(
        "UPDATE device_authorizations
         SET approved_account_id = $1, approved_at = $2
         WHERE authorization_id = $3 AND approval_secret_hash = $4 AND expires_at > $5
           AND approved_account_id IS NULL AND completed_at IS NULL",
    )
    .bind(user.0)
    .bind(now)
    .bind(request_id)
    .bind(sha256_hex(query.approval_secret.as_bytes()))
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if approved.rows_affected() != 1 {
        return Err(ApiError::gone(
            "authorization is expired, already approved, or already used",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/cli/authorizations/{request_id}/token",
    summary = "Complete Device device authorization",
    params(("request_id" = String, Path)),
    responses(
        (status = 200, body = DeviceTokens),
        (status = 401, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 428, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("pollSecret" = [])),
    tag = "cli-auth"
)]
pub(super) async fn complete_device_authorization(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> ApiResult<Json<DeviceTokens>> {
    let poll_secret = headers
        .get("X-Notary-Poll-Secret")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let now = unix_timestamp()?;
    let request = sqlx::query_as::<_, (Option<String>, String, i64, Option<i64>)>(
        "SELECT approved_account_id, device_name, expires_at, completed_at
         FROM device_authorizations
         WHERE authorization_id = $1 AND poll_secret_hash = $2",
    )
    .bind(&request_id)
    .bind(sha256_hex(poll_secret.as_bytes()))
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    if request.2 <= now || request.3.is_some() {
        return Err(ApiError::gone("authorization expired or was already used"));
    }
    let account_id = request.0.ok_or_else(ApiError::pending)?;

    // Mark consumption first with a compare-and-set. This makes a second poll
    // fail even if it races the successful poll.
    let consumed = sqlx::query(
        "UPDATE device_authorizations SET completed_at = $1
         WHERE authorization_id = $2 AND completed_at IS NULL AND expires_at > $3 AND approved_account_id IS NOT NULL",
    )
    .bind(now)
    .bind(&request_id)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::gone("authorization was already used"));
    }
    let tokens = issue_device_session(&state.database, &account_id, &request.1, now).await?;
    Ok(Json(tokens))
}

#[utoipa::path(
    post,
    path = "/api/cli/token",
    summary = "Rotate Device access and refresh tokens",
    request_body = RefreshRequest,
    responses(
        (status = 200, body = DeviceTokens),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
pub(super) async fn refresh_device_tokens(
    State(state): State<NotaryApiState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<Json<DeviceTokens>> {
    let now = unix_timestamp()?;
    let old_hash = sha256_hex(request.refresh_token.as_bytes());
    let device = sqlx::query_as::<_, (String, String)>(
        "SELECT device_id, account_id FROM devices
         WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(&old_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    let Some((device_id, account_id)) = device else {
        // Reusing a rotated token is a credential-theft signal: revoke the
        // Device that originally held it before rejecting the request.
        if let Some(device_id) = sqlx::query_scalar::<_, String>(
            "SELECT device_id FROM device_refresh_replays WHERE token_hash = $1",
        )
        .bind(&old_hash)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        {
            sqlx::query(
                "UPDATE devices SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(device_id)
            .execute(&state.database)
            .await
            .map_err(database_error)?;
        }
        return Err(ApiError::unauthorized());
    };
    let refresh_token = random_secret("notary_refresh_");
    let refreshed = sqlx::query(
        "UPDATE devices SET refresh_token_hash = $1, last_used_at = $2
         WHERE device_id = $3 AND refresh_token_hash = $4 AND revoked_at IS NULL AND expires_at > $5",
    )
    .bind(sha256_hex(refresh_token.as_bytes()))
    .bind(now)
    .bind(&device_id)
    .bind(&old_hash)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if refreshed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    sqlx::query(
        "INSERT INTO device_refresh_replays (token_hash, device_id, used_at)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(old_hash)
    .bind(&device_id)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    let access_token = issue_access_token(&state.database, &device_id, now).await?;
    let _ = account_id;
    Ok(Json(DeviceTokens {
        access_token,
        refresh_token,
        expires_in: DEVICE_ACCESS_TOKEN_TTL_SECS,
    }))
}

#[utoipa::path(
    post,
    path = "/api/cli/logout",
    summary = "Revoke a Device session by refresh token",
    request_body = RefreshRequest,
    responses(
        (status = 204, description = "Device session revoked"),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
pub(super) async fn logout_device_session(
    State(state): State<NotaryApiState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<StatusCode> {
    let now = unix_timestamp()?;
    sqlx::query(
        "UPDATE devices SET revoked_at = $1 WHERE refresh_token_hash = $2 AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(sha256_hex(request.refresh_token.as_bytes()))
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/cli/me",
    summary = "Get the Device access-token identity",
    responses(
        (status = 200, body = DeviceMeResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "cli-auth"
)]
pub(super) async fn device_me(
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
) -> ApiResult<Json<DeviceMeResponse>> {
    let principal =
        auth::authenticated_principal(&state, &headers, auth::ApiScope::AccountRead).await?;
    let user = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        "SELECT accounts.account_id, accounts.display_name, identity.provider_display_name,
                identity.provider_avatar_url, identity.provider
         FROM accounts
         JOIN LATERAL (
             SELECT provider, provider_display_name, provider_avatar_url
             FROM account_identities
             WHERE account_id = accounts.account_id
             ORDER BY last_used_at DESC, identity_id
             LIMIT 1
         ) AS identity ON TRUE
         WHERE accounts.account_id = $1",
    )
    .bind(&principal.account_id)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    let session = (principal.credential_kind == auth::CredentialKind::DeviceSession).then(|| {
        DeviceSessionResponse {
            device_name: principal.credential_name.clone(),
        }
    });
    let credits = admissions::account_access(&state, &principal.account_id).await?;
    let billing = admissions::account_billing_state(&state.database, &principal.account_id).await?;
    Ok(Json(DeviceMeResponse {
        account: PublicUser {
            id: user.0,
            provider_display_name: user.2,
            avatar_url: user.3,
            auth_provider: BrowserAuthProvider::from_database(&user.4)?,
            display_name: user.1,
        },
        credential: DeviceCredentialResponse {
            kind: principal.credential_kind,
            id: principal.credential_id,
            name: principal.credential_name,
        },
        session,
        billing: AccountBillingResponse::new(
            billing,
            state.billing.purchase_mode(),
            state.billing.subscriptions_configured(),
            &state.admission,
        ),
        credits,
    }))
}
async fn approval_request(
    state: &NotaryApiState,
    request_id: &str,
    approval_secret: &str,
) -> ApiResult<(String, String, i64)> {
    let now = unix_timestamp()?;
    let request = sqlx::query_as::<_, (String, String, i64, Option<i64>)>(
        "SELECT user_code, device_name, expires_at, completed_at
         FROM device_authorizations
         WHERE authorization_id = $1 AND approval_secret_hash = $2",
    )
    .bind(request_id)
    .bind(sha256_hex(approval_secret.as_bytes()))
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::not_found("authorization request was not found"))?;
    if request.2 <= now || request.3.is_some() {
        return Err(ApiError::gone(
            "authorization request expired or was already used",
        ));
    }
    Ok((request.0, request.1, request.2))
}

pub(super) async fn issue_device_session(
    database: &DatabasePool,
    account_id: &str,
    device_name: &str,
    now: i64,
) -> ApiResult<DeviceTokens> {
    let device_id = typed_id("dev-");
    let refresh_token = random_secret("notary_refresh_");
    sqlx::query(
        "INSERT INTO devices
         (device_id, account_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&device_id)
    .bind(account_id)
    .bind(device_name)
    .bind(sha256_hex(refresh_token.as_bytes()))
    .bind(now)
    .bind(now)
    .bind(now + DEVICE_REFRESH_TOKEN_TTL_SECS)
    .execute(database)
    .await
    .map_err(database_error)?;
    let access_token = issue_access_token(database, &device_id, now).await?;
    Ok(DeviceTokens {
        access_token,
        refresh_token,
        expires_in: DEVICE_ACCESS_TOKEN_TTL_SECS,
    })
}

async fn issue_access_token(
    database: &DatabasePool,
    device_id: &str,
    now: i64,
) -> ApiResult<String> {
    let access_token = random_secret("notary_access_");
    sqlx::query("INSERT INTO device_access_tokens (token_hash, device_id, expires_at, created_at) VALUES ($1, $2, $3, $4)")
        .bind(sha256_hex(access_token.as_bytes()))
        .bind(device_id)
        .bind(now + DEVICE_ACCESS_TOKEN_TTL_SECS)
        .bind(now)
        .execute(database)
        .await
        .map_err(database_error)?;
    Ok(access_token)
}
