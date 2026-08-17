//! Browser OAuth state, callbacks, provider identities, and sessions.

use super::*;

pub(super) fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(auth_providers))
        .routes(routes!(start_github_login))
        .routes(routes!(finish_github_login))
        .routes(routes!(start_google_login))
        .routes(routes!(finish_google_login))
        .routes(routes!(logout))
}

#[utoipa::path(
    get,
    path = "/api/auth/providers",
    summary = "List configured browser sign-in providers",
    responses((status = 200, body = AuthProvidersResponse)),
    tag = "browser-auth"
)]
pub(super) async fn auth_providers(
    State(state): State<NotaryApiState>,
) -> Json<AuthProvidersResponse> {
    Json(AuthProvidersResponse {
        github: !state.github_client_id.is_empty(),
        google: !state.google_client_id.is_empty(),
    })
}

#[utoipa::path(
    get,
    path = "/api/auth/github",
    summary = "Start GitHub browser sign-in",
    params(("return_to" = Option<String>, Query, description = "Allowed in-app hash route after sign-in")),
    responses(
        (status = 307, description = "Temporary redirect to GitHub", headers(("Location" = String), ("Set-Cookie" = String))),
        (status = 503, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "browser-auth"
)]
pub(super) async fn start_github_login(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Query(query): Query<OAuthLoginQuery>,
) -> ApiResult<(CookieJar, Redirect)> {
    if state.github_client_id.is_empty() {
        return Err(ApiError::service_unavailable(
            "GitHub sign-in is not configured",
        ));
    }
    let state_token = Uuid::new_v4().to_string();
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM browser_oauth_states WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO browser_oauth_states (state_hash, expires_at, return_to, provider)
         VALUES ($1, $2, $3, 'github')",
    )
    .bind(sha256_hex(state_token.as_bytes()))
    .bind(now + LOGIN_TTL_SECS)
    .bind(return_to)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    let authorization_url = state
        .authorization_url(&state_token)
        .map_err(ApiError::internal)?;
    Ok((
        jar.add(state.cookie(OAUTH_STATE_COOKIE, state_token, LOGIN_TTL_SECS)),
        Redirect::temporary(authorization_url.as_str()),
    ))
}

#[utoipa::path(
    get,
    path = "/api/auth/github/callback",
    summary = "Finish GitHub browser sign-in",
    params(
        ("code" = Option<String>, Query),
        ("state" = Option<String>, Query),
        ("error" = Option<String>, Query)
    ),
    responses(
        (status = 303, description = "Redirect to the hosted application", headers(("Location" = String), ("Set-Cookie" = String))),
        (status = 400, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "browser-auth"
)]
pub(super) async fn finish_github_login(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Query(callback): Query<OAuthCallback>,
) -> ApiResult<(CookieJar, Redirect)> {
    if callback.error.is_some() {
        return Err(ApiError::bad_request("GitHub sign-in was cancelled"));
    }
    let code = callback
        .code
        .ok_or_else(|| ApiError::bad_request("GitHub did not return an authorization code"))?;
    let callback_state = callback
        .state
        .ok_or_else(|| ApiError::bad_request("GitHub did not return OAuth state"))?;
    let cookie_state = jar
        .get(OAUTH_STATE_COOKIE)
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(|| ApiError::bad_request("OAuth login state is missing or expired"))?;
    if callback_state != cookie_state {
        return Err(ApiError::bad_request("OAuth login state did not match"));
    }

    let now = unix_timestamp()?;
    let state_hash = sha256_hex(cookie_state.as_bytes());
    let return_to = sqlx::query_scalar::<_, Option<String>>(
        "SELECT return_to FROM browser_oauth_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'github'",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed = sqlx::query(
        "DELETE FROM browser_oauth_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'github'",
    )
    .bind(state_hash)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::bad_request(
            "OAuth login state is invalid or expired",
        ));
    }

    let token = exchange_github_code(&state, &code).await?;
    let github_user = fetch_github_user(&state, &token.access_token).await?;
    let account_id = upsert_user(&state.database, &github_user, now).await?;
    let session_token = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(account_id)
    .bind(now + SESSION_TTL_SECS)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;

    Ok((
        jar.remove(state.expired_cookie(OAUTH_STATE_COOKIE))
            .add(state.cookie(SESSION_COOKIE, session_token, SESSION_TTL_SECS)),
        Redirect::to(
            return_to
                .as_deref()
                .and_then(|value| state.public_origin.join(value).ok())
                .unwrap_or_else(|| state.public_origin.clone())
                .as_str(),
        ),
    ))
}

#[utoipa::path(
    get,
    path = "/api/auth/google",
    summary = "Start Google browser sign-in",
    params(("return_to" = Option<String>, Query, description = "Allowed in-app hash route after sign-in")),
    responses(
        (status = 307, description = "Temporary redirect to Google", headers(("Location" = String), ("Set-Cookie" = String))),
        (status = 503, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "browser-auth"
)]
pub(super) async fn start_google_login(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Query(query): Query<OAuthLoginQuery>,
) -> ApiResult<(CookieJar, Redirect)> {
    if state.google_client_id.is_empty() {
        return Err(ApiError::service_unavailable(
            "Google sign-in is not configured",
        ));
    }
    let state_token = random_token();
    let pkce_verifier = random_token();
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM browser_oauth_states WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO browser_oauth_states (state_hash, expires_at, return_to, provider)
         VALUES ($1, $2, $3, 'google')",
    )
    .bind(sha256_hex(state_token.as_bytes()))
    .bind(now + LOGIN_TTL_SECS)
    .bind(return_to)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    let authorization_url = state
        .google_authorization_url(&state_token, &code_challenge)
        .map_err(ApiError::internal)?;
    Ok((
        jar.add(state.cookie(OAUTH_STATE_COOKIE, state_token, LOGIN_TTL_SECS))
            .add(state.cookie(GOOGLE_PKCE_COOKIE, pkce_verifier, LOGIN_TTL_SECS)),
        Redirect::temporary(authorization_url.as_str()),
    ))
}

#[utoipa::path(
    get,
    path = "/api/auth/google/callback",
    summary = "Finish Google browser sign-in",
    params(
        ("code" = Option<String>, Query),
        ("state" = Option<String>, Query),
        ("error" = Option<String>, Query)
    ),
    responses(
        (status = 303, description = "Redirect to the hosted application", headers(("Location" = String), ("Set-Cookie" = String))),
        (status = 400, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "browser-auth"
)]
pub(super) async fn finish_google_login(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Query(callback): Query<OAuthCallback>,
) -> ApiResult<(CookieJar, Redirect)> {
    if callback.error.is_some() {
        return Err(ApiError::bad_request("Google sign-in was cancelled"));
    }
    let code = callback
        .code
        .ok_or_else(|| ApiError::bad_request("Google did not return an authorization code"))?;
    let callback_state = callback
        .state
        .ok_or_else(|| ApiError::bad_request("Google did not return OAuth state"))?;
    let cookie_state = jar
        .get(OAUTH_STATE_COOKIE)
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(|| ApiError::bad_request("OAuth login state is missing or expired"))?;
    let pkce_verifier = jar
        .get(GOOGLE_PKCE_COOKIE)
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(|| ApiError::bad_request("Google sign-in verifier is missing or expired"))?;
    if callback_state != cookie_state {
        return Err(ApiError::bad_request("OAuth login state did not match"));
    }

    let now = unix_timestamp()?;
    let state_hash = sha256_hex(cookie_state.as_bytes());
    let return_to = sqlx::query_scalar::<_, Option<String>>(
        "SELECT return_to FROM browser_oauth_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'google'",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed = sqlx::query(
        "DELETE FROM browser_oauth_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'google'",
    )
    .bind(state_hash)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::bad_request(
            "OAuth login state is invalid or expired",
        ));
    }

    let token = exchange_google_code(&state, &code, &pkce_verifier).await?;
    let google_user = fetch_google_user(&state, &token.access_token).await?;
    if google_user.email_verified != Some(true) || google_user.email.is_none() {
        return Err(ApiError::forbidden_message(
            "Google account email is not verified",
        ));
    }
    let account_id = upsert_google_user(&state.database, &google_user, now).await?;
    let session_token = issue_web_session(&state.database, &account_id, now).await?;

    Ok((
        jar.remove(state.expired_cookie(OAUTH_STATE_COOKIE))
            .remove(state.expired_cookie(GOOGLE_PKCE_COOKIE))
            .add(state.cookie(SESSION_COOKIE, session_token, SESSION_TTL_SECS)),
        Redirect::to(
            return_to
                .as_deref()
                .and_then(|value| state.public_origin.join(value).ok())
                .unwrap_or_else(|| state.public_origin.clone())
                .as_str(),
        ),
    ))
}
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    summary = "End the browser session",
    responses(
        (status = 204, description = "Browser session ended", headers(("Set-Cookie" = String))),
        (status = 500, body = ErrorResponse)
    ),
    security((), ("browserSession" = [])),
    tag = "browser-auth"
)]
pub(super) async fn logout(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, StatusCode)> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM browser_sessions WHERE token_hash = $1")
            .bind(sha256_hex(cookie.value().as_bytes()))
            .execute(&state.database)
            .await
            .map_err(database_error)?;
    }
    Ok((
        jar.remove(state.expired_cookie(SESSION_COOKIE)),
        StatusCode::NO_CONTENT,
    ))
}
async fn exchange_github_code(state: &NotaryApiState, code: &str) -> ApiResult<GitHubToken> {
    state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .json(&serde_json::json!({
            "client_id": state.github_client_id,
            "client_secret": state.github_client_secret,
            "code": code,
            "redirect_uri": state.github_callback_url.as_str(),
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "exchanging GitHub OAuth code failed");
            ApiError::upstream()
        })?
        .error_for_status()
        .map_err(|error| {
            tracing::warn!(%error, "GitHub OAuth token endpoint rejected code");
            ApiError::upstream()
        })?
        .json::<GitHubToken>()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "parsing GitHub OAuth token response failed");
            ApiError::upstream()
        })
}

async fn fetch_github_user(state: &NotaryApiState, access_token: &str) -> ApiResult<GitHubUser> {
    state
        .http
        .get("https://api.github.com/user")
        .header(ACCEPT, "application/vnd.github+json")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(USER_AGENT, "notary-api/0.1")
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "fetching GitHub user failed");
            ApiError::upstream()
        })?
        .error_for_status()
        .map_err(|error| {
            tracing::warn!(%error, "GitHub user endpoint rejected token");
            ApiError::upstream()
        })?
        .json::<GitHubUser>()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "parsing GitHub user response failed");
            ApiError::upstream()
        })
}

async fn exchange_google_code(
    state: &NotaryApiState,
    code: &str,
    pkce_verifier: &str,
) -> ApiResult<GoogleToken> {
    state
        .http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", state.google_client_id.as_str()),
            ("client_secret", state.google_client_secret.as_str()),
            ("code", code),
            ("code_verifier", pkce_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", state.google_callback_url.as_str()),
        ])
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "exchanging Google OAuth code failed");
            ApiError::upstream()
        })?
        .error_for_status()
        .map_err(|error| {
            tracing::warn!(%error, "Google OAuth token endpoint rejected code");
            ApiError::upstream()
        })?
        .json::<GoogleToken>()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "parsing Google OAuth token response failed");
            ApiError::upstream()
        })
}

async fn fetch_google_user(state: &NotaryApiState, access_token: &str) -> ApiResult<GoogleUser> {
    state
        .http
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "fetching Google user failed");
            ApiError::upstream()
        })?
        .error_for_status()
        .map_err(|error| {
            tracing::warn!(%error, "Google userinfo endpoint rejected token");
            ApiError::upstream()
        })?
        .json::<GoogleUser>()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "parsing Google user response failed");
            ApiError::upstream()
        })
}

async fn upsert_user(
    database: &DatabasePool,
    github_account: &GitHubUser,
    now: i64,
) -> ApiResult<String> {
    let provider_subject = github_account.id.to_string();
    upsert_identity(
        database,
        "github",
        &provider_subject,
        Some(&github_account.login),
        github_account.avatar_url.as_deref(),
        now,
    )
    .await
}

pub(super) async fn upsert_google_user(
    database: &DatabasePool,
    google_account: &GoogleUser,
    now: i64,
) -> ApiResult<String> {
    let email = google_account
        .email
        .as_deref()
        .ok_or_else(|| ApiError::forbidden_message("Google account email is not available"))?;
    let display_name = google_account
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    if google_account.sub.is_empty()
        || google_account.sub.len() > 255
        || email.is_empty()
        || email.len() > 320
        || display_name.is_some_and(|name| name.len() > 255)
        || google_account
            .picture
            .as_ref()
            .is_some_and(|picture| picture.len() > 2_048)
    {
        return Err(ApiError::upstream());
    }
    upsert_identity(
        database,
        "google",
        &google_account.sub,
        display_name,
        google_account.picture.as_deref(),
        now,
    )
    .await
}

async fn upsert_identity(
    database: &DatabasePool,
    provider: &'static str,
    provider_subject: &str,
    provider_display_name: Option<&str>,
    provider_avatar_url: Option<&str>,
    now: i64,
) -> ApiResult<String> {
    let mut transaction = database.begin().await.map_err(database_error)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{provider}:{provider_subject}"))
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;

    let existing = sqlx::query_as::<_, (String, String, String)>(
        "SELECT accounts.account_id, accounts.display_name,
                account_identities.provider_display_name
         FROM account_identities
         JOIN accounts ON accounts.account_id = account_identities.account_id
         WHERE account_identities.provider = $1
           AND account_identities.provider_subject = $2
         FOR UPDATE OF accounts, account_identities",
    )
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?;

    let account_id = if let Some((account_id, display_name, previous_provider_name)) = existing {
        let provider_display_name = provider_display_name.unwrap_or(&previous_provider_name);
        let account_display_name = if display_name == previous_provider_name {
            provider_display_name
        } else {
            &display_name
        };
        sqlx::query("UPDATE accounts SET display_name = $1, updated_at = $2 WHERE account_id = $3")
            .bind(account_display_name)
            .bind(now)
            .bind(&account_id)
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
        sqlx::query(
            "UPDATE account_identities
             SET provider_display_name = $1, provider_avatar_url = $2,
                 updated_at = $3, last_used_at = $3
             WHERE provider = $4 AND provider_subject = $5",
        )
        .bind(provider_display_name)
        .bind(provider_avatar_url)
        .bind(now)
        .bind(provider)
        .bind(provider_subject)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        account_id
    } else {
        let account_id = typed_id("acct-");
        let provider_display_name = provider_display_name
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{provider}-{}", &account_id[..12]));
        sqlx::query(
            "INSERT INTO accounts (account_id, display_name, created_at, updated_at)
             VALUES ($1, $2, $3, $3)",
        )
        .bind(&account_id)
        .bind(&provider_display_name)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        sqlx::query(
            "INSERT INTO account_identities
             (identity_id, account_id, provider, provider_subject, provider_display_name,
              provider_avatar_url, created_at, updated_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&account_id)
        .bind(provider)
        .bind(provider_subject)
        .bind(&provider_display_name)
        .bind(provider_avatar_url)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        account_id
    };

    transaction.commit().await.map_err(database_error)?;
    Ok(account_id)
}

pub(super) async fn issue_web_session(
    database: &DatabasePool,
    account_id: &str,
    now: i64,
) -> ApiResult<String> {
    let session_token = random_token();
    sqlx::query(
        "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(account_id)
    .bind(now + SESSION_TTL_SECS)
    .bind(now)
    .execute(database)
    .await
    .map_err(database_error)?;
    Ok(session_token)
}
