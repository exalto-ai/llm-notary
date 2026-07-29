use std::{env, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use rand::RngCore;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use time::Duration as CookieDuration;
use url::Url;
use uuid::Uuid;

use certified::sha256_hex;
use k256::ecdsa::VerifyingKey;

const SESSION_COOKIE: &str = "llm_notary_session";
const OAUTH_STATE_COOKIE: &str = "llm_notary_oauth_state";
const LOGIN_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const CLI_AUTHORIZATION_TTL_SECS: i64 = 10 * 60;
const CLI_ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const CLI_REFRESH_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;

#[derive(Clone)]
struct AppState {
    database: SqlitePool,
    http: reqwest::Client,
    github_client_id: String,
    github_client_secret: String,
    callback_url: Url,
    app_url: Url,
    secure_cookies: bool,
    notary_key: NotaryDirectoryKey,
}

#[derive(Deserialize)]
struct GitHubCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GitHubLoginQuery {
    return_to: Option<String>,
}

#[derive(Deserialize)]
struct GitHubToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    avatar_url: Option<String>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct NotaryDirectoryEntry {
    format: &'static str,
    host: String,
    port: u16,
    key_id: String,
    public_key: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct NotaryDirectoryKey {
    host: String,
    port: u16,
    key_id: String,
    public_key: String,
}

#[derive(Serialize)]
struct PublicUser {
    id: String,
    github_login: String,
    avatar_url: Option<String>,
}

#[derive(Serialize)]
struct MeResponse {
    user: PublicUser,
}

#[derive(Serialize)]
struct WebCliSession {
    id: String,
    device_name: String,
    created_at: i64,
    last_used_at: i64,
    expires_at: i64,
}

#[derive(Serialize)]
struct WebCliSessionsResponse {
    sessions: Vec<WebCliSession>,
}

#[derive(Deserialize)]
struct CreateCliAuthorization {
    device_name: String,
}

#[derive(Serialize)]
struct CliAuthorizationStarted {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
    poll_secret: String,
}

#[derive(Deserialize)]
struct ApprovalQuery {
    approval_secret: String,
}

#[derive(Serialize)]
struct ApprovalDetails {
    user_code: String,
    device_name: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct ApprovedAuthorization {
    status: &'static str,
}

#[derive(Serialize)]
struct CliTokens {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize)]
struct CliSessionResponse {
    device_name: String,
}

#[derive(Serialize)]
struct CliMeResponse {
    user: PublicUser,
    session: CliSessionResponse,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "authentication required",
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    fn gone(message: &'static str) -> Self {
        Self {
            status: StatusCode::GONE,
            message,
        }
    }

    fn pending() -> Self {
        Self {
            status: StatusCode::PRECONDITION_REQUIRED,
            message: "authorization pending",
        }
    }

    fn upstream() -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: "GitHub sign-in failed",
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        tracing::error!(%error, "API request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    let state = AppState::from_env().await?;
    let listen = env::var("LLM_NOTARY_API_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()
        .context("LLM_NOTARY_API_LISTEN must be a socket address")?;
    let app = Router::new()
        .route("/api/healthz", get(health))
        .route("/api/notary", get(notary))
        .route("/api/auth/github", get(start_github_login))
        .route("/api/auth/github/callback", get(finish_github_login))
        .route("/api/auth/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/cli/sessions", get(list_cli_sessions))
        .route(
            "/api/cli/sessions/{session_id}",
            axum::routing::delete(revoke_web_cli_session),
        )
        .route("/api/cli/authorizations", post(start_cli_authorization))
        .route(
            "/api/cli/authorizations/{request_id}/approval",
            get(cli_approval_details).post(approve_cli_authorization),
        )
        .route(
            "/api/cli/authorizations/{request_id}/token",
            post(complete_cli_authorization),
        )
        .route("/api/cli/token", post(refresh_cli_tokens))
        .route("/api/cli/logout", post(logout_cli_session))
        .route("/api/cli/me", get(cli_me))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "LLM Notary API listening");
    axum::serve(listener, app).await?;
    Ok(())
}

impl AppState {
    async fn from_env() -> Result<Self> {
        let github_client_id = required_env("GITHUB_OAUTH_CLIENT_ID")?;
        let github_client_secret = required_env("GITHUB_OAUTH_CLIENT_SECRET")?;
        let app_url = Url::parse(
            &env::var("LLM_NOTARY_PUBLIC_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:4173".to_owned()),
        )
        .context("LLM_NOTARY_PUBLIC_ORIGIN must be an absolute URL")?;
        if app_url.path() != "/" || app_url.query().is_some() || app_url.fragment().is_some() {
            bail!("LLM_NOTARY_PUBLIC_ORIGIN must be an origin without a path, query, or fragment");
        }
        let callback_url = app_url
            .join("/api/auth/github/callback")
            .context("building GitHub OAuth callback URL")?;
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://llm-notary-api.db".to_owned());
        let notary_host =
            env::var("LLM_NOTARY_NOTARY_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
        if notary_host.is_empty() || notary_host.chars().any(char::is_whitespace) {
            bail!("LLM_NOTARY_NOTARY_HOST must be a non-empty hostname or IP address");
        }
        let notary_port = env::var("LLM_NOTARY_NOTARY_PORT")
            .unwrap_or_else(|_| "7047".to_owned())
            .parse::<u16>()
            .context("LLM_NOTARY_NOTARY_PORT must be a valid TCP port")?;
        let notary_public_key = env::var("LLM_NOTARY_NOTARY_PUBLIC_KEY")
            .context("LLM_NOTARY_NOTARY_PUBLIC_KEY is required")?;
        let public_key = hex::decode(&notary_public_key)
            .context("LLM_NOTARY_NOTARY_PUBLIC_KEY must be hexadecimal")?;
        VerifyingKey::from_sec1_bytes(&public_key)
            .context("LLM_NOTARY_NOTARY_PUBLIC_KEY must be a SEC1 secp256k1 key")?;
        let notary_key = NotaryDirectoryKey {
            host: notary_host.clone(),
            port: notary_port,
            key_id: format!("sha256:{}", sha256_hex(&public_key)),
            public_key: hex::encode(public_key),
        };
        let options = SqliteConnectOptions::from_str(&database_url)
            .context("DATABASE_URL must be a SQLite connection URL")?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let database = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context("opening API database")?;
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .context("migrating API database")?;
        Ok(Self {
            database,
            http: reqwest::Client::builder()
                .user_agent("LLM-Notary/0.1")
                .build()
                .context("building GitHub client")?,
            github_client_id,
            github_client_secret,
            callback_url,
            secure_cookies: app_url.scheme() == "https",
            app_url,
            notary_key,
        })
    }

    fn authorization_url(&self, state: &str) -> Result<Url> {
        let mut url = Url::parse("https://github.com/login/oauth/authorize")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.github_client_id)
            .append_pair("redirect_uri", self.callback_url.as_str())
            .append_pair("state", state);
        Ok(url)
    }

    fn cookie(&self, name: &'static str, value: String, max_age_secs: i64) -> Cookie<'static> {
        Cookie::build((name, value))
            .path("/")
            .http_only(true)
            .secure(self.secure_cookies)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::seconds(max_age_secs))
            .build()
    }

    fn expired_cookie(&self, name: &'static str) -> Cookie<'static> {
        self.cookie(name, String::new(), 0)
    }
}

async fn notary(State(state): State<AppState>) -> Json<NotaryDirectoryEntry> {
    Json(NotaryDirectoryEntry {
        format: "llm-notary/notary-directory/v1",
        host: state.notary_key.host,
        port: state.notary_key.port,
        key_id: state.notary_key.key_id,
        public_key: state.notary_key.public_key,
    })
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn start_github_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<GitHubLoginQuery>,
) -> ApiResult<(CookieJar, Redirect)> {
    let state_token = Uuid::new_v4().to_string();
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM oauth_login_states WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO oauth_login_states (state_hash, expires_at, return_to) VALUES (?, ?, ?)",
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

async fn finish_github_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(callback): Query<GitHubCallback>,
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
        "SELECT return_to FROM oauth_login_states WHERE state_hash = ? AND expires_at > ?",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed =
        sqlx::query("DELETE FROM oauth_login_states WHERE state_hash = ? AND expires_at > ?")
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
    let user_id = upsert_user(&state.database, &github_user, now).await?;
    let session_token = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(user_id)
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
                .and_then(|value| state.app_url.join(value).ok())
                .unwrap_or_else(|| state.app_url.clone())
                .as_str(),
        ),
    ))
}

async fn me(State(state): State<AppState>, jar: CookieJar) -> ApiResult<Json<MeResponse>> {
    let session_token = session_token(&jar)?;
    let now = unix_timestamp()?;
    let user = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT users.id, users.github_login, users.avatar_url
         FROM sessions JOIN users ON users.id = sessions.user_id
         WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(MeResponse {
        user: PublicUser {
            id: user.0,
            github_login: user.1,
            avatar_url: user.2,
        },
    }))
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, StatusCode)> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
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

async fn list_cli_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<WebCliSessionsResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let sessions = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT id, device_name, created_at, last_used_at, expires_at
         FROM cli_sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         ORDER BY last_used_at DESC, created_at DESC",
    )
    .bind(user.0)
    .bind(now)
    .fetch_all(&state.database)
    .await
    .map_err(database_error)?
    .into_iter()
    .map(|session| WebCliSession {
        id: session.0,
        device_name: session.1,
        created_at: session.2,
        last_used_at: session.3,
        expires_at: session.4,
    })
    .collect();
    Ok(Json(WebCliSessionsResponse { sessions }))
}

async fn revoke_web_cli_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(session_id): Path<String>,
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let revoked = sqlx::query(
        "UPDATE cli_sessions SET revoked_at = ?
         WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(now)
    .bind(session_id)
    .bind(user.0)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if revoked.rows_affected() != 1 {
        return Err(ApiError::not_found("CLI session was not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn start_cli_authorization(
    State(state): State<AppState>,
    Json(request): Json<CreateCliAuthorization>,
) -> ApiResult<Json<CliAuthorizationStarted>> {
    let device_name = request.device_name.trim();
    if device_name.is_empty() || device_name.len() > 120 {
        return Err(ApiError::bad_request(
            "device_name must be between 1 and 120 characters",
        ));
    }
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM cli_authorization_requests WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;

    // The displayed code is intentionally low-entropy. The browser approval
    // URL and the polling endpoint each also require an independent 256-bit
    // secret, so a guessed code cannot approve or consume an authorization.
    for _ in 0..10 {
        let request_id = Uuid::new_v4().to_string();
        let user_code = user_code();
        let poll_secret = random_token();
        let approval_secret = random_token();
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO cli_authorization_requests
             (id, user_code, poll_secret_hash, approval_secret_hash, device_name, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&request_id)
        .bind(&user_code)
        .bind(sha256_hex(poll_secret.as_bytes()))
        .bind(sha256_hex(approval_secret.as_bytes()))
        .bind(device_name)
        .bind(now)
        .bind(now + CLI_AUTHORIZATION_TTL_SECS)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
        if inserted.rows_affected() == 1 {
            let verification_uri_complete = format!(
                "{}#/authorize?request_id={}&approval_secret={}",
                state.app_url, request_id, approval_secret
            );
            return Ok(Json(CliAuthorizationStarted {
                request_id,
                user_code,
                verification_uri_complete,
                expires_in: CLI_AUTHORIZATION_TTL_SECS,
                interval: 3,
                poll_secret,
            }));
        }
    }
    Err(ApiError::internal(anyhow!(
        "could not allocate unique user code"
    )))
}

async fn cli_approval_details(
    State(state): State<AppState>,
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

async fn approve_cli_authorization(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(request_id): Path<String>,
    Query(query): Query<ApprovalQuery>,
) -> ApiResult<Json<ApprovedAuthorization>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let approved = sqlx::query(
        "UPDATE cli_authorization_requests
         SET approved_user_id = ?, approved_at = ?
         WHERE id = ? AND approval_secret_hash = ? AND expires_at > ?
           AND approved_user_id IS NULL AND completed_at IS NULL",
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
    Ok(Json(ApprovedAuthorization { status: "approved" }))
}

async fn complete_cli_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> ApiResult<Json<CliTokens>> {
    let poll_secret = headers
        .get("X-LLM-Notary-Poll-Secret")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let now = unix_timestamp()?;
    let request = sqlx::query_as::<_, (Option<String>, String, i64, Option<i64>)>(
        "SELECT approved_user_id, device_name, expires_at, completed_at
         FROM cli_authorization_requests
         WHERE id = ? AND poll_secret_hash = ?",
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
    let user_id = request.0.ok_or_else(ApiError::pending)?;

    // Mark consumption first with a compare-and-set. This makes a second poll
    // fail even if it races the successful poll.
    let consumed = sqlx::query(
        "UPDATE cli_authorization_requests SET completed_at = ?
         WHERE id = ? AND completed_at IS NULL AND expires_at > ? AND approved_user_id IS NOT NULL",
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
    let tokens = issue_cli_session(&state.database, &user_id, &request.1, now).await?;
    Ok(Json(tokens))
}

async fn refresh_cli_tokens(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<Json<CliTokens>> {
    let now = unix_timestamp()?;
    let old_hash = sha256_hex(request.refresh_token.as_bytes());
    let session = sqlx::query_as::<_, (String, String)>(
        "SELECT id, user_id FROM cli_sessions
         WHERE refresh_token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(&old_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    let Some((session_id, user_id)) = session else {
        // Reusing a rotated token is a credential-theft signal: revoke the
        // session that originally held it before rejecting the request.
        if let Some(session_id) = sqlx::query_scalar::<_, String>(
            "SELECT session_id FROM cli_used_refresh_tokens WHERE token_hash = ?",
        )
        .bind(&old_hash)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        {
            sqlx::query(
                "UPDATE cli_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(session_id)
            .execute(&state.database)
            .await
            .map_err(database_error)?;
        }
        return Err(ApiError::unauthorized());
    };
    let refresh_token = random_token();
    let refreshed = sqlx::query(
        "UPDATE cli_sessions SET refresh_token_hash = ?, last_used_at = ?
         WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(sha256_hex(refresh_token.as_bytes()))
    .bind(now)
    .bind(&session_id)
    .bind(&old_hash)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    if refreshed.rows_affected() != 1 {
        return Err(ApiError::unauthorized());
    }
    sqlx::query("INSERT OR IGNORE INTO cli_used_refresh_tokens (token_hash, session_id, used_at) VALUES (?, ?, ?)")
        .bind(old_hash)
        .bind(&session_id)
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let access_token = issue_access_token(&state.database, &session_id, now).await?;
    let _ = user_id;
    Ok(Json(CliTokens {
        access_token,
        refresh_token,
        expires_in: CLI_ACCESS_TOKEN_TTL_SECS,
    }))
}

async fn logout_cli_session(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> ApiResult<StatusCode> {
    let now = unix_timestamp()?;
    sqlx::query("UPDATE cli_sessions SET revoked_at = ? WHERE refresh_token_hash = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(sha256_hex(request.refresh_token.as_bytes()))
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cli_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<CliMeResponse>> {
    let token = bearer_token(&headers)?;
    let now = unix_timestamp()?;
    let session = sqlx::query_as::<_, (String, String, Option<String>, String)>(
        "SELECT users.id, users.github_login, users.avatar_url, cli_sessions.device_name
         FROM cli_access_tokens
         JOIN cli_sessions ON cli_sessions.id = cli_access_tokens.session_id
         JOIN users ON users.id = cli_sessions.user_id
         WHERE cli_access_tokens.token_hash = ? AND cli_access_tokens.expires_at > ?
           AND cli_sessions.revoked_at IS NULL",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(CliMeResponse {
        user: PublicUser {
            id: session.0,
            github_login: session.1,
            avatar_url: session.2,
        },
        session: CliSessionResponse {
            device_name: session.3,
        },
    }))
}

async fn authenticated_web_user(
    state: &AppState,
    jar: &CookieJar,
) -> ApiResult<(String, String, Option<String>)> {
    let token = session_token(jar)?;
    let now = unix_timestamp()?;
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT users.id, users.github_login, users.avatar_url
         FROM sessions JOIN users ON users.id = sessions.user_id
         WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)
}

async fn approval_request(
    state: &AppState,
    request_id: &str,
    approval_secret: &str,
) -> ApiResult<(String, String, i64)> {
    let now = unix_timestamp()?;
    let request = sqlx::query_as::<_, (String, String, i64, Option<i64>)>(
        "SELECT user_code, device_name, expires_at, completed_at
         FROM cli_authorization_requests
         WHERE id = ? AND approval_secret_hash = ?",
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

async fn issue_cli_session(
    database: &SqlitePool,
    user_id: &str,
    device_name: &str,
    now: i64,
) -> ApiResult<CliTokens> {
    let session_id = Uuid::new_v4().to_string();
    let refresh_token = random_token();
    sqlx::query(
        "INSERT INTO cli_sessions
         (id, user_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(device_name)
    .bind(sha256_hex(refresh_token.as_bytes()))
    .bind(now)
    .bind(now)
    .bind(now + CLI_REFRESH_TOKEN_TTL_SECS)
    .execute(database)
    .await
    .map_err(database_error)?;
    let access_token = issue_access_token(database, &session_id, now).await?;
    Ok(CliTokens {
        access_token,
        refresh_token,
        expires_in: CLI_ACCESS_TOKEN_TTL_SECS,
    })
}

async fn issue_access_token(
    database: &SqlitePool,
    session_id: &str,
    now: i64,
) -> ApiResult<String> {
    let access_token = random_token();
    sqlx::query("INSERT INTO cli_access_tokens (token_hash, session_id, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(sha256_hex(access_token.as_bytes()))
        .bind(session_id)
        .bind(now + CLI_ACCESS_TOKEN_TTL_SECS)
        .bind(now)
        .execute(database)
        .await
        .map_err(database_error)?;
    Ok(access_token)
}

fn bearer_token(headers: &HeaderMap) -> ApiResult<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(ApiError::unauthorized)
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn user_code() -> String {
    let mut bytes = [0_u8; 4];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "{:02X}{:02X}-{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

async fn exchange_github_code(state: &AppState, code: &str) -> ApiResult<GitHubToken> {
    state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(ACCEPT, "application/json")
        .json(&serde_json::json!({
            "client_id": state.github_client_id,
            "client_secret": state.github_client_secret,
            "code": code,
            "redirect_uri": state.callback_url.as_str(),
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

async fn fetch_github_user(state: &AppState, access_token: &str) -> ApiResult<GitHubUser> {
    state
        .http
        .get("https://api.github.com/user")
        .header(ACCEPT, "application/vnd.github+json")
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .header(USER_AGENT, "LLM-Notary/0.1")
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

async fn upsert_user(
    database: &SqlitePool,
    github_user: &GitHubUser,
    now: i64,
) -> ApiResult<String> {
    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, github_id, github_login, avatar_url, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(github_id) DO UPDATE SET
            github_login = excluded.github_login,
            avatar_url = excluded.avatar_url,
            updated_at = excluded.updated_at",
    )
    .bind(&user_id)
    .bind(github_user.id)
    .bind(&github_user.login)
    .bind(&github_user.avatar_url)
    .bind(now)
    .bind(now)
    .execute(database)
    .await
    .map_err(database_error)?;
    sqlx::query_scalar("SELECT id FROM users WHERE github_id = ?")
        .bind(github_user.id)
        .fetch_one(database)
        .await
        .map_err(database_error)
}

fn session_token(jar: &CookieJar) -> ApiResult<String> {
    jar.get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned())
        .ok_or_else(ApiError::unauthorized)
}

fn unix_timestamp() -> ApiResult<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| ApiError::internal(anyhow!(error)))
        .map(|duration| duration.as_secs() as i64)
}

fn database_error(error: sqlx::Error) -> ApiError {
    ApiError::internal(anyhow!(error))
}

fn required_env(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} must be set"))?;
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory_key() -> NotaryDirectoryKey {
        NotaryDirectoryKey {
            host: "notary.example.com".to_owned(),
            port: 7047,
            key_id: "sha256:test".to_owned(),
            public_key: "02".to_owned(),
        }
    }

    #[tokio::test]
    async fn authorization_url_uses_the_exact_callback_and_state() {
        let state = AppState {
            database: SqlitePool::connect_lazy("sqlite::memory:").expect("lazy database"),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://llmnotary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            app_url: Url::parse("https://llmnotary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_key: directory_key(),
        };
        let url = state
            .authorization_url("state-token")
            .expect("authorization URL");
        assert_eq!(url.origin().ascii_serialization(), "https://github.com");
        assert_eq!(url.path(), "/login/oauth/authorize");
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "client_id" && value == "client-id")
        );
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "state" && value == "state-token")
        );
        assert!(url.query_pairs().any(|(key, value)| {
            key == "redirect_uri" && value == "https://llmnotary.exalto.ai/api/auth/github/callback"
        }));
        assert!(!url.query_pairs().any(|(key, _)| key == "scope"));
    }

    #[tokio::test]
    async fn new_cli_session_is_usable_until_its_refresh_expiry() {
        let database = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .expect("migrations");
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'octo', 1, 1)",
        )
        .execute(&database)
        .await
        .expect("user");

        let now = match unix_timestamp() {
            Ok(now) => now,
            Err(_) => panic!("current time"),
        };
        let tokens = match issue_cli_session(&database, "user-1", "Test CLI", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("CLI session"),
        };
        let (created_at, last_used_at, expires_at) = sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT created_at, last_used_at, expires_at FROM cli_sessions",
        )
        .fetch_one(&database)
        .await
        .expect("stored session");
        assert_eq!((created_at, last_used_at), (now, now));
        assert_eq!(expires_at, now + CLI_REFRESH_TOKEN_TTL_SECS);

        let refreshed = refresh_cli_tokens(
            State(AppState {
                database,
                http: reqwest::Client::new(),
                github_client_id: "client-id".to_owned(),
                github_client_secret: "secret".to_owned(),
                callback_url: Url::parse("https://llmnotary.exalto.ai/api/auth/github/callback")
                    .expect("callback URL"),
                app_url: Url::parse("https://llmnotary.exalto.ai").expect("app URL"),
                secure_cookies: true,
                notary_key: directory_key(),
            }),
            Json(RefreshRequest {
                refresh_token: tokens.refresh_token,
            }),
        )
        .await;
        let refreshed = match refreshed {
            Ok(refreshed) => refreshed,
            Err(_) => panic!("new session refreshes"),
        };
        assert!(!refreshed.0.access_token.is_empty());
    }

    #[tokio::test]
    async fn web_users_can_list_and_revoke_only_their_cli_sessions() {
        let database = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .expect("migrations");
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'one', 1, 1), ('user-2', 2, 'two', 1, 1)",
        )
        .execute(&database)
        .await
        .expect("users");
        let now = match unix_timestamp() {
            Ok(now) => now,
            Err(_) => panic!("current time"),
        };
        let web_token = "web-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES (?, 'user-1', ?, ?)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .bind(now + SESSION_TTL_SECS)
        .bind(now)
        .execute(&database)
        .await
        .expect("web session");
        let own = match issue_cli_session(&database, "user-1", "Own CLI", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("own CLI session"),
        };
        let other = match issue_cli_session(&database, "user-2", "Other CLI", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("other CLI session"),
        };
        let own_id: String =
            sqlx::query_scalar("SELECT id FROM cli_sessions WHERE refresh_token_hash = ?")
                .bind(sha256_hex(own.refresh_token.as_bytes()))
                .fetch_one(&database)
                .await
                .expect("own CLI ID");
        let other_id: String =
            sqlx::query_scalar("SELECT id FROM cli_sessions WHERE refresh_token_hash = ?")
                .bind(sha256_hex(other.refresh_token.as_bytes()))
                .fetch_one(&database)
                .await
                .expect("other CLI ID");
        let state = AppState {
            database,
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://llmnotary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            app_url: Url::parse("https://llmnotary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_key: directory_key(),
        };
        let jar = || CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));

        let sessions = match list_cli_sessions(State(state.clone()), jar()).await {
            Ok(sessions) => sessions.0.sessions,
            Err(_) => panic!("list CLI sessions"),
        };
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, own_id);

        let revoked =
            revoke_web_cli_session(State(state.clone()), jar(), Path(own_id.clone())).await;
        assert!(matches!(revoked, Ok(StatusCode::NO_CONTENT)));
        let sessions = match list_cli_sessions(State(state.clone()), jar()).await {
            Ok(sessions) => sessions.0.sessions,
            Err(_) => panic!("list CLI sessions after revoke"),
        };
        assert!(sessions.is_empty());

        let cross_account = revoke_web_cli_session(State(state), jar(), Path(other_id)).await;
        assert!(matches!(
            cross_account,
            Err(ApiError {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ));
    }
}
