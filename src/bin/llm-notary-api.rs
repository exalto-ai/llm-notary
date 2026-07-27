use std::{env, net::SocketAddr, str::FromStr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
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

const SESSION_COOKIE: &str = "llm_notary_session";
const OAUTH_STATE_COOKIE: &str = "llm_notary_oauth_state";
const LOGIN_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone)]
struct AppState {
    database: SqlitePool,
    http: reqwest::Client,
    github_client_id: String,
    github_client_secret: String,
    callback_url: Url,
    app_url: Url,
    secure_cookies: bool,
    notary_host: String,
    notary_port: u16,
}

#[derive(Deserialize)]
struct GitHubCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
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
    host: String,
    port: u16,
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
            notary_host,
            notary_port,
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
        host: state.notary_host,
        port: state.notary_port,
    })
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn start_github_login(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Redirect)> {
    let state_token = Uuid::new_v4().to_string();
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM oauth_login_states WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    sqlx::query("INSERT INTO oauth_login_states (state_hash, expires_at) VALUES (?, ?)")
        .bind(sha256_hex(state_token.as_bytes()))
        .bind(now + LOGIN_TTL_SECS)
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
        Redirect::to(state.app_url.as_str()),
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
            notary_host: "notary.example.com".to_owned(),
            notary_port: 7047,
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
}
