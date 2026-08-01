use std::{
    env,
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{MatchedPath, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use rand::RngCore;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use time::Duration as CookieDuration;
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use llm_notary::notary_directory::{
    DIRECTORY_FORMAT_V3, NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus, NotaryTransport,
    key_id, parse_directory,
};
use llm_notary::sha256_hex;
use llm_notary::telemetry;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

#[path = "../api/admission.rs"]
mod admission;
#[path = "../api/intake.rs"]
mod intake;
#[path = "../api/publish.rs"]
mod publish;

const SESSION_COOKIE: &str = "llm_notary_session";
const OAUTH_STATE_COOKIE: &str = "llm_notary_oauth_state";
const LOGIN_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const CLI_AUTHORIZATION_TTL_SECS: i64 = 10 * 60;
const CLI_ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const CLI_REFRESH_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;
const DEFAULT_DATABASE_MAX_CONNECTIONS: u32 = 5;
const MAX_DATABASE_CONNECTIONS: u32 = 64;
const IDLE_SHUTDOWN_POLL_SECS: u64 = 1;

static ACTIVE_REQUESTS: AtomicUsize = AtomicUsize::new(0);

type DatabasePool = PgPool;

#[derive(Clone)]
struct AppState {
    database: DatabasePool,
    #[cfg(test)]
    // Keep the Testcontainers server alive for the lifetime of a test state.
    _test_database: Option<test_database::TestDatabase>,
    http: reqwest::Client,
    github_client_id: String,
    github_client_secret: String,
    callback_url: Url,
    app_url: Url,
    secure_cookies: bool,
    notary_directory: NotaryDirectory,
    publish: publish::PublishService,
    library_metadata: admission::MetadataService,
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

#[derive(Debug)]
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

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
        }
    }

    fn service_unavailable(message: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
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
    let _telemetry = telemetry::init("llm-notary-api")?;
    let state = AppState::from_env().await?;
    let listen = env::var("LLM_NOTARY_API_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()
        .context("LLM_NOTARY_API_LISTEN must be a socket address")?;
    publish::spawn_cleanup(state.clone());
    admission::spawn(state.clone());
    let shutdown_rx = idle_shutdown_secs()?.map(|idle_shutdown_secs| {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        spawn_idle_shutdown(state.clone(), idle_shutdown_secs, shutdown_tx);
        shutdown_rx
    });
    let app = Router::new()
        .route("/metrics", get(metrics))
        .route("/api/healthz", get(health))
        .route("/api/readyz", get(readiness))
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
        .merge(publish::router())
        .merge(admission::router())
        .layer(middleware::from_fn(observe_http_request))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "LLM Notary API listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            match shutdown_rx {
                Some(mut shutdown_rx) => {
                    let _ = shutdown_rx.changed().await;
                }
                None => std::future::pending().await,
            }
        })
        .await?;
    Ok(())
}

fn idle_shutdown_secs() -> Result<Option<u64>> {
    let value = match env::var("LLM_NOTARY_IDLE_SHUTDOWN_SECS") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error).context("reading LLM_NOTARY_IDLE_SHUTDOWN_SECS"),
    };
    parse_idle_shutdown_secs(&value).map(Some)
}

fn parse_idle_shutdown_secs(value: &str) -> Result<u64> {
    let seconds = value
        .parse::<u64>()
        .context("LLM_NOTARY_IDLE_SHUTDOWN_SECS must be a positive integer")?;
    if seconds == 0 {
        bail!("LLM_NOTARY_IDLE_SHUTDOWN_SECS must be a positive integer");
    }
    Ok(seconds)
}

fn spawn_idle_shutdown(
    state: AppState,
    idle_shutdown_secs: u64,
    shutdown: tokio::sync::watch::Sender<bool>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(IDLE_SHUTDOWN_POLL_SECS));
        let mut idle_since = None;
        loop {
            ticker.tick().await;
            let admission_work = match admission::has_pending_work(&state).await {
                Ok(pending) => pending,
                Err(error) => {
                    tracing::error!(%error, "checking admission idle-shutdown work state failed");
                    true
                }
            };
            let cleanup_work = match publish::has_pending_cleanup(&state).await {
                Ok(pending) => pending,
                Err(error) => {
                    tracing::error!(
                        status = %error.status,
                        error = error.message,
                        "checking cleanup idle-shutdown work state failed"
                    );
                    true
                }
            };
            if admission_work || cleanup_work || ACTIVE_REQUESTS.load(Ordering::Relaxed) != 0 {
                idle_since = None;
                continue;
            }
            let since = idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(idle_shutdown_secs) {
                tracing::info!(
                    idle_shutdown_secs,
                    "API has no active requests or background work; shutting down"
                );
                let _ = shutdown.send(true);
                return;
            }
        }
    });
}

async fn metrics() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        telemetry::prometheus_metrics(),
    )
        .into_response()
}

async fn observe_http_request(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched")
        .to_owned();
    let _activity = counts_as_request_activity(&route).then(RequestActivity::start);
    let request_id = Uuid::new_v4().to_string();
    let parent = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });
    let span = tracing::info_span!(
        "http.request",
        otel.name = "http.request",
        http.request.method = %method,
        http.route = %route,
        request.id = %request_id,
    );
    let _ = span.set_parent(parent);
    async move {
        let started = Instant::now();
        let mut response = next.run(request).await;
        let status = response.status().as_u16().to_string();
        let elapsed = started.elapsed().as_secs_f64();
        metrics::counter!(
            "llm_notary_http_requests_total",
            "method" => method.clone(),
            "route" => route.clone(),
            "status" => status.clone()
        )
        .increment(1);
        metrics::histogram!(
            "llm_notary_http_request_duration_seconds",
            "method" => method,
            "route" => route
        )
        .record(elapsed);
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&request_id).expect("UUID is a valid header value"),
        );
        tracing::info!(http.response.status_code = %status, duration_ms = (elapsed * 1_000.0) as u64, "HTTP request completed");
        response
    }
    .instrument(span)
    .await
}

fn counts_as_request_activity(route: &str) -> bool {
    !matches!(route, "/metrics" | "/api/healthz" | "/api/readyz")
}

struct RequestActivity;

impl RequestActivity {
    fn start() -> Self {
        ACTIVE_REQUESTS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for RequestActivity {
    fn drop(&mut self) {
        ACTIVE_REQUESTS.fetch_sub(1, Ordering::Relaxed);
    }
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
        let notary_directory = notary_directory_from_env()?;
        let publish = publish::PublishService::from_env(app_url.origin().ascii_serialization())?;
        publish.validate().await?;
        let database = {
            let database_url = required_env("DATABASE_URL")?;
            let options = database_url
                .parse::<PgConnectOptions>()
                .context("DATABASE_URL must be a PostgreSQL connection URL")?;
            PgPoolOptions::new()
                .max_connections(database_max_connections()?)
                .connect_with(options)
                .await
                .context("opening API database")?
        };
        Ok(Self {
            database,
            #[cfg(test)]
            _test_database: None,
            http: reqwest::Client::builder()
                .user_agent("LLM-Notary/0.1")
                .build()
                .context("building GitHub client")?,
            github_client_id,
            github_client_secret,
            callback_url,
            secure_cookies: app_url.scheme() == "https",
            app_url,
            notary_directory,
            publish,
            library_metadata: admission::MetadataService::from_env(),
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

fn database_max_connections() -> Result<u32> {
    let value = match env::var("LLM_NOTARY_DATABASE_MAX_CONNECTIONS") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(DEFAULT_DATABASE_MAX_CONNECTIONS),
        Err(error) => return Err(error).context("reading LLM_NOTARY_DATABASE_MAX_CONNECTIONS"),
    };
    let connections = value
        .parse::<u32>()
        .context("LLM_NOTARY_DATABASE_MAX_CONNECTIONS must be an integer")?;
    if connections == 0 || connections > MAX_DATABASE_CONNECTIONS {
        bail!(
            "LLM_NOTARY_DATABASE_MAX_CONNECTIONS must be between 1 and {MAX_DATABASE_CONNECTIONS}"
        );
    }
    Ok(connections)
}

async fn notary(State(state): State<AppState>) -> Json<NotaryDirectory> {
    Json(state.notary_directory)
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn readiness(State(state): State<AppState>) -> ApiResult<Json<Health>> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&state.database)
        .await
        .map_err(database_error)?;
    Ok(Json(Health { status: "ok" }))
}

async fn start_github_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<GitHubLoginQuery>,
) -> ApiResult<(CookieJar, Redirect)> {
    let state_token = Uuid::new_v4().to_string();
    let now = unix_timestamp()?;
    sqlx::query("DELETE FROM oauth_login_states WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO oauth_login_states (state_hash, expires_at, return_to) VALUES ($1, $2, $3)",
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
        "SELECT return_to FROM oauth_login_states WHERE state_hash = $1 AND expires_at > $2",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed =
        sqlx::query("DELETE FROM oauth_login_states WHERE state_hash = $1 AND expires_at > $2")
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
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)",
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
         WHERE sessions.token_hash = $1 AND sessions.expires_at > $2",
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
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
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
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
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
        "UPDATE cli_sessions SET revoked_at = $1
         WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL AND expires_at > $4",
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
    sqlx::query("DELETE FROM cli_authorization_requests WHERE expires_at <= $1")
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
            "INSERT INTO cli_authorization_requests
             (id, user_code, poll_secret_hash, approval_secret_hash, device_name, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT DO NOTHING",
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
) -> ApiResult<StatusCode> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let approved = sqlx::query(
        "UPDATE cli_authorization_requests
         SET approved_user_id = $1, approved_at = $2
         WHERE id = $3 AND approval_secret_hash = $4 AND expires_at > $5
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
    Ok(StatusCode::NO_CONTENT)
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
         WHERE id = $1 AND poll_secret_hash = $2",
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
        "UPDATE cli_authorization_requests SET completed_at = $1
         WHERE id = $2 AND completed_at IS NULL AND expires_at > $3 AND approved_user_id IS NOT NULL",
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
         WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
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
            "SELECT session_id FROM cli_used_refresh_tokens WHERE token_hash = $1",
        )
        .bind(&old_hash)
        .fetch_optional(&state.database)
        .await
        .map_err(database_error)?
        {
            sqlx::query(
                "UPDATE cli_sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
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
        "UPDATE cli_sessions SET refresh_token_hash = $1, last_used_at = $2
         WHERE id = $3 AND refresh_token_hash = $4 AND revoked_at IS NULL AND expires_at > $5",
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
    sqlx::query(
        "INSERT INTO cli_used_refresh_tokens (token_hash, session_id, used_at)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
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
    sqlx::query("UPDATE cli_sessions SET revoked_at = $1 WHERE refresh_token_hash = $2 AND revoked_at IS NULL")
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
         WHERE cli_access_tokens.token_hash = $1 AND cli_access_tokens.expires_at > $2
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
         WHERE sessions.token_hash = $1 AND sessions.expires_at > $2",
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
         WHERE id = $1 AND approval_secret_hash = $2",
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
    database: &DatabasePool,
    user_id: &str,
    device_name: &str,
    now: i64,
) -> ApiResult<CliTokens> {
    let session_id = Uuid::new_v4().to_string();
    let refresh_token = random_token();
    sqlx::query(
        "INSERT INTO cli_sessions
         (id, user_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
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
    database: &DatabasePool,
    session_id: &str,
    now: i64,
) -> ApiResult<String> {
    let access_token = random_token();
    sqlx::query("INSERT INTO cli_access_tokens (token_hash, session_id, expires_at, created_at) VALUES ($1, $2, $3, $4)")
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
    database: &DatabasePool,
    github_user: &GitHubUser,
    now: i64,
) -> ApiResult<String> {
    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, github_id, github_login, avatar_url, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)
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
    sqlx::query_scalar("SELECT id FROM users WHERE github_id = $1")
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

fn notary_directory_from_env() -> Result<NotaryDirectory> {
    if let Ok(value) = env::var("LLM_NOTARY_NOTARY_DIRECTORY_JSON")
        && !value.trim().is_empty()
    {
        let directory = parse_directory(value.as_bytes())
            .context("LLM_NOTARY_NOTARY_DIRECTORY_JSON is invalid")?;
        if let Ok(expected) = env::var("LLM_NOTARY_NOTARY_PUBLIC_KEY")
            && !directory
                .active()?
                .public_key
                .eq_ignore_ascii_case(expected.trim())
        {
            bail!("the active directory key does not match LLM_NOTARY_NOTARY_PUBLIC_KEY");
        }
        return Ok(directory);
    }
    let host = env::var("LLM_NOTARY_NOTARY_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("LLM_NOTARY_NOTARY_PORT")
        .unwrap_or_else(|_| "7047".to_owned())
        .parse::<u16>()
        .context("LLM_NOTARY_NOTARY_PORT must be a valid TCP port")?;
    let transport = env::var("LLM_NOTARY_NOTARY_TRANSPORT")
        .unwrap_or_else(|_| "tcp".to_owned())
        .parse::<NotaryTransport>()
        .context("LLM_NOTARY_NOTARY_TRANSPORT must be tcp or tls")?;
    let public_key = hex::decode(
        env::var("LLM_NOTARY_NOTARY_PUBLIC_KEY")
            .context("LLM_NOTARY_NOTARY_PUBLIC_KEY is required")?,
    )
    .context("LLM_NOTARY_NOTARY_PUBLIC_KEY must be hexadecimal")?;
    let key_id = key_id(&public_key);
    let directory = NotaryDirectory {
        format: DIRECTORY_FORMAT_V3.to_owned(),
        generation: env::var("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION")
            .unwrap_or_else(|_| "1".to_owned())
            .parse()
            .context("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION must be a u64")?,
        active_key_id: key_id.clone(),
        notaries: vec![NotaryDirectoryRecord {
            host,
            port,
            transport,
            key_id,
            public_key: hex::encode(public_key),
            status: NotaryKeyStatus::Active,
            valid_from_unix_ms: env::var("LLM_NOTARY_NOTARY_VALID_FROM_UNIX_MS")
                .unwrap_or_else(|_| "0".to_owned())
                .parse()
                .context("LLM_NOTARY_NOTARY_VALID_FROM_UNIX_MS must be a u64")?,
            valid_until_unix_ms: None,
            finalize_until_unix_ms: None,
        }],
    };
    directory.validate()?;
    Ok(directory)
}

#[cfg(test)]
mod test_database {
    use std::{ops::Deref, sync::Arc};

    use sqlx::{PgPool, postgres::PgPoolOptions};
    use testcontainers_modules::{
        postgres::Postgres,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };

    #[derive(Clone)]
    pub struct TestDatabase {
        pub pool: PgPool,
        _server: Arc<ContainerAsync<Postgres>>,
    }

    impl Deref for TestDatabase {
        type Target = PgPool;

        fn deref(&self) -> &Self::Target {
            &self.pool
        }
    }

    /// Creates an isolated PostgreSQL 17 container and applies exactly the
    /// production migration baseline. The container is removed when the
    /// associated test state is dropped.
    pub async fn fresh_database() -> TestDatabase {
        let server = Arc::new(
            Postgres::default()
                .with_tag("17.7-alpine")
                .start()
                .await
                .expect("start PostgreSQL test container"),
        );
        let postgres = server.as_ref();
        let host = postgres.get_host().await.expect("PostgreSQL test host");
        let port = postgres
            .get_host_port_ipv4(5432)
            .await
            .expect("PostgreSQL test port");
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("connect to isolated PostgreSQL test database");
        sqlx::migrate!("./migrations-postgres")
            .run(&pool)
            .await
            .expect("apply PostgreSQL test migrations");
        TestDatabase {
            pool,
            _server: server,
        }
    }
}

#[cfg(test)]
use test_database::fresh_database;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_shutdown_seconds_must_be_a_positive_integer() {
        assert_eq!(parse_idle_shutdown_secs("45").expect("valid duration"), 45);
        assert!(parse_idle_shutdown_secs("0").is_err());
        assert!(parse_idle_shutdown_secs("-1").is_err());
        assert!(parse_idle_shutdown_secs("soon").is_err());
    }

    #[test]
    fn observability_probes_do_not_extend_the_idle_window() {
        assert!(!counts_as_request_activity("/metrics"));
        assert!(!counts_as_request_activity("/api/healthz"));
        assert!(!counts_as_request_activity("/api/readyz"));
        assert!(counts_as_request_activity("/api/notary"));
    }

    #[test]
    fn request_activity_is_released_after_the_request_finishes() {
        let before = ACTIVE_REQUESTS.load(Ordering::Relaxed);
        let activity = RequestActivity::start();
        assert_eq!(ACTIVE_REQUESTS.load(Ordering::Relaxed), before + 1);
        drop(activity);
        assert_eq!(ACTIVE_REQUESTS.load(Ordering::Relaxed), before);
    }

    pub(super) fn directory_key() -> NotaryDirectory {
        let signing = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let key_id = key_id(&public_key);
        NotaryDirectory {
            format: DIRECTORY_FORMAT_V3.to_owned(),
            generation: 1,
            active_key_id: key_id.clone(),
            notaries: vec![NotaryDirectoryRecord {
                host: "notary.example.com".to_owned(),
                port: 7047,
                transport: NotaryTransport::Tcp,
                key_id,
                public_key: hex::encode(public_key),
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: 0,
                valid_until_unix_ms: None,
                finalize_until_unix_ms: None,
            }],
        }
    }

    #[tokio::test]
    async fn authorization_url_uses_the_exact_callback_and_state() {
        let state = AppState {
            database: PgPool::connect_lazy("postgres://postgres:postgres@localhost/postgres")
                .expect("lazy database"),
            _test_database: None,
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://llm-notary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            app_url: Url::parse("https://llm-notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            library_metadata: admission::MetadataService::from_env(),
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
            key == "redirect_uri"
                && value == "https://llm-notary.exalto.ai/api/auth/github/callback"
        }));
        assert!(!url.query_pairs().any(|(key, _)| key == "scope"));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn new_cli_session_is_usable_until_its_refresh_expiry() {
        let database = fresh_database().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'octo', 1, 1)",
        )
        .execute(&database.pool)
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
        .fetch_one(&database.pool)
        .await
        .expect("stored session");
        assert_eq!((created_at, last_used_at), (now, now));
        assert_eq!(expires_at, now + CLI_REFRESH_TOKEN_TTL_SECS);

        let refreshed = refresh_cli_tokens(
            State(AppState {
                database: database.pool.clone(),
                _test_database: Some(database),
                http: reqwest::Client::new(),
                github_client_id: "client-id".to_owned(),
                github_client_secret: "secret".to_owned(),
                callback_url: Url::parse("https://llm-notary.exalto.ai/api/auth/github/callback")
                    .expect("callback URL"),
                app_url: Url::parse("https://llm-notary.exalto.ai").expect("app URL"),
                secure_cookies: true,
                notary_directory: directory_key(),
                publish: publish::PublishService::disabled_for_test(),
                library_metadata: admission::MetadataService::from_env(),
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
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn web_users_can_list_and_revoke_only_their_cli_sessions() {
        let database = fresh_database().await;
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'one', 1, 1), ('user-2', 2, 'two', 1, 1)",
        )
        .execute(&database.pool)
        .await
        .expect("users");
        let now = match unix_timestamp() {
            Ok(now) => now,
            Err(_) => panic!("current time"),
        };
        let web_token = "web-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, $3)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .bind(now + SESSION_TTL_SECS)
        .bind(now)
        .execute(&database.pool)
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
            sqlx::query_scalar("SELECT id FROM cli_sessions WHERE refresh_token_hash = $1")
                .bind(sha256_hex(own.refresh_token.as_bytes()))
                .fetch_one(&database.pool)
                .await
                .expect("own CLI ID");
        let other_id: String =
            sqlx::query_scalar("SELECT id FROM cli_sessions WHERE refresh_token_hash = $1")
                .bind(sha256_hex(other.refresh_token.as_bytes()))
                .fetch_one(&database.pool)
                .await
                .expect("other CLI ID");
        let state = AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            callback_url: Url::parse("https://llm-notary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            app_url: Url::parse("https://llm-notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            library_metadata: admission::MetadataService::from_env(),
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
