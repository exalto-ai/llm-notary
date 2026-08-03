use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{MatchedPath, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use rand::RngCore;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::Duration as CookieDuration;
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use llm_notary_core::notary_directory::{
    NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus, NotaryTransport,
};
use llm_notary_core::sha256_hex;
use llm_notary_core::telemetry;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

mod admission;
mod config;
mod hosted_verifier;
mod intake;
pub mod migrate;
mod publish;
mod service_admission;
mod verify;

pub use config::{
    AdmissionConfig, AuthConfig, DatabaseConfig, MetadataConfig, NotaryDirectoryConfig,
    PlatformConfig, S3StorageConfig, StorageConfig, TierPolicy,
};

const SESSION_COOKIE: &str = "llm_notary_session";
const OAUTH_STATE_COOKIE: &str = "llm_notary_oauth_state";
const LOGIN_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const CLI_AUTHORIZATION_TTL_SECS: i64 = 10 * 60;
const CLI_ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const CLI_REFRESH_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;
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
    admission: Arc<AdmissionConfig>,
}

#[derive(Deserialize, ToSchema)]
struct GitHubCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, ToSchema)]
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

#[derive(Serialize, ToSchema)]
struct Health {
    status: &'static str,
}

#[derive(Serialize, ToSchema)]
struct PublicUser {
    id: String,
    github_login: String,
    avatar_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct MeResponse {
    user: PublicUser,
    plan: service_admission::ServicePlan,
    entitlements: service_admission::EffectiveEntitlements,
}

#[derive(Serialize, ToSchema)]
struct WebCliSession {
    id: String,
    device_name: String,
    created_at: i64,
    last_used_at: i64,
    expires_at: i64,
}

#[derive(Serialize, ToSchema)]
struct WebCliSessionsResponse {
    sessions: Vec<WebCliSession>,
}

#[derive(Deserialize, ToSchema)]
struct CreateCliAuthorization {
    device_name: String,
}

#[derive(Serialize, ToSchema)]
struct CliAuthorizationStarted {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
    poll_secret: String,
}

#[derive(Deserialize, ToSchema)]
struct ApprovalQuery {
    approval_secret: String,
}

#[derive(Serialize, ToSchema)]
struct ApprovalDetails {
    user_code: String,
    device_name: String,
    expires_at: i64,
}

#[derive(Serialize, ToSchema)]
struct CliTokens {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Deserialize, ToSchema)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Serialize, ToSchema)]
struct CliSessionResponse {
    device_name: String,
}

#[derive(Serialize, ToSchema)]
struct CliMeResponse {
    user: PublicUser,
    session: CliSessionResponse,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Serialize, ToSchema)]
struct NotaryDirectoryResponse {
    format: String,
    generation: u64,
    active_key_id: String,
    notaries: Vec<NotaryDirectoryRecordResponse>,
}

#[derive(Serialize, ToSchema)]
struct NotaryDirectoryRecordResponse {
    host: String,
    port: u16,
    transport: NotaryTransportResponse,
    key_id: String,
    public_key: String,
    status: NotaryKeyStatusResponse,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: Option<u64>,
    finalize_until_unix_ms: Option<u64>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum NotaryTransportResponse {
    Tcp,
    Tls,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum NotaryKeyStatusResponse {
    Active,
    Retiring,
    Retired,
    Revoked,
}

impl From<NotaryDirectory> for NotaryDirectoryResponse {
    fn from(directory: NotaryDirectory) -> Self {
        Self {
            format: directory.format,
            generation: directory.generation,
            active_key_id: directory.active_key_id,
            notaries: directory.notaries.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<NotaryDirectoryRecord> for NotaryDirectoryRecordResponse {
    fn from(record: NotaryDirectoryRecord) -> Self {
        Self {
            host: record.host,
            port: record.port,
            transport: match record.transport {
                NotaryTransport::Tcp => NotaryTransportResponse::Tcp,
                NotaryTransport::Tls => NotaryTransportResponse::Tls,
            },
            key_id: record.key_id,
            public_key: record.public_key,
            status: match record.status {
                NotaryKeyStatus::Active => NotaryKeyStatusResponse::Active,
                NotaryKeyStatus::Retiring => NotaryKeyStatusResponse::Retiring,
                NotaryKeyStatus::Retired => NotaryKeyStatusResponse::Retired,
                NotaryKeyStatus::Revoked => NotaryKeyStatusResponse::Revoked,
            },
            valid_from_unix_ms: record.valid_from_unix_ms,
            valid_until_unix_ms: record.valid_until_unix_ms,
            finalize_until_unix_ms: record.finalize_until_unix_ms,
        }
    }
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

    fn payment_required(message: &'static str) -> Self {
        Self {
            status: StatusCode::PAYMENT_REQUIRED,
            message,
        }
    }

    fn too_many_requests(message: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
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

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LLM Notary hosted platform API",
        version = "1.0.0",
        description = "Public website, account, CLI authorization, publication, and Library API for the hosted LLM Notary platform. This contract is separate from the loopback local administration API."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Hosted API health and discovery"),
        (name = "browser-auth", description = "GitHub-backed browser sessions"),
        (name = "cli-auth", description = "Local service authorization and CLI sessions"),
        (name = "notary-admission", description = "Hosted notary tickets and distributed leases"),
        (name = "verification", description = "Anonymous, retention-free portable package verification"),
        (name = "publication", description = "Authenticated publication intake"),
        (name = "library", description = "Public admitted traces and metadata")
    )
)]
struct HostedApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{
            ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme,
        };

        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "browserSession",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                    SESSION_COOKIE,
                    "HttpOnly hosted browser session cookie",
                ))),
            );
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some("Short-lived CLI access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "pollSecret",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-LLM-Notary-Poll-Secret",
                    "One-time secret returned when CLI authorization starts",
                ))),
            );
            components.add_security_scheme(
                "serviceBearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some("Dedicated notary-to-platform service credential"))
                        .build(),
                ),
            );
        }
    }
}

fn hosted_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(HostedApiDoc::openapi())
        .routes(routes!(health))
        .routes(routes!(readiness))
        .routes(routes!(notary))
        .routes(routes!(start_github_login))
        .routes(routes!(finish_github_login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(list_cli_sessions))
        .routes(routes!(revoke_web_cli_session))
        .routes(routes!(start_cli_authorization))
        .routes(routes!(cli_approval_details, approve_cli_authorization))
        .routes(routes!(complete_cli_authorization))
        .routes(routes!(refresh_cli_tokens))
        .routes(routes!(logout_cli_session))
        .routes(routes!(cli_me))
        .merge(publish::router())
        .merge(admission::router())
        .merge(verify::router())
        .merge(service_admission::router())
}

/// Returns the deterministic public hosted-platform contract.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    hosted_router().into_openapi()
}

/// Runs the private, stdin/stdout verifier subprocess used to enforce a hard
/// anonymous-verification timeout without retaining uploaded bytes.
#[doc(hidden)]
pub fn run_verification_worker() -> Result<()> {
    hosted_verifier::run_worker()
}

/// Runs the isolated verifier with the vendored private certificate authority.
/// This exists only behind `test-utils` for sanitized acceptance fixtures and
/// is deliberately a separate binary from the production worker.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub fn run_verification_fixture_worker() -> Result<()> {
    hosted_verifier::run_fixture_worker()
}

/// Runs the hosted LLM Notary platform API.
pub async fn run_api() -> Result<()> {
    dotenvy::dotenv().ok();
    let config = PlatformConfig::from_env()?;
    let _telemetry = telemetry::init("llm-notary-api")?;
    let state = AppState::from_config(&config).await?;
    let listen = config.listen;
    publish::spawn_cleanup(state.clone());
    admission::spawn(state.clone());
    let shutdown_rx = config.idle_shutdown_secs.map(|idle_shutdown_secs| {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        spawn_idle_shutdown(state.clone(), idle_shutdown_secs, shutdown_tx);
        shutdown_rx
    });
    let app: Router = hosted_router()
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(observe_http_request))
        .with_state(state)
        .into();
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
    async fn from_config(config: &PlatformConfig) -> Result<Self> {
        let publish = publish::PublishService::from_config(&config.storage)?;
        publish.validate().await?;
        let database = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect_with(config.database.connect_options.clone())
            .await
            .context("opening API database")?;
        Ok(Self {
            database,
            #[cfg(test)]
            _test_database: None,
            http: reqwest::Client::builder()
                .user_agent("LLM-Notary/0.1")
                .build()
                .context("building GitHub client")?,
            github_client_id: config.auth.github_client_id.clone(),
            github_client_secret: config.auth.github_client_secret.clone(),
            callback_url: config.auth.callback_url.clone(),
            secure_cookies: config.auth.app_url.scheme() == "https",
            app_url: config.auth.app_url.clone(),
            notary_directory: config.notary_directory.directory.clone(),
            publish,
            library_metadata: admission::MetadataService::from_config(config.metadata.as_ref()),
            admission: Arc::new(config.admission.clone()),
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

#[utoipa::path(
    get,
    path = "/api/notary",
    summary = "Get the signed notary directory",
    responses((status = 200, body = NotaryDirectoryResponse)),
    tag = "health"
)]
async fn notary(State(state): State<AppState>) -> Json<NotaryDirectoryResponse> {
    Json(state.notary_directory.into())
}

#[utoipa::path(
    get,
    path = "/api/healthz",
    summary = "Check API process health",
    responses((status = 200, body = Health)),
    tag = "health"
)]
async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

#[utoipa::path(
    get,
    path = "/api/readyz",
    summary = "Check database readiness",
    responses(
        (status = 200, body = Health),
        (status = 500, body = ErrorResponse)
    ),
    tag = "health"
)]
async fn readiness(State(state): State<AppState>) -> ApiResult<Json<Health>> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&state.database)
        .await
        .map_err(database_error)?;
    Ok(Json(Health { status: "ok" }))
}

#[utoipa::path(
    get,
    path = "/api/auth/github",
    summary = "Start GitHub browser sign-in",
    params(("return_to" = Option<String>, Query, description = "Allowed in-app hash route after sign-in")),
    responses(
        (status = 307, description = "Temporary redirect to GitHub", headers(("Location" = String), ("Set-Cookie" = String))),
        (status = 500, body = ErrorResponse)
    ),
    tag = "browser-auth"
)]
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
    let (plan, entitlements) = service_admission::account_plan(&state, &user.0).await?;
    Ok(Json(MeResponse {
        user: PublicUser {
            id: user.0,
            github_login: user.1,
            avatar_url: user.2,
        },
        plan,
        entitlements,
    }))
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

#[utoipa::path(
    get,
    path = "/api/cli/sessions",
    summary = "List the browser user's active CLI sessions",
    responses(
        (status = 200, body = WebCliSessionsResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    delete,
    path = "/api/cli/sessions/{session_id}",
    summary = "Revoke one of the browser user's CLI sessions",
    params(("session_id" = String, Path)),
    responses(
        (status = 204, description = "CLI session revoked"),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    post,
    path = "/api/cli/authorizations",
    summary = "Start CLI device authorization",
    request_body = CreateCliAuthorization,
    responses(
        (status = 200, body = CliAuthorizationStarted),
        (status = 400, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    post,
    path = "/api/cli/authorizations/{request_id}/approval",
    summary = "Approve a CLI device authorization",
    params(("request_id" = String, Path), ("approval_secret" = String, Query)),
    responses(
        (status = 204, description = "CLI device authorized"),
        (status = 401, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    post,
    path = "/api/cli/authorizations/{request_id}/token",
    summary = "Complete CLI device authorization",
    params(("request_id" = String, Path)),
    responses(
        (status = 200, body = CliTokens),
        (status = 401, body = ErrorResponse),
        (status = 410, body = ErrorResponse),
        (status = 428, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("pollSecret" = [])),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    post,
    path = "/api/cli/token",
    summary = "Rotate CLI access and refresh tokens",
    request_body = RefreshRequest,
    responses(
        (status = 200, body = CliTokens),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    post,
    path = "/api/cli/logout",
    summary = "Revoke a CLI session by refresh token",
    request_body = RefreshRequest,
    responses(
        (status = 204, description = "CLI session revoked"),
        (status = 500, body = ErrorResponse)
    ),
    tag = "cli-auth"
)]
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

#[utoipa::path(
    get,
    path = "/api/cli/me",
    summary = "Get the CLI access-token identity",
    responses(
        (status = 200, body = CliMeResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "cli-auth"
)]
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

pub(crate) async fn authenticated_web_user(
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

    pub(super) async fn blank_database() -> TestDatabase {
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
        TestDatabase {
            pool,
            _server: server,
        }
    }

    /// Creates an isolated PostgreSQL 17 container and applies exactly the
    /// production migration baseline. The container is removed when the
    /// associated test state is dropped.
    pub async fn fresh_database() -> TestDatabase {
        let database = blank_database().await;
        sqlx::migrate!("../../migrations-postgres")
            .run(&database.pool)
            .await
            .expect("apply PostgreSQL test migrations");
        database
    }
}

#[cfg(test)]
use test_database::fresh_database;

#[cfg(test)]
mod tests {
    use llm_notary_core::notary_directory::{
        DIRECTORY_FORMAT_V3, NotaryDirectoryRecord, NotaryKeyStatus, NotaryTransport, key_id,
    };

    use super::*;

    #[test]
    fn observability_probes_do_not_extend_the_idle_window() {
        assert!(!counts_as_request_activity("/metrics"));
        assert!(!counts_as_request_activity("/api/healthz"));
        assert!(!counts_as_request_activity("/api/readyz"));
        assert!(counts_as_request_activity("/api/notary"));
    }

    #[test]
    fn public_routes_and_openapi_are_registered_together() {
        let expected = [
            "DELETE /api/cli/sessions/{session_id}",
            "GET /api/auth/github",
            "GET /api/auth/github/callback",
            "GET /api/cli/authorizations/{request_id}/approval",
            "GET /api/cli/me",
            "GET /api/cli/sessions",
            "GET /api/healthz",
            "GET /api/me",
            "GET /api/me/publish-jobs",
            "GET /api/notary",
            "GET /api/public/collections/traces",
            "GET /api/public/traces/{trace_id}",
            "GET /api/public/traces/{trace_id}/trace.otlp.json",
            "GET /api/publish/jobs/{job_id}",
            "GET /api/readyz",
            "POST /api/auth/logout",
            "POST /api/cli/authorizations",
            "POST /api/cli/authorizations/{request_id}/approval",
            "POST /api/cli/authorizations/{request_id}/token",
            "POST /api/cli/logout",
            "POST /api/cli/token",
            "POST /api/public/traces/{trace_id}/events/download",
            "POST /api/verify",
            "POST /api/publish/jobs",
            "POST /api/publish/jobs/{job_id}/complete",
            "POST /api/internal/notary/admissions/redeem",
            "POST /api/internal/notary/leases/release",
            "POST /api/internal/notary/leases/renew",
            "POST /api/notary/admissions",
            "PUT /api/me/plan",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
        let document = serde_json::to_value(openapi_document()).expect("serialize OpenAPI");
        let paths = document["paths"].as_object().expect("OpenAPI paths");
        let mut actual = std::collections::BTreeSet::new();
        for (path, item) in paths {
            for method in ["get", "post", "put", "patch", "delete"] {
                if item.get(method).is_some() {
                    actual.insert(format!("{} {path}", method.to_uppercase()));
                }
            }
        }
        assert_eq!(actual, expected);
        assert!(!paths.contains_key("/metrics"));
        let upload_schema = &document["paths"]["/api/verify"]["post"]["requestBody"]["content"]
            [crate::intake::ARCHIVE_CONTENT_TYPE]["schema"];
        assert_eq!(
            upload_schema["$ref"],
            "#/components/schemas/TracePackageBody"
        );
        let upload_schema = &document["components"]["schemas"]["TracePackageBody"];
        assert_eq!(upload_schema["type"], "string");
        assert_eq!(upload_schema["format"], "binary");
    }

    #[tokio::test]
    async fn migration_from_0004_queues_legacy_objects_and_preserves_traces() {
        let database = super::test_database::blank_database().await;
        for migration in [
            include_str!("../../../migrations-postgres/0001_initial.sql"),
            include_str!("../../../migrations-postgres/0002_library_card_facts.sql"),
            include_str!("../../../migrations-postgres/0003_admitted_library_card_facts.sql"),
            include_str!("../../../migrations-postgres/0004_service_admission.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&database.pool)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('legacy-user', 1, 'legacy', 1, 1)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO publish_jobs (
                 id, user_id, idempotency_key, state, archive_format,
                 declared_size_bytes, declared_sha256, upload_object_key,
                 intake_object_key, upload_expires_at, created_at, updated_at,
                 actual_sha256, admitted_at, public_trace_object_key,
                 public_trace_size_bytes, public_trace_sha256,
                 public_stamp_object_key, public_stamp_size_bytes,
                 public_stamp_sha256, library_provider, library_host,
                 library_model, library_span_count, library_tool_use
             ) VALUES (
                 'legacy-job', 'legacy-user', 'legacy-idempotency', 'admitted', $1,
                 1, $2, 'legacy-upload', 'legacy-intake', 1, 1, 1, $2, 2,
                 'legacy-trace', 1, $3, 'legacy-stamp', 1, $4,
                 'OpenAI', 'api.openai.com', 'gpt-test', 1, FALSE
             )",
        )
        .bind(crate::intake::ARCHIVE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .execute(&database.pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0005_prepare_stamp_removal.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let legacy: (Option<String>, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT public_stamp_object_key, verified_at, source_package_sha256
             FROM publish_jobs WHERE id = 'legacy-job'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(legacy.0.as_deref(), Some("legacy-stamp"));
        assert_eq!(legacy.1, Some(2));
        assert_eq!(legacy.2.as_deref(), Some("a".repeat(64).as_str()));
        let queued_stamps: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM publication_object_cleanup WHERE artifact_kind = 'stamp'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            queued_stamps, 0,
            "stamp deletion belongs to contract migration"
        );
        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0006_remove_platform_stamp_contract.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let admitted: (Option<String>, Option<String>, Option<i64>) = sqlx::query_as(
            "SELECT public_trace_object_key, public_trace_sha256, verified_at
             FROM publish_jobs WHERE id = 'legacy-job'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(admitted.0.as_deref(), Some("legacy-trace"));
        assert_eq!(admitted.1.as_deref(), Some("b".repeat(64).as_str()));
        assert_eq!(admitted.2, Some(2));
        let cleanup: (String, Option<String>, String) = sqlx::query_as(
            "SELECT object_key, publication_id, artifact_kind
             FROM publication_object_cleanup WHERE object_key = 'legacy-stamp'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(cleanup.0, "legacy-stamp");
        assert_eq!(cleanup.1.as_deref(), Some("legacy-job"));
        assert_eq!(cleanup.2, "stamp");
        let legacy_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'publish_jobs'
               AND column_name LIKE 'public_stamp%'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(legacy_columns, 0);
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
            library_metadata: admission::MetadataService::disabled(),
            admission: Arc::new(AdmissionConfig::for_test()),
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
                library_metadata: admission::MetadataService::disabled(),
                admission: Arc::new(AdmissionConfig::for_test()),
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
            library_metadata: admission::MetadataService::disabled(),
            admission: Arc::new(AdmissionConfig::for_test()),
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
