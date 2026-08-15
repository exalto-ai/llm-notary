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
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::Duration as CookieDuration;
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use llm_notary_core::notary_directory::{
    NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus, NotaryTransport,
};
use llm_notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};
use llm_notary_core::sha256_hex;
use llm_notary_core::telemetry;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

mod admission;
mod api_keys;
mod authn;
mod billing;
mod config;
mod hosted_verifier;
mod intake;
pub mod migrate;
mod pagination;
mod publish;
mod service_admission;
mod verify;

pub use config::{
    AdmissionConfig, AdmissionPolicy, AuthConfig, BillingConfig, DatabaseConfig,
    NotaryDirectoryConfig, PlatformConfig, S3StorageConfig, StorageConfig, StripeConfig,
};

const SESSION_COOKIE: &str = "llm_notary_session";
const OAUTH_STATE_COOKIE: &str = "llm_notary_oauth_state";
const GOOGLE_PKCE_COOKIE: &str = "llm_notary_google_pkce";
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
    github_callback_url: Url,
    google_client_id: String,
    google_client_secret: String,
    google_callback_url: Url,
    app_url: Url,
    secure_cookies: bool,
    notary_directory: NotaryDirectory,
    publish: publish::PublishService,
    admission: Arc<AdmissionConfig>,
    billing: billing::BillingService,
}

#[derive(Deserialize, ToSchema)]
struct OAuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct OAuthLoginQuery {
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

#[derive(Deserialize)]
struct GoogleToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUser {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
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
    auth_provider: BrowserAuthProvider,
    display_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum BrowserAuthProvider {
    Github,
    Google,
}

impl BrowserAuthProvider {
    fn from_database(value: &str) -> ApiResult<Self> {
        match value {
            "github" => Ok(Self::Github),
            "google" => Ok(Self::Google),
            _ => Err(ApiError::internal(anyhow!(
                "database contains an invalid browser authentication provider"
            ))),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct AuthProvidersResponse {
    github: bool,
    google: bool,
}

#[derive(Serialize, ToSchema)]
struct MeResponse {
    user: PublicUser,
    billing: AccountBillingResponse,
    credits: service_admission::CreditSummary,
    notary_stats: NotaryStats,
    share_stats: ShareStats,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
struct AccountBillingResponse {
    service_plan: service_admission::ServicePlan,
    billing_status: service_admission::BillingStatus,
    purchase_mode: billing::BillingPurchaseMode,
    subscriptions_configured: bool,
    entitlements: service_admission::PlanEntitlements,
}

impl AccountBillingResponse {
    fn new(
        state: service_admission::AccountBillingState,
        purchase_mode: billing::BillingPurchaseMode,
        subscriptions_configured: bool,
        admission: &AdmissionConfig,
    ) -> Self {
        Self {
            service_plan: state.service_plan,
            billing_status: state.billing_status,
            purchase_mode,
            subscriptions_configured,
            entitlements: service_admission::plan_entitlements(admission, state.service_plan),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct ShareStats {
    total: i64,
    admitted: i64,
    in_progress: i64,
    stored_bytes: i64,
}

#[derive(Debug, Eq, PartialEq, Serialize, ToSchema)]
struct NotaryStats {
    /// Successfully completed capture sessions.
    captures: i64,
    /// Successfully completed finalization sessions.
    finalizations: i64,
}

async fn account_notary_stats(database: &DatabasePool, user_id: &str) -> ApiResult<NotaryStats> {
    let (captures, finalizations) = sqlx::query_as::<_, (i64, i64)>(
        "SELECT
             COUNT(*) FILTER (WHERE tickets.mode = 'capture')::BIGINT,
             COUNT(*) FILTER (WHERE tickets.mode = 'finalize')::BIGINT
         FROM notary_admission_tickets AS tickets
         JOIN notary_admission_leases AS leases
           ON leases.id = tickets.lease_id
          AND leases.subject_id = tickets.subject_id
          AND leases.mode = tickets.mode
         WHERE tickets.subject_id = $1
           AND leases.completion_outcome = 'completed'",
    )
    .bind(user_id)
    .fetch_one(database)
    .await
    .map_err(database_error)?;
    Ok(NotaryStats {
        captures,
        finalizations,
    })
}

#[derive(Serialize, ToSchema)]
struct WebCliSession {
    id: String,
    device_name: String,
    created_at: i64,
    last_used_at: i64,
    expires_at: i64,
}

#[derive(Deserialize, Serialize)]
struct CliSessionPagePosition {
    created_at: i64,
    id: String,
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
struct CliCredentialResponse {
    kind: authn::CredentialKind,
    id: String,
    name: String,
}

#[derive(Serialize, ToSchema)]
struct CliMeResponse {
    user: PublicUser,
    credential: CliCredentialResponse,
    session: Option<CliSessionResponse>,
    billing: AccountBillingResponse,
    credits: service_admission::CreditSummary,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: &'static str,
    message: &'static str,
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
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: message,
            message,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication required",
            message: "authentication required",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "insufficient_scope",
            message: "credential does not have the required scope",
        }
    }

    fn forbidden_message(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: message,
            message,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: message,
            message,
        }
    }

    fn gone(message: &'static str) -> Self {
        Self {
            status: StatusCode::GONE,
            code: message,
            message,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: message,
            message,
        }
    }

    fn too_many_requests(message: &'static str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: message,
            message,
        }
    }

    fn service_unavailable(message: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: message,
            message,
        }
    }

    fn pending() -> Self {
        Self {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: "authorization pending",
            message: "authorization pending",
        }
    }

    fn upstream() -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "identity provider sign-in failed",
            message: "identity provider sign-in failed",
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        tracing::error!(%error, "API request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal server error",
            message: "internal server error",
        }
    }

    fn coded(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorResponse {
                error: self.code,
                message: self.message,
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LLM Notary hosted platform API",
        version = "1.0.0",
        description = "Public website, account, CLI authorization, verified-session sharing, and Listed-share catalog API for the hosted LLM Notary platform. This contract is separate from the loopback local administration API."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Hosted API health and discovery"),
        (name = "browser-auth", description = "Google- or GitHub-backed browser sessions"),
        (name = "cli-auth", description = "Local service authorization and CLI sessions"),
        (name = "notary-admission", description = "Hosted notary tickets and distributed leases"),
        (name = "billing", description = "Stripe-hosted subscriptions and additional notarization purchases"),
        (name = "verification", description = "Anonymous, retention-free portable package verification"),
        (name = "sharing", description = "Authenticated share intake and stable direct links"),
        (name = "library", description = "Small catalog of Listed shares")
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
                        .description(Some(
                            "Short-lived CLI access token or stable scoped API key",
                        ))
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
        .routes(routes!(auth_providers))
        .routes(routes!(start_github_login))
        .routes(routes!(finish_github_login))
        .routes(routes!(start_google_login))
        .routes(routes!(finish_google_login))
        .routes(routes!(logout))
        .routes(routes!(me, delete_account))
        .routes(routes!(list_cli_sessions))
        .routes(routes!(revoke_web_cli_session))
        .routes(routes!(start_cli_authorization))
        .routes(routes!(cli_approval_details, approve_cli_authorization))
        .routes(routes!(complete_cli_authorization))
        .routes(routes!(refresh_cli_tokens))
        .routes(routes!(logout_cli_session))
        .routes(routes!(cli_me))
        .merge(api_keys::router())
        .merge(publish::router())
        .merge(admission::router())
        .merge(verify::router())
        .merge(service_admission::router())
        .merge(billing::router())
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
        if route.starts_with("/api/public/shares") {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
        }
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
        let http = reqwest::Client::builder()
            .user_agent("LLM-Notary/0.1")
            .build()
            .context("building hosted API HTTP client")?;
        let billing = billing::BillingService::from_config(
            &config.billing,
            &config.auth.app_url,
            http.clone(),
        )?;
        let database = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect_with(config.database.connect_options.clone())
            .await
            .context("opening API database")?;
        Ok(Self {
            database,
            #[cfg(test)]
            _test_database: None,
            http,
            github_client_id: config.auth.github_client_id.clone(),
            github_client_secret: config.auth.github_client_secret.clone(),
            github_callback_url: config.auth.github_callback_url.clone(),
            google_client_id: config.auth.google_client_id.clone(),
            google_client_secret: config.auth.google_client_secret.clone(),
            google_callback_url: config.auth.google_callback_url.clone(),
            secure_cookies: config.auth.app_url.scheme() == "https",
            app_url: config.auth.app_url.clone(),
            notary_directory: config.notary_directory.directory.clone(),
            publish,
            admission: Arc::new(config.admission.clone()),
            billing,
        })
    }

    fn authorization_url(&self, state: &str) -> Result<Url> {
        if self.github_client_id.is_empty() {
            return Err(anyhow!("GitHub OAuth is not configured"));
        }
        let mut url = Url::parse("https://github.com/login/oauth/authorize")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.github_client_id)
            .append_pair("redirect_uri", self.github_callback_url.as_str())
            .append_pair("state", state);
        Ok(url)
    }

    fn google_authorization_url(&self, state: &str, code_challenge: &str) -> Result<Url> {
        if self.google_client_id.is_empty() {
            return Err(anyhow!("Google OAuth is not configured"));
        }
        let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.google_client_id)
            .append_pair("redirect_uri", self.google_callback_url.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
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
    summary = "Get the versioned notary directory",
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
    path = "/api/auth/providers",
    summary = "List configured browser sign-in providers",
    responses((status = 200, body = AuthProvidersResponse)),
    tag = "browser-auth"
)]
async fn auth_providers(State(state): State<AppState>) -> Json<AuthProvidersResponse> {
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
async fn start_github_login(
    State(state): State<AppState>,
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
    sqlx::query("DELETE FROM oauth_login_states WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO oauth_login_states (state_hash, expires_at, return_to, provider)
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
async fn finish_github_login(
    State(state): State<AppState>,
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
        "SELECT return_to FROM oauth_login_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'github'",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed = sqlx::query(
        "DELETE FROM oauth_login_states
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
async fn start_google_login(
    State(state): State<AppState>,
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
    sqlx::query("DELETE FROM oauth_login_states WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
    let return_to = query
        .return_to
        .filter(|value| value.starts_with("#/authorize?"));
    sqlx::query(
        "INSERT INTO oauth_login_states (state_hash, expires_at, return_to, provider)
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
async fn finish_google_login(
    State(state): State<AppState>,
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
        "SELECT return_to FROM oauth_login_states
         WHERE state_hash = $1 AND expires_at > $2 AND provider = 'google'",
    )
    .bind(&state_hash)
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .flatten();
    let consumed = sqlx::query(
        "DELETE FROM oauth_login_states
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
    let user_id = upsert_google_user(&state.database, &google_user, now).await?;
    let session_token = issue_web_session(&state.database, &user_id, now).await?;

    Ok((
        jar.remove(state.expired_cookie(OAUTH_STATE_COOKIE))
            .remove(state.expired_cookie(GOOGLE_PKCE_COOKIE))
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
    let user = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        "SELECT users.id, users.display_name, identity.provider_display_name,
                identity.provider_avatar_url, identity.provider
         FROM sessions
         JOIN users ON users.id = sessions.user_id
         JOIN LATERAL (
             SELECT provider, provider_display_name, provider_avatar_url
             FROM user_identities
             WHERE user_id = users.id
             ORDER BY last_used_at DESC, id
             LIMIT 1
         ) AS identity ON TRUE
         WHERE sessions.token_hash = $1 AND sessions.expires_at > $2",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(now)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(ApiError::unauthorized)?;
    let credits = service_admission::account_access(&state, &user.0).await?;
    let billing = service_admission::account_billing_state(&state.database, &user.0).await?;
    let notary_stats = account_notary_stats(&state.database, &user.0).await?;
    let (total, admitted, in_progress, stored_bytes) = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT COUNT(*)::BIGINT,
                COUNT(*) FILTER (WHERE state = 'admitted')::BIGINT,
                COUNT(*) FILTER (
                    WHERE state IN ('uploading', 'queued', 'verifying')
                )::BIGINT,
                COALESCE(SUM(declared_size_bytes) FILTER (
                    WHERE state IN ('uploading', 'queued', 'verifying', 'admitted')
                ), 0)::BIGINT
         FROM publish_jobs WHERE user_id = $1",
    )
    .bind(&user.0)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(MeResponse {
        user: PublicUser {
            id: user.0,
            github_login: user.2,
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
async fn delete_account(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, StatusCode)> {
    let user = authenticated_web_user(&state, &jar).await?;
    let now = unix_timestamp()?;
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    sqlx::query(
        "INSERT INTO publication_object_cleanup
             (object_key, publication_id, artifact_kind, created_at)
         SELECT artifact.object_key, jobs.id, artifact.artifact_kind, $2
         FROM publish_jobs AS jobs
         CROSS JOIN LATERAL (
             VALUES
                 (jobs.upload_object_key, 'upload'),
                 (jobs.intake_object_key, 'intake'),
                 (jobs.public_trace_object_key, 'trace'),
                 (jobs.package_object_key, 'package')
         ) AS artifact(object_key, artifact_kind)
         WHERE jobs.user_id = $1 AND artifact.object_key IS NOT NULL
         ON CONFLICT (object_key) DO NOTHING",
    )
    .bind(&user.0)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user.0)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    transaction.commit().await.map_err(database_error)?;

    if state.publish.enabled() {
        let cleanup_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = publish::cleanup_publication_objects(&cleanup_state).await {
                tracing::error!(
                    status = %error.status,
                    error = error.message,
                    "cleaning up deleted account objects failed"
                );
            }
        });
    }
    Ok((
        jar.remove(state.expired_cookie(SESSION_COOKIE)),
        StatusCode::NO_CONTENT,
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
    params(("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 100), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = Page<WebCliSession>),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "cli-auth"
)]
async fn list_cli_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
    query: Result<Query<PageQuery>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Page<WebCliSession>>> {
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
        .map(|cursor| decode_cursor::<CliSessionPagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination::api_error)?;
    let sessions = sqlx::query_as::<_, (String, String, i64, i64, i64)>(
        "SELECT id, device_name, created_at, last_used_at, expires_at
         FROM cli_sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
           AND ($3::TEXT IS NULL OR (created_at, id) < ($4, $3))
         ORDER BY created_at DESC, id DESC
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
    .map(|session| WebCliSession {
        id: session.0,
        device_name: session.1,
        created_at: session.2,
        last_used_at: session.3,
        expires_at: session.4,
    })
    .collect();
    let page =
        Page::from_limit_plus_one(sessions, limit, &scope, |session| CliSessionPagePosition {
            created_at: session.created_at,
            id: session.id.clone(),
        })
        .map_err(pagination::api_error)?;
    Ok(Json(page))
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
        (status = 403, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("bearerAuth" = [])),
    tag = "cli-auth"
)]
async fn cli_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<CliMeResponse>> {
    let principal =
        authn::authenticated_principal(&state, &headers, authn::ApiScope::AccountRead).await?;
    let user = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        "SELECT users.id, users.display_name, identity.provider_display_name,
                identity.provider_avatar_url, identity.provider
         FROM users
         JOIN LATERAL (
             SELECT provider, provider_display_name, provider_avatar_url
             FROM user_identities
             WHERE user_id = users.id
             ORDER BY last_used_at DESC, id
             LIMIT 1
         ) AS identity ON TRUE
         WHERE users.id = $1",
    )
    .bind(&principal.user_id)
    .fetch_one(&state.database)
    .await
    .map_err(database_error)?;
    let session = (principal.credential_kind == authn::CredentialKind::CliSession).then(|| {
        CliSessionResponse {
            device_name: principal.credential_name.clone(),
        }
    });
    let credits = service_admission::account_access(&state, &principal.user_id).await?;
    let billing =
        service_admission::account_billing_state(&state.database, &principal.user_id).await?;
    Ok(Json(CliMeResponse {
        user: PublicUser {
            id: user.0,
            github_login: user.2,
            avatar_url: user.3,
            auth_provider: BrowserAuthProvider::from_database(&user.4)?,
            display_name: user.1,
        },
        credential: CliCredentialResponse {
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

pub(crate) async fn authenticated_web_user(
    state: &AppState,
    jar: &CookieJar,
) -> ApiResult<(String, String, Option<String>)> {
    let token = session_token(jar)?;
    let now = unix_timestamp()?;
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT users.id, identity.provider_display_name,
                identity.provider_avatar_url
         FROM sessions
         JOIN users ON users.id = sessions.user_id
         JOIN LATERAL (
             SELECT provider_display_name, provider_avatar_url
             FROM user_identities
             WHERE user_id = users.id
             ORDER BY last_used_at DESC, id
             LIMIT 1
         ) AS identity ON TRUE
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

async fn exchange_google_code(
    state: &AppState,
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

async fn fetch_google_user(state: &AppState, access_token: &str) -> ApiResult<GoogleUser> {
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
    github_user: &GitHubUser,
    now: i64,
) -> ApiResult<String> {
    let provider_subject = github_user.id.to_string();
    upsert_identity(
        database,
        "github",
        &provider_subject,
        Some(&github_user.login),
        github_user.avatar_url.as_deref(),
        now,
    )
    .await
}

async fn upsert_google_user(
    database: &DatabasePool,
    google_user: &GoogleUser,
    now: i64,
) -> ApiResult<String> {
    let email = google_user
        .email
        .as_deref()
        .ok_or_else(|| ApiError::forbidden_message("Google account email is not available"))?;
    let display_name = google_user
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    if google_user.sub.is_empty()
        || google_user.sub.len() > 255
        || email.is_empty()
        || email.len() > 320
        || display_name.is_some_and(|name| name.len() > 255)
        || google_user
            .picture
            .as_ref()
            .is_some_and(|picture| picture.len() > 2_048)
    {
        return Err(ApiError::upstream());
    }
    upsert_identity(
        database,
        "google",
        &google_user.sub,
        display_name,
        google_user.picture.as_deref(),
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
        "SELECT users.id, users.display_name,
                user_identities.provider_display_name
         FROM user_identities
         JOIN users ON users.id = user_identities.user_id
         WHERE user_identities.provider = $1
           AND user_identities.provider_subject = $2
         FOR UPDATE OF users, user_identities",
    )
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?;

    let user_id = if let Some((user_id, display_name, previous_provider_name)) = existing {
        let provider_display_name = provider_display_name.unwrap_or(&previous_provider_name);
        let account_display_name = if display_name == previous_provider_name {
            provider_display_name
        } else {
            &display_name
        };
        sqlx::query("UPDATE users SET display_name = $1, updated_at = $2 WHERE id = $3")
            .bind(account_display_name)
            .bind(now)
            .bind(&user_id)
            .execute(&mut *transaction)
            .await
            .map_err(database_error)?;
        sqlx::query(
            "UPDATE user_identities
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
        user_id
    } else {
        let user_id = Uuid::new_v4().to_string();
        let provider_display_name = provider_display_name
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{provider}-{}", &user_id[..12]));
        sqlx::query(
            "INSERT INTO users (id, display_name, created_at, updated_at)
             VALUES ($1, $2, $3, $3)",
        )
        .bind(&user_id)
        .bind(&provider_display_name)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        sqlx::query(
            "INSERT INTO user_identities
             (id, user_id, provider, provider_subject, provider_display_name,
              provider_avatar_url, created_at, updated_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_id)
        .bind(provider)
        .bind(provider_subject)
        .bind(&provider_display_name)
        .bind(provider_avatar_url)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        user_id
    };

    transaction.commit().await.map_err(database_error)?;
    Ok(user_id)
}

async fn issue_web_session(database: &DatabasePool, user_id: &str, now: i64) -> ApiResult<String> {
    let session_token = random_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(sha256_hex(session_token.as_bytes()))
    .bind(user_id)
    .bind(now + SESSION_TTL_SECS)
    .bind(now)
    .execute(database)
    .await
    .map_err(database_error)?;
    Ok(session_token)
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

    pub async fn database_through(target_version: i64) -> TestDatabase {
        let database = blank_database().await;
        let migrations = sqlx::migrate!("../../migrations-postgres");
        for migration in migrations
            .iter()
            .filter(|migration| migration.version <= target_version)
        {
            let mut transaction = database.pool.begin().await.expect("begin migration");
            sqlx::raw_sql(&migration.sql)
                .execute(&mut *transaction)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "apply PostgreSQL migration {} ({}): {error}",
                        migration.version, migration.description
                    )
                });
            transaction.commit().await.expect("commit migration");
        }
        database
    }
}

#[cfg(test)]
use test_database::fresh_database;

#[cfg(test)]
pub(crate) async fn insert_test_github_user(
    database: &DatabasePool,
    user_id: &str,
    provider_subject: i64,
    display_name: &str,
) {
    let mut transaction = database.begin().await.expect("begin test user insert");
    sqlx::query(
        "INSERT INTO users (id, display_name, created_at, updated_at)
         VALUES ($1, $2, 1, 1)",
    )
    .bind(user_id)
    .bind(display_name)
    .execute(&mut *transaction)
    .await
    .expect("insert test account");
    sqlx::query(
        "INSERT INTO user_identities
         (id, user_id, provider, provider_subject, provider_display_name,
          created_at, updated_at, last_used_at)
         VALUES ($1, $2, 'github', $3, $4, 1, 1, 1)",
    )
    .bind(format!("test-github-{provider_subject}"))
    .bind(user_id)
    .bind(provider_subject.to_string())
    .bind(display_name)
    .execute(&mut *transaction)
    .await
    .expect("insert test GitHub identity");
    transaction.commit().await.expect("commit test user insert");
}

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

    #[tokio::test]
    async fn account_notary_stats_count_only_completed_account_sessions() {
        let database = fresh_database().await;
        insert_test_github_user(&database, "user-1", 1, "User One").await;
        insert_test_github_user(&database, "user-2", 2, "User Two").await;
        sqlx::query(
            "INSERT INTO notary_admission_leases
                 (id, notary_instance_id, subject_id, credit_subject, access_pool, mode,
                  acquired_at, expires_at, released_at, terminal_state, completion_outcome)
             VALUES
                 ('capture-completed', 'notary-1', 'user-1', 'user:user-1', 'free',
                  'capture', 1, 2, 2, 'released', 'completed'),
                 ('finalize-completed', 'notary-1', 'user-1', 'user:user-1', 'free',
                  'finalize', 1, 2, 2, 'released', 'completed'),
                 ('capture-failed', 'notary-1', 'user-1', 'user:user-1', 'free',
                  'capture', 1, 2, 2, 'released', 'client_failed'),
                 ('finalize-active', 'notary-1', 'user-1', 'user:user-1', 'free',
                  'finalize', 1, 2, NULL, NULL, NULL),
                 ('other-capture', 'notary-1', 'user-2', 'user:user-2', 'free',
                  'capture', 1, 2, 2, 'released', 'completed')",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_admission_tickets
                 (token_hash, subject_id, credit_subject, access_pool, mode,
                  directory_generation, record_digest, requested_allowance_bytes,
                  max_attestable_http_bytes, max_frame_bytes, max_private_chunk_bytes,
                  max_private_chunk_commitments, issued_at, expires_at, consumed_at, lease_id)
             VALUES
                 ('ticket-capture-completed', 'user-1', 'user:user-1', 'free', 'capture',
                  1, NULL, 1, 1, 1, 1, 1, 1, 2, 1, 'capture-completed'),
                 ('ticket-finalize-completed', 'user-1', 'user:user-1', 'free', 'finalize',
                  1, $1, 1, 1, 1, 1, 1, 1, 2, 1, 'finalize-completed'),
                 ('ticket-capture-failed', 'user-1', 'user:user-1', 'free', 'capture',
                  1, NULL, 1, 1, 1, 1, 1, 1, 2, 1, 'capture-failed'),
                 ('ticket-finalize-active', 'user-1', 'user:user-1', 'free', 'finalize',
                  1, $2, 1, 1, 1, 1, 1, 1, 2, 1, 'finalize-active'),
                 ('ticket-other-capture', 'user-2', 'user:user-2', 'free', 'capture',
                  1, NULL, 1, 1, 1, 1, 1, 1, 2, 1, 'other-capture')",
        )
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .execute(&database.pool)
        .await
        .unwrap();

        assert_eq!(
            account_notary_stats(&database, "user-1").await.unwrap(),
            NotaryStats {
                captures: 1,
                finalizations: 1,
            }
        );
    }

    #[test]
    fn public_routes_and_openapi_are_registered_together() {
        let expected = [
            "DELETE /api/cli/sessions/{session_id}",
            "DELETE /api/me",
            "DELETE /api/me/api-keys/{api_key_id}",
            "GET /api/auth/google",
            "GET /api/auth/google/callback",
            "GET /api/auth/github",
            "GET /api/auth/github/callback",
            "GET /api/auth/providers",
            "GET /api/cli/authorizations/{request_id}/approval",
            "GET /api/cli/me",
            "GET /api/cli/sessions",
            "GET /api/healthz",
            "GET /api/me",
            "GET /api/me/api-keys",
            "GET /api/me/billing/purchases",
            "GET /api/me/billing/purchases/{purchase_id}",
            "GET /api/me/credits/history",
            "GET /api/me/shares",
            "GET /api/me/credit-offers",
            "GET /api/notary",
            "GET /api/public/shares",
            "GET /api/public/shares/{share_id}",
            "GET /api/public/shares/{share_id}/package.llmtrace",
            "GET /api/public/shares/{share_id}/trace.otlp.json",
            "GET /api/shares/{share_id}",
            "PATCH /api/shares/{share_id}",
            "GET /api/readyz",
            "POST /api/auth/logout",
            "POST /api/billing/stripe/webhook",
            "POST /api/cli/authorizations",
            "POST /api/cli/authorizations/{request_id}/approval",
            "POST /api/cli/authorizations/{request_id}/token",
            "POST /api/cli/logout",
            "POST /api/cli/token",
            "POST /api/me/api-keys",
            "POST /api/me/billing/checkout-sessions",
            "POST /api/me/billing/portal-sessions",
            "POST /api/me/billing/subscription-checkout-sessions",
            "POST /api/verify",
            "POST /api/shares",
            "POST /api/shares/{share_id}/complete",
            "POST /api/public/shares/{share_id}/reports",
            "POST /api/internal/notary/admissions/redeem",
            "POST /api/internal/notary/leases/release",
            "POST /api/internal/notary/leases/renew",
            "POST /api/me/credit-offers/{offer_id}/claim",
            "POST /api/notary/admissions",
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
        let settings_patch = &document["paths"]["/api/shares/{share_id}"]["patch"];
        for status in ["400", "403", "429"] {
            assert!(settings_patch["responses"].get(status).is_some());
        }
        assert_eq!(
            document["components"]["schemas"]["UpdateShareSettings"]["properties"]["expires_in_days"]
                ["maximum"],
            365
        );
        assert_eq!(
            document["components"]["schemas"]["CreateShareReport"]["properties"]["message"]["maxLength"],
            500
        );
    }

    #[tokio::test]
    async fn forward_migrations_remove_package_less_shares_after_preserving_compatibility() {
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
        let period_start: i64 =
            sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM date_trunc('month', now()))::BIGINT")
                .fetch_one(&database.pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO notary_finalization_credit_ledger
             (budget_subject, account_id, record_digest, allowance_bytes, period_start, created_at)
             VALUES
             ('user:legacy-user', 'legacy-user', $1, 1048576, $3, $3),
             ('public', NULL, $2, 2048, $3, $3)",
        )
        .bind("d".repeat(64))
        .bind("e".repeat(64))
        .bind(period_start)
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

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0008_share_visibility_and_packages.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let legacy_share: (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<i64>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT visibility, provider, provider_host, model,
                    package_object_key, package_size_bytes, package_sha256
             FROM publish_jobs WHERE id = 'legacy-job'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(legacy_share.0, "listed");
        assert_eq!(legacy_share.1, "OpenAI");
        assert_eq!(legacy_share.2, "api.openai.com");
        assert_eq!(legacy_share.3, "gpt-test");
        assert_eq!(legacy_share.4, None);
        assert_eq!(legacy_share.5, None);
        assert_eq!(legacy_share.6, None);
        let removed_contracts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = current_schema()
               AND table_name IN (
                   'publication_metadata',
                   'publication_activity_events',
                   'library_metadata_usage'
               )",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(removed_contracts, 0);
        let removed_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'publish_jobs'
               AND column_name IN (
                   'library_provider', 'library_host', 'library_model',
                   'library_span_count', 'library_tool_use', 'source_package_sha256'
               )",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(removed_columns, 0);

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0009_credit_grants_and_ip_subjects.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0010_restore_service_plan_rollback_compat.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0011_share_library_previews.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let previews: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT library_input_preview, library_output_preview
             FROM publish_jobs WHERE id = 'legacy-job'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(previews, (None, None));
        let accounting: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
                  FROM notary_credit_grants WHERE credit_subject = 'user:legacy-user'),
                 (SELECT COALESCE(SUM(allowance_bytes), 0)::BIGINT
                  FROM notary_credit_debits WHERE credit_subject = 'user:legacy-user'),
                 (SELECT COALESCE(SUM(allocations.amount_bytes), 0)::BIGINT
                  FROM notary_credit_debit_allocations AS allocations
                  JOIN notary_credit_debits AS debits ON debits.id = allocations.debit_id
                  WHERE debits.credit_subject = 'user:legacy-user')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(accounting, (640 << 20, 1 << 20, 1 << 20));
        let public: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM notary_credit_grants WHERE credit_subject = 'public'),
                 (SELECT COUNT(*) FROM notary_credit_grants WHERE credit_subject LIKE 'public:v%')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(public, (1, 0));
        let compatibility_plan: String =
            sqlx::query_scalar("SELECT service_plan FROM users WHERE id = 'legacy-user'")
                .fetch_one(&database.pool)
                .await
                .unwrap();
        assert_eq!(compatibility_plan, "free");
        let compatibility_ledger: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(allowance_bytes), 0)::BIGINT
             FROM notary_finalization_credit_ledger",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(compatibility_ledger, (2, (1 << 20) + 2048));
        sqlx::query(
            "INSERT INTO notary_admission_tickets
             (token_hash, subject_id, access_pool, mode, directory_generation,
              requested_allowance_bytes, session_timeout_secs, max_attestable_http_bytes,
              max_frame_bytes, max_private_chunk_bytes, max_private_chunk_commitments,
              issued_at, expires_at)
             VALUES ('legacy-ticket', NULL, 'public', 'capture', 1,
                     1, 300, 1, 1, 1, 1, 1, 2)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let compatibility_subject: String = sqlx::query_scalar(
            "SELECT credit_subject FROM notary_admission_tickets
             WHERE token_hash = 'legacy-ticket'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(compatibility_subject, "public");

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0012_remove_package_less_shares.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let legacy_share_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM publish_jobs WHERE id = 'legacy-job'")
                .fetch_one(&database.pool)
                .await
                .unwrap();
        assert_eq!(legacy_share_count, 0);
        let cleanup: Vec<(String, String)> = sqlx::query_as(
            "SELECT object_key, artifact_kind
             FROM publication_object_cleanup
             WHERE publication_id = 'legacy-job'
             ORDER BY object_key",
        )
        .fetch_all(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            cleanup,
            vec![
                ("legacy-intake".to_owned(), "intake".to_owned()),
                ("legacy-stamp".to_owned(), "stamp".to_owned()),
                ("legacy-trace".to_owned(), "trace".to_owned()),
                ("legacy-upload".to_owned(), "upload".to_owned()),
            ]
        );

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0025_require_retained_share_packages.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        let missing_package = sqlx::query(
            "INSERT INTO publish_jobs (
                 id, user_id, idempotency_key, state, archive_format,
                 declared_size_bytes, declared_sha256, upload_object_key,
                 intake_object_key, upload_expires_at, created_at, updated_at,
                 actual_sha256, admitted_at, public_trace_object_key,
                 public_trace_size_bytes, public_trace_sha256,
                 provider, provider_host, model
             ) VALUES (
                 'invalid-retention', 'legacy-user', 'invalid-retention', 'admitted', $1,
                 1, $2, 'invalid-upload', 'invalid-intake', 1, 1, 1, $2, 2,
                 'invalid-trace', 1, $3, 'OpenAI', 'api.openai.com', 'gpt-test'
             )",
        )
        .bind(crate::intake::ARCHIVE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .execute(&database.pool)
        .await
        .unwrap_err();
        assert!(
            missing_package
                .to_string()
                .contains("publish_jobs_admitted_share_facts")
        );
        sqlx::query(
            "INSERT INTO publish_jobs (
                 id, user_id, idempotency_key, state, archive_format,
                 declared_size_bytes, declared_sha256, upload_object_key,
                 intake_object_key, upload_expires_at, created_at, updated_at,
                 actual_sha256, admitted_at, public_trace_object_key,
                 public_trace_size_bytes, public_trace_sha256,
                 provider, provider_host, model, package_object_key,
                 package_size_bytes, package_sha256, public_package_safety_version
             ) VALUES (
                 'retained-package', 'legacy-user', 'retained-package', 'admitted', $1,
                 1, $2, 'retained-upload', 'retained-intake', 1, 1, 1, $2, 2,
                 'retained-trace', 1, $3, 'OpenAI', 'api.openai.com', 'gpt-test',
                 'retained-package', 1, $4, 'llm-notary/public-package-safety/v1'
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
            "../../../migrations-postgres/0013_account_deletion_cascades.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM users WHERE id = 'legacy-user'")
            .execute(&database.pool)
            .await
            .unwrap();
        let credit_rows: (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM notary_credit_grants
                  WHERE credit_subject = 'user:legacy-user'),
                 (SELECT COUNT(*) FROM notary_credit_debits
                  WHERE credit_subject = 'user:legacy-user'),
                 (SELECT COUNT(*)
                  FROM notary_credit_debit_allocations AS allocations
                  JOIN notary_credit_debits AS debits ON debits.id = allocations.debit_id
                  WHERE debits.credit_subject = 'user:legacy-user')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(credit_rows, (0, 0, 0));
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
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .expect("Google callback URL"),
            app_url: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
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
            key == "redirect_uri" && value == "https://notary.exalto.ai/api/auth/github/callback"
        }));
        assert!(!url.query_pairs().any(|(key, _)| key == "scope"));

        let google = state
            .google_authorization_url("google-state", "pkce-challenge")
            .expect("Google authorization URL");
        assert_eq!(
            google.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        assert_eq!(google.path(), "/o/oauth2/v2/auth");
        for (key, expected) in [
            ("client_id", "google-client-id"),
            (
                "redirect_uri",
                "https://notary.exalto.ai/api/auth/google/callback",
            ),
            ("response_type", "code"),
            ("scope", "openid email profile"),
            ("state", "google-state"),
            ("code_challenge", "pkce-challenge"),
            ("code_challenge_method", "S256"),
        ] {
            assert!(
                google
                    .query_pairs()
                    .any(|(name, value)| name == key && value == expected),
                "missing {key}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn google_identity_uses_sub_and_does_not_retain_email() {
        let database = fresh_database().await;
        let google_user = GoogleUser {
            sub: "google-subject-123".to_owned(),
            email: Some("person@example.com".to_owned()),
            email_verified: Some(true),
            name: Some("Example Person".to_owned()),
            picture: Some("https://example.com/avatar.png".to_owned()),
        };
        let first = upsert_google_user(&database.pool, &google_user, 10)
            .await
            .expect("create Google user");
        let second = upsert_google_user(&database.pool, &google_user, 20)
            .await
            .expect("refresh Google user");
        assert_eq!(first, second);
        let row = sqlx::query_as::<_, (String, String, String, Option<String>, i64, i64)>(
            "SELECT users.display_name, user_identities.provider_subject,
                    user_identities.provider_display_name,
                    user_identities.provider_avatar_url,
                    users.updated_at, user_identities.last_used_at
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = $1 AND user_identities.provider = 'google'",
        )
        .bind(&first)
        .fetch_one(&database.pool)
        .await
        .expect("stored Google identity");
        assert_eq!(row.0, "Example Person");
        assert_eq!(row.1, "google-subject-123");
        assert_eq!(row.2, "Example Person");
        assert_eq!(row.3.as_deref(), Some("https://example.com/avatar.png"));
        assert_eq!((row.4, row.5), (20, 20));
        let retained_email_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name IN ('users', 'user_identities')
               AND column_name IN ('email', 'provider_email')",
        )
        .fetch_one(&database.pool)
        .await
        .expect("inspect identity schema");
        assert_eq!(retained_email_columns, 0);

        let session_token = issue_web_session(
            &database.pool,
            &first,
            unix_timestamp().expect("current timestamp"),
        )
        .await
        .expect("issue Google web session");
        let state = AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .expect("GitHub callback URL"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .expect("Google callback URL"),
            app_url: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let response = me(
            State(state),
            CookieJar::new().add(Cookie::new(SESSION_COOKIE, session_token)),
        )
        .await
        .expect("load Google-backed account")
        .0;
        assert_eq!(response.user.auth_provider, BrowserAuthProvider::Google);
        assert_eq!(response.user.display_name, "Example Person");
        assert_eq!(response.user.github_login, "Example Person");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn provider_neutral_identity_migration_backfills_and_dual_writes() {
        let database = super::test_database::blank_database().await;
        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0001_initial.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users
             (id, github_id, github_login, avatar_url, created_at, updated_at)
             VALUES ('legacy-user', 41, 'legacy-login', 'https://example.test/old', 1, 2)",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0016_provider_neutral_identities.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();

        let display_name: String =
            sqlx::query_scalar("SELECT display_name FROM users WHERE id = 'legacy-user'")
                .fetch_one(&database.pool)
                .await
                .unwrap();
        assert_eq!(display_name, "legacy-login");
        let identity: (String, String, String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT id, user_id, provider, provider_display_name,
                    provider_avatar_url, last_used_at
             FROM user_identities
             WHERE provider = 'github' AND provider_subject = '41'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            identity,
            (
                "identity-github-41".to_owned(),
                "legacy-user".to_owned(),
                "github".to_owned(),
                "legacy-login".to_owned(),
                Some("https://example.test/old".to_owned()),
                2,
            )
        );

        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('new-user', 42, 'new-login', 3, 3)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let new_profile: (String, String) = sqlx::query_as(
            "SELECT users.display_name, user_identities.provider_display_name
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = 'new-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            new_profile,
            ("new-login".to_owned(), "new-login".to_owned())
        );

        sqlx::query(
            "UPDATE users
             SET github_login = 'renamed-login',
                 avatar_url = 'https://example.test/new',
                 updated_at = 4
             WHERE id = 'legacy-user'",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let updated: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT users.display_name, user_identities.provider_display_name,
                    user_identities.provider_avatar_url, user_identities.last_used_at
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = 'legacy-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            updated,
            (
                "renamed-login".to_owned(),
                "renamed-login".to_owned(),
                Some("https://example.test/new".to_owned()),
                4,
            )
        );

        sqlx::query("UPDATE users SET display_name = 'Custom name' WHERE id = 'legacy-user'")
            .execute(&database.pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE users
             SET github_login = 'renamed-again', updated_at = 5
             WHERE id = 'legacy-user'",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let customized: (String, String) = sqlx::query_as(
            "SELECT users.display_name, user_identities.provider_display_name
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = 'legacy-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            customized,
            ("Custom name".to_owned(), "renamed-again".to_owned())
        );

        sqlx::query("DELETE FROM users WHERE id = 'legacy-user'")
            .execute(&database.pool)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_identities WHERE user_id = 'legacy-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn provider_identity_cutover_uses_new_authority_and_preserves_rollback_compatibility() {
        let database = super::test_database::database_through(17).await;
        let github_user = GitHubUser {
            id: 51,
            login: "first-login".to_owned(),
            avatar_url: Some("https://example.test/first".to_owned()),
        };

        let user_id = upsert_user(&database.pool, &github_user, 10).await.unwrap();
        let profile: (
            String,
            String,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT users.display_name,
                    user_identities.provider_display_name,
                    user_identities.provider_avatar_url,
                    users.github_id, users.github_login, users.avatar_url
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = $1 AND user_identities.provider = 'github'",
        )
        .bind(&user_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            profile,
            (
                "first-login".to_owned(),
                "first-login".to_owned(),
                Some("https://example.test/first".to_owned()),
                Some(51),
                Some("first-login".to_owned()),
                Some("https://example.test/first".to_owned()),
            )
        );

        let renamed = GitHubUser {
            id: 51,
            login: "renamed-login".to_owned(),
            avatar_url: Some("https://example.test/renamed".to_owned()),
        };
        assert_eq!(
            upsert_user(&database.pool, &renamed, 11).await.unwrap(),
            user_id
        );
        let renamed_profile: (String, String, Option<String>) = sqlx::query_as(
            "SELECT users.display_name, user_identities.provider_display_name,
                    users.github_login
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = $1 AND user_identities.provider = 'github'",
        )
        .bind(&user_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            renamed_profile,
            (
                "renamed-login".to_owned(),
                "renamed-login".to_owned(),
                Some("renamed-login".to_owned()),
            )
        );

        sqlx::query("UPDATE users SET display_name = 'Custom name' WHERE id = $1")
            .bind(&user_id)
            .execute(&database.pool)
            .await
            .unwrap();
        let renamed_again = GitHubUser {
            id: 51,
            login: "renamed-again".to_owned(),
            avatar_url: None,
        };
        upsert_user(&database.pool, &renamed_again, 12)
            .await
            .unwrap();
        let customized: (String, String, Option<String>) = sqlx::query_as(
            "SELECT users.display_name, user_identities.provider_display_name,
                    users.github_login
             FROM users
             JOIN user_identities ON user_identities.user_id = users.id
             WHERE users.id = $1 AND user_identities.provider = 'github'",
        )
        .bind(&user_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            customized,
            (
                "Custom name".to_owned(),
                "renamed-again".to_owned(),
                Some("renamed-again".to_owned()),
            )
        );

        sqlx::query(
            "INSERT INTO users
             (id, github_id, github_login, avatar_url, created_at, updated_at)
             VALUES ('old-replica-user', 52, 'old-replica', NULL, 20, 20)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let mirrored_identity: (String, String) = sqlx::query_as(
            "SELECT provider_subject, provider_display_name
             FROM user_identities WHERE user_id = 'old-replica-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            mirrored_identity,
            ("52".to_owned(), "old-replica".to_owned())
        );

        let concurrent_user = GitHubUser {
            id: 53,
            login: "concurrent".to_owned(),
            avatar_url: None,
        };
        let (first, second) = tokio::join!(
            upsert_user(&database.pool, &concurrent_user, 30),
            upsert_user(&database.pool, &concurrent_user, 30),
        );
        assert_eq!(first.unwrap(), second.unwrap());
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM user_identities
                  WHERE provider = 'github' AND provider_subject = '53'),
                 (SELECT COUNT(*) FROM users
                  WHERE id IN (SELECT user_id FROM user_identities
                               WHERE provider = 'github' AND provider_subject = '53'))",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(counts, (1, 1));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn provider_identity_cleanup_reconciles_and_preserves_account_ownership() {
        let database = super::test_database::database_through(17).await;
        insert_test_github_user(&database.pool, "durable-user", 61, "durable").await;
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ('durable-session', 'durable-user', 100, 1)",
        )
        .execute(&database.pool)
        .await
        .unwrap();

        sqlx::query(
            "DELETE FROM user_identities
             WHERE user_id = 'durable-user' AND provider = 'github'",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        let error = sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0018_remove_legacy_github_identity.sql"
        ))
        .execute(&database.pool)
        .await
        .expect_err("cleanup must reject an account without its identity");
        assert!(error.to_string().contains("accounts are not reconciled"));

        sqlx::query(
            "INSERT INTO user_identities
             (id, user_id, provider, provider_subject, provider_display_name,
              created_at, updated_at, last_used_at)
             VALUES ('restored-identity', 'durable-user', 'github', '61',
                     'durable', 1, 1, 1)",
        )
        .execute(&database.pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../migrations-postgres/0018_remove_legacy_github_identity.sql"
        ))
        .execute(&database.pool)
        .await
        .unwrap();

        let account: (String, String, String) = sqlx::query_as(
            "SELECT users.id, users.display_name, sessions.user_id
             FROM users JOIN sessions ON sessions.user_id = users.id
             WHERE users.id = 'durable-user'",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            account,
            (
                "durable-user".to_owned(),
                "durable".to_owned(),
                "durable-user".to_owned(),
            )
        );

        let legacy_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'users'
               AND column_name IN ('github_id', 'github_login', 'avatar_url')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(legacy_columns, 0);
        let compatibility_triggers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_trigger
             WHERE NOT tgisinternal
               AND tgname IN (
                   'users_prepare_provider_neutral_profile_on_insert',
                   'users_prepare_provider_neutral_profile_on_github_login_update',
                   'users_sync_github_identity_on_insert',
                   'users_sync_github_identity_on_update',
                   'user_identities_sync_github_legacy_on_insert',
                   'user_identities_sync_github_legacy_on_update'
               )",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(compatibility_triggers, 0);
        let compatibility_functions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
             FROM pg_proc
             JOIN pg_namespace ON pg_namespace.oid = pg_proc.pronamespace
             WHERE pg_namespace.nspname = current_schema()
               AND pg_proc.proname IN (
                   'prepare_provider_neutral_user_profile',
                   'sync_github_user_identity',
                   'sync_github_identity_to_legacy_user'
               )",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(compatibility_functions, 0);

        sqlx::query("DELETE FROM users WHERE id = 'durable-user'")
            .execute(&database.pool)
            .await
            .unwrap();
        let remaining: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM user_identities
                  WHERE user_id = 'durable-user'),
                 (SELECT COUNT(*) FROM sessions
                  WHERE user_id = 'durable-user')",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(remaining, (0, 0));
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn new_cli_session_is_usable_until_its_refresh_expiry() {
        let database = fresh_database().await;
        insert_test_github_user(&database.pool, "user-1", 1, "octo").await;

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
                github_callback_url: Url::parse(
                    "https://notary.exalto.ai/api/auth/github/callback",
                )
                .expect("callback URL"),
                google_client_id: "google-client-id".to_owned(),
                google_client_secret: "google-secret".to_owned(),
                google_callback_url: Url::parse(
                    "https://notary.exalto.ai/api/auth/google/callback",
                )
                .expect("Google callback URL"),
                app_url: Url::parse("https://notary.exalto.ai").expect("app URL"),
                secure_cookies: true,
                notary_directory: directory_key(),
                publish: publish::PublishService::disabled_for_test(),
                admission: Arc::new(AdmissionConfig::for_test()),
                billing: billing::BillingService::disabled_for_test(),
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
        insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        insert_test_github_user(&database.pool, "user-2", 2, "two").await;
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
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .expect("Google callback URL"),
            app_url: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = || CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));

        let sessions =
            match list_cli_sessions(State(state.clone()), jar(), Ok(Query(PageQuery::default())))
                .await
            {
                Ok(sessions) => sessions.0.items,
                Err(_) => panic!("list CLI sessions"),
            };
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, own_id);

        let revoked =
            revoke_web_cli_session(State(state.clone()), jar(), Path(own_id.clone())).await;
        assert!(matches!(revoked, Ok(StatusCode::NO_CONTENT)));
        let sessions =
            match list_cli_sessions(State(state.clone()), jar(), Ok(Query(PageQuery::default())))
                .await
            {
                Ok(sessions) => sessions.0.items,
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

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn cli_session_pagination_is_stable_when_last_used_changes() {
        let database = fresh_database().await;
        insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        let now = unix_timestamp().expect("current time");
        let web_token = "web-session-pagination";
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
        for (device, created_at) in [("Newest", now), ("Middle", now - 1), ("Oldest", now - 2)] {
            issue_cli_session(&database, "user-1", device, created_at)
                .await
                .expect("CLI session");
        }
        let oldest_id: String =
            sqlx::query_scalar("SELECT id FROM cli_sessions WHERE device_name = 'Oldest'")
                .fetch_one(&database.pool)
                .await
                .expect("oldest session ID");
        let state = AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .expect("callback URL"),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .expect("Google callback URL"),
            app_url: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = || CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));

        let first = list_cli_sessions(
            State(state.clone()),
            jar(),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: None,
            })),
        )
        .await
        .expect("first page")
        .0;
        assert_eq!(first.items[0].device_name, "Newest");
        let cursor = first.next_cursor.expect("second page cursor");

        sqlx::query("UPDATE cli_sessions SET last_used_at = $1 WHERE id = $2")
            .bind(now + 100)
            .bind(&oldest_id)
            .execute(&state.database)
            .await
            .expect("refresh oldest session");

        let second = list_cli_sessions(
            State(state.clone()),
            jar(),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: Some(cursor),
            })),
        )
        .await
        .expect("second page")
        .0;
        assert_eq!(second.items[0].device_name, "Middle");
        let third = list_cli_sessions(
            State(state),
            jar(),
            Ok(Query(PageQuery {
                limit: Some(1),
                cursor: second.next_cursor,
            })),
        )
        .await
        .expect("third page")
        .0;
        assert_eq!(third.items[0].id, oldest_id);
        assert!(third.next_cursor.is_none());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn deleting_an_account_cascades_database_rows_and_queues_every_artifact() {
        let database = fresh_database().await;
        let pool = database.pool.clone();
        let web_token = "delete-web-session";
        insert_test_github_user(&pool, "delete-user", 44, "delete-me").await;
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'delete-user', 4102444800, 1)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cli_sessions
             (id, user_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
             VALUES ('delete-device', 'delete-user', 'Test device', 'delete-refresh', 1, 1, 4102444800)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO api_keys
             (id, display_prefix, user_id, name, secret_hash, scopes, created_at)
             VALUES ('delete-key', 'llmn_v1_delete', 'delete-user', 'Test key', $1,
                     ARRAY['account:read']::TEXT[], 1)",
        )
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO publish_jobs
             (id, user_id, idempotency_key, state, visibility, archive_format,
              declared_size_bytes, declared_sha256, upload_object_key, intake_object_key,
              upload_expires_at, created_at, updated_at, admitted_at,
              public_trace_object_key, public_trace_size_bytes, public_trace_sha256,
              provider, provider_host, model, package_object_key, package_size_bytes,
              package_sha256, public_package_safety_version)
             VALUES
             ('delete-trace', 'delete-user', 'delete-idempotency', 'admitted', 'listed', $1,
              1, $2, 'delete-upload', 'delete-intake', 2, 1, 1, 1,
              'delete-public-trace', 1, $3, 'openai', 'api.openai.com', 'gpt-test',
              'delete-package', 1, $4, 'llm-notary/public-package-safety/v1')",
        )
        .bind(crate::intake::ARCHIVE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_credit_grants
             (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind,
              source_reference, idempotency_key, created_at, available_at, display_label)
             VALUES ('delete-grant', 'user:delete-user', 'delete-user', 'notarization', 100, 'promotion',
                     'delete-grant', 'delete-grant', 1, 1, 'Test grant')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_credit_debits
             (id, credit_subject, account_id, credit_kind, record_digest, allowance_bytes, created_at)
             VALUES ('delete-debit', 'user:delete-user', 'delete-user', 'notarization', $1, 40, 1)",
        )
        .bind("d".repeat(64))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notary_credit_debit_allocations
             (debit_id, grant_id, amount_bytes, allocation_order)
             VALUES ('delete-debit', 'delete-grant', 40, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let state = AppState {
            database: pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://notary.exalto.ai/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://notary.exalto.ai/api/auth/google/callback")
                .unwrap(),
            app_url: Url::parse("https://notary.exalto.ai").unwrap(),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));
        let (_, status) = delete_account(State(state.clone()), jar).await.unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let remaining: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM users WHERE id = 'delete-user'),
                 (SELECT COUNT(*) FROM sessions WHERE user_id = 'delete-user'),
                 (SELECT COUNT(*) FROM cli_sessions WHERE user_id = 'delete-user'),
                 (SELECT COUNT(*) FROM api_keys WHERE user_id = 'delete-user'),
                 (SELECT COUNT(*) FROM publish_jobs WHERE user_id = 'delete-user'),
                 (SELECT COUNT(*) FROM notary_credit_grants WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM notary_credit_debit_allocations)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, (0, 0, 0, 0, 0, 0, 0));
        let queued: Vec<(String, String)> = sqlx::query_as(
            "SELECT object_key, artifact_kind FROM publication_object_cleanup
             WHERE publication_id = 'delete-trace' ORDER BY object_key",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            queued,
            vec![
                ("delete-intake".to_owned(), "intake".to_owned()),
                ("delete-package".to_owned(), "package".to_owned()),
                ("delete-public-trace".to_owned(), "trace".to_owned()),
                ("delete-upload".to_owned(), "upload".to_owned()),
            ]
        );
    }
}
