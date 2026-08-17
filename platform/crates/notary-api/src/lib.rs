use std::{future::Future, sync::Arc, time::Instant};

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
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::Duration as CookieDuration;
use tracing::Instrument as _;
use url::Url;
use uuid::Uuid;

use notary_core::pagination::{CursorScope, Page, PageQuery, decode_cursor};
use notary_core::registry::Registry;
use notary_core::sha256_hex;
use notary_core::telemetry;
use opentelemetry::global;
use opentelemetry_http::HeaderExtractor;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

mod account;
mod admissions;
mod api_keys;
mod auth;
mod billing;
mod browser_auth;
mod config;
mod credits;
mod devices;
pub mod migrate;
mod pagination;
mod registry;
mod traces;
mod verification;

#[cfg(test)]
use account::{NotaryStats, account_notary_stats, delete_account, me};
#[cfg(test)]
use browser_auth::{BrowserAuthProvider, GoogleUser, issue_web_session, upsert_google_user};
#[cfg(test)]
use devices::{
    RefreshRequest, issue_device_session, list_devices, refresh_device_tokens,
    revoke_web_device_session,
};

pub use config::{
    AdmissionTierLimits, BillingConfig, BrowserAuthConfig, DatabaseConfig, NotaryAdmissionConfig,
    NotaryApiConfig, RegistryConfig, S3TraceStorageConfig, StripeConfig, TraceStorageConfig,
};

const SESSION_COOKIE: &str = "notary_session";
const OAUTH_STATE_COOKIE: &str = "notary_oauth_state";
const GOOGLE_PKCE_COOKIE: &str = "notary_google_pkce";
const LOGIN_TTL_SECS: i64 = 10 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const DEVICE_AUTHORIZATION_TTL_SECS: i64 = 10 * 60;
const DEVICE_ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const DEVICE_REFRESH_TOKEN_TTL_SECS: i64 = 90 * 24 * 60 * 60;
type DatabasePool = PgPool;

#[derive(Clone)]
pub struct NotaryApiState {
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
    public_origin: Url,
    secure_cookies: bool,
    registry: Registry,
    traces: traces::owner::TraceService,
    admission: Arc<NotaryAdmissionConfig>,
    billing: billing::BillingService,
}

#[derive(Serialize, ToSchema)]
struct Health {
    status: &'static str,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: &'static str,
    message: &'static str,
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
        description = "Public website, account, Device authorization, verified-session sharing, and Listed-share catalog API for the hosted LLM Notary platform. This contract is separate from the loopback local administration API."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Hosted API health and discovery"),
        (name = "browser-auth", description = "Google- or GitHub-backed browser sessions"),
        (name = "cli-auth", description = "Local service authorization and Device sessions"),
        (name = "notary-admission", description = "One-operation hosted notary admission tickets"),
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
                            "Short-lived Device access token or stable scoped API key",
                        ))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "pollSecret",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-Notary-Poll-Secret",
                    "One-time secret returned when Device authorization starts",
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

fn hosted_router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::with_openapi(HostedApiDoc::openapi())
        .routes(routes!(health))
        .routes(routes!(readiness))
        .merge(registry::router())
        .merge(browser_auth::router())
        .merge(account::router())
        .merge(devices::router())
        .merge(api_keys::router())
        .merge(traces::owner::router())
        .merge(traces::public::router())
        .merge(verification::api::router())
        .merge(credits::router())
        .merge(admissions::router())
        .merge(billing::router())
}

/// Returns the deterministic public hosted-platform contract.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    hosted_router().into_openapi()
}

/// Runs the private stdin/stdout verifier used by both anonymous verification
/// and hosted Trace admission without retaining uploaded bytes.
#[doc(hidden)]
pub fn run_verification_worker() -> Result<()> {
    verification::worker::run_worker()
}

/// Runs the isolated verifier with the vendored private certificate authority.
/// This exists only behind `test-utils` for sanitized acceptance fixtures and
/// is deliberately a separate binary from the production worker.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub fn run_verification_fixture_worker() -> Result<()> {
    verification::worker::run_fixture_worker()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotaryApiCommand {
    Serve,
    Migrate,
    VerificationWorker,
    Help,
    Version,
}

/// Strict process argument decoder for the single `notary-api` executable.
pub struct NotaryApiArgs {
    command: NotaryApiCommand,
}

impl NotaryApiArgs {
    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::args_os().skip(1))
    }

    fn parse(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Self> {
        let arguments = arguments.into_iter().collect::<Vec<_>>();
        let command = match arguments.as_slice() {
            [command] if command == "serve" => NotaryApiCommand::Serve,
            [command] if command == "migrate" => NotaryApiCommand::Migrate,
            [command] if command == "verification-worker" => NotaryApiCommand::VerificationWorker,
            [help] if help == "--help" || help == "-h" || help == "help" => NotaryApiCommand::Help,
            [version] if version == "--version" || version == "-V" => NotaryApiCommand::Version,
            [command, help]
                if (command == "serve" || command == "migrate")
                    && (help == "--help" || help == "-h") =>
            {
                NotaryApiCommand::Help
            }
            _ => {
                anyhow::bail!("invalid arguments; run `notary-api --help` for usage")
            }
        };
        Ok(Self { command })
    }

    pub async fn run(self) -> Result<()> {
        match self.command {
            NotaryApiCommand::Serve => {
                dotenvy::dotenv().ok();
                let config = NotaryApiConfig::from_env()?;
                let _telemetry = telemetry::init("notary-api")?;
                describe_platform_metrics();
                serve(config, shutdown_signal()).await
            }
            NotaryApiCommand::Migrate => migrate::run_migrations().await,
            NotaryApiCommand::VerificationWorker => run_verification_worker(),
            NotaryApiCommand::Help => {
                println!(
                    "Hosted Notary platform API\n\nUsage: notary-api <COMMAND>\n\nCommands:\n  serve    Serve HTTP and run background workers\n  migrate  Apply PostgreSQL migrations\n  help     Print help"
                );
                Ok(())
            }
            NotaryApiCommand::Version => {
                println!("notary-api {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}

/// Constructs and validates every hosted API dependency.
pub async fn build_state(config: &NotaryApiConfig) -> Result<NotaryApiState> {
    NotaryApiState::from_config(config).await
}

/// Builds the exact OpenAPI-backed hosted application.
pub fn router(state: NotaryApiState) -> Router {
    hosted_router()
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(observe_http_request))
        .with_state(state)
        .into()
}

/// Serves HTTP and awaits the Trace verification and cleanup workers on the
/// same graceful-shutdown signal.
pub async fn serve<F>(config: NotaryApiConfig, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listen = config.listen;
    let state = build_state(&config).await?;
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(traces::owner::run_cleanup_worker(
        state.clone(),
        shutdown_rx.clone(),
    ));
    workers.spawn(admissions::run_recovery_worker(
        state.clone(),
        shutdown_rx.clone(),
    ));
    workers.spawn(traces::worker::run_worker(state, shutdown_rx));
    let worker_shutdown = shutdown_tx.clone();
    tracing::info!(%listen, "Notary platform API listening");
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        let _ = worker_shutdown.send(true);
        verification::process::shutdown_all().await;
    })
    .await;
    let _ = shutdown_tx.send(true);
    while let Some(worker) = workers.join_next().await {
        worker.context("hosted API worker task failed")?;
    }
    result.context("serving hosted API")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn describe_platform_metrics() {
    metrics::describe_counter!(
        "notary_api_trace_verifications_total",
        "Hosted Trace verification attempts by outcome"
    );
    metrics::describe_histogram!(
        "notary_api_trace_verification_duration_seconds",
        "End-to-end hosted Trace verification duration"
    );
    metrics::describe_histogram!(
        "notary_api_trace_package_bytes",
        "Hosted Trace package sizes admitted for verification"
    );
    metrics::describe_gauge!(
        "notary_api_trace_verification_queue_depth",
        "Hosted Traces waiting for verification"
    );
    metrics::describe_gauge!(
        "notary_api_trace_verification_oldest_queued_seconds",
        "Age of the oldest queued hosted Trace"
    );
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
            "notary_api_http_requests_total",
            "method" => method.clone(),
            "route" => route.clone(),
            "status" => status.clone()
        )
        .increment(1);
        metrics::histogram!(
            "notary_api_http_request_duration_seconds",
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

impl NotaryApiState {
    async fn from_config(config: &NotaryApiConfig) -> Result<Self> {
        let trace_service = traces::owner::TraceService::from_config(&config.storage)?;
        trace_service.validate().await?;
        let http = reqwest::Client::builder()
            .user_agent("notary-api/0.1")
            .build()
            .context("building hosted API HTTP client")?;
        let billing = billing::BillingService::from_config(
            &config.billing,
            &config.public_origin,
            http.clone(),
        )?;
        let database = PgPoolOptions::new()
            .max_connections(config.database.max_connections)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO notary_api, public")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(config.database.connect_options.clone())
            .await
            .context("opening API database")?;
        Ok(Self {
            database,
            #[cfg(test)]
            _test_database: None,
            http,
            github_client_id: config.browser_auth.github_client_id.clone(),
            github_client_secret: config.browser_auth.github_client_secret.clone(),
            github_callback_url: config.browser_auth.github_callback_url.clone(),
            google_client_id: config.browser_auth.google_client_id.clone(),
            google_client_secret: config.browser_auth.google_client_secret.clone(),
            google_callback_url: config.browser_auth.google_callback_url.clone(),
            secure_cookies: config.public_origin.scheme() == "https",
            public_origin: config.public_origin.clone(),
            registry: config.registry.registry.clone(),
            traces: trace_service,
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
async fn readiness(State(state): State<NotaryApiState>) -> ApiResult<Json<Health>> {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&state.database)
        .await
        .map_err(database_error)?;
    Ok(Json(Health { status: "ok" }))
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

fn random_secret(prefix: &str) -> String {
    format!("{prefix}{}", random_token())
}

fn typed_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

fn user_code() -> String {
    let mut bytes = [0_u8; 4];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "{:02X}{:02X}-{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
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
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO notary_api, public")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
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
        sqlx::migrate!("../../migrations")
            .run(&database.pool)
            .await
            .expect("apply PostgreSQL test migrations");
        database
    }
}

#[cfg(test)]
use test_database::fresh_database;

#[cfg(test)]
pub(crate) async fn insert_test_github_user(
    database: &DatabasePool,
    account_id: &str,
    provider_subject: i64,
    display_name: &str,
) {
    let mut transaction = database.begin().await.expect("begin test user insert");
    sqlx::query(
        "INSERT INTO accounts (account_id, display_name, created_at, updated_at)
         VALUES ($1, $2, 1, 1)",
    )
    .bind(account_id)
    .bind(display_name)
    .execute(&mut *transaction)
    .await
    .expect("insert test account");
    sqlx::query(
        "INSERT INTO account_identities
         (identity_id, account_id, provider, provider_subject, provider_display_name,
          created_at, updated_at, last_used_at)
         VALUES ($1, $2, 'github', $3, $4, 1, 1, 1)",
    )
    .bind(format!("test-github-{provider_subject}"))
    .bind(account_id)
    .bind(provider_subject.to_string())
    .bind(display_name)
    .execute(&mut *transaction)
    .await
    .expect("insert test GitHub identity");
    transaction.commit().await.expect("commit test user insert");
}

#[cfg(test)]
mod tests {
    use notary_core::registry::{
        NotaryKeyStatus, NotaryTransport, REGISTRY_FORMAT, RegistryRecord, key_id, parse_registry,
    };

    use super::*;

    #[test]
    fn single_executable_exposes_only_the_public_serve_and_migrate_commands() {
        let parse = |arguments: &[&str]| {
            NotaryApiArgs::parse(arguments.iter().map(std::ffi::OsString::from))
                .map(|arguments| arguments.command)
        };
        assert_eq!(parse(&["serve"]).unwrap(), NotaryApiCommand::Serve);
        assert_eq!(parse(&["migrate"]).unwrap(), NotaryApiCommand::Migrate);
        assert_eq!(
            parse(&["verification-worker"]).unwrap(),
            NotaryApiCommand::VerificationWorker
        );
        assert_eq!(parse(&["--help"]).unwrap(), NotaryApiCommand::Help);
        assert!(parse(&[]).is_err());
        assert!(parse(&["serve", "unexpected"]).is_err());
        assert!(parse(&["--verification-worker"]).is_err());
        assert!(parse(&["verification-worker", "--help"]).is_err());
    }

    pub(super) fn test_registry() -> Registry {
        let signing = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let key_id = key_id(&public_key);
        Registry {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 1,
            active_key_id: key_id.clone(),
            notaries: vec![RegistryRecord {
                name: "Test notary".to_owned(),
                operator: "Exalto".to_owned(),
                host: "notary.example.com".to_owned(),
                port: 7047,
                transport: NotaryTransport::Tcp,
                key_id,
                public_key: hex::encode(public_key),
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: 0,
                valid_until_unix_ms: None,
                notarize_until_unix_ms: None,
            }],
        }
    }

    #[test]
    fn hosted_registry_response_is_the_canonical_runtime_contract() {
        let response = registry::RegistryResponse::from(test_registry());
        let encoded = serde_json::to_vec(&response).unwrap();
        let registry = parse_registry(&encoded).unwrap();

        assert_eq!(registry.format, REGISTRY_FORMAT);
        assert_eq!(registry.notaries[0].name, "Test notary");
        assert_eq!(registry.notaries[0].operator, "Exalto");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn baseline_schema_is_canonical_and_contains_no_retired_surface() {
        let database = fresh_database().await;
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema = 'notary_api' ORDER BY table_name",
        )
        .fetch_all(&database.pool)
        .await
        .unwrap();
        assert_eq!(
            tables,
            vec![
                "account_billing_profiles",
                "account_identities",
                "accounts",
                "admission_tickets",
                "admitted_operations",
                "api_keys",
                "billing_purchases",
                "billing_subscription_checkouts",
                "billing_subscription_disputes",
                "billing_subscriptions",
                "browser_oauth_states",
                "browser_sessions",
                "credit_adjustments",
                "credit_debit_allocations",
                "credit_debits",
                "credit_grants",
                "device_access_tokens",
                "device_authorizations",
                "device_refresh_replays",
                "devices",
                "public_trace_rate_limits",
                "storage_cleanup_queue",
                "stripe_webhook_events",
                "trace_access_change_limits",
                "trace_reports",
                "traces",
                "verification_leases",
            ]
        );

        let retired: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema IN ('public', 'notary_api')
               AND table_name IN (
                   'users', 'sessions', 'cli_sessions', 'publish_jobs',
                   'publication_metadata', 'publication_activity_events',
                   'library_metadata_usage', 'notary_admission_tickets'
               )",
        )
        .fetch_one(&database.pool)
        .await
        .unwrap();
        assert_eq!(retired, 0);

        let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&database.pool)
            .await
            .unwrap();
        assert_eq!(migration_count, 1);
    }

    #[tokio::test]
    async fn account_notary_stats_count_only_completed_account_operations() {
        let database = fresh_database().await;
        insert_test_github_user(&database, "user-1", 1, "User One").await;
        insert_test_github_user(&database, "user-2", 2, "User Two").await;
        sqlx::query(
            "INSERT INTO admitted_operations
                 (operation_id, ticket_token_hash, notary_instance_id, account_id, credit_subject,
                  admission_tier, mode, record_digest, notarization_allowance_bytes,
                  max_attestable_http_bytes, admitted_at, activation_deadline, activated_at,
                  terminal_outcome,
                  settled_authenticated_bytes, settled_at)
             VALUES
                 ('capture-completed', $1, 'notary-1', 'user-1', 'account:user-1',
                  'free', 'capture', NULL, NULL, 1000, 1, 1, 1, 'completed', 100, 2),
                 ('notarization-completed', $2, 'notary-1', 'user-1', 'account:user-1',
                  'free', 'notarization', $7, 200, 1000, 1, 1, 1, 'completed', 200, 2),
                 ('capture-client-failed', $3, 'notary-1', 'user-1', 'account:user-1',
                  'free', 'capture', NULL, NULL, 1000, 1, 1, 1, 'client_failed', 50, 2),
                 ('capture-unsettled', $4, 'notary-1', 'user-1', 'account:user-1',
                  'free', 'capture', NULL, NULL, 1000, 1, 1, 1, NULL, NULL, NULL),
                 ('notarization-service-failed', $5, 'notary-1', 'user-1', 'account:user-1',
                  'free', 'notarization', $8, 300, 1000, 1, 1, 1, 'service_failed', 0, 2),
                 ('other-capture-completed', $6, 'notary-1', 'user-2', 'account:user-2',
                  'free', 'capture', NULL, NULL, 1000, 1, 1, 1, 'completed', 100, 2)",
        )
        .bind("1".repeat(64))
        .bind("2".repeat(64))
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .bind("6".repeat(64))
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .execute(&database.pool)
        .await
        .unwrap();

        assert_eq!(
            account_notary_stats(&database, "user-1").await.unwrap(),
            NotaryStats {
                captures: 1,
                notarizations: 1,
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
            "POST /api/internal/notary/operations/settle",
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
        assert!(!paths.contains_key("/api/internal/notary/leases/renew"));
        assert!(!paths.contains_key("/api/internal/notary/leases/release"));
        let upload_schema = &document["paths"]["/api/verify"]["post"]["requestBody"]["content"]
            [crate::traces::storage::ARCHIVE_CONTENT_TYPE]["schema"];
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
    async fn authorization_url_uses_the_exact_callback_and_state() {
        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
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
            "SELECT accounts.display_name, account_identities.provider_subject,
                    account_identities.provider_display_name,
                    account_identities.provider_avatar_url,
                    accounts.updated_at, account_identities.last_used_at
             FROM accounts
             JOIN account_identities ON account_identities.account_id = accounts.account_id
             WHERE accounts.account_id = $1 AND account_identities.provider = 'google'",
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
               AND table_name IN ('accounts', 'account_identities')
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
        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let response = me(
            State(state),
            CookieJar::new().add(Cookie::new(SESSION_COOKIE, session_token)),
        )
        .await
        .expect("load Google-backed account")
        .0;
        assert_eq!(response.account.auth_provider, BrowserAuthProvider::Google);
        assert_eq!(response.account.display_name, "Example Person");
        assert_eq!(response.account.provider_display_name, "Example Person");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn device_refresh_rotation_records_replay_and_revokes_the_chain() {
        let database = fresh_database().await;
        insert_test_github_user(&database.pool, "user-1", 1, "octo").await;

        let now = match unix_timestamp() {
            Ok(now) => now,
            Err(_) => panic!("current time"),
        };
        let tokens = match issue_device_session(&database, "user-1", "Test Device", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("Device session"),
        };
        let (created_at, last_used_at, expires_at) = sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT created_at, last_used_at, expires_at FROM devices",
        )
        .fetch_one(&database.pool)
        .await
        .expect("stored session");
        assert_eq!((created_at, last_used_at), (now, now));
        assert_eq!(expires_at, now + DEVICE_REFRESH_TOKEN_TTL_SECS);

        let original_refresh_token = tokens.refresh_token;
        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let refreshed = refresh_device_tokens(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: original_refresh_token.clone(),
            }),
        )
        .await;
        let refreshed = match refreshed {
            Ok(refreshed) => refreshed,
            Err(_) => panic!("new session refreshes"),
        };
        assert!(!refreshed.0.access_token.is_empty());

        let replay = refresh_device_tokens(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: original_refresh_token,
            }),
        )
        .await;
        let replay = match replay {
            Ok(_) => panic!("a rotated refresh token must be rejected"),
            Err(error) => error,
        };
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        let revoked_at: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM devices WHERE device_name = 'Test Device'")
                .fetch_one(&state.database)
                .await
                .expect("load replay-revoked Device");
        assert!(revoked_at.is_some());
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn web_users_can_list_and_revoke_only_their_devices() {
        let database = fresh_database().await;
        insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        insert_test_github_user(&database.pool, "user-2", 2, "two").await;
        let now = match unix_timestamp() {
            Ok(now) => now,
            Err(_) => panic!("current time"),
        };
        let web_token = "web-session";
        sqlx::query(
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, $3)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .bind(now + SESSION_TTL_SECS)
        .bind(now)
        .execute(&database.pool)
        .await
        .expect("web session");
        let own = match issue_device_session(&database, "user-1", "Own Device", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("own Device session"),
        };
        let other = match issue_device_session(&database, "user-2", "Other Device", now).await {
            Ok(tokens) => tokens,
            Err(_) => panic!("other Device session"),
        };
        let own_id: String =
            sqlx::query_scalar("SELECT device_id FROM devices WHERE refresh_token_hash = $1")
                .bind(sha256_hex(own.refresh_token.as_bytes()))
                .fetch_one(&database.pool)
                .await
                .expect("own Device ID");
        let other_id: String =
            sqlx::query_scalar("SELECT device_id FROM devices WHERE refresh_token_hash = $1")
                .bind(sha256_hex(other.refresh_token.as_bytes()))
                .fetch_one(&database.pool)
                .await
                .expect("other Device ID");
        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = || CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));

        let sessions = match list_devices(
            State(state.clone()),
            jar(),
            Ok(Query(PageQuery::default())),
        )
        .await
        {
            Ok(sessions) => sessions.0.items,
            Err(_) => panic!("list Device sessions"),
        };
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, own_id);

        let revoked =
            revoke_web_device_session(State(state.clone()), jar(), Path(own_id.clone())).await;
        assert!(matches!(revoked, Ok(StatusCode::NO_CONTENT)));
        let sessions = match list_devices(
            State(state.clone()),
            jar(),
            Ok(Query(PageQuery::default())),
        )
        .await
        {
            Ok(sessions) => sessions.0.items,
            Err(_) => panic!("list Device sessions after revoke"),
        };
        assert!(sessions.is_empty());

        let cross_account = revoke_web_device_session(State(state), jar(), Path(other_id)).await;
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
    async fn device_session_pagination_is_stable_when_last_used_changes() {
        let database = fresh_database().await;
        insert_test_github_user(&database.pool, "user-1", 1, "one").await;
        let now = unix_timestamp().expect("current time");
        let web_token = "web-session-pagination";
        sqlx::query(
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
             VALUES ($1, 'user-1', $2, $3)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .bind(now + SESSION_TTL_SECS)
        .bind(now)
        .execute(&database.pool)
        .await
        .expect("web session");
        for (device, created_at) in [("Newest", now), ("Middle", now - 1), ("Oldest", now - 2)] {
            issue_device_session(&database, "user-1", device, created_at)
                .await
                .expect("Device session");
        }
        let oldest_id: String =
            sqlx::query_scalar("SELECT device_id FROM devices WHERE device_name = 'Oldest'")
                .fetch_one(&database.pool)
                .await
                .expect("oldest session ID");
        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").expect("app URL"),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = || CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));

        let first = list_devices(
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

        sqlx::query("UPDATE devices SET last_used_at = $1 WHERE device_id = $2")
            .bind(now + 100)
            .bind(&oldest_id)
            .execute(&state.database)
            .await
            .expect("refresh oldest session");

        let second = list_devices(
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
        let third = list_devices(
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
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
             VALUES ($1, 'delete-user', 4102444800, 1)",
        )
        .bind(sha256_hex(web_token.as_bytes()))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO devices
             (device_id, account_id, device_name, refresh_token_hash, created_at, last_used_at, expires_at)
             VALUES ('delete-device', 'delete-user', 'Test device', 'delete-refresh', 1, 1, 4102444800)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO api_keys
             (key_id, display_prefix, account_id, name, secret_hash, scopes, created_at)
             VALUES ('delete-key', 'notary_key_delete', 'delete-user', 'Test key', $1,
                     ARRAY['account:read']::TEXT[], 1)",
        )
        .bind(vec![7_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO traces
             (trace_id, account_id, source_trace_id, idempotency_key, status, visibility, package_format,
              declared_package_size_bytes, declared_package_sha256, staging_object_key, committed_staging_object_key,
              upload_expires_at, created_at, updated_at, verified_at,
              admitted_package_size_bytes, admitted_package_sha256,
              content_object_key, content_size_bytes, content_sha256,
              provider, provider_host, model, package_object_key, package_size_bytes,
              package_sha256, disclosure_safety_version)
             VALUES
             ('delete-trace', 'delete-user', 'source-delete-trace', 'delete-idempotency', 'shared', 'listed', $1,
              1, $2, 'delete-upload', 'delete-intake', 2, 1, 1, 1, 1, $2,
              'delete-public-trace', 1, $3, 'openai', 'api.openai.com', 'gpt-test',
              'delete-package', 1, $4, 'notary/content-safety/v1')",
        )
        .bind(crate::traces::storage::PACKAGE_FORMAT)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO credit_grants
             (id, credit_subject, account_id, credit_kind, amount_bytes, source_kind,
              source_reference, idempotency_key, created_at, available_at, display_label)
             VALUES ('delete-grant', 'account:delete-user', 'delete-user', 'notarization', 100, 'promotion',
                     'delete-grant', 'delete-grant', 1, 1, 'Test grant')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO credit_debits
             (id, credit_subject, account_id, credit_kind, allowance_bytes, created_at)
             VALUES ('delete-debit', 'account:delete-user', 'delete-user', 'notarization', 40, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO credit_debit_allocations
             (debit_id, grant_id, amount_bytes, allocation_order)
             VALUES ('delete-debit', 'delete-grant', 40, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let state = NotaryApiState {
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
            public_origin: Url::parse("https://notary.exalto.ai").unwrap(),
            secure_cookies: true,
            registry: test_registry(),
            traces: traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing: billing::BillingService::disabled_for_test(),
        };
        let jar = CookieJar::new().add(Cookie::new(SESSION_COOKIE, web_token));
        let (_, status) = delete_account(State(state.clone()), jar).await.unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);

        let remaining: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM accounts WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM browser_sessions WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM devices WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM api_keys WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM traces WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM credit_grants WHERE account_id = 'delete-user'),
                 (SELECT COUNT(*) FROM credit_debit_allocations)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, (0, 0, 0, 0, 0, 0, 0));
        let queued: Vec<(String, String)> = sqlx::query_as(
            "SELECT object_key, artifact_kind FROM storage_cleanup_queue
             WHERE trace_id = 'delete-trace' ORDER BY object_key",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            queued,
            vec![
                ("delete-intake".to_owned(), "staging".to_owned()),
                ("delete-package".to_owned(), "package".to_owned()),
                ("delete-public-trace".to_owned(), "content".to_owned()),
                ("delete-upload".to_owned(), "staging".to_owned()),
            ]
        );
    }
}
