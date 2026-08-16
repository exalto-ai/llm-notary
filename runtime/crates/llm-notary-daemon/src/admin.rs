//! Authenticated loopback administration API and durable background work.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, watch};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{Modify, OpenApi, ToSchema};

use llm_notary_core::pagination::{
    CursorScope, Page, PageQuery, PaginationError, decode_cursor, encode_cursor,
};

use crate::{
    DeferredBundle,
    archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES, read_trace_package_archive},
    artifact_store::{
        ArtifactKey, ArtifactKind, ArtifactRecord, ArtifactSource, ArtifactStore,
        ArtifactStoreError,
    },
    bundle::{
        finalize_bundle_admitted_bytes_with_progress, finalize_bundle_bytes_with_progress,
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    cluster_runtime::{ClusterRuntime, Lifecycle},
    config::AgentConfig,
    metadata::TerminalOperationResult,
    metadata::{
        CaptureFilters, CapturePagePosition, CaptureSummary, Event, EventFilters, Operation,
        OperationAttempt, OperationFilters, OperationPagePosition, SharedNotaryTrust,
    },
    metadata_store::{FinalizationClaim, MetadataStore, MetadataStoreError},
    notary_directory::{NotaryDirectoryRecord, NotaryKeyStatus, key_id},
    persistence::Persistence,
    service::{DEFAULT_PUBLIC_ORIGIN, auth, notary, proxy, publish},
    vault::Vault,
};

const API_VERSION: &str = "v1";
const TRUSTED_NOTARY_KEY_HEADER: &str = "x-llm-notary-trusted-notary-key";
const SESSION_COOKIE: &str = "llm_notary_admin_session";
const SESSION_MAX_AGE_SECONDS: u64 = 43_200;
const DEPENDENCY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DEPENDENCY_PROBE_CACHE_TTL: Duration = Duration::from_secs(1);
const DASHBOARD_HEADER: &str = "x-llm-notary-request";
const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const DESKTOP_DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self' tauri://localhost http://tauri.localhost https://tauri.localhost";

#[derive(RustEmbed)]
#[folder = "dashboard/"]
struct DashboardAssets;

type DependencyProbeResult = std::result::Result<(), &'static str>;
type DependencyProbeCache = Option<(Instant, DependencyProbeResult)>;

#[derive(Clone)]
pub(crate) struct AdminState {
    persistence: Persistence,
    config: Arc<AgentConfig>,
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    pending_authorizations: Arc<Mutex<HashMap<String, auth::PendingAuthorization>>>,
    account_credentials: Arc<Mutex<()>>,
    pub(crate) work_available: Arc<Notify>,
    pub(crate) update_status: crate::update::SharedUpdateStatus,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    cluster_vault_identity: Option<String>,
    dependency_probe: Arc<Mutex<DependencyProbeCache>>,
    capture_mode: Arc<crate::service::proxy::CaptureMode>,
}

impl AdminState {
    pub(crate) async fn new(
        persistence: Persistence,
        config: Arc<AgentConfig>,
        cluster_runtime: Option<Arc<ClusterRuntime>>,
        cluster_vault_identity: Option<String>,
        capture_mode: Option<Arc<crate::service::proxy::CaptureMode>>,
    ) -> Result<Self> {
        if cluster_runtime.is_none() {
            let interrupted = persistence
                .metadata
                .interrupt_running_operations(now_ms()?)
                .await?;
            if interrupted > 0 {
                tracing::warn!(interrupted, "recovered interrupted finalization operations");
            }
        }
        let capture_mode = match capture_mode {
            Some(capture_mode) => capture_mode,
            None => Arc::new(crate::service::proxy::CaptureMode::new(
                persistence.metadata.capture_enabled().await?,
                config.notary_endpoint()?,
                config.clone(),
                persistence.clone(),
                cluster_runtime.clone(),
            )),
        };
        Ok(Self {
            persistence,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            account_credentials: Arc::new(Mutex::new(())),
            work_available: Arc::new(Notify::new()),
            update_status: if cluster_runtime.is_some() {
                crate::update::background_status_disabled("cluster_managed")
            } else {
                crate::update::background_status()
            },
            cluster_runtime,
            cluster_vault_identity,
            dependency_probe: Arc::new(Mutex::new(None)),
            capture_mode,
        })
    }
}

async fn probe_dependencies(state: &AdminState) -> std::result::Result<(), &'static str> {
    let mut cached = state.dependency_probe.lock().await;
    if let Some((checked_at, result)) = cached.as_ref()
        && checked_at.elapsed() < DEPENDENCY_PROBE_CACHE_TTL
    {
        return *result;
    }

    let persistence = state.persistence.clone();
    let cluster_runtime = state.cluster_runtime.clone();
    let opened_vault = state.cluster_vault_identity.clone();
    let require_shared_trust = state.capture_mode.enabled()
        && state.cluster_runtime.is_some()
        && state.config.notary.endpoint.is_none();
    let result = match tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, async move {
        persistence
            .metadata
            .readiness()
            .await
            .map_err(|_| "metadata_not_ready")?;
        persistence
            .artifacts
            .readiness()
            .await
            .map_err(|_| "artifact_not_ready")?;
        if let Some(cluster_runtime) = cluster_runtime {
            if opened_vault.is_none() {
                return Err("vault_not_ready");
            }
            if !persistence
                .cluster_metadata()
                .replica_ready(cluster_runtime.identity())
                .await
                .map_err(|_| "replica_lease_not_ready")?
            {
                return Err("replica_lease_not_ready");
            }
        }
        if require_shared_trust
            && persistence
                .cluster_metadata()
                .notary_trust_snapshot()
                .await
                .map_err(|_| "notary_trust_not_ready")?
                .is_none()
        {
            return Err("notary_trust_not_ready");
        }
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err("dependency_not_ready"),
    };
    *cached = Some((Instant::now(), result));
    result
}

pub(crate) fn router(state: AdminState) -> Result<Router> {
    let protected = Router::new()
        .route("/v1/status", get(status))
        .route(
            "/v1/settings/capture",
            get(capture_setting).put(update_capture_setting),
        )
        .route("/v1/notaries", get(notaries))
        .route("/v1/captures", get(captures))
        .route("/v1/captures/{capture_id}", get(capture))
        .route(
            "/v1/captures/{capture_id}/finalizations",
            post(start_finalization),
        )
        .route("/v1/operations", get(operations))
        .route("/v1/operations/{operation_id}", get(operation))
        .route("/v1/operations/{operation_id}/retry", post(retry_operation))
        .route("/v1/captures/{capture_id}/trace", get(trace))
        .route("/v1/captures/{capture_id}/package", get(download_package))
        .route("/v1/captures/{capture_id}/trace:verify", post(verify_trace))
        .route(
            "/v1/traces:verify",
            post(verify_uploaded_trace).layer(DefaultBodyLimit::max(
                usize::try_from(MAX_ARCHIVE_WIRE_BYTES).expect("archive limit fits in usize"),
            )),
        )
        .route("/v1/events", get(events))
        .route(
            "/v1/account",
            get(account_status)
                .post(start_account_connection)
                .delete(end_account_connection),
        )
        .route("/v1/account/{request_id}", get(poll_account_connection))
        .route("/v1/captures/{capture_id}/shares", post(share_capture))
        .route("/v1/shares/{share_id}", get(share_status))
        .route("/v1/session", delete(end_session))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Ok(Router::new()
        .route("/", get(dashboard_index))
        .route("/dashboard", get(dashboard_index))
        .route("/dashboard/", get(dashboard_index))
        .route("/assets/{*path}", get(dashboard_asset))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/openapi.json", get(openapi))
        .route("/v1/session", post(start_session))
        .merge(protected)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
                    tracing::info_span!(
                        "admin_request",
                        method = %request.method(),
                        path = %request.uri().path(),
                        version = ?request.version()
                    )
                })
                .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(DefaultOnResponse::new().level(tracing::Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .with_state(state))
}

#[derive(Deserialize)]
struct DashboardQuery {
    embedded: Option<String>,
}

async fn dashboard_index(Query(query): Query<DashboardQuery>) -> Response {
    let desktop_embed = query.embedded.as_deref() == Some("desktop");
    embedded_dashboard_response("local.html", desktop_embed)
}

async fn dashboard_asset(Path(path): Path<String>) -> Response {
    embedded_dashboard_response(&format!("assets/{path}"), false)
}

fn embedded_dashboard_response(path: &str, desktop_embed: bool) -> Response {
    let Some(asset) = DashboardAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = asset.data.into_owned().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type.as_ref()).expect("MIME type is a valid header"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, private"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if desktop_embed {
            DESKTOP_DASHBOARD_CSP
        } else {
            DASHBOARD_CSP
        }),
    );
    response
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LLM Notary local administration API",
        version = "1.0.0",
        description = "Loopback administration API. Routes are available without credentials by default; configure admin.auth to require HTTP Basic authentication."
    ),
    paths(
        health, readiness, openapi, start_session, end_session, status, capture_setting, update_capture_setting, notaries, captures, capture,
        start_finalization, operations, operation, retry_operation, trace,
        download_package, verify_trace, verify_uploaded_trace, events, account_status, start_account_connection,
        end_account_connection, poll_account_connection, share_capture,
        share_status
    ),
    components(schemas(
        HealthResponse, ReadinessResponse, StatusResponse, CaptureSettingResponse, UpdateCaptureSetting, CountsResponse, UpdateStatusResponse, NotariesResponse, NotaryResponse,
        PageQuery, CaptureResponse, CaptureDetailResponse, ArtifactResponse,
        OperationSummaryResponse, OperationResponse, OperationProgressResponse,
        OperationProofProgressResponse, OperationAttemptResponse,
        FinalizationResponse, EventResponse,
        EventListResponse, TraceResponse, VerificationResponse, AccountConnectionResponse,
        AccountConnectionRequest, AccountConnectionStartedResponse, CreateShareRequest,
        ShareVisibility, ShareResponse, ShareStatusResponse,
        ErrorBody, ErrorEnvelope
    )),
    modifiers(&SecurityAddon),
    tags((name = "local-admin", description = "Loopback-only administration"))
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "basicAuth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
        }
    }
}

#[utoipa::path(get, path = "/healthz", summary = "Check service health", description = "Returns the local service health and API version without requiring authentication.", responses((status = 200, body = HealthResponse)), tag = "local-admin")]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "llm-notaryd".into(),
        status: "ok".into(),
        api_version: API_VERSION.into(),
        build_id: crate::service::BUILD_ID.into(),
    })
}

#[utoipa::path(get, path = "/readyz", summary = "Check service readiness", description = "Runs bounded metadata, selected artifact-writer, and shared trust dependency probes. Dependency outages or schema mismatches make readiness fail while /healthz remains local liveness.", responses((status = 200, body = ReadinessResponse), (status = 503, body = ErrorEnvelope)), tag = "local-admin")]
async fn readiness(State(state): State<AdminState>) -> Result<Json<ReadinessResponse>, ApiError> {
    if state
        .cluster_runtime
        .as_ref()
        .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() != Lifecycle::Ready)
    {
        return Err(ApiError::service_unavailable("replica_not_ready"));
    }
    match probe_dependencies(&state).await {
        Ok(()) => Ok(Json(ReadinessResponse {
            service: "llm-notaryd".into(),
            status: "ready".into(),
            metadata_backend: state.persistence.metadata.backend_name().into(),
            artifact_backend: state.persistence.artifacts.backend_name().into(),
        })),
        Err(code) => Err(ApiError::service_unavailable(code)),
    }
}

#[utoipa::path(get, path = "/openapi.json", summary = "Get the OpenAPI contract", description = "Returns the exact OpenAPI 3.1 contract implemented by this local service.", responses((status = 200, description = "OpenAPI 3.1 document")), tag = "local-admin")]
async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(openapi_document())
}

/// Returns the exact code-generated contract served by `/openapi.json`.
/// Dashboard client generation uses this function through the export example.
pub fn openapi_document() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

#[utoipa::path(post, path = "/v1/session", summary = "Start a dashboard session", description = "Exchanges configured HTTP Basic credentials for an HttpOnly browser session cookie. Returns without a cookie when admin authentication is disabled.", responses((status = 204, description = "Dashboard access established"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_session(State(state): State<AdminState>, request: Request) -> Response {
    if state.config.admin.auth.is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    if !basic_matches(&state, request.headers()).await {
        return unauthorized_response();
    }
    let session = new_secret();
    let expires_at = match now_ms().and_then(|now| {
        now.checked_add(SESSION_MAX_AGE_SECONDS * 1_000)
            .context("dashboard session expiry overflowed")
    }) {
        Ok(expires_at) => expires_at,
        Err(_) => return ApiError::internal("clock_error").into_response(),
    };
    if state.cluster_runtime.is_some() {
        let created_at = expires_at - SESSION_MAX_AGE_SECONDS * 1_000;
        if state
            .persistence
            .cluster_metadata()
            .create_dashboard_session(&session_hash(&session), created_at, expires_at)
            .await
            .is_err()
        {
            return ApiError::service_unavailable("metadata_not_ready").into_response();
        }
        if let Err(error) = state
            .persistence
            .cluster_metadata()
            .prune_dashboard_sessions(created_at, 100)
            .await
        {
            tracing::warn!(%error, "expired dashboard sessions could not be pruned");
        }
    } else {
        state
            .sessions
            .lock()
            .await
            .insert(session.clone(), expires_at);
    }
    let cookie = format!(
        "{SESSION_COOKIE}={session}; {}HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}",
        if state.cluster_runtime.is_some() {
            "Secure; "
        } else {
            ""
        }
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated session cookie is valid"),
    );
    response
}

#[utoipa::path(delete, path = "/v1/session", summary = "End a dashboard session", description = "Deletes the current browser session and expires its local cookie.", responses((status = 204, description = "Dashboard session ended"), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_session(State(state): State<AdminState>, request: Request) -> Response {
    if let Some(session) = session_from_headers(request.headers()) {
        if state.cluster_runtime.is_some() {
            if state
                .persistence
                .cluster_metadata()
                .revoke_dashboard_session(&session_hash(session))
                .await
                .is_err()
            {
                return ApiError::service_unavailable("metadata_not_ready").into_response();
            }
        } else {
            state.sessions.lock().await.remove(session);
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "llm_notary_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        ),
    );
    response
}

async fn require_auth(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    if state.config.admin.auth.is_none() {
        return next.run(request).await;
    }
    let basic_ok = basic_matches(&state, request.headers()).await;
    let session_ok = if basic_ok {
        false
    } else if request
        .headers()
        .get(DASHBOARD_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("dashboard")
    {
        match (session_from_headers(request.headers()), now_ms()) {
            (Some(value), Ok(now)) if state.cluster_runtime.is_some() => match state
                .persistence
                .cluster_metadata()
                .dashboard_session_valid(&session_hash(value), now)
                .await
            {
                Ok(valid) => valid,
                Err(_) => {
                    return ApiError::service_unavailable("metadata_not_ready").into_response();
                }
            },
            (Some(value), Ok(now)) => {
                let mut sessions = state.sessions.lock().await;
                sessions.retain(|_, expires_at| *expires_at > now);
                sessions.contains_key(value)
            }
            _ => false,
        }
    } else {
        false
    };
    if basic_ok || session_ok {
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

fn session_hash(token: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"llm-notary/dashboard-session/v1\0");
    digest.update(token.as_bytes());
    digest.finalize().into()
}

#[utoipa::path(get, path = "/v1/status", summary = "Get local service status", description = "Returns listener addresses, bounded metadata and artifact-writer readiness, vault and notary configuration, preview limits, and current capture counts.", responses((status = 200, body = StatusResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn status(State(state): State<AdminState>) -> Result<Json<StatusResponse>, ApiError> {
    let metadata = state.persistence.metadata.clone();
    let probe_state = state.clone();
    let counts = tokio::time::timeout(DEPENDENCY_PROBE_TIMEOUT, async move {
        probe_dependencies(&probe_state).await.map_err(|_| ())?;
        metadata.counts().await.map_err(|_| ())
    })
    .await
    .map_err(|_| ApiError::service_unavailable("dependency_not_ready"))?
    .map_err(|_| ApiError::service_unavailable("dependency_not_ready"))?;
    let capture_enabled = state
        .persistence
        .metadata
        .capture_enabled()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    let update = state.update_status.read().await;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        build_id: crate::service::BUILD_ID.into(),
        runtime_profile: if state.cluster_runtime.is_some() {
            "cluster"
        } else {
            "local"
        }
        .into(),
        instance_id: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| cluster_runtime.identity().instance_id().to_owned()),
        incarnation_id: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| cluster_runtime.identity().incarnation_id().to_owned()),
        lifecycle: state
            .cluster_runtime
            .as_ref()
            .map(|cluster_runtime| {
                format!("{:?}", cluster_runtime.lifecycle()).to_ascii_lowercase()
            })
            .unwrap_or_else(|| "ready".into()),
        capture_enabled,
        proxy_listener: state.config.proxy.listen.to_string(),
        admin_listener: state.config.admin.listen.to_string(),
        proxy_origin: state
            .config
            .cluster
            .as_ref()
            .map(|cluster| cluster.proxy_origin.clone())
            .unwrap_or_else(|| format!("http://{}", state.config.proxy.listen)),
        admin_origin: state
            .config
            .cluster
            .as_ref()
            .map(|cluster| cluster.admin_origin.clone())
            .unwrap_or_else(|| format!("http://{}", state.config.admin.listen)),
        metadata_backend: state.persistence.metadata.backend_name().into(),
        metadata_status: "ready".into(),
        artifact_backend: state.persistence.artifacts.backend_name().into(),
        artifact_status: "ready".into(),
        vault: if state.cluster_runtime.is_some() {
            "shared cluster key"
        } else {
            Vault::status().unwrap_or("unavailable")
        }
        .into(),
        notary: if state.config.notary.endpoint.is_some() {
            "configured"
        } else {
            "directory"
        }
        .into(),
        preview_chars: state.config.catalog.prompt_preview_chars,
        counts: CountsResponse::from(counts),
        updates: UpdateStatusResponse {
            enabled: update.enabled,
            current_build_id: update.current_build_id.clone(),
            latest_build_id: update.latest_build_id.clone(),
            update_available: update.update_available,
            last_checked_unix_ms: update.last_checked_unix_ms,
            error_code: update.error_code.clone(),
        },
    }))
}

#[utoipa::path(get, path = "/v1/settings/capture", summary = "Get capture mode", description = "Returns the authoritative daemon-owned mode used when admitting new provider requests.", responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn capture_setting(
    State(state): State<AdminState>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let enabled = state
        .persistence
        .metadata
        .capture_enabled()
        .await
        .map_err(|_| ApiError::service_unavailable("metadata_not_ready"))?;
    Ok(Json(CaptureSettingResponse { enabled }))
}

#[utoipa::path(put, path = "/v1/settings/capture", summary = "Set capture mode", description = "Durably changes how later provider requests are admitted. Enabling first initializes trusted notary state; a failure leaves capture off.", request_body = UpdateCaptureSetting, responses((status = 200, body = CaptureSettingResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn update_capture_setting(
    State(state): State<AdminState>,
    Json(update): Json<UpdateCaptureSetting>,
) -> Result<Json<CaptureSettingResponse>, ApiError> {
    let enabled = state
        .capture_mode
        .set_enabled(update.enabled)
        .await
        .map_err(|error| {
            tracing::warn!("capture mode transition failed: {error:#}");
            ApiError::service_unavailable(if update.enabled {
                "capture_enable_initialization_failed"
            } else {
                "capture_setting_not_stored"
            })
        })?;
    Ok(Json(CaptureSettingResponse { enabled }))
}

#[utoipa::path(get, path = "/v1/notaries", summary = "Get configured notary trust", description = "Returns a safe read-only projection of the local or server-shared pinned notary trust history, or the explicitly configured self-hosted endpoint and key. Directory membership describes allowed protocol use and does not report endpoint health.", responses((status = 200, body = NotariesResponse), (status = 401, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn notaries(State(state): State<AdminState>) -> Result<Json<NotariesResponse>, ApiError> {
    let shared = if state.cluster_runtime.is_some() && state.config.notary.endpoint.is_none() {
        state
            .persistence
            .cluster_metadata()
            .notary_trust_snapshot()
            .await
            .map_err(|_| ApiError::service_unavailable("notary_trust_not_ready"))?
    } else {
        None
    };
    notaries_response(&state.config, shared)
        .map(Json)
        .map_err(|_| ApiError::internal("notary_trust_state_invalid"))
}

fn notaries_response(
    config: &AgentConfig,
    shared: Option<crate::metadata::SharedNotaryTrust>,
) -> Result<NotariesResponse> {
    if let (Some(endpoint), Some(public_key)) =
        (config.notary_endpoint()?, config.notary_public_key()?)
    {
        return Ok(NotariesResponse {
            source: "explicit_configuration".into(),
            directory_source: None,
            generation: None,
            active_key_id: None,
            notaries: vec![NotaryResponse {
                endpoint: endpoint.to_string(),
                transport: endpoint.transport.scheme().into(),
                key_id: key_id(&public_key),
                status: "configured".into(),
                valid_from_unix_ms: None,
                valid_until_unix_ms: None,
                finalize_until_unix_ms: None,
            }],
        });
    }

    let pinned = match shared {
        Some(shared) => Some(shared.into()),
        None => notary::pinned_state()?,
    };
    let Some(pinned) = pinned else {
        return Ok(NotariesResponse {
            source: "directory".into(),
            directory_source: None,
            generation: None,
            active_key_id: None,
            notaries: Vec::new(),
        });
    };
    Ok(directory_notaries_response(pinned))
}

fn directory_notaries_response(pinned: notary::PinnedNotaryState) -> NotariesResponse {
    let active_key_id = pinned.active_key_id;
    let mut records = pinned.records;
    records.sort_by(|left, right| {
        notary_record_order(left, &active_key_id)
            .cmp(&notary_record_order(right, &active_key_id))
            .then_with(|| right.valid_from_unix_ms.cmp(&left.valid_from_unix_ms))
            .then_with(|| left.key_id.cmp(&right.key_id))
    });
    NotariesResponse {
        source: "directory".into(),
        directory_source: pinned.directory_source,
        generation: Some(pinned.generation),
        active_key_id: Some(active_key_id),
        notaries: records.into_iter().map(NotaryResponse::from).collect(),
    }
}

fn notary_record_order(record: &NotaryDirectoryRecord, active_key_id: &str) -> u8 {
    if record.key_id == active_key_id {
        return 0;
    }
    match record.status {
        NotaryKeyStatus::Active => 1,
        NotaryKeyStatus::Retiring => 2,
        NotaryKeyStatus::Retired => 3,
        NotaryKeyStatus::Revoked => 4,
    }
}

#[derive(Debug, Default, Deserialize)]
struct CaptureQuery {
    query: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    capture_state: Option<String>,
    finalization_state: Option<String>,
    streaming: Option<bool>,
    created_after_unix_ms: Option<u64>,
    limit: Option<u32>,
    cursor: Option<String>,
    offset: Option<u64>,
}

#[utoipa::path(get, path = "/v1/captures", summary = "Search local captures", description = "Lists the local capture catalog with opaque cursor pagination, punctuation-safe preview search, and exact metadata filters. The legacy offset parameter is rejected; restart traversal without a cursor instead.", params(("query" = Option<String>, Query), ("model" = Option<String>, Query), ("provider" = Option<String>, Query), ("capture_state" = Option<String>, Query), ("finalization_state" = Option<String>, Query), ("streaming" = Option<bool>, Query), ("created_after_unix_ms" = Option<u64>, Query), ("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 200), ("cursor" = Option<String>, Query), ("offset" = Option<u64>, Query)), responses((status = 200, body = Page<CaptureResponse>), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn captures(
    State(state): State<AdminState>,
    query: Result<Query<CaptureQuery>, QueryRejection>,
) -> Result<Json<Page<CaptureResponse>>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    if query.offset.is_some() {
        return Err(ApiError::bad_request("offset_pagination_removed"));
    }
    if let Some(created_after) = query.created_after_unix_ms {
        validate_persisted_query_integer(created_after)?;
    }
    let limit = PageQuery {
        limit: query.limit,
        cursor: query.cursor.clone(),
    }
    .limit(50, 200)
    .map_err(pagination_api_error)?;
    let scope = CursorScope::new(
        "/v1/captures",
        &(
            &query.query,
            &query.model,
            &query.provider,
            &query.capture_state,
            &query.finalization_state,
            query.streaming,
            query.created_after_unix_ms,
        ),
        "created_at_unix_ms desc, capture_id desc",
    )
    .map_err(pagination_api_error)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<CapturePagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = cursor.as_ref() {
        validate_persisted_cursor_integer(position.created_at_unix_ms)?;
    }
    let values = state
        .persistence
        .metadata
        .captures(CaptureFilters {
            query: query.query,
            model: query.model,
            provider: query.provider,
            capture_state: query.capture_state,
            finalization_state: query.finalization_state,
            streaming: query.streaming,
            created_after_unix_ms: query.created_after_unix_ms,
            cursor,
            limit: limit + 1,
        })
        .await
        .map_err(metadata_api_error)?;
    let page = Page::from_limit_plus_one(values, limit, &scope, |capture| {
        CapturePagePosition::from(capture)
    })
    .map_err(pagination_api_error)?;
    Ok(Json(Page {
        items: page.items.into_iter().map(CaptureResponse::from).collect(),
        next_cursor: page.next_cursor,
    }))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}", summary = "Get a capture", description = "Returns safe capture metadata, retained artifact digests, and finalization history for one capture.", params(("capture_id" = String, Path)), responses((status = 200, body = CaptureDetailResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn capture(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<CaptureDetailResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let capture = state
        .persistence
        .metadata
        .capture(&capture_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("capture_not_found"))?;
    let artifacts = state
        .persistence
        .metadata
        .artifacts(&capture_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let capture_id = capture.capture_id.clone();
    let operations = state
        .persistence
        .metadata
        .operations(OperationFilters {
            capture_id: Some(capture_id.clone()),
            limit: 200,
            ..OperationFilters::default()
        })
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    let mut finalizations = Vec::with_capacity(operations.len());
    for operation in operations {
        finalizations.push(
            operation_response(&state.persistence.metadata, operation)
                .await
                .map_err(|_| ApiError::internal("metadata_query_failed"))?,
        );
    }
    Ok(Json(CaptureDetailResponse {
        capture: capture.into(),
        artifacts: artifacts
            .into_iter()
            .map(|artifact| ArtifactResponse {
                kind: artifact.key.kind().as_str().to_owned(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            })
            .collect(),
        finalizations,
    }))
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/finalizations", summary = "Queue capture finalization", description = "Queues durable proof generation for an eligible captured provider response or returns its existing finalization operation. Captures with non-success provider HTTP responses are rejected before proof generation because the current normalizers only support successful response schemas.", params(("capture_id" = String, Path)), responses((status = 202, body = FinalizationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_finalization(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<(StatusCode, Json<FinalizationResponse>), ApiError> {
    validate_id(&capture_id, "cap-")?;
    let capture = state
        .persistence
        .metadata
        .capture(&capture_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .filter(|capture| capture.capture_state == "captured")
        .ok_or_else(|| ApiError::not_found("captured_response_not_found"))?;
    if finalization_ineligibility_code(&capture).is_some() {
        return Err(ApiError::finalization_ineligible());
    }
    let queued = state
        .persistence
        .metadata
        .enqueue_finalization(
            &capture_id,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::internal("finalization_queue_failed"))?
        .ok_or_else(|| ApiError::not_found("captured_response_not_found"))?;
    let queued = (
        operation_response(&state.persistence.metadata, queued.0)
            .await
            .map_err(|_| ApiError::internal("metadata_query_failed"))?,
        queued.1,
    );
    state.work_available.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        Json(FinalizationResponse {
            operation: queued.0,
            deduplicated: queued.1,
        }),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct OperationQuery {
    state: Option<String>,
    kind: Option<String>,
    capture_id: Option<String>,
    limit: Option<u32>,
    cursor: Option<String>,
}

#[utoipa::path(get, path = "/v1/operations", summary = "List background operations", description = "Lists bounded operation summaries, including milestone progress, with opaque cursor pagination and optional state, kind, and capture filters. Fetch one operation for its complete attempt history.", params(("state" = Option<String>, Query), ("kind" = Option<String>, Query), ("capture_id" = Option<String>, Query), ("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 200), ("cursor" = Option<String>, Query)), responses((status = 200, body = Page<OperationSummaryResponse>), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn operations(
    State(state): State<AdminState>,
    query: Result<Query<OperationQuery>, QueryRejection>,
) -> Result<Json<Page<OperationSummaryResponse>>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    let limit = PageQuery {
        limit: query.limit,
        cursor: query.cursor.clone(),
    }
    .limit(50, 200)
    .map_err(pagination_api_error)?;
    let scope = CursorScope::new(
        "/v1/operations",
        &(&query.state, &query.kind, &query.capture_id),
        "created_at_unix_ms desc, operation_id desc",
    )
    .map_err(pagination_api_error)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<OperationPagePosition>(&scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = cursor.as_ref() {
        validate_persisted_cursor_integer(position.created_at_unix_ms)?;
    }
    let values = state
        .persistence
        .metadata
        .operations(OperationFilters {
            state: query.state,
            kind: query.kind,
            capture_id: query.capture_id,
            cursor,
            limit: limit + 1,
        })
        .await
        .map_err(metadata_api_error)?
        .into_iter()
        .map(OperationSummaryResponse::from)
        .collect::<Vec<_>>();
    let page =
        Page::from_limit_plus_one(values, limit, &scope, |operation| OperationPagePosition {
            created_at_unix_ms: operation.created_at_unix_ms,
            operation_id: operation.operation_id.clone(),
        })
        .map_err(pagination_api_error)?;
    Ok(Json(page))
}

#[utoipa::path(get, path = "/v1/operations/{operation_id}", summary = "Get an operation", description = "Returns the current state, milestone progress, and complete attempt history for one durable operation.", params(("operation_id" = String, Path)), responses((status = 200, body = OperationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<Json<OperationResponse>, ApiError> {
    validate_id(&operation_id, "op-")?;
    let operation = state
        .persistence
        .metadata
        .operation(&operation_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .ok_or_else(|| ApiError::not_found("operation_not_found"))?;
    let value = operation_response(&state.persistence.metadata, operation)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(post, path = "/v1/operations/{operation_id}/retry", summary = "Retry an operation", description = "Requeues a failed or restart-interrupted operation while preserving its durable identity and attempt history.", params(("operation_id" = String, Path)), responses((status = 202, body = OperationResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn retry_operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    validate_id(&operation_id, "op-")?;
    let operation = state
        .persistence
        .metadata
        .retry_operation(
            &operation_id,
            now_ms().map_err(|_| ApiError::internal("clock_failed"))?,
        )
        .await
        .map_err(|_| ApiError::internal("operation_retry_failed"))?
        .ok_or_else(|| ApiError::conflict("operation_not_retryable"))?;
    let value = operation_response(&state.persistence.metadata, operation)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?;
    state.work_available.notify_one();
    Ok((StatusCode::ACCEPTED, Json(value)))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}/trace", summary = "Decode a finalized trace", description = "Returns the finalized package manifest and canonical OpenTelemetry trace for inspection.", params(("capture_id" = String, Path)), responses((status = 200, body = TraceResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn trace(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<TraceResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let bytes = finalized_bytes(&state.persistence, &capture_id).await?;
    let value = tokio::task::spawn_blocking(move || -> Result<TraceResponse> {
        let archive = read_trace_package_archive(&bytes)?;
        Ok(TraceResponse {
            capture_id,
            manifest: serde_json::from_slice(archive.file("manifest.json")?)?,
            trace: serde_json::from_slice(archive.file("trace.otlp.json")?)?,
        })
    })
    .await
    .map_err(|_| ApiError::internal("trace_task_failed"))?
    .map_err(|_| ApiError::internal("trace_decode_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}/package", summary = "Download a finalized verified package", description = "Returns the exact stored canonical .llmtrace bytes as the primary portable verification artifact.", params(("capture_id" = String, Path)), responses((status = 200, body = Vec<u8>, content_type = "application/vnd.llmnotary.trace-package+zip"), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn download_package(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let bytes = finalized_bytes(&state.persistence, &capture_id).await?;
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{capture_id}.llmtrace\""))
            .map_err(|_| ApiError::internal("package_filename_invalid"))?;
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(ARCHIVE_CONTENT_TYPE),
            ),
            (header::CONTENT_DISPOSITION, content_disposition),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/trace:verify", summary = "Verify a finalized trace", description = "Verifies the package evidence, disclosure, hashes, provider mapping, and canonical trace against the configured trust source.", params(("capture_id" = String, Path)), responses((status = 200, body = VerificationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn verify_trace(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<VerificationResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let bytes = finalized_bytes(&state.persistence, &capture_id).await?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .config
        .notary_public_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<SharedNotaryTrust> =
        if configured_key.is_none() && state.cluster_runtime.is_some() {
            state
                .persistence
                .cluster_metadata()
                .notary_trust_snapshot()
                .await
                .map_err(|_| ApiError::service_unavailable("notary_trust_not_ready"))?
                .ok_or_else(|| ApiError::service_unavailable("notary_trust_not_ready"))?
                .into()
        } else {
            None
        };
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResponse> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = match configured_key {
            Some(key) => {
                let key_id = key_id(&key);
                (key, key_id, "configuration".to_owned())
            }
            None => {
                let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
                let (key_id, trust) = match &shared_trust {
                    Some(shared) => notary::shared_key_at(shared, &embedded_key, created_at)?,
                    None => notary::cached_key_at(&embedded_key, created_at)?,
                };
                (embedded_key, key_id, trust)
            }
        };
        let manifest = verify_trace_package_bytes(&bytes, &trusted_key)?.manifest;
        Ok(VerificationResponse {
            capture_id: manifest.capture_id().into(),
            verified: true,
            verified_at_unix_ms,
            notary_key_id,
            trust_source,
        })
    })
    .await
    .map_err(|_| ApiError::internal("verification_task_failed"))?
    .map_err(|_| ApiError::unprocessable("trace_verification_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(post, path = "/v1/traces:verify", summary = "Verify a portable finalized trace", description = "Verifies uploaded .llmtrace bytes against an optional explicit notary key or the daemon's configured trust source. The package is processed in memory and is not retained.", request_body(content = Vec<u8>, content_type = "application/vnd.llmnotary.trace-package+zip"), params(("x-llm-notary-trusted-notary-key" = Option<String>, Header, description = "Optional compressed SEC1 notary public key in hexadecimal")), responses((status = 200, body = VerificationResponse), (status = 401, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn verify_uploaded_trace(
    State(state): State<AdminState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<VerificationResponse>, ApiError> {
    let explicit_key = headers
        .get(TRUSTED_NOTARY_KEY_HEADER)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| ApiError::bad_request("invalid_trusted_notary_key"))?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .config
        .notary_public_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let shared_trust: Option<SharedNotaryTrust> =
        if explicit_key.is_none() && configured_key.is_none() && state.cluster_runtime.is_some() {
            state
                .persistence
                .cluster_metadata()
                .notary_trust_snapshot()
                .await
                .map_err(|_| ApiError::service_unavailable("notary_trust_not_ready"))?
                .ok_or_else(|| ApiError::service_unavailable("notary_trust_not_ready"))?
                .into()
        } else {
            None
        };
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResponse> {
        let embedded_key = trace_package_notary_key_bytes(&bytes)?;
        let (trusted_key, notary_key_id, trust_source) = if let Some(value) = explicit_key {
            let (key, key_id) = notary::explicit_key(&value)?;
            (key, key_id, "explicit_key".to_owned())
        } else if let Some(key) = configured_key {
            let key_id = key_id(&key);
            (key, key_id, "configuration".to_owned())
        } else {
            let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
            let (key_id, trust) = match &shared_trust {
                Some(shared) => notary::shared_key_at(shared, &embedded_key, created_at)?,
                None => notary::cached_key_at(&embedded_key, created_at)?,
            };
            (embedded_key, key_id, trust)
        };
        let manifest = verify_trace_package_bytes(&bytes, &trusted_key)?.manifest;
        Ok(VerificationResponse {
            capture_id: manifest.capture_id().into(),
            verified: true,
            verified_at_unix_ms,
            notary_key_id,
            trust_source,
        })
    })
    .await
    .map_err(|_| ApiError::internal("verification_task_failed"))?
    .map_err(|_| ApiError::unprocessable("trace_verification_failed"))?;
    Ok(Json(value))
}

#[derive(Debug, Default, Deserialize)]
struct EventQuery {
    /// Back-pagination cursor returned as `next_cursor`.
    cursor: Option<String>,
    /// High-water cursor returned by an earlier response; follows newer events.
    after: Option<String>,
    severity: Option<String>,
    event_type: Option<String>,
    capture_id: Option<String>,
    operation_id: Option<String>,
    created_after_unix_ms: Option<u64>,
    limit: Option<u32>,
}

#[utoipa::path(get, path = "/v1/events", summary = "List service events", description = "Lists redacted event history with opaque back-pagination and a separate high-water cursor for following new events.", params(("cursor" = Option<String>, Query), ("after" = Option<String>, Query), ("severity" = Option<String>, Query), ("event_type" = Option<String>, Query), ("capture_id" = Option<String>, Query), ("operation_id" = Option<String>, Query), ("created_after_unix_ms" = Option<u64>, Query), ("limit" = Option<u32>, Query, description = "Page size; defaults to 50", minimum = 1, maximum = 200)), responses((status = 200, body = EventListResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn events(
    State(state): State<AdminState>,
    query: Result<Query<EventQuery>, QueryRejection>,
) -> Result<Json<EventListResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    if let Some(created_after) = query.created_after_unix_ms {
        validate_persisted_query_integer(created_after)?;
    }
    let limit = PageQuery {
        limit: query.limit,
        cursor: query.cursor.clone(),
    }
    .limit(50, 200)
    .map_err(pagination_api_error)?;
    let filter_scope = (
        &query.severity,
        &query.event_type,
        &query.capture_id,
        &query.operation_id,
        query.created_after_unix_ms,
    );
    let follow_scope = CursorScope::new("/v1/events", &(filter_scope, "follow"), "event_id asc")
        .map_err(pagination_api_error)?;
    let after = query
        .after
        .as_deref()
        .map(|cursor| decode_cursor::<EventPagePosition>(&follow_scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = after.as_ref() {
        validate_persisted_cursor_integer(position.event_id)?;
    }
    let page_scope = CursorScope::new(
        "/v1/events",
        &(
            &query.severity,
            &query.event_type,
            &query.capture_id,
            &query.operation_id,
            query.created_after_unix_ms,
            after.as_ref().map(|position| position.event_id),
        ),
        if after.is_some() {
            "event_id asc"
        } else {
            "event_id desc"
        },
    )
    .map_err(pagination_api_error)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor::<EventPagePosition>(&page_scope, cursor))
        .transpose()
        .map_err(pagination_api_error)?;
    if let Some(position) = cursor.as_ref() {
        validate_persisted_cursor_integer(position.event_id)?;
    }
    let snapshot = state
        .persistence
        .metadata
        .events_snapshot(EventFilters {
            before: if after.is_none() {
                cursor.as_ref().map(|position| position.event_id)
            } else {
                None
            },
            after: if after.is_some() {
                cursor
                    .as_ref()
                    .map(|position| position.event_id)
                    .or_else(|| after.as_ref().map(|position| position.event_id))
            } else {
                None
            },
            severity: query.severity,
            event_type: query.event_type,
            capture_id: query.capture_id,
            operation_id: query.operation_id,
            created_after_unix_ms: query.created_after_unix_ms,
            limit: limit + 1,
        })
        .await
        .map_err(metadata_api_error)?;
    let page = Page::from_limit_plus_one(snapshot.events, limit, &page_scope, |event| {
        EventPagePosition {
            event_id: event.event_id,
        }
    })
    .map_err(pagination_api_error)?;
    let high_water_cursor = snapshot
        .high_water
        .map(|event_id| encode_cursor(&follow_scope, &EventPagePosition { event_id }))
        .transpose()
        .map_err(pagination_api_error)?;
    Ok(Json(EventListResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        next_cursor: page.next_cursor,
        high_water_cursor,
    }))
}

#[utoipa::path(get, path = "/v1/account", summary = "Get the LLM Notary account connection", description = "Reports whether this local service has an account connection used for hosted admission, credits, and sharing.", responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn account_status(
    State(_state): State<AdminState>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
    load_account_status().await
}

async fn load_account_status() -> Result<Json<AccountConnectionResponse>, ApiError> {
    let status = auth::account_connection_status()
        .await
        .map_err(|_| ApiError::internal("account_status_failed"))?;
    Ok(Json(AccountConnectionResponse {
        signed_in: status.signed_in,
        connection_state: Some(status.connection_state),
        provider_display_name: status.provider_display_name,
        display_name: status.display_name,
        auth_provider: status.auth_provider,
        device_name: status.device_name,
        credential_kind: status.credential_kind,
        credential_name: status.credential_name,
        billing: status.billing,
        credits: status.credits,
        links: Some(status.links),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
struct AccountConnectionRequest {
    #[serde(default = "default_public_origin")]
    api_origin: String,
    #[serde(default = "default_device_name")]
    device_name: String,
}

fn default_public_origin() -> String {
    DEFAULT_PUBLIC_ORIGIN.to_owned()
}

fn default_device_name() -> String {
    auth::DEFAULT_DEVICE_NAME.to_owned()
}

#[utoipa::path(post, path = "/v1/account", summary = "Connect an LLM Notary account", description = "Starts browser approval for an account connection used for hosted admission, credits, and sharing. Browser approval is unavailable while the daemon uses an injected API key.", request_body = AccountConnectionRequest, responses((status = 202, body = AccountConnectionStartedResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_account_connection(
    State(state): State<AdminState>,
    Json(body): Json<AccountConnectionRequest>,
) -> Result<(StatusCode, Json<AccountConnectionStartedResponse>), ApiError> {
    if auth::api_key_mode_active()
        .map_err(|_| ApiError::internal("account_connection_configuration_failed"))?
    {
        return Err(ApiError::api_key_mode());
    }
    let pending = auth::start_authorization(&body.api_origin, &body.device_name)
        .await
        .map_err(|_| ApiError::internal("account_connection_start_failed"))?;
    let response = AccountConnectionStartedResponse {
        request_id: pending.request_id.clone(),
        user_code: pending.user_code.clone(),
        verification_uri_complete: pending.verification_uri_complete.clone(),
        expires_in_seconds: pending.expires_in,
        poll_interval_seconds: pending.interval.clamp(1, 10),
        state: "pending".into(),
    };
    state
        .pending_authorizations
        .lock()
        .await
        .insert(pending.request_id.clone(), pending);
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[utoipa::path(get, path = "/v1/account/{request_id}", summary = "Poll account authorization", description = "Checks a pending LLM Notary account approval after its required polling interval.", params(("request_id" = String, Path)), responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn poll_account_connection(
    State(state): State<AdminState>,
    Path(request_id): Path<String>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
    if state.cluster_runtime.is_some() {
        return Err(ApiError::api_key_mode());
    }
    if request_id.is_empty()
        || request_id.len() > 256
        || !request_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err(ApiError::bad_request("invalid_authorization_identifier"));
    }
    let pending = state
        .pending_authorizations
        .lock()
        .await
        .get(&request_id)
        .cloned()
        .ok_or_else(|| ApiError::not_found("authorization_not_found"))?;
    let _credentials = state.account_credentials.lock().await;
    match auth::poll_authorization(&pending)
        .await
        .map_err(|_| ApiError::internal("account_connection_poll_failed"))?
    {
        auth::AuthorizationPoll::Pending => Ok(Json(AccountConnectionResponse {
            signed_in: false,
            connection_state: Some(auth::AccountConnectionState::Disconnected),
            provider_display_name: None,
            display_name: None,
            auth_provider: None,
            device_name: None,
            credential_kind: None,
            credential_name: None,
            billing: None,
            credits: None,
            links: Some(auth::account_action_links(&pending.api_origin)),
        })),
        auth::AuthorizationPoll::Complete => {
            state
                .pending_authorizations
                .lock()
                .await
                .remove(&request_id);
            load_account_status().await
        }
    }
}

#[utoipa::path(delete, path = "/v1/account", summary = "Disconnect the LLM Notary account", description = "Removes the local account credentials. Future hosted sessions use public access until a new browser approval is completed. Injected API keys must instead be revoked in the hosted dashboard.", responses((status = 204, description = "Account disconnected; hosted sessions return to public access"), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_account_connection(State(state): State<AdminState>) -> Result<StatusCode, ApiError> {
    let _credentials = state.account_credentials.lock().await;
    if auth::api_key_mode_active()
        .map_err(|_| ApiError::internal("account_connection_configuration_failed"))?
    {
        return Err(ApiError::api_key_mode());
    }
    auth::logout_for_service()
        .await
        .map_err(|_| ApiError::internal("account_disconnect_failed"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum ShareVisibility {
    Unlisted,
    Listed,
}

impl From<ShareVisibility> for publish::ShareVisibility {
    fn from(value: ShareVisibility) -> Self {
        match value {
            ShareVisibility::Unlisted => Self::Unlisted,
            ShareVisibility::Listed => Self::Listed,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateShareRequest {
    visibility: ShareVisibility,
    /// Accept only unexplained high-entropy false positives after review.
    #[serde(default)]
    force: bool,
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/shares", summary = "Share a finalized verified session", description = "Verifies one finalized capture locally, applies the public disclosure safety policy, and uploads the exact package. Force overrides only unexplained high-entropy values.", params(("capture_id" = String, Path)), request_body = CreateShareRequest, responses((status = 202, body = ShareResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn share_capture(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
    Json(body): Json<CreateShareRequest>,
) -> Result<(StatusCode, Json<ShareResponse>), ApiError> {
    validate_id(&capture_id, "cap-")?;
    let bytes = finalized_bytes(&state.persistence, &capture_id).await?;
    let _credentials = state.account_credentials.lock().await;
    let shared_trust = if state.cluster_runtime.is_some() && state.config.notary.endpoint.is_none()
    {
        let (directory, source) = proxy::fetch_notary_directory_from(
            &auth::configured_api_origin()
                .map_err(|_| ApiError::internal("share_configuration_invalid"))?,
        )
        .await
        .map_err(|_| ApiError::service_unavailable("notary_directory_unavailable"))?;
        Some(
            state
                .persistence
                .cluster_metadata()
                .pin_notary_directory(directory, source.as_str())
                .await
                .map_err(|_| ApiError::service_unavailable("notary_trust_not_ready"))?,
        )
    } else {
        None
    };
    let (share, verified_capture_id, _) = publish::share_package_bytes(
        &bytes,
        state.config.notary.public_key.as_deref(),
        shared_trust.as_ref(),
        body.visibility.into(),
        body.force,
    )
    .await
    .map_err(|_| ApiError::internal("share_failed"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(ShareResponse {
            capture_id: verified_capture_id,
            status_url: format!("/v1/shares/{}", share.share_id),
            share_id: share.share_id,
            state: share.state,
            visibility: body.visibility,
            share_url: share.share_url,
            package_url: share.package_url,
        }),
    ))
}

#[utoipa::path(get, path = "/v1/shares/{share_id}", summary = "Get share status", description = "Returns the latest admission state and stable links for a share.", params(("share_id" = String, Path)), responses((status = 200, body = ShareStatusResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn share_status(
    State(state): State<AdminState>,
    Path(share_id): Path<String>,
) -> Result<Json<ShareStatusResponse>, ApiError> {
    validate_id(&share_id, "")?;
    let _credentials = state.account_credentials.lock().await;
    let status = publish::share_status(&share_id)
        .await
        .map_err(|error| match error {
            publish::ShareStatusError::Authentication => {
                ApiError::account_authentication_required()
            }
            publish::ShareStatusError::NotFound => ApiError::not_found("share_not_found"),
            publish::ShareStatusError::Unavailable => {
                ApiError::service_unavailable("share_status_unavailable")
            }
        })?;
    Ok(Json(ShareStatusResponse {
        share_id: status.share_id,
        state: status.state,
        failure_code: status.failure_code,
        visibility: match status.visibility {
            publish::ShareVisibility::Unlisted => ShareVisibility::Unlisted,
            publish::ShareVisibility::Listed => ShareVisibility::Listed,
        },
        share_url: status.share_url,
        package_url: status.package_url,
    }))
}

async fn artifact_record(
    persistence: &Persistence,
    capture_id: &str,
    kind: ArtifactKind,
) -> Result<ArtifactRecord, ApiError> {
    persistence
        .metadata
        .artifacts(capture_id)
        .await
        .map_err(|_| ApiError::internal("metadata_query_failed"))?
        .into_iter()
        .find(|artifact| artifact.key.kind() == kind)
        .ok_or_else(|| ApiError::not_found("finalized_trace_not_found"))
}

async fn finalized_bytes(persistence: &Persistence, capture_id: &str) -> Result<Vec<u8>, ApiError> {
    let record = artifact_record(persistence, capture_id, ArtifactKind::FinalizedPackage).await?;
    let verified = persistence
        .artifacts
        .read_verified(&record, MAX_ARCHIVE_WIRE_BYTES)
        .await
        .map_err(map_artifact_read_error)?;
    verified.into_bytes().await.map_err(map_artifact_read_error)
}

fn map_artifact_read_error(error: ArtifactStoreError) -> ApiError {
    match error {
        ArtifactStoreError::NotFound { .. } => ApiError::not_found("artifact_missing"),
        ArtifactStoreError::TooLarge { .. } => ApiError::internal("artifact_too_large"),
        ArtifactStoreError::Integrity { .. } => ApiError::internal("artifact_corrupt"),
        ArtifactStoreError::Conflict { .. } => ApiError::artifact_conflict(),
        ArtifactStoreError::InvalidInput {
            code: "artifact_backend_unconfigured",
            ..
        } => ApiError::service_unavailable("artifact_backend_unconfigured"),
        ArtifactStoreError::Unavailable | ArtifactStoreError::Backend { .. } => {
            ApiError::service_unavailable("artifact_backend_unavailable")
        }
        ArtifactStoreError::InvalidInput { .. } => ApiError::internal("artifact_invalid"),
    }
}

fn artifact_failure_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<ArtifactStoreError>()
        .map(ArtifactStoreError::failure_code)
}

fn finalization_failure_code(error: &anyhow::Error) -> &'static str {
    auth::hosted_admission_failure(error)
        .map(|failure| failure.code())
        .or_else(|| crate::notary_admission_error(error).map(|_| "notary_capacity"))
        .or_else(|| artifact_failure_code(error))
        .unwrap_or("finalization_error")
}

pub(crate) fn spawn_finalization_worker(
    persistence: Persistence,
    config: Arc<AgentConfig>,
    vault: Arc<Vault>,
    work_available: Arc<Notify>,
    cluster_runtime: Option<Arc<ClusterRuntime>>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if cluster_runtime
                .as_ref()
                .is_some_and(|cluster_runtime| cluster_runtime.lifecycle() == Lifecycle::Draining)
            {
                tokio::select! {
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
                continue;
            }
            if cluster_runtime.is_some() {
                let mut reaper_unavailable = false;
                loop {
                    match persistence
                        .cluster_metadata()
                        .interrupt_next_expired_finalization()
                        .await
                    {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(error) => {
                            tracing::warn!(
                                error = %error,
                                "finalization expiry recovery could not reach the metadata backend; retrying"
                            );
                            reaper_unavailable = true;
                            break;
                        }
                    }
                }
                if reaper_unavailable {
                    if wait_for_worker_retry(&mut shutdown).await {
                        return Ok(());
                    }
                    continue;
                }
            }
            let (operation, claim) = match &cluster_runtime {
                Some(cluster_runtime) => match persistence
                    .cluster_metadata()
                    .claim_next_finalization_claimed(
                        cluster_runtime.identity(),
                        &cluster_runtime.new_fence_token(),
                        cluster_runtime.lease_seconds(),
                    )
                    .await
                {
                    Ok(Some(claim)) => (Some(claim.operation.clone()), Some(claim)),
                    Ok(None) => (None, None),
                    Err(error) => {
                        tracing::warn!(error = %error, "finalization worker could not reach the metadata backend; retrying");
                        if wait_for_worker_retry(&mut shutdown).await {
                            return Ok(());
                        }
                        continue;
                    }
                },
                None => match persistence
                    .metadata
                    .claim_next_finalization(now_ms()?)
                    .await
                {
                    Ok(operation) => (operation, None),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "finalization worker could not reach the metadata backend; retrying"
                        );
                        if wait_for_worker_retry(&mut shutdown).await {
                            return Ok(());
                        }
                        continue;
                    }
                },
            };
            let Some(operation) = operation else {
                tokio::select! {
                    () = work_available.notified() => {},
                    () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {},
                    result = shutdown.changed() => {
                        if result.is_err() || *shutdown.borrow() {
                            return Ok(());
                        }
                    },
                }
                continue;
            };
            let result = finalize_operation(
                &persistence,
                &config,
                &vault,
                &operation,
                claim.as_ref(),
                cluster_runtime.as_deref(),
            )
            .await;
            let now = now_ms()?;
            let failure_code = result.as_ref().err().map(finalization_failure_code);
            loop {
                let transition = match (&result, failure_code) {
                    (Ok(artifact), None) if claim.is_some() => {
                        persistence
                            .cluster_metadata()
                            .complete_finalization_claimed(
                                claim.as_ref().expect("checked"),
                                artifact.clone(),
                                now,
                            )
                            .await
                    }
                    (Err(_), Some(code)) if claim.is_some() => {
                        persistence
                            .cluster_metadata()
                            .fail_operation_claimed(claim.as_ref().expect("checked"), now, code)
                            .await
                    }
                    (Ok(artifact), None) => {
                        persistence
                            .metadata
                            .complete_finalization(&operation.operation_id, artifact.clone(), now)
                            .await
                    }
                    (Err(_), Some(code)) => {
                        persistence
                            .metadata
                            .fail_operation(&operation.operation_id, now, code)
                            .await
                    }
                    _ => unreachable!("finalization result and failure code must agree"),
                };
                match transition {
                    Ok(outcome) => {
                        require_terminal_operation_result(outcome)?;
                        break;
                    }
                    Err(MetadataStoreError::Fenced) if claim.is_some() => {
                        tracing::warn!(
                            operation_id = %operation.operation_id,
                            "stale finalization worker was fenced before its terminal transition"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(
                            operation_id = %operation.operation_id,
                            error = %error,
                            "finalization worker could not persist a terminal transition; retrying"
                        );
                        if wait_for_worker_retry(&mut shutdown).await {
                            return Ok(());
                        }
                    }
                }
            }
            if let Some(code) = failure_code {
                tracing::warn!(operation_id = %operation.operation_id, failure_code = code, "finalization operation failed");
            }
            if *shutdown.borrow() {
                return Ok(());
            }
        }
    })
}

async fn wait_for_worker_retry(shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(std::time::Duration::from_secs(2)) => false,
        result = shutdown.changed() => result.is_err() || *shutdown.borrow(),
    }
}

fn require_terminal_operation_result(outcome: TerminalOperationResult) -> Result<()> {
    match outcome {
        TerminalOperationResult::Applied | TerminalOperationResult::AlreadyApplied => Ok(()),
        TerminalOperationResult::NotFound => {
            anyhow::bail!("claimed finalization operation no longer exists")
        }
        TerminalOperationResult::Conflict { current_state } => {
            anyhow::bail!("claimed finalization operation is already {current_state}")
        }
    }
}

async fn finalize_operation(
    persistence: &Persistence,
    config: &AgentConfig,
    vault: &Arc<Vault>,
    operation: &Operation,
    claim: Option<&FinalizationClaim>,
    cluster_runtime: Option<&ClusterRuntime>,
) -> Result<ArtifactRecord> {
    let _claim_lease = match (cluster_runtime, claim) {
        (Some(cluster_runtime), Some(claim)) => {
            Some(cluster_runtime.keep_finalization_claim_alive(
                persistence.cluster_metadata().clone(),
                claim.clone(),
            ))
        }
        _ => None,
    };
    let last_proof_update = AtomicU64::new(0);
    let (progress_sender, mut progress_receiver) = tokio::sync::mpsc::unbounded_channel();
    let progress_metadata = persistence.metadata.clone();
    let progress_cluster_metadata = cluster_runtime.map(|_| persistence.cluster_metadata().clone());
    let progress_operation_id = operation.operation_id.clone();
    let progress_claim = claim.cloned();
    let progress_lease_seconds = cluster_runtime.map(ClusterRuntime::lease_seconds);
    let progress_recorder = tokio::spawn(async move {
        while let Some((progress, now)) = progress_receiver.recv().await {
            let result = match (progress_claim.as_ref(), progress_lease_seconds, progress) {
                (Some(claim), Some(lease), crate::FinalizationProgress::Phase(phase)) => {
                    progress_cluster_metadata
                        .as_ref()
                        .expect("claimed progress requires server metadata")
                        .update_operation_progress_claimed(claim, phase, now, lease)
                        .await
                }
                (Some(claim), Some(lease), crate::FinalizationProgress::Proof(proof)) => {
                    progress_cluster_metadata
                        .as_ref()
                        .expect("claimed progress requires server metadata")
                        .update_operation_proof_progress_claimed(claim, proof, now, lease)
                        .await
                }
                (None, _, crate::FinalizationProgress::Phase(phase)) => {
                    progress_metadata
                        .update_operation_progress(&progress_operation_id, phase, now)
                        .await
                }
                (None, _, crate::FinalizationProgress::Proof(proof)) => {
                    progress_metadata
                        .update_operation_proof_progress(&progress_operation_id, proof, now)
                        .await
                }
                (Some(_), None, _) => Err(MetadataStoreError::InvalidInput(
                    "server_claim_missing_lease",
                )),
            };
            if let Err(error) = result {
                tracing::warn!(
                    operation_id = %progress_operation_id,
                    error = %error,
                    "could not persist finalization progress"
                );
            }
        }
    });
    let report_progress = |progress| {
        let result = now_ms().map(|now| match progress {
            crate::FinalizationProgress::Phase(_) => {
                let _ = progress_sender.send((progress, now));
            }
            crate::FinalizationProgress::Proof(proof) => {
                let last = last_proof_update.load(Ordering::Relaxed);
                let complete = proof.bytes_completed == proof.bytes_total
                    && proof.commitments_completed == proof.commitments_total;
                if last != 0 && !complete && now.saturating_sub(last) < 1_000 {
                    return;
                }
                last_proof_update.store(now, Ordering::Relaxed);
                let _ = progress_sender.send((progress, now));
            }
        });
        if let Err(error) = result {
            tracing::warn!(
                operation_id = %operation.operation_id,
                error = %error,
                "could not persist finalization progress"
            );
        }
    };
    let capture_id = operation
        .capture_id
        .as_deref()
        .context("finalization operation has no capture")?;
    let bundle_record = persistence
        .metadata
        .artifacts(capture_id)
        .await?
        .into_iter()
        .find(|artifact| artifact.key.kind() == ArtifactKind::DeferredBundle)
        .context("capture has no encrypted deferred bundle")?;
    let bundle_bytes = persistence
        .artifacts
        .read_verified(&bundle_record, MAX_ARCHIVE_WIRE_BYTES)
        .await?
        .into_bytes()
        .await?;
    let bundle_vault = vault.clone();
    let bundle = tokio::task::spawn_blocking(move || {
        DeferredBundle::from_encrypted_bytes(&bundle_bytes, &bundle_vault)
    })
    .await
    .context("deferred bundle decryption task failed")??;
    anyhow::ensure!(
        bundle.capture_id() == capture_id,
        "deferred bundle capture does not match finalization operation"
    );
    let finalized_key = ArtifactKey::new(capture_id, ArtifactKind::FinalizedPackage)?;
    if claim.is_none()
        && let Some(existing) = persistence
            .artifacts
            .find(&finalized_key, MAX_ARCHIVE_WIRE_BYTES)
            .await?
    {
        let bytes = persistence
            .artifacts
            .read_verified(&existing, MAX_ARCHIVE_WIRE_BYTES)
            .await?
            .into_bytes()
            .await?;
        let (bytes, embedded_key, created_at) = tokio::task::spawn_blocking(move || {
            let embedded_key = trace_package_notary_key_bytes(&bytes)?;
            let created_at = trace_package_created_at_unix_ms_bytes(&bytes)?;
            Ok::<_, anyhow::Error>((bytes, embedded_key, created_at))
        })
        .await
        .context("finalized package inspection task failed")??;
        let key = match config.notary_public_key()? {
            Some(key) => key,
            None => {
                notary::cached_key_at(&embedded_key, created_at)?;
                embedded_key
            }
        };
        let verified_capture_id = tokio::task::spawn_blocking(move || {
            verify_trace_package_bytes(&bytes, &key)
                .map(|verified| verified.manifest.capture_id().to_owned())
        })
        .await
        .context("finalized package verification task failed")??;
        anyhow::ensure!(
            verified_capture_id == capture_id,
            "finalized package capture does not match finalization operation"
        );
        drop(progress_sender);
        progress_recorder
            .await
            .context("progress recorder exited")?;
        return Ok(existing);
    }
    let hosted_admission = proxy::hosted_admission_required(config);
    let (key, endpoint) = match (config.notary_public_key()?, config.notary_endpoint()?) {
        (Some(key), Some(endpoint)) => {
            bundle.verify_notary_key(&key)?;
            (key, endpoint)
        }
        (None, None) => {
            let (key, record) = if cluster_runtime.is_some() {
                let (directory, source) =
                    proxy::fetch_notary_directory_from(&auth::configured_api_origin()?).await?;
                let trust = persistence
                    .cluster_metadata()
                    .pin_notary_directory(directory, source.as_str())
                    .await?;
                notary::shared_record_for_bundle(&trust, &bundle)?
            } else {
                let _ = proxy::refresh_notary_directory().await;
                notary::cached_record_for_bundle(&bundle)?
            };
            let endpoint = proxy::resolve_notary(&record).await?;
            (key, endpoint)
        }
        _ => anyhow::bail!("notary endpoint and public key configuration are inconsistent"),
    };
    let package_result = if hosted_admission {
        let allowance = bundle.finalization_allowance_bytes()?;
        if allowance > config.proxy.max_attestable_http_bytes {
            anyhow::bail!("bundle exceeds the current local finalization byte limit");
        }
        let admission =
            auth::issue_finalization_admission(&bundle.record_digest_hex(), allowance).await?;
        finalize_bundle_admitted_bytes_with_progress(
            &bundle,
            &key,
            &endpoint,
            config
                .proxy
                .max_attestable_http_bytes
                .min(admission.max_attestable_http_bytes),
            config.notary.max_frame_bytes.min(admission.max_frame_bytes),
            &admission.ticket,
            &report_progress,
        )
        .await
    } else {
        finalize_bundle_bytes_with_progress(
            &bundle,
            &key,
            &endpoint,
            config.proxy.max_attestable_http_bytes,
            config.notary.max_frame_bytes,
            &report_progress,
        )
        .await
    };
    drop(progress_sender);
    progress_recorder
        .await
        .context("progress recorder exited")?;
    let package = package_result?;
    let record = if let Some(claim) = claim {
        persistence
            .artifacts
            .put_scoped(
                &finalized_key,
                &claim.publication_id,
                ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?
    } else {
        persistence
            .artifacts
            .put(
                &finalized_key,
                ArtifactSource::from_bytes(package),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await?
    };
    #[cfg(feature = "daemon-e2e")]
    if let Some(milliseconds) =
        std::env::var_os("LLM_NOTARY_DAEMON_E2E_PAUSE_AFTER_FINALIZED_ARTIFACT_MS")
    {
        let milliseconds = milliseconds
            .to_str()
            .context("Docker E2E finalization pause must be UTF-8")?
            .parse::<u64>()
            .context("Docker E2E finalization pause must be milliseconds")?;
        anyhow::ensure!(
            milliseconds <= 60_000,
            "Docker E2E finalization pause exceeds 60 seconds"
        );
        if milliseconds > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
        }
    }
    Ok(record)
}

fn validate_id(value: &str, prefix: &str) -> Result<(), ApiError> {
    if value.starts_with(prefix)
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid_identifier"))
    }
}

fn new_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn basic_credentials(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))?;
    if !value.0.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(value.1).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

async fn basic_matches(state: &AdminState, headers: &axum::http::HeaderMap) -> bool {
    let Some(auth) = state.config.admin.auth.as_ref() else {
        return true;
    };
    let Some((username, password)) = basic_credentials(headers) else {
        return false;
    };
    if username != auth.username {
        return false;
    }
    let Some(password_hash) = auth.password_hash.clone() else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}

fn unauthorized_response() -> Response {
    let mut response = ApiError::unauthorized().into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"LLM Notary\", charset=\"UTF-8\""),
    );
    response
}

fn session_from_headers(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix(&format!("{SESSION_COOKIE}=")))
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64")
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthResponse {
    service: String,
    status: String,
    api_version: String,
    build_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ReadinessResponse {
    service: String,
    status: String,
    metadata_backend: String,
    artifact_backend: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct CountsResponse {
    total_captures: u64,
    capturing: u64,
    ready_to_finalize: u64,
    finalized: u64,
    failed: u64,
    active_operations: u64,
}

impl From<crate::metadata::MetadataCounts> for CountsResponse {
    fn from(value: crate::metadata::MetadataCounts) -> Self {
        Self {
            total_captures: value.total_captures,
            capturing: value.capturing,
            ready_to_finalize: value.ready_to_finalize,
            finalized: value.finalized,
            failed: value.failed,
            active_operations: value.active_operations,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusResponse {
    version: String,
    build_id: String,
    runtime_profile: String,
    instance_id: Option<String>,
    incarnation_id: Option<String>,
    lifecycle: String,
    capture_enabled: bool,
    proxy_listener: String,
    admin_listener: String,
    proxy_origin: String,
    admin_origin: String,
    metadata_backend: String,
    metadata_status: String,
    artifact_backend: String,
    artifact_status: String,
    vault: String,
    notary: String,
    preview_chars: usize,
    counts: CountsResponse,
    updates: UpdateStatusResponse,
}

#[derive(Debug, Serialize, ToSchema)]
struct CaptureSettingResponse {
    enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
struct UpdateCaptureSetting {
    enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct UpdateStatusResponse {
    enabled: bool,
    current_build_id: String,
    latest_build_id: Option<String>,
    update_available: bool,
    last_checked_unix_ms: Option<u64>,
    error_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct NotariesResponse {
    /// `directory` for the locally pinned trust store or
    /// `explicit_configuration` for a self-hosted endpoint and key.
    source: String,
    /// Public URL from which the current pinned directory generation came.
    directory_source: Option<String>,
    generation: Option<u64>,
    /// Selected active directory key. Explicit configuration has no directory
    /// lifecycle selection and therefore leaves this field unset.
    active_key_id: Option<String>,
    notaries: Vec<NotaryResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
struct NotaryResponse {
    endpoint: String,
    transport: String,
    key_id: String,
    /// One of `active`, `retiring`, `retired`, `revoked`, or `configured`.
    status: String,
    valid_from_unix_ms: Option<u64>,
    valid_until_unix_ms: Option<u64>,
    finalize_until_unix_ms: Option<u64>,
}

impl From<NotaryDirectoryRecord> for NotaryResponse {
    fn from(record: NotaryDirectoryRecord) -> Self {
        let endpoint = record
            .endpoint()
            .expect("validated pinned notary record has an endpoint")
            .to_string();
        Self {
            endpoint,
            transport: record.transport.scheme().into(),
            key_id: record.key_id,
            status: match record.status {
                NotaryKeyStatus::Active => "active",
                NotaryKeyStatus::Retiring => "retiring",
                NotaryKeyStatus::Retired => "retired",
                NotaryKeyStatus::Revoked => "revoked",
            }
            .into(),
            valid_from_unix_ms: Some(record.valid_from_unix_ms),
            valid_until_unix_ms: record.valid_until_unix_ms,
            finalize_until_unix_ms: record.finalize_until_unix_ms,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct CaptureResponse {
    capture_id: String,
    created_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
    provider: String,
    operation: String,
    requested_model: Option<String>,
    response_model: Option<String>,
    http_status: Option<u16>,
    streaming: bool,
    request_bytes: u64,
    response_bytes: Option<u64>,
    duration_ms: Option<u64>,
    capture_state: String,
    finalization_state: String,
    finalization_eligible: bool,
    finalization_ineligibility_code: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
    output_preview: String,
    output_preview_truncated: bool,
    failure_code: Option<String>,
}

impl From<CaptureSummary> for CaptureResponse {
    fn from(value: CaptureSummary) -> Self {
        let finalization_eligible = finalization_eligible(&value);
        let finalization_ineligibility_code = finalization_ineligibility_code(&value);
        Self {
            capture_id: value.capture_id,
            created_at_unix_ms: value.created_at_unix_ms,
            completed_at_unix_ms: value.completed_at_unix_ms,
            provider: value.provider,
            operation: value.operation,
            requested_model: value.requested_model,
            response_model: value.response_model,
            http_status: value.http_status,
            streaming: value.streaming,
            request_bytes: value.request_bytes,
            response_bytes: value.response_bytes,
            duration_ms: value.duration_ms,
            capture_state: value.capture_state,
            finalization_state: value.finalization_state,
            finalization_eligible,
            finalization_ineligibility_code: finalization_ineligibility_code.map(str::to_owned),
            prompt_preview: value.prompt_preview,
            prompt_preview_truncated: value.prompt_preview_truncated,
            output_preview: value.output_preview,
            output_preview_truncated: value.output_preview_truncated,
            failure_code: value.failure_code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct ArtifactResponse {
    kind: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct CaptureDetailResponse {
    capture: CaptureResponse,
    artifacts: Vec<ArtifactResponse>,
    finalizations: Vec<OperationResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationResponse {
    operation_id: String,
    kind: String,
    capture_id: Option<String>,
    state: String,
    attempt: u32,
    created_at_unix_ms: u64,
    started_at_unix_ms: Option<u64>,
    completed_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
    progress: OperationProgressResponse,
    retryable: bool,
    attempt_history: Vec<OperationAttemptResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationSummaryResponse {
    operation_id: String,
    kind: String,
    capture_id: Option<String>,
    state: String,
    attempt: u32,
    created_at_unix_ms: u64,
    started_at_unix_ms: Option<u64>,
    completed_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
    progress: OperationProgressResponse,
}

impl From<Operation> for OperationSummaryResponse {
    fn from(value: Operation) -> Self {
        let progress = OperationProgressResponse::from(&value);
        Self {
            operation_id: value.operation_id,
            kind: value.kind,
            capture_id: value.capture_id,
            state: value.state,
            attempt: value.attempt,
            created_at_unix_ms: value.created_at_unix_ms,
            started_at_unix_ms: value.started_at_unix_ms,
            completed_at_unix_ms: value.completed_at_unix_ms,
            failure_code: value.failure_code,
            progress,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationProgressResponse {
    /// Current milestone: queued, preparing, proving, signing, packaging,
    /// complete, or unknown for an operation migrated from an older catalog.
    phase: String,
    /// Concrete work counters while the private proof is being generated.
    proof: Option<OperationProofProgressResponse>,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationProofProgressResponse {
    bytes_completed: u64,
    bytes_total: u64,
    commitments_completed: u64,
    commitments_total: u64,
}

impl From<&Operation> for OperationProgressResponse {
    fn from(value: &Operation) -> Self {
        Self {
            phase: value.progress_phase.clone(),
            proof: (value.proof_commitments_total > 0).then_some(OperationProofProgressResponse {
                bytes_completed: value.proof_bytes_completed,
                bytes_total: value.proof_bytes_total,
                commitments_completed: value.proof_commitments_completed,
                commitments_total: value.proof_commitments_total,
            }),
            updated_at_unix_ms: value.progress_updated_at_unix_ms,
        }
    }
}

async fn operation_response(
    metadata: &Arc<dyn MetadataStore>,
    value: Operation,
) -> Result<OperationResponse> {
    let attempt_history = metadata
        .operation_attempts(&value.operation_id)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let eligible_capture = match value.capture_id.as_deref() {
        Some(capture_id) => metadata
            .capture(capture_id)
            .await?
            .is_some_and(|capture| finalization_eligible(&capture)),
        None => false,
    };
    let retryable = ["failed", "interrupted"].contains(&value.state.as_str()) && eligible_capture;
    let progress = OperationProgressResponse::from(&value);
    Ok(OperationResponse {
        operation_id: value.operation_id,
        kind: value.kind,
        capture_id: value.capture_id,
        state: value.state,
        attempt: value.attempt,
        created_at_unix_ms: value.created_at_unix_ms,
        started_at_unix_ms: value.started_at_unix_ms,
        completed_at_unix_ms: value.completed_at_unix_ms,
        failure_code: value.failure_code,
        progress,
        retryable,
        attempt_history,
    })
}

const UNSUPPORTED_PROVIDER_HTTP_STATUS: &str = "unsupported_provider_http_status";

fn finalization_eligible(capture: &CaptureSummary) -> bool {
    capture
        .http_status
        .is_some_and(|status| (200..=299).contains(&status))
}

fn finalization_ineligibility_code(capture: &CaptureSummary) -> Option<&'static str> {
    capture
        .http_status
        .is_some_and(|status| !(200..=299).contains(&status))
        .then_some(UNSUPPORTED_PROVIDER_HTTP_STATUS)
}

#[derive(Debug, Serialize, ToSchema)]
struct OperationAttemptResponse {
    attempt: u32,
    state: String,
    started_at_unix_ms: u64,
    completed_at_unix_ms: Option<u64>,
    failure_code: Option<String>,
}

impl From<OperationAttempt> for OperationAttemptResponse {
    fn from(value: OperationAttempt) -> Self {
        Self {
            attempt: value.attempt,
            state: value.state,
            started_at_unix_ms: value.started_at_unix_ms,
            completed_at_unix_ms: value.completed_at_unix_ms,
            failure_code: value.failure_code,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct FinalizationResponse {
    operation: OperationResponse,
    deduplicated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct EventResponse {
    event_id: u64,
    created_at_unix_ms: u64,
    event_type: String,
    capture_id: Option<String>,
    operation_id: Option<String>,
    severity: String,
    message: String,
}

impl From<Event> for EventResponse {
    fn from(value: Event) -> Self {
        Self {
            event_id: value.event_id,
            created_at_unix_ms: value.created_at_unix_ms,
            event_type: value.event_type,
            capture_id: value.capture_id,
            operation_id: value.operation_id,
            severity: value.severity,
            message: value.message,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct EventListResponse {
    items: Vec<EventResponse>,
    next_cursor: Option<String>,
    /// Snapshot cursor for polling events committed after this response.
    high_water_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EventPagePosition {
    event_id: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct TraceResponse {
    capture_id: String,
    manifest: serde_json::Value,
    trace: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
struct VerificationResponse {
    capture_id: String,
    verified: bool,
    verified_at_unix_ms: u64,
    notary_key_id: String,
    trust_source: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct AccountConnectionResponse {
    signed_in: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_state: Option<auth::AccountConnectionState>,
    provider_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_provider: Option<String>,
    device_name: Option<String>,
    credential_kind: Option<String>,
    credential_name: Option<String>,
    billing: Option<auth::BillingState>,
    credits: Option<auth::CreditSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<auth::AccountActionLinks>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AccountConnectionStartedResponse {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in_seconds: u64,
    poll_interval_seconds: u64,
    state: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ShareResponse {
    capture_id: String,
    share_id: String,
    state: String,
    visibility: ShareVisibility,
    status_url: String,
    share_url: Option<String>,
    package_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ShareStatusResponse {
    share_id: String,
    state: String,
    failure_code: Option<String>,
    visibility: ShareVisibility,
    share_url: Option<String>,
    package_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorEnvelope {
    error: ErrorBody,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

fn pagination_api_error(error: PaginationError) -> ApiError {
    if error.is_client_error() {
        ApiError::bad_request(error.code())
    } else {
        ApiError::internal(error.code())
    }
}

fn validate_persisted_cursor_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| pagination_api_error(PaginationError::MalformedCursor))
}

fn validate_persisted_query_integer(value: u64) -> Result<(), ApiError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| ApiError::bad_request("invalid_query_parameter"))
}

fn metadata_api_error(error: MetadataStoreError) -> ApiError {
    match error.invalid_code() {
        Some(code) => ApiError::bad_request(code),
        None => ApiError::internal("metadata_query_failed"),
    }
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "authentication_required",
            message: "Admin authentication is required",
        }
    }
    fn bad_request(code: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: "The request is invalid",
        }
    }
    fn not_found(code: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            message: "The requested resource was not found",
        }
    }
    fn conflict(code: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: "The operation is not retryable",
        }
    }
    fn artifact_conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "artifact_collision",
            message: "Stored artifact bytes conflict with the immutable artifact record",
        }
    }
    fn api_key_mode() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "api_key_mode",
            message: "Browser login and logout are unavailable while the daemon uses an injected API key",
        }
    }
    fn finalization_ineligible() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: UNSUPPORTED_PROVIDER_HTTP_STATUS,
            message: "Finalization supports successful provider responses only",
        }
    }
    fn unprocessable(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: "The finalized trace did not verify",
        }
    }
    fn account_authentication_required() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "account_authentication_required",
            message: "LLM Notary account connection must be renewed",
        }
    }
    fn service_unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: "A required service dependency is temporarily unavailable",
        }
    }
    fn internal(code: &'static str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code,
            message: "The local service could not complete the request",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code.into(),
                    message: self.message.into(),
                },
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{PasswordHasher, password_hash::SaltString};
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use std::{io::Write as IoWrite, sync::Mutex as StdMutex};
    use tower::ServiceExt as _;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedLog(Arc<StdMutex<Vec<u8>>>);

    struct SharedLogWriter(Arc<StdMutex<Vec<u8>>>);

    impl IoWrite for SharedLogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for SharedLog {
        type Writer = SharedLogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            SharedLogWriter(self.0.clone())
        }
    }

    #[test]
    fn finalization_failures_preserve_hosted_admission_outcomes() {
        for (rejection, expected) in [
            (
                crate::NotaryAdmissionRejection::AdmissionExpired,
                "hosted_admission_expired",
            ),
            (
                crate::NotaryAdmissionRejection::AdmissionServiceUnavailable,
                "hosted_admission_unavailable",
            ),
            (
                crate::NotaryAdmissionRejection::FinalizationAllowanceExhausted,
                "finalization_credits_exhausted",
            ),
            (
                crate::NotaryAdmissionRejection::FinalizeAtCapacity,
                "notary_capacity",
            ),
        ] {
            let error = anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                rejection,
                Duration::from_secs(5),
            ));
            assert_eq!(finalization_failure_code(&error), expected);
        }

        let acquisition = anyhow::Error::new(auth::hosted_admission_denial(
            "finalization_credits_exhausted",
        ));
        assert_eq!(
            finalization_failure_code(&acquisition),
            "finalization_credits_exhausted"
        );
    }

    async fn state(directory: &std::path::Path) -> AdminState {
        state_with_auth(directory, None).await
    }

    async fn protected_state(directory: &std::path::Path) -> AdminState {
        let salt = SaltString::encode_b64(b"llm-notary-test-salt").unwrap();
        let password_hash = Argon2::default()
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();
        state_with_auth(
            directory,
            Some(crate::config::AdminAuthConfig {
                username: "local-admin".to_owned(),
                password_hash: Some(password_hash),
            }),
        )
        .await
    }

    async fn state_with_auth(
        directory: &std::path::Path,
        auth: Option<crate::config::AdminAuthConfig>,
    ) -> AdminState {
        let mut config = AgentConfig::default();
        config.catalog.path = directory.join("catalog.db");
        config.storage.bundle_dir = directory.join("bundles");
        config.storage.finalized_dir = directory.join("traces");
        config.admin.auth = auth;
        let persistence = Persistence::open(&config).await.unwrap();
        AdminState::new(persistence, Arc::new(config), None, None, None)
            .await
            .unwrap()
    }

    fn basic_header(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        )
    }

    fn notary_record(seed: u8, status: NotaryKeyStatus, valid_from: u64) -> NotaryDirectoryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        NotaryDirectoryRecord {
            host: format!("notary-{seed}.example"),
            port: 7047,
            transport: crate::notary_directory::NotaryTransport::Tls,
            key_id: key_id(&public_key),
            public_key: hex::encode(public_key),
            status,
            valid_from_unix_ms: valid_from,
            valid_until_unix_ms: Some(valid_from + 1_000),
            finalize_until_unix_ms: Some(valid_from + 2_000),
        }
    }

    #[tokio::test]
    async fn admin_routes_are_open_by_default() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn capture_setting_is_authoritative_durable_and_reflected_in_status() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::put("/v1/settings/capture")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let setting: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(setting["enabled"], false);

        let status = app
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["capture_enabled"], false);

        let persistence = Persistence::open(&{
            let mut config = AgentConfig::default();
            config.catalog.path = directory.path().join("catalog.db");
            config.storage.bundle_dir = directory.path().join("bundles");
            config.storage.finalized_dir = directory.path().join("traces");
            config
        })
        .await
        .unwrap();
        assert!(!persistence.metadata.capture_enabled().await.unwrap());
    }

    #[tokio::test]
    async fn protected_routes_reject_missing_or_wrong_auth_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(protected_state(directory.path()).await).unwrap();
        let wrong_header = basic_header("local-admin", "deliberately-wrong-secret");
        for value in [None, Some(wrong_header.as_str())] {
            let mut request = Request::builder().uri("/v1/status");
            if let Some(value) = value {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&body).contains("deliberately-wrong-secret"));
        }

        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/captures/cap-example/finalizations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(
                Request::put("/v1/settings/capture")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"enabled":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/status")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", "correct horse battery staple"),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn portable_trace_verification_rejects_invalid_uploaded_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(protected_state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::post("/v1/traces:verify")
                    .header(
                        header::AUTHORIZATION,
                        basic_header("local-admin", "correct horse battery staple"),
                    )
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.llmnotary.trace-package+zip",
                    )
                    .body(Body::from("not a trace package"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], "trace_verification_failed");
    }

    #[test]
    fn request_tracing_never_logs_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let output = Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(SharedLog(output.clone()))
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let secret = "deliberately-wrong-secret-that-must-not-appear";
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = tracing::dispatcher::with_default(&dispatch, || {
            // This unique callsite proves the test writer is active even when
            // other parallel tests have already populated tracing's global
            // callsite-interest cache without a subscriber.
            tracing::info!(request_path = "/v1/status", "capturing admin request logs");
            runtime.block_on(async {
                router(protected_state(directory.path()).await)
                    .unwrap()
                    .oneshot(
                        Request::get(format!("/v1/status?query={secret}"))
                            .header(header::AUTHORIZATION, basic_header("local-admin", secret))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            })
        });

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("/v1/status"));
        assert!(!logs.contains(secret));
    }

    #[tokio::test]
    async fn openapi_covers_every_admin_route_and_is_public() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["openapi"], "3.1.0");
        assert!(body["components"]["securitySchemes"]["basicAuth"].is_object());
        for path in [
            "/healthz",
            "/readyz",
            "/openapi.json",
            "/v1/status",
            "/v1/settings/capture",
            "/v1/notaries",
            "/v1/captures",
            "/v1/captures/{capture_id}",
            "/v1/captures/{capture_id}/finalizations",
            "/v1/operations",
            "/v1/operations/{operation_id}",
            "/v1/operations/{operation_id}/retry",
            "/v1/captures/{capture_id}/trace",
            "/v1/captures/{capture_id}/package",
            "/v1/captures/{capture_id}/trace:verify",
            "/v1/traces:verify",
            "/v1/events",
            "/v1/session",
            "/v1/account",
            "/v1/account/{request_id}",
            "/v1/captures/{capture_id}/shares",
            "/v1/shares/{share_id}",
        ] {
            assert!(body["paths"].get(path).is_some(), "OpenAPI missing {path}");
        }
        for (path, method) in [
            ("/v1/status", "get"),
            ("/v1/settings/capture", "get"),
            ("/v1/settings/capture", "put"),
            ("/v1/notaries", "get"),
            ("/v1/captures", "get"),
            ("/v1/captures/{capture_id}", "get"),
            ("/v1/captures/{capture_id}/finalizations", "post"),
            ("/v1/operations", "get"),
            ("/v1/operations/{operation_id}", "get"),
            ("/v1/operations/{operation_id}/retry", "post"),
            ("/v1/captures/{capture_id}/trace", "get"),
            ("/v1/captures/{capture_id}/package", "get"),
            ("/v1/captures/{capture_id}/trace:verify", "post"),
            ("/v1/traces:verify", "post"),
            ("/v1/events", "get"),
            ("/v1/account", "get"),
            ("/v1/account", "post"),
            ("/v1/account", "delete"),
            ("/v1/account/{request_id}", "get"),
            ("/v1/captures/{capture_id}/shares", "post"),
            ("/v1/shares/{share_id}", "get"),
            ("/v1/session", "delete"),
        ] {
            assert!(
                body["paths"][path][method]["responses"]["401"].is_object(),
                "OpenAPI missing the protected response for {method} {path}"
            );
            assert_eq!(
                body["paths"][path][method]["security"],
                serde_json::json!([{}, {"basicAuth": []}]),
                "OpenAPI must describe optional Basic authentication for {method} {path}"
            );
        }
        let mut documented_operations = 0;
        for path in body["paths"].as_object().unwrap().values() {
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(operation) = path.get(method) else {
                    continue;
                };
                assert!(
                    operation["summary"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} operation is missing a summary"
                );
                assert!(
                    operation["description"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "OpenAPI {method} operation is missing a description"
                );
                documented_operations += 1;
            }
        }
        assert_eq!(documented_operations, 26);
    }

    #[tokio::test]
    async fn package_download_returns_the_exact_stored_llmtrace() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        let capture_id = "cap-download";
        state
            .persistence
            .metadata
            .begin_capture(crate::metadata::NewCapture {
                capture_id: capture_id.to_owned(),
                created_at_unix_ms: 1,
                provider: "openai".to_owned(),
                operation: "responses".to_owned(),
                requested_model: Some("gpt-5".to_owned()),
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".to_owned(),
            })
            .await
            .unwrap();
        let deferred = state
            .persistence
            .artifacts
            .put(
                &ArtifactKey::new(capture_id, ArtifactKind::DeferredBundle).unwrap(),
                ArtifactSource::from_bytes(b"encrypted bundle fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    capture_id: capture_id.to_owned(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: Some("gpt-5".to_owned()),
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: deferred.size_bytes,
                    expected_artifact_sha256: deferred.sha256.clone(),
                },
                deferred,
            )
            .await
            .unwrap();
        let expected = b"exact canonical archive bytes";
        let key = ArtifactKey::new(capture_id, ArtifactKind::FinalizedPackage).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(expected.to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        let operation = state
            .persistence
            .metadata
            .enqueue_finalization(capture_id, 3)
            .await
            .unwrap()
            .unwrap()
            .0;
        let running = state
            .persistence
            .metadata
            .claim_next_finalization(4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(running.operation_id, operation.operation_id);
        state
            .persistence
            .metadata
            .complete_finalization(&running.operation_id, artifact, 5)
            .await
            .unwrap();

        let response = router(state)
            .unwrap()
            .oneshot(
                Request::get(format!("/v1/captures/{capture_id}/package"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            ARCHIVE_CONTENT_TYPE
        );
        assert_eq!(
            response.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"cap-download.llmtrace\""
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected.as_slice()
        );
    }

    #[test]
    fn directory_notary_projection_orders_lifecycle_and_retains_revocations() {
        let active = notary_record(1, NotaryKeyStatus::Active, 100);
        let retiring = notary_record(2, NotaryKeyStatus::Retiring, 90);
        let retired = notary_record(3, NotaryKeyStatus::Retired, 80);
        let revoked = notary_record(4, NotaryKeyStatus::Revoked, 110);
        let response = directory_notaries_response(notary::PinnedNotaryState {
            directory_source: Some("https://example.test/api/notary".into()),
            generation: 7,
            active_key_id: active.key_id.clone(),
            records: vec![
                revoked.clone(),
                retired.clone(),
                active.clone(),
                retiring.clone(),
            ],
        });

        assert_eq!(response.source, "directory");
        assert_eq!(response.generation, Some(7));
        assert_eq!(
            response.active_key_id.as_deref(),
            Some(active.key_id.as_str())
        );
        assert_eq!(
            response
                .notaries
                .iter()
                .map(|record| record.status.as_str())
                .collect::<Vec<_>>(),
            ["active", "retiring", "retired", "revoked"]
        );
        let revoked_response = response.notaries.last().unwrap();
        assert_eq!(revoked_response.key_id, revoked.key_id);
        assert_eq!(revoked_response.endpoint, "tls://notary-4.example:7047");
    }

    #[test]
    fn explicit_notary_projection_does_not_claim_directory_membership() {
        let signing = k256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap();
        let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
        let mut config = AgentConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".into());
        config.notary.public_key = Some(hex::encode(&public_key));

        let response = notaries_response(&config, None).unwrap();

        assert_eq!(response.source, "explicit_configuration");
        assert_eq!(response.directory_source, None);
        assert_eq!(response.generation, None);
        assert_eq!(response.active_key_id, None);
        assert_eq!(response.notaries.len(), 1);
        assert_eq!(response.notaries[0].status, "configured");
        assert_eq!(response.notaries[0].key_id, key_id(&public_key));
        assert_eq!(response.notaries[0].endpoint, "tcp://127.0.0.1:7047");
    }

    #[tokio::test]
    async fn invalid_numeric_queries_use_the_json_error_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        for path in [
            "/v1/captures?limit=-1",
            "/v1/operations?limit=-1",
            "/v1/events?limit=-1",
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], "invalid_query_parameter");
        }
    }

    #[tokio::test]
    async fn readiness_probes_metadata_without_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(protected_state(directory.path()).await)
            .unwrap()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "ready");
        assert_eq!(body["metadata_backend"], "sqlite");
        assert_eq!(body["artifact_backend"], "filesystem");
    }

    #[tokio::test]
    async fn capture_pages_are_stable_across_ties_and_new_inserts() {
        use crate::metadata::NewCapture;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for capture_id in ["cap-a", "cap-b", "cap-c"] {
            state
                .persistence
                .metadata
                .begin_capture(NewCapture {
                    capture_id: capture_id.into(),
                    created_at_unix_ms: 10,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: Some("gpt-5".into()),
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
        }
        let app = router(state.clone()).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/captures?limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first_status = first.status();
        let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            first_status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&first_bytes)
        );
        let first: serde_json::Value = serde_json::from_slice(&first_bytes).unwrap();
        assert_eq!(first["items"][0]["capture_id"], "cap-c");
        assert_eq!(first["items"][1]["capture_id"], "cap-b");
        let cursor = first["next_cursor"].as_str().unwrap();

        state
            .persistence
            .metadata
            .begin_capture(NewCapture {
                capture_id: "cap-new".into(),
                created_at_unix_ms: 11,
                provider: "openai".into(),
                operation: "responses".into(),
                requested_model: Some("gpt-5".into()),
                streaming: true,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::get(format!("/v1/captures?limit=2&cursor={cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let second: serde_json::Value =
            serde_json::from_slice(&second.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert_eq!(second["items"][0]["capture_id"], "cap-a");
        assert!(second["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn cursors_reject_malformed_cross_route_and_changed_filter_requests() {
        use crate::metadata::NewCapture;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for capture_id in ["cap-a", "cap-b"] {
            state
                .persistence
                .metadata
                .begin_capture(NewCapture {
                    capture_id: capture_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: None,
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
        }
        let app = router(state).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/captures?limit=1&provider=openai")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let cursor = first["next_cursor"].as_str().unwrap();
        for (path, expected) in [
            ("/v1/captures?cursor=not-a-cursor", "invalid_cursor"),
            ("/v1/captures?limit=201", "invalid_page_limit"),
            ("/v1/captures?offset=100", "offset_pagination_removed"),
            (
                &format!("/v1/captures?provider=anthropic&cursor={cursor}"),
                "cursor_scope_mismatch",
            ),
            (
                &format!("/v1/operations?cursor={cursor}"),
                "cursor_scope_mismatch",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], expected);
        }
    }

    #[tokio::test]
    async fn sqlite_integer_overflow_in_queries_and_forged_cursors_is_a_typed_400() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let no_text = None::<String>;
        let capture_scope = CursorScope::new(
            "/v1/captures",
            &(
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                None::<bool>,
                None::<u64>,
            ),
            "created_at_unix_ms desc, capture_id desc",
        )
        .unwrap();
        let operation_scope = CursorScope::new(
            "/v1/operations",
            &(&no_text, &no_text, &no_text),
            "created_at_unix_ms desc, operation_id desc",
        )
        .unwrap();
        let event_page_scope = CursorScope::new(
            "/v1/events",
            &(
                &no_text,
                &no_text,
                &no_text,
                &no_text,
                None::<u64>,
                None::<u64>,
            ),
            "event_id desc",
        )
        .unwrap();
        let event_follow_scope = CursorScope::new(
            "/v1/events",
            &(
                (&no_text, &no_text, &no_text, &no_text, None::<u64>),
                "follow",
            ),
            "event_id asc",
        )
        .unwrap();
        let capture_cursor = encode_cursor(
            &capture_scope,
            &CapturePagePosition {
                created_at_unix_ms: u64::MAX,
                capture_id: "cap-forged".to_owned(),
            },
        )
        .unwrap();
        let operation_cursor = encode_cursor(
            &operation_scope,
            &OperationPagePosition {
                created_at_unix_ms: u64::MAX,
                operation_id: "op-forged".to_owned(),
            },
        )
        .unwrap();
        let event_page_cursor =
            encode_cursor(&event_page_scope, &EventPagePosition { event_id: u64::MAX }).unwrap();
        let event_follow_cursor = encode_cursor(
            &event_follow_scope,
            &EventPagePosition { event_id: u64::MAX },
        )
        .unwrap();

        for (path, expected) in [
            (
                format!("/v1/captures?cursor={capture_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/operations?cursor={operation_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/events?cursor={event_page_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/events?after={event_follow_cursor}"),
                "invalid_cursor",
            ),
            (
                format!("/v1/captures?created_after_unix_ms={}", u64::MAX),
                "invalid_query_parameter",
            ),
            (
                format!("/v1/events?created_after_unix_ms={}", u64::MAX),
                "invalid_query_parameter",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["error"]["code"], expected);
        }
    }

    #[tokio::test]
    async fn event_history_and_follow_cursors_have_separate_directions() {
        use crate::metadata::NewCapture;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        for capture_id in ["cap-a", "cap-b"] {
            state
                .persistence
                .metadata
                .begin_capture(NewCapture {
                    capture_id: capture_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "responses".into(),
                    requested_model: None,
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: String::new(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                })
                .await
                .unwrap();
            let key = ArtifactKey::new(capture_id, ArtifactKind::DeferredBundle).unwrap();
            let artifact = state
                .persistence
                .artifacts
                .put(
                    &key,
                    ArtifactSource::from_bytes(b"encrypted bundle".to_vec()),
                    MAX_ARCHIVE_WIRE_BYTES,
                )
                .await
                .unwrap();
            state
                .persistence
                .metadata
                .complete_capture(
                    crate::metadata::CaptureCompletion {
                        capture_id: capture_id.into(),
                        completed_at_unix_ms: 2,
                        duration_ms: 1,
                        http_status: 200,
                        response_bytes: 1,
                        response_model: None,
                        output_preview: String::new(),
                        output_preview_truncated: false,
                        expected_artifact_size_bytes: artifact.size_bytes,
                        expected_artifact_sha256: artifact.sha256.clone(),
                    },
                    artifact,
                )
                .await
                .unwrap();
            state
                .persistence
                .metadata
                .enqueue_finalization(capture_id, 3)
                .await
                .unwrap();
        }
        let app = router(state.clone()).unwrap();
        let first = app
            .clone()
            .oneshot(
                Request::get("/v1/events?limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let first: serde_json::Value =
            serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let history_cursor = first["next_cursor"].as_str().unwrap();
        let high_water = first["high_water_cursor"].as_str().unwrap();
        let older = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/events?limit=1&cursor={history_cursor}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let older: serde_json::Value =
            serde_json::from_slice(&older.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(older["items"].as_array().unwrap().len(), 1);

        state
            .persistence
            .metadata
            .begin_capture(NewCapture {
                capture_id: "cap-c".into(),
                created_at_unix_ms: 2,
                provider: "openai".into(),
                operation: "responses".into(),
                requested_model: None,
                streaming: false,
                request_bytes: 1,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let key = ArtifactKey::new("cap-c", ArtifactKind::DeferredBundle).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(b"encrypted bundle".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    capture_id: "cap-c".into(),
                    completed_at_unix_ms: 3,
                    duration_ms: 1,
                    http_status: 200,
                    response_bytes: 1,
                    response_model: None,
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: artifact.size_bytes,
                    expected_artifact_sha256: artifact.sha256.clone(),
                },
                artifact,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .enqueue_finalization("cap-c", 4)
            .await
            .unwrap();
        let newer = app
            .oneshot(
                Request::get(format!("/v1/events?limit=1&after={high_water}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let newer: serde_json::Value =
            serde_json::from_slice(&newer.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(newer["items"].as_array().unwrap().len(), 1);
        assert_eq!(newer["items"][0]["capture_id"], "cap-c");
    }

    #[tokio::test]
    async fn provider_authentication_error_is_visible_but_ineligible_for_finalization() {
        use crate::metadata::NewCapture;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path()).await;
        state
            .persistence
            .metadata
            .begin_capture(NewCapture {
                capture_id: "cap-auth-error".into(),
                created_at_unix_ms: 1,
                provider: "openai".into(),
                operation: "/v1/responses".into(),
                requested_model: Some("gpt-5.2".into()),
                streaming: true,
                request_bytes: 128,
                prompt_preview: String::new(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:test".into(),
            })
            .await
            .unwrap();
        let key = ArtifactKey::new("cap-auth-error", ArtifactKind::DeferredBundle).unwrap();
        let artifact = state
            .persistence
            .artifacts
            .put(
                &key,
                ArtifactSource::from_bytes(b"encrypted provider authentication error".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        state
            .persistence
            .metadata
            .complete_capture(
                crate::metadata::CaptureCompletion {
                    capture_id: "cap-auth-error".into(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: 401,
                    response_bytes: 96,
                    response_model: None,
                    output_preview: String::new(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: artifact.size_bytes,
                    expected_artifact_sha256: artifact.sha256.clone(),
                },
                artifact,
            )
            .await
            .unwrap();
        let app = router(state).unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/captures/cap-auth-error")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["capture"]["http_status"], 401);
        assert_eq!(body["capture"]["finalization_eligible"], false);
        assert_eq!(
            body["capture"]["finalization_ineligibility_code"],
            UNSUPPORTED_PROVIDER_HTTP_STATUS
        );
        assert_eq!(body["finalizations"], serde_json::json!([]));

        let response = app
            .oneshot(
                Request::post("/v1/captures/cap-auth-error/finalizations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["code"], UNSUPPORTED_PROVIDER_HTTP_STATUS);
        assert_eq!(
            body["error"]["message"],
            "Finalization supports successful provider responses only"
        );
    }

    #[tokio::test]
    async fn dashboard_session_exchanges_basic_credentials_without_persisting_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let state = protected_state(directory.path()).await;
        let password = "correct horse battery staple";
        let app = router(state).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/session")
                    .header(header::AUTHORIZATION, basic_header("local-admin", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(!cookie.contains(password));
        assert!(!cookie.contains("local-admin"));

        let response = app
            .oneshot(
                Request::get("/v1/status")
                    .header(header::COOKIE, cookie)
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains(password));
    }

    #[tokio::test]
    async fn expired_dashboard_sessions_are_rejected_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let state = protected_state(directory.path()).await;
        state.sessions.lock().await.insert("expired".into(), 0);

        let response = router(state.clone())
            .unwrap()
            .oneshot(
                Request::get("/v1/status")
                    .header(header::COOKIE, format!("{SESSION_COOKIE}=expired"))
                    .header(DASHBOARD_HEADER, "dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.sessions.lock().await.is_empty());
    }
    #[tokio::test]
    async fn dashboard_assets_are_embedded_only_on_the_admin_router() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path()).await).unwrap();
        let index = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            DASHBOARD_CSP
        );
        let body = index.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("/assets/dashboard.js"));

        let script = app
            .oneshot(
                Request::get("/assets/dashboard.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(script.status(), StatusCode::OK);
        assert_eq!(
            script.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript"
        );

        let embedded = router(state(directory.path()).await)
            .unwrap()
            .oneshot(
                Request::get("/dashboard?embedded=desktop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            embedded
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            DESKTOP_DASHBOARD_CSP
        );
    }
}
