//! Authenticated loopback administration API and durable background work.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::{
    DeferredBundle,
    archive::{ARCHIVE_CONTENT_TYPE, read_trace_package_archive},
    bundle::{
        finalize_bundle, finalize_bundle_admitted, trace_package_created_at_unix_ms,
        trace_package_notary_key, verify_trace_package,
    },
    catalog::{
        CaptureFilters, CaptureSummary, Catalog, Event, EventFilters, Operation, OperationAttempt,
        OperationFilters,
    },
    cli::{DEFAULT_PUBLIC_ORIGIN, auth, download, notary, proxy, publish},
    config::AgentConfig,
    notary_directory::{NotaryDirectoryRecord, NotaryKeyStatus, key_id},
    vault::Vault,
};

const API_VERSION: &str = "v1";
const SESSION_COOKIE: &str = "llm_notary_admin_session";
const SESSION_MAX_AGE_SECONDS: u64 = 43_200;
const DASHBOARD_HEADER: &str = "x-llm-notary-request";

#[derive(RustEmbed)]
#[folder = "dashboard/"]
struct DashboardAssets;

#[derive(Clone)]
pub(crate) struct AdminState {
    catalog: Arc<Catalog>,
    config: Arc<AgentConfig>,
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    pending_authorizations: Arc<Mutex<HashMap<String, auth::PendingAuthorization>>>,
    publication_credentials: Arc<Mutex<()>>,
    pub(crate) work_available: Arc<Notify>,
}

impl AdminState {
    pub(crate) fn new(catalog: Arc<Catalog>, config: Arc<AgentConfig>) -> Result<Self> {
        let interrupted = catalog.recover_operations(now_ms()?)?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "recovered interrupted finalization operations");
        }
        Ok(Self {
            catalog,
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            publication_credentials: Arc::new(Mutex::new(())),
            work_available: Arc::new(Notify::new()),
        })
    }
}

pub(crate) fn router(state: AdminState) -> Result<Router> {
    let protected = Router::new()
        .route("/v1/status", get(status))
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
        .route("/v1/events", get(events))
        .route(
            "/v1/publication/auth",
            get(publication_auth_status)
                .post(start_publication_auth)
                .delete(end_publication_auth),
        )
        .route(
            "/v1/publication/auth/{request_id}",
            get(poll_publication_auth),
        )
        .route(
            "/v1/captures/{capture_id}/publications",
            post(publish_capture),
        )
        .route("/v1/publications/{job_id}", get(publication_status))
        .route(
            "/v1/public-traces/{publication_id}",
            get(download_public_trace),
        )
        .route(
            "/v1/public-traces/{publication_id}/verify",
            post(verify_public_trace),
        )
        .route("/v1/session", delete(end_session))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Ok(Router::new()
        .route("/", get(dashboard_index))
        .route("/dashboard", get(dashboard_index))
        .route("/dashboard/", get(dashboard_index))
        .route("/assets/{*path}", get(dashboard_asset))
        .route("/healthz", get(health))
        .route("/openapi.json", get(openapi))
        .route("/v1/session", post(start_session))
        .merge(protected)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
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

async fn dashboard_index() -> Response {
    embedded_dashboard_response("local.html")
}

async fn dashboard_asset(Path(path): Path<String>) -> Response {
    embedded_dashboard_response(&format!("assets/{path}"))
}

fn embedded_dashboard_response(path: &str) -> Response {
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
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
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
        health, openapi, start_session, end_session, status, notaries, captures, capture,
        start_finalization, operations, operation, retry_operation, trace,
        download_package, verify_trace, events, publication_auth_status, start_publication_auth,
        end_publication_auth, poll_publication_auth, publish_capture,
        publication_status, download_public_trace, verify_public_trace
    ),
    components(schemas(
        HealthResponse, StatusResponse, CountsResponse, NotariesResponse, NotaryResponse,
        CaptureResponse, CaptureDetailResponse, ArtifactResponse, CaptureListResponse,
        OperationResponse, OperationAttemptResponse, OperationListResponse, FinalizationResponse, EventResponse,
        EventListResponse, TraceResponse, VerificationResponse, AccountConnectionResponse,
        AccountConnectionRequest, AccountConnectionStartedResponse, PublicationResponse, PublicationStatusResponse,
        PublicTraceResponse, PublicTraceVerificationResponse, ErrorBody, ErrorEnvelope
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
    })
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

#[utoipa::path(post, path = "/v1/session", summary = "Start a dashboard session", description = "Exchanges configured HTTP Basic credentials for an HttpOnly browser session cookie. Returns without a cookie when admin authentication is disabled.", responses((status = 204, description = "Dashboard access established"), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
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
    state
        .sessions
        .lock()
        .await
        .insert(session.clone(), expires_at);
    let cookie = format!(
        "{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_MAX_AGE_SECONDS}"
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated session cookie is valid"),
    );
    response
}

#[utoipa::path(delete, path = "/v1/session", summary = "End a dashboard session", description = "Deletes the current browser session and expires its local cookie.", responses((status = 204, description = "Dashboard session ended"), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_session(State(state): State<AdminState>, request: Request) -> Response {
    if let Some(session) = session_from_headers(request.headers()) {
        state.sessions.lock().await.remove(session);
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

#[utoipa::path(get, path = "/v1/status", summary = "Get local service status", description = "Returns listener addresses, vault and notary configuration, preview limits, and current capture counts.", responses((status = 200, body = StatusResponse), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn status(State(state): State<AdminState>) -> Result<Json<StatusResponse>, ApiError> {
    let catalog = state.catalog.clone();
    let counts = tokio::task::spawn_blocking(move || catalog.counts())
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        proxy_listener: state.config.proxy.listen.to_string(),
        admin_listener: state.config.admin.listen.to_string(),
        vault: Vault::status().unwrap_or("unavailable").into(),
        notary: if state.config.notary.endpoint.is_some() {
            "configured"
        } else {
            "directory"
        }
        .into(),
        preview_chars: state.config.catalog.prompt_preview_chars,
        counts: CountsResponse::from(counts),
    }))
}

#[utoipa::path(get, path = "/v1/notaries", summary = "Get configured notary trust", description = "Returns a safe read-only projection of the pinned notary trust history or the explicitly configured self-hosted endpoint and key. Directory membership describes allowed protocol use and does not report endpoint health.", responses((status = 200, body = NotariesResponse), (status = 401, body = ErrorEnvelope), (status = 500, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn notaries(State(state): State<AdminState>) -> Result<Json<NotariesResponse>, ApiError> {
    notaries_response(&state.config)
        .map(Json)
        .map_err(|_| ApiError::internal("notary_trust_state_invalid"))
}

fn notaries_response(config: &AgentConfig) -> Result<NotariesResponse> {
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

    let Some(pinned) = notary::pinned_state()? else {
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
    limit: Option<usize>,
    offset: Option<usize>,
}

#[utoipa::path(get, path = "/v1/captures", summary = "Search local captures", description = "Lists the bounded local capture catalog with punctuation-safe preview search and exact metadata filters.", params(("query" = Option<String>, Query), ("model" = Option<String>, Query), ("provider" = Option<String>, Query), ("capture_state" = Option<String>, Query), ("finalization_state" = Option<String>, Query), ("limit" = Option<usize>, Query), ("offset" = Option<usize>, Query)), responses((status = 200, body = CaptureListResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn captures(
    State(state): State<AdminState>,
    query: Result<Query<CaptureQuery>, QueryRejection>,
) -> Result<Json<CaptureListResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    let catalog = state.catalog.clone();
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let values = tokio::task::spawn_blocking(move || {
        catalog.filtered_captures(&CaptureFilters {
            query: query.query.as_deref(),
            model: query.model.as_deref(),
            provider: query.provider.as_deref(),
            capture_state: query.capture_state.as_deref(),
            finalization_state: query.finalization_state.as_deref(),
            limit,
            offset,
        })
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::bad_request("invalid_capture_filter"))?;
    Ok(Json(CaptureListResponse {
        items: values.into_iter().map(CaptureResponse::from).collect(),
        limit,
        offset,
    }))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}", summary = "Get a capture", description = "Returns safe capture metadata, retained artifact digests, and finalization history for one capture.", params(("capture_id" = String, Path)), responses((status = 200, body = CaptureDetailResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn capture(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<CaptureDetailResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let catalog = state.catalog.clone();
    let capture_id_for_query = capture_id.clone();
    let capture = tokio::task::spawn_blocking(move || catalog.capture(&capture_id_for_query))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?
        .ok_or_else(|| ApiError::not_found("capture_not_found"))?;
    let catalog = state.catalog.clone();
    let artifacts = tokio::task::spawn_blocking(move || catalog.artifacts(&capture_id))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    let catalog = state.catalog.clone();
    let capture_id = capture.capture_id.clone();
    let finalizations = tokio::task::spawn_blocking(move || -> Result<Vec<OperationResponse>> {
        catalog
            .operations_for_capture(&capture_id)?
            .into_iter()
            .map(|operation| operation_response(&catalog, operation))
            .collect()
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    Ok(Json(CaptureDetailResponse {
        capture: capture.into(),
        artifacts: artifacts
            .into_iter()
            .map(|artifact| ArtifactResponse {
                kind: artifact.kind,
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
            })
            .collect(),
        finalizations,
    }))
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/finalizations", summary = "Queue capture finalization", description = "Queues durable proof generation for an eligible pending capture or returns its existing finalization operation. Captures with non-success provider HTTP responses are rejected before proof generation because the current normalizers only support successful response schemas.", params(("capture_id" = String, Path)), responses((status = 202, body = FinalizationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_finalization(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<(StatusCode, Json<FinalizationResponse>), ApiError> {
    validate_id(&capture_id, "cap-")?;
    let catalog = state.catalog.clone();
    let capture_id_for_eligibility = capture_id.clone();
    let capture = tokio::task::spawn_blocking(move || catalog.capture(&capture_id_for_eligibility))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?
        .filter(|capture| capture.capture_state == "pending")
        .ok_or_else(|| ApiError::not_found("pending_capture_not_found"))?;
    if finalization_ineligibility_code(&capture).is_some() {
        return Err(ApiError::finalization_ineligible());
    }
    let catalog = state.catalog.clone();
    let queued =
        tokio::task::spawn_blocking(move || -> Result<Option<(OperationResponse, bool)>> {
            let queued = catalog.enqueue_finalization(&capture_id, now_ms()?)?;
            queued
                .map(|(operation, deduplicated)| {
                    Ok((operation_response(&catalog, operation)?, deduplicated))
                })
                .transpose()
        })
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("finalization_queue_failed"))?
        .ok_or_else(|| ApiError::not_found("pending_capture_not_found"))?;
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
    limit: Option<usize>,
}

#[utoipa::path(get, path = "/v1/operations", summary = "List background operations", description = "Lists durable background operations with optional state, kind, and capture filters.", params(("state" = Option<String>, Query), ("kind" = Option<String>, Query), ("capture_id" = Option<String>, Query), ("limit" = Option<usize>, Query)), responses((status = 200, body = OperationListResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn operations(
    State(state): State<AdminState>,
    query: Result<Query<OperationQuery>, QueryRejection>,
) -> Result<Json<OperationListResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    let catalog = state.catalog.clone();
    let values = tokio::task::spawn_blocking(move || -> Result<Vec<OperationResponse>> {
        catalog
            .filtered_operations(&OperationFilters {
                state: query.state.as_deref(),
                kind: query.kind.as_deref(),
                capture_id: query.capture_id.as_deref(),
                limit: query.limit.unwrap_or(50),
            })?
            .into_iter()
            .map(|operation| operation_response(&catalog, operation))
            .collect()
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    Ok(Json(OperationListResponse { items: values }))
}

#[utoipa::path(get, path = "/v1/operations/{operation_id}", summary = "Get an operation", description = "Returns the current state and complete attempt history for one durable operation.", params(("operation_id" = String, Path)), responses((status = 200, body = OperationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<Json<OperationResponse>, ApiError> {
    validate_id(&operation_id, "op-")?;
    let catalog = state.catalog.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<Option<OperationResponse>> {
        catalog
            .operation(&operation_id)?
            .map(|operation| operation_response(&catalog, operation))
            .transpose()
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::internal("catalog_query_failed"))?
    .ok_or_else(|| ApiError::not_found("operation_not_found"))?;
    Ok(Json(value))
}

#[utoipa::path(post, path = "/v1/operations/{operation_id}/retry", summary = "Retry an operation", description = "Requeues a failed or restart-interrupted operation while preserving its durable identity and attempt history.", params(("operation_id" = String, Path)), responses((status = 202, body = OperationResponse), (status = 401, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn retry_operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    validate_id(&operation_id, "op-")?;
    let catalog = state.catalog.clone();
    let value = tokio::task::spawn_blocking(move || -> Result<Option<OperationResponse>> {
        catalog
            .retry_operation(&operation_id, now_ms()?)?
            .map(|operation| operation_response(&catalog, operation))
            .transpose()
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::internal("operation_retry_failed"))?
    .ok_or_else(|| ApiError::conflict("operation_not_retryable"))?;
    state.work_available.notify_one();
    Ok((StatusCode::ACCEPTED, Json(value)))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}/trace", summary = "Decode a finalized trace", description = "Returns the finalized package manifest and canonical OpenTelemetry trace for inspection.", params(("capture_id" = String, Path)), responses((status = 200, body = TraceResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn trace(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<TraceResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let path = finalized_path(&state.catalog, &capture_id).await?;
    let value = tokio::task::spawn_blocking(move || -> Result<TraceResponse> {
        let bytes = fs::read(path)?;
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

#[utoipa::path(get, path = "/v1/captures/{capture_id}/package", summary = "Download a finalized verified package", description = "Returns the exact stored canonical .llmtrace bytes as the primary portable verification artifact.", params(("capture_id" = String, Path)), responses((status = 200, body = Vec<u8>, content_type = "application/vnd.llmnotary.trace-package+zip"), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn download_package(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let path = finalized_path(&state.catalog, &capture_id).await?;
    let bytes = tokio::task::spawn_blocking(move || fs::read(path))
        .await
        .map_err(|_| ApiError::internal("package_task_failed"))?
        .map_err(|_| ApiError::not_found("finalized_trace_not_found"))?;
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

#[utoipa::path(post, path = "/v1/captures/{capture_id}/trace:verify", summary = "Verify a finalized trace", description = "Verifies the package evidence, disclosure, hashes, provider mapping, and canonical trace against the configured trust source.", params(("capture_id" = String, Path)), responses((status = 200, body = VerificationResponse), (status = 401, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn verify_trace(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<VerificationResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let path = finalized_path(&state.catalog, &capture_id).await?;
    let verified_at_unix_ms = now_ms().map_err(|_| ApiError::internal("clock_error"))?;
    let configured_key = state
        .config
        .notary_public_key()
        .map_err(|_| ApiError::internal("notary_configuration_invalid"))?;
    let value = tokio::task::spawn_blocking(move || -> Result<VerificationResponse> {
        let embedded_key = trace_package_notary_key(&path)?;
        let (trusted_key, notary_key_id, trust_source) = match configured_key {
            Some(key) => {
                let key_id = key_id(&key);
                (key, key_id, "configuration".to_owned())
            }
            None => {
                let created_at = trace_package_created_at_unix_ms(&path)?;
                let (key_id, trust) = notary::cached_key_at(&embedded_key, created_at)?;
                (embedded_key, key_id, trust)
            }
        };
        let manifest = verify_trace_package(&path, &trusted_key)?;
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
    cursor: Option<u64>,
    severity: Option<String>,
    event_type: Option<String>,
    capture_id: Option<String>,
    operation_id: Option<String>,
    created_after_unix_ms: Option<u64>,
    limit: Option<usize>,
}

#[utoipa::path(get, path = "/v1/events", summary = "List service events", description = "Lists the bounded redacted event history with cursor, severity, type, resource, and time filters.", params(("cursor" = Option<u64>, Query), ("severity" = Option<String>, Query), ("event_type" = Option<String>, Query), ("capture_id" = Option<String>, Query), ("operation_id" = Option<String>, Query), ("created_after_unix_ms" = Option<u64>, Query), ("limit" = Option<usize>, Query)), responses((status = 200, body = EventListResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn events(
    State(state): State<AdminState>,
    query: Result<Query<EventQuery>, QueryRejection>,
) -> Result<Json<EventListResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    let catalog = state.catalog.clone();
    let values = tokio::task::spawn_blocking(move || {
        catalog.filtered_events(&EventFilters {
            after: query.cursor,
            severity: query.severity.as_deref(),
            event_type: query.event_type.as_deref(),
            capture_id: query.capture_id.as_deref(),
            operation_id: query.operation_id.as_deref(),
            created_after_unix_ms: query.created_after_unix_ms,
            limit: query.limit.unwrap_or(50),
        })
    })
    .await
    .map_err(|_| ApiError::internal("catalog_task_failed"))?
    .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    let next_cursor = values.first().map(|event| event.event_id);
    Ok(Json(EventListResponse {
        items: values.into_iter().map(Into::into).collect(),
        next_cursor,
    }))
}

#[utoipa::path(get, path = "/v1/publication/auth", summary = "Get the LLM Notary account connection", description = "Reports whether this local service has an account connection used for hosted tier admission and trace publication.", responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn publication_auth_status(
    State(state): State<AdminState>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
    let _credentials = state.publication_credentials.lock().await;
    load_publication_auth_status().await
}

async fn load_publication_auth_status() -> Result<Json<AccountConnectionResponse>, ApiError> {
    let status = auth::account_connection_status()
        .await
        .map_err(|_| ApiError::internal("publication_auth_status_failed"))?;
    Ok(Json(AccountConnectionResponse {
        signed_in: status.signed_in,
        github_login: status.github_login,
        device_name: status.device_name,
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

#[utoipa::path(post, path = "/v1/publication/auth", summary = "Connect an LLM Notary account", description = "Starts browser approval for an account connection used for hosted tier admission and trace publication.", request_body = AccountConnectionRequest, responses((status = 202, body = AccountConnectionStartedResponse), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn start_publication_auth(
    State(state): State<AdminState>,
    Json(body): Json<AccountConnectionRequest>,
) -> Result<(StatusCode, Json<AccountConnectionStartedResponse>), ApiError> {
    let pending = auth::start_authorization(&body.api_origin, &body.device_name)
        .await
        .map_err(|_| ApiError::internal("publication_auth_start_failed"))?;
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

#[utoipa::path(get, path = "/v1/publication/auth/{request_id}", summary = "Poll account authorization", description = "Checks a pending LLM Notary account approval after its required polling interval.", params(("request_id" = String, Path)), responses((status = 200, body = AccountConnectionResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn poll_publication_auth(
    State(state): State<AdminState>,
    Path(request_id): Path<String>,
) -> Result<Json<AccountConnectionResponse>, ApiError> {
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
    let _credentials = state.publication_credentials.lock().await;
    match auth::poll_authorization(&pending)
        .await
        .map_err(|_| ApiError::internal("publication_auth_poll_failed"))?
    {
        auth::AuthorizationPoll::Pending => Ok(Json(AccountConnectionResponse {
            signed_in: false,
            github_login: None,
            device_name: None,
        })),
        auth::AuthorizationPoll::Complete => {
            state
                .pending_authorizations
                .lock()
                .await
                .remove(&request_id);
            load_publication_auth_status().await
        }
    }
}

#[utoipa::path(delete, path = "/v1/publication/auth", summary = "Disconnect the LLM Notary account", description = "Removes the local account credentials. Future hosted sessions use public access until a new browser approval is completed.", responses((status = 204, description = "Account disconnected; hosted sessions return to public access"), (status = 401, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn end_publication_auth(State(state): State<AdminState>) -> Result<StatusCode, ApiError> {
    let _credentials = state.publication_credentials.lock().await;
    auth::logout_for_service()
        .await
        .map_err(|_| ApiError::internal("publication_logout_failed"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/publications", summary = "Publish a finalized trace", description = "Verifies one finalized capture locally, uploads only its publication archive, and returns the durable publication job.", params(("capture_id" = String, Path)), responses((status = 202, body = PublicationResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn publish_capture(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<(StatusCode, Json<PublicationResponse>), ApiError> {
    validate_id(&capture_id, "cap-")?;
    let path = finalized_path(&state.catalog, &capture_id).await?;
    let _credentials = state.publication_credentials.lock().await;
    let (publication, verified_capture_id, _) =
        publish::publish_package(&path, state.config.notary.public_key.as_deref())
            .await
            .map_err(|_| ApiError::internal("publication_failed"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(PublicationResponse {
            capture_id: verified_capture_id,
            status_url: format!("/v1/publications/{}", publication.job_id),
            job_id: publication.job_id,
            state: publication.state,
        }),
    ))
}

#[utoipa::path(get, path = "/v1/publications/{job_id}", summary = "Get publication status", description = "Returns the latest admission state and public artifact links for a publication job.", params(("job_id" = String, Path)), responses((status = 200, body = PublicationStatusResponse), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope), (status = 503, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn publication_status(
    State(state): State<AdminState>,
    Path(job_id): Path<String>,
) -> Result<Json<PublicationStatusResponse>, ApiError> {
    validate_id(&job_id, "")?;
    let _credentials = state.publication_credentials.lock().await;
    let status = publish::publication_status(&job_id)
        .await
        .map_err(|error| match error {
            publish::PublicationStatusError::Authentication => {
                ApiError::publication_authentication_required()
            }
            publish::PublicationStatusError::NotFound => {
                ApiError::not_found("publication_not_found")
            }
            publish::PublicationStatusError::Unavailable => {
                ApiError::service_unavailable("publication_status_unavailable")
            }
        })?;
    Ok(Json(PublicationStatusResponse {
        job_id: status.job_id,
        state: status.state,
        failure_code: status.failure_code,
        trace_url: status.trace_url,
        stamp_url: status.stamp_url,
    }))
}

#[derive(Debug, Default, Deserialize)]
struct PublicTraceQuery {
    api_origin: Option<String>,
}

#[utoipa::path(get, path = "/v1/public-traces/{publication_id}", summary = "Get a public trace", description = "Fetches one public canonical trace and any legacy platform stamp through the configured publication API.", params(("publication_id" = String, Path), ("api_origin" = Option<String>, Query)), responses((status = 200, body = PublicTraceResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn download_public_trace(
    Path(publication_id): Path<String>,
    query: Result<Query<PublicTraceQuery>, QueryRejection>,
) -> Result<Json<PublicTraceResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    fetch_public_trace(publication_id, query.api_origin, false).await
}

#[utoipa::path(post, path = "/v1/public-traces/{publication_id}/verify", summary = "Verify a public trace", description = "Fetches a public trace and verifies its canonical bytes, contract versions, hash, issuer, key, and signature.", params(("publication_id" = String, Path), ("api_origin" = Option<String>, Query)), responses((status = 200, body = PublicTraceResponse), (status = 400, body = ErrorEnvelope), (status = 401, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope)), security((), ("basicAuth" = [])), tag = "local-admin")]
async fn verify_public_trace(
    Path(publication_id): Path<String>,
    query: Result<Query<PublicTraceQuery>, QueryRejection>,
) -> Result<Json<PublicTraceResponse>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::bad_request("invalid_query_parameter"))?;
    fetch_public_trace(publication_id, query.api_origin, true).await
}

async fn fetch_public_trace(
    publication_id: String,
    api_origin: Option<String>,
    verify: bool,
) -> Result<Json<PublicTraceResponse>, ApiError> {
    let value = download::fetch_public_trace(
        &publication_id,
        api_origin.as_deref().unwrap_or(DEFAULT_PUBLIC_ORIGIN),
        verify,
    )
    .await
    .map_err(|_| {
        if verify {
            ApiError::unprocessable("public_trace_verification_failed")
        } else {
            ApiError::not_found("public_trace_not_found")
        }
    })?;
    let verification = value
        .verification
        .map(|verified| PublicTraceVerificationResponse {
            verified: true,
            trace_sha256: verified.trace_sha256,
            issuer: verified.stamp.issuer,
            provider: verified.stamp.provider.name,
            issued_at_unix_ms: verified.stamp.issued_at_unix_ms,
        });
    Ok(Json(PublicTraceResponse {
        publication_id: value.publication_id,
        trace: value.trace,
        stamp: value
            .stamp
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| ApiError::internal("public_stamp_encode_failed"))?,
        verification,
    }))
}

async fn finalized_path(catalog: &Arc<Catalog>, capture_id: &str) -> Result<PathBuf, ApiError> {
    let catalog = catalog.clone();
    let capture_id = capture_id.to_owned();
    tokio::task::spawn_blocking(move || catalog.artifacts(&capture_id))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?
        .into_iter()
        .find(|artifact| artifact.kind == "finalized_package")
        .map(|artifact| artifact.path)
        .ok_or_else(|| ApiError::not_found("finalized_trace_not_found"))
}

pub(crate) fn spawn_finalization_worker(
    catalog: Arc<Catalog>,
    config: Arc<AgentConfig>,
    vault: Arc<Vault>,
    work_available: Arc<Notify>,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            let catalog_for_claim = catalog.clone();
            let operation = tokio::task::spawn_blocking(move || {
                catalog_for_claim.claim_next_finalization(now_ms()?)
            })
            .await
            .context("claim finalization task exited")??;
            let Some(operation) = operation else {
                tokio::select! {
                    () = work_available.notified() => {},
                    () = tokio::time::sleep(std::time::Duration::from_secs(2)) => {},
                }
                continue;
            };
            let result = finalize_operation(&catalog, &config, &vault, &operation).await;
            let now = now_ms()?;
            if result.is_ok() {
                catalog.finish_operation(&operation.operation_id, now)?;
            } else {
                let code = result
                    .as_ref()
                    .err()
                    .and_then(|error| crate::notary_admission_error(error))
                    .map(|_| "notary_capacity")
                    .unwrap_or("finalization_error");
                catalog.fail_operation(&operation.operation_id, now, code)?;
                tracing::warn!(operation_id = %operation.operation_id, failure_code = code, "finalization operation failed");
            }
        }
    })
}

async fn finalize_operation(
    catalog: &Catalog,
    config: &AgentConfig,
    vault: &Vault,
    operation: &Operation,
) -> Result<()> {
    let capture_id = operation
        .capture_id
        .as_deref()
        .context("finalization operation has no capture")?;
    let bundle_path = catalog
        .artifacts(capture_id)?
        .into_iter()
        .find(|artifact| artifact.kind == "deferred_bundle")
        .map(|artifact| artifact.path)
        .context("capture has no encrypted deferred bundle")?;
    let output = config
        .storage
        .finalized_dir
        .join(format!("{capture_id}.llmtrace"));
    if output.is_file() {
        let embedded_key = trace_package_notary_key(&output)?;
        let key = match config.notary_public_key()? {
            Some(key) => key,
            None => {
                let created_at = trace_package_created_at_unix_ms(&output)?;
                notary::cached_key_at(&embedded_key, created_at)?;
                embedded_key
            }
        };
        verify_trace_package(&output, &key)?;
        catalog.record_finalized_package(capture_id, &output)?;
        return Ok(());
    }
    let bundle = DeferredBundle::load(&bundle_path, vault)?;
    let hosted_admission = config.notary.endpoint.is_none();
    let (key, endpoint) = match (config.notary_public_key()?, config.notary_endpoint()?) {
        (Some(key), Some(endpoint)) => {
            bundle.verify_notary_key(&key)?;
            (key, endpoint)
        }
        (None, None) => {
            let _ = proxy::refresh_notary_directory().await;
            let (key, record) = notary::cached_record_for_bundle(&bundle)?;
            let endpoint = proxy::resolve_notary(&record).await?;
            (key, endpoint)
        }
        _ => anyhow::bail!("notary endpoint and public key configuration are inconsistent"),
    };
    let path = if hosted_admission {
        let allowance = bundle.finalization_allowance_bytes()?;
        if allowance > config.proxy.max_attestable_http_bytes {
            anyhow::bail!("bundle exceeds the current local finalization byte limit");
        }
        let admission =
            auth::issue_finalization_admission(&bundle.record_digest_hex(), allowance).await?;
        finalize_bundle_admitted(
            &bundle_path,
            &output,
            &key,
            vault,
            &endpoint,
            config
                .proxy
                .max_attestable_http_bytes
                .min(admission.max_attestable_http_bytes),
            config.notary.max_frame_bytes.min(admission.max_frame_bytes),
            &admission.ticket,
        )
        .await?
    } else {
        finalize_bundle(
            &bundle_path,
            &output,
            &key,
            vault,
            &endpoint,
            config.proxy.max_attestable_http_bytes,
            config.notary.max_frame_bytes,
        )
        .await?
    };
    catalog.record_finalized_package(capture_id, &path)?;
    Ok(())
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
    let password_hash = auth.password_hash.clone();
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
}

#[derive(Debug, Serialize, ToSchema)]
struct CountsResponse {
    total_captures: u64,
    capturing: u64,
    pending: u64,
    finalized: u64,
    failed: u64,
    active_operations: u64,
}

impl From<crate::catalog::CatalogCounts> for CountsResponse {
    fn from(value: crate::catalog::CatalogCounts) -> Self {
        Self {
            total_captures: value.total_captures,
            capturing: value.capturing,
            pending: value.pending,
            finalized: value.finalized,
            failed: value.failed,
            active_operations: value.active_operations,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusResponse {
    version: String,
    proxy_listener: String,
    admin_listener: String,
    vault: String,
    notary: String,
    preview_chars: usize,
    counts: CountsResponse,
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
struct CaptureListResponse {
    items: Vec<CaptureResponse>,
    limit: usize,
    offset: usize,
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
    retryable: bool,
    attempt_history: Vec<OperationAttemptResponse>,
}

fn operation_response(catalog: &Catalog, value: Operation) -> Result<OperationResponse> {
    let attempt_history = catalog
        .operation_attempts(&value.operation_id)?
        .into_iter()
        .map(Into::into)
        .collect();
    let eligible_capture = match value.capture_id.as_deref() {
        Some(capture_id) => catalog
            .capture(capture_id)?
            .is_some_and(|capture| finalization_eligible(&capture)),
        None => false,
    };
    let retryable = ["failed", "interrupted"].contains(&value.state.as_str()) && eligible_capture;
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
struct OperationListResponse {
    items: Vec<OperationResponse>,
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
    next_cursor: Option<u64>,
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
    github_login: Option<String>,
    device_name: Option<String>,
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
struct PublicationResponse {
    capture_id: String,
    job_id: String,
    state: String,
    status_url: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct PublicationStatusResponse {
    job_id: String,
    state: String,
    failure_code: Option<String>,
    trace_url: Option<String>,
    stamp_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct PublicTraceResponse {
    publication_id: String,
    trace: serde_json::Value,
    stamp: Option<serde_json::Value>,
    verification: Option<PublicTraceVerificationResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
struct PublicTraceVerificationResponse {
    verified: bool,
    trace_sha256: String,
    issuer: String,
    provider: String,
    issued_at_unix_ms: u64,
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
    fn publication_authentication_required() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "publication_authentication_required",
            message: "LLM Notary account connection must be renewed",
        }
    }
    fn service_unavailable(code: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: "The publication service is temporarily unavailable",
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

    fn state(directory: &std::path::Path) -> AdminState {
        state_with_auth(directory, None)
    }

    fn protected_state(directory: &std::path::Path) -> AdminState {
        let salt = SaltString::encode_b64(b"llm-notary-test-salt").unwrap();
        let password_hash = Argon2::default()
            .hash_password(b"correct horse battery staple", &salt)
            .unwrap()
            .to_string();
        state_with_auth(
            directory,
            Some(crate::config::AdminAuthConfig {
                username: "local-admin".to_owned(),
                password_hash,
            }),
        )
    }

    fn state_with_auth(
        directory: &std::path::Path,
        auth: Option<crate::config::AdminAuthConfig>,
    ) -> AdminState {
        let mut config = AgentConfig::default();
        config.catalog.path = directory.join("catalog.db");
        config.storage.bundle_dir = directory.join("bundles");
        config.storage.finalized_dir = directory.join("traces");
        config.admin.auth = auth;
        AdminState::new(
            Arc::new(Catalog::open_for_config(&config).unwrap()),
            Arc::new(config),
        )
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
        let response = router(state(directory.path()))
            .unwrap()
            .oneshot(Request::get("/v1/status").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_routes_reject_missing_or_wrong_auth_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(protected_state(directory.path())).unwrap();
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
                router(protected_state(directory.path()))
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
        let response = router(state(directory.path()))
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
            "/openapi.json",
            "/v1/status",
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
            "/v1/events",
            "/v1/session",
            "/v1/publication/auth",
            "/v1/publication/auth/{request_id}",
            "/v1/captures/{capture_id}/publications",
            "/v1/publications/{job_id}",
            "/v1/public-traces/{publication_id}",
            "/v1/public-traces/{publication_id}/verify",
        ] {
            assert!(body["paths"].get(path).is_some(), "OpenAPI missing {path}");
        }
        for (path, method) in [
            ("/v1/status", "get"),
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
            ("/v1/events", "get"),
            ("/v1/publication/auth", "get"),
            ("/v1/publication/auth", "post"),
            ("/v1/publication/auth", "delete"),
            ("/v1/publication/auth/{request_id}", "get"),
            ("/v1/captures/{capture_id}/publications", "post"),
            ("/v1/publications/{job_id}", "get"),
            ("/v1/public-traces/{publication_id}", "get"),
            ("/v1/public-traces/{publication_id}/verify", "post"),
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
        assert_eq!(documented_operations, 24);
    }

    #[tokio::test]
    async fn package_download_returns_the_exact_stored_llmtrace() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let capture_id = "cap-download";
        state
            .catalog
            .begin_capture(&crate::catalog::NewCapture {
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
            .unwrap();
        let package = directory.path().join("cap-download.llmtrace");
        let expected = b"exact canonical archive bytes";
        fs::write(&package, expected).unwrap();
        state
            .catalog
            .record_finalized_package(capture_id, &package)
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

        let response = notaries_response(&config).unwrap();

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
        let app = router(state(directory.path())).unwrap();
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
    async fn provider_authentication_error_is_visible_but_ineligible_for_finalization() {
        use crate::catalog::NewCapture;

        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let bundle = directory.path().join("bundles/cap-auth-error.llmbundle");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        fs::write(&bundle, b"encrypted provider authentication error").unwrap();
        state
            .catalog
            .begin_capture(&NewCapture {
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
            .unwrap();
        state
            .catalog
            .complete_capture("cap-auth-error", 2, 1, 401, 96, None, "", false, &bundle)
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
        let state = protected_state(directory.path());
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
        let state = protected_state(directory.path());
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
        let app = router(state(directory.path())).unwrap();
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
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
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
    }
}
