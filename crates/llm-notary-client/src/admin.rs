//! Authenticated loopback administration API and durable background work.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use tokio::sync::{Mutex, Notify};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::{
    DeferredBundle,
    bundle::{
        finalize_bundle, trace_package_created_at_unix_ms, trace_package_notary_key,
        verify_trace_package,
    },
    catalog::{CaptureFilters, CaptureSummary, Catalog, Event, Operation},
    cli::{DEFAULT_PUBLIC_ORIGIN, auth, download, notary, proxy, publish},
    config::AgentConfig,
    notary_directory::key_id,
    vault::Vault,
};

const API_VERSION: &str = "v1";
const SESSION_COOKIE: &str = "llm_notary_admin_session";
const DASHBOARD_HEADER: &str = "x-llm-notary-request";

#[derive(Clone)]
pub(crate) struct AdminState {
    catalog: Arc<Catalog>,
    config: Arc<AgentConfig>,
    token: Arc<str>,
    sessions: Arc<Mutex<HashSet<String>>>,
    pending_authorizations: Arc<Mutex<HashMap<String, auth::PendingAuthorization>>>,
    publication_credentials: Arc<Mutex<()>>,
    pub(crate) work_available: Arc<Notify>,
}

impl AdminState {
    pub(crate) fn new(catalog: Arc<Catalog>, config: Arc<AgentConfig>) -> Result<Self> {
        let token = load_or_create_token(&config.admin.token_path)?;
        let interrupted = catalog.recover_operations(now_ms()?)?;
        if interrupted > 0 {
            tracing::warn!(interrupted, "recovered interrupted finalization operations");
        }
        Ok(Self {
            catalog,
            config,
            token: Arc::from(token),
            sessions: Arc::new(Mutex::new(HashSet::new())),
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            publication_credentials: Arc::new(Mutex::new(())),
            work_available: Arc::new(Notify::new()),
        })
    }
}

pub(crate) fn router(state: AdminState) -> Result<Router> {
    let protected = Router::new()
        .route("/v1/status", get(status))
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
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .with_state(state))
}

#[derive(OpenApi)]
#[openapi(
    info(title = "LLM Notary local administration API", version = "1.0.0"),
    paths(
        health, openapi, start_session, end_session, status, captures, capture,
        start_finalization, operations, operation, retry_operation, trace,
        verify_trace, events, publication_auth_status, start_publication_auth,
        end_publication_auth, poll_publication_auth, publish_capture,
        download_public_trace, verify_public_trace
    ),
    components(schemas(
        HealthResponse, StatusResponse, CountsResponse,
        CaptureResponse, CaptureDetailResponse, ArtifactResponse, CaptureListResponse,
        OperationResponse, OperationListResponse, FinalizationResponse, EventResponse,
        EventListResponse, TraceResponse, VerificationResponse, PublicationAuthResponse,
        PublicationAuthRequest, PublicationAuthStartedResponse, PublicationResponse,
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
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque local token")
                        .build(),
                ),
            );
        }
    }
}

#[utoipa::path(get, path = "/healthz", responses((status = 200, body = HealthResponse)), tag = "local-admin")]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "llm-notary".into(),
        status: "ok".into(),
        api_version: API_VERSION.into(),
    })
}

#[utoipa::path(get, path = "/openapi.json", responses((status = 200, description = "OpenAPI 3.1 document")), tag = "local-admin")]
async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[utoipa::path(post, path = "/v1/session", responses((status = 204, description = "HttpOnly dashboard session established"), (status = 401, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn start_session(State(state): State<AdminState>, request: Request) -> Response {
    if !bearer_matches(&state, request.headers()) {
        return ApiError::unauthorized().into_response();
    }
    let session = new_secret();
    state.sessions.lock().await.insert(session.clone());
    let cookie =
        format!("{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200");
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated session cookie is valid"),
    );
    response
}

#[utoipa::path(delete, path = "/v1/session", responses((status = 204, description = "Dashboard session ended"), (status = 401, body = ErrorEnvelope)), tag = "local-admin")]
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
    let bearer_ok = bearer_matches(&state, request.headers());
    let session_ok = if bearer_ok {
        false
    } else if request
        .headers()
        .get(DASHBOARD_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("dashboard")
    {
        match session_from_headers(request.headers()) {
            Some(value) => state.sessions.lock().await.contains(value),
            None => false,
        }
    } else {
        false
    };
    if bearer_ok || session_ok {
        next.run(request).await
    } else {
        ApiError::unauthorized().into_response()
    }
}

#[utoipa::path(get, path = "/v1/status", responses((status = 200, body = StatusResponse), (status = 401, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
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

#[utoipa::path(get, path = "/v1/captures", params(("query" = Option<String>, Query), ("model" = Option<String>, Query), ("provider" = Option<String>, Query), ("capture_state" = Option<String>, Query), ("finalization_state" = Option<String>, Query), ("limit" = Option<usize>, Query), ("offset" = Option<usize>, Query)), responses((status = 200, body = CaptureListResponse), (status = 401, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn captures(
    State(state): State<AdminState>,
    Query(query): Query<CaptureQuery>,
) -> Result<Json<CaptureListResponse>, ApiError> {
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

#[utoipa::path(get, path = "/v1/captures/{capture_id}", params(("capture_id" = String, Path)), responses((status = 200, body = CaptureDetailResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
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
    }))
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/finalizations", params(("capture_id" = String, Path)), responses((status = 202, body = FinalizationResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn start_finalization(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<(StatusCode, Json<FinalizationResponse>), ApiError> {
    validate_id(&capture_id, "cap-")?;
    let catalog = state.catalog.clone();
    let queued =
        tokio::task::spawn_blocking(move || catalog.enqueue_finalization(&capture_id, now_ms()?))
            .await
            .map_err(|_| ApiError::internal("catalog_task_failed"))?
            .map_err(|_| ApiError::internal("finalization_queue_failed"))?
            .ok_or_else(|| ApiError::not_found("pending_capture_not_found"))?;
    state.work_available.notify_one();
    Ok((
        StatusCode::ACCEPTED,
        Json(FinalizationResponse {
            operation: queued.0.into(),
            deduplicated: queued.1,
        }),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

#[utoipa::path(get, path = "/v1/operations", params(("limit" = Option<usize>, Query)), responses((status = 200, body = OperationListResponse)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn operations(
    State(state): State<AdminState>,
    Query(query): Query<LimitQuery>,
) -> Result<Json<OperationListResponse>, ApiError> {
    let catalog = state.catalog.clone();
    let values = tokio::task::spawn_blocking(move || catalog.operations(query.limit.unwrap_or(50)))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?;
    Ok(Json(OperationListResponse {
        items: values.into_iter().map(Into::into).collect(),
    }))
}

#[utoipa::path(get, path = "/v1/operations/{operation_id}", params(("operation_id" = String, Path)), responses((status = 200, body = OperationResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<Json<OperationResponse>, ApiError> {
    validate_id(&operation_id, "op-")?;
    let catalog = state.catalog.clone();
    let value = tokio::task::spawn_blocking(move || catalog.operation(&operation_id))
        .await
        .map_err(|_| ApiError::internal("catalog_task_failed"))?
        .map_err(|_| ApiError::internal("catalog_query_failed"))?
        .ok_or_else(|| ApiError::not_found("operation_not_found"))?;
    Ok(Json(value.into()))
}

#[utoipa::path(post, path = "/v1/operations/{operation_id}/retry", params(("operation_id" = String, Path)), responses((status = 202, body = OperationResponse), (status = 409, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn retry_operation(
    State(state): State<AdminState>,
    Path(operation_id): Path<String>,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    validate_id(&operation_id, "op-")?;
    let catalog = state.catalog.clone();
    let value =
        tokio::task::spawn_blocking(move || catalog.retry_operation(&operation_id, now_ms()?))
            .await
            .map_err(|_| ApiError::internal("catalog_task_failed"))?
            .map_err(|_| ApiError::internal("operation_retry_failed"))?
            .ok_or_else(|| ApiError::conflict("operation_not_retryable"))?;
    state.work_available.notify_one();
    Ok((StatusCode::ACCEPTED, Json(value.into())))
}

#[utoipa::path(get, path = "/v1/captures/{capture_id}/trace", params(("capture_id" = String, Path)), responses((status = 200, body = TraceResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn trace(
    State(state): State<AdminState>,
    Path(capture_id): Path<String>,
) -> Result<Json<TraceResponse>, ApiError> {
    validate_id(&capture_id, "cap-")?;
    let path = finalized_path(&state.catalog, &capture_id).await?;
    let value = tokio::task::spawn_blocking(move || -> Result<TraceResponse> {
        Ok(TraceResponse {
            capture_id,
            manifest: serde_json::from_slice(&fs::read(path.join("manifest.json"))?)?,
            trace: serde_json::from_slice(&fs::read(path.join("trace.otlp.json"))?)?,
        })
    })
    .await
    .map_err(|_| ApiError::internal("trace_task_failed"))?
    .map_err(|_| ApiError::internal("trace_decode_failed"))?;
    Ok(Json(value))
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/trace:verify", params(("capture_id" = String, Path)), responses((status = 200, body = VerificationResponse), (status = 422, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
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
    limit: Option<usize>,
}

#[utoipa::path(get, path = "/v1/events", params(("cursor" = Option<u64>, Query), ("limit" = Option<usize>, Query)), responses((status = 200, body = EventListResponse)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn events(
    State(state): State<AdminState>,
    Query(query): Query<EventQuery>,
) -> Result<Json<EventListResponse>, ApiError> {
    let catalog = state.catalog.clone();
    let values = tokio::task::spawn_blocking(move || {
        catalog.events(query.cursor, query.limit.unwrap_or(50))
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

#[utoipa::path(get, path = "/v1/publication/auth", responses((status = 200, body = PublicationAuthResponse)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn publication_auth_status(
    State(state): State<AdminState>,
) -> Result<Json<PublicationAuthResponse>, ApiError> {
    let _credentials = state.publication_credentials.lock().await;
    load_publication_auth_status().await
}

async fn load_publication_auth_status() -> Result<Json<PublicationAuthResponse>, ApiError> {
    let status = auth::publication_auth_status()
        .await
        .map_err(|_| ApiError::internal("publication_auth_status_failed"))?;
    Ok(Json(PublicationAuthResponse {
        signed_in: status.signed_in,
        github_login: status.github_login,
        device_name: status.device_name,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
struct PublicationAuthRequest {
    #[serde(default = "default_public_origin")]
    api_origin: String,
    #[serde(default = "default_device_name")]
    device_name: String,
}

fn default_public_origin() -> String {
    DEFAULT_PUBLIC_ORIGIN.to_owned()
}

fn default_device_name() -> String {
    "LLM Notary local dashboard".to_owned()
}

#[utoipa::path(post, path = "/v1/publication/auth", request_body = PublicationAuthRequest, responses((status = 202, body = PublicationAuthStartedResponse)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn start_publication_auth(
    State(state): State<AdminState>,
    Json(body): Json<PublicationAuthRequest>,
) -> Result<(StatusCode, Json<PublicationAuthStartedResponse>), ApiError> {
    let pending = auth::start_authorization(&body.api_origin, &body.device_name)
        .await
        .map_err(|_| ApiError::internal("publication_auth_start_failed"))?;
    let response = PublicationAuthStartedResponse {
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

#[utoipa::path(get, path = "/v1/publication/auth/{request_id}", params(("request_id" = String, Path)), responses((status = 200, body = PublicationAuthResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn poll_publication_auth(
    State(state): State<AdminState>,
    Path(request_id): Path<String>,
) -> Result<Json<PublicationAuthResponse>, ApiError> {
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
        auth::AuthorizationPoll::Pending => Ok(Json(PublicationAuthResponse {
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

#[utoipa::path(delete, path = "/v1/publication/auth", responses((status = 204, description = "Publication credentials revoked")), security(("bearerAuth" = [])), tag = "local-admin")]
async fn end_publication_auth(State(state): State<AdminState>) -> Result<StatusCode, ApiError> {
    let _credentials = state.publication_credentials.lock().await;
    auth::logout_for_service()
        .await
        .map_err(|_| ApiError::internal("publication_logout_failed"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/v1/captures/{capture_id}/publications", params(("capture_id" = String, Path)), responses((status = 202, body = PublicationResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
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
            job_id: publication.job_id,
            state: publication.state,
            status_url: publication.status_url,
        }),
    ))
}

#[derive(Debug, Default, Deserialize)]
struct PublicTraceQuery {
    api_origin: Option<String>,
}

#[utoipa::path(get, path = "/v1/public-traces/{publication_id}", params(("publication_id" = String, Path), ("api_origin" = Option<String>, Query)), responses((status = 200, body = PublicTraceResponse), (status = 404, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn download_public_trace(
    Path(publication_id): Path<String>,
    Query(query): Query<PublicTraceQuery>,
) -> Result<Json<PublicTraceResponse>, ApiError> {
    fetch_public_trace(publication_id, query.api_origin, false).await
}

#[utoipa::path(post, path = "/v1/public-traces/{publication_id}/verify", params(("publication_id" = String, Path), ("api_origin" = Option<String>, Query)), responses((status = 200, body = PublicTraceResponse), (status = 422, body = ErrorEnvelope)), security(("bearerAuth" = [])), tag = "local-admin")]
async fn verify_public_trace(
    Path(publication_id): Path<String>,
    Query(query): Query<PublicTraceQuery>,
) -> Result<Json<PublicTraceResponse>, ApiError> {
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
        stamp: serde_json::to_value(value.stamp)
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
    let output = config.storage.finalized_dir.join(capture_id);
    if output.is_dir() {
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
    let path = finalize_bundle(
        &bundle_path,
        &output,
        &key,
        vault,
        &endpoint,
        config.proxy.max_attestable_http_bytes,
        config.notary.max_frame_bytes,
    )
    .await?;
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

fn load_or_create_token(path: &std::path::Path) -> Result<String> {
    if path.exists() {
        crate::cli::storage::ensure_private_file(path)?;
        let metadata = fs::metadata(path)
            .with_context(|| format!("reading admin token file {}", path.display()))?;
        if !metadata.is_file() {
            anyhow::bail!("admin token path is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                anyhow::bail!("admin token file must not be readable by group or others");
            }
        }
        let token = fs::read_to_string(path)
            .with_context(|| format!("reading admin token file {}", path.display()))?;
        let token = token.trim().to_owned();
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            anyhow::bail!("admin token file contains an invalid token");
        }
        return Ok(token);
    }
    let token = new_secret();
    crate::cli::storage::write_private_file_atomically(path, token.as_bytes())?;
    Ok(token)
}

fn new_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn token_matches(expected: &str, actual: &str) -> bool {
    expected.as_bytes().ct_eq(actual.as_bytes()).into()
}

fn bearer_matches(state: &AdminState, headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| token_matches(&state.token, value))
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
    prompt_preview: String,
    prompt_preview_truncated: bool,
    output_preview: String,
    output_preview_truncated: bool,
    failure_code: Option<String>,
}

impl From<CaptureSummary> for CaptureResponse {
    fn from(value: CaptureSummary) -> Self {
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
}

impl From<Operation> for OperationResponse {
    fn from(value: Operation) -> Self {
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
struct PublicationAuthResponse {
    signed_in: bool,
    github_login: Option<String>,
    device_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct PublicationAuthStartedResponse {
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
struct PublicTraceResponse {
    publication_id: String,
    trace: serde_json::Value,
    stamp: serde_json::Value,
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
    fn unprocessable(code: &'static str) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: "The finalized trace did not verify",
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
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn state(directory: &std::path::Path) -> AdminState {
        let mut config = AgentConfig::default();
        config.catalog.path = directory.join("catalog.db");
        config.storage.bundle_dir = directory.join("bundles");
        config.storage.finalized_dir = directory.join("traces");
        config.admin.token_path = directory.join("admin-token");
        AdminState::new(
            Arc::new(Catalog::open_for_config(&config).unwrap()),
            Arc::new(config),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn protected_routes_reject_missing_or_wrong_auth_without_echoing_it() {
        let directory = tempfile::tempdir().unwrap();
        let app = router(state(directory.path())).unwrap();
        for value in [None, Some("Bearer deliberately-wrong-secret")] {
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
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!String::from_utf8_lossy(&body).contains("deliberately-wrong-secret"));
        }

        let response = app
            .oneshot(
                Request::post("/v1/captures/cap-example/finalizations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
        assert!(body["components"]["securitySchemes"]["bearerAuth"].is_object());
        for path in [
            "/healthz",
            "/openapi.json",
            "/v1/status",
            "/v1/captures",
            "/v1/captures/{capture_id}",
            "/v1/captures/{capture_id}/finalizations",
            "/v1/operations",
            "/v1/operations/{operation_id}",
            "/v1/operations/{operation_id}/retry",
            "/v1/captures/{capture_id}/trace",
            "/v1/captures/{capture_id}/trace:verify",
            "/v1/events",
            "/v1/session",
            "/v1/publication/auth",
            "/v1/publication/auth/{request_id}",
            "/v1/captures/{capture_id}/publications",
            "/v1/public-traces/{publication_id}",
            "/v1/public-traces/{publication_id}/verify",
        ] {
            assert!(body["paths"].get(path).is_some(), "OpenAPI missing {path}");
        }
    }

    #[tokio::test]
    async fn dashboard_session_exchanges_the_token_without_returning_or_persisting_it() {
        let directory = tempfile::tempdir().unwrap();
        let state = state(directory.path());
        let token = state.token.to_string();
        let app = router(state).unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/session")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
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
        assert!(!cookie.contains(&token));

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
        assert!(!String::from_utf8_lossy(&body).contains(&token));
    }
}
