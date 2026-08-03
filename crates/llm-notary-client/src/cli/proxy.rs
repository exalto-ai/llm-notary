use std::{
    collections::HashSet,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

use super::{
    api_origin::ApiOrigin,
    config::load_agent_config,
    http_client_builder,
    notary::{parse_directory, pin},
};
use crate::{
    DeferredBundle, DeferredCaptureConfig, attestable_request_header_bytes,
    catalog::{Catalog, NewCapture},
    chunked_request_body,
    config::{AgentConfig, ProviderConfig},
    deferred_streaming_request_to, notary_admission_error,
    notary_directory::{NotaryDirectory, NotaryDirectoryRecord, NotaryEndpoint},
    vault::Vault,
};

#[cfg(test)]
use crate::{DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Provider {
    Openai,
    Anthropic,
    Deepseek,
    Openrouter,
}

impl Provider {
    const ALL: [Self; 4] = [
        Self::Openai,
        Self::Anthropic,
        Self::Deepseek,
        Self::Openrouter,
    ];

    fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Deepseek => "api.deepseek.com",
            Self::Openrouter => "openrouter.ai",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Deepseek => "deepseek",
            Self::Openrouter => "openrouter",
        }
    }

    #[cfg(test)]
    fn default_path_prefix(self) -> &'static str {
        match self {
            Self::Openai => "/openai",
            Self::Anthropic => "/anthropic",
            Self::Deepseek => "/deepseek",
            Self::Openrouter => "/openrouter",
        }
    }

    fn config(self, config: &AgentConfig) -> &ProviderConfig {
        match self {
            Self::Openai => &config.providers.openai,
            Self::Anthropic => &config.providers.anthropic,
            Self::Deepseek => &config.providers.deepseek,
            Self::Openrouter => &config.providers.openrouter,
        }
    }
}

#[derive(Debug)]
pub struct ProxyArgs {
    /// Versioned local agent configuration file. Defaults to the standard
    /// path, creating an editable default there on first use.
    pub(crate) config: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    notary: NotaryEndpoint,
    bundle_dir: PathBuf,
    max_frame_bytes: usize,
    max_attestable_http_bytes: usize,
    pub(crate) vault: Arc<Vault>,
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) config: Arc<AgentConfig>,
    config_fingerprint: Arc<str>,
    serial: Arc<Mutex<u64>>,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    let (config, config_path) = load_agent_config(args.config.as_deref())?;
    let listen = config.proxy.listen;
    let bundle_dir = config.storage.bundle_dir.clone();
    let max_frame_bytes = config.notary.max_frame_bytes;
    let max_attestable_http_bytes = config.proxy.max_attestable_http_bytes;
    if max_frame_bytes == 0 || max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    if max_attestable_http_bytes == 0 {
        bail!("maximum attestable HTTP bytes must be non-zero");
    }
    std::fs::create_dir_all(&bundle_dir)?;
    let notary = match config.notary_endpoint()? {
        Some(notary) => notary,
        None => discover_notary().await?,
    };
    let vault = Vault::open_or_init_interactive().context(
        "opening the local bundle vault (set LLM_NOTARY_VAULT_PASSPHRASE_FILE before first start when an OS vault is unavailable)",
    )?;
    let (catalog, recovery) = Catalog::open_for_proxy(&config)?;
    if recovery.recovered_bundles > 0 || recovery.interrupted_captures > 0 {
        tracing::warn!(
            recovered_bundles = recovery.recovered_bundles,
            interrupted_captures = recovery.interrupted_captures,
            "reconciled captures left incomplete by an earlier proxy process"
        );
    }
    let state = AppState {
        notary: notary.clone(),
        bundle_dir,
        max_frame_bytes,
        max_attestable_http_bytes,
        vault: Arc::new(vault),
        catalog: Arc::new(catalog),
        config_fingerprint: Arc::from(config.fingerprint()?),
        config: Arc::new(config),
        serial: Arc::new(Mutex::new(0)),
    };
    let app = router(state.clone());
    let admin_state = crate::admin::AdminState::new(state.catalog.clone(), state.config.clone())?;
    let admin = crate::admin::router(admin_state.clone())?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let admin_listener = tokio::net::TcpListener::bind(state.config.admin.listen).await?;
    tracing::info!(
        address = %listen,
        notary = %notary,
        config = %config_path.display(),
        providers = ?Provider::ALL,
        "LLM Notary proxy listening"
    );
    tracing::info!(address = %state.config.admin.listen, "LLM Notary admin API listening");
    let mut worker = crate::admin::spawn_finalization_worker(
        state.catalog.clone(),
        state.config.clone(),
        state.vault.clone(),
        admin_state.work_available.clone(),
    );
    let result = tokio::select! {
        result = axum::serve(listener, app) => result.map_err(Into::into),
        result = axum::serve(admin_listener, admin) => result.map_err(Into::into),
        result = &mut worker => result.context("finalization worker exited")?,
        () = shutdown_signal() => {
            tracing::info!("LLM Notary service shutting down");
            Ok(())
        },
    };
    worker.abort();
    result
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new().fallback(any(proxy)).with_state(state)
}

async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing Ctrl-C signal handler failed");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing termination signal handler failed")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}

pub(crate) async fn discover_notary() -> Result<NotaryEndpoint> {
    let directory = refresh_notary_directory().await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")?;
    resolve_notary(directory.active_at(now)?).await
}

pub(crate) async fn refresh_notary_directory() -> Result<NotaryDirectory> {
    refresh_notary_directory_from(&ApiOrigin::default_public()).await
}

pub(crate) async fn refresh_notary_directory_from(
    api_origin: &ApiOrigin,
) -> Result<NotaryDirectory> {
    let directory_url = notary_directory_url(api_origin);
    let bytes = http_client_builder()
        .build()?
        .get(directory_url.clone())
        .send()
        .await
        .with_context(|| format!("fetching notary endpoint from {directory_url}"))?
        .error_for_status()
        .with_context(|| format!("fetching notary endpoint from {directory_url}"))?
        .bytes()
        .await
        .context("reading notary directory from LLM Notary API")?;
    let directory = parse_directory(&bytes)?;
    pin(directory.clone(), directory_url.as_str())?;
    tracing::info!(
        key_id = %directory.active_key_id,
        key_count = directory.notaries.len(),
        "pinned trusted notary directory"
    );
    Ok(directory)
}

fn notary_directory_url(api_origin: &ApiOrigin) -> url::Url {
    api_origin.api_url("/api/notary")
}

pub(crate) async fn resolve_notary(record: &NotaryDirectoryRecord) -> Result<NotaryEndpoint> {
    record.endpoint()
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    match proxy_inner(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                kind = if notary_admission_error(&error).is_some() {
                    "notary_capacity"
                } else {
                    "proxy_error"
                },
                "proxy request failed"
            );
            proxy_error_response(&error)
        }
    }
}

fn proxy_error_response(error: &anyhow::Error) -> Response {
    let Some(admission) = notary_admission_error(error) else {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "application/json")],
            r#"{"error":{"message":"LLM Notary proxy request failed"}}"#,
        )
            .into_response();
    };
    let retry_after_seconds = admission.retry_after().as_secs().max(1);
    let message = match admission.rejection() {
        crate::NotaryAdmissionRejection::CaptureAtCapacity => {
            "LLM Notary capture capacity is temporarily full; retry shortly."
        }
        crate::NotaryAdmissionRejection::CaptureDisabled => {
            "LLM Notary is temporarily not accepting new captures."
        }
        crate::NotaryAdmissionRejection::FinalizeAtCapacity => {
            "LLM Notary returned an unexpected finalization-capacity rejection. Retry shortly."
        }
    };
    let body = serde_json::json!({
        "error": {
            "type": "notary_capacity",
            "code": admission.rejection().code(),
            "message": message,
            "retry_after_seconds": retry_after_seconds,
        }
    });
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response();
    response.headers_mut().insert(
        http::header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a u64 retry-after value is always a valid header"),
    );
    response
}

/// Selects a fixed provider adapter from the first local path segment and
/// removes that segment before the authenticated upstream request is formed.
/// This keeps the caller from choosing an arbitrary destination while letting
/// one local listener serve every supported provider.
fn provider_route(uri: &http::Uri, config: &AgentConfig) -> Option<(Provider, http::Uri)> {
    for provider in Provider::ALL {
        let provider_config = provider.config(config);
        if !provider_config.enabled {
            continue;
        }
        let prefix = provider_config.route_prefix.as_str();
        let Some(remainder) = uri.path().strip_prefix(prefix) else {
            continue;
        };
        if !remainder.is_empty() && !remainder.starts_with('/') {
            continue;
        }
        let upstream_path = if remainder.is_empty() { "/" } else { remainder };
        let path_and_query = match uri.query() {
            Some(query) => format!("{upstream_path}?{query}"),
            None => upstream_path.to_owned(),
        };
        let upstream_uri = path_and_query
            .parse()
            .expect("a path and query taken from a parsed URI remain valid");
        return Some((provider, upstream_uri));
    }
    None
}

fn provider_route_not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/json")],
        r#"{"error":{"message":"an enabled LLM Notary provider path is required"}}"#,
    )
        .into_response()
}

async fn proxy_inner(state: AppState, request: Request) -> Result<Response> {
    let (mut parts, body) = request.into_parts();
    for name in [
        http::header::AUTHORIZATION,
        http::header::PROXY_AUTHORIZATION,
        HeaderName::from_static("x-api-key"),
    ] {
        if let Some(value) = parts.headers.get_mut(name) {
            value.set_sensitive(true);
        }
    }
    if (parts.method == http::Method::GET || parts.method == http::Method::HEAD)
        && matches!(parts.uri.path(), "/" | "/healthz")
    {
        let mut response = if parts.method == http::Method::HEAD {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(
                r#"{"service":"llm-notary-proxy","status":"ok"}"#,
            ))
        };
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    if parts.method == http::Method::GET || parts.method == http::Method::HEAD {
        return Ok(provider_route_not_found_response());
    }
    if parts.method != http::Method::POST {
        let mut response =
            Response::new(Body::from(r#"{"error":{"message":"method not allowed"}}"#));
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(
            http::header::ALLOW,
            HeaderValue::from_static("GET, HEAD, POST"),
        );
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    let Some((provider, upstream_uri)) = provider_route(&parts.uri, &state.config) else {
        return Ok(provider_route_not_found_response());
    };
    let host = provider.host();
    let mut outbound_headers = end_to_end_headers(&parts.headers);
    // The provider hostname is selected by the local adapter, never by the
    // caller. `Host` is connection-specific here because we create a new
    // upstream connection rather than forwarding the caller's one.
    outbound_headers.remove(http::header::HOST);
    outbound_headers.remove(http::header::ACCEPT_ENCODING);
    outbound_headers.insert(
        http::header::HOST,
        HeaderValue::from_str(host).expect("provider host is a valid HTTP header value"),
    );
    outbound_headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let request_header_bytes =
        attestable_request_header_bytes(&parts.method, &upstream_uri, &outbound_headers)?;
    let request_body_limit = state
        .max_attestable_http_bytes
        .checked_sub(request_header_bytes)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "provider request headers exceed the {}-byte maximum attestable HTTP budget",
                state.max_attestable_http_bytes
            )
        })?;
    let input = collect_request_body(body, request_body_limit).await?;
    let streaming = wants_stream(&parts.headers, &input);
    let request_metadata =
        request_catalog_metadata(provider, &input, state.config.catalog.prompt_preview_chars);
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for notarization"
    );
    let operation = upstream_uri.path().to_owned();
    let mut outbound = http::Request::builder()
        .method(parts.method)
        .uri(upstream_uri);
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (capture_id, created_at_unix_ms) = next_capture_metadata(&state).await?;
    state.catalog.begin_capture(&NewCapture {
        capture_id: capture_id.clone(),
        created_at_unix_ms,
        provider: provider.name().to_owned(),
        operation,
        requested_model: request_metadata.requested_model.clone(),
        streaming,
        request_bytes: request_body_bytes,
        prompt_preview: request_metadata.prompt_preview,
        prompt_preview_truncated: request_metadata.prompt_preview_truncated,
        config_fingerprint: state.config_fingerprint.to_string(),
    })?;
    let started = Instant::now();
    let upstream = deferred_streaming_request_to(
        &state.notary,
        host,
        DeferredCaptureConfig {
            capture_id: capture_id.clone(),
            provider_name: provider.name().to_owned(),
            created_at_unix_ms,
            request_body_bytes,
            max_attestable_http_bytes: state.max_attestable_http_bytes,
            max_frame_bytes: state.max_frame_bytes,
        },
        outbound,
    )
    .await;
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = state
                .catalog
                .mark_capture_failed(&capture_id, "notary_error");
            return Err(error);
        }
    };

    if streaming {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let trace_state = state.clone();
        let capture_id_for_task = capture_id.clone();
        let response_preview_limit = state.config.catalog.output_preview_chars;
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            let mut client_connected = true;
            let mut output_preview = StreamingOutputPreview::new(provider, response_preview_limit);
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if let Ok(bytes) = &chunk {
                    output_preview.push(bytes);
                }
                if client_connected && body_sender.send(chunk).await.is_err() {
                    // Keep draining the provider stream so a caller
                    // disconnect does not prevent the bundle from sealing.
                    client_connected = false;
                }
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; sealing deferred bundle"
            );
            let bundle = upstream.bundle;
            drop(body_sender);
            match bundle.await {
                Ok(Ok(bundle)) => {
                    match save_bundle(&trace_state.bundle_dir, &bundle, &trace_state.vault) {
                        Ok(path) => {
                            let response_bytes = output_preview.response_bytes;
                            let preview = output_preview.finish();
                            let completed_at = current_unix_ms().unwrap_or(created_at_unix_ms);
                            if trace_state
                                .catalog
                                .complete_capture(
                                    &capture_id_for_task,
                                    completed_at,
                                    elapsed_ms(started),
                                    status.as_u16(),
                                    response_bytes,
                                    preview.response_model.as_deref(),
                                    &preview.text,
                                    preview.truncated,
                                    &path,
                                )
                                .is_err()
                            {
                                tracing::warn!(capture_id = %capture_id_for_task, "could not index deferred streaming bundle");
                            }
                            tracing::info!(capture_id = %capture_id_for_task, provider = provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote deferred streaming bundle")
                        }
                        Err(error) => {
                            let _ = trace_state
                                .catalog
                                .mark_capture_failed(&capture_id_for_task, "bundle_store_error");
                            tracing::warn!(%error, "could not save deferred streaming bundle")
                        }
                    }
                }
                Ok(Err(error)) => {
                    let _ = trace_state
                        .catalog
                        .mark_capture_failed(&capture_id_for_task, "capture_error");
                    tracing::warn!(%error, "stream ended without an LLM Notary deferred bundle")
                }
                Err(error) => {
                    let _ = trace_state
                        .catalog
                        .mark_capture_failed(&capture_id_for_task, "capture_task_error");
                    tracing::warn!(%error, "stream deferred capture task exited")
                }
            }
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_end_to_end_headers(response.headers_mut(), &headers);
        response.headers_mut().insert(
            "x-llm-notary-capture-id",
            HeaderValue::from_str(&capture_id)?,
        );
        return Ok(response);
    }

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = upstream.body.recv().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(error) => {
                let _ = state
                    .catalog
                    .mark_capture_failed(&capture_id, "response_error");
                return Err(error.into());
            }
        }
    }
    let bundle = match upstream.bundle.await {
        Ok(Ok(bundle)) => bundle,
        Ok(Err(error)) => {
            let _ = state
                .catalog
                .mark_capture_failed(&capture_id, "capture_error");
            return Err(error);
        }
        Err(error) => {
            let _ = state
                .catalog
                .mark_capture_failed(&capture_id, "capture_task_error");
            return Err(error).context("deferred bundle task exited");
        }
    };
    let path = match save_bundle(&state.bundle_dir, &bundle, &state.vault) {
        Ok(path) => path,
        Err(error) => {
            let _ = state
                .catalog
                .mark_capture_failed(&capture_id, "bundle_store_error");
            return Err(error);
        }
    };
    let response_metadata =
        response_catalog_metadata(provider, &body, state.config.catalog.output_preview_chars);
    if state
        .catalog
        .complete_capture(
            &capture_id,
            current_unix_ms().unwrap_or(created_at_unix_ms),
            elapsed_ms(started),
            status.as_u16(),
            body.len(),
            response_metadata.response_model.as_deref(),
            &response_metadata.output_preview,
            response_metadata.output_preview_truncated,
            &path,
        )
        .is_err()
    {
        tracing::warn!(capture_id = %capture_id, "could not index deferred bundle");
    }
    tracing::info!(capture_id = %capture_id, provider = host, "wrote deferred bundle");

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response.headers_mut().insert(
        "x-llm-notary-capture-id",
        HeaderValue::from_str(&capture_id)?,
    );
    Ok(response)
}

async fn collect_request_body(mut body: Body, maximum: usize) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            let length = collected
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow::anyhow!("request body byte count overflow"))?;
            if length > maximum {
                bail!(
                    "provider request body exceeds the {maximum}-byte maximum attestable HTTP budget"
                );
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(collected.freeze())
}

fn save_bundle(
    bundle_dir: &std::path::Path,
    bundle: &DeferredBundle,
    vault: &Vault,
) -> Result<PathBuf> {
    std::fs::create_dir_all(bundle_dir)?;
    let path = bundle_dir.join(format!("{}.llmbundle", bundle.capture_id()));
    bundle.save(&path, vault)?;
    Ok(path)
}

async fn next_capture_metadata(state: &AppState) -> Result<(String, u64)> {
    let mut serial = state.serial.lock().await;
    *serial += 1;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_millis();
    let created_at_unix_ms: u64 = created_at_unix_ms
        .try_into()
        .map_err(|_| anyhow::anyhow!("capture timestamp does not fit in u64"))?;
    Ok((
        format!(
            "cap-{created_at_unix_ms}-{serial:04}-{}",
            uuid::Uuid::new_v4().simple()
        ),
        created_at_unix_ms,
    ))
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Default)]
struct RequestCatalogMetadata {
    requested_model: Option<String>,
    prompt_preview: String,
    prompt_preview_truncated: bool,
}

#[derive(Default)]
struct ResponseCatalogMetadata {
    response_model: Option<String>,
    output_preview: String,
    output_preview_truncated: bool,
}

struct Preview {
    text: String,
    truncated: bool,
}

/// Pulls only known textual message fields from a supported request shape. It
/// intentionally never indexes raw HTTP, headers, or tool-call arguments.
fn request_catalog_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> RequestCatalogMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return RequestCatalogMetadata::default();
    };
    let requested_model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut preview = LimitedText::new(maximum_preview_chars);
    match provider {
        Provider::Openai | Provider::Deepseek | Provider::Openrouter => {
            append_messages(&mut preview, value.get("messages"));
            append_messages(&mut preview, value.get("input"));
        }
        Provider::Anthropic => {
            append_text_value(&mut preview, value.get("system"));
            append_messages(&mut preview, value.get("messages"));
        }
    }
    let preview = preview.finish();
    RequestCatalogMetadata {
        requested_model,
        prompt_preview: preview.text,
        prompt_preview_truncated: preview.truncated,
    }
}

/// Pulls visible assistant text from a complete non-streaming response.
fn response_catalog_metadata(
    provider: Provider,
    bytes: &[u8],
    maximum_preview_chars: usize,
) -> ResponseCatalogMetadata {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return ResponseCatalogMetadata::default();
    };
    let mut preview = LimitedText::new(maximum_preview_chars);
    append_response_text(provider, &mut preview, &value, false);
    let preview = preview.finish();
    ResponseCatalogMetadata {
        response_model: value
            .get("model")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        output_preview: preview.text,
        output_preview_truncated: preview.truncated,
    }
}

/// Incrementally extracts text from provider SSE events without retaining the
/// raw stream in the catalog.
struct StreamingOutputPreview {
    provider: Provider,
    preview: LimitedText,
    pending: Vec<u8>,
    response_bytes: usize,
    response_model: Option<String>,
}

struct StreamingResponseMetadata {
    text: String,
    truncated: bool,
    response_model: Option<String>,
}

impl StreamingOutputPreview {
    fn new(provider: Provider, maximum_preview_chars: usize) -> Self {
        Self {
            provider,
            preview: LimitedText::new(maximum_preview_chars),
            pending: Vec::new(),
            response_bytes: 0,
            response_model: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.response_bytes = self.response_bytes.saturating_add(bytes.len());
        self.pending.extend_from_slice(bytes);
        while let Some(newline) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=newline).collect::<Vec<_>>();
            let line = line.strip_suffix(b"\n").unwrap_or(&line);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let data = trim_ascii(data);
            if data == b"[DONE]" {
                continue;
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                if self.response_model.is_none() {
                    self.response_model = response_model_from_stream_event(&value);
                }
                append_response_text(self.provider, &mut self.preview, &value, true);
            }
        }
    }

    fn finish(mut self) -> StreamingResponseMetadata {
        // Some providers send a final JSON body rather than SSE. It is safe to
        // ignore an incomplete event rather than index raw bytes.
        self.pending.clear();
        let preview = self.preview.finish();
        StreamingResponseMetadata {
            text: preview.text,
            truncated: preview.truncated,
            response_model: self.response_model,
        }
    }
}

fn response_model_from_stream_event(value: &serde_json::Value) -> Option<String> {
    value
        .get("model")
        .or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("model"))
        })
        .or_else(|| {
            value
                .get("response")
                .and_then(|response| response.get("model"))
        })
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

struct LimitedText {
    maximum_chars: usize,
    text: String,
    truncated: bool,
}

impl LimitedText {
    fn new(maximum_chars: usize) -> Self {
        Self {
            maximum_chars,
            text: String::new(),
            truncated: false,
        }
    }

    fn push(&mut self, text: &str) {
        if text.is_empty() || self.truncated || self.maximum_chars == 0 {
            return;
        }
        let used = self.text.chars().count();
        let available = self.maximum_chars.saturating_sub(used);
        if available == 0 {
            self.truncated = true;
            return;
        }
        let mut characters = text.chars();
        let prefix = characters.by_ref().take(available).collect::<String>();
        self.text.push_str(&prefix);
        if characters.next().is_some() {
            self.truncated = true;
        }
    }

    fn separator(&mut self) {
        if !self.text.is_empty() {
            self.push("\n");
        }
    }

    fn finish(self) -> Preview {
        Preview {
            text: self.text,
            truncated: self.truncated,
        }
    }
}

fn append_messages(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(messages) = value.and_then(serde_json::Value::as_array) else {
        append_text_value(preview, value);
        return;
    };
    for message in messages {
        let Some(message) = message.as_object() else {
            append_text_value(preview, Some(message));
            continue;
        };
        let content = message.get("content").or_else(|| message.get("text"));
        let mut message_preview = LimitedText::new(usize::MAX);
        append_text_value(&mut message_preview, content);
        let message_preview = message_preview.finish();
        if message_preview.text.is_empty() {
            continue;
        }
        preview.separator();
        if let Some(role) = message.get("role").and_then(serde_json::Value::as_str) {
            preview.push(role);
            preview.push(": ");
        }
        preview.push(&message_preview.text);
    }
}

fn append_text_value(preview: &mut LimitedText, value: Option<&serde_json::Value>) {
    let Some(value) = value else {
        return;
    };
    if let Some(text) = value.as_str() {
        preview.push(text);
        return;
    }
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        if let Some(text) = item.as_str() {
            preview.push(text);
            continue;
        }
        let Some(item) = item.as_object() else {
            continue;
        };
        let kind = item.get("type").and_then(serde_json::Value::as_str);
        if matches!(kind, Some("text" | "input_text" | "output_text"))
            && let Some(text) = item.get("text").and_then(serde_json::Value::as_str)
        {
            preview.push(text);
        }
    }
}

fn append_response_text(
    provider: Provider,
    preview: &mut LimitedText,
    value: &serde_json::Value,
    streaming: bool,
) {
    match provider {
        Provider::Anthropic => {
            if streaming {
                if let Some(text) = value
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(serde_json::Value::as_str)
                {
                    preview.push(text);
                }
            } else {
                append_text_value(preview, value.get("content"));
            }
        }
        Provider::Openai | Provider::Deepseek | Provider::Openrouter => {
            if streaming {
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        if let Some(text) = choice
                            .get("delta")
                            .and_then(|delta| delta.get("content"))
                            .and_then(serde_json::Value::as_str)
                        {
                            preview.push(text);
                        }
                    }
                }
                if let Some(text) = value.get("delta").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
            } else {
                if let Some(text) = value.get("output_text").and_then(serde_json::Value::as_str) {
                    preview.push(text);
                }
                if let Some(choices) = value.get("choices").and_then(serde_json::Value::as_array) {
                    for choice in choices {
                        append_text_value(
                            preview,
                            choice
                                .get("message")
                                .and_then(|message| message.get("content")),
                        );
                    }
                }
                if let Some(output) = value.get("output").and_then(serde_json::Value::as_array) {
                    for item in output {
                        append_text_value(preview, item.get("content"));
                    }
                }
            }
        }
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn wants_stream(headers: &HeaderMap, input: &[u8]) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"))
        || serde_json::from_slice::<serde_json::Value>(input)
            .ok()
            .and_then(|json| json.get("stream").and_then(serde_json::Value::as_bool))
            .unwrap_or(false)
}

/// Returns headers that remain meaningful after the proxy opens a fresh HTTP
/// connection. RFC 9110 hop-by-hop fields must not cross that boundary,
/// including extension fields named by a `Connection` header.
fn end_to_end_headers(source: &HeaderMap) -> HeaderMap {
    let mut target = HeaderMap::new();
    copy_end_to_end_headers(&mut target, source);
    target
}

fn copy_end_to_end_headers(target: &mut HeaderMap, source: &HeaderMap) {
    let hop_by_hop = hop_by_hop_header_names(source);
    for (name, value) in source {
        if !hop_by_hop.contains(name) {
            target.append(name, value.clone());
        }
    }
}

fn hop_by_hop_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut names = [
        http::header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        http::header::PROXY_AUTHENTICATE,
        http::header::PROXY_AUTHORIZATION,
        http::header::TE,
        http::header::TRAILER,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if let Ok(name) = HeaderName::from_bytes(token.as_bytes()) {
                names.insert(name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        let config = AgentConfig::default();
        AppState {
            notary: "127.0.0.1:7047".parse().unwrap(),
            bundle_dir: PathBuf::from("bundles"),
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            vault: Arc::new(Vault::test_only()),
            catalog: Arc::new(Catalog::open(std::path::Path::new(":memory:"), true).unwrap()),
            config_fingerprint: Arc::from(config.fingerprint().unwrap()),
            config: Arc::new(config),
            serial: Arc::new(Mutex::new(0)),
        }
    }

    #[test]
    fn detects_streaming_from_accept_or_request_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(wants_stream(&headers, b"{}"));
        assert!(wants_stream(&HeaderMap::new(), br#"{"stream":true}"#));
        assert!(!wants_stream(&HeaderMap::new(), br#"{"stream":false}"#));
    }

    #[tokio::test]
    async fn request_collection_enforces_the_attestable_byte_budget() {
        assert_eq!(
            collect_request_body(Body::from("abc"), 3).await.unwrap(),
            Bytes::from_static(b"abc")
        );
        let error = collect_request_body(Body::from("abcd"), 3)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("maximum attestable HTTP budget"));
    }

    #[test]
    fn provider_adapters_pin_their_authenticated_hosts() {
        assert_eq!(Provider::Openrouter.host(), "openrouter.ai");
        assert_eq!(Provider::Openrouter.name(), "openrouter");
        assert_eq!(Provider::Openrouter.default_path_prefix(), "/openrouter");
    }

    #[test]
    fn provider_routes_select_the_adapter_and_strip_its_prefix() {
        let config = AgentConfig::default();
        let uri = "/openai/v1/responses?stream=true".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Openai);
        assert_eq!(upstream_uri, "/v1/responses?stream=true");

        let uri = "/deepseek/chat/completions".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Deepseek);
        assert_eq!(upstream_uri, "/chat/completions");
    }

    #[test]
    fn provider_routes_only_match_a_complete_first_path_segment() {
        let config = AgentConfig::default();
        let uri = "/openaiish/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());

        let uri = "/anthropic".parse().unwrap();
        let (provider, upstream_uri) = provider_route(&uri, &config).unwrap();
        assert_eq!(provider, Provider::Anthropic);
        assert_eq!(upstream_uri.to_string(), "/");
    }

    #[test]
    fn disabled_provider_routes_are_not_available() {
        let mut config = AgentConfig::default();
        config.providers.openai.enabled = false;
        let uri = "/openai/v1/responses".parse().unwrap();
        assert!(provider_route(&uri, &config).is_none());
    }

    #[test]
    fn catalog_previews_extract_textual_messages_without_headers() {
        let request = request_catalog_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Explain pricing"}]}"#,
            1_000,
        );
        assert_eq!(request.requested_model.as_deref(), Some("gpt-5"));
        assert_eq!(
            request.prompt_preview,
            "system: Be concise\nuser: Explain pricing"
        );

        let response = response_catalog_metadata(
            Provider::Openai,
            br#"{"model":"gpt-5","choices":[{"message":{"content":"Pricing is usage based."}}]}"#,
            1_000,
        );
        assert_eq!(response.response_model.as_deref(), Some("gpt-5"));
        assert_eq!(response.output_preview, "Pricing is usage based.");
    }

    #[test]
    fn streaming_preview_handles_split_sse_events() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        let first = br#"data: {"model":"gpt-5","choices":[{"delta":{"content":"Price"}}]}"#;
        let second = br#"data: {"choices":[{"delta":{"content":"d"}}]}"#;
        preview.push(first);
        preview.push(b"\n\n");
        preview.push(second);
        preview.push(b"\n\n");
        assert_eq!(preview.response_bytes, first.len() + second.len() + 4);
        let preview = preview.finish();
        assert_eq!(preview.text, "Priced");
        assert_eq!(preview.response_model.as_deref(), Some("gpt-5"));
    }

    #[test]
    fn streaming_preview_reads_the_openai_responses_model() {
        let mut preview = StreamingOutputPreview::new(Provider::Openai, 1_000);
        preview.push(
            b"data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-5-mini\"}}\n\n",
        );
        assert_eq!(
            preview.finish().response_model.as_deref(),
            Some("gpt-5-mini")
        );
    }

    #[test]
    fn zero_preview_limit_omits_text_without_marking_it_truncated() {
        let request = request_catalog_metadata(
            Provider::Openai,
            br#"{"messages":[{"role":"user","content":"Do not store this preview"}]}"#,
            0,
        );
        assert!(request.prompt_preview.is_empty());
        assert!(!request.prompt_preview_truncated);
    }

    #[test]
    fn strips_fixed_and_connection_nominated_hop_by_hop_headers() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-request-scoped"),
        );
        source.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        source.insert(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic proxy-secret"),
        );
        source.insert(http::header::TE, HeaderValue::from_static("trailers"));
        source.insert(
            http::header::TRAILER,
            HeaderValue::from_static("x-checksum"),
        );
        source.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        source.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        source.insert(
            "x-request-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer provider-credential"),
        );
        source.insert("x-end-to-end", HeaderValue::from_static("keep"));

        let forwarded = end_to_end_headers(&source);
        for name in [
            http::header::CONNECTION,
            HeaderName::from_static("keep-alive"),
            http::header::PROXY_AUTHORIZATION,
            http::header::TE,
            http::header::TRAILER,
            http::header::TRANSFER_ENCODING,
            http::header::UPGRADE,
            HeaderName::from_static("x-request-scoped"),
        ] {
            assert!(forwarded.get(name).is_none());
        }
        assert_eq!(
            forwarded.get(http::header::AUTHORIZATION).unwrap(),
            "Bearer provider-credential"
        );
        assert_eq!(forwarded.get("x-end-to-end").unwrap(), "keep");
    }

    #[test]
    fn strips_response_only_hop_by_hop_headers_and_connection_tokens() {
        let mut source = HeaderMap::new();
        source.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("x-response-scoped"),
        );
        source.insert(
            http::header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=proxy"),
        );
        source.insert(
            "x-response-scoped",
            HeaderValue::from_static("must-not-forward"),
        );
        source.insert("x-request-id", HeaderValue::from_static("provider-id"));

        let mut target = HeaderMap::new();
        copy_end_to_end_headers(&mut target, &source);
        assert!(target.get(http::header::CONNECTION).is_none());
        assert!(target.get(http::header::PROXY_AUTHENTICATE).is_none());
        assert!(target.get("x-response-scoped").is_none());
        assert_eq!(target.get("x-request-id").unwrap(), "provider-id");
    }

    #[test]
    fn directory_discovery_stays_on_the_configured_api_origin() {
        assert_eq!(
            notary_directory_url(&ApiOrigin::parse("https://self-hosted.example").unwrap())
                .as_str(),
            "https://self-hosted.example/api/notary"
        );
        assert!(ApiOrigin::parse("file:///tmp/notary").is_err());
    }

    #[tokio::test]
    async fn admin_paths_are_not_reachable_from_the_proxy_listener() {
        for (method, path) in [
            (http::Method::GET, "/openapi.json"),
            (http::Method::GET, "/v1/status"),
            (http::Method::GET, "/v1/captures"),
            (http::Method::POST, "/v1/captures/cap-example/finalizations"),
            (http::Method::GET, "/v1/operations/op-example"),
            (http::Method::POST, "/v1/operations/op-example/retry"),
            (http::Method::POST, "/v1/captures/cap-example/trace:verify"),
            (http::Method::GET, "/v1/events"),
            (http::Method::POST, "/v1/session"),
            (http::Method::GET, "/v1/publication/auth"),
            (http::Method::POST, "/v1/captures/cap-example/publications"),
            (http::Method::GET, "/v1/public-traces/publication-example"),
        ] {
            let state = state();
            let serial = state.serial.clone();
            let response = proxy_inner(
                state,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(response.headers().get("x-llm-notary-bundle").is_none());
            assert_eq!(*serial.lock().await, 0);
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_methods_locally_without_a_bundle() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::PUT)
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(http::header::ALLOW).unwrap(),
            "GET, HEAD, POST"
        );
        assert!(response.headers().get("x-llm-notary-bundle").is_none());
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn rejects_posts_outside_the_fixed_provider_paths_without_a_bundle() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/v1/responses")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("x-llm-notary-bundle").is_none());
        assert_eq!(*serial.lock().await, 0);
    }

    #[tokio::test]
    async fn maps_capture_capacity_to_a_retryable_service_unavailable_response() {
        let response =
            proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError::test_only(
                crate::NotaryAdmissionRejection::CaptureAtCapacity,
                std::time::Duration::from_secs(7),
            )));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(http::header::RETRY_AFTER).unwrap(),
            "7"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({
                "error": {
                    "type": "notary_capacity",
                    "code": "capture_at_capacity",
                    "message": "LLM Notary capture capacity is temporarily full; retry shortly.",
                    "retry_after_seconds": 7,
                }
            })
        );
    }
}
