use std::{
    collections::HashSet,
    net::SocketAddr,
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
use clap::{Args, ValueEnum};
use http_body_util::BodyExt as _;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

use super::{
    DEFAULT_PUBLIC_ORIGIN,
    notary::{parse_directory, pin},
};
use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES, DeferredBundle,
    DeferredCaptureConfig, attestable_request_header_bytes, chunked_request_body,
    deferred_streaming_request_to, notary_admission_error,
    notary_directory::{NotaryDirectory, NotaryDirectoryRecord, NotaryEndpoint},
    vault::Vault,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Provider {
    Openai,
    Anthropic,
    Deepseek,
    Openrouter,
}

impl Provider {
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
}

#[derive(Args, Debug)]
pub struct ProxyArgs {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    #[arg(long, value_enum, default_value_t = Provider::Openai)]
    provider: Provider,

    /// Override the notary endpoint discovered from LLM Notary's public API.
    /// Use tcp:// or tls://; a bare host:port remains raw TCP.
    #[arg(long)]
    notary: Option<NotaryEndpoint>,

    /// Where private local source bundles are written.
    #[arg(long, default_value = "bundles")]
    bundle_dir: PathBuf,

    /// Largest control-protocol frame accepted from the paired notary.
    /// Must match the notary's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,

    /// Maximum combined HTTP request and response bytes that can be privately
    /// committed and finalized by the notary.
    #[arg(long, default_value_t = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)]
    max_attestable_http_bytes: usize,
}

#[derive(Clone)]
struct AppState {
    provider: Provider,
    notary: NotaryEndpoint,
    bundle_dir: PathBuf,
    max_frame_bytes: usize,
    max_attestable_http_bytes: usize,
    vault: Arc<Vault>,
    serial: Arc<Mutex<u64>>,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    if args.max_frame_bytes == 0 || args.max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    if args.max_attestable_http_bytes == 0 {
        bail!("maximum attestable HTTP bytes must be non-zero");
    }
    std::fs::create_dir_all(&args.bundle_dir)?;
    let notary = match args.notary {
        Some(notary) => notary,
        None => discover_notary().await?,
    };
    let vault = Vault::open_or_init_interactive().context("opening the local bundle vault (use `llm-notary vault init --passphrase` if this machine has no OS vault)")?;
    let state = AppState {
        provider: args.provider,
        notary: notary.clone(),
        bundle_dir: args.bundle_dir,
        max_frame_bytes: args.max_frame_bytes,
        max_attestable_http_bytes: args.max_attestable_http_bytes,
        vault: Arc::new(vault),
        serial: Arc::new(Mutex::new(0)),
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(address = %args.listen, notary = %notary, "LLM Notary proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
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
    refresh_notary_directory_from(DEFAULT_PUBLIC_ORIGIN).await
}

pub(crate) async fn refresh_notary_directory_from(api_origin: &str) -> Result<NotaryDirectory> {
    let directory_url = notary_directory_url(api_origin)?;
    let bytes = reqwest::Client::builder()
        .user_agent("LLM-Notary/0.1")
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
    pin(directory.clone())?;
    tracing::info!(
        key_id = %directory.active_key_id,
        key_count = directory.notaries.len(),
        "pinned trusted notary directory"
    );
    Ok(directory)
}

fn notary_directory_url(api_origin: &str) -> Result<url::Url> {
    let origin = url::Url::parse(api_origin).context("invalid LLM Notary API origin")?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("LLM Notary API origin must be HTTP(S) without a query or fragment");
    }
    origin
        .join("/api/notary")
        .context("building notary directory URL")
}

pub(crate) async fn resolve_notary(record: &NotaryDirectoryRecord) -> Result<NotaryEndpoint> {
    record.endpoint()
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    match proxy_inner(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "proxy request failed");
            proxy_error_response(&error)
        }
    }
}

fn proxy_error_response(error: &anyhow::Error) -> Response {
    let Some(admission) = notary_admission_error(error) else {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "application/json")],
            format!(r#"{{"error":{{"message":"LLM Notary proxy error: {error}"}}}}"#),
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

async fn proxy_inner(state: AppState, request: Request) -> Result<Response> {
    let (parts, body) = request.into_parts();
    if parts.method == http::Method::GET || parts.method == http::Method::HEAD {
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
    let host = state.provider.host();
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
        attestable_request_header_bytes(&parts.method, &parts.uri, &outbound_headers)?;
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
    tracing::info!(
        provider = host,
        request_body_bytes = input.len(),
        streaming,
        "received provider request for notarization"
    );
    let mut outbound = http::Request::builder().method(parts.method).uri(
        parts
            .uri
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/"),
    );
    for (name, value) in &outbound_headers {
        outbound = outbound.header(name, value);
    }
    let request_body_bytes = input.len();
    let outbound = outbound.body(chunked_request_body(input))?;

    let (capture_id, created_at_unix_ms) = next_capture_metadata(&state).await?;
    let started = Instant::now();
    let upstream = deferred_streaming_request_to(
        &state.notary,
        host,
        DeferredCaptureConfig {
            capture_id,
            provider_name: state.provider.name().to_owned(),
            created_at_unix_ms,
            request_body_bytes,
            max_attestable_http_bytes: state.max_attestable_http_bytes,
            max_frame_bytes: state.max_frame_bytes,
        },
        outbound,
    )
    .await?;

    if streaming {
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let trace_state = state.clone();
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            let mut client_connected = true;
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
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
                            tracing::info!(bundle = %path.display(), provider = trace_state.provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote deferred streaming bundle")
                        }
                        Err(error) => {
                            tracing::warn!(%error, "could not save deferred streaming bundle")
                        }
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "stream ended without an LLM Notary deferred bundle")
                }
                Err(error) => {
                    tracing::warn!(%error, "stream deferred capture task exited")
                }
            }
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_end_to_end_headers(response.headers_mut(), &headers);
        return Ok(response);
    }

    let status = upstream.status;
    let headers = upstream.headers.clone();
    let mut upstream = upstream;
    let mut body = Vec::new();
    while let Some(chunk) = upstream.body.recv().await {
        body.extend_from_slice(&chunk?);
    }
    let bundle = upstream
        .bundle
        .await
        .context("deferred bundle task exited")??;
    let path = save_bundle(&state.bundle_dir, &bundle, &state.vault)?;
    tracing::info!(bundle = %path.display(), provider = host, "wrote deferred bundle");

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    copy_end_to_end_headers(response.headers_mut(), &headers);
    response.headers_mut().insert(
        "x-llm-notary-bundle",
        HeaderValue::from_str(&path.display().to_string())?,
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
        format!("cap-{created_at_unix_ms}-{serial:04}"),
        created_at_unix_ms,
    ))
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
        AppState {
            provider: Provider::Openai,
            notary: "127.0.0.1:7047".parse().unwrap(),
            bundle_dir: PathBuf::from("bundles"),
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            vault: Arc::new(Vault::test_only()),
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
            notary_directory_url("https://self-hosted.example/base")
                .unwrap()
                .as_str(),
            "https://self-hosted.example/api/notary"
        );
        assert!(notary_directory_url("file:///tmp/notary").is_err());
    }

    #[tokio::test]
    async fn answers_get_locally_without_creating_an_upstream_proof_task() {
        let state = state();
        let serial = state.serial.clone();
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/v1/models")
            .body(Body::empty())
            .unwrap();

        let response = proxy_inner(state, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("x-llm-notary-bundle").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"service": "llm-notary-proxy", "status": "ok"})
        );
        assert_eq!(*serial.lock().await, 0);
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
    async fn maps_capture_capacity_to_a_retryable_service_unavailable_response() {
        let response = proxy_error_response(&anyhow::Error::new(crate::NotaryAdmissionError {
            rejection: crate::NotaryAdmissionRejection::CaptureAtCapacity,
            retry_after: std::time::Duration::from_secs(7),
        }));
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
