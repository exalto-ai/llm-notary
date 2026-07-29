use std::{
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
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use clap::{Args, ValueEnum};
use http_body_util::BodyExt as _;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

use super::notary::{DirectoryRecord, pin, validate_directory};
use crate::{
    DEFAULT_NOTARY_MAX_FRAME_BYTES, DeferredBundle, chunked_request_body,
    deferred_streaming_request, vault::Vault,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Provider {
    Openai,
    Anthropic,
    Deepseek,
}

impl Provider {
    fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Deepseek => "api.deepseek.com",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Deepseek => "deepseek",
        }
    }
}

#[derive(Args, Debug)]
pub struct ProxyArgs {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    #[arg(long, value_enum, default_value_t = Provider::Openai)]
    provider: Provider,

    /// Override the notary address discovered from LLM Notary's public API.
    #[arg(long)]
    notary: Option<SocketAddr>,

    /// Where private local source bundles are written.
    #[arg(long, default_value = "bundles")]
    bundle_dir: PathBuf,

    /// Largest control-protocol frame accepted from the paired notary.
    /// Must match the notary's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,
}

#[derive(Clone)]
struct AppState {
    provider: Provider,
    notary: SocketAddr,
    bundle_dir: PathBuf,
    max_frame_bytes: usize,
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
    std::fs::create_dir_all(&args.bundle_dir)?;
    let notary = match args.notary {
        Some(notary) => notary,
        None => discover_notary().await?,
    };
    let vault = Vault::open_or_init_interactive().context("opening the local bundle vault (use `llm-notary vault init --passphrase` if this machine has no OS vault)")?;
    let state = AppState {
        provider: args.provider,
        notary,
        bundle_dir: args.bundle_dir,
        max_frame_bytes: args.max_frame_bytes,
        vault: Arc::new(vault),
        serial: Arc::new(Mutex::new(0)),
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(address = %args.listen, notary = %notary, "LLM Notary proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

const NOTARY_DIRECTORY_URL: &str = "https://llmnotary.exalto.ai/api/notary";

pub(crate) async fn discover_notary() -> Result<SocketAddr> {
    let endpoint = reqwest::Client::builder()
        .user_agent("LLM-Notary/0.1")
        .build()?
        .get(NOTARY_DIRECTORY_URL)
        .send()
        .await
        .with_context(|| format!("fetching notary endpoint from {NOTARY_DIRECTORY_URL}"))?
        .error_for_status()
        .with_context(|| format!("fetching notary endpoint from {NOTARY_DIRECTORY_URL}"))?
        .json::<DirectoryRecord>()
        .await
        .context("decoding notary directory from LLM Notary API")?;

    validate_directory(&endpoint)?;
    pin(endpoint.clone())?;
    tracing::info!(key_id = %endpoint.key_id, "pinned trusted notary directory key");

    tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port))
        .await
        .with_context(|| format!("resolving notary host {}", endpoint.host))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("notary host {} resolved to no addresses", endpoint.host))
}

#[axum::debug_handler]
async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    match proxy_inner(state, request).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "proxy request failed");
            (
                StatusCode::BAD_GATEWAY,
                [("content-type", "application/json")],
                format!(r#"{{"error":{{"message":"LLM Notary proxy error: {error}"}}}}"#),
            )
                .into_response()
        }
    }
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
    let input = body.collect().await?.to_bytes();
    let streaming = wants_stream(&parts.headers, &input);
    let host = state.provider.host();
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
    for (name, value) in &parts.headers {
        if name == http::header::HOST
            || name == http::header::CONNECTION
            || name == http::header::ACCEPT_ENCODING
            || name == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        outbound = outbound.header(name, value);
    }
    let outbound = outbound
        .header(http::header::HOST, host)
        .header(http::header::ACCEPT_ENCODING, "identity")
        .header(http::header::CONNECTION, "close")
        .body(chunked_request_body(input))?;

    let (capture_id, created_at_unix_ms) = next_capture_metadata(&state).await?;
    let started = Instant::now();
    let upstream = deferred_streaming_request(
        state.notary,
        host,
        capture_id,
        state.provider.name().to_owned(),
        created_at_unix_ms,
        outbound,
        state.max_frame_bytes,
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
        copy_response_headers(response.headers_mut(), &headers);
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
    copy_response_headers(response.headers_mut(), &headers);
    response.headers_mut().insert(
        "x-llm-notary-bundle",
        HeaderValue::from_str(&path.display().to_string())?,
    );
    Ok(response)
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

fn copy_response_headers(target: &mut HeaderMap, source: &HeaderMap) {
    for (name, value) in source {
        if name == http::header::CONNECTION || name == http::header::TRANSFER_ENCODING {
            continue;
        }
        target.append(name, value.clone());
    }
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
}
