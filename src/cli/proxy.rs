use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, bail};
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

use crate::{
    chunked_request_body, make_capture, notarized_request, notarized_streaming_request,
    save_capture,
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

    #[arg(long, default_value = "127.0.0.1:7047")]
    notary: SocketAddr,

    /// Where private, independently-verifiable local captures are written.
    #[arg(long, visible_alias = "trace-dir", default_value = "captures")]
    capture_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    provider: Provider,
    notary: SocketAddr,
    capture_dir: PathBuf,
    serial: Arc<Mutex<u64>>,
}

pub async fn run(args: ProxyArgs) -> Result<()> {
    std::fs::create_dir_all(&args.capture_dir)?;
    let state = AppState {
        provider: args.provider,
        notary: args.notary,
        capture_dir: args.capture_dir,
        serial: Arc::new(Mutex::new(0)),
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(address = %args.listen, "LLM Notary proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
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
    if parts.method != http::Method::POST {
        bail!("only POST API requests are supported in the proof of concept");
    }
    let input = body.collect().await?.to_bytes();
    let streaming = wants_stream(&parts.headers, &input);
    let host = state.provider.host();
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

    if streaming {
        let started = Instant::now();
        let upstream = notarized_streaming_request(state.notary, host, outbound).await?;
        tracing::info!(
            elapsed_ms = started.elapsed().as_millis(),
            "Proxy-TLS received upstream response headers"
        );
        let status = upstream.status;
        let headers = upstream.headers.clone();
        let capture_id = next_capture_id(&state).await?;
        let trace_state = state.clone();
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut upstream = upstream;
            let mut received_first_chunk = false;
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if body_sender.send(chunk).await.is_err() {
                    break;
                }
            }
            tracing::info!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; generating proof"
            );
            let proof = upstream.proof;
            drop(body_sender);
            tokio::spawn(async move {
                match proof.await {
                    Ok(Ok(proof)) => match make_capture(
                        &proof,
                        capture_id,
                        trace_state.provider.name().to_owned(),
                    )
                    .and_then(|capture| save_capture(&trace_state.capture_dir, &capture))
                    {
                        Ok(path) => {
                            tracing::info!(capture = %path.display(), provider = trace_state.provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote verified streaming capture")
                        }
                        Err(error) => {
                            tracing::warn!(%error, "could not save streaming capture")
                        }
                    },
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "stream ended without an LLM Notary capture")
                    }
                    Err(error) => {
                        tracing::warn!(%error, "stream capture proof task exited")
                    }
                }
            });
        });

        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = status;
        copy_response_headers(response.headers_mut(), &headers);
        return Ok(response);
    }

    let upstream = notarized_request(state.notary, host, outbound).await?;
    let capture = make_capture(
        &upstream.proof,
        next_capture_id(&state).await?,
        state.provider.name().to_owned(),
    )?;
    let path = save_capture(&state.capture_dir, &capture)?;
    tracing::info!(capture = %path.display(), provider = host, "wrote verified capture");

    let mut response = Response::new(Body::from(upstream.body));
    *response.status_mut() = upstream.status;
    copy_response_headers(response.headers_mut(), &upstream.headers);
    response.headers_mut().insert(
        "x-llm-notary-capture",
        HeaderValue::from_str(&path.display().to_string())?,
    );
    Ok(response)
}

async fn next_capture_id(state: &AppState) -> Result<String> {
    let mut serial = state.serial.lock().await;
    *serial += 1;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the Unix epoch"))?
        .as_millis();
    Ok(format!("cap-{created_at_unix_ms}-{serial:04}"))
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
