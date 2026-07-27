use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
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
use bytes::Bytes;
use certified::{
    chunked_request_body, make_full_trace_bundle, notarized_request, notarized_streaming_request,
    save_bundle,
};
use clap::{Parser, ValueEnum};
use http_body_util::BodyExt as _;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Provider {
    Openai,
    Anthropic,
}

impl Provider {
    fn host(self) -> &'static str {
        match self {
            Self::Openai => "api.openai.com",
            Self::Anthropic => "api.anthropic.com",
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Local Certified API proxy (TLSNotary proof of concept)")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    #[arg(long, value_enum, default_value_t = Provider::Openai)]
    provider: Provider,

    #[arg(long, default_value = "127.0.0.1:7047")]
    notary: SocketAddr,

    /// Where portable, independently-verifiable proof bundles are written.
    #[arg(long, default_value = "traces")]
    trace_dir: PathBuf,
}

#[derive(Clone)]
struct AppState {
    provider: Provider,
    notary: SocketAddr,
    trace_dir: PathBuf,
    serial: Arc<Mutex<u64>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.trace_dir)?;
    let state = AppState {
        provider: args.provider,
        notary: args.notary,
        trace_dir: args.trace_dir,
        serial: Arc::new(Mutex::new(0)),
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(address = %args.listen, "Certified proxy listening");
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
                format!(r#"{{"error":{{"message":"Certified proxy error: {error}"}}}}"#),
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
        let path = next_trace_path(&state).await;
        let proof_path = path.clone();
        let trace_state = state.clone();
        let (body_sender, body_receiver) = tokio::sync::mpsc::channel(32);
        let notary = state.notary;
        let host = host.to_owned();
        tokio::spawn(async move {
            let started = Instant::now();
            // Codex expects streaming bytes promptly. SSE comments are
            // protocol no-ops, but keep the local client alive while Proxy-TLS
            // completes its handshake and the provider starts sampling.
            let _ = body_sender
                .send(Ok(Bytes::from_static(b": certified-pending\n\n")))
                .await;
            let mut opening = Box::pin(notarized_streaming_request(notary, &host, outbound));
            let mut keepalive = tokio::time::interval(Duration::from_secs(3));
            keepalive.tick().await;
            let mut upstream = loop {
                tokio::select! {
                    result = &mut opening => break match result {
                        Ok(upstream) => {
                            tracing::warn!(elapsed_ms = started.elapsed().as_millis(), "Proxy-TLS received upstream response headers");
                            upstream
                        }
                        Err(error) => {
                            tracing::warn!(%error, elapsed_ms = started.elapsed().as_millis(), "Proxy-TLS failed before upstream response headers");
                            let _ = body_sender.send(Err(io::Error::other(error.to_string()))).await;
                            return;
                        }
                    },
                    _ = keepalive.tick() => {
                        let _ = body_sender.send(Ok(Bytes::from_static(b": certified-pending\n\n"))).await;
                    }
                }
            };

            let mut received_first_chunk = false;
            while let Some(chunk) = upstream.body.recv().await {
                if !received_first_chunk {
                    received_first_chunk = true;
                    tracing::warn!(
                        elapsed_ms = started.elapsed().as_millis(),
                        "Proxy-TLS received first upstream response chunk"
                    );
                }
                if body_sender.send(chunk).await.is_err() {
                    break;
                }
            }

            tracing::warn!(
                elapsed_ms = started.elapsed().as_millis(),
                "Proxy-TLS upstream stream ended; generating proof"
            );

            // Do not make the client wait for selective disclosure and
            // attestation creation. The trace path remains pending until this
            // task writes the certificate, but the SSE response has already
            // reached its terminal event and can close immediately.
            let proof = upstream.proof;
            drop(body_sender);
            tokio::spawn(async move {
                match proof.await {
                    Ok(Ok(proof)) => match make_full_trace_bundle(&proof)
                        .and_then(|bundle| save_bundle(&proof_path, &bundle))
                    {
                        Ok(()) => {
                            tracing::warn!(trace = %proof_path.display(), provider = trace_state.provider.host(), elapsed_ms = started.elapsed().as_millis(), "wrote verified streaming trace bundle")
                        }
                        Err(error) => {
                            tracing::warn!(%error, trace = %proof_path.display(), "could not save streaming trace bundle")
                        }
                    },
                    Ok(Err(error)) => {
                        tracing::warn!(%error, trace = %proof_path.display(), "stream ended without a certified trace")
                    }
                    Err(error) => {
                        tracing::warn!(%error, trace = %proof_path.display(), "stream proof task exited")
                    }
                }
            });
        });

        // In the successful Responses streaming path, the provider returns
        // HTTP 200 SSE. Send local headers immediately so clients can receive
        // keepalives before the notarized upstream headers are available.
        let mut response = Response::new(Body::from_stream(ReceiverStream::new(body_receiver)));
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream; charset=utf-8"),
        );
        response.headers_mut().insert(
            "x-certified-trace",
            HeaderValue::from_str(&path.display().to_string())?,
        );
        response.headers_mut().insert(
            "x-certified-trace-state",
            HeaderValue::from_static("pending"),
        );
        return Ok(response);
    }

    let upstream = notarized_request(state.notary, host, outbound).await?;
    let bundle = make_full_trace_bundle(&upstream.proof)?;
    let path = next_trace_path(&state).await;
    save_bundle(&path, &bundle)?;
    tracing::info!(trace = %path.display(), provider = host, "wrote verified trace bundle");

    let mut response = Response::new(Body::from(upstream.body));
    *response.status_mut() = upstream.status;
    copy_response_headers(response.headers_mut(), &upstream.headers);
    response.headers_mut().insert(
        "x-certified-trace",
        HeaderValue::from_str(&path.display().to_string())?,
    );
    Ok(response)
}

async fn next_trace_path(state: &AppState) -> PathBuf {
    let mut serial = state.serial.lock().await;
    *serial += 1;
    state.trace_dir.join(format!("trace-{:08}.json", *serial))
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
