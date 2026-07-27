//! Opt-in split-process resource benchmark for the Proxy-TLS proof path.
//!
//! Run this in a client container on the same Docker network as a
//! `certified-notary` container. Give this client the network alias
//! `test-server.io`; the client hosts the TLS echo fixture on port 443 while
//! the separate notary container connects to it.
//!
//! Example:
//! `TLSN_PROFILE_TOKENS=1050000 TLSN_ZK_EPHEMERAL_CHUNK_BYTES=1048576 \
//!   TLSN_NOTARY_ADDR=notary:7047 cargo test --release --test proxy_tls_split_profile \
//!   -- --ignored --nocapture`

use std::{env, time::Instant};

use anyhow::{Context, Result};
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use tiktoken_rs::o200k_base;
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    transcript::{Direction, TranscriptCommitConfig},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::HttpTranscript;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

const DEFAULT_PROFILE_TOKENS: usize = 1_050_000;

fn cgroup_memory(file: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/fs/cgroup/{file}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn profile_tokens() -> Result<usize> {
    env::var("TLSN_PROFILE_TOKENS")
        .unwrap_or_else(|_| DEFAULT_PROFILE_TOKENS.to_string())
        .parse()
        .context("TLSN_PROFILE_TOKENS must be an unsigned token count")
}

fn chunk_bytes() -> Result<usize> {
    let value = env::var("TLSN_ZK_EPHEMERAL_CHUNK_BYTES")
        .context("TLSN_ZK_EPHEMERAL_CHUNK_BYTES is required")?
        .parse()
        .context("TLSN_ZK_EPHEMERAL_CHUNK_BYTES must be an unsigned byte count")?;
    anyhow::ensure!(value > 0, "TLSN_ZK_EPHEMERAL_CHUNK_BYTES must be non-zero");
    Ok(value)
}

fn body(tokens: usize) -> Result<Bytes> {
    let body = " a".repeat(tokens);
    let tokenizer = o200k_base().context("load the o200k_base tokenizer")?;
    let actual = tokenizer.encode_with_special_tokens(&body).len();
    anyhow::ensure!(actual == tokens, "expected {tokens} tokens, got {actual}");
    Ok(Bytes::from(body))
}

fn fixture_roots() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

fn commit_chunked_private_http(
    transcript: &HttpTranscript,
    source: &tlsn::transcript::Transcript,
    chunk_bytes: usize,
) -> Result<TranscriptCommitConfig> {
    anyhow::ensure!(
        transcript.requests.len() == 1 && transcript.responses.len() == 1,
        "expected exactly one HTTP request and response"
    );
    let mut builder = TranscriptCommitConfig::builder(source);
    let request = &transcript.requests[0];
    builder.commit(request.without_data(), Direction::Sent)?;
    builder.commit(&request.request.target, Direction::Sent)?;
    for header in &request.headers {
        if header.name.as_str().eq_ignore_ascii_case("authorization")
            || header.name.as_str().eq_ignore_ascii_case("x-api-key")
        {
            builder.commit(header.without_value(), Direction::Sent)?;
        } else {
            builder.commit(header, Direction::Sent)?;
        }
    }
    if let Some(body) = &request.body {
        commit_body_chunks(
            &mut builder,
            body.indices().iter(),
            Direction::Sent,
            chunk_bytes,
        )?;
    }

    let response = &transcript.responses[0];
    builder.commit(response.without_data(), Direction::Received)?;
    for header in &response.headers {
        builder.commit(header, Direction::Received)?;
    }
    if let Some(body) = &response.body {
        commit_body_chunks(
            &mut builder,
            body.indices().iter(),
            Direction::Received,
            chunk_bytes,
        )?;
    }
    Ok(builder.build()?)
}

fn commit_body_chunks(
    builder: &mut tlsn::transcript::TranscriptCommitConfigBuilder,
    ranges: impl Iterator<Item = std::ops::Range<usize>>,
    direction: Direction,
    chunk_bytes: usize,
) -> Result<()> {
    for range in ranges {
        for start in (range.start..range.end).step_by(chunk_bytes) {
            builder.commit(start..(start + chunk_bytes).min(range.end), direction)?;
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "resource benchmark; run in separate client and notary containers"]
async fn profiles_notary_and_client_in_separate_processes() -> Result<()> {
    let tokens = profile_tokens()?;
    let chunk_bytes = chunk_bytes()?;
    let body = body(tokens)?;
    let notary_addr = env::var("TLSN_NOTARY_ADDR").unwrap_or_else(|_| "notary:7047".to_owned());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:443")
        .await
        .context("bind fixture to port 443")?;
    let fixture_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        bind_test_server_hyper(stream.compat()).await?;
        Result::<()>::Ok(())
    });

    let socket = tokio::net::TcpStream::connect(&notary_addr)
        .await
        .with_context(|| format!("connect to notary at {notary_addr}"))?;
    let mut session = Session::new(socket.compat());
    let prover = session.new_prover(ProverConfig::builder().build()?)?;
    let (driver, _handle) = session.split();
    tokio::spawn(driver);

    let committed = prover
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN)?)
                .build()?,
        )
        .await?;
    let (tls_connection, prover) = committed.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(fixture_roots())
            .build()?,
    )?;
    let (mut sender, connection) =
        http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls_connection.compat())).await?;
    tokio::spawn(connection);
    let prover_task = tokio::spawn(prover.into_future());
    let response = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("/echo")
                .header("authorization", "Bearer profile-secret")
                .body(Full::new(body.clone()))?,
        )
        .await?;
    assert_eq!(response.into_body().collect().await?.to_bytes(), body);
    drop(sender);

    let mut prover = prover_task.await??;
    let transcript = HttpTranscript::parse(prover.transcript())?;
    let commitments = commit_chunked_private_http(&transcript, prover.transcript(), chunk_bytes)?;
    let mut prove = ProveConfig::builder(prover.transcript());
    prove.transcript_commit(commitments);
    prove.chunked_private_commitments(chunk_bytes)?;
    let proof_started = Instant::now();
    let output = prover.prove(&prove.build()?).await?;
    let proof_ms = proof_started.elapsed().as_millis();
    prover.close().await?;
    fixture_task.await??;

    eprintln!(
        "split_proxy_tls_client tokens={tokens} bytes={} chunk_bytes={chunk_bytes} commitments={} proof_output_bytes={} proof_ms={proof_ms} cgroup_memory_current_bytes={:?} cgroup_memory_peak_bytes={:?}",
        body.len(),
        output.transcript_commitments.len(),
        bincode::serialized_size(&output)?,
        cgroup_memory("memory.current"),
        cgroup_memory("memory.peak"),
    );
    Ok(())
}
