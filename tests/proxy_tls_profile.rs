//! Deterministic, opt-in resource benchmark for the exact Proxy-TLS proof path.
//!
//! Run with, for example:
//! `TLSN_PROFILE_BYTES=65536 cargo test --release --test proxy_tls_profile -- --ignored --nocapture`
//!
//! For an exact OpenAI-scale request and response, use
//! `TLSN_PROFILE_TOKENS=1050000`. This creates a token corpus that is counted
//! with OpenAI's `o200k_base` encoding before it is sent and echoed.
//!
//! To exercise the bounded private-proof path, add
//! `TLSN_PROFILE_CHUNKED_BODY_COMMIT=1` and set
//! `TLSN_ZK_EPHEMERAL_CHUNK_BYTES` for this benchmark. The prover and notary
//! use fixed protocol scheduling; no peer-matched environment flags are needed.

use std::{env, time::Instant};

use anyhow::{Context, Result};
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use tiktoken_rs::o200k_base;
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
use tlsn::hash::HashAlgId;
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    transcript::{
        Direction, TranscriptCommitConfig, TranscriptCommitmentKind, TranscriptProofBuilder,
    },
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn cgroup_memory(file: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/fs/cgroup/{file}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn profile_bytes() -> Result<usize> {
    env::var("TLSN_PROFILE_BYTES")
        .unwrap_or_else(|_| "32768".to_owned())
        .parse()
        .context("TLSN_PROFILE_BYTES must be an unsigned byte count")
}

fn profile_tokens() -> Result<Option<usize>> {
    env::var("TLSN_PROFILE_TOKENS")
        .ok()
        .map(|value| {
            value
                .parse()
                .context("TLSN_PROFILE_TOKENS must be an unsigned token count")
        })
        .transpose()
}

fn profile_body(bytes: usize, tokens: Option<usize>) -> Result<(Bytes, Option<usize>)> {
    let Some(tokens) = tokens else {
        return Ok((Bytes::from(vec![0x42; bytes]), None));
    };

    // A leading-space ASCII word is a standalone token in o200k_base. Count
    // rather than assume that property so this remains an exact benchmark if
    // the tokenizer implementation changes.
    let body = " a".repeat(tokens);
    let tokenizer = o200k_base().context("load the o200k_base tokenizer")?;
    let actual = tokenizer.encode_with_special_tokens(&body).len();
    anyhow::ensure!(
        actual == tokens,
        "the generated corpus encoded to {actual} o200k_base tokens, expected {tokens}"
    );

    Ok((Bytes::from(body), Some(actual)))
}

fn fixture_roots() -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    }
}

#[derive(Clone, Copy)]
struct ProofProfile {
    bytes: usize,
    tokens: Option<usize>,
    reveal_all: bool,
    commit_http: bool,
    minimal_http_commit: bool,
    chunked_body_commit: bool,
    chunked_body_bytes: usize,
    sha256_commitments: bool,
    verifier_max_chunk_bytes: usize,
    verifier_max_total_chunk_bytes: usize,
    verifier_max_commitments: usize,
    tamper_child_key: bool,
    expect_policy_rejection: bool,
}

async fn run_proxy_tls_http_commitment_and_proof(profile: ProofProfile) -> Result<()> {
    let (body, profile_tokens) = profile_body(profile.bytes, profile.tokens)?;
    let bytes = body.len();
    let started = Instant::now();

    // This is the same in-memory Proxy-TLS topology as TLSN's own proxy test,
    // but with the application's HTTP transcript commitment and proof path.
    let (prover_socket, verifier_socket) = tokio::io::duplex(16 << 20);
    let mut prover_session = Session::new(prover_socket.compat());
    let mut verifier_session = Session::new(verifier_socket.compat());
    let prover = prover_session.new_prover(ProverConfig::builder().build()?)?;
    let verifier = verifier_session.new_verifier(
        VerifierConfig::builder()
            .root_store(fixture_roots())
            .max_chunked_private_bytes(profile.verifier_max_chunk_bytes)
            .max_total_chunked_private_bytes(profile.verifier_max_total_chunk_bytes)
            .max_chunked_private_commitments(profile.verifier_max_commitments)
            .build()?,
    )?;
    let (prover_driver, _prover_handle) = prover_session.split();
    let (verifier_driver, _verifier_handle) = verifier_session.split();
    tokio::spawn(prover_driver);
    tokio::spawn(verifier_driver);

    let (notary_upstream, fixture_socket) = tokio::io::duplex(16 << 20);
    let fixture_task = tokio::spawn(bind_test_server_hyper(fixture_socket.compat()));
    let verifier_task = tokio::spawn(async move {
        let verifier = verifier.commit().await?;
        let VerifierCommitStart::Proxy(verifier) = verifier else {
            unreachable!("profile benchmark always uses Proxy-TLS");
        };
        let verifier = verifier
            .accept()
            .await?
            .run(notary_upstream.compat())
            .await?;
        let (output, verifier) = verifier.verify().await?.accept().await?;
        assert!(
            output.transcript.is_none(),
            "the notary must not receive a private transcript"
        );
        verifier.close().await?;
        Result::<()>::Ok(())
    });

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
    let response_body = response.into_body().collect().await?.to_bytes();
    assert_eq!(
        response_body, body,
        "echo response must preserve the token corpus"
    );
    drop(sender);

    let mut prover = prover_task.await??;
    if profile.tamper_child_key {
        prover.test_only_tamper_proxy_child_key()?;
    }
    let transcript_commit = {
        let transcript = HttpTranscript::parse(prover.transcript())?;
        assert_eq!(transcript.requests.len(), 1);
        assert_eq!(transcript.responses.len(), 1);
        let mut builder = TranscriptCommitConfig::builder(prover.transcript());
        if profile.sha256_commitments {
            builder.default_kind(TranscriptCommitmentKind::Hash {
                alg: HashAlgId::SHA256,
            });
        }
        if profile.commit_http {
            if profile.chunked_body_commit {
                assert!(
                    profile.chunked_body_bytes > 0,
                    "chunked body commitments require TLSN_ZK_EPHEMERAL_CHUNK_BYTES"
                );
                let request = &transcript.requests[0];
                builder.commit(request.without_data(), Direction::Sent)?;
                builder.commit(&request.request.target, Direction::Sent)?;
                for value in &request.headers {
                    if value.name.as_str().eq_ignore_ascii_case("authorization")
                        || value.name.as_str().eq_ignore_ascii_case("x-api-key")
                    {
                        builder.commit(value.without_value(), Direction::Sent)?;
                    } else {
                        builder.commit(value, Direction::Sent)?;
                    }
                }
                let response = &transcript.responses[0];
                builder.commit(response.without_data(), Direction::Received)?;
                for value in &response.headers {
                    builder.commit(value, Direction::Received)?;
                }
                for (direction, body) in [
                    (Direction::Sent, request.body.as_ref()),
                    (Direction::Received, response.body.as_ref()),
                ] {
                    let body = body.expect("echo fixture has request and response bodies");
                    for range in body.indices().iter() {
                        for start in (range.start..range.end).step_by(profile.chunked_body_bytes) {
                            let end = (start + profile.chunked_body_bytes).min(range.end);
                            builder.commit(start..end, direction)?;
                        }
                    }
                }
            } else if profile.minimal_http_commit {
                builder.commit(&transcript.requests[0], Direction::Sent)?;
                builder.commit(&transcript.responses[0], Direction::Received)?;
            } else {
                DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
            }
        }
        builder.build()?
    };
    let expected_commitment_count = transcript_commit.to_request().iter_hash().count();
    let mut prove_config = ProveConfig::builder(prover.transcript());
    if profile.commit_http {
        prove_config.transcript_commit(transcript_commit);
    }
    if profile.chunked_body_commit {
        prove_config.chunked_private_commitments(profile.chunked_body_bytes)?;
    }
    if profile.reveal_all {
        prove_config.reveal_sent_all()?;
        prove_config.reveal_recv_all()?;
    }
    let prove_started = Instant::now();
    let prove_result = prover.prove(&prove_config.build()?).await;
    if profile.tamper_child_key {
        let error = prove_result.expect_err("a child key different from the root key must fail");
        assert!(
            error
                .to_string()
                .contains("ephemeral child key binding mismatch"),
            "unexpected prover error: {error:#}"
        );
        let error = verifier_task
            .await?
            .expect_err("verifier must reject the mismatched child key");
        assert!(
            error
                .to_string()
                .contains("ephemeral child key binding mismatch"),
            "unexpected verifier error: {error:#}"
        );
        fixture_task.await??;
        return Ok(());
    }
    if profile.expect_policy_rejection {
        let error = prove_result.expect_err("notary policy must reject an oversized private chunk");
        assert!(
            error.to_string().contains("proving rejected by verifier"),
            "unexpected prover error: {error:#}"
        );
        let error = verifier_task
            .await?
            .expect_err("verifier must report its oversized-chunk rejection");
        assert!(
            error.to_string().contains("verifier"),
            "unexpected verifier error: {error:#}"
        );
        fixture_task.await??;
        return Ok(());
    }
    let output = prove_result?;
    let proof_output_bytes = bincode::serialized_size(&output)?;
    if profile.commit_http {
        assert_eq!(
            output.transcript_commitments.len(),
            expected_commitment_count,
            "the proof must contain every configured commitment"
        );
    }
    let prover_transcript = prover.transcript().clone();
    let transcript_sent = prover_transcript.sent().len();
    let transcript_received = prover_transcript.received().len();
    if profile.chunked_body_commit {
        // Exercise the application's exact selective-disclosure shape. In
        // particular, the entire response is assembled from metadata and body
        // chunks while the Authorization value remains undisclosed.
        let http = HttpTranscript::parse(&prover_transcript)?;
        let request = &http.requests[0];
        let mut builder =
            TranscriptProofBuilder::new(&prover_transcript, &output.transcript_secrets);
        builder.reveal_sent(request.without_data())?;
        builder.reveal_sent(&request.request.target)?;
        for value in &request.headers {
            if value.name.as_str().eq_ignore_ascii_case("authorization")
                || value.name.as_str().eq_ignore_ascii_case("x-api-key")
            {
                builder.reveal_sent(value.without_value())?;
            } else {
                builder.reveal_sent(value)?;
            }
        }
        if let Some(body) = &request.body {
            builder.reveal_sent(body)?;
        }
        builder.reveal_recv(&http.responses[0])?;
        let partial = builder.build()?.verify_with_provider(
            &tlsn::hash::HashProvider::default(),
            &prover_transcript.length(),
            &output.transcript_commitments,
        )?;
        assert_eq!(
            partial.received_unsafe(),
            prover_transcript.received(),
            "the chunked layout must commit and disclose every response byte"
        );
        assert!(
            !partial
                .sent_unsafe()
                .windows(b"Bearer profile-secret".len())
                .any(|window| window == b"Bearer profile-secret"),
            "selective proof must not disclose the Authorization value"
        );
    }
    prover.close().await?;
    verifier_task.await??;
    fixture_task.await??;
    let cgroup_memory_current_bytes = cgroup_memory("memory.current");
    let cgroup_memory_peak_bytes = cgroup_memory("memory.peak");

    eprintln!(
        "proxy_tls_profile bytes={bytes} tokens={profile_tokens:?} reveal_all={} commit_http={} minimal_http_commit={} chunked_body_commit={} sha256_commitments={} transcript_sent={} transcript_received={} commitments={} proof_output_bytes={proof_output_bytes} cgroup_memory_current_bytes={cgroup_memory_current_bytes:?} cgroup_memory_peak_bytes={cgroup_memory_peak_bytes:?} elapsed_ms={} prove_ms={}",
        profile.reveal_all,
        profile.commit_http,
        profile.minimal_http_commit,
        profile.chunked_body_commit,
        profile.sha256_commitments,
        transcript_sent,
        transcript_received,
        output.transcript_commitments.len(),
        started.elapsed().as_millis(),
        prove_started.elapsed().as_millis(),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_chunk_proof_hides_the_transcript_and_redacts_authorization() -> Result<()> {
    run_proxy_tls_http_commitment_and_proof(ProofProfile {
        bytes: 4096,
        tokens: None,
        reveal_all: false,
        commit_http: true,
        minimal_http_commit: false,
        chunked_body_commit: true,
        chunked_body_bytes: 1024,
        sha256_commitments: false,
        verifier_max_chunk_bytes: 1024 * 1024,
        verifier_max_total_chunk_bytes: 16 * 1024 * 1024,
        verifier_max_commitments: 64,
        tamper_child_key: false,
        expect_policy_rejection: false,
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_private_chunk_key_is_rejected_by_both_parties() -> Result<()> {
    run_proxy_tls_http_commitment_and_proof(ProofProfile {
        bytes: 1024,
        tokens: None,
        reveal_all: false,
        commit_http: true,
        minimal_http_commit: false,
        chunked_body_commit: true,
        chunked_body_bytes: 1024,
        sha256_commitments: false,
        verifier_max_chunk_bytes: 1024 * 1024,
        verifier_max_total_chunk_bytes: 16 * 1024 * 1024,
        verifier_max_commitments: 64,
        tamper_child_key: true,
        expect_policy_rejection: false,
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_rejects_a_private_chunk_over_its_policy_limit() -> Result<()> {
    run_proxy_tls_http_commitment_and_proof(ProofProfile {
        bytes: 1024,
        tokens: None,
        reveal_all: false,
        commit_http: true,
        minimal_http_commit: false,
        chunked_body_commit: true,
        chunked_body_bytes: 1024,
        sha256_commitments: false,
        verifier_max_chunk_bytes: 512,
        verifier_max_total_chunk_bytes: 16 * 1024 * 1024,
        verifier_max_commitments: 64,
        tamper_child_key: false,
        expect_policy_rejection: true,
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifier_rejects_private_chunks_over_its_total_policy_limit() -> Result<()> {
    run_proxy_tls_http_commitment_and_proof(ProofProfile {
        bytes: 1024,
        tokens: None,
        reveal_all: false,
        commit_http: true,
        minimal_http_commit: false,
        chunked_body_commit: true,
        chunked_body_bytes: 1024,
        sha256_commitments: false,
        verifier_max_chunk_bytes: 1024,
        verifier_max_total_chunk_bytes: 1024,
        verifier_max_commitments: 64,
        tamper_child_key: false,
        expect_policy_rejection: true,
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "resource benchmark; invoke explicitly with TLSN_PROFILE_BYTES"]
async fn profiles_proxy_tls_http_commitment_and_proof() -> Result<()> {
    let _profiler = env::var("TLSN_DHAT")
        .ok()
        .filter(|value| value == "1")
        .map(|_| dhat::Profiler::builder().build());
    run_proxy_tls_http_commitment_and_proof(ProofProfile {
        bytes: profile_bytes()?,
        tokens: profile_tokens()?,
        reveal_all: env::var("TLSN_PROFILE_REVEAL_ALL").as_deref() == Ok("1"),
        commit_http: env::var("TLSN_PROFILE_NO_HTTP_COMMIT").as_deref() != Ok("1"),
        minimal_http_commit: env::var("TLSN_PROFILE_MINIMAL_HTTP_COMMIT").as_deref() == Ok("1"),
        chunked_body_commit: env::var("TLSN_PROFILE_CHUNKED_BODY_COMMIT").as_deref() == Ok("1"),
        chunked_body_bytes: env::var("TLSN_ZK_EPHEMERAL_CHUNK_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        sha256_commitments: env::var("TLSN_PROFILE_SHA256_COMMITMENTS").as_deref() == Ok("1"),
        verifier_max_chunk_bytes: 1024 * 1024,
        verifier_max_total_chunk_bytes: 16 * 1024 * 1024,
        verifier_max_commitments: 64,
        tamper_child_key: false,
        expect_policy_rejection: false,
    })
    .await
}
