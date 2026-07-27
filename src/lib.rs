//! Shared TLSNotary plumbing for the LLM Notary proof of concept.
//!
//! The boundary here is deliberate: the local proxy owns request plaintext and
//! the API key, while the remote notary relays authenticated TLS traffic and
//! signs an attestation for the committed transcript.

use std::{future::IntoFuture, io, net::SocketAddr, path::Path, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body::Frame;
use http_body_util::{BodyExt as _, StreamBody, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming, header};
use hyper_util::rt::TokioIo;
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{
        CertBinding, ConnectionInfo, DnsName, HandshakeData, ServerName, TranscriptLength,
    },
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

pub mod cli;

const MAX_FRAME_LEN: usize = 32 << 20;
const REQUEST_WRITE_CHUNK: usize = 8 << 10;
const TRACE_FORMAT: &str = "llm-notary.tlsn.v1";
const LEGACY_TRACE_FORMAT: &str = "certified.tlsn.v1";

/// A request body split into bounded frames, avoiding one unbounded local write
/// for a large agent request.
pub type HttpRequestBody = BoxBody<Bytes, std::convert::Infallible>;

pub fn chunked_request_body(bytes: Bytes) -> HttpRequestBody {
    let frames = bytes
        .chunks(REQUEST_WRITE_CHUNK)
        .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
        .collect::<Vec<Result<_, std::convert::Infallible>>>();
    StreamBody::new(futures::stream::iter(frames)).boxed()
}

/// The portable evidence retained by the trace author. `presentation` is what
/// a buyer/verifier receives; `attestation` and `secrets` are retained locally
/// until a presentation is made.
#[derive(Debug, Serialize, Deserialize)]
pub struct LocalProof {
    pub server_name: String,
    pub attestation: Vec<u8>,
    pub secrets: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceBundle {
    pub format: String,
    pub server_name: String,
    /// Hashes of exactly the authenticated, selectively disclosed transcript
    /// bytes. They intentionally include redacted authorization values.
    pub disclosed_request_sha256: String,
    pub disclosed_response_sha256: String,
    pub presentation: Vec<u8>,
}

pub struct NotarizedResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
    pub proof: LocalProof,
}

/// An upstream response whose bytes are delivered as they arrive. The proof is
/// only available after the upstream HTTP message ends, because the TLS
/// transcript must be complete before it can be committed and attested.
pub struct NotarizedStreamResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: mpsc::Receiver<Result<Bytes, io::Error>>,
    pub proof: oneshot::Receiver<Result<LocalProof>>,
}

/// Sends a single HTTP/1.1 request through a TLSNotary Proxy-TLS session.
///
/// `request` must use an `identity` response encoding; otherwise the disclosed
/// bytes would not be a stable JSON trace. The notary validates the public TLS
/// chain using its own Mozilla root store.
pub async fn notarized_request(
    notary_addr: SocketAddr,
    server_name: &str,
    request: Request<HttpRequestBody>,
) -> Result<NotarizedResponse> {
    let mut response = notarized_streaming_request(notary_addr, server_name, request).await?;
    let status = response.status;
    let headers = response.headers.clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.body.recv().await {
        body.extend_from_slice(&chunk?);
    }
    let proof = response
        .proof
        .await
        .context("notarized response proof task exited")??;

    Ok(NotarizedResponse {
        status,
        headers,
        body,
        proof,
    })
}

/// Begins a Proxy-TLS HTTP request and returns response headers as soon as the
/// provider sends them. The notary relays encrypted TLS packets to the
/// allowlisted provider; response data is forwarded frame-by-frame and the
/// attestation resolves through `proof` at end-of-stream.
pub async fn notarized_streaming_request(
    notary_addr: SocketAddr,
    server_name: &str,
    request: Request<HttpRequestBody>,
) -> Result<NotarizedStreamResponse> {
    let notary_socket = TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("connecting to notary at {notary_addr}"))?;
    notary_socket.set_nodelay(true)?;

    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server_name)?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server_name.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, HttpRequestBody>(tls_connection).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "upstream HTTP/1 connection ended");
        }
    });

    let response: Response<Incoming> = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    let (body_sender, body_receiver) = mpsc::channel(16);
    let (proof_sender, proof_receiver) = oneshot::channel();
    let server_name = server_name.to_owned();
    tokio::spawn(async move {
        let result = async {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    // Keep recording even if the local caller disconnects; the
                    // saved proof is still useful and avoids a half-trace.
                    let _ = body_sender.send(Ok(data)).await;
                }
            }

            let mut prover = prover_task.await??;
            // `HttpTranscript` contains non-Send views into the transcript.
            // Drop it before the next await so this task stays spawnable.
            let transcript_commit = {
                let transcript = HttpTranscript::parse(prover.transcript())?;
                if transcript.requests.len() != 1 || transcript.responses.len() != 1 {
                    bail!("expected exactly one HTTP request and response in TLS transcript");
                }

                let mut commitment_builder = TranscriptCommitConfig::builder(prover.transcript());
                DefaultHttpCommitter::default()
                    .commit_transcript(&mut commitment_builder, &transcript)?;
                commitment_builder.build()?
            };

            let mut request_config_builder = RequestConfig::builder();
            request_config_builder.transcript_commit(transcript_commit.clone());
            let request_config = request_config_builder.build()?;
            let mut disclosure_config_builder = ProveConfig::builder(prover.transcript());
            disclosure_config_builder.transcript_commit(transcript_commit);
            let disclosure_config = disclosure_config_builder.build()?;
            let ProverOutput {
                transcript_commitments,
                transcript_secrets,
                ..
            } = prover.prove(&disclosure_config).await?;

            let prover_transcript = prover.transcript().clone();
            let tls_transcript = prover.tls_transcript().clone();
            prover.close().await?;

            let mut attestation_builder = AttestationRequest::builder(&request_config);
            attestation_builder
                .server_name(ServerName::Dns(server_name.as_str().try_into()?))
                .handshake_data(HandshakeData {
                    certs: tls_transcript
                        .server_cert_chain()
                        .ok_or_else(|| anyhow!("missing upstream certificate chain"))?
                        .to_vec(),
                    sig: tls_transcript
                        .server_signature()
                        .ok_or_else(|| anyhow!("missing upstream certificate signature"))?
                        .clone(),
                    binding: tls_transcript.certificate_binding().clone(),
                })
                .transcript(prover_transcript)
                .transcript_commitments(transcript_secrets, transcript_commitments);
            let (attestation_request, secrets) =
                attestation_builder.build(&CryptoProvider::default())?;

            handle.close();
            let mut socket = driver_task.await??;
            write_frame(&mut socket, &bincode::serialize(&attestation_request)?).await?;
            let attestation: Attestation = bincode::deserialize(&read_frame(&mut socket).await?)?;
            attestation_request.validate(&attestation, &CryptoProvider::default())?;

            Ok(LocalProof {
                server_name,
                attestation: bincode::serialize(&attestation)?,
                secrets: bincode::serialize(&secrets)?,
            })
        }
        .await;

        if let Err(error) = &result {
            let _ = body_sender
                .send(Err(io::Error::other(error.to_string())))
                .await;
        }
        let _ = proof_sender.send(result);
    });

    Ok(NotarizedStreamResponse {
        status: parts.status,
        headers: parts.headers,
        body: body_receiver,
        proof: proof_receiver,
    })
}

/// Serves one remote Proxy-TLS notary session. The notary opens the upstream
/// TCP connection itself and relays encrypted TLS records, so local DNS cannot
/// redirect the provider connection. It never receives the API key or HTTP
/// plaintext.
pub async fn run_notary_session(
    socket: TcpStream,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;
    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            verifier
                .reject(Some("LLM Notary accepts Proxy-TLS sessions only"))
                .await?;
            bail!("rejected MPC-TLS session")
        }
        VerifierCommitStart::Proxy(verifier) => {
            let server_name = verifier.config().server_name().as_str().to_owned();
            if !allowed_hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(&server_name))
            {
                verifier
                    .reject(Some("provider hostname is not allowed by this notary"))
                    .await?;
                bail!("rejected disallowed provider hostname: {server_name}");
            }
            let upstream = TcpStream::connect((server_name.as_str(), 443))
                .await
                .with_context(|| format!("notary connecting to {server_name}:443"))?;
            upstream.set_nodelay(true)?;
            verifier.accept().await?.run(upstream.compat()).await?
        }
    };
    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            (record.typ == ContentType::ApplicationData).then_some(record.ciphertext.len())
        })
        .sum::<usize>();
    let received_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            (record.typ == ContentType::ApplicationData).then_some(record.ciphertext.len())
        })
        .sum::<usize>();
    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        bail!("unsupported TLS certificate binding");
    };

    handle.close();
    let mut socket = driver_task.await??;
    let request: AttestationRequest = bincode::deserialize(&read_frame(&mut socket).await?)?;

    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);
    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .build()?;
    let mut builder = Attestation::builder(&attestation_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len.try_into().context("sent transcript too large")?,
                received: received_len
                    .try_into()
                    .context("received transcript too large")?,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider)?;
    write_frame(&mut socket, &bincode::serialize(&attestation)?).await?;
    Ok(())
}

/// Creates a portable presentation that reveals the request and response while
/// redacting every Authorization header value. A marketplace can store this as
/// opaque encrypted data; a buyer verifies it locally.
pub fn make_full_trace_bundle(proof: &LocalProof) -> Result<TraceBundle> {
    use tlsn::attestation::{Attestation, CryptoProvider, Secrets, presentation::Presentation};

    let attestation: Attestation = bincode::deserialize(&proof.attestation)?;
    let secrets: Secrets = bincode::deserialize(&proof.secrets)?;
    let transcript = HttpTranscript::parse(secrets.transcript())?;
    if transcript.requests.len() != 1 || transcript.responses.len() != 1 {
        bail!("expected exactly one HTTP request and response in proof");
    }

    let mut builder = secrets.transcript_proof_builder();
    let request = &transcript.requests[0];
    builder.reveal_sent(request.without_data())?;
    builder.reveal_sent(&request.request.target)?;
    for value in &request.headers {
        if value
            .name
            .as_str()
            .eq_ignore_ascii_case(header::AUTHORIZATION.as_str())
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
    builder.reveal_recv(&transcript.responses[0])?;
    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut presentation_builder = attestation.presentation_builder(&provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation_builder.build()?;

    let output = presentation.clone().verify(&provider)?;
    let partial = output
        .transcript
        .ok_or_else(|| anyhow!("locally built presentation omitted transcript"))?;
    Ok(TraceBundle {
        format: TRACE_FORMAT.to_owned(),
        server_name: proof.server_name.clone(),
        disclosed_request_sha256: sha256_hex(partial.sent_unsafe()),
        disclosed_response_sha256: sha256_hex(partial.received_unsafe()),
        presentation: bincode::serialize(&presentation)?,
    })
}

/// Verifies the signed TLS presentation and returns the disclosed transcript.
pub fn verify_trace_bundle(
    bundle: &TraceBundle,
    trusted_notary_key: &[u8],
) -> Result<(String, String)> {
    use tlsn::attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
    };

    if bundle.format != TRACE_FORMAT && bundle.format != LEGACY_TRACE_FORMAT {
        bail!("unsupported trace bundle format: {}", bundle.format);
    }
    let presentation: Presentation = bincode::deserialize(&bundle.presentation)?;
    if presentation.verifying_key().data.as_slice() != trusted_notary_key {
        bail!("presentation was not signed by the trusted notary key");
    }
    let PresentationOutput {
        server_name,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;
    let expected = server_name.ok_or_else(|| anyhow!("presentation omitted server identity"))?;
    if expected.to_string() != bundle.server_name {
        bail!("bundle server name does not match presentation");
    }
    let transcript = transcript.ok_or_else(|| anyhow!("presentation omitted transcript"))?;
    if sha256_hex(transcript.sent_unsafe()) != bundle.disclosed_request_sha256
        || sha256_hex(transcript.received_unsafe()) != bundle.disclosed_response_sha256
    {
        bail!("bundle transcript hashes do not match the authenticated presentation");
    }
    let sent = String::from_utf8_lossy(transcript.sent_unsafe()).into_owned();
    let received = String::from_utf8_lossy(transcript.received_unsafe()).into_owned();
    Ok((sent, received))
}

pub fn save_bundle(path: &Path, bundle: &TraceBundle) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(bundle)?)
        .with_context(|| format!("writing bundle to {}", path.display()))?;
    Ok(())
}

pub fn load_bundle(path: &Path) -> Result<TraceBundle> {
    serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .context("parsing trace bundle")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn write_frame<S: futures::AsyncWrite + Unpin>(socket: &mut S, value: &[u8]) -> Result<()> {
    if value.len() > MAX_FRAME_LEN {
        bail!("refusing oversized notary frame");
    }
    socket
        .write_all(&(value.len() as u32).to_be_bytes())
        .await?;
    socket.write_all(value).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_frame<S: futures::AsyncRead + Unpin>(socket: &mut S) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_LEN {
        bail!("refusing oversized notary frame");
    }
    let mut value = vec![0u8; length];
    socket.read_exact(&mut value).await?;
    Ok(value)
}
