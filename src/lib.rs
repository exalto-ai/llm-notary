//! Shared TLSNotary plumbing for the LLM Notary proof of concept.
//!
//! The boundary here is deliberate: the local proxy owns request plaintext and
//! the API key, while the remote notary relays authenticated TLS traffic and
//! signs an attestation for the committed transcript.

use std::{
    fs,
    future::IntoFuture,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

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
const CAPTURE_FORMAT: &str = "llm-notary/capture/v1";

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

/// Metadata for a local capture directory. The manifest duplicates only facts
/// that a verifier can derive from the evidence and artifact hashes; it is not
/// itself an attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureManifest {
    pub format: String,
    pub capture_id: String,
    pub created_at_unix_ms: u64,
    pub provider: CaptureProvider,
    pub notary: CaptureNotary,
    pub artifacts: CaptureArtifacts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureProvider {
    pub name: String,
    pub host: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureNotary {
    /// Hex-encoded secp256k1 SEC1 public key carried by the presentation.
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureArtifacts {
    pub evidence_sha256: String,
    pub request_disclosed_sha256: String,
    pub response_sha256: String,
}

/// Private, local-first record of one provider exchange. `request_disclosed`
/// intentionally contains the authenticated selective disclosure rather than
/// the original request: API-key values are never persisted.
#[derive(Debug)]
pub struct Capture {
    pub manifest: CaptureManifest,
    pub evidence: Vec<u8>,
    pub request_disclosed: Vec<u8>,
    pub response: Vec<u8>,
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

struct DisclosedPresentation {
    presentation: tlsn::attestation::presentation::Presentation,
    request_disclosed: Vec<u8>,
    response: Vec<u8>,
}

/// Creates a selectively disclosed presentation that reveals the request and
/// response while redacting every Authorization and x-api-key header value.
fn make_disclosed_presentation(proof: &LocalProof) -> Result<DisclosedPresentation> {
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
    Ok(DisclosedPresentation {
        presentation,
        request_disclosed: partial.sent_unsafe().to_vec(),
        response: partial.received_unsafe().to_vec(),
    })
}

/// Builds a local capture directory payload. The raw provider response is
/// retained locally; the request stores only the verifiable disclosure, so an
/// API key cannot be recovered from a capture directory.
pub fn make_capture(
    proof: &LocalProof,
    capture_id: String,
    provider_name: String,
) -> Result<Capture> {
    validate_capture_id(&capture_id)?;
    let disclosed = make_disclosed_presentation(proof)?;
    let evidence = bincode::serialize(&disclosed.presentation)?;
    let created_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("capture timestamp does not fit in u64")?;
    let manifest = CaptureManifest {
        format: CAPTURE_FORMAT.to_owned(),
        capture_id,
        created_at_unix_ms,
        provider: CaptureProvider {
            name: provider_name,
            host: proof.server_name.clone(),
        },
        notary: CaptureNotary {
            public_key: hex::encode(disclosed.presentation.verifying_key().data.as_slice()),
        },
        artifacts: CaptureArtifacts {
            evidence_sha256: sha256_hex(&evidence),
            request_disclosed_sha256: sha256_hex(&disclosed.request_disclosed),
            response_sha256: sha256_hex(&disclosed.response),
        },
    };
    Ok(Capture {
        manifest,
        evidence,
        request_disclosed: disclosed.request_disclosed,
        response: disclosed.response,
    })
}

/// Saves a capture atomically into `<capture_root>/<capture_id>/`.
pub fn save_capture(capture_root: &Path, capture: &Capture) -> Result<PathBuf> {
    validate_capture_id(&capture.manifest.capture_id)?;
    fs::create_dir_all(capture_root)
        .with_context(|| format!("creating capture root {}", capture_root.display()))?;
    restrict_directory(capture_root)?;
    let target = capture_root.join(&capture.manifest.capture_id);
    if target.exists() {
        bail!("capture directory already exists: {}", target.display());
    }
    let staging = capture_root.join(format!(
        ".{}.{}.partial",
        capture.manifest.capture_id,
        std::process::id()
    ));
    if staging.exists() {
        bail!(
            "capture staging directory already exists: {}",
            staging.display()
        );
    }
    fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;
    restrict_directory(&staging)?;
    write_private_file(&staging.join("evidence.tlsn"), &capture.evidence)?;
    write_private_file(
        &staging.join("request.disclosed.http"),
        &capture.request_disclosed,
    )?;
    write_private_file(&staging.join("response.http"), &capture.response)?;
    write_private_file(
        &staging.join("manifest.json"),
        &serde_json::to_vec_pretty(&capture.manifest)?,
    )?;
    fs::rename(&staging, &target)
        .with_context(|| format!("finalizing capture {}", target.display()))?;
    Ok(target)
}

pub fn load_capture(path: &Path) -> Result<Capture> {
    let directory = if path.is_dir() {
        path
    } else if path.file_name().is_some_and(|name| name == "manifest.json") {
        path.parent()
            .ok_or_else(|| anyhow!("capture manifest has no parent directory"))?
    } else {
        bail!(
            "expected a capture directory or its manifest.json: {}",
            path.display()
        );
    };
    let manifest: CaptureManifest = serde_json::from_slice(
        &fs::read(directory.join("manifest.json"))
            .with_context(|| format!("reading capture manifest in {}", directory.display()))?,
    )
    .context("parsing capture manifest")?;
    if manifest.format != CAPTURE_FORMAT {
        bail!("unsupported capture format: {}", manifest.format);
    }
    validate_capture_id(&manifest.capture_id)?;
    Ok(Capture {
        manifest,
        evidence: read_capture_file(directory, "evidence.tlsn")?,
        request_disclosed: read_capture_file(directory, "request.disclosed.http")?,
        response: read_capture_file(directory, "response.http")?,
    })
}

/// Verifies both the presentation and every local capture artifact.
pub fn verify_capture(
    path: &Path,
    trusted_notary_key: &[u8],
) -> Result<(CaptureManifest, String, String)> {
    use tlsn::attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
    };

    let capture = load_capture(path)?;
    if capture.manifest.artifacts.evidence_sha256 != sha256_hex(&capture.evidence)
        || capture.manifest.artifacts.request_disclosed_sha256
            != sha256_hex(&capture.request_disclosed)
        || capture.manifest.artifacts.response_sha256 != sha256_hex(&capture.response)
    {
        bail!("capture artifact hashes do not match the manifest");
    }
    let presentation: Presentation = bincode::deserialize(&capture.evidence)?;
    if presentation.verifying_key().data.as_slice() != trusted_notary_key {
        bail!("presentation was not signed by the trusted notary key");
    }
    if hex::encode(presentation.verifying_key().data.as_slice())
        != capture.manifest.notary.public_key
    {
        bail!("capture manifest notary key does not match the presentation");
    }
    let PresentationOutput {
        server_name,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;
    let server_name = server_name.ok_or_else(|| anyhow!("presentation omitted server identity"))?;
    if server_name.to_string() != capture.manifest.provider.host {
        bail!("capture provider host does not match the presentation");
    }
    let transcript = transcript.ok_or_else(|| anyhow!("presentation omitted transcript"))?;
    if transcript.sent_unsafe() != capture.request_disclosed
        || transcript.received_unsafe() != capture.response
    {
        bail!("capture HTTP artifacts do not match the authenticated presentation");
    }
    Ok((
        capture.manifest,
        String::from_utf8_lossy(&capture.request_disclosed).into_owned(),
        String::from_utf8_lossy(&capture.response).into_owned(),
    ))
}

fn validate_capture_id(capture_id: &str) -> Result<()> {
    if capture_id.is_empty()
        || capture_id == "."
        || capture_id == ".."
        || capture_id.contains('/')
        || capture_id.contains('\\')
    {
        bail!("capture ID must be a single, non-empty directory name");
    }
    Ok(())
}

fn read_capture_file(directory: &Path, name: &str) -> Result<Vec<u8>> {
    fs::read(directory.join(name)).with_context(|| {
        format!(
            "reading capture artifact {}",
            directory.join(name).display()
        )
    })
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)
        .with_context(|| format!("writing capture artifact {}", path.display()))?;
    restrict_file(path)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting capture directory {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting capture artifact {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_capture() -> Capture {
        let evidence = b"presentation".to_vec();
        let request_disclosed = b"POST /v1/messages HTTP/1.1\r\n\r\n{}".to_vec();
        let response = b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec();
        Capture {
            manifest: CaptureManifest {
                format: CAPTURE_FORMAT.to_owned(),
                capture_id: "cap-test-0001".to_owned(),
                created_at_unix_ms: 1,
                provider: CaptureProvider {
                    name: "anthropic".to_owned(),
                    host: "api.anthropic.com".to_owned(),
                },
                notary: CaptureNotary {
                    public_key: "test-key".to_owned(),
                },
                artifacts: CaptureArtifacts {
                    evidence_sha256: sha256_hex(&evidence),
                    request_disclosed_sha256: sha256_hex(&request_disclosed),
                    response_sha256: sha256_hex(&response),
                },
            },
            evidence,
            request_disclosed,
            response,
        }
    }

    #[test]
    fn capture_directory_round_trips_with_named_artifacts() {
        let root = std::env::temp_dir().join(format!(
            "llm-notary-capture-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after Unix epoch")
                .as_nanos()
        ));
        let capture = test_capture();
        let path = save_capture(&root, &capture).expect("save capture");
        assert_eq!(path, root.join("cap-test-0001"));
        assert!(path.join("manifest.json").is_file());
        assert!(path.join("evidence.tlsn").is_file());
        assert!(path.join("request.disclosed.http").is_file());
        assert!(path.join("response.http").is_file());

        let loaded = load_capture(&path).expect("load capture");
        assert_eq!(loaded.manifest.capture_id, "cap-test-0001");
        assert_eq!(loaded.request_disclosed, capture.request_disclosed);
        assert_eq!(loaded.response, capture.response);
        assert!(save_capture(&root, &capture).is_err());

        fs::remove_dir_all(&root).expect("remove test capture directory");
    }

    #[test]
    fn capture_ids_cannot_escape_the_capture_root() {
        assert!(validate_capture_id("cap-01").is_ok());
        assert!(validate_capture_id("../outside").is_err());
        assert!(validate_capture_id("nested/capture").is_err());
        assert!(validate_capture_id("").is_err());
    }
}
