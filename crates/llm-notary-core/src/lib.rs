//! Shared TLSNotary plumbing for the LLM Notary proof of concept.
//!
//! The boundary here is deliberate: the local proxy owns request plaintext and
//! the API key, while the remote notary relays authenticated TLS traffic and
//! signs an attestation for the committed transcript.

use std::{
    fmt,
    future::IntoFuture,
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(feature = "cli")]
use std::{fs, io::Write as _, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use http::{HeaderMap, Method, Uri};
use http_body::Frame;
use http_body_util::{BodyExt as _, StreamBody, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
};
use rustls::{
    ClientConfig, RootCertStore as OuterRootCertStore, pki_types::ServerName as TlsServerName,
};
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
        CertBinding, ConnectionInfo, DnsName, HandshakeData, ServerEphemKey, ServerName,
        TranscriptLength,
    },
    prover::ProverOutput,
    rangeset::set::RangeSet,
    transcript::{ContentType, Direction, Transcript, TranscriptCommitConfig},
    verifier::VerifierCommitStart,
    webpki::RootCertStore,
};
use tlsn_formats::http::{HttpTranscript, Response as HttpTranscriptResponse};
use tokio::{
    io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// Versioned source-capture contract referenced by private and public evidence.
pub const CAPTURE_FORMAT: &str = "llm-notary/capture/v1";

/// Hash bytes using the spelling used by the versioned artifact contracts.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub mod archive;
pub mod bundle;
pub mod normalize;
pub mod notary_directory;
pub mod pagination;
pub mod public;
pub mod public_safety;
pub mod telemetry;
#[cfg(feature = "cli")]
pub mod vault;

use crate::notary_directory::{NotaryEndpoint, NotaryTransport};

/// Default cap for one serialized control-protocol frame.
pub const DEFAULT_NOTARY_MAX_FRAME_BYTES: usize = 128 << 20;
/// Shared HTTP transcript budget for local capture and deferred finalization.
///
/// This stays below the notary's 128 × 128 KiB private-proof limit so normal
/// HTTP headers and transfer framing cannot turn a successfully captured
/// bundle into a proof the public notary must reject.
pub const DEFAULT_MAX_ATTESTABLE_HTTP_BYTES: usize = 15 << 20;
const REQUEST_WRITE_CHUNK: usize = 8 << 10;
/// Keeps the bounded proof path below the 1 GiB notary budget in the measured
/// Proxy-TLS configuration.
const CHUNKED_PROOF_BYTES: usize = 128 << 10;
const DISCLOSED_HEADER_VALUE_NAME: &str = "transfer-encoding";
const DISCLOSED_TRANSFER_ENCODING_VALUE: &[u8] = b"chunked";
const DEFERRED_BUNDLE_FORMAT: &str = "llm-notary/deferred-bundle/v1";
const DEFERRED_RECEIPT_FORMAT: &str = "llm-notary/deferred-receipt/v1";
const NOTARY_CONTROL_MAGIC_V1: &[u8; 8] = b"LLMN\0\0\0\x01";
const NOTARY_CONTROL_MAGIC_V2: &[u8; 8] = b"LLMN\0\0\0\x02";
const NOTARY_CONTROL_MAGIC_V3: &[u8; 8] = b"LLMN\0\0\0\x03";
pub const MAX_NOTARY_ADMISSION_TICKET_BYTES: usize = 512;
const NOTARY_MODE_CAPTURE: u8 = 2;
const NOTARY_MODE_FINALIZE: u8 = 3;
const NOTARY_ADMISSION_ACCEPTED: u8 = 1;
const NOTARY_ADMISSION_REJECTED: u8 = 2;
const NOTARY_REJECTION_CAPTURE_AT_CAPACITY: u8 = 1;
const NOTARY_REJECTION_FINALIZE_AT_CAPACITY: u8 = 2;
const NOTARY_REJECTION_CAPTURE_DISABLED: u8 = 3;
const NOTARY_REJECTION_ADMISSION_DENIED: u8 = 4;
const NOTARY_REJECTION_COORDINATOR_UNAVAILABLE: u8 = 5;

/// Stable milestones emitted while a deferred capture is finalized.
///
/// These stages describe completed transitions in the proof pipeline. They do
/// not imply equal work or provide a time estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizationPhase {
    Proving,
    Signing,
    Packaging,
}

impl FinalizationPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proving => "proving",
            Self::Signing => "signing",
            Self::Packaging => "packaging",
        }
    }
}

/// Concrete private-proof work completed inside the dominant finalization
/// phase. Byte counts advance after bounded authentication batches; commitment
/// counts advance after each complete child proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FinalizationProofProgress {
    pub bytes_completed: u64,
    pub bytes_total: u64,
    pub commitments_completed: u64,
    pub commitments_total: u64,
}

/// One non-secret progress update emitted during finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizationProgress {
    Phase(FinalizationPhase),
    Proof(FinalizationProofProgress),
}

/// Receives best-effort progress from the finalization pipeline.
pub type FinalizationProgressObserver<'a> = &'a (dyn Fn(FinalizationProgress) + Send + Sync);
const NOTARY_REJECTION_FINALIZATION_CREDITS_EXHAUSTED: u8 = 6;
const NOTARY_REJECTION_CAPTURE_CREDITS_EXHAUSTED: u8 = 7;
pub const NOTARY_CAPACITY_RETRY_AFTER_SECS: u64 = 5;

trait NotaryStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> NotaryStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type NotaryIo = Box<dyn NotaryStream>;

/// A validated notary protocol operation selected by the versioned prelude.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotarySessionMode {
    Capture,
    Finalize,
}

/// A service-level reason a notary declined a session before the TLSN protocol
/// began. These are safe to show to a local proxy or CLI user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotaryAdmissionRejection {
    CaptureAtCapacity,
    FinalizeAtCapacity,
    CaptureDisabled,
    AdmissionDenied,
    CoordinatorUnavailable,
    CaptureCreditsExhausted,
    FinalizationCreditsExhausted,
}

impl NotaryAdmissionRejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::CaptureAtCapacity => "capture_at_capacity",
            Self::FinalizeAtCapacity => "finalize_at_capacity",
            Self::CaptureDisabled => "capture_disabled",
            Self::AdmissionDenied => "admission_denied",
            Self::CoordinatorUnavailable => "coordinator_unavailable",
            Self::CaptureCreditsExhausted => "capture_credits_exhausted",
            Self::FinalizationCreditsExhausted => "finalization_credits_exhausted",
        }
    }

    fn from_wire(code: u8) -> Result<Self> {
        match code {
            NOTARY_REJECTION_CAPTURE_AT_CAPACITY => Ok(Self::CaptureAtCapacity),
            NOTARY_REJECTION_FINALIZE_AT_CAPACITY => Ok(Self::FinalizeAtCapacity),
            NOTARY_REJECTION_CAPTURE_DISABLED => Ok(Self::CaptureDisabled),
            NOTARY_REJECTION_ADMISSION_DENIED => Ok(Self::AdmissionDenied),
            NOTARY_REJECTION_COORDINATOR_UNAVAILABLE => Ok(Self::CoordinatorUnavailable),
            NOTARY_REJECTION_CAPTURE_CREDITS_EXHAUSTED => Ok(Self::CaptureCreditsExhausted),
            NOTARY_REJECTION_FINALIZATION_CREDITS_EXHAUSTED => {
                Ok(Self::FinalizationCreditsExhausted)
            }
            _ => bail!("unknown notary admission rejection code"),
        }
    }

    fn wire_code(self) -> u8 {
        match self {
            Self::CaptureAtCapacity => NOTARY_REJECTION_CAPTURE_AT_CAPACITY,
            Self::FinalizeAtCapacity => NOTARY_REJECTION_FINALIZE_AT_CAPACITY,
            Self::CaptureDisabled => NOTARY_REJECTION_CAPTURE_DISABLED,
            Self::AdmissionDenied => NOTARY_REJECTION_ADMISSION_DENIED,
            Self::CoordinatorUnavailable => NOTARY_REJECTION_COORDINATOR_UNAVAILABLE,
            Self::CaptureCreditsExhausted => NOTARY_REJECTION_CAPTURE_CREDITS_EXHAUSTED,
            Self::FinalizationCreditsExhausted => NOTARY_REJECTION_FINALIZATION_CREDITS_EXHAUSTED,
        }
    }
}

/// A typed service error returned by a v2 notary before session work begins.
/// It deliberately contains no information about other clients or server
/// capacity. `retry_after` applies to transient rejection variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotaryAdmissionError {
    rejection: NotaryAdmissionRejection,
    retry_after: std::time::Duration,
}

impl NotaryAdmissionError {
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn test_only(
        rejection: NotaryAdmissionRejection,
        retry_after: std::time::Duration,
    ) -> Self {
        Self {
            rejection,
            retry_after,
        }
    }

    pub fn rejection(self) -> NotaryAdmissionRejection {
        self.rejection
    }

    pub fn retry_after(self) -> std::time::Duration {
        self.retry_after
    }
}

impl fmt::Display for NotaryAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.retry_after.as_secs().max(1);
        match self.rejection {
            NotaryAdmissionRejection::CaptureAtCapacity => write!(
                formatter,
                "notary capture capacity is temporarily full; retry in {seconds} seconds"
            ),
            NotaryAdmissionRejection::FinalizeAtCapacity => write!(
                formatter,
                "notary finalization capacity is temporarily full; retry in {seconds} seconds"
            ),
            NotaryAdmissionRejection::CaptureDisabled => {
                write!(
                    formatter,
                    "notary is temporarily not accepting new captures"
                )
            }
            NotaryAdmissionRejection::AdmissionDenied => {
                write!(formatter, "notary admission was denied")
            }
            NotaryAdmissionRejection::CoordinatorUnavailable => {
                write!(
                    formatter,
                    "notary admission service is temporarily unavailable"
                )
            }
            NotaryAdmissionRejection::CaptureCreditsExhausted => write!(
                formatter,
                "hosted capture allowance is exhausted; wait for the monthly reset"
            ),
            NotaryAdmissionRejection::FinalizationCreditsExhausted => write!(
                formatter,
                "hosted notarization allowance is exhausted; wait for the monthly reset or buy additional credits"
            ),
        }
    }
}

impl std::error::Error for NotaryAdmissionError {}

/// Finds a typed admission rejection after callers add ordinary `anyhow`
/// context around the connection operation.
pub fn notary_admission_error(error: &anyhow::Error) -> Option<&NotaryAdmissionError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NotaryAdmissionError>())
}

/// A parsed notary session prelude. v1 clients do not expect an admission
/// response, v2 clients accept typed admission responses, and v3 clients also
/// carry a one-time hosted admission ticket.
#[derive(Clone, PartialEq, Eq)]
pub struct NotarySessionPrelude {
    mode: NotarySessionMode,
    admission_response: bool,
    admission_ticket: Option<String>,
}

impl NotarySessionPrelude {
    pub fn mode(&self) -> NotarySessionMode {
        self.mode
    }

    /// Returns the purpose-specific hosted admission ticket without granting
    /// the notary access to the caller's reusable account credential.
    pub fn admission_ticket(&self) -> Option<&str> {
        self.admission_ticket.as_deref()
    }
}

impl fmt::Debug for NotarySessionPrelude {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotarySessionPrelude")
            .field("mode", &self.mode)
            .field("admission_response", &self.admission_response)
            .field(
                "admission_ticket",
                &self.admission_ticket.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Coordinator-authorized limits for one hosted notary session. The notary
/// intersects these values with its process-local hard maxima.
#[derive(Clone, Debug)]
pub struct HostedNotarySessionLimits {
    pub expected_record_digest: Option<[u8; 32]>,
    pub expected_transcript_bytes: Option<usize>,
    pub session_timeout: Duration,
    pub max_private_chunk_bytes: usize,
    pub max_total_private_chunk_bytes: usize,
    pub max_private_chunk_commitments: usize,
    pub max_frame_bytes: usize,
}

#[derive(Serialize, Deserialize)]
struct DeferredCaptureRequest {
    root_binding: [u8; 32],
    record_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct DeferredFinalizeRequest {
    receipt: DeferredReceipt,
    records: tlsn::deferred::DeferredRecordTranscript,
    prove_request: tlsn::config::prove::ProveRequest,
}

/// A request body split into bounded frames, avoiding one unbounded local write
/// for a large agent request.
pub type HttpRequestBody = BoxBody<Bytes, std::convert::Infallible>;

/// Local metadata and resource limits for one deferred provider capture.
pub struct DeferredCaptureConfig {
    pub capture_id: String,
    pub provider_name: String,
    pub created_at_unix_ms: u64,
    pub request_body_bytes: usize,
    pub max_attestable_http_bytes: usize,
    pub max_frame_bytes: usize,
}

/// Tracks the HTTP bytes that will need private commitments in a deferred
/// proof. One budget covers the request and response of a capture.
pub struct AttestableHttpBudget {
    maximum: usize,
    used: usize,
}

impl AttestableHttpBudget {
    pub fn new(maximum: usize) -> Result<Self> {
        if maximum == 0 {
            bail!("maximum attestable HTTP bytes must be non-zero");
        }
        Ok(Self { maximum, used: 0 })
    }

    pub fn remaining(&self) -> usize {
        self.maximum.saturating_sub(self.used)
    }

    pub fn reserve(&mut self, bytes: usize, phase: &'static str) -> Result<()> {
        let used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("attestable HTTP byte count overflow"))?;
        if used > self.maximum {
            bail!(
                "{phase} exceeds the {}-byte maximum attestable HTTP budget",
                self.maximum
            );
        }
        self.used = used;
        Ok(())
    }
}

/// Returns the conservative on-wire cost of the request line and headers that
/// the proxy will commit. Header values are counted in full even when a later
/// disclosure redacts them, so this can only reject early, never undercount.
pub fn attestable_request_header_bytes(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<usize> {
    let target = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let headers = attestable_header_fields_bytes(headers)?;
    method
        .as_str()
        .len()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(target.len()))
        .and_then(|bytes| bytes.checked_add(" HTTP/1.1\r\n".len()))
        .and_then(|bytes| bytes.checked_add(headers))
        .ok_or_else(|| anyhow!("attestable HTTP header byte count overflow"))
}

fn attestable_response_header_bytes(
    status: http::StatusCode,
    headers: &HeaderMap,
) -> Result<usize> {
    let headers = attestable_header_fields_bytes(headers)?;
    "HTTP/1.1 "
        .len()
        .checked_add(status.as_str().len())
        .and_then(|bytes| bytes.checked_add("\r\n".len()))
        .and_then(|bytes| bytes.checked_add(headers))
        .ok_or_else(|| anyhow!("attestable HTTP header byte count overflow"))
}

fn attestable_header_fields_bytes(headers: &HeaderMap) -> Result<usize> {
    let mut total = 2usize;
    for (name, header_value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(2))
            .and_then(|bytes| bytes.checked_add(header_value.as_bytes().len()))
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or_else(|| anyhow!("attestable HTTP header byte count overflow"))?;
    }
    Ok(total)
}

pub fn chunked_request_body(bytes: Bytes) -> HttpRequestBody {
    let length = bytes.len();
    let frames =
        futures::stream::iter((0..length).step_by(REQUEST_WRITE_CHUNK).map(move |start| {
            let end = start.saturating_add(REQUEST_WRITE_CHUNK).min(length);
            Ok(Frame::data(bytes.slice(start..end)))
        }));
    StreamBody::new(frames).boxed()
}

fn deferred_transcript_commit(
    transcript: &Transcript,
    max_attestable_http_bytes: usize,
) -> Result<TranscriptCommitConfig> {
    let http = HttpTranscript::parse(transcript)?;
    let ranges = disclosed_http_ranges(&http, "in TLS transcript")?;
    ensure_attestable_ranges(&ranges, max_attestable_http_bytes)?;
    let mut builder = TranscriptCommitConfig::builder(transcript);
    commit_bounded_ranges(&mut builder, ranges.sent.iter(), Direction::Sent)?;
    commit_bounded_ranges(&mut builder, ranges.received.iter(), Direction::Received)?;
    Ok(builder.build()?)
}

fn ensure_attestable_http_bytes(transcript: &Transcript, maximum: usize) -> Result<()> {
    let http = HttpTranscript::parse(transcript)?;
    ensure_attestable_ranges(&disclosed_http_ranges(&http, "in TLS transcript")?, maximum)
}

fn ensure_attestable_ranges(ranges: &DisclosedHttpRanges, maximum: usize) -> Result<()> {
    let mut budget = AttestableHttpBudget::new(maximum)?;
    budget.reserve(
        ranges.sent.iter().map(|range| range.len()).sum::<usize>(),
        "provider request",
    )?;
    budget.reserve(
        ranges
            .received
            .iter()
            .map(|range| range.len())
            .sum::<usize>(),
        "provider response",
    )
}

/// Uses a non-overlapping commitment layout compatible with
/// `make_disclosed_presentation`.
///
/// The standard HTTP committer deliberately adds overlapping whole-message and
/// field commitments for flexibility. Chunked private proofs reject that
/// overlap, so the production large-message path commits exactly the fields we
/// disclose and replaces each body commitment with bounded pieces.
struct DisclosedHttpRanges {
    sent: RangeSet<usize>,
    received: RangeSet<usize>,
}

fn disclosed_http_ranges(
    transcript: &HttpTranscript,
    context: &'static str,
) -> Result<DisclosedHttpRanges> {
    if transcript.requests.len() != 1 {
        bail!("expected exactly one HTTP request {context}");
    }
    if transcript
        .responses
        .iter()
        .any(|response| response.status.code.as_str() == "101")
    {
        bail!("HTTP 101 Switching Protocols is not supported {context}");
    }
    let request = &transcript.requests[0];
    let mut sent = RangeSet::default();
    sent.union_mut(request.without_data());
    sent.union_mut(&request.request.target);
    for value in &request.headers {
        if may_disclose_header_value(&value.name.as_str(), &value.value.as_bytes()) {
            sent.union_mut(value);
        } else {
            sent.union_mut(value.without_value());
        }
    }
    if let Some(body) = &request.body {
        sent.union_mut(body);
    }

    let mut final_responses = transcript
        .responses
        .iter()
        .filter(|response| !is_interim_http_response(response));
    let response = final_responses
        .next()
        .ok_or_else(|| anyhow!("expected exactly one final HTTP response {context}"))?;
    if final_responses.next().is_some() {
        bail!("expected exactly one final HTTP response {context}");
    }
    let mut received = RangeSet::default();
    received.union_mut(response.without_data());
    for value in &response.headers {
        if may_disclose_header_value(&value.name.as_str(), &value.value.as_bytes()) {
            received.union_mut(value);
        } else {
            received.union_mut(value.without_value());
        }
    }
    if let Some(body) = &response.body {
        received.union_mut(body);
    }
    Ok(DisclosedHttpRanges { sent, received })
}

/// HTTP/1.1 permits informational responses before the final response. They
/// are covered by the TLS transcript but are not part of the provider response
/// disclosed in a capture. `101 Switching Protocols` is rejected separately
/// because the proxy only supports ordinary HTTP/1.1 exchanges.
fn is_interim_http_response(response: &HttpTranscriptResponse) -> bool {
    let code = response.status.code.as_str();
    code.starts_with('1')
}

/// Packs disjoint HTTP ranges into the fewest bounded commitments. One child
/// proof VM is created per commitment, so grouping headers and fragmented SSE
/// body ranges materially reduces finalization latency without disclosing
/// credential-header values.
fn commit_bounded_ranges(
    builder: &mut tlsn::transcript::TranscriptCommitConfigBuilder,
    ranges: impl Iterator<Item = std::ops::Range<usize>>,
    direction: Direction,
) -> Result<()> {
    let mut pending = RangeSet::default();
    let mut pending_bytes = 0usize;
    for range in ranges {
        let mut start = range.start;
        while start < range.end {
            let available = CHUNKED_PROOF_BYTES - pending_bytes;
            let end = (start + available).min(range.end);
            pending.union_mut(start..end);
            pending_bytes += end - start;
            start = end;
            if pending_bytes == CHUNKED_PROOF_BYTES {
                builder.commit(&pending, direction)?;
                pending = RangeSet::default();
                pending_bytes = 0;
            }
        }
    }
    if pending_bytes != 0 {
        builder.commit(&pending, direction)?;
    }
    Ok(())
}

fn may_disclose_header_value(name: &str, value: &[u8]) -> bool {
    name.eq_ignore_ascii_case(DISCLOSED_HEADER_VALUE_NAME)
        && value
            .trim_ascii()
            .eq_ignore_ascii_case(DISCLOSED_TRANSFER_ENCODING_VALUE)
}

/// Enforces the finalized-package disclosure contract after the TLSNotary
/// presentation has authenticated these bytes.
pub fn validate_disclosed_http_redactions(request: &[u8], response: &[u8]) -> Result<()> {
    validate_redacted_headers(request, "request")?;
    validate_redacted_headers(response, "response")
}

fn validate_redacted_headers(bytes: &[u8], label: &str) -> Result<()> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("{label} does not contain a complete HTTP header block"))?;
    for line in bytes[..header_end].split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            bail!("{label} contains a malformed HTTP header");
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        let visible = value
            .iter()
            .any(|byte| !byte.is_ascii_whitespace() && *byte != 0);
        let allowlisted = may_disclose_header_value(
            std::str::from_utf8(name)
                .map_err(|_| anyhow!("{label} contains a non-UTF-8 HTTP header name"))?,
            value,
        );
        if visible && (!allowlisted || value.contains(&0)) {
            bail!("{label} discloses a non-allowlisted HTTP header value");
        }
    }
    Ok(())
}

/// The proof material retained while constructing a selectively disclosed
/// provider capture.
#[derive(Serialize, Deserialize)]
pub struct LocalProof {
    pub server_name: String,
    pub attestation: Vec<u8>,
    pub secrets: Vec<u8>,
}

impl fmt::Debug for LocalProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalProof")
            .field("server_name", &self.server_name)
            .field("attestation", &RedactedBytes(self.attestation.len()))
            .field("secrets", &RedactedBytes(self.secrets.len()))
            .finish()
    }
}

/// A notary-signed, end-of-stream binding for a deferred private proof.
///
/// The receipt covers a TLSN root binding and the exact encrypted application
/// record layout. It is public, but it is not itself a disclosure of the HTTP
/// request or response.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeferredReceipt {
    format: String,
    server_name: String,
    root_binding: [u8; 32],
    record_digest: [u8; 32],
    connection_info: ConnectionInfo,
    server_ephemeral_key: ServerEphemKey,
    signature: Vec<u8>,
}

impl DeferredReceipt {
    /// Returns the provider host the notary authenticated during capture.
    fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Verifies this receipt against the trusted notary public key.
    fn verify(&self, trusted_notary_key: &[u8]) -> Result<()> {
        if self.format != DEFERRED_RECEIPT_FORMAT {
            bail!("unsupported deferred receipt format: {}", self.format);
        }
        let key = VerifyingKey::from_sec1_bytes(trusted_notary_key)
            .context("invalid trusted notary public key")?;
        let signature =
            Signature::from_slice(&self.signature).context("invalid deferred receipt signature")?;
        key.verify(&deferred_receipt_message(self)?, &signature)
            .context("deferred receipt signature did not verify")
    }

    /// Ensures the encrypted records supplied for a later proof are the ones
    /// the notary authenticated when it issued this receipt.
    fn validate_records(&self, records: &tlsn::deferred::DeferredRecordTranscript) -> Result<()> {
        if self.record_digest != records.digest() {
            bail!("deferred receipt does not match encrypted application records");
        }
        Ok(())
    }
}

fn deferred_receipt_message(receipt: &DeferredReceipt) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct UnsignedReceipt<'a> {
        format: &'a str,
        server_name: &'a str,
        root_binding: [u8; 32],
        record_digest: [u8; 32],
        connection_info: &'a ConnectionInfo,
        server_ephemeral_key: &'a ServerEphemKey,
    }

    let payload = bincode::serialize(&UnsignedReceipt {
        format: &receipt.format,
        server_name: &receipt.server_name,
        root_binding: receipt.root_binding,
        record_digest: receipt.record_digest,
        connection_info: &receipt.connection_info,
        server_ephemeral_key: &receipt.server_ephemeral_key,
    })?;
    let mut message = b"LLM Notary deferred receipt\0".to_vec();
    message.extend_from_slice(&payload);
    Ok(message)
}

/// Issues a receipt after the notary has validated the live TLS connection.
///
/// This is not a client API: callers must first authenticate the provider's
/// certificate and the root binding from the original Proxy-TLS session.
fn issue_deferred_receipt(
    signing_key: &SigningKey,
    server_name: String,
    root_binding: [u8; 32],
    records: &tlsn::deferred::DeferredRecordTranscript,
    connection_info: ConnectionInfo,
    server_ephemeral_key: ServerEphemKey,
) -> Result<DeferredReceipt> {
    let mut receipt = DeferredReceipt {
        format: DEFERRED_RECEIPT_FORMAT.to_owned(),
        server_name,
        root_binding,
        record_digest: records.digest(),
        connection_info,
        server_ephemeral_key,
        signature: Vec::new(),
    };
    let signature: Signature = signing_key.sign(&deferred_receipt_message(&receipt)?);
    receipt.signature = signature.to_bytes().to_vec();
    Ok(receipt)
}

/// A private, client-held deferred-proof artifact.
///
/// The checkpoint contains the complete plaintext transcript and TLS traffic
/// keys required to produce a proof later. Store it only with user-only file
/// permissions and encrypt it at rest when the platform provides a keychain
/// or equivalent facility.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeferredBundle {
    format: String,
    receipt: DeferredReceipt,
    capture_id: String,
    provider_name: String,
    created_at_unix_ms: u64,
    handshake_data: HandshakeData,
    checkpoint: Vec<u8>,
}

impl fmt::Debug for DeferredBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeferredBundle")
            .field("format", &self.format)
            .field("receipt", &self.receipt)
            .field("capture_id", &self.capture_id)
            .field("provider_name", &self.provider_name)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("handshake_data", &self.handshake_data)
            .field("checkpoint", &RedactedBytes(self.checkpoint.len()))
            .finish()
    }
}

impl DeferredBundle {
    /// Creates a portable client-held bundle after a deferred capture ends.
    fn new(
        receipt: DeferredReceipt,
        capture_id: String,
        provider_name: String,
        created_at_unix_ms: u64,
        handshake_data: HandshakeData,
        state: &tlsn::deferred::DeferredProverState,
    ) -> Result<Self> {
        validate_capture_id(&capture_id)?;
        validate_provider_name(&provider_name, receipt.server_name())?;
        receipt.validate_records(state.records())?;
        Ok(Self {
            format: DEFERRED_BUNDLE_FORMAT.to_owned(),
            receipt,
            capture_id,
            provider_name,
            created_at_unix_ms,
            handshake_data,
            checkpoint: bincode::serialize(state).context("serializing deferred checkpoint")?,
        })
    }

    /// Returns the stable local capture identifier.
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    /// Returns the provider adapter name.
    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    /// Returns the immutable TLS record digest used to bind a one-time
    /// finalization admission to this bundle without disclosing plaintext.
    pub fn record_digest_hex(&self) -> String {
        hex::encode(self.receipt.record_digest)
    }

    /// Returns the immutable finalization allowance authenticated by the
    /// receipt's sent and received TLS application-data lengths.
    pub fn finalization_allowance_bytes(&self) -> Result<usize> {
        checked_transcript_allowance(&self.receipt.connection_info.transcript_length)
    }

    /// Returns the bundle creation time in Unix milliseconds.
    pub fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    /// Returns the provider connection time authenticated by the notary
    /// receipt. Trust stores use this—not the local file timestamp—when
    /// evaluating a rotated key's validity window.
    pub fn authenticated_connection_time_unix_ms(&self) -> Result<u64> {
        self.receipt
            .connection_info
            .time
            .checked_mul(1000)
            .context("authenticated connection timestamp does not fit in milliseconds")
    }

    /// Checks whether this pending bundle's receipt was issued by a key.
    pub fn verify_notary_key(&self, public_key: &[u8]) -> Result<()> {
        self.receipt.verify(public_key)
    }

    /// Deserializes the private client checkpoint.
    fn checkpoint(&self) -> Result<tlsn::deferred::DeferredProverState> {
        if self.format != DEFERRED_BUNDLE_FORMAT {
            bail!("unsupported deferred bundle format: {}", self.format);
        }
        let state: tlsn::deferred::DeferredProverState =
            bincode::deserialize(&self.checkpoint).context("decoding deferred checkpoint")?;
        self.receipt.validate_records(state.records())?;
        Ok(state)
    }

    /// Writes this pending bundle encrypted with the local vault.
    #[cfg(feature = "cli")]
    pub fn save(&self, path: &Path, vault: &crate::vault::Vault) -> Result<()> {
        if path.exists() {
            bail!("refusing to overwrite existing bundle: {}", path.display());
        }
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("bundle path has no file name"))?
            .to_string_lossy();
        let staging = parent.join(format!(
            ".{file_name}.{}.{:016x}.partial",
            std::process::id(),
            rand::random::<u64>()
        ));
        let bytes = bincode::serialize(self).context("serializing deferred bundle")?;
        let encrypted = vault.encrypt(&bytes)?;
        let result = (|| -> Result<()> {
            write_private_file(&staging, &encrypted)?;
            fs::rename(&staging, path)
                .with_context(|| format!("finalizing encrypted bundle {}", path.display()))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging);
        }
        result
    }

    /// Reads and decrypts a pending bundle.
    #[cfg(feature = "cli")]
    pub fn load(path: &Path, vault: &crate::vault::Vault) -> Result<Self> {
        let encrypted = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let bundle: Self = bincode::deserialize(&vault.decrypt(&encrypted)?)
            .context("decoding deferred bundle")?;
        if bundle.format != DEFERRED_BUNDLE_FORMAT {
            bail!("unsupported deferred bundle format: {}", bundle.format);
        }
        validate_capture_id(&bundle.capture_id)?;
        validate_provider_name(&bundle.provider_name, bundle.receipt.server_name())?;
        bundle.checkpoint()?;
        Ok(bundle)
    }
}

fn checked_transcript_allowance(length: &TranscriptLength) -> Result<usize> {
    usize::try_from(length.sent)
        .context("sent transcript length does not fit in usize")?
        .checked_add(
            usize::try_from(length.received)
                .context("received transcript length does not fit in usize")?,
        )
        .ok_or_else(|| anyhow!("total transcript length does not fit in usize"))
}

/// Metadata that binds finalized trace evidence to its authenticated source.
/// The manifest duplicates only facts a verifier can derive from the evidence
/// and artifact hashes; it is not itself an attestation.
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

/// Source evidence for one finalized trace package. `request_disclosed`
/// intentionally contains authenticated selective disclosure rather than the
/// original request, so API-key values are never retained.
pub struct Capture {
    pub manifest: CaptureManifest,
    pub evidence: Vec<u8>,
    pub request_disclosed: Vec<u8>,
    pub response: Vec<u8>,
}

impl fmt::Debug for Capture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Capture")
            .field("manifest", &self.manifest)
            .field("evidence", &RedactedBytes(self.evidence.len()))
            .field(
                "request_disclosed",
                &RedactedBytes(self.request_disclosed.len()),
            )
            .field("response", &RedactedBytes(self.response.len()))
            .finish()
    }
}

struct RedactedBytes(usize);

impl fmt::Debug for RedactedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted: {} bytes>", self.0)
    }
}

/// A streaming provider response whose private deferred bundle becomes
/// available shortly after the provider stream ends.
pub struct DeferredStreamResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: mpsc::Receiver<Result<Bytes, io::Error>>,
    pub bundle: oneshot::Receiver<Result<DeferredBundle>>,
}

async fn complete_deferred_response<F>(
    body_sender: mpsc::Sender<Result<Bytes, io::Error>>,
    bundle_sender: oneshot::Sender<Result<DeferredBundle>>,
    seal: F,
) where
    F: std::future::Future<Output = Result<DeferredBundle>>,
{
    // EOF belongs to the provider response. Publish it before awaiting the
    // separate receipt/checkpoint step so a sealing failure cannot
    // retroactively fail an otherwise successful model call.
    drop(body_sender);
    let _ = bundle_sender.send(seal.await);
}

/// Streams one provider request and returns a client-held deferred bundle at
/// end-of-stream without running the expensive private proof.
pub async fn deferred_streaming_request(
    notary_addr: SocketAddr,
    server_name: &str,
    capture: DeferredCaptureConfig,
    request: Request<HttpRequestBody>,
) -> Result<DeferredStreamResponse> {
    let endpoint = NotaryEndpoint::new(
        notary_addr.ip().to_string(),
        notary_addr.port(),
        NotaryTransport::Tcp,
    )?;
    deferred_streaming_request_to(&endpoint, server_name, capture, request).await
}

/// Streams one provider request through a raw-TCP or public-CA TLS notary
/// endpoint, retaining the endpoint hostname for TLS SNI validation.
pub async fn deferred_streaming_request_to(
    notary: &NotaryEndpoint,
    server_name: &str,
    capture: DeferredCaptureConfig,
    request: Request<HttpRequestBody>,
) -> Result<DeferredStreamResponse> {
    deferred_streaming_request_to_with_admission(notary, server_name, capture, request, None).await
}

/// Runs a hosted capture after placing a short-lived admission ticket in the
/// bounded outer notary prelude. The ticket is never included in evidence.
pub async fn deferred_streaming_request_to_admitted(
    notary: &NotaryEndpoint,
    server_name: &str,
    capture: DeferredCaptureConfig,
    request: Request<HttpRequestBody>,
    admission_ticket: &str,
) -> Result<DeferredStreamResponse> {
    deferred_streaming_request_to_with_admission(
        notary,
        server_name,
        capture,
        request,
        Some(admission_ticket),
    )
    .await
}

async fn deferred_streaming_request_to_with_admission(
    notary: &NotaryEndpoint,
    server_name: &str,
    capture: DeferredCaptureConfig,
    request: Request<HttpRequestBody>,
    admission_ticket: Option<&str>,
) -> Result<DeferredStreamResponse> {
    validate_notary_frame_limit(capture.max_frame_bytes)?;
    let mut attestable_budget = AttestableHttpBudget::new(capture.max_attestable_http_bytes)?;
    attestable_budget.reserve(
        attestable_request_header_bytes(request.method(), request.uri(), request.headers())?,
        "provider request headers",
    )?;
    attestable_budget.reserve(capture.request_body_bytes, "provider request body")?;
    let notary_socket = connect_notary(notary, NOTARY_MODE_CAPTURE, admission_ticket).await?;

    let session = Session::new(notary_socket);
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
            tracing::debug!(%error, "deferred upstream HTTP/1 connection ended");
        }
    });

    let response: Response<Incoming> = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    attestable_budget.reserve(
        attestable_response_header_bytes(parts.status, &parts.headers)?,
        "provider response headers",
    )?;
    let (body_sender, body_receiver) = mpsc::channel(16);
    let (bundle_sender, bundle_receiver) = oneshot::channel();
    let server_name = server_name.to_owned();
    tokio::spawn(async move {
        let stream_result: Result<()> = async {
            let mut body = body;
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    attestable_budget.reserve(data.len(), "provider response body")?;
                    let _ = body_sender.send(Ok(data)).await;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = stream_result {
            let _ = body_sender
                .send(Err(io::Error::other(error.to_string())))
                .await;
            drop(body_sender);
            let _ = bundle_sender.send(Err(error));
            return;
        }

        complete_deferred_response(body_sender, bundle_sender, async {
            let prover = prover_task.await??;
            let tls_transcript = prover.tls_transcript().clone();
            let handshake_data = handshake_data(&tls_transcript)?;
            let state = prover.into_deferred(rand::random()).await?;
            ensure_attestable_http_bytes(state.transcript(), capture.max_attestable_http_bytes)?;
            let request = DeferredCaptureRequest {
                root_binding: state.root_binding(),
                record_digest: state.record_digest(),
            };
            handle.close();
            let mut socket = driver_task.await??;
            write_frame(
                &mut socket,
                &bincode::serialize(&request)?,
                capture.max_frame_bytes,
            )
            .await?;
            let receipt: DeferredReceipt =
                bincode::deserialize(&read_frame(&mut socket, capture.max_frame_bytes).await?)?;
            if receipt.server_name() != server_name {
                bail!("notary receipt provider does not match capture provider");
            }
            DeferredBundle::new(
                receipt,
                capture.capture_id,
                capture.provider_name,
                capture.created_at_unix_ms,
                handshake_data,
                &state,
            )
        })
        .await;
    });

    Ok(DeferredStreamResponse {
        status: parts.status,
        headers: parts.headers,
        body: body_receiver,
        bundle: bundle_receiver,
    })
}

/// Completes the expensive private proof for a previously captured bundle and
/// returns ordinary TLSNotary evidence suitable for deterministic OTLP
/// normalization.
pub async fn finalize_deferred_bundle(
    notary_addr: SocketAddr,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
) -> Result<LocalProof> {
    let endpoint = NotaryEndpoint::new(
        notary_addr.ip().to_string(),
        notary_addr.port(),
        NotaryTransport::Tcp,
    )?;
    finalize_deferred_bundle_to(
        &endpoint,
        bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
    )
    .await
}

/// Completes a deferred proof through a raw-TCP or public-CA TLS notary
/// endpoint.
pub async fn finalize_deferred_bundle_to(
    notary: &NotaryEndpoint,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
) -> Result<LocalProof> {
    finalize_deferred_bundle_to_with_progress(
        notary,
        bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
        &|_| {},
    )
    .await
}

/// Completes a deferred proof and reports stable proof-pipeline milestones.
pub async fn finalize_deferred_bundle_to_with_progress(
    notary: &NotaryEndpoint,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
    progress: FinalizationProgressObserver<'_>,
) -> Result<LocalProof> {
    finalize_deferred_bundle_to_with_admission(
        notary,
        bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
        None,
        progress,
    )
    .await
}

/// Finalizes a hosted bundle using a one-time ticket bound to the bundle's
/// immutable record digest and requested allowance.
pub async fn finalize_deferred_bundle_to_admitted(
    notary: &NotaryEndpoint,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
    admission_ticket: &str,
) -> Result<LocalProof> {
    finalize_deferred_bundle_to_admitted_with_progress(
        notary,
        bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
        admission_ticket,
        &|_| {},
    )
    .await
}

/// Completes an admitted deferred proof and reports stable milestones.
pub async fn finalize_deferred_bundle_to_admitted_with_progress(
    notary: &NotaryEndpoint,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
    admission_ticket: &str,
    progress: FinalizationProgressObserver<'_>,
) -> Result<LocalProof> {
    finalize_deferred_bundle_to_with_admission(
        notary,
        bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
        Some(admission_ticket),
        progress,
    )
    .await
}

async fn finalize_deferred_bundle_to_with_admission(
    notary: &NotaryEndpoint,
    bundle: &DeferredBundle,
    trusted_notary_key: &[u8],
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
    admission_ticket: Option<&str>,
    progress: FinalizationProgressObserver<'_>,
) -> Result<LocalProof> {
    validate_notary_frame_limit(max_frame_bytes)?;
    AttestableHttpBudget::new(max_attestable_http_bytes)?;
    bundle.receipt.verify(trusted_notary_key)?;
    let state = bundle.checkpoint()?;
    let transcript_commit =
        deferred_transcript_commit(state.transcript(), max_attestable_http_bytes)?;
    let mut request_config_builder = RequestConfig::builder();
    request_config_builder.transcript_commit(transcript_commit.clone());
    let request_config = request_config_builder.build()?;
    let mut prove_config_builder = ProveConfig::builder(state.transcript());
    prove_config_builder.transcript_commit(transcript_commit);
    prove_config_builder.chunked_private_commitments(CHUNKED_PROOF_BYTES)?;
    let prove_config = prove_config_builder.build()?;

    let mut socket = connect_notary(notary, NOTARY_MODE_FINALIZE, admission_ticket).await?;
    let request = DeferredFinalizeRequest {
        receipt: bundle.receipt.clone(),
        records: state.records().clone(),
        prove_request: prove_config.to_request(),
    };
    write_frame(&mut socket, &bincode::serialize(&request)?, max_frame_bytes).await?;

    let session = Session::new(socket);
    let mut prover_context = session.new_context()?;
    let (driver, handle) = session.split();
    let driver_task = tokio::spawn(driver);
    progress(FinalizationProgress::Phase(FinalizationPhase::Proving));
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = state
        .prove_with_progress(
            &mut prover_context,
            &prove_config,
            CHUNKED_PROOF_BYTES,
            &|value| {
                progress(FinalizationProgress::Proof(FinalizationProofProgress {
                    bytes_completed: value.bytes_completed as u64,
                    bytes_total: value.bytes_total as u64,
                    commitments_completed: value.commitments_completed as u64,
                    commitments_total: value.commitments_total as u64,
                }));
            },
        )
        .await?;

    progress(FinalizationProgress::Phase(FinalizationPhase::Signing));
    let mut attestation_builder = AttestationRequest::builder(&request_config);
    attestation_builder
        .server_name(ServerName::Dns(
            bundle.receipt.server_name.as_str().try_into()?,
        ))
        .handshake_data(bundle.handshake_data.clone())
        .transcript(state.transcript().clone())
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (attestation_request, secrets) = attestation_builder.build(&CryptoProvider::default())?;
    handle.close();
    let mut socket = driver_task.await??;
    write_frame(
        &mut socket,
        &bincode::serialize(&attestation_request)?,
        max_frame_bytes,
    )
    .await?;
    let attestation: Attestation =
        bincode::deserialize(&read_frame(&mut socket, max_frame_bytes).await?)?;
    attestation_request.validate(&attestation, &CryptoProvider::default())?;
    Ok(LocalProof {
        server_name: bundle.receipt.server_name.clone(),
        attestation: bincode::serialize(&attestation)?,
        secrets: bincode::serialize(&secrets)?,
    })
}

/// Dispatches one versioned notary control connection.
pub async fn run_notary_session(
    mut socket: TcpStream,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
) -> Result<()> {
    validate_notary_frame_limit(max_frame_bytes)?;
    let prelude = read_notary_session_prelude(&mut socket).await?;
    write_notary_admission(&mut socket, &prelude, Ok(())).await?;
    run_notary_session_after_prelude(
        socket,
        prelude.mode(),
        signing_key,
        allowed_hosts,
        max_private_chunk_bytes,
        max_total_private_chunk_bytes,
        max_private_chunk_commitments,
        max_frame_bytes,
    )
    .await
}

/// Reads and validates the short versioned prelude before expensive protocol
/// admission. Public servers should apply a short timeout around this call.
pub async fn read_notary_session_mode(socket: &mut TcpStream) -> Result<NotarySessionMode> {
    Ok(read_notary_session_prelude(socket).await?.mode())
}

/// Reads and validates a versioned session prelude. The generic helper accepts
/// v1 and v2 for explicit self-hosted callers; v3 adds a hosted admission
/// ticket. Hosted servers use `read_hosted_notary_session_prelude` instead.
pub async fn read_notary_session_prelude(socket: &mut TcpStream) -> Result<NotarySessionPrelude> {
    let (version, mode, admission_ticket) = read_notary_prelude(socket).await?;
    let mode = match mode {
        NOTARY_MODE_CAPTURE => NotarySessionMode::Capture,
        NOTARY_MODE_FINALIZE => NotarySessionMode::Finalize,
        _ => bail!("unsupported notary control mode"),
    };
    Ok(NotarySessionPrelude {
        mode,
        admission_response: version >= 2,
        admission_ticket,
    })
}

/// Reads the mandatory hosted prelude. Unlike the generic protocol helper,
/// this rejects legacy clients before any TLSNotary work begins.
pub async fn read_hosted_notary_session_prelude(
    socket: &mut TcpStream,
) -> Result<NotarySessionPrelude> {
    let prelude = read_notary_session_prelude(socket).await?;
    if prelude.admission_ticket.is_none() {
        bail!("hosted notary admission ticket is required");
    }
    Ok(prelude)
}

/// Sends the v2/v3 admission response after the server has applied its cheap
/// policy and capacity checks. A v1 client receives no bytes so explicit
/// self-hosted sessions remain wire-compatible.
pub async fn write_notary_admission(
    socket: &mut TcpStream,
    prelude: &NotarySessionPrelude,
    result: Result<(), NotaryAdmissionRejection>,
) -> Result<()> {
    if !prelude.admission_response {
        return Ok(());
    }
    match result {
        Ok(()) => socket.write_all(&[NOTARY_ADMISSION_ACCEPTED]).await?,
        Err(rejection) => {
            socket
                .write_all(&[NOTARY_ADMISSION_REJECTED, rejection.wire_code()])
                .await?;
            socket
                .write_all(&(NOTARY_CAPACITY_RETRY_AFTER_SECS as u32).to_be_bytes())
                .await?;
        }
    }
    socket.flush().await?;
    Ok(())
}

/// Runs a notary session after its prelude has been validated and consumed.
#[allow(clippy::too_many_arguments)]
pub async fn run_notary_session_after_prelude(
    socket: TcpStream,
    mode: NotarySessionMode,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
) -> Result<()> {
    run_notary_session_with_limits(
        socket,
        mode,
        signing_key,
        allowed_hosts,
        max_private_chunk_bytes,
        max_total_private_chunk_bytes,
        max_private_chunk_commitments,
        max_frame_bytes,
        None,
        None,
        None,
    )
    .await
    .map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedNotarySessionResult {
    /// Authenticated TLS application-data ciphertext bytes in both directions.
    pub authenticated_transcript_bytes: usize,
}

/// Persists the authenticated capture size before the notary returns its
/// receipt. Hosted services use this to make exact allowance settlement
/// recoverable across coordinator outages and process restarts.
pub type HostedCaptureSettlementRecorder = Box<dyn FnOnce(usize) -> Result<()> + Send>;

/// Runs a coordinator-admitted hosted session with effective limits already
/// intersected with the notary's process-local maxima.
pub async fn run_hosted_notary_session_after_prelude(
    socket: TcpStream,
    mode: NotarySessionMode,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    limits: HostedNotarySessionLimits,
    capture_settlement_recorder: Option<HostedCaptureSettlementRecorder>,
) -> Result<HostedNotarySessionResult> {
    let authenticated_transcript_bytes = run_notary_session_with_limits(
        socket,
        mode,
        signing_key,
        allowed_hosts,
        limits.max_private_chunk_bytes,
        limits.max_total_private_chunk_bytes,
        limits.max_private_chunk_commitments,
        limits.max_frame_bytes,
        limits.expected_record_digest,
        limits.expected_transcript_bytes,
        capture_settlement_recorder,
    )
    .await?;
    Ok(HostedNotarySessionResult {
        authenticated_transcript_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_notary_session_with_limits(
    socket: TcpStream,
    mode: NotarySessionMode,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
    expected_record_digest: Option<[u8; 32]>,
    expected_transcript_bytes: Option<usize>,
    capture_settlement_recorder: Option<HostedCaptureSettlementRecorder>,
) -> Result<usize> {
    validate_notary_frame_limit(max_frame_bytes)?;
    match mode {
        NotarySessionMode::Capture => {
            run_deferred_capture_session(
                socket,
                signing_key,
                allowed_hosts,
                max_total_private_chunk_bytes,
                max_frame_bytes,
                capture_settlement_recorder,
            )
            .await
        }
        NotarySessionMode::Finalize => {
            run_deferred_finalize_session(
                socket,
                signing_key,
                max_private_chunk_bytes,
                max_total_private_chunk_bytes,
                max_private_chunk_commitments,
                max_frame_bytes,
                expected_record_digest,
                expected_transcript_bytes,
            )
            .await
        }
    }
}

async fn run_deferred_capture_session(
    socket: TcpStream,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_transcript_bytes: usize,
    max_frame_bytes: usize,
    capture_settlement_recorder: Option<HostedCaptureSettlementRecorder>,
) -> Result<usize> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let (verifier, server_name) = match handle
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore::mozilla())
                .build()?,
        )?
        .commit()
        .await?
    {
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
            let upstream = TcpStream::connect((server_name.as_str(), 443)).await?;
            upstream.set_nodelay(true)?;
            (
                verifier.accept().await?.run(upstream.compat()).await?,
                server_name,
            )
        }
    };
    let tls_transcript = verifier.tls_transcript().clone();
    let transcript_bytes = application_data_bytes(tls_transcript.sent())?
        .checked_add(application_data_bytes(tls_transcript.recv())?)
        .ok_or_else(|| anyhow!("TLS application-data byte count overflow"))?;
    if transcript_bytes > max_transcript_bytes {
        bail!(
            "TLS application data exceeds the authorized {max_transcript_bytes}-byte session limit"
        );
    }
    let (_, connection_info, server_ephemeral_key) =
        verified_connection_metadata(&tls_transcript, &server_name)?;
    let deferred = verifier.into_deferred().await?;

    handle.close();
    let mut socket = driver_task.await??;
    let request: DeferredCaptureRequest =
        bincode::deserialize(&read_frame(&mut socket, max_frame_bytes).await?)?;
    if request.root_binding != deferred.root_binding()
        || request.record_digest != deferred.record_digest()
    {
        bail!("client deferred checkpoint does not match notary session state");
    }
    if let Some(record_settlement) = capture_settlement_recorder {
        record_settlement(transcript_bytes)
            .context("persisting hosted capture allowance settlement")?;
    }
    let receipt = issue_deferred_receipt(
        &signing_key,
        server_name,
        deferred.root_binding(),
        deferred.records(),
        connection_info,
        server_ephemeral_key,
    )?;
    write_frame(&mut socket, &bincode::serialize(&receipt)?, max_frame_bytes).await?;
    Ok(transcript_bytes)
}

fn application_data_bytes(records: &[tlsn::transcript::Record]) -> Result<usize> {
    records
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .try_fold(0usize, |total, record| {
            total
                .checked_add(record.ciphertext.len())
                .ok_or_else(|| anyhow!("TLS application-data byte count overflow"))
        })
}

#[allow(clippy::too_many_arguments)]
async fn run_deferred_finalize_session(
    mut socket: TcpStream,
    signing_key: Arc<SigningKey>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
    expected_record_digest: Option<[u8; 32]>,
    expected_transcript_bytes: Option<usize>,
) -> Result<usize> {
    let request: DeferredFinalizeRequest =
        bincode::deserialize(&read_tokio_frame(&mut socket, max_frame_bytes).await?)?;
    request
        .receipt
        .verify(signing_key.verifying_key().to_sec1_bytes().as_ref())?;
    request.receipt.validate_records(&request.records)?;
    if expected_record_digest.is_some_and(|expected| expected != request.receipt.record_digest) {
        bail!("finalization bundle does not match its admission authorization");
    }
    let transcript_bytes =
        checked_transcript_allowance(&request.receipt.connection_info.transcript_length)?;
    if expected_transcript_bytes.is_some_and(|expected| expected != transcript_bytes) {
        bail!("finalization bundle length does not match its admission authorization");
    }
    validate_deferred_request_limits(
        &request.prove_request,
        max_private_chunk_bytes,
        max_total_private_chunk_bytes,
        max_private_chunk_commitments,
    )?;

    let session = Session::new(socket.compat());
    let mut verifier_context = session.new_context()?;
    let (driver, handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let verifier =
        tlsn::deferred::DeferredVerifierState::new(request.receipt.root_binding, request.records);
    let output = verifier
        .verify(
            &mut verifier_context,
            &request.prove_request,
            Some(ServerName::Dns(
                request.receipt.server_name.as_str().try_into()?,
            )),
            max_private_chunk_bytes,
        )
        .await?;
    handle.close();
    let mut socket = driver_task.await??;
    let attestation_request: AttestationRequest =
        bincode::deserialize(&read_frame(&mut socket, max_frame_bytes).await?)?;
    let attestation = sign_attestation(
        &signing_key,
        attestation_request,
        request.receipt.connection_info,
        request.receipt.server_ephemeral_key,
        output.transcript_commitments,
    )?;
    write_frame(
        &mut socket,
        &bincode::serialize(&attestation)?,
        max_frame_bytes,
    )
    .await?;
    Ok(transcript_bytes)
}

fn sign_attestation(
    signing_key: &SigningKey,
    request: AttestationRequest,
    connection_info: ConnectionInfo,
    server_ephemeral_key: ServerEphemKey,
    transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
) -> Result<Attestation> {
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);
    let config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()))
        .build()?;
    let mut builder = Attestation::builder(&config).accept_request(request)?;
    builder
        .connection_info(connection_info)
        .server_ephemeral_key(server_ephemeral_key)
        .transcript_commitments(transcript_commitments);
    Ok(builder.build(&provider)?)
}

fn validate_deferred_request_limits(
    request: &tlsn::config::prove::ProveRequest,
    max_chunk_bytes: usize,
    max_total_bytes: usize,
    max_commitments: usize,
) -> Result<()> {
    let Some(commitments) = request.transcript_commit() else {
        bail!("deferred proof requires transcript commitments");
    };
    let mut count = 0usize;
    let mut total = 0usize;
    for (_, range, _) in commitments.iter_hash() {
        count += 1;
        total = total
            .checked_add(range.len())
            .ok_or_else(|| anyhow!("deferred proof byte count overflow"))?;
        if range.len() > max_chunk_bytes || total > max_total_bytes || count > max_commitments {
            bail!("deferred proof request exceeds notary resource limits");
        }
    }
    if count == 0 {
        bail!("deferred proof requires hash commitments");
    }
    Ok(())
}

struct DisclosedPresentation {
    presentation: tlsn::attestation::presentation::Presentation,
    request_disclosed: Vec<u8>,
    response: Vec<u8>,
    connection_time_unix_seconds: u64,
}

/// Creates a selectively disclosed presentation that reveals the request and
/// response while redacting configured authentication, cookie, and session
/// header values.
fn make_disclosed_presentation_with_provider(
    proof: &LocalProof,
    provider: &CryptoProvider,
) -> Result<DisclosedPresentation> {
    use tlsn::attestation::{Attestation, Secrets, presentation::Presentation};

    let attestation: Attestation = bincode::deserialize(&proof.attestation)?;
    let secrets: Secrets = bincode::deserialize(&proof.secrets)?;
    let transcript = HttpTranscript::parse(secrets.transcript())?;
    let ranges = disclosed_http_ranges(&transcript, "in proof")?;

    let mut builder = secrets.transcript_proof_builder();
    builder.reveal_sent(ranges.sent.iter())?;
    builder.reveal_recv(ranges.received.iter())?;
    let transcript_proof = builder.build()?;

    let mut presentation_builder = attestation.presentation_builder(provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation_builder.build()?;

    let output = presentation.clone().verify(provider)?;
    let connection_time_unix_seconds = output.connection_info.time;
    let partial = output
        .transcript
        .ok_or_else(|| anyhow!("locally built presentation omitted transcript"))?;
    Ok(DisclosedPresentation {
        presentation,
        request_disclosed: partial.sent_unsafe().to_vec(),
        response: partial.received_unsafe().to_vec(),
        connection_time_unix_seconds,
    })
}

/// Builds source evidence for a finalized trace package. The request stores
/// only the verifiable disclosure, so an API key cannot be recovered from the
/// resulting package.
pub fn make_capture(
    proof: &LocalProof,
    capture_id: String,
    provider_name: String,
) -> Result<Capture> {
    make_capture_with_provider(proof, capture_id, provider_name, &CryptoProvider::default())
}

fn make_capture_with_provider(
    proof: &LocalProof,
    capture_id: String,
    provider_name: String,
    crypto_provider: &CryptoProvider,
) -> Result<Capture> {
    validate_capture_id(&capture_id)?;
    validate_provider_name(&provider_name, &proof.server_name)?;
    let presentation_build_started = Instant::now();
    let disclosed = make_disclosed_presentation_with_provider(proof, crypto_provider)?;
    tracing::info!(
        presentation_build_ms = presentation_build_started.elapsed().as_millis(),
        request_disclosed_bytes = disclosed.request_disclosed.len(),
        response_bytes = disclosed.response.len(),
        "built selectively disclosed local presentation"
    );
    let evidence = bincode::serialize(&disclosed.presentation)?;
    let created_at_unix_ms = disclosed
        .connection_time_unix_seconds
        .checked_mul(1000)
        .context("authenticated TLS connection timestamp does not fit in milliseconds")?;
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

/// Verifies in-memory source evidence before it is included in a trace package.
pub fn verify_capture_value(
    capture: &Capture,
    trusted_notary_key: &[u8],
) -> Result<(CaptureManifest, String, String)> {
    verify_capture_value_with_provider(capture, trusted_notary_key, &CryptoProvider::default())
}

fn verify_capture_value_with_provider(
    capture: &Capture,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<(CaptureManifest, String, String)> {
    use tlsn::attestation::presentation::{Presentation, PresentationOutput};

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
        connection_info,
        transcript,
        ..
    } = presentation.verify(crypto_provider)?;
    let server_name = server_name.ok_or_else(|| anyhow!("presentation omitted server identity"))?;
    if server_name.to_string() != capture.manifest.provider.host {
        bail!("capture provider host does not match the presentation");
    }
    validate_provider_name(
        &capture.manifest.provider.name,
        &capture.manifest.provider.host,
    )?;
    if capture.manifest.created_at_unix_ms
        != connection_info
            .time
            .checked_mul(1000)
            .context("authenticated TLS connection timestamp does not fit in milliseconds")?
    {
        bail!("capture timestamp does not match the authenticated TLS connection");
    }
    let transcript = transcript.ok_or_else(|| anyhow!("presentation omitted transcript"))?;
    if transcript.sent_unsafe() != capture.request_disclosed
        || transcript.received_unsafe() != capture.response
    {
        bail!("capture HTTP artifacts do not match the authenticated presentation");
    }
    validate_disclosed_http_redactions(&capture.request_disclosed, &capture.response)?;
    Ok((
        capture.manifest.clone(),
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

fn validate_provider_name(provider_name: &str, host: &str) -> Result<()> {
    let expected = match host {
        "api.openai.com" => "openai",
        "chatgpt.com" => "openai",
        "api.anthropic.com" => "anthropic",
        "api.deepseek.com" => "deepseek",
        "openrouter.ai" => "openrouter",
        // Non-production test fixtures and explicitly configured future hosts
        // use their authenticated DNS name as the unambiguous provider label.
        other => other,
    };
    if provider_name != expected {
        bail!(
            "provider name {provider_name:?} does not match authenticated host {host:?}; expected {expected:?}"
        );
    }
    Ok(())
}

#[cfg(feature = "cli")]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating private artifact {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing private artifact {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing private artifact {}", path.display()))?;
    restrict_file(path)
}

#[cfg(all(feature = "cli", unix))]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting capture artifact {}", path.display()))
}

#[cfg(all(feature = "cli", not(unix)))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn handshake_data(transcript: &tlsn::transcript::TlsTranscript) -> Result<HandshakeData> {
    Ok(HandshakeData {
        certs: transcript
            .server_cert_chain()
            .ok_or_else(|| anyhow!("missing upstream certificate chain"))?
            .to_vec(),
        sig: transcript
            .server_signature()
            .ok_or_else(|| anyhow!("missing upstream certificate signature"))?
            .clone(),
        binding: transcript.certificate_binding().clone(),
    })
}

fn verified_connection_metadata(
    transcript: &tlsn::transcript::TlsTranscript,
    server_name: &str,
) -> Result<(HandshakeData, ConnectionInfo, ServerEphemKey)> {
    verified_connection_metadata_with_roots(transcript, server_name, &RootCertStore::mozilla())
}

fn verified_connection_metadata_with_roots(
    transcript: &tlsn::transcript::TlsTranscript,
    server_name: &str,
    roots: &RootCertStore,
) -> Result<(HandshakeData, ConnectionInfo, ServerEphemKey)> {
    let handshake = handshake_data(transcript)?;
    let CertBinding::V1_2(binding) = transcript.certificate_binding() else {
        bail!("unsupported TLS certificate binding");
    };
    let name = ServerName::Dns(server_name.try_into()?);
    let cert_verifier = tlsn::verifier::ServerCertVerifier::new(roots)?;
    handshake.verify(
        &cert_verifier,
        transcript.time(),
        &binding.server_ephemeral_key,
        &name,
    )?;
    let sent = transcript
        .sent()
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.ciphertext.len())
        .sum::<usize>();
    let received = transcript
        .recv()
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.ciphertext.len())
        .sum::<usize>();
    Ok((
        handshake,
        ConnectionInfo {
            time: transcript.time(),
            version: transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent.try_into().context("sent transcript too large")?,
                received: received
                    .try_into()
                    .context("received transcript too large")?,
            },
        },
        binding.server_ephemeral_key.clone(),
    ))
}

async fn connect_notary(
    notary: &NotaryEndpoint,
    mode: u8,
    admission_ticket: Option<&str>,
) -> Result<NotaryIo> {
    if admission_ticket.is_some()
        && notary.transport == NotaryTransport::Tcp
        && !matches!(notary.host.as_str(), "127.0.0.1" | "::1" | "localhost")
    {
        bail!("hosted admission tickets require outer TLS except on loopback");
    }
    let socket = TcpStream::connect((notary.host.as_str(), notary.port))
        .await
        .with_context(|| format!("connecting to notary at {notary}"))?;
    socket.set_nodelay(true)?;

    match notary.transport {
        NotaryTransport::Tcp => {
            let mut socket = socket;
            write_selected_notary_prelude(&mut socket, mode, admission_ticket).await?;
            read_notary_admission(&mut socket).await?;
            Ok(Box::new(socket.compat()))
        }
        NotaryTransport::Tls => {
            let mut socket = connect_notary_tls(&notary.host, socket, default_notary_tls_config())
                .await
                .with_context(|| format!("validating TLS for notary at {notary}"))?;
            write_selected_notary_prelude(&mut socket, mode, admission_ticket).await?;
            read_notary_admission(&mut socket).await?;
            Ok(Box::new(socket.compat()))
        }
    }
}

fn default_notary_tls_config() -> Arc<ClientConfig> {
    let roots = OuterRootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .expect("AWS-LC supports Rustls default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

async fn connect_notary_tls(
    host: &str,
    socket: TcpStream,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = TlsServerName::try_from(host.to_owned())
        .context("notary TLS endpoint has an invalid server name")?;
    TlsConnector::from(config)
        .connect(server_name, socket)
        .await
        .context("performing notary TLS handshake")
}

async fn write_notary_prelude<S: tokio::io::AsyncWrite + Unpin>(
    socket: &mut S,
    mode: u8,
) -> Result<()> {
    socket.write_all(NOTARY_CONTROL_MAGIC_V2).await?;
    socket.write_all(&[mode]).await?;
    socket.flush().await?;
    Ok(())
}

async fn write_selected_notary_prelude<S: tokio::io::AsyncWrite + Unpin>(
    socket: &mut S,
    mode: u8,
    admission_ticket: Option<&str>,
) -> Result<()> {
    let Some(ticket) = admission_ticket else {
        return write_notary_prelude(socket, mode).await;
    };
    if ticket.is_empty() || ticket.len() > MAX_NOTARY_ADMISSION_TICKET_BYTES {
        bail!("hosted admission ticket length is invalid");
    }
    socket.write_all(NOTARY_CONTROL_MAGIC_V3).await?;
    socket.write_all(&[mode]).await?;
    socket
        .write_all(&(ticket.len() as u16).to_be_bytes())
        .await?;
    socket.write_all(ticket.as_bytes()).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_notary_prelude(socket: &mut TcpStream) -> Result<(u8, u8, Option<String>)> {
    let mut magic = [0u8; NOTARY_CONTROL_MAGIC_V2.len()];
    socket.read_exact(&mut magic).await?;
    let version = if &magic == NOTARY_CONTROL_MAGIC_V1 {
        1
    } else if &magic == NOTARY_CONTROL_MAGIC_V2 {
        2
    } else if &magic == NOTARY_CONTROL_MAGIC_V3 {
        3
    } else {
        bail!("invalid notary control protocol prelude");
    };
    let mut mode = [0u8; 1];
    socket.read_exact(&mut mode).await?;
    let admission_ticket = if version == 3 {
        let mut length = [0u8; 2];
        socket.read_exact(&mut length).await?;
        let length = u16::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_NOTARY_ADMISSION_TICKET_BYTES {
            bail!("hosted admission ticket length is invalid");
        }
        let mut ticket = vec![0; length];
        socket.read_exact(&mut ticket).await?;
        let ticket = String::from_utf8(ticket).context("hosted admission ticket is not UTF-8")?;
        Some(ticket)
    } else {
        None
    };
    Ok((version, mode[0], admission_ticket))
}

async fn read_notary_admission<S: tokio::io::AsyncRead + Unpin>(socket: &mut S) -> Result<()> {
    let mut status = [0u8; 1];
    socket.read_exact(&mut status).await?;
    match status[0] {
        NOTARY_ADMISSION_ACCEPTED => Ok(()),
        NOTARY_ADMISSION_REJECTED => {
            let mut rejection = [0u8; 1];
            socket.read_exact(&mut rejection).await?;
            let mut retry_after_secs = [0u8; 4];
            socket.read_exact(&mut retry_after_secs).await?;
            Err(NotaryAdmissionError {
                rejection: NotaryAdmissionRejection::from_wire(rejection[0])?,
                retry_after: std::time::Duration::from_secs(
                    u32::from_be_bytes(retry_after_secs) as u64
                ),
            }
            .into())
        }
        _ => bail!("invalid notary admission response"),
    }
}

async fn read_tokio_frame(socket: &mut TcpStream, max_frame_bytes: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    validate_frame_length(length, max_frame_bytes)?;
    let mut value = vec![0; length];
    socket.read_exact(&mut value).await?;
    Ok(value)
}

async fn write_frame<S: futures::AsyncWrite + Unpin>(
    socket: &mut S,
    value: &[u8],
    max_frame_bytes: usize,
) -> Result<()> {
    validate_frame_length(value.len(), max_frame_bytes)?;
    socket
        .write_all(&(value.len() as u32).to_be_bytes())
        .await?;
    socket.write_all(value).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_frame<S: futures::AsyncRead + Unpin>(
    socket: &mut S,
    max_frame_bytes: usize,
) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    socket.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    validate_frame_length(length, max_frame_bytes)?;
    let mut value = vec![0u8; length];
    socket.read_exact(&mut value).await?;
    Ok(value)
}

fn validate_notary_frame_limit(max_frame_bytes: usize) -> Result<()> {
    if max_frame_bytes == 0 || max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    Ok(())
}

fn validate_frame_length(length: usize, max_frame_bytes: usize) -> Result<()> {
    if length > max_frame_bytes {
        bail!("refusing {length}-byte notary frame above configured {max_frame_bytes}-byte limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cli")]
    use std::time::{SystemTime, UNIX_EPOCH};
    use tls_server_fixture::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
    use tlsn::rangeset::ops::Set;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn v2_admission_rejection_is_typed_and_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let prelude = read_notary_session_prelude(&mut socket).await.unwrap();
            assert_eq!(prelude.mode(), NotarySessionMode::Capture);
            write_notary_admission(
                &mut socket,
                &prelude,
                Err(NotaryAdmissionRejection::CaptureAtCapacity),
            )
            .await
            .unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        write_notary_prelude(&mut client, NOTARY_MODE_CAPTURE)
            .await
            .unwrap();
        let error = read_notary_admission(&mut client).await.unwrap_err();
        let admission = error.downcast_ref::<NotaryAdmissionError>().unwrap();
        assert_eq!(
            admission.rejection(),
            NotaryAdmissionRejection::CaptureAtCapacity
        );
        assert_eq!(
            admission.retry_after(),
            std::time::Duration::from_secs(NOTARY_CAPACITY_RETRY_AFTER_SECS)
        );
        server.await.unwrap();
    }

    #[test]
    fn hosted_policy_rejections_have_stable_wire_codes() {
        for (rejection, code) in [
            (
                NotaryAdmissionRejection::CaptureCreditsExhausted,
                "capture_credits_exhausted",
            ),
            (
                NotaryAdmissionRejection::FinalizationCreditsExhausted,
                "finalization_credits_exhausted",
            ),
        ] {
            assert_eq!(rejection.code(), code);
            assert_eq!(
                NotaryAdmissionRejection::from_wire(rejection.wire_code()).unwrap(),
                rejection
            );
        }
    }

    #[tokio::test]
    async fn v3_hosted_prelude_carries_a_bounded_redacted_ticket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let prelude = read_hosted_notary_session_prelude(&mut socket)
                .await
                .unwrap();
            assert_eq!(prelude.mode(), NotarySessionMode::Capture);
            assert_eq!(prelude.admission_ticket(), Some("one-time-ticket"));
            let debug = format!("{prelude:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("one-time-ticket"));
            write_notary_admission(&mut socket, &prelude, Ok(()))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        write_selected_notary_prelude(&mut client, NOTARY_MODE_CAPTURE, Some("one-time-ticket"))
            .await
            .unwrap();
        read_notary_admission(&mut client).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hosted_reader_rejects_legacy_and_ticket_writer_rejects_oversize() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            assert!(
                read_hosted_notary_session_prelude(&mut socket)
                    .await
                    .is_err()
            );
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        write_notary_prelude(&mut client, NOTARY_MODE_CAPTURE)
            .await
            .unwrap();
        server.await.unwrap();

        let mut sink = tokio::io::sink();
        assert!(
            write_selected_notary_prelude(
                &mut sink,
                NOTARY_MODE_CAPTURE,
                Some(&"x".repeat(MAX_NOTARY_ADMISSION_TICKET_BYTES + 1)),
            )
            .await
            .is_err()
        );
    }

    fn fixture_notary_tls_config() -> Arc<ClientConfig> {
        let mut roots = OuterRootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                CA_CERT_DER.to_vec(),
            ))
            .unwrap();
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    fn fixture_notary_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
        let cert = rustls::pki_types::CertificateDer::from(SERVER_CERT_DER);
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    #[tokio::test]
    async fn outer_tls_validates_before_the_notary_prelude() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = fixture_notary_tls_acceptor().accept(socket).await.unwrap();
            let mut prelude = [0; NOTARY_CONTROL_MAGIC_V2.len() + 1];
            socket.read_exact(&mut prelude).await.unwrap();
            assert_eq!(
                &prelude[..NOTARY_CONTROL_MAGIC_V2.len()],
                NOTARY_CONTROL_MAGIC_V2
            );
            assert_eq!(prelude[NOTARY_CONTROL_MAGIC_V2.len()], NOTARY_MODE_CAPTURE);
            socket
                .write_all(&[NOTARY_ADMISSION_ACCEPTED])
                .await
                .unwrap();
            socket.flush().await.unwrap();
        });

        let socket = TcpStream::connect(address).await.unwrap();
        let mut socket = connect_notary_tls(SERVER_DOMAIN, socket, fixture_notary_tls_config())
            .await
            .unwrap();
        write_notary_prelude(&mut socket, NOTARY_MODE_CAPTURE)
            .await
            .unwrap();
        read_notary_admission(&mut socket).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn outer_tls_rejects_a_notary_hostname_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = fixture_notary_tls_acceptor().accept(socket).await;
        });

        let socket = TcpStream::connect(address).await.unwrap();
        assert!(
            connect_notary_tls("notary.example", socket, fixture_notary_tls_config())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[test]
    fn attestable_http_budget_is_shared_between_request_and_response() {
        let mut budget = AttestableHttpBudget::new(10).unwrap();
        budget.reserve(6, "provider request").unwrap();
        let error = budget.reserve(5, "provider response").unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider response exceeds the 10-byte maximum attestable HTTP budget"
        );
    }

    #[test]
    fn finalization_allowance_is_the_checked_total_of_signed_transcript_lengths() {
        assert_eq!(
            checked_transcript_allowance(&TranscriptLength {
                sent: 1_024,
                received: 2_048,
            })
            .unwrap(),
            3_072
        );
    }

    #[tokio::test]
    async fn v1_prelude_does_not_receive_an_admission_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let prelude = read_notary_session_prelude(&mut socket).await.unwrap();
            assert_eq!(prelude.mode(), NotarySessionMode::Finalize);
            write_notary_admission(&mut socket, &prelude, Ok(()))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(NOTARY_CONTROL_MAGIC_V1).await.unwrap();
        client.write_all(&[NOTARY_MODE_FINALIZE]).await.unwrap();
        client.flush().await.unwrap();
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                client.read_exact(&mut byte),
            )
            .await
            .is_err()
        );
        server.await.unwrap();
    }

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
    fn private_artifact_debug_output_is_redacted() {
        let proof = LocalProof {
            server_name: "api.example".to_owned(),
            attestation: b"public-attestation".to_vec(),
            secrets: b"proof-secret-sentinel".to_vec(),
        };
        let proof_debug = format!("{proof:?}");
        assert!(proof_debug.contains("api.example"));
        assert!(proof_debug.contains("<redacted: 18 bytes>"));
        assert!(proof_debug.contains("<redacted: 21 bytes>"));
        assert!(!proof_debug.contains(&format!("{:?}", proof.attestation)));
        assert!(!proof_debug.contains(&format!("{:?}", proof.secrets)));

        let capture = test_capture();
        let capture_debug = format!("{capture:?}");
        assert!(capture_debug.contains(&capture.manifest.capture_id));
        assert!(!capture_debug.contains(&format!("{:?}", capture.evidence)));
        assert!(!capture_debug.contains(&format!("{:?}", capture.request_disclosed)));
        assert!(!capture_debug.contains(&format!("{:?}", capture.response)));
    }

    #[tokio::test]
    async fn request_body_frames_preserve_bytes_and_boundaries() {
        for (length, expected_lengths) in [
            (0, vec![]),
            (1, vec![1]),
            (REQUEST_WRITE_CHUNK, vec![REQUEST_WRITE_CHUNK]),
            (REQUEST_WRITE_CHUNK + 1, vec![REQUEST_WRITE_CHUNK, 1]),
            (
                REQUEST_WRITE_CHUNK * 2,
                vec![REQUEST_WRITE_CHUNK, REQUEST_WRITE_CHUNK],
            ),
        ] {
            let input = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let mut body = chunked_request_body(Bytes::from(input.clone()));
            let mut output = Vec::new();
            let mut actual_lengths = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.unwrap();
                let data = frame
                    .into_data()
                    .unwrap_or_else(|_| panic!("request body emitted a non-data frame"));
                actual_lengths.push(data.len());
                output.extend_from_slice(&data);
            }
            assert_eq!(actual_lengths, expected_lengths);
            assert_eq!(output, input);
        }
    }

    #[test]
    fn disclosed_http_rejects_every_non_allowlisted_header_value() {
        let response = b"HTTP/1.1 200 OK\r\nset-cookie:\0\0\0\r\n\r\n{}";
        assert!(
            validate_disclosed_http_redactions(
                b"POST /v1 HTTP/1.1\r\nauthorization:\0\0\0\r\ncookie: \0\r\n\r\n{}",
                response,
            )
            .is_ok()
        );
        assert!(
            validate_disclosed_http_redactions(
                b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n{}",
                response,
            )
            .is_err()
        );
        assert!(
            validate_disclosed_http_redactions(
                b"POST /v1 HTTP/1.1\r\n\r\n{}",
                b"HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\n\r\n{}",
            )
            .is_err()
        );
        assert!(
            validate_disclosed_http_redactions(
                b"POST /v1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
                b"HTTP/1.1 200 OK\r\n\r\n{}",
            )
            .is_err()
        );
        assert!(
            validate_disclosed_http_redactions(
                b"POST /v1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            )
            .is_ok()
        );
    }

    #[test]
    fn disclosure_header_policy_has_one_exact_value_allowlist() {
        let empty_response = b"HTTP/1.1 200 OK\r\n\r\n{}";
        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key",
            "content-type",
            "content-length",
            "x-request-id",
            "x-organization-id",
            "x-ratelimit-remaining",
        ] {
            let visible = format!("POST /v1 HTTP/1.1\r\n{name}: private-value\r\n\r\n{{}}");
            assert!(
                validate_disclosed_http_redactions(visible.as_bytes(), empty_response).is_err(),
                "{name} must be rejected when its value is visible"
            );
            let redacted = format!("POST /v1 HTTP/1.1\r\n{name}: \0\0\0\r\n\r\n{{}}");
            assert!(
                validate_disclosed_http_redactions(redacted.as_bytes(), empty_response).is_ok(),
                "{name} must remain valid when its value is redacted"
            );
        }

        let empty_request = b"POST /v1 HTTP/1.1\r\n\r\n{}";
        for name in [
            "set-cookie",
            "content-type",
            "content-length",
            "x-request-id",
            "x-ratelimit-limit",
        ] {
            let visible = format!("HTTP/1.1 200 OK\r\n{name}: private-value\r\n\r\n{{}}");
            assert!(
                validate_disclosed_http_redactions(empty_request, visible.as_bytes()).is_err(),
                "{name} must be rejected when its value is visible"
            );
            let redacted = format!("HTTP/1.1 200 OK\r\n{name}: \0\0\0\r\n\r\n{{}}");
            assert!(
                validate_disclosed_http_redactions(empty_request, redacted.as_bytes()).is_ok(),
                "{name} must remain valid when its value is redacted"
            );
        }

        assert!(may_disclose_header_value("Transfer-Encoding", b" chunked "));
        assert!(may_disclose_header_value("transfer-encoding", b"CHUNKED"));
        assert!(!may_disclose_header_value(
            "transfer-encoding",
            b"gzip, chunked"
        ));
        assert!(!may_disclose_header_value("content-type", b"chunked"));
    }

    #[test]
    fn capture_ids_are_single_path_components() {
        assert!(validate_capture_id("cap-01").is_ok());
        assert!(validate_capture_id("../outside").is_err());
        assert!(validate_capture_id("nested/capture").is_err());
        assert!(validate_capture_id("").is_err());
    }

    #[test]
    fn provider_labels_must_match_the_authenticated_host() {
        assert!(validate_provider_name("openai", "api.openai.com").is_ok());
        assert!(validate_provider_name("openai", "chatgpt.com").is_ok());
        assert!(validate_provider_name("anthropic", "api.anthropic.com").is_ok());
        assert!(validate_provider_name("deepseek", "api.deepseek.com").is_ok());
        assert!(validate_provider_name("openrouter", "openrouter.ai").is_ok());
        assert!(validate_provider_name("anthropic", "api.openai.com").is_err());
        assert!(validate_provider_name("openai", "openrouter.ai").is_err());
    }

    #[tokio::test]
    async fn post_stream_sealing_failure_does_not_fail_the_provider_body() {
        let (body_sender, mut body_receiver) = mpsc::channel(2);
        body_sender
            .send(Ok(Bytes::from_static(b"provider-complete")))
            .await
            .unwrap();
        let (bundle_sender, bundle_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel::<()>();
        tokio::spawn(complete_deferred_response(
            body_sender,
            bundle_sender,
            async move {
                let _ = release_receiver.await;
                bail!("receipt failed after provider EOF")
            },
        ));

        assert_eq!(
            body_receiver.recv().await.unwrap().unwrap(),
            Bytes::from_static(b"provider-complete")
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), body_receiver.recv())
                .await
                .unwrap()
                .is_none(),
            "provider EOF must not wait for bundle sealing"
        );
        release_sender.send(()).unwrap();
        assert!(bundle_receiver.await.unwrap().is_err());
    }

    #[test]
    fn chunked_http_commitments_exclude_redacted_header_values() {
        let body = vec![b'x'; 64 << 10];
        let mut sent = b"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer auth-secret\r\nChatGPT-Account-ID: account-routing-secret\r\nX-OpenAI-FedRAMP: fedramp-routing-secret\r\nAnthropic-Beta: oauth-2025-04-20\r\nAnthropic-Version: 2023-06-01\r\nProxy-Authorization: Basic proxy-secret\r\nCookie: session=cookie-secret\r\nx-api-key: key-secret\r\nHTTP-Referer: https://example.test\r\nX-Title: LLM Notary test\r\nContent-Length: 65536\r\n\r\n".to_vec();
        sent.extend_from_slice(&body);
        let mut received =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: session=response-secret\r\nContent-Length: 65536\r\n\r\n"
                .to_vec();
        received.extend_from_slice(&body);
        let transcript = Transcript::new(sent, received);
        let http = HttpTranscript::parse(&transcript).expect("parse HTTP transcript");

        let config = deferred_transcript_commit(&transcript, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)
            .expect("build chunked commitment config");
        let budget_error = deferred_transcript_commit(&transcript, 64)
            .expect_err("commit construction must reject an oversized transcript");
        assert!(
            budget_error
                .to_string()
                .contains("maximum attestable HTTP budget")
        );
        let disclosure =
            disclosed_http_ranges(&http, "in test").expect("derive disclosed HTTP ranges");
        let request = config.to_request();
        let mut committed_sent = RangeSet::default();
        let mut committed_received = RangeSet::default();
        for (direction, ranges, _) in request.iter_hash() {
            match direction {
                Direction::Sent => committed_sent.union_mut(ranges),
                Direction::Received => committed_received.union_mut(ranges),
            }
        }
        assert_eq!(committed_sent, disclosure.sent);
        assert_eq!(committed_received, disclosure.received);
        assert_eq!(
            request.iter_hash().count(),
            2,
            "one bounded commitment should cover each HTTP direction"
        );
        for (direction, ranges, _) in request.iter_hash() {
            let headers = match direction {
                Direction::Sent => &http.requests[0].headers,
                Direction::Received => &http.responses[0].headers,
            };
            for header in headers {
                let disclosed =
                    may_disclose_header_value(&header.name.as_str(), &header.value.as_bytes());
                if !disclosed {
                    assert!(
                        ranges.intersection(header.value.indices()).next().is_none(),
                        "a private commitment must not include non-allowlisted {} values",
                        header.name.as_str()
                    );
                } else {
                    assert!(
                        ranges.intersection(header.value.indices()).next().is_some(),
                        "the chunked transfer-encoding value {} must remain disclosed",
                        header.name.as_str()
                    );
                }
            }
        }
    }

    #[test]
    fn deferred_http_commitments_ignore_interim_responses() {
        let sent = b"POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".to_vec();
        let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
        let final_response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
        let mut received = interim.to_vec();
        received.extend_from_slice(final_response);
        let transcript = Transcript::new(sent, received);
        let http = HttpTranscript::parse(&transcript).expect("parse HTTP transcript");
        assert_eq!(http.responses.len(), 2);

        let config = deferred_transcript_commit(&transcript, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)
            .expect("interim response must not prevent deferred commitments");
        let disclosure =
            disclosed_http_ranges(&http, "in test").expect("derive disclosed HTTP ranges");
        let mut committed_received = RangeSet::default();
        for (direction, ranges, _) in config.to_request().iter_hash() {
            if *direction == Direction::Received {
                committed_received.union_mut(ranges);
            }
        }

        assert_eq!(committed_received, disclosure.received);
        assert!(
            committed_received
                .iter()
                .all(|range| range.start >= interim.len()),
            "interim response bytes must remain undisclosed"
        );

        let upgrade = Transcript::new(
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n".to_vec(),
        );
        let error = deferred_transcript_commit(&upgrade, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)
            .expect_err("protocol upgrades must remain unsupported");
        assert!(error.to_string().contains("101 Switching Protocols"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deferred_bundle_survives_a_disconnected_stateless_notary() {
        use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
        use tlsn::{
            Session,
            config::{
                prover::ProverConfig, tls::TlsClientConfig, tls_commit::proxy::ProxyTlsConfig,
                verifier::VerifierConfig,
            },
            connection::{DnsName, ServerName},
            verifier::VerifierCommitStart,
            webpki::{CertificateDer, RootCertStore},
        };
        use tokio_util::compat::TokioAsyncReadCompatExt;

        fn fixture_roots() -> RootCertStore {
            RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            }
        }

        let signing_key = SigningKey::from_slice(&[9; 32]).unwrap();
        let trusted_public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
        let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
        let mut prover_session = Session::new(prover_socket.compat());
        let mut verifier_session = Session::new(verifier_socket.compat());
        let prover = prover_session
            .new_prover(ProverConfig::builder().build().unwrap())
            .unwrap();
        let verifier = verifier_session
            .new_verifier(
                VerifierConfig::builder()
                    .root_store(fixture_roots())
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let (prover_driver, prover_handle) = prover_session.split();
        let (verifier_driver, verifier_handle) = verifier_session.split();
        tokio::spawn(prover_driver);
        tokio::spawn(verifier_driver);

        let (notary_upstream, fixture_socket) = tokio::io::duplex(2 << 16);
        let fixture_task = tokio::spawn(bind_test_server_hyper(fixture_socket.compat()));
        let prover_task = async {
            let prover = prover
                .commit(
                    ProxyTlsConfig::builder()
                        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
                        .build()
                        .unwrap(),
                )
                .await
                .unwrap();
            let (connection, prover) = prover
                .connect(
                    TlsClientConfig::builder()
                        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                        .root_store(fixture_roots())
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let (mut sender, connection) = hyper::client::conn::http1::handshake::<
                _,
                HttpRequestBody,
            >(TokioIo::new(connection.compat()))
            .await
            .unwrap();
            tokio::spawn(connection);
            let prover_task = tokio::spawn(prover.into_future());
            let response = sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("/echo")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer fixture-secret")
                        .header("cookie", "session=fixture-cookie")
                        .header("x-request-id", "request-fixture-private")
                        .header("openai-organization", "organization-fixture-private")
                        .header("openai-project", "project-fixture-private")
                        .body(chunked_request_body(Bytes::from_static(
                            br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#,
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            let response = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                response,
                Bytes::from_static(
                    br#"{"model":"fixture","messages":[{"role":"user","content":"hello"}],"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#
                )
            );
            drop(sender);
            prover_task
                .await
                .unwrap()
                .unwrap()
                .into_deferred([7; 16])
                .await
                .unwrap()
        };
        let verifier_task = async {
            let verifier = verifier.commit().await.unwrap();
            let VerifierCommitStart::Proxy(verifier) = verifier else {
                unreachable!("the test always uses Proxy-TLS");
            };
            let verifier = verifier
                .accept()
                .await
                .unwrap()
                .run(notary_upstream.compat())
                .await
                .unwrap();
            let tls_transcript = verifier.tls_transcript().clone();
            let (handshake, connection_info, server_ephemeral_key) =
                verified_connection_metadata_with_roots(
                    &tls_transcript,
                    SERVER_DOMAIN,
                    &fixture_roots(),
                )
                .unwrap();
            let deferred = verifier.into_deferred().await.unwrap();
            let receipt = issue_deferred_receipt(
                &signing_key,
                SERVER_DOMAIN.to_owned(),
                deferred.root_binding(),
                // This is the only state the simulated notary uses to issue
                // its receipt; it is discarded before the later proof.
                deferred.records(),
                connection_info,
                server_ephemeral_key,
            )
            .unwrap();
            (receipt, handshake)
        };
        let (state, (receipt, handshake)) = tokio::join!(prover_task, verifier_task);
        prover_handle.close();
        verifier_handle.close();
        fixture_task.await.unwrap().unwrap();

        receipt.verify(&trusted_public_key).unwrap();
        let wrong_key = SigningKey::from_slice(&[8; 32]).unwrap();
        assert!(
            receipt
                .verify(wrong_key.verifying_key().to_sec1_bytes().as_ref())
                .is_err()
        );
        receipt.validate_records(state.records()).unwrap();
        let mut forged = receipt.clone();
        forged.server_name = "attacker.example".to_owned();
        assert!(forged.verify(&trusted_public_key).is_err());

        // This is the durability boundary: no original TLSN session or
        // verifier state remains after this point. Only the client-held bundle
        // is deserialized for a later proof.
        let bundle = DeferredBundle::new(
            receipt.clone(),
            "cap-test".to_owned(),
            SERVER_DOMAIN.to_owned(),
            1,
            handshake,
            &state,
        )
        .unwrap();
        let bundle = bincode::serialize(&bundle).unwrap();
        drop(state);
        let bundle: DeferredBundle = bincode::deserialize(&bundle).unwrap();
        let bundle_debug = format!("{bundle:?}");
        assert!(bundle_debug.contains("cap-test"));
        assert!(bundle_debug.contains(&format!("<redacted: {} bytes>", bundle.checkpoint.len())));
        assert!(!bundle_debug.contains(&format!("{:?}", bundle.checkpoint)));

        let mut record_tampered = bundle.clone();
        *record_tampered.checkpoint.last_mut().unwrap() ^= 1;
        assert!(
            record_tampered
                .checkpoint()
                .err()
                .unwrap()
                .to_string()
                .contains("encrypted application records"),
            "mutated encrypted records must fail the receipt digest check"
        );

        // bincode encodes the fixed-size root binding and salt first, followed
        // by the client-only traffic keys. Changing the first traffic-key byte
        // leaves the signed record digest intact, reaches the fresh proof, and
        // must fail its root-binding check.
        let mut key_tampered = bundle.clone();
        assert!(key_tampered.checkpoint.len() > 48);
        key_tampered.checkpoint[48] ^= 1;
        key_tampered.checkpoint().unwrap();
        let tampered_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tampered_notary_addr = tampered_listener.local_addr().unwrap();
        let tampered_signing_key = signing_key.clone();
        let tampered_finalizer = tokio::spawn(async move {
            let (socket, _) = tampered_listener.accept().await.unwrap();
            run_notary_session(
                socket,
                Arc::new(tampered_signing_key),
                Arc::new(Vec::new()),
                CHUNKED_PROOF_BYTES,
                8 << 20,
                4096,
                DEFAULT_NOTARY_MAX_FRAME_BYTES,
            )
            .await
        });
        assert!(
            finalize_deferred_bundle(
                tampered_notary_addr,
                &key_tampered,
                &trusted_public_key,
                DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
                DEFAULT_NOTARY_MAX_FRAME_BYTES,
            )
            .await
            .is_err(),
            "mutated client traffic keys must fail the fresh private proof"
        );
        assert!(tampered_finalizer.await.unwrap().is_err());

        // A fresh process with the same signing key can finalize the client
        // checkpoint. It has no stored state from the original TLS session.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let notary_addr = listener.local_addr().unwrap();
        let finalizer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            run_notary_session(
                socket,
                Arc::new(signing_key),
                Arc::new(Vec::new()),
                CHUNKED_PROOF_BYTES,
                8 << 20,
                4096,
                DEFAULT_NOTARY_MAX_FRAME_BYTES,
            )
            .await
            .unwrap();
        });
        let endpoint = NotaryEndpoint::new(
            notary_addr.ip().to_string(),
            notary_addr.port(),
            NotaryTransport::Tcp,
        )
        .unwrap();
        let progress_updates = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record_progress = {
            let progress_updates = progress_updates.clone();
            move |progress| progress_updates.lock().unwrap().push(progress)
        };
        let proof = finalize_deferred_bundle_to_with_progress(
            &endpoint,
            &bundle,
            &trusted_public_key,
            DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            DEFAULT_NOTARY_MAX_FRAME_BYTES,
            &record_progress,
        )
        .await
        .unwrap();
        finalizer.await.unwrap();

        let progress_updates = progress_updates.lock().unwrap();
        assert_eq!(
            progress_updates.first(),
            Some(&FinalizationProgress::Phase(FinalizationPhase::Proving))
        );
        assert_eq!(
            progress_updates.last(),
            Some(&FinalizationProgress::Phase(FinalizationPhase::Signing))
        );
        let proof_updates = progress_updates
            .iter()
            .filter_map(|progress| match progress {
                FinalizationProgress::Proof(progress) => Some(*progress),
                FinalizationProgress::Phase(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(proof_updates.len() > 2);
        assert!(proof_updates.windows(2).all(|updates| {
            updates[0].bytes_completed <= updates[1].bytes_completed
                && updates[0].commitments_completed <= updates[1].commitments_completed
                && updates[0].bytes_total == updates[1].bytes_total
                && updates[0].commitments_total == updates[1].commitments_total
        }));
        let final_proof_progress = proof_updates.last().unwrap();
        assert!(final_proof_progress.bytes_total > 0);
        assert_eq!(
            final_proof_progress.bytes_completed,
            final_proof_progress.bytes_total
        );
        assert!(final_proof_progress.commitments_total > 0);
        assert_eq!(
            final_proof_progress.commitments_completed,
            final_proof_progress.commitments_total
        );

        let crypto_provider = CryptoProvider {
            cert: tlsn::verifier::ServerCertVerifier::new(&fixture_roots()).unwrap(),
            ..CryptoProvider::default()
        };
        let capture = make_capture_with_provider(
            &proof,
            "cap-test".to_owned(),
            SERVER_DOMAIN.to_owned(),
            &crypto_provider,
        )
        .unwrap();
        let (manifest, request, response) =
            verify_capture_value_with_provider(&capture, &trusted_public_key, &crypto_provider)
                .unwrap();
        assert_eq!(manifest.provider.host, SERVER_DOMAIN);
        assert!(request.contains(r#""model":"fixture""#));
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower.contains("authorization"));
        assert!(request_lower.contains("cookie"));
        assert!(!request.contains("fixture-secret"));
        assert!(!request.contains("fixture-cookie"));
        assert!(response.contains(r#""model":"fixture""#));

        #[cfg(feature = "cli")]
        {
            let root = std::env::temp_dir().join(format!(
                "llm-notary-package-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&root).unwrap();
            let valid = root.join("valid.llmtrace");
            crate::bundle::write_trace_package_with_provider(
                &capture,
                &valid,
                &trusted_public_key,
                &crypto_provider,
            )
            .unwrap();
            let repeated = root.join("repeated.llmtrace");
            crate::bundle::write_trace_package_with_provider(
                &capture,
                &repeated,
                &trusted_public_key,
                &crypto_provider,
            )
            .unwrap();
            assert_eq!(
                fs::read(&valid).unwrap(),
                fs::read(&repeated).unwrap(),
                "identical finalized inputs must produce identical .llmtrace bytes"
            );
            let finalized_bytes = fs::read(&valid).unwrap();
            for secret in [
                b"fixture-secret".as_slice(),
                b"fixture-cookie".as_slice(),
                b"request-fixture-private".as_slice(),
                b"organization-fixture-private".as_slice(),
                b"project-fixture-private".as_slice(),
            ] {
                assert!(
                    !finalized_bytes
                        .windows(secret.len())
                        .any(|window| window == secret),
                    "finalized .llmtrace bytes must not retain header secrets"
                );
            }
            crate::bundle::verify_trace_package_with_provider(
                &valid,
                &trusted_public_key,
                &crypto_provider,
            )
            .unwrap();

            fn unpack_package(source: &Path, destination: &Path) {
                crate::archive::extract_trace_package_archive(
                    &fs::read(source).unwrap(),
                    destination,
                )
                .unwrap();
            }

            fn archive_package(source: &Path, destination: &Path) {
                fs::write(
                    destination,
                    crate::archive::build_trace_package_archive(source).unwrap(),
                )
                .unwrap();
            }

            for name in [
                "evidence.tlsn",
                "request.disclosed.http",
                "response.disclosed.http",
                "trace.otlp.json",
            ] {
                let directory = root.join(format!("tampered-{}-dir", name.replace('.', "-")));
                let tampered = root.join(format!("tampered-{}.llmtrace", name.replace('.', "-")));
                unpack_package(&valid, &directory);
                let path = directory.join(name);
                let mut bytes = fs::read(&path).unwrap();
                bytes.push(b' ');
                fs::write(path, bytes).unwrap();
                archive_package(&directory, &tampered);
                assert!(
                    crate::bundle::verify_trace_package_with_provider(
                        &tampered,
                        &trusted_public_key,
                        &crypto_provider,
                    )
                    .is_err(),
                    "tampered {name} must be rejected"
                );
            }

            for (label, mutate) in [
                (
                    "source",
                    Box::new(|manifest: &mut serde_json::Value| {
                        manifest["source"]["capture_id"] = serde_json::json!("cap-forged");
                    }) as Box<dyn Fn(&mut serde_json::Value)>,
                ),
                (
                    "trace-hash",
                    Box::new(|manifest: &mut serde_json::Value| {
                        manifest["trace_sha256"] = serde_json::json!("00");
                    }),
                ),
                (
                    "normalizer-version",
                    Box::new(|manifest: &mut serde_json::Value| {
                        manifest["normalizer_version"] = serde_json::json!("unsupported");
                    }),
                ),
            ] {
                let directory = root.join(format!("tampered-{label}-dir"));
                let tampered = root.join(format!("tampered-{label}.llmtrace"));
                unpack_package(&valid, &directory);
                let manifest_path = directory.join("manifest.json");
                let mut manifest: serde_json::Value =
                    serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
                mutate(&mut manifest);
                fs::write(
                    &manifest_path,
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                )
                .unwrap();
                archive_package(&directory, &tampered);
                assert!(
                    crate::bundle::verify_trace_package_with_provider(
                        &tampered,
                        &trusted_public_key,
                        &crypto_provider,
                    )
                    .is_err(),
                    "tampered {label} must be rejected"
                );
            }

            assert!(
                crate::bundle::verify_trace_package_with_provider(
                    &valid,
                    wrong_key.verifying_key().to_sec1_bytes().as_ref(),
                    &crypto_provider,
                )
                .is_err(),
                "a package must reject the wrong trusted notary key"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }
}
