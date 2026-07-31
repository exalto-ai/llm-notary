//! Shared TLSNotary plumbing for the LLM Notary proof of concept.
//!
//! The boundary here is deliberate: the local proxy owns request plaintext and
//! the API key, while the remote notary relays authenticated TLS traffic and
//! signs an attestation for the committed transcript.

use std::{
    fmt, fs,
    future::IntoFuture,
    io::{self, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http::{HeaderMap, Method, Uri};
use http_body::Frame;
use http_body_util::{BodyExt as _, StreamBody, combinators::BoxBody};
use hyper::{Request, Response, body::Incoming};
use hyper_util::rt::TokioIo;
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer as _, Verifier as _},
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
use tlsn_formats::http::HttpTranscript;
use tokio::{
    io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

pub mod archive;
#[cfg(any(feature = "api", feature = "cli"))]
pub mod bundle;
#[cfg(feature = "cli")]
pub mod cli;
pub mod normalize;
pub mod notary_directory;
pub mod public;
#[cfg(feature = "cli")]
pub mod vault;

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
const REDACTED_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
];
const REDACTED_RESPONSE_HEADERS: &[&str] = &["set-cookie"];
pub const CAPTURE_FORMAT: &str = "llm-notary/capture/v1";
const DEFERRED_BUNDLE_FORMAT: &str = "llm-notary/deferred-bundle/v1";
const DEFERRED_RECEIPT_FORMAT: &str = "llm-notary/deferred-receipt/v1";
const NOTARY_CONTROL_MAGIC_V1: &[u8; 8] = b"LLMN\0\0\0\x01";
const NOTARY_CONTROL_MAGIC_V2: &[u8; 8] = b"LLMN\0\0\0\x02";
const NOTARY_MODE_CAPTURE: u8 = 2;
const NOTARY_MODE_FINALIZE: u8 = 3;
const NOTARY_ADMISSION_ACCEPTED: u8 = 1;
const NOTARY_ADMISSION_REJECTED: u8 = 2;
const NOTARY_REJECTION_CAPTURE_AT_CAPACITY: u8 = 1;
const NOTARY_REJECTION_FINALIZE_AT_CAPACITY: u8 = 2;
const NOTARY_REJECTION_CAPTURE_DISABLED: u8 = 3;
pub const NOTARY_CAPACITY_RETRY_AFTER_SECS: u64 = 5;

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
}

impl NotaryAdmissionRejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::CaptureAtCapacity => "capture_at_capacity",
            Self::FinalizeAtCapacity => "finalize_at_capacity",
            Self::CaptureDisabled => "capture_disabled",
        }
    }

    fn from_wire(code: u8) -> Result<Self> {
        match code {
            NOTARY_REJECTION_CAPTURE_AT_CAPACITY => Ok(Self::CaptureAtCapacity),
            NOTARY_REJECTION_FINALIZE_AT_CAPACITY => Ok(Self::FinalizeAtCapacity),
            NOTARY_REJECTION_CAPTURE_DISABLED => Ok(Self::CaptureDisabled),
            _ => bail!("unknown notary admission rejection code"),
        }
    }

    fn wire_code(self) -> u8 {
        match self {
            Self::CaptureAtCapacity => NOTARY_REJECTION_CAPTURE_AT_CAPACITY,
            Self::FinalizeAtCapacity => NOTARY_REJECTION_FINALIZE_AT_CAPACITY,
            Self::CaptureDisabled => NOTARY_REJECTION_CAPTURE_DISABLED,
        }
    }
}

/// A typed, retryable error returned by a v2 notary before session work
/// begins. It deliberately contains no information about other clients or
/// server capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotaryAdmissionError {
    rejection: NotaryAdmissionRejection,
    retry_after: std::time::Duration,
}

impl NotaryAdmissionError {
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
/// response; v2 clients do, allowing capacity rejections to be surfaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotarySessionPrelude {
    mode: NotarySessionMode,
    admission_response: bool,
}

impl NotarySessionPrelude {
    pub fn mode(self) -> NotarySessionMode {
        self.mode
    }
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
    if transcript.requests.len() != 1 || transcript.responses.len() != 1 {
        bail!("expected exactly one HTTP request and response {context}");
    }
    let request = &transcript.requests[0];
    let mut sent = RangeSet::default();
    sent.union_mut(request.without_data());
    sent.union_mut(&request.request.target);
    for value in &request.headers {
        if is_redacted_request_header(&value.name.as_str()) {
            sent.union_mut(value.without_value());
        } else {
            sent.union_mut(value);
        }
    }
    if let Some(body) = &request.body {
        sent.union_mut(body);
    }

    let response = &transcript.responses[0];
    let mut received = RangeSet::default();
    received.union_mut(response.without_data());
    for value in &response.headers {
        if is_redacted_response_header(&value.name.as_str()) {
            received.union_mut(value.without_value());
        } else {
            received.union_mut(value);
        }
    }
    if let Some(body) = &response.body {
        received.union_mut(body);
    }
    Ok(DisclosedHttpRanges { sent, received })
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

fn is_redacted_request_header(name: &str) -> bool {
    REDACTED_REQUEST_HEADERS
        .iter()
        .any(|redacted| name.eq_ignore_ascii_case(redacted))
}

fn is_redacted_response_header(name: &str) -> bool {
    REDACTED_RESPONSE_HEADERS
        .iter()
        .any(|redacted| name.eq_ignore_ascii_case(redacted))
}

/// Enforces the finalized-package disclosure contract after the TLSNotary
/// presentation has authenticated these bytes.
pub fn validate_disclosed_http_redactions(request: &[u8], response: &[u8]) -> Result<()> {
    validate_redacted_headers(request, REDACTED_REQUEST_HEADERS, "request")?;
    validate_redacted_headers(response, REDACTED_RESPONSE_HEADERS, "response")
}

fn validate_redacted_headers(bytes: &[u8], sensitive: &[&str], label: &str) -> Result<()> {
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
        if sensitive
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected.as_bytes()))
            && line[colon + 1..]
                .iter()
                .any(|byte| !byte.is_ascii_whitespace() && *byte != 0)
        {
            bail!("{label} discloses a credential or cookie header value");
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
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("bundle path has no file name"))?
            .to_string_lossy();
        let staging = parent.join(format!(".{file_name}.{}.partial", std::process::id()));
        if staging.exists() {
            bail!("bundle staging file already exists: {}", staging.display());
        }
        let bytes = bincode::serialize(self).context("serializing deferred bundle")?;
        write_private_file(&staging, &vault.encrypt(&bytes)?)?;
        fs::rename(&staging, path)
            .with_context(|| format!("finalizing encrypted bundle {}", path.display()))
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
    validate_notary_frame_limit(capture.max_frame_bytes)?;
    let mut attestable_budget = AttestableHttpBudget::new(capture.max_attestable_http_bytes)?;
    attestable_budget.reserve(
        attestable_request_header_bytes(request.method(), request.uri(), request.headers())?,
        "provider request headers",
    )?;
    attestable_budget.reserve(capture.request_body_bytes, "provider request body")?;
    let mut notary_socket = TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("connecting to notary at {notary_addr}"))?;
    notary_socket.set_nodelay(true)?;
    write_notary_prelude(&mut notary_socket, NOTARY_MODE_CAPTURE).await?;
    read_notary_admission(&mut notary_socket).await?;

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

    let mut socket = TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("connecting to notary at {notary_addr}"))?;
    socket.set_nodelay(true)?;
    write_notary_prelude(&mut socket, NOTARY_MODE_FINALIZE).await?;
    read_notary_admission(&mut socket).await?;
    let request = DeferredFinalizeRequest {
        receipt: bundle.receipt.clone(),
        records: state.records().clone(),
        prove_request: prove_config.to_request(),
    };
    write_tokio_frame(&mut socket, &bincode::serialize(&request)?, max_frame_bytes).await?;

    let session = Session::new(socket.compat());
    let mut prover_context = session.new_context()?;
    let (driver, handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = state
        .prove(&mut prover_context, &prove_config, CHUNKED_PROOF_BYTES)
        .await?;

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
    write_notary_admission(&mut socket, prelude, Ok(())).await?;
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

/// Reads and validates a versioned session prelude. v1 remains accepted for
/// already-deployed clients, while v2 enables a server admission response.
pub async fn read_notary_session_prelude(socket: &mut TcpStream) -> Result<NotarySessionPrelude> {
    let (version, mode) = read_notary_prelude(socket).await?;
    let mode = match mode {
        NOTARY_MODE_CAPTURE => NotarySessionMode::Capture,
        NOTARY_MODE_FINALIZE => NotarySessionMode::Finalize,
        _ => bail!("unsupported notary control mode"),
    };
    Ok(NotarySessionPrelude {
        mode,
        admission_response: version == 2,
    })
}

/// Sends the v2 admission response after the server has applied its cheap
/// policy and capacity checks. A v1 client receives no bytes so its existing
/// TLSN session remains wire-compatible.
pub async fn write_notary_admission(
    socket: &mut TcpStream,
    prelude: NotarySessionPrelude,
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
    validate_notary_frame_limit(max_frame_bytes)?;
    match mode {
        NotarySessionMode::Capture => {
            run_deferred_capture_session(socket, signing_key, allowed_hosts, max_frame_bytes).await
        }
        NotarySessionMode::Finalize => {
            run_deferred_finalize_session(
                socket,
                signing_key,
                max_private_chunk_bytes,
                max_total_private_chunk_bytes,
                max_private_chunk_commitments,
                max_frame_bytes,
            )
            .await
        }
    }
}

async fn run_deferred_capture_session(
    socket: TcpStream,
    signing_key: Arc<SigningKey>,
    allowed_hosts: Arc<Vec<String>>,
    max_frame_bytes: usize,
) -> Result<()> {
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
    let receipt = issue_deferred_receipt(
        &signing_key,
        server_name,
        deferred.root_binding(),
        deferred.records(),
        connection_info,
        server_ephemeral_key,
    )?;
    write_frame(&mut socket, &bincode::serialize(&receipt)?, max_frame_bytes).await?;
    Ok(())
}

async fn run_deferred_finalize_session(
    mut socket: TcpStream,
    signing_key: Arc<SigningKey>,
    max_private_chunk_bytes: usize,
    max_total_private_chunk_bytes: usize,
    max_private_chunk_commitments: usize,
    max_frame_bytes: usize,
) -> Result<()> {
    let request: DeferredFinalizeRequest =
        bincode::deserialize(&read_tokio_frame(&mut socket, max_frame_bytes).await?)?;
    request
        .receipt
        .verify(signing_key.verifying_key().to_sec1_bytes().as_ref())?;
    request.receipt.validate_records(&request.records)?;
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
    Ok(())
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

/// Builds a local capture directory payload. The raw provider response is
/// retained locally; the request stores only the verifiable disclosure, so an
/// API key cannot be recovered from a capture directory.
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
    let capture = load_capture(path)?;
    verify_capture_value(&capture, trusted_notary_key)
}

/// Verifies a fully loaded local capture.
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

fn read_capture_file(directory: &Path, name: &str) -> Result<Vec<u8>> {
    fs::read(directory.join(name)).with_context(|| {
        format!(
            "reading capture artifact {}",
            directory.join(name).display()
        )
    })
}

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

async fn write_notary_prelude(socket: &mut TcpStream, mode: u8) -> Result<()> {
    socket.write_all(NOTARY_CONTROL_MAGIC_V2).await?;
    socket.write_all(&[mode]).await?;
    socket.flush().await?;
    Ok(())
}

async fn read_notary_prelude(socket: &mut TcpStream) -> Result<(u8, u8)> {
    let mut magic = [0u8; NOTARY_CONTROL_MAGIC_V2.len()];
    socket.read_exact(&mut magic).await?;
    let version = if &magic == NOTARY_CONTROL_MAGIC_V1 {
        1
    } else if &magic == NOTARY_CONTROL_MAGIC_V2 {
        2
    } else {
        bail!("invalid notary control protocol prelude");
    };
    let mut mode = [0u8; 1];
    socket.read_exact(&mut mode).await?;
    Ok((version, mode[0]))
}

async fn read_notary_admission(socket: &mut TcpStream) -> Result<()> {
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

async fn write_tokio_frame(
    socket: &mut TcpStream,
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
    use std::time::{SystemTime, UNIX_EPOCH};
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
                prelude,
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
    fn attestable_http_budget_is_shared_between_request_and_response() {
        let mut budget = AttestableHttpBudget::new(10).unwrap();
        budget.reserve(6, "provider request").unwrap();
        let error = budget.reserve(5, "provider response").unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider response exceeds the 10-byte maximum attestable HTTP budget"
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
            write_notary_admission(&mut socket, prelude, Ok(()))
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
    fn disclosed_http_rejects_visible_credentials_and_cookies() {
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
    }

    #[test]
    fn disclosure_header_policy_covers_every_sensitive_header() {
        let empty_response = b"HTTP/1.1 200 OK\r\n\r\n{}";
        for name in REDACTED_REQUEST_HEADERS {
            assert!(is_redacted_request_header(&name.to_ascii_uppercase()));
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
        for name in REDACTED_RESPONSE_HEADERS {
            assert!(is_redacted_response_header(&name.to_ascii_uppercase()));
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

        assert!(!is_redacted_request_header("http-referer"));
        assert!(!is_redacted_response_header("content-type"));
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

    #[test]
    fn provider_labels_must_match_the_authenticated_host() {
        assert!(validate_provider_name("openai", "api.openai.com").is_ok());
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
        let mut sent = b"POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer auth-secret\r\nProxy-Authorization: Basic proxy-secret\r\nCookie: session=cookie-secret\r\nx-api-key: key-secret\r\nHTTP-Referer: https://example.test\r\nX-Title: LLM Notary test\r\nContent-Length: 65536\r\n\r\n".to_vec();
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
                let redacted = match direction {
                    Direction::Sent => is_redacted_request_header(&header.name.as_str()),
                    Direction::Received => is_redacted_response_header(&header.name.as_str()),
                };
                if redacted {
                    assert!(
                        ranges.intersection(header.value.indices()).next().is_none(),
                        "a private commitment must not include the {} value",
                        header.name.as_str()
                    );
                } else if header.name.as_str().eq_ignore_ascii_case("http-referer")
                    || header.name.as_str().eq_ignore_ascii_case("x-title")
                {
                    assert!(
                        ranges.intersection(header.value.indices()).next().is_some(),
                        "safe OpenRouter attribution header {} must remain disclosed",
                        header.name.as_str()
                    );
                }
            }
        }
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
        let proof = finalize_deferred_bundle(
            notary_addr,
            &bundle,
            &trusted_public_key,
            DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            DEFAULT_NOTARY_MAX_FRAME_BYTES,
        )
        .await
        .unwrap();
        finalizer.await.unwrap();

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
            let valid = root.join("valid");
            crate::bundle::write_trace_package_with_provider(
                &capture,
                &valid,
                &trusted_public_key,
                &crypto_provider,
            )
            .unwrap();
            crate::bundle::verify_trace_package_with_provider(
                &valid,
                &trusted_public_key,
                &crypto_provider,
            )
            .unwrap();

            fn copy_package(source: &Path, destination: &Path) {
                fs::create_dir_all(destination).unwrap();
                for name in [
                    "evidence.tlsn",
                    "manifest.json",
                    "request.disclosed.http",
                    "response.http",
                    "trace.otlp.json",
                ] {
                    fs::copy(source.join(name), destination.join(name)).unwrap();
                }
            }

            for name in [
                "evidence.tlsn",
                "request.disclosed.http",
                "response.http",
                "trace.otlp.json",
            ] {
                let tampered = root.join(format!("tampered-{}", name.replace('.', "-")));
                copy_package(&valid, &tampered);
                let path = tampered.join(name);
                let mut bytes = fs::read(&path).unwrap();
                bytes.push(b' ');
                fs::write(path, bytes).unwrap();
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
                let tampered = root.join(format!("tampered-{label}"));
                copy_package(&valid, &tampered);
                let manifest_path = tampered.join("manifest.json");
                let mut manifest: serde_json::Value =
                    serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
                mutate(&mut manifest);
                fs::write(
                    &manifest_path,
                    serde_json::to_vec_pretty(&manifest).unwrap(),
                )
                .unwrap();
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
