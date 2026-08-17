//! Shared, retention-free `.llmtrace` verification for admission and the
//! anonymous hosted endpoint.

use std::{
    io::{Read as _, Write as _},
    sync::{Arc, LazyLock},
};

use notary_core::{
    archive::{MAX_ARCHIVE_WIRE_BYTES, ValidatedTracePackageArchive, read_trace_package_archive},
    notarization::{trace_manifest_from_archive, verify_trace_package_archive},
    registry::Registry,
};
use serde::Serialize;
#[cfg(feature = "test-utils")]
use tlsn::{
    attestation::CryptoProvider,
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const TRUST_SOURCE: &str = "hosted_registry";

// A near-limit package can use most of one 512 MiB API Machine while its ZIP
// entries and TLSNotary proof are decoded. Admission and anonymous requests
// must reserve the same per-process capacity before reading package bytes.
static PACKAGE_VERIFICATION_CAPACITY: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(1)));

pub(crate) async fn acquire_verification_capacity() -> OwnedSemaphorePermit {
    PACKAGE_VERIFICATION_CAPACITY
        .clone()
        .acquire_owned()
        .await
        .expect("package verification capacity is never closed")
}

pub(crate) fn try_acquire_verification_capacity() -> Option<OwnedSemaphorePermit> {
    PACKAGE_VERIFICATION_CAPACITY
        .clone()
        .try_acquire_owned()
        .ok()
}

pub(crate) struct HostedVerifiedPackage {
    pub source_trace_id: String,
    pub authenticated_at_unix_ms: u64,
    pub provider_name: String,
    pub provider_host: String,
    pub request_path: String,
    pub notary_key_id: String,
    pub registry_generation: u64,
    pub package_sha256: String,
    pub content_sha256: String,
    pub trace: Vec<u8>,
}

struct PreparedPackage {
    validated: ValidatedTracePackageArchive,
    notary_key_id: String,
    trusted_key: Vec<u8>,
}

pub(crate) const WORKER_VERIFIED: u8 = b'V';
pub(crate) const WORKER_REJECTED: u8 = b'R';
pub(crate) const MAX_WORKER_OUTPUT_BYTES: u64 = MAX_ARCHIVE_WIRE_BYTES + 2 * 1024 * 1024;

#[derive(Serialize)]
struct HostedVerificationMetadata<'a> {
    verified: bool,
    source_trace_id: &'a str,
    authenticated_at_unix_ms: u64,
    provider: &'a str,
    host: &'a str,
    notary_key_id: &'a str,
    registry_generation: u64,
    trust_source: &'static str,
    package_sha256: &'a str,
    content_sha256: &'a str,
}

#[derive(Debug)]
pub(crate) enum HostedVerificationError {
    Malformed,
    Tampered,
    UnsupportedVersion,
    UntrustedNotary,
    Service(anyhow::Error),
}

impl HostedVerificationError {
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed_package",
            Self::Tampered => "tampered_package",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UntrustedNotary => "untrusted_notary",
            Self::Service(_) => "verification_unavailable",
        }
    }

    pub fn admission_code(&self) -> Option<&'static str> {
        match self {
            Self::Malformed => Some("archive_invalid"),
            Self::Tampered | Self::UnsupportedVersion => Some("package_invalid"),
            Self::UntrustedNotary => Some("notary_untrusted"),
            Self::Service(_) => None,
        }
    }
}

pub(crate) fn verify_package(
    archive: &[u8],
    directory: &Registry,
) -> Result<HostedVerifiedPackage, HostedVerificationError> {
    let package_sha256 = notary_core::sha256_hex(archive);
    let prepared = prepare_package(archive, directory)?;
    let verified =
        verify_trace_package_archive(prepared.validated, package_sha256, &prepared.trusted_key)
            .map_err(classify_package_error)?;
    Ok(HostedVerifiedPackage {
        source_trace_id: verified.manifest.trace_id().to_owned(),
        authenticated_at_unix_ms: verified.manifest.created_at_unix_ms(),
        provider_name: verified.manifest.provider_name().to_owned(),
        provider_host: verified.manifest.provider_host().to_owned(),
        request_path: verified.request_path,
        notary_key_id: prepared.notary_key_id,
        registry_generation: directory.generation,
        package_sha256: verified.package_sha256,
        content_sha256: verified.trace_sha256,
        trace: verified.trace,
    })
}

#[cfg(feature = "test-utils")]
fn verify_fixture_package(
    archive: &[u8],
    directory: &Registry,
    crypto_provider: &CryptoProvider,
) -> Result<HostedVerifiedPackage, HostedVerificationError> {
    let package_sha256 = notary_core::sha256_hex(archive);
    let prepared = prepare_package(archive, directory)?;
    let verified = notary_core::notarization::verify_trace_package_archive_with_provider_for_test(
        prepared.validated,
        package_sha256,
        &prepared.trusted_key,
        crypto_provider,
    )
    .map_err(classify_package_error)?;
    Ok(HostedVerifiedPackage {
        source_trace_id: verified.manifest.trace_id().to_owned(),
        authenticated_at_unix_ms: verified.manifest.created_at_unix_ms(),
        provider_name: verified.manifest.provider_name().to_owned(),
        provider_host: verified.manifest.provider_host().to_owned(),
        request_path: verified.request_path,
        notary_key_id: prepared.notary_key_id,
        registry_generation: directory.generation,
        package_sha256: verified.package_sha256,
        content_sha256: verified.trace_sha256,
        trace: verified.trace,
    })
}

fn prepare_package(
    archive: &[u8],
    directory: &Registry,
) -> Result<PreparedPackage, HostedVerificationError> {
    let validated = read_trace_package_archive(archive).map_err(classify_archive_error)?;
    let manifest = trace_manifest_from_archive(&validated).map_err(classify_package_error)?;
    let embedded_key = manifest
        .notary_public_key()
        .map_err(classify_package_error)?;
    let authenticated_at = manifest.created_at_unix_ms();
    let record = directory
        .notaries
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(&embedded_key))
        })
        .ok_or(HostedVerificationError::UntrustedNotary)?;
    if !record.trusted_at(authenticated_at) {
        return Err(HostedVerificationError::UntrustedNotary);
    }
    let trusted_key = record
        .public_key_bytes()
        .map_err(HostedVerificationError::Service)?;
    Ok(PreparedPackage {
        validated,
        notary_key_id: record.key_id.clone(),
        trusted_key,
    })
}

pub(crate) fn run_worker() -> anyhow::Result<()> {
    run_worker_with(verify_package)
}

fn run_worker_with<F>(verify: F) -> anyhow::Result<()>
where
    F: FnOnce(&[u8], &Registry) -> Result<HostedVerifiedPackage, HostedVerificationError>,
{
    const MAX_DIRECTORY_BYTES: u64 = 1024 * 1024;
    let mut stdin = std::io::stdin().lock();
    let mut length = [0u8; 8];
    stdin.read_exact(&mut length)?;
    let directory_length = u64::from_be_bytes(length);
    anyhow::ensure!(
        directory_length <= MAX_DIRECTORY_BYTES,
        "directory input is too large"
    );
    let mut directory = vec![0; usize::try_from(directory_length)?];
    stdin.read_exact(&mut directory)?;
    let directory: Registry = serde_json::from_slice(&directory)?;
    stdin.read_exact(&mut length)?;
    let archive_length = u64::from_be_bytes(length);
    anyhow::ensure!(
        archive_length <= MAX_ARCHIVE_WIRE_BYTES,
        "archive input is too large"
    );
    let mut archive = vec![0; usize::try_from(archive_length)?];
    stdin.read_exact(&mut archive)?;
    let mut trailing = [0u8; 1];
    anyhow::ensure!(stdin.read(&mut trailing)? == 0, "unexpected worker input");
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    match verify(&archive, &directory) {
        Ok(package) => write_verified_response(&mut stdout, &package)?,
        Err(error) => {
            write_worker_frame(&mut stdout, WORKER_REJECTED, error.public_code().as_bytes())?;
        }
    }
    stdout.flush()?;
    Ok(())
}

#[cfg(feature = "test-utils")]
pub(crate) fn run_fixture_worker() -> anyhow::Result<()> {
    let roots = RootCertStore {
        roots: vec![CertificateDer(tls_server_fixture::CA_CERT_DER.to_vec())],
    };
    let crypto_provider = CryptoProvider {
        cert: ServerCertVerifier::new(&roots)?,
        ..CryptoProvider::default()
    };
    run_worker_with(|archive, directory| {
        verify_fixture_package(archive, directory, &crypto_provider)
    })
}

fn write_verified_response(
    output: &mut impl std::io::Write,
    package: &HostedVerifiedPackage,
) -> anyhow::Result<()> {
    let metadata = HostedVerificationMetadata {
        verified: true,
        source_trace_id: &package.source_trace_id,
        authenticated_at_unix_ms: package.authenticated_at_unix_ms,
        provider: &package.provider_name,
        host: &package.provider_host,
        notary_key_id: &package.notary_key_id,
        registry_generation: package.registry_generation,
        trust_source: TRUST_SOURCE,
        package_sha256: &package.package_sha256,
        content_sha256: &package.content_sha256,
    };
    let mut prefix = serde_json::to_vec(&metadata)?;
    anyhow::ensure!(prefix.pop() == Some(b'}'), "invalid verification metadata");
    let body_length = prefix
        .len()
        .checked_add(b",\"trace\":".len())
        .and_then(|length| length.checked_add(package.trace.len()))
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("verification response size overflow"))?;
    anyhow::ensure!(
        body_length as u64 <= MAX_WORKER_OUTPUT_BYTES,
        "verification response is too large"
    );
    output.write_all(&[WORKER_VERIFIED])?;
    output.write_all(&(body_length as u64).to_be_bytes())?;
    output.write_all(&prefix)?;
    output.write_all(b",\"trace\":")?;
    output.write_all(&package.trace)?;
    output.write_all(b"}")?;
    Ok(())
}

fn write_worker_frame(
    output: &mut impl std::io::Write,
    outcome: u8,
    body: &[u8],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        body.len() as u64 <= MAX_WORKER_OUTPUT_BYTES,
        "worker response is too large"
    );
    output.write_all(&[outcome])?;
    output.write_all(&(body.len() as u64).to_be_bytes())?;
    output.write_all(body)?;
    Ok(())
}

fn classify_archive_error(error: anyhow::Error) -> HostedVerificationError {
    let message = error.to_string();
    if message.contains("unsupported") {
        HostedVerificationError::UnsupportedVersion
    } else if message.contains("hash mismatch") || message.contains("size mismatch") {
        HostedVerificationError::Tampered
    } else {
        HostedVerificationError::Malformed
    }
}

fn classify_package_error(error: anyhow::Error) -> HostedVerificationError {
    if error.to_string().contains("unsupported") {
        HostedVerificationError::UnsupportedVersion
    } else {
        HostedVerificationError::Tampered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_error_codes_do_not_expose_crypto_details() {
        assert_eq!(
            HostedVerificationError::Malformed.public_code(),
            "malformed_package"
        );
        assert_eq!(
            HostedVerificationError::Tampered.public_code(),
            "tampered_package"
        );
        assert_eq!(
            HostedVerificationError::UnsupportedVersion.public_code(),
            "unsupported_version"
        );
        assert_eq!(
            HostedVerificationError::UntrustedNotary.public_code(),
            "untrusted_notary"
        );
    }

    #[test]
    fn worker_success_body_embeds_trace_without_reencoding_it() {
        let package = HostedVerifiedPackage {
            source_trace_id: "trc-test".to_owned(),
            authenticated_at_unix_ms: 1_700_000_000_000,
            provider_name: "OpenAI".to_owned(),
            provider_host: "api.openai.com".to_owned(),
            request_path: "/v1/chat/completions".to_owned(),
            notary_key_id: "sha256:test".to_owned(),
            registry_generation: 7,
            package_sha256: "a".repeat(64),
            content_sha256: "b".repeat(64),
            trace: br#"{"resourceSpans":[]}"#.to_vec(),
        };
        let mut output = Vec::new();
        write_verified_response(&mut output, &package).unwrap();
        assert_eq!(output[0], WORKER_VERIFIED);
        let body_length = u64::from_be_bytes(output[1..9].try_into().unwrap()) as usize;
        assert_eq!(body_length, output.len() - 9);
        let value: serde_json::Value = serde_json::from_slice(&output[9..]).unwrap();
        assert_eq!(value["verified"], true);
        assert_eq!(value["provider"], "OpenAI");
        assert_eq!(value["trace"]["resourceSpans"], serde_json::json!([]));
    }
}
