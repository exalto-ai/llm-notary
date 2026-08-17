//! Shared, retention-free `.llmtrace` verification for admission and the
//! anonymous hosted endpoint.

use std::{
    io::{Read as _, Write as _},
    sync::{Arc, LazyLock},
};

use notary_core::{
    archive::{MAX_ARCHIVE_WIRE_BYTES, ValidatedTracePackageArchive, read_trace_package_archive},
    notarization::{trace_manifest_from_archive, verify_trace_package_archive},
    public_safety::{
        PublicPackageSafetyContext, validate_public_trace_package_with_context_and_force,
    },
    registry::Registry,
};
#[cfg(feature = "test-utils")]
use tlsn::{
    attestation::CryptoProvider,
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::process::{
    MAX_REGISTRY_BYTES, MAX_WORKER_OUTPUT_BYTES, TRUST_SOURCE, VerificationPurpose,
    VerifiedPackage, WORKER_REJECTED, WORKER_VERIFIED, WorkerMetadata,
};

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

struct PreparedPackage {
    validated: ValidatedTracePackageArchive,
    notary_key_id: String,
    trusted_key: Vec<u8>,
}

#[derive(Debug)]
enum HostedVerificationError {
    Malformed,
    Tampered,
    UnsupportedVersion,
    UntrustedNotary,
    Service,
}

impl HostedVerificationError {
    fn public_code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed_package",
            Self::Tampered => "tampered_package",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UntrustedNotary => "untrusted_notary",
            Self::Service => "verification_unavailable",
        }
    }

    fn admission_code(&self) -> Option<&'static str> {
        match self {
            Self::Malformed => Some("archive_invalid"),
            Self::Tampered | Self::UnsupportedVersion => Some("package_invalid"),
            Self::UntrustedNotary => Some("notary_untrusted"),
            Self::Service => None,
        }
    }
}

fn verify_package(
    archive: &[u8],
    registry: &Registry,
) -> Result<VerifiedPackage, HostedVerificationError> {
    let package_sha256 = notary_core::sha256_hex(archive);
    let prepared = prepare_package(archive, registry)?;
    let verified =
        verify_trace_package_archive(prepared.validated, package_sha256, &prepared.trusted_key)
            .map_err(classify_package_error)?;
    Ok(VerifiedPackage {
        source_trace_id: verified.manifest.trace_id().to_owned(),
        authenticated_at_unix_ms: verified.manifest.created_at_unix_ms(),
        provider_name: verified.manifest.provider_name().to_owned(),
        provider_host: verified.manifest.provider_host().to_owned(),
        request_path: verified.request_path,
        notary_key_id: prepared.notary_key_id,
        registry_generation: registry.generation,
        package_sha256: verified.package_sha256,
        content_sha256: verified.trace_sha256,
        trace: verified.trace,
        safety_override_applied: None,
    })
}

#[cfg(feature = "test-utils")]
fn verify_fixture_package(
    archive: &[u8],
    registry: &Registry,
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedPackage, HostedVerificationError> {
    let package_sha256 = notary_core::sha256_hex(archive);
    let prepared = prepare_package(archive, registry)?;
    let verified = notary_core::notarization::verify_trace_package_archive_with_provider_for_test(
        prepared.validated,
        package_sha256,
        &prepared.trusted_key,
        crypto_provider,
    )
    .map_err(classify_package_error)?;
    Ok(VerifiedPackage {
        source_trace_id: verified.manifest.trace_id().to_owned(),
        authenticated_at_unix_ms: verified.manifest.created_at_unix_ms(),
        provider_name: verified.manifest.provider_name().to_owned(),
        provider_host: verified.manifest.provider_host().to_owned(),
        request_path: verified.request_path,
        notary_key_id: prepared.notary_key_id,
        registry_generation: registry.generation,
        package_sha256: verified.package_sha256,
        content_sha256: verified.trace_sha256,
        trace: verified.trace,
        safety_override_applied: None,
    })
}

fn prepare_package(
    archive: &[u8],
    registry: &Registry,
) -> Result<PreparedPackage, HostedVerificationError> {
    let validated = read_trace_package_archive(archive).map_err(classify_archive_error)?;
    let manifest = trace_manifest_from_archive(&validated).map_err(classify_package_error)?;
    let embedded_key = manifest
        .notary_public_key()
        .map_err(classify_package_error)?;
    let authenticated_at = manifest.created_at_unix_ms();
    let record = registry
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
        .map_err(|_| HostedVerificationError::Service)?;
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
    F: FnOnce(&[u8], &Registry) -> Result<VerifiedPackage, HostedVerificationError>,
{
    let mut stdin = std::io::stdin().lock();
    let mut purpose = [0u8; 1];
    stdin.read_exact(&mut purpose)?;
    let purpose = VerificationPurpose::from_wire(purpose[0])
        .ok_or_else(|| anyhow::anyhow!("unsupported verification purpose"))?;
    let mut length = [0u8; 8];
    stdin.read_exact(&mut length)?;
    let registry_length = u64::from_be_bytes(length);
    anyhow::ensure!(
        registry_length <= MAX_REGISTRY_BYTES,
        "Registry input is too large"
    );
    let mut registry = vec![0; usize::try_from(registry_length)?];
    stdin.read_exact(&mut registry)?;
    let registry: Registry = serde_json::from_slice(&registry)?;
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
    match verify_for_purpose(&archive, &registry, purpose, verify) {
        Ok(package) => write_verified_response(&mut stdout, &package)?,
        Err(code) => write_worker_frame(&mut stdout, WORKER_REJECTED, code.as_bytes())?,
    }
    stdout.flush()?;
    Ok(())
}

fn verify_for_purpose<F>(
    archive: &[u8],
    registry: &Registry,
    purpose: VerificationPurpose,
    verify: F,
) -> Result<VerifiedPackage, String>
where
    F: FnOnce(&[u8], &Registry) -> Result<VerifiedPackage, HostedVerificationError>,
{
    let mut package = verify(archive, registry).map_err(|error| match purpose {
        VerificationPurpose::Anonymous => error.public_code().to_owned(),
        VerificationPurpose::Hosted { .. } => error
            .admission_code()
            .unwrap_or_else(|| error.public_code())
            .to_owned(),
    })?;
    if let VerificationPurpose::Hosted { allow_high_entropy } = purpose {
        let safety = validate_public_trace_package_with_context_and_force(
            archive,
            PublicPackageSafetyContext {
                provider_host: &package.provider_host,
                request_path: &package.request_path,
            },
            allow_high_entropy,
        )
        .map_err(|error| error.admission_code())?;
        package.safety_override_applied = Some(safety.high_entropy_override_applied);
    }
    Ok(package)
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
    run_worker_with(|archive, registry| verify_fixture_package(archive, registry, &crypto_provider))
}

fn write_verified_response(
    output: &mut impl std::io::Write,
    package: &VerifiedPackage,
) -> anyhow::Result<()> {
    let metadata = WorkerMetadata {
        verified: true,
        source_trace_id: package.source_trace_id.clone(),
        authenticated_at_unix_ms: package.authenticated_at_unix_ms,
        provider: package.provider_name.clone(),
        host: package.provider_host.clone(),
        request_path: package.request_path.clone(),
        notary_key_id: package.notary_key_id.clone(),
        registry_generation: package.registry_generation,
        trust_source: TRUST_SOURCE.to_owned(),
        package_sha256: package.package_sha256.clone(),
        content_sha256: package.content_sha256.clone(),
        safety_override_applied: package.safety_override_applied,
    };
    let metadata = serde_json::to_vec(&metadata)?;
    let body_length = 8usize
        .checked_add(metadata.len())
        .and_then(|length| length.checked_add(package.trace.len()))
        .ok_or_else(|| anyhow::anyhow!("verification response size overflow"))?;
    anyhow::ensure!(
        body_length as u64 <= MAX_WORKER_OUTPUT_BYTES,
        "verification response is too large"
    );
    output.write_all(&[WORKER_VERIFIED])?;
    output.write_all(&(body_length as u64).to_be_bytes())?;
    output.write_all(&(metadata.len() as u64).to_be_bytes())?;
    output.write_all(&metadata)?;
    output.write_all(&package.trace)?;
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
    use std::fs;

    use notary_core::archive::{PACKAGE_FILES, build_trace_package_archive};

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
        let package = VerifiedPackage {
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
            safety_override_applied: None,
        };
        let mut output = Vec::new();
        write_verified_response(&mut output, &package).unwrap();
        assert_eq!(output[0], WORKER_VERIFIED);
        let body_length = u64::from_be_bytes(output[1..9].try_into().unwrap()) as usize;
        assert_eq!(body_length, output.len() - 9);
        let metadata_length = u64::from_be_bytes(output[9..17].try_into().unwrap()) as usize;
        let trace_offset = 17 + metadata_length;
        let metadata: serde_json::Value =
            serde_json::from_slice(&output[17..trace_offset]).unwrap();
        assert_eq!(metadata["verified"], true);
        assert_eq!(metadata["provider"], "OpenAI");
        assert_eq!(&output[trace_offset..], package.trace);
    }

    #[test]
    fn hosted_worker_performs_public_safety_validation() {
        let trace = br#"{"resourceSpans":[]}"#.to_vec();
        let package_dir = std::env::temp_dir().join(format!(
            "notary-hosted-worker-safety-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&package_dir).unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => br#"{"format":"notary/trace-evidence/v1"}"#.to_vec(),
                "request.disclosed.http" => b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: \0\0\0\0\r\n\r\n{\"model\":\"gpt-test\"}".to_vec(),
                "response.disclosed.http" => b"HTTP/1.1 200 OK\r\nContent-Type: \0\0\0\r\n\r\n{\"id\":\"chatcmpl-7Qx9Za2Bc4De6Fg8Hi0Jk3Lm5Np\",\"choices\":[]}".to_vec(),
                "trace.otlp.json" => trace.clone(),
                _ => b"public TLSNotary evidence".to_vec(),
            };
            fs::write(package_dir.join(name), bytes).unwrap();
        }
        let archive = build_trace_package_archive(&package_dir).unwrap();
        fs::remove_dir_all(package_dir).unwrap();
        let registry: Registry = serde_json::from_value(serde_json::json!({
            "format": "notary/registry/v1",
            "generation": 0,
            "active_key_id": "unused",
            "notaries": []
        }))
        .unwrap();
        let verified = verify_for_purpose(
            &archive,
            &registry,
            VerificationPurpose::Hosted {
                allow_high_entropy: false,
            },
            |_, _| {
                Ok(VerifiedPackage {
                    source_trace_id: "trc-test".to_owned(),
                    authenticated_at_unix_ms: 1_700_000_000_000,
                    provider_name: "OpenAI".to_owned(),
                    provider_host: "api.openai.com".to_owned(),
                    request_path: "/v1/chat/completions".to_owned(),
                    notary_key_id: "sha256:test".to_owned(),
                    registry_generation: 0,
                    package_sha256: notary_core::sha256_hex(&archive),
                    content_sha256: notary_core::sha256_hex(&trace),
                    trace,
                    safety_override_applied: None,
                })
            },
        )
        .unwrap();
        assert_eq!(verified.safety_override_applied, Some(false));
    }
}
