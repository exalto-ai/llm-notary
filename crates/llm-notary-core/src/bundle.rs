//! Deferred bundle finalization and offline-verifiable trace packages.

use std::{fs, path::Path};
#[cfg(feature = "cli")]
use std::{fs::OpenOptions, io::Write as _, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tlsn::attestation::CryptoProvider;

use crate::{
    Capture, CaptureManifest,
    archive::{
        VERIFIED_TRACE_PACKAGE_FORMAT, ValidatedTracePackageArchive, read_trace_package_archive,
    },
    normalize::{render_public_trace, verified_inference_from_capture},
    public::NORMALIZER_VERSION,
    sha256_hex, verify_capture_value_with_provider,
};
#[cfg(feature = "cli")]
use crate::{
    DeferredBundle,
    archive::{build_trace_package_archive, create_staging_directory},
    finalize_deferred_bundle_to, finalize_deferred_bundle_to_admitted, make_capture,
    notary_directory::NotaryEndpoint,
    vault::Vault,
};

/// Metadata binding a normalized trace to the included TLSNotary evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTraceManifest {
    format: String,
    normalizer_version: String,
    source: CaptureManifest,
    trace_sha256: String,
}

/// The authenticated result of fully verifying one canonical `.llmtrace`.
pub struct VerifiedTracePackage {
    pub manifest: VerifiedTraceManifest,
    /// Authenticated origin-form path from the provider request line.
    pub request_path: String,
    pub package_sha256: String,
    pub trace_sha256: String,
    pub trace: Vec<u8>,
}

impl VerifiedTraceManifest {
    /// Returns the source capture identifier.
    pub fn capture_id(&self) -> &str {
        &self.source.capture_id
    }

    /// Returns the provider connection time authenticated by the source
    /// presentation.
    pub fn created_at_unix_ms(&self) -> u64 {
        self.source.created_at_unix_ms
    }

    pub fn provider_name(&self) -> &str {
        &self.source.provider.name
    }

    pub fn provider_host(&self) -> &str {
        &self.source.provider.host
    }

    /// Returns the SEC1 key that signed the package source evidence.
    pub fn notary_public_key(&self) -> Result<Vec<u8>> {
        hex::decode(&self.source.notary.public_key)
            .context("trace package source notary key must be hexadecimal")
    }
}

/// Reads enough verified-package metadata to select a previously cached trust
/// anchor before full offline verification.
pub fn trace_package_notary_key(path: &Path) -> Result<Vec<u8>> {
    read_trace_manifest(path)?.notary_public_key()
}

/// Reads the embedded notary key from already-snapshotted `.llmtrace` bytes.
pub fn trace_package_notary_key_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    trace_manifest_from_archive(&read_trace_package_archive(bytes)?)?.notary_public_key()
}

/// Reads the authenticated provider-connection timestamp recorded in a
/// verified-package manifest. Callers must still perform full package
/// verification before trusting the value.
pub fn trace_package_created_at_unix_ms(path: &Path) -> Result<u64> {
    Ok(read_trace_manifest(path)?.created_at_unix_ms())
}

/// Reads the authenticated provider-connection time from already-snapshotted
/// `.llmtrace` bytes. Full verification is still required before trusting it.
pub fn trace_package_created_at_unix_ms_bytes(bytes: &[u8]) -> Result<u64> {
    Ok(trace_manifest_from_archive(&read_trace_package_archive(bytes)?)?.created_at_unix_ms())
}

/// Completes a deferred proof and atomically writes an offline-verifiable
/// `.llmtrace` archive.
#[cfg(feature = "cli")]
pub async fn finalize_bundle(
    bundle_path: &Path,
    output_path: &Path,
    trusted_notary_key: &[u8],
    vault: &Vault,
    notary: &NotaryEndpoint,
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
) -> Result<PathBuf> {
    let bundle = DeferredBundle::load(bundle_path, vault)?;
    let proof = finalize_deferred_bundle_to(
        notary,
        &bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
    )
    .await?;
    let capture = make_capture(
        &proof,
        bundle.capture_id().to_owned(),
        bundle.provider_name().to_owned(),
    )?;
    write_trace_package(&capture, output_path, trusted_notary_key)
}

/// Completes a hosted finalization with a one-time coordinator ticket.
#[cfg(feature = "cli")]
#[allow(clippy::too_many_arguments)]
pub async fn finalize_bundle_admitted(
    bundle_path: &Path,
    output_path: &Path,
    trusted_notary_key: &[u8],
    vault: &Vault,
    notary: &NotaryEndpoint,
    max_attestable_http_bytes: usize,
    max_frame_bytes: usize,
    admission_ticket: &str,
) -> Result<PathBuf> {
    let bundle = DeferredBundle::load(bundle_path, vault)?;
    let proof = finalize_deferred_bundle_to_admitted(
        notary,
        &bundle,
        trusted_notary_key,
        max_attestable_http_bytes,
        max_frame_bytes,
        admission_ticket,
    )
    .await?;
    let capture = make_capture(
        &proof,
        bundle.capture_id().to_owned(),
        bundle.provider_name().to_owned(),
    )?;
    write_trace_package(&capture, output_path, trusted_notary_key)
}

#[cfg(feature = "cli")]
fn write_trace_package(
    capture: &Capture,
    output_path: &Path,
    trusted_notary_key: &[u8],
) -> Result<PathBuf> {
    write_trace_package_with_provider(
        capture,
        output_path,
        trusted_notary_key,
        &CryptoProvider::default(),
    )
}

#[cfg(feature = "cli")]
pub(crate) fn write_trace_package_with_provider(
    capture: &Capture,
    output_path: &Path,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<PathBuf> {
    let (source, request, response) =
        verify_capture_value_with_provider(capture, trusted_notary_key, crypto_provider)?;
    let inference = verified_inference_from_capture(&source, &request, &response)?;
    let trace = render_public_trace(&[inference])?;
    let manifest = VerifiedTraceManifest {
        format: VERIFIED_TRACE_PACKAGE_FORMAT.to_owned(),
        normalizer_version: NORMALIZER_VERSION.to_owned(),
        source,
        trace_sha256: sha256_hex(&trace),
    };

    write_package_archive(output_path, capture, &trace, &manifest)?;
    Ok(output_path.to_path_buf())
}

#[cfg(feature = "cli")]
fn write_package_archive(
    output_path: &Path,
    capture: &Capture,
    trace: &[u8],
    manifest: &VerifiedTraceManifest,
) -> Result<()> {
    if output_path.exists() {
        bail!(
            "refusing to overwrite existing trace package: {}",
            output_path.display()
        );
    }
    let staging = create_staging_directory(output_path)?;

    let result = (|| -> Result<()> {
        fs::write(staging.join("evidence.tlsn"), &capture.evidence)?;
        fs::write(
            staging.join("request.disclosed.http"),
            &capture.request_disclosed,
        )?;
        fs::write(staging.join("response.disclosed.http"), &capture.response)?;
        fs::write(staging.join("trace.otlp.json"), trace)?;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(manifest)?,
        )?;
        let archive = build_trace_package_archive(&staging)?;
        write_atomic_trace(output_path, &archive)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

#[cfg(feature = "cli")]
fn write_atomic_trace(output_path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let file_name = output_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("trace package output has no file name"))?
        .to_string_lossy();
    for _ in 0..16 {
        let partial = parent.join(format!(
            ".{file_name}.{}.{:016x}.partial",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&partial) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", partial.display()));
            }
        };
        let result = (|| -> Result<()> {
            file.write_all(bytes)
                .with_context(|| format!("writing {}", partial.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing {}", partial.display()))?;
            drop(file);
            fs::hard_link(&partial, output_path).with_context(|| {
                format!(
                    "atomically publishing trace package {}",
                    output_path.display()
                )
            })?;
            fs::remove_file(&partial)
                .with_context(|| format!("removing staging file {}", partial.display()))?;
            #[cfg(unix)]
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("syncing trace package directory {}", parent.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        return result;
    }
    bail!(
        "could not create a unique staging file beside {}",
        output_path.display()
    )
}

/// Verifies a trace package and re-runs the deterministic provider adapter.
pub fn verify_trace_package(
    path: &Path,
    trusted_notary_key: &[u8],
) -> Result<VerifiedTraceManifest> {
    Ok(
        verify_trace_package_with_provider(path, trusted_notary_key, &CryptoProvider::default())?
            .manifest,
    )
}

pub(crate) fn verify_trace_package_with_provider(
    path: &Path,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedTracePackage> {
    let bytes = read_trace_package_file(path)?;
    verify_trace_package_bytes_with_provider(&bytes, trusted_notary_key, crypto_provider)
}

/// Verifies exact `.llmtrace` bytes without retaining or extracting them.
pub fn verify_trace_package_bytes(
    bytes: &[u8],
    trusted_notary_key: &[u8],
) -> Result<VerifiedTracePackage> {
    let archive = read_trace_package_archive(bytes)?;
    verify_trace_package_archive_with_provider(
        archive,
        sha256_hex(bytes),
        trusted_notary_key,
        &CryptoProvider::default(),
    )
}

fn verify_trace_package_bytes_with_provider(
    bytes: &[u8],
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedTracePackage> {
    let archive = read_trace_package_archive(bytes)?;
    verify_trace_package_archive_with_provider(
        archive,
        sha256_hex(bytes),
        trusted_notary_key,
        crypto_provider,
    )
}

/// Fully verifies one already validated in-memory archive without parsing or
/// retaining a second copy of its ZIP entries.
pub fn verify_trace_package_archive(
    archive: ValidatedTracePackageArchive,
    package_sha256: String,
    trusted_notary_key: &[u8],
) -> Result<VerifiedTracePackage> {
    verify_trace_package_archive_with_provider(
        archive,
        package_sha256,
        trusted_notary_key,
        &CryptoProvider::default(),
    )
}

fn verify_trace_package_archive_with_provider(
    archive: ValidatedTracePackageArchive,
    package_sha256: String,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedTracePackage> {
    let manifest = trace_manifest_from_archive(&archive)?;
    let mut files = archive.into_files();
    let capture = Capture {
        manifest: manifest.source.clone(),
        evidence: files
            .remove("evidence.tlsn")
            .expect("validated archive contains evidence"),
        request_disclosed: files
            .remove("request.disclosed.http")
            .expect("validated archive contains request disclosure"),
        response: files
            .remove("response.disclosed.http")
            .expect("validated archive contains response disclosure"),
    };
    let (source, request, response) =
        verify_capture_value_with_provider(&capture, trusted_notary_key, crypto_provider)?;
    let request_path = verified_request_path(&request)?;
    let inference = verified_inference_from_capture(&source, &request, &response)?;
    let expected = render_public_trace(&[inference])?;
    let actual = files
        .remove("trace.otlp.json")
        .expect("validated archive contains canonical trace");
    if manifest.trace_sha256 != sha256_hex(&actual) || actual != expected {
        bail!("OTLP trace does not match the authenticated source bundle");
    }
    let trace_sha256 = sha256_hex(&actual);
    Ok(VerifiedTracePackage {
        manifest,
        request_path,
        package_sha256,
        trace_sha256,
        trace: actual,
    })
}

fn verified_request_path(request: &str) -> Result<String> {
    let start_line = request
        .lines()
        .next()
        .context("verified provider request has no start line")?;
    let mut fields = start_line.split_ascii_whitespace();
    let _method = fields
        .next()
        .context("verified provider request has no method")?;
    let target = fields
        .next()
        .context("verified provider request has no target")?;
    let _version = fields
        .next()
        .context("verified provider request has no HTTP version")?;
    if fields.next().is_some() {
        bail!("verified provider request has an invalid start line");
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    if !path.starts_with('/') {
        bail!("verified provider request target is not origin-form");
    }
    Ok(path.to_owned())
}

/// Test-only entry point for exercising the complete package verifier with a
/// private certificate authority fixture. Production callers must use the
/// default public-root verifier above.
#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub fn verify_trace_package_archive_with_provider_for_test(
    archive: ValidatedTracePackageArchive,
    package_sha256: String,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedTracePackage> {
    verify_trace_package_archive_with_provider(
        archive,
        package_sha256,
        trusted_notary_key,
        crypto_provider,
    )
}

fn read_trace_manifest(path: &Path) -> Result<VerifiedTraceManifest> {
    let bytes = read_trace_package_file(path)?;
    let archive = read_trace_package_archive(&bytes)?;
    trace_manifest_from_archive(&archive)
}

/// Parses and version-checks the source manifest from a canonical archive
/// that has already passed entry, size, metadata, and hash validation.
/// Its fields remain untrusted until the complete package verifier succeeds.
pub fn trace_manifest_from_archive(
    archive: &ValidatedTracePackageArchive,
) -> Result<VerifiedTraceManifest> {
    let manifest: VerifiedTraceManifest = serde_json::from_slice(archive.file("manifest.json")?)
        .context("parsing trace package manifest")?;
    if manifest.format != VERIFIED_TRACE_PACKAGE_FORMAT
        || manifest.normalizer_version != NORMALIZER_VERSION
    {
        bail!("unsupported verified trace package format or normalizer version");
    }
    Ok(manifest)
}

fn read_trace_package_file(path: &Path) -> Result<Vec<u8>> {
    if path
        .extension()
        .is_some_and(|extension| extension == "llmbundle")
    {
        bail!(
            "encrypted .llmbundle files are private retry state and cannot be verified as finalized packages"
        );
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading trace package {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "verified trace package must be one regular .llmtrace file: {}",
            path.display()
        );
    }
    fs::read(path).with_context(|| format!("reading trace package {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_bundle_is_never_accepted_as_a_verified_package() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("capture.llmbundle");
        fs::write(&bundle, b"encrypted private retry state").unwrap();

        let error = verify_trace_package(&bundle, &[0; 33]).unwrap_err();

        assert!(error.to_string().contains("private retry state"));
    }
}
