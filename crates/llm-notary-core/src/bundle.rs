//! Deferred bundle finalization and offline-verifiable trace packages.

#[cfg(feature = "cli")]
use std::path::PathBuf;
use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tlsn::attestation::CryptoProvider;

use crate::{
    Capture, CaptureManifest,
    archive::VERIFIED_TRACE_PACKAGE_FORMAT,
    normalize::{render_public_trace, verified_inference_from_capture},
    public::NORMALIZER_VERSION,
    sha256_hex, verify_capture_value_with_provider,
};
#[cfg(feature = "cli")]
use crate::{
    DeferredBundle, archive::create_staging_directory, finalize_deferred_bundle_to,
    finalize_deferred_bundle_to_admitted, make_capture, notary_directory::NotaryEndpoint,
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

/// Reads the authenticated provider-connection timestamp recorded in a
/// verified-package manifest. Callers must still perform full package
/// verification before trusting the value.
pub fn trace_package_created_at_unix_ms(path: &Path) -> Result<u64> {
    Ok(read_trace_manifest(path)?.created_at_unix_ms())
}

/// Completes a deferred proof and writes an offline-verifiable trace package.
#[cfg(feature = "cli")]
pub async fn finalize_bundle(
    bundle_path: &Path,
    output_dir: &Path,
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
    write_trace_package(&capture, output_dir, trusted_notary_key)
}

/// Completes a hosted finalization with a one-time coordinator ticket.
#[cfg(feature = "cli")]
#[allow(clippy::too_many_arguments)]
pub async fn finalize_bundle_admitted(
    bundle_path: &Path,
    output_dir: &Path,
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
    write_trace_package(&capture, output_dir, trusted_notary_key)
}

#[cfg(feature = "cli")]
fn write_trace_package(
    capture: &Capture,
    output_dir: &Path,
    trusted_notary_key: &[u8],
) -> Result<PathBuf> {
    write_trace_package_with_provider(
        capture,
        output_dir,
        trusted_notary_key,
        &CryptoProvider::default(),
    )
}

#[cfg(feature = "cli")]
pub(crate) fn write_trace_package_with_provider(
    capture: &Capture,
    output_dir: &Path,
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

    write_package(output_dir, capture, &trace, &manifest)?;
    Ok(output_dir.to_path_buf())
}

#[cfg(feature = "cli")]
fn write_package(
    output_dir: &Path,
    capture: &Capture,
    trace: &[u8],
    manifest: &VerifiedTraceManifest,
) -> Result<()> {
    if output_dir.exists() {
        bail!(
            "refusing to overwrite existing trace package: {}",
            output_dir.display()
        );
    }
    let staging = create_staging_directory(output_dir)?;

    let result = (|| -> Result<()> {
        fs::write(staging.join("evidence.tlsn"), &capture.evidence)?;
        fs::write(
            staging.join("request.disclosed.http"),
            &capture.request_disclosed,
        )?;
        fs::write(staging.join("response.http"), &capture.response)?;
        fs::write(staging.join("trace.otlp.json"), trace)?;
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_vec_pretty(manifest)?,
        )?;
        fs::rename(&staging, output_dir)
            .with_context(|| format!("finalizing trace package {}", output_dir.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Verifies a trace package and re-runs the deterministic provider adapter.
pub fn verify_trace_package(
    path: &Path,
    trusted_notary_key: &[u8],
) -> Result<VerifiedTraceManifest> {
    verify_trace_package_with_provider(path, trusted_notary_key, &CryptoProvider::default())
}

pub(crate) fn verify_trace_package_with_provider(
    path: &Path,
    trusted_notary_key: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<VerifiedTraceManifest> {
    let manifest = read_trace_manifest(path)?;
    let capture = Capture {
        manifest: manifest.source.clone(),
        evidence: fs::read(path.join("evidence.tlsn"))?,
        request_disclosed: fs::read(path.join("request.disclosed.http"))?,
        response: fs::read(path.join("response.http"))?,
    };
    let (source, request, response) =
        verify_capture_value_with_provider(&capture, trusted_notary_key, crypto_provider)?;
    let inference = verified_inference_from_capture(&source, &request, &response)?;
    let expected = render_public_trace(&[inference])?;
    let actual = fs::read(path.join("trace.otlp.json"))?;
    if manifest.trace_sha256 != sha256_hex(&actual) || actual != expected {
        bail!("OTLP trace does not match the authenticated source bundle");
    }
    Ok(manifest)
}

fn read_trace_manifest(path: &Path) -> Result<VerifiedTraceManifest> {
    let manifest: VerifiedTraceManifest = serde_json::from_slice(
        &fs::read(path.join("manifest.json"))
            .with_context(|| format!("reading package manifest in {}", path.display()))?,
    )
    .context("parsing trace package manifest")?;
    if manifest.format != VERIFIED_TRACE_PACKAGE_FORMAT
        || manifest.normalizer_version != NORMALIZER_VERSION
    {
        bail!("unsupported verified trace package format or normalizer version");
    }
    Ok(manifest)
}
