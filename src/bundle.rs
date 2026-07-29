//! Deferred bundle finalization and offline-verifiable trace packages.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tlsn::attestation::CryptoProvider;

use crate::{
    Capture, CaptureManifest, DeferredBundle, finalize_deferred_bundle, make_capture,
    normalize::{render_public_trace, verified_inference_from_capture},
    public::NORMALIZER_VERSION,
    sha256_hex,
    vault::Vault,
    verify_capture_value_with_provider,
};

const TRACE_PACKAGE_FORMAT: &str = "llm-notary/verified-trace/v1";

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
}

/// Completes a deferred proof and writes an offline-verifiable trace package.
pub async fn finalize_bundle(
    bundle_path: &Path,
    output_dir: &Path,
    trusted_notary_key: &[u8],
    vault: &Vault,
    notary_addr: SocketAddr,
    max_frame_bytes: usize,
) -> Result<PathBuf> {
    let bundle = DeferredBundle::load(bundle_path, vault)?;
    let proof =
        finalize_deferred_bundle(notary_addr, &bundle, trusted_notary_key, max_frame_bytes).await?;
    let capture = make_capture(
        &proof,
        bundle.capture_id().to_owned(),
        bundle.provider_name().to_owned(),
    )?;
    write_trace_package(&capture, output_dir, trusted_notary_key)
}

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
        format: TRACE_PACKAGE_FORMAT.to_owned(),
        normalizer_version: NORMALIZER_VERSION.to_owned(),
        source,
        trace_sha256: sha256_hex(&trace),
    };

    write_package(output_dir, capture, &trace, &manifest)?;
    Ok(output_dir.to_path_buf())
}

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
    let parent = output_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let package_name = output_dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("trace package path has no directory name"))?
        .to_string_lossy();
    let staging = parent.join(format!(".{package_name}.{}.partial", std::process::id()));
    if staging.exists() {
        bail!(
            "trace package staging directory already exists: {}",
            staging.display()
        );
    }

    let result = (|| -> Result<()> {
        fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;
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
    let manifest: VerifiedTraceManifest = serde_json::from_slice(
        &fs::read(path.join("manifest.json"))
            .with_context(|| format!("reading package manifest in {}", path.display()))?,
    )
    .context("parsing trace package manifest")?;
    if manifest.format != TRACE_PACKAGE_FORMAT || manifest.normalizer_version != NORMALIZER_VERSION
    {
        bail!("unsupported verified trace package format or normalizer version");
    }

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
