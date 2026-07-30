use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Args;
use k256::ecdsa::VerifyingKey;
use reqwest::{Client, Response, header};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

use super::DEFAULT_PUBLIC_ORIGIN;
use crate::public::{
    PLATFORM_STAMP_FORMAT, PublicStamp, platform_key_id, validate_public_trace_bytes,
    verify_public_trace_bytes,
};

const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const TRACE_FILE: &str = "trace.otlp.json";
const STAMP_FILE: &str = "stamp.json";

#[derive(Args, Debug)]
pub struct DownloadArgs {
    /// The UUID shown for a public Library publication.
    publication_id: String,

    /// Directory for the downloaded trace and stamp. Defaults to ./<publication-id>.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Replace an existing output directory only after a complete download succeeds.
    #[arg(long)]
    overwrite: bool,

    /// Verify the canonical trace and platform stamp before saving the download.
    #[arg(long)]
    verify: bool,

    /// LLM Notary API origin. Intended for local development and self-hosting.
    #[arg(long, default_value = DEFAULT_PUBLIC_ORIGIN)]
    api: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicTraceMetadata {
    id: String,
    #[allow(dead_code)]
    author: String,
    #[allow(dead_code)]
    admitted_at: i64,
    trace_url: String,
    stamp_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformDirectory {
    format: String,
    issuer: String,
    key_id: String,
    public_key: String,
}

pub async fn run(args: DownloadArgs) -> Result<()> {
    let publication_id = validated_publication_id(&args.publication_id)?;
    let origin = normalize_origin(&args.api)?;
    let output = output_path(&publication_id, args.output)?;
    prepare_output(&output, args.overwrite)?;

    let client = Client::builder()
        .user_agent("llm-notary-cli/0.1")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building public download client")?;
    let metadata_url = origin
        .join(&format!("api/public/traces/{publication_id}"))
        .expect("validated API origin always accepts a relative path");
    let metadata: PublicTraceMetadata =
        get_json(&client, metadata_url, "resolving publication").await?;
    ensure!(
        metadata.id == publication_id,
        "publication API returned metadata for a different publication"
    );
    let trace_url = artifact_url(&origin, &metadata.trace_url, &publication_id, TRACE_FILE)?;
    let stamp_url = artifact_url(&origin, &metadata.stamp_url, &publication_id, STAMP_FILE)?;

    let parent = output_parent(&output)?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".llm-notary-download-")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "creating download staging directory in {}",
                parent.display()
            )
        })?;
    let trace_path = staging.path().join(TRACE_FILE);
    let stamp_path = staging.path().join(STAMP_FILE);
    download_artifact(&client, trace_url, &trace_path, "downloading public trace").await?;
    download_artifact(
        &client,
        stamp_url,
        &stamp_path,
        "downloading platform stamp",
    )
    .await?;

    let trace = fs::read(&trace_path).context("reading downloaded public trace")?;
    let stamp = fs::read(&stamp_path).context("reading downloaded platform stamp")?;
    validate_downloaded_artifacts(&trace, &stamp)?;
    let verified = if args.verify {
        let directory: PlatformDirectory = get_json(
            &client,
            origin
                .join("api/platform")
                .expect("validated API origin always accepts a relative path"),
            "retrieving platform signing key",
        )
        .await?;
        Some(verify_with_platform_directory(&trace, &stamp, directory)?)
    } else {
        None
    };

    let staging_path = staging.keep();
    if let Err(error) = install_output(&staging_path, &output, args.overwrite) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error);
    }

    println!("trace: {}", output.join(TRACE_FILE).display());
    println!("stamp: {}", output.join(STAMP_FILE).display());
    if let Some(verified) = verified {
        println!("verification: passed");
        println!("trace sha256: {}", verified.trace_sha256);
        println!("platform issuer: {}", verified.stamp.issuer);
    }
    Ok(())
}

fn validated_publication_id(value: &str) -> Result<String> {
    let id = Uuid::parse_str(value).context("publication ID must be a UUID")?;
    let canonical = id.hyphenated().to_string();
    ensure!(
        value == canonical,
        "publication ID must be a lowercase hyphenated UUID"
    );
    Ok(canonical)
}

fn normalize_origin(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("--api must be an absolute URL")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("--api must be an HTTP(S) origin without a path, credentials, query, or fragment")
    }
    if url.scheme() == "http" && !is_loopback_url(&url) {
        bail!("--api must use HTTPS except for a loopback development origin")
    }
    url.set_path("/");
    Ok(url)
}

fn is_loopback_url(url: &Url) -> bool {
    url.host().is_some_and(|host| match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    })
}

fn output_path(publication_id: &str, requested: Option<PathBuf>) -> Result<PathBuf> {
    let value = requested.unwrap_or_else(|| PathBuf::from(publication_id));
    let path = if value.is_absolute() {
        value
    } else {
        std::env::current_dir()
            .context("determining current directory")?
            .join(value)
    };
    Ok(path)
}

fn output_parent(output: &Path) -> Result<&Path> {
    output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("download output must name a directory below a parent directory"))
}

fn prepare_output(output: &Path, overwrite: bool) -> Result<()> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", output.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        bail!("download output must not be a symlink")
    }
    if !metadata.is_dir() {
        bail!("download output already exists and is not a directory")
    }
    if !overwrite {
        bail!(
            "download output {} already exists; pass --overwrite to replace it after a successful download",
            output.display()
        )
    }
    Ok(())
}

fn artifact_url(origin: &Url, value: &str, publication_id: &str, file: &str) -> Result<Url> {
    let url = origin
        .join(value)
        .context("publication API returned an invalid artifact URL")?;
    let expected_path = format!("/api/public/traces/{publication_id}/{file}");
    if url.origin() != origin.origin()
        || url.path() != expected_path
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("publication API returned an unsafe artifact URL")
    }
    Ok(url)
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &Client,
    url: Url,
    action: &str,
) -> Result<T> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| action.to_owned())?;
    let bytes = response_bytes(response, action, MAX_METADATA_BYTES).await?;
    serde_json::from_slice(&bytes).with_context(|| format!("reading API response while {action}"))
}

async fn download_artifact(
    client: &Client,
    url: Url,
    destination: &Path,
    action: &str,
) -> Result<()> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| action.to_owned())?;
    validate_response(&response, action)?;
    let temporary = destination.with_extension("json.part");
    let mut file = tokio::fs::File::create(&temporary)
        .await
        .with_context(|| format!("creating {}", temporary.display()))?;
    let mut response = response;
    let mut length = 0usize;
    while let Some(chunk) = response.chunk().await.with_context(|| action.to_owned())? {
        length = length
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("{action} exceeds the maximum artifact size"))?;
        if length > MAX_ARTIFACT_BYTES {
            bail!("{action} exceeds the maximum artifact size")
        }
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing {}", temporary.display()))?;
    }
    file.flush()
        .await
        .with_context(|| format!("flushing {}", temporary.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", temporary.display()))?;
    drop(file);
    tokio::fs::rename(&temporary, destination)
        .await
        .with_context(|| format!("publishing downloaded artifact {}", destination.display()))?;
    Ok(())
}

async fn response_bytes(response: Response, action: &str, limit: usize) -> Result<Vec<u8>> {
    validate_response(&response, action)?;
    let bytes = response.bytes().await.with_context(|| action.to_owned())?;
    if bytes.len() > limit {
        bail!("{action} returned an oversized response")
    }
    Ok(bytes.to_vec())
}

fn validate_response(response: &Response, action: &str) -> Result<()> {
    if response.status().is_redirection() {
        bail!("{action} returned an unexpected redirect")
    }
    if !response.status().is_success() {
        bail!("{action} failed with HTTP {}", response.status())
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim());
    if !matches!(content_type, Some(value) if value.eq_ignore_ascii_case("application/json")) {
        bail!("{action} returned a non-JSON response")
    }
    Ok(())
}

fn validate_downloaded_artifacts(trace: &[u8], stamp: &[u8]) -> Result<()> {
    validate_public_trace_bytes(trace)
        .context("downloaded trace is not a canonical public trace")?;
    let stamp: PublicStamp =
        serde_json::from_slice(stamp).context("downloaded stamp is not a platform stamp")?;
    ensure!(
        stamp.format == PLATFORM_STAMP_FORMAT,
        "downloaded stamp has an unsupported format"
    );
    Ok(())
}

fn verify_with_platform_directory(
    trace: &[u8],
    stamp: &[u8],
    directory: PlatformDirectory,
) -> Result<crate::public::VerifiedPublicTrace> {
    ensure!(
        directory.format == "llm-notary/platform-directory/v1",
        "platform directory has an unsupported format"
    );
    ensure!(
        !directory.issuer.trim().is_empty(),
        "platform directory issuer must not be empty"
    );
    let key =
        hex::decode(&directory.public_key).context("platform directory key is not hexadecimal")?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&key)
        .context("platform directory key is not a secp256k1 SEC1 public key")?;
    ensure!(
        directory.key_id == platform_key_id(&verifying_key),
        "platform directory key ID does not match its public key"
    );
    let verified = verify_public_trace_bytes(trace, stamp, &key)?;
    ensure!(
        verified.stamp.issuer == directory.issuer,
        "platform stamp issuer does not match the platform directory"
    );
    Ok(verified)
}

fn install_output(staging: &Path, output: &Path, overwrite: bool) -> Result<()> {
    let existing = match fs::symlink_metadata(output) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", output.display()));
        }
    };
    if let Some(metadata) = &existing {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("download output changed while downloading")
        }
        if !overwrite {
            bail!("download output was created while downloading")
        }
    }

    if existing.is_none() {
        fs::rename(staging, output)
            .with_context(|| format!("saving download to {}", output.display()))?;
        return Ok(());
    }

    let parent = output_parent(output)?;
    let backup = parent.join(format!(".llm-notary-download-backup-{}", Uuid::new_v4()));
    fs::rename(output, &backup)
        .with_context(|| format!("preparing to replace {}", output.display()))?;
    if let Err(error) = fs::rename(staging, output) {
        let _ = fs::rename(&backup, output);
        return Err(error).with_context(|| format!("saving download to {}", output.display()));
    }
    fs::remove_dir_all(&backup)
        .with_context(|| format!("removing replaced download {}", backup.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get,
    };

    use super::*;

    const ID: &str = "3d3d727f-e0b1-432e-be3c-0b2e3ead35d1";
    const TRACE: &[u8] = include_bytes!("../../tests/fixtures/public-trace/trace.otlp.json");
    const STAMP: &[u8] = include_bytes!("../../tests/fixtures/public-trace/stamp.json");
    const TAMPERED_STAMP: &[u8] =
        include_bytes!("../../tests/fixtures/public-trace/stamp.tampered.json");
    const PUBLIC_KEY: &str = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";

    #[test]
    fn publication_ids_must_be_canonical_uuids() {
        assert_eq!(validated_publication_id(ID).unwrap(), ID);
        assert!(validated_publication_id("../etc/passwd").is_err());
        assert!(validated_publication_id(&ID.to_uppercase()).is_err());
    }

    #[test]
    fn artifact_urls_stay_on_the_public_api() {
        let origin = normalize_origin("https://example.test").unwrap();
        assert!(
            artifact_url(
                &origin,
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/trace.otlp.json",
                ID,
                TRACE_FILE
            )
            .is_ok()
        );
        assert!(
            artifact_url(
                &origin,
                "https://other.test/trace.otlp.json",
                ID,
                TRACE_FILE
            )
            .is_err()
        );
        assert!(
            artifact_url(
                &origin,
                "/api/public/traces/other/trace.otlp.json",
                ID,
                TRACE_FILE
            )
            .is_err()
        );
        assert!(normalize_origin("http://example.test").is_err());
        assert!(normalize_origin("http://127.0.0.1:8787").is_ok());
    }

    #[tokio::test]
    async fn downloads_and_verifies_a_public_fixture_atomically() {
        #[derive(Clone)]
        struct Fixture {
            origin: Arc<str>,
        }
        async fn metadata(State(fixture): State<Fixture>) -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "id": ID,
                "author": "fixture",
                "admitted_at": 1,
                "trace_url": format!("{}/api/public/traces/{ID}/trace.otlp.json", fixture.origin),
                "stamp_url": format!("/api/public/traces/{ID}/stamp.json"),
            }))
        }
        async fn trace() -> impl IntoResponse {
            (
                [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
                TRACE,
            )
        }
        async fn stamp() -> impl IntoResponse {
            (
                [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
                STAMP,
            )
        }
        async fn platform() -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "format": "llm-notary/platform-directory/v1",
                "issuer": "LLM Notary fixture issuer",
                "key_id": "sha256:3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801",
                "public_key": PUBLIC_KEY,
            }))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin: Arc<str> = format!("http://{}", listener.local_addr().unwrap()).into();
        let app = Router::new()
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1",
                get(metadata),
            )
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/trace.otlp.json",
                get(trace),
            )
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/stamp.json",
                get(stamp),
            )
            .route("/api/platform", get(platform))
            .with_state(Fixture {
                origin: origin.clone(),
            });
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("download");
        run(DownloadArgs {
            publication_id: ID.to_owned(),
            output: Some(output.clone()),
            overwrite: false,
            verify: true,
            api: origin.to_string(),
        })
        .await
        .unwrap();
        assert_eq!(fs::read(output.join(TRACE_FILE)).unwrap(), TRACE);
        assert_eq!(fs::read(output.join(STAMP_FILE)).unwrap(), STAMP);

        fs::write(output.join("obsolete"), b"replace me").unwrap();
        run(DownloadArgs {
            publication_id: ID.to_owned(),
            output: Some(output.clone()),
            overwrite: true,
            verify: true,
            api: origin.to_string(),
        })
        .await
        .unwrap();
        assert!(!output.join("obsolete").exists());
        assert_eq!(fs::read(output.join(TRACE_FILE)).unwrap(), TRACE);
    }

    #[tokio::test]
    async fn failed_download_does_not_replace_existing_output() {
        async fn metadata() -> Json<serde_json::Value> {
            Json(serde_json::json!({
                "id": ID, "author": "fixture", "admitted_at": 1,
                "trace_url": format!("/api/public/traces/{ID}/trace.otlp.json"),
                "stamp_url": format!("/api/public/traces/{ID}/stamp.json"),
            }))
        }
        async fn trace() -> impl IntoResponse {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                TRACE,
            )
        }
        async fn broken_stamp() -> impl IntoResponse {
            (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "text/html")],
                "<html>error</html>",
            )
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1",
                get(metadata),
            )
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/trace.otlp.json",
                get(trace),
            )
            .route(
                "/api/public/traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/stamp.json",
                get(broken_stamp),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("download");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("previous"), b"keep me").unwrap();
        assert!(
            run(DownloadArgs {
                publication_id: ID.to_owned(),
                output: Some(output.clone()),
                overwrite: true,
                verify: false,
                api: origin,
            })
            .await
            .is_err()
        );
        assert_eq!(fs::read(output.join("previous")).unwrap(), b"keep me");
        assert!(!output.join(TRACE_FILE).exists());
    }

    #[test]
    fn verification_rejects_a_tampered_stamp() {
        let directory = PlatformDirectory {
            format: "llm-notary/platform-directory/v1".to_owned(),
            issuer: "LLM Notary fixture issuer".to_owned(),
            key_id: "sha256:3828b21f26c49a0ff546f6f4bcee6a64bdc685faf4a961b3c00d05814cda9801"
                .to_owned(),
            public_key: PUBLIC_KEY.to_owned(),
        };
        assert!(verify_with_platform_directory(TRACE, TAMPERED_STAMP, directory).is_err());
    }
}
