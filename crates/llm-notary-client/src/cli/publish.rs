use std::{collections::BTreeMap, path::PathBuf};

use crate::{
    archive::{
        ARCHIVE_CONTENT_TYPE, ARCHIVE_FORMAT, build_trace_package_archive,
        extract_trace_package_archive,
    },
    bundle::{trace_package_created_at_unix_ms, trace_package_notary_key, verify_trace_package},
    cli::{
        api_origin::ApiOrigin, auth, http_client_builder, notary,
        proxy::refresh_notary_directory_from,
    },
    sha256_hex,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use reqwest::{Method, Response, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// One finalized trace package directory produced by `llm-notary finalize`.
    package: PathBuf,

    /// Hex-encoded secp256k1 key used to verify the package's notary evidence.
    #[arg(long)]
    trusted_notary_key: Option<String>,

    /// Print the job result as one JSON object.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct CreatePublishJob<'a> {
    archive_format: &'a str,
    size_bytes: u64,
    sha256: &'a str,
}

#[derive(Deserialize)]
struct CreatePublishJobResponse {
    job: PublishJob,
    upload: Option<UploadInstructions>,
}

#[derive(Clone, Deserialize)]
struct PublishJob {
    id: String,
    state: String,
    status_url: String,
    failure_code: Option<String>,
    trace_url: Option<String>,
    stamp_url: Option<String>,
}

#[derive(Deserialize)]
struct UploadInstructions {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PublishOutput {
    pub(crate) job_id: String,
    pub(crate) state: String,
    pub(crate) status_url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PublicationStatus {
    pub(crate) job_id: String,
    pub(crate) state: String,
    pub(crate) failure_code: Option<String>,
    pub(crate) trace_url: Option<String>,
    pub(crate) stamp_url: Option<String>,
}

pub async fn run(args: PublishArgs) -> Result<()> {
    let (output, capture_id, key_id) =
        publish_package(&args.package, args.trusted_notary_key.as_deref()).await?;
    if args.json {
        println!("{}", serde_json::to_string(&output)?);
    } else {
        println!("submitted verified trace package: {capture_id}");
        println!("trusted notary key: {key_id}");
        println!("publication job: {}", output.job_id);
        println!("state: {}", output.state);
        println!("status: {}", output.status_url);
    }
    Ok(())
}

pub(crate) async fn publish_package(
    package: &std::path::Path,
    trusted_key: Option<&str>,
) -> Result<(PublishOutput, String, String)> {
    reject_bundle_path(package)?;
    // Snapshot the package before verification. Verification and upload then
    // operate on the same immutable archive bytes even if the source directory
    // changes concurrently.
    let archive = build_trace_package_archive(package)
        .context("building deterministic publication archive; nothing was uploaded")?;
    let snapshot = tempfile::tempdir().context("creating private publication snapshot")?;
    let snapshot_path = snapshot.path().join("package");
    extract_trace_package_archive(&archive, &snapshot_path)
        .context("validating private publication snapshot")?;
    let embedded_key = trace_package_notary_key(&snapshot_path)?;
    let (trusted_notary_key, key_id) = match trusted_key {
        Some(value) => notary::explicit_key(value)?,
        None => {
            let created_at = trace_package_created_at_unix_ms(&snapshot_path)?;
            let (key_id, _) = notary::cached_key_at(&embedded_key, created_at)?;
            (embedded_key, key_id)
        }
    };
    let manifest = verify_trace_package(&snapshot_path, &trusted_notary_key)
        .context("local trace package verification failed; nothing was uploaded")?;
    drop(snapshot);
    let archive_sha256 = sha256_hex(&archive);

    // Everything above is intentionally local so malformed packages never
    // create a publication job. Authenticate first to recover the configured
    // API origin, then refresh that origin's directory before any upload.
    let authenticated = auth::authenticate().await?;
    refresh_notary_directory_from(&authenticated.origin).await?;
    notary::cached_key_at(&trusted_notary_key, manifest.created_at_unix_ms())
        .context("the package notary is no longer trusted; nothing was uploaded")?;
    let job = submit_archive(
        &authenticated,
        &archive,
        &archive_sha256,
        &archive_idempotency_key(&archive_sha256),
    )
    .await?;
    let status_url = absolute_status_url(&authenticated.origin, &job.status_url)?;
    let output = PublishOutput {
        job_id: job.id,
        state: job.state,
        status_url,
    };
    Ok((output, manifest.capture_id().to_owned(), key_id))
}

pub(crate) async fn publication_status(job_id: &str) -> Result<PublicationStatus> {
    let authenticated = auth::authenticate().await?;
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building publication status client")?;
    let job = api_json::<PublishJob>(
        client
            .get(
                authenticated
                    .origin
                    .api_url(&format!("/api/publish/jobs/{job_id}")),
            )
            .bearer_auth(&authenticated.access_token)
            .send()
            .await
            .context("polling publication job")?,
        "polling publication job",
    )
    .await?;
    if job.id != job_id {
        bail!("publication API returned the wrong job identifier");
    }
    let trace_url = job
        .trace_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()?;
    let stamp_url = job
        .stamp_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()?;
    Ok(PublicationStatus {
        job_id: job.id,
        state: job.state,
        failure_code: job.failure_code,
        trace_url,
        stamp_url,
    })
}

async fn submit_archive(
    authenticated: &auth::AuthenticatedApi,
    archive: &[u8],
    archive_sha256: &str,
    idempotency_key: &str,
) -> Result<PublishJob> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building publication client")?;
    let created = api_json::<CreatePublishJobResponse>(
        client
            .post(authenticated.origin.api_url("/api/publish/jobs"))
            .bearer_auth(&authenticated.access_token)
            .header("Idempotency-Key", idempotency_key)
            .json(&CreatePublishJob {
                archive_format: ARCHIVE_FORMAT,
                size_bytes: archive.len() as u64,
                sha256: archive_sha256,
            })
            .send()
            .await
            .context("creating publication job")?,
        "creating publication job",
    )
    .await?;

    if created.job.state == "uploading" {
        let upload = created
            .upload
            .ok_or_else(|| anyhow!("publication API omitted upload instructions"))?;
        upload_archive(&client, &authenticated.origin, upload, archive).await?;
        api_json::<PublishJob>(
            client
                .post(
                    authenticated
                        .origin
                        .api_url(&format!("/api/publish/jobs/{}/complete", created.job.id)),
                )
                .bearer_auth(&authenticated.access_token)
                .send()
                .await
                .context("completing publication upload")?,
            "completing publication upload",
        )
        .await?;
    } else if created.upload.is_some() {
        bail!("publication API returned upload instructions for a non-uploading job");
    }

    api_json::<PublishJob>(
        client
            .get(
                authenticated
                    .origin
                    .api_url(&format!("/api/publish/jobs/{}", created.job.id)),
            )
            .bearer_auth(&authenticated.access_token)
            .send()
            .await
            .context("polling publication job")?,
        "polling publication job",
    )
    .await
    .with_context(|| {
        format!(
            "publication job {} was uploaded and completed, but status polling failed",
            created.job.id
        )
    })
}

async fn upload_archive(
    client: &reqwest::Client,
    api_origin: &ApiOrigin,
    instructions: UploadInstructions,
    archive: &[u8],
) -> Result<()> {
    if instructions.method != Method::PUT.as_str() {
        bail!("publication API returned an unsupported upload method");
    }
    let url = validated_upload_url(api_origin, &instructions.url)?;
    let mut headers = header::HeaderMap::new();
    for (name, value) in instructions.headers {
        let name = header::HeaderName::from_bytes(name.as_bytes())
            .context("publication API returned an invalid upload header name")?;
        if matches!(
            name,
            header::AUTHORIZATION | header::COOKIE | header::HOST | header::PROXY_AUTHORIZATION
        ) {
            bail!("publication API returned a forbidden upload header");
        }
        let value = header::HeaderValue::from_str(&value)
            .context("publication API returned an invalid upload header value")?;
        headers.append(name, value);
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(ARCHIVE_CONTENT_TYPE)
    {
        bail!("publication API returned the wrong upload content type");
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        != Some(archive.len().to_string().as_str())
    {
        bail!("publication API returned the wrong upload content length");
    }

    // Never attach the presigned URL to an error: its query is a temporary
    // storage capability and must not appear in logs or terminal history.
    let response = match client
        .request(Method::PUT, url)
        .headers(headers)
        .body(archive.to_vec())
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_timeout() => bail!("publication object upload timed out"),
        Err(_) => bail!("publication object upload request failed"),
    };
    if !response.status().is_success() {
        bail!(
            "publication object upload failed with HTTP {}",
            response.status()
        );
    }
    Ok(())
}

fn archive_idempotency_key(archive_sha256: &str) -> String {
    format!("trace-package:{archive_sha256}")
}

fn validated_upload_url(api_origin: &ApiOrigin, value: &str) -> Result<url::Url> {
    let upload =
        url::Url::parse(value).context("publication API returned an invalid upload URL")?;
    if upload.host_str().is_none()
        || !upload.username().is_empty()
        || upload.password().is_some()
        || upload.fragment().is_some()
    {
        bail!("publication API returned an invalid upload URL");
    }

    let api_is_loopback = api_origin.is_loopback();
    let upload_is_loopback = is_loopback_host(&upload);
    let upload_is_private_ip = upload.host().is_some_and(|host| match host {
        url::Host::Ipv4(address) => {
            address.is_private()
                || address.is_link_local()
                || address.is_loopback()
                || address.is_unspecified()
        }
        url::Host::Ipv6(address) => {
            address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_loopback()
                || address.is_unspecified()
        }
        url::Host::Domain(_) => false,
    });
    if upload.scheme() == "https" && !upload_is_private_ip {
        return Ok(upload);
    }
    if matches!(upload.scheme(), "http" | "https") && api_is_loopback && upload_is_loopback {
        return Ok(upload);
    }
    bail!("publication uploads require a public HTTPS URL (loopback HTTP is development-only)")
}

fn is_loopback_host(url: &url::Url) -> bool {
    url.host().is_some_and(|host| match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    })
}

async fn api_json<T: DeserializeOwned>(response: Response, action: &str) -> Result<T> {
    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .await
            .with_context(|| format!("reading API response while {action}"));
    }
    let message = response
        .json::<ApiErrorResponse>()
        .await
        .ok()
        .map(|body| body.error)
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("request failed")
                .to_owned()
        });
    if status == StatusCode::UNAUTHORIZED {
        bail!("{action} failed: {message}; run `llm-notary login` again");
    }
    bail!("{action} failed with HTTP {status}: {message}")
}

fn absolute_status_url(origin: &ApiOrigin, status_url: &str) -> Result<String> {
    absolute_same_origin_url(origin, status_url)
}

fn absolute_same_origin_url(origin: &ApiOrigin, value: &str) -> Result<String> {
    let url = origin
        .url()
        .join(value)
        .context("publication API returned an invalid same-origin URL")?;
    if url.origin() != origin.url().origin() {
        bail!("publication API returned a cross-origin URL");
    }
    Ok(url.to_string())
}

fn reject_bundle_path(path: &std::path::Path) -> Result<()> {
    if path
        .extension()
        .is_some_and(|extension| extension == "llmbundle")
    {
        bail!("encrypted .llmbundle files cannot be published; run `llm-notary finalize` first");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::{get, post, put},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct MockState {
        uploaded: Arc<Mutex<Vec<u8>>>,
    }

    #[tokio::test]
    async fn submits_uploads_completes_and_polls() {
        async fn create(
            State(origin): State<String>,
            headers: HeaderMap,
            Json(request): Json<serde_json::Value>,
        ) -> (StatusCode, Json<serde_json::Value>) {
            assert!(headers.contains_key("authorization"));
            assert!(headers.contains_key("idempotency-key"));
            let size = request["size_bytes"].as_u64().unwrap();
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "job": {"id":"job-1","state":"uploading","status_url":"/api/publish/jobs/job-1"},
                    "upload": {
                        "method":"PUT",
                        "url":format!("{origin}/upload"),
                        "headers":{
                            "content-length":size.to_string(),
                            "content-type":ARCHIVE_CONTENT_TYPE
                        }
                    }
                })),
            )
        }
        async fn upload(State(state): State<MockState>, bytes: Bytes) -> StatusCode {
            *state.uploaded.lock().unwrap() = bytes.to_vec();
            StatusCode::NO_CONTENT
        }
        async fn complete(Path(job_id): Path<String>) -> Json<serde_json::Value> {
            assert_eq!(job_id, "job-1");
            Json(serde_json::json!({
                "id":"job-1","state":"queued","status_url":"/api/publish/jobs/job-1"
            }))
        }
        async fn status(Path(job_id): Path<String>) -> Json<serde_json::Value> {
            assert_eq!(job_id, "job-1");
            Json(serde_json::json!({
                "id":"job-1","state":"queued","status_url":"/api/publish/jobs/job-1"
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let uploads = MockState::default();
        let app = Router::new()
            .route(
                "/api/publish/jobs",
                post({
                    let origin = origin.clone();
                    move |headers, body| create(State(origin.clone()), headers, body)
                }),
            )
            .route("/api/publish/jobs/{job_id}/complete", post(complete))
            .route("/api/publish/jobs/{job_id}", get(status))
            .route("/upload", put(upload))
            .with_state(uploads.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let authenticated = auth::AuthenticatedApi {
            origin: ApiOrigin::parse(&origin).unwrap(),
            access_token: "access-token".to_owned(),
        };
        let archive = b"deterministic archive";
        let result = submit_archive(
            &authenticated,
            archive,
            &sha256_hex(archive),
            "idempotency-key",
        )
        .await
        .unwrap();
        assert_eq!(result.id, "job-1");
        assert_eq!(result.state, "queued");
        assert_eq!(&*uploads.uploaded.lock().unwrap(), archive);
        server.abort();
    }

    #[test]
    fn rejects_private_bundle_paths_and_cross_origin_status_urls() {
        assert!(reject_bundle_path(PathBuf::from("secret.llmbundle").as_path()).is_err());
        assert!(
            absolute_status_url(
                &ApiOrigin::parse("https://llmnotary.example").unwrap(),
                "https://attacker.example/job"
            )
            .is_err()
        );
        let digest = "a".repeat(64);
        assert_eq!(
            archive_idempotency_key(&digest),
            format!("trace-package:{digest}")
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("https://llmnotary.example").unwrap(),
                "http://objects.example/upload"
            )
            .is_err()
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("https://llmnotary.example").unwrap(),
                "https://127.0.0.1/upload"
            )
            .is_err()
        );
        assert!(
            validated_upload_url(
                &ApiOrigin::parse("http://127.0.0.1:3000").unwrap(),
                "http://127.0.0.1:9000/upload"
            )
            .is_ok()
        );
    }
}
