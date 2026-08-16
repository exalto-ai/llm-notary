use std::collections::BTreeMap;

use crate::{
    archive::{ARCHIVE_CONTENT_TYPE, ARCHIVE_FORMAT},
    bundle::{
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    metadata::SharedNotaryTrust,
    public_safety::{
        PublicPackageSafetyContext, validate_public_trace_package_with_context_and_force,
    },
    service::{
        api_origin::ApiOrigin, auth, http_client_builder, notary,
        proxy::refresh_notary_directory_from,
    },
    sha256_hex,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use reqwest::{Method, Response, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ShareVisibility {
    Unlisted,
    Listed,
}

impl ShareVisibility {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
}

#[derive(Serialize)]
struct CreateShare<'a> {
    archive_format: &'a str,
    size_bytes: u64,
    sha256: &'a str,
    visibility: &'a str,
    force: bool,
}

#[derive(Deserialize)]
struct CreateShareResponse {
    share: ShareJob,
    upload: Option<UploadInstructions>,
}

#[derive(Clone, Deserialize)]
struct ShareJob {
    id: String,
    state: String,
    visibility: ShareVisibility,
    status_url: String,
    failure_code: Option<String>,
    share_url: Option<String>,
    package_url: Option<String>,
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
pub(crate) struct ShareOutput {
    pub(crate) share_id: String,
    pub(crate) state: String,
    pub(crate) status_url: String,
    pub(crate) visibility: ShareVisibility,
    pub(crate) share_url: Option<String>,
    pub(crate) package_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShareStatus {
    pub(crate) share_id: String,
    pub(crate) state: String,
    pub(crate) failure_code: Option<String>,
    pub(crate) share_url: Option<String>,
    pub(crate) package_url: Option<String>,
    pub(crate) visibility: ShareVisibility,
}

#[derive(Debug)]
pub(crate) enum ShareStatusError {
    Authentication,
    NotFound,
    Unavailable,
}

/// Verifies and shares exact already-snapshotted package bytes.
pub(crate) async fn share_package_bytes(
    archive: &[u8],
    trusted_key: Option<&str>,
    shared_trust: Option<&SharedNotaryTrust>,
    visibility: ShareVisibility,
    force: bool,
) -> Result<(ShareOutput, String, String)> {
    let embedded_key = trace_package_notary_key_bytes(archive)
        .context("validating finalized .llmtrace; nothing was uploaded")?;
    let (trusted_notary_key, key_id) = match trusted_key {
        Some(value) => notary::explicit_key(value)?,
        None => {
            let created_at = trace_package_created_at_unix_ms_bytes(archive)?;
            let (key_id, _) = match shared_trust {
                Some(shared) => notary::shared_key_at(shared, &embedded_key, created_at)?,
                None => notary::cached_key_at(&embedded_key, created_at)?,
            };
            (embedded_key, key_id)
        }
    };
    let verified = verify_trace_package_bytes(archive, &trusted_notary_key)
        .context("local trace package verification failed; nothing was uploaded")?;
    validate_public_trace_package_with_context_and_force(
        archive,
        PublicPackageSafetyContext {
            provider_host: verified.manifest.provider_host(),
            request_path: &verified.request_path,
        },
        force,
    )
    .context("local public disclosure safety check failed; nothing was uploaded")?;
    let archive_sha256 = sha256_hex(archive);

    // Everything above is intentionally local so malformed packages never
    // create a share. Authenticate first to recover the configured
    // API origin, then refresh that origin's directory before any upload.
    let authenticated = auth::authenticate().await?;
    if let Some(shared) = shared_trust {
        notary::shared_key_at(
            shared,
            &trusted_notary_key,
            verified.manifest.created_at_unix_ms(),
        )
        .context("the package notary is no longer trusted; nothing was uploaded")?;
    } else {
        refresh_notary_directory_from(&authenticated.origin).await?;
        notary::cached_key_at(&trusted_notary_key, verified.manifest.created_at_unix_ms())
            .context("the package notary is no longer trusted; nothing was uploaded")?;
    }
    let share = submit_archive(
        &authenticated,
        archive,
        &archive_sha256,
        &archive_idempotency_key(&archive_sha256, visibility, force),
        visibility,
        force,
    )
    .await?;
    let status_url = absolute_status_url(&authenticated.origin, &share.status_url)?;
    let share_url = share
        .share_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()?;
    let package_url = share
        .package_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()?;
    let output = ShareOutput {
        share_id: share.id,
        state: share.state,
        status_url,
        visibility: share.visibility,
        share_url,
        package_url,
    };
    Ok((output, verified.manifest.capture_id().to_owned(), key_id))
}

pub(crate) async fn share_status(
    share_id: &str,
) -> std::result::Result<ShareStatus, ShareStatusError> {
    let authenticated = auth::authenticate_for_publication_status()
        .await
        .map_err(|error| match error {
            auth::PublicationAuthenticationError::Required => ShareStatusError::Authentication,
            auth::PublicationAuthenticationError::Unavailable => ShareStatusError::Unavailable,
        })?;
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ShareStatusError::Unavailable)?;
    let response = client
        .get(
            authenticated
                .origin
                .api_url(&format!("/api/shares/{share_id}")),
        )
        .bearer_auth(&authenticated.access_token)
        .send()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    if let Some(error) = share_status_http_error(response.status()) {
        return Err(error);
    }
    let share = response
        .json::<ShareJob>()
        .await
        .map_err(|_| ShareStatusError::Unavailable)?;
    if share.id != share_id {
        return Err(ShareStatusError::Unavailable);
    }
    let share_url = share
        .share_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()
        .map_err(|_| ShareStatusError::Unavailable)?;
    let package_url = share
        .package_url
        .as_deref()
        .map(|value| absolute_same_origin_url(&authenticated.origin, value))
        .transpose()
        .map_err(|_| ShareStatusError::Unavailable)?;
    Ok(ShareStatus {
        share_id: share.id,
        state: share.state,
        failure_code: share.failure_code,
        share_url,
        package_url,
        visibility: share.visibility,
    })
}

fn share_status_http_error(status: StatusCode) -> Option<ShareStatusError> {
    match status {
        StatusCode::NOT_FOUND => Some(ShareStatusError::NotFound),
        StatusCode::UNAUTHORIZED => Some(ShareStatusError::Authentication),
        status if !status.is_success() => Some(ShareStatusError::Unavailable),
        _ => None,
    }
}

async fn submit_archive(
    authenticated: &auth::AuthenticatedApi,
    archive: &[u8],
    archive_sha256: &str,
    idempotency_key: &str,
    visibility: ShareVisibility,
    force: bool,
) -> Result<ShareJob> {
    let client = http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building share client")?;
    let created = api_json::<CreateShareResponse>(
        client
            .post(authenticated.origin.api_url("/api/shares"))
            .bearer_auth(&authenticated.access_token)
            .header("Idempotency-Key", idempotency_key)
            .json(&CreateShare {
                archive_format: ARCHIVE_FORMAT,
                size_bytes: archive.len() as u64,
                sha256: archive_sha256,
                visibility: visibility.as_str(),
                force,
            })
            .send()
            .await
            .context("creating share")?,
        "creating share",
    )
    .await?;

    if created.share.state == "uploading" {
        let upload = created
            .upload
            .ok_or_else(|| anyhow!("share API omitted upload instructions"))?;
        upload_archive(&client, &authenticated.origin, upload, archive).await?;
        api_json::<ShareJob>(
            client
                .post(
                    authenticated
                        .origin
                        .api_url(&format!("/api/shares/{}/complete", created.share.id)),
                )
                .bearer_auth(&authenticated.access_token)
                .send()
                .await
                .context("completing share upload")?,
            "completing share upload",
        )
        .await?;
    } else if created.upload.is_some() {
        bail!("share API returned upload instructions for a non-uploading share");
    }

    api_json::<ShareJob>(
        client
            .get(
                authenticated
                    .origin
                    .api_url(&format!("/api/shares/{}", created.share.id)),
            )
            .bearer_auth(&authenticated.access_token)
            .send()
            .await
            .context("polling share")?,
        "polling share",
    )
    .await
    .with_context(|| {
        format!(
            "share {} was uploaded and completed, but status polling failed",
            created.share.id
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
        bail!("share API returned an unsupported upload method");
    }
    let url = validated_upload_url(api_origin, &instructions.url)?;
    let mut headers = header::HeaderMap::new();
    for (name, value) in instructions.headers {
        let name = header::HeaderName::from_bytes(name.as_bytes())
            .context("share API returned an invalid upload header name")?;
        if matches!(
            name,
            header::AUTHORIZATION | header::COOKIE | header::HOST | header::PROXY_AUTHORIZATION
        ) {
            bail!("share API returned a forbidden upload header");
        }
        let value = header::HeaderValue::from_str(&value)
            .context("share API returned an invalid upload header value")?;
        headers.append(name, value);
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(ARCHIVE_CONTENT_TYPE)
    {
        bail!("share API returned the wrong upload content type");
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        != Some(archive.len().to_string().as_str())
    {
        bail!("share API returned the wrong upload content length");
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
        Err(error) if error.is_timeout() => bail!("share object upload timed out"),
        Err(_) => bail!("share object upload request failed"),
    };
    if !response.status().is_success() {
        bail!("share object upload failed with HTTP {}", response.status());
    }
    Ok(())
}

fn archive_idempotency_key(
    archive_sha256: &str,
    visibility: ShareVisibility,
    force: bool,
) -> String {
    let base = format!("trace-package:{archive_sha256}:{}", visibility.as_str());
    if force { format!("{base}:force") } else { base }
}

fn validated_upload_url(api_origin: &ApiOrigin, value: &str) -> Result<url::Url> {
    let upload = url::Url::parse(value).context("share API returned an invalid upload URL")?;
    if upload.host_str().is_none()
        || !upload.username().is_empty()
        || upload.password().is_some()
        || upload.fragment().is_some()
    {
        bail!("share API returned an invalid upload URL");
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
    bail!("share uploads require a public HTTPS URL (loopback HTTP is development-only)")
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
        bail!(
            "{action} failed: {message}; connect an account through the local dashboard or administration API"
        );
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
        .context("share API returned an invalid same-origin URL")?;
    if url.origin() != origin.url().origin() {
        bail!("share API returned a cross-origin URL");
    }
    Ok(url.to_string())
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
            assert_eq!(request["visibility"], "unlisted");
            assert_eq!(request["force"], true);
            let size = request["size_bytes"].as_u64().unwrap();
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "share": {"id":"job-1","state":"uploading","visibility":"unlisted","status_url":"/api/shares/job-1"},
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
                "id":"job-1","state":"queued","visibility":"unlisted","status_url":"/api/shares/job-1"
            }))
        }
        async fn status(Path(job_id): Path<String>) -> Json<serde_json::Value> {
            assert_eq!(job_id, "job-1");
            Json(serde_json::json!({
                "id":"job-1","state":"queued","visibility":"unlisted","status_url":"/api/shares/job-1"
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let uploads = MockState::default();
        let app = Router::new()
            .route(
                "/api/shares",
                post({
                    let origin = origin.clone();
                    move |headers, body| create(State(origin.clone()), headers, body)
                }),
            )
            .route("/api/shares/{job_id}/complete", post(complete))
            .route("/api/shares/{job_id}", get(status))
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
            ShareVisibility::Unlisted,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.id, "job-1");
        assert_eq!(result.state, "queued");
        assert_eq!(&*uploads.uploaded.lock().unwrap(), archive);
        server.abort();
    }

    #[test]
    fn rejects_cross_origin_status_urls() {
        assert!(
            absolute_status_url(
                &ApiOrigin::parse("https://llmnotary.example").unwrap(),
                "https://attacker.example/job"
            )
            .is_err()
        );
        let digest = "a".repeat(64);
        assert_eq!(
            archive_idempotency_key(&digest, ShareVisibility::Listed, false),
            format!("trace-package:{digest}:listed")
        );
        assert_eq!(
            archive_idempotency_key(&digest, ShareVisibility::Listed, true),
            format!("trace-package:{digest}:listed:force")
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

    #[test]
    fn publication_status_preserves_not_found_authentication_and_outage_errors() {
        assert!(matches!(
            share_status_http_error(StatusCode::NOT_FOUND),
            Some(ShareStatusError::NotFound)
        ));
        assert!(matches!(
            share_status_http_error(StatusCode::UNAUTHORIZED),
            Some(ShareStatusError::Authentication)
        ));
        assert!(matches!(
            share_status_http_error(StatusCode::BAD_GATEWAY),
            Some(ShareStatusError::Unavailable)
        ));
        assert!(share_status_http_error(StatusCode::OK).is_none());
    }
}
