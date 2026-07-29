use std::{collections::BTreeMap, env, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    presigning::PresigningConfig,
};

pub const ARCHIVE_FORMAT: &str = "llmnotary.trace-package-archive/v1";
pub const ARCHIVE_CONTENT_TYPE: &str = "application/vnd.llmnotary.trace-package+zip";

const SHA256_METADATA: &str = "declared-sha256";
const FORMAT_METADATA: &str = "archive-format";

#[derive(Clone)]
pub enum IntakeStorage {
    Disabled,
    S3(S3IntakeStorage),
    #[cfg(test)]
    Mock(MockIntakeStorage),
}

#[derive(Clone)]
pub struct S3IntakeStorage {
    client: Client,
    bucket: String,
    prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub size_bytes: i64,
    pub metadata: BTreeMap<String, String>,
}

impl IntakeStorage {
    pub fn from_env() -> Result<Self> {
        let Some(bucket) = optional_env("LLM_NOTARY_S3_BUCKET") else {
            return Ok(Self::Disabled);
        };
        validate_bucket(&bucket)?;
        let endpoint = required_env("LLM_NOTARY_S3_ENDPOINT")?;
        validate_endpoint(&endpoint)?;
        let region = required_env("LLM_NOTARY_S3_REGION")?;
        let access_key_id = required_env("LLM_NOTARY_S3_ACCESS_KEY_ID")?;
        let secret_access_key = required_env("LLM_NOTARY_S3_SECRET_ACCESS_KEY")?;
        let prefix = env::var("LLM_NOTARY_S3_PREFIX").unwrap_or_else(|_| "llm-notary".to_owned());
        validate_prefix(&prefix)?;
        let force_path_style = optional_bool_env("LLM_NOTARY_S3_FORCE_PATH_STYLE")?.unwrap_or(true);

        let credentials = Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "llm-notary-environment",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(region))
            .endpoint_url(endpoint)
            .force_path_style(force_path_style)
            .build();
        Ok(Self::S3(S3IntakeStorage {
            client: Client::from_conf(config),
            bucket,
            prefix: prefix.trim_matches('/').to_owned(),
        }))
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub async fn validate(&self) -> Result<()> {
        match self {
            Self::Disabled => Ok(()),
            Self::S3(storage) => {
                storage
                    .client
                    .head_bucket()
                    .bucket(&storage.bucket)
                    .send()
                    .await
                    .context("accessing configured Spaces intake bucket")?;
                Ok(())
            }
            #[cfg(test)]
            Self::Mock(_) => Ok(()),
        }
    }

    pub fn upload_object_key(&self, user_id: &str, job_id: &str, nonce: &str) -> Result<String> {
        validate_identifier(user_id, "user ID")?;
        validate_identifier(job_id, "job ID")?;
        validate_identifier(nonce, "upload nonce")?;
        let prefix = self.prefix()?;
        Ok(format!(
            "{prefix}/uploads/{user_id}/{job_id}/{nonce}.llmtrace"
        ))
    }

    pub fn intake_object_key(&self, user_id: &str, job_id: &str) -> Result<String> {
        validate_identifier(user_id, "user ID")?;
        validate_identifier(job_id, "job ID")?;
        let prefix = self.prefix()?;
        Ok(format!("{prefix}/intake/{user_id}/{job_id}.llmtrace"))
    }

    pub async fn presign_upload(
        &self,
        object_key: &str,
        size_bytes: i64,
        declared_sha256: &str,
        expires_in: Duration,
    ) -> Result<UploadRequest> {
        match self {
            Self::Disabled => bail!("publication intake storage is disabled"),
            Self::S3(storage) => {
                let presigned = storage
                    .client
                    .put_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .content_length(size_bytes)
                    .content_type(ARCHIVE_CONTENT_TYPE)
                    .metadata(SHA256_METADATA, declared_sha256)
                    .metadata(FORMAT_METADATA, ARCHIVE_FORMAT)
                    .presigned(
                        PresigningConfig::expires_in(expires_in)
                            .context("invalid upload URL lifetime")?,
                    )
                    .await
                    .context("presigning Spaces upload")?;
                Ok(UploadRequest {
                    method: presigned.method().to_owned(),
                    url: presigned.uri().to_owned(),
                    headers: presigned
                        .headers()
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .collect(),
                })
            }
            #[cfg(test)]
            Self::Mock(storage) => {
                storage.presign_calls.lock().expect("mock lock").push((
                    object_key.to_owned(),
                    size_bytes,
                    declared_sha256.to_owned(),
                ));
                Ok(UploadRequest {
                    method: "PUT".to_owned(),
                    url: format!("https://uploads.example/{object_key}"),
                    headers: BTreeMap::from([
                        ("content-length".to_owned(), size_bytes.to_string()),
                        ("content-type".to_owned(), ARCHIVE_CONTENT_TYPE.to_owned()),
                        (
                            format!("x-amz-meta-{SHA256_METADATA}"),
                            declared_sha256.to_owned(),
                        ),
                        (
                            format!("x-amz-meta-{FORMAT_METADATA}"),
                            ARCHIVE_FORMAT.to_owned(),
                        ),
                    ]),
                })
            }
        }
    }

    pub async fn head_object(&self, object_key: &str) -> Result<Option<StoredObject>> {
        match self {
            Self::Disabled => bail!("publication intake storage is disabled"),
            Self::S3(storage) => {
                match storage
                    .client
                    .head_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .send()
                    .await
                {
                    Ok(output) => Ok(Some(StoredObject {
                        size_bytes: output.content_length().unwrap_or_default(),
                        metadata: output
                            .metadata()
                            .cloned()
                            .unwrap_or_default()
                            .into_iter()
                            .collect(),
                    })),
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(anyhow!(error).context("reading Spaces object metadata")),
                }
            }
            #[cfg(test)]
            Self::Mock(storage) => Ok(storage
                .objects
                .lock()
                .expect("mock lock")
                .get(object_key)
                .cloned()),
        }
    }

    pub async fn promote_object(&self, source_key: &str, destination_key: &str) -> Result<()> {
        match self {
            Self::Disabled => bail!("publication intake storage is disabled"),
            Self::S3(storage) => {
                storage
                    .client
                    .copy_object()
                    .bucket(&storage.bucket)
                    .key(destination_key)
                    .copy_source(format!("{}/{}", storage.bucket, source_key))
                    .send()
                    .await
                    .context("promoting uploaded Spaces object")?;
                Ok(())
            }
            #[cfg(test)]
            Self::Mock(storage) => {
                let mut objects = storage.objects.lock().expect("mock lock");
                let object = objects
                    .get(source_key)
                    .cloned()
                    .ok_or_else(|| anyhow!("mock source object is missing"))?;
                objects.insert(destination_key.to_owned(), object);
                Ok(())
            }
        }
    }

    pub async fn delete_object(&self, object_key: &str) -> Result<()> {
        match self {
            Self::Disabled => Ok(()),
            Self::S3(storage) => {
                storage
                    .client
                    .delete_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .send()
                    .await
                    .context("deleting Spaces intake object")?;
                Ok(())
            }
            #[cfg(test)]
            Self::Mock(storage) => {
                storage
                    .objects
                    .lock()
                    .expect("mock lock")
                    .remove(object_key);
                storage
                    .deleted
                    .lock()
                    .expect("mock lock")
                    .push(object_key.to_owned());
                Ok(())
            }
        }
    }

    pub fn has_expected_metadata(object: &StoredObject, sha256: &str) -> bool {
        object
            .metadata
            .get(SHA256_METADATA)
            .is_some_and(|value| value == sha256)
            && object
                .metadata
                .get(FORMAT_METADATA)
                .is_some_and(|value| value == ARCHIVE_FORMAT)
    }

    fn prefix(&self) -> Result<&str> {
        match self {
            Self::Disabled => bail!("publication intake storage is disabled"),
            Self::S3(storage) => Ok(&storage.prefix),
            #[cfg(test)]
            Self::Mock(storage) => Ok(&storage.prefix),
        }
    }
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required_env(name: &str) -> Result<String> {
    optional_env(name).ok_or_else(|| anyhow!("{name} must be set when Spaces intake is enabled"))
}

fn optional_bool_env(name: &str) -> Result<Option<bool>> {
    optional_env(name)
        .map(|value| match value.as_str() {
            "1" | "true" | "TRUE" => Ok(true),
            "0" | "false" | "FALSE" => Ok(false),
            _ => bail!("{name} must be true or false"),
        })
        .transpose()
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = url::Url::parse(endpoint).context("LLM_NOTARY_S3_ENDPOINT must be a URL")?;
    if endpoint.scheme() != "https"
        && !(endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost")))
    {
        bail!("LLM_NOTARY_S3_ENDPOINT must use HTTPS except for local test services");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("LLM_NOTARY_S3_ENDPOINT must not contain a query or fragment");
    }
    Ok(())
}

fn validate_bucket(bucket: &str) -> Result<()> {
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
    {
        bail!("LLM_NOTARY_S3_BUCKET is not a valid lowercase bucket name");
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<()> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty()
        || trimmed.len() > 120
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "..")
    {
        bail!("LLM_NOTARY_S3_PREFIX must be a safe, non-empty object prefix");
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{label} contains characters that are unsafe in an object key");
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Default)]
pub struct MockIntakeStorage {
    prefix: String,
    pub objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, StoredObject>>>,
    pub deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    pub presign_calls: std::sync::Arc<std::sync::Mutex<Vec<(String, i64, String)>>>,
}

#[cfg(test)]
impl MockIntakeStorage {
    pub fn new() -> Self {
        Self {
            prefix: "test".to_owned(),
            ..Self::default()
        }
    }

    pub fn object(&self, key: impl Into<String>, size_bytes: i64, sha256: &str) {
        self.objects.lock().expect("mock lock").insert(
            key.into(),
            StoredObject {
                size_bytes,
                metadata: BTreeMap::from([
                    (SHA256_METADATA.to_owned(), sha256.to_owned()),
                    (FORMAT_METADATA.to_owned(), ARCHIVE_FORMAT.to_owned()),
                ]),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    #[ignore = "requires an explicitly configured private S3-compatible test bucket"]
    async fn live_s3_presigned_upload_and_promotion_round_trip() {
        let storage = IntakeStorage::from_env().expect("S3 intake configuration");
        assert!(storage.is_enabled(), "S3 intake must be configured");
        storage.validate().await.expect("S3 bucket access");
        let job_id = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().simple().to_string();
        let upload_key = storage
            .upload_object_key("integration-user", &job_id, &nonce)
            .expect("upload key");
        let intake_key = storage
            .intake_object_key("integration-user", &job_id)
            .expect("intake key");
        let payload = b"LLM Notary private intake integration check";
        let sha256 = hex::encode(Sha256::digest(payload));
        let upload = storage
            .presign_upload(
                &upload_key,
                payload.len() as i64,
                &sha256,
                Duration::from_secs(60),
            )
            .await
            .expect("presigned upload");
        assert_eq!(upload.method, "PUT");
        let mut request = reqwest::Client::new()
            .put(&upload.url)
            .body(payload.as_slice());
        for (name, value) in upload.headers {
            request = request.header(name, value);
        }
        request
            .send()
            .await
            .expect("upload request")
            .error_for_status()
            .expect("successful upload");

        let staged = storage
            .head_object(&upload_key)
            .await
            .expect("staging metadata")
            .expect("staging object");
        assert_eq!(staged.size_bytes, payload.len() as i64);
        assert!(IntakeStorage::has_expected_metadata(&staged, &sha256));

        storage
            .promote_object(&upload_key, &intake_key)
            .await
            .expect("promotion");
        let promoted = storage
            .head_object(&intake_key)
            .await
            .expect("intake metadata")
            .expect("intake object");
        assert_eq!(promoted, staged);

        storage
            .delete_object(&upload_key)
            .await
            .expect("delete staging object");
        storage
            .delete_object(&intake_key)
            .await
            .expect("delete intake object");
    }
}
