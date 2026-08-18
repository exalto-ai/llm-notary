use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    presigning::PresigningConfig,
    primitives::ByteStream,
};

pub use notary_core::archive::{ARCHIVE_CONTENT_TYPE, TRACE_PACKAGE_FORMAT as PACKAGE_FORMAT};

use crate::config::TraceStorageConfig;

const SHA256_METADATA: &str = "declared-sha256";
const FORMAT_METADATA: &str = "archive-format";
const PUBLIC_SHA256_METADATA: &str = "artifact-sha256";
const PUBLIC_KIND_METADATA: &str = "artifact-kind";

#[derive(Clone)]
pub enum TraceStorage {
    Disabled,
    S3(S3TraceStorage),
    #[cfg(test)]
    Mock(MockTraceStorage),
}

#[derive(Clone)]
pub struct S3TraceStorage {
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

impl TraceStorage {
    pub fn from_config(config: &TraceStorageConfig) -> Result<Self> {
        let Some(storage) = &config.s3 else {
            return Ok(Self::Disabled);
        };

        let credentials = Credentials::new(
            storage.access_key_id.clone(),
            storage.secret_access_key.clone(),
            None,
            None,
            "notary-api-config",
        );
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(credentials)
            .region(Region::new(storage.region.clone()))
            .endpoint_url(storage.endpoint.as_str())
            .force_path_style(storage.force_path_style)
            .build();
        Ok(Self::S3(S3TraceStorage {
            client: Client::from_conf(config),
            bucket: storage.bucket.clone(),
            prefix: storage.prefix.clone(),
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

    pub fn staging_object_key(
        &self,
        account_id: &str,
        trace_id: &str,
        upload_generation: i64,
    ) -> Result<String> {
        validate_identifier(account_id, "Account ID")?;
        validate_identifier(trace_id, "Trace ID")?;
        if upload_generation < 0 {
            bail!("upload generation must not be negative");
        }
        let prefix = self.prefix()?;
        Ok(format!(
            "{prefix}/staging/{account_id}/{trace_id}/{upload_generation}.llmtrace"
        ))
    }

    pub fn committed_staging_object_key(
        &self,
        account_id: &str,
        job_id: &str,
        upload_generation: i64,
    ) -> Result<String> {
        validate_identifier(account_id, "Account ID")?;
        validate_identifier(job_id, "Trace ID")?;
        if upload_generation < 0 {
            bail!("upload generation must not be negative");
        }
        let prefix = self.prefix()?;
        Ok(format!(
            "{prefix}/staging/{account_id}/{job_id}/{upload_generation}-committed.llmtrace"
        ))
    }

    pub fn committed_artifact_key(
        &self,
        trace_id: &str,
        verification_claim: &str,
        kind: &str,
        sha256: &str,
    ) -> Result<String> {
        validate_identifier(trace_id, "trace ID")?;
        validate_identifier(verification_claim, "verification claim")?;
        if !matches!(kind, "content" | "package") {
            bail!("committed artifact kind is unsupported");
        }
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("public artifact SHA-256 is invalid");
        }
        let prefix = self.prefix()?;
        let (segment, extension) = match kind {
            "package" => ("packages", "llmtrace"),
            "content" => ("content", "json"),
            _ => unreachable!("validated above"),
        };
        Ok(format!(
            "{prefix}/{segment}/{trace_id}/{verification_claim}/{sha256}.{extension}"
        ))
    }

    pub async fn presign_upload(
        &self,
        object_key: &str,
        size_bytes: i64,
        declared_package_sha256: &str,
        expires_in: Duration,
    ) -> Result<UploadRequest> {
        match self {
            Self::Disabled => bail!("hosted Trace staging storage is disabled"),
            Self::S3(storage) => {
                let presigned = storage
                    .client
                    .put_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .content_length(size_bytes)
                    .content_type(ARCHIVE_CONTENT_TYPE)
                    .metadata(SHA256_METADATA, declared_package_sha256)
                    .metadata(FORMAT_METADATA, PACKAGE_FORMAT)
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
                    declared_package_sha256.to_owned(),
                ));
                Ok(UploadRequest {
                    method: "PUT".to_owned(),
                    url: format!("https://uploads.example/{object_key}"),
                    headers: BTreeMap::from([
                        ("content-length".to_owned(), size_bytes.to_string()),
                        ("content-type".to_owned(), ARCHIVE_CONTENT_TYPE.to_owned()),
                        (
                            format!("x-amz-meta-{SHA256_METADATA}"),
                            declared_package_sha256.to_owned(),
                        ),
                        (
                            format!("x-amz-meta-{FORMAT_METADATA}"),
                            PACKAGE_FORMAT.to_owned(),
                        ),
                    ]),
                })
            }
        }
    }

    pub async fn head_object(&self, object_key: &str) -> Result<Option<StoredObject>> {
        match self {
            Self::Disabled => bail!("hosted Trace staging storage is disabled"),
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

    pub async fn get_object(&self, object_key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Disabled => bail!("hosted Trace staging storage is disabled"),
            Self::S3(storage) => {
                let output = match storage
                    .client
                    .get_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .send()
                    .await
                {
                    Ok(output) => output,
                    Err(error)
                        if error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 404) =>
                    {
                        return Ok(None);
                    }
                    Err(error) => {
                        return Err(anyhow!(error).context("downloading Spaces intake object"));
                    }
                };
                if output.content_length().unwrap_or_default() < 0
                    || output.content_length().unwrap_or_default() as usize > max_bytes
                {
                    bail!("Spaces intake object exceeds the admission download limit");
                }
                let capacity = output.content_length().unwrap_or_default().max(0) as usize;
                let mut stream = output.body;
                let mut body = Vec::with_capacity(capacity);
                while let Some(chunk) = stream
                    .try_next()
                    .await
                    .context("reading Spaces intake object body")?
                {
                    let next_len = body
                        .len()
                        .checked_add(chunk.len())
                        .ok_or_else(|| anyhow!("Spaces intake object size overflow"))?;
                    if next_len > max_bytes {
                        bail!("Spaces intake object exceeds the admission download limit");
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(body))
            }
            #[cfg(test)]
            Self::Mock(storage) => Ok(storage
                .bodies
                .lock()
                .expect("mock lock")
                .get(object_key)
                .filter(|body| body.len() <= max_bytes)
                .cloned()),
        }
    }

    pub async fn promote_object(&self, source_key: &str, destination_key: &str) -> Result<()> {
        match self {
            Self::Disabled => bail!("hosted Trace staging storage is disabled"),
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
                let mut bodies = storage.bodies.lock().expect("mock lock");
                if let Some(body) = bodies.get(source_key).cloned() {
                    bodies.insert(destination_key.to_owned(), body);
                }
                Ok(())
            }
        }
    }

    pub async fn put_public_artifact(
        &self,
        object_key: &str,
        kind: &str,
        sha256: &str,
        bytes: &[u8],
    ) -> Result<()> {
        match self {
            Self::Disabled => bail!("hosted Trace storage is disabled"),
            Self::S3(storage) => {
                let content_type = if kind == "package" {
                    ARCHIVE_CONTENT_TYPE
                } else {
                    "application/json; charset=utf-8"
                };
                storage
                    .client
                    .put_object()
                    .bucket(&storage.bucket)
                    .key(object_key)
                    .content_type(content_type)
                    .cache_control("public, max-age=31536000, immutable")
                    .metadata(PUBLIC_KIND_METADATA, kind)
                    .metadata(PUBLIC_SHA256_METADATA, sha256)
                    .body(ByteStream::from(bytes.to_vec()))
                    .send()
                    .await
                    .context("writing public artifact to Spaces")?;
                Ok(())
            }
            #[cfg(test)]
            Self::Mock(storage) => {
                storage.objects.lock().expect("mock lock").insert(
                    object_key.to_owned(),
                    StoredObject {
                        size_bytes: bytes.len() as i64,
                        metadata: BTreeMap::from([
                            (PUBLIC_KIND_METADATA.to_owned(), kind.to_owned()),
                            (PUBLIC_SHA256_METADATA.to_owned(), sha256.to_owned()),
                        ]),
                    },
                );
                storage
                    .bodies
                    .lock()
                    .expect("mock lock")
                    .insert(object_key.to_owned(), bytes.to_vec());
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
                if storage
                    .delete_failures
                    .lock()
                    .expect("mock lock")
                    .contains(object_key)
                {
                    bail!("injected mock delete failure");
                }
                storage
                    .objects
                    .lock()
                    .expect("mock lock")
                    .remove(object_key);
                storage.bodies.lock().expect("mock lock").remove(object_key);
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
                .is_some_and(|value| value == PACKAGE_FORMAT)
    }

    pub fn has_expected_public_metadata(
        object: &StoredObject,
        kind: &str,
        sha256: &str,
        size_bytes: i64,
    ) -> bool {
        object.size_bytes == size_bytes
            && object
                .metadata
                .get(PUBLIC_KIND_METADATA)
                .is_some_and(|value| value == kind)
            && object
                .metadata
                .get(PUBLIC_SHA256_METADATA)
                .is_some_and(|value| value == sha256)
    }

    fn prefix(&self) -> Result<&str> {
        match self {
            Self::Disabled => bail!("hosted Trace staging storage is disabled"),
            Self::S3(storage) => Ok(&storage.prefix),
            #[cfg(test)]
            Self::Mock(storage) => Ok(&storage.prefix),
        }
    }
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
pub struct MockTraceStorage {
    prefix: String,
    pub objects: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, StoredObject>>>,
    pub bodies: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
    pub deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    pub delete_failures: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    pub presign_calls: std::sync::Arc<std::sync::Mutex<Vec<(String, i64, String)>>>,
}

#[cfg(test)]
impl MockTraceStorage {
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
                    (FORMAT_METADATA.to_owned(), PACKAGE_FORMAT.to_owned()),
                ]),
            },
        );
    }

    pub fn object_bytes(&self, key: impl Into<String>, bytes: Vec<u8>) {
        let key = key.into();
        let sha256 = notary_core::sha256_hex(&bytes);
        self.object(&key, bytes.len() as i64, &sha256);
        self.bodies.lock().expect("mock lock").insert(key, bytes);
    }

    pub fn fail_delete(&self, key: impl Into<String>) {
        self.delete_failures
            .lock()
            .expect("mock lock")
            .insert(key.into());
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;

    #[test]
    fn committed_artifact_keys_are_unique_to_each_verification_claim() {
        let storage = TraceStorage::Mock(MockTraceStorage::new());
        let sha256 = "a".repeat(64);
        let first = storage
            .committed_artifact_key("trc-retry", "claim-one", "package", &sha256)
            .unwrap();
        let retry = storage
            .committed_artifact_key("trc-retry", "claim-two", "package", &sha256)
            .unwrap();

        assert_ne!(first, retry);
        assert_eq!(
            retry,
            format!("test/packages/trc-retry/claim-two/{sha256}.llmtrace")
        );
    }

    #[tokio::test]
    #[ignore = "requires an explicitly configured private S3-compatible test bucket"]
    async fn live_s3_presigned_upload_and_promotion_round_trip() {
        let config =
            crate::config::TraceStorageConfig::from_env().expect("S3 intake configuration");
        let storage = TraceStorage::from_config(&config).expect("S3 intake storage");
        assert!(storage.is_enabled(), "S3 intake must be configured");
        storage.validate().await.expect("S3 bucket access");
        let job_id = Uuid::new_v4().to_string();
        let upload_key = storage
            .staging_object_key("integration-user", &job_id, 0)
            .expect("upload key");
        let intake_key = storage
            .committed_staging_object_key("integration-user", &job_id, 0)
            .expect("intake key");
        let payload = b"Notary private intake integration check";
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
        assert!(TraceStorage::has_expected_metadata(&staged, &sha256));

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
