use std::{fs, path::PathBuf, time::Duration};

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, database_error, publish::PublishJobRow, unix_timestamp,
};
use certified::{
    archive::extract_trace_package_archive,
    bundle::{trace_package_created_at_unix_ms, trace_package_notary_key, verify_trace_package},
    public::{ProviderProvenance, TLSNOTARY_PROVENANCE, platform_key_id, stamp_trace},
    sha256_hex, validate_disclosed_http_redactions,
};

const ADMISSION_INTERVAL_SECS: u64 = 2;
const CLAIM_TIMEOUT_SECS: i64 = 15 * 60;
const MAX_JOBS_PER_TICK: usize = 4;

#[derive(FromRow)]
struct PublicArtifactRow {
    id: String,
    github_login: String,
    admitted_at: i64,
    public_trace: Vec<u8>,
    public_stamp: Vec<u8>,
}

#[derive(Serialize)]
struct PublicTraceMetadata {
    id: String,
    author: String,
    admitted_at: i64,
    trace_url: String,
    stamp_url: String,
}

#[derive(Serialize)]
struct PlatformDirectory {
    format: &'static str,
    issuer: String,
    key_id: String,
    public_key: String,
}

enum AdmissionFailure {
    Reject(&'static str, anyhow::Error),
    Retry(anyhow::Error),
}

struct AdmittedArtifacts {
    trace: Vec<u8>,
    stamp: Vec<u8>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/platform", get(platform_directory))
        .route("/api/public/traces/{trace_id}", get(public_trace_metadata))
        .route(
            "/api/public/traces/{trace_id}/trace.otlp.json",
            get(public_trace),
        )
        .route(
            "/api/public/traces/{trace_id}/stamp.json",
            get(public_stamp),
        )
}

async fn platform_directory(State(state): State<AppState>) -> ApiResult<Json<PlatformDirectory>> {
    let key =
        state.publish.platform_signing_key.as_ref().ok_or_else(|| {
            ApiError::service_unavailable("publication signing is not configured")
        })?;
    Ok(Json(PlatformDirectory {
        format: "llm-notary/platform-directory/v1",
        issuer: state.publish.stamp_issuer.clone(),
        key_id: platform_key_id(key.verifying_key()),
        public_key: hex::encode(key.verifying_key().to_sec1_bytes()),
    }))
}

pub fn spawn(state: AppState) {
    if !state.publish.enabled() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(ADMISSION_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if let Err(error) = recover_stale_claims(&state).await {
                tracing::error!(%error, "recovering stale publication claims failed");
                continue;
            }
            if let Err(error) = purge_admitted_private_objects(&state).await {
                tracing::error!(%error, "purging admitted private objects failed");
            }
            for _ in 0..MAX_JOBS_PER_TICK {
                match claim_next_job(&state).await {
                    Ok(Some((job, claim))) => process_claim(&state, job, claim).await,
                    Ok(None) => break,
                    Err(error) => {
                        tracing::error!(%error, "claiming publication job failed");
                        break;
                    }
                }
            }
        }
    });
}

async fn claim_next_job(state: &AppState) -> Result<Option<(PublishJobRow, String)>> {
    let claim = Uuid::new_v4().to_string();
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let updated = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'verifying', verification_claim = ?, verification_started_at = ?,
             updated_at = ?, failure_code = NULL
         WHERE id = (
             SELECT id FROM publish_jobs
             WHERE state = 'queued'
             ORDER BY queued_at, id
             LIMIT 1
         ) AND state = 'queued'",
    )
    .bind(&claim)
    .bind(now)
    .bind(now)
    .execute(&state.database)
    .await?;
    if updated.rows_affected() == 0 {
        return Ok(None);
    }
    let job = sqlx::query_as("SELECT * FROM publish_jobs WHERE verification_claim = ?")
        .bind(&claim)
        .fetch_one(&state.database)
        .await?;
    Ok(Some((job, claim)))
}

async fn process_claim(state: &AppState, job: PublishJobRow, claim: String) {
    let archive = match state
        .publish
        .storage
        .get_object(
            &job.intake_object_key,
            state.publish.max_archive_bytes as usize,
        )
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            reject_claim(state, &job, &claim, "object_missing", None).await;
            return;
        }
        Err(error) => {
            retry_claim(state, &job, &claim, error).await;
            return;
        }
    };
    let actual_size = archive.len() as i64;
    let actual_sha256 = sha256_hex(&archive);
    if actual_size != job.declared_size_bytes {
        reject_claim(
            state,
            &job,
            &claim,
            "object_size_mismatch",
            Some((actual_size, actual_sha256)),
        )
        .await;
        return;
    }
    if actual_sha256 != job.declared_sha256 {
        reject_claim(
            state,
            &job,
            &claim,
            "object_sha256_mismatch",
            Some((actual_size, actual_sha256)),
        )
        .await;
        return;
    }

    let directory = state.notary_directory.clone();
    let signing_key = state
        .publish
        .platform_signing_key
        .clone()
        .expect("enabled publication service has a platform signing key");
    let issuer = state.publish.stamp_issuer.clone();
    let job_id = job.id.clone();
    let issued_at = match unix_timestamp() {
        Ok(value) => value as u64 * 1000,
        Err(error) => {
            retry_claim(state, &job, &claim, anyhow::anyhow!(error.message)).await;
            return;
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        verify_and_stamp(
            &job_id,
            &archive,
            &directory,
            &signing_key,
            issuer,
            issued_at,
        )
    })
    .await;
    match result {
        Ok(Ok(artifacts)) => {
            if let Err(error) =
                admit_claim(state, &job, &claim, actual_size, &actual_sha256, artifacts).await
            {
                retry_claim(state, &job, &claim, error).await;
            }
        }
        Ok(Err(AdmissionFailure::Reject(code, error))) => {
            tracing::info!(job_id = %job.id, failure_code = code, %error, "publication rejected");
            reject_claim(
                state,
                &job,
                &claim,
                code,
                Some((actual_size, actual_sha256)),
            )
            .await;
        }
        Ok(Err(AdmissionFailure::Retry(error))) => retry_claim(state, &job, &claim, error).await,
        Err(error) => retry_claim(state, &job, &claim, anyhow::anyhow!(error)).await,
    }
}

fn verify_and_stamp(
    job_id: &str,
    archive: &[u8],
    directory: &certified::notary_directory::NotaryDirectory,
    signing_key: &k256::ecdsa::SigningKey,
    issuer: String,
    issued_at_unix_ms: u64,
) -> std::result::Result<AdmittedArtifacts, AdmissionFailure> {
    let workspace = AdmissionWorkspace::new(job_id)
        .map_err(|error| AdmissionFailure::Retry(error.context("creating admission workspace")))?;
    extract_trace_package_archive(archive, &workspace.package)
        .map_err(|error| AdmissionFailure::Reject("archive_invalid", error))?;
    let embedded_key = trace_package_notary_key(&workspace.package)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let authenticated_at = trace_package_created_at_unix_ms(&workspace.package)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let record = directory
        .notaries
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(&embedded_key))
        })
        .ok_or_else(|| {
            AdmissionFailure::Reject(
                "notary_untrusted",
                anyhow::anyhow!("package notary is absent from the server directory"),
            )
        })?;
    if !record.trusted_at(authenticated_at) {
        return Err(AdmissionFailure::Reject(
            "notary_untrusted",
            anyhow::anyhow!("package notary is not trusted at its authenticated timestamp"),
        ));
    }
    let trusted_key = record
        .public_key_bytes()
        .map_err(|error| AdmissionFailure::Retry(error.context("reading trusted notary key")))?;
    let manifest = verify_trace_package(&workspace.package, &trusted_key)
        .map_err(|error| AdmissionFailure::Reject("package_invalid", error))?;
    let request = fs::read(workspace.package.join("request.disclosed.http"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    let response = fs::read(workspace.package.join("response.http"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    validate_disclosed_http_redactions(&request, &response)
        .map_err(|error| AdmissionFailure::Reject("sensitive_header_disclosed", error))?;
    let trace = fs::read(workspace.package.join("trace.otlp.json"))
        .map_err(|error| AdmissionFailure::Retry(error.into()))?;
    let stamp = stamp_trace(
        &trace,
        issuer,
        issued_at_unix_ms,
        ProviderProvenance {
            evidence: TLSNOTARY_PROVENANCE.to_owned(),
            host: manifest.provider_host().to_owned(),
            name: manifest.provider_name().to_owned(),
        },
        signing_key,
    )
    .map_err(|error| AdmissionFailure::Retry(error.context("signing public trace")))?;
    let mut stamp =
        serde_json::to_vec_pretty(&stamp).map_err(|error| AdmissionFailure::Retry(error.into()))?;
    stamp.push(b'\n');
    Ok(AdmittedArtifacts { trace, stamp })
}

async fn admit_claim(
    state: &AppState,
    job: &PublishJobRow,
    claim: &str,
    actual_size: i64,
    actual_sha256: &str,
    artifacts: AdmittedArtifacts,
) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let updated = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'admitted', actual_size_bytes = ?, actual_sha256 = ?,
             admitted_at = ?, updated_at = ?, public_trace = ?, public_stamp = ?,
             verification_claim = NULL
         WHERE id = ? AND state = 'verifying' AND verification_claim = ?
           AND public_trace IS NULL AND public_stamp IS NULL",
    )
    .bind(actual_size)
    .bind(actual_sha256)
    .bind(now)
    .bind(now)
    .bind(artifacts.trace)
    .bind(artifacts.stamp)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("publication claim was lost before admission");
    }
    purge_private_object(state, job).await;
    Ok(())
}

async fn reject_claim(
    state: &AppState,
    job: &PublishJobRow,
    claim: &str,
    code: &'static str,
    actual: Option<(i64, String)>,
) {
    let now = unix_timestamp()
        .map(|value| value)
        .unwrap_or(job.updated_at);
    let (actual_size, actual_sha256) = actual
        .map(|(size, sha256)| (Some(size), Some(sha256)))
        .unwrap_or((None, None));
    match sqlx::query(
        "UPDATE publish_jobs
         SET state = 'rejected', failure_code = ?, actual_size_bytes = ?,
             actual_sha256 = ?, updated_at = ?, verification_claim = NULL
         WHERE id = ? AND state = 'verifying' AND verification_claim = ?",
    )
    .bind(code)
    .bind(actual_size)
    .bind(actual_sha256)
    .bind(now)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        Ok(result) if result.rows_affected() == 1 => purge_private_object(state, job).await,
        Ok(_) => tracing::warn!(job_id = %job.id, "publication rejection lost its claim"),
        Err(error) => tracing::error!(job_id = %job.id, %error, "recording rejection failed"),
    }
}

async fn retry_claim(state: &AppState, job: &PublishJobRow, claim: &str, error: anyhow::Error) {
    tracing::error!(job_id = %job.id, %error, "publication admission will retry");
    let now = unix_timestamp()
        .map(|value| value)
        .unwrap_or(job.updated_at);
    if let Err(update_error) = sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', updated_at = ?, verification_claim = NULL,
             verification_started_at = NULL
         WHERE id = ? AND state = 'verifying' AND verification_claim = ?",
    )
    .bind(now)
    .bind(&job.id)
    .bind(claim)
    .execute(&state.database)
    .await
    {
        tracing::error!(job_id = %job.id, %update_error, "requeueing publication failed");
    }
}

async fn purge_private_object(state: &AppState, job: &PublishJobRow) {
    match state
        .publish
        .storage
        .delete_object(&job.intake_object_key)
        .await
    {
        Ok(()) => {
            let now = unix_timestamp()
                .map(|value| value)
                .unwrap_or(job.updated_at);
            if let Err(error) = sqlx::query(
                "UPDATE publish_jobs SET private_purged_at = ?, updated_at = ?
                 WHERE id = ? AND private_purged_at IS NULL",
            )
            .bind(now)
            .bind(now)
            .bind(&job.id)
            .execute(&state.database)
            .await
            {
                tracing::error!(job_id = %job.id, %error, "recording private purge failed");
            }
        }
        Err(error) => tracing::error!(job_id = %job.id, %error, "private object purge failed"),
    }
}

async fn purge_admitted_private_objects(state: &AppState) -> Result<()> {
    let jobs = sqlx::query_as::<_, PublishJobRow>(
        "SELECT * FROM publish_jobs
         WHERE state IN ('admitted', 'rejected') AND private_purged_at IS NULL
         ORDER BY updated_at LIMIT 100",
    )
    .fetch_all(&state.database)
    .await?;
    for job in jobs {
        purge_private_object(state, &job).await;
    }
    Ok(())
}

async fn recover_stale_claims(state: &AppState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let cutoff = now - CLAIM_TIMEOUT_SECS;
    sqlx::query(
        "UPDATE publish_jobs
         SET state = 'queued', verification_claim = NULL,
             verification_started_at = NULL, updated_at = ?
         WHERE state = 'verifying' AND verification_started_at < ?
           AND public_trace IS NULL AND public_stamp IS NULL",
    )
    .bind(now)
    .bind(cutoff)
    .execute(&state.database)
    .await?;
    Ok(())
}

async fn load_public_artifact(state: &AppState, trace_id: &str) -> ApiResult<PublicArtifactRow> {
    sqlx::query_as(
        "SELECT publish_jobs.id, users.github_login, publish_jobs.admitted_at,
                publish_jobs.public_trace, publish_jobs.public_stamp
         FROM publish_jobs
         JOIN users ON users.id = publish_jobs.user_id
         WHERE publish_jobs.id = ? AND publish_jobs.state = 'admitted'
           AND publish_jobs.public_trace IS NOT NULL
           AND publish_jobs.public_stamp IS NOT NULL",
    )
    .bind(trace_id)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::not_found("public trace was not found"))
}

async fn public_trace_metadata(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Json<PublicTraceMetadata>> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    Ok(Json(PublicTraceMetadata {
        id: artifact.id.clone(),
        author: artifact.github_login,
        admitted_at: artifact.admitted_at,
        trace_url: format!("/api/public/traces/{}/trace.otlp.json", artifact.id),
        stamp_url: format!("/api/public/traces/{}/stamp.json", artifact.id),
    }))
}

async fn public_trace(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Response> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    Ok(public_bytes(
        artifact.public_trace,
        "application/json; charset=utf-8",
    ))
}

async fn public_stamp(
    State(state): State<AppState>,
    AxumPath(trace_id): AxumPath<String>,
) -> ApiResult<Response> {
    let artifact = load_public_artifact(&state, &trace_id).await?;
    Ok(public_bytes(
        artifact.public_stamp,
        "application/json; charset=utf-8",
    ))
}

fn public_bytes(bytes: Vec<u8>, content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Body::from(bytes),
    )
        .into_response()
}

struct AdmissionWorkspace {
    root: PathBuf,
    package: PathBuf,
}

impl AdmissionWorkspace {
    fn new(job_id: &str) -> Result<Self> {
        if !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("job ID is unsafe for an admission workspace");
        }
        let root = std::env::temp_dir().join(format!(
            "llm-notary-admission-{job_id}-{}",
            Uuid::new_v4().simple()
        ));
        fs::create_dir(&root)?;
        let package = root.join("package");
        Ok(Self { root, package })
    }
}

impl Drop for AdmissionWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;
    use url::Url;

    use super::super::intake::MockIntakeStorage;
    use super::super::publish::PublishService;
    use super::*;

    async fn test_state() -> (AppState, MockIntakeStorage) {
        let database = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&database).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, github_id, github_login, created_at, updated_at)
             VALUES ('user-1', 1, 'publisher', 1, 1)",
        )
        .execute(&database)
        .await
        .unwrap();
        let storage = MockIntakeStorage::new();
        (
            AppState {
                database,
                http: reqwest::Client::new(),
                github_client_id: "client-id".to_owned(),
                github_client_secret: "secret".to_owned(),
                callback_url: Url::parse("https://example.com/callback").unwrap(),
                app_url: Url::parse("https://example.com").unwrap(),
                secure_cookies: true,
                notary_directory: super::super::tests::directory_key(),
                publish: PublishService::mock(storage.clone()),
            },
            storage,
        )
    }

    async fn queued_job(state: &AppState, bytes: &[u8], sha256: &str) -> PublishJobRow {
        sqlx::query(
            "INSERT INTO publish_jobs
             (id, user_id, idempotency_key, state, archive_format,
              declared_size_bytes, declared_sha256, upload_object_key,
              intake_object_key, upload_expires_at, created_at, updated_at, queued_at)
             VALUES ('job-1', 'user-1', 'idempotency-key-0001', 'queued', ?,
                     ?, ?, 'upload-key', 'intake-key', 1000, 1, 1, 1)",
        )
        .bind(certified::archive::ARCHIVE_FORMAT)
        .bind(bytes.len() as i64)
        .bind(sha256)
        .execute(&state.database)
        .await
        .unwrap();
        sqlx::query_as("SELECT * FROM publish_jobs WHERE id = 'job-1'")
            .fetch_one(&state.database)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn atomic_claim_allows_only_one_worker() {
        let (state, _) = test_state().await;
        queued_job(&state, b"archive", &sha256_hex(b"archive")).await;
        assert!(claim_next_job(&state).await.unwrap().is_some());
        assert!(claim_next_job(&state).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_archive_is_rejected_with_stable_code_and_purged() {
        let (state, storage) = test_state().await;
        let bytes = b"not a ZIP archive".to_vec();
        let sha256 = sha256_hex(&bytes);
        queued_job(&state, &bytes, &sha256).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        process_claim(&state, job, claim).await;
        let row: (String, Option<String>, Option<i64>) = sqlx::query_as(
            "SELECT state, failure_code, private_purged_at
             FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "rejected");
        assert_eq!(row.1.as_deref(), Some("archive_invalid"));
        assert!(row.2.is_some());
        assert!(!storage.bodies.lock().unwrap().contains_key("intake-key"));
    }

    #[tokio::test]
    async fn downloaded_bytes_must_match_the_declared_sha256() {
        let (state, storage) = test_state().await;
        let bytes = b"same length".to_vec();
        queued_job(&state, &bytes, &"0".repeat(64)).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        process_claim(&state, job, claim).await;
        let row: (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT state, failure_code, actual_sha256
             FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "rejected");
        assert_eq!(row.1.as_deref(), Some("object_sha256_mismatch"));
        assert_eq!(row.2.as_deref(), Some(sha256_hex(b"same length").as_str()));
    }

    #[tokio::test]
    async fn admission_writes_one_immutable_public_pair() {
        let (state, storage) = test_state().await;
        let bytes = b"archive".to_vec();
        let sha256 = sha256_hex(&bytes);
        queued_job(&state, &bytes, &sha256).await;
        storage.object_bytes("intake-key", bytes);
        let (job, claim) = claim_next_job(&state).await.unwrap().unwrap();
        admit_claim(
            &state,
            &job,
            &claim,
            7,
            &sha256,
            AdmittedArtifacts {
                trace: b"{\"trace\":1}\n".to_vec(),
                stamp: b"{\"stamp\":1}\n".to_vec(),
            },
        )
        .await
        .unwrap();
        assert!(
            admit_claim(
                &state,
                &job,
                &claim,
                7,
                &sha256,
                AdmittedArtifacts {
                    trace: b"different".to_vec(),
                    stamp: b"different".to_vec(),
                },
            )
            .await
            .is_err()
        );
        let row: (String, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT state, public_trace, public_stamp FROM publish_jobs WHERE id = 'job-1'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(row.0, "admitted");
        assert_eq!(row.1, b"{\"trace\":1}\n");
        assert_eq!(row.2, b"{\"stamp\":1}\n");
        let public = load_public_artifact(&state, "job-1").await.unwrap();
        assert_eq!(public.github_login, "publisher");
        assert_eq!(public.public_trace, row.1);
        let directory = platform_directory(State(state)).await.unwrap().0;
        assert_eq!(directory.format, "llm-notary/platform-directory/v1");
        assert!(directory.key_id.starts_with("sha256:"));
    }
}
