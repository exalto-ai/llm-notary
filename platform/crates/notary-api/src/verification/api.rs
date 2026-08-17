//! Anonymous, retention-free hosted verification.

use std::{
    collections::HashSet,
    future::Future,
    net::IpAddr,
    process::Stdio,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::{Child, Command},
    sync::OwnedSemaphorePermit,
};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use crate::{
    DatabasePool, ErrorResponse, NotaryApiState, unix_timestamp,
    verification::worker::{
        MAX_WORKER_OUTPUT_BYTES, WORKER_REJECTED, WORKER_VERIFIED,
        try_acquire_verification_capacity,
    },
};
use notary_core::{
    archive::{ARCHIVE_CONTENT_TYPE, MAX_ARCHIVE_WIRE_BYTES},
    registry::Registry,
    sha256_hex,
};

const EXTRACTION_TIMEOUT: Duration = Duration::from_secs(30);
const LIMITER_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_INPUT_TIMEOUT: Duration = Duration::from_secs(10);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);
const VERIFICATION_LEASE_SECS: i64 = 5 * 60;
static ANONYMOUS_IN_FLIGHT: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
struct TracePackageBody(Vec<u8>);

#[derive(ToSchema)]
#[allow(dead_code)]
struct VerificationResponse {
    verified: bool,
    trace_id: String,
    authenticated_at_unix_ms: u64,
    provider: String,
    host: String,
    notary_key_id: String,
    registry_generation: u64,
    trust_source: String,
    package_sha256: String,
    content_sha256: String,
    trace: serde_json::Value,
}

struct LocalPermit {
    client: String,
}

impl LocalPermit {
    fn acquire(client: String) -> Result<Self, ()> {
        let mut clients = ANONYMOUS_IN_FLIGHT.lock().map_err(|_| ())?;
        if !clients.insert(client.clone()) {
            return Err(());
        }
        Ok(Self { client })
    }
}

impl Drop for LocalPermit {
    fn drop(&mut self) {
        if let Ok(mut clients) = ANONYMOUS_IN_FLIGHT.lock() {
            clients.remove(&self.client);
        }
    }
}

struct VerificationPermits {
    _local: LocalPermit,
    _capacity: OwnedSemaphorePermit,
    database: DatabasePool,
    client_key_sha256: String,
    lease_id: String,
}

#[derive(Debug)]
enum PermitError {
    InFlight,
    Capacity,
    Unavailable,
}

impl VerificationPermits {
    async fn acquire(database: &DatabasePool, client: String) -> Result<Self, PermitError> {
        let local = LocalPermit::acquire(client.clone()).map_err(|_| PermitError::InFlight)?;
        let capacity = try_acquire_verification_capacity().ok_or(PermitError::Capacity)?;
        let client_key_sha256 = sha256_hex(client.as_bytes());
        let lease_id = Uuid::new_v4().to_string();
        let now = unix_timestamp().map_err(|_| PermitError::Unavailable)?;
        tokio::time::timeout(
            LIMITER_TIMEOUT,
            sqlx::query(
                "DELETE FROM verification_leases
                 WHERE expires_at <= $1
                   AND client_key_sha256 IN (
                     SELECT client_key_sha256 FROM verification_leases
                     WHERE expires_at <= $1
                     ORDER BY expires_at
                     LIMIT 64
                 )",
            )
            .bind(now)
            .execute(database),
        )
        .await
        .map_err(|_| PermitError::Unavailable)?
        .map_err(|_| PermitError::Unavailable)?;
        let lease = tokio::time::timeout(
            LIMITER_TIMEOUT,
            sqlx::query_scalar::<_, String>(
                "INSERT INTO verification_leases
                     (client_key_sha256, lease_id, expires_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (client_key_sha256) DO UPDATE
                 SET lease_id = EXCLUDED.lease_id, expires_at = EXCLUDED.expires_at
                 WHERE verification_leases.expires_at <= $4
                 RETURNING lease_id",
            )
            .bind(&client_key_sha256)
            .bind(&lease_id)
            .bind(now + VERIFICATION_LEASE_SECS)
            .bind(now)
            .fetch_optional(database),
        )
        .await
        .map_err(|_| PermitError::Unavailable)?
        .map_err(|_| PermitError::Unavailable)?;
        if lease.as_deref() != Some(lease_id.as_str()) {
            return Err(PermitError::InFlight);
        }
        Ok(Self {
            _local: local,
            _capacity: capacity,
            database: database.clone(),
            client_key_sha256,
            lease_id,
        })
    }

    async fn release(self) {
        let _ = tokio::time::timeout(
            LIMITER_TIMEOUT,
            sqlx::query(
                "DELETE FROM verification_leases
                 WHERE client_key_sha256 = $1 AND lease_id = $2",
            )
            .bind(&self.client_key_sha256)
            .bind(&self.lease_id)
            .execute(&self.database),
        )
        .await;
    }
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new().routes(routes!(verify))
}

#[utoipa::path(
    post,
    path = "/api/verify",
    summary = "Verify a portable .llmtrace package",
    request_body(content = TracePackageBody, content_type = "application/vnd.exalto.notary.trace-package+zip"),
    responses(
        (status = 200, body = VerificationResponse),
        (status = 408, body = ErrorResponse),
        (status = 413, body = ErrorResponse),
        (status = 415, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
        (status = 429, body = ErrorResponse),
        (status = 503, body = ErrorResponse)
    ),
    tag = "verification"
)]
async fn verify(State(state): State<NotaryApiState>, request: Request) -> Response {
    verify_request(state, request).await
}

async fn verify_request(state: NotaryApiState, request: Request) -> Response {
    verify_request_with(state, request, run_worker_process).await
}

async fn verify_request_with<F, Fut>(
    state: NotaryApiState,
    request: Request,
    run_worker: F,
) -> Response
where
    F: FnOnce(Vec<u8>, Registry) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, WorkerError>>,
{
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(ARCHIVE_CONTENT_TYPE)
    {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }

    let max_bytes = match usize::try_from(state.traces.max_package_bytes) {
        Ok(max_bytes) => max_bytes.min(MAX_ARCHIVE_WIRE_BYTES as usize),
        Err(_) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verification_unavailable");
        }
    };
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > max_bytes as u64)
    {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "package_too_large");
    }

    let client = client_ip(request.headers());
    let permits = match VerificationPermits::acquire(&state.database, client).await {
        Ok(permits) => permits,
        Err(PermitError::InFlight) => {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "verification_in_flight");
        }
        Err(PermitError::Capacity) => {
            return error_response(StatusCode::TOO_MANY_REQUESTS, "verification_capacity");
        }
        Err(PermitError::Unavailable) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verification_unavailable");
        }
    };
    let archive =
        match tokio::time::timeout(EXTRACTION_TIMEOUT, to_bytes(request.into_body(), max_bytes))
            .await
        {
            Ok(Ok(archive)) => archive.to_vec(),
            Ok(Err(_)) => {
                permits.release().await;
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "package_too_large");
            }
            Err(_) => {
                permits.release().await;
                return error_response(StatusCode::REQUEST_TIMEOUT, "extraction_timeout");
            }
        };

    let result = run_worker(archive, state.registry.clone()).await;
    permits.release().await;
    let encoded = match result {
        Ok(encoded) => encoded,
        Err(WorkerError::Rejected(code)) => return rejected_response(&code),
        Err(WorkerError::Timeout) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verification_timeout");
        }
        Err(WorkerError::Unavailable) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verification_unavailable");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Body::from(encoded),
    )
        .into_response()
}

#[derive(Debug)]
enum WorkerError {
    Rejected(String),
    Timeout,
    Unavailable,
}

async fn run_worker_process(archive: Vec<u8>, directory: Registry) -> Result<Vec<u8>, WorkerError> {
    let directory = serde_json::to_vec(&directory).map_err(|_| WorkerError::Unavailable)?;
    let executable = std::env::current_exe().map_err(|_| WorkerError::Unavailable)?;
    let mut command = Command::new(executable);
    command.arg("verification-worker");
    run_worker_command(
        command,
        archive,
        directory,
        WORKER_INPUT_TIMEOUT,
        VERIFICATION_TIMEOUT,
    )
    .await
}

async fn run_worker_command(
    mut command: Command,
    archive: Vec<u8>,
    directory: Vec<u8>,
    input_timeout: Duration,
    verification_timeout: Duration,
) -> Result<Vec<u8>, WorkerError> {
    if archive.len() as u64 > MAX_ARCHIVE_WIRE_BYTES {
        return Err(WorkerError::Unavailable);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| WorkerError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(WorkerError::Unavailable)?;
    let mut stdout = child.stdout.take().ok_or(WorkerError::Unavailable)?;
    let output_reader = tokio::spawn(async move {
        let mut outcome = [0u8; 1];
        stdout.read_exact(&mut outcome).await?;
        let mut encoded_length = [0u8; 8];
        stdout.read_exact(&mut encoded_length).await?;
        let output_length = u64::from_be_bytes(encoded_length);
        if output_length > MAX_WORKER_OUTPUT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "worker output is too large",
            ));
        }
        let mut output = vec![
            0;
            usize::try_from(output_length).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "worker output is too large",
                )
            })?
        ];
        stdout.read_exact(&mut output).await?;
        let mut trailing = [0u8; 1];
        if stdout.read(&mut trailing).await? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected worker output",
            ));
        }
        Ok::<_, std::io::Error>((outcome[0], output))
    });
    let input = async move {
        stdin
            .write_all(&(directory.len() as u64).to_be_bytes())
            .await?;
        stdin.write_all(&directory).await?;
        stdin
            .write_all(&(archive.len() as u64).to_be_bytes())
            .await?;
        stdin.write_all(&archive).await?;
        stdin.shutdown().await
    };
    match tokio::time::timeout(input_timeout, input).await {
        Ok(Ok(())) => {}
        _ => {
            terminate_worker(&mut child).await;
            output_reader.abort();
            let _ = output_reader.await;
            return Err(WorkerError::Unavailable);
        }
    }
    let status = match tokio::time::timeout(verification_timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => {
            terminate_worker(&mut child).await;
            output_reader.abort();
            let _ = output_reader.await;
            return Err(WorkerError::Unavailable);
        }
        Err(_) => {
            terminate_worker(&mut child).await;
            output_reader.abort();
            let _ = output_reader.await;
            return Err(WorkerError::Timeout);
        }
    };
    let (outcome, output) = output_reader
        .await
        .map_err(|_| WorkerError::Unavailable)?
        .map_err(|_| WorkerError::Unavailable)?;
    if !status.success() || output.len() as u64 > MAX_WORKER_OUTPUT_BYTES {
        return Err(WorkerError::Unavailable);
    }
    match outcome {
        WORKER_VERIFIED => Ok(output),
        WORKER_REJECTED if output.len() <= 64 => {
            let code = String::from_utf8(output).map_err(|_| WorkerError::Unavailable)?;
            Err(WorkerError::Rejected(code))
        }
        _ => Err(WorkerError::Unavailable),
    }
}

async fn terminate_worker(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn rejected_response(code: &str) -> Response {
    match code {
        "malformed_package" | "tampered_package" | "unsupported_version" | "untrusted_notary" => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, stable_code(code))
        }
        _ => error_response(StatusCode::SERVICE_UNAVAILABLE, "verification_unavailable"),
    }
}

fn stable_code(code: &str) -> &'static str {
    match code {
        "malformed_package" => "malformed_package",
        "tampered_package" => "tampered_package",
        "unsupported_version" => "unsupported_version",
        "untrusted_notary" => "untrusted_notary",
        _ => "verification_unavailable",
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    ["x-notary-client-ip", "fly-client-ip", "cf-connecting-ip"]
        .into_iter()
        .filter_map(|name| headers.get(name))
        .filter_map(|value| value.to_str().ok())
        .find_map(parse_ip)
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .and_then(parse_ip)
        })
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().parse().ok()
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(ErrorResponse {
            error: code,
            message: code,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::traces::owner::TraceService;

    static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn test_state() -> NotaryApiState {
        let database = crate::fresh_database().await;
        NotaryApiState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://example.com/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://example.com/api/auth/google/callback")
                .unwrap(),
            public_origin: Url::parse("https://example.com").unwrap(),
            secure_cookies: true,
            registry: crate::tests::directory_key(),
            traces: TraceService::disabled_for_test(),
            admission: std::sync::Arc::new(crate::config::NotaryAdmissionConfig::for_test()),
            billing: crate::billing::BillingService::disabled_for_test(),
        }
    }

    #[test]
    fn client_identity_accepts_only_ip_addresses() {
        let mut headers = HeaderMap::new();
        headers.insert("fly-client-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&headers), "203.0.113.7");
        headers.insert("fly-client-ip", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(&headers), "unknown");
    }

    #[tokio::test]
    async fn distributed_limiter_does_not_hold_a_pool_connection() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        let first = VerificationPermits::acquire(&state.database, "198.51.100.42".to_owned())
            .await
            .unwrap();
        let mut connections = Vec::new();
        for _ in 0..crate::config::DEFAULT_DATABASE_MAX_CONNECTIONS {
            connections.push(state.database.acquire().await.unwrap());
        }
        drop(connections);
        first.release().await;
    }

    #[tokio::test]
    async fn distributed_limiter_allows_one_verification_per_client() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        let first = VerificationPermits::acquire(&state.database, "198.51.100.43".to_owned())
            .await
            .unwrap();
        assert!(matches!(
            VerificationPermits::acquire(&state.database, "198.51.100.43".to_owned()).await,
            Err(PermitError::InFlight)
        ));
        first.release().await;
        assert!(
            VerificationPermits::acquire(&state.database, "198.51.100.43".to_owned())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn global_capacity_is_reserved_before_request_body_extraction() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        let first = VerificationPermits::acquire(&state.database, "198.51.100.44".to_owned())
            .await
            .unwrap();
        assert!(matches!(
            VerificationPermits::acquire(&state.database, "198.51.100.45".to_owned()).await,
            Err(PermitError::Capacity)
        ));
        first.release().await;
    }

    #[tokio::test]
    async fn admission_and_anonymous_verification_share_capacity() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        let admission = crate::verification::worker::acquire_verification_capacity().await;
        assert!(matches!(
            VerificationPermits::acquire(&state.database, "198.51.100.47".to_owned()).await,
            Err(PermitError::Capacity)
        ));
        drop(admission);

        let anonymous = VerificationPermits::acquire(&state.database, "198.51.100.48".to_owned())
            .await
            .unwrap();
        assert!(
            crate::verification::worker::try_acquire_verification_capacity().is_none(),
            "anonymous verification must block admission capacity"
        );
        anonymous.release().await;
    }

    #[tokio::test]
    async fn permit_acquisition_removes_expired_client_hashes() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        sqlx::query(
            "INSERT INTO verification_leases
                 (client_key_sha256, lease_id, expires_at)
             VALUES ('expired-client-hash', 'abandoned-lease', 0)",
        )
        .execute(&state.database)
        .await
        .unwrap();

        let permit = VerificationPermits::acquire(&state.database, "198.51.100.46".to_owned())
            .await
            .unwrap();
        let expired: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM verification_leases
             WHERE client_key_sha256 = 'expired-client-hash'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(expired, 0);
        permit.release().await;
    }

    #[tokio::test]
    async fn worker_termination_waits_until_the_child_is_reaped() {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("sleep 60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        terminate_worker(&mut child).await;
        assert!(child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn worker_process_timeout_terminates_a_live_child() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("cat >/dev/null; sleep 60");
        let result = run_worker_command(
            command,
            b"not a package".to_vec(),
            b"{}".to_vec(),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .await;
        assert!(matches!(result, Err(WorkerError::Timeout)));
    }

    #[tokio::test]
    async fn successful_anonymous_verification_retains_no_content_or_activity() {
        let _serial = TEST_SERIAL.lock().await;
        let state = test_state().await;
        let _database_server = state._test_database.clone();
        let database = state.database.clone();
        let package = b"sanitized valid package fixture".to_vec();
        let expected_package = package.clone();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "verified": true,
            "trace_id": "trc-sanitized",
            "authenticated_at_unix_ms": 1_785_000_000_000_u64,
            "provider": "fixture",
            "host": "fixture.example",
            "notary_key_id": "sha256:fixture",
            "registry_generation": 7,
            "trust_source": "hosted_registry",
            "package_sha256": "a".repeat(64),
            "content_sha256": "b".repeat(64),
            "trace": { "resourceSpans": [] }
        }))
        .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/verify")
            .header(header::CONTENT_TYPE, ARCHIVE_CONTENT_TYPE)
            .header("fly-client-ip", "198.51.100.91")
            .body(Body::from(package))
            .unwrap();
        let response = verify_request_with(state, request, move |archive, _directory| {
            let encoded = encoded.clone();
            async move {
                assert_eq!(archive, expected_package);
                Ok(encoded)
            }
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["trace_id"], "trc-sanitized");

        let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM traces")
            .fetch_one(&database)
            .await
            .unwrap();
        assert_eq!(retained, 0);
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM verification_leases")
            .fetch_one(&database)
            .await
            .unwrap();
        assert_eq!(leases, 0, "the distributed lease must be released");
    }
}
