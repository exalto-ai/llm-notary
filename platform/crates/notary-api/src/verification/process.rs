//! Bounded lifecycle and typed protocol for the isolated package verifier.

use std::{
    collections::HashMap,
    process::Stdio,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use notary_core::{archive::MAX_ARCHIVE_WIRE_BYTES, registry::Registry, sha256_hex};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::{Child, Command},
    sync::{Notify, watch},
};
use uuid::Uuid;

pub(crate) const TRUST_SOURCE: &str = "hosted_registry";
pub(crate) const WORKER_VERIFIED: u8 = b'V';
pub(crate) const WORKER_REJECTED: u8 = b'R';
pub(crate) const MAX_WORKER_OUTPUT_BYTES: u64 = MAX_ARCHIVE_WIRE_BYTES + 2 * 1024 * 1024;
pub(crate) const MAX_REGISTRY_BYTES: u64 = 1024 * 1024;

const ANONYMOUS_PURPOSE: u8 = b'A';
const HOSTED_PURPOSE: u8 = b'H';
const HOSTED_OVERRIDE_PURPOSE: u8 = b'F';
const WORKER_INPUT_TIMEOUT: Duration = Duration::from_secs(10);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerificationPurpose {
    Anonymous,
    Hosted { allow_high_entropy: bool },
}

impl VerificationPurpose {
    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            ANONYMOUS_PURPOSE => Some(Self::Anonymous),
            HOSTED_PURPOSE => Some(Self::Hosted {
                allow_high_entropy: false,
            }),
            HOSTED_OVERRIDE_PURPOSE => Some(Self::Hosted {
                allow_high_entropy: true,
            }),
            _ => None,
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            Self::Anonymous => ANONYMOUS_PURPOSE,
            Self::Hosted {
                allow_high_entropy: false,
            } => HOSTED_PURPOSE,
            Self::Hosted {
                allow_high_entropy: true,
            } => HOSTED_OVERRIDE_PURPOSE,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPackage {
    pub source_trace_id: String,
    pub authenticated_at_unix_ms: u64,
    pub provider_name: String,
    pub provider_host: String,
    pub request_path: String,
    pub notary_key_id: String,
    pub registry_generation: u64,
    pub package_sha256: String,
    pub content_sha256: String,
    pub trace: Vec<u8>,
    pub safety_override_applied: Option<bool>,
}

impl VerifiedPackage {
    pub(crate) fn anonymous_response_body(&self) -> Result<Vec<u8>, VerificationError> {
        #[derive(Serialize)]
        struct ResponseMetadata<'a> {
            verified: bool,
            trace_id: &'a str,
            authenticated_at_unix_ms: u64,
            provider: &'a str,
            host: &'a str,
            notary_key_id: &'a str,
            registry_generation: u64,
            trust_source: &'static str,
            package_sha256: &'a str,
            content_sha256: &'a str,
        }

        let mut body = serde_json::to_vec(&ResponseMetadata {
            verified: true,
            trace_id: &self.source_trace_id,
            authenticated_at_unix_ms: self.authenticated_at_unix_ms,
            provider: &self.provider_name,
            host: &self.provider_host,
            notary_key_id: &self.notary_key_id,
            registry_generation: self.registry_generation,
            trust_source: TRUST_SOURCE,
            package_sha256: &self.package_sha256,
            content_sha256: &self.content_sha256,
        })
        .map_err(|_| VerificationError::Unavailable)?;
        if body.pop() != Some(b'}') {
            return Err(VerificationError::Unavailable);
        }
        body.extend_from_slice(b",\"trace\":");
        body.extend_from_slice(&self.trace);
        body.push(b'}');
        if body.len() as u64 > MAX_WORKER_OUTPUT_BYTES
            || serde_json::from_slice::<serde_json::Value>(&body).is_err()
        {
            return Err(VerificationError::Unavailable);
        }
        Ok(body)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum VerificationError {
    Rejected(String),
    Timeout,
    Cancelled,
    Unavailable,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct WorkerMetadata {
    pub verified: bool,
    pub source_trace_id: String,
    pub authenticated_at_unix_ms: u64,
    pub provider: String,
    pub host: String,
    pub request_path: String,
    pub notary_key_id: String,
    pub registry_generation: u64,
    pub trust_source: String,
    pub package_sha256: String,
    pub content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_override_applied: Option<bool>,
}

pub(crate) async fn verify_anonymous(
    archive: Vec<u8>,
    registry: Registry,
) -> Result<VerifiedPackage, VerificationError> {
    run_process(archive, registry, VerificationPurpose::Anonymous).await
}

pub(crate) async fn verify_hosted(
    archive: Vec<u8>,
    registry: Registry,
    allow_high_entropy: bool,
) -> Result<VerifiedPackage, VerificationError> {
    run_process(
        archive,
        registry,
        VerificationPurpose::Hosted { allow_high_entropy },
    )
    .await
}

async fn run_process(
    archive: Vec<u8>,
    registry: Registry,
    purpose: VerificationPurpose,
) -> Result<VerifiedPackage, VerificationError> {
    let executable = std::env::current_exe().map_err(|_| VerificationError::Unavailable)?;
    let mut command = Command::new(executable);
    command.arg("verification-worker");
    run_command(
        command,
        archive,
        registry,
        purpose,
        WORKER_INPUT_TIMEOUT,
        VERIFICATION_TIMEOUT,
    )
    .await
}

async fn run_command(
    mut command: Command,
    archive: Vec<u8>,
    registry: Registry,
    purpose: VerificationPurpose,
    input_timeout: Duration,
    verification_timeout: Duration,
) -> Result<VerifiedPackage, VerificationError> {
    if archive.len() as u64 > MAX_ARCHIVE_WIRE_BYTES {
        return Err(VerificationError::Unavailable);
    }
    let package_sha256 = sha256_hex(&archive);
    let registry_bytes =
        serde_json::to_vec(&registry).map_err(|_| VerificationError::Unavailable)?;
    if registry_bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(VerificationError::Unavailable);
    }

    let mut registration = ProcessRegistration::register()?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| VerificationError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(VerificationError::Unavailable)?;
    let mut stdout = child.stdout.take().ok_or(VerificationError::Unavailable)?;
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
        stdin.write_all(&[purpose.to_wire()]).await?;
        stdin
            .write_all(&(registry_bytes.len() as u64).to_be_bytes())
            .await?;
        stdin.write_all(&registry_bytes).await?;
        stdin
            .write_all(&(archive.len() as u64).to_be_bytes())
            .await?;
        stdin.write_all(&archive).await?;
        stdin.shutdown().await
    };
    let input_result = tokio::select! {
        biased;
        changed = registration.cancel.changed() => {
            let _ = changed;
            Err(VerificationError::Cancelled)
        }
        result = tokio::time::timeout(input_timeout, input) => match result {
            Ok(Ok(())) => Ok(()),
            _ => Err(VerificationError::Unavailable),
        },
    };
    if let Err(error) = input_result {
        terminate_worker(&mut child).await;
        output_reader.abort();
        let _ = output_reader.await;
        return Err(error);
    }

    let status = tokio::select! {
        biased;
        changed = registration.cancel.changed() => {
            let _ = changed;
            terminate_worker(&mut child).await;
            output_reader.abort();
            let _ = output_reader.await;
            return Err(VerificationError::Cancelled);
        }
        result = tokio::time::timeout(verification_timeout, child.wait()) => match result {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                terminate_worker(&mut child).await;
                output_reader.abort();
                let _ = output_reader.await;
                return Err(VerificationError::Unavailable);
            }
            Err(_) => {
                terminate_worker(&mut child).await;
                output_reader.abort();
                let _ = output_reader.await;
                return Err(VerificationError::Timeout);
            }
        },
    };
    let (outcome, output) = output_reader
        .await
        .map_err(|_| VerificationError::Unavailable)?
        .map_err(|_| VerificationError::Unavailable)?;
    if !status.success() || output.len() as u64 > MAX_WORKER_OUTPUT_BYTES {
        return Err(VerificationError::Unavailable);
    }
    match outcome {
        WORKER_VERIFIED => decode_verified(output, &package_sha256, &registry, purpose),
        WORKER_REJECTED if output.len() <= 128 => {
            let code = String::from_utf8(output).map_err(|_| VerificationError::Unavailable)?;
            Err(VerificationError::Rejected(code))
        }
        _ => Err(VerificationError::Unavailable),
    }
}

fn decode_verified(
    output: Vec<u8>,
    package_sha256: &str,
    registry: &Registry,
    purpose: VerificationPurpose,
) -> Result<VerifiedPackage, VerificationError> {
    let metadata_length = output
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(VerificationError::Unavailable)?;
    let metadata_end = 8usize
        .checked_add(metadata_length)
        .filter(|end| *end <= output.len())
        .ok_or(VerificationError::Unavailable)?;
    let metadata: WorkerMetadata = serde_json::from_slice(&output[8..metadata_end])
        .map_err(|_| VerificationError::Unavailable)?;
    let trace = output[metadata_end..].to_vec();
    let expected_safety = match purpose {
        VerificationPurpose::Anonymous => None,
        VerificationPurpose::Hosted { .. } => Some(()),
    };
    let impossible_override = matches!(
        purpose,
        VerificationPurpose::Hosted {
            allow_high_entropy: false
        }
    ) && metadata.safety_override_applied == Some(true);
    if !metadata.verified
        || metadata.trust_source != TRUST_SOURCE
        || metadata.registry_generation != registry.generation
        || metadata.package_sha256 != package_sha256
        || metadata.content_sha256 != sha256_hex(&trace)
        || metadata.safety_override_applied.map(|_| ()) != expected_safety
        || impossible_override
        || serde_json::from_slice::<serde_json::Value>(&trace).is_err()
    {
        return Err(VerificationError::Unavailable);
    }
    let trusted_record = registry.notaries.iter().any(|record| {
        record.key_id == metadata.notary_key_id
            && record.trusted_at(metadata.authenticated_at_unix_ms)
    });
    if !trusted_record {
        return Err(VerificationError::Unavailable);
    }
    Ok(VerifiedPackage {
        source_trace_id: metadata.source_trace_id,
        authenticated_at_unix_ms: metadata.authenticated_at_unix_ms,
        provider_name: metadata.provider,
        provider_host: metadata.host,
        request_path: metadata.request_path,
        notary_key_id: metadata.notary_key_id,
        registry_generation: metadata.registry_generation,
        package_sha256: metadata.package_sha256,
        content_sha256: metadata.content_sha256,
        trace,
        safety_override_applied: metadata.safety_override_applied,
    })
}

async fn terminate_worker(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

struct ActiveProcess {
    cancel: watch::Sender<bool>,
    completion: std::sync::Arc<ProcessCompletion>,
}

struct ProcessCompletion {
    finished: AtomicBool,
    notify: Notify,
}

impl ProcessCompletion {
    async fn wait(&self) {
        while !self.finished.load(Ordering::Acquire) {
            let notified = self.notify.notified();
            if self.finished.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Default)]
struct Supervisor {
    shutting_down: bool,
    active: HashMap<Uuid, ActiveProcess>,
}

static SUPERVISOR: LazyLock<Mutex<Supervisor>> =
    LazyLock::new(|| Mutex::new(Supervisor::default()));

struct ProcessRegistration {
    id: Uuid,
    cancel: watch::Receiver<bool>,
    completion: std::sync::Arc<ProcessCompletion>,
}

impl ProcessRegistration {
    fn register() -> Result<Self, VerificationError> {
        let id = Uuid::new_v4();
        let (cancel, receiver) = watch::channel(false);
        let completion = std::sync::Arc::new(ProcessCompletion {
            finished: AtomicBool::new(false),
            notify: Notify::new(),
        });
        let mut supervisor = SUPERVISOR
            .lock()
            .map_err(|_| VerificationError::Unavailable)?;
        if supervisor.shutting_down {
            return Err(VerificationError::Cancelled);
        }
        supervisor.active.insert(
            id,
            ActiveProcess {
                cancel,
                completion: completion.clone(),
            },
        );
        Ok(Self {
            id,
            cancel: receiver,
            completion,
        })
    }
}

impl Drop for ProcessRegistration {
    fn drop(&mut self) {
        self.completion.finished.store(true, Ordering::Release);
        self.completion.notify.notify_waiters();
        if let Ok(mut supervisor) = SUPERVISOR.lock() {
            supervisor.active.remove(&self.id);
        }
    }
}

/// Cancels every verifier child and returns only after each child has been reaped.
pub(crate) async fn shutdown_all() {
    let active = {
        let Ok(mut supervisor) = SUPERVISOR.lock() else {
            return;
        };
        supervisor.shutting_down = true;
        supervisor
            .active
            .values()
            .map(|process| (process.cancel.clone(), process.completion.clone()))
            .collect::<Vec<_>>()
    };
    for (cancel, _) in &active {
        let _ = cancel.send(true);
    }
    for (_, completion) in active {
        completion.wait().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn empty_registry() -> Registry {
        serde_json::from_value(serde_json::json!({
            "format": "notary/registry/v1",
            "generation": 0,
            "active_key_id": "unused",
            "notaries": []
        }))
        .unwrap()
    }

    fn reset_supervisor() {
        let mut supervisor = SUPERVISOR.lock().unwrap();
        assert!(supervisor.active.is_empty());
        supervisor.shutting_down = false;
    }

    #[tokio::test]
    async fn timeout_terminates_and_reaps_worker() {
        let _serial = TEST_SERIAL.lock().await;
        reset_supervisor();
        let mut command = Command::new("sh");
        command.arg("-c").arg("cat >/dev/null; sleep 60");
        let result = run_command(
            command,
            b"not a package".to_vec(),
            empty_registry(),
            VerificationPurpose::Anonymous,
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .await;
        assert_eq!(result, Err(VerificationError::Timeout));
        assert!(SUPERVISOR.lock().unwrap().active.is_empty());
    }

    #[tokio::test]
    async fn shutdown_cancels_and_reaps_worker() {
        let _serial = TEST_SERIAL.lock().await;
        reset_supervisor();
        let mut command = Command::new("sh");
        command.arg("-c").arg("cat >/dev/null; sleep 60");
        let worker = tokio::spawn(run_command(
            command,
            b"not a package".to_vec(),
            empty_registry(),
            VerificationPurpose::Anonymous,
            Duration::from_secs(1),
            Duration::from_secs(60),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !SUPERVISOR.lock().unwrap().active.is_empty() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        shutdown_all().await;
        assert_eq!(worker.await.unwrap(), Err(VerificationError::Cancelled));
        assert!(SUPERVISOR.lock().unwrap().active.is_empty());
        reset_supervisor();
    }
}
