//! Backend-neutral asynchronous metadata persistence for the local daemon.
//!
//! The daemon, administration API, and finalization worker depend on this
//! contract. Backend-specific connection, migration, and blocking behavior
//! lives with each adapter.

use std::{error::Error as StdError, fmt};

use async_trait::async_trait;

use crate::{
    FinalizationPhase, FinalizationProofProgress,
    artifact_store::ArtifactRecord,
    metadata::{
        CaptureCompletion, CaptureFilters, CaptureSummary, EventFilters, EventSnapshot,
        IncompleteCapture, MetadataCounts, NewCapture, Operation, OperationAttempt,
        OperationFilters, SharedNotaryTrust, TerminalOperationResult,
    },
    notary_directory::NotaryDirectory,
};

pub type MetadataResult<T> = std::result::Result<T, MetadataStoreError>;

#[derive(Debug)]
pub enum MetadataStoreError {
    InvalidInput(&'static str),
    Fenced,
    Backend(anyhow::Error),
}

impl MetadataStoreError {
    pub fn invalid_code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput(code) => Some(code),
            Self::Fenced | Self::Backend(_) => None,
        }
    }
}

impl fmt::Display for MetadataStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(code) => write!(formatter, "invalid metadata query: {code}"),
            Self::Fenced => formatter.write_str("metadata mutation was fenced"),
            Self::Backend(_) => formatter.write_str("metadata backend operation failed"),
        }
    }
}

impl StdError for MetadataStoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidInput(_) | Self::Fenced => None,
            Self::Backend(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaIdentity {
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
}

impl ReplicaIdentity {
    pub(crate) fn new(instance_id: impl Into<String>) -> MetadataResult<Self> {
        let instance_id = instance_id.into();
        if instance_id.is_empty()
            || instance_id.len() > 64
            || !instance_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(MetadataStoreError::InvalidInput("invalid_instance_id"));
        }
        Ok(Self {
            instance_id,
            incarnation_id: uuid::Uuid::new_v4().to_string(),
        })
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) fn incarnation_id(&self) -> &str {
        &self.incarnation_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureClaim {
    pub(crate) capture_id: String,
    pub(crate) owner: ReplicaIdentity,
    pub(crate) fence_token: String,
    pub(crate) publication_id: String,
}

impl CaptureClaim {
    pub(crate) fn new(capture_id: impl Into<String>, owner: ReplicaIdentity) -> Self {
        Self {
            capture_id: capture_id.into(),
            owner,
            fence_token: uuid::Uuid::new_v4().to_string(),
            publication_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CaptureRecoveryClaim {
    pub claim: CaptureClaim,
    pub completion: Option<CaptureCompletion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationClaim {
    pub(crate) operation: Operation,
    pub(crate) owner: ReplicaIdentity,
    pub(crate) fence_token: String,
    pub(crate) publication_id: String,
}

/// Complete metadata behavior required by every local-daemon backend.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    fn backend_name(&self) -> &'static str;

    /// Verifies that the backend can serve the exact schema understood by
    /// this binary. Implementations must not mutate schema or data.
    async fn readiness(&self) -> MetadataResult<()>;

    /// Returns the daemon-owned mode used when admitting new provider
    /// requests. The setting is durable and shared by every runtime using the
    /// same metadata backend.
    async fn capture_enabled(&self) -> MetadataResult<bool>;

    /// Atomically stores the capture mode and records its safe activity event.
    /// Implementations return the authoritative stored value so callers never
    /// have to infer the winner of a concurrent update.
    async fn set_capture_enabled(&self, enabled: bool, now_unix_ms: u64) -> MetadataResult<bool>;

    async fn begin_capture(&self, capture: NewCapture) -> MetadataResult<()>;
    async fn mark_capture_failed(&self, capture_id: &str, failure_code: &str)
    -> MetadataResult<()>;
    /// Persists completion fields while the capture remains unavailable.
    ///
    /// Callers stage this descriptor before artifact publication so recovery
    /// can finish the same transition if the process stops after storing the
    /// bytes but before [`Self::complete_capture`] commits.
    async fn prepare_capture_completion(&self, completion: CaptureCompletion)
    -> MetadataResult<()>;
    async fn complete_capture(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()>;
    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>>;
    async fn recover_capture(
        &self,
        capture_id: &str,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()>;
    async fn captures(&self, filters: CaptureFilters) -> MetadataResult<Vec<CaptureSummary>>;
    async fn capture(&self, capture_id: &str) -> MetadataResult<Option<CaptureSummary>>;
    async fn artifacts(&self, capture_id: &str) -> MetadataResult<Vec<ArtifactRecord>>;
    async fn counts(&self) -> MetadataResult<MetadataCounts>;

    async fn enqueue_finalization(
        &self,
        capture_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>>;
    async fn claim_next_finalization(&self, now_unix_ms: u64) -> MetadataResult<Option<Operation>>;
    async fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: FinalizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: FinalizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool>;
    async fn complete_finalization(
        &self,
        operation_id: &str,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn fail_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult>;
    async fn interrupt_running_operations(&self, now_unix_ms: u64) -> MetadataResult<usize>;
    async fn retry_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<Operation>>;
    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>>;
    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>>;
    async fn operation_attempts(&self, operation_id: &str)
    -> MetadataResult<Vec<OperationAttempt>>;

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot>;

    // Server-only coordination. SQLite deliberately retains the default
    // rejection so selecting PostgreSQL+S3 never implicitly enables it.
    async fn register_replica(
        &self,
        _identity: &ReplicaIdentity,
        _compatibility_sha256: &str,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn heartbeat_replica(
        &self,
        _identity: &ReplicaIdentity,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn replica_ready(&self, _identity: &ReplicaIdentity) -> MetadataResult<bool> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn release_replica(&self, _identity: &ReplicaIdentity) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn begin_capture_claimed(
        &self,
        _capture: NewCapture,
        _claim: &CaptureClaim,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn prepare_capture_completion_claimed(
        &self,
        _completion: CaptureCompletion,
        _claim: &CaptureClaim,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn complete_capture_claimed(
        &self,
        _completion: CaptureCompletion,
        _artifact: ArtifactRecord,
        _claim: &CaptureClaim,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn fail_capture_claimed(
        &self,
        _claim: &CaptureClaim,
        _failure_code: &str,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn renew_capture_claim(
        &self,
        _claim: &CaptureClaim,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn claim_next_stale_capture(
        &self,
        _identity: &ReplicaIdentity,
        _fence_token: &str,
        _lease_seconds: u64,
    ) -> MetadataResult<Option<CaptureRecoveryClaim>> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn claim_next_finalization_claimed(
        &self,
        _identity: &ReplicaIdentity,
        _fence_token: &str,
        _lease_seconds: u64,
    ) -> MetadataResult<Option<FinalizationClaim>> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn update_operation_progress_claimed(
        &self,
        _claim: &FinalizationClaim,
        _phase: FinalizationPhase,
        _now_unix_ms: u64,
        _lease_seconds: u64,
    ) -> MetadataResult<bool> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn renew_finalization_claim(
        &self,
        _claim: &FinalizationClaim,
        _lease_seconds: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn update_operation_proof_progress_claimed(
        &self,
        _claim: &FinalizationClaim,
        _progress: FinalizationProofProgress,
        _now_unix_ms: u64,
        _lease_seconds: u64,
    ) -> MetadataResult<bool> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn complete_finalization_claimed(
        &self,
        _claim: &FinalizationClaim,
        _artifact: ArtifactRecord,
        _now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn fail_operation_claimed(
        &self,
        _claim: &FinalizationClaim,
        _now_unix_ms: u64,
        _failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn interrupt_next_expired_finalization(&self) -> MetadataResult<Option<String>> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }

    async fn create_dashboard_session(
        &self,
        _token_hash: &[u8; 32],
        _created_at_unix_ms: u64,
        _expires_at_unix_ms: u64,
    ) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn dashboard_session_valid(
        &self,
        _token_hash: &[u8; 32],
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn revoke_dashboard_session(&self, _token_hash: &[u8; 32]) -> MetadataResult<()> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn prune_dashboard_sessions(
        &self,
        _now_unix_ms: u64,
        _limit: usize,
    ) -> MetadataResult<usize> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }

    async fn pin_notary_directory(
        &self,
        _directory: NotaryDirectory,
        _directory_source: &str,
    ) -> MetadataResult<SharedNotaryTrust> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
    async fn notary_trust_snapshot(&self) -> MetadataResult<Option<SharedNotaryTrust>> {
        Err(MetadataStoreError::InvalidInput("server_not_supported"))
    }
}

#[cfg(test)]
#[path = "metadata_store_conformance.rs"]
pub(crate) mod conformance;
