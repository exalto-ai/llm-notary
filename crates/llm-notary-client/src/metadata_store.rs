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
        OperationFilters, TerminalOperationResult,
    },
};

pub type MetadataResult<T> = std::result::Result<T, MetadataStoreError>;

/// Stable error classes callers may safely map to HTTP behavior.
#[derive(Debug)]
pub enum MetadataStoreError {
    InvalidInput(&'static str),
    Backend(anyhow::Error),
}

impl MetadataStoreError {
    pub fn invalid_code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput(code) => Some(code),
            Self::Backend(_) => None,
        }
    }
}

impl fmt::Display for MetadataStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(code) => write!(formatter, "invalid metadata query: {code}"),
            Self::Backend(_) => formatter.write_str("metadata backend operation failed"),
        }
    }
}

impl StdError for MetadataStoreError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidInput(_) => None,
            Self::Backend(error) => Some(error.as_ref()),
        }
    }
}

/// Complete metadata behavior required by every local-daemon backend.
#[async_trait]
pub trait MetadataStore: Send + Sync {
    fn backend_name(&self) -> &'static str;

    /// Verifies that the backend can serve the exact schema understood by
    /// this binary. Implementations must not mutate schema or data.
    async fn readiness(&self) -> MetadataResult<()>;

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
}

#[cfg(test)]
#[path = "metadata_store_conformance.rs"]
pub(crate) mod conformance;
