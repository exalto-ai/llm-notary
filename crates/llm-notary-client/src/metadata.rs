//! Backend-neutral durable metadata records shared by every store adapter.

use serde::{Deserialize, Serialize};

/// The durable capture fields that are safe and useful to query locally.
#[derive(Clone, Debug)]
pub struct NewCapture {
    pub capture_id: String,
    pub created_at_unix_ms: u64,
    pub provider: String,
    pub operation: String,
    pub requested_model: Option<String>,
    pub streaming: bool,
    pub request_bytes: usize,
    pub prompt_preview: String,
    pub prompt_preview_truncated: bool,
    pub config_fingerprint: String,
}

/// Capture fields committed after the encrypted artifact is durably stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureCompletion {
    pub capture_id: String,
    pub completed_at_unix_ms: u64,
    pub duration_ms: u64,
    pub http_status: u16,
    pub response_bytes: u64,
    pub response_model: Option<String>,
    pub output_preview: String,
    pub output_preview_truncated: bool,
}

/// One capture that was still active when a daemon stopped.
///
/// A completion is present only after the response metadata was durably
/// staged. Returning it with the identifier lets recovery inspect each row
/// from one backend snapshot instead of querying the capture again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteCapture {
    pub capture_id: String,
    pub completion: Option<CaptureCompletion>,
}

/// One searchable capture summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureSummary {
    pub capture_id: String,
    pub created_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub provider: String,
    pub operation: String,
    pub requested_model: Option<String>,
    pub response_model: Option<String>,
    pub http_status: Option<u16>,
    pub streaming: bool,
    pub request_bytes: u64,
    pub response_bytes: Option<u64>,
    pub duration_ms: Option<u64>,
    pub capture_state: String,
    pub finalization_state: String,
    pub prompt_preview: String,
    pub prompt_preview_truncated: bool,
    pub output_preview: String,
    pub output_preview_truncated: bool,
    pub failure_code: Option<String>,
}

/// One persisted administration operation. Error details are represented by
/// bounded codes rather than arbitrary strings from providers or local paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub operation_id: String,
    pub kind: String,
    pub capture_id: Option<String>,
    pub state: String,
    pub attempt: u32,
    pub created_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub completed_at_unix_ms: Option<u64>,
    pub failure_code: Option<String>,
    pub progress_phase: String,
    pub progress_updated_at_unix_ms: u64,
    pub proof_bytes_completed: u64,
    pub proof_bytes_total: u64,
    pub proof_commitments_completed: u64,
    pub proof_commitments_total: u64,
}

/// One durable attempt belonging to an operation. Attempt history is kept
/// separately because retries deliberately preserve the operation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationAttempt {
    pub attempt: u32,
    pub state: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub failure_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub event_id: u64,
    pub created_at_unix_ms: u64,
    pub event_type: String,
    pub capture_id: Option<String>,
    pub operation_id: Option<String>,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct CaptureFilters {
    pub query: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub capture_state: Option<String>,
    pub finalization_state: Option<String>,
    pub streaming: Option<bool>,
    pub created_after_unix_ms: Option<u64>,
    pub cursor: Option<CapturePagePosition>,
    pub limit: usize,
}

#[derive(Clone, Debug, Default)]
pub struct OperationFilters {
    pub state: Option<String>,
    pub kind: Option<String>,
    pub capture_id: Option<String>,
    pub cursor: Option<OperationPagePosition>,
    pub limit: usize,
}

#[derive(Clone, Debug, Default)]
pub struct EventFilters {
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub severity: Option<String>,
    pub event_type: Option<String>,
    pub capture_id: Option<String>,
    pub operation_id: Option<String>,
    pub created_after_unix_ms: Option<u64>,
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSnapshot {
    pub events: Vec<Event>,
    pub high_water: Option<u64>,
}

/// Outcome of an attempted terminal operation transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOperationResult {
    /// A running operation entered the requested terminal state.
    Applied,
    /// The operation was already in the identical terminal state.
    AlreadyApplied,
    /// No operation exists for the supplied identifier.
    NotFound,
    /// The operation exists, but its current state forbids the transition.
    Conflict { current_state: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CapturePagePosition {
    pub created_at_unix_ms: u64,
    pub capture_id: String,
}

impl From<&CaptureSummary> for CapturePagePosition {
    fn from(capture: &CaptureSummary) -> Self {
        Self {
            created_at_unix_ms: capture.created_at_unix_ms,
            capture_id: capture.capture_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationPagePosition {
    pub created_at_unix_ms: u64,
    pub operation_id: String,
}

impl From<&Operation> for OperationPagePosition {
    fn from(operation: &Operation) -> Self {
        Self {
            created_at_unix_ms: operation.created_at_unix_ms,
            operation_id: operation.operation_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataCounts {
    pub total_captures: u64,
    pub capturing: u64,
    pub ready_to_finalize: u64,
    pub finalized: u64,
    pub failed: u64,
    pub active_operations: u64,
}
