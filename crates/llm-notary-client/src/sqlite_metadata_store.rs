//! Asynchronous adapter for the daemon's SQLite metadata catalog.

use std::{path::PathBuf, sync::Arc};

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{
    FinalizationPhase, FinalizationProofProgress,
    artifact_store::ArtifactRecord,
    metadata::{
        CaptureCompletion, CaptureFilters, CaptureSummary, EventFilters, EventSnapshot,
        IncompleteCapture, MetadataCounts, NewCapture, Operation, OperationAttempt,
        OperationFilters, TerminalOperationResult,
    },
    metadata_store::{MetadataResult, MetadataStore, MetadataStoreError},
    sqlite_catalog::SqliteCatalog,
};

/// Async adapter around the existing SQLite implementation.
#[derive(Clone)]
pub struct SqliteMetadataStore {
    catalog: Arc<SqliteCatalog>,
    full_text_search: bool,
}

impl SqliteMetadataStore {
    pub async fn open(path: PathBuf, full_text_search: bool) -> MetadataResult<Self> {
        let catalog =
            tokio::task::spawn_blocking(move || SqliteCatalog::open(&path, full_text_search))
                .await
                .map_err(|error| MetadataStoreError::Backend(anyhow!(error)))?
                .map_err(MetadataStoreError::Backend)?;
        Ok(Self {
            catalog: Arc::new(catalog),
            full_text_search,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_catalog(catalog: SqliteCatalog, full_text_search: bool) -> Self {
        Self {
            catalog: Arc::new(catalog),
            full_text_search,
        }
    }

    async fn blocking<T, F>(&self, operation: F) -> MetadataResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&SqliteCatalog) -> anyhow::Result<T> + Send + 'static,
    {
        let catalog = self.catalog.clone();
        tokio::task::spawn_blocking(move || operation(&catalog))
            .await
            .map_err(|error| MetadataStoreError::Backend(anyhow!(error)))?
            .map_err(MetadataStoreError::Backend)
    }
}

fn validate_i64(value: u64, code: &'static str) -> MetadataResult<()> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_usize_i64(value: usize, code: &'static str) -> MetadataResult<()> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_artifact_size(artifact: &ArtifactRecord) -> MetadataResult<()> {
    artifact
        .validate()
        .map_err(|_| MetadataStoreError::InvalidInput("invalid_artifact_record"))?;
    validate_i64(artifact.size_bytes, "artifact_size_out_of_range")
}

fn validate_completion(completion: &CaptureCompletion) -> MetadataResult<()> {
    validate_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?;
    validate_i64(completion.duration_ms, "duration_out_of_range")?;
    validate_i64(completion.response_bytes, "response_bytes_out_of_range")?;
    validate_i64(
        completion.expected_artifact_size_bytes,
        "artifact_size_out_of_range",
    )?;
    if completion.expected_artifact_sha256.len() != 64
        || !completion
            .expected_artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MetadataStoreError::InvalidInput(
            "invalid_expected_artifact_sha256",
        ));
    }
    Ok(())
}

fn validate_proof_progress(progress: FinalizationProofProgress) -> MetadataResult<()> {
    for value in [
        progress.bytes_completed,
        progress.bytes_total,
        progress.commitments_completed,
        progress.commitments_total,
    ] {
        validate_i64(value, "proof_progress_out_of_range")?;
    }
    if progress.bytes_completed > progress.bytes_total
        || progress.commitments_completed > progress.commitments_total
    {
        return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
    }
    Ok(())
}

fn validate_limit(limit: usize) -> MetadataResult<()> {
    if (1..=201).contains(&limit) {
        Ok(())
    } else {
        Err(MetadataStoreError::InvalidInput("invalid_page_limit"))
    }
}

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    async fn readiness(&self) -> MetadataResult<()> {
        self.blocking(SqliteCatalog::readiness).await
    }

    async fn capture_enabled(&self) -> MetadataResult<bool> {
        self.blocking(SqliteCatalog::capture_enabled).await
    }

    async fn set_capture_enabled(&self, enabled: bool, now_unix_ms: u64) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |catalog| catalog.set_capture_enabled(enabled, now_unix_ms))
            .await
    }

    async fn begin_capture(&self, capture: NewCapture) -> MetadataResult<()> {
        validate_i64(
            capture.created_at_unix_ms,
            "capture_created_at_out_of_range",
        )?;
        validate_usize_i64(capture.request_bytes, "request_bytes_out_of_range")?;
        self.blocking(move |catalog| catalog.begin_capture(&capture))
            .await
    }

    async fn mark_capture_failed(
        &self,
        capture_id: &str,
        failure_code: &str,
    ) -> MetadataResult<()> {
        let capture_id = capture_id.to_owned();
        let failure_code = failure_code.to_owned();
        self.blocking(move |catalog| catalog.mark_capture_failed(&capture_id, &failure_code))
            .await
    }

    async fn prepare_capture_completion(
        &self,
        completion: CaptureCompletion,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        self.blocking(move |catalog| catalog.prepare_capture_completion(&completion))
            .await
    }

    async fn complete_capture(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        validate_artifact_size(&artifact)?;
        self.blocking(move |catalog| catalog.complete_capture_record(&completion, &artifact))
            .await
    }

    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>> {
        self.blocking(SqliteCatalog::incomplete_captures).await
    }

    async fn recover_capture(
        &self,
        capture_id: &str,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        validate_artifact_size(&artifact)?;
        let capture_id = capture_id.to_owned();
        self.blocking(move |catalog| catalog.recover_capture_record(&capture_id, &artifact))
            .await
    }

    async fn captures(&self, filters: CaptureFilters) -> MetadataResult<Vec<CaptureSummary>> {
        validate_limit(filters.limit)?;
        if filters.query.as_deref() == Some("") {
            return Ok(Vec::new());
        }
        if filters
            .query
            .as_ref()
            .is_some_and(|query| !query.is_empty())
            && !self.full_text_search
        {
            return Err(MetadataStoreError::InvalidInput("preview_search_disabled"));
        }
        if let Some(value) = filters.created_after_unix_ms {
            validate_i64(value, "created_after_out_of_range")?;
        }
        if let Some(cursor) = &filters.cursor {
            validate_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        self.blocking(move |catalog| catalog.filtered_captures(&filters))
            .await
    }

    async fn capture(&self, capture_id: &str) -> MetadataResult<Option<CaptureSummary>> {
        let capture_id = capture_id.to_owned();
        self.blocking(move |catalog| catalog.capture(&capture_id))
            .await
    }

    async fn artifacts(&self, capture_id: &str) -> MetadataResult<Vec<ArtifactRecord>> {
        let capture_id = capture_id.to_owned();
        self.blocking(move |catalog| catalog.artifact_records(&capture_id))
            .await
    }

    async fn counts(&self) -> MetadataResult<MetadataCounts> {
        self.blocking(SqliteCatalog::counts).await
    }

    async fn enqueue_finalization(
        &self,
        capture_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        let capture_id = capture_id.to_owned();
        self.blocking(move |catalog| catalog.enqueue_finalization(&capture_id, now_unix_ms))
            .await
    }

    async fn claim_next_finalization(&self, now_unix_ms: u64) -> MetadataResult<Option<Operation>> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |catalog| catalog.claim_next_finalization(now_unix_ms))
            .await
    }

    async fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: FinalizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| {
            catalog.update_operation_progress(&operation_id, phase, now_unix_ms)
        })
        .await
    }

    async fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: FinalizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_proof_progress(progress)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| {
            catalog.update_operation_proof_progress(&operation_id, progress, now_unix_ms)
        })
        .await
    }

    async fn complete_finalization(
        &self,
        operation_id: &str,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_artifact_size(&artifact)?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| {
            catalog.complete_finalization(&operation_id, &artifact, now_unix_ms)
        })
        .await
    }

    async fn fail_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        let operation_id = operation_id.to_owned();
        let failure_code = failure_code.to_owned();
        self.blocking(move |catalog| {
            catalog.fail_operation(&operation_id, now_unix_ms, &failure_code)
        })
        .await
    }

    async fn interrupt_running_operations(&self, now_unix_ms: u64) -> MetadataResult<usize> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        self.blocking(move |catalog| catalog.recover_operations(now_unix_ms))
            .await
    }

    async fn retry_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<Operation>> {
        validate_i64(now_unix_ms, "timestamp_out_of_range")?;
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| catalog.retry_operation(&operation_id, now_unix_ms))
            .await
    }

    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>> {
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| catalog.operation(&operation_id))
            .await
    }

    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>> {
        validate_limit(filters.limit)?;
        if let Some(cursor) = &filters.cursor {
            validate_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        self.blocking(move |catalog| catalog.filtered_operations(&filters))
            .await
    }

    async fn operation_attempts(
        &self,
        operation_id: &str,
    ) -> MetadataResult<Vec<OperationAttempt>> {
        let operation_id = operation_id.to_owned();
        self.blocking(move |catalog| catalog.operation_attempts(&operation_id))
            .await
    }

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot> {
        validate_limit(filters.limit)?;
        if filters.before.is_some() && filters.after.is_some() {
            return Err(MetadataStoreError::InvalidInput(
                "conflicting_event_positions",
            ));
        }
        for value in [filters.before, filters.after, filters.created_after_unix_ms]
            .into_iter()
            .flatten()
        {
            validate_i64(value, "event_position_out_of_range")?;
        }
        self.blocking(move |catalog| {
            let (events, high_water) = catalog.filtered_events_with_high_water(&filters)?;
            Ok(EventSnapshot { events, high_water })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::artifact_store::ArtifactKind;

    use super::*;
    use crate::metadata_store::conformance;

    #[tokio::test]
    async fn capture_mode_survives_store_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        let first = SqliteMetadataStore::open(path.clone(), true).await.unwrap();
        assert!(first.capture_enabled().await.unwrap());
        assert!(!first.set_capture_enabled(false, 1).await.unwrap());
        drop(first);

        let reopened = SqliteMetadataStore::open(path, true).await.unwrap();
        assert!(!reopened.capture_enabled().await.unwrap());
    }

    async fn sqlite_conformance(full_text_search: bool) {
        let directory = tempfile::tempdir().unwrap();
        let sequence = AtomicUsize::new(0);
        conformance::run(
            || {
                let database = directory.path().join(format!(
                    "conformance-{}.db",
                    sequence.fetch_add(1, Ordering::Relaxed)
                ));
                async move {
                    let store = SqliteMetadataStore::open(database, full_text_search)
                        .await
                        .unwrap();
                    assert_eq!(store.backend_name(), "sqlite");
                    Arc::new(store) as Arc<dyn MetadataStore>
                }
            },
            full_text_search,
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_conforms_with_full_text_search() {
        sqlite_conformance(true).await;
    }

    #[tokio::test]
    async fn sqlite_conforms_without_full_text_search() {
        sqlite_conformance(false).await;
    }

    #[tokio::test]
    async fn sqlite_adapter_migrates_schema_versions_one_through_seven() {
        let directory = tempfile::tempdir().unwrap();
        for version in 1..=7 {
            let database = directory.path().join(format!("schema-v{version}.db"));
            crate::sqlite_catalog::create_schema_fixture(&database, version).unwrap();
            let store: Arc<dyn MetadataStore> = Arc::new(
                SqliteMetadataStore::open(database.clone(), true)
                    .await
                    .unwrap(),
            );
            let capture_id = format!("migrated-v{version}");
            store
                .begin_capture(conformance::new_capture(&capture_id, 1))
                .await
                .unwrap();
            let artifact = conformance::artifact(
                &capture_id,
                crate::artifact_store::ArtifactKind::DeferredBundle,
                version as u8,
            );
            let mut completion = conformance::completion(&capture_id, 2, 200);
            completion.expected_artifact_size_bytes = artifact.size_bytes;
            completion.expected_artifact_sha256 = artifact.sha256.clone();
            store
                .prepare_capture_completion(completion.clone())
                .await
                .unwrap();
            store.complete_capture(completion, artifact).await.unwrap();
            assert_eq!(
                store
                    .captures(CaptureFilters {
                        query: Some("quarterly-pricing".to_owned()),
                        limit: 1,
                        ..CaptureFilters::default()
                    })
                    .await
                    .unwrap()
                    .len(),
                1
            );
            let operation = store
                .enqueue_finalization(&capture_id, 3)
                .await
                .unwrap()
                .unwrap()
                .0;
            let running = store.claim_next_finalization(4).await.unwrap().unwrap();
            assert_eq!(running.operation_id, operation.operation_id);
            assert!(
                store
                    .update_operation_proof_progress(
                        &running.operation_id,
                        FinalizationProofProgress {
                            bytes_completed: 1,
                            bytes_total: 2,
                            commitments_completed: 0,
                            commitments_total: 1,
                        },
                        5,
                    )
                    .await
                    .unwrap()
            );
            assert_eq!(
                store
                    .complete_finalization(
                        &running.operation_id,
                        conformance::artifact(&capture_id, ArtifactKind::FinalizedPackage, 2,),
                        6,
                    )
                    .await
                    .unwrap(),
                TerminalOperationResult::Applied
            );
            assert_eq!(
                store
                    .operation_attempts(&running.operation_id)
                    .await
                    .unwrap()[0]
                    .state,
                "finalized"
            );
            drop(store);

            let connection = rusqlite::Connection::open(database).unwrap();
            let migrated: i64 = connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(migrated, 8);
        }
    }
}
