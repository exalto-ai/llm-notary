//! Synchronous SQLite metadata implementation and schema migrations.

use std::{fs, path::Path, sync::Mutex};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::artifact_store::{ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord};
use crate::metadata::{
    CaptureCompletion, CaptureFilters, CaptureSummary, Event, EventFilters, IncompleteCapture,
    MetadataCounts, NewCapture, Operation, OperationAttempt, OperationFilters,
    TerminalOperationResult, capture_search_expression,
};

const CATALOG_SCHEMA_VERSION: i64 = 8;

/// A single-process SQLite capture inventory.
pub(crate) struct SqliteCatalog {
    connection: Mutex<Connection>,
    full_text_search: bool,
}

impl SqliteCatalog {
    /// Opens and migrates a local SQLite catalog.
    pub fn open(path: &Path, full_text_search: bool) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut connection = Connection::open(path)
            .with_context(|| format!("opening capture catalog {}", path.display()))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .context("enabling SQLite foreign keys")?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("enabling SQLite WAL mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("configuring SQLite durability")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            full_text_search,
        })
    }

    pub fn readiness(&self) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let (count, version): (i64, Option<i64>) = connection.query_row(
            "SELECT COUNT(*), MAX(version) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        anyhow::ensure!(
            count == CATALOG_SCHEMA_VERSION && version == Some(CATALOG_SCHEMA_VERSION),
            "SQLite catalog schema journal does not exactly match version {CATALOG_SCHEMA_VERSION}"
        );
        connection.query_row("SELECT COUNT(*) FROM captures", [], |row| {
            row.get::<_, i64>(0).map(|_| ())
        })?;
        Ok(())
    }

    pub fn capture_enabled(&self) -> Result<bool> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection
            .query_row(
                "SELECT capture_enabled FROM daemon_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .context("reading capture mode")
    }

    pub fn set_capture_enabled(&self, enabled: bool, now_unix_ms: u64) -> Result<bool> {
        let mut connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.transaction()?;
        let current: bool = transaction.query_row(
            "SELECT capture_enabled FROM daemon_settings WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if current != enabled {
            transaction.execute(
                "UPDATE daemon_settings SET capture_enabled = ? WHERE singleton = 1",
                [enabled],
            )?;
            insert_event(
                &transaction,
                now_unix_ms,
                if enabled {
                    "capture_enabled"
                } else {
                    "capture_disabled"
                },
                None,
                None,
                "info",
                if enabled {
                    "Capture requests enabled"
                } else {
                    "Capture requests disabled"
                },
            )?;
        }
        transaction.commit()?;
        Ok(enabled)
    }

    /// Records the start of a capture before the notary connection begins.
    pub fn begin_capture(&self, capture: &NewCapture) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection.execute(
            "INSERT INTO captures (
                capture_id, created_at_unix_ms, provider, operation, requested_model,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, capture_state, finalization_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'capturing', 'not_requested')",
            params![
                capture.capture_id,
                i64::try_from(capture.created_at_unix_ms)?,
                capture.provider,
                capture.operation,
                capture.requested_model,
                capture.streaming,
                i64::try_from(capture.request_bytes)?,
                capture.prompt_preview,
                capture.prompt_preview_truncated,
                capture.config_fingerprint,
            ],
        )?;
        Ok(())
    }

    /// Marks a capture unavailable without persisting error strings that could
    /// contain provider or credential material.
    pub fn mark_capture_failed(&self, capture_id: &str, failure_code: &str) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let current = transaction
            .query_row(
                "SELECT capture_state, failure_code FROM captures WHERE capture_id = ?",
                params![capture_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        if current.0 == "failed" && current.1.as_deref() == Some(failure_code) {
            return Ok(());
        }
        anyhow::ensure!(current.0 == "capturing", "capture is not active");
        let changed = transaction.execute(
            "UPDATE captures
             SET capture_state = 'failed', failure_code = ?
             WHERE capture_id = ? AND capture_state = 'capturing'",
            params![failure_code, capture_id],
        )?;
        anyhow::ensure!(changed == 1, "active capture transition was lost");
        transaction.commit()?;
        Ok(())
    }

    /// Stages completion fields without advertising an artifact as available.
    pub fn prepare_capture_completion(&self, completion: &CaptureCompletion) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let current = transaction
            .query_row(
                "SELECT capture_state, completed_at_unix_ms IS NOT NULL
                 FROM captures WHERE capture_id = ?",
                params![completion.capture_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        anyhow::ensure!(
            current.0 == "capturing" || current.0 == "captured",
            "capture cannot accept completion metadata"
        );
        if current.1 {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?,
                "capture completion conflicts with persisted metadata"
            );
            return Ok(());
        }
        anyhow::ensure!(current.0 == "capturing", "capture is not active");
        let changed = transaction.execute(
            "UPDATE captures SET
                completed_at_unix_ms = ?, duration_ms = ?, http_status = ?, response_bytes = ?,
                response_model = ?, output_preview = ?, output_preview_truncated = ?,
                expected_artifact_size_bytes = ?, expected_artifact_sha256 = ?
             WHERE capture_id = ? AND capture_state = 'capturing'
               AND completed_at_unix_ms IS NULL",
            params![
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview.as_str(),
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256.as_str(),
                completion.capture_id,
            ],
        )?;
        anyhow::ensure!(changed == 1, "capture completion staging was lost");
        transaction.commit()?;
        Ok(())
    }

    /// Commits capture completion and a previously stored artifact atomically.
    pub fn complete_capture_record(
        &self,
        completion: &CaptureCompletion,
        artifact: &ArtifactRecord,
    ) -> Result<()> {
        require_artifact(
            artifact,
            &completion.capture_id,
            ArtifactKind::DeferredBundle,
        )?;
        anyhow::ensure!(
            artifact.size_bytes == completion.expected_artifact_size_bytes
                && artifact.sha256 == completion.expected_artifact_sha256,
            "artifact does not match the staged capture publication"
        );
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let (current_state, completion_prepared) = transaction
            .query_row(
                "SELECT capture_state, completed_at_unix_ms IS NOT NULL
                 FROM captures WHERE capture_id = ?",
                params![completion.capture_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        if current_state == "captured" {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?
                    && artifact_exists_exact(&transaction, artifact)?,
                "capture completion conflicts with persisted metadata"
            );
            return Ok(());
        }
        anyhow::ensure!(current_state == "capturing", "capture is not active");
        if completion_prepared {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?,
                "capture completion conflicts with staged metadata"
            );
        }
        let changed = transaction.execute(
            "UPDATE captures SET
                completed_at_unix_ms = ?, duration_ms = ?, http_status = ?, response_bytes = ?,
                response_model = ?, output_preview = ?, output_preview_truncated = ?,
                expected_artifact_size_bytes = ?, expected_artifact_sha256 = ?,
                capture_state = 'captured', failure_code = NULL
             WHERE capture_id = ? AND capture_state = 'capturing'",
            params![
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview.as_str(),
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256.as_str(),
                completion.capture_id,
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("active capture transition was lost");
        }
        insert_artifact(&transaction, artifact)?;
        if self.full_text_search {
            transaction.execute(
                "DELETE FROM capture_search WHERE capture_id = ?",
                params![completion.capture_id],
            )?;
            transaction.execute(
                "INSERT INTO capture_search(capture_id, prompt_preview, output_preview)
                 VALUES (?, (SELECT prompt_preview FROM captures WHERE capture_id = ?), ?)",
                params![
                    completion.capture_id,
                    completion.capture_id,
                    completion.output_preview.as_str()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns captures left active when a single-daemon process stopped.
    pub fn incomplete_captures(&self) -> Result<Vec<IncompleteCapture>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT capture_id, completed_at_unix_ms, duration_ms, http_status,
                    response_bytes, response_model, output_preview,
                    output_preview_truncated, expected_artifact_size_bytes,
                    expected_artifact_sha256
             FROM captures WHERE capture_state = 'capturing'",
        )?;
        let mut rows = statement.query([])?;
        let mut captures = Vec::new();
        while let Some(row) = rows.next()? {
            let capture_id = row.get::<_, String>(0)?;
            let completed_at = row.get::<_, Option<i64>>(1)?;
            let duration = row.get::<_, Option<i64>>(2)?;
            let http_status = row.get::<_, Option<i64>>(3)?;
            let response_bytes = row.get::<_, Option<i64>>(4)?;
            let expected_size = row.get::<_, Option<i64>>(8)?;
            let expected_sha256 = row.get::<_, Option<String>>(9)?;
            let completion = match (
                completed_at,
                duration,
                http_status,
                response_bytes,
                expected_size,
                expected_sha256,
            ) {
                (
                    Some(completed_at),
                    Some(duration),
                    Some(http_status),
                    Some(response_bytes),
                    Some(expected_size),
                    Some(expected_sha256),
                ) => Some(CaptureCompletion {
                    capture_id: capture_id.clone(),
                    completed_at_unix_ms: completed_at.try_into()?,
                    duration_ms: duration.try_into()?,
                    http_status: http_status.try_into()?,
                    response_bytes: response_bytes.try_into()?,
                    response_model: row.get(5)?,
                    output_preview: row.get(6)?,
                    output_preview_truncated: row.get(7)?,
                    expected_artifact_size_bytes: expected_size.try_into()?,
                    expected_artifact_sha256: expected_sha256,
                }),
                _ => None,
            };
            captures.push(IncompleteCapture {
                capture_id,
                completion,
            });
        }
        Ok(captures)
    }

    /// Recovers one durable deferred bundle found by the artifact backend.
    pub fn recover_capture_record(
        &self,
        capture_id: &str,
        artifact: &ArtifactRecord,
    ) -> Result<()> {
        require_artifact(artifact, capture_id, ArtifactKind::DeferredBundle)?;
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let changed = transaction.execute(
            "UPDATE captures SET capture_state = 'captured', failure_code = NULL
             WHERE capture_id = ? AND capture_state = 'capturing'",
            params![capture_id],
        )?;
        if changed != 1 {
            anyhow::bail!("capture is not recoverable");
        }
        insert_artifact(&transaction, artifact)?;
        if self.full_text_search {
            transaction.execute(
                "DELETE FROM capture_search WHERE capture_id = ?",
                params![capture_id],
            )?;
            transaction.execute(
                "INSERT INTO capture_search(capture_id, prompt_preview, output_preview)
                 SELECT capture_id, prompt_preview, output_preview
                 FROM captures WHERE capture_id = ?",
                params![capture_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Lists captures using the complete REST filter set. Filter values are
    /// bound parameters, and the result is always bounded.
    pub fn filtered_captures(&self, filters: &CaptureFilters) -> Result<Vec<CaptureSummary>> {
        if filters.query.is_some() && !self.full_text_search {
            anyhow::bail!("full-text preview search is disabled in this agent configuration");
        }
        let search_query = filters.query.as_deref().and_then(capture_search_expression);
        if filters.query.is_some() && search_query.is_none() {
            return Ok(Vec::new());
        }
        let limit = filters.limit.clamp(1, 201);
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut sql = if search_query.is_some() {
            "SELECT c.* FROM captures c JOIN capture_search search ON search.capture_id = c.capture_id WHERE capture_search MATCH ?".to_owned()
        } else {
            "SELECT c.* FROM captures c WHERE 1 = 1".to_owned()
        };
        let mut values = Vec::<rusqlite::types::Value>::new();
        if let Some(query) = search_query {
            values.push(query.into());
        }
        for (column, value) in [
            ("c.requested_model", filters.model.as_deref()),
            ("c.provider", filters.provider.as_deref()),
            ("c.capture_state", filters.capture_state.as_deref()),
            (
                "c.finalization_state",
                filters.finalization_state.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                sql.push_str(" AND ");
                sql.push_str(column);
                sql.push_str(" = ?");
                values.push(value.to_owned().into());
            }
        }
        if let Some(streaming) = filters.streaming {
            sql.push_str(" AND c.streaming = ?");
            values.push(streaming.into());
        }
        if let Some(created_after) = filters.created_after_unix_ms {
            sql.push_str(" AND c.created_at_unix_ms >= ?");
            values.push(i64::try_from(created_after)?.into());
        }
        if let Some(cursor) = &filters.cursor {
            sql.push_str(
                " AND (c.created_at_unix_ms < ? OR (c.created_at_unix_ms = ? AND c.capture_id < ?))",
            );
            let created_at = i64::try_from(cursor.created_at_unix_ms)?;
            values.push(created_at.into());
            values.push(created_at.into());
            values.push(cursor.capture_id.clone().into());
        }
        sql.push_str(" ORDER BY c.created_at_unix_ms DESC, c.capture_id DESC LIMIT ?");
        values.push(i64::try_from(limit)?.into());
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(values))?;
        let mut captures = Vec::new();
        while let Some(row) = rows.next()? {
            captures.push(capture_from_row(row)?);
        }
        Ok(captures)
    }

    pub fn capture(&self, capture_id: &str) -> Result<Option<CaptureSummary>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection
            .query_row(
                "SELECT * FROM captures WHERE capture_id = ?",
                params![capture_id],
                capture_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Returns backend-neutral artifact records while preserving legacy raw
    /// filesystem locators from the unchanged SQLite schema.
    pub fn artifact_records(&self, capture_id: &str) -> Result<Vec<ArtifactRecord>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT capture_id, kind, path, size_bytes, sha256
             FROM artifacts
             WHERE capture_id = ? AND state = 'available'
             ORDER BY kind",
        )?;
        let rows = statement
            .query_map(params![capture_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(capture_id, kind, locator, size_bytes, sha256)| {
                ArtifactRecord::new(
                    ArtifactKey::new(capture_id, ArtifactKind::try_from(kind.as_str())?)?,
                    ArtifactLocator::from_stored(locator)?,
                    size_bytes.try_into()?,
                    sha256,
                )
            })
            .collect()
    }

    pub fn counts(&self) -> Result<MetadataCounts> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection
            .query_row(
                "SELECT
                    COUNT(*),
                    SUM(capture_state = 'capturing'),
                    SUM(capture_state = 'captured' AND finalization_state = 'not_requested'
                        AND http_status BETWEEN 200 AND 299),
                    SUM(finalization_state = 'finalized'),
                    SUM(capture_state = 'failed' OR finalization_state = 'failed'),
                    (SELECT COUNT(*) FROM operations WHERE state IN ('queued', 'running'))
                 FROM captures",
                [],
                |row| {
                    Ok(MetadataCounts {
                        total_captures: row.get::<_, i64>(0)?.try_into().unwrap_or(0),
                        capturing: row
                            .get::<_, Option<i64>>(1)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        ready_to_finalize: row
                            .get::<_, Option<i64>>(2)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        finalized: row
                            .get::<_, Option<i64>>(3)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        failed: row
                            .get::<_, Option<i64>>(4)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        active_operations: row.get::<_, i64>(5)?.try_into().unwrap_or(0),
                    })
                },
            )
            .map_err(Into::into)
    }

    /// Queues a finalization or returns the durable operation that already
    /// represents it. Failed and interrupted work keeps the same identity and
    /// must be resumed through the explicit retry endpoint.
    pub fn enqueue_finalization(
        &self,
        capture_id: &str,
        now: u64,
    ) -> Result<Option<(Operation, bool)>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM captures
                 WHERE capture_id = ? AND capture_state = 'captured'
                   AND http_status BETWEEN 200 AND 299",
                params![capture_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Ok(None);
        }
        if let Some(operation) = transaction
            .query_row(
                "SELECT * FROM operations WHERE capture_id = ? AND kind = 'finalization' ORDER BY created_at_unix_ms DESC LIMIT 1",
                params![capture_id],
                operation_from_row,
            )
            .optional()?
        {
            return Ok(Some((operation, true)));
        }
        let operation_id = format!("op-{}", uuid::Uuid::new_v4().simple());
        transaction.execute(
            "INSERT INTO operations (
                operation_id, kind, capture_id, state, attempt,
                created_at_unix_ms, progress_phase, progress_updated_at_unix_ms
             ) VALUES (?, 'finalization', ?, 'queued', 0, ?, 'queued', ?)",
            params![
                operation_id,
                capture_id,
                i64::try_from(now)?,
                i64::try_from(now)?
            ],
        )?;
        transaction.execute(
            "UPDATE captures SET finalization_state = 'queued' WHERE capture_id = ?",
            params![capture_id],
        )?;
        insert_event(
            &transaction,
            now,
            "finalization_queued",
            Some(capture_id),
            Some(&operation_id),
            "info",
            "Finalization queued",
        )?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        transaction.commit()?;
        Ok(Some((operation, false)))
    }

    pub fn claim_next_finalization(&self, now: u64) -> Result<Option<Operation>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let operation_id = transaction
            .query_row(
                "SELECT operation_id FROM operations WHERE kind = 'finalization' AND state = 'queued' ORDER BY created_at_unix_ms LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        transaction.execute(
            "UPDATE operations
             SET state = 'running', attempt = attempt + 1,
                 started_at_unix_ms = ?, completed_at_unix_ms = NULL,
                 failure_code = NULL, progress_phase = 'preparing',
                 progress_updated_at_unix_ms = ?, proof_bytes_completed = 0,
                 proof_bytes_total = 0, proof_commitments_completed = 0,
                 proof_commitments_total = 0
             WHERE operation_id = ? AND state = 'queued'",
            params![i64::try_from(now)?, i64::try_from(now)?, operation_id],
        )?;
        transaction.execute(
            "UPDATE captures SET finalization_state = 'running' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        transaction.execute(
            "INSERT INTO operation_attempts (operation_id, attempt, state, started_at_unix_ms) VALUES (?, ?, 'running', ?)",
            params![operation.operation_id, operation.attempt, i64::try_from(now)?],
        )?;
        insert_event(
            &transaction,
            now,
            "finalization_started",
            operation.capture_id.as_deref(),
            Some(&operation.operation_id),
            "info",
            "Finalization started",
        )?;
        transaction.commit()?;
        Ok(Some(operation))
    }

    /// Records one stable finalization milestone. The update is ignored if the
    /// operation is no longer running, which keeps a late callback from
    /// changing terminal state after interruption or failure.
    pub fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: crate::FinalizationPhase,
        now: u64,
    ) -> Result<bool> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let phase = phase.as_str();
        let changed = transaction.execute(
            "UPDATE operations
             SET progress_phase = ?, progress_updated_at_unix_ms = ?
             WHERE operation_id = ? AND state = 'running' AND progress_phase <> ?",
            params![phase, i64::try_from(now)?, operation_id, phase],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        let capture_id: Option<String> = transaction.query_row(
            "SELECT capture_id FROM operations WHERE operation_id = ?",
            params![operation_id],
            |row| row.get(0),
        )?;
        let message = match phase {
            "proving" => "Generating private proof",
            "signing" => "Requesting notary signature",
            "packaging" => "Building verified package",
            _ => "Finalization advanced",
        };
        insert_event(
            &transaction,
            now,
            "finalization_progress",
            capture_id.as_deref(),
            Some(operation_id),
            "info",
            message,
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Persists throttled proof-work counters without emitting one activity
    /// event per batch. The first update also records entry into the proving
    /// phase for the activity feed.
    pub fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: crate::FinalizationProofProgress,
        now: u64,
    ) -> Result<bool> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let previous = transaction
            .query_row(
                "SELECT progress_phase, proof_bytes_completed, proof_bytes_total,
                        proof_commitments_completed, proof_commitments_total
                 FROM operations
                 WHERE operation_id = ? AND state = 'running'",
                params![operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            previous_phase,
            bytes_completed,
            bytes_total,
            commitments_completed,
            commitments_total,
        )) = previous
        else {
            return Ok(false);
        };
        let bytes_completed = u64::try_from(bytes_completed)?;
        let bytes_total = u64::try_from(bytes_total)?;
        let commitments_completed = u64::try_from(commitments_completed)?;
        let commitments_total = u64::try_from(commitments_total)?;
        if previous_phase == "proving"
            && bytes_completed == progress.bytes_completed
            && bytes_total == progress.bytes_total
            && commitments_completed == progress.commitments_completed
            && commitments_total == progress.commitments_total
        {
            return Ok(false);
        }
        anyhow::ensure!(
            progress.bytes_completed >= bytes_completed
                && progress.commitments_completed >= commitments_completed,
            "proof progress cannot decrease"
        );
        anyhow::ensure!(
            bytes_total == 0 || progress.bytes_total == bytes_total,
            "proof byte total cannot change after it is established"
        );
        anyhow::ensure!(
            commitments_total == 0 || progress.commitments_total == commitments_total,
            "proof commitment total cannot change after it is established"
        );
        transaction.execute(
            "UPDATE operations
             SET progress_phase = 'proving', progress_updated_at_unix_ms = ?,
                 proof_bytes_completed = ?, proof_bytes_total = ?,
                 proof_commitments_completed = ?, proof_commitments_total = ?
             WHERE operation_id = ? AND state = 'running'",
            params![
                i64::try_from(now)?,
                i64::try_from(progress.bytes_completed)?,
                i64::try_from(progress.bytes_total)?,
                i64::try_from(progress.commitments_completed)?,
                i64::try_from(progress.commitments_total)?,
                operation_id,
            ],
        )?;
        if previous_phase != "proving" {
            let capture_id: Option<String> = transaction.query_row(
                "SELECT capture_id FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| row.get(0),
            )?;
            insert_event(
                &transaction,
                now,
                "finalization_progress",
                capture_id.as_deref(),
                Some(operation_id),
                "info",
                "Generating private proof",
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn complete_finalization(
        &self,
        operation_id: &str,
        artifact: &ArtifactRecord,
        now: u64,
    ) -> Result<TerminalOperationResult> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let Some((current_state, capture_id)) = transaction
            .query_row(
                "SELECT state, capture_id FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
        else {
            return Ok(TerminalOperationResult::NotFound);
        };
        validate_persisted_operation_state(&current_state)?;
        let capture_id = capture_id.context("finalization operation has no capture")?;
        require_artifact(artifact, &capture_id, ArtifactKind::FinalizedPackage)?;
        if current_state == "finalized" {
            anyhow::ensure!(
                artifact_exists_exact(&transaction, artifact)?,
                "finalized operation artifact does not match persisted metadata"
            );
            return Ok(TerminalOperationResult::AlreadyApplied);
        }
        if current_state != "running" {
            return Ok(TerminalOperationResult::Conflict { current_state });
        }

        insert_artifact(&transaction, artifact)?;
        let changed = transaction.execute(
            "UPDATE operations
             SET state = 'finalized', completed_at_unix_ms = ?, failure_code = NULL,
                 progress_phase = 'complete', progress_updated_at_unix_ms = ?
             WHERE operation_id = ? AND state = 'running'",
            params![i64::try_from(now)?, i64::try_from(now)?, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation transition was lost");
        let changed = transaction.execute(
            "UPDATE operation_attempts SET state = 'finalized', completed_at_unix_ms = ?, failure_code = NULL WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)",
            params![i64::try_from(now)?, operation_id, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation has no current attempt");
        let changed = transaction.execute(
            "UPDATE captures SET finalization_state = 'finalized' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        anyhow::ensure!(changed == 1, "finalization operation has no capture");
        insert_event(
            &transaction,
            now,
            "finalization_completed",
            Some(&capture_id),
            Some(operation_id),
            "success",
            "Finalization completed",
        )?;
        transaction.commit()?;
        Ok(TerminalOperationResult::Applied)
    }

    pub fn fail_operation(
        &self,
        operation_id: &str,
        now: u64,
        failure_code: &str,
    ) -> Result<TerminalOperationResult> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let Some((current_state, current_failure_code)) = transaction
            .query_row(
                "SELECT state, failure_code FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
        else {
            return Ok(TerminalOperationResult::NotFound);
        };
        validate_persisted_operation_state(&current_state)?;
        if current_state == "failed" && current_failure_code.as_deref() == Some(failure_code) {
            return Ok(TerminalOperationResult::AlreadyApplied);
        }
        if current_state != "running" {
            return Ok(TerminalOperationResult::Conflict { current_state });
        }

        let changed = transaction.execute(
            "UPDATE operations SET state = 'failed', completed_at_unix_ms = ?, failure_code = ? WHERE operation_id = ? AND state = 'running'",
            params![i64::try_from(now)?, failure_code, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation transition was lost");
        let changed = transaction.execute(
            "UPDATE operation_attempts SET state = 'failed', completed_at_unix_ms = ?, failure_code = ? WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)",
            params![i64::try_from(now)?, failure_code, operation_id, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation has no current attempt");
        let changed = transaction.execute(
            "UPDATE captures SET finalization_state = 'failed' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        anyhow::ensure!(changed == 1, "finalization operation has no capture");
        let capture_id: Option<String> = transaction.query_row(
            "SELECT capture_id FROM operations WHERE operation_id = ?",
            params![operation_id],
            |row| row.get(0),
        )?;
        insert_event(
            &transaction,
            now,
            "finalization_failed",
            capture_id.as_deref(),
            Some(operation_id),
            "error",
            "Finalization failed",
        )?;
        transaction.commit()?;
        Ok(TerminalOperationResult::Applied)
    }

    pub fn recover_operations(&self, now: u64) -> Result<usize> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let mut statement = transaction
            .prepare("SELECT operation_id, capture_id FROM operations WHERE state = 'running'")?;
        let interrupted = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (operation_id, capture_id) in &interrupted {
            transaction.execute("UPDATE operations SET state = 'interrupted', completed_at_unix_ms = ?, failure_code = 'service_restarted' WHERE operation_id = ?", params![i64::try_from(now)?, operation_id])?;
            transaction.execute("UPDATE operation_attempts SET state = 'interrupted', completed_at_unix_ms = ?, failure_code = 'service_restarted' WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)", params![i64::try_from(now)?, operation_id, operation_id])?;
            transaction.execute(
                "UPDATE captures SET finalization_state = 'interrupted' WHERE capture_id = ?",
                params![capture_id],
            )?;
            insert_event(
                &transaction,
                now,
                "finalization_interrupted",
                capture_id.as_deref(),
                Some(operation_id),
                "warning",
                "Finalization interrupted by service restart",
            )?;
        }
        transaction.commit()?;
        Ok(interrupted.len())
    }

    pub fn retry_operation(&self, operation_id: &str, now: u64) -> Result<Option<Operation>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        let changed = transaction.execute(
            "UPDATE operations
             SET state = 'queued', started_at_unix_ms = NULL,
                 completed_at_unix_ms = NULL, failure_code = NULL,
                 progress_phase = 'queued', progress_updated_at_unix_ms = ?,
                 proof_bytes_completed = 0, proof_bytes_total = 0,
                 proof_commitments_completed = 0, proof_commitments_total = 0
             WHERE operation_id = ? AND state IN ('failed', 'interrupted')
               AND EXISTS (
                   SELECT 1 FROM captures
                   WHERE captures.capture_id = operations.capture_id
                     AND captures.http_status BETWEEN 200 AND 299
               )",
            params![i64::try_from(now)?, operation_id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        transaction.execute("UPDATE captures SET finalization_state = 'queued' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)", params![operation_id])?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        insert_event(
            &transaction,
            now,
            "finalization_retried",
            operation.capture_id.as_deref(),
            Some(operation_id),
            "info",
            "Finalization queued for retry",
        )?;
        transaction.commit()?;
        Ok(Some(operation))
    }

    pub fn operation(&self, operation_id: &str) -> Result<Option<Operation>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection
            .query_row(
                "SELECT * FROM operations WHERE operation_id = ?",
                params![operation_id],
                operation_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn filtered_operations(&self, filters: &OperationFilters) -> Result<Vec<Operation>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut sql = "SELECT * FROM operations WHERE 1 = 1".to_owned();
        let mut values = Vec::<rusqlite::types::Value>::new();
        for (column, value) in [
            ("state", filters.state.as_deref()),
            ("kind", filters.kind.as_deref()),
            ("capture_id", filters.capture_id.as_deref()),
        ] {
            if let Some(value) = value {
                sql.push_str(" AND ");
                sql.push_str(column);
                sql.push_str(" = ?");
                values.push(value.to_owned().into());
            }
        }
        if let Some(cursor) = &filters.cursor {
            sql.push_str(
                " AND (created_at_unix_ms < ? OR (created_at_unix_ms = ? AND operation_id < ?))",
            );
            let created_at = i64::try_from(cursor.created_at_unix_ms)?;
            values.push(created_at.into());
            values.push(created_at.into());
            values.push(cursor.operation_id.clone().into());
        }
        sql.push_str(" ORDER BY created_at_unix_ms DESC, operation_id DESC LIMIT ?");
        values.push(i64::try_from(filters.limit.clamp(1, 201))?.into());
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(values))?;
        let mut operations = Vec::new();
        while let Some(row) = rows.next()? {
            operations.push(operation_from_row(row)?);
        }
        Ok(operations)
    }

    pub fn operation_attempts(&self, operation_id: &str) -> Result<Vec<OperationAttempt>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT attempt, state, started_at_unix_ms, completed_at_unix_ms, failure_code
             FROM operation_attempts WHERE operation_id = ? ORDER BY attempt DESC",
        )?;
        let rows = statement.query_map(params![operation_id], operation_attempt_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Reads the displayed page and its follow watermark from one SQLite
    /// snapshot so an event committed between the two reads cannot be skipped.
    pub fn filtered_events_with_high_water(
        &self,
        filters: &EventFilters,
    ) -> Result<(Vec<Event>, Option<u64>)> {
        let mut connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.transaction()?;
        let events = filtered_events(&transaction, filters)?;
        let high_water = event_high_water(&transaction, filters)?;
        transaction.commit()?;
        Ok((events, high_water))
    }
}

fn filtered_events(connection: &Connection, filters: &EventFilters) -> Result<Vec<Event>> {
    if filters.before.is_some() && filters.after.is_some() {
        anyhow::bail!("event history and follow positions are mutually exclusive");
    }
    let mut sql = "SELECT * FROM events WHERE 1 = 1".to_owned();
    let mut values = Vec::<rusqlite::types::Value>::new();
    if let Some(before) = filters.before {
        sql.push_str(" AND event_id < ?");
        values.push(i64::try_from(before)?.into());
    }
    if let Some(after) = filters.after {
        sql.push_str(" AND event_id > ?");
        values.push(i64::try_from(after)?.into());
    }
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("capture_id", filters.capture_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            sql.push_str(" AND ");
            sql.push_str(column);
            sql.push_str(" = ?");
            values.push(value.to_owned().into());
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        sql.push_str(" AND created_at_unix_ms >= ?");
        values.push(i64::try_from(created_after)?.into());
    }
    if filters.after.is_some() {
        sql.push_str(" ORDER BY event_id ASC LIMIT ?");
    } else {
        sql.push_str(" ORDER BY event_id DESC LIMIT ?");
    }
    values.push(i64::try_from(filters.limit.clamp(1, 201))?.into());
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(event_from_row(row)?);
    }
    Ok(events)
}

fn event_high_water(connection: &Connection, filters: &EventFilters) -> Result<Option<u64>> {
    let mut sql = "SELECT MAX(event_id) FROM events WHERE 1 = 1".to_owned();
    let mut values = Vec::<rusqlite::types::Value>::new();
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("capture_id", filters.capture_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            sql.push_str(" AND ");
            sql.push_str(column);
            sql.push_str(" = ?");
            values.push(value.to_owned().into());
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        sql.push_str(" AND created_at_unix_ms >= ?");
        values.push(i64::try_from(created_after)?.into());
    }
    connection
        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
            row.get::<_, Option<i64>>(0)
        })?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
}

fn validate_persisted_operation_state(state: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(
            state,
            "queued" | "running" | "interrupted" | "failed" | "finalized"
        ),
        "operation has an invalid persisted state"
    );
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<()> {
    migrate_to(connection, CATALOG_SCHEMA_VERSION)
}

#[cfg(test)]
pub(crate) fn create_schema_fixture(path: &Path, version: i64) -> Result<()> {
    let mut connection = Connection::open(path)?;
    migrate_to(&mut connection, version)
}

fn migrate_to(connection: &mut Connection, target_version: i64) -> Result<()> {
    anyhow::ensure!(
        (1..=CATALOG_SCHEMA_VERSION).contains(&target_version),
        "invalid catalog migration target"
    );
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY
        );",
    )?;
    let version = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?
        .unwrap_or(0);
    if version > CATALOG_SCHEMA_VERSION {
        anyhow::bail!("capture catalog was created by a newer client version");
    }
    if version == 0 && target_version >= 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE captures (
                capture_id TEXT PRIMARY KEY,
                created_at_unix_ms INTEGER NOT NULL,
                completed_at_unix_ms INTEGER,
                provider TEXT NOT NULL,
                operation TEXT NOT NULL,
                requested_model TEXT,
                response_model TEXT,
                http_status INTEGER,
                streaming INTEGER NOT NULL,
                request_bytes INTEGER NOT NULL,
                response_bytes INTEGER,
                duration_ms INTEGER,
                prompt_preview TEXT NOT NULL,
                prompt_preview_truncated INTEGER NOT NULL,
                output_preview TEXT NOT NULL DEFAULT '',
                output_preview_truncated INTEGER NOT NULL DEFAULT 0,
                config_fingerprint TEXT NOT NULL,
                capture_state TEXT NOT NULL,
                finalization_state TEXT NOT NULL,
                failure_code TEXT
            );
            CREATE TABLE artifacts (
                capture_id TEXT NOT NULL REFERENCES captures(capture_id),
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                PRIMARY KEY(capture_id, kind)
            );
            CREATE INDEX captures_created_at_idx ON captures(created_at_unix_ms DESC);
            CREATE INDEX captures_model_idx ON captures(requested_model);
            CREATE VIRTUAL TABLE capture_search USING fts5(
                capture_id UNINDEXED,
                prompt_preview,
                output_preview
            );",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (1)", [])?;
        transaction.commit()?;
    }
    if version < 2 && target_version >= 2 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                capture_id TEXT REFERENCES captures(capture_id),
                state TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0,
                created_at_unix_ms INTEGER NOT NULL,
                started_at_unix_ms INTEGER,
                completed_at_unix_ms INTEGER,
                failure_code TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_finalization_per_capture
                ON operations(capture_id, kind)
                WHERE kind = 'finalization' AND state IN ('queued', 'running');
            CREATE INDEX IF NOT EXISTS operations_created_at_idx ON operations(created_at_unix_ms DESC);
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_unix_ms INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                capture_id TEXT REFERENCES captures(capture_id),
                operation_id TEXT REFERENCES operations(operation_id),
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_created_at_idx ON events(created_at_unix_ms DESC);",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (2)", [])?;
        transaction.commit()?;
    }
    if version < 3 && target_version >= 3 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE operation_attempts (
                operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                attempt INTEGER NOT NULL,
                state TEXT NOT NULL,
                started_at_unix_ms INTEGER NOT NULL,
                completed_at_unix_ms INTEGER,
                failure_code TEXT,
                PRIMARY KEY(operation_id, attempt)
            );
            CREATE INDEX operation_attempts_started_at_idx
                ON operation_attempts(started_at_unix_ms DESC);
            INSERT INTO operation_attempts (
                operation_id, attempt, state, started_at_unix_ms,
                completed_at_unix_ms, failure_code
            )
            SELECT operation_id, attempt, state, started_at_unix_ms,
                   completed_at_unix_ms, failure_code
            FROM operations
            WHERE attempt > 0 AND started_at_unix_ms IS NOT NULL;",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (3)", [])?;
        transaction.commit()?;
    }
    if version < 4 && target_version >= 4 {
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE captures SET capture_state = 'captured' WHERE capture_state = 'pending'",
            [],
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (4)", [])?;
        transaction.commit()?;
    }
    if version < 5 && target_version >= 5 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE INDEX IF NOT EXISTS captures_page_idx
                ON captures(created_at_unix_ms DESC, capture_id DESC);
            CREATE INDEX IF NOT EXISTS operations_page_idx
                ON operations(created_at_unix_ms DESC, operation_id DESC);",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (5)", [])?;
        transaction.commit()?;
    }
    if version < 6 && target_version >= 6 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "ALTER TABLE operations
                ADD COLUMN progress_phase TEXT NOT NULL DEFAULT 'queued';
             ALTER TABLE operations
                ADD COLUMN progress_updated_at_unix_ms INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE operations
                ADD COLUMN proof_bytes_completed INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE operations
                ADD COLUMN proof_bytes_total INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE operations
                ADD COLUMN proof_commitments_completed INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE operations
                ADD COLUMN proof_commitments_total INTEGER NOT NULL DEFAULT 0;
             UPDATE operations
             SET progress_phase = CASE state
                    WHEN 'finalized' THEN 'complete'
                    WHEN 'running' THEN 'preparing'
                    WHEN 'queued' THEN 'queued'
                    ELSE 'unknown'
                 END,
                 progress_updated_at_unix_ms = COALESCE(
                    completed_at_unix_ms, started_at_unix_ms, created_at_unix_ms
                 );",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (6)", [])?;
        transaction.commit()?;
    }
    if version < 7 && target_version >= 7 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "ALTER TABLE captures
                ADD COLUMN expected_artifact_size_bytes INTEGER;
             ALTER TABLE captures
                ADD COLUMN expected_artifact_sha256 TEXT;",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (7)", [])?;
        transaction.commit()?;
    }
    if version < 8 && target_version >= 8 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE daemon_settings (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capture_enabled INTEGER NOT NULL CHECK (capture_enabled IN (0, 1))
             );
             INSERT INTO daemon_settings (singleton, capture_enabled) VALUES (1, 1);",
        )?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (8)", [])?;
        transaction.commit()?;
    }
    Ok(())
}

fn require_artifact(artifact: &ArtifactRecord, capture_id: &str, kind: ArtifactKind) -> Result<()> {
    if artifact.key.capture_id() != capture_id {
        anyhow::bail!("artifact capture does not match metadata transition");
    }
    if artifact.key.kind() != kind {
        anyhow::bail!("artifact kind does not match metadata transition");
    }
    Ok(())
}

fn insert_artifact(
    transaction: &rusqlite::Transaction<'_>,
    artifact: &ArtifactRecord,
) -> Result<()> {
    let changed = transaction.execute(
        "INSERT INTO artifacts (capture_id, kind, path, size_bytes, sha256, state)
         VALUES (?, ?, ?, ?, ?, 'available')
         ON CONFLICT(capture_id, kind) DO NOTHING",
        params![
            artifact.key.capture_id(),
            artifact.key.kind().as_str(),
            artifact.locator.as_stored(),
            i64::try_from(artifact.size_bytes)?,
            artifact.sha256.as_str(),
        ],
    )?;
    anyhow::ensure!(
        changed == 1 || artifact_exists_exact(transaction, artifact)?,
        "artifact metadata conflicts with an existing immutable record"
    );
    Ok(())
}

fn artifact_exists_exact(
    transaction: &rusqlite::Transaction<'_>,
    artifact: &ArtifactRecord,
) -> Result<bool> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifacts
                WHERE capture_id = ? AND kind = ? AND path = ?
                  AND size_bytes = ? AND sha256 = ? AND state = 'available'
             )",
            params![
                artifact.key.capture_id(),
                artifact.key.kind().as_str(),
                artifact.locator.as_stored(),
                i64::try_from(artifact.size_bytes)?,
                artifact.sha256.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn capture_completion_matches(
    transaction: &rusqlite::Transaction<'_>,
    completion: &CaptureCompletion,
) -> Result<bool> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM captures
                WHERE capture_id = ?
                  AND completed_at_unix_ms = ? AND duration_ms = ? AND http_status = ?
                  AND response_bytes = ? AND response_model IS ?
                  AND output_preview = ? AND output_preview_truncated = ?
                  AND expected_artifact_size_bytes = ? AND expected_artifact_sha256 = ?
             )",
            params![
                completion.capture_id,
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview,
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256,
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn capture_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaptureSummary> {
    Ok(CaptureSummary {
        capture_id: row.get("capture_id")?,
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        provider: row.get("provider")?,
        operation: row.get("operation")?,
        requested_model: row.get("requested_model")?,
        response_model: row.get("response_model")?,
        http_status: row
            .get::<_, Option<i64>>("http_status")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        streaming: row.get("streaming")?,
        request_bytes: row
            .get::<_, i64>("request_bytes")?
            .try_into()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        response_bytes: row
            .get::<_, Option<i64>>("response_bytes")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        duration_ms: row
            .get::<_, Option<i64>>("duration_ms")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        capture_state: row.get("capture_state")?,
        finalization_state: row.get("finalization_state")?,
        prompt_preview: row.get("prompt_preview")?,
        prompt_preview_truncated: row.get("prompt_preview_truncated")?,
        output_preview: row.get("output_preview")?,
        output_preview_truncated: row.get("output_preview_truncated")?,
        expected_artifact_size_bytes: row
            .get::<_, Option<i64>>("expected_artifact_size_bytes")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    21,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        expected_artifact_sha256: row.get("expected_artifact_sha256")?,
        failure_code: row.get("failure_code")?,
    })
}

fn operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    Ok(Operation {
        operation_id: row.get("operation_id")?,
        kind: row.get("kind")?,
        capture_id: row.get("capture_id")?,
        state: row.get("state")?,
        attempt: row.get::<_, i64>("attempt")?.try_into().unwrap_or(0),
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        started_at_unix_ms: row
            .get::<_, Option<i64>>("started_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        failure_code: row.get("failure_code")?,
        progress_phase: row.get("progress_phase")?,
        progress_updated_at_unix_ms: row
            .get::<_, i64>("progress_updated_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        proof_bytes_completed: row
            .get::<_, i64>("proof_bytes_completed")?
            .try_into()
            .unwrap_or(0),
        proof_bytes_total: row
            .get::<_, i64>("proof_bytes_total")?
            .try_into()
            .unwrap_or(0),
        proof_commitments_completed: row
            .get::<_, i64>("proof_commitments_completed")?
            .try_into()
            .unwrap_or(0),
        proof_commitments_total: row
            .get::<_, i64>("proof_commitments_total")?
            .try_into()
            .unwrap_or(0),
    })
}

fn operation_attempt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationAttempt> {
    Ok(OperationAttempt {
        attempt: row.get::<_, i64>("attempt")?.try_into().unwrap_or(0),
        state: row.get("state")?,
        started_at_unix_ms: row
            .get::<_, i64>("started_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        failure_code: row.get("failure_code")?,
    })
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        event_id: row.get::<_, i64>("event_id")?.try_into().unwrap_or(0),
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        event_type: row.get("event_type")?,
        capture_id: row.get("capture_id")?,
        operation_id: row.get("operation_id")?,
        severity: row.get("severity")?,
        message: row.get("message")?,
    })
}

fn insert_event(
    transaction: &rusqlite::Transaction<'_>,
    now: u64,
    event_type: &str,
    capture_id: Option<&str>,
    operation_id: Option<&str>,
    severity: &str,
    message: &str,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO events (created_at_unix_ms, event_type, capture_id, operation_id, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
        params![i64::try_from(now)?, event_type, capture_id, operation_id, severity, message],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_capture(id: &str) -> NewCapture {
        NewCapture {
            capture_id: id.to_owned(),
            created_at_unix_ms: 1,
            provider: "openai".to_owned(),
            operation: "responses".to_owned(),
            requested_model: Some("gpt-5".to_owned()),
            streaming: false,
            request_bytes: 12,
            prompt_preview: "Explain quarterly pricing".to_owned(),
            prompt_preview_truncated: false,
            config_fingerprint: "sha256:test".to_owned(),
        }
    }

    fn deferred_artifact(id: &str) -> ArtifactRecord {
        ArtifactRecord::new(
            ArtifactKey::new(id, ArtifactKind::DeferredBundle).unwrap(),
            ArtifactLocator::from_stored(format!("test-artifacts/{id}.llmcapture")).unwrap(),
            10,
            "00".repeat(32),
        )
        .unwrap()
    }

    fn complete_capture(catalog: &SqliteCatalog, id: &str, status: u16, output: &str) {
        catalog
            .complete_capture_record(
                &CaptureCompletion {
                    capture_id: id.to_owned(),
                    completed_at_unix_ms: 2,
                    duration_ms: 1,
                    http_status: status,
                    response_bytes: 24,
                    response_model: Some("gpt-5".to_owned()),
                    output_preview: output.to_owned(),
                    output_preview_truncated: false,
                    expected_artifact_size_bytes: 10,
                    expected_artifact_sha256: "00".repeat(32),
                },
                &deferred_artifact(id),
            )
            .unwrap();
    }

    #[test]
    fn migrates_completed_capture_state_to_captured() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        let catalog = SqliteCatalog::open(&path, true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();
        complete_capture(&catalog, "cap-1", 200, "done");
        {
            let connection = catalog.connection.lock().unwrap();
            connection
                .execute(
                    "UPDATE captures SET capture_state = 'pending' WHERE capture_id = 'cap-1'",
                    [],
                )
                .unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE operations DROP COLUMN progress_phase;
                     ALTER TABLE operations DROP COLUMN progress_updated_at_unix_ms;
                     ALTER TABLE operations DROP COLUMN proof_bytes_completed;
                     ALTER TABLE operations DROP COLUMN proof_bytes_total;
                     ALTER TABLE operations DROP COLUMN proof_commitments_completed;
                     ALTER TABLE operations DROP COLUMN proof_commitments_total;
                     ALTER TABLE captures DROP COLUMN expected_artifact_size_bytes;
                     ALTER TABLE captures DROP COLUMN expected_artifact_sha256;
                     DROP TABLE daemon_settings;
                     DELETE FROM schema_migrations WHERE version >= 4;",
                )
                .unwrap();
        }
        drop(catalog);

        let migrated = SqliteCatalog::open(&path, true).unwrap();
        assert_eq!(
            migrated.capture("cap-1").unwrap().unwrap().capture_state,
            "captured"
        );
        let version: i64 = migrated
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, CATALOG_SCHEMA_VERSION);
    }

    #[test]
    fn legacy_prepared_capture_recovery_preserves_its_search_preview() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        create_schema_fixture(&path, 6).unwrap();
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO captures (
                    capture_id, created_at_unix_ms, completed_at_unix_ms, provider,
                    operation, requested_model, response_model, http_status, streaming,
                    request_bytes, response_bytes, duration_ms, prompt_preview,
                    prompt_preview_truncated, output_preview, output_preview_truncated,
                    config_fingerprint, capture_state, finalization_state, failure_code
                 ) VALUES (
                    'cap-legacy-prepared', 1, 2, 'openai', 'responses', 'gpt-5',
                    'gpt-5', 200, 0, 12, 24, 1, 'Legacy staged prompt', 0,
                    'Legacy staged output', 0, 'sha256:test', 'capturing',
                    'not_requested', NULL
                 )",
                [],
            )
            .unwrap();
        drop(connection);

        let catalog = SqliteCatalog::open(&path, true).unwrap();
        catalog
            .recover_capture_record(
                "cap-legacy-prepared",
                &deferred_artifact("cap-legacy-prepared"),
            )
            .unwrap();
        let matches = catalog
            .filtered_captures(&CaptureFilters {
                query: Some("legacy output".to_owned()),
                limit: 50,
                ..CaptureFilters::default()
            })
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].capture_id, "cap-legacy-prepared");
        assert_eq!(matches[0].expected_artifact_size_bytes, None);
        assert_eq!(matches[0].expected_artifact_sha256, None);
    }

    #[test]
    fn durable_operation_migration_is_atomic_and_resumable() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        connection
            .execute_batch(
                "ALTER TABLE captures DROP COLUMN expected_artifact_size_bytes;
                 ALTER TABLE captures DROP COLUMN expected_artifact_sha256;",
            )
            .unwrap();
        connection
            .execute("DELETE FROM schema_migrations WHERE version >= 2", [])
            .unwrap();
        connection
            .execute_batch(
                "DROP TABLE operation_attempts;
                 DROP TABLE events;
                 DROP TABLE daemon_settings;
                 DROP INDEX operations_created_at_idx;
                 DROP INDEX one_active_finalization_per_capture;
                 DROP TABLE operations;
                 CREATE TABLE operations (operation_id TEXT PRIMARY KEY);",
            )
            .unwrap();

        assert!(migrate(&mut connection).is_err());
        assert_eq!(
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            1
        );

        connection.execute("DROP TABLE operations", []).unwrap();
        migrate(&mut connection).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            CATALOG_SCHEMA_VERSION
        );
    }
}
