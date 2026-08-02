//! SQLite-backed local capture inventory and preview search.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::{config::AgentConfig, sha256_hex};

const CATALOG_SCHEMA_VERSION: i64 = 2;

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogCounts {
    pub total_captures: u64,
    pub capturing: u64,
    pub pending: u64,
    pub finalized: u64,
    pub failed: u64,
    pub active_operations: u64,
}

#[derive(Clone, Debug, Default)]
pub struct CaptureFilters<'a> {
    pub query: Option<&'a str>,
    pub model: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub capture_state: Option<&'a str>,
    pub finalization_state: Option<&'a str>,
    pub limit: usize,
    pub offset: usize,
}

/// One stored local artifact belonging to a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub kind: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

/// The result of reconciling captures that were active when the prior process
/// stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub recovered_bundles: usize,
    pub interrupted_captures: usize,
}

/// A single-process SQLite capture inventory.
pub struct Catalog {
    connection: Mutex<Connection>,
    full_text_search: bool,
}

impl Catalog {
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

    /// Opens the configured catalog without changing capture state. This is
    /// safe for concurrent read-only CLI commands while a proxy is capturing.
    pub fn open_for_config(config: &AgentConfig) -> Result<Self> {
        Self::open(&config.catalog.path, config.catalog.full_text_search)
    }

    /// Opens the configured catalog and recovers any source bundle saved just
    /// before an earlier proxy process stopped. Only proxy startup performs
    /// recovery so catalog readers cannot mistake a live capture for an
    /// interrupted one. The capture row is intentionally written before
    /// capture begins, so its identifier also determines the encrypted bundle
    /// filename without reading private bundle contents.
    pub fn open_for_proxy(config: &AgentConfig) -> Result<(Self, RecoverySummary)> {
        let catalog = Self::open_for_config(config)?;
        let recovery = catalog.reconcile_incomplete_captures(&config.storage.bundle_dir)?;
        Ok((catalog, recovery))
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
        connection.execute(
            "UPDATE captures
             SET capture_state = 'failed', failure_code = ?
             WHERE capture_id = ?",
            params![failure_code, capture_id],
        )?;
        Ok(())
    }

    /// Makes one encrypted source bundle available in the capture inventory.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_capture(
        &self,
        capture_id: &str,
        completed_at_unix_ms: u64,
        duration_ms: u64,
        http_status: u16,
        response_bytes: usize,
        response_model: Option<&str>,
        output_preview: &str,
        output_preview_truncated: bool,
        bundle_path: &Path,
    ) -> Result<()> {
        let (size_bytes, sha256) = artifact_digest(bundle_path)?;
        let path = bundle_path.to_string_lossy().into_owned();
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE captures SET
                completed_at_unix_ms = ?, duration_ms = ?, http_status = ?, response_bytes = ?,
                response_model = ?, output_preview = ?, output_preview_truncated = ?,
                capture_state = 'pending', failure_code = NULL
             WHERE capture_id = ?",
            params![
                i64::try_from(completed_at_unix_ms)?,
                i64::try_from(duration_ms)?,
                i64::from(http_status),
                i64::try_from(response_bytes)?,
                response_model,
                output_preview,
                output_preview_truncated,
                capture_id,
            ],
        )?;
        transaction.execute(
            "INSERT INTO artifacts (capture_id, kind, path, size_bytes, sha256, state)
             VALUES (?, 'deferred_bundle', ?, ?, ?, 'available')
             ON CONFLICT(capture_id, kind) DO UPDATE SET
                path = excluded.path,
                size_bytes = excluded.size_bytes,
                sha256 = excluded.sha256,
                state = 'available'",
            params![capture_id, path, i64::try_from(size_bytes)?, sha256,],
        )?;
        if self.full_text_search {
            transaction.execute(
                "DELETE FROM capture_search WHERE capture_id = ?",
                params![capture_id],
            )?;
            transaction.execute(
                "INSERT INTO capture_search(capture_id, prompt_preview, output_preview)
                 VALUES (?, (SELECT prompt_preview FROM captures WHERE capture_id = ?), ?)",
                params![capture_id, capture_id, output_preview],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Records one finalized package without removing its source bundle.
    pub fn record_finalized_package(&self, capture_id: &str, path: &Path) -> Result<()> {
        let (size_bytes, sha256) = artifact_digest(path)?;
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO artifacts (capture_id, kind, path, size_bytes, sha256, state)
             VALUES (?, 'finalized_package', ?, ?, ?, 'available')
             ON CONFLICT(capture_id, kind) DO UPDATE SET
                path = excluded.path,
                size_bytes = excluded.size_bytes,
                sha256 = excluded.sha256,
                state = 'available'",
            params![
                capture_id,
                path.to_string_lossy(),
                i64::try_from(size_bytes)?,
                sha256,
            ],
        )?;
        transaction.execute(
            "UPDATE captures SET finalization_state = 'finalized' WHERE capture_id = ?",
            params![capture_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Reconciles `capturing` rows from an earlier process. A present bundle is
    /// made visible as pending evidence; a missing bundle is marked as an
    /// interrupted capture instead of appearing to run forever.
    pub fn reconcile_incomplete_captures(&self, bundle_dir: &Path) -> Result<RecoverySummary> {
        let capture_ids = {
            let connection = self.connection.lock().expect("catalog mutex poisoned");
            let mut statement = connection
                .prepare("SELECT capture_id FROM captures WHERE capture_state = 'capturing'")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };

        let mut summary = RecoverySummary::default();
        for capture_id in capture_ids {
            let path = bundle_dir.join(format!("{capture_id}.llmbundle"));
            if path.is_file() {
                self.recover_bundle(&capture_id, &path)?;
                summary.recovered_bundles += 1;
            } else {
                self.mark_capture_failed(&capture_id, "interrupted")?;
                summary.interrupted_captures += 1;
            }
        }
        Ok(summary)
    }

    fn recover_bundle(&self, capture_id: &str, path: &Path) -> Result<()> {
        let (size_bytes, sha256) = artifact_digest(path)?;
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE captures SET capture_state = 'pending', failure_code = NULL
             WHERE capture_id = ?",
            params![capture_id],
        )?;
        transaction.execute(
            "INSERT INTO artifacts (capture_id, kind, path, size_bytes, sha256, state)
             VALUES (?, 'deferred_bundle', ?, ?, ?, 'available')
             ON CONFLICT(capture_id, kind) DO UPDATE SET
                path = excluded.path,
                size_bytes = excluded.size_bytes,
                sha256 = excluded.sha256,
                state = 'available'",
            params![
                capture_id,
                path.to_string_lossy(),
                i64::try_from(size_bytes)?,
                sha256,
            ],
        )?;
        if self.full_text_search {
            transaction.execute(
                "DELETE FROM capture_search WHERE capture_id = ?",
                params![capture_id],
            )?;
            transaction.execute(
                "INSERT INTO capture_search(capture_id, prompt_preview, output_preview)
                 VALUES (?, (SELECT prompt_preview FROM captures WHERE capture_id = ?), '')",
                params![capture_id, capture_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Lists captures, optionally filtering their prompt and output previews
    /// with SQLite FTS5 and/or filtering their requested model.
    pub fn list_captures(
        &self,
        query: Option<&str>,
        model: Option<&str>,
    ) -> Result<Vec<CaptureSummary>> {
        if query.is_some() && !self.full_text_search {
            anyhow::bail!("full-text preview search is disabled in this agent configuration");
        }
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = match (query, model) {
            (Some(_), Some(_)) => connection.prepare(
                "SELECT c.* FROM captures c
                 JOIN capture_search search ON search.capture_id = c.capture_id
                 WHERE capture_search MATCH ? AND c.requested_model = ?
                 ORDER BY c.created_at_unix_ms DESC",
            )?,
            (Some(_), None) => connection.prepare(
                "SELECT c.* FROM captures c
                 JOIN capture_search search ON search.capture_id = c.capture_id
                 WHERE capture_search MATCH ?
                 ORDER BY c.created_at_unix_ms DESC",
            )?,
            (None, Some(_)) => connection.prepare(
                "SELECT c.* FROM captures c
                 WHERE c.requested_model = ?
                 ORDER BY c.created_at_unix_ms DESC",
            )?,
            (None, None) => connection
                .prepare("SELECT c.* FROM captures c ORDER BY c.created_at_unix_ms DESC")?,
        };
        let mut rows = match (query, model) {
            (Some(query), Some(model)) => statement.query(params![query, model])?,
            (Some(query), None) => statement.query(params![query])?,
            (None, Some(model)) => statement.query(params![model])?,
            (None, None) => statement.query([])?,
        };
        let mut captures = Vec::new();
        while let Some(row) = rows.next()? {
            captures.push(capture_from_row(row)?);
        }
        Ok(captures)
    }

    /// Lists captures using the complete REST filter set. Filter values are
    /// bound parameters, and the result is always bounded.
    pub fn filtered_captures(&self, filters: &CaptureFilters<'_>) -> Result<Vec<CaptureSummary>> {
        if filters.query.is_some() && !self.full_text_search {
            anyhow::bail!("full-text preview search is disabled in this agent configuration");
        }
        let limit = filters.limit.clamp(1, 200);
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut sql = if filters.query.is_some() {
            "SELECT c.* FROM captures c JOIN capture_search search ON search.capture_id = c.capture_id WHERE capture_search MATCH ?".to_owned()
        } else {
            "SELECT c.* FROM captures c WHERE 1 = 1".to_owned()
        };
        let mut values = Vec::<rusqlite::types::Value>::new();
        if let Some(query) = filters.query {
            values.push(query.to_owned().into());
        }
        for (column, value) in [
            ("c.requested_model", filters.model),
            ("c.provider", filters.provider),
            ("c.capture_state", filters.capture_state),
            ("c.finalization_state", filters.finalization_state),
        ] {
            if let Some(value) = value {
                sql.push_str(" AND ");
                sql.push_str(column);
                sql.push_str(" = ?");
                values.push(value.to_owned().into());
            }
        }
        sql.push_str(" ORDER BY c.created_at_unix_ms DESC LIMIT ? OFFSET ?");
        values.push(i64::try_from(limit)?.into());
        values.push(i64::try_from(filters.offset)?.into());
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

    pub fn artifacts(&self, capture_id: &str) -> Result<Vec<Artifact>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection.prepare(
            "SELECT kind, path, size_bytes, sha256
             FROM artifacts WHERE capture_id = ? ORDER BY kind",
        )?;
        let rows = statement.query_map(params![capture_id], |row| {
            Ok(Artifact {
                kind: row.get(0)?,
                path: PathBuf::from(row.get::<_, String>(1)?),
                size_bytes: row.get::<_, i64>(2)?.try_into().map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?,
                sha256: row.get(3)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn counts(&self) -> Result<CatalogCounts> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        connection
            .query_row(
                "SELECT
                    COUNT(*),
                    SUM(capture_state = 'capturing'),
                    SUM(capture_state = 'pending'),
                    SUM(finalization_state = 'finalized'),
                    SUM(capture_state = 'failed' OR finalization_state = 'failed'),
                    (SELECT COUNT(*) FROM operations WHERE state IN ('queued', 'running'))
                 FROM captures",
                [],
                |row| {
                    Ok(CatalogCounts {
                        total_captures: row.get::<_, i64>(0)?.try_into().unwrap_or(0),
                        capturing: row
                            .get::<_, Option<i64>>(1)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        pending: row
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
                "SELECT 1 FROM captures WHERE capture_id = ? AND capture_state = 'pending'",
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
            "INSERT INTO operations (operation_id, kind, capture_id, state, attempt, created_at_unix_ms) VALUES (?, 'finalization', ?, 'queued', 0, ?)",
            params![operation_id, capture_id, i64::try_from(now)?],
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
            "UPDATE operations SET state = 'running', attempt = attempt + 1, started_at_unix_ms = ?, completed_at_unix_ms = NULL, failure_code = NULL WHERE operation_id = ? AND state = 'queued'",
            params![i64::try_from(now)?, operation_id],
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

    pub fn finish_operation(&self, operation_id: &str, now: u64) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE operations SET state = 'finalized', completed_at_unix_ms = ?, failure_code = NULL WHERE operation_id = ?",
            params![i64::try_from(now)?, operation_id],
        )?;
        transaction.execute(
            "UPDATE captures SET finalization_state = 'finalized' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        let capture_id: Option<String> = transaction.query_row(
            "SELECT capture_id FROM operations WHERE operation_id = ?",
            params![operation_id],
            |row| row.get(0),
        )?;
        insert_event(
            &transaction,
            now,
            "finalization_completed",
            capture_id.as_deref(),
            Some(operation_id),
            "success",
            "Finalization completed",
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn fail_operation(&self, operation_id: &str, now: u64, failure_code: &str) -> Result<()> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE operations SET state = 'failed', completed_at_unix_ms = ?, failure_code = ? WHERE operation_id = ?",
            params![i64::try_from(now)?, failure_code, operation_id],
        )?;
        transaction.execute(
            "UPDATE captures SET finalization_state = 'failed' WHERE capture_id = (SELECT capture_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
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
        Ok(())
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
            "UPDATE operations SET state = 'queued', started_at_unix_ms = NULL, completed_at_unix_ms = NULL, failure_code = NULL WHERE operation_id = ? AND state IN ('failed', 'interrupted')",
            params![operation_id],
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

    pub fn operations(&self, limit: usize) -> Result<Vec<Operation>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection
            .prepare("SELECT * FROM operations ORDER BY created_at_unix_ms DESC LIMIT ?")?;
        let rows = statement.query_map(
            params![i64::try_from(limit.clamp(1, 200))?],
            operation_from_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn events(&self, after: Option<u64>, limit: usize) -> Result<Vec<Event>> {
        let connection = self.connection.lock().expect("catalog mutex poisoned");
        let mut statement = connection
            .prepare("SELECT * FROM events WHERE event_id > ? ORDER BY event_id DESC LIMIT ?")?;
        let rows = statement.query_map(
            params![
                i64::try_from(after.unwrap_or(0))?,
                i64::try_from(limit.clamp(1, 200))?
            ],
            event_from_row,
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

fn migrate(connection: &mut Connection) -> Result<()> {
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
    if version == 0 {
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
    if version < 2 {
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
    Ok(())
}

fn artifact_digest(path: &Path) -> Result<(u64, String)> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading artifact metadata {}", path.display()))?;
    if metadata.is_file() {
        let bytes =
            fs::read(path).with_context(|| format!("reading artifact {}", path.display()))?;
        return Ok((metadata.len(), sha256_hex(&bytes)));
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "artifact {} is neither a file nor directory",
            path.display()
        );
    }

    let mut files = Vec::new();
    collect_files(path, path, &mut files)?;
    files.sort();
    let mut canonical = Vec::new();
    let mut size_bytes = 0_u64;
    for file in files {
        let relative = file
            .strip_prefix(path)
            .expect("artifact file remains below its root")
            .to_string_lossy();
        let bytes =
            fs::read(&file).with_context(|| format!("reading artifact file {}", file.display()))?;
        size_bytes = size_bytes
            .checked_add(u64::try_from(bytes.len())?)
            .ok_or_else(|| anyhow::anyhow!("artifact size overflow"))?;
        canonical.extend_from_slice(relative.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(&bytes);
    }
    Ok((size_bytes, sha256_hex(&canonical)))
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(directory).with_context(|| format!("reading {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_file() {
            files.push(path);
        } else if kind.is_dir() {
            collect_files(root, &path, files)?;
        } else if path != root {
            anyhow::bail!(
                "artifact contains unsupported filesystem entry {}",
                path.display()
            );
        }
    }
    Ok(())
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

    #[test]
    fn catalog_lists_and_searches_plain_text_previews() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("cap-1.llmbundle");
        fs::write(&bundle, b"ciphertext").unwrap();
        let catalog = Catalog::open(&directory.path().join("catalog.db"), true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();
        catalog
            .complete_capture(
                "cap-1",
                2,
                1,
                200,
                24,
                Some("gpt-5"),
                "Quarterly pricing is available.",
                false,
                &bundle,
            )
            .unwrap();

        let matches = catalog.list_captures(Some("quarterly"), None).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].requested_model.as_deref(), Some("gpt-5"));
        assert_eq!(matches[0].capture_state, "pending");
        assert!(matches[0].output_preview.contains("pricing"));
        assert_eq!(catalog.artifacts("cap-1").unwrap().len(), 1);
    }

    #[test]
    fn failed_captures_have_only_a_safe_failure_code() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(&directory.path().join("catalog.db"), true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();
        catalog
            .mark_capture_failed("cap-1", "notary_error")
            .unwrap();
        let capture = catalog.capture("cap-1").unwrap().unwrap();
        assert_eq!(capture.capture_state, "failed");
    }

    #[test]
    fn reconciliation_makes_a_saved_bundle_searchable_after_an_interruption() {
        let directory = tempfile::tempdir().unwrap();
        let bundle_dir = directory.path().join("bundles");
        fs::create_dir_all(&bundle_dir).unwrap();
        let bundle = bundle_dir.join("cap-1.llmbundle");
        fs::write(&bundle, b"ciphertext").unwrap();
        let catalog = Catalog::open(&directory.path().join("catalog.db"), true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();

        assert_eq!(
            catalog.reconcile_incomplete_captures(&bundle_dir).unwrap(),
            RecoverySummary {
                recovered_bundles: 1,
                interrupted_captures: 0,
            }
        );
        let capture = catalog.capture("cap-1").unwrap().unwrap();
        assert_eq!(capture.capture_state, "pending");
        assert_eq!(catalog.artifacts("cap-1").unwrap().len(), 1);
        assert_eq!(
            catalog
                .list_captures(Some("quarterly"), None)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn reconciliation_marks_missing_bundles_interrupted() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(&directory.path().join("catalog.db"), true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();

        assert_eq!(
            catalog
                .reconcile_incomplete_captures(&directory.path().join("bundles"))
                .unwrap(),
            RecoverySummary {
                recovered_bundles: 0,
                interrupted_captures: 1,
            }
        );
        assert_eq!(
            catalog.capture("cap-1").unwrap().unwrap().capture_state,
            "failed"
        );
    }

    #[test]
    fn finalization_operations_are_deduplicated_recovered_and_retryable() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("cap-1.llmbundle");
        fs::write(&bundle, b"encrypted bundle fixture").unwrap();
        let catalog = Catalog::open(&directory.path().join("catalog.db"), true).unwrap();
        catalog.begin_capture(&new_capture("cap-1")).unwrap();
        catalog
            .complete_capture("cap-1", 2, 1, 200, 10, None, "done", false, &bundle)
            .unwrap();

        let (queued, duplicate) = catalog.enqueue_finalization("cap-1", 3).unwrap().unwrap();
        assert!(!duplicate);
        let (same, duplicate) = catalog.enqueue_finalization("cap-1", 4).unwrap().unwrap();
        assert!(duplicate);
        assert_eq!(same.operation_id, queued.operation_id);

        let running = catalog.claim_next_finalization(5).unwrap().unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(running.attempt, 1);
        assert_eq!(catalog.recover_operations(6).unwrap(), 1);
        assert_eq!(
            catalog
                .operation(&running.operation_id)
                .unwrap()
                .unwrap()
                .state,
            "interrupted"
        );
        let (same, duplicate) = catalog.enqueue_finalization("cap-1", 7).unwrap().unwrap();
        assert!(duplicate);
        assert_eq!(same.operation_id, running.operation_id);
        assert_eq!(same.state, "interrupted");
        let retried = catalog
            .retry_operation(&running.operation_id, 8)
            .unwrap()
            .unwrap();
        assert_eq!(retried.state, "queued");
        assert_eq!(catalog.events(None, 20).unwrap().len(), 4);
    }

    #[test]
    fn durable_operation_migration_is_atomic_and_resumable() {
        let mut connection = Connection::open_in_memory().unwrap();
        migrate(&mut connection).unwrap();
        connection
            .execute("DELETE FROM schema_migrations WHERE version = 2", [])
            .unwrap();
        connection
            .execute_batch(
                "DROP TABLE events;
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
            2
        );
    }
}
