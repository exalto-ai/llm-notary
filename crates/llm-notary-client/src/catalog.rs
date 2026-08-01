//! SQLite-backed local capture inventory and preview search.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::sha256_hex;

const CATALOG_SCHEMA_VERSION: i64 = 1;

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
}

/// One stored local artifact belonging to a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub kind: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
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
        let connection = Connection::open(path)
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
        migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            full_text_search,
        })
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
}

fn migrate(connection: &Connection) -> Result<()> {
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
        connection.execute_batch(
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
        connection.execute(
            "INSERT INTO schema_migrations(version) VALUES (?)",
            params![CATALOG_SCHEMA_VERSION],
        )?;
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
    })
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
}
