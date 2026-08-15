//! SQLx PostgreSQL implementation of the local daemon metadata contract.
//!
//! Runtime construction is deliberately read-only with respect to schema.
//! Operators apply the daemon-owned migration journal through
//! [`migrate_database`] before starting a daemon that uses this adapter.

use std::time::Duration;

use anyhow::{Context as _, anyhow, ensure};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use sqlx::{
    Connection as _, PgConnection, PgPool, Postgres, QueryBuilder, Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
};

use crate::{
    FinalizationPhase, FinalizationProofProgress,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord},
    config::PostgresSslMode,
    metadata::{
        CaptureCompletion, CaptureFilters, CaptureSummary, Event, EventFilters, EventSnapshot,
        IncompleteCapture, MetadataCounts, NewCapture, Operation, OperationAttempt,
        OperationFilters, TerminalOperationResult, capture_search_parts,
    },
    metadata_store::{MetadataResult, MetadataStore, MetadataStoreError},
};

const SCHEMA: &str = "llm_notary_daemon";
const JOURNAL: &str = "llm_notary_daemon.schema_migrations";
const MIGRATION_LOCK_NAMESPACE: &str = "llm-notary/daemon-postgres-migrations/v1";
const LATEST_SCHEMA_VERSION: i64 = 1;
const INITIAL_MIGRATION: &str = include_str!("../migrations-postgres-daemon/0001_initial.sql");

/// A pooled PostgreSQL metadata backend whose schema has already been migrated.
#[derive(Clone)]
pub(crate) struct PostgresMetadataStore {
    pool: PgPool,
    full_text_search: bool,
}

impl PostgresMetadataStore {
    /// Opens a runtime pool and verifies, without mutating, the exact daemon schema version.
    pub(crate) async fn connect(
        database_url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        acquire_timeout: Duration,
        ssl_mode: PostgresSslMode,
        full_text_search: bool,
    ) -> MetadataResult<Self> {
        if max_connections == 0 {
            return Err(MetadataStoreError::InvalidInput(
                "invalid_postgres_pool_size",
            ));
        }
        let options = database_url
            .parse::<PgConnectOptions>()
            .map_err(|error| db(anyhow!(error).context("parsing daemon PostgreSQL URL")))?
            .ssl_mode(pg_ssl_mode(ssl_mode));
        tokio::time::timeout(connect_timeout, async move {
            let pool = PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(acquire_timeout)
                .connect_with(options)
                .await
                .map_err(|error| db(anyhow!(error).context("opening daemon PostgreSQL pool")))?;
            Self::from_pool(pool, full_text_search).await
        })
        .await
        .map_err(|_| {
            db(anyhow!(
                "opening and validating daemon PostgreSQL timed out"
            ))
        })?
    }

    /// Wraps an existing pool after verifying the daemon-owned migration journal.
    async fn from_pool(pool: PgPool, full_text_search: bool) -> MetadataResult<Self> {
        require_current_schema(&pool).await?;
        Ok(Self {
            pool,
            full_text_search,
        })
    }
}

/// Applies daemon PostgreSQL migrations with a dedicated schema, journal, and advisory lock.
///
/// This one-shot API expects a direct connection URL and is never called by runtime
/// construction. The lock timeout bounds coordination with another daemon migrator.
pub(crate) async fn migrate_database(
    database_url: &str,
    ssl_mode: PostgresSslMode,
    connect_timeout: Duration,
    lock_timeout: Duration,
) -> anyhow::Result<()> {
    ensure!(
        !connect_timeout.is_zero(),
        "daemon migration connect timeout must be non-zero"
    );
    ensure!(
        !lock_timeout.is_zero(),
        "daemon migration lock timeout must be non-zero"
    );
    ensure!(
        lock_timeout.as_millis() <= i64::MAX as u128,
        "daemon migration lock timeout is out of range"
    );
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("daemon migration URL must be PostgreSQL")?
        .ssl_mode(pg_ssl_mode(ssl_mode));
    let mut connection =
        tokio::time::timeout(connect_timeout, PgConnection::connect_with(&options))
            .await
            .context("opening direct daemon migration connection timed out")?
            .context("opening direct daemon migration connection")?;
    let timeout_ms = lock_timeout.as_millis().to_string();
    sqlx::query("SELECT set_config('lock_timeout', $1, false)")
        .bind(format!("{timeout_ms}ms"))
        .execute(&mut connection)
        .await
        .context("setting daemon migration lock timeout")?;

    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(MIGRATION_LOCK_NAMESPACE)
        .execute(&mut connection)
        .await
        .context("acquiring daemon migration advisory lock")?;
    let mut transaction = connection
        .begin()
        .await
        .context("starting daemon migration transaction")?;
    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(&mut *transaction)
        .await
        .context("reading daemon migration role")?;
    let schema_owner: Option<String> =
        sqlx::query_scalar("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = $1")
            .bind(SCHEMA)
            .fetch_optional(&mut *transaction)
            .await
            .context("checking daemon schema ownership")?;
    if let Some(owner) = schema_owner {
        ensure!(
            owner == current_user,
            "daemon metadata schema is owned by a different PostgreSQL role"
        );
    } else {
        sqlx::query("CREATE SCHEMA llm_notary_daemon")
            .execute(&mut *transaction)
            .await
            .context("creating daemon metadata schema")?;
    }
    sqlx::query("REVOKE ALL ON SCHEMA llm_notary_daemon FROM PUBLIC")
        .execute(&mut *transaction)
        .await
        .context("restricting daemon metadata schema")?;
    sqlx::raw_sql(&format!(
        "CREATE TABLE IF NOT EXISTS {JOURNAL} (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );"
    ))
    .execute(&mut *transaction)
    .await
    .context("creating daemon migration journal")?;

    let rows = sqlx::query(&format!(
        "SELECT version, description, checksum FROM {JOURNAL} ORDER BY version"
    ))
    .fetch_all(&mut *transaction)
    .await
    .context("reading daemon migration journal")?;
    ensure!(
        rows.len() <= usize::try_from(LATEST_SCHEMA_VERSION).unwrap_or(0),
        "daemon PostgreSQL schema is newer than this binary"
    );
    let checksum = hex::encode(Sha256::digest(INITIAL_MIGRATION.as_bytes()));
    if let Some(row) = rows.first() {
        ensure!(
            row.try_get::<i64, _>("version")? == 1,
            "daemon migration journal has a gap"
        );
        ensure!(
            row.try_get::<String, _>("description")? == "initial daemon metadata schema"
                && row.try_get::<String, _>("checksum")? == checksum,
            "daemon migration 1 differs from the installed migration"
        );
    } else {
        sqlx::raw_sql(INITIAL_MIGRATION)
            .execute(&mut *transaction)
            .await
            .context("applying daemon PostgreSQL migration 1")?;
        sqlx::query(&format!(
            "INSERT INTO {JOURNAL} (version, description, checksum) VALUES (1, $1, $2)"
        ))
        .bind("initial daemon metadata schema")
        .bind(&checksum)
        .execute(&mut *transaction)
        .await
        .context("recording daemon PostgreSQL migration 1")?;
    }
    transaction
        .commit()
        .await
        .context("committing daemon PostgreSQL migrations")?;
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(MIGRATION_LOCK_NAMESPACE)
        .fetch_one(&mut connection)
        .await
        .context("releasing daemon migration advisory lock")?;
    ensure!(unlocked, "daemon migration advisory lock was not held");
    Ok(())
}

fn pg_ssl_mode(mode: PostgresSslMode) -> sqlx::postgres::PgSslMode {
    match mode {
        PostgresSslMode::Disable => sqlx::postgres::PgSslMode::Disable,
        PostgresSslMode::Require => sqlx::postgres::PgSslMode::Require,
        PostgresSslMode::VerifyFull => sqlx::postgres::PgSslMode::VerifyFull,
    }
}

async fn require_current_schema(pool: &PgPool) -> MetadataResult<()> {
    let journal_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('llm_notary_daemon.schema_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(|error| db(anyhow!(error).context("checking daemon migration journal")))?;
    if !journal_exists {
        return Err(db(anyhow!(
            "daemon PostgreSQL schema is not migrated; run the daemon migrator"
        )));
    }
    let rows = sqlx::query(&format!(
        "SELECT version, description, checksum FROM {JOURNAL} ORDER BY version"
    ))
    .fetch_all(pool)
    .await
    .map_err(|error| db(anyhow!(error).context("reading daemon schema version")))?;
    let checksum = hex::encode(Sha256::digest(INITIAL_MIGRATION.as_bytes()));
    let current = rows.first();
    let exact = rows.len() == 1
        && current.is_some_and(|row| {
            row.try_get::<i64, _>("version").ok() == Some(LATEST_SCHEMA_VERSION)
                && row.try_get::<String, _>("description").ok().as_deref()
                    == Some("initial daemon metadata schema")
                && row.try_get::<String, _>("checksum").ok().as_deref() == Some(checksum.as_str())
        });
    if !exact {
        return Err(db(anyhow!(
            "daemon PostgreSQL schema journal does not exactly match version {LATEST_SCHEMA_VERSION}"
        )));
    }
    sqlx::query("SELECT capture_id FROM llm_notary_daemon.captures LIMIT 0")
        .execute(pool)
        .await
        .map_err(|error| db(anyhow!(error).context("probing daemon metadata tables")))?;
    Ok(())
}

fn db(error: anyhow::Error) -> MetadataStoreError {
    MetadataStoreError::Backend(error)
}

fn invalid_i64(value: u64, code: &'static str) -> MetadataResult<i64> {
    i64::try_from(value).map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_limit(limit: usize) -> MetadataResult<i64> {
    if !(1..=201).contains(&limit) {
        return Err(MetadataStoreError::InvalidInput("invalid_page_limit"));
    }
    i64::try_from(limit).map_err(|_| MetadataStoreError::InvalidInput("invalid_page_limit"))
}

fn validate_completion(completion: &CaptureCompletion) -> MetadataResult<()> {
    invalid_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?;
    invalid_i64(completion.duration_ms, "duration_out_of_range")?;
    invalid_i64(completion.response_bytes, "response_bytes_out_of_range")?;
    Ok(())
}

fn validate_artifact(artifact: &ArtifactRecord) -> MetadataResult<()> {
    artifact
        .validate()
        .map_err(|_| MetadataStoreError::InvalidInput("invalid_artifact_record"))?;
    invalid_i64(artifact.size_bytes, "artifact_size_out_of_range")?;
    Ok(())
}

fn validate_proof(progress: FinalizationProofProgress) -> MetadataResult<()> {
    for value in [
        progress.bytes_completed,
        progress.bytes_total,
        progress.commitments_completed,
        progress.commitments_total,
    ] {
        invalid_i64(value, "proof_progress_out_of_range")?;
    }
    if progress.bytes_completed > progress.bytes_total
        || progress.commitments_completed > progress.commitments_total
    {
        return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
    }
    Ok(())
}

fn require_artifact(
    artifact: &ArtifactRecord,
    capture_id: &str,
    kind: ArtifactKind,
) -> MetadataResult<()> {
    if artifact.key.capture_id() != capture_id || artifact.key.kind() != kind {
        return Err(db(anyhow!("artifact does not match metadata transition")));
    }
    Ok(())
}

fn validate_operation_state(state: &str) -> MetadataResult<()> {
    if matches!(
        state,
        "queued" | "running" | "interrupted" | "failed" | "finalized"
    ) {
        Ok(())
    } else {
        Err(db(anyhow!("operation has an invalid persisted state")))
    }
}

fn row_u64(row: &PgRow, name: &str) -> anyhow::Result<u64> {
    Ok(row.try_get::<i64, _>(name)?.try_into()?)
}

fn row_optional_u64(row: &PgRow, name: &str) -> anyhow::Result<Option<u64>> {
    row.try_get::<Option<i64>, _>(name)?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
}

fn capture_from_row(row: &PgRow) -> anyhow::Result<CaptureSummary> {
    Ok(CaptureSummary {
        capture_id: row.try_get("capture_id")?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        provider: row.try_get("provider")?,
        operation: row.try_get("operation")?,
        requested_model: row.try_get("requested_model")?,
        response_model: row.try_get("response_model")?,
        http_status: row
            .try_get::<Option<i32>, _>("http_status")?
            .map(TryInto::try_into)
            .transpose()?,
        streaming: row.try_get("streaming")?,
        request_bytes: row_u64(row, "request_bytes")?,
        response_bytes: row_optional_u64(row, "response_bytes")?,
        duration_ms: row_optional_u64(row, "duration_ms")?,
        capture_state: row.try_get("capture_state")?,
        finalization_state: row.try_get("finalization_state")?,
        prompt_preview: row.try_get("prompt_preview")?,
        prompt_preview_truncated: row.try_get("prompt_preview_truncated")?,
        output_preview: row.try_get("output_preview")?,
        output_preview_truncated: row.try_get("output_preview_truncated")?,
        failure_code: row.try_get("failure_code")?,
    })
}

fn operation_from_row(row: &PgRow) -> anyhow::Result<Operation> {
    Ok(Operation {
        operation_id: row.try_get("operation_id")?,
        kind: row.try_get("kind")?,
        capture_id: row.try_get("capture_id")?,
        state: row.try_get("state")?,
        attempt: row.try_get::<i32, _>("attempt")?.try_into()?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        started_at_unix_ms: row_optional_u64(row, "started_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        failure_code: row.try_get("failure_code")?,
        progress_phase: row.try_get("progress_phase")?,
        progress_updated_at_unix_ms: row_u64(row, "progress_updated_at_unix_ms")?,
        proof_bytes_completed: row_u64(row, "proof_bytes_completed")?,
        proof_bytes_total: row_u64(row, "proof_bytes_total")?,
        proof_commitments_completed: row_u64(row, "proof_commitments_completed")?,
        proof_commitments_total: row_u64(row, "proof_commitments_total")?,
    })
}

fn attempt_from_row(row: &PgRow) -> anyhow::Result<OperationAttempt> {
    Ok(OperationAttempt {
        attempt: row.try_get::<i32, _>("attempt")?.try_into()?,
        state: row.try_get("state")?,
        started_at_unix_ms: row_u64(row, "started_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        failure_code: row.try_get("failure_code")?,
    })
}

fn event_from_row(row: &PgRow) -> anyhow::Result<Event> {
    Ok(Event {
        event_id: row_u64(row, "event_id")?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        event_type: row.try_get("event_type")?,
        capture_id: row.try_get("capture_id")?,
        operation_id: row.try_get("operation_id")?,
        severity: row.try_get("severity")?,
        message: row.try_get("message")?,
    })
}

async fn insert_event(
    connection: &mut PgConnection,
    now: i64,
    event_type: &str,
    capture_id: Option<&str>,
    operation_id: Option<&str>,
    severity: &str,
    message: &str,
) -> MetadataResult<()> {
    sqlx::query(
        "INSERT INTO llm_notary_daemon.events
         (created_at_unix_ms, event_type, capture_id, operation_id, severity, message)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(now)
    .bind(event_type)
    .bind(capture_id)
    .bind(operation_id)
    .bind(severity)
    .bind(message)
    .execute(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("inserting daemon event")))?;
    Ok(())
}

async fn artifact_exists_exact(
    connection: &mut PgConnection,
    artifact: &ArtifactRecord,
) -> MetadataResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM llm_notary_daemon.artifacts
            WHERE capture_id = $1 AND kind = $2 AND locator = $3
              AND size_bytes = $4 AND sha256 = $5 AND state = 'available'
         )",
    )
    .bind(artifact.key.capture_id())
    .bind(artifact.key.kind().as_str())
    .bind(artifact.locator.as_stored())
    .bind(invalid_i64(
        artifact.size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&artifact.sha256)
    .fetch_one(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("checking immutable artifact metadata")))
}

async fn insert_artifact(
    connection: &mut PgConnection,
    artifact: &ArtifactRecord,
) -> MetadataResult<()> {
    let changed = sqlx::query(
        "INSERT INTO llm_notary_daemon.artifacts
         (capture_id, kind, locator, size_bytes, sha256, state)
         VALUES ($1, $2, $3, $4, $5, 'available')
         ON CONFLICT (capture_id, kind) DO NOTHING",
    )
    .bind(artifact.key.capture_id())
    .bind(artifact.key.kind().as_str())
    .bind(artifact.locator.as_stored())
    .bind(invalid_i64(
        artifact.size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&artifact.sha256)
    .execute(&mut *connection)
    .await
    .map_err(|error| db(anyhow!(error).context("inserting artifact metadata")))?
    .rows_affected();
    if changed != 1 && !artifact_exists_exact(connection, artifact).await? {
        return Err(db(anyhow!(
            "artifact metadata conflicts with an immutable record"
        )));
    }
    Ok(())
}

async fn completion_matches(
    connection: &mut PgConnection,
    completion: &CaptureCompletion,
) -> MetadataResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM llm_notary_daemon.captures
            WHERE capture_id = $1 AND completed_at_unix_ms = $2 AND duration_ms = $3
              AND http_status = $4 AND response_bytes = $5
              AND response_model IS NOT DISTINCT FROM $6
              AND output_preview = $7 AND output_preview_truncated = $8
         )",
    )
    .bind(&completion.capture_id)
    .bind(invalid_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?)
    .bind(invalid_i64(
        completion.duration_ms,
        "duration_out_of_range",
    )?)
    .bind(i32::from(completion.http_status))
    .bind(invalid_i64(
        completion.response_bytes,
        "response_bytes_out_of_range",
    )?)
    .bind(&completion.response_model)
    .bind(&completion.output_preview)
    .bind(completion.output_preview_truncated)
    .fetch_one(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("checking capture completion metadata")))
}

#[async_trait]
impl MetadataStore for PostgresMetadataStore {
    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    async fn readiness(&self) -> MetadataResult<()> {
        require_current_schema(&self.pool).await
    }

    async fn begin_capture(&self, capture: NewCapture) -> MetadataResult<()> {
        let created_at = invalid_i64(
            capture.created_at_unix_ms,
            "capture_created_at_out_of_range",
        )?;
        let request_bytes = i64::try_from(capture.request_bytes)
            .map_err(|_| MetadataStoreError::InvalidInput("request_bytes_out_of_range"))?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.captures (
                capture_id, created_at_unix_ms, provider, operation, requested_model,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, capture_state, finalization_state
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'capturing', 'not_requested')",
        )
        .bind(capture.capture_id)
        .bind(created_at)
        .bind(capture.provider)
        .bind(capture.operation)
        .bind(capture.requested_model)
        .bind(capture.streaming)
        .bind(request_bytes)
        .bind(capture.prompt_preview)
        .bind(capture.prompt_preview_truncated)
        .bind(capture.config_fingerprint)
        .execute(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("beginning capture metadata")))?;
        Ok(())
    }

    async fn mark_capture_failed(
        &self,
        capture_id: &str,
        failure_code: &str,
    ) -> MetadataResult<()> {
        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                db(anyhow!(error).context("starting capture failure transaction"))
            })?;
        let current = sqlx::query(
            "SELECT capture_state, failure_code FROM llm_notary_daemon.captures
             WHERE capture_id = $1 FOR UPDATE",
        )
        .bind(capture_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking capture for failure")))?
        .ok_or_else(|| db(anyhow!("capture does not exist")))?;
        let state: String = current
            .try_get("capture_state")
            .map_err(|error| db(anyhow!(error)))?;
        let current_code: Option<String> = current
            .try_get("failure_code")
            .map_err(|error| db(anyhow!(error)))?;
        if state == "failed" && current_code.as_deref() == Some(failure_code) {
            return Ok(());
        }
        if state != "capturing" {
            return Err(db(anyhow!("capture is not active")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures
             SET capture_state = 'failed', failure_code = $2
             WHERE capture_id = $1 AND capture_state = 'capturing'",
        )
        .bind(capture_id)
        .bind(failure_code)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("marking capture failed")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("active capture transition was lost")));
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing capture failure")))
    }

    async fn prepare_capture_completion(
        &self,
        completion: CaptureCompletion,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        let mut transaction = self.pool.begin().await.map_err(|error| {
            db(anyhow!(error).context("starting capture completion preparation"))
        })?;
        let current = sqlx::query(
            "SELECT capture_state, completed_at_unix_ms IS NOT NULL AS prepared
             FROM llm_notary_daemon.captures WHERE capture_id = $1 FOR UPDATE",
        )
        .bind(&completion.capture_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking capture completion")))?
        .ok_or_else(|| db(anyhow!("capture does not exist")))?;
        let state: String = current.try_get("capture_state").map_err(|e| db(e.into()))?;
        let prepared: bool = current.try_get("prepared").map_err(|e| db(e.into()))?;
        if state != "capturing" && state != "captured" {
            return Err(db(anyhow!("capture cannot accept completion metadata")));
        }
        if prepared {
            if !completion_matches(&mut transaction, &completion).await? {
                return Err(db(anyhow!(
                    "capture completion conflicts with persisted metadata"
                )));
            }
            return Ok(());
        }
        if state != "capturing" {
            return Err(db(anyhow!("capture is not active")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET
                completed_at_unix_ms = $2, duration_ms = $3, http_status = $4,
                response_bytes = $5, response_model = $6, output_preview = $7,
                output_preview_truncated = $8
             WHERE capture_id = $1 AND capture_state = 'capturing'
               AND completed_at_unix_ms IS NULL",
        )
        .bind(&completion.capture_id)
        .bind(invalid_i64(
            completion.completed_at_unix_ms,
            "capture_completed_at_out_of_range",
        )?)
        .bind(invalid_i64(
            completion.duration_ms,
            "duration_out_of_range",
        )?)
        .bind(i32::from(completion.http_status))
        .bind(invalid_i64(
            completion.response_bytes,
            "response_bytes_out_of_range",
        )?)
        .bind(&completion.response_model)
        .bind(&completion.output_preview)
        .bind(completion.output_preview_truncated)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("preparing capture completion")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("capture completion staging was lost")));
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing capture preparation")))
    }

    async fn complete_capture(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        validate_artifact(&artifact)?;
        require_artifact(
            &artifact,
            &completion.capture_id,
            ArtifactKind::DeferredBundle,
        )?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting capture completion")))?;
        let current = sqlx::query(
            "SELECT capture_state, completed_at_unix_ms IS NOT NULL AS prepared
             FROM llm_notary_daemon.captures WHERE capture_id = $1 FOR UPDATE",
        )
        .bind(&completion.capture_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking capture completion")))?
        .ok_or_else(|| db(anyhow!("capture does not exist")))?;
        let state: String = current.try_get("capture_state").map_err(|e| db(e.into()))?;
        let prepared: bool = current.try_get("prepared").map_err(|e| db(e.into()))?;
        if state == "captured" {
            if completion_matches(&mut transaction, &completion).await?
                && artifact_exists_exact(&mut transaction, &artifact).await?
            {
                return Ok(());
            }
            return Err(db(anyhow!(
                "capture completion conflicts with persisted metadata"
            )));
        }
        if state != "capturing" {
            return Err(db(anyhow!("capture is not active")));
        }
        if prepared && !completion_matches(&mut transaction, &completion).await? {
            return Err(db(anyhow!(
                "capture completion conflicts with staged metadata"
            )));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET
                completed_at_unix_ms = $2, duration_ms = $3, http_status = $4,
                response_bytes = $5, response_model = $6, output_preview = $7,
                output_preview_truncated = $8, capture_state = 'captured', failure_code = NULL
             WHERE capture_id = $1 AND capture_state = 'capturing'",
        )
        .bind(&completion.capture_id)
        .bind(invalid_i64(
            completion.completed_at_unix_ms,
            "capture_completed_at_out_of_range",
        )?)
        .bind(invalid_i64(
            completion.duration_ms,
            "duration_out_of_range",
        )?)
        .bind(i32::from(completion.http_status))
        .bind(invalid_i64(
            completion.response_bytes,
            "response_bytes_out_of_range",
        )?)
        .bind(&completion.response_model)
        .bind(&completion.output_preview)
        .bind(completion.output_preview_truncated)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("completing capture")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("active capture transition was lost")));
        }
        insert_artifact(&mut transaction, &artifact).await?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.capture_search
                (capture_id, prompt_document, output_document)
             SELECT capture_id, to_tsvector('simple', prompt_preview),
                to_tsvector('simple', output_preview)
             FROM llm_notary_daemon.captures WHERE capture_id = $1
             ON CONFLICT (capture_id) DO UPDATE SET
                prompt_document = excluded.prompt_document,
                output_document = excluded.output_document",
        )
        .bind(&completion.capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("indexing capture preview")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing capture completion")))
    }

    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>> {
        let rows = sqlx::query(
            "SELECT capture_id, completed_at_unix_ms, duration_ms, http_status,
                    response_bytes, response_model, output_preview,
                    output_preview_truncated
             FROM llm_notary_daemon.captures
             WHERE capture_state = 'capturing' ORDER BY capture_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("listing active captures")))?;
        rows.iter()
            .map(|row| -> anyhow::Result<_> {
                let capture_id: String = row.try_get("capture_id")?;
                let completed_at: Option<i64> = row.try_get("completed_at_unix_ms")?;
                let duration: Option<i64> = row.try_get("duration_ms")?;
                let http_status: Option<i32> = row.try_get("http_status")?;
                let response_bytes: Option<i64> = row.try_get("response_bytes")?;
                let completion = match (completed_at, duration, http_status, response_bytes) {
                    (
                        Some(completed_at),
                        Some(duration),
                        Some(http_status),
                        Some(response_bytes),
                    ) => Some(CaptureCompletion {
                        capture_id: capture_id.clone(),
                        completed_at_unix_ms: completed_at.try_into()?,
                        duration_ms: duration.try_into()?,
                        http_status: http_status.try_into()?,
                        response_bytes: response_bytes.try_into()?,
                        response_model: row.try_get("response_model")?,
                        output_preview: row.try_get("output_preview")?,
                        output_preview_truncated: row.try_get("output_preview_truncated")?,
                    }),
                    _ => None,
                };
                Ok(IncompleteCapture {
                    capture_id,
                    completion,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn recover_capture(
        &self,
        capture_id: &str,
        artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        validate_artifact(&artifact)?;
        require_artifact(&artifact, capture_id, ArtifactKind::DeferredBundle)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting capture recovery")))?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures
             SET capture_state = 'captured', failure_code = NULL
             WHERE capture_id = $1 AND capture_state = 'capturing'",
        )
        .bind(capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("recovering capture")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("capture is not recoverable")));
        }
        insert_artifact(&mut transaction, &artifact).await?;
        sqlx::query("DELETE FROM llm_notary_daemon.capture_search WHERE capture_id = $1")
            .bind(capture_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("clearing recovered capture search")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing capture recovery")))
    }

    async fn captures(&self, filters: CaptureFilters) -> MetadataResult<Vec<CaptureSummary>> {
        let limit = validate_limit(filters.limit)?;
        if let Some(value) = filters.created_after_unix_ms {
            invalid_i64(value, "created_after_out_of_range")?;
        }
        if let Some(cursor) = &filters.cursor {
            invalid_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        let search = filters
            .query
            .as_deref()
            .filter(|query| !query.is_empty())
            .map(|query| {
                if !self.full_text_search {
                    return Err(MetadataStoreError::InvalidInput("preview_search_disabled"));
                }
                Ok(capture_search_parts(query))
            })
            .transpose()?
            .flatten();
        if filters.query.is_some() && search.is_none() {
            return Ok(Vec::new());
        }

        let mut query =
            QueryBuilder::<Postgres>::new("SELECT c.* FROM llm_notary_daemon.captures c ");
        if search.is_some() {
            query.push(
                "JOIN llm_notary_daemon.capture_search search ON search.capture_id = c.capture_id ",
            );
        }
        query.push("WHERE TRUE");
        if let Some(parts) = search.as_deref() {
            for part in parts {
                let expression = part.expression();
                query
                    .push(" AND (search.prompt_document @@ websearch_to_tsquery('simple', ")
                    .push_bind(expression.clone())
                    .push(") OR search.output_document @@ websearch_to_tsquery('simple', ")
                    .push_bind(expression)
                    .push("))");
            }
        }
        for (column, value) in [
            ("requested_model", filters.model.as_deref()),
            ("provider", filters.provider.as_deref()),
            ("capture_state", filters.capture_state.as_deref()),
            ("finalization_state", filters.finalization_state.as_deref()),
        ] {
            if let Some(value) = value {
                query
                    .push(" AND c.")
                    .push(column)
                    .push(" = ")
                    .push_bind(value);
            }
        }
        if let Some(streaming) = filters.streaming {
            query.push(" AND c.streaming = ").push_bind(streaming);
        }
        if let Some(created_after) = filters.created_after_unix_ms {
            query
                .push(" AND c.created_at_unix_ms >= ")
                .push_bind(i64::try_from(created_after).expect("validated timestamp"));
        }
        if let Some(cursor) = &filters.cursor {
            let created = i64::try_from(cursor.created_at_unix_ms).expect("validated cursor");
            query
                .push(" AND (c.created_at_unix_ms < ")
                .push_bind(created)
                .push(" OR (c.created_at_unix_ms = ")
                .push_bind(created)
                .push(" AND c.capture_id < ")
                .push_bind(&cursor.capture_id)
                .push("))");
        }
        query
            .push(" ORDER BY c.created_at_unix_ms DESC, c.capture_id DESC LIMIT ")
            .push_bind(limit);
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("querying captures")))?
            .iter()
            .map(capture_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn capture(&self, capture_id: &str) -> MetadataResult<Option<CaptureSummary>> {
        sqlx::query("SELECT * FROM llm_notary_daemon.captures WHERE capture_id = $1")
            .bind(capture_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("querying capture")))?
            .as_ref()
            .map(capture_from_row)
            .transpose()
            .map_err(db)
    }

    async fn artifacts(&self, capture_id: &str) -> MetadataResult<Vec<ArtifactRecord>> {
        let rows = sqlx::query(
            "SELECT capture_id, kind, locator, size_bytes, sha256
             FROM llm_notary_daemon.artifacts
             WHERE capture_id = $1 AND state = 'available' ORDER BY kind",
        )
        .bind(capture_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("querying artifact metadata")))?;
        rows.iter()
            .map(|row| -> anyhow::Result<_> {
                let capture_id: String = row.try_get("capture_id")?;
                let kind: String = row.try_get("kind")?;
                let locator: String = row.try_get("locator")?;
                let size_bytes: i64 = row.try_get("size_bytes")?;
                let sha256: String = row.try_get("sha256")?;
                ArtifactRecord::new(
                    ArtifactKey::new(&capture_id, ArtifactKind::try_from(kind.as_str())?)?,
                    ArtifactLocator::from_stored(locator)?,
                    size_bytes.try_into()?,
                    sha256,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn counts(&self) -> MetadataResult<MetadataCounts> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE capture_state = 'capturing') AS capturing,
                COUNT(*) FILTER (WHERE capture_state = 'captured'
                    AND finalization_state = 'not_requested' AND http_status BETWEEN 200 AND 299)
                    AS ready,
                COUNT(*) FILTER (WHERE finalization_state = 'finalized') AS finalized,
                COUNT(*) FILTER (WHERE capture_state = 'failed' OR finalization_state = 'failed')
                    AS failed,
                (SELECT COUNT(*) FROM llm_notary_daemon.operations
                 WHERE state IN ('queued', 'running')) AS active
             FROM llm_notary_daemon.captures",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("counting daemon metadata")))?;
        let value = |name| -> anyhow::Result<u64> { Ok(row.try_get::<i64, _>(name)?.try_into()?) };
        Ok(MetadataCounts {
            total_captures: value("total").map_err(db)?,
            capturing: value("capturing").map_err(db)?,
            ready_to_finalize: value("ready").map_err(db)?,
            finalized: value("finalized").map_err(db)?,
            failed: value("failed").map_err(db)?,
            active_operations: value("active").map_err(db)?,
        })
    }

    async fn enqueue_finalization(
        &self,
        capture_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting finalization enqueue")))?;
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM llm_notary_daemon.captures
                WHERE capture_id = $1 AND capture_state = 'captured'
                  AND http_status BETWEEN 200 AND 299
                FOR UPDATE
             )",
        )
        .bind(capture_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking capture for finalization")))?;
        if !eligible {
            return Ok(None);
        }
        if let Some(row) = sqlx::query(
            "SELECT * FROM llm_notary_daemon.operations
             WHERE capture_id = $1 AND kind = 'finalization'",
        )
        .bind(capture_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("checking existing finalization")))?
        {
            return operation_from_row(&row)
                .map(|operation| Some((operation, true)))
                .map_err(db);
        }
        let operation_id = format!("op-{}", uuid::Uuid::new_v4().simple());
        let row = sqlx::query(
            "INSERT INTO llm_notary_daemon.operations (
                operation_id, kind, capture_id, state, attempt,
                created_at_unix_ms, progress_phase, progress_updated_at_unix_ms
             ) VALUES ($1, 'finalization', $2, 'queued', 0, $3, 'queued', $3)
             RETURNING *",
        )
        .bind(&operation_id)
        .bind(capture_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("inserting finalization operation")))?;
        sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state = 'queued'
             WHERE capture_id = $1",
        )
        .bind(capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("queuing capture finalization")))?;
        insert_event(
            &mut transaction,
            now,
            "finalization_queued",
            Some(capture_id),
            Some(&operation_id),
            "info",
            "Finalization queued",
        )
        .await?;
        let operation = operation_from_row(&row).map_err(db)?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing finalization enqueue")))?;
        Ok(Some((operation, false)))
    }

    async fn claim_next_finalization(&self, now_unix_ms: u64) -> MetadataResult<Option<Operation>> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting finalization claim")))?;
        let operation_id: Option<String> = sqlx::query_scalar(
            "SELECT operation_id FROM llm_notary_daemon.operations
             WHERE kind = 'finalization' AND state = 'queued'
             ORDER BY created_at_unix_ms, operation_id
             FOR UPDATE SKIP LOCKED LIMIT 1",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("selecting queued finalization")))?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        let row = sqlx::query(
            "UPDATE llm_notary_daemon.operations SET
                state = 'running', attempt = attempt + 1, started_at_unix_ms = $2,
                completed_at_unix_ms = NULL, failure_code = NULL,
                progress_phase = 'preparing', progress_updated_at_unix_ms = $2,
                proof_bytes_completed = 0, proof_bytes_total = 0,
                proof_commitments_completed = 0, proof_commitments_total = 0
             WHERE operation_id = $1 AND state = 'queued'
             RETURNING *",
        )
        .bind(&operation_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("claiming finalization")))?;
        let operation = operation_from_row(&row).map_err(db)?;
        let capture_id = operation
            .capture_id
            .as_deref()
            .ok_or_else(|| db(anyhow!("finalization operation has no capture")))?;
        sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state = 'running'
             WHERE capture_id = $1",
        )
        .bind(capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("marking capture finalization running")))?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.operation_attempts
             (operation_id, attempt, state, started_at_unix_ms)
             VALUES ($1, $2, 'running', $3)",
        )
        .bind(&operation.operation_id)
        .bind(i32::try_from(operation.attempt).map_err(|error| db(error.into()))?)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("recording finalization attempt")))?;
        insert_event(
            &mut transaction,
            now,
            "finalization_started",
            Some(capture_id),
            Some(&operation.operation_id),
            "info",
            "Finalization started",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing finalization claim")))?;
        Ok(Some(operation))
    }

    async fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: FinalizationPhase,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let phase = phase.as_str();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting progress update")))?;
        let capture_id: Option<String> = sqlx::query_scalar(
            "UPDATE llm_notary_daemon.operations
             SET progress_phase = $2, progress_updated_at_unix_ms = $3
             WHERE operation_id = $1 AND state = 'running' AND progress_phase <> $2
             RETURNING capture_id",
        )
        .bind(operation_id)
        .bind(phase)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("updating finalization progress")))?;
        let Some(capture_id) = capture_id else {
            return Ok(false);
        };
        let message = match phase {
            "proving" => "Generating private proof",
            "signing" => "Requesting notary signature",
            "packaging" => "Building verified package",
            _ => "Finalization advanced",
        };
        insert_event(
            &mut transaction,
            now,
            "finalization_progress",
            Some(&capture_id),
            Some(operation_id),
            "info",
            message,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing progress update")))?;
        Ok(true)
    }

    async fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: FinalizationProofProgress,
        now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_proof(progress)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting proof progress update")))?;
        let previous = sqlx::query(
            "SELECT progress_phase, proof_bytes_completed, proof_bytes_total,
                    proof_commitments_completed, proof_commitments_total, capture_id
             FROM llm_notary_daemon.operations
             WHERE operation_id = $1 AND state = 'running' FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking proof progress")))?;
        let Some(previous) = previous else {
            return Ok(false);
        };
        let previous_phase: String = previous
            .try_get("progress_phase")
            .map_err(|e| db(e.into()))?;
        let bytes_completed = row_u64(&previous, "proof_bytes_completed").map_err(db)?;
        let bytes_total = row_u64(&previous, "proof_bytes_total").map_err(db)?;
        let commitments_completed =
            row_u64(&previous, "proof_commitments_completed").map_err(db)?;
        let commitments_total = row_u64(&previous, "proof_commitments_total").map_err(db)?;
        if previous_phase == "proving"
            && bytes_completed == progress.bytes_completed
            && bytes_total == progress.bytes_total
            && commitments_completed == progress.commitments_completed
            && commitments_total == progress.commitments_total
        {
            return Ok(false);
        }
        if progress.bytes_completed < bytes_completed
            || progress.commitments_completed < commitments_completed
        {
            return Err(db(anyhow!("proof progress cannot decrease")));
        }
        if (bytes_total != 0 && progress.bytes_total != bytes_total)
            || (commitments_total != 0 && progress.commitments_total != commitments_total)
        {
            return Err(db(anyhow!("proof progress total cannot change")));
        }
        sqlx::query(
            "UPDATE llm_notary_daemon.operations SET
                progress_phase = 'proving', progress_updated_at_unix_ms = $2,
                proof_bytes_completed = $3, proof_bytes_total = $4,
                proof_commitments_completed = $5, proof_commitments_total = $6
             WHERE operation_id = $1 AND state = 'running'",
        )
        .bind(operation_id)
        .bind(now)
        .bind(i64::try_from(progress.bytes_completed).expect("validated proof progress"))
        .bind(i64::try_from(progress.bytes_total).expect("validated proof progress"))
        .bind(i64::try_from(progress.commitments_completed).expect("validated proof progress"))
        .bind(i64::try_from(progress.commitments_total).expect("validated proof progress"))
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("updating proof progress")))?;
        if previous_phase != "proving" {
            let capture_id: String = previous.try_get("capture_id").map_err(|e| db(e.into()))?;
            insert_event(
                &mut transaction,
                now,
                "finalization_progress",
                Some(&capture_id),
                Some(operation_id),
                "info",
                "Generating private proof",
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing proof progress")))?;
        Ok(true)
    }

    async fn complete_finalization(
        &self,
        operation_id: &str,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_artifact(&artifact)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting finalization completion")))?;
        let current = sqlx::query(
            "SELECT state, capture_id FROM llm_notary_daemon.operations
             WHERE operation_id = $1 FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking finalization completion")))?;
        let Some(current) = current else {
            return Ok(TerminalOperationResult::NotFound);
        };
        let state: String = current.try_get("state").map_err(|e| db(e.into()))?;
        validate_operation_state(&state)?;
        let capture_id: String = current.try_get("capture_id").map_err(|e| db(e.into()))?;
        require_artifact(&artifact, &capture_id, ArtifactKind::FinalizedPackage)?;
        if state == "finalized" {
            if artifact_exists_exact(&mut transaction, &artifact).await? {
                return Ok(TerminalOperationResult::AlreadyApplied);
            }
            return Err(db(anyhow!(
                "finalized operation artifact does not match persisted metadata"
            )));
        }
        if state != "running" {
            return Ok(TerminalOperationResult::Conflict {
                current_state: state,
            });
        }
        insert_artifact(&mut transaction, &artifact).await?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.operations SET
                state = 'finalized', completed_at_unix_ms = $2, failure_code = NULL,
                progress_phase = 'complete', progress_updated_at_unix_ms = $2
             WHERE operation_id = $1 AND state = 'running'",
        )
        .bind(operation_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("completing finalization operation")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("running operation transition was lost")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.operation_attempts
             SET state = 'finalized', completed_at_unix_ms = $2, failure_code = NULL
             WHERE operation_id = $1 AND attempt = (
                SELECT attempt FROM llm_notary_daemon.operations WHERE operation_id = $1
             )",
        )
        .bind(operation_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("completing finalization attempt")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("running operation has no current attempt")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state = 'finalized'
             WHERE capture_id = $1",
        )
        .bind(&capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("completing capture finalization")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("finalization operation has no capture")));
        }
        insert_event(
            &mut transaction,
            now,
            "finalization_completed",
            Some(&capture_id),
            Some(operation_id),
            "success",
            "Finalization completed",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing finalization completion")))?;
        Ok(TerminalOperationResult::Applied)
    }

    async fn fail_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting operation failure")))?;
        let current = sqlx::query(
            "SELECT state, failure_code, capture_id FROM llm_notary_daemon.operations
             WHERE operation_id = $1 FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking operation failure")))?;
        let Some(current) = current else {
            return Ok(TerminalOperationResult::NotFound);
        };
        let state: String = current.try_get("state").map_err(|e| db(e.into()))?;
        validate_operation_state(&state)?;
        let current_code: Option<String> =
            current.try_get("failure_code").map_err(|e| db(e.into()))?;
        if state == "failed" && current_code.as_deref() == Some(failure_code) {
            return Ok(TerminalOperationResult::AlreadyApplied);
        }
        if state != "running" {
            return Ok(TerminalOperationResult::Conflict {
                current_state: state,
            });
        }
        let capture_id: String = current.try_get("capture_id").map_err(|e| db(e.into()))?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.operations
             SET state = 'failed', completed_at_unix_ms = $2, failure_code = $3
             WHERE operation_id = $1 AND state = 'running'",
        )
        .bind(operation_id)
        .bind(now)
        .bind(failure_code)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("failing operation")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("running operation transition was lost")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.operation_attempts
             SET state = 'failed', completed_at_unix_ms = $2, failure_code = $3
             WHERE operation_id = $1 AND attempt = (
                SELECT attempt FROM llm_notary_daemon.operations WHERE operation_id = $1
             )",
        )
        .bind(operation_id)
        .bind(now)
        .bind(failure_code)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("failing operation attempt")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("running operation has no current attempt")));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state = 'failed'
             WHERE capture_id = $1",
        )
        .bind(&capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("failing capture finalization")))?
        .rows_affected();
        if changed != 1 {
            return Err(db(anyhow!("finalization operation has no capture")));
        }
        insert_event(
            &mut transaction,
            now,
            "finalization_failed",
            Some(&capture_id),
            Some(operation_id),
            "error",
            "Finalization failed",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing operation failure")))?;
        Ok(TerminalOperationResult::Applied)
    }

    async fn interrupt_running_operations(&self, now_unix_ms: u64) -> MetadataResult<usize> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting operation interruption")))?;
        let rows = sqlx::query(
            "SELECT operation_id, capture_id FROM llm_notary_daemon.operations
             WHERE state = 'running' ORDER BY operation_id FOR UPDATE SKIP LOCKED",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking running operations")))?;
        for row in &rows {
            let operation_id: String = row.try_get("operation_id").map_err(|e| db(e.into()))?;
            let capture_id: String = row.try_get("capture_id").map_err(|e| db(e.into()))?;
            sqlx::query(
                "UPDATE llm_notary_daemon.operations
                 SET state = 'interrupted', completed_at_unix_ms = $2,
                     failure_code = 'service_restarted'
                 WHERE operation_id = $1 AND state = 'running'",
            )
            .bind(&operation_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("interrupting operation")))?;
            sqlx::query(
                "UPDATE llm_notary_daemon.operation_attempts
                 SET state = 'interrupted', completed_at_unix_ms = $2,
                     failure_code = 'service_restarted'
                 WHERE operation_id = $1 AND attempt = (
                    SELECT attempt FROM llm_notary_daemon.operations WHERE operation_id = $1
                 )",
            )
            .bind(&operation_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("interrupting operation attempt")))?;
            sqlx::query(
                "UPDATE llm_notary_daemon.captures SET finalization_state = 'interrupted'
                 WHERE capture_id = $1",
            )
            .bind(&capture_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("interrupting capture finalization")))?;
            insert_event(
                &mut transaction,
                now,
                "finalization_interrupted",
                Some(&capture_id),
                Some(&operation_id),
                "warning",
                "Finalization interrupted by service restart",
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing operation interruption")))?;
        Ok(rows.len())
    }

    async fn retry_operation(
        &self,
        operation_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<Operation>> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting operation retry")))?;
        let current = sqlx::query(
            "SELECT o.state, o.capture_id, c.http_status
             FROM llm_notary_daemon.operations o
             JOIN llm_notary_daemon.captures c ON c.capture_id = o.capture_id
             WHERE o.operation_id = $1 FOR UPDATE OF o, c",
        )
        .bind(operation_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking operation retry")))?;
        let Some(current) = current else {
            return Ok(None);
        };
        let state: String = current.try_get("state").map_err(|e| db(e.into()))?;
        let status: Option<i32> = current.try_get("http_status").map_err(|e| db(e.into()))?;
        if !matches!(state.as_str(), "failed" | "interrupted")
            || !status.is_some_and(|status| (200..=299).contains(&status))
        {
            return Ok(None);
        }
        let capture_id: String = current.try_get("capture_id").map_err(|e| db(e.into()))?;
        let row = sqlx::query(
            "UPDATE llm_notary_daemon.operations SET
                state = 'queued', started_at_unix_ms = NULL, completed_at_unix_ms = NULL,
                failure_code = NULL, progress_phase = 'queued',
                progress_updated_at_unix_ms = $2, proof_bytes_completed = 0,
                proof_bytes_total = 0, proof_commitments_completed = 0,
                proof_commitments_total = 0
             WHERE operation_id = $1 AND state IN ('failed', 'interrupted')
             RETURNING *",
        )
        .bind(operation_id)
        .bind(now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("retrying operation")))?;
        sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state = 'queued'
             WHERE capture_id = $1",
        )
        .bind(&capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("retrying capture finalization")))?;
        insert_event(
            &mut transaction,
            now,
            "finalization_retried",
            Some(&capture_id),
            Some(operation_id),
            "info",
            "Finalization queued for retry",
        )
        .await?;
        let operation = operation_from_row(&row).map_err(db)?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing operation retry")))?;
        Ok(Some(operation))
    }

    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>> {
        sqlx::query("SELECT * FROM llm_notary_daemon.operations WHERE operation_id = $1")
            .bind(operation_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("querying operation")))?
            .as_ref()
            .map(operation_from_row)
            .transpose()
            .map_err(db)
    }

    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>> {
        let limit = validate_limit(filters.limit)?;
        if let Some(cursor) = &filters.cursor {
            invalid_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        let mut query =
            QueryBuilder::<Postgres>::new("SELECT * FROM llm_notary_daemon.operations WHERE TRUE");
        for (column, value) in [
            ("state", filters.state.as_deref()),
            ("kind", filters.kind.as_deref()),
            ("capture_id", filters.capture_id.as_deref()),
        ] {
            if let Some(value) = value {
                query
                    .push(" AND ")
                    .push(column)
                    .push(" = ")
                    .push_bind(value);
            }
        }
        if let Some(cursor) = &filters.cursor {
            let created = i64::try_from(cursor.created_at_unix_ms).expect("validated cursor");
            query
                .push(" AND (created_at_unix_ms < ")
                .push_bind(created)
                .push(" OR (created_at_unix_ms = ")
                .push_bind(created)
                .push(" AND operation_id < ")
                .push_bind(&cursor.operation_id)
                .push("))");
        }
        query
            .push(" ORDER BY created_at_unix_ms DESC, operation_id DESC LIMIT ")
            .push_bind(limit);
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("querying operations")))?
            .iter()
            .map(operation_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn operation_attempts(
        &self,
        operation_id: &str,
    ) -> MetadataResult<Vec<OperationAttempt>> {
        sqlx::query(
            "SELECT attempt, state, started_at_unix_ms, completed_at_unix_ms, failure_code
             FROM llm_notary_daemon.operation_attempts WHERE operation_id = $1
             ORDER BY attempt DESC",
        )
        .bind(operation_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("querying operation attempts")))?
        .iter()
        .map(attempt_from_row)
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(db)
    }

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot> {
        let limit = validate_limit(filters.limit)?;
        if filters.before.is_some() && filters.after.is_some() {
            return Err(MetadataStoreError::InvalidInput(
                "conflicting_event_positions",
            ));
        }
        for value in [filters.before, filters.after, filters.created_after_unix_ms]
            .into_iter()
            .flatten()
        {
            invalid_i64(value, "event_position_out_of_range")?;
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting event snapshot")))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("configuring event snapshot")))?;

        let mut page =
            QueryBuilder::<Postgres>::new("SELECT * FROM llm_notary_daemon.events WHERE TRUE");
        if let Some(before) = filters.before {
            page.push(" AND event_id < ")
                .push_bind(i64::try_from(before).expect("validated event position"));
        }
        if let Some(after) = filters.after {
            page.push(" AND event_id > ")
                .push_bind(i64::try_from(after).expect("validated event position"));
        }
        push_event_filters(&mut page, &filters);
        if filters.after.is_some() {
            page.push(" ORDER BY event_id ASC LIMIT ").push_bind(limit);
        } else {
            page.push(" ORDER BY event_id DESC LIMIT ").push_bind(limit);
        }
        let events = page
            .build()
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("querying event page")))?
            .iter()
            .map(event_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)?;

        let mut high_water = QueryBuilder::<Postgres>::new(
            "SELECT MAX(event_id) AS high_water FROM llm_notary_daemon.events WHERE TRUE",
        );
        push_event_filters(&mut high_water, &filters);
        let row = high_water
            .build()
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("querying event high-water")))?;
        let high_water = row_optional_u64(&row, "high_water").map_err(db)?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing event snapshot")))?;
        Ok(EventSnapshot { events, high_water })
    }
}

fn push_event_filters<'a>(query: &mut QueryBuilder<'a, Postgres>, filters: &'a EventFilters) {
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("capture_id", filters.capture_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            query
                .push(" AND ")
                .push(column)
                .push(" = ")
                .push_bind(value);
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        query
            .push(" AND created_at_unix_ms >= ")
            .push_bind(i64::try_from(created_after).expect("validated event position"));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use sqlx::{Connection as _, PgConnection, PgPool, postgres::PgPoolOptions};
    use testcontainers_modules::{
        postgres::Postgres,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };

    use crate::{
        config::PostgresSslMode,
        metadata::CaptureFilters,
        metadata_store::{MetadataStore, conformance},
    };

    use super::{MIGRATION_LOCK_NAMESPACE, PostgresMetadataStore, migrate_database};

    struct TestPostgres {
        admin: PgPool,
        base_url: String,
        _server: Arc<ContainerAsync<Postgres>>,
    }

    impl TestPostgres {
        async fn start() -> Self {
            let server = Arc::new(
                Postgres::default()
                    .with_tag("17.7-alpine")
                    .start()
                    .await
                    .expect("start PostgreSQL 17 test container"),
            );
            let host = server.get_host().await.expect("PostgreSQL test host");
            let port = server
                .get_host_port_ipv4(5432)
                .await
                .expect("PostgreSQL test port");
            let base_url = format!("postgres://postgres:postgres@{host}:{port}");
            let admin = PgPoolOptions::new()
                .max_connections(10)
                .connect(&format!("{base_url}/postgres"))
                .await
                .expect("connect to PostgreSQL test server");
            Self {
                admin,
                base_url,
                _server: server,
            }
        }

        async fn create_database(&self, name: &str) -> String {
            assert!(
                name.chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            );
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&self.admin)
                .await
                .expect("create isolated daemon test database");
            format!("{}/{name}", self.base_url)
        }
    }

    async fn run_conformance(server: &TestPostgres, full_text_search: bool) {
        let sequence = Arc::new(AtomicUsize::new(0));
        let admin = server.admin.clone();
        let base_url = server.base_url.clone();
        conformance::run(
            move || {
                let sequence = sequence.clone();
                let admin = admin.clone();
                let base_url = base_url.clone();
                async move {
                    let index = sequence.fetch_add(1, Ordering::Relaxed);
                    let database = format!(
                        "daemon_{}_{}",
                        if full_text_search { "fts" } else { "plain" },
                        index
                    );
                    sqlx::query(&format!("CREATE DATABASE {database}"))
                        .execute(&admin)
                        .await
                        .expect("create conformance database");
                    let url = format!("{base_url}/{database}");
                    migrate_database(
                        &url,
                        PostgresSslMode::Disable,
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )
                    .await
                    .expect("migrate conformance database");
                    let store = PostgresMetadataStore::connect(
                        &url,
                        16,
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        PostgresSslMode::Disable,
                        full_text_search,
                    )
                    .await
                    .expect("open conformance store");
                    assert_eq!(store.backend_name(), "postgres");
                    Arc::new(store) as Arc<dyn MetadataStore>
                }
            },
            full_text_search,
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn postgres_17_conforms_with_search_enabled_and_disabled() {
        let server = TestPostgres::start().await;
        run_conformance(&server, true).await;
        run_conformance(&server, false).await;
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn migration_is_explicit_isolated_idempotent_and_lock_bounded() {
        let server = TestPostgres::start().await;
        let blank_url = server.create_database("daemon_blank").await;
        assert!(
            PostgresMetadataStore::connect(
                &blank_url,
                2,
                Duration::from_secs(5),
                Duration::from_secs(5),
                PostgresSslMode::Disable,
                true,
            )
            .await
            .is_err(),
            "runtime construction must not auto-migrate"
        );
        assert!(
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::from_secs(5),
                Duration::ZERO,
            )
            .await
            .is_err()
        );
        assert!(
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::ZERO,
                Duration::from_secs(5),
            )
            .await
            .is_err()
        );

        migrate_database(
            &blank_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("apply isolated daemon migration");
        migrate_database(
            &blank_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("daemon migration is idempotent");
        let pool = PgPoolOptions::new()
            .connect(&blank_url)
            .await
            .expect("open migrated test database");
        let daemon_journal: bool = sqlx::query_scalar(
            "SELECT to_regclass('llm_notary_daemon.schema_migrations') IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let hosted_journal: bool =
            sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(daemon_journal);
        assert!(!hosted_journal);

        sqlx::query("CREATE ROLE daemon_runtime LOGIN PASSWORD 'runtime-test-password'")
            .execute(&server.admin)
            .await
            .unwrap();
        sqlx::raw_sql(
            "GRANT CONNECT ON DATABASE daemon_blank TO daemon_runtime;
             GRANT USAGE ON SCHEMA llm_notary_daemon TO daemon_runtime;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES
                IN SCHEMA llm_notary_daemon TO daemon_runtime;
             GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES
                IN SCHEMA llm_notary_daemon TO daemon_runtime;",
        )
        .execute(&pool)
        .await
        .unwrap();
        let runtime_url = blank_url.replacen(
            "postgres://postgres:postgres@",
            "postgres://daemon_runtime:runtime-test-password@",
            1,
        );
        let runtime = PostgresMetadataStore::connect(
            &runtime_url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        runtime.readiness().await.unwrap();
        assert!(
            sqlx::query("CREATE TABLE llm_notary_daemon.runtime_must_not_ddl (id bigint)")
                .execute(&runtime.pool)
                .await
                .is_err(),
            "the runtime role must not own DDL privileges"
        );

        let exhausted_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100))
            .connect(&runtime_url)
            .await
            .unwrap();
        let exhausted_store = PostgresMetadataStore::from_pool(exhausted_pool.clone(), true)
            .await
            .unwrap();
        let held_connection = exhausted_pool.acquire().await.unwrap();
        let exhausted = tokio::time::timeout(Duration::from_secs(1), exhausted_store.readiness())
            .await
            .expect("the pool acquire timeout must bound readiness");
        assert!(exhausted.is_err(), "pool exhaustion must fail readiness");
        drop(held_connection);

        let search_disabled = PostgresMetadataStore::from_pool(pool.clone(), false)
            .await
            .unwrap();
        let capture = conformance::new_capture("search-toggle", 1);
        search_disabled.begin_capture(capture).await.unwrap();
        search_disabled
            .complete_capture(
                conformance::completion("search-toggle", 2, 200),
                conformance::artifact(
                    "search-toggle",
                    crate::artifact_store::ArtifactKind::DeferredBundle,
                    1,
                ),
            )
            .await
            .unwrap();
        let search_enabled = PostgresMetadataStore::from_pool(pool.clone(), true)
            .await
            .unwrap();
        assert_eq!(
            search_enabled
                .captures(CaptureFilters {
                    query: Some("quarterly".to_owned()),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap()
                .len(),
            1,
            "captures written while search is disabled must be indexed for a later enable"
        );

        let mut lock = PgConnection::connect(&blank_url).await.unwrap();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind(MIGRATION_LOCK_NAMESPACE)
            .execute(&mut lock)
            .await
            .unwrap();
        let blocked = tokio::time::timeout(
            Duration::from_secs(2),
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::from_secs(5),
                Duration::from_millis(100),
            ),
        )
        .await
        .expect("migration lock timeout must bound the wait");
        assert!(blocked.is_err());
        let unlocked: bool =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                .bind(MIGRATION_LOCK_NAMESPACE)
                .fetch_one(&mut lock)
                .await
                .unwrap();
        assert!(unlocked);
    }
}
