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
        OperationFilters, SharedNotaryTrust, TerminalOperationResult, capture_search_parts,
    },
    metadata_store::{
        CaptureClaim, CaptureRecoveryClaim, FinalizationClaim, MetadataResult, MetadataStore,
        MetadataStoreError, ReplicaIdentity,
    },
    notary_directory::NotaryDirectory,
};

const SCHEMA: &str = "llm_notary_daemon";
const JOURNAL: &str = "llm_notary_daemon.schema_migrations";
const MIGRATION_LOCK_NAMESPACE: &str = "llm-notary/daemon-postgres-migrations/v1";
const LATEST_SCHEMA_VERSION: i64 = 3;
const INITIAL_MIGRATION: &str = include_str!("../migrations-postgres-daemon/0001_initial.sql");
const ARTIFACT_EXPECTATION_MIGRATION: &str =
    include_str!("../migrations-postgres-daemon/0002_capture_artifact_expectation.sql");
const SERVER_COORDINATION_MIGRATION: &str =
    include_str!("../migrations-postgres-daemon/0003_server_coordination.sql");
const MIGRATIONS: [(i64, &str, &str); 3] = [
    (1, "initial daemon metadata schema", INITIAL_MIGRATION),
    (
        2,
        "bind capture completion to encrypted artifact",
        ARTIFACT_EXPECTATION_MIGRATION,
    ),
    (
        3,
        "server replica leases, fencing, and shared state",
        SERVER_COORDINATION_MIGRATION,
    ),
];

/// A pooled PostgreSQL metadata backend whose schema has already been migrated.
#[derive(Clone)]
pub(crate) struct PostgresMetadataStore {
    pool: PgPool,
    full_text_search: bool,
    server_mode: bool,
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
        Self::connect_mode(
            database_url,
            max_connections,
            connect_timeout,
            acquire_timeout,
            ssl_mode,
            full_text_search,
            false,
        )
        .await
    }

    async fn connect_mode(
        database_url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        acquire_timeout: Duration,
        ssl_mode: PostgresSslMode,
        full_text_search: bool,
        server_mode: bool,
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
            Self::from_pool_mode(pool, full_text_search, server_mode).await
        })
        .await
        .map_err(|_| {
            db(anyhow!(
                "opening and validating daemon PostgreSQL timed out"
            ))
        })?
    }

    /// Wraps an existing pool after verifying the daemon-owned migration journal.
    #[cfg(test)]
    async fn from_pool(pool: PgPool, full_text_search: bool) -> MetadataResult<Self> {
        Self::from_pool_mode(pool, full_text_search, false).await
    }

    async fn from_pool_mode(
        pool: PgPool,
        full_text_search: bool,
        server_mode: bool,
    ) -> MetadataResult<Self> {
        require_current_schema(&pool).await?;
        require_runtime_profile(&pool, server_mode).await?;
        Ok(Self {
            pool,
            full_text_search,
            server_mode,
        })
    }

    /// Opens a runtime pool which rejects every legacy unfenced mutation.
    pub(crate) async fn connect_server(
        database_url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        acquire_timeout: Duration,
        ssl_mode: PostgresSslMode,
        full_text_search: bool,
    ) -> MetadataResult<Self> {
        Self::connect_mode(
            database_url,
            max_connections,
            connect_timeout,
            acquire_timeout,
            ssl_mode,
            full_text_search,
            true,
        )
        .await
    }

    fn require_local_mutation(&self) -> MetadataResult<()> {
        if self.server_mode {
            Err(MetadataStoreError::InvalidInput("server_requires_claim"))
        } else {
            Ok(())
        }
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
    for (index, (version, description, migration)) in MIGRATIONS.iter().enumerate() {
        let checksum = hex::encode(Sha256::digest(migration.as_bytes()));
        if let Some(row) = rows.get(index) {
            ensure!(
                row.try_get::<i64, _>("version")? == *version,
                "daemon migration journal has a gap"
            );
            ensure!(
                row.try_get::<String, _>("description")? == *description
                    && row.try_get::<String, _>("checksum")? == checksum,
                "daemon migration {version} differs from the installed migration"
            );
            continue;
        }
        sqlx::raw_sql(migration)
            .execute(&mut *transaction)
            .await
            .with_context(|| format!("applying daemon PostgreSQL migration {version}"))?;
        sqlx::query(&format!(
            "INSERT INTO {JOURNAL} (version, description, checksum) VALUES ($1, $2, $3)"
        ))
        .bind(version)
        .bind(description)
        .bind(&checksum)
        .execute(&mut *transaction)
        .await
        .with_context(|| format!("recording daemon PostgreSQL migration {version}"))?;
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

/// Pins the operator-provided, non-secret server compatibility identity after
/// migrations. Exact replay is idempotent; a different profile never replaces
/// the installed identity.
pub(crate) async fn configure_server_compatibility(
    database_url: &str,
    ssl_mode: PostgresSslMode,
    connect_timeout: Duration,
    compatibility_sha256: &str,
) -> anyhow::Result<()> {
    ensure!(
        compatibility_sha256.len() == 64
            && compatibility_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "server compatibility identity is invalid"
    );
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("daemon migration URL must be PostgreSQL")?
        .ssl_mode(pg_ssl_mode(ssl_mode));
    let mut connection =
        tokio::time::timeout(connect_timeout, PgConnection::connect_with(&options))
            .await
            .context("opening server compatibility connection timed out")?
            .context("opening server compatibility connection")?;
    let active_legacy_work: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM llm_notary_daemon.captures
             WHERE capture_state='capturing' AND capture_fence IS NULL
             UNION ALL
             SELECT 1 FROM llm_notary_daemon.operations
             WHERE state='running' AND claim_fence IS NULL
         )",
    )
    .fetch_one(&mut connection)
    .await
    .context("checking for unfenced active daemon work")?;
    ensure!(
        !active_legacy_work,
        "server activation requires a quiesced daemon with no unfenced active work"
    );
    sqlx::query(
        "INSERT INTO llm_notary_daemon.server_invariants
             (singleton, compatibility_sha256)
         VALUES (TRUE, $1)
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(compatibility_sha256)
    .execute(&mut connection)
    .await
    .context("pinning server compatibility identity")?;
    let configured: String = sqlx::query_scalar(
        "SELECT compatibility_sha256
         FROM llm_notary_daemon.server_invariants
         WHERE singleton = TRUE",
    )
    .fetch_one(&mut connection)
    .await
    .context("reading server compatibility identity")?;
    ensure!(
        configured == compatibility_sha256,
        "server compatibility identity differs from the installed profile"
    );
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
    let exact = rows.len() == MIGRATIONS.len()
        && rows
            .iter()
            .zip(MIGRATIONS.iter())
            .all(|(row, (version, description, migration))| {
                let checksum = hex::encode(Sha256::digest(migration.as_bytes()));
                row.try_get::<i64, _>("version").ok() == Some(*version)
                    && row.try_get::<String, _>("description").ok().as_deref() == Some(*description)
                    && row.try_get::<String, _>("checksum").ok().as_deref()
                        == Some(checksum.as_str())
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

async fn require_runtime_profile(pool: &PgPool, server_mode: bool) -> MetadataResult<()> {
    let server_pinned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM llm_notary_daemon.server_invariants WHERE singleton=TRUE
         )",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| db(anyhow!(error).context("checking daemon runtime profile")))?;
    match (server_mode, server_pinned) {
        (false, true) => Err(MetadataStoreError::InvalidInput("server_profile_required")),
        (true, false) => Err(MetadataStoreError::InvalidInput("server_not_initialized")),
        _ => Ok(()),
    }
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
    invalid_i64(
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
        expected_artifact_size_bytes: row_optional_u64(row, "expected_artifact_size_bytes")?,
        expected_artifact_sha256: row.try_get("expected_artifact_sha256")?,
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
              AND expected_artifact_size_bytes = $9 AND expected_artifact_sha256 = $10
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
    .bind(invalid_i64(
        completion.expected_artifact_size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&completion.expected_artifact_sha256)
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
        require_current_schema(&self.pool).await?;
        require_runtime_profile(&self.pool, self.server_mode).await
    }

    async fn begin_capture(&self, capture: NewCapture) -> MetadataResult<()> {
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
                output_preview_truncated = $8, expected_artifact_size_bytes = $9,
                expected_artifact_sha256 = $10
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
        .bind(invalid_i64(
            completion.expected_artifact_size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&completion.expected_artifact_sha256)
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
        self.require_local_mutation()?;
        validate_completion(&completion)?;
        validate_artifact(&artifact)?;
        require_artifact(
            &artifact,
            &completion.capture_id,
            ArtifactKind::DeferredBundle,
        )?;
        if artifact.size_bytes != completion.expected_artifact_size_bytes
            || artifact.sha256 != completion.expected_artifact_sha256
        {
            return Err(db(anyhow!(
                "artifact does not match the staged capture publication"
            )));
        }
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
                output_preview_truncated = $8, expected_artifact_size_bytes = $9,
                expected_artifact_sha256 = $10, capture_state = 'captured', failure_code = NULL
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
        .bind(invalid_i64(
            completion.expected_artifact_size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&completion.expected_artifact_sha256)
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
                    output_preview_truncated, expected_artifact_size_bytes,
                    expected_artifact_sha256
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
                let expected_size: Option<i64> = row.try_get("expected_artifact_size_bytes")?;
                let expected_sha256: Option<String> = row.try_get("expected_artifact_sha256")?;
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
                        response_model: row.try_get("response_model")?,
                        output_preview: row.try_get("output_preview")?,
                        output_preview_truncated: row.try_get("output_preview_truncated")?,
                        expected_artifact_size_bytes: expected_size.try_into()?,
                        expected_artifact_sha256: expected_sha256,
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
        self.require_local_mutation()?;
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
        .bind(capture_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("indexing recovered capture preview")))?;
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
            "SELECT capture_id, kind, locator, size_bytes, sha256,
                    publication_id::text AS publication_id
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
                let record = ArtifactRecord::new(
                    ArtifactKey::new(&capture_id, ArtifactKind::try_from(kind.as_str())?)?,
                    ArtifactLocator::from_stored(locator)?,
                    size_bytes.try_into()?,
                    sha256,
                )?;
                match row.try_get::<Option<String>, _>("publication_id")? {
                    Some(publication_id) => record.with_publication_id(publication_id),
                    None => Ok(record),
                }
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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
        self.require_local_mutation()?;
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

    async fn register_replica(
        &self,
        identity: &ReplicaIdentity,
        compatibility_sha256: &str,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        if compatibility_sha256.len() != 64
            || !compatibility_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MetadataStoreError::InvalidInput(
                "invalid_server_compatibility",
            ));
        }
        let configured = sqlx::query_scalar::<_, String>(
            "SELECT compatibility_sha256
             FROM llm_notary_daemon.server_invariants
             WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("checking server compatibility")))?;
        if configured.as_deref() != Some(compatibility_sha256) {
            return Err(MetadataStoreError::InvalidInput(
                "server_compatibility_mismatch",
            ));
        }
        let has_filesystem_artifacts: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM llm_notary_daemon.artifacts
                 WHERE locator NOT LIKE 'artifact/v1/s3/%'
             )",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("checking server artifact compatibility")))?;
        if has_filesystem_artifacts {
            return Err(MetadataStoreError::InvalidInput(
                "server_filesystem_artifacts_present",
            ));
        }
        let lease = lease_i32(lease_seconds)?;
        let row = sqlx::query_scalar::<_, String>(
            "INSERT INTO llm_notary_daemon.replicas
                (instance_id, incarnation_id, heartbeat_at, lease_expires_at)
             VALUES ($1, $2::uuid, clock_timestamp(),
                     clock_timestamp() + make_interval(secs => $3))
             ON CONFLICT (instance_id) DO UPDATE SET
                incarnation_id = excluded.incarnation_id,
                heartbeat_at = excluded.heartbeat_at,
                lease_expires_at = excluded.lease_expires_at
             WHERE llm_notary_daemon.replicas.lease_expires_at <= clock_timestamp()
                OR llm_notary_daemon.replicas.incarnation_id = excluded.incarnation_id
             RETURNING instance_id",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(lease)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("registering server replica")))?;
        if row.is_none() {
            return Err(MetadataStoreError::InvalidInput(
                "live_instance_id_collision",
            ));
        }
        Ok(())
    }

    async fn heartbeat_replica(
        &self,
        identity: &ReplicaIdentity,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.replicas SET
                heartbeat_at = clock_timestamp(),
                lease_expires_at = clock_timestamp() + make_interval(secs => $3)
             WHERE instance_id = $1 AND incarnation_id = $2::uuid
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(lease)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("heartbeating server replica")))?
        .rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing replica heartbeat")))
    }

    async fn replica_ready(&self, identity: &ReplicaIdentity) -> MetadataResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM llm_notary_daemon.replicas
                 WHERE instance_id=$1 AND incarnation_id=$2::uuid
                   AND lease_expires_at>clock_timestamp()
             )",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .fetch_one(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("checking replica lease readiness")))
    }

    async fn release_replica(&self, identity: &ReplicaIdentity) -> MetadataResult<()> {
        sqlx::query(
            "DELETE FROM llm_notary_daemon.replicas
             WHERE instance_id = $1 AND incarnation_id = $2::uuid",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .execute(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("releasing server replica")))?;
        Ok(())
    }

    async fn begin_capture_claimed(
        &self,
        capture: NewCapture,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        if capture.capture_id != claim.capture_id {
            return Err(MetadataStoreError::InvalidInput("capture_claim_mismatch"));
        }
        let created_at = invalid_i64(
            capture.created_at_unix_ms,
            "capture_created_at_out_of_range",
        )?;
        let request_bytes = i64::try_from(capture.request_bytes)
            .map_err(|_| MetadataStoreError::InvalidInput("request_bytes_out_of_range"))?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.captures (
                capture_id, created_at_unix_ms, provider, operation, requested_model,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, capture_state, finalization_state,
                owner_instance_id, owner_incarnation_id, capture_fence,
                artifact_publication_id, claim_lease_expires_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'capturing','not_requested',
                       $11,$12::uuid,$13::uuid,$14::uuid,
                       clock_timestamp() + make_interval(secs => $15))",
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
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
        .bind(lease)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("beginning claimed capture")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing claimed capture")))
    }

    async fn renew_capture_claim(
        &self,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET
                claim_lease_expires_at = clock_timestamp() + make_interval(secs => $6)
             WHERE capture_id = $1 AND capture_state = 'capturing'
               AND owner_instance_id = $2 AND owner_incarnation_id = $3::uuid
               AND capture_fence = $4::uuid AND artifact_publication_id = $5::uuid
               AND claim_lease_expires_at > clock_timestamp()",
        )
        .bind(&claim.capture_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
        .bind(lease)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("renewing capture claim")))?
        .rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing capture renewal")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    async fn prepare_capture_completion_claimed(
        &self,
        completion: CaptureCompletion,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        if completion.capture_id != claim.capture_id {
            return Err(MetadataStoreError::InvalidInput("capture_claim_mismatch"));
        }
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let prepared: Option<bool> = sqlx::query_scalar(
            "SELECT expected_artifact_size_bytes IS NOT NULL
             FROM llm_notary_daemon.captures
             WHERE capture_id=$1 AND capture_state='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_publication_id=$5::uuid
               AND claim_lease_expires_at>clock_timestamp()
             FOR UPDATE",
        )
        .bind(&claim.capture_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("checking claimed capture preparation")))?;
        let Some(prepared) = prepared else {
            return Err(MetadataStoreError::Fenced);
        };
        if prepared && !completion_matches(&mut transaction, &completion).await? {
            return Err(MetadataStoreError::InvalidInput(
                "capture_completion_conflict",
            ));
        }
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET
                completed_at_unix_ms=$6,duration_ms=$7,http_status=$8,response_bytes=$9,
                response_model=$10,output_preview=$11,output_preview_truncated=$12,
                expected_artifact_size_bytes=$13,expected_artifact_sha256=$14,
                claim_lease_expires_at=clock_timestamp()+make_interval(secs => $15)
             WHERE capture_id=$1 AND capture_state='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_publication_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp()",
        )
        .bind(&claim.capture_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
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
        .bind(invalid_i64(
            completion.expected_artifact_size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&completion.expected_artifact_sha256)
        .bind(lease)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("preparing claimed capture")))?
        .rows_affected();
        if changed == 1 {
            transaction.commit().await.map_err(|error| {
                db(anyhow!(error).context("committing claimed capture preparation"))
            })
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    async fn complete_capture_claimed(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
        claim: &CaptureClaim,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        validate_artifact(&artifact)?;
        require_artifact(&artifact, &claim.capture_id, ArtifactKind::DeferredBundle)?;
        if artifact.publication_id() != Some(claim.publication_id.as_str()) {
            return Err(MetadataStoreError::InvalidInput(
                "artifact_publication_mismatch",
            ));
        }
        if artifact.size_bytes != completion.expected_artifact_size_bytes
            || artifact.sha256 != completion.expected_artifact_sha256
        {
            return Err(MetadataStoreError::InvalidInput(
                "capture_artifact_mismatch",
            ));
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET capture_state='captured', failure_code=NULL
             WHERE capture_id=$1 AND capture_state='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_publication_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp()
               AND expected_artifact_size_bytes=$6 AND expected_artifact_sha256=$7",
        )
        .bind(&claim.capture_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
        .bind(invalid_i64(
            artifact.size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&artifact.sha256)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?
        .rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        insert_artifact(&mut transaction, &artifact).await?;
        sqlx::query("UPDATE llm_notary_daemon.artifacts SET publication_id=$3::uuid WHERE capture_id=$1 AND kind=$2")
            .bind(&claim.capture_id).bind(ArtifactKind::DeferredBundle.as_str()).bind(&claim.publication_id)
            .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.capture_search (capture_id,prompt_document,output_document)
             SELECT capture_id,to_tsvector('simple',prompt_preview),to_tsvector('simple',output_preview)
             FROM llm_notary_daemon.captures WHERE capture_id=$1
             ON CONFLICT(capture_id) DO UPDATE SET prompt_document=excluded.prompt_document,output_document=excluded.output_document",
        ).bind(&claim.capture_id).execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))
    }

    async fn fail_capture_claimed(
        &self,
        claim: &CaptureClaim,
        failure_code: &str,
    ) -> MetadataResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.captures SET capture_state='failed',failure_code=$6
             WHERE capture_id=$1 AND capture_state='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_publication_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp()",
        )
        .bind(&claim.capture_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .bind(&claim.publication_id)
        .bind(failure_code)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?
        .rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing claimed capture failure")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    async fn claim_next_stale_capture(
        &self,
        identity: &ReplicaIdentity,
        fence_token: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<CaptureRecoveryClaim>> {
        let lease = lease_i32(lease_seconds)?;
        let row = sqlx::query(
            "WITH live_owner AS (
                SELECT instance_id FROM llm_notary_daemon.replicas
                WHERE instance_id=$1 AND incarnation_id=$2::uuid
                  AND lease_expires_at>clock_timestamp() FOR UPDATE),
             candidate AS (
                SELECT c.capture_id FROM llm_notary_daemon.captures c
                WHERE c.capture_state='capturing' AND c.claim_lease_expires_at <= clock_timestamp()
                ORDER BY c.claim_lease_expires_at,c.capture_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE llm_notary_daemon.captures c SET owner_instance_id=$1,
                owner_incarnation_id=$2::uuid,capture_fence=$3::uuid,
                claim_lease_expires_at=clock_timestamp()+make_interval(secs => $4)
             FROM candidate,live_owner WHERE c.capture_id=candidate.capture_id
             RETURNING c.*,c.artifact_publication_id::text AS publication_id",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(fence_token)
        .bind(lease)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("claiming stale capture")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let capture_id: String = row.try_get("capture_id").map_err(|e| db(e.into()))?;
        let publication_id: String = row.try_get("publication_id").map_err(|e| db(e.into()))?;
        let completion = completion_from_row(&row).map_err(db)?;
        Ok(Some(CaptureRecoveryClaim {
            claim: CaptureClaim {
                capture_id,
                owner: identity.clone(),
                fence_token: fence_token.to_owned(),
                publication_id,
            },
            completion,
        }))
    }

    async fn claim_next_finalization_claimed(
        &self,
        identity: &ReplicaIdentity,
        fence_token: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<FinalizationClaim>> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, identity).await?;
        let row = sqlx::query(
            "WITH moment AS (
                SELECT clock_timestamp() AS ts,
                       floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms),
             candidate AS (
                SELECT operation_id FROM llm_notary_daemon.operations
                WHERE kind='finalization' AND state='queued'
                ORDER BY created_at_unix_ms,operation_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE llm_notary_daemon.operations o SET state='running',attempt=attempt+1,
                started_at_unix_ms=moment.unix_ms,completed_at_unix_ms=NULL,failure_code=NULL,
                progress_phase='preparing',progress_updated_at_unix_ms=moment.unix_ms,
                proof_bytes_completed=0,proof_bytes_total=0,
                proof_commitments_completed=0,proof_commitments_total=0,
                owner_instance_id=$1,owner_incarnation_id=$2::uuid,claim_fence=$3::uuid,
                artifact_publication_id=$3::uuid,
                claim_lease_expires_at=moment.ts+make_interval(secs => $4)
             FROM candidate,moment WHERE o.operation_id=candidate.operation_id RETURNING o.*",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(fence_token)
        .bind(lease)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("claiming server finalization")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let operation = operation_from_row(&row).map_err(db)?;
        let capture_id = operation
            .capture_id
            .as_deref()
            .ok_or_else(|| db(anyhow!("finalization has no capture")))?;
        sqlx::query("UPDATE llm_notary_daemon.captures SET finalization_state='running' WHERE capture_id=$1")
            .bind(capture_id).execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        sqlx::query(
            "INSERT INTO llm_notary_daemon.operation_attempts
                (operation_id,attempt,state,started_at_unix_ms,owner_instance_id,owner_incarnation_id,claim_fence)
             VALUES($1,$2,'running',$3,$4,$5::uuid,$6::uuid)",
        ).bind(&operation.operation_id).bind(i32::try_from(operation.attempt).map_err(|e| db(e.into()))?)
          .bind(invalid_i64(operation.started_at_unix_ms.unwrap_or(0), "timestamp_out_of_range")?)
          .bind(identity.instance_id()).bind(identity.incarnation_id()).bind(fence_token)
          .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut transaction,
            invalid_i64(
                operation.started_at_unix_ms.unwrap_or(0),
                "timestamp_out_of_range",
            )?,
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
            .map_err(|error| db(anyhow!(error)))?;
        Ok(Some(FinalizationClaim {
            operation,
            owner: identity.clone(),
            fence_token: fence_token.to_owned(),
            publication_id: fence_token.to_owned(),
        }))
    }

    async fn renew_finalization_claim(
        &self,
        claim: &FinalizationClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE llm_notary_daemon.operations SET claim_lease_expires_at=clock_timestamp()+make_interval(secs => $6)
             WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2
               AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid
               AND artifact_publication_id=$5::uuid AND claim_lease_expires_at>clock_timestamp()",
        ).bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id())
          .bind(&claim.fence_token).bind(&claim.publication_id).bind(lease)
          .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error).context("renewing finalization claim")))?.rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing finalization renewal")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    async fn update_operation_progress_claimed(
        &self,
        claim: &FinalizationClaim,
        phase: FinalizationPhase,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT progress_phase FROM llm_notary_daemon.operations WHERE operation_id=$1
               AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp() FOR UPDATE",
        )
        .bind(&claim.operation.operation_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        let Some(previous) = previous else {
            return Err(MetadataStoreError::Fenced);
        };
        let changed = previous != phase.as_str();
        sqlx::query("UPDATE llm_notary_daemon.operations SET progress_phase=$2,progress_updated_at_unix_ms=$3,claim_lease_expires_at=clock_timestamp()+make_interval(secs => $4) WHERE operation_id=$1")
            .bind(&claim.operation.operation_id).bind(phase.as_str()).bind(now).bind(lease)
            .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        if changed {
            let message = match phase.as_str() {
                "proving" => "Generating private proof",
                "signing" => "Requesting notary signature",
                "packaging" => "Building verified package",
                _ => "Finalization advanced",
            };
            insert_event(
                &mut transaction,
                now,
                "finalization_progress",
                claim.operation.capture_id.as_deref(),
                Some(&claim.operation.operation_id),
                "info",
                message,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        Ok(changed)
    }

    async fn update_operation_proof_progress_claimed(
        &self,
        claim: &FinalizationClaim,
        progress: FinalizationProofProgress,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool> {
        validate_proof(progress)?;
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let row = sqlx::query(
            "SELECT progress_phase,proof_bytes_completed,proof_bytes_total,
                    proof_commitments_completed,proof_commitments_total
             FROM llm_notary_daemon.operations WHERE operation_id=$1 AND state='running'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp() FOR UPDATE",
        )
        .bind(&claim.operation.operation_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.fence_token)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else {
            return Err(MetadataStoreError::Fenced);
        };
        let old_phase: String = row.try_get("progress_phase").map_err(|e| db(e.into()))?;
        let old_bc = row_u64(&row, "proof_bytes_completed").map_err(db)?;
        let old_bt = row_u64(&row, "proof_bytes_total").map_err(db)?;
        let old_cc = row_u64(&row, "proof_commitments_completed").map_err(db)?;
        let old_ct = row_u64(&row, "proof_commitments_total").map_err(db)?;
        if progress.bytes_completed < old_bc
            || progress.commitments_completed < old_cc
            || (old_bt != 0 && progress.bytes_total != old_bt)
            || (old_ct != 0 && progress.commitments_total != old_ct)
        {
            return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
        }
        let changed = old_phase != "proving"
            || old_bc != progress.bytes_completed
            || old_bt != progress.bytes_total
            || old_cc != progress.commitments_completed
            || old_ct != progress.commitments_total;
        sqlx::query("UPDATE llm_notary_daemon.operations SET progress_phase='proving',progress_updated_at_unix_ms=$2,proof_bytes_completed=$3,proof_bytes_total=$4,proof_commitments_completed=$5,proof_commitments_total=$6,claim_lease_expires_at=clock_timestamp()+make_interval(secs => $7) WHERE operation_id=$1")
            .bind(&claim.operation.operation_id).bind(now)
            .bind(i64::try_from(progress.bytes_completed).expect("validated")).bind(i64::try_from(progress.bytes_total).expect("validated"))
            .bind(i64::try_from(progress.commitments_completed).expect("validated")).bind(i64::try_from(progress.commitments_total).expect("validated")).bind(lease)
            .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        if old_phase != "proving" {
            insert_event(
                &mut transaction,
                now,
                "finalization_progress",
                claim.operation.capture_id.as_deref(),
                Some(&claim.operation.operation_id),
                "info",
                "Generating private proof",
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        Ok(changed)
    }

    async fn complete_finalization_claimed(
        &self,
        claim: &FinalizationClaim,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_artifact(&artifact)?;
        let capture_id = claim
            .operation
            .capture_id
            .as_deref()
            .ok_or_else(|| db(anyhow!("finalization has no capture")))?;
        require_artifact(&artifact, capture_id, ArtifactKind::FinalizedPackage)?;
        if artifact.publication_id() != Some(claim.publication_id.as_str()) {
            return Err(MetadataStoreError::InvalidInput(
                "artifact_publication_mismatch",
            ));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut tx, &claim.owner).await?;
        let row=sqlx::query("SELECT state,claim_fence::text AS claim_fence FROM llm_notary_daemon.operations WHERE operation_id=$1 FOR UPDATE")
            .bind(&claim.operation.operation_id).fetch_optional(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else {
            return Ok(TerminalOperationResult::NotFound);
        };
        let state: String = row.try_get("state").map_err(|e| db(e.into()))?;
        let stored_fence: Option<String> = row.try_get("claim_fence").map_err(|e| db(e.into()))?;
        if stored_fence.as_deref() != Some(&claim.fence_token) {
            return Err(MetadataStoreError::Fenced);
        }
        if state == "finalized" {
            return if artifact_exists_exact(&mut tx, &artifact).await? {
                Ok(TerminalOperationResult::AlreadyApplied)
            } else {
                Err(MetadataStoreError::Fenced)
            };
        }
        if state != "running" {
            return Err(MetadataStoreError::Fenced);
        }
        let changed=sqlx::query("UPDATE llm_notary_daemon.operations SET state='finalized',completed_at_unix_ms=$5,failure_code=NULL,progress_phase='complete',progress_updated_at_unix_ms=$5 WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp()")
            .bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id()).bind(&claim.fence_token).bind(now)
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        insert_artifact(&mut tx, &artifact).await?;
        sqlx::query("UPDATE llm_notary_daemon.artifacts SET publication_id=$3::uuid WHERE capture_id=$1 AND kind=$2")
            .bind(capture_id).bind(ArtifactKind::FinalizedPackage.as_str()).bind(&claim.publication_id).execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        let attempt_changed=sqlx::query("UPDATE llm_notary_daemon.operation_attempts SET state='finalized',completed_at_unix_ms=$5,failure_code=NULL WHERE operation_id=$1 AND attempt=$2 AND owner_instance_id=$3 AND claim_fence=$4::uuid")
            .bind(&claim.operation.operation_id).bind(i32::try_from(claim.operation.attempt).map_err(|e| db(e.into()))?).bind(claim.owner.instance_id()).bind(&claim.fence_token).bind(now)
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if attempt_changed != 1 {
            return Err(db(anyhow!("claimed attempt missing")));
        }
        sqlx::query("UPDATE llm_notary_daemon.captures SET finalization_state='finalized' WHERE capture_id=$1")
            .bind(capture_id).execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            now,
            "finalization_completed",
            Some(capture_id),
            Some(&claim.operation.operation_id),
            "success",
            "Finalization completed",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(TerminalOperationResult::Applied)
    }

    async fn fail_operation_claimed(
        &self,
        claim: &FinalizationClaim,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let capture_id = claim
            .operation
            .capture_id
            .as_deref()
            .ok_or_else(|| db(anyhow!("finalization has no capture")))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut tx, &claim.owner).await?;
        let changed=sqlx::query("UPDATE llm_notary_daemon.operations SET state='failed',completed_at_unix_ms=$5,failure_code=$6 WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp()")
            .bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id()).bind(&claim.fence_token).bind(now).bind(failure_code)
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        let attempt_changed=sqlx::query("UPDATE llm_notary_daemon.operation_attempts SET state='failed',completed_at_unix_ms=$5,failure_code=$6 WHERE operation_id=$1 AND attempt=$2 AND owner_instance_id=$3 AND claim_fence=$4::uuid")
            .bind(&claim.operation.operation_id).bind(i32::try_from(claim.operation.attempt).map_err(|e| db(e.into()))?).bind(claim.owner.instance_id()).bind(&claim.fence_token).bind(now).bind(failure_code)
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if attempt_changed != 1 {
            return Err(db(anyhow!("claimed attempt missing")));
        }
        sqlx::query(
            "UPDATE llm_notary_daemon.captures SET finalization_state='failed' WHERE capture_id=$1",
        )
        .bind(capture_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            now,
            "finalization_failed",
            Some(capture_id),
            Some(&claim.operation.operation_id),
            "error",
            "Finalization failed",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(TerminalOperationResult::Applied)
    }

    async fn interrupt_next_expired_finalization(&self) -> MetadataResult<Option<String>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        let row=sqlx::query(
            "WITH moment AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms),
             candidate AS (SELECT o.operation_id FROM llm_notary_daemon.operations o
                WHERE o.state='running' AND o.claim_lease_expires_at<=clock_timestamp()
                ORDER BY o.claim_lease_expires_at,o.operation_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE llm_notary_daemon.operations o SET state='interrupted',completed_at_unix_ms=moment.unix_ms,failure_code='claim_expired'
             FROM candidate,moment WHERE o.operation_id=candidate.operation_id RETURNING o.operation_id,o.capture_id,o.attempt,o.completed_at_unix_ms",
        ).fetch_optional(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else { return Ok(None) };
        let operation_id: String = row.try_get("operation_id").map_err(|e| db(e.into()))?;
        let capture_id: String = row.try_get("capture_id").map_err(|e| db(e.into()))?;
        let attempt: i32 = row.try_get("attempt").map_err(|e| db(e.into()))?;
        let now: i64 = row
            .try_get("completed_at_unix_ms")
            .map_err(|e| db(e.into()))?;
        sqlx::query("UPDATE llm_notary_daemon.operation_attempts SET state='interrupted',completed_at_unix_ms=$3,failure_code='claim_expired' WHERE operation_id=$1 AND attempt=$2 AND state='running'")
            .bind(&operation_id).bind(attempt).bind(now).execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        sqlx::query("UPDATE llm_notary_daemon.captures SET finalization_state='interrupted' WHERE capture_id=$1").bind(&capture_id).execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            now,
            "finalization_interrupted",
            Some(&capture_id),
            Some(&operation_id),
            "warning",
            "Finalization claim expired",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(Some(operation_id))
    }

    async fn create_dashboard_session(
        &self,
        token_hash: &[u8; 32],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> MetadataResult<()> {
        let created = invalid_i64(created_at_unix_ms, "timestamp_out_of_range")?;
        let expires = invalid_i64(expires_at_unix_ms, "timestamp_out_of_range")?;
        let ttl = expires
            .checked_sub(created)
            .ok_or(MetadataStoreError::InvalidInput("invalid_session_expiry"))?;
        if !(1..=86_400_000).contains(&ttl) {
            return Err(MetadataStoreError::InvalidInput("invalid_session_expiry"));
        }
        sqlx::query("WITH moment AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms)
             INSERT INTO llm_notary_daemon.dashboard_sessions(token_hash,created_at_unix_ms,expires_at_unix_ms)
             SELECT $1,moment.unix_ms,moment.unix_ms+$2 FROM moment")
            .bind(token_hash.as_slice()).bind(ttl).execute(&self.pool).await
            .map_err(|error| db(anyhow!(error).context("creating dashboard session")))?;
        Ok(())
    }

    async fn dashboard_session_valid(
        &self,
        token_hash: &[u8; 32],
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM llm_notary_daemon.dashboard_sessions WHERE token_hash=$1 AND to_timestamp(expires_at_unix_ms::double precision/1000.0) > clock_timestamp())")
            .bind(token_hash.as_slice()).fetch_one(&self.pool).await
            .map_err(|error| db(anyhow!(error).context("checking dashboard session")))
    }

    async fn revoke_dashboard_session(&self, token_hash: &[u8; 32]) -> MetadataResult<()> {
        sqlx::query("DELETE FROM llm_notary_daemon.dashboard_sessions WHERE token_hash=$1")
            .bind(token_hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("revoking dashboard session")))?;
        Ok(())
    }

    async fn prune_dashboard_sessions(
        &self,
        _now_unix_ms: u64,
        limit: usize,
    ) -> MetadataResult<usize> {
        let limit =
            i64::try_from(limit).map_err(|_| MetadataStoreError::InvalidInput("invalid_limit"))?;
        let affected = sqlx::query("DELETE FROM llm_notary_daemon.dashboard_sessions WHERE token_hash IN (SELECT token_hash FROM llm_notary_daemon.dashboard_sessions WHERE to_timestamp(expires_at_unix_ms::double precision/1000.0) <= clock_timestamp() ORDER BY expires_at_unix_ms LIMIT $1)")
            .bind(limit).execute(&self.pool).await.map_err(|error| db(anyhow!(error).context("pruning dashboard sessions")))?.rows_affected();
        usize::try_from(affected).map_err(|error| db(error.into()))
    }

    async fn pin_notary_directory(
        &self,
        directory: NotaryDirectory,
        directory_source: &str,
    ) -> MetadataResult<SharedNotaryTrust> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting notary trust transaction")))?;
        let current = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT state_json FROM llm_notary_daemon.notary_trust
             WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking shared notary trust")))?
        .map(|bytes| {
            serde_json::from_slice::<SharedNotaryTrust>(&bytes)
                .context("parsing shared notary trust")
                .map_err(db)
        })
        .transpose()?;
        let trust = crate::cli::notary::merge_shared_trust(current, directory, directory_source)
            .map_err(|error| db(error.context("merging shared notary trust")))?;
        let generation = i64::try_from(trust.generation)
            .map_err(|_| MetadataStoreError::InvalidInput("notary_generation_out_of_range"))?;
        let state_json = serde_json::to_vec(&trust)
            .map_err(|error| db(anyhow!(error).context("encoding shared notary trust")))?;
        if state_json.len() > 1_048_576 {
            return Err(MetadataStoreError::InvalidInput("notary_trust_too_large"));
        }
        sqlx::query(
            "INSERT INTO llm_notary_daemon.notary_trust(
                 singleton,generation,directory_sha256,directory_source,active_key_id,state_json,updated_at)
             VALUES(TRUE,$1,$2,$3,$4,$5,clock_timestamp())
             ON CONFLICT(singleton) DO UPDATE SET
                 generation=excluded.generation,
                 directory_sha256=excluded.directory_sha256,
                 directory_source=excluded.directory_source,
                 active_key_id=excluded.active_key_id,
                 state_json=excluded.state_json,
                 updated_at=clock_timestamp()",
        )
        .bind(generation)
        .bind(&trust.directory_sha256)
        .bind(&trust.directory_source)
        .bind(&trust.active_key_id)
        .bind(&state_json)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("publishing shared notary trust")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing shared notary trust")))?;
        Ok(trust)
    }

    async fn notary_trust_snapshot(&self) -> MetadataResult<Option<SharedNotaryTrust>> {
        let value = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT state_json FROM llm_notary_daemon.notary_trust WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("reading shared notary trust")))?
        .map(|bytes| {
            serde_json::from_slice::<SharedNotaryTrust>(&bytes)
                .context("parsing shared notary trust")
                .and_then(|trust| {
                    crate::cli::notary::validate_shared_trust(&trust)?;
                    Ok(trust)
                })
                .map_err(db)
        })
        .transpose()?;
        Ok(value)
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

fn lease_i32(value: u64) -> MetadataResult<i32> {
    if !(1..=300).contains(&value) {
        return Err(MetadataStoreError::InvalidInput("invalid_server_lease"));
    }
    i32::try_from(value).map_err(|_| MetadataStoreError::InvalidInput("invalid_server_lease"))
}

async fn lock_live_replica(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    identity: &ReplicaIdentity,
) -> MetadataResult<()> {
    let live = sqlx::query_scalar::<_, String>(
        "SELECT instance_id FROM llm_notary_daemon.replicas
         WHERE instance_id=$1 AND incarnation_id=$2::uuid
           AND lease_expires_at>clock_timestamp()
         FOR UPDATE",
    )
    .bind(identity.instance_id())
    .bind(identity.incarnation_id())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| db(anyhow!(error).context("locking live server replica")))?;
    if live.is_some() {
        Ok(())
    } else {
        Err(MetadataStoreError::Fenced)
    }
}

fn completion_from_row(row: &PgRow) -> anyhow::Result<Option<CaptureCompletion>> {
    let Some(completed_at_unix_ms) = row_optional_u64(row, "completed_at_unix_ms")? else {
        return Ok(None);
    };
    let (
        Some(duration_ms),
        Some(http_status),
        Some(response_bytes),
        Some(expected_size),
        Some(expected_sha),
    ) = (
        row_optional_u64(row, "duration_ms")?,
        row.try_get::<Option<i32>, _>("http_status")?,
        row_optional_u64(row, "response_bytes")?,
        row_optional_u64(row, "expected_artifact_size_bytes")?,
        row.try_get::<Option<String>, _>("expected_artifact_sha256")?,
    )
    else {
        return Ok(None);
    };
    Ok(Some(CaptureCompletion {
        capture_id: row.try_get("capture_id")?,
        completed_at_unix_ms,
        duration_ms,
        http_status: u16::try_from(http_status)?,
        response_bytes,
        response_model: row.try_get("response_model")?,
        output_preview: row.try_get("output_preview")?,
        output_preview_truncated: row.try_get("output_preview_truncated")?,
        expected_artifact_size_bytes: expected_size,
        expected_artifact_sha256: expected_sha,
    }))
}

#[cfg(test)]
mod tests {
    const TEST_SERVER_COMPATIBILITY: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use sha2::{Digest as _, Sha256};
    use sqlx::{Connection as _, PgConnection, PgPool, postgres::PgPoolOptions};
    use testcontainers_modules::{
        postgres::Postgres,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };
    use tokio::sync::Barrier;

    use crate::{
        FinalizationPhase,
        artifact_store::{ArtifactKind, ArtifactLocator},
        config::PostgresSslMode,
        metadata::{CaptureFilters, NewCapture, TerminalOperationResult},
        metadata_store::{
            CaptureClaim, MetadataStore, MetadataStoreError, ReplicaIdentity, conformance,
        },
        notary_directory::{
            DIRECTORY_FORMAT_V3, NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus,
            NotaryTransport, key_id,
        },
    };

    use super::{
        INITIAL_MIGRATION, JOURNAL, MIGRATION_LOCK_NAMESPACE, PostgresMetadataStore,
        configure_server_compatibility, migrate_database,
    };

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
    async fn server_replica_fencing_and_hashed_sessions() {
        let server = TestPostgres::start().await;
        let url = server.create_database("daemon_server").await;
        migrate_database(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        configure_server_compatibility(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            TEST_SERVER_COMPATIBILITY,
        )
        .await
        .unwrap();
        let store = PostgresMetadataStore::connect_server(
            &url,
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        let first = ReplicaIdentity::new("daemon-a").unwrap();
        let collision = ReplicaIdentity::new("daemon-a").unwrap();
        store
            .register_replica(&first, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let incompatible = ReplicaIdentity::new("daemon-incompatible").unwrap();
        assert!(matches!(
            store
                .register_replica(&incompatible, &"1".repeat(64), 20)
                .await,
            Err(MetadataStoreError::InvalidInput(
                "server_compatibility_mismatch"
            ))
        ));
        assert!(matches!(
            store
                .register_replica(&collision, TEST_SERVER_COMPATIBILITY, 20)
                .await,
            Err(MetadataStoreError::InvalidInput(
                "live_instance_id_collision"
            ))
        ));

        let capture_id = "cap-server-fencing";
        let original = CaptureClaim::new(capture_id, first.clone());
        store
            .begin_capture_claimed(
                NewCapture {
                    capture_id: capture_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "/v1/responses".into(),
                    requested_model: Some("gpt-test".into()),
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: "safe".into(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                },
                &original,
                20,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE llm_notary_daemon.captures SET claim_lease_expires_at=clock_timestamp()-interval '1 second' WHERE capture_id=$1")
            .bind(capture_id).execute(&store.pool).await.unwrap();
        sqlx::query("UPDATE llm_notary_daemon.replicas SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE instance_id=$1")
            .bind(first.instance_id()).execute(&store.pool).await.unwrap();
        store
            .register_replica(&collision, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let recovered = store
            .claim_next_stale_capture(&collision, &uuid::Uuid::new_v4().to_string(), 20)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.claim.publication_id, original.publication_id);
        assert!(matches!(
            store.renew_capture_claim(&original, 20).await,
            Err(MetadataStoreError::Fenced)
        ));

        let mut bundle = conformance::artifact(capture_id, ArtifactKind::DeferredBundle, 2);
        bundle.locator = ArtifactLocator::from_stored(
            "artifact/v1/s3/Y2x1c3Rlci1jYXB0dXJlLWRlZmVycmVkLWJ1bmRsZQ",
        )
        .unwrap();
        let bundle = bundle
            .with_publication_id(&recovered.claim.publication_id)
            .unwrap();
        let mut completion = conformance::completion(capture_id, 9, 200);
        completion.expected_artifact_size_bytes = bundle.size_bytes;
        completion.expected_artifact_sha256 = bundle.sha256.clone();
        assert!(matches!(
            store
                .prepare_capture_completion_claimed(completion.clone(), &original, 20)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .complete_capture_claimed(completion.clone(), bundle.clone(), &original)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store.fail_capture_claimed(&original, "stale_owner").await,
            Err(MetadataStoreError::Fenced)
        ));
        store
            .prepare_capture_completion_claimed(completion.clone(), &recovered.claim, 20)
            .await
            .unwrap();
        store
            .complete_capture_claimed(completion, bundle, &recovered.claim)
            .await
            .unwrap();

        let (operation, _) = store
            .enqueue_finalization(capture_id, 10)
            .await
            .unwrap()
            .unwrap();
        let second = ReplicaIdentity::new("daemon-b").unwrap();
        store
            .register_replica(&second, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let first_contender = {
            let store = store.clone();
            let identity = collision.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_next_finalization_claimed(
                        &identity,
                        &uuid::Uuid::new_v4().to_string(),
                        20,
                    )
                    .await
            })
        };
        let second_contender = {
            let store = store.clone();
            let identity = second.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_next_finalization_claimed(
                        &identity,
                        &uuid::Uuid::new_v4().to_string(),
                        20,
                    )
                    .await
            })
        };
        let first_claim = first_contender.await.unwrap().unwrap();
        let second_claim = second_contender.await.unwrap().unwrap();
        assert_eq!(
            usize::from(first_claim.is_some()) + usize::from(second_claim.is_some()),
            1
        );
        let old_finalization = first_claim.or(second_claim).unwrap();
        assert_eq!(
            old_finalization.operation.operation_id,
            operation.operation_id
        );
        assert!(
            store
                .update_operation_progress_claimed(
                    &old_finalization,
                    FinalizationPhase::Signing,
                    11,
                    20,
                )
                .await
                .unwrap()
        );
        sqlx::query("UPDATE llm_notary_daemon.operations SET claim_lease_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1")
            .bind(&operation.operation_id).execute(&store.pool).await.unwrap();
        assert_eq!(
            store.interrupt_next_expired_finalization().await.unwrap(),
            Some(operation.operation_id.clone())
        );
        assert!(
            store
                .interrupt_next_expired_finalization()
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .update_operation_progress_claimed(
                    &old_finalization,
                    FinalizationPhase::Packaging,
                    12,
                    20,
                )
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        let mut stale_package =
            conformance::artifact(capture_id, ArtifactKind::FinalizedPackage, 3);
        stale_package.locator = ArtifactLocator::from_stored(
            "artifact/v1/s3/Y2x1c3Rlci1jYXB0dXJlLWZpbmFsaXplZC1wYWNrYWdl",
        )
        .unwrap();
        let stale_package = stale_package
            .with_publication_id(&old_finalization.publication_id)
            .unwrap();
        assert!(matches!(
            store
                .complete_finalization_claimed(&old_finalization, stale_package, 13)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .fail_operation_claimed(&old_finalization, 13, "stale_failure")
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        store
            .retry_operation(&operation.operation_id, 13)
            .await
            .unwrap()
            .unwrap();
        let retry_owner = if old_finalization.owner == collision {
            second.clone()
        } else {
            collision.clone()
        };
        let winner = store
            .claim_next_finalization_claimed(&retry_owner, &uuid::Uuid::new_v4().to_string(), 20)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(winner.fence_token, old_finalization.fence_token);
        assert_eq!(
            store
                .fail_operation_claimed(&winner, 14, "test_failure")
                .await
                .unwrap(),
            TerminalOperationResult::Applied
        );

        let token_hash = [7_u8; 32];
        store
            .create_dashboard_session(&token_hash, 1, 60_001)
            .await
            .unwrap();
        assert!(store.dashboard_session_valid(&token_hash, 0).await.unwrap());
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT token_hash FROM llm_notary_daemon.dashboard_sessions")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(stored, token_hash);

        let expired_token_hash = [8_u8; 32];
        store
            .create_dashboard_session(&expired_token_hash, 0, 1_000)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE llm_notary_daemon.dashboard_sessions SET created_at_unix_ms=0, expires_at_unix_ms=1 WHERE token_hash=$1",
        )
        .bind(expired_token_hash.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(
            !store
                .dashboard_session_valid(&expired_token_hash, 0)
                .await
                .unwrap()
        );
        assert_eq!(store.prune_dashboard_sessions(0, 10).await.unwrap(), 1);
        let expired_stored: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM llm_notary_daemon.dashboard_sessions WHERE token_hash=$1)",
        )
        .bind(expired_token_hash.as_slice())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!expired_stored);
        assert!(store.dashboard_session_valid(&token_hash, 0).await.unwrap());
        store.revoke_dashboard_session(&token_hash).await.unwrap();
        assert!(!store.dashboard_session_valid(&token_hash, 0).await.unwrap());

        let directory_record = |seed: u8| {
            let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
            let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
            NotaryDirectoryRecord {
                host: "notary.example".into(),
                port: 7047,
                transport: NotaryTransport::Tcp,
                key_id: key_id(&public_key),
                public_key: hex::encode(public_key),
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: 0,
                valid_until_unix_ms: None,
                finalize_until_unix_ms: None,
            }
        };
        let old = directory_record(9);
        let new = directory_record(10);
        let source = "https://api.example/api/notary";
        let first_directory = NotaryDirectory {
            format: DIRECTORY_FORMAT_V3.into(),
            generation: 1,
            active_key_id: old.key_id.clone(),
            notaries: vec![old.clone()],
        };
        store
            .pin_notary_directory(first_directory.clone(), source)
            .await
            .unwrap();
        let second_directory = NotaryDirectory {
            format: DIRECTORY_FORMAT_V3.into(),
            generation: 2,
            active_key_id: new.key_id.clone(),
            notaries: vec![new.clone()],
        };
        let updated = store
            .pin_notary_directory(second_directory.clone(), source)
            .await
            .unwrap();
        assert_eq!(updated.generation, 2);
        assert_eq!(
            updated
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let replayed = store
            .pin_notary_directory(second_directory.clone(), source)
            .await
            .unwrap();
        assert_eq!(replayed.generation, updated.generation);
        assert_eq!(replayed.directory_sha256, updated.directory_sha256);
        assert_eq!(replayed.directory_source, updated.directory_source);
        assert_eq!(
            replayed
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mirror_source = "https://mirror.example/api/notary";
        assert!(
            store
                .pin_notary_directory(second_directory.clone(), mirror_source)
                .await
                .is_err()
        );
        let source_unchanged = store.notary_trust_snapshot().await.unwrap().unwrap();
        assert_eq!(source_unchanged.generation, updated.generation);
        assert_eq!(source_unchanged.directory_sha256, updated.directory_sha256);
        assert_eq!(source_unchanged.directory_source, source);
        assert_eq!(
            source_unchanged
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mut conflicting_new = new.clone();
        conflicting_new.host = "conflict.example".into();
        assert!(
            store
                .pin_notary_directory(
                    NotaryDirectory {
                        format: DIRECTORY_FORMAT_V3.into(),
                        generation: 2,
                        active_key_id: conflicting_new.key_id.clone(),
                        notaries: vec![conflicting_new],
                    },
                    source,
                )
                .await
                .is_err()
        );
        assert!(
            store
                .pin_notary_directory(first_directory, source)
                .await
                .is_err()
        );

        let mut revoked_old = old.clone();
        revoked_old.status = NotaryKeyStatus::Revoked;
        let revoked = store
            .pin_notary_directory(
                NotaryDirectory {
                    format: DIRECTORY_FORMAT_V3.into(),
                    generation: 3,
                    active_key_id: new.key_id.clone(),
                    notaries: vec![new.clone(), revoked_old],
                },
                source,
            )
            .await
            .unwrap();
        assert_eq!(
            revoked
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
        let mut attempted_restore = old.clone();
        attempted_restore.status = NotaryKeyStatus::Retired;
        let non_resurrected = store
            .pin_notary_directory(
                NotaryDirectory {
                    format: DIRECTORY_FORMAT_V3.into(),
                    generation: 4,
                    active_key_id: new.key_id.clone(),
                    notaries: vec![new, attempted_restore],
                },
                source,
            )
            .await
            .unwrap();
        assert_eq!(
            non_resurrected
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
        assert_eq!(
            store
                .notary_trust_snapshot()
                .await
                .unwrap()
                .unwrap()
                .generation,
            4
        );
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

        let legacy_url = server.create_database("daemon_legacy_prepared").await;
        let mut legacy = PgConnection::connect(&legacy_url).await.unwrap();
        sqlx::query("CREATE SCHEMA llm_notary_daemon")
            .execute(&mut legacy)
            .await
            .unwrap();
        sqlx::raw_sql(&format!(
            "CREATE TABLE {JOURNAL} (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            );"
        ))
        .execute(&mut legacy)
        .await
        .unwrap();
        sqlx::raw_sql(INITIAL_MIGRATION)
            .execute(&mut legacy)
            .await
            .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {JOURNAL} (version, description, checksum) VALUES (1, $1, $2)"
        ))
        .bind("initial daemon metadata schema")
        .bind(hex::encode(Sha256::digest(INITIAL_MIGRATION.as_bytes())))
        .execute(&mut legacy)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO llm_notary_daemon.captures (
                capture_id, created_at_unix_ms, completed_at_unix_ms, provider,
                operation, requested_model, response_model, http_status, streaming,
                request_bytes, response_bytes, duration_ms, prompt_preview,
                prompt_preview_truncated, output_preview, output_preview_truncated,
                config_fingerprint, capture_state, finalization_state, failure_code
             ) VALUES (
                'cap-legacy-prepared', 1, 2, 'openai', 'responses', 'gpt-5',
                'gpt-5', 200, FALSE, 12, 24, 1, 'Legacy staged prompt', FALSE,
                'Legacy staged output', FALSE, 'sha256:test', 'capturing',
                'not_requested', NULL
             )",
        )
        .execute(&mut legacy)
        .await
        .unwrap();
        drop(legacy);
        migrate_database(
            &legacy_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let legacy_store = PostgresMetadataStore::connect(
            &legacy_url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        legacy_store
            .recover_capture(
                "cap-legacy-prepared",
                conformance::artifact("cap-legacy-prepared", ArtifactKind::DeferredBundle, 2),
            )
            .await
            .unwrap();
        let legacy_matches = legacy_store
            .captures(CaptureFilters {
                query: Some("legacy output".to_owned()),
                limit: 20,
                ..CaptureFilters::default()
            })
            .await
            .unwrap();
        assert_eq!(legacy_matches.len(), 1);
        assert_eq!(legacy_matches[0].capture_id, "cap-legacy-prepared");
        assert_eq!(legacy_matches[0].expected_artifact_size_bytes, None);
        assert_eq!(legacy_matches[0].expected_artifact_sha256, None);

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
