CREATE TABLE llm_notary_daemon.captures (
    capture_id TEXT PRIMARY KEY,
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    provider TEXT NOT NULL,
    operation TEXT NOT NULL,
    requested_model TEXT,
    response_model TEXT,
    http_status INTEGER CHECK (http_status BETWEEN 0 AND 65535),
    streaming BOOLEAN NOT NULL,
    request_bytes BIGINT NOT NULL CHECK (request_bytes >= 0),
    response_bytes BIGINT CHECK (response_bytes >= 0),
    duration_ms BIGINT CHECK (duration_ms >= 0),
    prompt_preview TEXT NOT NULL,
    prompt_preview_truncated BOOLEAN NOT NULL,
    output_preview TEXT NOT NULL DEFAULT '',
    output_preview_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    config_fingerprint TEXT NOT NULL,
    capture_state TEXT NOT NULL CHECK (capture_state IN ('capturing', 'captured', 'failed')),
    finalization_state TEXT NOT NULL CHECK (
        finalization_state IN ('not_requested', 'queued', 'running', 'interrupted', 'failed', 'finalized')
    ),
    failure_code TEXT
);

CREATE INDEX captures_created_page_idx
    ON llm_notary_daemon.captures(created_at_unix_ms DESC, capture_id DESC);
CREATE INDEX captures_model_idx
    ON llm_notary_daemon.captures(requested_model);

CREATE TABLE llm_notary_daemon.capture_search (
    capture_id TEXT PRIMARY KEY REFERENCES llm_notary_daemon.captures(capture_id) ON DELETE CASCADE,
    prompt_document TSVECTOR NOT NULL,
    output_document TSVECTOR NOT NULL
);
CREATE INDEX capture_search_prompt_document_idx
    ON llm_notary_daemon.capture_search USING GIN(prompt_document);
CREATE INDEX capture_search_output_document_idx
    ON llm_notary_daemon.capture_search USING GIN(output_document);

CREATE TABLE llm_notary_daemon.artifacts (
    capture_id TEXT NOT NULL REFERENCES llm_notary_daemon.captures(capture_id),
    kind TEXT NOT NULL CHECK (kind IN ('deferred_bundle', 'finalized_package')),
    locator TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('available', 'missing')),
    PRIMARY KEY(capture_id, kind)
);

CREATE TABLE llm_notary_daemon.operations (
    operation_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind = 'finalization'),
    capture_id TEXT NOT NULL REFERENCES llm_notary_daemon.captures(capture_id),
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'interrupted', 'failed', 'finalized')),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    started_at_unix_ms BIGINT CHECK (started_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    failure_code TEXT,
    progress_phase TEXT NOT NULL DEFAULT 'queued',
    progress_updated_at_unix_ms BIGINT NOT NULL DEFAULT 0 CHECK (progress_updated_at_unix_ms >= 0),
    proof_bytes_completed BIGINT NOT NULL DEFAULT 0 CHECK (proof_bytes_completed >= 0),
    proof_bytes_total BIGINT NOT NULL DEFAULT 0 CHECK (proof_bytes_total >= 0),
    proof_commitments_completed BIGINT NOT NULL DEFAULT 0 CHECK (proof_commitments_completed >= 0),
    proof_commitments_total BIGINT NOT NULL DEFAULT 0 CHECK (proof_commitments_total >= 0),
    CHECK (proof_bytes_completed <= proof_bytes_total),
    CHECK (proof_commitments_completed <= proof_commitments_total)
);
CREATE UNIQUE INDEX one_finalization_per_capture
    ON llm_notary_daemon.operations(capture_id, kind);
CREATE INDEX operations_created_page_idx
    ON llm_notary_daemon.operations(created_at_unix_ms DESC, operation_id DESC);

CREATE TABLE llm_notary_daemon.operation_attempts (
    operation_id TEXT NOT NULL REFERENCES llm_notary_daemon.operations(operation_id),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    state TEXT NOT NULL CHECK (state IN ('running', 'interrupted', 'failed', 'finalized')),
    started_at_unix_ms BIGINT NOT NULL CHECK (started_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    failure_code TEXT,
    PRIMARY KEY(operation_id, attempt)
);
CREATE INDEX operation_attempts_started_idx
    ON llm_notary_daemon.operation_attempts(started_at_unix_ms DESC);

CREATE TABLE llm_notary_daemon.events (
    event_id BIGSERIAL PRIMARY KEY,
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    event_type TEXT NOT NULL,
    capture_id TEXT REFERENCES llm_notary_daemon.captures(capture_id),
    operation_id TEXT REFERENCES llm_notary_daemon.operations(operation_id),
    severity TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX events_created_idx
    ON llm_notary_daemon.events(created_at_unix_ms DESC);
