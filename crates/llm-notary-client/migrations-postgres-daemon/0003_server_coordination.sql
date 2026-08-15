CREATE TABLE llm_notary_daemon.replicas (
    instance_id TEXT PRIMARY KEY,
    incarnation_id UUID NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (length(instance_id) BETWEEN 1 AND 64)
);

ALTER TABLE llm_notary_daemon.captures
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN capture_fence UUID,
    ADD COLUMN artifact_publication_id UUID,
    ADD COLUMN claim_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT captures_claim_all_or_none CHECK (
        (owner_instance_id IS NULL AND owner_incarnation_id IS NULL AND capture_fence IS NULL
         AND artifact_publication_id IS NULL AND claim_lease_expires_at IS NULL)
        OR
        (owner_instance_id IS NOT NULL AND owner_incarnation_id IS NOT NULL AND capture_fence IS NOT NULL
         AND artifact_publication_id IS NOT NULL AND claim_lease_expires_at IS NOT NULL)
    );
CREATE INDEX captures_expired_claim_idx
    ON llm_notary_daemon.captures(claim_lease_expires_at, capture_id)
    WHERE capture_state = 'capturing';

ALTER TABLE llm_notary_daemon.operations
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN claim_fence UUID,
    ADD COLUMN artifact_publication_id UUID,
    ADD COLUMN claim_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT operations_claim_all_or_none CHECK (
        (owner_instance_id IS NULL AND owner_incarnation_id IS NULL AND claim_fence IS NULL
         AND artifact_publication_id IS NULL AND claim_lease_expires_at IS NULL)
        OR
        (owner_instance_id IS NOT NULL AND owner_incarnation_id IS NOT NULL AND claim_fence IS NOT NULL
         AND artifact_publication_id IS NOT NULL AND claim_lease_expires_at IS NOT NULL)
    );
CREATE INDEX operations_server_queue_idx
    ON llm_notary_daemon.operations(created_at_unix_ms, operation_id)
    WHERE kind = 'finalization' AND state = 'queued';
CREATE INDEX operations_expired_claim_idx
    ON llm_notary_daemon.operations(claim_lease_expires_at, operation_id)
    WHERE kind = 'finalization' AND state = 'running';

ALTER TABLE llm_notary_daemon.operation_attempts
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN claim_fence UUID;

ALTER TABLE llm_notary_daemon.artifacts
    ADD COLUMN publication_id UUID;

CREATE TABLE llm_notary_daemon.dashboard_sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL CHECK (expires_at_unix_ms > created_at_unix_ms)
);
CREATE INDEX dashboard_sessions_expiry_idx
    ON llm_notary_daemon.dashboard_sessions(expires_at_unix_ms);

CREATE TABLE llm_notary_daemon.server_invariants (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    compatibility_sha256 TEXT NOT NULL CHECK (compatibility_sha256 ~ '^[0-9a-f]{64}$'),
    configured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE llm_notary_daemon.notary_trust (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    directory_sha256 TEXT NOT NULL CHECK (directory_sha256 ~ '^[0-9a-f]{64}$'),
    directory_source TEXT NOT NULL CHECK (length(directory_source) BETWEEN 1 AND 2048),
    active_key_id TEXT NOT NULL CHECK (length(active_key_id) BETWEEN 1 AND 128),
    state_json BYTEA NOT NULL CHECK (octet_length(state_json) BETWEEN 1 AND 1048576),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
