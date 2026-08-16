CREATE TABLE publication_object_cleanup (
    object_key TEXT PRIMARY KEY NOT NULL,
    publication_id TEXT,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('stamp', 'upload', 'intake')),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_attempt_at BIGINT,
    created_at BIGINT NOT NULL
);

ALTER TABLE publish_jobs
    ADD COLUMN authenticated_provider_connection_unix_ms BIGINT,
    ADD COLUMN verified_at BIGINT,
    ADD COLUMN verified_notary_key_id TEXT,
    ADD COLUMN verified_directory_generation BIGINT,
    ADD COLUMN verified_trust_source TEXT,
    ADD COLUMN source_package_sha256 TEXT;

UPDATE publish_jobs
SET verified_at = admitted_at,
    source_package_sha256 = actual_sha256
WHERE state = 'admitted';

CREATE TABLE anonymous_verification_leases (
    client_key_sha256 TEXT PRIMARY KEY NOT NULL,
    lease_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX publication_object_cleanup_retry_idx
    ON publication_object_cleanup (attempts, created_at);

CREATE INDEX anonymous_verification_leases_expiry_idx
    ON anonymous_verification_leases (expires_at);
