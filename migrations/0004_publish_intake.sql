CREATE TABLE publish_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'uploading',
            'queued',
            'verifying',
            'admitted',
            'rejected',
            'purged',
            'expired',
            'failed'
        )
    ),
    archive_format TEXT NOT NULL,
    declared_size_bytes INTEGER NOT NULL CHECK (declared_size_bytes > 0),
    declared_sha256 TEXT NOT NULL,
    upload_object_key TEXT NOT NULL UNIQUE,
    intake_object_key TEXT NOT NULL UNIQUE,
    upload_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    queued_at INTEGER,
    failure_code TEXT,
    UNIQUE (user_id, idempotency_key)
);

CREATE INDEX publish_jobs_user_created_idx
    ON publish_jobs (user_id, created_at DESC);

CREATE INDEX publish_jobs_state_updated_idx
    ON publish_jobs (state, updated_at);

CREATE INDEX publish_jobs_upload_expiry_idx
    ON publish_jobs (upload_expires_at)
    WHERE state = 'uploading';
