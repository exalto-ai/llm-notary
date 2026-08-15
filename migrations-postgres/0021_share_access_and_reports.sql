-- Owner-controlled publication access. Public artifacts remain retained so an
-- owner can publish the same stable share again without repeating admission.
ALTER TABLE publish_jobs
    ADD COLUMN published BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN share_expires_at BIGINT,
    ADD COLUMN share_password_hash TEXT,
    ADD CONSTRAINT publish_jobs_share_expiry_after_creation CHECK (
        share_expires_at IS NULL OR share_expires_at > created_at
    );

CREATE TABLE share_reports (
    id TEXT PRIMARY KEY NOT NULL,
    share_id TEXT NOT NULL REFERENCES publish_jobs(id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (
        reason IN (
            'sensitive_information',
            'harassment',
            'illegal_content',
            'spam',
            'other'
        )
    ),
    message TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CHECK (message IS NULL OR char_length(message) <= 500)
);

CREATE INDEX share_reports_share_created_idx
    ON share_reports (share_id, created_at DESC);

-- Network-derived keys are used only for abuse limits. Report records remain
-- append-only so people sharing a household, office, VPN, or carrier address
-- cannot replace one another's moderation evidence.
CREATE TABLE share_request_limits (
    share_id TEXT NOT NULL REFERENCES publish_jobs(id) ON DELETE CASCADE,
    subject_key_sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('password', 'report')),
    window_started_at BIGINT NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (share_id, subject_key_sha256, action)
);

CREATE INDEX share_request_limits_updated_idx
    ON share_request_limits (updated_at);

CREATE TABLE share_password_change_limits (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    window_started_at BIGINT NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at BIGINT NOT NULL
);

CREATE INDEX share_password_change_limits_updated_idx
    ON share_password_change_limits (updated_at);
