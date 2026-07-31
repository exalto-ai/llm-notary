CREATE TABLE cli_authorization_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    poll_secret_hash TEXT NOT NULL,
    approval_secret_hash TEXT NOT NULL,
    device_name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    approved_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    approved_at BIGINT,
    completed_at BIGINT
);

CREATE INDEX cli_authorization_requests_expires_at_idx
    ON cli_authorization_requests (expires_at);

CREATE TABLE cli_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE INDEX cli_sessions_user_id_idx ON cli_sessions (user_id);

CREATE TABLE cli_used_refresh_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES cli_sessions(id) ON DELETE CASCADE,
    used_at BIGINT NOT NULL
);

CREATE TABLE cli_access_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES cli_sessions(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX cli_access_tokens_expires_at_idx ON cli_access_tokens (expires_at);
