CREATE TABLE IF NOT EXISTS cli_authorization_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    poll_secret_hash TEXT NOT NULL,
    approval_secret_hash TEXT NOT NULL,
    device_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    approved_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    approved_at INTEGER,
    completed_at INTEGER
);

CREATE INDEX IF NOT EXISTS cli_authorization_requests_expires_at_idx
    ON cli_authorization_requests (expires_at);

CREATE TABLE IF NOT EXISTS cli_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS cli_sessions_user_id_idx ON cli_sessions (user_id);

CREATE TABLE IF NOT EXISTS cli_used_refresh_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES cli_sessions(id) ON DELETE CASCADE,
    used_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cli_access_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES cli_sessions(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS cli_access_tokens_expires_at_idx ON cli_access_tokens (expires_at);
