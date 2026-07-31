CREATE TABLE users (
    id TEXT PRIMARY KEY NOT NULL,
    github_id BIGINT NOT NULL UNIQUE,
    github_login TEXT NOT NULL,
    avatar_url TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE oauth_login_states (
    state_hash TEXT PRIMARY KEY NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
