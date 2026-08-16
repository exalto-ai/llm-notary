CREATE TABLE api_keys (
    id TEXT PRIMARY KEY NOT NULL,
    display_prefix TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    secret_hash BYTEA NOT NULL CHECK (octet_length(secret_hash) = 32),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) > 0
        AND scopes <@ ARRAY[
            'account:read',
            'notary:admit',
            'publish:read',
            'publish:write'
        ]::TEXT[]
    ),
    created_at BIGINT NOT NULL,
    last_used_at BIGINT,
    expires_at BIGINT,
    revoked_at BIGINT
);

CREATE INDEX api_keys_user_created_idx
    ON api_keys (user_id, created_at DESC, id DESC);
