CREATE TABLE publication_metadata (
    publication_id TEXT PRIMARY KEY NOT NULL REFERENCES publish_jobs(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    title_source TEXT NOT NULL CHECK (title_source IN ('generated', 'fallback')),
    generator_model TEXT,
    generator_prompt_version TEXT,
    generated_at INTEGER,
    last_generation_attempt_at INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE INDEX publication_metadata_generated_idx
    ON publication_metadata (title_source, last_generation_attempt_at);

-- This deliberately records a generic event type so the Library can grow
-- beyond downloads without another analytics schema.  The subject key is an
-- opaque, client-generated nonce; it is hashed before storage and does not
-- retain an IP address, account, or other directly identifying value.
CREATE TABLE publication_activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    publication_id TEXT NOT NULL REFERENCES publish_jobs(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    subject_key_sha256 TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    UNIQUE (publication_id, event_type, subject_key_sha256)
);

CREATE INDEX publication_activity_events_recent_idx
    ON publication_activity_events (event_type, occurred_at DESC, publication_id);
