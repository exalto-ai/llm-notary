CREATE TABLE library_metadata_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start INTEGER NOT NULL,
    model TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL CHECK (prompt_tokens >= 0),
    completion_tokens INTEGER NOT NULL CHECK (completion_tokens >= 0),
    estimated_cost_microusd INTEGER NOT NULL CHECK (estimated_cost_microusd >= 0),
    created_at INTEGER NOT NULL
);

CREATE INDEX library_metadata_usage_period_idx
    ON library_metadata_usage (period_start, created_at DESC);
