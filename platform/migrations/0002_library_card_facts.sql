ALTER TABLE publish_jobs
    ADD COLUMN library_provider TEXT,
    ADD COLUMN library_host TEXT,
    ADD COLUMN library_model TEXT,
    ADD COLUMN library_span_count BIGINT CHECK (library_span_count IS NULL OR library_span_count > 0),
    ADD COLUMN library_tool_use BOOLEAN;

CREATE INDEX publish_jobs_library_card_idx
    ON publish_jobs (admitted_at DESC)
    WHERE state = 'admitted' AND library_provider IS NOT NULL;
