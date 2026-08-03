-- Reframe admitted publications as stable shares. Existing admitted rows were
-- discoverable in the Library, so preserve them as Listed. New rows default to
-- Unlisted and require an explicit choice to become discoverable.
ALTER TABLE publish_jobs
    ADD COLUMN visibility TEXT NOT NULL DEFAULT 'listed'
        CHECK (visibility IN ('unlisted', 'listed')),
    ADD COLUMN package_object_key TEXT,
    ADD COLUMN package_size_bytes BIGINT,
    ADD COLUMN package_sha256 TEXT,
    ADD COLUMN public_package_safety_version TEXT;

ALTER TABLE publish_jobs ALTER COLUMN visibility SET DEFAULT 'unlisted';

DROP INDEX IF EXISTS publish_jobs_library_card_idx;
ALTER TABLE publish_jobs
    DROP CONSTRAINT IF EXISTS publish_jobs_admitted_library_card_facts;
ALTER TABLE publish_jobs RENAME COLUMN library_provider TO provider;
ALTER TABLE publish_jobs RENAME COLUMN library_host TO provider_host;
ALTER TABLE publish_jobs RENAME COLUMN library_model TO model;
ALTER TABLE publish_jobs
    DROP COLUMN library_span_count,
    DROP COLUMN library_tool_use,
    DROP COLUMN source_package_sha256;

ALTER TABLE publish_jobs
    ADD CONSTRAINT publish_jobs_admitted_share_facts CHECK (
        state <> 'admitted'
        OR (
            provider IS NOT NULL
            AND provider_host IS NOT NULL
            AND model IS NOT NULL
            AND (
                -- Legacy publications did not retain the source package.
                (package_object_key IS NULL
                 AND package_size_bytes IS NULL
                 AND package_sha256 IS NULL
                 AND public_package_safety_version IS NULL)
                OR
                (package_object_key IS NOT NULL
                 AND package_size_bytes > 0
                 AND package_sha256 IS NOT NULL
                 AND public_package_safety_version IS NOT NULL)
            )
        )
    );

CREATE INDEX publish_jobs_listed_idx
    ON publish_jobs (authenticated_provider_connection_unix_ms DESC, id DESC)
    WHERE state = 'admitted' AND visibility = 'listed';

-- Titles, tags, usage accounting, and popularity events belonged to the old
-- Library-first model. The Listed catalog now derives its small summary from
-- the durable share row.
DROP TABLE publication_activity_events;
DROP TABLE publication_metadata;
DROP TABLE library_metadata_usage;
