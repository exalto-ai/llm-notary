-- Migration 0012 removed admitted shares that predated exact package
-- retention. Make that invariant durable so a trace-only share cannot be
-- admitted again through a future write path.
ALTER TABLE publish_jobs
    DROP CONSTRAINT publish_jobs_admitted_share_facts,
    ADD CONSTRAINT publish_jobs_admitted_share_facts CHECK (
        state <> 'admitted'
        OR (
            provider IS NOT NULL
            AND provider_host IS NOT NULL
            AND model IS NOT NULL
            AND package_object_key IS NOT NULL
            AND package_size_bytes IS NOT NULL
            AND package_size_bytes > 0
            AND package_sha256 IS NOT NULL
            AND public_package_safety_version IS NOT NULL
        )
    );
