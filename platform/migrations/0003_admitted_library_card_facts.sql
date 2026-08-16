ALTER TABLE publish_jobs
    ADD CONSTRAINT publish_jobs_admitted_library_card_facts CHECK (
        state <> 'admitted'
        OR (
            library_provider IS NOT NULL
            AND library_host IS NOT NULL
            AND library_model IS NOT NULL
            AND library_span_count IS NOT NULL
            AND library_tool_use IS NOT NULL
        )
    );
