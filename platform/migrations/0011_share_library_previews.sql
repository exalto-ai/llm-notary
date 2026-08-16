-- Listed shares are already public. Keep short excerpts beside their durable
-- metadata so the Library can distinguish sessions without fetching every
-- complete trace. Existing shares remain valid and show metadata-only rows.
ALTER TABLE publish_jobs
    ADD COLUMN library_input_preview TEXT,
    ADD COLUMN library_output_preview TEXT;
