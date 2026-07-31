ALTER TABLE publication_metadata ADD COLUMN generation_claim TEXT;
ALTER TABLE publication_metadata ADD COLUMN generation_claimed_at BIGINT;

CREATE INDEX publication_metadata_claim_idx
    ON publication_metadata (generation_claimed_at)
    WHERE generation_claim IS NOT NULL;
