ALTER TABLE publish_jobs ADD COLUMN verification_claim TEXT;
ALTER TABLE publish_jobs ADD COLUMN verification_started_at INTEGER;
ALTER TABLE publish_jobs ADD COLUMN actual_size_bytes INTEGER;
ALTER TABLE publish_jobs ADD COLUMN actual_sha256 TEXT;
ALTER TABLE publish_jobs ADD COLUMN admitted_at INTEGER;
ALTER TABLE publish_jobs ADD COLUMN private_purged_at INTEGER;
ALTER TABLE publish_jobs ADD COLUMN public_trace BLOB;
ALTER TABLE publish_jobs ADD COLUMN public_stamp BLOB;

CREATE UNIQUE INDEX publish_jobs_verification_claim_idx
    ON publish_jobs (verification_claim)
    WHERE verification_claim IS NOT NULL;

CREATE INDEX publish_jobs_public_idx
    ON publish_jobs (admitted_at DESC)
    WHERE state = 'admitted';
