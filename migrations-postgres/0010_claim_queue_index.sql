CREATE INDEX publish_jobs_claim_queue_idx
    ON publish_jobs (queued_at, id)
    WHERE state = 'queued';
