-- A publisher may explicitly accept heuristic high-entropy false positives.
-- Concrete secret detections and all verification failures remain mandatory.
ALTER TABLE publish_jobs
    ADD COLUMN force_publication BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN public_package_safety_override BOOLEAN NOT NULL DEFAULT FALSE;
