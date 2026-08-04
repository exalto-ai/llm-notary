-- A public trace is usable evidence only when the exact admitted .llmtrace
-- package is retained beside it. Remove legacy trace-only publications and
-- hand every remaining object to the existing retryable cleanup worker.
ALTER TABLE publication_object_cleanup
    DROP CONSTRAINT publication_object_cleanup_artifact_kind_check,
    ADD CONSTRAINT publication_object_cleanup_artifact_kind_check
        CHECK (artifact_kind IN ('stamp', 'upload', 'intake', 'trace', 'package'));

INSERT INTO publication_object_cleanup
    (object_key, publication_id, artifact_kind, created_at)
SELECT artifact.object_key,
       jobs.id,
       artifact.artifact_kind,
       COALESCE(jobs.admitted_at, jobs.updated_at)
FROM publish_jobs AS jobs
CROSS JOIN LATERAL (
    VALUES
        (jobs.upload_object_key, 'upload'),
        (jobs.intake_object_key, 'intake'),
        (jobs.public_trace_object_key, 'trace')
) AS artifact(object_key, artifact_kind)
WHERE jobs.state = 'admitted'
  AND jobs.package_object_key IS NULL
  AND artifact.object_key IS NOT NULL
ON CONFLICT (object_key) DO NOTHING;

DELETE FROM publish_jobs
WHERE state = 'admitted'
  AND package_object_key IS NULL;
