INSERT INTO publication_object_cleanup
    (object_key, publication_id, artifact_kind, created_at)
SELECT public_stamp_object_key, id, 'stamp', COALESCE(admitted_at, updated_at)
FROM publish_jobs
WHERE public_stamp_object_key IS NOT NULL
ON CONFLICT (object_key) DO NOTHING;

ALTER TABLE publish_jobs
    DROP COLUMN public_stamp_object_key,
    DROP COLUMN public_stamp_size_bytes,
    DROP COLUMN public_stamp_sha256;
