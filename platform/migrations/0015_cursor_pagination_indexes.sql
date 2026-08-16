CREATE INDEX publish_jobs_owner_page_idx
    ON publish_jobs (user_id, created_at DESC, id DESC);

CREATE INDEX publish_jobs_library_page_idx
    ON publish_jobs (
        authenticated_provider_connection_unix_ms DESC NULLS LAST,
        id DESC
    )
    WHERE state = 'admitted'
      AND visibility = 'listed'
      AND public_trace_object_key IS NOT NULL
      AND package_object_key IS NOT NULL;

CREATE INDEX publish_jobs_library_provider_page_idx
    ON publish_jobs (
        provider,
        authenticated_provider_connection_unix_ms DESC NULLS LAST,
        id DESC
    )
    WHERE state = 'admitted'
      AND visibility = 'listed'
      AND public_trace_object_key IS NOT NULL
      AND package_object_key IS NOT NULL;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

ALTER TABLE publish_jobs
    ADD COLUMN library_search_text TEXT;

UPDATE publish_jobs
SET library_search_text = LOWER(CONCAT_WS(
    ' ', publish_jobs.provider, publish_jobs.model, users.github_login,
    publish_jobs.library_input_preview, publish_jobs.library_output_preview
))
FROM users
WHERE users.id = publish_jobs.user_id
  AND publish_jobs.state = 'admitted';

CREATE INDEX publish_jobs_library_search_idx
    ON publish_jobs USING GIN (library_search_text gin_trgm_ops)
    WHERE state = 'admitted'
      AND visibility = 'listed'
      AND public_trace_object_key IS NOT NULL
      AND package_object_key IS NOT NULL;

CREATE FUNCTION refresh_library_search_on_login_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.github_login IS DISTINCT FROM OLD.github_login THEN
        UPDATE publish_jobs
        SET library_search_text = LOWER(CONCAT_WS(
            ' ', provider, model, NEW.github_login,
            library_input_preview, library_output_preview
        ))
        WHERE user_id = NEW.id
          AND state = 'admitted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_refresh_library_search
AFTER UPDATE OF github_login ON users
FOR EACH ROW
EXECUTE FUNCTION refresh_library_search_on_login_change();

CREATE INDEX cli_sessions_active_page_idx
    ON cli_sessions (user_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX notary_credit_grants_subject_history_idx
    ON notary_credit_grants (credit_subject, created_at DESC, id DESC);

CREATE INDEX notary_credit_debits_subject_history_idx
    ON notary_credit_debits (credit_subject, created_at DESC, id DESC);
