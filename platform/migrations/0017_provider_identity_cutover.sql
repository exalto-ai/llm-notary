-- Make user_identities the application-facing identity source while preserving
-- compatibility for old API Machines during this rolling deployment. The
-- reverse mirror is removed, with the legacy columns, only after this release
-- is running everywhere (tracked by issue #215).
ALTER TABLE users
    ALTER COLUMN github_id DROP NOT NULL,
    ALTER COLUMN github_login DROP NOT NULL;

CREATE OR REPLACE FUNCTION sync_github_user_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.github_id IS NULL OR NEW.github_login IS NULL THEN
        RETURN NEW;
    END IF;

    INSERT INTO user_identities (
        id,
        user_id,
        provider,
        provider_subject,
        provider_display_name,
        provider_avatar_url,
        created_at,
        updated_at,
        last_used_at
    ) VALUES (
        'identity-github-' || NEW.github_id::TEXT,
        NEW.id,
        'github',
        NEW.github_id::TEXT,
        NEW.github_login,
        NEW.avatar_url,
        NEW.created_at,
        NEW.updated_at,
        NEW.updated_at
    )
    ON CONFLICT (provider, provider_subject) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        provider_display_name = EXCLUDED.provider_display_name,
        provider_avatar_url = EXCLUDED.provider_avatar_url,
        updated_at = EXCLUDED.updated_at,
        last_used_at = EXCLUDED.last_used_at;
    RETURN NEW;
END;
$$;

DROP TRIGGER users_sync_github_identity_on_update ON users;

CREATE TRIGGER users_sync_github_identity_on_update
AFTER UPDATE OF github_id, github_login, avatar_url ON users
FOR EACH ROW
WHEN (
    OLD.github_id IS DISTINCT FROM NEW.github_id
    OR OLD.github_login IS DISTINCT FROM NEW.github_login
    OR OLD.avatar_url IS DISTINCT FROM NEW.avatar_url
)
EXECUTE FUNCTION sync_github_user_identity();

CREATE FUNCTION sync_github_identity_to_legacy_user()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider <> 'github' THEN
        RETURN NEW;
    END IF;

    UPDATE users
    SET github_id = NEW.provider_subject::BIGINT,
        github_login = NEW.provider_display_name,
        avatar_url = NEW.provider_avatar_url,
        updated_at = GREATEST(updated_at, NEW.updated_at)
    WHERE id = NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER user_identities_sync_github_legacy_on_insert
AFTER INSERT ON user_identities
FOR EACH ROW
WHEN (NEW.provider = 'github')
EXECUTE FUNCTION sync_github_identity_to_legacy_user();

CREATE TRIGGER user_identities_sync_github_legacy_on_update
AFTER UPDATE OF user_id, provider_subject, provider_display_name,
                provider_avatar_url, updated_at ON user_identities
FOR EACH ROW
WHEN (
    NEW.provider = 'github'
    AND (
        OLD.user_id IS DISTINCT FROM NEW.user_id
        OR OLD.provider_subject IS DISTINCT FROM NEW.provider_subject
        OR OLD.provider_display_name IS DISTINCT FROM NEW.provider_display_name
        OR OLD.provider_avatar_url IS DISTINCT FROM NEW.provider_avatar_url
        OR OLD.updated_at IS DISTINCT FROM NEW.updated_at
    )
)
EXECUTE FUNCTION sync_github_identity_to_legacy_user();

DROP TRIGGER users_refresh_library_search ON users;
DROP FUNCTION refresh_library_search_on_login_change();

CREATE FUNCTION refresh_library_search_on_display_name_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE publish_jobs
    SET library_search_text = LOWER(CONCAT_WS(
        ' ', provider, model, NEW.display_name,
        library_input_preview, library_output_preview
    ))
    WHERE user_id = NEW.id
      AND state = 'admitted';
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_refresh_library_search
AFTER UPDATE OF display_name ON users
FOR EACH ROW
WHEN (OLD.display_name IS DISTINCT FROM NEW.display_name)
EXECUTE FUNCTION refresh_library_search_on_display_name_change();

UPDATE publish_jobs
SET library_search_text = LOWER(CONCAT_WS(
    ' ', publish_jobs.provider, publish_jobs.model, users.display_name,
    publish_jobs.library_input_preview, publish_jobs.library_output_preview
))
FROM users
WHERE users.id = publish_jobs.user_id
  AND publish_jobs.state = 'admitted';
