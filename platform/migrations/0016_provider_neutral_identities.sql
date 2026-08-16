-- Introduce the provider-neutral account and identity shapes without changing
-- the current GitHub-only authentication or API contracts. The legacy GitHub
-- columns remain the active compatibility source during the staged cutover.
ALTER TABLE users
    ADD COLUMN display_name TEXT;

UPDATE users
SET display_name = github_login;

CREATE FUNCTION prepare_provider_neutral_user_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.display_name IS NULL OR NEW.display_name = '' THEN
            NEW.display_name := NEW.github_login;
        END IF;
    ELSIF NEW.display_name = OLD.display_name
          AND OLD.display_name = OLD.github_login THEN
        NEW.display_name := NEW.github_login;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_prepare_provider_neutral_profile_on_insert
BEFORE INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION prepare_provider_neutral_user_profile();

CREATE TRIGGER users_prepare_provider_neutral_profile_on_github_login_update
BEFORE UPDATE OF github_login ON users
FOR EACH ROW
EXECUTE FUNCTION prepare_provider_neutral_user_profile();

ALTER TABLE users
    ALTER COLUMN display_name SET NOT NULL;

CREATE TABLE user_identities (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (
        provider ~ '^[a-z][a-z0-9_-]{0,31}$'
    ),
    provider_subject TEXT NOT NULL CHECK (
        LENGTH(provider_subject) BETWEEN 1 AND 255
    ),
    provider_display_name TEXT NOT NULL CHECK (
        LENGTH(provider_display_name) BETWEEN 1 AND 255
    ),
    provider_avatar_url TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    UNIQUE (provider, provider_subject),
    UNIQUE (user_id, provider)
);

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
)
SELECT
    'identity-github-' || github_id::TEXT,
    id,
    'github',
    github_id::TEXT,
    github_login,
    avatar_url,
    created_at,
    updated_at,
    updated_at
FROM users;

CREATE FUNCTION sync_github_user_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
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

CREATE TRIGGER users_sync_github_identity_on_insert
AFTER INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION sync_github_user_identity();

CREATE TRIGGER users_sync_github_identity_on_update
AFTER UPDATE OF github_id, github_login, avatar_url ON users
FOR EACH ROW
EXECUTE FUNCTION sync_github_user_identity();
