-- Contract the provider-identity schema only after migration 0017 and its
-- identity-authoritative application release are running on every API Machine.
-- Abort instead of discarding legacy metadata if the rollout mirrors are not
-- fully reconciled.
DO $$
DECLARE
    account_count BIGINT;
    unreconciled_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO account_count FROM users;
    SELECT COUNT(*) INTO unreconciled_count
    FROM users
    LEFT JOIN user_identities
      ON user_identities.user_id = users.id
     AND user_identities.provider = 'github'
    WHERE user_identities.id IS NULL
       OR users.github_id::TEXT IS DISTINCT FROM user_identities.provider_subject
       OR users.github_login IS DISTINCT FROM user_identities.provider_display_name
       OR users.avatar_url IS DISTINCT FROM user_identities.provider_avatar_url;

    IF unreconciled_count <> 0 THEN
        RAISE EXCEPTION
            'provider identity cleanup refused: % of % accounts are not reconciled',
            unreconciled_count,
            account_count;
    END IF;

    RAISE NOTICE
        'provider identity reconciliation succeeded for % accounts',
        account_count;
END;
$$;

DROP TRIGGER users_prepare_provider_neutral_profile_on_insert ON users;
DROP TRIGGER users_prepare_provider_neutral_profile_on_github_login_update ON users;
DROP FUNCTION prepare_provider_neutral_user_profile();

DROP TRIGGER users_sync_github_identity_on_insert ON users;
DROP TRIGGER users_sync_github_identity_on_update ON users;
DROP FUNCTION sync_github_user_identity();

DROP TRIGGER user_identities_sync_github_legacy_on_insert ON user_identities;
DROP TRIGGER user_identities_sync_github_legacy_on_update ON user_identities;
DROP FUNCTION sync_github_identity_to_legacy_user();

ALTER TABLE users
    DROP COLUMN github_id,
    DROP COLUMN github_login,
    DROP COLUMN avatar_url;
