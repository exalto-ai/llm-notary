-- Bind every one-time OAuth state to the provider that created it so a state
-- issued for one callback cannot be consumed by another provider callback.
-- Google account subjects and profile metadata use the provider-neutral
-- user_identities table introduced by migrations 0016-0018.
ALTER TABLE oauth_login_states
    ADD COLUMN provider TEXT NOT NULL DEFAULT 'github'
        CHECK (provider IN ('github', 'google'));
