CREATE SCHEMA notary_api;
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE TABLE notary_api.accounts (
    account_id TEXT PRIMARY KEY NOT NULL,
    display_name TEXT NOT NULL
        CHECK (length(display_name) BETWEEN 1 AND 255),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE notary_api.account_identities (
    identity_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    provider TEXT NOT NULL
        CHECK (provider ~ '^[a-z][a-z0-9_-]{0,31}$'),
    provider_subject TEXT NOT NULL
        CHECK (length(provider_subject) BETWEEN 1 AND 255),
    provider_display_name TEXT NOT NULL
        CHECK (length(provider_display_name) BETWEEN 1 AND 255),
    provider_avatar_url TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    UNIQUE (provider, provider_subject),
    UNIQUE (account_id, provider)
);

CREATE TABLE notary_api.browser_oauth_states (
    state_hash TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('github', 'google')),
    return_to TEXT,
    expires_at BIGINT NOT NULL
);

CREATE TABLE notary_api.browser_sessions (
    token_hash TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX browser_sessions_account_idx
    ON notary_api.browser_sessions (account_id);
CREATE INDEX browser_sessions_expiry_idx
    ON notary_api.browser_sessions (expires_at);

CREATE TABLE notary_api.device_authorizations (
    authorization_id TEXT PRIMARY KEY NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    poll_secret_hash TEXT NOT NULL,
    approval_secret_hash TEXT NOT NULL,
    device_name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    approved_account_id TEXT
        REFERENCES notary_api.accounts(account_id) ON DELETE SET NULL,
    approved_at BIGINT,
    completed_at BIGINT
);

CREATE INDEX device_authorizations_expiry_idx
    ON notary_api.device_authorizations (expires_at);

CREATE TABLE notary_api.devices (
    device_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT
);

CREATE INDEX devices_account_idx
    ON notary_api.devices (account_id);
CREATE INDEX devices_active_page_idx
    ON notary_api.devices (account_id, created_at DESC, device_id DESC)
    WHERE revoked_at IS NULL;

CREATE TABLE notary_api.device_refresh_replays (
    token_hash TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL
        REFERENCES notary_api.devices(device_id) ON DELETE CASCADE,
    used_at BIGINT NOT NULL
);

CREATE TABLE notary_api.device_access_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL
        REFERENCES notary_api.devices(device_id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX device_access_tokens_expiry_idx
    ON notary_api.device_access_tokens (expires_at);

CREATE TABLE notary_api.api_keys (
    key_id TEXT PRIMARY KEY NOT NULL,
    display_prefix TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    secret_hash BYTEA NOT NULL CHECK (octet_length(secret_hash) = 32),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) > 0
        AND scopes <@ ARRAY[
            'account:read',
            'traces:read',
            'traces:share',
            'capture:request',
            'notarization:request'
        ]::TEXT[]
    ),
    created_at BIGINT NOT NULL,
    last_used_at BIGINT,
    expires_at BIGINT,
    revoked_at BIGINT
);

CREATE INDEX api_keys_account_page_idx
    ON notary_api.api_keys (account_id, created_at DESC, key_id DESC);

CREATE TABLE notary_api.traces (
    trace_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    source_trace_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'uploading',
            'queued',
            'verifying',
            'shared',
            'stopped',
            'rejected',
            'failed'
        )
    ),
    package_format TEXT NOT NULL,
    declared_package_size_bytes BIGINT NOT NULL
        CHECK (declared_package_size_bytes > 0),
    declared_package_sha256 TEXT NOT NULL
        CHECK (declared_package_sha256 ~ '^[0-9a-f]{64}$'),
    staging_object_key TEXT NOT NULL UNIQUE,
    committed_staging_object_key TEXT NOT NULL UNIQUE,
    upload_expires_at BIGINT NOT NULL,
    upload_generation BIGINT NOT NULL DEFAULT 0
        CHECK (upload_generation >= 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    queued_at BIGINT,
    failure_code TEXT,
    verification_claim TEXT,
    verification_started_at BIGINT,
    admitted_package_size_bytes BIGINT,
    admitted_package_sha256 TEXT,
    verified_at BIGINT,
    staging_purged_at BIGINT,
    provider TEXT,
    provider_host TEXT,
    model TEXT,
    authenticated_provider_connection_unix_ms BIGINT,
    verified_notary_key_id TEXT,
    verified_registry_generation BIGINT,
    verified_trust_source TEXT,
    package_object_key TEXT,
    package_size_bytes BIGINT,
    package_sha256 TEXT,
    content_object_key TEXT,
    content_size_bytes BIGINT,
    content_sha256 TEXT,
    disclosure_safety_version TEXT,
    disclosure_safety_override BOOLEAN NOT NULL DEFAULT false,
    visibility TEXT NOT NULL DEFAULT 'unlisted'
        CHECK (visibility IN ('unlisted', 'listed')),
    access_expires_at BIGINT,
    access_password_hash TEXT,
    allow_high_entropy BOOLEAN NOT NULL DEFAULT false,
    input_preview TEXT,
    output_preview TEXT,
    listing_search_text TEXT,
    UNIQUE (account_id, source_trace_id),
    UNIQUE (account_id, idempotency_key),
    CHECK (access_expires_at IS NULL OR access_expires_at > created_at),
    CHECK (
        admitted_package_size_bytes IS NULL
        OR admitted_package_size_bytes > 0
    ),
    CHECK (
        admitted_package_sha256 IS NULL
        OR admitted_package_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CHECK (
        package_sha256 IS NULL
        OR package_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CHECK (
        content_sha256 IS NULL
        OR content_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT traces_verified_artifacts_check CHECK (
        status NOT IN ('shared', 'stopped')
        OR (
            verified_at IS NOT NULL
            AND admitted_package_size_bytes > 0
            AND admitted_package_sha256 IS NOT NULL
            AND package_object_key IS NOT NULL
            AND package_size_bytes > 0
            AND package_sha256 IS NOT NULL
            AND content_object_key IS NOT NULL
            AND content_size_bytes > 0
            AND content_sha256 IS NOT NULL
            AND disclosure_safety_version IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX traces_verification_claim_idx
    ON notary_api.traces (verification_claim)
    WHERE verification_claim IS NOT NULL;
CREATE INDEX traces_claim_queue_idx
    ON notary_api.traces (queued_at, trace_id)
    WHERE status = 'queued';
CREATE INDEX traces_upload_expiry_idx
    ON notary_api.traces (upload_expires_at)
    WHERE status = 'uploading';
CREATE INDEX traces_status_updated_idx
    ON notary_api.traces (status, updated_at);
CREATE INDEX traces_owner_page_idx
    ON notary_api.traces (account_id, created_at DESC, trace_id DESC);
CREATE INDEX traces_listed_page_idx
    ON notary_api.traces (
        authenticated_provider_connection_unix_ms DESC NULLS LAST,
        trace_id DESC
    )
    WHERE status = 'shared' AND visibility = 'listed';
CREATE INDEX traces_listed_provider_page_idx
    ON notary_api.traces (
        provider,
        authenticated_provider_connection_unix_ms DESC NULLS LAST,
        trace_id DESC
    )
    WHERE status = 'shared' AND visibility = 'listed';
CREATE INDEX traces_listing_search_idx
    ON notary_api.traces USING GIN (listing_search_text public.gin_trgm_ops)
    WHERE status = 'shared' AND visibility = 'listed';

CREATE FUNCTION notary_api.refresh_listing_search_on_account_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE notary_api.traces
    SET listing_search_text = LOWER(CONCAT_WS(
        ' ', provider, model, NEW.display_name, input_preview, output_preview
    ))
    WHERE account_id = NEW.account_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER accounts_refresh_listing_search
AFTER UPDATE OF display_name ON notary_api.accounts
FOR EACH ROW
WHEN (OLD.display_name IS DISTINCT FROM NEW.display_name)
EXECUTE FUNCTION notary_api.refresh_listing_search_on_account_change();

CREATE TABLE notary_api.storage_cleanup_queue (
    object_key TEXT PRIMARY KEY NOT NULL,
    trace_id TEXT,
    artifact_kind TEXT NOT NULL
        CHECK (artifact_kind IN ('staging', 'package', 'content')),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_attempt_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX storage_cleanup_queue_retry_idx
    ON notary_api.storage_cleanup_queue (attempts, created_at);

CREATE TABLE notary_api.trace_access_change_limits (
    account_id TEXT PRIMARY KEY NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    window_started_at BIGINT NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at BIGINT NOT NULL
);

CREATE INDEX trace_access_change_limits_updated_idx
    ON notary_api.trace_access_change_limits (updated_at);

CREATE TABLE notary_api.trace_reports (
    report_id TEXT PRIMARY KEY NOT NULL,
    trace_id TEXT NOT NULL
        REFERENCES notary_api.traces(trace_id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (
        reason IN (
            'sensitive_information',
            'harassment',
            'illegal_content',
            'spam',
            'other'
        )
    ),
    message TEXT CHECK (message IS NULL OR char_length(message) <= 500),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX trace_reports_trace_page_idx
    ON notary_api.trace_reports (trace_id, created_at DESC);

CREATE TABLE notary_api.public_trace_rate_limits (
    trace_id TEXT NOT NULL
        REFERENCES notary_api.traces(trace_id) ON DELETE CASCADE,
    subject_key_sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('password', 'report')),
    window_started_at BIGINT NOT NULL,
    request_count BIGINT NOT NULL CHECK (request_count > 0),
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (trace_id, subject_key_sha256, action)
);

CREATE INDEX public_trace_rate_limits_updated_idx
    ON notary_api.public_trace_rate_limits (updated_at);

CREATE TABLE notary_api.verification_leases (
    client_key_sha256 TEXT PRIMARY KEY NOT NULL,
    lease_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX verification_leases_expiry_idx
    ON notary_api.verification_leases (expires_at);

CREATE TABLE notary_api.admission_tickets (
    token_hash TEXT PRIMARY KEY NOT NULL,
    account_id TEXT
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    credit_subject TEXT NOT NULL
        CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    admission_tier TEXT NOT NULL
        CHECK (admission_tier IN ('public', 'free', 'one_gb', 'ten_gb')),
    mode TEXT NOT NULL CHECK (mode IN ('capture', 'notarization')),
    registry_generation BIGINT NOT NULL CHECK (registry_generation >= 0),
    record_digest TEXT,
    max_attestable_http_bytes BIGINT NOT NULL
        CHECK (max_attestable_http_bytes > 0),
    max_frame_bytes BIGINT NOT NULL CHECK (max_frame_bytes > 0),
    max_private_chunk_bytes BIGINT NOT NULL
        CHECK (max_private_chunk_bytes > 0),
    max_private_chunk_commitments BIGINT NOT NULL
        CHECK (max_private_chunk_commitments > 0),
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    notarization_allowance_bytes BIGINT,
    CHECK (
        (
            mode = 'capture'
            AND record_digest IS NULL
            AND notarization_allowance_bytes IS NULL
        )
        OR (
            mode = 'notarization'
            AND record_digest ~ '^[0-9a-f]{64}$'
            AND notarization_allowance_bytes > 0
        )
    )
);

CREATE INDEX admission_tickets_expiry_idx
    ON notary_api.admission_tickets (expires_at);
CREATE INDEX admission_tickets_account_issued_idx
    ON notary_api.admission_tickets (account_id, issued_at DESC);
CREATE INDEX admission_tickets_public_issued_idx
    ON notary_api.admission_tickets (issued_at DESC)
    WHERE account_id IS NULL;

CREATE TABLE notary_api.admitted_operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    ticket_token_hash TEXT NOT NULL UNIQUE,
    notary_instance_id TEXT NOT NULL
        CHECK (octet_length(notary_instance_id) BETWEEN 1 AND 128),
    account_id TEXT
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    credit_subject TEXT NOT NULL
        CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    admission_tier TEXT NOT NULL
        CHECK (admission_tier IN ('public', 'free', 'one_gb', 'ten_gb')),
    mode TEXT NOT NULL CHECK (mode IN ('capture', 'notarization')),
    record_digest TEXT,
    notarization_allowance_bytes BIGINT,
    max_attestable_http_bytes BIGINT NOT NULL
        CHECK (max_attestable_http_bytes > 0),
    admitted_at BIGINT NOT NULL,
    terminal_outcome TEXT CHECK (
        terminal_outcome IN ('completed', 'client_failed', 'service_failed')
    ),
    settled_authenticated_bytes BIGINT
        CHECK (settled_authenticated_bytes >= 0),
    settled_at BIGINT,
    CHECK (
        (
            mode = 'capture'
            AND record_digest IS NULL
            AND notarization_allowance_bytes IS NULL
        )
        OR (
            mode = 'notarization'
            AND record_digest ~ '^[0-9a-f]{64}$'
            AND notarization_allowance_bytes > 0
        )
    ),
    CHECK (
        (
            terminal_outcome IS NULL
            AND settled_authenticated_bytes IS NULL
            AND settled_at IS NULL
        )
        OR (
            terminal_outcome IS NOT NULL
            AND settled_authenticated_bytes IS NOT NULL
            AND settled_at IS NOT NULL
        )
    )
);

CREATE INDEX admitted_operations_account_idx
    ON notary_api.admitted_operations (account_id, admitted_at DESC)
    WHERE account_id IS NOT NULL;
CREATE INDEX admitted_operations_unsettled_idx
    ON notary_api.admitted_operations (admitted_at)
    WHERE terminal_outcome IS NULL;

CREATE TABLE notary_api.account_billing_profiles (
    account_id TEXT PRIMARY KEY NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    plan TEXT NOT NULL CHECK (plan IN ('free', 'one_gb', 'ten_gb')),
    billing_status TEXT NOT NULL CHECK (billing_status IN ('active', 'review')),
    updated_at BIGINT NOT NULL
);

CREATE TABLE notary_api.billing_purchases (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    client_idempotency_key TEXT NOT NULL
        CHECK (octet_length(client_idempotency_key) BETWEEN 1 AND 128),
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    state TEXT NOT NULL CHECK (
        state IN (
            'creating',
            'checkout_open',
            'paid',
            'failed',
            'refunded',
            'disputed'
        )
    ),
    currency TEXT NOT NULL CHECK (currency = 'usd'),
    unit_amount_cents BIGINT NOT NULL CHECK (unit_amount_cents > 0),
    quantity_gb BIGINT NOT NULL CHECK (quantity_gb BETWEEN 1 AND 20),
    credit_bytes BIGINT NOT NULL
        CHECK (credit_bytes = 1000000000::BIGINT * quantity_gb),
    expected_amount_cents BIGINT NOT NULL
        CHECK (expected_amount_cents = unit_amount_cents * quantity_gb),
    provider_price_id TEXT NOT NULL
        CHECK (octet_length(provider_price_id) BETWEEN 1 AND 255),
    provider_checkout_session_id TEXT UNIQUE,
    provider_payment_intent_id TEXT UNIQUE,
    provider_charge_id TEXT UNIQUE,
    provider_dispute_id TEXT UNIQUE,
    provider_customer_id TEXT,
    livemode BOOLEAN NOT NULL,
    amount_paid_cents BIGINT NOT NULL DEFAULT 0 CHECK (amount_paid_cents >= 0),
    amount_refunded_cents BIGINT NOT NULL DEFAULT 0
        CHECK (amount_refunded_cents >= 0),
    amount_disputed_cents BIGINT NOT NULL DEFAULT 0
        CHECK (amount_disputed_cents >= 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    paid_at BIGINT,
    UNIQUE (account_id, client_idempotency_key),
    UNIQUE (id, account_id),
    CHECK (amount_refunded_cents <= amount_paid_cents),
    CHECK (amount_disputed_cents <= amount_paid_cents),
    CHECK (amount_refunded_cents + amount_disputed_cents <= amount_paid_cents)
);

CREATE INDEX billing_purchases_account_page_idx
    ON notary_api.billing_purchases (account_id, created_at DESC, id DESC);
CREATE INDEX billing_purchases_state_idx
    ON notary_api.billing_purchases (state, updated_at);

CREATE TABLE notary_api.billing_subscriptions (
    provider_subscription_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    provider_customer_id TEXT NOT NULL,
    provider_price_id TEXT NOT NULL,
    plan TEXT NOT NULL CHECK (plan IN ('one_gb', 'ten_gb')),
    status TEXT NOT NULL CHECK (
        status IN (
            'trialing',
            'active',
            'past_due',
            'paused',
            'unpaid',
            'canceled',
            'incomplete',
            'incomplete_expired'
        )
    ),
    livemode BOOLEAN NOT NULL,
    current_period_end BIGINT,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE UNIQUE INDEX billing_subscriptions_current_account_idx
    ON notary_api.billing_subscriptions (account_id)
    WHERE status NOT IN ('canceled', 'incomplete_expired');
CREATE INDEX billing_subscriptions_account_idx
    ON notary_api.billing_subscriptions (account_id, updated_at DESC);
CREATE INDEX billing_subscriptions_status_idx
    ON notary_api.billing_subscriptions (status, updated_at);

CREATE TABLE notary_api.billing_subscription_checkouts (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    client_idempotency_key TEXT NOT NULL
        CHECK (octet_length(client_idempotency_key) BETWEEN 1 AND 128),
    target_plan TEXT NOT NULL CHECK (target_plan IN ('one_gb', 'ten_gb')),
    state TEXT NOT NULL CHECK (
        state IN ('creating', 'checkout_open', 'completed', 'expired')
    ),
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    provider_price_id TEXT NOT NULL
        CHECK (octet_length(provider_price_id) BETWEEN 1 AND 255),
    provider_checkout_session_id TEXT UNIQUE,
    provider_customer_id TEXT,
    provider_subscription_id TEXT,
    livemode BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, client_idempotency_key)
);

CREATE INDEX billing_subscription_checkouts_account_idx
    ON notary_api.billing_subscription_checkouts (
        account_id,
        created_at DESC,
        id DESC
    );

CREATE TABLE notary_api.billing_subscription_disputes (
    provider_dispute_id TEXT PRIMARY KEY NOT NULL,
    provider_subscription_id TEXT NOT NULL
        REFERENCES notary_api.billing_subscriptions(provider_subscription_id)
        ON DELETE CASCADE,
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    provider_charge_id TEXT NOT NULL,
    amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
    currency TEXT NOT NULL CHECK (currency = 'usd'),
    active BOOLEAN NOT NULL,
    livemode BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX billing_subscription_disputes_account_idx
    ON notary_api.billing_subscription_disputes (account_id, active)
    WHERE active;

CREATE TABLE notary_api.stripe_webhook_events (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    event_type TEXT NOT NULL
        CHECK (octet_length(event_type) BETWEEN 1 AND 120),
    object_id TEXT CHECK (
        object_id IS NULL OR octet_length(object_id) BETWEEN 1 AND 255
    ),
    livemode BOOLEAN NOT NULL,
    provider_created_at BIGINT NOT NULL,
    received_at BIGINT NOT NULL,
    processed_at BIGINT,
    outcome TEXT CHECK (outcome IN ('processed', 'ignored', 'rejected')),
    error_code TEXT CHECK (
        error_code IS NULL OR octet_length(error_code) BETWEEN 1 AND 120
    )
);

CREATE INDEX stripe_webhook_events_received_idx
    ON notary_api.stripe_webhook_events (received_at DESC);

CREATE TABLE notary_api.credit_grants (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL
        CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    amount_bytes BIGINT NOT NULL CHECK (
        (source_kind = 'operation_overage' AND amount_bytes = 0)
        OR (source_kind <> 'operation_overage' AND amount_bytes > 0)
    ),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'included_monthly',
            'promotion',
            'manual_adjustment',
            'external_purchase',
            'service_refund',
            'operation_overage'
        )
    ),
    source_reference TEXT NOT NULL
        CHECK (octet_length(source_reference) BETWEEN 1 AND 256),
    idempotency_key TEXT NOT NULL
        CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    period_start BIGINT,
    period_end BIGINT,
    created_at BIGINT NOT NULL,
    available_at BIGINT NOT NULL,
    expires_at BIGINT,
    display_label TEXT CHECK (
        display_label IS NULL OR octet_length(display_label) <= 120
    ),
    credit_kind TEXT NOT NULL CHECK (
        credit_kind IN ('capture', 'notarization')
    ),
    UNIQUE (credit_subject, idempotency_key),
    UNIQUE (credit_subject, source_kind, source_reference),
    CHECK (expires_at IS NULL OR expires_at > available_at),
    CHECK (
        (
            source_kind = 'included_monthly'
            AND period_start IS NOT NULL
            AND period_end IS NOT NULL
        )
        OR (
            source_kind <> 'included_monthly'
            AND period_start IS NULL
            AND period_end IS NULL
        )
    )
);

CREATE INDEX credit_grants_account_idx
    ON notary_api.credit_grants (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;
CREATE INDEX credit_grants_subject_page_idx
    ON notary_api.credit_grants (credit_subject, created_at DESC, id DESC);
CREATE INDEX credit_grants_available_idx
    ON notary_api.credit_grants (
        credit_subject,
        credit_kind,
        available_at,
        expires_at
    );

CREATE TABLE notary_api.credit_debits (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL
        CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    allowance_bytes BIGINT NOT NULL CHECK (allowance_bytes >= 0),
    created_at BIGINT NOT NULL,
    credit_kind TEXT NOT NULL CHECK (
        credit_kind IN ('capture', 'notarization')
    ),
    operation_id TEXT UNIQUE
        REFERENCES notary_api.admitted_operations(operation_id) ON DELETE CASCADE
);

CREATE INDEX credit_debits_account_idx
    ON notary_api.credit_debits (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;
CREATE INDEX credit_debits_subject_page_idx
    ON notary_api.credit_debits (credit_subject, created_at DESC, id DESC);
CREATE INDEX credit_debits_subject_kind_idx
    ON notary_api.credit_debits (credit_subject, credit_kind, created_at DESC);

CREATE TABLE notary_api.credit_debit_allocations (
    debit_id TEXT NOT NULL
        REFERENCES notary_api.credit_debits(id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL
        REFERENCES notary_api.credit_grants(id) ON DELETE CASCADE,
    amount_bytes BIGINT NOT NULL CHECK (amount_bytes > 0),
    allocation_order INTEGER NOT NULL CHECK (allocation_order >= 0),
    PRIMARY KEY (debit_id, grant_id),
    UNIQUE (debit_id, allocation_order)
);

CREATE INDEX credit_debit_allocations_grant_idx
    ON notary_api.credit_debit_allocations (grant_id);

CREATE TABLE notary_api.credit_adjustments (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL
        CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT NOT NULL
        REFERENCES notary_api.accounts(account_id) ON DELETE CASCADE,
    purchase_id TEXT NOT NULL,
    amount_bytes BIGINT NOT NULL,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'purchase_refund',
            'purchase_dispute',
            'dispute_reinstatement'
        )
    ),
    source_reference TEXT NOT NULL
        CHECK (octet_length(source_reference) BETWEEN 1 AND 256),
    idempotency_key TEXT NOT NULL
        CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    display_label TEXT NOT NULL
        CHECK (octet_length(display_label) BETWEEN 1 AND 120),
    created_at BIGINT NOT NULL,
    UNIQUE (credit_subject, idempotency_key),
    UNIQUE (credit_subject, source_kind, source_reference),
    FOREIGN KEY (purchase_id, account_id)
        REFERENCES notary_api.billing_purchases(id, account_id)
        ON DELETE CASCADE,
    CHECK (credit_subject = 'account:' || account_id),
    CHECK (
        (
            source_kind IN ('purchase_refund', 'purchase_dispute')
            AND amount_bytes < 0
        )
        OR (
            source_kind = 'dispute_reinstatement'
            AND amount_bytes > 0
        )
    )
);

CREATE INDEX credit_adjustments_account_idx
    ON notary_api.credit_adjustments (account_id, created_at DESC, id DESC);
