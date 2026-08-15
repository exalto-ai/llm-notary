-- Replace the prototype credit/purchase model with explicit subscription
-- entitlements. Existing prototype billing and metering rows are disposable;
-- users and admitted public traces remain intact.
TRUNCATE TABLE
    billing_provider_events,
    notary_credit_debit_allocations,
    notary_credit_adjustments,
    notary_credit_debits,
    notary_credit_grants,
    notary_admission_tickets,
    notary_admission_leases,
    billing_purchases,
    account_billing_profiles
CASCADE;

-- The subscription cutover is intentionally not rollback-compatible. Remove
-- the temporary columns, trigger, and view that existed only for old images.
DROP VIEW IF EXISTS notary_finalization_credit_ledger;
DROP TRIGGER IF EXISTS notary_admission_tickets_legacy_credit_subject
    ON notary_admission_tickets;
DROP TRIGGER IF EXISTS notary_admission_leases_legacy_credit_subject
    ON notary_admission_leases;
DROP FUNCTION IF EXISTS populate_legacy_credit_subject();
ALTER TABLE users DROP COLUMN IF EXISTS service_plan;
ALTER TABLE notary_admission_tickets DROP COLUMN IF EXISTS session_timeout_secs;

ALTER TABLE account_billing_profiles
    DROP CONSTRAINT account_billing_profiles_service_plan_check,
    ADD CONSTRAINT account_billing_profiles_service_plan_check
        CHECK (service_plan IN ('free', 'one_gb', 'ten_gb'));

ALTER TABLE notary_admission_tickets
    DROP CONSTRAINT notary_admission_tickets_access_pool_check,
    ADD CONSTRAINT notary_admission_tickets_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'one_gb', 'ten_gb'));
ALTER TABLE notary_admission_leases
    DROP CONSTRAINT notary_admission_leases_access_pool_check,
    ADD CONSTRAINT notary_admission_leases_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'one_gb', 'ten_gb'));

-- Monthly capture and notarization allowances are deliberately separate.
-- Supplemental purchases are always notarization credits.
ALTER TABLE notary_credit_grants
    ADD COLUMN credit_kind TEXT NOT NULL
        CHECK (credit_kind IN ('capture', 'notarization'));

ALTER TABLE notary_credit_debits
    ADD COLUMN credit_kind TEXT NOT NULL
        CHECK (credit_kind IN ('capture', 'notarization'));
ALTER TABLE notary_credit_debits
    DROP CONSTRAINT notary_credit_debits_allowance_bytes_check,
    ADD CONSTRAINT notary_credit_debits_allowance_bytes_check
        CHECK (allowance_bytes >= 0);
ALTER TABLE notary_credit_debits
    DROP CONSTRAINT notary_credit_debits_credit_subject_record_digest_key,
    ADD CONSTRAINT notary_credit_debits_subject_kind_digest_key
        UNIQUE (credit_subject, credit_kind, record_digest);

CREATE INDEX notary_credit_grants_subject_kind_available_idx
    ON notary_credit_grants (credit_subject, credit_kind, available_at, expires_at);
CREATE INDEX notary_credit_debits_subject_kind_created_idx
    ON notary_credit_debits (credit_subject, credit_kind, created_at DESC);

-- Capture sessions reserve their per-session ceiling when admitted, then
-- settle to the authenticated TLS application-data byte count on release.
ALTER TABLE notary_admission_tickets
    ADD COLUMN settled_allowance_bytes BIGINT CHECK (
        settled_allowance_bytes >= 0
        AND settled_allowance_bytes <= requested_allowance_bytes
    );

-- Stripe Checkout sessions for recurring plans are separate from one-time
-- credit purchases so webhook reconciliation cannot confuse the two products.
CREATE TABLE billing_subscription_checkouts (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_idempotency_key TEXT NOT NULL CHECK (
        octet_length(client_idempotency_key) BETWEEN 1 AND 128
    ),
    target_plan TEXT NOT NULL CHECK (target_plan IN ('one_gb', 'ten_gb')),
    state TEXT NOT NULL CHECK (
        state IN ('creating', 'checkout_open', 'completed', 'expired')
    ),
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    provider_price_id TEXT NOT NULL CHECK (octet_length(provider_price_id) BETWEEN 1 AND 255),
    provider_checkout_session_id TEXT UNIQUE,
    provider_customer_id TEXT,
    provider_subscription_id TEXT,
    livemode BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (account_id, client_idempotency_key)
);

CREATE TABLE billing_subscriptions (
    provider_subscription_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    provider_customer_id TEXT NOT NULL,
    provider_price_id TEXT NOT NULL,
    service_plan TEXT NOT NULL CHECK (service_plan IN ('one_gb', 'ten_gb')),
    status TEXT NOT NULL CHECK (
        status IN (
            'trialing', 'active', 'past_due', 'paused', 'unpaid',
            'canceled', 'incomplete', 'incomplete_expired'
        )
    ),
    livemode BOOLEAN NOT NULL,
    current_period_end BIGINT,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX billing_subscription_checkouts_account_created_idx
    ON billing_subscription_checkouts (account_id, created_at DESC, id DESC);
CREATE INDEX billing_subscriptions_status_updated_idx
    ON billing_subscriptions (status, updated_at);
CREATE INDEX billing_subscriptions_account_updated_idx
    ON billing_subscriptions (account_id, updated_at DESC);
CREATE UNIQUE INDEX billing_subscriptions_one_current_account_idx
    ON billing_subscriptions (account_id)
    WHERE status NOT IN ('canceled', 'incomplete_expired');

-- Recurring invoice disputes are separate from one-time credit purchase
-- disputes. Keeping each Stripe dispute lets webhook retries and multiple
-- billing periods reconcile without a lossy boolean on the subscription.
CREATE TABLE billing_subscription_disputes (
    provider_dispute_id TEXT PRIMARY KEY NOT NULL,
    provider_subscription_id TEXT NOT NULL
        REFERENCES billing_subscriptions(provider_subscription_id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_charge_id TEXT NOT NULL,
    amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
    currency TEXT NOT NULL CHECK (currency = 'usd'),
    active BOOLEAN NOT NULL,
    livemode BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX billing_subscription_disputes_account_active_idx
    ON billing_subscription_disputes (account_id, active)
    WHERE active;
