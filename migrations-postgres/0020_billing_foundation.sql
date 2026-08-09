-- Production billing state is separate from the rollback-only service_plan
-- column restored by migration 0010. A missing row remains the Free plan.
CREATE TABLE account_billing_profiles (
    account_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_plan TEXT NOT NULL CHECK (service_plan IN ('free', 'paid')),
    billing_status TEXT NOT NULL CHECK (billing_status IN ('active', 'review')),
    updated_at BIGINT NOT NULL
);

CREATE TABLE billing_purchases (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_idempotency_key TEXT NOT NULL CHECK (
        octet_length(client_idempotency_key) BETWEEN 1 AND 128
    ),
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    state TEXT NOT NULL CHECK (
        state IN ('creating', 'checkout_open', 'paid', 'failed', 'refunded', 'disputed')
    ),
    currency TEXT NOT NULL CHECK (currency = 'usd'),
    unit_amount_cents BIGINT NOT NULL CHECK (unit_amount_cents > 0),
    quantity_gb BIGINT NOT NULL CHECK (quantity_gb BETWEEN 1 AND 20),
    credit_bytes BIGINT NOT NULL CHECK (credit_bytes > 0),
    expected_amount_cents BIGINT NOT NULL CHECK (expected_amount_cents > 0),
    provider_price_id TEXT NOT NULL CHECK (octet_length(provider_price_id) BETWEEN 1 AND 255),
    provider_checkout_session_id TEXT UNIQUE,
    provider_payment_intent_id TEXT UNIQUE,
    provider_charge_id TEXT UNIQUE,
    provider_dispute_id TEXT UNIQUE,
    provider_customer_id TEXT,
    livemode BOOLEAN NOT NULL,
    amount_paid_cents BIGINT NOT NULL DEFAULT 0 CHECK (amount_paid_cents >= 0),
    amount_refunded_cents BIGINT NOT NULL DEFAULT 0 CHECK (amount_refunded_cents >= 0),
    amount_disputed_cents BIGINT NOT NULL DEFAULT 0 CHECK (amount_disputed_cents >= 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    paid_at BIGINT,
    CHECK (expected_amount_cents = unit_amount_cents * quantity_gb),
    CHECK (credit_bytes = 1000000000::BIGINT * quantity_gb),
    CHECK (amount_refunded_cents <= amount_paid_cents),
    CHECK (amount_disputed_cents <= amount_paid_cents),
    CHECK (amount_refunded_cents + amount_disputed_cents <= amount_paid_cents),
    UNIQUE (account_id, client_idempotency_key)
);

CREATE INDEX billing_purchases_account_created_idx
    ON billing_purchases (account_id, created_at DESC, id DESC);
CREATE INDEX billing_purchases_state_updated_idx
    ON billing_purchases (state, updated_at);

-- Store safe provider references and processing outcomes only. Raw webhook
-- bodies, signatures, payment methods, and customer PII are never retained.
CREATE TABLE billing_provider_events (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'stripe'),
    event_type TEXT NOT NULL CHECK (octet_length(event_type) BETWEEN 1 AND 120),
    object_id TEXT CHECK (octet_length(object_id) BETWEEN 1 AND 255),
    livemode BOOLEAN NOT NULL,
    provider_created_at BIGINT NOT NULL,
    received_at BIGINT NOT NULL,
    processed_at BIGINT,
    outcome TEXT CHECK (outcome IN ('processed', 'ignored', 'rejected')),
    error_code TEXT CHECK (octet_length(error_code) BETWEEN 1 AND 120)
);

CREATE INDEX billing_provider_events_received_idx
    ON billing_provider_events (received_at DESC);

-- Refunds and disputes are signed, append-only changes to an account's
-- usable balance. They do not rewrite grants or debit allocations.
CREATE TABLE notary_credit_adjustments (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purchase_id TEXT NOT NULL REFERENCES billing_purchases(id) ON DELETE CASCADE,
    amount_bytes BIGINT NOT NULL CHECK (amount_bytes <> 0),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('purchase_refund', 'purchase_dispute', 'dispute_reinstatement')
    ),
    source_reference TEXT NOT NULL CHECK (octet_length(source_reference) BETWEEN 1 AND 256),
    idempotency_key TEXT NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    display_label TEXT NOT NULL CHECK (octet_length(display_label) BETWEEN 1 AND 120),
    created_at BIGINT NOT NULL,
    CHECK (credit_subject = 'user:' || account_id),
    UNIQUE (credit_subject, source_kind, source_reference),
    UNIQUE (credit_subject, idempotency_key)
);

CREATE INDEX notary_credit_adjustments_account_history_idx
    ON notary_credit_adjustments (account_id, created_at DESC, id DESC);

-- A successful explicit service-failure settlement is represented as a new
-- non-expiring grant, keeping both the original debit and restoration visible.
ALTER TABLE notary_credit_grants
    DROP CONSTRAINT notary_credit_grants_source_kind_check,
    ADD CONSTRAINT notary_credit_grants_source_kind_check CHECK (
        source_kind IN (
            'included_monthly',
            'promotion',
            'manual_adjustment',
            'external_purchase',
            'service_refund'
        )
    );

ALTER TABLE notary_admission_tickets
    DROP CONSTRAINT notary_admission_tickets_access_pool_check,
    ADD CONSTRAINT notary_admission_tickets_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'paid', 'paid_preview'));
ALTER TABLE notary_admission_leases
    DROP CONSTRAINT notary_admission_leases_access_pool_check,
    ADD CONSTRAINT notary_admission_leases_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'paid', 'paid_preview')),
    ADD COLUMN completion_outcome TEXT CHECK (
        completion_outcome IN ('completed', 'client_failed', 'service_failed')
    );
