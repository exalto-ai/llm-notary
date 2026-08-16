-- Hosted accounts now have one Free access model. Normalize disposable
-- preview data before removing plan and per-session timeout concepts.
UPDATE notary_admission_tickets SET access_pool = 'free' WHERE access_pool = 'paid_preview';
UPDATE notary_admission_leases SET access_pool = 'free' WHERE access_pool = 'paid_preview';

ALTER TABLE notary_admission_tickets
    DROP CONSTRAINT notary_admission_tickets_access_pool_check,
    ADD CONSTRAINT notary_admission_tickets_access_pool_check
        CHECK (access_pool IN ('public', 'free')),
    DROP COLUMN session_timeout_secs;
ALTER TABLE notary_admission_leases
    DROP CONSTRAINT notary_admission_leases_access_pool_check,
    ADD CONSTRAINT notary_admission_leases_access_pool_check
        CHECK (access_pool IN ('public', 'free'));
ALTER TABLE users DROP COLUMN service_plan;

-- Keep the account foreign key separate from the opaque subject used for
-- admission and credits.
ALTER TABLE notary_admission_tickets ADD COLUMN credit_subject TEXT;
ALTER TABLE notary_admission_leases ADD COLUMN credit_subject TEXT;

UPDATE notary_admission_tickets
SET credit_subject = CASE
    WHEN subject_id IS NULL THEN 'public'
    ELSE 'user:' || subject_id
END;

UPDATE notary_admission_leases
SET credit_subject = CASE
    WHEN subject_id IS NULL THEN 'public'
    ELSE 'user:' || subject_id
END;

ALTER TABLE notary_admission_tickets ALTER COLUMN credit_subject SET NOT NULL;
ALTER TABLE notary_admission_leases ALTER COLUMN credit_subject SET NOT NULL;

CREATE TABLE notary_credit_grants (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    amount_bytes BIGINT NOT NULL CHECK (amount_bytes > 0),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'included_monthly',
            'promotion',
            'manual_adjustment',
            'external_purchase'
        )
    ),
    source_reference TEXT NOT NULL CHECK (octet_length(source_reference) BETWEEN 1 AND 256),
    idempotency_key TEXT NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 256),
    period_start BIGINT,
    period_end BIGINT,
    created_at BIGINT NOT NULL,
    available_at BIGINT NOT NULL,
    expires_at BIGINT,
    display_label TEXT CHECK (octet_length(display_label) <= 120),
    CHECK (expires_at IS NULL OR expires_at > available_at),
    CHECK (
        (source_kind = 'included_monthly' AND period_start IS NOT NULL AND period_end IS NOT NULL)
        OR (source_kind <> 'included_monthly' AND period_start IS NULL AND period_end IS NULL)
    ),
    UNIQUE (credit_subject, source_kind, source_reference),
    UNIQUE (credit_subject, idempotency_key)
);

CREATE INDEX notary_credit_grants_available_idx
    ON notary_credit_grants (credit_subject, available_at, expires_at);
CREATE INDEX notary_credit_grants_account_history_idx
    ON notary_credit_grants (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;

-- All existing prototype accounts receive the same non-expiring supplemental
-- grant. Runtime issuance uses this source reference for accounts created after
-- the migration and for idempotent repair on first use.
INSERT INTO notary_credit_grants
    (id, credit_subject, account_id, amount_bytes, source_kind,
     source_reference, idempotency_key, created_at, available_at, display_label)
SELECT 'testing-grant-' || id,
       'user:' || id,
       id,
       134217728,
       'manual_adjustment',
       'hosted-finalization-testing-v1',
       'hosted-finalization-testing-v1',
       EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT,
       EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT,
       'Automatic testing credits'
FROM users;

CREATE TABLE notary_credit_debits (
    id TEXT PRIMARY KEY NOT NULL,
    credit_subject TEXT NOT NULL CHECK (octet_length(credit_subject) BETWEEN 1 AND 160),
    account_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    record_digest TEXT NOT NULL CHECK (
        octet_length(record_digest) = 64 AND record_digest = lower(record_digest)
    ),
    allowance_bytes BIGINT NOT NULL CHECK (allowance_bytes > 0),
    created_at BIGINT NOT NULL,
    UNIQUE (credit_subject, record_digest)
);

CREATE INDEX notary_credit_debits_account_history_idx
    ON notary_credit_debits (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;

CREATE TABLE notary_credit_debit_allocations (
    debit_id TEXT NOT NULL REFERENCES notary_credit_debits(id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES notary_credit_grants(id) ON DELETE RESTRICT,
    amount_bytes BIGINT NOT NULL CHECK (amount_bytes > 0),
    allocation_order INTEGER NOT NULL CHECK (allocation_order >= 0),
    PRIMARY KEY (debit_id, grant_id),
    UNIQUE (debit_id, allocation_order)
);

CREATE INDEX notary_credit_debit_allocations_grant_idx
    ON notary_credit_debit_allocations (grant_id);

-- Preserve immutable digest idempotency before replacing the legacy ledger.
INSERT INTO notary_credit_debits
    (id, credit_subject, account_id, record_digest, allowance_bytes, created_at)
SELECT 'legacy-debit-' || id, budget_subject, account_id, record_digest,
       allowance_bytes, created_at
FROM notary_finalization_credit_ledger;

-- Materialize one deterministic included grant for each historical subject
-- and period. Authenticated balances receive the Free monthly ceiling minus
-- existing usage. The aggregate public subject is retained only as history;
-- new IP-derived subjects never reuse it.
WITH period_usage AS (
    SELECT ledger.budget_subject AS credit_subject,
           ledger.account_id,
           ledger.period_start,
           MIN(ledger.id) AS first_ledger_id,
           SUM(ledger.allowance_bytes)::BIGINT AS used_bytes
    FROM notary_finalization_credit_ledger AS ledger
    GROUP BY ledger.budget_subject, ledger.account_id, ledger.period_start
)
INSERT INTO notary_credit_grants
    (id, credit_subject, account_id, amount_bytes, source_kind,
     source_reference, idempotency_key, period_start, period_end,
     created_at, available_at, expires_at, display_label)
SELECT 'legacy-grant-' || first_ledger_id,
       credit_subject,
       account_id,
       CASE
           WHEN account_id IS NULL THEN used_bytes
           ELSE GREATEST(used_bytes, 536870912::BIGINT)
       END,
       'included_monthly',
       'legacy-monthly:' || period_start,
       'legacy-monthly:' || period_start,
       period_start,
       EXTRACT(EPOCH FROM (
           (date_trunc('month', to_timestamp(period_start) AT TIME ZONE 'UTC') + interval '1 month')
           AT TIME ZONE 'UTC'
       ))::BIGINT,
       period_start,
       period_start,
       EXTRACT(EPOCH FROM (
           (date_trunc('month', to_timestamp(period_start) AT TIME ZONE 'UTC') + interval '1 month')
           AT TIME ZONE 'UTC'
       ))::BIGINT,
       'Monthly included credits (migrated)'
FROM period_usage;

INSERT INTO notary_credit_debit_allocations
    (debit_id, grant_id, amount_bytes, allocation_order)
SELECT 'legacy-debit-' || ledger.id,
       grants.id,
       ledger.allowance_bytes,
       0
FROM notary_finalization_credit_ledger AS ledger
JOIN notary_credit_grants AS grants
  ON grants.credit_subject = ledger.budget_subject
 AND grants.source_kind = 'included_monthly'
 AND grants.source_reference = 'legacy-monthly:' || ledger.period_start;

DROP TABLE notary_finalization_credit_ledger;
