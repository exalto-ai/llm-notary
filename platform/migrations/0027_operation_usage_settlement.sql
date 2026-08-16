-- A redeemed admission creates one durable operation identity. Settlement is
-- independent of session lifetime and carries no raw ticket or account
-- credential over the service boundary.
CREATE TABLE notary_admission_operations (
    id TEXT PRIMARY KEY NOT NULL CHECK (octet_length(id) BETWEEN 1 AND 128),
    ticket_token_hash TEXT NOT NULL UNIQUE CHECK (octet_length(ticket_token_hash) = 64),
    notary_instance_id TEXT NOT NULL CHECK (
        octet_length(notary_instance_id) BETWEEN 1 AND 128
    ),
    subject_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    credit_subject TEXT NOT NULL CHECK (
        octet_length(credit_subject) BETWEEN 1 AND 160
    ),
    access_pool TEXT NOT NULL CHECK (
        access_pool IN ('public', 'free', 'one_gb', 'ten_gb')
    ),
    mode TEXT NOT NULL CHECK (mode IN ('capture', 'finalize')),
    record_digest TEXT,
    authenticated_allowance_bytes BIGINT,
    max_attestable_http_bytes BIGINT NOT NULL CHECK (max_attestable_http_bytes > 0),
    admitted_at BIGINT NOT NULL,
    terminal_outcome TEXT CHECK (
        terminal_outcome IN ('completed', 'client_failed', 'service_failed')
    ),
    settled_authenticated_bytes BIGINT CHECK (settled_authenticated_bytes >= 0),
    settled_at BIGINT,
    CHECK (
        (mode = 'capture' AND record_digest IS NULL
             AND authenticated_allowance_bytes IS NULL)
        OR (mode = 'finalize'
             AND octet_length(record_digest) = 64
             AND record_digest = lower(record_digest)
             AND authenticated_allowance_bytes > 0)
    ),
    CHECK (
        (terminal_outcome IS NULL
             AND settled_authenticated_bytes IS NULL
             AND settled_at IS NULL)
        OR (terminal_outcome IS NOT NULL
             AND settled_authenticated_bytes IS NOT NULL
             AND settled_at IS NOT NULL)
    )
);

CREATE INDEX notary_admission_operations_account_admitted_idx
    ON notary_admission_operations (subject_id, admitted_at DESC)
    WHERE subject_id IS NOT NULL;
CREATE INDEX notary_admission_operations_unsettled_idx
    ON notary_admission_operations (admitted_at)
    WHERE terminal_outcome IS NULL;

-- Usage is charged per admitted operation. Keep the legacy digest uniqueness
-- contract while the immediately previous API remains rollbackable. New
-- operation debits use an operation-derived synthetic digest, while the real
-- finalization digest remains on notary_admission_operations.
ALTER TABLE notary_credit_debits
    ADD COLUMN operation_id TEXT UNIQUE
        REFERENCES notary_admission_operations(id) ON DELETE CASCADE;

-- Overage allocations live on a dedicated zero-value grant rather than
-- inflating an included-monthly grant's used bytes. That keeps the debt intact
-- if the immediately previous API runs ensure_monthly_grant during rollback.
ALTER TABLE notary_credit_grants
    DROP CONSTRAINT notary_credit_grants_amount_bytes_check,
    DROP CONSTRAINT notary_credit_grants_source_kind_check,
    ADD CONSTRAINT notary_credit_grants_amount_bytes_check CHECK (
        (source_kind = 'operation_overage' AND amount_bytes = 0)
        OR (source_kind <> 'operation_overage' AND amount_bytes > 0)
    ),
    ADD CONSTRAINT notary_credit_grants_source_kind_check CHECK (
        source_kind IN (
            'included_monthly',
            'promotion',
            'manual_adjustment',
            'external_purchase',
            'service_refund',
            'operation_overage'
        )
    );
