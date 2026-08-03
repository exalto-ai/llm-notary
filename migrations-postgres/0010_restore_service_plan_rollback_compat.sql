-- Migration 0009 removed this column in the same release that stopped using
-- it. Restore it temporarily so the previous API image remains usable after
-- a deployment rollback. Current code does not read or write this column.
--
-- IF NOT EXISTS lets operators apply this repair immediately; the normal
-- SQLx migration runner can subsequently record the migration checksum.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS service_plan TEXT NOT NULL DEFAULT 'free'
        CHECK (service_plan IN ('free', 'paid_preview'));

-- The previous API writes this value explicitly. The default only keeps
-- inserts from the current API compatible while the column exists.
ALTER TABLE notary_admission_tickets
    ADD COLUMN IF NOT EXISTS session_timeout_secs BIGINT NOT NULL DEFAULT 900
        CHECK (session_timeout_secs > 0);

ALTER TABLE notary_admission_tickets
    DROP CONSTRAINT IF EXISTS notary_admission_tickets_access_pool_check,
    ADD CONSTRAINT notary_admission_tickets_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'paid_preview'));
ALTER TABLE notary_admission_leases
    DROP CONSTRAINT IF EXISTS notary_admission_leases_access_pool_check,
    ADD CONSTRAINT notary_admission_leases_access_pool_check
        CHECK (access_pool IN ('public', 'free', 'paid_preview'));

-- Old images do not send credit_subject. Fill only missing values so current
-- images retain their IP-scoped anonymous subjects.
CREATE OR REPLACE FUNCTION populate_legacy_credit_subject()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.credit_subject IS NULL THEN
        NEW.credit_subject := CASE
            WHEN NEW.subject_id IS NULL THEN 'public'
            ELSE 'user:' || NEW.subject_id
        END;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS notary_admission_tickets_legacy_credit_subject
    ON notary_admission_tickets;
CREATE TRIGGER notary_admission_tickets_legacy_credit_subject
BEFORE INSERT ON notary_admission_tickets
FOR EACH ROW EXECUTE FUNCTION populate_legacy_credit_subject();

DROP TRIGGER IF EXISTS notary_admission_leases_legacy_credit_subject
    ON notary_admission_leases;
CREATE TRIGGER notary_admission_leases_legacy_credit_subject
BEFORE INSERT ON notary_admission_leases
FOR EACH ROW EXECUTE FUNCTION populate_legacy_credit_subject();

-- Keep the legacy balance reads used by the previous API on the authoritative
-- credit ledger. This view is intentionally read-only: an old image must not
-- create debits that the current credit allocator cannot see after roll-forward.
CREATE OR REPLACE VIEW notary_finalization_credit_ledger AS
SELECT row_number() OVER (ORDER BY debits.id)::BIGINT AS id,
       debits.credit_subject AS budget_subject,
       debits.account_id,
       debits.record_digest,
       debits.allowance_bytes,
       COALESCE(
           MIN(grants.period_start),
           EXTRACT(EPOCH FROM (
               date_trunc('month', to_timestamp(debits.created_at) AT TIME ZONE 'UTC')
               AT TIME ZONE 'UTC'
           ))::BIGINT
       ) AS period_start,
       debits.created_at
FROM notary_credit_debits AS debits
JOIN notary_credit_debit_allocations AS allocations
  ON allocations.debit_id = debits.id
JOIN notary_credit_grants AS grants
  ON grants.id = allocations.grant_id
GROUP BY debits.id;
