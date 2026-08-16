-- Add the one-operation finalization binding without removing the immediately
-- previous lease schema. Production deploys the backward-compatible notary
-- before this API migration, so the prior API remains usable throughout the
-- mixed-version rollout and rollback window.
--
-- `requested_allowance_bytes` and `notary_admission_leases` are temporary
-- rollback scaffolding. The one-operation API stores only a policy ceiling in
-- the legacy capture field and never reads it as an account-balance grant.
-- Remove both compatibility paths under https://github.com/exalto-ai/notary/issues/298.
ALTER TABLE notary_admission_tickets
    ADD COLUMN authenticated_allowance_bytes BIGINT GENERATED ALWAYS AS (
        CASE WHEN mode = 'finalize' THEN requested_allowance_bytes ELSE NULL END
    ) STORED;

ALTER TABLE notary_admission_tickets
    ADD CONSTRAINT notary_admission_tickets_authenticated_allowance_check CHECK (
        (mode = 'capture' AND authenticated_allowance_bytes IS NULL)
        OR (mode = 'finalize' AND authenticated_allowance_bytes > 0)
    );
