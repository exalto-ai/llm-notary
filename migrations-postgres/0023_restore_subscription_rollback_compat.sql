-- Migration 0022 split the capture and notarization ledgers, but the previous
-- API image omits credit_kind from its inserts. Keep that rollback image
-- usable until it leaves the production rollback window. New images always
-- write the column explicitly. Cleanup is tracked in issue #271.
ALTER TABLE notary_credit_grants
    ALTER COLUMN credit_kind SET DEFAULT 'notarization';

ALTER TABLE notary_credit_debits
    ALTER COLUMN credit_kind SET DEFAULT 'notarization';
