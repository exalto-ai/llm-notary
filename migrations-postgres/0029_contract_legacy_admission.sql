-- The operation-only detach release (0028) is now the immediately previous
-- production image. It does not read or write any of this compatibility
-- surface, so both the current image and its rollback image remain valid after
-- this forward-only contract migration.
--
-- This completes https://github.com/exalto-ai/notary/issues/298.
DROP TRIGGER notary_admission_tickets_allowance_bridge
    ON notary_admission_tickets;
DROP FUNCTION notary_admission_ticket_allowance_bridge();

ALTER TABLE notary_admission_tickets
    DROP COLUMN settled_allowance_bytes,
    DROP COLUMN requested_allowance_bytes,
    DROP COLUMN consumed_by_instance,
    DROP COLUMN lease_id,
    DROP COLUMN credit_debit_id,
    DROP COLUMN credit_debit_refundable;

DROP TABLE notary_admission_leases;

ALTER TABLE notary_credit_debits
    DROP CONSTRAINT notary_credit_debits_subject_kind_digest_key,
    DROP COLUMN record_digest,
    DROP COLUMN retry_of_debit_id;
