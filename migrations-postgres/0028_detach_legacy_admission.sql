-- Detach the one-operation runtime from the legacy lease schema without
-- invalidating the immediately previous stop-legacy API image. That image
-- writes `requested_allowance_bytes`; the new image writes
-- `authenticated_allowance_bytes` directly. The temporary trigger mirrors the
-- finalization allowance in either direction so both writers remain safe
-- during rollout and rollback.
--
-- Remove this bridge, the legacy ticket columns, lease table, and debit digest
-- compatibility under https://github.com/exalto-ai/notary/issues/298 only
-- after this release is the immediately previous production image.
ALTER TABLE notary_admission_tickets
    ALTER COLUMN authenticated_allowance_bytes DROP EXPRESSION,
    ALTER COLUMN requested_allowance_bytes DROP NOT NULL;

CREATE FUNCTION notary_admission_ticket_allowance_bridge()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.mode = 'finalize' THEN
        IF NEW.authenticated_allowance_bytes IS NULL THEN
            NEW.authenticated_allowance_bytes := NEW.requested_allowance_bytes;
        ELSIF NEW.requested_allowance_bytes IS NULL THEN
            NEW.requested_allowance_bytes := NEW.authenticated_allowance_bytes;
        ELSIF NEW.authenticated_allowance_bytes <> NEW.requested_allowance_bytes THEN
            RAISE EXCEPTION 'finalization allowance columns must match'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER notary_admission_tickets_allowance_bridge
BEFORE INSERT OR UPDATE OF mode, requested_allowance_bytes,
    authenticated_allowance_bytes
ON notary_admission_tickets
FOR EACH ROW
EXECUTE FUNCTION notary_admission_ticket_allowance_bridge();

-- Operation settlement is keyed by the unique operation ID. Keep the legacy
-- digest column and uniqueness constraint writable for the rollback image,
-- while allowing the detached runtime to omit its synthetic compatibility
-- digest. PostgreSQL uniqueness treats NULL values as distinct.
ALTER TABLE notary_credit_debits
    ALTER COLUMN record_digest DROP NOT NULL;
