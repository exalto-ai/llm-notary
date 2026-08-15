-- Every image remaining in the production rollback window writes credit_kind
-- explicitly. Remove the temporary defaults that allowed the pre-subscription
-- API image to omit the column.
ALTER TABLE notary_credit_grants
    ALTER COLUMN credit_kind DROP DEFAULT;

ALTER TABLE notary_credit_debits
    ALTER COLUMN credit_kind DROP DEFAULT;
