-- Account deletion removes both sides of immutable credit allocations. The
-- allocation rows carry no independent account value and must follow their
-- owning debit or grant instead of blocking the user cascade.
ALTER TABLE notary_credit_debit_allocations
    DROP CONSTRAINT notary_credit_debit_allocations_debit_id_fkey,
    ADD CONSTRAINT notary_credit_debit_allocations_debit_id_fkey
        FOREIGN KEY (debit_id) REFERENCES notary_credit_debits(id) ON DELETE CASCADE,
    DROP CONSTRAINT notary_credit_debit_allocations_grant_id_fkey,
    ADD CONSTRAINT notary_credit_debit_allocations_grant_id_fkey
        FOREIGN KEY (grant_id) REFERENCES notary_credit_grants(id) ON DELETE CASCADE;
