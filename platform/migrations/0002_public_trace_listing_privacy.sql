DROP INDEX notary_api.traces_listed_page_idx;
DROP INDEX notary_api.traces_listed_provider_page_idx;

CREATE INDEX traces_listed_page_idx
    ON notary_api.traces (
        (CASE WHEN access_password_hash IS NULL THEN verified_at ELSE 0 END) DESC,
        trace_id DESC
    )
    WHERE status = 'shared' AND visibility = 'listed';

CREATE INDEX traces_listed_provider_page_idx
    ON notary_api.traces (
        provider,
        (CASE WHEN access_password_hash IS NULL THEN verified_at ELSE 0 END) DESC,
        trace_id DESC
    )
    WHERE status = 'shared' AND visibility = 'listed';
