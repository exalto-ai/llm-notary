ALTER TABLE llm_notary_daemon.captures
    ADD COLUMN expected_artifact_size_bytes BIGINT CHECK (expected_artifact_size_bytes >= 0),
    ADD COLUMN expected_artifact_sha256 TEXT CHECK (
        expected_artifact_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT capture_artifact_expectation_complete CHECK (
        (expected_artifact_size_bytes IS NULL) = (expected_artifact_sha256 IS NULL)
    );
