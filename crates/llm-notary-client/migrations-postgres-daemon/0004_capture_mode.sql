CREATE TABLE llm_notary_daemon.daemon_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    capture_enabled BOOLEAN NOT NULL
);

INSERT INTO llm_notary_daemon.daemon_settings (singleton, capture_enabled)
VALUES (TRUE, TRUE);
