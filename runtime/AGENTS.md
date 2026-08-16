# LLM Notary runtime agent guide

- `crates/llm-notary-core` owns protocol and evidence contracts.
- `crates/llm-notary-daemon` is the local proxy/API daemon and supports optional PostgreSQL/S3 clustering.
- `crates/llm-notary-cli` is a thin REST client for the daemon.
- `crates/llm-notary-server` is the generic remote notary.
- `crates/llm-notary-updater` owns signed release updates.
- `apps/local-dashboard` is the daemon's embedded dashboard.

The local proxy handles plaintext and credentials; a remote notary must never receive either. Never log provider credentials. A deferred `.llmcapture` contains an encrypted checkpoint capable of reconstructing the original request and must only be written with vault encryption.

Run `./tooling/check-boundary.sh`, `cargo fmt --check -p llm-notary-core -p llm-notary-daemon -p llm-notary-cli -p llm-notary-updater -p llm-notary-server`, `cargo test --workspace --all-targets --all-features`, and `npm --prefix apps/local-dashboard run build` for changes that affect the corresponding code.
