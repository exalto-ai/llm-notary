# Contributing to LLM Notary

LLM Notary is a pre-release security-sensitive prototype. Keep changes small,
make trust claims no broader than the verifier, and update affected contracts
and documentation together.

Before changing code, read:

- [Architecture and trust model](docs/architecture.md)
- [Development and validation](docs/development.md)
- [Repository agent guide](AGENTS.md)
- [Design language](DESIGN.md) for UI work

The local proxy handles credentials and plaintext; the remote notary must not.
Never add sensitive values to logs, metrics, errors, fixtures, screenshots, or
Git history. Never write a deferred `.llmcapture` without vault encryption.

Run the checks relevant to the files you changed. The full validation set is
documented in [Development and validation](docs/development.md#required-checks).
Real-provider, PostgreSQL-container, and large-proof profiles are explicit
opt-in checks; ordinary tests remain deterministic and offline.

Use a normal pull request for one independent change. Use `gh stack` for two or
more dependent pull requests, ordered from the foundational change upward, as
described in [AGENTS.md](AGENTS.md#stacked-pull-requests).

LLM Notary is dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE),
at your option.
