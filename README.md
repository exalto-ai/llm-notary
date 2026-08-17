# LLM Notary monorepo

LLM Notary creates selectively disclosed, independently verifiable evidence for model-provider HTTP exchanges. This private monorepo owns both the publishable runtime and Exalto's hosted product.

## Repository boundary

- [`runtime/`](runtime/README.md) is the complete public runtime: `notaryd`, the thin `llm-notary` REST client, the generic remote notary, protocol/evidence contracts, local dashboard, updater, documentation, CI, and pinned TLSNotary sources. It builds on its own and is the only tree projected into the public runtime repository.
- `platform/crates/notary-api` owns accounts, credits, billing, uploads, sharing, and the hosted HTTP API.
- `platform/crates/notary-server-platform-adapter` injects private platform admission and usage settlement policy into the generic runtime notary.
- `platform/migrations` contains forward-only hosted database migrations.
- `js/app` is the public website and hosted dashboard; `js/desktop` is the private native wrapper around `notaryd`.
- `deploy`, `compose.yml`, and the root `Dockerfile` define Exalto's hosted deployment.

The public runtime must never import the platform, website, desktop wrapper, billing, account, or hosted-admission trees. Enforce that boundary with:

```bash
runtime/tooling/check-boundary.sh
```

## Validate

```bash
cargo fmt --check
cargo test -p notary-api -p notary-server-platform-adapter --all-targets --all-features
cargo test --manifest-path runtime/Cargo.toml --workspace --all-targets --all-features
npm --prefix runtime/apps/local-dashboard run build
npm --prefix js/app run build
npm --prefix runtime/apps/local-dashboard run check:local-docs
```

See [private documentation](docs/README.md) and [runtime documentation](runtime/docs/README.md).
