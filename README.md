# Notary

**Notary by Exalto** creates selectively disclosed, independently verifiable evidence for model-provider HTTP exchanges. The local proxy handles provider plaintext and credentials; the remote notary witnesses the authenticated TLS session without receiving either, so a notarized `.llmtrace` package is verifiable against the notary's public key by anyone.

A **Trace** is the evidence primitive. A trace is **Captured** while only its private `.llmcapture` checkpoint exists, and becomes **Notarized** once notarization commits a portable `.llmtrace` package. Sharing is a separate explicit action on a notarized trace.

## Components

| Component | Tree | Responsibility |
| --- | --- | --- |
| `notaryd` | [`runtime/crates/notaryd`](runtime/crates/notaryd) | Provider proxy, vault, trace/artifact store, notarization orchestrator, admin API, embedded dashboard |
| `notaryctl` | [`runtime/crates/notaryctl`](runtime/crates/notaryctl) | Thin human/script/agent client for the `notaryd` administration API |
| `notary-server` | [`runtime/crates/notary-server`](runtime/crates/notary-server) | Generic, coordinator-free, self-hostable remote Proxy-TLS notary |
| `notary-app` | [`apps/notary-app`](apps/notary-app) | Desktop application that bundles and supervises `notaryd` |
| `notary-api` | [`platform/crates/notary-api`](platform/crates/notary-api) | Hosted accounts, credits, billing, uploads, sharing, verification, and Registry |

## Repository boundary

This private monorepo owns both the publishable runtime and Exalto's hosted product.

- [`runtime/`](runtime/README.md) is the complete public runtime: `notaryd`, the thin `notaryctl` REST client, the generic remote notary, protocol/evidence contracts, local dashboard, updater, documentation, CI, and pinned TLSNotary sources. It builds on its own and is the only tree projected into the public runtime repository.
- `platform/crates/notary-api` owns accounts, credits, billing, uploads, sharing, and the hosted HTTP API.
- `platform/crates/notary-server-platform-adapter` injects private platform admission and usage settlement policy into the generic runtime notary.
- `platform/migrations` contains forward-only hosted database migrations.
- `platform/web` is the public website and hosted Account frontend; `apps/notary-app` is the private native wrapper around `notaryd`.
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
npm --prefix runtime/apps/admin-dashboard run build
npm --prefix platform/web run build
npm --prefix runtime/apps/admin-dashboard run check:local-docs
node scripts/check-terminology.mjs
```

See [private documentation](docs/README.md) and [runtime documentation](runtime/docs/README.md).
