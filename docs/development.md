# Development and validation

This guide covers repository layout, generated contracts, test tiers, and the
documentation update rules that protect LLM Notary's trust boundaries.

## Workspace map

| Path | Responsibility |
| --- | --- |
| `crates/llm-notary-core/` | Proxy-TLS protocol, bundle and package contracts, normalization, trust directory, verification |
| `crates/llm-notary-client/` | local daemon, proxy, catalog, vault integration, REST API, embedded dashboard, command client |
| `crates/llm-notary-server/` | remote notary protocol and capacity enforcement |
| `crates/llm-notary-platform/` | hosted API, identity, admission tickets, session sharing, verification, Library, PostgreSQL |
| `js/app/` | public Vite/React SPA and local dashboard source |
| `migrations-postgres/` | forward-only hosted schema migrations |
| `vendor/tlsn/` | pinned, locally patched TLSNotary dependency |
| `vendor/tlsn-utils/` | pinned parser-stack patch used by TLSNotary formats |
| `compose.yml`, `deploy/`, `.github/workflows/` | containers, production deployment, and CI |

Treat `vendor/` as third-party code. Change it only when the protocol requires
the patch, keep the diff narrow, and explain the divergence in the corresponding
vendor README or change description.

## Toolchains

- Rust is pinned to 1.95.0.
- The JavaScript CI uses Node.js 24 and `npm ci`.
- PostgreSQL integration tests use disposable PostgreSQL 17.7 containers.
- Dashboard screenshot generation uses Playwright Chromium.

Install JavaScript dependencies only when working on the site, dashboard,
generated API clients, or their documentation:

```bash
npm --prefix js/app ci
```

## Generated API contracts

Both Rust routers generate OpenAPI 3.1. The TypeScript clients are generated
from committed contract copies.

```bash
npm --prefix js/app run generate:local-api
npm --prefix js/app run generate:platform-api
```

Use the check forms in CI or before review:

```bash
npm --prefix js/app run check:local-api
npm --prefix js/app run check:platform-api
```

Do not hand-edit files under either `generated/` directory. When a route,
method, status, field, or authentication rule changes, update the Rust schema,
regenerate the contract and client, then update prose examples in the same
change.

## Required checks

Run the checks relevant to edited code:

```bash
cargo fmt --check
cargo clippy \
  -p llm-notary-core \
  -p llm-notary-client \
  -p llm-notary-server \
  -p llm-notary-platform \
  --all-targets --all-features -- -D warnings
cargo test \
  -p llm-notary-core \
  -p llm-notary-client \
  -p llm-notary-server \
  -p llm-notary-platform \
  --all-targets --all-features
npm --prefix js/app run build
npm --prefix js/app run test:dashboard
npm --prefix js/app run test:site
npm --prefix js/app run check:local-docs
```

Ordinary tests must remain deterministic and offline. They do not need a
provider credential, hosted account, production notary, or external database.

## Optional integration and profile tests

The PostgreSQL-backed API tests need a running Docker daemon and create their
own disposable database:

```bash
cargo test -p llm-notary-platform \
  new_cli_session_is_usable_until_its_refresh_expiry -- --ignored
cargo test -p llm-notary-platform \
  web_users_can_list_and_revoke_only_their_cli_sessions -- --ignored
cargo test -p llm-notary-platform \
  service_admission::tests -- --ignored
```

Large proof and real-provider checks are opt-in. The
`proxy_tls_split_profile` test measures the production split process against a
separate notary container without making a billable inference. Use
`--profile-sessions` only in an isolated Linux cgroup with one measured session
at a time.

## Container validation

For Compose or deployment changes, run the digest-resolution test and validate
Compose with placeholder secrets. Never use real credentials in a validation
command that can enter logs or shell history.

```bash
bash deploy/fly/test-resolve-image-digest.sh
docker compose --env-file /path/to/placeholder.env config --quiet
```

## Documentation sources

Keep each surface focused:

- `README.md` is the short project entry point.
- `docs/` contains durable user, reference, operator, and contributor guides.
- `js/app/src/main.jsx` contains the shorter public-site documentation journey.
- `js/app/public/llms.txt` is the machine-readable public documentation index.
- generated OpenAPI is the exact route and schema authority.
- `AGENTS.md` contains repository constraints for coding agents.
- `DESIGN.md` contains the UI language and content rules.

When behavior changes, update every affected surface. In particular:

| Change | Documentation that must move with it |
| --- | --- |
| CLI command or exit code | README quick path, local-service guide, agent playbook, public docs |
| REST route or schema | OpenAPI annotations, generated clients, local-service guide, contract check |
| Artifact or disclosure rule | core producer and verifier, artifact guide, architecture, share admission |
| Notary trust policy | architecture, key lifecycle, local service, hosted public copy |
| Deployment or migration order | Fly guide, database guide, workflow comments |
| Dashboard workflow | dashboard guide, screenshots, fixture, browser tests |

Run the documentation contract check after prose changes:

```bash
node js/app/scripts/check-local-docs.mjs
```

It checks local API coverage, contract terms, screenshot references, obsolete
commands, relative links, and exact trailing newlines.

## Dashboard screenshots

Committed dashboard images use synthetic fixtures and a fixed clock. Regenerate
them only after a dashboard change:

```bash
npx --prefix js/app playwright install chromium
npm --prefix js/app run capture:dashboard-docs
npm --prefix js/app run check:local-docs
```

Review every generated image for sensitive data and layout regressions before
committing it.

## Sensitive data

Never commit or log:

- provider credentials or cookie values;
- notary private keys or admission service tokens;
- database URLs, presigned storage URLs, or `.env` files;
- `.llmcapture` files, vault keys, decrypted checkpoints, or raw captures; or
- request and response bodies from real users.

Fixtures must be synthetic and deterministic. Errors, events, metrics, and
operational spans use bounded safe codes and metadata only.

## Release state

There are no GitHub Releases or immutable semantic-version releases yet.
After the normal production deployment succeeds, client-affecting changes on
`main` build macOS, Linux, and Windows archives and their SHA-256 files. The
publisher uploads one immutable build directory, verifies every public object,
and moves `cli/v0.1/current` last. The website installer supports macOS and
Linux and resolves that moving pointer.

Keep the download bucket separate from private capture intake. Never expose
its upload credential to a deployed application. SHA-256 files share the same
publisher as their archives and must be described as corruption checks, not
independent release authentication.
