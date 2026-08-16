# Development and validation

This guide covers repository layout, generated contracts, test tiers, and the
documentation update rules that protect LLM Notary's trust boundaries.

## Workspace map

| Path | Responsibility |
| --- | --- |
| `runtime/` | self-contained public Cargo/frontend workspace, docs, tests, containers, and vendored dependencies |
| `runtime/crates/llm-notary-daemon/` | local proxy, catalog, vault integration, REST API, clustered operation, and embedded dashboard |
| `runtime/crates/llm-notary-cli/` | thin localhost REST command client |
| `runtime/crates/llm-notary-updater/` | signed-update verification shared by CLI and desktop |
| `runtime/crates/llm-notary-core/` | Proxy-TLS protocol, evidence contracts, normalization, trust directory, and verification |
| `runtime/crates/llm-notary-server/` | coordinator-free remote notary runtime and generic admission/lifecycle seam |
| `runtime/apps/local-dashboard/` | independently locked dashboard source, generated local API, tests, and assets |
| `platform/crates/llm-notary-hosted-server/` | private hosted ticket redemption, durable usage outbox, and settlement adapter |
| `platform/crates/llm-notary-api/` | hosted API, identity, admission tickets, sharing, verification, Library, and billing |
| `platform/migrations/` | forward-only hosted schema migrations |
| `js/app/` | private platform website |
| `compose.yml`, `deploy/`, `.github/workflows/` | containers, production deployment, and CI |

Treat `runtime/vendor/` as third-party code. Change it only when the protocol requires
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
npm --prefix runtime/apps/local-dashboard ci
```

## Generated API contracts

Both Rust routers generate OpenAPI 3.1. The TypeScript clients are generated
from committed contract copies.

```bash
npm --prefix runtime/apps/local-dashboard run generate:api
npm --prefix js/app run generate:platform-api
```

Use the check forms in CI or before review:

```bash
npm --prefix runtime/apps/local-dashboard run check:api
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
cargo fmt --manifest-path runtime/Cargo.toml --check \
  -p llm-notary-core -p llm-notary-daemon -p llm-notary-cli \
  -p llm-notary-updater -p llm-notary-server
cargo clippy \
  -p llm-notary-api \
  -p llm-notary-hosted-server \
  --all-targets --all-features -- -D warnings
cargo clippy --manifest-path runtime/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
cargo test \
  -p llm-notary-api \
  -p llm-notary-hosted-server \
  --all-targets --all-features
cargo test --manifest-path runtime/Cargo.toml \
  --workspace --all-targets --all-features
npm --prefix runtime/apps/local-dashboard run build
npm --prefix js/app run build
npm --prefix runtime/apps/local-dashboard run test
npm --prefix js/app run test:site
npm --prefix js/app run check:local-docs
```

Ordinary tests must remain deterministic and offline. They do not need a
provider credential, hosted account, production notary, or external database.

## Optional integration and profile tests

The PostgreSQL-backed API tests need a running Docker daemon and create their
own disposable database:

```bash
cargo test -p llm-notary-api \
  new_cli_session_is_usable_until_its_refresh_expiry -- --ignored
cargo test -p llm-notary-api \
  web_users_can_list_and_revoke_only_their_cli_sessions -- --ignored
cargo test -p llm-notary-api \
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

Run the complete local-daemon persistence test with no arguments:

```bash
runtime/test-daemon-persistence-e2e.sh
```

Pass `smoke` for the shorter recovery check. The explicit matrix form remains
available to CI and later storage backends:

```bash
runtime/test-daemon-persistence-e2e.sh smoke
runtime/test-daemon-persistence-e2e.sh sqlite filesystem 1 full
runtime/test-daemon-persistence-e2e.sh sqlite s3 1 smoke
runtime/test-daemon-persistence-e2e.sh sqlite s3 1 full
runtime/test-daemon-persistence-e2e.sh postgres filesystem 1 smoke
runtime/test-daemon-persistence-e2e.sh postgres filesystem 1 full
runtime/test-daemon-persistence-e2e.sh postgres s3 1 smoke
runtime/test-daemon-persistence-e2e.sh postgres s3 1 full
runtime/test-daemon-persistence-e2e.sh postgres s3 2 full
```

The smoke test builds and launches the real `llm-notaryd` and `llm-notary`
binaries in Docker without publishing either loopback listener. It initializes
the vault and schema, checks `/healthz`, and runs the REST-backed command client.
It then uses deterministic synthetic rows and deliberately invalid encrypted
checkpoint bytes to exercise filesystem recovery, catalog search/detail,
finalization enqueue and bounded failure history, events, SQLite integrity,
and preservation of exact artifact bytes after the daemon container is removed
and recreated with its durable volume.

The S3 entries add pinned MinIO server and client containers, create a bucket
inside the Compose project's disposable volume, and use explicit synthetic
credentials. The generated daemon configuration enables path-style access and
the fixed `daemon-e2e/artifacts` prefix; insecure HTTP is enabled only for this
internal MinIO endpoint. The harness verifies that deferred bundles and
finalized packages use the configured prefix and private namespace, survive
daemon recreation, and complete the same capture, list/detail, finalization,
download, verification, and exact-byte sharing path as filesystem storage.
Both ordinary JSON responses and OpenAI-style SSE streaming responses traverse
the real proxy/notary fixture, produce finalized packages, and upload those
exact verified bytes to a loopback-only hosted-share fixture with a synthetic
API key.

The two-replica row uses PostgreSQL 17 and MinIO behind a health-aware Caddy
frontend with retries and buffering disabled. It verifies distinct replica
incarnations, cross-replica dashboard sessions, fenced finalization ownership,
cross-replica capture/package access, and safe peer removal.

S3 recovery coverage includes a metadata row whose object is missing, a
same-size object whose digest does not match its metadata, and a package that
was published before the daemon was killed but whose metadata transaction was
not completed. The first two must fail closed; retrying the last case must
reuse the exact immutable object. The harness also stops MinIO beneath the
running daemon and checks that `/healthz` remains live while `/readyz` and
`/v1/status` return `503`, then verifies readiness recovery. Object-size
rejection and a conflicting same-key write are exercised by the artifact-store
tests rather than this daemon harness because the public daemon API does not
expose a safe way to inject either condition. Do not substitute a
successful-looking fixture for those remaining end-to-end cases.

At the end of every matrix row the harness stops the daemon and runs the
shipped `reconcile-artifacts` command. Filesystem rows must report every
reference verified. S3 rows must inventory the complete managed prefix and
report the deliberately corrupt reference without printing keys or deleting
objects.

The PostgreSQL entries launch `postgres:17.7-alpine` with a project-scoped data
volume and run the shipped daemon's one-shot `migrate` subcommand before
starting the service. The harness proves that runtime refuses an unmigrated
schema and an unavailable database, applies the migration twice to check
idempotency, and then runs the same REST, restart, artifact, and full Proxy-TLS
assertions as SQLite. It also stops PostgreSQL beneath a running daemon and
checks that `/healthz` remains live, `/readyz` returns `503`, and readiness
recovers after the database restarts. Runtime receives only
`LLM_NOTARY_METADATA_DATABASE_URL`; the one-shot migrator receives only
`LLM_NOTARY_METADATA_MIGRATION_URL`. The daemon never applies PostgreSQL schema
changes during normal service startup.

Set `DAEMON_E2E_POSTGRES_SCENARIOS=extended` on a PostgreSQL matrix entry to
also run two migrators concurrently and hold the migration advisory lock long
enough to verify the configured lock timeout. Database names, roles, and
passwords in this Compose file are fixed synthetic fixtures on an internal-only
network. This fixture explicitly sets `ssl_mode = "disable"`; production keeps
the secure TLS default. Never reuse these settings outside the disposable E2E
project.

The full profile also creates an ephemeral private CA and provider certificate
inside the Compose project's disposable volume, starts a TLS provider on the
`api.openai.com` Docker network alias, and starts the feature-gated raw notary
fixture. It exercises a successful Proxy-TLS capture, REST-backed list and
detail, finalization, exact package download, daemon and file verification, and
package recovery after container recreation. The provider request and response
are fixed synthetic JSON and no external provider is contacted.

The full profile also pauses one finalization immediately after immutable
package publication, kills the daemon, and checks that startup marks the first
attempt interrupted. Retrying must reuse the exact package inode and SHA-256,
produce one completion event, and finalize a second attempt without replacing
the orphaned bytes.

The private root hook is compiled only into the `daemon-e2e` image and is used
only when `LLM_NOTARY_DAEMON_E2E_ROOT_CA_DER` explicitly names a regular DER
file. The production `daemon` image is built without that feature, ignores the
E2E variable, retains Mozilla/WebPKI roots, and keeps the fixed provider
allowlist. The generated CA private key and captured artifacts live only in the
unique Compose project and are deleted with its volumes. The request uses a
fixed, clearly synthetic test credential; never substitute a real key.

## Frontend source and embedded output

The public SPA is split by domain under `js/app/src/site/`, with
`js/app/src/main.tsx` as the application shell and router. Keep the public docs
as structured, task-focused site content rather than treating the deeper
repository guides as runtime Markdown. The audiences and navigation are
different; `check-local-docs.mjs` enforces consistency for commands, routes,
security boundaries, and other high-risk claims across both surfaces.

`crates/llm-notary-client/dashboard/` is intentionally committed build output.
`llm-notaryd` embeds that directory with `RustEmbed`, while source installs,
release builds, and desktop sidecar builds can invoke Cargo without Node. Do not
delete or ignore the directory unless every Rust build path is first replaced
with a deterministic asset-generation step. After changing the local dashboard,
run `npm --prefix js/app run build` to regenerate the embedded files; do not edit
them by hand.

## Documentation sources

Keep each surface focused:

- `README.md` is the short project entry point.
- `docs/` contains durable user, reference, operator, and contributor guides.
- `js/app/src/site/PublicDocs.tsx` contains the shorter public-site documentation journey.
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
`main` build Apple silicon macOS, Linux, and Windows clients. Every published
binary carries the same build ID: the commit SHA, GitHub Actions run ID, and run
attempt joined with hyphens. The publisher uploads raw command-line binaries,
archives, the DMG, and the signed macOS updater bundle to one immutable build
directory, then verifies each public object before moving a channel pointer.

`cli/channels/latest.json` is the canonical pointer. It is a signed envelope
whose exact payload identifies an immutable `release.json` by URL, SHA-256,
build ID, and detached Minisign signature. It also carries a monotonically
increasing channel revision allocated as one more than the currently published,
authenticated revision. Clients
persist the highest authenticated revision they have accepted and reject a
replay or conflicting reuse. A first installation still relies on HTTPS and
the download-bucket access policy for freshness; after first contact, bucket
credentials alone cannot select an older signed release. The manifest in turn
binds every installable payload to an immutable URL, byte size, and SHA-256
value. The legacy text `cli/latest` pointer remains available for older
installers, but the JSON pointer is moved last. The two mutable objects cannot
move atomically, so new clients must treat the JSON pointer as the source of
truth.

The macOS updater bundle also has the independent signature required by Tauri.
Apple Developer ID signing and notarization protect the installed application;
the Tauri signature protects the updater payload; and the signed release
manifest authenticates the release selected by command-line clients. An
authorized channel update may intentionally point to any differently identified
signed build, including an older build, but it must use a new signed channel
revision. A storage or CDN writer without the release signing key cannot
authorize that rollback.

Keep the download bucket separate from private capture intake. Never expose
its upload credential to a deployed application. SHA-256 files by themselves
are corruption checks, not independent release authentication.

The updater's long-lived private key and password live only in the protected
`macos-release` GitHub environment as `TAURI_SIGNING_PRIVATE_KEY` and
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. The matching public key is committed at
`runtime/config/updater-public-key.txt`. Back up the private key outside GitHub: losing
it prevents installed clients from accepting future updates. Rotate it only
through a release signed by the old key that also teaches clients the new key.
