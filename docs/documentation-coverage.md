# Documentation coverage checklist

Use this checklist for any cross-cutting documentation audit. The checked state
records the current baseline; reset every affected row in a behavioral pull
request and check it again only after the implementation, generated contract,
internal reference, and external user journey agree.

## Public runtime

- [x] Repository boundary and build: root and runtime READMEs explain the
  standalone `runtime/` workspace, public repository, toolchains, and boundary
  check.
- [x] Provider request routing: the getting-started and provider guides cover
  all five fixed routes, supported HTTP/1.1 clients, subscription-auth limits,
  streaming, redirects, and the explicit hostname allowlist.
- [x] Capture-on flow: architecture and artifact guides identify every
  plaintext holder, admission seam, deferred receipt, local preview, vault, and
  `.llmcapture` boundary.
- [x] Capture-off flow: architecture, service, dashboard, desktop, public site,
  and `llms.txt` agree that direct passthrough creates no evidence and is never
  an availability fallback.
- [x] Local configuration and persistence: the service guide covers generated
  config, loopback listeners, optional Basic auth, vault modes, preview policy,
  SQLite/filesystem defaults, PostgreSQL/S3 options, and report-only artifact
  reconciliation.
- [x] CLI and local REST API: the service guide, agent playbook, portable skill,
  dashboard, and generated local OpenAPI cover status, capture search,
  finalization, operations, verification, events, notary trust, account
  connection, sharing, updates, and exit behavior.
- [x] Deferred finalization: getting-started, architecture, dashboard, service,
  and artifact guides agree on asynchronous operations, deduplication,
  progress, interruption, retry, deterministic packaging, and source-capture
  retention.
- [x] Verification and evidence: architecture and artifact guides distinguish
  structural capture recovery, full `.llmtrace` verification, bare trace JSON,
  authenticated/derived/observed facts, disclosure, and non-guarantees.
- [x] Local dashboard: the dashboard guide and deterministic screenshots cover
  overview, capture inspection, finalization, verification, consented sharing,
  activity, settings, responsive navigation, themes, empty/error states, and
  account connection.
- [x] Agent integration: getting-started, provider setup, agent playbook, and
  portable skill agree on installation paths, `--metadata-only`, approval
  boundaries, secret handling, and live OpenAPI discovery.
- [x] Generic remote notary: runtime architecture, self-hosting, and key
  lifecycle cover signing keys, transport TLS, allowlists, capture/finalization
  capacity, lifecycle states, ticketless admission, and injected policy seams.
- [x] Clustered daemon: cluster, service, database, and dashboard guides cover
  PostgreSQL/S3, migrations, one shared vault key, replica identity, readiness,
  drain behavior, ingress, backup, restore, and reconciliation.
- [x] Client releases and updates: getting-started, desktop, development, and
  public copy distinguish the moving channel, signed manifest, checksums,
  desktop signatures, build identity, rollback semantics, and manual restart.

## Hosted product

- [x] Browser identity: hosted platform, identity ADR, public privacy copy, and
  generated OpenAPI cover configured Google/GitHub providers,
  provider-neutral identities, HttpOnly sessions, logout, and account deletion.
- [x] Device sessions and API keys: hosted platform, API-key guide, local
  service, dashboard, desktop, and generated contracts cover browser approval,
  polling, token rotation, revocation, scopes, and mutually exclusive daemon
  credential modes.
- [x] Admission and usage settlement: hosted platform, architecture, plans,
  deployment guide, and generated OpenAPI cover one-operation tickets, private
  redemption, limit intersection, record bindings, durable outbox settlement,
  idempotency, and failure behavior.
- [x] Plans, credits, subscriptions, and purchases: plan guide, public docs,
  pricing, account UI, Stripe operator steps, and contract agree on allowances,
  anonymous address scoping, billing states, additional notarization,
  promotions, refunds, disputes, and test/live modes.
- [x] Retention-free hosted verification: hosted platform, public docs, privacy
  copy, verifier UI, and contract agree on explicit upload, bounded processing,
  trusted directory verification, no share creation, no retained package, and
  no durable signed receipt.
- [x] Share intake and admission: hosted platform, intake and admission specs,
  local consent surfaces, public docs, and contract cover presigned private
  intake, size/digest completion, safety checks, cryptographic verification,
  exact-package retention, cleanup, Unlisted/Listed semantics, and force limits.
- [x] Public trace access: hosted platform, architecture, admission spec,
  public Traces/share UI, and contract distinguish rendered inspection from evidence
  export and cover passwords, expiry, stop sharing, discovery, reports, and
  cache policy.
- [x] Hosted deployment: Fly, database, development, and architecture guides
  cover the stable gateway, API/site/notary ownership, migration ordering,
  object storage, secrets, health/readiness, scaling, usage outbox, and signing
  key/directory preservation.
- [x] Desktop wrapper: desktop and provider guides cover five-stage onboarding,
  daemon supervision, capture control, Keychain/passphrase vaults, embedded
  loopback dashboard, client routing limits, signed updates, and lifecycle
  validation.

## Contributor contracts

- [x] Generated local OpenAPI matches its Rust router and every local operation
  is assigned to runtime workflow documentation by `check:local-docs`.
- [x] Generated hosted OpenAPI matches its Rust router and every hosted
  operation is assigned to [Hosted platform components and
  flows](hosted-platform.md) by the hosted documentation check.
- [x] Relative links, repository paths, obsolete command names, key trust
  claims, screenshots, and exact trailing newlines are checked automatically
  where practical.
- [x] Documentation ownership rules name every surface that must move with CLI,
  REST, artifact, trust, deployment, dashboard, hosted-flow, or repository
  boundary changes.
