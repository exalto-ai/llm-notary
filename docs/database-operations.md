# PostgreSQL and Neon operations

The hosted platform API uses PostgreSQL exclusively. The local daemon uses
SQLite by default and can be configured with a separate PostgreSQL schema.
These schemas and migrators are intentionally independent; never point one
migrator at the other's migration journal.

## Provision and configure Neon

Create a Neon project in the API region and obtain both its pooled and direct
connection URLs. Store them only in the deployment secret store:

- `DATABASE_URL` is the pooled URL used by API replicas.
- `DATABASE_MIGRATIONS_URL` is the direct URL used only by the migrator.

Retain `sslmode=require`; remove Neon's optional `channel_binding=require`
parameter, which SQLx does not use. SQLx migrations use a session advisory
lock, which Neon’s transaction-mode pooler does not support, so the migrator
must never use the pooled URL.

Budget the total of `LLM_NOTARY_DATABASE_MAX_CONNECTIONS` across API replicas,
plus one transient migration connection, within the Neon plan's limit. The
production configuration uses two API Machines with a five-connection pool per
Machine, so reserve ten pooled connections plus one direct migration
connection.

For Fly, stage the secret before merging. This records it without restarting
the current API release:

```bash
fly secrets set --stage \
  DATABASE_URL='postgresql://…-pooler…?sslmode=require' \
  DATABASE_MIGRATIONS_URL='postgresql://…?sslmode=require' \
  -a llm-notary-prod-api
```

For a self-hosted Compose deployment, put both values in a root-owned
environment file outside the repository, such as `/etc/llm-notary/compose.env`.
For a direct local PostgreSQL instance, the two values can be the same. Pass
that exact path with `docker compose --env-file`; never commit a connection
URL, signing key, capture, or environment file.

## Deploy schema migrations

`platform/migrations/0001_initial.sql` is the PostgreSQL baseline. Do not alter
an applied migration: schema changes must use new, forward-only migration files.
Fly runs `llm-notary-api-migrate` as the API release command before replacing
any API Machines. Compose runs the same one-shot `migrate` service before it
starts API replicas. SQLx takes an advisory migration lock. The migrator uses a
60-second PostgreSQL lock timeout so contention fails clearly instead of
consuming the entire deploy timeout; a migration failure stops the new API
replicas from starting.

Production rollback restores the previous API image without rerunning that
older image's release command. Every migration must therefore leave the
immediately previous API usable. Add new tables, columns, or indexes before
requiring them; stop old code from using obsolete schema in a later release;
and remove obsolete schema only after at least one further successful release.
A migration that cannot meet this expand/contract sequence needs a separately
reviewed, staged rollout and recovery procedure before it is merged.

1. Preserve the notary signing key and published notary directory so existing
   evidence keeps the same trust history. Do not generate new signing material.
2. Confirm both staged secrets exist, then merge the release. The normal Fly
   deploy invokes the release command against the direct
   `DATABASE_MIGRATIONS_URL`; no database secret belongs in GitHub.
3. Confirm the release command applied pending migrations and that two Machines
   become healthy:

   ```bash
   fly status -a llm-notary-prod-api
   curl --fail https://notary.exalto.ai/api/readyz
   ```

4. Exercise each configured sign-in provider, local-service refresh-token rotation, and one complete
   share-admission cycle. Confirm the admitted trace and exact-package object keys,
   sizes, and SHA-256 values match their private objects.

For source development, run the same migrator before starting the API:

```bash
DATABASE_MIGRATIONS_URL='postgresql://…?sslmode=require' \
cargo run -p llm-notary-api --bin llm-notary-api-migrate
```

## Operate a PostgreSQL-backed local daemon

The local daemon migrations live under
`runtime/crates/llm-notary-daemon/migrations-postgres-daemon/`, use the
`llm_notary_daemon` schema and migration journal, and take a daemon-specific
advisory lock. They do not use the hosted platform's `platform/migrations/`
directory or SQLx migration journal.

Select `catalog.backend = "postgres"` and supply
`LLM_NOTARY_METADATA_DATABASE_URL` (or its `_FILE` form), then run:

```bash
llm-notaryd migrate --config /etc/llm-notary/config.toml
llm-notaryd --config /etc/llm-notary/config.toml
```

By default the migrate command uses the same URL. For least-privilege
deployments, give the runtime role only data access and override migrations
with `LLM_NOTARY_METADATA_MIGRATION_URL` or its `_FILE` form.

Keep `catalog.postgres.ssl_mode = "verify_full"` for remote databases and
provide the CA settings required by the PostgreSQL URL. `require` encrypts but
does not validate the server hostname. `disable` is only for an explicitly
trusted local test server.

Running the migrator again is safe. Concurrent migrators serialize on the
daemon advisory lock and fail after the configured lock timeout instead of
waiting indefinitely. The runtime validates the exact schema version but does
not apply migrations.

Use separate login roles for migration and runtime. The migrator creates the
schema as its owner, rejects an existing schema owned by another role, and
revokes public schema access. After the first migration, an administrator can
grant the runtime role only the access it needs (replace the example role
names with provisioned roles):

```sql
GRANT CONNECT ON DATABASE llm_notary TO llm_notary_daemon_runtime;
GRANT USAGE ON SCHEMA llm_notary_daemon TO llm_notary_daemon_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES
  IN SCHEMA llm_notary_daemon TO llm_notary_daemon_runtime;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES
  IN SCHEMA llm_notary_daemon TO llm_notary_daemon_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE llm_notary_daemon_migrator
  IN SCHEMA llm_notary_daemon
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO llm_notary_daemon_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE llm_notary_daemon_migrator
  IN SCHEMA llm_notary_daemon
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO llm_notary_daemon_runtime;
```

The runtime role must not own the schema or have `CREATE`/DDL privileges.

Backups must capture both sides of persistence: the daemon PostgreSQL schema
contains metadata, operation/event history, artifact locators and searchable
plaintext previews; the selected filesystem directories or private S3 prefix
contain the vault-encrypted checkpoints and finalized packages. To obtain a
mutually consistent point in this single-daemon release, stop the daemon after
confirming no capture or finalization is running, snapshot both stores, then
restart it. For S3, enable object versioning or use a provider snapshot that can
restore the complete managed prefix to the same point. After a restore, verify
every advertised artifact locator, size, and SHA-256 before serving traffic by
running `llm-notaryd reconcile-artifacts --config <path>` while the daemon is
stopped. Resolve every reported finding. The command is report-only and never
deletes objects. No
SQLite-to-PostgreSQL or filesystem-to-S3 importer is provided.

Keep the sum of `catalog.postgres.max_connections` across running daemons plus
one direct migrator connection within the provider's pool budget. PostgreSQL
with filesystem artifacts remains single-process. Multiple daemon replicas are
supported only by server mode with PostgreSQL and S3; see
[Cluster operations](../runtime/docs/cluster-operations.md).

## Scale and monitor

Every API replica serves HTTP and runs cleanup and admission work.
PostgreSQL coordinates claims with row locking and `SKIP LOCKED`, so replicas
do not process a claimed job concurrently.

Fly keeps both production API Machines running continuously. This avoids API
cold starts and lets cleanup and admission workers process due work without
waiting for an incoming request. The web Machine is also always running; the
notary Machine remains suspendable because its durable operation state and
usage outbox are designed for that lifecycle. Add API capacity only after
confirming the Neon connection budget:

```bash
fly scale count 3 -a llm-notary-prod-api
```

For a same-host Compose deployment, the `migrate` service is a required API
dependency. It applies pending migrations before any API replica starts. Deploy
with the root-owned environment file outside the repository:

```bash
docker compose --env-file /etc/llm-notary/compose.env up -d --scale api=3
```

If a deployment tool updates an image without recreating services, include its
equivalent of `--force-recreate migrate api` so the one-shot service runs the
new image before the API is replaced.

Watch `/api/readyz`, API error rate, queued-admission age, and Neon connection
usage. If PostgreSQL becomes unavailable, readiness fails and Fly removes the
affected Machine from service; `/api/healthz` alone is not a database check.
