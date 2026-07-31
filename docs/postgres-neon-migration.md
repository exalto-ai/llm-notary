# PostgreSQL / Neon migration runbook

This runbook moves the API's durable state from the legacy SQLite volume to a
shared PostgreSQL database. It is a maintenance operation: do not run the old
SQLite-backed API and the PostgreSQL-backed API against the public site at the
same time.

## Prepare the Neon database

Create a Neon project or production branch in the API's region. Copy both URLs
from the Neon console, retain `sslmode=require`, and keep them only in the
deployment secret store:

- Set `DATABASE_URL` to the **pooled** URL for normal API replicas.
- The schema migrator accepts either Neon URL. Prefer the **direct
  (non-pooled)** URL for this one-off administrative command when it is
  available, and keep it out of the long-lived API configuration.

SQLx protects migrations with a PostgreSQL advisory lock. Neon’s pooler supports
this migrator, but the migrator remains separate from API startup so that only
an explicitly invoked process can change schema. Budget at least the number of
API replicas times `LLM_NOTARY_DATABASE_MAX_CONNECTIONS`, plus the connection
used by the migrator.

On Fly, stage the pooled URL without committing it. `--stage` avoids restarting
the still-SQLite-backed Machine; the secret is applied by the subsequent API
deployment:

```bash
fly secrets set --stage DATABASE_URL='postgresql://…?sslmode=require' \
  -a llm-notary-prod-api
```

For Compose, set the same value in the root-owned
`deploy/digitalocean/deploy.env` file. The checked-in example deliberately uses
a non-working hostname and credentials. Neon URLs commonly include the
libpq-specific `channel_binding=require` parameter. SQLx does not implement
that parameter, so omit it from the stored URL while retaining
`sslmode=require` to avoid a harmless startup warning.

## Migrate schema and data

1. Schedule a maintenance window and stop the API replicas. Preserve the
   platform signing key, notary directory, and the `api_data` Docker volume
   (or its SQLite file) before changing anything. The signing key must not
   change.
2. Run the included schema migrator once against an empty target database. Use
   the direct (non-pooled) URL when available; the pooled URL is also supported:

   ```bash
   DATABASE_URL='postgresql://…?sslmode=require' \
     cargo run --no-default-features --features api --bin llm-notary-api-migrate
   ```

   The migrator uses PostgreSQL's advisory migration lock, so concurrent
   invocations serialize. It is deliberately separate from API startup: normal
   replicas use the pooled URL and never run migrations.
3. Copy application rows from the SQLite backup into the already-migrated
   PostgreSQL schema using a tested data-only importer. Copy every application
   table except `_sqlx_migrations`; that bookkeeping table contains SQLite
   migration checksums and must be created by `llm-notary-api-migrate` in the
   target. Preserve all identifiers, token hashes, object keys, timestamps,
   and platform metadata exactly. After copying generated identity values,
   reset the `publication_activity_events` and `library_metadata_usage`
   sequences to their imported maxima. Do not copy credentials, `.llmbundle`
   files, or any bucket data: those are outside the database migration.
4. Before routing traffic, compare row counts for every copied table and sample
   admitted publications. For each sample, verify that the database object
   keys, sizes, and SHA-256 values match the private object store. Confirm a
   website session and a CLI refresh-token rotation still work.
5. Start one PostgreSQL-backed API replica and wait for `GET /api/readyz` to
   return 200. Then start the remaining replicas and restore public traffic.

Keep the SQLite backup read-only until the new deployment has completed a
normal publication and an admission retry. A rollback means stopping the
PostgreSQL-backed replicas and restoring the old API with that untouched volume;
never attempt bidirectional writes.

## Scale after cutover

Every API replica serves HTTP and runs cleanup, admission, and metadata work.
Publication and metadata claims are coordinated in PostgreSQL, so replicas do
not process the same claimed item concurrently. The deployment keeps each
replica's database pool at five connections by default; adjust replicas before
raising pool size.

Fly keeps two API Machines running. Add capacity with:

```bash
fly scale count 3 -a llm-notary-prod-api
```

For a same-host Compose deployment, use:

```bash
docker compose --env-file deploy/digitalocean/deploy.env up -d --scale api=3
```

Watch readiness, API error rate, queued-admission age, and Neon connection
usage during the change. If database availability drops, `/api/readyz` fails
and Fly removes the affected Machine from service; do not rely on `/api/healthz`
for database readiness.
