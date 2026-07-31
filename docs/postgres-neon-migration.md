# PostgreSQL / Neon cutover runbook

The API uses PostgreSQL exclusively. This cutover intentionally starts with an
empty database; it does not import the retired SQLite volume. Keep the existing
volume untouched until the new release has been stable, but do not run or
maintain a SQLite-backed API or data importer.

## Provision and configure Neon

Create a Neon project in the API region and obtain its pooled connection URL.
Store it only in the deployment secret store as `DATABASE_URL`. Retain
`sslmode=require`; remove Neon's optional `channel_binding=require` parameter,
which SQLx does not use. The pooled URL is correct for both the API and the
migrator.

Budget the total of `LLM_NOTARY_DATABASE_MAX_CONNECTIONS` across API replicas,
plus one transient migration connection, within the Neon plan's limit. The
production configuration uses two API Machines with a five-connection pool per
Machine.

For Fly, stage the secret before merging. This records it without restarting
the current API release:

```bash
fly secrets set --stage DATABASE_URL='postgresql://…?sslmode=require' \
  -a llm-notary-prod-api
```

For Compose, put the same value in the root-owned
`deploy/digitalocean/deploy.env` file. Never commit a connection URL, a signing
key, a capture, or a `.env` file.

## Deploy the clean baseline

`migrations-postgres/0001_initial.sql` is the single baseline for this
unshipped database. Fly runs `llm-notary-api-migrate` as the API release command
before replacing any API Machines. SQLx takes an advisory migration lock, and
a migration failure stops the release while the previous Machines continue
serving traffic.

1. Preserve the platform signing key, notary directory, and existing `api_data`
   volume as rollback evidence. Do not generate new signing material.
2. Merge the release. The normal Fly deploy invokes the release command against
   the staged pooled `DATABASE_URL`; no database secret belongs in GitHub.
3. Confirm the release command created exactly the baseline migration and that
   two Machines become healthy:

   ```bash
   fly status -a llm-notary-prod-api
   curl --fail https://llm-notary.exalto.ai/api/readyz
   ```

4. Exercise GitHub sign-in, CLI refresh-token rotation, and one complete
   publication/admission cycle. Confirm the public object keys, sizes, and
   SHA-256 values match their private objects.

The current PostgreSQL schema history may be flattened because no production
PostgreSQL data is being preserved. After this cutover, never alter
`0001_initial.sql`: future PostgreSQL schema changes must be new, forward-only
migration files.

For source development or a Compose deployment, run the same migrator once
before starting or scaling API replicas:

```bash
DATABASE_URL='postgresql://…?sslmode=require' \
  cargo run --no-default-features --features api --bin llm-notary-api-migrate
```

## Scale and monitor

Every API replica serves HTTP and runs cleanup, admission, and metadata work.
PostgreSQL coordinates claims with row locking and `SKIP LOCKED`, so replicas
do not process a claimed job concurrently.

Fly keeps two API Machines running. Add capacity only after confirming the Neon
connection budget:

```bash
fly scale count 3 -a llm-notary-prod-api
```

For a same-host Compose deployment:

```bash
docker compose --env-file deploy/digitalocean/deploy.env up -d --scale api=3
```

Watch `/api/readyz`, API error rate, queued-admission age, and Neon connection
usage. If PostgreSQL becomes unavailable, readiness fails and Fly removes the
affected Machine from service; `/api/healthz` alone is not a database check.
