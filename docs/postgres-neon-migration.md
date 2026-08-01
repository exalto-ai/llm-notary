# PostgreSQL / Neon deployment operations

The API uses PostgreSQL exclusively. This guide covers ongoing PostgreSQL/Neon
deployment, schema-migration, scaling, and rollback operations. SQLite is no
longer a supported API backend and no SQLite importer is maintained.

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
Machine.

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

`migrations-postgres/0001_initial.sql` is the PostgreSQL baseline. Do not alter
it: future PostgreSQL schema changes must be new, forward-only migration files.
Fly runs `llm-notary-api-migrate` as the API release command before replacing
any API Machines. Compose runs the same one-shot `migrate` service before it
starts API replicas. SQLx takes an advisory migration lock. The migrator uses a
60-second PostgreSQL lock timeout so contention fails clearly instead of
consuming the entire deploy timeout; a migration failure stops the new API
replicas from starting.

1. Preserve the platform signing key and notary directory as rollback evidence.
   Do not generate new signing material.
2. Confirm both staged secrets exist, then merge the release. The normal Fly
   deploy invokes the release command against the direct
   `DATABASE_MIGRATIONS_URL`; no database secret belongs in GitHub.
3. Confirm the release command applied pending migrations and that two Machines
   become healthy:

   ```bash
   fly status -a llm-notary-prod-api
   curl --fail https://llm-notary.exalto.ai/api/readyz
   ```

4. Exercise GitHub sign-in, CLI refresh-token rotation, and one complete
   publication/admission cycle. Confirm the public object keys, sizes, and
   SHA-256 values match their private objects.

For source development, run the same migrator before starting the API:

```bash
DATABASE_MIGRATIONS_URL='postgresql://…?sslmode=require' \
cargo run -p llm-notary-platform --bin llm-notary-api-migrate
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
