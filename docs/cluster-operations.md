# Run LLM Notary on a server

Server mode runs the same daemon behind HTTPS with PostgreSQL for metadata and
S3-compatible private object storage. It is safe to run more than one daemon
replica, but replica leases, fencing tokens, and recovery timings are internal
defaults rather than setup tasks.

Desktop and local CLI users do not need this mode. Their existing loopback,
SQLite, filesystem, and OS-vault setup remains the default.

## Fastest setup: one server, two replicas

The bundled Compose deployment includes two daemon replicas, PostgreSQL,
MinIO, and Caddy with automatic HTTPS. You need:

- Docker with `docker compose`;
- an unprivileged account allowed to use Docker (do not run setup with
  `sudo`);
- two DNS names pointing at the server, one for provider traffic and one for
  the dashboard; and
- an LLM Notary API key.

From a checkout of this repository, run:

```bash
scripts/llm-notary-server.sh init proxy.notary.example admin.notary.example
scripts/llm-notary-server.sh up
```

`init` privately prompts for the API key, generates all other secrets, writes
the short server configuration under `.llm-notary-server/`, and prints the one
generated dashboard password. It never overwrites an existing setup. For
automation, pass the API key only for the initialization process:

```bash
LLM_NOTARY_BOOTSTRAP_API_KEY='llmn_v1_...' \
  scripts/llm-notary-server.sh init proxy.notary.example admin.notary.example
```

Open `https://admin.notary.example` and sign in as `admin` with the printed
password. Point provider SDKs at the other origin while leaving the provider
credential in the SDK:

```text
https://proxy.notary.example/openai/v1
https://proxy.notary.example/anthropic
https://proxy.notary.example/deepseek
https://proxy.notary.example/openrouter/api/v1
```

The normal operator commands are deliberately small:

```bash
scripts/llm-notary-server.sh status
scripts/llm-notary-server.sh logs
scripts/llm-notary-server.sh down   # preserves database, objects, TLS, and secrets
```

Back up `.llm-notary-server/` and the named PostgreSQL, MinIO, and Caddy
volumes. The Compose bundle survives process and replica replacement, but all
state still lives on one host. Use managed PostgreSQL and S3 for host-level or
regional availability.

## The server configuration

The generated configuration exposes only the choices an application needs:

```toml
format = "llm-notary/agent-config/v1"

[server]
enabled = true
proxy_origin = "https://proxy.notary.example"
admin_origin = "https://admin.notary.example"

[proxy]
listen = "0.0.0.0:8787"

[admin]
listen = "0.0.0.0:8788"

[admin.auth]
username = "admin"

[catalog]
backend = "postgres"

[storage]
backend = "s3"
```

The PostgreSQL connection and migration URL, S3 credentials, hosted API key,
dashboard password, and vault key come from mounted secret files. The daemon
hashes the dashboard password in memory. A replica gets its readable instance
name from `LLM_NOTARY_SERVER_INSTANCE_ID` when set, otherwise from the
container hostname. Every process still receives a fresh boot identity.

The shared vault is one exact 32-byte file mounted as
`LLM_NOTARY_SERVER_VAULT_KEY_FILE`. There is no passphrase prompt, per-replica
salt, or digest to copy into TOML. The migration command pins a derived key
identity and the non-secret server configuration in PostgreSQL, so a replica
with the wrong key or storage namespace is rejected before serving traffic.
To prepare this key outside the Compose helper:

```bash
llm-notaryd server init --vault-key /run/secrets/server-vault.key
```

Existing experimental `[cluster]` configurations and verifier-backed
passphrase vaults remain readable for migration, but new deployments should
use `[server]` and the shared key file.

## External PostgreSQL and S3

For Kubernetes or multiple hosts, keep the same server configuration and
replace the bundled PostgreSQL and MinIO endpoints. Run one setup job before
the Deployment:

```bash
llm-notaryd --config /etc/llm-notary/config.toml migrate
```

Then run two or more identical daemon pods. Give every pod the same config,
database, S3 namespace, API key, dashboard password, and 32-byte vault key.
Replica names are automatic; set `LLM_NOTARY_SERVER_INSTANCE_ID` only when an
orchestrator does not provide a useful unique hostname.

The runtime secret variables are:

- `LLM_NOTARY_METADATA_DATABASE_URL_FILE` (an optional separate
  `LLM_NOTARY_METADATA_MIGRATION_URL_FILE` may use a more privileged setup
  role);
- `LLM_NOTARY_ARTIFACT_S3_ACCESS_KEY_ID_FILE` and
  `LLM_NOTARY_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE`;
- `LLM_NOTARY_API_KEY_FILE`;
- `LLM_NOTARY_ADMIN_PASSWORD_FILE`; and
- `LLM_NOTARY_SERVER_VAULT_KEY_FILE`.

Use HTTPS and hostname verification for external PostgreSQL/S3 services. The
insecure database and object-store endpoints in the Compose template are
allowed only because they stay on its private Docker network.

## Ingress, readiness, and shutdown

Keep provider and admin traffic on separate HTTPS origins. The provider proxy
must use HTTP/1.1 streaming and must not retry or replay a request. The bundled
Caddy configuration has those properties and removes replicas using
`GET /readyz`.

`GET /healthz` reports only process liveness. `GET /readyz` also checks the
replica lifecycle, PostgreSQL schema, S3 namespace, shared vault identity, and
shared notary trust. On SIGTERM a replica becomes unready before it stops
accepting work, then drains admitted streams within a bounded deadline.

PostgreSQL time, expiring ownership, and per-operation fence tokens prevent a
paused or stale replica from publishing after a peer takes over. S3 objects
are immutable and claim-scoped for the same reason. These rules are always on
in server mode and normally need no tuning.

The dashboard identifies the responding replica and shows the public server
origins, PostgreSQL/S3 status, lifecycle, and deployment-managed update state.
Sessions are shared through PostgreSQL as hashes, so sign-in and sign-out work
through a load balancer without sticky sessions.

## Backup and verification

Quiesce both replicas before taking a coordinated PostgreSQL and S3 backup.
Preserve the server vault key and PostgreSQL notary trust history with it.
After a restore, keep replicas stopped and run the report-only reconciliation:

```bash
llm-notaryd --config /etc/llm-notary/config.toml reconcile-artifacts
```

The disposable full validation remains:

```bash
scripts/test-daemon-persistence-e2e.sh postgres s3 2 full
```
