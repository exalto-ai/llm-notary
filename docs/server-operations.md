# Run LLM Notary on a server

Server mode runs plain-HTTP daemon replicas with PostgreSQL for metadata and
S3-compatible private object storage. Your load balancer or ingress owns the
public endpoints, TLS, certificates, and DNS. Replica leases, fencing tokens,
and recovery timings remain internal rather than becoming setup tasks.

Desktop and local CLI users do not need this mode. Their existing loopback,
SQLite, filesystem, and OS-vault setup remains the default.

## Reference Compose example

The bundled Compose file is a runnable single-host example, not the required
production topology. It defines one daemon service with two replicas, plus
PostgreSQL and MinIO. It deliberately does not include a load balancer, public
ports, or TLS termination.

In a real server deployment, translate the `daemon` service into the replicated
workload provided by your platform, such as a Kubernetes Deployment, an ECS
service, a Nomad job, or a Docker Swarm service. Use managed PostgreSQL and S3
when you need availability beyond one host.

To run the reference example as written, you need:

- Docker with `docker compose`;
- an unprivileged account allowed to use Docker (do not run setup with
  `sudo`);
- an operator-managed load balancer or ingress that can join the example's
  Docker network, with two DNS names—one for provider traffic and one for the
  dashboard; and
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

`up` starts the single `daemon` service with the replica count from
`SERVER_REPLICAS` (two by default). On the `llm-notary-server` Docker network,
the service is available as `daemon:8787` for provider traffic and
`daemon:8788` for administration and readiness. Configure your load balancer,
then open
`https://admin.notary.example` and sign in as `admin` with the printed
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
scripts/llm-notary-server.sh down   # preserves database, objects, and secrets
```

Back up `.llm-notary-server/` and the named PostgreSQL and MinIO volumes if you
use the example as written. It survives process and replica replacement, but
all state still lives on one host.

## The server configuration

The generated configuration exposes only the choices an application needs:

```toml
format = "llm-notary/agent-config/v1"

[server]
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

The two origins describe the public URLs owned by your ingress. They do not
make the daemon bind public ports, request certificates, or terminate TLS.

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

## External PostgreSQL and S3

For Kubernetes or another production scheduler, keep the same server
configuration and replace the bundled PostgreSQL and MinIO endpoints. Run one
setup job before the replicated daemon workload:

```bash
llm-notaryd migrate --config /etc/llm-notary/config.toml
```

Then run two or more identical daemon instances. Give every instance the same
config, database, S3 namespace, API key, dashboard password, and 32-byte vault
key. Replica names are automatic; set `LLM_NOTARY_SERVER_INSTANCE_ID` only when
an orchestrator does not provide a useful unique hostname.

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

## Operator-managed load balancing

Keep provider and admin traffic on separate public HTTPS origins. The daemon
backends themselves speak HTTP. Your provider pool must preserve HTTP/1.1
streaming and must not retry or replay requests. Your admin pool must preserve
authorization headers and dashboard cookies. Sticky sessions are unnecessary.

The reference Compose file intentionally publishes no host ports. A
containerized load balancer can join the `llm-notary-server` Docker network and
use `daemon:8787` and `daemon:8788`. Other platforms should expose the same two
container ports through their normal internal service discovery. The daemon
does not need to know which load balancer, ingress controller, or certificate
manager you use.

The reference uses the standard Compose replication shape:

```yaml
services:
  daemon:
    image: ...
    deploy:
      mode: replicated
      replicas: 2
```

Change `SERVER_REPLICAS` in `.llm-notary-server/.env` to scale the runnable
example. In a real deployment, change the replica count in your scheduler
instead.

Health-check each replica with `GET /readyz` on its admin port and remove an
unready replica from both pools. Do not use `/healthz` for load balancing.

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

Quiesce all replicas before taking a coordinated PostgreSQL and S3 backup.
Preserve the server vault key and PostgreSQL notary trust history with it.
After a restore, keep replicas stopped and run the report-only reconciliation:

```bash
llm-notaryd --config /etc/llm-notary/config.toml reconcile-artifacts
```

The disposable full validation remains:

```bash
scripts/test-daemon-persistence-e2e.sh postgres s3 2 full
```
