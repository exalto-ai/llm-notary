# Multi-replica daemon operations

Cluster mode runs two or more `llm-notaryd` replicas against one PostgreSQL
schema and one private S3 namespace. It is explicit: selecting PostgreSQL and
S3 does not enable cluster behavior. Local mode remains the default.

## Required shared state

Every replica must use:

- the same migrated PostgreSQL database;
- the same S3 bucket, prefix, region, endpoint profile, and credentials;
- the same pre-provisioned passphrase vault files and passphrase secret;
- either the same explicit notary endpoint and public key, or the shared
  PostgreSQL-backed hosted notary directory;
- the same injected hosted API key; and
- a distinct, stable `cluster.instance_id`.

The process creates a fresh incarnation ID at every start. PostgreSQL uses the
stable instance ID, incarnation ID, expiring lease, and a new fence token for
each capture or finalization claim. A stale replica cannot publish progress or
complete work after another replica has recovered the claim. Artifact objects
are also claim-scoped, so a stale S3 writer cannot overwrite the winning
object before its metadata transaction is rejected.

An explicit self-hosted notary trust anchor remains available. If `[notary]`
is omitted, replicas fetch the authenticated hosted directory and merge it
transactionally into PostgreSQL. Lower generations and same-generation digest
conflicts are rejected, removed keys remain available as retired history, and
revocation cannot be undone by a later directory response. Verification and
finalization use one validated database snapshot rather than a replica-local
cache.

## Provision the vault

Initialize one passphrase vault before starting any replica. Run the command
with the same `XDG_CONFIG_HOME` that the replicas will mount and a private
passphrase file:

```bash
export XDG_CONFIG_HOME=/srv/llm-notary/config
export LLM_NOTARY_VAULT_PASSPHRASE_FILE=/run/secrets/vault-passphrase
llm-notaryd vault-init-passphrase
llm-notaryd vault-compatibility
```

Put the printed 64-character digest in
`cluster.vault_compatibility_sha256`. It identifies the exact vault
configuration and verifier, not merely the passphrase. Mount the vault config
and key-check read-only into every runtime replica. Cluster startup never
prompts, initializes, or adopts the first replica's vault material.

## Configure each replica

Use an explicit configuration file. The cluster additions below sit alongside
the PostgreSQL and S3 settings documented in [Local service and REST
API](local-service.md):

```toml
format = "llm-notary/agent-config/v1"

[cluster]
enabled = true
instance_id = "daemon-a" # unique and stable for this replica slot
heartbeat_interval_seconds = 5
lease_seconds = 20
claim_max_runtime_seconds = 3600
withdrawal_delay_seconds = 8
shutdown_grace_seconds = 120
trusted_ingress = true
vault_compatibility_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[proxy]
listen = "0.0.0.0:8787"

[admin]
listen = "0.0.0.0:8788"

[admin.auth]
username = "cluster-admin"
password_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."

# Optional for a self-hosted notary. Omit both fields to use the shared hosted
# directory stored in PostgreSQL.
[notary]
endpoint = "tcp://notary.internal:7047"
public_key = "02..."

[catalog]
backend = "postgres"

[catalog.postgres]
ssl_mode = "verify_full"

[storage]
backend = "s3"

[storage.s3]
bucket = "llm-notary-private"
region = "us-east-1"
endpoint = "https://s3.example.com"
prefix = "production/daemon"
force_path_style = false
allow_insecure_http = false
```

Supply database URLs, S3 credentials, the vault passphrase file, and exactly
one of `LLM_NOTARY_API_KEY` or `LLM_NOTARY_API_KEY_FILE` through the documented
secret environment variables. Cluster validation rejects SQLite, filesystem
artifact writes, missing admin authentication, insecure S3, inconsistent
notary configuration, desktop child-process control, and auto-initialized vault state before
the listeners bind. Background self-update and browser account connection are
disabled; deploy cluster binaries through the orchestrator.

Apply migrations once with the same image before rolling out replicas:

```bash
llm-notaryd --config /etc/llm-notary/config.toml migrate
```

For a cluster configuration, the migrator also pins a normalized non-secret
compatibility digest in PostgreSQL. Replica slot names are excluded, but the
vault identity, notary trust mode, S3 namespace, listeners, and lease policy must
match. Runtime startup fails rather than joining a differently configured
cluster. It also refuses metadata that still references filesystem artifacts.
Start with a database whose artifact records are already S3-backed; there is no
automatic filesystem-to-S3 importer.

The Dockerfile's `daemon-cluster` target runs as UID/GID 10001, exposes only
ports 8787 and 8788, and expects configuration and secrets to be mounted by the
orchestrator.

## Ingress and health

Terminate TLS on trusted infrastructure. Keep the provider proxy and admin API
on separate frontends and do not expose the admin frontend without its
configured authentication. The ingress must use HTTP/1.1, stream request and
response bodies immediately, and never retry, replay, or redistribute a
provider request. `deploy/daemon-cluster/Caddyfile` is a minimal internal
example; place it behind the environment's TLS and network controls.

Use `GET /healthz` only for process liveness. Use `GET /readyz` to select load
balancer backends. Readiness fails while starting or draining and when the
PostgreSQL schema, selected S3 namespace, shared vault, or directory trust is
unavailable. Dependency probes are serialized and cached for one second per
replica so load-balancer polling cannot stampede PostgreSQL or S3. `/v1/status`
identifies the runtime profile, instance, incarnation, lifecycle, and backend
status without exposing URLs or credentials. Its capture and operation counts
are cluster-wide; listener addresses, lifecycle, incarnation, and build data
describe the responding replica.

The bundled `llm-notary` CLI intentionally remains a loopback, single-daemon
client and rejects the cluster's non-loopback listener configuration. Cluster
operators and automation should use the authenticated HTTPS admin frontend and
the generated OpenAPI clients. Do not point the CLI at an individual replica.

On SIGTERM the replica first enters `draining`, making readiness fail and
rejecting new proxy captures. A short withdrawal interval lets the load
balancer observe that state. Existing HTTP streams and the finalization already
owned by the replica finish while heartbeats continue; queued work remains for
another replica. If the process is paused or killed, PostgreSQL time determines
lease expiry, one peer records the interruption, and an explicit retry receives
a new fence. Configure the orchestrator's termination grace period to exceed
`withdrawal_delay_seconds + shutdown_grace_seconds`; after the bounded grace
expires, the process aborts remaining local tasks and peers recover expired
claims.

Dashboard session bearer values are returned only as secure cookies. The
database stores a domain-separated SHA-256 digest, so a session issued on one
replica can be validated or revoked on another without persisting the token.

## Backup, restore, and verification

Quiesce the cluster before taking a coordinated PostgreSQL and S3 backup. After
restore, keep all replicas stopped and run the report-only artifact
reconciliation command. Resolve missing, corrupt, invalid, or old unreferenced
objects before serving traffic. Preserve the shared vault files and the
PostgreSQL notary trust history (or explicit key) with the backup; restoring
only the passphrase is insufficient.

The disposable two-replica validation is:

```bash
scripts/test-daemon-persistence-e2e.sh postgres s3 2 full
```

It exercises shared hashed sessions, non-replaying ingress traffic,
cross-replica capture/finalization/download and verification, event high-water
paging, PostgreSQL and MinIO outages, vault mismatch rejection, duplicate
instance fencing, stale artifact and terminal fencing, exactly-once expiry and
retry, peer removal, bounded finalization drain, and a rolling replacement with
an admitted streaming request and queued peer work against PostgreSQL 17 and
MinIO.
