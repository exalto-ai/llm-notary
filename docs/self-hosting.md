# Self-hosting

Self-hosting can mean either running a private notary for local clients or
running the complete account, admission, Library, and web stack. Start with the
smaller boundary unless the hosted platform is actually required.

## Private notary for local clients

Generate a 32-byte development key and start the notary:

```bash
openssl rand -hex 32 > notary.key
cargo run -p llm-notary-server --bin llm-notary-server -- \
  --signing-key notary.key \
  --allow-host api.openai.com \
  --allow-host api.anthropic.com \
  --allow-host api.deepseek.com \
  --allow-host openrouter.ai
```

The server prints its compressed SEC1 public key. Pair the endpoint and key in
each local daemon's `config.toml`:

```toml
[notary]
endpoint = "tcp://127.0.0.1:7047"
public_key = "02..."
```

Use `tls://notary.example:443` when a public-CA TLS terminator protects the
network endpoint. TLS authenticates transport before the LLMN protocol; the
configured secp256k1 key remains the evidence trust anchor.

The current prototype reads a signing-key file. Keep it outside the repository
with owner-only permissions, encrypted backups, and restricted process access.
Do not expose the development default allowlist implicitly in production;
pass every allowed hostname deliberately.

## Capacity and limits

Important notary flags are:

| Flag | Default | Meaning |
| --- | ---: | --- |
| `--max-concurrent-captures` | 8 | Live capture sessions |
| `--max-concurrent-finalizations` | 1 | CPU-intensive deferred proofs |
| `--max-total-private-chunk-bytes` | 15 MiB | Total private transcript commitment bytes |
| `--max-private-chunk-bytes` | 128 KiB | Largest individual private chunk |
| `--max-private-chunk-commitments` | 128 | Number of private proof commitments |
| `--max-frame-bytes` | 128 MiB | Largest serialized protocol frame |
| `--session-timeout-secs` | 1,800 | Wall-clock session limit |

Keep the notary's total-private-byte limit at least as large as the local
daemon's `proxy.max_attestable_http_bytes`. Measure real transcript shapes
before increasing concurrency or proof limits.

`--finalize-only` rejects new capture sessions while allowing existing bundles
to drain during a planned key rotation. See [Notary key
lifecycle](notary-key-lifecycle.md).

## Full platform with Compose

The checked-in `compose.yml` runs:

- one-shot PostgreSQL migrations;
- the hosted API and background workers;
- the public SPA;
- the stable Caddy `web` gateway;
- the notary;
- a Cloudflare Tunnel connector.

The full stack requires external services. It is not a zero-configuration local
demo.

### External prerequisites

Prepare:

1. PostgreSQL URLs: a pooled `DATABASE_URL` for API replicas and a direct
   `DATABASE_MIGRATIONS_URL` for SQLx migrations. They may be identical for a
   direct local PostgreSQL server.
2. A private S3-compatible bucket and bucket-scoped credentials.
3. A GitHub OAuth App whose callback is
   `<LLM_NOTARY_PUBLIC_ORIGIN>/api/auth/github/callback`.
4. A named Cloudflare Tunnel targeting the stable `web` service, or an
   equivalent private ingress arrangement if Compose is adapted.
5. A notary signing key, a separate random admission service token shared only
   by the API and notary, and a distinct API-only HMAC key for opaque anonymous
   credit subjects.

Generate the three file secrets outside the repository:

```bash
install -d -m 0700 /secure/llm-notary
openssl rand -hex 32 > /secure/llm-notary/notary-signing-key
openssl rand -hex 32 > /secure/llm-notary/admission-service-token
openssl rand -hex 32 > /secure/llm-notary/anonymous-subject-hmac-key
chmod 0600 /secure/llm-notary/*
```

Print the matching public key without exposing the private value:

```bash
cargo run -p llm-notary-server --bin llm-notary-server -- \
  --signing-key /secure/llm-notary/notary-signing-key \
  --print-public-key
```

### Environment file

Create a root-owned environment file outside the repository. It must define at
least:

```dotenv
NOTARY_SIGNING_KEY_FILE=/secure/llm-notary/notary-signing-key
ADMISSION_SERVICE_TOKEN_FILE=/secure/llm-notary/admission-service-token
ANONYMOUS_SUBJECT_HMAC_KEY_FILE=/secure/llm-notary/anonymous-subject-hmac-key
LLM_NOTARY_NOTARY_PUBLIC_KEY=02...
LLM_NOTARY_NOTARY_HOST=notary.example.com
LLM_NOTARY_NOTARY_TRANSPORT=tls
LLM_NOTARY_PUBLIC_ORIGIN=https://notary.example.com

DATABASE_URL=postgresql://...
DATABASE_MIGRATIONS_URL=postgresql://...

GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...

LLM_NOTARY_S3_ACCESS_KEY_ID=...
LLM_NOTARY_S3_SECRET_ACCESS_KEY=...
LLM_NOTARY_S3_BUCKET=...
LLM_NOTARY_S3_ENDPOINT=https://...
LLM_NOTARY_S3_REGION=...

CLOUDFLARE_TUNNEL_TOKEN=...
```

Do not copy this example into the repository. Do not put real credentials in
shell history, Compose files, or Git.

### Validate and start

Validate interpolation before changing containers:

```bash
docker compose --env-file /etc/llm-notary/compose.env config --quiet
```

Then start the stack. The one-shot `migrate` service must succeed before the
API starts:

```bash
docker compose --env-file /etc/llm-notary/compose.env up -d
docker compose --env-file /etc/llm-notary/compose.env ps
```

Check the public health and database-backed readiness routes:

```bash
curl --fail https://notary.example.com/api/healthz
curl --fail https://notary.example.com/api/readyz
curl --fail https://notary.example.com/api/notary
```

`/api/healthz` does not prove database availability; `/api/readyz` does.

### API keys for self-hosted automation

The hosted account dashboard manages account-owned API keys through
`/api/me/api-keys`; these routes require the HttpOnly browser session. A local
daemon using a self-hosted key needs both its injected key and the public HTTPS
origin:

```bash
LLM_NOTARY_API_ORIGIN=https://notary.example.com \
LLM_NOTARY_API_KEY_FILE=/run/secrets/llm-notary-api-key \
llm-notaryd
```

Do not add either value to the editable daemon configuration or Compose image.
Mount the key file from the deployment secret store. API keys remain between
the daemon and platform API; the notary receives only the existing one-time
admission ticket. See [API keys for automation](api-key-automation.md) for
scope selection, manual rotation, and a CI example.

## Hosted admission control

Every hosted capture or finalization obtains a short-lived one-time ticket from
`POST /api/notary/admissions`. The notary redeems it through the internal API
and renews a PostgreSQL-backed lease while work continues. New sessions fail
closed if the coordinator is unavailable.

The shared admission service token authenticates only the notary's internal
redeem, renew, and release calls. It is never sent to local clients and is
unrelated to provider credentials or session-sharing access tokens.

Anonymous hosted allowances use a period-scoped HMAC of the canonical client
address. The API trusts `X-LLM-Notary-Client-IP` only when the socket peer is in
`LLM_NOTARY_TRUSTED_PROXY_CIDRS`; otherwise it uses the socket peer and ignores
forwarding headers. Compose defaults this list to its private bridge range
because the API is reachable only through the stable `web` gateway. If you
change the network topology, replace that range with the exact proxy networks;
never trust all public peers. Rotate the HMAC key only together with an
incremented `LLM_NOTARY_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION`, knowing that a new
version starts new anonymous subjects for the current period.

See [Credits and utilization](hosted-credits.md) for the signed-in account,
supplemental-credit, and address-scoping model.

## Storage and database operations

The private bucket has distinct staging, intake, and admitted-trace prefixes.
Keep it private; public reads pass through the API after integrity checks.

Use forward-only database migrations. Migration `0009` deliberately removes
obsolete account-policy columns, so deploy the matching API and notary images
together rather than rolling back to the previous admission binary. See
[Database operations](database-operations.md) and
[Share admission v1](share-admission-v1.md).

## Observability

The API serves Prometheus metrics on its internal `/metrics` route. The notary
serves metrics only when `LLM_NOTARY_METRICS_LISTEN` is set. Never route either
endpoint through the public gateway by accident.

Both services emit structured operational logs and can export OTLP spans when
standard OpenTelemetry environment variables are configured. Logs, metrics,
and operational spans must never include request or response bodies, header
values, credentials, presigned URLs, or `.llmcapture` paths.

## Production-specific deployment

The repository's production Fly.io topology, immutable image rollout,
rollback, idling, and metrics queries are documented separately in [Fly.io
deployment](../deploy/fly/README.md). Do not copy its app names, regions, or
transport assumptions into an unrelated self-hosted environment without
review.
