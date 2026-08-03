# Fly.io deployment

The production deployment runs three Fly apps in `sjc`:

```text
internet ── HTTPS ──> llm-notary.exalto.ai
                              │
                              └── Flycast HTTP ──> llm-notary-prod-api

local proxies ── TLS:443 ──> llm-notary-prod-notary.fly.dev
```

The API is private behind Flycast so its PostgreSQL connection and intake endpoint
are never directly exposed. Fly Proxy terminates the notary's public TLS
connection and forwards the unmodified binary protocol to port 7047 through
Fly's encrypted backhaul. The configuration deliberately uses the `tls` handler
only—not the HTTP handler. Fly supplies the certificate for the app's
`.fly.dev` hostname, so no custom DNS is required.

The checked-in configuration targets the `llm-notary-prod` organization. Create
the three apps and provision a private Flycast address for the API before the
first deployment. The notary's TLS handler can use Fly's shared IPv4 routing.
Create a Neon PostgreSQL database and stage its pooled connection URL as the
`DATABASE_URL` Fly secret and its direct connection URL as the
`DATABASE_MIGRATIONS_URL` Fly secret before deploying the API; staging avoids
restarting the previous API revision. The API deploy runs the supplied migrator
once as Fly's release command before replacing Machines. Create a private Tigris bucket for
the API; the service accepts the standard `AWS_*` and `BUCKET_NAME` variables
that `fly storage create` sets, as well as the portable `LLM_NOTARY_S3_*`
variables used by self-hosted container deployments.

Two base64-encoded file secrets are required:

- `PLATFORM_SIGNING_KEY_B64` on the API;
- `NOTARY_SIGNING_KEY_B64` on the notary.

The API also needs its normal GitHub OAuth credentials, the notary public key,
and its signing-key directory. The production endpoint is
`https://llm-notary.exalto.ai`; keep the GitHub OAuth App callback at
`https://llm-notary.exalto.ai/api/auth/github/callback`.

Never create a new platform signing key during a migration. Preserve the
existing key and notary directory so published stamps and historic proofs
remain valid. Ongoing PostgreSQL/Neon migration operations are documented in
[`docs/postgres-neon-migration.md`](../../docs/postgres-neon-migration.md).

Clients cache the signed notary directory by its generation. When moving its
advertised hostname, transport, port, or key set, increase
`LLM_NOTARY_NOTARY_DIRECTORY_GENERATION`; reusing a generation for different
directory contents is intentionally rejected as a rollback/conflict.

The TLS certificate authenticates the network endpoint but does not replace the
notary signing key in the directory. A self-hosted notary can advertise either
`tcp` or `tls`; TLS termination need not be provided by Fly.

## Production rollout

Production is deployed only by the `Production deployment` job in CI. A push
to `main` first completes the required Rust, PostgreSQL, SPA, documentation,
and deployment-configuration checks. CI then calls the reusable Fly workflow;
the Fly workflow has no independent push or manual trigger.

Fly remains the image builder and registry. The workflow uses `fly deploy
--build-only --push` to build all three images before changing any Machine and
gives each image a tag unique to the commit and CI run. The rollout then uses
that tag to resolve an immutable `sha256` digest and deploys only the digest.
It therefore neither rebuilds nor promotes a different image:

1. Deploy the notary and check the v2 admission prelude.
2. Deploy the API and check it through the still-old web gateway.
3. Deploy the web gateway and check the public readiness route again.

Before the first change, the workflow records every app's current Fly image.
If a deploy or compatibility check fails, it restores each attempted app in
reverse order. API rollback skips the old image's release command: PostgreSQL
migrations are forward-only and the previous API must remain usable against
the newly migrated schema.

### Rolling compatibility contract

Every production change must support the mixed versions that can exist during
a rolling deployment and its rollback:

- a new notary continues accepting the control protocols used by the current
  and immediately previous clients;
- the API works with both the current and immediately previous notary and web
  contracts;
- the web gateway works with both the current and immediately previous API;
- Fly environment/configuration changes remain valid for the previous image;
- database changes use expand/contract migrations: add compatible schema
  first, stop using old schema in a later release, and remove it only after at
  least one further release has made rollback to the old use impossible.

Breaking any of these contracts requires an explicitly staged multi-release
migration. Do not merge an incompatible change and rely on deployment order to
hide it.

For a break-glass, operator-driven deployment from the repository root, use the
same build-then-deploy split and retain the previous image references for
rollback. Normal production changes must go through CI:

```bash
label="manual-$(git rev-parse --short=12 HEAD)-$(date -u +%Y%m%d%H%M%S)"
fly deploy --build-only --push --image-label "$label" -c deploy/fly/notary.fly.toml
fly deploy --build-only --push --image-label "$label" -c deploy/fly/api.fly.toml
fly deploy js/app --build-only --push --image-label "$label" \
  -c "$PWD/deploy/fly/web.fly.toml"

fly deploy --image "registry.fly.io/llm-notary-prod-notary:$label" \
  --ha=false -c deploy/fly/notary.fly.toml
fly deploy --image "registry.fly.io/llm-notary-prod-api:$label" \
  --ha=true -c deploy/fly/api.fly.toml
fly deploy js/app --image "registry.fly.io/llm-notary-prod-web:$label" \
  --ha=false -c "$PWD/deploy/fly/web.fly.toml"
```

Fly's registry can briefly return `not found` after a successful manifest
push. CI waits for each labeled image to become visible, validates its digest,
and only then records the digest-pinned references used for rollout. If a
digest never becomes visible within the bounded retry window, the deployment
stops before changing any Machine.

The web and notary apps suspend when idle. The API's configured
`LLM_NOTARY_IDLE_SHUTDOWN_SECS=45` makes API Machines exit after 45 seconds
with no application request or currently-due durable work; Flycast autostarts
a stopped Machine on the next API request. This idling behavior is opt-in, so
local and self-hosted API processes remain running unless their operator sets
the variable. Its readiness check is `/api/readyz`, which verifies the shared
database connection. Every running Machine runs the background workers;
PostgreSQL claims prevent duplicate admission and metadata generation. Expired
upload cleanup and Library metadata retries that become due while every API
Machine is stopped resume on the next API request. Add capacity with `fly scale
count <n> -a llm-notary-prod-api`, keeping the total configured database pool
size within the Neon connection budget.

## Metrics

Fly scrapes the API's private `:8080/metrics` endpoint and the notary's
private `:9090/metrics` endpoint every 15 seconds. The web gateway is covered
by Fly's built-in proxy metrics. These are available in the managed Grafana
instance and through Fly's Prometheus-compatible API, which retains roughly 15
days of operational data.

Create a short-lived, read-only organization token before querying the API;
do not use a deploy token or commit this token to an environment file:

```bash
fly tokens create readonly --org <org-slug> --expiry 1h --name llm-notary-metrics
```

With that token in `FLY_METRICS_TOKEN`, query
`https://api.fly.io/prometheus/<org-slug>/api/v1/query` using the
`Authorization: FlyV1 <token>` header. Useful MetricsQL/PromQL expressions:

```text
# Fly edge response rate by status for the public gateway.
sum(rate(fly_edge_http_responses_count{app="llm-notary-prod-web"}[5m])) by (status)

# p95 API handler latency by route (application time, excluding Fly routing).
histogram_quantile(0.95, sum(rate(llm_notary_http_request_duration_seconds_bucket{app="llm-notary-prod-api"}[5m])) by (le, route))

# Admission backlog and age of its oldest item.
max(llm_notary_admission_queue_depth{app="llm-notary-prod-api"})
max(llm_notary_admission_oldest_queued_seconds{app="llm-notary-prod-api"})

# Admission outcomes and p95 verification time.
sum(increase(llm_notary_admission_jobs_total{app="llm-notary-prod-api"}[1h])) by (outcome)
histogram_quantile(0.95, sum(rate(llm_notary_admission_duration_seconds_bucket{app="llm-notary-prod-api"}[15m])) by (le, outcome))

# Raw TCP demand plus active notary protocol sessions.
sum(increase(fly_edge_tcp_connects_count{app="llm-notary-prod-notary"}[5m]))
sum(llm_notary_notary_active_sessions{app="llm-notary-prod-notary"}) by (mode)
```

The binaries can also export OTLP traces when an
`OTEL_EXPORTER_OTLP[_TRACES]_ENDPOINT` is configured, but Fly's managed
service is not an OTLP trace backend. Point that setting at a separate
OpenTelemetry Collector/Tempo-compatible backend if distributed traces are
needed.
