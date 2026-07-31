# Fly.io deployment

The production deployment runs three Fly apps in `sjc`:

```text
internet ── HTTPS ──> llm-notary-prod-web.fly.dev
                              │
                              └── Flycast HTTP ──> llm-notary-prod-api

local proxies ── raw TCP:7047 ──> llm-notary-prod-notary.fly.dev
```

The API is private behind Flycast so its SQLite database and intake endpoint
are never directly exposed. The notary is intentionally exposed as raw TCP;
allocate a dedicated IPv4 address for it because raw TCP cannot use Fly's shared
IPv4 routing.

The checked-in configuration targets the `llm-notary-prod` organization. Create
the three apps and provision a private Flycast address for the API and a public
dedicated IPv4 address for the raw-TCP notary before the first deployment. The
API uses a 1 GiB encrypted Fly Volume named `api_data`. Create a private Tigris bucket for
the API; the service accepts the standard `AWS_*` and `BUCKET_NAME` variables
that `fly storage create` sets, as well as the portable `LLM_NOTARY_S3_*`
variables used by the DigitalOcean deployment.

Two base64-encoded file secrets are required:

- `PLATFORM_SIGNING_KEY_B64` on the API;
- `NOTARY_SIGNING_KEY_B64` on the notary.

The API also needs its normal GitHub OAuth credentials, the notary public key,
and its signing-key directory. The initial endpoint is
`https://llm-notary-prod-web.fly.dev`; GitHub OAuth cannot complete there while
the OAuth App's callback remains on the canonical production hostname. Before
moving users, set both public-origin values to that canonical origin and update
the OAuth callback only if the hostname changes.

Never create a new platform signing key during a migration. Copy the existing
key, the SQLite state, and the notary directory together so published stamps,
sessions, and historic proofs remain valid.

Deploy from the repository root:

```bash
fly deploy . -c deploy/fly/api.fly.toml --flycast
fly deploy . -c deploy/fly/notary.fly.toml
# Fly resolves a relative config path against the supplied frontend context.
fly deploy js/app -c "$PWD/deploy/fly/web.fly.toml"
```

The web and notary apps suspend when idle. The API uses application-managed
idle shutdown: it keeps running while it has active HTTP requests, queued or
verifying admissions, pending private-artifact cleanup, expired uploads, or
Library metadata work. Once those are clear for 45 seconds it exits cleanly;
Flycast autostarts the existing Machine for the next API request. This avoids
using Fly Proxy's inbound-connection heuristic to interrupt background work.

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
