# LLM Notary

LLM Notary is available under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option. See
[third-party notices](THIRD-PARTY-NOTICES.md) for distributed dependencies.

LLM Notary captures provider-origin model behavior and turns selected calls
into independently verifiable OpenTelemetry traces. A local proxy receives an
ordinary API request and performs a real TLSNotary Proxy-TLS session with a
remote notary. The API key and application plaintext stay on the local
machine; the notary resolves the provider and relays authenticated encrypted
TLS records.

## Current scope

- HTTP/1.1 `POST` API requests, including Server-Sent Events (`stream: true` or
  `Accept: text/event-stream`). SSE bytes are relayed as they arrive.
- Proxy-TLS: the remote notary resolves and opens the TCP connection to the
  allowlisted provider, while the local machine performs the TLS handshake.
  This avoids MPC-TLS's per-byte online cost without giving the notary the API
  key or plaintext trace.
- OpenAI (`api.openai.com`), Anthropic (`api.anthropic.com`), DeepSeek
  (`api.deepseek.com`), and OpenRouter (`openrouter.ai`) host allowlist.
- At the end of each provider response, the proxy encrypts a client-held
  `.llmbundle`. The bundle contains the private transcript checkpoint and a
  notary-signed receipt, but does not perform the expensive private proof.
- The local service can later finalize a selected capture by reconnecting to any notary instance holding the
  same signing key, completes the proof, redacts every HTTP header value except
  the exact `Transfer-Encoding: chunked` framing value, and emits one portable
  `<capture-id>.llmtrace` package. The notary
  stores no per-bundle state.
- Finalized packages contain the canonical `trace.otlp.json`, the TLSNotary
  evidence and disclosed HTTP artifacts, and a `manifest.json` binding the
  trace to the authenticated source.
- The notary, not the local machine, resolves and connects to the allowed
  provider hostname. The local TLS client validates that provider's certificate
  chain with Mozilla roots, so local DNS cannot substitute an endpoint.

Streaming responses are relayed without synthetic events. Sealing a bundle
requires one short post-stream exchange with the notary. Finalization is the
slow step and can happen in a later process after both sides have discarded
the original live TLS session.

## Install the local service

Releases include `llm-notaryd` and `llm-notary` for macOS and Linux, with a
checksum-verified installer. `llm-notaryd` is the long-running local service;
`llm-notary` is its short-lived REST-backed command client. The command below
is the recommended two-step form so the script is available for inspection
before it runs:

```bash
export LLM_NOTARY_PUBLIC_ORIGIN=https://your-notary.example
curl -fsSLO "$LLM_NOTARY_PUBLIC_ORIGIN/install.sh"
sh install.sh
```

Windows x86_64 releases are available as ZIP archives on GitHub Releases.

## Run locally from source

Generate an ephemeral development signing key:

```bash
openssl rand -hex 32 > notary.dev.key
cargo run -p llm-notary-server --bin llm-notary-server -- --signing-key notary.dev.key
```

The notary prints its public key at startup. A local or private deployment sets
that value as `notary.public_key` alongside its explicit endpoint and reports
its key identifier during finalized-trace verification. Production clients
discover and pin the public key through the signed directory.

In another terminal, start `llm-notaryd`. The foreground daemon owns both the
provider proxy at `127.0.0.1:8787` and the administration API at
`127.0.0.1:8788`. A service manager can supervise that same foreground
process. On first use it automatically writes an
editable configuration file in the standard platform location: XDG config on
Linux, `%APPDATA%` on Windows, and `~/Library/Application Support/llm-notary`
on macOS. The generated configuration enables all built-in providers, writes
encrypted source bundles under the platform data directory, and creates a
SQLite capture catalog with 1,000-character prompt and output previews. By
default the released client discovers the current public notary endpoint from
`$LLM_NOTARY_PUBLIC_ORIGIN/api/notary`. For a local notary, set
`notary.endpoint = "tcp://127.0.0.1:7047"` and the printed key as
`notary.public_key` in that file.

```bash
llm-notaryd
# Or choose a configuration explicitly:
llm-notaryd --config /path/to/config.toml
```

The loopback admin listener is available without credentials by default. Set
`admin.auth` to require a username and an Argon2id password hash. The provider
proxy does not mount any admin route. `llm-notary` verifies `/healthz` and uses
only the versioned REST API; it never opens the catalog, vault, or artifacts
directly. Use `--json` for stable automation output:

```bash
llm-notary status
llm-notary captures list --provider openai --limit 20
llm-notary finalize cap-example
llm-notary operations show op-example --json
llm-notary open
```

If admin authentication is enabled, the CLI prompts without echoing the
password. Automation can pass `--admin-password-file /private/path`, whose
file must be private on Unix; the password is never accepted as an argument.

Open [http://127.0.0.1:8788](http://127.0.0.1:8788) for the local evidence
dashboard. It opens directly under the default configuration. When
`admin.auth` is enabled, it exchanges the configured credentials for an
HttpOnly browser session. It supports the complete capture, finalization,
verification, activity, and publication workflow. See the [local service and REST API guide](docs/local-service.md),
[dashboard guide](docs/local-dashboard.md), and [coding-agent
playbook](docs/agent-playbook.md) for the complete flow.

> **Breaking rename:** `llm-notary` no longer starts the local service. Start
> the foreground daemon with `llm-notaryd`; use `llm-notary`, the dashboard,
> or the code-generated REST API for local operations. There is no compatibility
> shim for the former `llm-notary --config ...` daemon invocation.

### Configure the local client

`config.toml` is the service’s durable, user-editable setup. The service writes it
once and never replaces it, so it is the place to change a listener, storage
location, enabled providers, or catalog behavior. To use a configuration file
outside the standard location, pass `--config /path/to/config.toml` when
starting `llm-notaryd`, and pass the same option to `llm-notary` commands.

The generated file includes all defaults. This shorter, valid configuration
shows the settings most installations change:

```toml
format = "llm-notary/agent-config/v1"

[proxy]
listen = "127.0.0.1:8787"

[admin]
listen = "127.0.0.1:8788"

# Optional. The admin listener is open to local processes when this table is absent.
# [admin.auth]
# username = "local-admin"
# password_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."

[notary]
# Set this only for a local or self-hosted notary.
# endpoint = "tcp://127.0.0.1:7047"
# public_key = "02..." # Compressed SEC1 key printed by that notary.

[storage]
# bundle_dir = "/platform/data/llm-notary/bundles"
# finalized_dir = "/platform/data/llm-notary/traces"

[catalog]
# path = "/platform/data/llm-notary/catalog.db"
prompt_preview_chars = 1000
output_preview_chars = 1000
full_text_search = true

[providers.openai]
enabled = true
route_prefix = "/openai"
```

Both listeners are restricted to loopback addresses. If other local processes
should not be able to use the admin API, enable `admin.auth` and store only an
Argon2id PHC string, never a plaintext password. A password tool that prompts
instead of putting the secret in the process list can generate one; for
example, `caddy hash-password --algorithm argon2id`. Copy its complete output,
including the salt and work parameters, into `password_hash`.

All four built-in providers start enabled. Set a provider’s `enabled` value to
`false` to remove its local route, or change its `route_prefix` to fit an
existing local setup. Enabled prefixes must be distinct and non-overlapping.
The provider hostname and API format stay fixed by the built-in adapter; the
configuration does not permit arbitrary upstream hosts.

For a local or self-hosted notary, set `notary.endpoint` and
`notary.public_key` together. The service refuses an explicit endpoint without
its expected compressed SEC1 key; this is an intentional trust decision.
Hosted installations leave both values unset and use the signed notary
directory instead.

One listener serves every supported provider at a fixed first path segment. The
proxy removes that local segment before making the authenticated upstream
request, and it does not accept a provider URL from the caller:

| Provider | Local SDK base URL | Upstream request path |
| --- | --- | --- |
| OpenAI | `http://127.0.0.1:8787/openai/v1` | `/v1/...` |
| Anthropic | `http://127.0.0.1:8787/anthropic` | `/v1/...` |
| DeepSeek | `http://127.0.0.1:8787/deepseek` | `/...` |
| OpenRouter | `http://127.0.0.1:8787/openrouter/api/v1` | `/api/v1/...` |

Keep the API key in the SDK as usual. Each completed request writes an
encrypted `.llmbundle` and records a local catalog entry. The catalog stores
the provider, requested and response model when available, request/response
size and status, plus short plain-text prompt and output previews. Its FTS5
index powers `GET /v1/captures?query=pricing`, which can locate a capture
without decrypting every bundle. Search punctuation is treated as text
boundaries rather than raw FTS syntax, and quoted phrases remain phrases. The
catalog deliberately
does not store HTTP header values, cookies, or credentials. Its previews are
plain local text; set either `catalog.*_preview_chars` to `0` if that is not
appropriate for a particular machine. Both listeners must remain on distinct
loopback addresses. On macOS and Windows, the default vault
key is stored in the OS credential store; on Linux it uses the desktop secret
service. To use a passphrase instead
(including an intentionally empty passphrase), point
`LLM_NOTARY_VAULT_PASSPHRASE_FILE` at a private file before the first service
start. That startup choice initializes the passphrase-backed vault.

Set `LLM_NOTARY_CONFIG_DIR` to use a non-default vault configuration directory,
which is useful for isolated development and automation.

For noninteractive automation, set `LLM_NOTARY_VAULT_PASSPHRASE_FILE` to a
private (`0600`) UTF-8 file containing the vault passphrase. The service reads the
file during service startup and later capture/finalization operations;
it never prints the value. Use a CI secret file, not a command-line argument
or environment variable containing the passphrase itself.

## Finalize and verify a capture

Use the admin API to find a capture by its identifier and queue finalization.
The service fetches and caches the production directory key automatically,
uses the configured finalized-package directory, and retains the encrypted
source bundle. Finalization returns `202 Accepted` with a durable operation
identifier; poll that operation until it reaches `finalized`, `failed`, or
`interrupted`:

```bash
curl 'http://127.0.0.1:8788/v1/captures?query=pricing'
curl -X POST \
  http://127.0.0.1:8788/v1/captures/cap-example/finalizations
curl http://127.0.0.1:8788/v1/operations/op-example
```

Finalization currently accepts only captures whose provider response has a
`2xx` HTTP status. A captured provider error remains encrypted local evidence,
but the service rejects finalization before proof generation with `409` and
the stable code `unsupported_provider_http_status`; retrying the same capture
cannot change that response schema.

For optional authentication, exact state transitions, deduplication, restart
recovery, and retry behavior, follow the [local service guide](docs/local-service.md).

Finalization atomically creates one deterministic, portable
`traces/<capture-id>.llmtrace` ZIP. It contains exactly:

```text
cap-....llmtrace (ZIP)
├── archive-manifest.json
├── evidence.tlsn
├── manifest.json
├── request.disclosed.http
├── response.disclosed.http
└── trace.otlp.json
```

Verify it locally by rechecking the TLSNotary presentation, every source-file
hash, the provider adapter, and the exact canonical OTLP bytes:

```bash
curl -X POST \
  http://127.0.0.1:8788/v1/captures/cap-example/trace:verify

curl --output cap-example.llmtrace \
  http://127.0.0.1:8788/v1/captures/cap-example/package

llm-notary traces verify ./cap-example.llmtrace
```

The encrypted bundle is the most sensitive artifact: its deferred TLS
checkpoint can reconstruct the complete original request, including
`Authorization` or `x-api-key` values. Keep the vault protected and do not
share or upload `.llmbundle` files. They are never finalized evidence.
Finalized `.llmtrace` packages reveal authenticated header names and structural
bytes but hide every request and response header value except
`Transfer-Encoding: chunked`, which the normalizer needs to remove HTTP chunk
framing. Request IDs, organization/project metadata, rate-limit values,
cookies, and content types therefore remain hidden. The complete request and
response bodies remain disclosed so the verifier can reproduce the normalized
trace. The finalized trace retains normalized
system context, messages, model-emitted tool calls and results, usage, and
finish reasons when the provider supplies them. A provider trace proves the
model exchange; it does not claim that a local runtime actually executed a
requested tool.

### Anthropic

Anthropic's Messages API is available at the `/anthropic` local route. Keep
the `x-api-key` and `anthropic-version` headers in the client exactly as usual:

```bash
curl http://127.0.0.1:8787/anthropic/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":32,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

### DeepSeek

DeepSeek's OpenAI-compatible Chat Completions API can be traced through the
same listener. Point the client to `http://127.0.0.1:8787/deepseek` and retain
`DEEPSEEK_API_KEY` in the client environment:

```bash
curl http://127.0.0.1:8787/deepseek/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The default DeepSeek endpoint is `https://api.deepseek.com` (without a `/v1`
suffix); the proxy preserves the requested API path.

### OpenRouter

OpenRouter's OpenAI-compatible Chat Completions API is available at the
`/openrouter` local route. Point an OpenAI-compatible SDK at
`http://127.0.0.1:8787/openrouter/api/v1`, and retain `OPENROUTER_API_KEY` in
the client environment:

```bash
curl http://127.0.0.1:8787/openrouter/api/v1/chat/completions \
  -H "Authorization: Bearer $OPENROUTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'HTTP-Referer: https://example.test' \
  -H 'X-Title: LLM Notary example' \
  -d '{"model":"openai/gpt-4o","stream":true,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The verified provider is always **OpenRouter** at `openrouter.ai`. A model slug
such as `openai/gpt-4o` or `anthropic/claude-sonnet-4.5` is authenticated model
metadata; it does not prove a direct TLS connection to OpenAI, Anthropic, or
another upstream model vendor. Finalized `.llmtrace` packages retain the
authenticated `Authorization`, `HTTP-Referer`, and `X-Title` header names but
hide all three values.

To exercise a real streamed request deliberately, run the command above with
an `OPENROUTER_API_KEY`, wait for the encrypted bundle, find its identifier
with `GET /v1/captures`, queue `POST
/v1/captures/{capture_id}/finalizations`, poll the returned operation, and then
call `POST /v1/captures/{capture_id}/trace:verify`. This is an opt-in network
and billing check; the regular test suite uses deterministic fixtures.

Verify a named Library publication without a private capture or local path:

```bash
curl -X POST \
  http://127.0.0.1:8788/v1/public-traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/verify
```

The verifier hashes `trace.otlp.json`, checks the platform signature, and
reports the provider, verification time, and normalizer version named in the
stamp.

Retrieve the canonical public trace and stamp as JSON through the admin API:

```bash
curl http://127.0.0.1:8788/v1/public-traces/3d3d727f-e0b1-432e-be3c-0b2e3ead35d1
```

The service resolves public artifact links through the configured API, rejects
redirects and non-JSON responses, and never accepts an arbitrary local output
path. Verification obtains the platform directory and checks the canonical
trace bytes, trace hash, public-stamp contract versions, platform key ID,
stamp issuer, and ECDSA signature before reporting success. For a self-hosted
site, pass its loopback or HTTPS origin as the documented `api_origin` query
parameter on the public-trace REST operation.

### Public trace and stamp contract

`trace.otlp.json` is UTF-8 canonical JSON: object keys are sorted by UTF-8
byte order, arrays retain their order, scalar values use compact JSON encoding,
and the file ends in exactly one LF. The SHA-256 in `stamp.json` is over those
exact bytes, including that LF. A verifier rejects valid JSON that is not in
this byte form, so reformatting a trace changes the artifact and invalidates
its stamp.

The trace is a minimal OTLP JSON `resourceSpans` payload with one or more
ordered `gen_ai.inference` client spans. Its resource attributes are
`llmnotary.format` (`llm-notary/otlp-trace/v1`),
`llmnotary.normalizer.version` (`llm-notary/normalizer/v1`),
`otel.semconv.version` (`1.37.0`), and `service.name` (`llm-notary`). The only
supported span attributes are:

- `gen_ai.provider.name`, `gen_ai.operation.name`, and `gen_ai.request.model`
  (required strings)
- `gen_ai.response.model` (optional string)
- `gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens` (optional
  non-negative integer strings, as required by OTLP JSON)
- `gen_ai.input.messages` and `gen_ai.output.messages` (optional canonical JSON
  message arrays encoded as strings in OTLP JSON). Messages retain text and
  model-emitted tool calls or tool-call results.
- `gen_ai.response.finish_reasons`, `gen_ai.conversation.id`, and
  `server.address` (optional provider-inference metadata)

A finalized capture is normalized as a span in its conversation trace. This
deliberately excludes runtime-reported agent and tool-execution spans: a model
requesting a tool is recorded as a message part; no claim is made that a local
runtime actually executed it.

`stamp.json` has format `llm-notary/platform-stamp/v1` and includes the issuer,
SHA-256-derived platform key ID, issue time in Unix milliseconds, trace
SHA-256, capture format, normalizer version, OpenTelemetry semantic-convention
version, canonicalization ID, and provider provenance (`name`, `host`, and
`tlsnotary-presentation/v1`). Its `signature` is a compact, low-S secp256k1
ECDSA signature over the SHA-256 of the canonical JSON encoding of every stamp
field except `signature`; the signing payload has the same lexicographic JSON
rule but no trailing LF. `POST /v1/public-traces/{publication_id}/verify`
checks every version and provenance claim against the trace before it verifies
the signature.

The stamp says that the LLM Notary platform admitted this exact normalized
trace after checking private source evidence. It does **not** include or replace
the private TLSNotary presentation, and it does not make the public trace a
direct cryptographic proof of provider behavior. Verifiers trust the platform
key for that admission assertion; they need neither a source capture nor a
network connection.

## Codex CLI

Codex can use the proxy through a custom Responses provider. The custom
provider setting matters: it disables Codex's optional Responses WebSocket
prewarm, which this HTTP/1.1 prototype intentionally does not implement.

```toml
model_provider = "llm-notary"
model = "gpt-5-mini"
model_reasoning_effort = "low"

[model_providers.llm-notary]
name = "LLM Notary local proxy"
base_url = "http://127.0.0.1:8787/openai/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
supports_websockets = false
```

For a one-off CLI invocation (with `OPENAI_API_KEY` already in the
environment):

```bash
codex exec --ephemeral --ignore-user-config --skip-git-repo-check \
  -m gpt-5-mini \
  -c 'model_reasoning_effort="low"' \
  -c 'model_provider="llm-notary"' \
  -c 'model_providers.llm-notary.name="LLM Notary local proxy"' \
  -c 'model_providers.llm-notary.base_url="http://127.0.0.1:8787/openai/v1"' \
  -c 'model_providers.llm-notary.env_key="OPENAI_API_KEY"' \
  -c 'model_providers.llm-notary.wire_api="responses"' \
  -c 'model_providers.llm-notary.supports_websockets=false' \
  'Reply with exactly: llm-notary'
```

Validated locally with real OpenAI, Anthropic, and DeepSeek tool-call requests:
each bundle finalized into a package that verified against the notary public
key. A real Codex tool-use run also streamed normally and produced retryable
bundles. Large agent transcripts remain expensive to finalize—a roughly
2.3 MB Codex bundle was still computing after 12 minutes in a local debug
build—so deferred finalization avoids blocking the live chat but does not yet
solve proof latency.

This remains an HTTP/1.1 prototype. WebSocket relaying, multiple notaries, and
a public transparency log remain future work.

The notary bounds expensive work with private-proof byte/commitment limits,
independent capture and finalization concurrency budgets, and a wall-clock
session timeout. The default budgets are eight live captures and one deferred
finalization. This is a safe starting point for the provided 1 GiB container:
an isolated 32k-token profile peaked near 71 MiB for capture and 233 MiB for
finalization. Set `--max-concurrent-captures` and
`--max-concurrent-finalizations` independently for the worker's CPU and memory
budget; profile the transcript sizes your users actually produce before
increasing either. Deferred receipts are replayable by design because the
service is stateless, so a public deployment still needs per-source or per-user
quotas. When a mode is full, current local clients receive a typed, retryable
rejection before TLSN setup: the proxy returns HTTP `503` with `Retry-After`
and `error.code` set to `capture_at_capacity`, while a finalization operation
records the safe failure code `notary_capacity`. The encrypted bundle remains
unchanged and the same durable operation can be retried.

The proxy and finalizer share the `proxy.max_attestable_http_bytes` setting
(15 MiB by default) across one provider request and response. The proxy
accounts for the request before opening the authenticated provider connection
and accounts for the response as it arrives, so it cannot write a deferred
bundle that exceeds the default notary private-proof limit. The same configured
value is automatically used for finalization. Keep the public notary's
`--max-total-private-chunk-bytes` at least as large. Raising it requires
raising and capacity-testing the notary's private-proof byte and commitment
limits as well.

The full 15 MiB envelope is tested with escape-dense JSON in request-heavy,
response-heavy, and balanced shapes by the `json_stack_safety` suite, which
also covers the known 544,933-byte escaped-string reproduction, chunked
transfer framing, and SSE streaming. JSON bodies are accepted up to 128
levels of object/array nesting (matching `serde_json`'s default); deeper
nesting is rejected with a typed parse error at capture time, never a crash.
Transcript parsing uses constant stack regardless of input size, so these
limits hold on the default runtime; the client additionally reserves a 32 MiB
worker stack purely as containment.

For staged capacity measurements, run the notary in a Linux cgroup container
with `--profile-sessions` and no other workload in that cgroup. It emits a
structured record tagged `mode=capture` or `mode=finalize`, including elapsed
time, CPU use, sampled and kernel-tracked memory peaks, and cgroup memory
limits. cgroup v2 also reports user/system CPU splits and OOM counters; cgroup
v1 reports aggregate CPU use and CPU throttling. The opt-in
`proxy_tls_split_profile` test runs the production protocol against a separate
notary container and uses an intentionally invalid synthetic provider
credential, so it never needs an API key or creates an inference. The smaller
in-process `proxy_tls_profile` test remains useful for deterministic timing
regressions but is not a substitute for isolated notary measurements.

## Website sign-in

The website supports GitHub OAuth for the account surface. The API only asks
GitHub to identify the account; it requests no repository, organization, or
email scopes. Configure a GitHub OAuth App with this production callback URL:

```text
$LLM_NOTARY_PUBLIC_ORIGIN/api/auth/github/callback
```

Set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` for the API.
Also set `LLM_NOTARY_NOTARY_PUBLIC_KEY` to the compressed SEC1 public key for
the configured notary signing key; the API refuses to advertise an unchecked
or malformed key. Planned rotation can supply a complete v3 directory through
`LLM_NOTARY_NOTARY_DIRECTORY_JSON`; its active key must match the colocated
notary key.
For source development, `LLM_NOTARY_PUBLIC_ORIGIN` defaults to
`http://localhost:4173`, but `DATABASE_URL` is required and must point to a
PostgreSQL database. A Neon development branch is a suitable low-operations
choice; use its pooled URL for `DATABASE_URL`, its direct URL for
`DATABASE_MIGRATIONS_URL`, and keep `LLM_NOTARY_DATABASE_MAX_CONNECTIONS` at
or below 5. For a direct local PostgreSQL instance, the two URLs can be the
same. GitHub OAuth Apps have one callback URL, so use a separate development
OAuth App with `http://localhost:4173/api/auth/github/callback` and place that
app's credentials and both database URLs in the local `.env`. Start the schema
migrator once, then start the API alongside the SPA with:

```bash
cargo run -p llm-notary-platform --bin llm-notary-api-migrate
cargo run -p llm-notary-platform --bin llm-notary-api
```

The PostgreSQL-backed API integration tests use disposable local PostgreSQL
17.7 containers through Testcontainers. They are skipped by the normal test
suite because they require a running Docker daemon. Run them explicitly with:

```bash
cargo test -p llm-notary-platform new_cli_session_is_usable_until_its_refresh_expiry -- --ignored
cargo test -p llm-notary-platform web_users_can_list_and_revoke_only_their_cli_sessions -- --ignored
```

They require no database URL, database credentials, or external provider
account; each test state receives a fresh production-schema database.

The API has `GET /api/notary` for local-service endpoint and public-key discovery,
`GET /api/auth/github`, `GET /api/auth/github/callback`, `GET /api/me`,
`POST /api/auth/logout`, `GET /api/healthz`, and database-backed
`GET /api/readyz`, plus authenticated publication intake endpoints and
publication endpoints for serving admitted traces. Set
`LLM_NOTARY_NOTARY_HOST`, `LLM_NOTARY_NOTARY_TRANSPORT` (`tcp` or `tls`), and
`LLM_NOTARY_NOTARY_PUBLIC_KEY` to the public notary endpoint and its compressed
SEC1 public key. The v3 directory contains stable key IDs, monotonic
generations, a transport-aware hostname and port, separate capture/finalization
deadlines, and endpoints for an active key and historical rotation records.
Clients reject directory rollback, cache revocation monotonically, route
pending bundles to an active or retiring signer, and retain retired keys for
timestamp-scoped offline verification. The
`POST /v1/captures/{capture_id}/publications` endpoint refreshes the directory
after local verification so current revocations are enforced before upload. A
retiring notary process must run with `--finalize-only`. The
Compose health check compares the advertised active key with the running
notary key. The lifecycle and operator rotation procedure are documented in
[`docs/notary-key-lifecycle-v2.md`](docs/notary-key-lifecycle-v2.md). GitHub
sign-in authorizes publication; the platform signing key is the trust root for
published stamps.

To use an explicit endpoint, set `notary.endpoint` in the local agent
configuration to `tls://host:443` for a public-CA TLS endpoint or `host:7047`
(equivalent to `tcp://host:7047`) for direct TCP. TLS validates the advertised
hostname before the LLMN protocol begins; local development and self-hosted
deployments may continue to use direct loopback TCP.

### Operational telemetry

The server binaries emit structured JSON logs to stderr. They deliberately log
only operational metadata: never add request or response bodies, HTTP headers,
credentials, presigned upload URLs, or `.llmbundle` paths to a log, metric, or
span.

`llm-notary-api` exposes Prometheus text metrics at its internal-only
`GET /metrics` endpoint. It is intentionally not routed through the public
Caddy gateway. The notary exposes the same format when
`LLM_NOTARY_METRICS_LISTEN` is set; Compose binds it on the private Docker
network at `notary:9090/metrics`. Key metrics cover HTTP latency/status,
publication queue depth and verification outcomes, and notary sessions,
timeouts, and capacity rejections.

Set standard OTLP environment variables such as
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, and
`OTEL_SERVICE_NAME` to export operational spans directly to a compatible
backend. Without an endpoint, tracing remains local JSON logging and metrics
remain available for Prometheus scraping. These operational spans are separate
from the cryptographically verifiable `trace.otlp.json` evidence artifacts.

Authenticated publication intake uses:

- `POST /api/publish/jobs` with an `Idempotency-Key` header to create one
  short-lived finalized-package upload;
- `POST /api/publish/jobs/{id}/complete` to freeze the uploaded object under a
  server-only key and queue it;
- `GET /api/publish/jobs/{id}` to poll status.

The create body declares `archive_format`, `size_bytes`, and `sha256`. The
current format identifier is `llmnotary.trace-package-archive/v2`, with media
type `application/vnd.llmnotary.trace-package+zip`. The API checks object size
and signed upload metadata before queueing, but the declared hash remains
untrusted until the admission worker downloads and hashes the actual bytes.
Encrypted `.llmbundle` files are local retry state and are never valid uploads.
The complete request, response, idempotency, and storage-boundary contract is
documented in [`docs/publish-intake-v1.md`](docs/publish-intake-v1.md).

Queued uploads are admitted by database-coordinated workers in every API
replica. PostgreSQL claims a queued job with row locking and `SKIP LOCKED`, so
only one replica verifies a job; Library metadata has the same lease pattern.
The worker downloads and hashes the actual private object, validates the
transport archive, verifies the notary evidence and authenticated provider,
reproduces the exact canonical trace, enforces credential-header redaction,
and issues the platform stamp. Immutable public bodies live under a distinct
private Spaces `public/` prefix while PostgreSQL retains their object keys,
sizes, and hashes. Public trace and stamp files are available under
`/api/public/traces/{id}` only after the pair is committed atomically;
the private intake object is then purged. The consent and retention boundary,
state machine, rejection codes, and public endpoints are documented in
[`docs/publication-admission-v1.md`](docs/publication-admission-v1.md).

### Publication sign-in

Before submitting a finalized trace, start the existing device authorization
flow through the local API:

```bash
curl -X POST \
  -H 'content-type: application/json' -d '{}' \
  http://127.0.0.1:8788/v1/publication/auth
```

The response contains a short code and browser URL. Open that URL in any browser
already signed in to your configured public LLM Notary site, inspect the requested local device
name and code, and approve it. The service polls using a separate high-entropy
secret; the displayed code alone cannot approve or retrieve credentials.
When the device-flow request sets `api_origin` for a self-hosted site, use
HTTPS; plain HTTP is accepted only for a loopback development origin.

GitHub is used only by the website to identify the account. The service never
receives, logs, or persists a GitHub token. It stores only an LLM Notary
rotating refresh credential, in the macOS Keychain when available or otherwise
in a mode-`0600` configuration file. Check or revoke the local session through
`GET` or `DELETE /v1/publication/auth`.

Publish access credentials last 15 minutes. Refresh credentials expire after
90 days, rotate on every use, and a replayed refresh credential revokes its
session.

### Publish a finalized package

The publication operation accepts only a finalized capture identifier. It
snapshots the cataloged `.llmtrace` file, then
verifies the TLSNotary evidence, trusted notary key, authenticated HTTP
disclosure, and deterministic OTLP mapping from that exact snapshot. Only
after those checks pass does it refresh the publication login and create an upload job:

```bash
curl -X POST \
  http://127.0.0.1:8788/v1/captures/cap-example/publications
```

The service validates the deterministic
`llmnotary.trace-package-archive/v2` snapshot in memory, then uploads those
exact `.llmtrace` bytes through the
job-scoped presigned URL, completes the upload, and returns the durable job ID
and local status URL. Its idempotency key is derived from the archive hash, so
repeating the operation for identical bytes resumes the same job after an
ambiguous network failure. The response contains `capture_id`, `job_id`,
`state`, and `status_url`.

Poll admission through the local service; the browser or agent
does not need the separate vault-held publication credential:

```bash
job_id=job-example
curl --fail-with-body \
  "http://127.0.0.1:8788/v1/publications/$job_id"
```

`GET /v1/publications/{job_id}` returns the current state, a bounded failure
code when applicable, and public trace and stamp URLs only after admission.

Publishing is an explicit consent boundary: the current admission design may
inspect the disclosed plaintext in the finalized package to reproduce and
verify the public trace. Provider credentials and cookie values remain
redacted. The encrypted `.llmbundle` is private retry state and is never a
valid input to the publication endpoint.

## Important trust statement

This proof demonstrates the central cryptographic property: a local client
cannot unilaterally fabricate provider response bytes and obtain a valid notary
attestation. A verifier still chooses to trust the notary signing key and the
TLSNotary implementation. Provider-native response signatures would remain a
stronger final design.
