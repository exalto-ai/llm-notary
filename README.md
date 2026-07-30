# LLM Notary

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
- OpenAI (`api.openai.com`), Anthropic (`api.anthropic.com`), and DeepSeek
  (`api.deepseek.com`) host allowlist.
- At the end of each provider response, the proxy encrypts a client-held
  `.llmbundle`. The bundle contains the private transcript checkpoint and a
  notary-signed receipt, but does not perform the expensive private proof.
- `llm-notary finalize` later reconnects to any notary instance holding the
  same signing key, completes the proof, redacts sensitive authentication and
  session-header values, and emits one verified trace package. The notary
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

## Install the CLI

Releases include `llm-notary` for macOS and Linux, with a checksum-verified
installer. The command below is the recommended two-step form so the script is
available for inspection before it runs:

```bash
curl -fsSLO https://llmnotary.exalto.ai/install.sh
sh install.sh
```

Windows x86_64 releases are available as ZIP archives on GitHub Releases.

## Run locally from source

Generate an ephemeral development signing key:

```bash
openssl rand -hex 32 > notary.dev.key
cargo run --bin certified-notary -- --signing-key notary.dev.key
```

The notary prints its public key at startup. Retain that value for local or
private deployments, where it is supplied with `--trusted-notary-key` as the
explicit trust anchor. Production clients discover and pin the public key.

In another terminal start the proxy. By default the released CLI discovers the
current public notary endpoint from `https://llmnotary.exalto.ai/api/notary`.
For a local notary, pass its address explicitly:

```bash
cargo run --bin llm-notary -- proxy start --notary 127.0.0.1:7047 --provider openai --bundle-dir bundles
```

Point an OpenAI-compatible SDK at `http://127.0.0.1:8787/v1`; keep the API key
in the SDK as usual. The proxy does not accept a provider URL from the caller.
Each completed request writes an encrypted `bundles/cap-....llmbundle`. On
macOS and Windows, the default vault key is stored in the OS credential store;
on Linux it uses the desktop secret service. To use a passphrase instead
(including an intentionally empty passphrase), initialize the vault before
starting the proxy:

```bash
llm-notary vault init --passphrase
```

Set `LLM_NOTARY_CONFIG_DIR` to use a non-default vault configuration directory,
which is useful for isolated development and automation.

## Finalize a bundle

List the locally encrypted bundles, then finalize one. The CLI fetches and
caches the production directory key automatically:

```bash
llm-notary bundles list
llm-notary finalize bundles/cap-....llmbundle \
  --output traces/cap-...
```

The output directory is a single portable package:

```text
traces/cap-.../
├── evidence.tlsn
├── manifest.json
├── request.disclosed.http
├── response.http
└── trace.otlp.json
```

Verify it offline by rechecking the TLSNotary presentation, every source-file
hash, the provider adapter, and the exact canonical OTLP bytes:

```bash
llm-notary verify-trace traces/cap-...
```

The encrypted bundle is the most sensitive artifact: its deferred TLS
checkpoint can reconstruct the complete original request, including
`Authorization` or `x-api-key` values. Keep the vault protected and do not
share `.llmbundle` files. Finalized packages reveal only the authenticated
header names—not values—for `Authorization`, `Proxy-Authorization`, `Cookie`,
`x-api-key`, and response `Set-Cookie`. The finalized trace retains normalized
system context, messages, model-emitted tool calls and results, usage, and
finish reasons when the provider supplies them. A provider trace proves the
model exchange; it does not claim that a local runtime actually executed a
requested tool.

### DeepSeek

DeepSeek's OpenAI-compatible Chat Completions API can be traced through the
same proxy. Start it with `--provider deepseek`, point the client to
`http://127.0.0.1:8787`, and retain `DEEPSEEK_API_KEY` in the client
environment:

```bash
cargo run --bin llm-notary -- proxy start --provider deepseek --bundle-dir bundles

curl http://127.0.0.1:8787/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The default DeepSeek endpoint is `https://api.deepseek.com` (without a `/v1`
suffix); the proxy preserves the requested API path.

The older private-capture verifier remains available for capture directories:

```bash
cargo run --bin llm-notary -- verify captures/cap-...
```

The verifier checks the TLSNotary presentation locally and prints the disclosed
request and response only after checking a locally pinned directory key. The
HTTPS LLM Notary directory is the initial online trust bootstrap; a package
cannot add its own trusted key. Use `--trusted-notary-key` to explicitly
override that bootstrap for private notaries or independent verification.

Pass `--summary` to verify the certificate and hashes without printing the
disclosed transcript.

With an installed release, use the public command instead:

```bash
llm-notary proxy start --provider openai --bundle-dir bundles
```

Verify a published trace and platform stamp without a capture:

```bash
llm-notary verify-public trace.otlp.json stamp.json \
  --trusted-platform-key <platform-public-key>
```

The verifier hashes `trace.otlp.json`, checks the platform signature, and
reports the provider, verification time, and normalizer version named in the
stamp.

Download a public Library publication, verify it before it is made visible in
the output directory, and keep the two public artifacts together:

```bash
llm-notary download 3d3d727f-e0b1-432e-be3c-0b2e3ead35d1 --verify
```

By default this creates `./3d3d727f-e0b1-432e-be3c-0b2e3ead35d1/` containing
`trace.otlp.json` and `stamp.json`. Use `--output path/to/directory` to choose
another directory, or `--overwrite` only when replacing an existing completed
download is intended. The command resolves public artifact links through the
API, rejects redirects and non-JSON responses, and leaves no completed output
directory if transfer or verification fails. With `--verify`, it obtains the
platform directory from the configured API origin and checks the canonical
trace bytes, trace hash, public-stamp contract versions, platform key ID,
stamp issuer, and ECDSA signature before reporting success. Use `--api` for a
local loopback or HTTPS self-hosted API origin.

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

Several verified private captures can be normalized in CLI order as spans in a
single conversation trace. This deliberately excludes runtime-reported agent
and tool-execution spans: a model requesting a tool is recorded as a message
part; no claim is made that a local runtime actually executed it.

`stamp.json` has format `llm-notary/platform-stamp/v1` and includes the issuer,
SHA-256-derived platform key ID, issue time in Unix milliseconds, trace
SHA-256, capture format, normalizer version, OpenTelemetry semantic-convention
version, canonicalization ID, and provider provenance (`name`, `host`, and
`tlsnotary-presentation/v1`). Its `signature` is a compact, low-S secp256k1
ECDSA signature over the SHA-256 of the canonical JSON encoding of every stamp
field except `signature`; the signing payload has the same lexicographic JSON
rule but no trailing LF. `verify-public` checks every version and provenance
claim against the trace before it verifies the signature.

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

[model_providers.llm-notary]
name = "LLM Notary local proxy"
base_url = "http://127.0.0.1:8787/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
supports_websockets = false
```

For a one-off CLI invocation (with `OPENAI_API_KEY` already in the
environment):

```bash
CODEX_HOME=$(mktemp -d) codex exec --ephemeral --skip-git-repo-check \
  -m gpt-4.1-mini \
  -c 'model_provider="llm-notary"' \
  -c 'model_providers.llm-notary.name="LLM Notary local proxy"' \
  -c 'model_providers.llm-notary.base_url="http://127.0.0.1:8787/v1"' \
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

The notary bounds expensive work with private-proof byte/commitment limits, a
global concurrent-session limit, and a wall-clock session timeout. Deferred
receipts are replayable by design because the service is stateless, so a public
deployment still needs authenticated per-user quotas before open access.

## Website sign-in

The website supports GitHub OAuth for the account surface. The API only asks
GitHub to identify the account; it requests no repository, organization, or
email scopes. Configure a GitHub OAuth App with this production callback URL:

```text
https://llmnotary.exalto.ai/api/auth/github/callback
```

Set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` for the API.
Also set `LLM_NOTARY_NOTARY_PUBLIC_KEY` to the compressed SEC1 public key for
the configured notary signing key; the API refuses to advertise an unchecked
or malformed key. Planned rotation can supply a complete v2 directory through
`LLM_NOTARY_NOTARY_DIRECTORY_JSON`; its active key must match the colocated
notary key.
For source development, `LLM_NOTARY_PUBLIC_ORIGIN` defaults to
`http://localhost:4173` and the API creates a local SQLite database. GitHub
OAuth Apps have one callback URL, so use a separate development OAuth App with
`http://localhost:4173/api/auth/github/callback` and place that app's
credentials in the local `.env`. Start the API alongside the SPA with:

```bash
cargo run --bin llm-notary-api
```

The API has `GET /api/notary` for CLI endpoint and public-key discovery,
`GET /api/auth/github`, `GET /api/auth/github/callback`, `GET /api/me`,
`POST /api/auth/logout`, and `GET /api/healthz`, plus authenticated publication
intake endpoints and publication endpoints for serving admitted traces. Set
`LLM_NOTARY_NOTARY_HOST` and `LLM_NOTARY_NOTARY_PUBLIC_KEY` to the public TCP
notary hostname and its compressed SEC1 public key. The v2 directory contains
stable key IDs, monotonic generations, separate capture/finalization
deadlines, and endpoints for an active key and historical rotation records.
Clients reject directory rollback, cache revocation monotonically, route
pending bundles to an active or retiring signer, and retain retired keys for
timestamp-scoped offline verification. `publish` refreshes the directory after
local verification so current revocations are enforced before upload. A
retiring notary process must run with `--finalize-only`. The
Compose health check compares the advertised active key with the running
notary key. The lifecycle and operator rotation procedure are documented in
[`docs/notary-key-lifecycle-v2.md`](docs/notary-key-lifecycle-v2.md). GitHub
sign-in authorizes publication; the platform signing key is the trust root for
published stamps.

Authenticated CLI publication intake uses:

- `POST /api/publish/jobs` with an `Idempotency-Key` header to create one
  short-lived finalized-package upload;
- `POST /api/publish/jobs/{id}/complete` to freeze the uploaded object under a
  server-only key and queue it;
- `GET /api/publish/jobs/{id}` to poll status.

The create body declares `archive_format`, `size_bytes`, and `sha256`. The
current format identifier is `llmnotary.trace-package-archive/v1`, with media
type `application/vnd.llmnotary.trace-package+zip`. The API checks object size
and signed upload metadata before queueing, but the declared hash remains
untrusted until the admission worker downloads and hashes the actual bytes.
Encrypted `.llmbundle` files are local retry state and are never valid uploads.
The complete request, response, idempotency, and storage-boundary contract is
documented in [`docs/publish-intake-v1.md`](docs/publish-intake-v1.md).

Queued uploads are admitted by a database-backed worker in the API process.
The worker downloads and hashes the actual private object, validates the
transport archive, verifies the notary evidence and authenticated provider,
reproduces the exact canonical trace, enforces credential-header redaction,
and issues the platform stamp. Immutable public bodies live under a distinct
private Spaces `public/` prefix while SQLite retains their object keys, sizes,
and hashes. Public trace and stamp files are available under
`/api/public/traces/{id}` only after the pair is committed atomically;
the private intake object is then purged. The consent and retention boundary,
state machine, rejection codes, and public endpoints are documented in
[`docs/publication-admission-v1.md`](docs/publication-admission-v1.md).

### CLI publishing sign-in

Before submitting a finalized trace package, authorize the installed CLI with
your LLM Notary account:

```bash
llm-notary login
```

The command prints a short code and a browser URL. Open that URL in any browser
already signed in to `llmnotary.exalto.ai`, inspect the requested CLI device
name and code, and approve it. The CLI polls using a separate high-entropy
secret; the displayed code alone cannot approve or retrieve credentials.

GitHub is used only by the website to identify the account. The CLI never
receives, logs, or persists a GitHub token. It stores only an LLM Notary
rotating refresh credential, in the macOS Keychain when available or otherwise
in a mode-`0600` configuration file. Check or revoke the local session with:

```bash
llm-notary whoami
llm-notary logout
```

Publish access credentials last 15 minutes. Refresh credentials expire after
90 days, rotate on every use, and a replayed refresh credential revokes its
session.

### Publish a finalized package

`publish` accepts exactly one directory produced by `llm-notary finalize`. It
first snapshots that directory into the deterministic transport archive, then
verifies the TLSNotary evidence, trusted notary key, authenticated HTTP
disclosure, and deterministic OTLP mapping from that exact snapshot. Only
after those checks pass does it refresh the CLI login and create an upload job:

```bash
llm-notary publish verified-trace
```

The command creates a deterministic
`llmnotary.trace-package-archive/v1` object in memory, uploads it through the
job-scoped presigned URL, completes the upload, and prints the durable job ID
and status URL. Its idempotency key is derived from the archive hash, so
repeating the command for identical bytes resumes the same job after an
ambiguous network failure. Use `--json` for a single script-friendly object
containing `job_id`, `state`, and `status_url`.

Publishing is an explicit consent boundary: the current admission design may
inspect the disclosed plaintext in the finalized package to reproduce and
verify the public trace. Provider credentials and cookie values remain
redacted. The encrypted `.llmbundle` is private retry state and is never a
valid input to `publish`.

## Important trust statement

This proof demonstrates the central cryptographic property: a local client
cannot unilaterally fabricate provider response bytes and obtain a valid notary
attestation. A verifier still chooses to trust the notary signing key and the
TLSNotary implementation. Provider-native response signatures would remain a
stronger final design.
