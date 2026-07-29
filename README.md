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

List the locally encrypted bundles, then finalize one with the notary public
key printed at notary startup:

```bash
llm-notary bundles list
llm-notary finalize bundles/cap-....llmbundle \
  --output traces/cap-... \
  --trusted-notary-key <notary-public-key>
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
llm-notary verify-trace traces/cap-... \
  --trusted-notary-key <notary-public-key>
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
or malformed key.
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
`POST /api/auth/logout`, and `GET /api/healthz`, plus publication endpoints
for admitting a standardized trace and serving its OTLP JSON and stamp. Set
`LLM_NOTARY_NOTARY_HOST` and `LLM_NOTARY_NOTARY_PUBLIC_KEY` to the public TCP
notary hostname and its compressed SEC1 public key. The directory contains a
stable key ID, validity interval, and any prior keys still accepted for the
rotation window. Clients cache the last successful directory record, so offline
verification only trusts cached keys. The Compose health check compares the
advertised key with the running notary key. GitHub sign-in authorizes publication; the platform signing key is
the trust root for published stamps.

For a key rotation, advertise the new key as active and add the old key to
`LLM_NOTARY_NOTARY_PREVIOUS_KEYS_JSON` with `status: "previous"` and a finite
`valid_until_unix`. New proxy sessions use only the active key; cached records
keep already-finalized captures verifiable until the old key expires.

### CLI publishing sign-in

Before submitting a capture for publication, authorize the installed CLI with
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

## Important trust statement

This proof demonstrates the central cryptographic property: a local client
cannot unilaterally fabricate provider response bytes and obtain a valid notary
attestation. A verifier still chooses to trust the notary signing key and the
TLSNotary implementation. Provider-native response signatures would remain a
stronger final design.
