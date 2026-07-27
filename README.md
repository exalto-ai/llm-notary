# LLM Notary

LLM Notary publishes provider-origin model behavior as portable OpenTelemetry
traces. A local proxy receives an ordinary API request and performs a real
TLSNotary Proxy-TLS session with a remote notary. When the author publishes,
LLM Notary verifies that private source capture and admits a standardized OTLP
trace with a signed platform stamp. The API key remains in the local request;
the notary relays encrypted TLS packets and never receives application
plaintext.

## Current scope

- HTTP/1.1 `POST` API requests, including Server-Sent Events (`stream: true` or
  `Accept: text/event-stream`). SSE bytes are relayed as they arrive; the proof
  is constructed and saved only after the terminal frame.
- Proxy-TLS: the remote notary resolves and opens the TCP connection to the
  allowlisted provider, while the local machine performs the TLS handshake.
  This avoids MPC-TLS's per-byte online cost without giving the notary the API
  key or plaintext trace.
- OpenAI (`api.openai.com`), Anthropic (`api.anthropic.com`), and DeepSeek
  (`api.deepseek.com`) host allowlist.
- A private local capture directory with an independently verifiable
  presentation, a selectively disclosed request, and the authenticated provider
  response. `Authorization` and `x-api-key` values are never saved.
- Published artifacts are `trace.otlp.json` and `stamp.json`, not a capture
  directory. The OTLP trace carries normalized GenAI spans; the platform stamp
  signs its exact hash after LLM Notary verifies the private source capture.
- The notary, not the local machine, resolves and connects to the allowed
  provider hostname. The local TLS client validates that provider's certificate
  chain with Mozilla roots, so local DNS cannot substitute an endpoint.

Streaming responses are relayed from the provider without synthetic events.
Their trace package is written only after the terminal frame, because a TLS
transcript cannot be attested until it is complete.

Published stamps are a platform assertion, separate from the TLSNotary
presentation used during admission. A recipient can verify a stamp and the
standardized trace without receiving the raw provider request, response, or
TLSNotary evidence.

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

The notary prints its public key at startup. Save that value; it is required to
verify a receipt and is the explicit trust anchor.

In another terminal start the proxy. By default the released CLI discovers the
current public notary endpoint from `https://llmnotary.exalto.ai/api/notary`.
For a local notary, pass its address explicitly:

```bash
cargo run --bin llm-notary -- proxy start --notary 127.0.0.1:7047 --provider openai --capture-dir captures
```

Point an OpenAI-compatible SDK at `http://127.0.0.1:8787/v1`; keep the API key
in the SDK as usual. The proxy does not accept a provider URL from the caller.
Each completed request writes `captures/cap-.../` with `manifest.json`,
`evidence.tlsn`, `request.disclosed.http`, and `response.http`. Capture
directories are private verification inputs; they are not the public format.

## Publish a trace

Publishing converts a private capture to a normalized OpenTelemetry GenAI
trace, checks that trace against the authenticated source capture, and returns
the two shareable artifacts:

```bash
llm-notary publish captures/cap-... \
  --title "Refusal boundary test" \
  --license "CC BY 4.0"
```

```text
published/
├── trace.otlp.json  # portable OpenTelemetry GenAI spans
└── stamp.json       # LLM Notary signature over the exact trace hash
```

`trace.otlp.json` is the collection record. It can include model inference
spans, normalized input/output messages, model-emitted tool calls, timing, and
usage. Tool execution spans supplied by an agent runtime are marked as
runtime-reported; a provider capture proves the model call, not execution in a
local tool process.

The source capture is used to verify publication and is not retained as the
published artifact. `stamp.json` is independent of the TLSNotary proof: it is
LLM Notary's signed statement that it verified source evidence for the exact
normalized trace at publication time.

### DeepSeek

DeepSeek's OpenAI-compatible Chat Completions API can be traced through the
same proxy. Start it with `--provider deepseek`, point the client to
`http://127.0.0.1:8787`, and retain `DEEPSEEK_API_KEY` in the client
environment:

```bash
cargo run --bin llm-notary -- proxy start --provider deepseek --capture-dir captures

curl http://127.0.0.1:8787/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-v4-flash","messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The default DeepSeek endpoint is `https://api.deepseek.com` (without a `/v1`
suffix); the proxy preserves the requested API path.

Verify a private capture without contacting LLM Notary:

```bash
cargo run --bin llm-notary -- verify captures/cap-... --trusted-notary-key <notary-public-key>
```

The verifier checks the TLSNotary presentation locally and prints the disclosed
request and response only after checking the expected notary public key. A
production version should distribute that key through a signed public-key
directory and transparency log.

Pass `--summary` to verify the certificate and hashes without printing the
disclosed transcript.

With an installed release, use the public command instead:

```bash
llm-notary proxy start --provider openai --capture-dir captures
llm-notary verify captures/cap-... --trusted-notary-key <notary-public-key>
```

Verify a published trace and platform stamp without a capture:

```bash
llm-notary verify-public trace.otlp.json stamp.json \
  --trusted-platform-key <platform-public-key>
```

The verifier hashes `trace.otlp.json`, checks the platform signature, and
reports the provider, verification time, and normalizer version named in the
stamp.

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

Validated locally with a streamed 45 KB OpenAI request and with the one-off
Codex command above (8,837 input tokens): both streamed normally and the Codex
trace verified against the notary public key. The vendored TLSNotary relay has
a small drain-scheduling fix for multi-frame encrypted requests; upstream
would otherwise forward only the first mux frame until unrelated I/O occurred.

This remains an HTTP/1.1 prototype. WebSocket relaying, multiple notaries, and
a public transparency log remain future work.

## Website sign-in

The website supports GitHub OAuth for the account surface. The API only asks
GitHub to identify the account; it requests no repository, organization, or
email scopes. Configure a GitHub OAuth App with this production callback URL:

```text
https://llmnotary.exalto.ai/api/auth/github/callback
```

Set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` for the API.
For source development, `LLM_NOTARY_PUBLIC_ORIGIN` defaults to
`http://localhost:4173` and the API creates a local SQLite database. GitHub
OAuth Apps have one callback URL, so use a separate development OAuth App with
`http://localhost:4173/api/auth/github/callback` and place that app's
credentials in the local `.env`. Start the API alongside the SPA with:

```bash
cargo run --bin llm-notary-api
```

The API has `GET /api/notary` for CLI endpoint discovery,
`GET /api/auth/github`, `GET /api/auth/github/callback`, `GET /api/me`,
`POST /api/auth/logout`, and `GET /api/healthz`, plus publication endpoints
for admitting a standardized trace and serving its OTLP JSON and stamp. Set
`LLM_NOTARY_NOTARY_HOST` to the public TCP notary hostname or reserved IP;
this keeps that deployment detail out of released clients and permits endpoint
rotation. GitHub sign-in authorizes publication; the platform signing key is
the trust root for published stamps.

## Important trust statement

This proof demonstrates the central cryptographic property: a local client
cannot unilaterally fabricate provider response bytes and obtain a valid notary
attestation. A verifier still chooses to trust the notary signing key and the
TLSNotary implementation. Provider-native response signatures would remain a
stronger final design.
