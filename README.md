# LLM Notary

LLM Notary is an early Rust implementation of independently verifiable
LLM traces. A local proxy receives an ordinary API request, performs a real
TLSNotary Proxy-TLS session with a remote notary, and stores a portable
TLSNotary presentation. The API key remains in the local request; the notary
relays encrypted TLS packets and never receives application plaintext.

## Current scope

- HTTP/1.1 `POST` API requests, including Server-Sent Events (`stream: true` or
  `Accept: text/event-stream`). SSE bytes are relayed as they arrive; the proof
  is constructed and saved only after the terminal frame.
- Proxy-TLS: the remote notary resolves and opens the TCP connection to the
  allowlisted provider, while the local machine performs the TLS handshake.
  This avoids MPC-TLS's per-byte online cost without giving the notary the API
  key or plaintext trace.
- OpenAI (`api.openai.com`) and Anthropic (`api.anthropic.com`) host allowlist.
- An independently verifiable presentation which discloses the complete request
  and response but redacts `Authorization` and `x-api-key` values.
- The notary, not the local machine, resolves and connects to the allowed
  provider hostname. The local TLS client validates that provider's certificate
  chain with Mozilla roots, so local DNS cannot substitute an endpoint.

Streaming responses are relayed from the provider without synthetic events.
Their trace package is written only after the terminal frame, because a TLS
transcript cannot be attested until it is complete.

It is **not production-ready**. In particular, receipt-key distribution,
notary authentication, rate limiting, raw WebSockets, encrypted marketplace
storage, multiple notaries, and a transparency log remain to be built.

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

In another terminal start the proxy:

```bash
cargo run --bin llm-notary -- proxy start --provider openai --trace-dir traces
```

Point an OpenAI-compatible SDK at `http://127.0.0.1:8787/v1`; keep the API key
in the SDK as usual. The proxy does not accept a provider URL from the caller.
Each supported request writes `traces/trace-XXXXXXXX.json`.

Verify a trace without contacting LLM Notary:

```bash
cargo run --bin llm-notary -- verify traces/trace-00000001.json --trusted-notary-key <notary-public-key>
```

The verifier checks the TLSNotary presentation locally and prints the disclosed
request and response only after checking the expected notary public key. A
production version should distribute that key through a signed public-key
directory and transparency log.

Pass `--summary` to verify the certificate and hashes without printing the
disclosed transcript.

With an installed release, use the public command instead:

```bash
llm-notary proxy start --provider openai --trace-dir traces
llm-notary verify traces/trace-00000001.json --trusted-notary-key <notary-public-key>
```

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

This remains an HTTP/1.1 prototype. WebSocket relaying, production notary
authentication and authorization, receipt-key distribution, and marketplace
storage still need product-grade implementations.

## Important trust statement

This proof demonstrates the central cryptographic property: a local client
cannot unilaterally fabricate provider response bytes and obtain a valid notary
attestation. A verifier still chooses to trust the notary signing key and the
TLSNotary implementation. Provider-native response signatures would remain a
stronger final design.
