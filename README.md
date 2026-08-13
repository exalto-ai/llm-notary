# LLM Notary

LLM Notary records model-provider API calls through a local proxy and turns
selected calls into portable, independently verifiable OpenTelemetry trace
packages.

> [!IMPORTANT]
> LLM Notary is a pre-release prototype with no stable compatibility promise.
> The website's `latest` binaries track the latest published `main` build, so
> expect artifact, API, and configuration formats to change without a new
> version number.

## What it proves

A valid `.llmtrace` package proves that its disclosed request and response
bytes came from a TLS connection to the named provider, as witnessed by a
trusted LLM Notary signing key. Verification also checks every package hash and
reproduces the canonical OpenTelemetry trace from those authenticated bytes.

It does not prove that a model response is correct, that a person authored the
prompt, that a local tool ran, or that every call in a larger agent session was
disclosed. A verifier must independently decide which notary keys to trust.

## How it works

```text
model client
    │ provider-compatible HTTP/1.1
    ▼
local llm-notaryd ── encrypted TLS records ── remote notary ── provider
    │                                              │
    │ encrypted private checkpoint                │ signed receipt / proof
    ▼                                              │
<capture-id>.llmcapture ─── deferred finalization ─┘
    │
    ▼
<capture-id>.llmtrace ── local or hosted verification
```

The local daemon sees the provider credential, prompt, and response. The
remote notary resolves and connects to an allowlisted provider and relays the
encrypted TLS records, but does not receive the application plaintext or API
key. The local TLS client validates the provider certificate.

Capture stays on the interactive path; private proof generation does not. At
the end of a provider response, the daemon vault-encrypts a deferred
`.llmcapture`. Finalization later reconnects to a compatible notary and writes
one deterministic `.llmtrace` ZIP:

```text
<capture-id>.llmtrace
├── archive-manifest.json
├── evidence.tlsn
├── manifest.json
├── request.disclosed.http
├── response.disclosed.http
└── trace.otlp.json
```

The package hides every HTTP header value except the exact structural value
`Transfer-Encoding: chunked`. Header names and complete request and response
bodies remain disclosed, so inspect a package before sharing or uploading it.
The `.llmcapture` can reconstruct the original credential-bearing request and
must remain vault-encrypted and local.

## Current scope

- HTTP/1.1 `POST` requests, including Server-Sent Events.
- OpenAI, Anthropic, DeepSeek, and OpenRouter through fixed local routes and an
  explicit upstream hostname allowlist.
- One remote notary per capture or finalization. Hosted clients use a
  versioned key-and-endpoint directory served over authenticated HTTPS;
  self-hosted clients pair an explicit endpoint with an explicit public key.
- Deferred private proof generation and deterministic `.llmtrace` archives.
- Local CLI, dashboard, SQLite capture catalog, and versioned loopback REST
  API.
- Optional consent-based sharing of a finalized session after server-side
  admission verifies and safety-scans its exact source package.

WebSocket proxying, provider-native response signatures, multi-notary proofs,
and a public transparency log are outside the current prototype.

## Install

For a guided setup on an Apple silicon Mac running macOS 12 or later, choose
**Download for macOS** on the [LLM Notary website](https://llm-notary.exalto.ai/),
open the DMG, and move LLM Notary to Applications. Production downloads are
Developer ID signed, notarized by Apple, and stapled for Gatekeeper checks. See
[Desktop app](docs/desktop-app.md) for the supported workflow and development
details.

For SDK integrations, coding agents, scripts, and servers, the moving `latest`
website channel provides command-line builds for Apple silicon Macs and x86-64
or ARM64 Linux systems. It installs both `llm-notaryd` and `llm-notary` into
`~/.local/bin` by default:

```bash
curl -fsSL https://llm-notary.exalto.ai/install.sh | sh
```

Set `LLM_NOTARY_INSTALL_DIR` to choose another destination. The installer
downloads the platform archive and its SHA-256 file from the website and
rejects a mismatch. Because both files come from the same publishing system,
that checksum detects download corruption but is not an independent release
signature.

Official command-line builds can then authenticate and install the signed
`latest` channel without contacting the daemon:

```bash
llm-notary update --check
llm-notary update
```

An update replaces the CLI and daemon together. On Unix it does not stop a
running daemon; restart the service only after captures and finalizations are
idle. On Windows, stop the daemon before updating.
Source builds report the latest signed build but do not overwrite themselves.

Building the current source instead requires:

- Rust 1.95.0, selected automatically by `rust-toolchain.toml`.
- A C toolchain required by the vendored cryptographic dependencies.
- Node.js 24 and npm only when building or testing the web applications.

```bash
git clone https://github.com/exalto-ai/llm-notary.git
cd llm-notary
cargo install --locked --path crates/llm-notary-client
```

Start `llm-notaryd` in the foreground. On first start it creates an editable
`config.toml` in the standard user configuration directory and initializes the
local encrypted vault:

```bash
llm-notaryd
```

The daemon serves two distinct loopback listeners:

| Listener | Default | Purpose |
| --- | --- | --- |
| Provider proxy | `http://127.0.0.1:8787` | Provider-compatible requests and private capture |
| Administration | `http://127.0.0.1:8788` | Dashboard, health, OpenAPI, and `/v1` operations |

Open [http://127.0.0.1:8788](http://127.0.0.1:8788), or use the REST-backed
command client:

```bash
llm-notary status
llm-notary captures list --limit 20
```

## Connect a provider client

Keep the provider API key in the original client and replace only its base URL:

| Provider | Local base URL | Authenticated upstream |
| --- | --- | --- |
| OpenAI | `http://127.0.0.1:8787/openai/v1` | `api.openai.com` |
| Anthropic | `http://127.0.0.1:8787/anthropic` | `api.anthropic.com` |
| DeepSeek | `http://127.0.0.1:8787/deepseek` | `api.deepseek.com` |
| OpenRouter | `http://127.0.0.1:8787/openrouter/api/v1` | `openrouter.ai` |

For OpenRouter, the evidence authenticates `openrouter.ai`; a namespaced model
slug is metadata and does not prove a direct connection to the vendor named in
that slug.

See [Provider and agent setup](docs/provider-setup.md) for curl, SDK, Codex,
and streaming examples.

## Finalize and verify

Find a completed capture, queue finalization, and poll the returned operation:

```bash
llm-notary captures list --provider openai
llm-notary finalize cap-example --wait
```

Finalization accepts only captured `2xx` provider responses. It creates
`<capture-id>.llmtrace` without consuming the encrypted source capture. While
the proof is running, the CLI reports authenticated transcript bytes and
completed commitments instead of treating unequal stages as equal progress.

Verify a package without the daemon by using the locally cached notary trust
history, or pass an explicit key for a self-hosted package:

```bash
llm-notary traces verify ./cap-example.llmtrace
llm-notary traces verify ./cap-example.llmtrace --trusted-notary-key 02...
```

The anonymous hosted verifier accepts the same package only after explicit
upload consent. It does not publish or retain the package, and its live result
is not a signed receipt:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/vnd.llmnotary.trace-package+zip' \
  --data-binary @cap-example.llmtrace \
  https://llm-notary.exalto.ai/api/verify
```

Use local verification when the package contents should not leave the
machine.

## Documentation

Start with the [documentation index](docs/README.md):

- [Getting started](docs/getting-started.md)
- [Architecture and trust model](docs/architecture.md)
- [Provider and agent setup](docs/provider-setup.md)
- [Artifact formats and verification](docs/artifact-formats.md)
- [Local service and REST API](docs/local-service.md)
- [Local dashboard](docs/local-dashboard.md)
- [API keys for CI and unattended automation](docs/api-key-automation.md)
- [Self-hosting](docs/self-hosting.md)
- [Development and validation](docs/development.md)

The local service serves its exact OpenAPI 3.1 contract at
`http://127.0.0.1:8788/openapi.json`. The hosted API contract is generated from
the router and committed at
`js/app/src/platform-api/generated/openapi.json`.

## Repository layout

- `crates/llm-notary-core/`: Proxy-TLS protocol, artifact contracts,
  normalization, and verification.
- `crates/llm-notary-client/`: `llm-notaryd`, the local REST API and dashboard,
  and the `llm-notary` command client.
- `crates/llm-notary-server/`: remote notary service.
- `crates/llm-notary-platform/`: hosted identity, admission, verification,
  session-sharing, and Library APIs.
- `js/app/`: public SPA and the embedded local dashboard source.
- `vendor/tlsn/` and `vendor/tlsn-utils/`: pinned, locally patched upstream
  dependencies.

## Security and trust

LLM Notary narrows fabrication risk; it does not remove trust. A verifier
trusts the selected notary key, the TLSNotary and LLM Notary implementations,
and the key-distribution policy. Provider-native signatures would provide a
stronger origin primitive.

Never commit provider keys, notary signing keys, admission tokens, database
URLs, `.env` files, `.llmcapture` files, captures, or decrypted transcript
material. See [Architecture and trust model](docs/architecture.md) before
changing a trust boundary.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and review guidance.
LLM Notary is available under either the [MIT license](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE). Distributed dependency notices are in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
