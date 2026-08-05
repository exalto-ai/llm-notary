# Getting started

This guide builds the pre-release local service from source, captures one
provider call, and explains the next finalization and verification steps.

LLM Notary has not published a release or stable file-format promise. The
checked-in installer becomes usable only after a version tag creates matching
GitHub release assets.

## Requirements

- Rust 1.95.0. The repository's `rust-toolchain.toml` selects it.
- A C toolchain for the vendored cryptographic dependencies.
- A provider API key for an optional real capture. Ordinary tests do not need
  one.
- Node.js 24 and npm only for the public site and dashboard source.

## Install the local programs from source

```bash
git clone https://github.com/exalto-ai/llm-notary.git
cd llm-notary
cargo install --locked --path crates/llm-notary-client
```

The two programs have separate jobs:

- `llm-notaryd` is the long-running local proxy and administration daemon.
- `llm-notary` is a short-lived REST client for that daemon.

`llm-notary` does not start the service and does not open the catalog, vault,
or artifacts directly.

## Start the daemon

```bash
llm-notaryd
```

The first start writes `config.toml` once and initializes the bundle vault. The
default configuration enables all four providers and binds only these distinct
loopback listeners:

| Listener | Address | Purpose |
| --- | --- | --- |
| Provider proxy | `127.0.0.1:8787` | Provider-compatible API requests |
| Administration | `127.0.0.1:8788` | Dashboard, health, OpenAPI, and `/v1` |

Configuration locations are:

- Linux: `$XDG_CONFIG_HOME/llm-notary/config.toml` when `XDG_CONFIG_HOME` is
  set, otherwise `~/.config/llm-notary/config.toml`
- macOS: `~/Library/Application Support/llm-notary/config.toml`
- Windows: `%APPDATA%\llm-notary\config.toml`

Use an explicit file when developing isolated configurations:

```bash
llm-notaryd --config /path/to/config.toml
```

Pass the same `--config` option to `llm-notary` commands.

## Check the local service

Open [http://127.0.0.1:8788](http://127.0.0.1:8788), or query it directly:

```bash
curl --fail-with-body http://127.0.0.1:8788/healthz
curl --fail-with-body http://127.0.0.1:8788/openapi.json
llm-notary status
```

The administration API is open to other local processes by default. Configure
`admin.auth` when that is too broad for the machine. Both listeners remain
loopback-only even when authentication is enabled. See [Local service and REST
API](local-service.md#start-and-supervise-the-service).

## Choose a notary

With no explicit notary configuration, the daemon obtains one-time hosted
admission and the versioned notary directory from the configured public LLM
Notary origin. The directory is authenticated by HTTPS; it is not a separately
signed document. The client pins accepted generations and key lifecycle state
locally.

For local or self-hosted development, start a notary and explicitly pin its
key:

```bash
openssl rand -hex 32 > notary.dev.key
cargo run -p llm-notary-server --bin llm-notary-server -- \
  --signing-key notary.dev.key
```

The process prints its compressed SEC1 public key. Stop the local daemon, then
set both values in its `config.toml`:

```toml
[notary]
endpoint = "tcp://127.0.0.1:7047"
public_key = "02..."
```

An explicit endpoint without its expected key is rejected. Restart the daemon
after editing the file.

For CI, cron, or an unattended host that cannot preserve rotating device
credentials, inject a stable scoped platform API key into `llm-notaryd`. See
[API keys for automation](api-key-automation.md). The key is separate from the
provider API key used by the model client.

## Capture one call

Keep the API key in the provider client and replace only its base URL. For an
OpenAI Responses request:

```bash
curl http://127.0.0.1:8787/openai/v1/responses \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"YOUR_RESPONSES_MODEL","input":"Reply with exactly: llm-notary"}'
```

Use a model available to the provider account. See [Provider and agent
setup](provider-setup.md) for every route and the Codex configuration.

The response is relayed normally. After it ends, the daemon records a catalog
row and vault-encrypts `<capture-id>.llmcapture`. The capture file is a private
checkpoint containing enough information to reconstruct the original request,
including its credential. Do not inspect, copy, or upload it as though it were
a proof.

Find the capture without decrypting every bundle:

```bash
llm-notary captures list --provider openai --limit 20
llm-notary captures show cap-example
```

## Finalize and verify

Only captured `2xx` responses are currently eligible for finalization.
Finalization is asynchronous and can take much longer than capture:

```bash
llm-notary finalize cap-example
llm-notary operations show op-example --json
```

Poll while the operation is `queued` or `running`. Its terminal state is
`finalized`, `failed`, or `interrupted`. A successful operation writes one
deterministic `<capture-id>.llmtrace` package and retains the encrypted bundle.

```bash
llm-notary traces verify cap-example
llm-notary traces verify ./cap-example.llmtrace
```

Verification checks the notary evidence, authenticated provider, disclosed
HTTP bytes, package hashes, privacy policy, and exact normalized trace. Read
[Artifact formats and verification](artifact-formats.md) before sharing the
package.

## Next steps

- [Use the dashboard](local-dashboard.md)
- [Configure providers and coding agents](provider-setup.md)
- [Operate the daemon and REST API](local-service.md)
- [Understand the architecture and trust model](architecture.md)
- [Run a self-hosted notary or platform](self-hosting.md)
