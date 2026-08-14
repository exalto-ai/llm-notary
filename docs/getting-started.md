# Getting started

Choose the macOS app for a guided experience, or install the command-line tools
when you need to connect an SDK, coding agent, server, or automated workflow.
Both run the same local capture service and keep private capture material on
your machine.

LLM Notary is pre-release and does not yet promise stable compatibility or file
formats. The website's `latest` channel is deliberately moving: each successful
publication replaces the previous release.

## Choose an interface

| | macOS app | CLI and local service |
| --- | --- | --- |
| Best for | Most people using a supported Mac | Developers, system administrators, and automation |
| Setup | Guided first run | Shell installer and explicit service control |
| Daily use | Native window and menu-bar controls | Terminal, local REST API, or embedded dashboard |
| Integrations | Supported coding tools and providers | SDK routing, coding agents, scripts, CI, and servers |

## Install the macOS app

The app currently supports Apple silicon Macs (M1 or newer) running macOS 12
Monterey or later.

1. Choose **Download for macOS** on the [LLM Notary website](https://llm-notary.exalto.ai/).
2. Open the downloaded DMG.
3. Move LLM Notary to Applications, then launch it.

Production downloads are signed with a Developer ID certificate, notarized by
Apple, and stapled for offline Gatekeeper checks. The app walks through capture
protection, provider selection, and service setup. It then supervises its
bundled local service and opens the complete capture workspace. Normal use does
not require a terminal.

Provider credentials remain in the SDK or coding tool that sends the model
request. The app does not ask for or store them.

See [Desktop app](desktop-app.md) for lifecycle, capture-protection, and
development details.

## Install the CLI and local service

Use this path for SDK and agent integration, scripting, unattended systems, or
direct control of the local API. The installer supports Apple silicon Macs and
x86-64 or ARM64 Linux systems. It requires `curl`, `tar`, and either
`sha256sum` or `shasum`.

```bash
curl -fsSL https://llm-notary.exalto.ai/install.sh | sh
```

The installer selects the current complete `latest` build, verifies the selected
archive against its published SHA-256 value, and places `llm-notaryd` and
`llm-notary` in `~/.local/bin`. Set `LLM_NOTARY_INSTALL_DIR` to choose another
destination. The checksum detects corruption in transit or storage; it is not
an independent signature because the archive and checksum share a publisher.

After the first install, official builds authenticate the signed channel and
release manifest before trusting either binary's size and SHA-256. The client
remembers the highest signed channel revision it accepted, so replaying an
older pointer cannot silently downgrade it:

```bash
llm-notary version
llm-notary update --check
llm-notary update
```

The build ID, not the package's pre-release `0.1.0` label or a timestamp,
decides whether an update is available. Any different build ID is accepted,
including an intentional rollback selected by the trusted `latest` channel.
The updater stages and verifies both programs before changing either one and
keeps rollback copies until both replacements are confirmed. It never stops a
running daemon. Restart `llm-notaryd` yourself after active capture and proof
work finishes. On Windows the daemon must already be stopped. The update is
applied by a short-lived helper after the running CLI exits; the version
command reports the helper's last durable result.

To build from source instead, install Rust 1.95.0 and a C toolchain, then run:

```bash
git clone https://github.com/exalto-ai/llm-notary.git
cd llm-notary
cargo install --locked --path crates/llm-notary-client
```

Node.js 24 and npm are needed only for public-site and dashboard development.

The two installed programs have separate jobs:

- `llm-notaryd` is the long-running local proxy and administration daemon.
- `llm-notary` is a short-lived REST client for that daemon.

`llm-notary` does not start the service and does not open the catalog, vault,
or artifacts directly.

## Start the daemon

```bash
llm-notaryd
```

The first start writes `config.toml` once and initializes the bundle vault. The
default configuration enables the five built-in routes and binds only these
distinct loopback listeners:

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
setup](provider-setup.md) for every route, including the live-tested Codex CLI
and Claude Code subscription configurations.

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
llm-notary finalize cap-example --wait
```

Without `--wait`, save the returned operation identifier and poll it while the
operation is `queued` or `running`. With `--wait`, the CLI follows the operation
and reports authenticated transcript bytes and completed commitments. Its
terminal state is `finalized`, `failed`, or `interrupted`. A successful
operation writes one deterministic `<capture-id>.llmtrace` package and retains
the encrypted bundle. `--json --wait` suppresses intermediate lines so standard
output remains one JSON value.

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
