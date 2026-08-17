import { ChevronDown } from 'lucide-react';
import type { MouseEventHandler, ReactNode } from 'react';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';

type DocPageKey =
  | 'overview'
  | 'how-it-works'
  | 'getting-started'
  | 'hosted-credits'
  | 'trace-packages'
  | 'share';

type DocStep = { title: string; body: string };
type DocCard = { meta: string; title: string; body: string };
type DocColumn = { title: string; items: string[] };
type DocDefinition = { term: string; description: string };
type DocBlock = {
  heading: string;
  body?: string;
  code?: string;
  note?: string;
  items?: string[];
  steps?: DocStep[];
  cards?: DocCard[];
  columns?: DocColumn[];
  definitions?: DocDefinition[];
};
type DocPage = { title: string; lead: string; blocks: DocBlock[] };
type DocOutlineItem = { block: DocBlock; children: DocBlock[] };
type DocNavigationGroup = { label: string; pages: Array<readonly [DocPageKey, string]> };

const installCommand = 'curl -fsSL https://notary.exalto.ai/install.sh | sh';
const sourceInstallCommand = `git clone https://github.com/exalto-ai/notary-runtime.git
cd notary-runtime
cargo install --locked --path crates/notaryd --bin notaryd
cargo install --locked --path crates/llm-notary-cli --bin llm-notary`;

const docPages: Record<DocPageKey, DocPage> = {
  overview: {
    title: 'How LLM Notary fits.',
    lead: 'Run your existing model client through a local proxy, keep encrypted evidence on your machine, and turn only the interactions you choose into independently verifiable OpenTelemetry trace packages.',
    blocks: [
      {
        heading: 'The workflow',
        steps: [
          {
            title: 'Capture',
            body: 'Point an SDK or agent at the local proxy. Requests and streamed responses continue normally while each completed provider call becomes an encrypted local checkpoint.',
          },
          {
            title: 'Choose',
            body: 'Checkpoints wait on your disk. Nothing is shared automatically, and interactive model use does not wait for the expensive proof step.',
          },
          {
            title: 'Notarize',
            body: 'Turn a selected checkpoint into authenticated TLS evidence and a deterministic OTel GenAI trace. This can happen long after the original model call.',
          },
          {
            title: 'Verify or share',
            body: 'Check the package locally, keep it private, or deliberately share its disclosed conversation and portable proof through a stable link.',
          },
        ],
      },
      {
        heading: 'Three states, three jobs',
        cards: [
          {
            meta: 'Private',
            title: 'Encrypted checkpoint',
            body: 'A sensitive local checkpoint that can be notarized later. It is not yet evidence another person can verify.',
          },
          {
            meta: 'Portable',
            title: 'Trace package',
            body: 'TLSNotary evidence, disclosed authenticated HTTP, canonical OTLP, and a manifest binding the files together.',
          },
          {
            meta: 'Public',
            title: 'Shared session',
            body: 'A readable conversation plus the exact admitted .llmtrace package. Unlisted stays out of the Library; Listed opts into discovery.',
          },
        ],
      },
      {
        heading: 'What is automatic',
        items: [
          'The first service start creates or opens the local encrypted-checkpoint vault. On a desktop OS, its random key is stored in the system credential service.',
          'The service discovers the production notary endpoint and public key from the LLM Notary directory, then pins that trust information locally.',
          'Notarization and verification use the pinned notary identity. Normal hosted use does not require copying a public key into an API request.',
          'Provider credentials remain in your existing SDK or agent environment; LLM Notary does not require a project .env file.',
        ],
      },
      {
        heading: 'A first successful run',
        code: `${installCommand}\n\nnotaryd\n# Open http://127.0.0.1:8788 for the local dashboard.\n# Point an OpenAI client at http://127.0.0.1:8787/openai/v1.\n\nllm-notary status\nllm-notary captures list`,
      },
      {
        heading: 'The claim',
        note: 'A trusted notary attests that disclosed bytes came from an authenticated TLS interaction with the named provider, and LLM Notary deterministically binds the OpenTelemetry representation to those bytes.',
      },
    ],
  },
  'how-it-works': {
    title: 'Trust and guarantees',
    lead: 'LLM Notary makes a narrow provenance claim. Understanding who sees what—and what the proof does not establish—is part of using it correctly.',
    blocks: [
      {
        heading: 'Each participant',
        cards: [
          {
            meta: 'User / client',
            title: 'Holds the plaintext',
            body: 'The local proxy sees the request and response. A user cannot change authenticated bytes or invent a provider response and still produce valid notarized evidence.',
          },
          {
            meta: 'Notary',
            title: 'Witnesses ciphertext',
            body: 'The notary sees the provider hostname, encrypted traffic, sizes, timing, and protocol metadata. It does not receive the API key, prompt, or response plaintext.',
          },
          {
            meta: 'Provider',
            title: 'Serves a normal request',
            body: 'No provider integration is required. Origin follows from the authenticated provider TLS session, not from a special provider signature.',
          },
          {
            meta: 'Verifier',
            title: 'Checks independently',
            body: 'A verifier checks the notary signature, provider identity, disclosed transcript, artifact hashes, and deterministic mapping using the trusted notary public key.',
          },
        ],
      },
      {
        heading: 'Authenticated versus observed',
        items: [
          'A model-emitted tool call is authenticated provider output.',
          'A tool result in the next request proves that the client sent that value—not that the local tool really ran or returned a truthful result.',
          'A session ID is authenticated as client-supplied request metadata. It can correlate calls, but it does not prove one genuine agent process created them.',
          'Each provider call is proved independently. A larger agent run can group those calls without upgrading locally observed activity into provider-authenticated evidence.',
        ],
      },
      {
        heading: 'What this does not prove',
        items: [
          'That a response is correct, safe, complete, or useful.',
          'That a particular human authored the prompt.',
          'That every call from a larger session was disclosed.',
          'That a local tool executed, or that its reported output was accurate.',
          'That the trusted notary private key has never been compromised.',
        ],
      },
      {
        heading: 'How trust is established',
        body: 'The service retrieves the versioned production Notary Registry over authenticated HTTPS and caches its key history. The JSON directory is not separately signed. Notarized packages identify the notary key that signed their evidence; verification accepts it only if that key was trusted at the package timestamp. A self-hosted deployment pairs `notary.endpoint` with `notary.public_key` in `config.toml`, but that is not part of the normal hosted workflow.',
      },
    ],
  },
  'getting-started': {
    title: 'Choose how to run LLM Notary.',
    lead: 'Use the guided macOS app for everyday capture and review. Use the CLI and local service when you are integrating an SDK, coding agent, server, or automated workflow.',
    blocks: [
      {
        heading: 'Choose an interface',
        cards: [
          {
            meta: 'Most Mac users',
            title: 'macOS app',
            body: 'Guided setup, menu-bar service controls, and the complete capture workspace in one signed application. No terminal is required for normal use.',
          },
          {
            meta: 'Developers and operators',
            title: 'CLI + local service',
            body: 'Two command-line programs for SDK routing, coding-agent configuration, scripting, automation, and explicit service supervision.',
          },
        ],
      },
      {
        heading: 'Install the macOS app',
        body: 'On the home page, choose Download for macOS. Open the downloaded DMG, move LLM Notary to Applications, then launch it. The app guides first-time setup and supervises its bundled local service.',
      },
      {
        heading: 'System requirements',
        items: [
          'A Mac with Apple silicon (M1 or newer).',
          'macOS 12 Monterey or later.',
          'A supported model provider account when you are ready to capture a real interaction.',
        ],
      },
      {
        heading: 'What the app manages',
        body: 'The app configures capture protection, helps connect a provider or coding tool, starts and stops its bundled `notaryd`, and embeds the local capture workspace. Provider credentials stay in the tool that sends the model request; the app does not ask for or store them.',
      },
      {
        heading: 'Install the CLI and local service',
        body: 'The shell installer supports Apple silicon Macs and x86-64 or ARM64 Linux systems. It selects the complete `latest` website build and checks the archive against its published SHA-256 value. This is a moving pre-release pointer. The checksum detects corruption but is not an independent signature because it shares the archive publisher.',
        code: installCommand,
      },
      {
        heading: 'Build from source',
        body: 'To build the same two local programs yourself, use Rust 1.95.0 and the public runtime repository toolchain file. That repository contains the complete protocol, daemon, CLI, generic notary, dashboard, updater, and verification implementation. Hosted accounts, billing, admission policy, and the public website are operated separately and are not part of the runtime source tree.',
        code: sourceInstallCommand,
      },
      {
        heading: 'Programs',
        body: '`notaryd` is the long-running local service. `llm-notary` is its short-lived REST client. The website archive installs both together.',
      },
      {
        heading: 'Install the agent skill',
        body: 'The CLI bundles portable instructions for finding Traces, notarizing with approval, verifying packages, diagnosing operations, and protecting private evidence. Install them for Codex, Claude Code, or both. The command does not contact or start the daemon. Use `--skills-dir /path/to/agent/skills` for another Agent Skills compatible client; re-run with `--force` only after inspecting a different existing skill. Claude Code uses `$CLAUDE_CONFIG_DIR/skills` when that environment variable is nonempty and `~/.claude/skills` otherwise. It detects changes inside an existing personal skills directory; restart it if that directory did not exist when the current session started.',
        code: 'llm-notary skill install --target codex\nllm-notary skill install --target claude\nllm-notary skill install --target all',
      },
      { heading: 'Start the service', code: 'notaryd' },
      {
        heading: 'Open the local dashboard',
        body: 'Visit `http://127.0.0.1:8788` and use the tabs for captures, notarizations, trace verification, sharing, activity, and settings. The default loopback configuration opens directly. If `admin.auth` is enabled, sign in with its configured username and password; the dashboard exchanges them for an `HttpOnly` session and does not store the password.',
      },
      {
        heading: 'Configuration file',
        body: 'The first service start creates an editable `config.toml` at the standard Notary user location: `~/.config/notary/config.toml` on Linux, `%APPDATA%\\notary\\config.toml` on Windows, and `~/Library/Application Support/notary/config.toml` on macOS. It is written once and never replaced. Start with an explicit file when needed:',
        code: 'notaryd --config /path/to/config.toml',
      },
      {
        heading: 'Use the command client',
        body: "`llm-notary` is a short-lived client for the daemon's versioned loopback API. It checks daemon health and never opens the metadata store or vault directly. Add `--json` for automation. Raw capture-list JSON includes stored prompt and output previews, so add `--metadata-only` before sending structured capture results to an agent transcript.",
        code: 'llm-notary status\nllm-notary captures list --provider openai\nllm-notary --json captures list --provider openai --metadata-only\nllm-notary operation op-example --json\nllm-notary open',
      },
      {
        heading: 'Connect a hosted account when needed',
        body: 'Local capture, notarization, and verification do not require an account. Connect one to use account allowances, share a notarized trace, or manage the same device from hosted Settings. `llm-notary login` opens a browser approval flow and stores the rotating device credential only in the daemon credential vault. `whoami` shows the connected identity, plan, and balances without revealing the credential; `logout` disconnects that device without deleting local evidence.',
        code: 'llm-notary login\nllm-notary whoami\nllm-notary logout',
      },
      {
        heading: 'Use an API key for unattended hosts',
        body: 'Create a deployment-specific, least-privilege key in hosted Account settings and inject it as `NOTARYD_PLATFORM_API_KEY` or through the private `NOTARYD_PLATFORM_API_KEY_FILE`. The complete key is shown once and never belongs in `config.toml`, logs, or artifacts. One daemon can use an injected API key or a browser-approved device session, never both; revoke API keys from hosted Settings.',
        code: 'export NOTARYD_PLATFORM_API_KEY_FILE=/run/secrets/notary-platform-api-key\nnotaryd',
      },
      {
        heading: 'What it controls',
        body: '`config.toml` holds the listener address, optional admin authentication, an optional local or self-hosted notary endpoint, filesystem or private S3-compatible artifact settings, SQLite or PostgreSQL metadata settings and preview limits, and the enabled provider routes. SQLite and filesystem storage remain the defaults. All built-in providers start enabled. The hostname and API behavior of each provider remain fixed; configuration cannot direct the proxy to an arbitrary upstream host.',
      },
      {
        heading: 'Pause capture without changing clients',
        body: 'Turn Capture requests off in the local dashboard or macOS app to keep the same fixed provider proxy URLs while bypassing admission, the remote notary, capture storage, and evidence creation for new requests. The daemon opens an ordinary WebPKI-verified HTTPS connection to the provider and streams the request and response directly. In-flight requests keep the mode they started with, and the durable setting survives restarts. Turning capture back on initializes the notary first; if that fails, capture stays off rather than silently falling back.',
      },
      {
        heading: 'Optional admin sign-in',
        body: 'The loopback administration API is available to local processes without credentials by default. To require sign-in, configure a username and an Argon2id PHC password hash. Store the hash, including its salt and work parameters, rather than the plaintext password. A prompted tool such as caddy hash-password --algorithm argon2id can generate it.',
        code: '[admin.auth]\nusername = "local-admin"\npassword_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."',
      },
      {
        heading: 'Capture encryption is automatic',
        body: 'On first use, the proxy creates a random capture-encryption key and stores it in Keychain on macOS, Credential Manager on Windows, or the desktop secret service on Linux. The OS may ask you to unlock that credential. You do not need to run a separate initialization command.',
      },
      {
        heading: 'Optional passphrase mode',
        body: 'If you prefer a passphrase instead of the operating-system credential service, point `NOTARYD_VAULT_PASSPHRASE_FILE` at a private UTF-8 file before the first service start. An empty passphrase is accepted for low-friction local testing, but it provides no meaningful protection if someone obtains both your captures and vault configuration.',
        code: 'export NOTARYD_VAULT_PASSPHRASE_FILE=/private/local/path/vault-passphrase\nnotaryd',
      },
      {
        heading: 'What happens online',
        body: 'The local proxy handles plaintext while the notary participates in the provider TLS connection without seeing application data. Provider response bytes stream back to your agent as they arrive.',
      },
      {
        heading: 'What happens at end-of-stream',
        body: 'The proxy seals encrypted deferred state into one `.llmcapture`. It does not perform the expensive final proof before returning control to your workflow.',
      },
      {
        heading: 'Connect an SDK',
        definitions: [
          {
            term: 'OpenAI',
            description:
              'Set your SDK base URL to http://127.0.0.1:8787/openai/v1 and continue using the Responses API.',
          },
          {
            term: 'Codex with a ChatGPT plan',
            description:
              'Live-tested with Codex CLI. Add a custom provider with base URL http://127.0.0.1:8787/codex and requires_openai_auth = true. Codex keeps and attaches its own ChatGPT login.',
          },
          {
            term: 'Anthropic / Claude Code',
            description:
              'Live-tested with Claude Code. Set the base URL to http://127.0.0.1:8787/anthropic and continue sending Messages API requests with either its API key or its own saved claude.ai login.',
          },
          {
            term: 'DeepSeek',
            description:
              'Set the OpenAI-compatible base URL to http://127.0.0.1:8787/deepseek and continue using /chat/completions.',
          },
          {
            term: 'OpenRouter',
            description:
              'Set the OpenAI-compatible base URL to http://127.0.0.1:8787/openrouter/api/v1, retain OPENROUTER_API_KEY, and use /chat/completions. Verified origin is openrouter.ai; a namespaced model slug is metadata, not proof of a direct upstream-vendor connection.',
          },
        ],
      },
      {
        heading: 'OpenRouter + Chat Completions',
        body: 'The model slug remains trace metadata. The resulting evidence authenticates OpenRouter—not the vendor named in that slug. The Authorization, HTTP-Referer, and X-Title header values are hidden in a notarized package.',
        code: 'curl http://127.0.0.1:8787/openrouter/api/v1/chat/completions \\\n  -H "Authorization: Bearer $OPENROUTER_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -H "HTTP-Referer: https://example.test" \\\n  -H "X-Title: LLM Notary example" \\\n  -d \'{"model":"YOUR_MODEL","stream":true,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}\'',
      },
      {
        heading: 'Where subscription login works',
        body: 'The supported, live-tested clients are Codex CLI with its saved ChatGPT login and Claude Code with its saved claude.ai login. The LLM Notary macOS app can supervise the local proxy, but it does not configure or sign in to either client. Native Claude Desktop cannot use this route. Codex desktop is not yet end-to-end tested or supported. Browser, Slack, remote, and cloud sessions cannot reach the local proxy.',
      },
      {
        heading: 'Where the API key comes from',
        body: 'Keep configuring credentials exactly as your SDK or agent expects—for example, OPENAI_API_KEY in your shell or secret manager. LLM Notary does not create, load, or require a .env file. A .env file is only one optional way your own application might populate environment variables.',
      },
      {
        heading: 'Provider boundary',
        body: 'The first local path segment selects a fixed adapter: /openai, /codex, /anthropic, /deepseek, or /openrouter. Each adapter fixes the upstream hostname and path to an explicit allowlist. The notary—not a caller-supplied URL—resolves and opens the provider connection.',
      },
      {
        heading: 'Codex + OpenAI API key',
        body: "Replace YOUR_RESPONSES_MODEL with a model available to the OpenAI API key. The explicit no-WebSocket capability keeps Codex on this prototype's supported HTTP transport.",
        code: 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary"\nmodel = "YOUR_RESPONSES_MODEL"\n\n[model_providers.llm-notary]\nname = "LLM Notary local proxy"\nbase_url = "http://127.0.0.1:8787/openai/v1"\nenv_key = "OPENAI_API_KEY"\nwire_api = "responses"\nsupports_websockets = false',
      },
      {
        heading: 'Codex + ChatGPT plan',
        body: 'This flow is live-tested with Codex CLI. First run codex login status and confirm that Codex says it is logged in using ChatGPT. Do not set env_key in this provider. Codex owns the login and refreshes it; LLM Notary only forwards the request headers and hides every header value from the notarized package. The proof authenticates chatgpt.com and the disclosed bodies, not the account owner, plan, or billing. Codex desktop is not yet end-to-end tested or supported, and cloud work cannot reach the loopback route.',
        code: 'Add this to ~/.codex/config.toml:\n\nmodel_provider = "llm-notary-chatgpt"\n\n[model_providers.llm-notary-chatgpt]\nname = "LLM Notary — ChatGPT plan"\nbase_url = "http://127.0.0.1:8787/codex"\nrequires_openai_auth = true\nwire_api = "responses"\nsupports_websockets = false',
      },
      {
        heading: 'Run Codex',
        code: "codex exec --ephemeral --skip-git-repo-check \\\n  'Reply with exactly: hello'",
      },
      {
        heading: 'Claude Code + Anthropic API key',
        body: "Set Claude Code's Anthropic base URL to the local route, keep the API key in its normal environment, and choose a model available to that account.",
        code: "ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic \\\nclaude --bare --no-session-persistence \\\n  -p --model YOUR_MODEL \\\n  'Reply with exactly: hello'",
      },
      {
        heading: 'Claude Code + claude.ai plan',
        body: 'Run claude auth status first; Claude Code itself must report a saved first-party login. A login in the native Claude desktop app is separate. Remove apiKeyHelper and do not set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN. Claude Code owns login and refresh; LLM Notary forwards its authorization and Messages protocol unchanged and hides every header value from the notarized package. The proof authenticates api.anthropic.com and the disclosed bodies, not the account owner, subscription, or billing. Native Claude Desktop, web, Slack, remote, and cloud sessions do not run through this local route.',
        code: "env -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN \\\n  ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic \\\n  claude -p 'Reply with exactly: llm-notary'",
      },
      {
        heading: 'OpenCode + DeepSeek',
        body: 'Set the provider base URL to http://127.0.0.1:8787/deepseek and retain DEEPSEEK_API_KEY in the OpenCode environment.',
      },
      {
        heading: 'Search local Traces',
        body: 'Each completed provider interaction keeps its vault-encrypted checkpoint in the selected private artifact store and gains a row in the selected metadata store. Use the dashboard, or fetch the live OpenAPI document and query the local admin API:',
        code: 'curl "http://127.0.0.1:8788/v1/traces?query=pricing&provider=openai"',
      },
      {
        heading: 'Search punctuation safely',
        body: 'Capture search treats punctuation as text boundaries instead of raw full-text-search syntax. Hyphenated terms, emphasis marks, multiple words, and double-quoted phrases return matches or an empty list through the normal JSON response.',
      },
      {
        heading: 'Filter Traces and Activity',
        body: 'The service applies Trace status and Activity severity/type filters before returning bounded results. Coding agents should discover state, status, provider, event type, severity, and time filters from the live OpenAPI document instead of reimplementing them client-side.',
        code: 'GET /v1/traces?status=notarization_failed&limit=20\nGET /v1/activity?severity=error&event_type=notarization_failed&limit=20',
      },
      {
        heading: 'What Trace metadata records',
        body: 'A Trace records its provider, request and response model when available, HTTP status, request and response sizes, duration, state, operational status, and retained artifact facts. By default, it indexes the first 1,000 characters of the request prompt and output as plain local text. It does not store header values, cookies, or credentials. Change the metadata path, disable full-text search, or set either preview limit to 0 in config.toml.',
      },
      {
        heading: 'Stopping and retrying',
        body: 'Once the end-of-stream checkpoint is sealed, stopping the proxy does not invalidate it. Notarization can happen later. Retry a failed or interrupted attempt through the owning Trace; the unchanged checkpoint is retained, although interrupted proof computation starts over.',
      },
    ],
  },
  'hosted-credits': {
    title: 'Plans and usage',
    lead: 'Each subscription has separate monthly capture and notarization allowances, plus storage for uploaded trace packages.',
    blocks: [
      {
        heading: 'Three plans',
        body: 'Free includes 50 MB of capture and 50 MB of notarization each month, with up to 1 GB of uploaded trace packages. The $9.99 monthly plan includes 1 GB for each monthly allowance and up to 10 GB of trace packages. The $49.99 monthly plan includes 10 GB for each monthly allowance and no fixed trace-storage ceiling, subject to fair-use and abuse controls.',
      },
      {
        heading: 'Capture and notarization are separate',
        body: 'A hosted capture reserves capture allowance for its authenticated HTTP byte limit. Turning a capture into a portable proof spends notarization allowance separately. Monthly allowances refresh on the account reset date; unused monthly allowance does not roll over.',
      },
      {
        heading: 'Buy more notarization',
        body: 'Every plan can buy additional notarization credits for $10 USD per GB through Stripe Checkout. Purchased credits do not expire. LLM Notary consumes monthly notarization allowance before non-expiring purchased credits. Refunds and disputes remove the corresponding credits; reinstated payments restore them.',
      },
      {
        heading: 'Trace storage',
        body: 'The trace limit is the total declared size of trace-package uploads that are in progress, being checked, or admitted to your account. Rejected, failed, expired, and purged uploads do not count. A per-file safety limit still applies on every plan.',
      },
      {
        heading: 'Anonymous allowances are scoped by network address',
        body: 'Public hosted use derives a rotating, keyed subject from the connection address: one IPv4 address or one IPv6 /64 prefix. Only explicitly trusted reverse proxies may supply the client address. The raw address is not stored in admission records or sent to a notary worker.',
      },
      {
        heading: 'An abuse control, not an identity claim',
        note: 'Network-address scoping is only a coarse abuse control. People behind the same NAT, corporate gateway, or VPN can share an allowance, while one person may appear under different addresses. The derived subject does not identify a person and is not a privacy guarantee.',
      },
      {
        heading: 'Your usage',
        body: 'The hosted dashboard shows the current plan, capture and notarization balances, trace storage, monthly reset, purchases, offers, and activity. A connected local service can retrieve the same account summary with `llm-notary whoami --json`.',
      },
      {
        heading: 'Evidence is unchanged',
        body: 'Admission and credit bookkeeping do not change TLSNotary evidence, trace-package verification, local checkpoint retention, or the trust claim. Self-hosted notaries do not need the hosted credit ledger unless their operator deliberately adopts it.',
      },
    ],
  },
  'trace-packages': {
    title: 'Notarize and verify',
    lead: 'Turn one encrypted capture into a portable evidence package, inspect its canonical OpenTelemetry trace, and verify the entire package offline.',
    blocks: [
      {
        heading: 'Notarize one interaction',
        body: 'Select a Captured Trace in the dashboard or admin API. The service atomically commits `trace-packages/<trace-id>.llmtrace`, records that exact package in Trace metadata, and retains the encrypted source checkpoint.',
        code: 'curl -X POST http://127.0.0.1:8788/v1/traces/trc-example/notarizations',
      },
      {
        heading: 'Notary discovery is automatic',
        body: 'For hosted use, the service refreshes the production Notary Registry, selects a worker compatible with the capture, and verifies the resulting evidence against its locally pinned key history. For local or self-hosted use, set `notary.endpoint` and `notary.public_key` together in `config.toml`.',
      },
      {
        heading: 'Fresh notary connection',
        body: 'The original provider stream and proxy no longer need to be running. A new notary session using the compatible signing identity can complete notarization from the encrypted local checkpoint.',
      },
      {
        heading: 'Expect this step to take time',
        body: 'Private proof generation is slower than capture. Deferring it keeps the interactive agent response fast and makes proof work an explicit background or batch operation.',
      },
      {
        heading: 'Interruption behavior',
        body: 'The pending checkpoint is not consumed. If notarization fails or the service stops, retry through `POST /v1/traces/{trace_id}/notarizations`; proof work from the interrupted attempt is not resumed.',
      },
      {
        heading: 'Package layout',
        code: '<trace-id>.llmtrace (ZIP)\n├── archive-manifest.json\n├── evidence.tlsn\n├── manifest.json\n├── request.disclosed.http\n├── response.disclosed.http\n└── trace.otlp.json',
      },
      {
        heading: 'Artifact responsibilities',
        definitions: [
          {
            term: 'archive-manifest.json',
            description:
              'The deterministic archive format, ordered entry sizes and hashes, and package digest.',
          },
          {
            term: 'evidence.tlsn',
            description: 'The cryptographic TLSNotary evidence and notary signature.',
          },
          {
            term: 'request.disclosed.http',
            description:
              'Authenticated request bytes selected for disclosure. Every header value is hidden except the exact structural value Transfer-Encoding: chunked; the body remains disclosed.',
          },
          {
            term: 'response.disclosed.http',
            description:
              'The authenticated provider response, including streamed events. Header values follow the same default-deny rule and the body remains disclosed.',
          },
          {
            term: 'trace.otlp.json',
            description:
              'A deterministic OpenTelemetry GenAI mapping of the authenticated request and response, including text, model-emitted tool calls, correlated tool results, model, and usage.',
          },
          {
            term: 'manifest.json',
            description:
              'The versioned source metadata and trace hash. The cryptographic signature lives in evidence.tlsn, not in this JSON file.',
          },
        ],
      },
      {
        heading: 'Package versus shared view',
        body: 'The notarized `.llmtrace` package carries all cryptographic evidence and is independently verifiable. A shared session presents a readable view derived from that package and retains the exact admitted bytes for download and independent verification.',
      },
      {
        heading: 'Verify a portable package',
        code: 'llm-notary traces verify ./capture.llmtrace\nPOST /api/verify',
        body: 'Use the local CLI to verify locally, or upload the package on the public Verify page. The hosted page checks the package without saving it.',
      },
      {
        heading: 'Complete context is intentional',
        body: 'A `.llmtrace` can include system context, tool definitions, session metadata, prompts, responses, and tool results. All HTTP header values are hidden by default, but request and response bodies remain disclosed. Inspect it before sharing; the encrypted `.llmcapture` is private retry state and must stay local.',
      },
      {
        heading: 'Download or verify locally',
        code: 'GET /v1/traces/{trace_id}/package.llmtrace\nPOST /v1/traces/{trace_id}/verify\nllm-notary traces verify ./trace.llmtrace',
      },
      {
        heading: 'What verification checks',
        items: [
          'The notary signature and expected notary public key.',
          'The authenticated provider identity and TLS evidence.',
          'The disclosed HTTP bytes against the cryptographic evidence.',
          'Every artifact hash named by the package manifest.',
          'The deterministic, versioned OTLP mapping byte-for-byte.',
        ],
      },
      {
        heading: 'Offline trust',
        body: 'Verification does not contact the provider or a live notary. It uses the notary key history already cached by the service, or notary.public_key for a self-hosted endpoint. A hosted service must successfully refresh its Registry before it can trust previously unseen evidence.',
      },
      {
        heading: 'Tool-use boundary',
        note: 'Verification proves that the model emitted a tool call and, on a later request, that the client sent a particular tool result. It does not prove the local tool actually executed.',
      },
    ],
  },
  share: {
    title: 'Share a verified session',
    lead: 'Sharing is a deliberate upload of one already-notarized package. The local service verifies it and shows the full disclosed conversation before it contacts LLM Notary.',
    blocks: [
      {
        heading: 'Connect the local service',
        body: 'Use the dashboard Share view, or begin the documented `POST /v1/account` device flow and poll its returned request identifier at the required interval.',
      },
      {
        heading: 'Choose visibility',
        body: 'Unlisted is recommended and stays out of the Library. Listed appears in the Library. Both start accessible to anyone with the stable link.',
      },
      {
        heading: 'Manage access after admission',
        body: 'From Account → Traces, you can stop sharing a trace, require a password, or set an expiry of up to 365 days. Protected Listed traces remain discoverable, but their conversation previews are withheld.',
      },
      {
        heading: 'Share one Notarized Trace',
        code: 'PUT /v1/traces/{trace_id}/share\n{"visibility":"unlisted"}',
      },
      {
        heading: 'Script-friendly output',
        body: 'Poll the same Trace share singleton on the loopback administration API so the browser or agent never receives the vault-held hosted credential.',
        code: '{"trace_id":"trc-…","progress":"shared","visibility":"unlisted","access_enabled":true,"password_protected":false,"expires_at_unix_ms":null,"failure_code":null,"share_url":"https://notary.exalto.ai/s/trc-…","package_url":"https://notary.exalto.ai/api/public/traces/trc-…/package.llmtrace","updated_at_unix_ms":1785294000000}',
      },
      {
        heading: 'The upload boundary',
        columns: [
          {
            title: 'Uploaded',
            items: [
              'evidence.tlsn and manifest.json',
              'request.disclosed.http with all header values hidden by default',
              'response.disclosed.http with authenticated provider output',
              'the deterministic trace.otlp.json',
            ],
          },
          {
            title: 'Never uploaded',
            items: [
              'encrypted .llmcapture checkpoints',
              'API-key or cookie values',
              'unselected captures from the same session',
              'extra files or symlink targets',
            ],
          },
        ],
      },
      {
        heading: 'Admission checks',
        body: 'The local service and hosted admission service validate the deterministic archive, verify its evidence, require hidden header values, and scan every archive entry and nested disclosed body for credential patterns and high-entropy secrets. After storage, admission downloads the exact public bytes and repeats validation, scanning, and verification before exposing the link.',
      },
      {
        heading: 'Current consent boundary',
        body: 'The admission service inspects disclosed request and response bodies, system context, and tool data to verify and reproduce the shared view. Every HTTP header value is hidden except the exact structural value Transfer-Encoding: chunked.',
      },
      {
        heading: 'Exact package retention',
        body: 'An admitted session keeps the exact verified `.llmtrace` bytes, size, and SHA-256 digest. The session page makes that package available for independent verification; the encrypted `.llmcapture` never leaves the local vault.',
      },
      {
        heading: 'Retry behavior',
        body: 'An upload or API failure does not change or delete the local package. Submitting the same capture with the same visibility reuses the archive-derived idempotency key and resumes the retry-safe share job.',
      },
    ],
  },
};

const docSubheadings: Partial<Record<DocPageKey, ReadonlySet<string>>> = {
  'getting-started': new Set([
    'System requirements',
    'What the app manages',
    'Build from source',
    'Programs',
    'Start the service',
    'Open the local dashboard',
    'Configuration file',
    'Use the command client',
    'What it controls',
    'Pause capture without changing clients',
    'Optional admin sign-in',
    'Capture encryption is automatic',
    'Optional passphrase mode',
    'What happens online',
    'What happens at end-of-stream',
    'OpenRouter + Chat Completions',
    'Where subscription login works',
    'Where the API key comes from',
    'Provider boundary',
    'Codex + OpenAI API key',
    'Codex + ChatGPT plan',
    'Run Codex',
    'Claude Code + Anthropic API key',
    'Claude Code + claude.ai plan',
    'OpenCode + DeepSeek',
    'What the metadata store records',
    'Stopping and retrying',
  ]),
  'trace-packages': new Set([
    'Notary discovery is automatic',
    'Fresh notary connection',
    'Expect this step to take time',
    'Interruption behavior',
    'Artifact responsibilities',
    'Package versus shared view',
    'Complete context is intentional',
    'What verification checks',
    'Offline trust',
    'Tool-use boundary',
  ]),
  'hosted-credits': new Set([
    'Monthly and supplemental grants',
    'Anonymous allowances are scoped by network address',
    'An abuse control, not an identity claim',
    'Account summary',
    'Evidence is unchanged',
  ]),
  share: new Set([
    'Choose visibility',
    'Submit one notarized package',
    'Script-friendly output',
    'Admission checks',
    'Current consent boundary',
    'Exact package retention',
    'Retry behavior',
  ]),
};

const docNavigation: DocNavigationGroup[] = [
  {
    label: 'Start',
    pages: [
      ['overview', 'Overview'],
      ['getting-started', 'Install options'],
    ],
  },
  {
    label: 'Understand',
    pages: [
      ['how-it-works', 'Trust model'],
      ['hosted-credits', 'Plans and usage'],
      ['trace-packages', 'Trace packages'],
    ],
  },
  { label: 'Share', pages: [['share', 'Share a session']] },
];
const docOrder = docNavigation.flatMap((group) => group.pages.map(([key]) => key));
const docAliases: Record<string, DocPageKey> = {
  install: 'getting-started',
  proxy: 'getting-started',
  checkpoints: 'getting-started',
  captures: 'getting-started',
  providers: 'getting-started',
  credits: 'hosted-credits',
  plans: 'hosted-credits',
  harnesses: 'getting-started',
  notarize: 'trace-packages',
  artifacts: 'trace-packages',
  verify: 'trace-packages',
  publish: 'share',
};

function docHref(key: DocPageKey, section?: string) {
  const route = key === 'overview' ? '#/docs' : `#/docs/${key}`;
  return section ? `${route}?section=${encodeURIComponent(section)}` : route;
}

function docSlug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function docHeadingLevel(pageKey: DocPageKey, block: DocBlock) {
  return docSubheadings[pageKey]?.has(block.heading) ? 3 : 2;
}

function getDocOutline(pageKey: DocPageKey, blocks: DocBlock[]) {
  return blocks.reduce<DocOutlineItem[]>((items, block) => {
    if (docHeadingLevel(pageKey, block) === 3 && items.length) {
      items.at(-1)?.children.push(block);
    } else {
      items.push({ block, children: [] });
    }
    return items;
  }, []);
}

function getBlockText(block: DocBlock) {
  return [
    block.heading,
    block.body,
    block.code,
    block.note,
    ...(block.items || []),
    ...(block.steps || []).flatMap((step) => [step.title, step.body]),
    ...(block.cards || []).flatMap((card) => [card.meta, card.title, card.body]),
    ...(block.definitions || []).flatMap((item) => [item.term, item.description]),
  ]
    .filter(Boolean)
    .join(' ');
}

function copyToClipboard(value: string) {
  return navigator.clipboard?.writeText(value).catch(() => {});
}

function LinkIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M10.6 13.4a4 4 0 0 0 5.7.1l2-2a4 4 0 0 0-5.7-5.7l-1.1 1.1M13.4 10.6a4 4 0 0 0-5.7-.1l-2 2a4 4 0 0 0 5.7 5.7l1.1-1.1" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m5 12 4.2 4.2L19 6.5" />
    </svg>
  );
}

function DocsInlineText({ children }: { children: ReactNode }) {
  return String(children)
    .split('`')
    .map((part, index) =>
      index % 2 ? (
        <code className="docs-inline-code" key={`${part}-${index}`}>
          {part}
        </code>
      ) : (
        part
      ),
    );
}

function DocsBlock({ block, pageKey }: { block: DocBlock; pageKey: DocPageKey }) {
  const Heading = docHeadingLevel(pageKey, block) === 3 ? 'h3' : 'h2';
  const slug = docSlug(block.heading);
  const code = block.code;
  const headingLink = `${window.location.origin}${window.location.pathname}${docHref(pageKey, slug)}`;
  const [copied, setCopied] = useState(false);
  const copy = (value: string) => {
    copyToClipboard(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  return (
    <section
      id={slug}
      className={`docs-section docs-section--level-${docHeadingLevel(pageKey, block)}`}
    >
      <div className="docs-heading-row">
        <Heading>{block.heading}</Heading>
        <button
          type="button"
          className="docs-copy-button docs-anchor"
          onClick={() => copy(headingLink)}
          aria-label={`${copied ? 'Copied link to' : 'Copy link to'} ${block.heading}`}
          title={copied ? 'Copied' : 'Copy link'}
        >
          {copied ? <CheckIcon /> : <LinkIcon />}
        </button>
      </div>
      {block.body && (
        <p>
          <DocsInlineText>{block.body}</DocsInlineText>
        </p>
      )}
      {code && (
        <div className="docs-code">
          <button
            type="button"
            className="docs-copy-button"
            onClick={() => copy(code)}
            aria-label={`Copy code for ${block.heading}`}
          >
            {copied ? 'Copied' : 'Copy'}
          </button>
          <pre>
            <code>{code}</code>
          </pre>
        </div>
      )}
      {block.note && (
        <aside className="docs-note">
          <DocsInlineText>{block.note}</DocsInlineText>
        </aside>
      )}
      {block.items && (
        <ul className="docs-list">
          {block.items.map((item) => (
            <li key={item}>
              <DocsInlineText>{item}</DocsInlineText>
            </li>
          ))}
        </ul>
      )}
      {block.steps && (
        <ol className="docs-flow">
          {block.steps.map((step, index) => (
            <li key={step.title}>
              <span>{String(index + 1).padStart(2, '0')}</span>
              <div>
                <b>{step.title}</b>
                <p>
                  <DocsInlineText>{step.body}</DocsInlineText>
                </p>
              </div>
            </li>
          ))}
        </ol>
      )}
      {block.cards && (
        <div className="docs-card-grid">
          {block.cards.map((card) => (
            <article key={`${card.meta}-${card.title}`}>
              <span>{card.meta}</span>
              <h3>{card.title}</h3>
              <p>
                <DocsInlineText>{card.body}</DocsInlineText>
              </p>
            </article>
          ))}
        </div>
      )}
      {block.columns && (
        <div className="docs-boundary-grid">
          {block.columns.map((column) => (
            <article key={column.title}>
              <h3>{column.title}</h3>
              <ul>
                {column.items.map((item) => (
                  <li key={item}>
                    <DocsInlineText>{item}</DocsInlineText>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      )}
      {block.definitions && (
        <dl className="docs-definitions">
          {block.definitions.map((item) => (
            <div key={item.term}>
              <dt>{item.term}</dt>
              <dd>
                <DocsInlineText>{item.description}</DocsInlineText>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

function DocsOutline({
  page,
  pageKey,
  section,
  onNavigate,
}: {
  page: DocPage;
  pageKey: DocPageKey;
  section?: string;
  onNavigate?: MouseEventHandler<HTMLAnchorElement>;
}) {
  const linkFor = (block: DocBlock) => docHref(pageKey, docSlug(block.heading));
  return (
    <ol className="docs-toc-list">
      {getDocOutline(pageKey, page.blocks).map(({ block, children }) => (
        <li key={block.heading}>
          <a
            className={section === docSlug(block.heading) ? 'active' : ''}
            href={linkFor(block)}
            onClick={onNavigate}
            aria-current={section === docSlug(block.heading) ? 'location' : undefined}
          >
            {block.heading}
          </a>
          {children.length > 0 && (
            <ol>
              {children.map((child) => (
                <li key={child.heading}>
                  <a
                    className={section === docSlug(child.heading) ? 'active' : ''}
                    href={linkFor(child)}
                    onClick={onNavigate}
                    aria-current={section === docSlug(child.heading) ? 'location' : undefined}
                  >
                    {child.heading}
                  </a>
                </li>
              ))}
            </ol>
          )}
        </li>
      ))}
    </ol>
  );
}

function DocsSearch({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const entries = useMemo(
    () =>
      Object.keys(docPages)
        .filter(isDocPageKey)
        .map((key) => {
          const page = docPages[key];
          return {
            key,
            title: page.title,
            lead: page.lead,
            blocks: page.blocks,
            text: `${page.title} ${page.lead} ${page.blocks.map(getBlockText).join(' ')}`.toLowerCase(),
          };
        }),
    [],
  );
  const results = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return entries.slice(0, 7);
    return entries.filter((entry) => terms.every((term) => entry.text.includes(term))).slice(0, 10);
  }, [entries, query]);
  useEffect(() => {
    if (open) setQuery('');
  }, [open]);
  const choose = (result: { key: DocPageKey }) => {
    window.location.hash = docHref(result.key);
    onClose();
  };
  return (
    <CommandDialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) onClose();
      }}
      title="Search documentation"
      description="Search setup, captures, providers, and sharing."
      className="docs-command-dialog"
    >
      <Command shouldFilter={false} className="docs-command">
        <CommandInput
          value={query}
          onValueChange={setQuery}
          placeholder="Search setup, captures, providers…"
        />
        <CommandList>
          <CommandEmpty>No documentation matches “{query}”.</CommandEmpty>
          {results.map((result) => (
            <CommandItem value={result.key} onSelect={() => choose(result)} key={result.key}>
              <span className="docs-command-copy">
                <b>{result.title}</b>
                <small>{result.lead}</small>
              </span>
            </CommandItem>
          ))}
        </CommandList>
        <div className="docs-command-footer">
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
        </div>
      </Command>
    </CommandDialog>
  );
}

function DocsMobileToolbar({
  currentKey,
  page,
  section,
  onSearch,
}: {
  currentKey: DocPageKey;
  page: DocPage;
  section?: string;
  onSearch: () => void;
}) {
  const [panel, setPanel] = useState<'docs' | 'toc' | null>(null);
  const toolbarRef = useRef<HTMLElement>(null);
  const currentLabel =
    docNavigation.flatMap((group) => group.pages).find(([key]) => key === currentKey)?.[1] ||
    page.title;
  useEffect(() => setPanel(null), [currentKey, section]);
  useEffect(() => {
    const close = (event: MouseEvent | KeyboardEvent) => {
      const escapePressed = event instanceof KeyboardEvent && event.key === 'Escape';
      const outsideClick =
        event instanceof MouseEvent &&
        event.target instanceof Node &&
        !toolbarRef.current?.contains(event.target);
      if (escapePressed || outsideClick) setPanel(null);
    };
    document.addEventListener('mousedown', close);
    window.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      window.removeEventListener('keydown', close);
    };
  }, []);
  const toggle = (nextPanel: 'docs' | 'toc') =>
    setPanel((current) => (current === nextPanel ? null : nextPanel));
  return (
    <nav className="docs-mobile-toolbar" aria-label="Documentation navigation" ref={toolbarRef}>
      <button
        type="button"
        className="docs-search-trigger"
        onClick={() => {
          setPanel(null);
          onSearch();
        }}
      >
        Search documentation <kbd>⌘ K</kbd>
      </button>
      <div className="docs-mobile-toolbar-row">
        <button
          type="button"
          className={panel === 'docs' ? 'active' : ''}
          onClick={() => toggle('docs')}
          aria-expanded={panel === 'docs'}
          aria-controls="docs-mobile-panel"
        >
          <span>
            <small>Docs</small>
            {currentLabel}
          </span>
          <ChevronDown aria-hidden="true" />
        </button>
        <button
          type="button"
          className={panel === 'toc' ? 'active' : ''}
          onClick={() => toggle('toc')}
          aria-expanded={panel === 'toc'}
          aria-controls="docs-mobile-panel"
        >
          <span>
            <small>Page</small>On this page
          </span>
          <ChevronDown aria-hidden="true" />
        </button>
      </div>
      {panel && (
        <div className="docs-mobile-panel" id="docs-mobile-panel">
          {panel === 'docs' ? (
            docNavigation.map((group) => (
              <div className="docs-mobile-nav-group" key={group.label}>
                <span>{group.label}</span>
                {group.pages.map(([key, label]) => (
                  <a
                    className={currentKey === key ? 'active' : ''}
                    href={docHref(key)}
                    aria-current={currentKey === key ? 'page' : undefined}
                    onClick={() => setPanel(null)}
                    key={key}
                  >
                    {label}
                  </a>
                ))}
              </div>
            ))
          ) : (
            <div className="docs-mobile-toc">
              <span>{page.title}</span>
              <DocsOutline
                page={page}
                pageKey={currentKey}
                section={section}
                onNavigate={() => setPanel(null)}
              />
            </div>
          )}
        </div>
      )}
    </nav>
  );
}

function isDocPageKey(value: string): value is DocPageKey {
  return Object.hasOwn(docPages, value);
}

export function Docs({ pageKey, section }: { pageKey: string; section?: string }) {
  const currentKey = isDocPageKey(pageKey) ? pageKey : docAliases[pageKey] || 'overview';
  const page = docPages[currentKey];
  const currentIndex = docOrder.indexOf(currentKey);
  const previousKey = docOrder[currentIndex - 1];
  const nextKey = docOrder[currentIndex + 1];
  const next = nextKey ? { href: docHref(nextKey), label: docPages[nextKey].title } : null;
  const [searchOpen, setSearchOpen] = useState(false);
  useEffect(() => {
    window.requestAnimationFrame(() => {
      if (section) document.getElementById(section)?.scrollIntoView({ block: 'start' });
      else window.scrollTo({ top: 0, behavior: 'instant' });
    });
  }, [currentKey, section]);
  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setSearchOpen(true);
      }
      if (event.key === 'Escape') setSearchOpen(false);
      if (event.altKey && event.key === 'ArrowLeft' && previousKey)
        window.location.hash = docHref(previousKey);
      if (event.altKey && event.key === 'ArrowRight' && nextKey)
        window.location.hash = docHref(nextKey);
    };
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [nextKey, previousKey]);
  return (
    <>
      <DocsMobileToolbar
        currentKey={currentKey}
        page={page}
        section={section}
        onSearch={() => setSearchOpen(true)}
      />
      <main className="docs-shell">
        <aside className="docs-sidebar">
          <button type="button" className="docs-search-trigger" onClick={() => setSearchOpen(true)}>
            Search <kbd>⌘ K</kbd>
          </button>
          {docNavigation.map((group) => (
            <div className="docs-nav-group" key={group.label}>
              <span className="docs-group">{group.label}</span>
              {group.pages.map(([key, label]) => (
                <a
                  className={currentKey === key ? 'active' : ''}
                  href={docHref(key)}
                  aria-current={currentKey === key ? 'page' : undefined}
                  key={key}
                >
                  {label}
                </a>
              ))}
            </div>
          ))}
        </aside>
        <article className="docs-content">
          <h1>{page.title}</h1>
          <p className="docs-lead">{page.lead}</p>
          {page.blocks.map((block) => (
            <DocsBlock block={block} pageKey={currentKey} key={block.heading} />
          ))}
          <div className="docs-page-nav">
            {previousKey ? (
              <a href={docHref(previousKey)}>
                <span>Previous</span>
                {docPages[previousKey].title}
              </a>
            ) : (
              <span />
            )}
            {next && (
              <a href={next.href}>
                <span>Next</span>
                {next.label}
              </a>
            )}
          </div>
        </article>
        <aside className="docs-toc" aria-label="On this page">
          <span>On this page</span>
          <DocsOutline page={page} pageKey={currentKey} section={section} />
          <p>
            <kbd>⌥</kbd> <kbd>←</kbd>
            <kbd>→</kbd> pages
          </p>
        </aside>
      </main>
      <DocsSearch open={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
