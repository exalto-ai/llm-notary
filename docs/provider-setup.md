# Provider and agent setup

`llm-notaryd` exposes provider-compatible HTTP/1.1 routes on one loopback
listener. Keep credentials in the original SDK, agent, or secret manager and
replace only the base URL.

## Route map

| Provider | Local SDK base URL | Upstream host | Typical operation |
| --- | --- | --- | --- |
| OpenAI | `http://127.0.0.1:8787/openai/v1` | `api.openai.com` | Responses |
| Anthropic | `http://127.0.0.1:8787/anthropic` | `api.anthropic.com` | Messages |
| DeepSeek | `http://127.0.0.1:8787/deepseek` | `api.deepseek.com` | Chat Completions |
| OpenRouter | `http://127.0.0.1:8787/openrouter/api/v1` | `openrouter.ai` | Chat Completions |

The daemon removes the configured local route prefix before forwarding. A
caller cannot provide an arbitrary upstream URL. Enabled prefixes must be
distinct and non-overlapping.

Examples below use `YOUR_MODEL` deliberately. Choose a model available to the
provider account rather than copying a time-sensitive model name.

## OpenAI

```bash
curl http://127.0.0.1:8787/openai/v1/responses \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"YOUR_MODEL","input":"Reply with exactly: llm-notary","stream":true}'
```

Use the Responses API. Chat Completions normalization remains covered by
fixtures for compatible provider inputs, but the Codex integration below uses
Responses.

## Anthropic

```bash
curl http://127.0.0.1:8787/anthropic/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H 'anthropic-version: 2023-06-01' \
  -H 'content-type: application/json' \
  -d '{"model":"YOUR_MODEL","max_tokens":64,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The `x-api-key` value, `anthropic-version` value, and content type are hidden in
the finalized disclosure. Their header names remain visible.

## DeepSeek

DeepSeek's upstream origin has no implied `/v1` suffix; the proxy preserves the
requested API path.

```bash
curl http://127.0.0.1:8787/deepseek/chat/completions \
  -H "Authorization: Bearer $DEEPSEEK_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"YOUR_MODEL","messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

## OpenRouter

```bash
curl http://127.0.0.1:8787/openrouter/api/v1/chat/completions \
  -H "Authorization: Bearer $OPENROUTER_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'HTTP-Referer: https://example.test' \
  -H 'X-Title: LLM Notary example' \
  -d '{"model":"YOUR_MODEL","stream":true,"messages":[{"role":"user","content":"Reply with exactly: llm-notary"}]}'
```

The verified provider is OpenRouter at `openrouter.ai`. A slug such as
`vendor/model` is authenticated request metadata; it does not prove a direct
TLS connection to that vendor. The values of `Authorization`, `HTTP-Referer`,
and `X-Title` are hidden in a finalized package.

## Streaming behavior

Server-Sent Events are relayed as they arrive. The proxy does not synthesize
events or buffer the full response before returning it. After the provider
stream ends, one short notary exchange seals the deferred bundle.

The proxy does not implement WebSocket transport. Configure clients to use
HTTP streaming when they can select between HTTP and WebSockets.

## Codex CLI

Codex can use the OpenAI route through a custom Responses provider. The
`supports_websockets = false` setting is important because this prototype is
HTTP/1.1-only.

Add the following to `~/.codex/config.toml`, replacing the model with one
available to the OpenAI API key:

```toml
model_provider = "llm-notary"
model = "YOUR_RESPONSES_MODEL"

[model_providers.llm-notary]
name = "LLM Notary local proxy"
base_url = "http://127.0.0.1:8787/openai/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
supports_websockets = false
```

Then run Codex normally, for example:

```bash
codex exec --ephemeral --skip-git-repo-check \
  'Reply with exactly: llm-notary'
```

The custom-provider keys above follow the current Codex configuration
reference. Avoid the built-in `openai_base_url` shortcut here: a named provider
makes the no-WebSocket capability explicit.

## Other agents and SDKs

- For Claude Code, set its Anthropic base URL to
  `http://127.0.0.1:8787/anthropic` and keep `ANTHROPIC_API_KEY` in its normal
  environment.
- For an OpenAI-compatible DeepSeek or OpenRouter client, use the corresponding
  base URL from the route table and keep the provider's normal API-key
  variable.
- If a client hard-codes HTTP/2 or WebSockets with no HTTP/1.1 fallback, it is
  outside the current proxy scope.

## Capture size and response status

The default shared request-plus-response envelope is 15 MiB. The proxy counts
the request before opening the provider connection and the response while it
arrives, so it cannot knowingly write a bundle above the configured
finalization limit.

Non-`2xx` provider responses are still captured as encrypted local evidence,
but current normalizers reject them for finalization with
`unsupported_provider_http_status` before proof generation.

Real provider requests can incur cost. The ordinary test suite uses offline
fixtures; run live requests only as an explicit integration check.
