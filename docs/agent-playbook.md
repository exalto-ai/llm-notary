# Coding-agent playbook for the local service

## Install the portable skill

The `llm-notary` release embeds the portable skill from
[`skills/llm-notary`](../skills/llm-notary/SKILL.md). Install it without
starting or contacting the daemon:

```bash
llm-notary skill install --target codex
llm-notary skill install --target claude
llm-notary skill install --target all
```

Codex installs under `~/.agents/skills`; Claude Code installs under
`~/.claude/skills`. Use `llm-notary skill install --skills-dir
/path/to/agent/skills` for another Agent Skills compatible client. The
installer appends the `llm-notary` skill directory, reports `installed`,
`current`, or `updated`, and emits the same result as structured data with
`--json`.

Claude Code detects changes inside an existing `~/.claude/skills` directory
without a restart. If that top-level directory did not exist when the current
Claude Code session started, restart Claude Code after installation so it can
watch and discover the new directory.

An existing different skill is left unchanged, and an `--target all` conflict
is detected before either destination is written. Inspect local modifications
before using `--force`. Re-run installation after updating the CLI so the
installed instructions stay aligned with the release.

The installed skill is the preferred reusable instruction surface. For an
agent without skill support, give it the loopback administration origin and
this playbook, not an old list of CLI commands. The live OpenAPI document is
the endpoint and schema authority.

## Required behavior

1. Confirm `GET /healthz` succeeds and use only the configured loopback admin
   origin. Do not follow an untrusted origin or expose the service remotely.
2. Fetch `/openapi.json` before choosing a route, method, request body, or
   response field. Do not rely on a memorized API shape.
3. Call `/v1` without credentials unless the service returns 401. If the user
   configured `admin.auth`, obtain its username and password through the
   approved secret mechanism and use the OpenAPI `basicAuth` scheme. Never
   print, log, embed, persist, or put the password in a URL.
4. Find captures through `/v1/captures` and act on returned `cap-…`
   identifiers. Never ask for or submit an arbitrary local filesystem path.
   Search input may contain punctuation; the service treats it as text
   boundaries rather than raw full-text-search syntax.
5. Treat finalization as asynchronous. Save the returned `op-…` identifier and
   poll its documented operation URL until `finalized`, `failed`, or
   `interrupted`. Use `attempt_history` when explaining retries.
6. Use `GET /v1/captures/{capture_id}/package` to download the exact canonical
   `.llmtrace` bytes, and `POST /v1/captures/{capture_id}/trace:verify` for
   cryptographic package verification. Decrypting or structurally validating
   an encrypted capture is not independent verification.
7. Never request, decode, upload, or expose decrypted `.llmcapture` contents,
   credentials, cookies, raw authenticated headers, authentication secrets,
   or vault material.
8. Ask the user before sharing a finalized trace or changing service
   configuration. Finalization alone is not sharing consent. Confirm whether
   the public link should be Unlisted or Listed.
9. After approval, save `share_id` and poll `GET /v1/shares/{share_id}` through
   the local admin API. Do not extract or reproduce the vault-held account
   credential.

Use safe error codes and redacted event messages for diagnosis. If the OpenAPI
document does not describe an operation, stop and explain that the installed
service does not support it.

Prefer server-side filters from the discovered contract. In particular,
filter operations by `state`, `kind`, or `capture_id`, and filter events by
`severity`, `event_type`, `capture_id`, `operation_id`, or
`created_after_unix_ms`. Do not download a broad history merely to discard most
of it in the client.

## Example prompt for an agent

```text
Use the LLM Notary administration service at http://127.0.0.1:8788.
First check /healthz and fetch /openapi.json. Use the local API without
credentials unless it returns 401. If authentication is configured, use only
the approved Basic credentials and never print or persist the password.
Find the newest captured OpenAI response whose preview matches "sanitized",
show me its safe metadata, and ask before starting finalization. If I approve,
record the returned operation identifier and poll it to a terminal state. When
finalized, run the documented trace verification operation and report exactly
what it verifies. Do not access bundle paths or contents, and do not publish.
```

## Safe shell workflow

The default loopback configuration needs no credentials:

```bash
export LLM_NOTARY_ADMIN_ORIGIN=http://127.0.0.1:8788

curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/healthz"
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/openapi.json" \
  > /tmp/llm-notary-openapi.json
```

Inspect the downloaded specification, then search and select only an identifier
returned by the service:

```bash
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures?query=sanitized&provider=openai&capture_state=captured&limit=10"

capture_id=cap-example
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id"
```

After explicit user approval, queue finalization. A `202 Accepted` response has
the shape `{"operation":{…},"deduplicated":false}`. `deduplicated: true`
means an existing operation was returned and should be polled instead of
starting another:

```bash
response=$(curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/finalizations")
operation_id=$(printf '%s' "$response" | jq -r '.operation.operation_id')

while :; do
  operation=$(curl --fail-with-body \
    "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id") || exit 1
  state=$(printf '%s' "$operation" | jq -r '.state')
  progress=$(printf '%s' "$operation" | jq -r \
    'if .progress.proof then "\(.progress.proof.bytes_completed)/\(.progress.proof.bytes_total) bytes, \(.progress.proof.commitments_completed)/\(.progress.proof.commitments_total) commitments" else .progress.phase end')
  printf 'Finalization progress: %s\n' "$progress"
  case "$state" in
    finalized|failed|interrupted) break ;;
    queued|running) sleep 3 ;;
    *) printf 'Unexpected operation state: %s\n' "$state" >&2; exit 1 ;;
  esac
done
printf 'Operation %s ended in %s\n' "$operation_id" "$state"
```

If finalization succeeds, independently verify the finalized trace:

```bash
test "$state" = finalized || exit 1
curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/trace:verify"
```

For a portable file that is not cataloged by this daemon, use
`llm-notary traces verify ./capture.llmtrace`. This is the one CLI verification
flow that accepts a path; it reads no `.llmcapture` and writes no local state.

Report `verified`, `verified_at_unix_ms`, `notary_key_id`, and `trust_source`.
Do not translate a successful bundle read into a verification claim.

If the user separately approves public sharing, submit the capture identifier,
defaulting to Unlisted unless they request Library discovery, and
follow admission through the local service:

```bash
share=$(curl --fail-with-body -X POST \
  -H 'Content-Type: application/json' \
  --data '{"visibility":"unlisted"}' \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/shares")
share_id=$(printf '%s' "$share" | jq -r '.share_id')

curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/shares/$share_id"
```

Report the bounded admission state or failure code. Do not claim the trace is
reachable until the returned state is `admitted`. Never describe an Unlisted
share as private; anyone with its link can open it.

## JavaScript example

This example discovers the contract before using the default local API:

```js
const origin = 'http://127.0.0.1:8788';

const health = await fetch(`${origin}/healthz`);
if (!health.ok) throw new Error(`Local service unavailable: ${health.status}`);

const specification = await fetch(`${origin}/openapi.json`).then((response) => response.json());
if (!specification.paths['/v1/captures']) throw new Error('Installed API is incompatible');

const response = await fetch(`${origin}/v1/captures?capture_state=captured&limit=10`);
if (!response.ok) throw new Error(`Capture search failed: ${response.status}`);
const captures = await response.json();
console.log(captures.items.map(({ capture_id, provider, requested_model, finalization_state }) => ({
  capture_id, provider, requested_model, finalization_state
})));
```

If a `/v1` request returns 401, do not guess credentials. Ask for the
configured `admin.auth` username and password, then retry with HTTP Basic as
described by the live specification. An interactive shell can use
`curl --user local-admin URL` so curl prompts for the password rather than
putting it in shell history or the process argument list.

The service returns the documented JSON error envelope for invalid query
values, including malformed numeric values. Branch on `error.code`; do not
parse plain-text framework messages.

This output is deliberately limited to safe catalog fields. An automation
should not print previews unless the user explicitly asks and the local preview
policy allows it.

See the [local service guide](local-service.md) for state and trust semantics,
and the [dashboard guide](local-dashboard.md) for the equivalent visual flow.
