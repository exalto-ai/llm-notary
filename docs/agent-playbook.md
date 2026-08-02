# Coding-agent playbook for the local service

Give a coding agent the loopback administration origin and this playbook, not
an old list of CLI commands. The live OpenAPI document is the endpoint and
schema authority.

## Required behavior

1. Confirm `GET /healthz` succeeds and use only the configured loopback admin
   origin. Do not follow an untrusted origin or expose the service remotely.
2. Fetch `/openapi.json` before choosing a route, method, request body, or
   response field. Do not rely on a memorized API shape.
3. Read the approved local bearer token into `LLM_NOTARY_ADMIN_TOKEN`; send it
   only in the `Authorization` header. Never print, log, embed, persist, or put
   it in a URL.
4. Find captures through `/v1/captures` and act on returned `cap-…`
   identifiers. Never ask for or submit an arbitrary local filesystem path.
5. Treat finalization as asynchronous. Save the returned `op-…` identifier and
   poll its documented operation URL until `finalized`, `failed`, or
   `interrupted`.
6. Use `POST /v1/captures/{capture_id}/trace:verify` for cryptographic package
   verification. Decrypting or structurally validating an encrypted bundle is
   not independent verification.
7. Never request, decode, upload, or expose decrypted `.llmbundle` contents,
   credentials, cookies, raw authenticated headers, bearer tokens, or vault
   material.
8. Ask the user before publishing a finalized trace or changing service
   configuration. Finalization alone is not publication consent.

Use safe error codes and redacted event messages for diagnosis. If the OpenAPI
document does not describe an operation, stop and explain that the installed
service does not support it.

## Example prompt for an agent

```text
Use the LLM Notary administration service at http://127.0.0.1:8788.
First check /healthz and fetch /openapi.json. Use the bearer token already
available as LLM_NOTARY_ADMIN_TOKEN, but never print it or put it in a URL.
Find the newest pending OpenAI capture whose preview matches "sanitized",
show me its safe metadata, and ask before starting finalization. If I approve,
record the returned operation identifier and poll it to a terminal state. When
finalized, run the documented trace verification operation and report exactly
what it verifies. Do not access bundle paths or contents, and do not publish.
```

## Safe shell workflow

Load the token from the configured private file. This keeps the value itself
out of shell history:

```bash
export LLM_NOTARY_ADMIN_ORIGIN=http://127.0.0.1:8788
export LLM_NOTARY_ADMIN_TOKEN_FILE=/private/local/path/admin-token
IFS= read -r LLM_NOTARY_ADMIN_TOKEN < "$LLM_NOTARY_ADMIN_TOKEN_FILE"
export LLM_NOTARY_ADMIN_TOKEN

curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/healthz"
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/openapi.json" \
  > /tmp/llm-notary-openapi.json
```

Inspect the downloaded specification, then search and select only an identifier
returned by the service:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $LLM_NOTARY_ADMIN_TOKEN" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures?query=sanitized&provider=openai&capture_state=pending&limit=10&offset=0"

capture_id=cap-example
curl --fail-with-body \
  -H "Authorization: Bearer $LLM_NOTARY_ADMIN_TOKEN" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id"
```

After explicit user approval, queue finalization. A `202 Accepted` response has
the shape `{"operation":{…},"deduplicated":false}`. `deduplicated: true`
means an existing operation was returned and should be polled instead of
starting another:

```bash
response=$(curl --fail-with-body -X POST \
  -H "Authorization: Bearer $LLM_NOTARY_ADMIN_TOKEN" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/finalizations")
operation_id=$(printf '%s' "$response" | jq -r '.operation.operation_id')

while :; do
  operation=$(curl --fail-with-body \
    -H "Authorization: Bearer $LLM_NOTARY_ADMIN_TOKEN" \
    "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id") || exit 1
  state=$(printf '%s' "$operation" | jq -r '.state')
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
  -H "Authorization: Bearer $LLM_NOTARY_ADMIN_TOKEN" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/trace:verify"
```

Report `verified`, `verified_at_unix_ms`, `notary_key_id`, and `trust_source`.
Do not translate a successful bundle read into a verification claim.

## JavaScript example

This example assumes the token is already supplied by an approved secret
mechanism. It discovers the contract before making an authenticated request:

```js
const origin = 'http://127.0.0.1:8788';
const token = process.env.LLM_NOTARY_ADMIN_TOKEN;
if (!token) throw new Error('LLM_NOTARY_ADMIN_TOKEN is required');

const health = await fetch(`${origin}/healthz`);
if (!health.ok) throw new Error(`Local service unavailable: ${health.status}`);

const specification = await fetch(`${origin}/openapi.json`).then((response) => response.json());
if (!specification.paths['/v1/captures']) throw new Error('Installed API is incompatible');

const response = await fetch(`${origin}/v1/captures?capture_state=pending&limit=10&offset=0`, {
  headers: { Authorization: `Bearer ${token}` }
});
if (!response.ok) throw new Error(`Capture search failed: ${response.status}`);
const captures = await response.json();
console.log(captures.items.map(({ capture_id, provider, requested_model, finalization_state }) => ({
  capture_id, provider, requested_model, finalization_state
})));
```

This output is deliberately limited to safe catalog fields. An automation
should not print previews unless the user explicitly asks and the local preview
policy allows it.

See the [local service guide](local-service.md) for state and trust semantics,
and the [dashboard guide](local-dashboard.md) for the equivalent visual flow.

