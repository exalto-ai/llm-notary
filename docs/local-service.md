# Local service and REST API

The `llm-notaryd` process is the only local runtime and the only writer of the
catalog, vault, artifacts, and durable operation state. The short-lived
`llm-notary` command talks to it through the versioned loopback API.
`llm-notaryd` owns two different loopback listeners:

| Listener | Default | Purpose |
| --- | --- | --- |
| Provider proxy | `http://127.0.0.1:8787` | Receives provider-compatible requests and creates private captures. |
| Administration | `http://127.0.0.1:8788` | Serves the dashboard, health check, OpenAPI document, and `/v1` API. |

Both addresses must be distinct and loopback-only. The separation prevents a
program that can send model requests through the proxy from automatically
receiving access to capture management. An `/admin` path on the proxy would
not provide that boundary: a route prefix is organization, not authentication.

## Start and supervise the service

Run the service in the foreground. It writes the default configuration on
first start, or accepts an explicit file:

```bash
llm-notaryd --config /path/to/config.toml
```

The process logs lifecycle metadata to standard error and exits when it cannot
bind either listener or safely open its storage. A service manager such as
systemd, launchd, or the Windows Service Control Manager can supervise this
same foreground command. Stop it through the manager or with the terminal's
normal interrupt; do not run a second process against the same catalog.

There is no compatibility alias: `llm-notary` does not start the service.
Service-manager `ExecStart`, launchd `ProgramArguments`, and Windows service
definitions must invoke `llm-notaryd`, optionally followed by `--config` and
the configuration path.

The executable name is the same in each supervisor. Adapt the executable and
configuration paths to the installation:

```ini
# systemd service
ExecStart=/usr/local/bin/llm-notaryd --config /etc/llm-notary/config.toml
```

```xml
<!-- launchd ProgramArguments -->
<array>
  <string>/usr/local/bin/llm-notaryd</string>
  <string>--config</string>
  <string>/Users/example/Library/Application Support/llm-notary/config.toml</string>
</array>
```

```powershell
# Windows Service Control Manager
sc.exe create LLMNotary binPath= '"C:\Program Files\LLM Notary\llm-notaryd.exe" --config "C:\ProgramData\LLM Notary\config.toml"'
```

The smallest useful explicit configuration is:

```toml
format = "llm-notary/agent-config/v1"

[proxy]
listen = "127.0.0.1:8787"

[admin]
listen = "127.0.0.1:8788"

# Optional. Omit this table to allow access from local processes without credentials.
# [admin.auth]
# username = "local-admin"
# password_hash = "$argon2id$v=19$m=32768,t=2,p=1$..."

[notary]
# A local/self-hosted endpoint and its compressed SEC1 public key are paired.
# endpoint = "tcp://127.0.0.1:7047"
# public_key = "02..."
```

The admin listener is open to local processes by default. Both listeners must
still use loopback addresses, and the provider proxy never mounts admin
routes. This is the simplest setup for a single-user workstation and for a
coding agent already running with the user's local permissions.

To require credentials, add `[admin.auth]` with a username and an Argon2id PHC
password hash. The hash contains its salt and work parameters; never store the
plaintext password in the configuration. Generate it with a tool that prompts
for the password instead of accepting it as a command-line value. For example:

```bash
caddy hash-password --algorithm argon2id
```

Copy the complete output into `password_hash`. LLM Notary rejects plaintext,
bcrypt, and malformed values. The Argon2id requirement follows current
[OWASP password-storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html);
the prompted Caddy command is one convenient generator, not a runtime
dependency.

## Health, discovery, and authentication

The dashboard shell, its static assets, `GET /healthz`, and
`GET /openapi.json` are always public on the loopback admin listener. With the
default configuration, `/v1` is also available without credentials. OpenAPI
describes each operation as accepting anonymous access or HTTP Basic because
the exact requirement is a local configuration choice.

Start with the default flow:

```bash
export LLM_NOTARY_ADMIN_ORIGIN=http://127.0.0.1:8788

curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/healthz"
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/openapi.json" > /tmp/llm-notary-openapi.json
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/v1/status"
```

Keep the origin fixed to the configured loopback listener. Do not accept an
origin from untrusted input.

When `admin.auth` is configured, API clients may send standard HTTP Basic
credentials. A browser receives 401, shows the username/password form, and
exchanges those credentials at `POST /v1/session` for an HttpOnly, SameSite
cookie. It clears the fields and does not keep the password in browser storage.
For an interactive shell, `curl --user local-admin URL` prompts for the
password without placing it in shell history or the process argument list.
Noninteractive clients should obtain the password from their approved secret
mechanism and follow the `basicAuth` scheme in OpenAPI. The service sends no
cross-origin access headers, so another website cannot use the admin API as a
browser backend.

The bundled CLI reads the daemon configuration only to resolve the loopback
admin listener and configured username. It rejects non-loopback listeners,
checks `/healthz` for API `v1` before each command, and sends every stateful
operation through `/v1`. With Basic authentication enabled it prompts for the
password without echoing it. For automation, store the password in a private
UTF-8 file and pass its path rather than the secret itself:

```bash
llm-notary status
llm-notary --admin-password-file /private/admin-password status
llm-notary --config /path/to/config.toml captures list --json
```

On Unix, the password file must not be accessible to group or other users.
The CLI never reads the Argon2id hash as though it were a password and never
stores a prompted password.

## Command client

Human-readable output is the default. `--json` prints one JSON value to
standard output for automation. List filters map directly to server-side REST
filters, and accepted mutations print the durable operation or job identifier
without waiting indefinitely:

```bash
llm-notary captures list --query sanitized --provider openai --limit 20
llm-notary captures show cap-example
llm-notary finalize cap-example
llm-notary operations list --state failed --kind finalization
llm-notary operations retry op-example
llm-notary traces show cap-example --json
llm-notary traces verify cap-example
llm-notary traces verify ./cap-example.llmtrace
llm-notary events --severity error --limit 20
llm-notary notaries list
llm-notary open
```

Publication identity remains daemon-owned. Login, logout, account inspection,
and publication all use the local REST API, so only `llm-notaryd` accesses the
credential vault or finalized artifact:

```bash
llm-notary login
llm-notary whoami
llm-notary publish cap-example
llm-notary logout
```

Exit code `2` is invalid input, `3` means the daemon is unavailable, `4` is an
authentication failure, `5` is not found, `6` is a state conflict, `7` is a
retryable daemon failure, and `8` is an API-version mismatch. Other failures
use `1`. Error text is safe and never echoes credentials or plaintext headers.

## API conventions

- `/v1` is the current administration API version. Fetch `/openapi.json` at
  runtime rather than guessing routes, fields, or future versions.
- Request and response bodies are JSON where the OpenAPI operation declares a
  body. Identifiers are opaque strings such as `cap-…` and `op-…`.
- Errors use `{"error":{"code":"safe_code","message":"safe message"}}`.
  Codes and messages exclude credentials, plaintext headers, and local paths.
  Invalid query values use the same JSON envelope; for example, a negative
  `limit` returns `invalid_query_parameter` instead of a framework error page.
- Capture lists use `limit` and `offset`. Supported filters are `query`,
  `provider`, `model`, `capture_state`, and `finalization_state`.
- Capture search treats punctuation as token boundaries, so `safety-review`
  and `**safety**` are safe inputs. Space-separated words must all match;
  double quotes preserve a phrase such as `"safety review"`.
- Operation lists support exact `state`, `kind`, and `capture_id` filters plus
  `limit`.
- Activity supports exact `severity`, `event_type`, `capture_id`, and
  `operation_id` filters, a `created_after_unix_ms` lower bound, and `limit`.
  It also uses a monotonic `cursor`; pass the returned `next_cursor` on a later
  request to ask only for newer events.
- Mutations that start or retry background work return `202 Accepted`. Record
  the returned operation identifier and poll its resource. A 202 response does
  not mean the proof is complete.
- Cancellation is not implemented. Do not invent or call a cancellation route.

The OpenAPI document is the complete schema reference. This compact map shows
which workflow owns each operation:

| Workflow | Operations |
| --- | --- |
| Session and status | `POST /v1/session`, `DELETE /v1/session`, `GET /v1/status` |
| Notary trust | `GET /v1/notaries` |
| Captures | `GET /v1/captures`, `GET /v1/captures/{capture_id}` |
| Finalization | `POST /v1/captures/{capture_id}/finalizations`, `GET /v1/operations`, `GET /v1/operations/{operation_id}`, `POST /v1/operations/{operation_id}/retry` |
| Finalized trace | `GET /v1/captures/{capture_id}/package`, `GET /v1/captures/{capture_id}/trace`, `POST /v1/captures/{capture_id}/trace:verify` |
| Activity | `GET /v1/events` |
| Publication account | `GET /v1/publication/auth`, `POST /v1/publication/auth`, `GET /v1/publication/auth/{request_id}`, `DELETE /v1/publication/auth` |
| Publication | `POST /v1/captures/{capture_id}/publications`, `GET /v1/publications/{job_id}` |
| Public trace | `GET /v1/public-traces/{publication_id}` |

`GET /v1/notaries` returns a safe read-only view of the locally pinned notary
directory and trust history, or the explicitly configured self-hosted endpoint
and key. Its lifecycle records describe allowed protocol use; they are not an
endpoint health check.

For example, search the plain-text preview index and fetch one capture by its
identifier:

```bash
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures?query=sanitized&provider=openai&limit=20&offset=0"

capture_id=cap-example
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id"
```

Inspect only failed finalizations or error events without downloading and
filtering the entire bounded history in the client:

```bash
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations?state=failed&kind=finalization&limit=20"

curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/events?severity=error&event_type=finalization_failed&limit=20"
```

The catalog preview is local plaintext. Set `prompt_preview_chars` and
`output_preview_chars` to `0` when even a short searchable preview is not
appropriate for the machine.

## Capture and finalization lifecycle

A provider request begins as `capturing`. A successfully sealed encrypted
bundle becomes `pending`; a capture failure becomes `failed`. Its finalization
state moves independently through `not_requested`, `queued`, `running`, and
`finalized`, or ends in `failed` or `interrupted`.

The current provider normalizers support successful response schemas only.
When capture completes with a non-`2xx` provider status, capture detail sets
`finalization_eligible` to `false` and reports
`finalization_ineligibility_code: unsupported_provider_http_status`. Starting
finalization returns `409` with the same code before any proof work is queued.
The encrypted bundle remains local and unchanged; retry is not offered because
the recorded provider response cannot become successful on a later attempt.

Queue finalization with `POST /v1/captures/{capture_id}/finalizations` and save
the durable operation identifier from the 202 response. Poll it with
`GET /v1/operations/{operation_id}`:

```bash
capture_id=cap-example
response=$(curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/finalizations")
operation_id=$(printf '%s' "$response" | jq -r '.operation.operation_id')
printf 'Queued operation %s\n' "$operation_id"

curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id"
```

If the same capture is submitted while an operation already exists, the
service returns that operation and sets `deduplicated` to `true`. It does not
start a competing proof. Poll while `state` is `queued` or `running`; terminal
states are `finalized`, `failed`, and `interrupted`. The service reports a
stage, not a made-up percentage.

After a restart, work that was `running` is recorded as `interrupted` with the
safe code `service_restarted`. Queued work remains durable. Retry only a
`failed` or `interrupted` operation whose response says `retryable: true` with
`POST /v1/operations/{operation_id}/retry`; retrying requeues the same
operation and increments its attempt when the worker claims it:

```bash
curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id/retry"
```

Capture detail includes its `finalizations` history. Every operation response
includes `retryable` and `attempt_history`, so an agent can avoid deterministic
rejections and distinguish earlier interrupted or failed attempts from the
current aggregate state without searching a bounded event page.

## Validation, verification, and publication

An encrypted `.llmbundle` is private retry state. Checking that the vault can
decrypt and parse it establishes only that the local artifact is structurally
usable; it is not independent proof of the provider response. The bundle can
reconstruct the original authenticated request, including credentials, so it
must remain vault-encrypted and local.

A finalized trace is one deterministic `.llmtrace` ZIP containing the
TLSNotary evidence, disclosed HTTP artifacts, manifest, archive manifest, and
canonical OpenTelemetry JSON. Every HTTP header value is hidden except the
exact structural value `Transfer-Encoding: chunked`; the authenticated request
and response bodies remain disclosed. Download its exact bytes or verify it
through the capture identifier:

```bash
capture_id=cap-example
curl --fail-with-body --output "$capture_id.llmtrace" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/package"

curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/captures/$capture_id/trace:verify"
```

A successful response contains `verified: true`, a verification time, notary
key identifier, and trust source. This operation rechecks the evidence,
disclosure, hashes, provider adapter, and canonical trace bytes.
`GET /v1/captures/{capture_id}/trace` decodes the same finalized package into
its manifest and canonical trace document for inspection; it does not replace
the verification operation.

Publication is a later, explicit consent decision. It is never part of local
finalization. The `/v1/publication/auth` device flow authorizes the local
service, and `POST /v1/captures/{capture_id}/publications` accepts only an
eligible finalized capture. Ask the user before either publishing or changing
service configuration. Device authorization starts with `202 Accepted`; obey
its `poll_interval_seconds` and keep polling the returned
`/v1/publication/auth/{request_id}` route while `signed_in` is false.
After submission, poll `GET /v1/publications/{job_id}` on the local admin
listener. The service uses the vault-held publication credential
to fetch admission state; agents and the dashboard never receive that
credential. A missing job returns `404`; missing or expired publication
authorization returns `409`; a temporary platform or network failure returns
`503` rather than pretending the job disappeared. Public Library traces can be
inspected through `GET /v1/public-traces/{publication_id}`. A bare Library trace
does not carry the cryptographic evidence; use the source `.llmtrace` package
with `llm-notary traces verify` for independent verification.

## Local trust boundary

The API is intentionally identifier-based. It does not accept arbitrary input
or output paths and does not return decrypted bundle contents, credential
values, cookies, raw authenticated headers, vault keys, token values, or
presigned upload URLs. API errors and activity events follow the same rule.
Foreground startup diagnostics can name a configured local path when that path
must be repaired, so treat process logs as local-sensitive operational data.
Keep these constraints when adding endpoints: private evidence stays local,
and public artifacts must not claim guarantees beyond what their verifier
checks.

For exact operations and schemas, use the live [OpenAPI document](http://127.0.0.1:8788/openapi.json).
For the visual workflow, continue with the [local dashboard guide](local-dashboard.md).
