# Local service and REST API

In the default local profile, one `notaryd` process owns the catalog,
vault, artifacts, and durable operation state. The short-lived
`llm-notary` command talks to it through the versioned loopback API.
`notaryd` owns two different loopback listeners:

| Listener | Default | Purpose |
| --- | --- | --- |
| Provider proxy | `http://127.0.0.1:8787` | Receives provider-compatible requests and creates private captures. |
| Administration | `http://127.0.0.1:8788` | Serves the dashboard, health check, OpenAPI document, and `/v1` API. |

Both addresses must be distinct and loopback-only. The separation prevents a
program that can send model requests through the proxy from automatically
receiving access to capture management. An `/admin` path on the proxy would
not provide that boundary: a route prefix is organization, not authentication.
The PostgreSQL-and-S3 cluster profile is documented separately in
[Cluster deployment](cluster-operations.md).

## Pause new captures

Use the **Capture requests** switch in the dashboard Settings page or the
generated local API:

`GET /v1/settings/capture` reads the authoritative value and
`PUT /v1/settings/capture` changes it.

```bash
curl http://127.0.0.1:8788/v1/settings/capture
curl -X PUT http://127.0.0.1:8788/v1/settings/capture \
  -H 'content-type: application/json' \
  -d '{"enabled":false}'
```

The write returns the authoritative stored value. The setting lives in daemon
metadata, defaults to on, and survives daemon and desktop restarts. If admin
authentication is configured, these routes require it like the other `/v1`
routes.

Off does not stop or bypass the local daemon. Existing configured provider
URLs continue to work, but new requests stream from `notaryd` directly to
the adapter's fixed provider origin over HTTPS. There is no remote notary,
hosted admission, capture row, capture ID, preview, or `.llmcapture`, so nothing
from that request can later be notarized or verified. Existing captures and
notarizations remain usable. Enabling capture first initializes trusted notary
state; if that fails, the API returns
`capture_enable_initialization_failed` and capture stays off.

## Start and supervise the service

Run the service in the foreground. It writes the default configuration on
first start, or accepts an explicit file:

```bash
notaryd --config /path/to/config.toml
```

The process logs lifecycle metadata to standard error and exits when it cannot
bind either listener or safely open its storage. A service manager such as
systemd, launchd, or the Windows Service Control Manager can supervise this
same foreground command. Stop it through the manager or with the terminal's
normal interrupt; do not run a second process against the same catalog.

On interrupt or termination, the daemon first closes both listeners to new
requests. Existing provider response streams are allowed to finish and seal
their private capture, and the notarization worker stops claiming queued work
after it finishes the operation it already owns. Queued operations remain in
the catalog for the next start. The desktop app requests the same drain over
its private child-process pipe. It does not send a kill signal as an update or
normal stop mechanism.

There is no compatibility alias: `llm-notary` does not start the service.
Service-manager `ExecStart`, launchd `ProgramArguments`, and Windows service
definitions must invoke `notaryd`, optionally followed by `--config` and
the configuration path.

The executable name is the same in each supervisor. Adapt the executable and
configuration paths to the installation:

```ini
# systemd service
ExecStart=/usr/local/bin/notaryd --config /etc/llm-notary/config.toml
```

```xml
<!-- launchd ProgramArguments -->
<array>
  <string>/usr/local/bin/notaryd</string>
  <string>--config</string>
  <string>/Users/example/Library/Application Support/llm-notary/config.toml</string>
</array>
```

```powershell
# Windows Service Control Manager
sc.exe create LLMNotary binPath= '"C:\Program Files\LLM Notary\notaryd.exe" --config "C:\ProgramData\LLM Notary\config.toml"'
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

### Metadata backend

SQLite remains the default, and existing catalogs open in place. To run one
daemon with PostgreSQL instead, change only the backend:

```toml
[catalog]
backend = "postgres"
```

```bash
export LLM_NOTARY_METADATA_DATABASE_URL='postgresql://…'
notaryd migrate --config /path/to/config.toml
notaryd --config /path/to/config.toml
```

Use `LLM_NOTARY_METADATA_DATABASE_URL_FILE` for a mounted secret. The defaults
verify the database certificate and hostname and use up to eight pooled
connections. Separate migration credentials, TLS/pool tuning, role grants, and
backup steps are covered in [cluster operations](cluster-operations.md).

The migrator touches only the daemon-owned schema; runtime startup never
migrates or falls back to SQLite. Prompt and output previews are plaintext in
PostgreSQL even though deferred checkpoints remain vault-encrypted. PostgreSQL
alone does not make multiple daemon processes safe. Keep one process unless
cluster mode is enabled with PostgreSQL and S3.

### Artifact backend

The filesystem remains the default artifact writer. Existing untagged catalog
paths and legacy `.llmbundle` files continue to read in place. To write new
vault-encrypted `.llmcapture` checkpoints and exact `.llmtrace` packages to an
S3-compatible private bucket, select S3 explicitly:

```toml
[storage]
backend = "s3"

[storage.s3]
bucket = "llm-notary-private"
```

That minimal form uses AWS S3 in `us-east-1`, the private `llm-notary`
prefix, HTTPS, virtual-hosted addressing, and bounded timeouts. Set `region`
for another AWS region. S3-compatible services may also set `endpoint` and
`force_path_style`; plain HTTP additionally requires the explicit
`allow_insecure_http = true` opt-in and is intended only for a trusted local
emulator such as MinIO. Filesystem directories remain available as legacy
readers when old metadata still points at local artifacts.

Credentials never belong in `config.toml`. Set
`LLM_NOTARY_ARTIFACT_S3_ACCESS_KEY_ID` and
`LLM_NOTARY_ARTIFACT_S3_SECRET_ACCESS_KEY`, or use their `_FILE` forms. An
optional session token uses `LLM_NOTARY_ARTIFACT_S3_SESSION_TOKEN` or its
`_FILE` form. A direct value wins without reading the corresponding file.
Ambient instance metadata and shared SDK profiles are not used.

An explicit endpoint must be an origin with no credentials, path, query, or
fragment. Give the runtime `GetObject` and `PutObject` access within the
configured prefix, plus `ListBucket` constrained with `s3:prefix` to the
managed `daemon-private/` namespace. Readiness uses one bounded, non-mutating
list request against that namespace; reconciliation uses the same permission.
Runtime credentials do not need `DeleteObject`. Objects are always addressed
under `daemon-private/deferred_bundle` or
`notaryd/trace-packages`. Neither bucket nor object keys contain
prompts, outputs, or provider credentials.

The daemon privately spools, hashes, conditionally creates, reads back, and
verifies each object before metadata can advertise it. A retry reuses an exact
size/hash match and never overwrites different bytes. Locators record the
backend, so filesystem and S3 records remain independently readable when the
selected writer changes. Keep the old S3 profile and credentials configured if
metadata still references it. Writes go to one selected backend only; there is
no dual-write migration or automatic copy.

Missing objects return `artifact_missing`; wrong size or hash returns
`artifact_corrupt`; size limits, immutable collisions, unavailable backends,
and missing historical backend configuration have separate safe codes. The
runtime does not automatically delete unreferenced objects. An object left by
a stop after PUT but before metadata commit remains adoptable by capture
recovery or notarization retry. Stop the daemon and run the bounded,
report-only check before cleanup:

```bash
notaryd reconcile-artifacts --config /etc/llm-notary/config.toml
```

The JSON report verifies every referenced artifact and counts old,
unreferenced candidates only beneath the configured managed prefix. The safe
default ignores objects newer than seven days; `--orphan-grace-days` can
override that threshold. The command never prints object keys, mutates
metadata, or deletes bytes, and it follows bounded S3 pages until the complete
managed prefix has been scanned. Operators may
remove candidates only after resolving every missing, corrupt, invalid, or
backend finding, while the daemon remains stopped, and after comparing the
report with a consistent metadata backup. Never apply that cleanup rule
outside the managed prefix.

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

The dashboard shell, its static assets, `GET /healthz`, `GET /readyz`, and
`GET /openapi.json` are always public on the loopback admin listener. With the
default configuration, `/v1` is also available without credentials. OpenAPI
describes each operation as accepting anonymous access or HTTP Basic because
the exact requirement is a local configuration choice.

Start with the default flow:

```bash
export LLM_NOTARY_ADMIN_ORIGIN=http://127.0.0.1:8788

curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/healthz"
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/readyz"
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/openapi.json" > /tmp/llm-notary-openapi.json
curl --fail-with-body "$LLM_NOTARY_ADMIN_ORIGIN/v1/status"
```

Keep the origin fixed to the configured loopback listener. Do not accept an
origin from untrusted input.

`/healthz` is local process liveness and stays healthy during a database or S3
outage. `/readyz` runs bounded probes for metadata and the selected artifact
writer and returns `503` when either dependency is unavailable. Historical
inactive artifact readers are checked when an artifact needs them, not by the
global readiness probe.

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
llm-notary --config /path/to/config.toml captures list --metadata-only --json
```

On Unix, the password file must not be accessible to group or other users.
The CLI never reads the Argon2id hash as though it were a password and never
stores a prompted password.

`llm-notary version`, `llm-notary update --check`, `llm-notary update`, and
`llm-notary skill install` run before configuration loading and daemon
compatibility checks. This keeps release recovery and agent-skill installation
available when the service is stopped or an installed pair has an incompatible
API. Official daemons authenticate the signed `latest` channel and its
monotonically increasing revision, then check it in the background after
startup and about every six hours with jitter. `/v1/status` reports only the
current/latest build IDs, availability, last check time, and a bounded failure
code; development builds make no update request.

## Command client

Human-readable output is the default. `--json` prints one JSON value to
standard output for automation on success or failure. A failure retains its
nonzero exit status and uses the bounded
`{"error":{"code":"...","message":"..."}}` envelope without a duplicate
plain-text diagnostic. List filters map directly to server-side REST filters,
and accepted mutations print the durable operation or job identifier without
waiting indefinitely. Capture-list JSON includes stored prompt and output
previews; use `--metadata-only` before sending it to an agent transcript:

```bash
llm-notary captures list --query sanitized --provider openai --limit 20
llm-notary captures list --cursor "$next_cursor"
llm-notary captures list --provider openai --all --metadata-only --json
llm-notary captures show trc-example
llm-notary notarize trc-example --wait
llm-notary operations list --state failed --kind notarization
llm-notary operations retry op-example
llm-notary traces show trc-example --json
llm-notary traces verify trc-example
llm-notary events --severity error --limit 20
llm-notary events --after "$high_water_cursor"
llm-notary notaries list
llm-notary skill install --target all
llm-notary open
```

The skill installer writes the release's portable `llm-notary` skill to Codex,
Claude Code, both, or a custom skills directory. It preflights every requested
destination and refuses to replace different bundled files without `--force`.
It does not contact the daemon. See the [coding-agent
playbook](agent-playbook.md) for paths and consent boundaries.

Sharing identity remains daemon-owned. Login, logout, account inspection,
and sharing all use the local REST API, so only `notaryd` accesses the
credential vault or notarized artifact:

```bash
llm-notary login
llm-notary whoami
llm-notary whoami --json
llm-notary share trc-example                         # Unlisted by default
llm-notary share trc-example --visibility listed
llm-notary share trc-example --force                 # Only after disclosure review
llm-notary logout
```

`whoami` reports an explicit connection state (`disconnected`, `connected`,
`reauthorization_required`, or `unavailable`) and, when available, the display
name, sign-in provider, device or API-key mode, plan, billing state, account
links, and credit balances. Human output is intended for quick inspection;
`--json` is the stable machine-readable form. When connected, account
inspection includes the same total, monthly, additional, reset, and expiration
values returned by the hosted account API.
The account dashboard retrieves credit activity separately from the paginated
`GET /api/me/credits/history` route. These fields affect hosted notarization
only; they do not enter local captures or notarized evidence.

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
- Capture lists use `limit` and an opaque `cursor`. Supported filters are
  `query`, `provider`, `model`, `capture_state`, `notarization_status`,
  `streaming`, and `created_after_unix_ms`. A cursor is valid only with the
  route and filters that produced it. The removed `offset` parameter returns
  `offset_pagination_removed`; callers must restart at page one and follow
  `next_cursor`.
- Capture search treats punctuation as token boundaries, so `safety-review`
  and `**safety**` are safe inputs. Space-separated words must all match;
  double quotes preserve a phrase such as `"safety review"`.
- Operation lists support exact `state`, `kind`, and `trace_id` filters plus
  `limit` and an opaque `cursor`.
- Activity supports exact `severity`, `event_type`, `trace_id`, and
  `operation_id` filters, a `created_after_unix_ms` lower bound, and `limit`.
  Use `next_cursor` to continue backward through history. Save the separate
  `high_water_cursor` and pass it as `after` to follow newer events without
  changing the meaning of the back-pagination cursor.
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
| Captures | `GET /v1/traces`, `GET /v1/traces/{trace_id}` |
| Notarization | `POST /v1/traces/{trace_id}/notarizations`, `GET /v1/operations`, `GET /v1/operations/{operation_id}`, `POST /v1/operations/{operation_id}/retry` |
| Notarized trace | `GET /v1/traces/{trace_id}/package`, `GET /v1/traces/{trace_id}/trace`, `POST /v1/traces/{trace_id}/trace:verify` |
| Activity | `GET /v1/events` |
| Account connection | `GET /v1/account`, `POST /v1/account`, `GET /v1/account/{request_id}`, `DELETE /v1/account` |
| Sharing | `POST /v1/traces/{trace_id}/shares`, `GET /v1/shares/{share_id}` |

`GET /v1/notaries` returns a safe read-only view of the locally pinned or
server-shared notary
directory and trust history, or the explicitly configured self-hosted endpoint
and key. Its lifecycle records describe allowed protocol use; they are not an
endpoint health check.

For example, search the plain-text preview index and fetch one capture by its
identifier:

```bash
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/traces?query=sanitized&provider=openai&limit=20"

trace_id=trc-example
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/traces/$trace_id"
```

Inspect only failed notarizations or error events without downloading and
filtering the entire bounded history in the client:

```bash
curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations?state=failed&kind=notarization&limit=20"

curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/events?severity=error&event_type=notarization_failed&limit=20"
```

The catalog preview is local plaintext. Set `prompt_preview_chars` and
`output_preview_chars` to `0` when even a short searchable preview is not
appropriate for the machine.

## Capture and notarization lifecycle

A provider request begins as `capturing`. A successfully sealed encrypted
bundle becomes `captured`; a capture failure becomes `failed`. Its notarization
state moves independently through `not_requested`, `queued`, `running`, and
`notarized`, or ends in `failed` or `interrupted`. The status field
`ready_to_notarize` counts eligible captured responses whose notarization state
is still `not_requested`.

The current provider normalizers support successful response schemas only.
When capture completes with a non-`2xx` provider status, capture detail sets
`notarization_eligible` to `false` and reports
`notarization_ineligibility_code: unsupported_provider_http_status`. Starting
notarization returns `409` with the same code before any proof work is queued.
The encrypted bundle remains local and unchanged; retry is not offered because
the recorded provider response cannot become successful on a later attempt.

Queue notarization with `POST /v1/traces/{trace_id}/notarizations` and save
the durable operation identifier from the 202 response. Poll it with
`GET /v1/operations/{operation_id}`:

```bash
trace_id=trc-example
response=$(curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/traces/$trace_id/notarizations")
operation_id=$(printf '%s' "$response" | jq -r '.operation.operation_id')
printf 'Queued operation %s\n' "$operation_id"

curl --fail-with-body \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id"
```

If the same capture is submitted while an operation already exists, the
service returns that operation and sets `deduplicated` to `true`. It does not
start a competing proof. Poll while `state` is `queued` or `running`; terminal
states are `notarized`, `failed`, and `interrupted`.

Every operation response includes `progress.phase`. The values are `queued`,
`preparing`, `proving`, `signing`, `packaging`, and `complete`; these are named
milestones, not equal portions of elapsed time. During `proving`,
`progress.proof` reports `bytes_completed`, `bytes_total`,
`commitments_completed`, and `commitments_total`. The byte ratio measures
private transcript authentication inside the dominant proof loop. It is not an
overall ETA, and the service retains the last proof counters while signing or
packaging. The daemon updates durable counters at most about once per second.

After a restart, work that was `running` is recorded as `interrupted` with the
safe code `service_restarted`. Queued work remains durable. Retry only a
`failed` or `interrupted` operation whose response says `retryable: true` with
`POST /v1/operations/{operation_id}/retry`; retrying requeues the same
operation and increments its attempt when the worker claims it:

```bash
curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/operations/$operation_id/retry"
```

Capture detail includes its `notarizations` history. Operation list rows are
bounded summaries; `GET /v1/operations/{operation_id}` includes `retryable`
and complete `attempt_history`, so an agent can avoid deterministic rejections
and distinguish earlier interrupted or failed attempts from the current
aggregate state without searching an event page.

## Validation, verification, and sharing

An encrypted `.llmcapture` is private retry state. Checking that the vault can
decrypt and parse it establishes only that the local artifact is structurally
usable; it is not independent proof of the provider response. The capture can
reconstruct the original authenticated request, including credentials, so it
must remain vault-encrypted and local.

A notarized trace is one deterministic `.llmtrace` ZIP containing the
TLSNotary evidence, disclosed HTTP artifacts, manifest, archive manifest, and
canonical OpenTelemetry JSON. Every HTTP header value is hidden except the
exact structural value `Transfer-Encoding: chunked`; the authenticated request
and response bodies remain disclosed. Download its exact bytes or verify it
through the capture identifier:

```bash
trace_id=trc-example
curl --fail-with-body --output "$trace_id.llmtrace" \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/traces/$trace_id/package"

curl --fail-with-body -X POST \
  "$LLM_NOTARY_ADMIN_ORIGIN/v1/traces/$trace_id/trace:verify"
```

`POST /v1/traces:verify` accepts portable `.llmtrace` bytes for in-memory
verification without adding them to the catalog or artifact store. The thin
CLI uses this loopback route for path-based verification.

A successful response contains `verified: true`, a verification time, notary
key identifier, and trust source. This operation rechecks the evidence,
disclosure, hashes, provider adapter, and canonical trace bytes.
`GET /v1/traces/{trace_id}/trace` decodes the same notarized package into
its manifest and canonical trace document for inspection; it does not replace
the verification operation.

Sharing is a later, explicit consent decision. It is never part of local
notarization. The `/v1/account` device flow authorizes the local service, and
`POST /v1/traces/{trace_id}/shares` accepts only an eligible notarized
capture plus an explicit `unlisted` or `listed` visibility. Ask the user before
sharing or changing service configuration. Device authorization starts with `202 Accepted`; obey
its `poll_interval_seconds` and keep polling the returned
`/v1/account/{request_id}` route while `signed_in` is false.
When the daemon uses an injected API key, `POST /v1/account` and
`DELETE /v1/account` return `409`; create and revoke API keys in the hosted
dashboard instead.
Before it authenticates or uploads, the local service cryptographically verifies
the exact notarized package and applies the same versioned public-disclosure
safety policy used by hosted admission. The hosted worker repeats both checks;
local acceptance never guarantees admission by a newer server policy.
An explicit `force: true` request, exposed by `llm-notary share --force`, accepts
only unexplained high-entropy values after the publisher reviews the complete
disclosure. It cannot override known secret patterns, credential fields,
disclosed header values, signed credential queries, invalid archives, or failed
cryptographic verification.
After submission, poll `GET /v1/shares/{share_id}` on the local admin
listener. The service uses the vault-held account credential
to fetch admission state; agents and the dashboard never receive that
credential. A missing share returns `404`; missing or expired account
authorization returns `409`; a temporary platform or network failure returns
`503` rather than pretending the share disappeared. An admitted response
contains the stable `share_url` and exact public `package_url`. Anyone with an
Unlisted or Listed link can read the disclosure; this is not private access.

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
For the on-disk privacy and verification boundary, see [Artifact formats and
verification](artifact-formats.md).
