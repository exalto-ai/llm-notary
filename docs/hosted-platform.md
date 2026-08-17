# Hosted platform components and flows

This guide maps the private hosted implementation around the independently
buildable public runtime. It is an ownership and request-flow reference; the
generated hosted OpenAPI document remains the exact HTTP contract.

## Component ownership

| Component | Source | State it owns | Trust boundary |
| --- | --- | --- | --- |
| Stable web gateway | `deploy/gateway.Caddyfile` | none | Routes public site and API traffic; it is the only component allowed to supply the trusted client-address header |
| Hosted website | `js/app/` | browser UI state | Renders public docs, verification, Library, sign-in, account, billing, device approval, and hosted Trace management |
| Hosted API | `platform/crates/notary-api/` | PostgreSQL accounts, sessions, keys, credits, operations, Traces, reports, and cleanup work | Authenticates public and account requests, issues admission tickets, verifies uploads, and owns hosted policy |
| Generic notary | `runtime/crates/llm-notary-server/` | signing key and process-local capacity | Runs the public Proxy-TLS protocol and provider allowlist without account or billing semantics |
| Hosted notary adapter | `platform/crates/llm-notary-hosted-server/` | private durable usage-settlement outbox | Injects ticket redemption and settlement through the generic `AdmissionPolicy` and `SessionLifecycle` seams |
| Local runtime client | `runtime/crates/notaryd/` | local vault, Trace catalog, artifacts, account credential, and trust cache | Sees provider plaintext; requests hosted admission and sharing without exposing the provider credential to the platform or notary |
| Hosted PostgreSQL | `platform/migrations/` | authoritative hosted relational state | Separate schema and migration journal from an optional daemon PostgreSQL backend |
| Private object storage | hosted API configuration | intake objects, admitted exact packages, canonical traces | Receives a notarized disclosure only after an explicit verify or share action; never receives `.llmcapture` |

The root Cargo workspace builds only the hosted API, hosted notary adapter, and
desktop wrapper. The public runtime is the excluded `runtime/` workspace and
must pass `runtime/tooling/check-boundary.sh`; it cannot import platform,
website, billing, or hosted-admission code.

## Identity and authorization flows

Browser sign-in uses Google or GitHub OAuth when the corresponding provider is
configured. The callback resolves a provider-neutral identity and establishes
an HttpOnly browser session. Provider access tokens are not retained. Browser
sessions authorize account, billing, key-management, device-management, and
hosted Trace management operations; they never authorize model-provider requests.

The local daemon uses a browser-approved device session by default:

1. It starts authorization and receives a user code, browser URL, poll secret,
   expiry, and server-selected polling interval.
2. The user signs in and approves the named device in the browser.
3. The daemon polls with the one-time secret, then stores the returned refresh
   credential in its private credential vault.
4. Short-lived access tokens authenticate account, admission, and hosted Trace
   calls. Refresh-token rotation invalidates replay of an older token.
5. The user can disconnect locally or revoke a device from hosted Settings.

An account API key is the unattended alternative. Browser Settings creates and
revokes scoped keys, while the daemon accepts one injected key or one stored
device session, never both. API keys cannot manage keys, browser sessions,
billing, or account deletion. See [API keys for automation](api-key-automation.md)
for scopes and secret injection.

## Hosted capture and notarization admission

The same one-operation control plane serves signed-in and anonymous public
allowances:

1. Immediately before a captured request or notarization, the daemon requests
   an admission for exactly one `capture` or `notarization` operation. It does not
   request a renewable lease or trust a locally cached balance.
2. The API checks identity or the rotating anonymous address subject, billing
   state, the relevant allowance, and operation-specific limits. A notarization
   is additionally bound to the source record digest and authenticated-byte
   allowance.
3. The daemon places the short-lived ticket only in the protected v3 notary
   prelude. It does not persist the ticket or add it to evidence, logs, metrics,
   previews, or errors.
4. The hosted notary adapter redeems the ticket through the private API before
   expensive protocol work. The API atomically consumes it, binds the operation
   to the notary instance, and returns limits that can only tighten the generic
   notary's process maxima.
5. After admission, the cryptographic session no longer depends on the API.
   The adapter durably records authenticated bytes and the terminal outcome in
   its private outbox.
6. Settlement retries by operation ID until the API acknowledges the exact
   mode, byte count, instance, and outcome. Identical retries are idempotent;
   conflicting reports fail without changing the ledger.

The hosted adapter receives the opaque ticket and authenticated byte counts,
not the API key, prompt, response, or credential-bearing HTTP headers. The
generic runtime assigns no account or billing meaning to the admission value.
The completed lease-to-operation migration is summarized in
[Plans and usage](hosted-credits.md); production rollout details live in the
[Fly guide](../deploy/fly/README.md).

## Verification flow

Anonymous hosted verification accepts one notarized `.llmtrace`, applies
bounded upload and concurrency limits, verifies it against the current trusted
notary directory, and returns the verification facts and canonical trace. It
does not create a hosted Trace, account record, or durable receipt, and it does not
retain the uploaded package after the request.

This service is a convenience verifier. Independent verification uses the same
runtime contracts and a chosen trusted-key history. A successful live response
must not be described as a signed or durable attestation.

## Hosted Trace and Library flow

Sharing is separate from capture, notarization, and one-off verification:

1. An authenticated daemon creates or resumes a hosted Trace for one notarized
   package and explicit `unlisted` or `listed` visibility.
2. The API reserves account storage and returns a presigned private intake
   upload. That URL stays inside the daemon and is never returned by the local
   admin API or dashboard.
3. The daemon uploads the exact locally verified package and completes the
   upload with its declared size and SHA-256.
4. A worker re-downloads the intake object, applies the versioned disclosure
   safety policy, cryptographically verifies the package, reproduces the
   canonical trace, and materializes bounded Library facts.
5. Admission stores the exact verified package and canonical trace, then
   deletes the private intake object. Failed deletion enters the durable cleanup
   queue.
6. Unlisted and Listed Traces are both readable by anyone with an allowed link.
   Listed adds Library discovery. Owners can later stop sharing, set an expiry, or
   require a password without changing the retained package bytes.

Visitors can inspect the rendered trace or download the exact admitted package
for independent verification. Password, expiry, publication state, publisher
label, popularity, and reports are hosted observations and access controls, not
cryptographic facts. See [Share intake](share-intake-v1.md) and [Share
admission](share-admission-v1.md) for the storage and safety contracts.

## Credits and billing flow

Capture bytes, notarization bytes, and stored Trace-package bytes are separate
allowances. Stripe Checkout and the Billing Portal collect payment details;
the API accepts credit or subscription state only after validating signed
webhooks against configured live/test mode, Prices, Checkout Sessions, payment
objects, and account ownership. Webhook retries are idempotent, and raw webhook
bodies, signatures, and payment methods are not retained.

The account dashboard combines aggregate balances from the account projection
with cursor-paginated credit activity, purchases, eligible promotions, trace
storage, connected devices, API keys, and owned hosted Traces. Billing controls are
hidden when Stripe is disabled and visibly marked in test mode. Exact plan,
settlement, refund, dispute, and subscription behavior is documented in
[Plans and usage](hosted-credits.md).

## Hosted API route inventory

The generated contract is committed at
`js/app/src/platform-api/generated/openapi.json`. This inventory assigns every
operation to one flow so a route cannot land without an owner and documentation
review.

| Flow | Operations |
| --- | --- |
| Health and trust discovery | `GET /api/healthz`, `GET /api/readyz`, `GET /api/registry` |
| Browser identity | `GET /api/auth/providers`, `GET /api/auth/github`, `GET /api/auth/github/callback`, `GET /api/auth/google`, `GET /api/auth/google/callback`, `POST /api/auth/logout`, `GET /api/account`, `GET /api/usage`, `DELETE /api/account` |
| Device identity | `POST /api/device-authorizations`, `GET /api/device-authorizations/{request_id}/approval`, `POST /api/device-authorizations/{request_id}/approval`, `POST /api/device-authorizations/{request_id}/token`, `POST /api/device-session/token`, `DELETE /api/device-session`, `GET /api/device-session`, `GET /api/devices`, `DELETE /api/devices/{device_id}` |
| API keys | `GET /api/api-keys`, `POST /api/api-keys`, `DELETE /api/api-keys/{api_key_id}` |
| Admission and settlement | `POST /api/notary/admissions`, `POST /api/internal/notary/admissions/redeem`, `POST /api/internal/notary/operations/settle` |
| Billing and credits | `POST /api/billing/stripe/webhook`, `POST /api/billing/checkout-sessions`, `POST /api/billing/subscription-checkout-sessions`, `POST /api/billing/portal-sessions`, `GET /api/billing/purchases`, `GET /api/billing/purchases/{purchase_id}`, `GET /api/credit-offers`, `POST /api/credit-offers/{offer_id}/claim`, `GET /api/credits/history` |
| Hosted Trace submission and owner management | `POST /api/traces`, `GET /api/traces`, `GET /api/traces/{trace_id}`, `POST /api/traces/{trace_id}/upload-completion`, `PATCH /api/traces/{trace_id}`, `DELETE /api/traces/{trace_id}/share` |
| Public Library and Trace access | `GET /api/public/traces`, `GET /api/public/traces/{trace_id}`, `POST /api/public/traces/{trace_id}/access`, `GET /api/public/traces/{trace_id}/content`, `GET /api/public/traces/{trace_id}/trace.otlp.json`, `GET /api/public/traces/{trace_id}/package.llmtrace`, `POST /api/public/traces/{trace_id}/reports` |
| Retention-free verification | `POST /api/verify` |

## Deployment and data ownership

The production gateway is stable while website and API Machines are replaceable
behind it. API migrations run before new API replicas and follow expand/contract
compatibility. The hosted notary image combines the generic runtime with the
private adapter and keeps its usage outbox on a durable volume. The notary
signing key and published directory history must survive deployments so old
evidence remains verifiable.

PostgreSQL is authoritative for hosted state. Object storage is authoritative
for retained hosted Trace packages and canonical traces. The notary outbox is authoritative for
usage that has been observed but not yet acknowledged. None of those stores may
receive provider credentials, `.llmcapture`, vault keys, or raw admission
tickets. See [Database operations](database-operations.md) and [Fly.io
deployment](../deploy/fly/README.md) for migration, backup, health, and rollout
procedures.
