# Local evidence dashboard

Open [http://127.0.0.1:8788](http://127.0.0.1:8788) while `llm-notary` is
running. On the first visit, paste the value from the `admin.token_path` named
in the service configuration. The dashboard exchanges it for an HttpOnly local
session, clears the field, and does not store the bearer token in a URL or
browser storage.

The dashboard is served only by the loopback administration listener. The
provider proxy on port 8787 never serves it.

## Find the next useful action

The **Overview** starts with service, vault, notary, and work-queue health. The
capture-state strip distinguishes live captures, pending evidence, active
finalization work, finalized traces, and failures. Recent activity uses safe
event summaries and links back to the relevant work.

![Local dashboard in light mode showing an online service, available vault and notary, capture-state counts, the next finalization action, and recent activity.](images/local-dashboard/overview-light.png)

The stable left sidebar separates the local workflow:

- **Captures** searches and filters private evidence, then opens a selected
  capture in a detail panel.
- **Finalizations** shows durable queued, running, interrupted, failed, and
  completed proof operations.
- **Finalized traces** presents the portable package and an independent local
  verification action.
- **Publishing** keeps optional public publication separate from local proof
  creation and requires a deliberate confirmation.
- **Activity** shows a bounded redacted event stream.
- **Settings and API** reports safe listener, vault, notary, and preview-policy
  state and links to the live OpenAPI contract.

## Inspect a capture

Use full-text search over enabled previews, then narrow by provider or
finalization state. A result always has a textual state; color is only a second
signal. The detail panel shows safe model and response metadata, a lifecycle,
privacy-aware truncated previews, artifact availability, hashes, and prior
finalization state. It never decrypts or renders the source bundle.

![Local dashboard in dark mode with Captures selected, provider and finalization filters, a running Anthropic capture selected in the results, privacy-aware previews, lifecycle, and artifact details.](images/local-dashboard/captures-dark.png)

A pending capture has one **Finalize** action. The service responds with a
durable operation, and the dashboard moves to its finalization view. Repeating
the action resolves to the already-active operation and is labeled as
deduplicated; it does not create parallel work.

## Monitor and retry finalization

The operation queue shows state, capture identifier, attempt, and enqueue time.
The inspector shows the known stage and timestamps. Proof generation may take
minutes, so a running operation deliberately has no invented percentage.

Failed and restart-interrupted operations show only a safe failure code and a
**Retry finalization** action. Retry requeues the same durable operation.

![Finalizations view with a failed benchmark operation selected, its attempt and safe notary-capacity failure code visible, and a Retry finalization action.](images/local-dashboard/finalization-retry.png)

## Verify a finalized trace

Select **Finalized traces**, choose a capture, and inspect four document-like
views:

- **Summary** describes the authenticated inference and package format.
- **Evidence** shows the trace hash, authenticated provider, redaction state,
  and included TLS evidence.
- **Trace** shows the canonical OpenTelemetry document.
- **Verification** contains the durable human-readable result after **Verify
  now** rechecks the package.

![Finalized trace inspector in dark mode with the Verification tab selected and a passed receipt showing the capture, verification time, notary key identifier, and directory trust source.](images/local-dashboard/trace-verification.png)

Bundle availability is not the same as trace verification. Only the
verification receipt confirms that the finalized package's evidence,
disclosure, hashes, provider mapping, and canonical trace bytes agree.

## Publish only with consent

The Publishing view first shows whether the service has an authorized public
account. Its device flow displays a short code and approval URL. After approval,
select one eligible finalized trace and review the explicit confirmation. The
source `.llmbundle` is never a publication input. Nothing is uploaded merely
because a trace was finalized or verified.

## Activity, settings, and API discovery

Activity can be refreshed and filtered by severity. Events contain bounded
messages and identifiers, never request bodies, response bodies, raw headers,
credentials, or filesystem paths. Settings and API shows safe runtime facts
and the exact `http://127.0.0.1:8788/openapi.json` discovery URL for scripts and
coding agents.

## Responsive navigation and color mode

At 820 px and below, the sidebar becomes a full-height drawer and list/detail
workspaces become a single routed panel. Use the back action to return from a
capture inspector. Keyboard focus is visible, dialogs and drawers return focus
to their trigger, and reduced-motion preferences are respected.

![Mobile local dashboard with a private capture detail behind the open full-height navigation drawer, including pending and active-work counts and all dashboard destinations.](images/local-dashboard/mobile-navigation.png)

The header provides **System**, **Light**, and **Dark** choices. System follows
the operating-system preference and is the default. An explicit override is
stored locally and can always be returned to System. Dark mode uses neutral
charcoal surfaces; the lime accent remains reserved for verified or ready
states and a focal action.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Service unavailable | Confirm the foreground process is running and the browser uses the configured loopback admin address, normally port 8788. |
| Address already in use | Stop the other process or assign distinct loopback `proxy.listen` and `admin.listen` ports, then restart. |
| Unauthorized session | Re-read the private token file named by `admin.token_path`; the service can reject an old token after the file or profile changes. Never add the token to the URL. |
| Vault unavailable | Unlock the OS credential store or supply the configured private passphrase file, then restart. Do not move encrypted bundles outside their initialized vault profile. |
| Notary directory unavailable | Check network access and directory configuration. An explicit local notary endpoint is appropriate only for local/self-hosted development. |
| Operation interrupted | A running job was stopped by service restart. Inspect its safe code and use Retry finalization. |
| Missing artifact | Keep the catalog, encrypted bundle directory, and finalized package directory together. The API intentionally does not accept a replacement filesystem path. |
| Safe failure code | Use the code for diagnosis, then inspect redacted service logs. The UI will not expose underlying credentials, headers, or evidence plaintext. |

## Documentation fixture and screenshots

All images above come from `js/app/src/local-dashboard/fixtures.ts`. The data
is synthetic and fixed: it contains no user prompts, provider keys, account
names, local paths, or bundle contents. Desktop captures use 1440 × 1000 px;
the mobile capture uses 390 × 844 px. The overview, finalization, and mobile
images use Light mode. Captures and trace verification use Dark mode.

Regenerate every image from the repository root after a dashboard change:

```bash
npm --prefix js/app ci
npx --prefix js/app playwright install chromium
npm --prefix js/app run capture:dashboard-docs
npm --prefix js/app run check:local-docs
```

The capture command starts an isolated Vite server on `127.0.0.1:4175`, opens
fixed fixture deep links in headless Chromium, and replaces only the five files
under `docs/images/local-dashboard/`. Review every image for layout and
sensitive data before committing it.

