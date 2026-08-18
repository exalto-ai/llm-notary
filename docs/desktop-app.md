# Desktop app

The macOS app is the guided way to run Notary. It packages setup, service
controls, and the local Trace workspace in one native application. Normal use
does not require a terminal or a separate browser window.

## Install

The current app requires an Apple silicon Mac (M1 or newer) running macOS 12
Monterey or later.

1. Choose **Download for macOS** on the [Notary by Exalto website](https://notary.exalto.ai/).
2. Open the downloaded DMG.
3. Move Notary to Applications, then launch it.

Production downloads are signed with a Developer ID certificate, notarized by
Apple, and stapled for offline Gatekeeper checks. Each successful production
build replaces the website's moving `latest` pointer; no stable compatibility
or file-format promise applies yet.

## What the app does

The app provides a five-stage first run, supervises the bundled `notaryd`
process, exposes its status from the menu bar, and contains the complete local
capture workspace. Users do not need to open a localhost page in a browser.
Closing the window removes the app from the Dock and leaves the menu-bar
controller running; opening it from the menu bar restores the regular app
window. Quitting the app asks a daemon that it started to stop accepting new
work, waits for open response streams and the currently running notarization to
finish, and then exits. It never force-kills the service if draining takes too
long. Once onboarding is complete, later app launches start the bundled
service automatically for Keychain and empty-passphrase vaults. A protected
passphrase vault opens locked and starts capture only after the user unlocks it.

The service-backed Settings screen and the checked **Capture new requests** menu-bar item
read and change the daemon-owned setting. On uses the remote notary and creates
private local Traces. Off leaves the service and loopback provider routes running,
but sends later requests directly from the daemon to the fixed provider and
creates no Trace. The home status and route diagram distinguish this state
from both **Ready to capture** and **Service stopped**. The menu item is
disabled when the daemon is unreachable; the desktop process does not keep a
second preference. Existing traces can still be browsed, notarized,
verified, and shared while capture is off.

First run detects the local agent config, capture vault, and service before it
changes anything. It then guides the user through capture protection, choosing
a provider and optional default model, starting the service, optionally
connecting a hosted account, and confirming the ready state. Provider
credentials remain in the user's coding tool; the desktop app never asks for or
stores them.

The capture workspace is served by the supervised daemon on the fixed loopback
address `127.0.0.1:8788` and embedded in the native window. The desktop content
security policy permits that exact local frame; it does not permit public or
arbitrary remote pages.

## Connect an account (optional)

After the local service starts, onboarding offers an optional hosted-account
connection. The approval page opens in the system browser, so the desktop app
never handles the hosted sign-in password or provider credentials. Skipping the
step does not affect local capture, notarization, or verification.

Settings shows the same account connection card after onboarding. It identifies
the connected account and sign-in provider, device or API-key mode, plan and
billing state, and capture/notarization credits (used, remaining, included,
supplemental, reset, and expiration values when supplied). Account, usage,
pricing, and settings actions open only validated links returned by the local
service in the default browser. A browser-approved device session can be
disconnected from Settings; an injected API key must instead be managed in the
hosted account settings and is never revoked by the local app.
Connecting does not upload or share local Traces. It authorizes only the hosted
features the user later chooses to invoke.

## Share a Notarized Trace

**Share** is a secondary action inside one Notarized Trace. Capturing,
Captured, failed, and Notarizing traces are not eligible. If no hosted account
is connected, Share keeps the same Trace open while the user completes browser
approval; connecting alone uploads nothing.

Before upload, the app renders the disclosed conversation and tool content
from the exact `.llmtrace` package—not from the private `.llmcapture`
checkpoint—and identifies the publishing account. The user chooses Unlisted
or Listed visibility, an optional password, and an optional expiration before
confirming **Share trace**. Unlisted is link-accessible, not private.

Preparing, Uploading, Verifying, Shared, Rejected, and Sharing failed remain
inline on the originating Trace. A successful share exposes **Copy link**,
**Open shared trace**, **Manage access**, and **Stop sharing**. Access changes
reuse the one canonical link. Stopping sharing makes that link unavailable
without deleting the local Trace or changing its Notarized state.

## Activity and Providers

Activity keeps severity, date, and Trace ID directly visible. Operation ID and
the raw event name are under **More filters**. A Trace-linked event opens that
Trace; service-only events remain inspectable in Activity. The concise label is
shown first, while timestamp, bounded failure code, operation ID, and raw event
name remain available as technical details. Activity never carries prompts,
responses, credentials, raw headers, vault material, or decrypted capture
checkpoints.

Providers is the only desktop destination for supported provider routes. Each
provider shows its client/API style, explicit allowed host, local base URL,
readiness, capture state, setup note, and Copy action. The external client keeps
its credential and chooses its provider model. Notary does not expose an
arbitrary-provider or arbitrary-host control.

## Settings

Desktop Settings has five groups in this order:

1. **General** — Capture new requests and Open Notary at sign-in. Closing the
   window leaves Notary available from the menu bar.
2. **Account** — connection state, reconnect/disconnect, plan and usage links,
   and API-key management where applicable.
3. **Security** — Local data protection and Notaries. The active notary name,
   operator, verification key, and state stay visible; lifecycle windows,
   historical keys, and exact identifiers are under **View details**.
4. **Updates** — app version, automatic signed-update state, Check now,
   Restart to update, and the exact reason a restart is blocked.
5. **Advanced** — Service listeners/profile/build facts and Developer
   diagnostics/OpenAPI. Provider routes are not duplicated here.

The local dashboard supplies service-backed facts. A bounded parent/frame
bridge supplies only launch and signed-updater state and accepts only those
desktop actions; vault keys and other native secrets never cross the frame.

## Connect subscription-backed clients

Choosing a provider during setup shows and copies the local base URL; it does
not reconfigure or sign in to the vendor client. Subscription-backed capture is
supported and live-tested with Codex CLI using its saved ChatGPT login and
Claude Code using its saved claude.ai login. Notary can supervise
the proxy while either CLI sends requests through it.

This does not intercept traffic from vendor applications automatically. Native
Claude Desktop cannot currently use the local route. Codex desktop is not yet
an end-to-end-tested or supported client surface, even though local Codex work
may read the same configuration. Browser, Slack, remote, and cloud sessions run
outside this Mac's loopback proxy. See [Provider and agent setup](../runtime/docs/provider-setup.md)
for the exact supported commands and configuration.

## Automatic updates

Signed production builds check the `latest` channel shortly after launch and
about every six hours after that. A different authenticated build ID means an
update is available, even when the channel intentionally points back to an
older build. The app downloads and verifies the whole signed application in
the background. Local source builds do not contact the update service.

The app never installs or restarts on its own. It shows **Update ready** and
keeps the verified download until the user chooses **Restart to update** in
Settings. Background checks discard a downloaded build if a newer signed
channel revision withdraws or replaces it. Restart is unavailable during a
capture or notarization. On click, the app authenticates `latest` again, checks
activity again, asks its managed daemon to stop accepting new work, waits for
open streams, detached capture sealing, and the current notarization to finish,
installs the application, and reopens it. A daemon started outside the app is
never stopped or replaced by this flow. A protected passphrase vault reopens
locked after the update and requires the passphrase before capture resumes.

## Private capture protection

All `.llmcapture` files remain encrypted before they are written. First run
selects **Protect private captures with Keychain** by default. macOS protects
the random vault key, and there is no separate password to remember.

Advanced options allow a passphrase instead. The passphrase is required again
when the app opens and is retained only for that app session. It is never
written to the vault configuration. New passphrase vaults include an encrypted
key check in a private sidecar next to the configuration so the app can reject
an incorrect passphrase before starting the local service while preserving the
v1 configuration format for older readers. An empty passphrase is allowed as
an explicit convenience choice: captures are still encrypted on disk, but this
provides no meaningful protection to anyone who can access that account's
application data.

The app unlocks the vault before launching the daemon and sends the already
unlocked key through the child's anonymous standard-input pipe. The key is not
placed in command-line arguments, environment-variable values, logs, or files.
An environment flag only tells the supervised child to read the key from the
pipe. Temporary key buffers are cleared when dropped.

Legacy passphrase vaults without a key check remain usable from the CLI, but
the desktop app refuses to unlock them because it cannot safely reject a typo
before starting capture. Vault migration remains a future workflow; the current
settings screen explains this instead of silently changing protection for
existing captures.

## Develop from source

The desktop app is built with Tauri 2 under the private package and executable
name `notary-app`. Its application identifier is `ai.exalto.notary`; the
Milestone 2 prototype does not migrate an older desktop application identity.
The source stays portable so Windows and Linux packaging can follow without
replacing the application shell.

Install the desktop dependencies once:

```bash
npm --prefix apps/notary-app install
```

Start the Tauri development app with a debug `notaryd` sidecar:

```bash
npm --prefix apps/notary-app run tauri:dev
```

Build a release application bundle and DMG with a release sidecar:

```bash
npm --prefix apps/notary-app run tauri:build
```

The command creates the native bundle and DMG. Local builds use a Developer ID
identity and Apple notarization credentials from the environment when they are
present.

Pull requests that affect the desktop app build a debug Apple Silicon
application bundle in CI without receiving production signing credentials.
GitHub's **Desktop DMG** workflow is reserved for manual package checks and the
production publisher. Manual checks can build an unsigned preview. A successful
production publication signs, notarizes, staples, and checks the package, then
publishes the DMG and its SHA-256 checksum together with Tauri's signed
`.app.tar.gz` updater bundle. They live in the same immutable website build as
the command-line clients. Release builds carry the shared immutable build ID;
local source builds report `dev` and do not participate in published updates.
Unsigned preview builds carry a test build ID but have updates explicitly
disabled; build identity alone never grants authority to follow production.

The signed workflow reads these secrets from the branch-restricted
`macos-release` GitHub environment:

- `APPLE_CERTIFICATE` and `APPLE_CERTIFICATE_PASSWORD` contain an encrypted,
  base64-encoded Developer ID Application identity and its password.
- `APPLE_SIGNING_IDENTITY` and `APPLE_TEAM_ID` select the certificate and Apple
  developer team.
- `APPLE_NOTARIZATION_KEY_BASE64`, `APPLE_NOTARIZATION_KEY_ID`, and
  `APPLE_NOTARIZATION_ISSUER_ID` provide a dedicated App Store Connect API key
  for notarization.
- `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` sign the
  updater bundle and release manifest. This key is separate from Apple's code
  signing identity and must be backed up for the lifetime of installed clients.

The sidecar preparation script asks Cargo for the active target triple and
copies the matching daemon binary to Tauri's target-specific external-binary
name. The checked-in source therefore does not assume Apple Silicon even
though macOS is the first supported package.

## Validate

```bash
npm --prefix apps/notary-app run build
cargo check -p notary-app
npm --prefix apps/notary-app run tauri:build:debug
```

The native lifecycle should also be exercised on clean config, data, and vault
directories: confirm the no-setup state, complete all five onboarding stages,
exercise both Keychain and advanced passphrase setup (including the empty
passphrase warning), start the service, use the embedded capture workspace,
restart it, stop it, start it again, relaunch and unlock a passphrase vault, and
confirm that quitting the desktop app terminates its managed child.
