# Desktop app

The macOS app is the guided way to run LLM Notary. It packages setup, service
controls, and the local capture workspace in one native application. Normal use
does not require a terminal or a separate browser window.

## Install

The current app requires an Apple silicon Mac (M1 or newer) running macOS 12
Monterey or later.

1. Choose **Download for macOS** on the [LLM Notary website](https://llm-notary.exalto.ai/).
2. Open the downloaded DMG.
3. Move LLM Notary to Applications, then launch it.

Production downloads are signed with a Developer ID certificate, notarized by
Apple, and stapled for offline Gatekeeper checks. Each successful production
build replaces the website's moving `latest` pointer; no stable compatibility
or file-format promise applies yet.

## What the app does

The app provides a four-stage first run, supervises the bundled `llm-notaryd`
process, exposes its status from the menu bar, and contains the complete local
capture workspace. Users do not need to open a localhost page in a browser.
Closing the window removes the app from the Dock and leaves the menu-bar
controller running; opening it from the menu bar restores the regular app
window. Quitting the app asks a daemon that it started to stop accepting new
work, waits for open response streams and the currently running finalization to
finish, and then exits. It never force-kills the service if draining takes too
long. Once onboarding
is complete, later app launches start the bundled service automatically.

First run detects the local agent config, capture vault, and service before it
changes anything. It then guides the user through capture protection, choosing
a provider and optional default model, starting the service, and confirming the
ready state. Provider credentials remain in the user's coding tool; the desktop
app never asks for or stores them.

The capture workspace is served by the supervised daemon on the fixed loopback
address `127.0.0.1:8788` and embedded in the native window. The desktop content
security policy permits that exact local frame; it does not permit public or
arbitrary remote pages.

## Connect subscription-backed clients

Choosing a provider during setup shows and copies the local base URL; it does
not reconfigure or sign in to the vendor client. Subscription-backed capture is
supported and live-tested with Codex CLI using its saved ChatGPT login and
Claude Code using its saved claude.ai login. The LLM Notary app can supervise
the proxy while either CLI sends requests through it.

This does not intercept traffic from vendor applications automatically. Native
Claude Desktop cannot currently use the local route. Codex desktop is not yet
an end-to-end-tested or supported client surface, even though local Codex work
may read the same configuration. Browser, Slack, remote, and cloud sessions run
outside this Mac's loopback proxy. See [Provider and agent setup](provider-setup.md)
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
capture or finalization. On click, the app authenticates `latest` again, checks
activity again, asks its managed daemon to stop accepting new work, waits for
open streams, detached capture sealing, and the current finalization to finish,
installs the application, and reopens it. A daemon started outside the app is
never stopped or replaced by this flow.

## Private capture protection

All `.llmcapture` files remain encrypted before they are written. First run
selects **Protect private captures with Keychain** by default. macOS protects
the random vault key, and there is no separate password to remember.

Advanced options allow a passphrase instead. The passphrase is required again
when the app opens and is retained only for that app session. It is never
written to the vault configuration. New passphrase vaults include an encrypted
key check so the app can reject an incorrect passphrase before starting the
local service. An empty passphrase is allowed as an explicit convenience
choice: captures are still encrypted on disk, but this provides no meaningful
protection to anyone who can access that account's application data.

The app unlocks the vault before launching the daemon and sends the already
unlocked key through the child's anonymous standard-input pipe. The key is not
placed in command-line arguments, environment-variable values, logs, or files.
An environment flag only tells the supervised child to read the key from the
pipe. Temporary key buffers are cleared when dropped.

An existing passphrase vault created outside the desktop app can be unlocked in
the same screen. Vault migration remains a future workflow; the current
settings screen explains this instead of silently changing protection for
existing captures.

## Develop from source

The desktop app is built with Tauri 2. Its source stays portable so Windows and
Linux packaging can follow without replacing the application shell.

Install the desktop dependencies once:

```bash
npm --prefix js/desktop install
```

Start the Tauri development app with a debug `llm-notaryd` sidecar:

```bash
npm --prefix js/desktop run tauri:dev
```

Build a release application bundle and DMG with a release sidecar:

```bash
npm --prefix js/desktop run tauri:build
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
npm --prefix js/desktop run build
cargo check -p llm-notary-desktop
npm --prefix js/desktop run tauri:build:debug
```

The native lifecycle should also be exercised on clean config, data, and vault
directories: confirm the no-setup state, complete all four onboarding stages,
exercise both Keychain and advanced passphrase setup (including the empty
passphrase warning), start the service, use the embedded capture workspace,
restart it, stop it, start it again, relaunch and unlock a passphrase vault, and
confirm that quitting the desktop app terminates its managed child.
