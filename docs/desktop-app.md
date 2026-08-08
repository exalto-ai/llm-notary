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
window. Quitting the app stops a daemon that the app started. Once onboarding
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

## Private capture protection

All `.llmcapture` files remain encrypted before they are written. First run
offers two choices:

- **Protect private captures with Keychain** is the recommended default. The
  app unlocks the vault through the operating system credential store.
- **No device protection** is an explicit convenience choice. The capture is
  still encrypted on disk, but the same local user account has everything
  needed to open it, so this does not protect against access to that account's
  application data.

The app unlocks the vault before launching the daemon and sends the already
unlocked key through the child's anonymous standard-input pipe. The key is not
placed in command-line arguments, environment-variable values, logs, or files.
An environment flag only tells the supervised child to read the key from the
pipe. Temporary key buffers are cleared when dropped.

An existing passphrase vault created outside the desktop app is detected but
cannot yet be unlocked in the desktop UI. Vault migration also remains a
future workflow; the current settings screen explains this instead of silently
changing protection for existing captures.

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

GitHub's **Desktop DMG** workflow builds an Apple Silicon package. Pull requests
and non-production download tests build an unsigned DMG so unreviewed code never
receives production signing credentials. A successful main build signs,
notarizes, staples, and checks the package, then publishes the DMG and its
SHA-256 checksum in the same immutable website build selected by the `latest`
pointer as the CLI archives.

The signed workflow reads these secrets from the branch-restricted
`macos-release` GitHub environment:

- `APPLE_CERTIFICATE` and `APPLE_CERTIFICATE_PASSWORD` contain an encrypted,
  base64-encoded Developer ID Application identity and its password.
- `APPLE_SIGNING_IDENTITY` and `APPLE_TEAM_ID` select the certificate and Apple
  developer team.
- `APPLE_NOTARIZATION_KEY_BASE64`, `APPLE_NOTARIZATION_KEY_ID`, and
  `APPLE_NOTARIZATION_ISSUER_ID` provide a dedicated App Store Connect API key
  for notarization.

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
start the service, use the embedded capture workspace, restart it, stop it,
start it again, and confirm that quitting the desktop app terminates its managed
child.
