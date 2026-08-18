# API keys for automation

Use a stable, scoped LLM Notary API key when `notaryd` runs without a
person available to approve and preserve a rotating device session. API keys
are intended for CI systems, cron jobs, and unattended hosts. They authenticate
the daemon to the hosted platform; they are not model-provider credentials.

## Create and rotate a key

Sign in to the hosted dashboard, open **Account**, and choose **Create API
key**. Give the key a deployment-specific name, choose the smallest required
scope set, and optionally choose an expiration date. The complete key appears
only in the creation receipt. Store it before closing that receipt.

The supported scopes are:

| Scope | Permitted platform operations |
| --- | --- |
| `account:read` | Read the authenticated identity used by `account show` and connection status |
| `traces:read` | Read hosted Traces owned by the account |
| `traces:share` | Create, upload, complete, and manage hosted Traces |
| `capture:request` | Request one-operation capture admission tickets |
| `notarization:request` | Request one-operation notarization admission tickets |

Key management, browser sessions, plan changes, billing, and administrative
routes never accept an API key.

Rotate manually by creating a replacement, deploying it, confirming the new
key works, and then revoking the old key. Both keys may overlap. They use the
same account plan, concurrency, rate limits, and credit budget.

## Inject the key into the daemon

For ordinary CI secret injection, set the key directly in the daemon's
environment:

```bash
export NOTARYD_PLATFORM_API_KEY='notary_key_…'
notaryd
```

When a runner or service manager can mount secrets, prefer a private UTF-8
regular file. On Unix it must not be readable by group or other users. A final
CRLF or LF line ending is accepted:

```bash
export NOTARYD_PLATFORM_API_KEY_FILE=/run/secrets/notary-api-key
notaryd
```

For a self-hosted platform, set the HTTPS API origin separately:

```bash
export NOTARYD_PLATFORM_API_ORIGIN=https://notary.example.com
export NOTARYD_PLATFORM_API_KEY_FILE=/run/secrets/notary-api-key
notaryd
```

`NOTARYD_PLATFORM_API_KEY` and `NOTARYD_PLATFORM_API_KEY_FILE` are mutually exclusive. An
injected API key and a stored browser-approved device session are also mutually
exclusive; `notaryd` fails at startup if both exist. Disconnect the stored
device session before switching an existing installation to API-key mode.

The key is never copied into `config.toml`, `credentials.json`, the capture
catalog, or the OS keychain. It is sent only as a bearer credential to the
configured platform API. The remote notary receives the resulting short-lived,
one-time admission ticket—not the API key or any platform access credential.

Browser-driven login and logout are unavailable while an injected API key is
active. Revoke the key from the hosted dashboard. `notaryctl account show` and the
local Traces view report the account, credential kind, and key name
without displaying the key.

## GitHub Actions example

Store the platform key as the protected environment secret
`NOTARYD_PLATFORM_API_KEY`. The vault passphrase below is a separate runner secret
used to encrypt private local bundles on a host without an OS vault.

```yaml
jobs:
  capture:
    runs-on: ubuntu-latest
    environment: llm-notary
    env:
      NOTARYD_PLATFORM_API_KEY: ${{ secrets.NOTARYD_PLATFORM_API_KEY }}
      LLM_NOTARY_VAULT_PASSPHRASE_FILE: ${{ runner.temp }}/llm-notary-vault-passphrase
    steps:
      - name: Check out the public runtime
        uses: actions/checkout@v6
        with:
          repository: exalto-ai/notary-runtime
      - uses: dtolnay/rust-toolchain@1.95.0
      - name: Install LLM Notary
        run: |
          cargo install --locked --path crates/notaryd --bin notaryd
          cargo install --locked --path crates/notaryctl --bin notaryctl
      - name: Start the local service
        env:
          VAULT_PASSPHRASE: ${{ secrets.LLM_NOTARY_VAULT_PASSPHRASE }}
        run: |
          umask 077
          printf '%s' "$VAULT_PASSPHRASE" > "$LLM_NOTARY_VAULT_PASSPHRASE_FILE"
          notaryd > "$RUNNER_TEMP/notaryd.log" 2>&1 &
          for attempt in $(seq 1 30); do
            curl --fail --silent http://127.0.0.1:8788/healthz && exit 0
            sleep 1
          done
          exit 1
      - name: Confirm the account connection
        run: notaryctl account show
```

Do not print the daemon environment or upload its log, catalog, encrypted
bundles, configuration directory, or vault files as workflow artifacts. Add
only the scopes used by later capture, notarization, or hosted Trace steps.
