---
name: llm-notary
description: Inspect and operate the local LLM Notary service, captures, notarization jobs, verified traces, packages, events, notary trust, accounts, and shares. Use when a user asks to find or inspect recorded LLM calls, list or verify traces, notarize a capture, diagnose local proof work, or share a verified session through notaryd.
---

# LLM Notary

Use the installed `llm-notary` command client for supported operations. It
resolves the daemon's configured loopback address, checks the API version, and
handles configured local authentication without exposing a password in a URL.

## Start safely

1. Run `llm-notary --json status` before acting on daemon state.
2. Use `llm-notary --json captures list --metadata-only` to obtain capture
   identifiers and timestamps without placing stored prompt or output previews
   in the agent transcript. Operate only on identifiers returned by the daemon.
3. Prefer a documented CLI command. When the CLI does not expose the requested
   operation, fetch `/openapi.json` from the configured loopback admin origin
   and follow that installed contract rather than a memorized route or schema.
4. Ask for confirmation before finalizing a capture, retrying proof work,
   connecting or disconnecting an account, or sharing a trace.
5. Read [references/workflows.md](references/workflows.md) before performing a
   state-changing operation or diagnosing a failed operation.

## Protect private evidence

- Never request, decrypt, print, upload, or expose `.llmcapture` or legacy
  `.llmbundle` contents, provider credentials, cookies, authenticated header
  values, admin passwords, hosted account credentials, or vault material.
- Treat a `.llmtrace` as disclosed evidence, not as private input. Explain that
  its request and response bodies remain visible even though header values are
  hidden by policy.
- Run `llm-notary traces show` only when the user explicitly asks to disclose
  the notarized request and response bodies in the current agent transcript.
- Never describe a successfully opened capture or package as cryptographically
  verified. Use `llm-notary traces verify` and report its exact result.
- Never share a trace without the user's separate approval. Default to an
  unlisted link unless the user explicitly requests public Library listing.

## Handle authentication

If the daemon requires admin authentication, do not guess or ask the user to
paste the password into a command. Ask for an approved private password-file
path and pass it with `--admin-password-file`. Never read, print, log, or
persist the password itself.

## Report precisely

- Distinguish capture, notarization, verification, and sharing as separate
  states.
- Treat notarization and sharing as asynchronous. Preserve returned operation
  or share identifiers and poll only the documented status operation.
- Branch on stable JSON fields and `error.code`; do not parse human-readable
  prose when `--json` is available.
- Do not assume list ordering, defaults, or pagination semantics that the live
  contract does not state. Compare returned timestamps when the user asks for
  the newest or oldest record.
- If the live OpenAPI document lacks the requested operation, explain that the
  installed daemon does not support it and stop.
