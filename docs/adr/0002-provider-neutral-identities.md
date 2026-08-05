# ADR 0002: Stage provider-neutral account identities

Status: accepted

## Context

The durable `users.id` already owns browser sessions, CLI sessions, API keys,
credits, and publications, but the `users` row also requires a GitHub numeric
ID and login. Adding another login provider directly to that row would make
account ownership ambiguous and would encourage unsafe linking by email.

## Decision

`users` remains the durable account record. It gains a required account-level
`display_name`, initially copied from `github_login`. A new `user_identities`
table stores authentication identities separately with:

- a stable identity ID;
- the owning `user_id`;
- a provider name;
- the provider's stable subject as opaque text;
- provider display and avatar metadata; and
- created, updated, and last-used timestamps.

`(provider, provider_subject)` uniquely identifies a login identity. A user can
have at most one identity for a given provider. Deleting an account cascades to
its identities. Email is deliberately absent: it is neither an account key nor
an automatic linking signal.

Migration 0016 backfills exactly one GitHub identity for every existing user.
Database triggers mirror current GitHub-only inserts and profile updates into
the new table, so old and new application replicas can run around the migration
boundary without leaving the shadow identity data stale. The account display
name follows GitHub login changes only while it has not been customized.

## Transitional authority

Migration 0017 changes GitHub OAuth lookup and profile reads to use
`user_identities`. New accounts are written to `users` plus
`user_identities`; the GitHub-only columns are no longer application authority.
Existing API and UI contracts continue to expose the GitHub login.

The migration temporarily mirrors GitHub identities back to the legacy columns
so a pre-cutover API Machine can still serve traffic or be used for rollback
during the rolling deployment. It also keeps the old-to-new mirror for those
replicas. This compatibility dual write is deliberately limited to the rollout
window and is covered by the follow-up issue below.

## Tracked cutover

[Issue #215](https://github.com/exalto-ai/llm-notary/issues/215) tracks this
cutover through removal of the compatibility dual write. Only after migration
0017 and its application release are deployed everywhere may the next migration
remove the GitHub-only columns and synchronization triggers. That removal makes
the provider-neutral application release the oldest safe rollback target.

Adding Google or another provider requires an explicit authenticated linking
flow; matching provider emails must never merge accounts automatically.
