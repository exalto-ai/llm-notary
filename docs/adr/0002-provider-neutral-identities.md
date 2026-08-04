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

This migration does not add another provider or change login behavior. GitHub
OAuth still reads and writes `users.github_id`, `users.github_login`, and
`users.avatar_url`; existing API and UI contracts continue to expose the GitHub
login. Those columns and the synchronization triggers remain until all readers
and writers have moved to the provider-neutral model.

## Later cutover

A follow-up can move GitHub lookup and linking to `user_identities`, expose
account-level display fields, and make provider configuration optional. Only
after that cutover is deployed everywhere may a later migration remove the
GitHub-only columns and synchronization triggers. Adding Google or another
provider requires an explicit authenticated linking flow; matching provider
emails must never merge accounts automatically.
