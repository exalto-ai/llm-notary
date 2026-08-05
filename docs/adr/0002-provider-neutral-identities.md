# ADR 0002: Provider-neutral account identities

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

## Authority

Migration 0017 changes GitHub OAuth lookup and profile reads to use
`user_identities`. New accounts are written to `users` plus
`user_identities`; the GitHub-only columns are no longer application authority.
Existing API and UI contracts continue to expose the GitHub login.

Migration 0018 makes that authority permanent. It reconciles every account's
legacy GitHub metadata against its GitHub identity and aborts if any row is
missing or stale. After a successful reconciliation it removes both mirror
directions and drops `users.github_id`, `users.github_login`, and
`users.avatar_url`.

The durable account ID and account-level `display_name` live in `users`.
Authentication subjects and provider profile metadata live only in
`user_identities`. The current `github_login` response field is a compatibility
API name populated from the GitHub identity; it is not a database authority.

## Deployment and rollback boundary

Migration 0017 temporarily mirrored GitHub identities back to the legacy
columns so a pre-cutover API Machine could serve traffic or be used for rollback
during its rolling deployment. Migration 0018 was released only after the 0017
application image was healthy on every production API Machine. The deployment
workflow may roll back to that identity-authoritative image because it does not
query the removed columns. Images older than the 0017 application release are
not safe rollback targets after migration 0018.

Adding Google or another provider requires an explicit authenticated linking
flow; matching provider emails must never merge accounts automatically.
