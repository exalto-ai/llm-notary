# ADR 0001: Cursor pagination for list APIs

Status: accepted

## Decision

Every unbounded list uses the same request fields and response envelope:

```text
?limit=<positive integer>&cursor=<opaque token>
{"items": [...], "next_cursor": "..." | null}
```

Each route sets and documents a default and maximum limit. Invalid limits are
rejected instead of clamped. Queries fetch `limit + 1` rows and sort by a
stable, unique tuple. When another page exists, `next_cursor` continues after
the last returned row; otherwise it is `null`.

Cursors are URL-safe, versioned, and bounded before decoding. They contain a
typed sort position plus an unkeyed checksum that detects corruption, not a
cryptographic proof of authenticity. A scope digest binds each cursor to its
route, normalized filter values, and sort order. Malformed, unsupported,
corrupted, cross-route, and cross-filter cursors receive typed `400` responses.
A caller can forge a syntactically valid position by recomputing the checksum,
so cursor data is never used as SQL text and never grants access: every query
still applies its full user and visibility predicates.

The shared Rust types are `PageQuery`, `Page<T>`, `CursorScope`, and
`PaginationError` in `notary_core::pagination`. The `openapi` feature adds
schemas for the request and response shapes used by both HTTP services.

## Stability under writes

Descending keyset queries select rows strictly below the cursor tuple. Newer
inserts may appear when the client restarts from page one, but do not shift or
duplicate rows in an in-progress traversal. Rows deleted between requests are
simply absent. A route that offers a live high-water cursor exposes it as a
separate field rather than overloading the backward-pagination cursor.

## Array-response inventory

| Surface | Response or field | Classification | Rationale or migration |
| --- | --- | --- | --- |
| Local `GET /v1/traces` | Trace list | Paginated | Uses `(created_at_unix_ms, trace_id)` with stable traversal and cursor-scope tests. |
| Local `GET /v1/activity` | Activity list | Paginated | Uses `event_id` for back-pagination and exposes a separate live high-water cursor. |
| Local `GET /v1/notaries` and status `notaries` | configured notaries | Statically bounded | The trusted directory is configuration, not user data. |
| Local Trace detail `artifacts` and `notarization` | child records | Embedded bounded | A Trace has a fixed artifact set and one durable notarization lineage. |
| Local operation `attempt_history` | child records | Embedded detail | Complete attempt history is returned only for one explicitly selected operation, never in list rows. |
| Hosted `GET /api/public/traces` | public Traces | Paginated | Uses authenticated provider time plus Trace ID; the landing page requests five rows. |
| Hosted `GET /api/traces` | account hosted Traces | Paginated | Uses creation time plus Trace ID under the account predicate. |
| Hosted `GET /api/devices` | connected devices | Paginated | Uses immutable creation time plus session ID under the account and active-session predicates. |
| Hosted `GET /api/api-keys` | API keys | Paginated | Uses creation time plus key ID under the account predicate. |
| Hosted `GET /api/credits/history` | credit ledger | Paginated | Dedicated account-scoped history; `/api/account` retains aggregate balances only. |
| Hosted `GET /api/credit-offers` | configured offers | Statically bounded | Operators define the small offer catalog. |
| Hosted Registry `notaries` | configured notaries | Statically bounded | The HTTPS-authenticated Registry has an operator-defined maximum. |
| API-key `scopes`, verification diagnostics, trace spans, and package entries | value-object arrays | Embedded | These arrays describe one selected resource and are not independently listed. |

New array responses must be added to this table and classified before their
API contract is merged.

## Consequences

Offset pagination is removed from list contracts. Clients must treat cursors
as opaque and discard them whenever a filter changes. Generated OpenAPI clients
share one envelope shape, and route tests cover empty, partial, exact-boundary,
multi-page, tied-sort, concurrent-insert, and invalid-cursor behavior.
