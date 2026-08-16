# Runtime architecture

`llm-notaryd` is the only component in the provider request path that sees plaintext and provider credentials. It terminates the caller's local HTTP connection, establishes the Proxy-TLS protocol with a remote `llm-notary-server`, and retains the encrypted checkpoint and private catalog locally.

The remote notary resolves and opens the upstream provider connection. Its hostname allowlist is explicit. It observes protocol messages and authenticated byte counts, but it must not receive provider credentials or plaintext request/response bodies.

`llm-notary` is intentionally a thin client for the daemon's versioned loopback REST API. It does not open the catalog, vault, captures, or protocol implementation. The local dashboard uses the same API contract.

The generic notary accepts an `AdmissionPolicy` implementation and reports terminal outcomes through `SessionLifecycle`. The public runtime ships a ticketless policy with hard local limits. A deployment may supply a policy adapter, but account, billing, and hosted-product rules are outside this tree.

Clustered daemon mode replaces SQLite/filesystem state with PostgreSQL and S3-compatible storage. Replicas share one vault key and a compatibility fingerprint derived only from runtime configuration and that key—not from any hosted platform origin.
