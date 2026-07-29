# Consent-based publication admission v1

This is the first server-side admission path for
`llmnotary.trace-package-archive/v1`. It is an explicit publication action,
not an automatic upload from the proxy.

## Privacy boundary

The worker downloads the private finalized-package archive and may inspect its
authenticated disclosed request and response, including prompts, system
context, tool definitions and calls, provider metadata, and model output. It
does not receive the encrypted `.llmbundle`, local vault key, provider
credential values, or cookie values.

Successful and rejected intake objects are deleted immediately after the
database transition. A background purge pass retries failed deletions. Public
endpoints serve only the canonical `trace.otlp.json`, the platform-signed
`stamp.json`, and intentionally public account metadata.

This path does not claim that the service learns only the public trace. Issue
#36 must introduce a new versioned artifact and verifier for that stronger
property; it cannot silently reinterpret previously uploaded v1 packages.

## State machine

```text
uploading -> queued -> verifying -> admitted
                              \-> rejected
```

SQLite atomically moves one queued job to `verifying` with a unique claim.
Stale claims without public artifacts return to `queued`. Cryptographic and
normalization work runs on a blocking worker thread, outside Axum request
handlers. The final database update requires the same claim and empty artifact
columns, so a retry cannot replace or duplicate an admitted pair.

For this single-node MVP, the two public JSON artifacts are stored as SQLite
BLOBs in the same atomic update as the admitted state. DigitalOcean Spaces is
used only for private intake. A public object store or CDN can replace the BLOB
storage when artifact size or traffic justifies the additional consistency and
access-control surface.

## Admission checks

The worker:

1. downloads the immutable intake object with a hard byte limit;
2. computes its actual size and SHA-256 and compares both with the job;
3. defensively validates and extracts the canonical stored ZIP;
4. selects a trusted notary directory record using the embedded key and
   authenticated provider-connection timestamp;
5. verifies the TLSNotary presentation, provider hostname, package hashes,
   disclosed HTTP bytes, and exact deterministic OTLP reproduction;
6. rejects visible `Authorization`, `Proxy-Authorization`, `Cookie`,
   `x-api-key`, or `Set-Cookie` values;
7. signs the exact canonical trace with the separate platform key; and
8. atomically records the public pair before deleting the private object.

Stable client-visible rejection codes currently include
`object_missing`, `object_size_mismatch`, `object_sha256_mismatch`,
`archive_invalid`, `package_invalid`, `notary_untrusted`, and
`sensitive_header_disclosed`. Infrastructure failures are logged and requeued
without exposing internal error strings.

## Public API

- `GET /api/platform` returns the platform issuer and current stamp public key.
- `GET /api/public/traces/{id}` returns public metadata and artifact links.
- `GET /api/public/traces/{id}/trace.otlp.json` returns the canonical trace.
- `GET /api/public/traces/{id}/stamp.json` returns its immutable stamp.

Authenticated `GET /api/publish/jobs/{id}` also returns `trace_url` and
`stamp_url` after admission.

## Key handling

The platform stamp key is separate from every notary key. Production mounts a
32-byte hexadecimal key from
`LLM_NOTARY_PLATFORM_SIGNING_KEY_FILE`. The deploy workflow creates this file
once on the droplet if it is absent; operators must back it up before relying
on the resulting public key as a durable trust root. Rotation for platform
stamp keys is not yet implemented.
