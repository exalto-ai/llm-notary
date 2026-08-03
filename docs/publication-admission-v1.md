# Consent-based publication admission v1

This is the server-side admission path for
`llmnotary.trace-package-archive/v2`. It is an explicit publication action,
not an automatic upload from the proxy.

## Privacy boundary

The worker downloads the private finalized-package archive and may inspect its
authenticated disclosed request and response, including prompts, system
context, tool definitions and calls, provider metadata, and model output. It
does not receive the encrypted `.llmbundle`, local vault key, provider
credential values, or cookie values.

Version 2 is privacy-minimized for verifier input: authenticated request and
response bodies remain disclosed, but every HTTP header value is hidden except
the exact structural value `Transfer-Encoding: chunked`.

Successful and rejected intake objects are deleted after the database
transition. Failed deletions enter a durable cleanup queue and are retried.
Public endpoints serve only the canonical `trace.otlp.json`, intentionally
public account metadata, and generated Library metadata. Library titles and
tags are discovery aids, not part of the cryptographic claim.

## State machine

```text
uploading -> queued -> verifying -> admitted
     |                    \-> rejected
     \-> expired -> uploading
```

Upload expiry and reopening are intake transitions; admission begins only at
`queued`. A successful completion request is therefore not a verification or
publication result.

PostgreSQL atomically selects a queued job with `FOR UPDATE SKIP LOCKED` and
moves it to `verifying` with a unique claim. Every API replica runs the worker,
but a job can therefore be verified by only one replica at a time. Stale claims
without a public artifact return to `queued`. Cryptographic and normalization
work runs in the bounded shared verifier worker pool, outside Axum request
handlers. The final database update requires the same claim and an empty public
trace column, so a retry cannot replace or duplicate an admitted artifact.

The worker writes canonical OTLP JSON to a content-addressed key under the
private Space's distinct `llm-notary/public/` prefix and verifies its size,
kind, and SHA-256 metadata. PostgreSQL stores the immutable object key, size,
hash, admission state, source package hash, notary key ID, authenticated
provider-connection time, verification time, directory generation, and trust
source. The database transition is the publication boundary: an unreferenced
candidate is not reachable from public APIs, while a committed row is
sufficient to retrieve and integrity-check the trace.

The bucket remains private. Public downloads pass through the API and can be
cached by Cloudflare using immutable response headers. This keeps the private
intake access boundary intact and removes the single-replica database volume
from artifact durability.

## Admission checks

The worker:

1. downloads the immutable intake object with a hard byte limit;
2. computes its actual size and SHA-256 and compares both with the job;
3. defensively validates the canonical ZIP entirely from the uploaded bytes;
4. selects a trusted notary directory record using the embedded key and
   authenticated provider-connection timestamp;
5. verifies the TLSNotary evidence, provider hostname, package hashes,
   disclosed HTTP bytes, and exact deterministic OTLP reproduction;
6. rejects every visible HTTP header value except the exact structural
   `Transfer-Encoding: chunked` value;
7. stores and integrity-checks the public trace; and
8. atomically records its immutable key, hash, and verification metadata before
   deleting the private object.

After admission, a best-effort metadata worker can send a bounded excerpt of
the public normalized trace to the configured model to propose a title and
tags. It cannot change the trace or verification metadata. If generation fails,
the Library uses deterministic provider/model fallbacks.

Rejection codes are bounded and safe to expose. They identify archive,
verification, trust, privacy, or platform failure categories without returning
plaintext or low-level parser details.

## Anonymous verification

`POST /api/verify` accepts exactly one `.llmtrace` body with content type
`application/vnd.llmnotary.trace-package+zip`. It uses the same verifier,
directory selection, byte limit, process isolation, and timeout policy as
publication admission. The response includes the canonical trace, provider,
host, authenticated capture time, notary key ID, trust source, directory
generation, trace SHA-256, and package SHA-256.

The route does not require an account and does not create publication,
activity, or content records. It processes the request without retaining the
package. A per-address lease and a shared worker budget bound anonymous use.
The result is not signed and must not be presented as a durable receipt.

## Public API

- `GET /api/public/collections/traces` lists admitted Library metadata.
- `GET /api/public/traces/{id}` returns one admitted publication record.
- `GET /api/public/traces/{id}/trace.otlp.json` returns its immutable canonical
  trace after storage integrity checks.
- `POST /api/public/traces/{id}/events/download` records a bounded anonymous
  popularity signal without changing verification metadata.
- Authenticated `GET /api/publish/jobs/{id}` returns `trace_url` only after
  admission.

A bare public trace is inspectable output admitted from a verified source
package. It does not include TLSNotary evidence and is not independently
verifiable. Preserve the source `.llmtrace` package when recipients need to
verify the provenance claim themselves.
