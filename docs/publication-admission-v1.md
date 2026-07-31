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
`stamp.json`, intentionally public account metadata, and generated Library
metadata. Library titles and tags are discovery aids, not part of the
cryptographic claim or platform stamp.

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
columns, so a retry cannot replace or duplicate an admitted pair. The fixed
15-minute claim timeout assumes the current single in-process worker; add lease
renewal before sharing the queue across independent worker processes.

The worker writes the two public JSON artifacts to content-addressed keys under
the private Space's distinct `llm-notary/public/` prefix and verifies their
size, kind, and SHA-256 metadata. SQLite stores only the immutable object keys,
sizes, hashes, and admission state. The database transition is the publication
boundary: unreferenced candidates are not reachable from public APIs, while a
committed row is sufficient to retrieve and integrity-check both objects.

The bucket remains private. Public downloads pass through the API and can be
cached by Cloudflare using immutable response headers. This keeps the private
intake access boundary intact and removes the single-droplet SQLite volume
from artifact durability. A separate public Space or CDN origin can replace
this prefix later without changing the trace/stamp contract.

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
7. signs the exact canonical trace with the separate platform key;
8. stores and verifies the public pair in Spaces; and
9. atomically records its immutable keys and hashes before deleting the
   private object.

After admission, a best-effort metadata worker can send a bounded excerpt of
the public normalized trace to the configured metadata model to generate a
short title and controlled tags. This processing is never an admission check:
if it is unavailable, the Library uses a deterministic fallback title and
retries later. Operators must configure the model only when publication
consent covers that additional processor.

The default metadata budget is 1,000 cents per UTC week. Before each request,
the worker checks the configured worst-case 32,000 input and 256 output
tokens against that week's recorded usage; completed requests persist the
API-reported token usage and a
cost estimate. The default rates are the current standard `gpt-5.6-luna` rates
($0.20/M input, $0.02/M cached input, $0.25/M cache writes, and $1.20/M output);
configure all rates whenever the metadata model is
changed. A budget-limited trace keeps a fallback title and is retried later.

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
- `POST /api/public/traces/{id}/events/download` records a successful client
  download using an opaque client nonce. It is used only as a recent-download
  ranking signal; ordinary artifact requests are not counted.

The activity table is intentionally generic (`event_type`, opaque subject key,
and timestamp) so additional product events can be introduced without a new
analytics schema. Only `download` is accepted today.

Authenticated `GET /api/publish/jobs/{id}` also returns `trace_url` and
`stamp_url` after admission.

## CLI download

`llm-notary download <publication-id>` first resolves the public metadata
endpoint, then accepts only its same-origin canonical trace and stamp paths.
It writes both artifacts into a staging directory and renames that directory
into place only after both downloads are complete. Existing output requires
`--overwrite`; failed transfer or verification leaves the existing directory
unchanged. `--verify` fetches the platform directory from the same configured
API origin and applies the independent public-trace verifier before saving the
download.

## Key handling

The platform stamp key is separate from every notary key. Production mounts a
32-byte hexadecimal key from
`LLM_NOTARY_PLATFORM_SIGNING_KEY_FILE`. The deploy workflow creates this file
once on the droplet if it is absent; operators must back it up before relying
on the resulting public key as a durable trust root. Rotation for platform
stamp keys is not yet implemented.
