# Hosted Trace intake API v1

This contract uploads one locally notarized `.llmtrace` package to private
object storage for hosted verification. Sharing is an explicit action. Capture
and notarization never upload automatically, and an encrypted `.llmcapture` is
never valid input.

The hosted API treats every uploaded byte as untrusted. Its worker owns strict
archive validation, secret scanning, cryptographic verification, public
artifact storage, and the final reachability decision.

## Package contract

The package uses the deterministic `notary/trace-package/v1` `.llmtrace` ZIP
layout:

```text
archive-manifest.json
evidence.tlsn
manifest.json
request.disclosed.http
response.disclosed.http
trace.otlp.json
```

No other entry is permitted. The reader rejects directories, links, duplicate
names, traversal, non-canonical ZIP metadata, comments, extra bytes,
non-canonical manifests, and undeclared files. It reconstructs the archive and
requires byte-for-byte equality.

## Create or resume a hosted Trace

```http
POST /api/traces
Authorization: Bearer <account access token or API key>
Idempotency-Key: hosted-trace:<source_trace_id>
Content-Type: application/json

{
  "source_trace_id": "trc-local-example",
  "package_format": "notary/trace-package/v1",
  "package_size_bytes": 12345,
  "package_sha256": "<64 lowercase hexadecimal characters>",
  "visibility": "unlisted",
  "password": null,
  "expires_in_days": null,
  "allow_high_entropy": false
}
```

`visibility` is required. `unlisted` creates a stable link without public
discovery and adds no-index response headers. `listed` also includes the Trace
in public Traces. A password of 8 through 128 bytes and an expiry of at most 365
days may be applied atomically so a protected Trace is never briefly exposed.

Set `allow_high_entropy` only after reviewing the complete disclosure and
accepting an entropy-heuristic false positive. It cannot override known secret
formats, credential fields or headers, signed credential queries, malformed
packages, or failed cryptographic verification. The hosted Trace records the
decision and whether the worker actually applied an override.

The source Trace ID is the stable account-scoped identity. An identical retry
returns the same hosted Trace. Reusing it with different package metadata
returns `409 Conflict`. While an upload is open, the response also includes a
short-lived private upload capability:

```json
{
  "trace": {
    "trace_id": "trc-hosted-example",
    "source_trace_id": "trc-local-example",
    "status": "verifying",
    "access": {
      "visibility": "unlisted",
      "password_protected": false,
      "expires_at": null
    },
    "package": {
      "format": "notary/trace-package/v1",
      "declared_size_bytes": 12345,
      "declared_sha256": "<sha256>",
      "admitted_size_bytes": null,
      "admitted_sha256": null
    },
    "verification": {
      "verified_at": null,
      "failure_code": null
    },
    "allow_high_entropy": false,
    "created_at": 1785294000,
    "updated_at": 1785294000,
    "status_url": "/api/traces/trc-hosted-example",
    "public_url": null,
    "package_url": null,
    "owner_package_url": null
  },
  "upload": {
    "method": "PUT",
    "url": "https://<private-presigned-url>",
    "headers": {
      "content-length": "12345",
      "content-type": "application/vnd.exalto.notary.trace-package+zip"
    },
    "expires_at": 1785294900
  }
}
```

The presigned URL is a temporary write capability and must never be logged.
Upload the exact package bytes with every returned header.

## Complete, poll, and manage access

Completion repeats the declared size and hash. The API rejects missing,
oversized, or mismatched objects and never queues ambiguous bytes:

```http
POST /api/traces/{trace_id}/upload-completion
Authorization: Bearer <account access token or API key>
Content-Type: application/json

{
  "package_size_bytes": 12345,
  "package_sha256": "<sha256>"
}
```

Poll `GET /api/traces/{trace_id}`. The public status model is:

```text
verifying -> shared
        \-> rejected
        \-> failed
shared   -> stopped
```

Only active, unexpired `shared` Traces receive `public_url` and `package_url`.
After admission, `owner_package_url` remains available to the authenticated
owner even when public access expires or is stopped. Failure codes are bounded
machine values and never include matched secret text.

Owners list their Traces with `GET /api/traces` and update access without
changing the stable ID:

```http
PATCH /api/traces/{trace_id}
Content-Type: application/json

{
  "visibility": "listed",
  "password": "a new password",
  "expires_in_days": 30
}
```

Fields are optional, but at least one is required. An empty password removes
password protection; `expires_in_days: 0` removes the deadline. Password
changes are rate-limited. `DELETE /api/traces/{trace_id}/share` immediately
stops public access while retaining the verified artifacts. Creating the same
source Trace again can resume sharing at the stable URL.

## Storage lifecycle

Private staging objects are short-lived and deleted after verification or
rejection, with bucket lifecycle rules as recovery backstops. A shared
`trace.otlp.json` and exact `.llmtrace` package use immutable,
content-addressed keys. The database records each key, byte size, SHA-256, and
the disclosure-safety contract version. Owner and public responses use
`private, no-store` so password, expiry, and stop-sharing changes take effect
immediately.
