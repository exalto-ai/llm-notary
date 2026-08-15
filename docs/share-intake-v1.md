# Share intake API v1

This contract uploads one locally finalized `.llmtrace` package to private
object storage for verified-session admission. Sharing is a separate,
consent-based action. The proxy never uploads a capture automatically, and an
encrypted `.llmcapture` is never a valid input.

The intake API treats every uploaded byte as untrusted. Admission owns strict
archive validation, secret scanning, cryptographic verification, public
storage, and the final reachability decision.

## Package contract

The package uses the deterministic
`llmnotary.trace-package-archive/v2` ZIP layout:

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

## Create or resume a share

```http
POST /api/shares
Authorization: Bearer <account access token>
Idempotency-Key: <16-200 safe ASCII characters>
Content-Type: application/json

{
  "archive_format": "llmnotary.trace-package-archive/v2",
  "size_bytes": 12345,
  "sha256": "<64 lowercase hexadecimal characters>",
  "visibility": "unlisted",
  "force": false
}
```

`visibility` is required:

- `unlisted` is the default product choice. Anyone with the stable link can
  open it, but it does not appear in the Library and public responses carry a
  no-index directive.
- `listed` has the same link access and also appears in the Library index.

Owners may add a password or expiry after admission. Those settings gate the
stable public routes; they do not prevent the platform admission service from
inspecting and retaining the disclosed package.

`force` defaults to `false`. Set it to `true` only after reviewing the complete
disclosure and accepting an entropy-heuristic false positive. It does not
override known secret formats, credential fields or headers, signed credential
queries, malformed packages, or failed cryptographic verification. The share
record and admitted public detail retain whether force was requested and
whether the entropy override was actually applied.

A new share returns `201 Created`. Reusing the idempotency key with identical
metadata, visibility, and force decision returns `200 OK` and the same share. Reusing it with
different input returns `409 Conflict`. The local client derives its key from
the exact archive SHA-256 and chosen visibility so ambiguous network failures
resume safely.

The response contains a small share record and, while `uploading`, one-use
upload instructions:

```json
{
  "share": {
    "id": "c52ecff9-2bd4-42f3-bb1d-b6ad2b671605",
    "state": "uploading",
    "visibility": "unlisted",
    "published": true,
    "password_protected": false,
    "expires_at": null,
    "force": false,
    "created_at": 1785294000,
    "updated_at": 1785294000,
    "admitted_at": null,
    "failure_code": null,
    "status_url": "/api/shares/c52ecff9-2bd4-42f3-bb1d-b6ad2b671605",
    "share_url": null,
    "package_url": null
  },
  "upload": {
    "method": "PUT",
    "url": "https://<private-presigned-url>",
    "headers": {
      "content-length": "12345",
      "content-type": "application/vnd.llmnotary.trace-package+zip"
    },
    "expires_at": 1785294900
  }
}
```

The presigned URL is a temporary write capability and must never be logged.
Send the exact archived bytes with every returned header.

## Complete and poll

```http
POST /api/shares/{share_id}/complete
Authorization: Bearer <account access token>
```

Completion checks signed object metadata, promotes the upload to a
generation-specific private key, and atomically queues admission. It does not
claim that the bytes are safe or verified.

```http
GET /api/shares/{share_id}
Authorization: Bearer <account access token>
```

The state machine is:

```text
uploading -> queued -> verifying -> admitted
     |                    \-> rejected
     \-> expired -> uploading
```

Only `admitted` shares receive `share_url`. New shares also receive
`package_url`; legacy admitted records may not have a retained package.
Failure codes are bounded machine codes and never include matched secret
values.

An owner can change discoverability, publication state, password access, and
expiry without changing the stable link. Browser-session and bearer-token
authentication are both accepted:

```http
PATCH /api/shares/{share_id}
Authorization: Bearer <account access token>
Content-Type: application/json

{
  "visibility": "listed",
  "published": true,
  "password": "a new password",
  "expires_in_days": 30
}
```

Fields are optional, but at least one is required. A non-empty `password` must
contain 8 through 128 bytes; an empty value removes password protection.
`expires_in_days` accepts `1` through `365`; `0` removes
the deadline. `published: false` immediately makes the detail, trace, package,
and report routes return `404`, while retaining the admitted artifacts so the
owner can publish the same stable share again.

Public clients send a protected share's UTF-8 password as unpadded base64url in
the `X-Share-Password` header. The encoding keeps every password accepted by
the JSON settings API safe for HTTP headers; it is transport encoding, not
encryption. HTTPS still provides confidentiality in transit.

## Storage lifecycle

Private staging and intake objects are short-lived and deleted after admission
or rejection, with bucket lifecycle rules as recovery backstops. Admitted
`trace.otlp.json` and the exact admitted `.llmtrace` package use content-addressed
object keys. HTTP responses use `private, no-store` because owner access changes
must take effect immediately. The database records each object key, byte size,
SHA-256, and the public-package safety contract version.
