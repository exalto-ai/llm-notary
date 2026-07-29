# Publication intake API v1

This contract uploads one locally finalized trace package to private object
storage. It does not admit or publish the package; the admission path owns
content hashing, safe extraction, cryptographic verification, and stamping.

The supported CLI packages a finalized trace directory as
`llmnotary.trace-package-archive/v1`. It must never package or upload an
encrypted `.llmbundle`. The intake API deliberately treats uploaded bytes as
untrusted and opaque, so a malicious client can mislabel arbitrary bytes. The
later admission verifier must reject anything that is not the declared
finalized-package archive.

## Create or resume an upload

```http
POST /api/publish/jobs
Authorization: Bearer <CLI access token>
Idempotency-Key: <16-200 safe ASCII characters>
Content-Type: application/json

{
  "archive_format": "llmnotary.trace-package-archive/v1",
  "size_bytes": 12345,
  "sha256": "<64 lowercase hexadecimal characters>"
}
```

`size_bytes` must be between 1 byte and the configured limit, which defaults to
128 MiB. `sha256` is the client's declaration and is not trusted until
admission downloads and hashes the object.

A new job returns `201 Created`. Reusing the idempotency key with identical
metadata returns `200 OK` and the same job. Reusing it with different metadata
returns `409 Conflict`.

```json
{
  "job": {
    "id": "c52ecff9-2bd4-42f3-bb1d-b6ad2b671605",
    "state": "uploading",
    "archive_format": "llmnotary.trace-package-archive/v1",
    "size_bytes": 12345,
    "sha256": "<declared hash>",
    "created_at": 1785294000,
    "updated_at": 1785294000,
    "upload_expires_at": 1785294900,
    "queued_at": null,
    "failure_code": null,
    "status_url": "/api/publish/jobs/c52ecff9-2bd4-42f3-bb1d-b6ad2b671605"
  },
  "upload": {
    "method": "PUT",
    "url": "https://<private-presigned-url>",
    "headers": {
      "content-length": "12345",
      "content-type": "application/vnd.llmnotary.trace-package+zip",
      "x-amz-meta-archive-format": "llmnotary.trace-package-archive/v1",
      "x-amz-meta-declared-sha256": "<declared hash>"
    },
    "expires_at": 1785294900
  }
}
```

The upload URL is a temporary write capability and must not be logged. Send the
archive bytes directly to that URL with the returned method and every returned
header. The API never returns Spaces credentials.

If a duplicate create request finds a job that is no longer accepting uploads,
`upload` is `null`.

## Complete an upload

```http
POST /api/publish/jobs/{job_id}/complete
Authorization: Bearer <CLI access token>
```

Completion checks the staging object's size and signed metadata, then copies it
to a key that was never exposed by a presigned URL. Only after that promotion
does the job enter `queued`; the staging object is deleted. Repeating completion
for a queued job returns the same queued job.

The metadata check proves that the object was uploaded through the job's signed
request. It does not prove the bytes match the declared SHA-256. Admission must
compute that hash.

Completion returns:

- `200 OK` with the queued job on success or an idempotent retry;
- `404 Not Found` when the authenticated user does not own the job;
- `409 Conflict` while the object is missing, has the wrong size or metadata,
  or the job is not accepting an upload;
- `410 Gone` after upload expiry.

## Poll status

```http
GET /api/publish/jobs/{job_id}
Authorization: Bearer <CLI access token>
```

Jobs are account-scoped. A caller cannot discover another user's job by ID.
Times are Unix seconds. This version defines `uploading`, `queued`, `expired`,
and `failed`; the same response can later expose `verifying`, `admitted`,
`rejected`, and `purged` as admission is implemented.

## Storage lifecycle

The API stores uploads under two private prefixes:

- `llm-notary/uploads/` contains revocable staging objects;
- `llm-notary/intake/` contains server-promoted objects ready for admission.

Application cleanup expires ordinary staging uploads after 15 minutes. Bucket
lifecycle rules delete staging objects after one day and intake objects after
seven days as recovery backstops. Admission should delete private input sooner
after success or rejection.
