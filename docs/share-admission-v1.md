# Verified-session share admission v1

Share admission is the server-side boundary that turns an explicitly uploaded
`.llmtrace` into a stable `/s/{share_id}` link. Local capture, finalization,
and verification never imply sharing.

## Privacy and safety boundary

The worker may inspect every disclosed request and response body, including
prompts, system context, tool definitions, tool calls, tool results, provider
metadata, and model output. It never receives an encrypted `.llmbundle`, vault
key, or provider credential value.

Before a share can become reachable, the worker applies the versioned
`llm-notary/public-package-safety/v2` contract to the exact archive bytes. It:

1. requires the strict canonical archive and manifest layout;
2. rejects every visible request or response header value except the structural
   `Transfer-Encoding: chunked` value;
3. scans entry bytes, HTTP bodies, nested JSON strings, and OTLP attribute
   values;
4. rejects credential-shaped keys, signed credential query parameters, known
   token formats, private-key material, and unexplained high-entropy values;
5. reports only bounded error codes and locations, never matched plaintext.

Known public hashes, signatures, public keys, and key identifiers are exempt
from entropy rejection when their structure identifies them as public proof
material. After cryptographic package verification, documented OpenAI response
IDs are also exempt from entropy rejection only for `api.openai.com`, the exact
`/v1/chat/completions` or `/v1/responses` request path, and the root response
`/id` with the matching `chatcmpl-...` or `resp_...` format. Known-secret
patterns still run on those IDs. Nested IDs, other providers and operations,
tool data, and model content receive no exemption. Hostile fixtures cover
tokens split across parsing boundaries, nested tool data, signed queries,
private keys, and high-entropy secrets.

## Admission and storage

The state machine is:

```text
uploading -> queued -> verifying -> admitted
     |                    \-> rejected
     \-> expired -> uploading
```

PostgreSQL claims queued rows with `FOR UPDATE SKIP LOCKED`. Verification runs
outside request handlers under the same bounded process capacity used by the
anonymous verifier. The worker then:

1. downloads the immutable private intake object with a hard byte limit;
2. compares its actual size and SHA-256 with the share declaration;
3. verifies the TLSNotary evidence, trusted notary record, provider hostname,
   disclosed HTTP bytes, package hashes, and deterministic OTLP reproduction;
4. runs the public-package safety contract with the authenticated provider host
   and request path;
5. extracts the model only for the small durable share summary;
6. writes both canonical `trace.otlp.json` and the exact package to immutable
   content-addressed public keys;
7. re-downloads the stored package through the recipient storage path;
8. repeats exact-byte, size, hash, full cryptographic verification, and safety
   validation with the authenticated context;
9. atomically records both artifacts and their verification metadata before
   deleting the private intake object.

An unreferenced candidate is not reachable. The database transition to
`admitted` is the public boundary.

## Visibility

Both visibility modes are public to anyone with the stable link:

- Unlisted shares are directly accessible but excluded from
  `GET /api/public/shares`; their detail and artifact responses include
  `X-Robots-Tag: noindex, nofollow, noarchive`.
- Listed shares are directly accessible and appear in the Library index.

Changing visibility does not change `/s/{share_id}` or either artifact URL.
Access-controlled private shares are outside this contract.

## Public API

- `GET /api/public/shares` returns the minimal Listed index.
- `GET /api/public/shares/{share_id}` returns one admitted share record for
  either visibility.
- `GET /api/public/shares/{share_id}/trace.otlp.json` returns its
  integrity-checked canonical trace.
- `GET /api/public/shares/{share_id}/package.llmtrace` returns the exact
  admitted package with immutable caching, byte size, and SHA-256 metadata.
- Authenticated `GET /api/me/shares` returns the current account's small share
  records.

The direct page leads with a readable conversation. Tool calls and results are
inline and collapsible; hashes, notary identity, and other proof details are
secondary. The downloaded package remains independently verifiable.

Legacy rows that existed before exact-package retention remain Listed so the
forward migration does not hide them. Their direct page and canonical trace
remain available, while the package endpoint returns `410 Gone`.

## Anonymous verification

`POST /api/verify` remains retention-free. It uses the same cryptographic
verifier but does not create a share, activity event, or content record. Its
live response is not a durable signed receipt.
