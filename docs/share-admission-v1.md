# Hosted Trace verification and public access v1

Hosted verification is the server-side boundary that turns an explicitly
uploaded `.llmtrace` into a stable `/s/{trace_id}` link. Local capture,
notarization, and verification never imply sharing.

## Privacy and safety boundary

The worker may inspect every disclosed request and response body, including
prompts, system context, tool definitions, tool calls, tool results, provider
metadata, and model output. It never receives an encrypted `.llmcapture`, vault
key, or provider credential value.

Before a Trace becomes reachable, the worker applies the versioned
`notary/public-package-safety/v1` contract to the exact archive bytes. It:

1. requires the strict canonical archive and manifest layout;
2. rejects every visible request or response header value except the structural
   `Transfer-Encoding: chunked` value;
3. scans entry bytes, HTTP bodies, nested JSON strings, and OTLP attributes;
4. rejects credential-shaped keys, signed credential query parameters, known
   token formats, private-key material, and unexplained high-entropy values;
5. reports bounded error codes and locations, never matched plaintext.

The local client runs the same contract on the exact, cryptographically
verified package before authentication or upload. The server repeats it as the
authoritative check. `allow_high_entropy: true` can accept only unexplained
high-entropy values after disclosure review; it cannot override known secrets,
malformed evidence, or a verification failure.

Known public hashes, signatures, keys, and provider response identifiers are
exempt only at their documented, cryptographically authenticated protocol
locations. Nested IDs, tool arguments and results, model content, providers,
and operations receive no broad exemption. Hostile fixtures cover tokens split
across parsing boundaries, nested tool data, signed queries, private keys,
malformed SSE, and high-entropy secrets.

## Verification and storage

PostgreSQL claims work with `FOR UPDATE SKIP LOCKED`. Verification runs outside
request handlers under the same bounded process capacity as the anonymous
verifier. The worker:

1. downloads the immutable private intake object with a hard byte limit;
2. compares exact size and SHA-256 with the Trace declaration;
3. verifies TLSNotary evidence, trusted notary identity, provider hostname,
   disclosed HTTP bytes, package hashes, and deterministic OTLP reproduction;
4. applies the disclosure-safety contract with authenticated provider context;
5. derives only the bounded metadata needed by public views;
6. writes canonical `trace.otlp.json` and the exact package to immutable keys;
7. re-downloads through the recipient storage path and repeats exact-byte,
   hash, cryptographic, and safety checks;
8. atomically records both artifacts before deleting private intake bytes.

An unreferenced candidate object is not reachable. The atomic transition to
`shared` is the public boundary.

## Visibility and protected discovery

Unlisted Traces are reachable by stable link but excluded from
`GET /api/public/traces`; detail and artifact responses include
`X-Robots-Tag: noindex, nofollow, noarchive`. Listed Traces also appear in the
Library.

Password-protected Listed entries disclose only generic discovery fields. They
do not reveal provider, model, publisher, timestamp, title, prompt/response
preview, or provider-filter/search matches before access. Expired and stopped
Traces are excluded from the Library and unavailable from every public route.

## Public API

- `GET /api/public/traces` returns a cursor-paginated Listed index. Search and
  provider filters run before pagination. Search requires three consecutive
  letters or numbers and treats regular-expression punctuation literally.
- `POST /api/public/traces/{trace_id}/access` accepts a bounded JSON password.
  Correct access returns `204` and a host-only `notary_trace_access` cookie
  scoped to that exact Trace path. The cookie is HttpOnly, Secure in production,
  SameSite=Lax, expires within 24 hours, and becomes invalid if the password
  changes. Passwords never appear in URLs or headers.
- `GET /api/public/traces/{trace_id}` returns admitted verification metadata.
- `GET /api/public/traces/{trace_id}/content` returns a bounded projection of
  disclosed input and output messages.
- `GET /api/public/traces/{trace_id}/trace.otlp.json` returns the exact,
  integrity-checked canonical OpenTelemetry trace.
- `GET /api/public/traces/{trace_id}/package.llmtrace` returns the exact admitted
  package with integrity metadata.
- `POST /api/public/traces/{trace_id}/reports` records a bounded reason and an
  optional 500-character note.

Missing, stopped, expired, and incorrectly protected Trace IDs use the same
generic `404` response. Password attempts and reports have keyed per-network,
per-Trace rate limits without storing raw client addresses. Public artifacts
use `private, no-store`; protected responses also vary on the scoped cookie.

The direct page leads with the disclosed conversation. Proof hashes and notary
identity remain secondary, and the package remains independently verifiable.
An admitted row without complete package metadata is internal corruption, not
a supported legacy shape.

## Anonymous verification

`POST /api/verify` remains retention-free. It uses the same cryptographic
verifier but creates no hosted Trace, report, or durable receipt. A successful
live response is not a signed attestation.
