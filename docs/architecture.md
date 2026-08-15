# Architecture and trust model

LLM Notary makes one narrow provenance claim: disclosed HTTP bytes came from a
TLS connection to a named provider, as witnessed by a selected notary key, and
the included OpenTelemetry trace is the deterministic normalization of those
bytes.

This document separates that claim from local observations and platform
convenience features.

## Components

| Component | Holds plaintext? | Durable state | Main responsibility |
| --- | --- | --- | --- |
| Provider client | yes | provider credential | Sends an ordinary provider request to the local proxy |
| `llm-notaryd` | yes | vault, catalog, operations, artifacts, trust cache | Runs the proxy, captures private state, finalizes, and verifies |
| Remote notary | no application plaintext | signing key only | Resolves the provider, relays encrypted TLS records, witnesses the session, and completes proof work |
| Model provider | yes | provider-owned | Serves an ordinary HTTPS request without an LLM Notary integration |
| Hosted platform | only explicitly uploaded disclosures | accounts, share intake, admitted traces and exact packages | Issues admission tickets, verifies uploads, serves stable links, and indexes Listed shares |
| Independent verifier | disclosed package contents | chosen trust policy | Verifies a `.llmtrace` against a trusted notary key |

The notary is not a generic forward proxy. The protocol selects one of four
fixed provider adapters, and the notary enforces the corresponding hostname
allowlist before it resolves or connects upstream.

## Capture flow

1. A provider client sends an HTTP/1.1 request to a fixed local route.
2. The local daemon selects the fixed provider hostname from that route.
3. The remote notary resolves and opens the upstream TCP connection.
4. The local daemon performs the provider TLS handshake through the notary and
   validates the provider certificate with Mozilla roots.
5. The notary relays encrypted TLS records and witnesses the Proxy-TLS session.
6. The local daemon streams provider response bytes back to the caller.
7. After the final response, the notary signs a deferred receipt and the local
   daemon vault-encrypts its client checkpoint as `.llmcapture`.

The notary learns the selected provider hostname, ciphertext sizes, timing,
and protocol metadata. It does not receive the provider credential, prompt, or
response plaintext. The local daemon necessarily sees all three.

Capture and finalization have independent notary capacity budgets. Capture is
latency-sensitive; finalization is CPU- and memory-intensive. A capacity
rejection happens before expensive TLSNotary work and leaves any existing
bundle unchanged.

## Deferred finalization

The capture contains the client state required to reconstruct and prove the
original session. It also contains a notary-signed receipt that binds it to the
signing key and lets a later finalizer select a compatible notary.

The original socket and notary process do not need to survive. Any notary
instance holding the same signing key can complete finalization before that
key's drain deadline. The notary stores no per-bundle checkpoint.

Finalization creates selective TLSNotary disclosure, verifies it locally,
normalizes the authenticated provider exchange, and writes the deterministic
`.llmtrace` archive atomically. It never consumes the source capture.

## Trust anchors and key discovery

Hosted clients fetch `GET /api/notary` from the configured public origin over
authenticated HTTPS. The response is a versioned lifecycle directory; it is
not itself cryptographically signed. Clients defend against accidental or
stale changes by caching accepted generations, rejecting rollback or a
conflicting document at the same generation, and remembering revocations
monotonically.

HTTPS origin security and the local cache are therefore part of hosted key
distribution. The notary signing key remains the evidence trust anchor. A
package-embedded public key is only a key identifier until the verifier matches
it to trusted history for the authenticated provider-connection time.

A self-hosted client bypasses the directory and pairs `notary.endpoint` with
`notary.public_key` in local configuration. That is an explicit operator trust
decision with no lifecycle policy beyond the configured key.

See [Notary key lifecycle](notary-key-lifecycle.md) for rotation and
revocation.

## What verification establishes

Full package verification checks:

1. the archive is the one canonical versioned ZIP representation;
2. every entry matches the archive manifest;
3. the embedded notary key matches the verifier's trust source;
4. the TLSNotary presentation and notary signature are valid;
5. the presentation authenticates the expected provider identity;
6. the disclosed HTTP bytes match the presentation;
7. every non-structural HTTP header value remains hidden;
8. the verified-package manifest hashes the disclosed artifacts; and
9. `trace.otlp.json` is reproduced byte-for-byte from the authenticated
   exchange.

Verification is offline after the trust source is available. It does not
contact the provider or a live notary.

## Authenticated, derived, and observed data

Use these distinctions when describing a trace:

- Provider response bytes, including a model-emitted tool call, are
  authenticated provider output.
- Request bytes are authenticated as values the client sent. A tool result in
  a later request does not prove that a local tool ran or produced that result.
- The canonical trace is deterministically derived from authenticated request
  and response bodies.
- Catalog previews, local operation events, device labels, share visibility,
  and publisher labels are local or platform observations. They are not
  upgraded into cryptographic claims by appearing beside a verified trace.
- A shared conversation is rendered from an admitted canonical trace. The
  retained exact `.llmtrace` download carries the proof needed for independent
  verification; the rendered page alone does not.

## What the system does not prove

LLM Notary does not establish:

- that a model response is true, correct, safe, complete, or useful;
- that a named person authored a prompt;
- that a local tool executed or returned truthful output;
- that all calls from an agent run or conversation were disclosed;
- that client-supplied conversation metadata names a genuine runtime session;
- that a trusted notary key was never compromised; or
- that a model routed through OpenRouter came directly from the vendor named in
  its model slug.

Provider-native response signatures would provide a stronger origin primitive.
A transparency log would strengthen key-history auditing. Neither exists in
the current prototype.

## Sharing boundary

Local capture, finalization, and verification never imply sharing.
Sharing requires a separately authorized and explicit action plus an Unlisted
or Listed choice. Owners can later unpublish, set an expiry, or require a
password on the stable link. These are hosted access controls, not a change to
the package disclosure: admission still receives and inspects the complete
shared `.llmtrace`.

The platform receives the complete `.llmtrace`, including disclosed request
and response bodies, and may inspect them to scan and reproduce the trace. It never
needs the encrypted `.llmcapture`, local vault material, or redacted credential
values. Admission stores the canonical trace and the exact safety-checked,
verified `.llmtrace` package after re-downloading and re-verifying the stored
bytes. The private intake object is then deleted, with failed deletions placed
on a durable cleanup queue.

Anonymous hosted verification uses the same core verifier but creates no
share or content record. Its live response is not signed and is not a
durable receipt.
