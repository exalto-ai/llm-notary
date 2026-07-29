# ADR 0001: Privacy-preserving transcript normalization

Status: **research draft; not accepted for production**

Issue: #36

## Decision

Keep the consent-based v1 publication path unchanged. For a future v2 path,
prototype zero-knowledge execution of the existing Rust normalizer in a
general-purpose zkVM. Do not ship field-level selective disclosure as proof of
complete canonical normalization.

Selective disclosure remains useful for inspection and debugging, but a
server that sees only selected HTTP/JSON/SSE ranges cannot distinguish an
honest transcript from one with an omitted event, hidden tool call, duplicate
key, or parser-significant delimiter unless it verifies essentially the whole
parser and normalizer. Building that application-specific proof verifier would
duplicate the most fragile part of the product.

This decision is provisional until an implementation proves a cryptographic
bridge from a TLSNotary-authenticated complete transcript commitment into a
zkVM guest and measures the target sizes.

## Required cryptographic statement

The v2 proof must establish:

```text
Given:
  authenticated provider host and connection timestamp
  notary-authenticated commitments to complete sent and received transcripts
  normalizer version
  SHA-256 of canonical trace.otlp.json

There exist:
  complete request and response transcript bytes
  commitment openings/blinders accepted by the notary commitment scheme

Such that:
  the openings match the complete authenticated transcript commitments
  the versioned HTTP/SSE/JSON parser accepts the transcript without ambiguity
  the selected provider adapter normalizes it
  canonical serialization equals the public trace hash
  credential and cookie values are not public inputs
```

The notary signature alone is insufficient if it authenticates only
individually disclosed facts. Completeness requires the proof input to be
cryptographically tied to the entire sent and received transcript lengths and
commitment roots.

## Proposed artifact

New identifier:
`llmnotary.private-normalization-archive/v2`

New media type:
`application/vnd.llmnotary.private-normalization+zip`

Canonical stored ZIP entries:

- `proof-manifest.json`
- `trace.otlp.json`
- `notary-attestation.bin`
- `transcript-commitments.json`
- `normalization-proof.bin`

The archive never contains `.llmbundle`, vault material, raw request/response
files, unfinished prover state, commitment blinders, or provider credentials.

`proof-manifest.json` binds:

- archive and proof format versions
- normalizer, canonicalization, OTel semantic-convention, zkVM guest, and
  notary-attestation versions
- provider name and authenticated host
- notary key ID and authenticated connection timestamp
- sent/received transcript lengths and commitment roots
- trace SHA-256
- proof and attestation SHA-256 values

## Admission algorithm

1. Enforce the ordinary intake job's actual object size and SHA-256.
2. Parse the v2 archive under independent compressed/uncompressed limits.
3. Resolve the notary key ID using the v2 directory lifecycle from #44.
4. Verify the notary attestation over provider identity, timestamp, transcript
   lengths, and the complete commitment roots.
5. Hash and validate canonical `trace.otlp.json`.
6. Verify the zkVM receipt with the exact public inputs from steps 3–5.
7. Reject unsupported guest, normalizer, parser, provider-adapter, or artifact
   versions.
8. Issue the existing platform stamp with an additional provenance identifier
   for private normalization v2.

No admission step parses plaintext request or response bytes.

## Observation matrix

| Party | v1 consent path | proposed v2 path |
| --- | --- | --- |
| Local user | bundle, transcript, trace, proof | same |
| Notary | provider endpoint, TLS protocol metadata, ciphertext, proof protocol | same plus complete transcript commitment roots/lengths |
| Object-store operator | encrypted transport, object size, archive metadata | object size and opaque proof archive |
| Admission API | disclosed request/response, evidence, trace | trace, provider/host, timestamp, lengths, roots, proof metadata |
| Public verifier | trace and platform stamp | same, unless v2 proof is also published |

Transcript lengths and provider timing may themselves be sensitive. The spike
must determine whether lengths can be bucketed or hidden without weakening
completeness or resource limits.

## Completeness and ambiguity requirements

The zkVM guest must reject:

- omitted, reordered, or duplicated SSE events
- a hidden tool call or tool result
- duplicate JSON object keys, even if the host parser would keep one
- trailing non-whitespace bytes and multiple JSON roots
- conflicting content-length and transfer-encoding interpretations
- invalid chunked framing or decompression bombs
- a provider route/model shape unsupported by that normalizer version
- a public trace with one-byte, ordering, or canonicalization changes

[`tests/privacy_binding_completeness.rs`](../../tests/privacy_binding_completeness.rs)
is a non-cryptographic regression harness demonstrating why a naive
fact-disclosure binding fails. It does not satisfy the issue's prototype
acceptance criterion.

## Integration and migration

### Client and #41

- `finalize` continues to create the local v1 package until v2 is explicitly
  selected and supported by the notary.
- Add archive construction for v2 rather than changing v1 bytes.
- Before upload, verify the zkVM receipt locally and check every public input.
- Negotiate supported artifact versions with the API. Never fall back from a
  requested private v2 publication to consent v1 without a new user action.

### Intake and #31

- Preserve the single private presigned object.
- Add the new archive-format allowlist value and format-specific size limit.
- Persist the requested format per job; idempotency cannot change it.
- Retain queued v1 jobs under v1 semantics. No in-place conversion exists.

### Admission and #32

- Dispatch to a new v2 verifier by exact archive format.
- Give zk verification its own bounded worker pool, timeout, memory limit,
  stable rejection codes, and guest verification-key registry.
- Keep v1 consent disclosure and v2 private normalization as distinct public
  provenance values.

### Rollout

1. Benchmark behind an unreleased CLI flag.
2. Deploy admission verification with v2 creation disabled.
3. Publish supported versions and guest verification keys.
4. Enable opt-in v2 creation for one provider adapter.
5. Run parallel v1/v2 fixtures and independent verification.
6. Expand providers only with versioned guest releases.
7. Retire v1 creation, if desired, while retaining historical v1 artifacts and
   their original consent label.

Previously admitted v1 publications never gain the v2 privacy claim.

## Blocking questions for the prototype

- Which TLSNotary commitment/root can a zkVM efficiently open, and does the
  current attestation authenticate the complete transcript lengths?
- Can the vendored normalizer and required HTTP/SSE parser compile into the
  selected guest without behavior drift?
- What are proving time, peak memory, proof size, and verification time at
  10 KiB, 100 KiB, and 1 MiB on ordinary client hardware?
- Does proof generation expose transcript data to a remote prover? The MVP
  must assume local proving unless a separately encrypted/delegated design is
  reviewed.
- How are zkVM guest verification keys rotated and retained alongside notary
  and platform signing-key histories?

Until these are answered with an executable tool-calling OpenAI fixture, this
ADR is research guidance rather than a production commitment.
