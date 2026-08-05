# Artifact formats and verification

LLM Notary uses three artifacts with different privacy and trust properties.
Do not describe them interchangeably.

| Artifact | Location | Contains proof? | Shareable? |
| --- | --- | --- | --- |
| `.llmcapture` | local vault-backed storage | no, deferred private state | no |
| `.llmtrace` | local finalized storage | yes, with an external trusted key | only after reviewing disclosed bodies |
| Public `trace.otlp.json` | hosted Library | no portable evidence | yes, for inspection |

## Encrypted deferred capture

Format: `llm-notary/deferred-bundle/v1` inside vault encryption.

The capture contains the client checkpoint and signed receipt required to
complete private proof generation later. That checkpoint can reconstruct the
original request, including credentials and cookie values. The file is
therefore more sensitive than the finalized package.

A successful vault decrypt or capture parse proves only local structural
usability. It does not authenticate the provider response to another party.
Never upload, publish, or log a `.llmcapture`.

Existing `.llmbundle` files remain readable as legacy private captures. New
captures use `.llmcapture`; renaming does not change the encrypted bytes or
make either extension safe to share.

## Finalized trace package

The `.llmtrace` extension names one deterministic ZIP archive. Its archive
format is `llmnotary.trace-package-archive/v2`, its verified-package manifest
format is `llm-notary/verified-trace-package/v2`, and its media type is
`application/vnd.llmnotary.trace-package+zip`.

The archive contains exactly six entries in this order:

```text
archive-manifest.json
evidence.tlsn
manifest.json
request.disclosed.http
response.disclosed.http
trace.otlp.json
```

No directory, symlink, duplicate, extra entry, absolute path, parent traversal,
archive comment, prepended byte, or trailing byte is accepted. Every entry is
stored without compression, with mode `0644` and the fixed DOS timestamp
`1980-01-01T00:00:00`. Validation reconstructs the complete ZIP and requires
byte-for-byte equality.

The five package entries are limited to 128 MiB uncompressed in total. The
wire ceiling adds a 64 KiB archive-manifest allowance and 16 KiB of ZIP
container overhead.

## Entry responsibilities

### `archive-manifest.json`

Declares the archive and verified-package formats, the ordered path, size, and
SHA-256 of every package entry, and `package_sha256`. The package digest covers
compact JSON containing the verified-package format and ordered file
declarations; it is independent of ZIP metadata. A separate outer SHA-256
binds the complete archive during share intake.

### `evidence.tlsn`

Contains the serialized TLSNotary presentation, notary signature, provider TLS
identity binding, and selective-disclosure proof. It is the cryptographic
evidence, not a human-readable receipt.

### `manifest.json`

Uses `llm-notary/verified-trace-package/v2`. It records the source capture
identifier, authenticated provider and host, authenticated provider-connection
time, embedded notary key, source-artifact hashes, normalizer version, and
trace SHA-256. The embedded key is not trusted merely because it appears here.

### `request.disclosed.http`

Contains the authenticated request line, header names, structural delimiters,
and body. Every header value is replaced by undisclosed bytes except an exact,
case-insensitive `Transfer-Encoding: chunked` value. The complete request body
remains visible and can include system instructions, tool definitions,
messages, and tool results.

### `response.disclosed.http`

Contains the authenticated final provider response and body, including SSE
events. It follows the same header-value policy. The body can include model
output, usage, finish reasons, and tool calls.

### `trace.otlp.json`

Contains canonical UTF-8 JSON in `llm-notary/otlp-trace/v1`. Object keys are
sorted by UTF-8 byte order, arrays retain input order, scalar values use compact
JSON encoding, and the file ends in exactly one LF. This rule is identified as
`llm-notary/json-lexicographic-v1`; it is intentionally not described as RFC
8785.

## Canonical trace shape

The trace is a minimal OTLP JSON `resourceSpans` payload. It has one resource
and instrumentation scope and one or more ordered `gen_ai.inference` client
spans. The resource identifies:

- `llmnotary.format = llm-notary/otlp-trace/v1`
- `llmnotary.normalizer.version = llm-notary/normalizer/v1`
- `otel.semconv.version = 1.37.0`
- `service.name = llm-notary`

Supported span attributes are:

- required `gen_ai.provider.name`, `gen_ai.operation.name`, and
  `gen_ai.request.model`;
- optional `gen_ai.response.model`;
- optional non-negative `gen_ai.usage.input_tokens` and
  `gen_ai.usage.output_tokens`, encoded as OTLP JSON integer strings;
- optional canonical JSON strings in `gen_ai.input.messages` and
  `gen_ai.output.messages`;
- optional `gen_ai.response.finish_reasons`, `gen_ai.conversation.id`, and
  `server.address`.

A model-emitted tool call is provider-authenticated output. A tool result in a
later request is authenticated only as input supplied by the client. The trace
does not claim that a local runtime executed the tool.

## Local verification

Verify a cataloged capture through the daemon:

```bash
llm-notary traces verify cap-example
```

Verify a portable file without the daemon:

```bash
llm-notary traces verify ./cap-example.llmtrace
```

Path-based verification selects a key from the locally cached hosted directory
by default. For an explicit self-hosted trust anchor:

```bash
llm-notary traces verify ./cap-example.llmtrace \
  --trusted-notary-key 02...
```

Full verification checks canonical archive bytes, entry hashes, trust-key
selection, TLSNotary evidence, provider identity, selective disclosure,
header-value privacy, manifest hashes, and exact trace reproduction.

## Hosted verification and sharing

`POST /api/verify` accepts one `.llmtrace` and performs the same core
verification without creating an account, share, or content record. The
service processes the package without durable retention. Its response is not
signed, so it is not a portable receipt.

Sharing is separate. The platform safety-scans and cryptographically verifies
the uploaded source package, stores its canonical trace and the exact admitted
`.llmtrace`, then re-downloads and repeats the checks before admission. The
stable share page links the retained package so a recipient can verify it
independently.

## Compatibility rule

Artifact formats are versioned together. A change to capture metadata,
disclosure policy, archive layout, normalization, trust selection, or
verification must update its producers, consumers, fixtures, tests, and
documentation in the same change. Never weaken a verifier while leaving an old
format identifier in place.
