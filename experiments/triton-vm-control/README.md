# Triton VM control

This isolated program measures a **lower bound** for a transparent generic
zkVM: a proof over a sequence of private elements with one public accumulator.
It is not, and must never be represented as, a TLS or LLM Notary proof.

It omits AES-CTR, the SHA-256 root binding, canonical TLS records, BLAKE3
commitments, and the signed receipt. It therefore has less work than the
required statement; a full guest will be slower and larger. Its value is to
measure generic VM proof overhead and validate private-input/journal behavior.

Run a release profile, for example:

```sh
TRITON_CONTROL_ELEMENTS=2048 cargo run --release
```

The only public output is the accumulator. The deterministic synthetic witness
contains no capture material, traffic key, credential, plaintext, or tool data.
