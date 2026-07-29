# Plonky3 hiding-FRI control

This isolated program proves a private 1,024-row multiplication trace using
Plonky3's hiding FRI PCS and its benchmark ZK parameters (216 conjectured FRI
soundness bits). It validates the transparent ZK substrate and records resource
use; the trace has no public output.

`cargo run --release --bin blake3` additionally proves the maintained
`p3-blake3-air` BLAKE3 *permutation* trace under the same PCS. This is a more
representative constraint-system control, but still does not bind a transcript
digest or prove the full BLAKE3 hash/tree construction.

`cargo run --release --bin sbox_lookup` proves private AES S-box
input/output pairs against a public FIPS-197 S-box table using the
lookup-capable `p3-batch-stark` layer and the same hiding FRI PCS. Set
`P3_SBOX_ROWS` and `P3_SBOX_LANES` to explore packing. It is a real private
AES primitive, not an AES round, AES-CTR relation, traffic-key binding, or
receipt proof.

It is not an LLM Notary proof. A real backend must implement and audit the
receipt-bound AES-CTR, SHA-256 key-binding, BLAKE3 commitment, range, and
versioned-verifier relations.
