# Spartan2 ZK SHA-256 control

This isolated experiment proves that the prover knows a private 1 KiB SHA-256
preimage matching a public digest, using Spartan2's `SpartanZkSNARK` path.

It is not the LLM Notary proof statement and has no receipt, TLS record,
AES-CTR, key-binding, BLAKE3, or selective-disclosure semantics. Spartan2's
curve-based commitment assumptions are also a different security basis from a
transparent STARK. Use its result only to estimate the tradeoff of accepting
that changed basis; it is not an equal-assumption replacement.
