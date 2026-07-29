# Receipt-bound reference statement

This crate is a deterministic, synthetic reference evaluator for the first
custom-ZK backend fixture. It intentionally does **not** prove anything and is
not linked into the product. It fixes the relations that a replacement proof
must enforce before performance claims are meaningful:

- the existing salted TLS traffic-key root binding;
- the existing canonical deferred-record digest;
- AES-128-CTR using the current four-byte static IV, eight-byte public record
  nonce, and TLSN's counter-one convention; and
- current BLAKE3 transcript commitments, `BLAKE3(plaintext || blinder)`.

All input bytes are synthetic test data. The public journal contains only the
root binding, encrypted records, record digest, commitment identifiers, and
commitments. Keys, plaintext, and blinders remain witness-only. The test suite
mutates every binding edge so a future AIR can use the same vectors and failure
oracle without accidentally proving a weaker statement.

This initial fixture uses one whole-record commitment per direction. The
production backend must extend it to the exact versioned range layout used by
the capture while preserving these equations.
