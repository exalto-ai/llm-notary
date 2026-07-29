# Receipt-bound ZK backend feasibility

This is a design and benchmark gate for a replacement of the deferred
two-party proof engine. It is deliberately not an implementation promise or a
claim that a STARK is faster: no candidate has yet proved the full LLM Notary
statement.

## Goal and non-goals

The goal is a substantially faster *local* proof that preserves the existing
privacy boundary. The proxy remains the only party with plaintext HTTP,
credentials, tool calls, and tool results. The notary receives neither those
values nor a reusable traffic key. It issues a receipt over its authenticated
TLS session; a third party can independently verify the resulting evidence.

This effort must not substitute a trusted execution environment, a second
non-colluding notary, transcript disclosure, a ceremony, a remote proving
service, or a GPU operated by another party. Those are different products with
additional trust or privacy assumptions.

## The exact replacement statement

The current child proof binds a private TLS key opening to the root MPC-TLS
session by checking:

```
root_binding = SHA256(
  "llm-notary/ephemeral-key-binding/v1" ||
  client_write_key || client_write_iv ||
  server_write_key || server_write_iv || salt
)
```

The salt and the AES traffic keys are witness values. `root_binding` is public
and comes from the root protocol/receipt. The replacement must additionally
show, for each canonical TLS application record in both directions, that:

1. the provided key and IV produce its TLS 1.3 AES-CTR keystream for the
   record sequence number and nonce construction;
2. XOR with the authenticated ciphertext produces the witness plaintext;
3. the exact, versioned transcript-range encoding yields the public BLAKE3
   commitment(s), including their algorithm identifier and blinders;
4. the canonical encrypted-record digest in the signed receipt matches the
   records used by the proof; and
5. the receipt signature and provider/hostname policy are verified outside or
   inside the proof by a versioned verifier.

The public journal must contain only identifiers and cryptographic values such
as a protocol version, receipt/root binding, encrypted-record digest, selected
range metadata, commitment algorithm, and commitments. It must **not** contain
plaintext, credentials, tool traces, TLS traffic keys, or a plaintext-derived
debug value.

Making only the BLAKE3 digest public is insufficient: without constraints
linking all input ciphertext records to the traffic-key opening, it would not
attest to a provider TLS exchange. Likewise, a generic proof that a client
knows a transcript is insufficient without this receipt binding.

## Candidate matrix

| Candidate | Equal trust/privacy? | Expected position | Decision |
| --- | --- | --- | --- |
| Current MPZ 2PC/ZK (QuickSilver + Ferret RCOT) | Yes | Measured 9.84 s at 200 KiB combined; 113.7 s at 2.4 MB combined | Baseline |
| Custom **zero-knowledge** transparent STARK AIR (Plonky3-class hiding FRI PCS) | Yes, if it uses audited trace masking, parameters target the existing security level, and proving stays local | ZK controls pass the basic resource/API gate; the complete TLS statement remains unmeasured | **First feasibility prototype** |
| Generic transparent ZK-STARK VM (Triton VM class) | Potentially: only with documented trace randomization, local proving, and an adequate configured security level | Lower engineering start-up cost; likely substantially less efficient than a specialized AES/BLAKE AIR | **Second, measured comparator** after the custom statement is fixed |
| Generic transparent ZK-STARK VM (Miden class) | Potentially, but its API/version and receipt semantics must be fixed and audited | Another useful VM comparison, with the same software-crypto overhead risk | Research only; do not build against an unstable release |
| Recursive zkVM receipt with Groth16 compression | No under the strict comparison: adds a pairing/curve and setup-dependent layer | May be convenient or fast | Do not use as an equal-trust production candidate |
| Plonk/Halo2 lookup circuit | Not automatically; common deployments add a structured/universal setup and curve assumptions | AES lookups could be attractive | Explore only if the project explicitly accepts those assumptions |
| Transparent lookup STARK | Potentially yes | Promising specialized follow-on if the first AIR shows AES is dominant | Research after a reference AIR exists |
| GPU prover on the user's own machine | The proof claim can remain, but device-memory and side-channel posture must be assessed | May improve large proofs; does not reduce work or make a remote prover private | Optional local-only benchmark after CPU reference |
| Spartan2 ZK R1CS/Hyrax | Privacy-preserving and does not require a ceremony, but changes to curve-based commitment assumptions | Very fast SHA-256 circuit control, but prohibitive local memory | Rejected for bounded-memory use; retain only as changed-assumption data |

Winterfell is a suitable *reference category*, not a selected dependency. Its
[documentation](https://docs.rs/winterfell/latest/winterfell/) describes a
transparent STARK prover/verifier with no initial trusted setup, a hand-authored
AIR and trace, concurrent proving, and highly workload-dependent proof
size/timing. It does **not**, by that description alone, establish that the
trace is zero-knowledge. A bare AIR/trace implementation must not be used for
this product unless an audited trace-masking/zero-knowledge construction is
part of the backend. That is exactly why a measured specialized proof is
required before making performance claims.

RISC Zero is a useful generic-zkVM comparison, not the first production path.
Its [public repository](https://github.com/risc0/risc0) describes a STARK-based
RISC-V platform, but its default receipt construction includes a Groth16 layer
and states 98 bits of conjectured security at its default parameters. It cannot
be counted as an assumption-preserving result until a pure transparent receipt
mode, security parameters, artifact format, and independent verifier are
established.

Triton VM is the better generic-zkVM comparator for the strict lane: its
[published source documentation](https://docs.rs/triton-vm/latest/triton_vm/)
describes trace randomizers as integral to its zk-STARK construction and
exposes an explicit security-level parameter. The experiment must prove the
actual receipt-bound statement and measure memory, not simply compile the
current Rust code into a VM. The likely cost is a much wider/longer trace for
software AES, SHA-256, and BLAKE3 than in a specialized AIR.

### Triton lower-bound result (not a TLS proof)

An isolated `experiments/triton-vm-control` program was run on the same M5 Max.
It proves only a public accumulator over private elements with Triton's default
160-bit STARK configuration. It intentionally omits AES-CTR, SHA-256, BLAKE3,
canonical records, range encoding, and receipt binding. Thus it is a lower
bound for generic-VM cost, not an evidence-compatible backend result.

| Private byte-valued elements | Prove | Verify | Serialized proof | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 128 | 113 ms | 6 ms | 638 KB | 145 MB |
| 512 | 367 ms | 7 ms | 722 KB | 511 MB |
| 1,024 | 686 ms | 8 ms | 772 KB | 1.02 GB |
| 2,048 | about 1.4–1.5 s | 9 ms | about 0.81–0.82 MB | 2.00 GB |

The lower bound exhausts a 1 GiB process budget at only 1,024 logical witness
bytes. A full 16 KiB statement is therefore not a responsible local run, and
the generic Triton control is rejected as a near-term LLM Notary backend. It
does validate the expected private-input/journal behavior and fast verification;
the blocker is prover memory, before the real cryptographic workload begins.

Miden's [design documentation](https://docs.miden.xyz/design/) describes a
STARK-based VM optimized for zero-knowledge proving. It is worth watching, but
is a less direct initial experiment: its versioned VM/program model and
evidence-journal semantics must be pinned before it could be compared fairly.

### Additional library screen

| Library / path | Result | Decision |
| --- | --- | --- |
| Miden VM 0.23.5 | Its available prover hard-codes the convenience/production option to about 96 bits; current 0.25.8 requires Rust 1.96.1, newer than this host's 1.95.0 toolchain. | Not an equal-security experiment on this host. Revisit only after pinning a >=128-bit release and verifier. |
| Maat 0.19 | It labels itself a ZK STARK, but documents its production parameters as about 97 conjectural bits. | Exclude from the strict lane. |
| STWO 2.3 core | SIMD/Circle-STARK core is attractive for a custom AIR, but a source/API screen found no documented ZK trace-hiding construction in the core crate. | Do not build a private-capture proof on it without a reviewed masking construction. |
| STWO `privacy-prove` 1.3.1 | This separate Cairo-specific package does call `add_zk_blinding`, but it proves a Cairo PIE through a fixed privacy bootloader and circuit-verifier stack; its public result also carries an `output_preimage` value. | Not a drop-in custom-AIR backend. It needs a distinct statement/privacy review and a compatible guest before any performance result would be meaningful. |
| ObelyZK `stwo-gpu` 2.0 | It advertises GPU acceleration, but is an external STWO fork and does not supply the missing private-trace construction for our statement. | Keep as a local-hardware acceleration research item only after a vetted ZK STWO/Cairo statement exists. |
| Plonky3 `p3-uni-stark` 0.6 | Has an explicit hiding FRI PCS and ZK mode. Its `new_benchmark_zk` configuration has `2 * 100 + 16 = 216` conjectured FRI soundness bits before accounting for the chosen field/hash assumptions. An actual hiding-FRI BLAKE3-permutation control ran successfully. | Strongest transparent custom-AIR substrate found. It has a maintained BLAKE3-permutation AIR, but no AES-CTR, SHA-256 key-binding, or receipt-binding AIR. |
| Spartan2 0.9 `SpartanZkSNARK` | Actual ZK 1 KiB private-SHA-256-to-public-digest control: 427 ms setup, 12 ms prep, **171 ms prove**, 30 ms verify, 92,520-byte proof, **1.75 GB RSS**. | Reject for this bounded-memory deployment; also a changed curve-based security basis. |

The Spartan2 result is deliberately not compared with the LLM Notary baseline:
it proves only SHA-256, omits the receipt/TLS/AES/BLAKE3 relations, and uses a
different commitment family. Its value is that even this favorable partial
circuit breaches the resource budget, while making the changed-assumption
tradeoff explicit.

The additional STWO screen is important: a SIMD implementation does not by
itself solve the private-witness problem. The raw 2.3 core is useful
performance technology, but its source does not expose a generic masking API.
The separate `privacy-prove` package demonstrates that its wider Cairo stack
has a blinding layer, yet it is a fixed Cairo/recursive-verifier product rather
than a reusable STARK PCS. Its `PrivacyProofOutput` intentionally includes an
`output_preimage`; using it for LLM Notary would require a new output format
that never serializes plaintext-derived values. It is therefore not safe to
benchmark it as though it were an interchangeable backend.

### Plonky3 hiding-FRI controls (not a TLS proof)

`experiments/plonky3-zk-control` uses `HidingFriPcs` and
`MerkleTreeHidingMmcs`, rather than an integrity-only STARK. Its provisional
`new_benchmark_zk` FRI parameters report 216 conjectured FRI soundness bits.
That number is not a complete system-security claim: the field, hash,
constraint system, public-input binding, and verifier all still need an
independent review.

The synthetic multiplication control establishes that the explicit ZK API has
modest resource use. The more representative `p3-blake3-air` control proves
private BLAKE3 **permutations** (not a complete BLAKE3 hash/tree commitment)
using the upstream generated trace. Its inputs and outputs are private in this
control and it deliberately has no public journal. Timings below are the prove
timer after trace construction; RSS is the whole process on the M5 Max.

| Control | Private trace cells | Prove | Verify | Serialized proof | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| Multiplication, 1,024 rows | 3,072 | 24 ms | 9 ms | 538 KB | 9.3 MB |
| Multiplication, 8,192 rows | 24,576 | 189 ms | 12 ms | 750 KB | 48.2 MB |
| Multiplication, 32,768 rows | 98,304 | 738 ms | 15 ms | 910 KB | 181 MB |
| BLAKE3 permutation, 1 row (serial features) | 9,168 | 21 ms | 89 ms | 4.75 MB | 22.3 MB |
| BLAKE3 permutation, 512 rows (serial features) | 4,694,016 | 793 ms | 89 ms | 5.14 MB | 195 MB |
| BLAKE3 permutation, 4,096 rows (serial features) | 37,552,128 | 6.35 s | 90 ms | 5.34 MB | 1.40 GB |
| BLAKE3 permutation, 4,096 rows (parallel features, 4 workers) | 37,552,128 | 1.76 s | 94 ms | 5.34 MB | 1.40 GB |
| BLAKE3 permutation, 4,096 rows (parallel features, 8 workers) | 37,552,128 | 982 ms | 98 ms | 5.34 MB | 1.42 GB |
| BLAKE3 permutation, 4,096 rows (parallel features, 16 workers) | 37,552,128 | **640 ms** | 96 ms | 5.34 MB | 1.42 GB |
| BLAKE3 permutation, 16,384 rows (parallel features, 16 workers) | 150,208,512 | 2.53 s | 98 ms | 5.49 MB | 5.55 GB |
| BLAKE3 permutation, 32,768 rows (parallel features, 16 workers) | 300,417,024 | 5.22 s | 106 ms | 5.57 MB | 11.08 GB |

The first BLAKE3 runs accidentally used Plonky3's serial fallback: the
parallel feature is opt-in on `p3-dft`, `p3-uni-stark`, and `p3-blake3-air`.
Enabling it yields a genuine 9.9x speedup at 4,096 permutations on 16 workers
without changing the statement, witness visibility, PCS, or FRI parameters.
That is a configuration result, not a product optimization, but it establishes
that a custom backend can exploit local parallel hardware safely.

This is the first equal-trust candidate that clears a real ZK proof at useful
scale. It is still not evidence of a 10x product win. The existing BLAKE3 AIR
is deliberately very wide (9,168 columns per permutation): 32,768
permutations--only 2 MiB worth of 64-byte compression blocks before BLAKE3
tree/finalization details--already consume 11.08 GB. It also doesn't yet
express the actual BLAKE3 hash mode, transcript ranges/blinders, AES-CTR,
SHA-256 root binding, receipt record digest, or public receipt signature. The
next useful engineering unit is therefore a fixed-size, receipt-bound
**AES-CTR record AIR**, followed by a narrower, exact BLAKE3 hash-mode
construction; more generic-VM benchmarking cannot answer the product question.

### Plonky3 lookup-backed AES S-box controls (not AES-CTR)

The normal `p3-uni-stark` API does not itself wire lookup arguments. The
adjacent `p3-batch-stark` layer does: it implements LogUp interactions and can
use the same hiding FRI PCS. `experiments/plonky3-zk-control --bin sbox_lookup`
therefore proves private `(input, AES_SBOX(input))` pairs against a public,
preprocessed FIPS-197 table. The private trace cannot select an alternate
S-box; the batched lookup terminal must balance against the fixed table.

Packing many independent S-box lookups into a trace row is essential. It is
the shape a future unrolled AES round would use, and it has no effect on what
the proof asserts.

| Private S-box queries | Rows × packed lanes | Prove | Verify | Serialized proof | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 256 × 1 | 21 ms | 13 ms | 559 KB | not separately sampled |
| 65,536 | 65,536 × 1 | 293 ms | 19 ms | 1.17 MB | 431 MB |
| 65,536 | 4,096 × 16 | 79 ms | 15 ms | 880 KB | 49.8 MB |
| 1,048,576 | 65,536 × 16 | 424 ms | 21 ms | 1.22 MB | 639 MB |
| 1,048,576 | 16,384 × 64 | 258 ms | 21 ms | 1.19 MB | 373 MB |
| 1,048,576 | 8,192 × 128 | 219 ms | 24 ms | 1.31 MB | 321 MB |
| 4,194,304 | 32,768 × 128 | 775 ms | 26 ms | 1.48 MB | 1.22 GB |
| 16,777,216 | 131,072 × 128 | 2.72 s | 34 ms | 1.66 MB | 4.64 GB |
| 33,554,432 | 262,144 × 128 | 4.92 s | 35 ms | 1.76 MB | 10.31 GB |

AES-128 performs 160 S-box substitutions per encrypted 16-byte counter block.
About 2.4 MiB therefore needs roughly 25.2 million substitutions; the final
row above is the next power-of-two packed control. It establishes that the
lookup layer has a plausible **time** path to a large improvement while
preserving a local, transparent ZK proof. It also establishes a large
**memory** requirement before adding AES key expansion, AddRoundKey,
ShiftRows, MixColumns, counter construction, ciphertext XOR, receipt binding,
or the separate BLAKE3 relation. It must not be compared directly to the
current end-to-end private proof.

The immediate implementation target is now narrow and testable: one fixed
AES-128-CTR record AIR which constrains all ten rounds, reuses one private key
schedule over its public counter blocks, and ties its plaintext/ciphertext to
the synthetic receipt-bound reference fixture. Only after its mutation tests
pass should it be combined with BLAKE3 and the root-binding circuit.

## Phased feasibility prototype

### Phase 0 — frozen statement and vectors

Produce deterministic test vectors from the existing capture format for 16 KiB
in one direction. Include ciphertext records, sequence mapping, the receipt
binding/digest, private keys/salt only in local fixture data, canonical ranges,
and expected BLAKE3 commitments. The verifier fixture must reject each of:

- one changed ciphertext byte;
- a key/IV from another capture;
- a changed salt or root binding;
- a reordered record or changed sequence number;
- an altered range, commitment algorithm, blinder, or commitment; and
- a receipt whose record digest/signature does not match the supplied records.

This phase does not introduce a new runtime dependency. It makes it possible
to test any backend against one statement instead of measuring incomparable
toy AES circuits.

The first piece now exists as
`experiments/receipt-bound-reference`. It is an isolated, synthetic reference
evaluator with mutation tests for the exact current root-binding domain and
field order, canonical deferred-record digest, AES-128-CTR nonce/counter
convention, and `BLAKE3(plaintext || blinder)` commitment. It never serializes
its artificial witness values and is not a production dependency or a proof.
It currently covers one whole-record commitment per direction; completing
Phase 0 still requires the exact production range layout and a 16 KiB
multi-record vector.

The existing disconnected-finalization test already supplies the initial
semantic mutation oracle: it verifies a signed receipt, rejects a changed
encrypted record through its digest, and reaches the fresh proof before
rejecting a changed client traffic key. It uses an in-memory fixture and does
not export a sensitive checkpoint. A deterministic 16 KiB vector with the
complete range/blinder form remains the first implementation task for a custom
ZK-STARK, rather than something a generic VM benchmark can substitute.

### Phase 1 — zero-knowledge transparent reference proof

Implement a versioned experimental proof format and independent verifier for
the 16 KiB fixture. Keep all witness material local and make only the journal
above public. The backend must include an explicit, reviewed zero-knowledge
trace-masking construction; a transparent integrity proof alone is rejected.
Prefer a small custom AIR to an entire HTTP parser or a general RISC-V guest.
The first version may prove one fixed-size range, but it may not weaken the
receipt/key/ciphertext linkage.

Parameter selection must explicitly state target soundness, hash function,
field, FRI configuration, maximum trace length, proof-size limit, and verifier
resource limits. Do not use library example parameters (which can target only
about 96 bits) as production parameters.

### Phase 2 — equivalence and scale

Add both directions, the actual range/blinder encoding, and 20 KiB, 200 KiB,
2 MiB, and 2.4 MiB profiles. At every size, compare against the existing
backend using the same encrypted records and evidence output. Record:

- client prove wall/CPU time and peak RSS;
- notary/receipt work separately (the replacement should not disclose witness
  material to it);
- proof bytes, public journal bytes, verifier time/RSS, and network bytes;
- rejection behavior for all Phase 0 mutations; and
- concurrent-finalization behavior under the deployed memory limit.

### Phase 2b — generic-VM control

Implement the same fixed 16 KiB statement in a Triton VM guest with private
input and the identical minimal journal. Do not include HTTP parsing, provider
I/O, or receipt signing in the guest. This is a calibration control: it tests
the practical price of a generic VM versus the specialized AIR while holding
the product statement constant. Advance it to the full size matrix only if the
16 KiB proof preserves the mutation behavior and is within a defensible
multiple of the specialized reference's time and memory.

### Phase 3 — adversarial review gate

Before any production capture can use the new artifact, require a separate
verifier implementation or review, protocol-version migration rules, fuzzing
of record/range parsing, bounded allocations, no plaintext logging, and an
independent cryptographic audit. Existing artifacts must continue to verify
under their original verifier.

## Decision criteria

The prototype has earned continued engineering only if it verifies every
mutation case, keeps the journal non-sensitive, has an explicitly documented
transparent parameter set with a security target at least as strong as the
current product policy, and at 200 KiB shows a convincing path to materially
better **end-to-end** latency without exceeding the current bounded-memory
profile. A large speedup on a standalone AES benchmark, or a proof with an
unreviewed/new trust assumption, does not meet this bar.

If the reference STARK misses this gate, the next equal-trust work should be
inside the current engine: vectorized/bit-sliced authenticated AES,
memory-bounded larger ZK execution batches, and RCOT instrumentation and
precomputation with strict per-session binding and erasure rules. Those target
the measured 58% AES/authentication and 40% BLAKE3 proof phases without
changing the evidence protocol.
