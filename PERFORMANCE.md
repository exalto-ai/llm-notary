# Deferred proof-engine evaluation

This note separates measurements from hypotheses.  The measurements describe
the current Proxy-TLS private-proof path; candidate backends are **not** claimed
to have the listed speeds until they are implemented and profiled against the
same workload.

## Trust boundary held constant

The local proxy sees the plaintext HTTP exchange.  The notary only receives the
authenticated encrypted TLS record transcript and the interactive proof needed
to attest to selected transcript ranges.  Any replacement considered here must
preserve that boundary, retain independent verification, and use a versioned
proof format plus a separate cryptographic audit.

Normal LLM captures must retain the complete request and response bodies needed
for the trace, including tool calls and tool results.  Selective disclosure can
be a privacy feature, but it is not treated as the primary latency reduction in
these results.

## Measurement method

- Host: Apple M5 Max, 18 logical CPUs, 128 GiB RAM.
- Command:
  `TLSN_PROFILE_CHUNKED_BODY_COMMIT=1 TLSN_ZK_EPHEMERAL_CHUNK_BYTES=131072 cargo test --release --test proxy_tls_profile profiles_proxy_tls_http_commitment_and_proof -- --ignored --nocapture`.
- Workload: deterministic, in-memory Proxy-TLS core profile with 102,400 bytes
  in each HTTP direction (about 205 KiB of application transcript) and nine
  bounded commitments.  It excludes provider latency, TCP/TLS setup, disk, and
  final attestation signing.
- The current session executor already uses available host parallelism.  Timings
  below are wall-clock times, not isolated CPU-cycle benchmarks; host variance
  is visible in the ranges.
- `/usr/bin/time -l` RSS values for the core harness include both prover and
  verifier in one process. They are useful for trend and headroom checks, but
  must not be interpreted as the standalone notary memory requirement.

Set `TLSN_PROFILE_BYTES` to choose the body size. For the SHA-256 comparison,
run the same command with `TLSN_PROFILE_SHA256_COMMITMENTS=1`. The production
path explicitly pins BLAKE3; the proof records its algorithm identifier for
verification.

The finalization path uses MPZ's `mpz-zk` prover/verifier VM: a circuit-based
ZK protocol with authenticated-wire MACs, QuickSilver consistency checks, and
Ferret correlated OT. The earlier MPC-TLS setup also has a separate
semi-honest garbler/evaluator component. They are distinct engines; the
table below concerns the former, which is the finalization hot path.

## Configurations actually run

| Private-proof configuration | 100 KiB profile wall time | Evidence | Resource/security result | Decision |
| --- | ---: | --- | --- | --- |
| MPZ QuickSilver ZK/RCOT backend; BLAKE3; 128 KiB commitment chunks; 2 KiB plaintext-auth batches; authenticated AES key-schedule reuse | **9.84 s** (n=1) | 9 commitments; 102,400 bytes in each direction; 635 MB peak RSS | Same proof statement and key binding; full suite and tamper tests pass | Adopted: about 8–9% faster |
| Same backend before AES key-schedule reuse | **10.81 s** in a paired baseline run | Same proof layout; 646 MB peak RSS | Historical control | Replaced |
| Same backend; SHA-256 commitments | **14.96 s** in the paired run | Same disclosure/layout; 645 MB peak RSS | Same trust model, but **28% slower** in this paired profile | Reject as default |
| Same backend; BLAKE3; 16 KiB commitment chunks | **10.89 s** in the paired-nearby run | 21 commitments; 2,706-byte proof; 815 MB peak RSS | Same cryptographic claim, but more child proofs and higher resource cost | Reject: no latency win |
| Same backend; 100k-gate QuickSilver check batch (profile only) | **11.09 s** (n=1) | Same proof shape; 658 MB peak RSS | Existing proof statement; more frequent checks | Reject: slower than the 200k default |
| Same backend; 400k-gate QuickSilver check batch (profile only) | **10.52 s** (n=1) | Same proof shape; 1.03 GB peak RSS | Existing proof statement; fewer, larger checks | Reject: exceeds a 1 GiB combined-process budget for an inconclusive speed change |
| Same backend; BLAKE3; 8 KiB plaintext-auth batches | 10.5 s (n=1) | Same workload | At a 1 MiB trial, resident memory exceeded 1.5 GiB | Reject: availability/capacity regression |
| Same backend; BLAKE3; 16 KiB plaintext-auth batches | 10.4 s (n=1) | Same workload | Requires a much larger working set; no safe bounded-memory profile established | Reject: availability/capacity regression |
| Same optimized baseline at 1.2 MB per direction (2.4 MB combined) | **113.7 s** (n=1) | 27 commitments; 3,438-byte proof; 812 MB combined-process peak RSS | Same evidence; 8% faster and lower measured combined-process RSS | Require split-process and concurrency capacity profiles |
| Same configuration before AES key-schedule reuse | **123.5 s** (n=1) | 27 commitments; 3,438-byte proof; 926 MB combined-process peak RSS | Historical control | Replaced |

The large-batch rows are experiments, not proposed defaults.  They show why a
small benchmark-only reduction in wall time is insufficient: bounded memory is
also a denial-of-service control at the notary.

`TLSN_ZK_PROFILE_BATCH_GATES` is a paired-local profiling override for MPZ's
QuickSilver consistency-check batch. It is unset in production, defaults to
200,000 AND gates, and both peers must use the same value. It is included to
make these scheduler measurements reproducible, not as a production tuning
interface.

### Parallelism and safe-batch probes

These are same-host 100 KiB-per-direction runs after the AES key-schedule
change. They are narrow scheduler measurements, so they do not override the
baseline without a split-process/concurrency profile.

| Probe | Proof wall time | Peak combined-process RSS | Result |
| --- | ---: | ---: | --- |
| Rayon forced to 1 worker | 23.18 s | 637 MB | Parallel execution matters: 2.4× slower than the 8-worker result. |
| Rayon forced to 4 workers | 10.92 s | 680 MB | Nearly all useful speedup is already obtained. |
| Rayon forced to 8 workers | **9.64 s** | 682 MB | Best observed current-engine scheduler point. |
| Rayon forced to 16 workers | 9.69 s | 642 MB | No material latency gain; additional CPU use only. |
| 3 KiB auth batches, 8 Rayon workers | 9.23 s | 611 MB | One-run 4% gain; needs large-profile capacity repeat. |
| 4 KiB auth batches, 8 Rayon workers | 9.21 s | 986 MB | One-run 4–5% gain, but too close to a 1 GiB combined-process budget. |

The new `TLSN_ZK_PROFILE_PLAINTEXT_AUTH_BATCH_BYTES` override exists only for
these paired local experiments. It ignores malformed/zero values and defaults
to the existing 2 KiB limit. It is not exposed as a production setting because
both peers must agree and larger batches multiply live circuit/OT memory.

MPZ source inspection explains the curve: the enabled Rayon paths are in the
QuickSilver consistency checks, while the AES-circuit/RCOT work does not have a
drop-in SIMD or bit-sliced executor. Thread tuning can recover a factor of
about 2.4 versus serial execution, but has already saturated by eight workers;
it cannot produce an order-of-magnitude improvement.

### Baseline scaling observations

| HTTP bytes in each direction | Combined authenticated application bytes | Baseline proof wall time | Approximate combined throughput | Confidence |
| ---: | ---: | ---: | ---: | --- |
| 10 KiB | 20 KiB | 1.5 s | 13 KiB/s | one release run |
| 100 KiB | 200 KiB | 9.84 s | 20 KiB/s | optimized release run; earlier baseline 10.8–13.8 s |
| 1 MiB | 2 MiB | about 2 min | about 17 KiB/s | exploratory one release run |
| 1.2 MB | 2.4 MB | 113.7 s | 21 KiB/s | optimized release run; 812 MB combined-process peak RSS |

The roughly linear scaling is evidence that this is an engine-throughput
problem, rather than a fixed connection/setup cost.  It is not enough evidence
to extrapolate a production completion time: an end-to-end profile must include
notary transport, resource contention, and the configured memory limits.

## Where the work is today

In the optimized 102.4 KiB body run, BLAKE3 spent 2.8–3.1 seconds in plaintext
authentication and about 2.0 seconds in streaming hash proof work per
direction. Before key-schedule reuse, authentication was 3.2–3.3 seconds.
SHA-256 kept authentication unchanged but raised hash work to 4.1 seconds.
Child-session binding was about 24–26 ms. The 2 KiB scheduler
therefore executes 51 ZK authentication sub-batches for each 102.4 KiB
body. These samples rule out child-binding micro-optimizations as a material
answer and identify circuit/RCOT execution plus safe batching as the engine
work. The code emits these durations and batch counts without plaintext or
credentials.

### Measured Amdahl ceilings (100 KiB profile)

The two 102.4 KiB body commitments take the dominant part of the 10.83-second
proof time. These are upper bounds, not promised speedups: a replacement still
has integration and transport costs.

| Component removed or made free | Sampled body time | Maximum end-to-end reduction | Implication |
| --- | ---: | ---: | --- |
| Plaintext authentication / AES circuit work | 5.91 s | about 58% | The highest-value equal-trust engine target |
| BLAKE3 hash proof work | 4.04 s | about 40% | Worth optimizing, but cannot alone solve multi-minute bundles |
| Child-key binding | about 0.05 s for the two bodies | under 1% | Do not spend protocol-engine effort here |
| HTTP/header chunks and residual scheduling | about 0.20 s | under 2% | Keep bounded, but it is not the main bottleneck |

## Candidate engine work

| Candidate | Expected latency leverage | Trust/privacy effect if correct | Main tradeoffs and proof needed | Priority |
| --- | --- | --- | --- | --- |
| Pin BLAKE3 commitments | Measured: 24–28% faster than SHA-256 in this profile | Unchanged: algorithm is bound into the verified commitment | Maintain test coverage and compatibility/version policy | Adopted |
| Reuse the authenticated AES key schedule across CTR blocks | Measured: 8% faster at 2.4 MB combined, with lower measured combined RSS | Unchanged: AES-128 is factored into equivalent key-schedule and post-schedule circuits | Keep equivalence and tamper coverage; vendor patch requires review | Adopted |
| Vectorized/bit-sliced QuickSilver circuit execution and AES circuit construction | High: plaintext authentication is the largest sampled phase | Can preserve the current two-party privacy and verifier semantics | Constant-time implementation, vectorized-circuit equivalence tests, cross-platform fallback, external audit | First engine prototype |
| Streaming ZK scheduler that retains safe batches without a 2 KiB execute/flush cadence | High if it retains the 8–16 KiB experiment's latency while capping memory | Can preserve the current proof statement | Explicit working-set budget, circuit/RCOT backpressure, cancellation/DoS tests, audit of state lifetime | First engine prototype |
| RCOT/Ferret precomputation or better extension batching | Medium only if added traces show RCOT setup/round trips dominate | Potentially unchanged, but lifecycle and binding must prevent cross-session misuse | Instrument OT bytes/messages and checks; strict session binding, erasure/lifetime rules, replay tests, formal protocol review | Investigate after instrumentation |
| Work-conserving outer parallelism with a global CPU/memory budget | Latency reduction only; no total-work reduction | Unchanged when sessions stay isolated | Current executor already consumes host parallelism; avoid oversubscription and memory multiplication | Scheduler experiment, not default |
| GPU evaluation for AES/GC/OT kernels | Unknown; may help very large batches | The cryptographic claim can remain, but deployment/hardware assumptions become harder | Device-memory exposure, kernel side channels, transfer overhead, reproducibility, GPU-specific audit | Research only |
| Receipt-bound transparent ZK proof (Plonky3-class hiding FRI PCS with a custom AIR) for the current key binding, AES-CTR, and BLAKE3 relation | Only credible non-parallel path to a possible order-of-magnitude change; **full statement unmeasured**. A hiding-FRI LogUp control proved 33.55M private AES S-box mappings in 4.92 s / 10.31 GB; a BLAKE3-permutation control used 5.22 s / 11.08 GB at 32,768 permutations. | Can preserve privacy: the proof witness is the traffic keys/plaintext, while the notary sees only its signed receipt, ciphertext digest, and proof | Controls omit AES round/key/counter wiring and all receipt/hash binding. A naive composition already exceeds the current memory target; new proof format/verifier, proof-size economics, and an independent audit remain mandatory. | Build a fixed receipt-bound AES-CTR record AIR against the mutation-tested reference fixture, then an exact BLAKE3 construction; see `ZK_BACKEND_FEASIBILITY.md` |
| Replace the full 2PC/ZK backend | Potentially high, but unmeasured | Only preserves the product claim after proving equivalent privacy, soundness, and verification semantics | Versioned capture/proof format, transcript compatibility, independent audit, migration verifier, new DoS limits | Separate project |

TLSNotary already moved transcript commitments to BLAKE3 specifically for a
faster, parallelizable commitment primitive.  That supports keeping BLAKE3 as
the baseline, not treating a hash swap as a replacement for the 2PC engine.

The exact receipt-bound statement, candidate assumptions, mutation tests, and
go/no-go benchmark for a transparent replacement are specified in
[`ZK_BACKEND_FEASIBILITY.md`](ZK_BACKEND_FEASIBILITY.md). It starts with a
specialized **zero-knowledge** transparent-STARK reference implementation; a
transparent integrity proof without audited witness masking is not sufficient.
It does not count a generic zkVM or a Groth16-compressed receipt as an
equal-assumption result.

### Designs excluded from the equal-trust comparison

| Design | Why it is not an equal-assumption speedup |
| --- | --- |
| Single-notary trusted execution environment | Replaces the cryptographic privacy boundary with hardware, operator, and vendor trust assumptions. |
| Two independent notaries that split the transcript | Adds a non-collusion and availability assumption, plus a new distributed protocol. |
| Reveal the transcript to the notary or omit tool exchanges | Violates the private-capture product boundary and/or loses trace evidence. |
| Cache reusable proof randomness without binding and erasure rules | Risks cross-session correlation or replay; it is not safe simply because it benchmarks faster. |

## Benchmark gate for each prototype

Before comparing backends, record the following for client and notary
separately at 20 KiB, 200 KiB, 2 MiB, and 2.4 MiB combined application
transcript sizes:

1. Wall time for AES/plaintext authentication, hash proof, RCOT/Ferret setup
   and extension, QuickSilver execution/checks, transport, and attestation.
2. CPU time, peak resident memory, total network bytes, protocol message count,
   and per-chunk gate, authentication-sub-batch, and check counts.
3. Verified output equivalence: same committed ranges, redactions, capture
   hashes, selective-disclosure result, and rejection behavior for tampering.
4. Capacity behavior under concurrent finalizations, with the configured memory
   limit enforced.

A candidate is not ready merely because it wins the in-memory 100 KiB test. It
must meet the bounded-memory concurrent profile, preserve all verifier checks,
and receive an audit appropriate to the amount of cryptographic code changed.

### Split-process status

The repository's split profile now sends the production capture-session
prelude, but its TLS echo fixture is signed by a private test CA. A production
`certified-notary` correctly rejects that CA, so it cannot be used as the
split-profile notary. The remaining capacity measurement requires a dedicated
test-only notary binary/configuration that trusts only the fixture CA; it must
not add that CA to production roots. This is a test-harness gap, not evidence
that the production notary can safely run the 2.4 MB profile within 1 GiB.
