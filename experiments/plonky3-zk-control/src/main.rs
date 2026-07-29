//! Plonky3 hiding-FRI control using production-like ZK FRI parameters.
//!
//! This proves a private trace of `a * b = c` rows. It is a resource check for
//! the ZK PCS/AIR substrate only: it does not implement TLS, AES-CTR, SHA-256,
//! BLAKE3, range commitments, or the signed receipt relation required by LLM
//! Notary.

use std::{env, time::Instant};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::{SeedableRng, rngs::SmallRng};

const WIDTH: usize = 3;
const DEFAULT_ROWS: usize = 1 << 10;

fn rows() -> usize {
    let rows = env::var("P3_CONTROL_ROWS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .expect("P3_CONTROL_ROWS must be a positive power of two")
        .unwrap_or(DEFAULT_ROWS);
    assert!(
        rows.is_power_of_two() && rows > 0,
        "P3_CONTROL_ROWS must be a positive power of two"
    );
    rows
}

#[derive(Clone, Copy, Debug)]
struct MulAir;

impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        builder.assert_zero(row[0] * row[1] - row[2]);
    }
}

fn main() {
    let rows = rows();
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Perm = Poseidon2BabyBear<16>;
    type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
    type ValMmcs = MerkleTreeHidingMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        Hash,
        Compress,
        SmallRng,
        2,
        8,
        4,
    >;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
    type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
    type Config = StarkConfig<Pcs, Challenge, Challenger>;

    let mut rng = SmallRng::seed_from_u64(7);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let value_mmcs = ValMmcs::new(hash, compress, 0, rng);
    let challenge_mmcs = ChallengeMmcs::new(value_mmcs.clone());
    let fri = FriParameters::new_benchmark_zk(challenge_mmcs);
    let soundness_bits = fri.conjectured_soundness_bits();
    assert_eq!(soundness_bits, 216);
    let pcs = Pcs::new(
        Dft::default(),
        value_mmcs,
        fri,
        4,
        SmallRng::seed_from_u64(9),
    );
    let config = Config::new(pcs, Challenger::new(perm));
    let air = MulAir;

    let mut values = Vec::with_capacity(rows * WIDTH);
    for row in 0..rows {
        let a = Val::from_u32((row as u32 % 251) + 1);
        let b = Val::from_u32(((row as u32 * 17) % 251) + 1);
        values.extend([a, b, a * b]);
    }
    let trace = RowMajorMatrix::new(values, WIDTH);

    let prove_start = Instant::now();
    let proof = prove(&config, &air, trace, &[]);
    let prove_elapsed = prove_start.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof)
        .expect("proof must serialize")
        .len();

    let verify_start = Instant::now();
    verify(&config, &air, &proof, &[]).expect("proof must verify");
    let verify_elapsed = verify_start.elapsed();
    println!(
        "rows={rows} private_trace_cells={} zk_fri_soundness_bits={} prove_ms={} verify_ms={} proof_bytes={proof_bytes}",
        rows * WIDTH,
        soundness_bits,
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis(),
    );
}
