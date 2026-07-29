//! Hiding-FRI control for an actual AES S-box lookup argument.
//!
//! The private query trace contains AES S-box input/output pairs. A separate,
//! public preprocessed table contains all 256 canonical S-box entries; the
//! batch-STARK LogUp argument binds the private pairs to that table. This is a
//! real AES primitive, but not an AES round, AES-CTR proof, TLS record proof,
//! or receipt-bound LLM Notary proof.

use std::{env, time::Instant};

use p3_air::{Air, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_batch_stark::{ProverData, StarkInstance, prove_batch, verify_batch};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_lookup::{Count, InteractionBuilder, LookupBus};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::{SeedableRng, rngs::SmallRng};

const DEFAULT_ROWS: usize = 256;
const DEFAULT_LANES: usize = 1;
const SBOX_BUS: LookupBus<'static> = LookupBus::new("aes-sbox");

// FIPS-197 AES S-box. Keeping this data in the AIR's public preprocessed table
// prevents a prover from choosing an arbitrary input/output mapping.
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn rows() -> usize {
    let rows = env::var("P3_SBOX_ROWS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .expect("P3_SBOX_ROWS must be a positive power of two")
        .unwrap_or(DEFAULT_ROWS);
    assert!(
        rows.is_power_of_two() && rows > 0,
        "P3_SBOX_ROWS must be a positive power of two"
    );
    rows
}

fn lanes() -> usize {
    let lanes = env::var("P3_SBOX_LANES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .expect("P3_SBOX_LANES must be a positive power of two")
        .unwrap_or(DEFAULT_LANES);
    assert!(
        lanes.is_power_of_two() && lanes > 0,
        "P3_SBOX_LANES must be a positive power of two"
    );
    lanes
}

#[derive(Clone, Copy)]
enum SboxAir {
    Query { lanes: usize },
    Table,
}

impl<F: PrimeCharacteristicRing + Send + Sync> BaseAir<F> for SboxAir {
    fn width(&self) -> usize {
        match self {
            Self::Query { lanes } => lanes * 2,
            Self::Table => 1,
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Query { .. } => None,
            Self::Table => {
                let mut values = F::zero_vec(256 * 2);
                for (index, output) in AES_SBOX.iter().copied().enumerate() {
                    values[index * 2] = F::from_u8(index as u8);
                    values[index * 2 + 1] = F::from_u8(output);
                }
                Some(RowMajorMatrix::new(values, 2))
            }
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Query { .. } => 0,
            Self::Table => 2,
        }
    }
}

impl<AB: PermutationAirBuilder + InteractionBuilder> Air<AB> for SboxAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Query { lanes } => {
                let main = builder.main();
                let row = main.current_slice();
                for lane in 0..*lanes {
                    SBOX_BUS.lookup_key(
                        builder,
                        [row[lane * 2].into(), row[lane * 2 + 1].into()],
                        Count::bounded(AB::Expr::ONE, 1),
                    );
                }
            }
            Self::Table => {
                let count = builder.main().current(0).unwrap();
                let input = builder.preprocessed().current(0).unwrap();
                let output = builder.preprocessed().current(1).unwrap();
                SBOX_BUS.table_entry(builder, [input.into(), output.into()], count);
            }
        }
    }
}

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

fn config() -> Config {
    let mut rng = SmallRng::seed_from_u64(7);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let value_mmcs = ValMmcs::new(hash, compress, 0, rng.clone());
    let challenge_mmcs = ChallengeMmcs::new(value_mmcs.clone());
    let fri = FriParameters::new_benchmark_zk(challenge_mmcs);
    assert_eq!(fri.conjectured_soundness_bits(), 216);
    let pcs = Pcs::new(Dft::default(), value_mmcs, fri, 4, rng);
    Config::new(pcs, Challenger::new(perm))
}

fn query_trace(rows: usize, lanes: usize) -> (RowMajorMatrix<Val>, [u32; 256]) {
    let mut counts = [0u32; 256];
    let mut values = Vec::with_capacity(rows * lanes * 2);
    for row in 0..rows {
        for lane in 0..lanes {
            let input = ((row * 73 + lane * 29 + 19) & 0xff) as u8;
            counts[input as usize] += 1;
            values.extend([Val::from_u8(input), Val::from_u8(AES_SBOX[input as usize])]);
        }
    }
    (RowMajorMatrix::new(values, lanes * 2), counts)
}

fn table_trace(counts: &[u32; 256]) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(
        counts.iter().map(|count| Val::from_u32(*count)).collect(),
        1,
    )
}

fn main() {
    let rows = rows();
    let lanes = lanes();
    let config = config();
    let (query_trace, counts) = query_trace(rows, lanes);
    let table_trace = table_trace(&counts);
    let query_air = SboxAir::Query { lanes };
    let table_air = SboxAir::Table;
    let instances = vec![
        StarkInstance {
            air: &query_air,
            trace: &query_trace,
            public_values: vec![],
        },
        StarkInstance {
            air: &table_air,
            trace: &table_trace,
            public_values: vec![],
        },
    ];
    let prover_data = ProverData::from_instances(&config, &instances);
    let prove_start = Instant::now();
    let proof = prove_batch(&config, &instances, &prover_data);
    let prove_elapsed = prove_start.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof)
        .expect("proof must serialize")
        .len();
    let verify_start = Instant::now();
    verify_batch(
        &config,
        &[query_air, table_air],
        &proof,
        &[vec![], vec![]],
        &prover_data.common,
    )
    .expect("AES S-box lookup proof must verify");
    let verify_elapsed = verify_start.elapsed();
    println!(
        "private_aes_sbox_queries={} rows={rows} lanes={lanes} zk_fri_soundness_bits=216 prove_ms={} verify_ms={} proof_bytes={proof_bytes}",
        rows * lanes,
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis(),
    );
}
