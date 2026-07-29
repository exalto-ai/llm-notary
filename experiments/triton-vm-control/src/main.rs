//! Generic-zkVM lower-bound control for deferred-proof research.
//!
//! This program is intentionally *not* the LLM Notary proof statement. It
//! proves a public linear accumulator over private field elements in Triton VM.
//! It measures the cost of private-input handling and a ZK-STARK proof as a
//! lower bound. It has no AES-CTR, SHA-256, BLAKE3, TLS-record semantics, or
//! receipt binding; those omissions make it unsuitable as evidence output.

use std::{env, time::Instant};

use triton_vm::prelude::*;

fn input_elements() -> usize {
    let value = env::var("TRITON_CONTROL_ELEMENTS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .expect("TRITON_CONTROL_ELEMENTS must be a positive integer")
        .unwrap_or(2_048);
    assert!(value > 0, "TRITON_CONTROL_ELEMENTS must be positive");
    value
}

fn main() {
    let elements = input_elements();
    let program = triton_program!(
        read_io 1           // count
        push 0              // count accumulator
        call accumulate
        write_io 1          // emit accumulator as the public journal
        halt

        accumulate:         // count accumulator
            dup 1
            push 0 eq
            skiz
                return
            divine 1
            add
            swap 1
            push -1 add
            swap 1
            recurse
    );

    let witness = (0..elements)
        .map(|index| bfe!((index as u64 % 251) + 1))
        .collect::<Vec<_>>();
    let expected_sum = witness
        .iter()
        .copied()
        .fold(BFieldElement::new(0), |sum, value| sum + value);
    let start = Instant::now();
    let (stark, claim, proof) = triton_vm::prove_program(
        program,
        PublicInput::from([bfe!(elements)]),
        NonDeterminism::from(witness),
    )
    .expect("control proof must generate");
    let prove_elapsed = start.elapsed();

    let verify_start = Instant::now();
    assert!(triton_vm::verify(stark, &claim, &proof));
    let verify_elapsed = verify_start.elapsed();
    assert_eq!(claim.output, vec![expected_sum]);

    let proof_bytes = bincode::serialize(&proof).expect("proof serializes").len();
    println!(
        "elements={elements} private_bytes_lower_bound={elements} prove_ms={} verify_ms={} proof_bytes={proof_bytes} padded_height={} security_bits={}",
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis(),
        proof
            .padded_height()
            .expect("control proof has padded height"),
        stark.security_level,
    );
}
