//! Spartan2 ZK SHA-256 control.
//!
//! This is a private preimage-to-public-SHA-256-digest control, not the LLM
//! Notary statement. It deliberately omits TLS record binding, AES-CTR,
//! SHA-256 traffic-key binding, BLAKE3 commitments, and receipt verification.
//! Spartan2 uses a different, curve-based polynomial-commitment security
//! basis; its result is a changed-assumption comparison only.

use std::{marker::PhantomData, time::Instant};

use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    ConstraintSystem, SynthesisError,
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
};
use ff::{Field, PrimeField, PrimeFieldBits};
use sha2::{Digest, Sha256};
use spartan2::{
    provider::T256HyraxEngine,
    spartan_zk::SpartanZkSNARK,
    traits::{Engine, circuit::SpartanCircuit, snark::R1CSSNARKTrait},
};

type Engine256 = T256HyraxEngine;

#[derive(Clone, Debug)]
struct Sha256Circuit<Scalar: PrimeField> {
    preimage: Vec<u8>,
    _marker: PhantomData<Scalar>,
}

impl<Scalar: PrimeField + PrimeFieldBits> Sha256Circuit<Scalar> {
    fn new(preimage: Vec<u8>) -> Self {
        Self {
            preimage,
            _marker: PhantomData,
        }
    }
}

impl<E: Engine> SpartanCircuit<E> for Sha256Circuit<E::Scalar> {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        let digest = Sha256::digest(&self.preimage);
        Ok(digest
            .iter()
            .flat_map(|byte| {
                (0..8).rev().map(move |bit| {
                    if (byte >> bit) & 1 == 1 {
                        E::Scalar::ONE
                    } else {
                        E::Scalar::ZERO
                    }
                })
            })
            .collect())
    }

    fn shared<CS: ConstraintSystem<E::Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<E::Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<E::Scalar>],
        _: &[AllocatedNum<E::Scalar>],
        _: Option<&[E::Scalar]>,
    ) -> Result<(), SynthesisError> {
        let bits = self
            .preimage
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |bit| (byte >> bit) & 1 == 1))
            .map(Some)
            .map(|value| AllocatedBit::alloc(cs.namespace(|| "private preimage bit"), value))
            .map(|bit| bit.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;
        let digest_bits = sha256(cs.namespace(|| "sha256"), &bits)?;

        for bit in digest_bits {
            let value = bit.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let public = AllocatedNum::alloc(cs.namespace(|| "public digest bit"), || {
                Ok(if value {
                    E::Scalar::ONE
                } else {
                    E::Scalar::ZERO
                })
            })?;
            cs.enforce(
                || "digest bit equals public input",
                |_| bit.lc(CS::one(), E::Scalar::ONE),
                |lc| lc + CS::one(),
                |lc| lc + public.get_variable(),
            );
            public.inputize(cs.namespace(|| "publish digest bit"))?;
        }
        Ok(())
    }
}

fn main() {
    let circuit = Sha256Circuit::<<Engine256 as Engine>::Scalar>::new(vec![0; 1_024]);
    let setup_start = Instant::now();
    let (prover_key, verifier_key) =
        SpartanZkSNARK::<Engine256>::setup(circuit.clone()).expect("ZK setup must succeed");
    let setup_elapsed = setup_start.elapsed();

    let prep_start = Instant::now();
    let prepared = SpartanZkSNARK::<Engine256>::prep_prove(&prover_key, circuit.clone(), false)
        .expect("ZK preparation must succeed");
    let prep_elapsed = prep_start.elapsed();

    let prove_start = Instant::now();
    let (proof, _) = SpartanZkSNARK::<Engine256>::prove(&prover_key, circuit, prepared, false)
        .expect("ZK proving must succeed");
    let prove_elapsed = prove_start.elapsed();

    let proof_bytes = bincode::serialize(&proof)
        .expect("proof must serialize")
        .len();
    let verify_start = Instant::now();
    proof.verify(&verifier_key).expect("ZK proof must verify");
    let verify_elapsed = verify_start.elapsed();
    println!(
        "private_sha256_bytes=1024 setup_ms={} prep_ms={} prove_ms={} verify_ms={} proof_bytes={proof_bytes}",
        setup_elapsed.as_millis(),
        prep_elapsed.as_millis(),
        prove_elapsed.as_millis(),
        verify_elapsed.as_millis(),
    );
}
