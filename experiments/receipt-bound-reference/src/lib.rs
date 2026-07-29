//! Deterministic reference evaluator for a receipt-bound private-proof fixture.
//!
//! This mirrors the present TLSN deferred-proof relations on synthetic data.
//! It is deliberately *not* a proof system: it pins the public/witness split
//! and supplies mutation cases for a future independently verified AIR.

use aes::Aes128;
use ctr::{
    Ctr32BE,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ROOT_BINDING_DOMAIN: &[u8] = b"llm-notary/ephemeral-key-binding/v1";
const RECORD_DIGEST_DOMAIN: &[u8] = b"tlsn/deferred-records/v1";
pub const TRANSCRIPT_COMMITMENT_ALGORITHM: &str = "blake3/v1/plaintext-plus-blinder";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedRecord {
    pub sequence: u64,
    pub explicit_nonce: [u8; 8],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicJournal {
    pub root_binding: [u8; 32],
    pub record_digest: [u8; 32],
    pub commitment_algorithm: &'static str,
    pub sent_records: Vec<EncryptedRecord>,
    pub recv_records: Vec<EncryptedRecord>,
    pub sent_commitment: [u8; 32],
    pub recv_commitment: [u8; 32],
}

/// The local-only witness. Nothing in this type belongs in a receipt, public
/// artifact, debug log, or remote prover request.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateWitness {
    pub client_write_key: [u8; 16],
    pub client_write_iv: [u8; 4],
    pub server_write_key: [u8; 16],
    pub server_write_iv: [u8; 4],
    pub root_binding_salt: [u8; 16],
    pub sent_plaintext: Vec<Vec<u8>>,
    pub recv_plaintext: Vec<Vec<u8>>,
    pub sent_blinder: [u8; 16],
    pub recv_blinder: [u8; 16],
}

#[derive(Clone, PartialEq, Eq)]
pub struct Fixture {
    pub journal: PublicJournal,
    pub witness: PrivateWitness,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StatementError {
    #[error("the public journal uses an unsupported transcript commitment algorithm")]
    CommitmentAlgorithm,
    #[error("the supplied traffic-key opening does not match the receipt root binding")]
    RootBinding,
    #[error("the encrypted records do not match the receipt record digest")]
    RecordDigest,
    #[error("the record count does not match the private witness")]
    RecordCount,
    #[error("a private plaintext does not decrypt from its signed encrypted record")]
    AesCtr,
    #[error("a blinded transcript commitment does not match its private plaintext")]
    TranscriptCommitment,
}

/// Evaluates the statement a replacement ZK proof must establish for this
/// fixture. The journal is public; `witness` is private.
pub fn verify_statement(
    journal: &PublicJournal,
    witness: &PrivateWitness,
) -> Result<(), StatementError> {
    if journal.commitment_algorithm != TRANSCRIPT_COMMITMENT_ALGORITHM {
        return Err(StatementError::CommitmentAlgorithm);
    }
    if root_binding(witness) != journal.root_binding {
        return Err(StatementError::RootBinding);
    }
    if deferred_record_digest(&journal.sent_records, &journal.recv_records) != journal.record_digest
    {
        return Err(StatementError::RecordDigest);
    }
    verify_direction(
        &journal.sent_records,
        &witness.sent_plaintext,
        &witness.client_write_key,
        &witness.client_write_iv,
    )?;
    verify_direction(
        &journal.recv_records,
        &witness.recv_plaintext,
        &witness.server_write_key,
        &witness.server_write_iv,
    )?;
    if transcript_commitment(&witness.sent_plaintext, &witness.sent_blinder)
        != journal.sent_commitment
        || transcript_commitment(&witness.recv_plaintext, &witness.recv_blinder)
            != journal.recv_commitment
    {
        return Err(StatementError::TranscriptCommitment);
    }
    Ok(())
}

/// Creates a fully deterministic fixture containing only artificial bytes.
pub fn synthetic_fixture() -> Fixture {
    let witness = PrivateWitness {
        client_write_key: [0x11; 16],
        client_write_iv: [0x22; 4],
        server_write_key: [0x33; 16],
        server_write_iv: [0x44; 4],
        root_binding_salt: [0x55; 16],
        sent_plaintext: vec![b"synthetic request bytes; no credential material".to_vec()],
        recv_plaintext: vec![b"synthetic response bytes; no provider data".to_vec()],
        sent_blinder: [0x66; 16],
        recv_blinder: [0x77; 16],
    };
    let sent_records = vec![encrypted_record(
        3,
        [0x88; 8],
        &witness.sent_plaintext[0],
        &witness.client_write_key,
        &witness.client_write_iv,
    )];
    let recv_records = vec![encrypted_record(
        7,
        [0x99; 8],
        &witness.recv_plaintext[0],
        &witness.server_write_key,
        &witness.server_write_iv,
    )];
    let journal = PublicJournal {
        root_binding: root_binding(&witness),
        record_digest: deferred_record_digest(&sent_records, &recv_records),
        commitment_algorithm: TRANSCRIPT_COMMITMENT_ALGORITHM,
        sent_records,
        recv_records,
        sent_commitment: transcript_commitment(&witness.sent_plaintext, &witness.sent_blinder),
        recv_commitment: transcript_commitment(&witness.recv_plaintext, &witness.recv_blinder),
    };
    // Keep the fixture construction and evaluator coupled even in release
    // builds. This must never generate a silently invalid reference vector.
    verify_statement(&journal, &witness).expect("synthetic fixture must be valid");
    Fixture { journal, witness }
}

pub fn root_binding(witness: &PrivateWitness) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_BINDING_DOMAIN);
    hasher.update(witness.client_write_key);
    hasher.update(witness.client_write_iv);
    hasher.update(witness.server_write_key);
    hasher.update(witness.server_write_iv);
    hasher.update(witness.root_binding_salt);
    hasher.finalize().into()
}

pub fn deferred_record_digest(sent: &[EncryptedRecord], recv: &[EncryptedRecord]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DIGEST_DOMAIN);
    for records in [sent, recv] {
        hasher.update((records.len() as u64).to_be_bytes());
        for record in records {
            hasher.update(record.sequence.to_be_bytes());
            hasher.update((record.explicit_nonce.len() as u64).to_be_bytes());
            hasher.update(record.explicit_nonce);
            hasher.update((record.ciphertext.len() as u64).to_be_bytes());
            hasher.update(&record.ciphertext);
        }
    }
    hasher.finalize().into()
}

pub fn transcript_commitment(plaintext: &[Vec<u8>], blinder: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for fragment in plaintext {
        hasher.update(fragment);
    }
    hasher.update(blinder);
    *hasher.finalize().as_bytes()
}

fn encrypted_record(
    sequence: u64,
    explicit_nonce: [u8; 8],
    plaintext: &[u8],
    key: &[u8; 16],
    iv: &[u8; 4],
) -> EncryptedRecord {
    let mut ciphertext = plaintext.to_vec();
    aes_ctr_apply_keystream(key, iv, &explicit_nonce, &mut ciphertext);
    EncryptedRecord {
        sequence,
        explicit_nonce,
        ciphertext,
    }
}

fn verify_direction(
    records: &[EncryptedRecord],
    plaintext: &[Vec<u8>],
    key: &[u8; 16],
    iv: &[u8; 4],
) -> Result<(), StatementError> {
    if records.len() != plaintext.len() {
        return Err(StatementError::RecordCount);
    }
    for (record, expected_plaintext) in records.iter().zip(plaintext) {
        let mut decrypted = record.ciphertext.clone();
        aes_ctr_apply_keystream(key, iv, &record.explicit_nonce, &mut decrypted);
        if decrypted != *expected_plaintext {
            return Err(StatementError::AesCtr);
        }
    }
    Ok(())
}

/// Matches `tlsn::transcript_internal::auth::aes_ctr_apply_keystream` exactly:
/// a 4-byte static IV, 8-byte public explicit nonce, and counter block one.
fn aes_ctr_apply_keystream(
    key: &[u8; 16],
    iv: &[u8; 4],
    explicit_nonce: &[u8; 8],
    input: &mut [u8],
) {
    let mut full_iv = [0u8; 16];
    full_iv[..4].copy_from_slice(iv);
    full_iv[4..12].copy_from_slice(explicit_nonce);
    let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
    cipher.seek(16);
    cipher.apply_keystream(input);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_fixture_satisfies_every_receipt_bound_relation() {
        let fixture = synthetic_fixture();
        assert_eq!(verify_statement(&fixture.journal, &fixture.witness), Ok(()));
    }

    #[test]
    fn root_binding_rejects_a_key_from_another_capture() {
        let mut fixture = synthetic_fixture();
        fixture.witness.client_write_key[0] ^= 1;
        assert_eq!(
            verify_statement(&fixture.journal, &fixture.witness),
            Err(StatementError::RootBinding)
        );
    }

    #[test]
    fn receipt_digest_rejects_ciphertext_or_nonce_or_sequence_mutation() {
        for mutation in [0, 1, 2] {
            let mut fixture = synthetic_fixture();
            match mutation {
                0 => fixture.journal.sent_records[0].ciphertext[0] ^= 1,
                1 => fixture.journal.sent_records[0].explicit_nonce[0] ^= 1,
                2 => fixture.journal.sent_records[0].sequence ^= 1,
                _ => unreachable!(),
            }
            assert_eq!(
                verify_statement(&fixture.journal, &fixture.witness),
                Err(StatementError::RecordDigest)
            );
        }
    }

    #[test]
    fn aes_ctr_rejects_an_inconsistent_private_plaintext_after_a_reissued_digest() {
        let mut fixture = synthetic_fixture();
        fixture.journal.sent_records[0].ciphertext[0] ^= 1;
        fixture.journal.record_digest =
            deferred_record_digest(&fixture.journal.sent_records, &fixture.journal.recv_records);
        assert_eq!(
            verify_statement(&fixture.journal, &fixture.witness),
            Err(StatementError::AesCtr)
        );
    }

    #[test]
    fn transcript_commitment_rejects_plaintext_blinder_and_algorithm_mutation() {
        let mut fixture = synthetic_fixture();
        fixture.witness.sent_plaintext[0][0] ^= 1;
        assert_eq!(
            verify_statement(&fixture.journal, &fixture.witness),
            Err(StatementError::AesCtr)
        );

        let mut fixture = synthetic_fixture();
        fixture.witness.sent_blinder[0] ^= 1;
        assert_eq!(
            verify_statement(&fixture.journal, &fixture.witness),
            Err(StatementError::TranscriptCommitment)
        );

        let mut fixture = synthetic_fixture();
        fixture.journal.commitment_algorithm = "sha256/v1/plaintext-plus-blinder";
        assert_eq!(
            verify_statement(&fixture.journal, &fixture.witness),
            Err(StatementError::CommitmentAlgorithm)
        );
    }
}
