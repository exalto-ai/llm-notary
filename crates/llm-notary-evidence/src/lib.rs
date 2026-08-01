//! Stable, reusable formats for finalized LLM Notary evidence.
//!
//! This crate intentionally contains parsers, validators, canonicalization,
//! and archive construction only. It does not know about the hosted platform,
//! local credentials, or notary transport configuration.

use sha2::{Digest, Sha256};

/// Versioned source-capture contract referenced by private and public evidence.
pub const CAPTURE_FORMAT: &str = "llm-notary/capture/v1";

/// Hash bytes using the spelling used by the versioned artifact contracts.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub mod archive;
pub mod public;
