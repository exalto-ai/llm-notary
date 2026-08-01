use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::public::verify_public_trace;

#[derive(Args, Debug)]
pub struct VerifyPublicArgs {
    /// Canonical trace.otlp.json emitted by the LLM Notary normalizer.
    trace: PathBuf,

    /// The accompanying platform stamp.json.
    stamp: PathBuf,

    /// Hex-encoded secp256k1 SEC1 public key for the trusted platform issuer.
    #[arg(long)]
    trusted_platform_key: String,
}

pub fn run_verify_public(args: VerifyPublicArgs) -> Result<()> {
    let trusted_platform_key = hex::decode(&args.trusted_platform_key)?;
    let verified = verify_public_trace(&args.trace, &args.stamp, &trusted_platform_key)?;
    println!("verified public trace: {}", verified.trace_sha256);
    println!("verified issuer: {}", verified.stamp.issuer);
    println!(
        "verified provider: {} ({})",
        verified.stamp.provider.name, verified.stamp.provider.host
    );
    println!("issued at unix ms: {}", verified.stamp.issued_at_unix_ms);
    println!("normalizer version: {}", verified.stamp.normalizer_version);
    Ok(())
}
