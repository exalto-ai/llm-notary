use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use crate::{cli::notary, load_capture, verify_capture};

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// A capture directory or its manifest.json file.
    capture: PathBuf,

    /// Hex-encoded secp256k1 SEC1 public key from the trusted LLM Notary notary.
    #[arg(long)]
    trusted_notary_key: Option<String>,

    /// Verify without printing the disclosed transcript.
    #[arg(long)]
    summary: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let embedded_key = hex::decode(&load_capture(&args.capture)?.manifest.notary.public_key)
        .context("capture manifest notary key must be hexadecimal")?;
    let (trusted_notary_key, key_id) = match args.trusted_notary_key {
        Some(value) => notary::explicit_key(&value)?,
        None => {
            let (key_id, _) = notary::cached_key(&embedded_key)?;
            (embedded_key, key_id)
        }
    };
    let (manifest, request, response) = verify_capture(&args.capture, &trusted_notary_key)?;
    println!("verified capture: {}", manifest.capture_id);
    println!("verified provider: {}", manifest.provider.host);
    println!("trusted notary key: {key_id}");
    println!(
        "disclosed request SHA-256: {}",
        manifest.artifacts.request_disclosed_sha256
    );
    println!(
        "disclosed response SHA-256: {}",
        manifest.artifacts.response_sha256
    );
    if args.summary {
        return Ok(());
    }
    println!("\n--- disclosed request ---\n{request}");
    println!("\n--- disclosed response ---\n{response}");
    Ok(())
}
