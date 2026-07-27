use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::verify_capture;

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// A capture directory or its manifest.json file.
    capture: PathBuf,

    /// Hex-encoded secp256k1 SEC1 public key from the trusted LLM Notary notary.
    #[arg(long)]
    trusted_notary_key: String,

    /// Verify without printing the disclosed transcript.
    #[arg(long)]
    summary: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let trusted_notary_key = hex::decode(&args.trusted_notary_key)?;
    let (manifest, request, response) = verify_capture(&args.capture, &trusted_notary_key)?;
    println!("verified capture: {}", manifest.capture_id);
    println!("verified provider: {}", manifest.provider.host);
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
