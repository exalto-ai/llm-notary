use anyhow::Result;
use certified::{load_bundle, verify_trace_bundle};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Verify a portable Certified TLS-notarized trace")]
struct Args {
    bundle: PathBuf,

    /// Hex-encoded secp256k1 SEC1 public key from the trusted Certified notary.
    #[arg(long)]
    trusted_notary_key: String,

    /// Verify without printing the disclosed transcript.
    #[arg(long)]
    summary: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let bundle = load_bundle(&args.bundle)?;
    let trusted_notary_key = hex::decode(&args.trusted_notary_key)?;
    let (request, response) = verify_trace_bundle(&bundle, &trusted_notary_key)?;
    println!("verified provider: {}", bundle.server_name);
    println!(
        "disclosed request SHA-256: {}",
        bundle.disclosed_request_sha256
    );
    println!(
        "disclosed response SHA-256: {}",
        bundle.disclosed_response_sha256
    );
    if args.summary {
        return Ok(());
    }
    println!("\n--- disclosed request ---\n{request}");
    println!("\n--- disclosed response ---\n{response}");
    Ok(())
}
