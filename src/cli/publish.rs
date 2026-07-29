use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::{
    normalize::{render_public_trace, verified_inference_from_capture},
    verify_capture,
};

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// One or more private capture directories, in conversation order.
    #[arg(required = true, num_args = 1..)]
    captures: Vec<PathBuf>,

    /// Directory that will receive the unsigned trace.otlp.json preview.
    #[arg(long)]
    out: PathBuf,

    /// Hex-encoded secp256k1 SEC1 public key of the trusted TLSNotary service.
    #[arg(long)]
    trusted_notary_key: Option<String>,
}

pub fn run(args: PublishArgs) -> Result<()> {
    let mut inferences = Vec::with_capacity(args.captures.len());
    let mut used_key_ids = Vec::new();
    for capture in &args.captures {
        // `verify_capture` authenticates every artifact before the provider
        // adapter sees a byte of it. Do not replace this with load_capture.
        let embedded_key = hex::decode(&crate::load_capture(capture)?.manifest.notary.public_key)
            .context("capture manifest notary key must be hexadecimal")?;
        let (trusted_notary_key, key_id) = match args.trusted_notary_key.as_deref() {
            Some(value) => crate::cli::notary::explicit_key(value)?,
            None => {
                let (key_id, _) = crate::cli::notary::cached_key(&embedded_key)?;
                (embedded_key, key_id)
            }
        };
        let (manifest, request, response) = verify_capture(capture, &trusted_notary_key)?;
        used_key_ids.push(key_id);
        inferences.push(verified_inference_from_capture(
            &manifest, &request, &response,
        )?);
    }
    let trace = render_public_trace(&inferences)?;
    fs::create_dir_all(&args.out)
        .with_context(|| format!("creating preview directory {}", args.out.display()))?;
    let destination = args.out.join("trace.otlp.json");
    if destination.exists() {
        bail!(
            "refusing to overwrite existing preview {}",
            destination.display()
        );
    }
    let temporary = args.out.join(".trace.otlp.json.partial");
    if temporary.exists() {
        bail!(
            "preview staging file already exists: {}",
            temporary.display()
        );
    }
    fs::write(&temporary, trace)
        .with_context(|| format!("writing preview {}", temporary.display()))?;
    fs::rename(&temporary, &destination)
        .with_context(|| format!("finalizing preview {}", destination.display()))?;
    println!(
        "wrote unsigned public trace preview: {}",
        destination.display()
    );
    used_key_ids.sort();
    used_key_ids.dedup();
    println!("trusted notary key(s): {}", used_key_ids.join(", "));
    Ok(())
}
