//! Commands for local source bundles and verified trace packages.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{
    DEFAULT_NOTARY_MAX_FRAME_BYTES, DeferredBundle,
    bundle::{finalize_bundle, trace_package_notary_key, verify_trace_package},
    cli::notary,
    cli::proxy::discover_notary,
    vault::Vault,
};

#[derive(Args, Debug)]
pub struct FinalizeArgs {
    /// Local `.llmbundle` file.
    bundle: PathBuf,
    /// Destination directory for the verified trace package.
    #[arg(long)]
    output: PathBuf,
    /// Hex-encoded notary public key used to verify the source evidence.
    #[arg(long)]
    trusted_notary_key: Option<String>,
    /// Override the notary discovered from LLM Notary's public directory.
    #[arg(long)]
    notary: Option<SocketAddr>,
    /// Largest control-protocol frame accepted from the paired notary.
    /// Must match the notary's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Verified trace package directory.
    package: PathBuf,
    /// Hex-encoded notary public key used to verify the source evidence.
    #[arg(long)]
    trusted_notary_key: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum BundlesCommand {
    /// List encrypted pending bundles.
    List(ListArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Directory containing pending `.llmbundle` files.
    #[arg(long, default_value = "bundles")]
    bundle_dir: PathBuf,
}

pub async fn finalize(args: FinalizeArgs) -> Result<()> {
    let vault = Vault::open_interactive()?;
    let notary = match args.notary {
        Some(notary) => notary,
        None => discover_notary().await?,
    };
    let (key, key_id) = match args.trusted_notary_key.as_deref() {
        Some(value) => notary::explicit_key(value)?,
        None => notary::cached_active_key()?,
    };
    eprintln!(
        "finalizing {}; private proof generation can take several minutes",
        args.bundle.display()
    );
    eprintln!(
        "the encrypted bundle is unchanged and can be retried if this command is interrupted"
    );
    let path = finalize_bundle(
        &args.bundle,
        &args.output,
        &key,
        &vault,
        notary,
        args.max_frame_bytes,
    )
    .await?;
    println!("wrote verified trace package: {}", path.display());
    println!("trusted notary key: {key_id}");
    Ok(())
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    let embedded_key = trace_package_notary_key(&args.package)?;
    let (key, key_id) = match args.trusted_notary_key.as_deref() {
        Some(value) => notary::explicit_key(value)?,
        None => {
            let (key_id, _) = notary::cached_key(&embedded_key)?;
            (embedded_key, key_id)
        }
    };
    let manifest = verify_trace_package(&args.package, &key)?;
    println!("verified trace package: {}", manifest.capture_id());
    println!("trusted notary key: {key_id}");
    Ok(())
}

pub fn bundles(command: BundlesCommand) -> Result<()> {
    match command {
        BundlesCommand::List(args) => {
            let vault = Vault::open_interactive()?;
            let mut paths = std::fs::read_dir(&args.bundle_dir)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().is_some_and(|ext| ext == "llmbundle"))
                .collect::<Vec<_>>();
            paths.sort();
            println!("ID\tPROVIDER\tCREATED_MS\tPATH");
            for path in paths {
                let bundle = DeferredBundle::load(&path, &vault)?;
                println!(
                    "{}\t{}\t{}\t{}",
                    bundle.capture_id(),
                    bundle.provider_name(),
                    bundle.created_at_unix_ms(),
                    path.display()
                );
            }
        }
    }
    Ok(())
}
