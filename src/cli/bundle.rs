//! Commands for local source bundles and verified trace packages.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Subcommand};

use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES, DeferredBundle,
    bundle::{
        finalize_bundle, trace_package_created_at_unix_ms, trace_package_notary_key,
        verify_trace_package,
    },
    cli::notary,
    cli::proxy::{refresh_notary_directory, resolve_notary},
    notary_directory::NotaryEndpoint,
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
    /// Override the notary endpoint discovered from LLM Notary's public directory.
    /// Use tcp:// or tls://; a bare host:port remains raw TCP.
    #[arg(long)]
    notary: Option<NotaryEndpoint>,
    /// Largest control-protocol frame accepted from the paired notary.
    /// Must match the notary's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,
    /// Maximum combined HTTP request and response bytes that may be privately
    /// committed. This must match the budget used while capturing the bundle.
    #[arg(long, default_value_t = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES)]
    max_attestable_http_bytes: usize,
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
    let bundle = DeferredBundle::load(&args.bundle, &vault)?;
    if args.trusted_notary_key.is_none() || args.notary.is_none() {
        refresh_notary_directory().await?;
    }
    let (key, key_id, directory_record) = match args.trusted_notary_key.as_deref() {
        Some(value) => {
            let (key, key_id) = notary::explicit_key(value)?;
            let record = notary::cached_record_for_key(&key).ok();
            (key, key_id, record)
        }
        None => {
            let (key, record) = notary::cached_record_for_bundle(&bundle)?;
            let key_id = record.key_id.clone();
            (key, key_id, Some(record))
        }
    };
    let notary = match (args.notary, directory_record) {
        (Some(notary), _) => notary,
        (None, Some(record)) if record.accepts_finalization_at(current_unix_ms()?) => {
            resolve_notary(&record).await?
        }
        (None, Some(_)) => bail!("the selected notary key is not accepting finalization"),
        (None, None) => {
            bail!("the explicit trusted key has no cached endpoint; also supply --notary")
        }
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
        &notary,
        args.max_attestable_http_bytes,
        args.max_frame_bytes,
    )
    .await
    .map_err(|error| {
        let Some(admission) = crate::notary_admission_error(&error) else {
            return error;
        };
        anyhow::anyhow!(
            "{admission}. The encrypted bundle at {} is unchanged and can be retried.",
            args.bundle.display()
        )
    })?;
    println!("wrote verified trace package: {}", path.display());
    println!("trusted notary key: {key_id}");
    Ok(())
}

pub fn verify(args: VerifyArgs) -> Result<()> {
    let embedded_key = trace_package_notary_key(&args.package)?;
    let (key, key_id) = match args.trusted_notary_key.as_deref() {
        Some(value) => notary::explicit_key(value)?,
        None => {
            let created_at = trace_package_created_at_unix_ms(&args.package)?;
            let (key_id, _) = notary::cached_key_at(&embedded_key, created_at)?;
            (embedded_key, key_id)
        }
    };
    let manifest = verify_trace_package(&args.package, &key)?;
    println!("verified trace package: {}", manifest.capture_id());
    println!("trusted notary key: {key_id}");
    Ok(())
}

fn current_unix_ms() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
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
