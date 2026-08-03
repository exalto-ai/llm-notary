//! Commands for local source bundles and verified trace packages.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;

use crate::{
    DeferredBundle,
    bundle::{
        finalize_bundle, finalize_bundle_admitted, trace_package_created_at_unix_ms,
        trace_package_notary_key, verify_trace_package,
    },
    catalog::Catalog,
    cli::proxy::{refresh_notary_directory, resolve_notary},
    cli::{auth, config::load_agent_config, notary},
    vault::Vault,
};

#[derive(Args, Debug)]
pub struct FinalizeArgs {
    /// Local `.llmbundle` file.
    bundle: PathBuf,
    /// Destination directory for the verified trace package.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Agent configuration file. Defaults to the standard path. The default
    /// output location is `storage.finalized_dir/<capture-id>` and the package
    /// is cataloged.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Hex-encoded notary public key used to verify the source evidence.
    #[arg(long)]
    trusted_notary_key: Option<String>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Verified trace package directory.
    package: PathBuf,
    /// Hex-encoded notary public key used to verify the source evidence.
    #[arg(long)]
    trusted_notary_key: Option<String>,
}

pub async fn finalize(args: FinalizeArgs) -> Result<()> {
    let (config, _) = load_agent_config(args.config.as_deref())?;
    let vault = Vault::open_interactive()?;
    let bundle = DeferredBundle::load(&args.bundle, &vault)?;
    let hosted_admission = config.notary.endpoint.is_none();
    let output = args
        .output
        .unwrap_or_else(|| config.storage.finalized_dir.join(bundle.capture_id()));
    if args.trusted_notary_key.is_none() {
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
    let notary = match (config.notary_endpoint()?, directory_record) {
        (Some(notary), _) => notary,
        (None, Some(record)) if record.accepts_finalization_at(current_unix_ms()?) => {
            resolve_notary(&record).await?
        }
        (None, Some(_)) => bail!("the selected notary key is not accepting finalization"),
        (None, None) => bail!(
            "the explicit trusted key has no cached endpoint; set notary.endpoint in the agent configuration"
        ),
    };
    eprintln!(
        "finalizing {}; private proof generation can take several minutes",
        args.bundle.display()
    );
    eprintln!(
        "the encrypted bundle is unchanged and can be retried if this command is interrupted"
    );
    let result = if hosted_admission {
        let allowance = bundle.finalization_allowance_bytes()?;
        if allowance > config.proxy.max_attestable_http_bytes {
            anyhow::bail!("bundle exceeds the current local finalization byte limit");
        }
        let admission =
            auth::issue_finalization_admission(&bundle.record_digest_hex(), allowance).await?;
        finalize_bundle_admitted(
            &args.bundle,
            &output,
            &key,
            &vault,
            &notary,
            config
                .proxy
                .max_attestable_http_bytes
                .min(admission.max_attestable_http_bytes),
            config.notary.max_frame_bytes.min(admission.max_frame_bytes),
            &admission.ticket,
        )
        .await
    } else {
        finalize_bundle(
            &args.bundle,
            &output,
            &key,
            &vault,
            &notary,
            config.proxy.max_attestable_http_bytes,
            config.notary.max_frame_bytes,
        )
        .await
    };
    let path = result.map_err(|error| {
        let Some(admission) = crate::notary_admission_error(&error) else {
            return error;
        };
        anyhow::anyhow!(
            "{admission}. The encrypted bundle at {} is unchanged and can be retried.",
            args.bundle.display()
        )
    })?;
    if Catalog::open_for_config(&config)
        .and_then(|catalog| catalog.record_finalized_package(bundle.capture_id(), &path))
        .is_err()
    {
        eprintln!(
            "warning: finalized package was written but could not be added to the local catalog"
        );
    }
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
