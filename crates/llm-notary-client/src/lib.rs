//! Local LLM Notary daemon and its REST-backed command client.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `llm-notary-core`.

use anyhow::Result;
use std::path::PathBuf;

use clap::Parser;

pub use llm_notary_core::*;

pub mod admin;
pub mod artifact_store;
mod catalog;
pub mod cli;
pub mod config;
mod local_cli;
pub mod metadata;
pub mod metadata_store;
pub mod persistence;
pub mod update;

#[derive(Parser, Debug)]
#[command(
    name = "llm-notaryd",
    about = "Run the local LLM Notary proxy and administration daemon",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("LLM_NOTARY_BUILD_ID"), ")")
)]
struct DaemonCli {
    /// Versioned local service configuration file. Defaults to the standard
    /// user configuration path and is created on first start.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Runs the client command line using process arguments.
pub async fn run_daemon() -> Result<()> {
    let _telemetry = telemetry::init("llm-notaryd")?;
    let cli = DaemonCli::parse();
    cli::auth::validate_credential_configuration()?;
    cli::proxy::run(cli::proxy::ProxyArgs { config: cli.config }).await
}

/// Runs the short-lived REST-backed command line client.
pub async fn run_cli() -> std::result::Result<(), local_cli::CliError> {
    local_cli::run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_accepts_only_configuration() {
        assert!(DaemonCli::try_parse_from(["llm-notaryd"]).is_ok());
        assert!(DaemonCli::try_parse_from(["llm-notaryd", "captures"]).is_err());
    }
}
