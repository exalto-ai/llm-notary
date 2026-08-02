//! Local proxy and CLI workflow for LLM Notary.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `llm-notary-core`.

use anyhow::Result;
use std::path::PathBuf;

use clap::Parser;

pub use llm_notary_core::*;

pub mod admin;
pub mod catalog;
pub mod cli;
pub mod config;

#[derive(Parser, Debug)]
#[command(
    name = "llm-notary",
    about = "Capture and verify provider-origin LLM traces",
    version
)]
struct Cli {
    /// Versioned local service configuration file. Defaults to the standard
    /// user configuration path and is created on first start.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Runs the client command line using process arguments.
pub async fn run() -> Result<()> {
    let _telemetry = telemetry::init("llm-notary-local-service")?;
    let cli = Cli::parse();
    cli::proxy::run(cli::proxy::ProxyArgs { config: cli.config }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operational_subcommands_are_no_longer_accepted() {
        assert!(Cli::try_parse_from(["llm-notary"]).is_ok());
        for removed in ["proxy", "captures", "finalize", "verify-trace", "publish"] {
            assert!(Cli::try_parse_from(["llm-notary", removed]).is_err());
        }
    }
}
