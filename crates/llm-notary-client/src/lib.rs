//! Local LLM Notary daemon and its REST-backed command client.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `llm-notary-core`.

use anyhow::Result;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use llm_notary_core::*;

pub mod admin;
pub mod artifact_store;
pub mod cli;
pub mod config;
mod local_cli;
pub mod metadata;
pub mod metadata_store;
pub mod persistence;
pub mod postgres_metadata_store;
mod sqlite_catalog;
pub mod sqlite_metadata_store;
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
    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Apply the daemon-owned PostgreSQL metadata migrations and exit.
    Migrate,
}

/// Runs the client command line using process arguments.
pub async fn run_daemon() -> Result<()> {
    let cli = DaemonCli::parse();
    if matches!(cli.command, Some(DaemonCommand::Migrate)) {
        return run_daemon_migrator(cli.config).await;
    }
    let _telemetry = telemetry::init("llm-notaryd")?;
    cli::auth::validate_credential_configuration()?;
    cli::proxy::run(cli::proxy::ProxyArgs { config: cli.config }).await
}

/// Applies only the daemon-owned PostgreSQL metadata migrations.
async fn run_daemon_migrator(config_path: Option<PathBuf>) -> Result<()> {
    use std::time::Duration;

    let path = match config_path {
        Some(path) => path,
        None => config::default_config_path()?,
    };
    let config = config::AgentConfig::load_for_metadata_migration(&path)?;
    let postgres = config.catalog.postgres.as_ref().ok_or_else(|| {
        anyhow::anyhow!("the daemon metadata migrator requires catalog.backend = \"postgres\"")
    })?;
    let database_url = config.postgres_migration_url()?;
    println!("Applying local daemon PostgreSQL metadata migrations");
    postgres_metadata_store::migrate_database(
        database_url.expose(),
        postgres.ssl_mode,
        Duration::from_secs(postgres.connect_timeout_seconds),
        Duration::from_secs(postgres.migration_lock_timeout_seconds),
    )
    .await
    .map_err(|_| anyhow::anyhow!("local daemon PostgreSQL metadata migration failed"))?;
    println!("Local daemon PostgreSQL metadata migrations are current");
    Ok(())
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
        assert!(DaemonCli::try_parse_from(["llm-notaryd", "migrate", "captures"]).is_err());
        assert!(DaemonCli::try_parse_from(["llm-notaryd", "migrate"]).is_ok());
        assert!(
            DaemonCli::try_parse_from(["llm-notaryd", "--config", "agent.toml", "migrate"]).is_ok()
        );
    }
}
