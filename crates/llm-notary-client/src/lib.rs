//! Local proxy and CLI workflow for LLM Notary.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `llm-notary-core`.

use anyhow::Result;
use clap::{Parser, Subcommand};

pub use llm_notary_core::*;

pub mod cli;

#[derive(Parser, Debug)]
#[command(
    name = "llm-notary",
    about = "Capture and verify provider-origin LLM traces",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: CommandName,
}

#[derive(Subcommand, Debug)]
enum CommandName {
    /// Sign in to the configured LLM Notary site to authorize publishing.
    Login(cli::auth::LoginArgs),
    /// Revoke this CLI session and remove its local credentials.
    Logout,
    /// Show the account authenticated for publishing.
    Whoami,
    /// Start the local API proxy and save encrypted local bundles.
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Turn an encrypted local bundle into a verified OTel trace package.
    Finalize(cli::bundle::FinalizeArgs),
    /// Inspect encrypted local bundles.
    Bundles {
        #[command(subcommand)]
        command: cli::bundle::BundlesCommand,
    },
    /// Verify a finalized OTel trace package without uploading it.
    VerifyTrace(cli::bundle::VerifyArgs),
    /// Configure encryption for local bundles.
    Vault {
        #[command(subcommand)]
        command: cli::vault::VaultCommand,
    },
    /// Verify a public trace and platform stamp without a private capture.
    VerifyPublic(cli::public::VerifyPublicArgs),
    /// Download a public trace and platform stamp from the LLM Notary Library.
    Download(cli::download::DownloadArgs),
    /// Upload one finalized, locally verified trace package for publication.
    Publish(cli::publish::PublishArgs),
}

#[derive(Subcommand, Debug)]
enum ProxyCommand {
    /// Start a local proxy.
    Start(cli::proxy::ProxyArgs),
}

/// Runs the client command line using process arguments.
pub async fn run() -> Result<()> {
    let _telemetry = telemetry::init("llm-notary-cli")?;
    match Cli::parse().command {
        CommandName::Login(args) => cli::auth::login(args).await,
        CommandName::Logout => cli::auth::logout().await,
        CommandName::Whoami => cli::auth::whoami().await,
        CommandName::Proxy {
            command: ProxyCommand::Start(args),
        } => cli::proxy::run(args).await,
        CommandName::Finalize(args) => cli::bundle::finalize(args).await,
        CommandName::Bundles { command } => cli::bundle::bundles(command),
        CommandName::VerifyTrace(args) => cli::bundle::verify(args),
        CommandName::Vault { command } => cli::vault::run(command),
        CommandName::VerifyPublic(args) => cli::public::run_verify_public(args),
        CommandName::Download(args) => cli::download::run(args).await,
        CommandName::Publish(args) => cli::publish::run(args).await,
    }
}
