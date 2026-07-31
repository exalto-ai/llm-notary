use anyhow::Result;
use certified::cli::{
    auth::{self, LoginArgs},
    bundle::{self, BundlesCommand, FinalizeArgs, VerifyArgs as VerifyTraceArgs},
    download::{self, DownloadArgs},
    proxy::{self, ProxyArgs},
    public::{self, VerifyPublicArgs},
    publish::{self, PublishArgs},
    vault::{self, VaultCommand},
    verify::{self, VerifyArgs},
};
use clap::{Parser, Subcommand};

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
    Login(LoginArgs),
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
    Finalize(FinalizeArgs),
    /// Inspect encrypted local bundles.
    Bundles {
        #[command(subcommand)]
        command: BundlesCommand,
    },
    /// Verify a finalized OTel trace package without uploading it.
    VerifyTrace(VerifyTraceArgs),
    /// Configure encryption for local bundles.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    /// Verify a local capture without uploading it.
    Verify(VerifyArgs),
    /// Verify a public trace and platform stamp without a private capture.
    VerifyPublic(VerifyPublicArgs),
    /// Download a public trace and platform stamp from the LLM Notary Library.
    Download(DownloadArgs),
    /// Upload one finalized, locally verified trace package for publication.
    Publish(PublishArgs),
}

#[derive(Subcommand, Debug)]
enum ProxyCommand {
    /// Start a local proxy.
    Start(ProxyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = certified::telemetry::init("llm-notary-cli")?;
    match Cli::parse().command {
        CommandName::Login(args) => auth::login(args).await,
        CommandName::Logout => auth::logout().await,
        CommandName::Whoami => auth::whoami().await,
        CommandName::Proxy {
            command: ProxyCommand::Start(args),
        } => proxy::run(args).await,
        CommandName::Finalize(args) => bundle::finalize(args).await,
        CommandName::Bundles { command } => bundle::bundles(command),
        CommandName::VerifyTrace(args) => bundle::verify(args),
        CommandName::Vault { command } => vault::run(command),
        CommandName::Verify(args) => verify::run(args),
        CommandName::VerifyPublic(args) => public::run_verify_public(args),
        CommandName::Download(args) => download::run(args).await,
        CommandName::Publish(args) => publish::run(args).await,
    }
}
