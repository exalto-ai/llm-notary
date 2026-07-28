use anyhow::Result;
use certified::cli::{
    auth::{self, LoginArgs},
    proxy::{self, ProxyArgs},
    public::{self, VerifyPublicArgs},
    publish::{self, PublishArgs},
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
    /// Sign in to llmnotary.exalto.ai to authorize publishing.
    Login(LoginArgs),
    /// Revoke this CLI session and remove its local credentials.
    Logout,
    /// Show the account authenticated for publishing.
    Whoami,
    /// Start the local API proxy and save verifiable local captures.
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Verify a local capture without uploading it.
    Verify(VerifyArgs),
    /// Verify a public trace and platform stamp without a private capture.
    VerifyPublic(VerifyPublicArgs),
    /// Verify private captures locally and write an unsigned public trace preview.
    Publish(PublishArgs),
}

#[derive(Subcommand, Debug)]
enum ProxyCommand {
    /// Start a local proxy.
    Start(ProxyArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    match Cli::parse().command {
        CommandName::Login(args) => auth::login(args).await,
        CommandName::Logout => auth::logout().await,
        CommandName::Whoami => auth::whoami().await,
        CommandName::Proxy {
            command: ProxyCommand::Start(args),
        } => proxy::run(args).await,
        CommandName::Verify(args) => verify::run(args),
        CommandName::VerifyPublic(args) => public::run_verify_public(args),
        CommandName::Publish(args) => publish::run(args),
    }
}
