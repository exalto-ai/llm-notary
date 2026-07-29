//! Commands for initializing the local bundle vault.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};

use crate::vault::Vault;

#[derive(Subcommand, Debug)]
pub enum VaultCommand {
    /// Initialize the local vault.
    Init(InitArgs),
    /// Show the configured vault mode without exposing secrets.
    Status,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Use a passphrase instead of the operating system credential vault.
    #[arg(long)]
    passphrase: bool,
}

pub fn run(command: VaultCommand) -> Result<()> {
    match command {
        VaultCommand::Init(args) if args.passphrase => {
            let first = rpassword::prompt_password(
                "Choose LLM Notary vault passphrase (Enter for none): ",
            )?;
            let second = rpassword::prompt_password("Confirm vault passphrase: ")?;
            if first != second {
                bail!("passphrases do not match");
            }
            if first.is_empty() {
                eprintln!("warning: an empty passphrase does not protect bundle confidentiality");
            }
            Vault::init_passphrase(&first)?;
            println!("initialized passphrase vault");
        }
        VaultCommand::Init(_) => {
            Vault::init_os().context("initializing the OS credential vault")?;
            println!("initialized OS vault");
        }
        VaultCommand::Status => println!("{}", Vault::status()?),
    }
    Ok(())
}
