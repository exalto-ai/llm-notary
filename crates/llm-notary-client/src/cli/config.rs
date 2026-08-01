//! Commands for creating and checking local agent configuration.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::{AgentConfig, default_config_path};

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Create an editable local agent configuration file.
    Init(ConfigPathArgs),
    /// Parse and validate an agent configuration file without starting a proxy.
    Validate(ConfigPathArgs),
}

#[derive(Args, Debug)]
pub struct ConfigPathArgs {
    /// Agent configuration file. Defaults to the standard user configuration path.
    #[arg(long)]
    path: Option<PathBuf>,
}

pub fn run(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Init(args) => {
            let path = config_path(args.path)?;
            AgentConfig::write_default(&path)?;
            println!("wrote agent configuration: {}", path.display());
        }
        ConfigCommand::Validate(args) => {
            let path = config_path(args.path)?;
            let config = AgentConfig::load(&path)?;
            println!("valid agent configuration: {}", path.display());
            println!("configuration fingerprint: {}", config.fingerprint()?);
        }
    }
    Ok(())
}

pub(crate) fn config_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => default_config_path(),
    }
}
