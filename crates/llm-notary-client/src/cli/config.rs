//! Commands and helpers for local agent configuration.

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::config::{AgentConfig, default_config_path};

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Parse and validate an agent configuration file without starting a proxy.
    Validate(ConfigPathArgs),
}

#[derive(Args, Debug)]
pub struct ConfigPathArgs {
    /// Agent configuration file. Defaults to the standard user configuration path.
    #[arg(long)]
    config: Option<PathBuf>,
}

pub fn run(command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Validate(args) => {
            let (config, path) = load_agent_config(args.config.as_deref())?;
            println!("valid agent configuration: {}", path.display());
            println!("configuration fingerprint: {}", config.fingerprint()?);
        }
    }
    Ok(())
}

pub(crate) fn config_path(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path.to_owned()),
        None => default_config_path(),
    }
}

/// Loads an agent configuration, generating the editable defaults on first
/// use. Every config-driven command shares this behavior so a fresh install
/// can start the proxy without a setup command.
pub(crate) fn load_agent_config(path: Option<&Path>) -> Result<(AgentConfig, PathBuf)> {
    let explicit = path.is_some();
    let path = config_path(path)?;
    if explicit {
        return Ok((AgentConfig::load(&path)?, path));
    }
    let (config, created) = AgentConfig::load_or_create(&path)?;
    if created {
        eprintln!("created default agent configuration: {}", path.display());
    }
    Ok((config, path))
}
