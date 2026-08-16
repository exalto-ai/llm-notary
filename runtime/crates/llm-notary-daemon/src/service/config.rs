//! Helpers for loading local service configuration.

use std::path::{Path, PathBuf};

use crate::config::{AgentConfig, default_config_path};
use anyhow::Result;

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
        let mut config = AgentConfig::load(&path)?;
        config.resolve_runtime_secrets()?;
        return Ok((config, path));
    }
    let (mut config, created) = AgentConfig::load_or_create(&path)?;
    if created {
        eprintln!("created default agent configuration: {}", path.display());
    }
    config.resolve_runtime_secrets()?;
    Ok((config, path))
}
