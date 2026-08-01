//! Versioned local configuration for the proxy and capture catalog.

use std::{
    env, fs,
    io::{ErrorKind, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    notary_directory::NotaryEndpoint, sha256_hex,
};

/// The versioned identifier for an agent configuration file.
pub const CONFIG_FORMAT: &str = "llm-notary/agent-config/v1";

/// Local proxy configuration. This is intentionally separate from the private
/// vault state, which contains key references and passphrase KDF parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub format: String,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub notary: NotaryConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub providers: ProvidersConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_max_attestable_http_bytes")]
    pub max_attestable_http_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryConfig {
    /// Optional explicit endpoint. Without this the client uses the signed
    /// notary directory at the configured public API origin.
    pub endpoint: Option<String>,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            max_frame_bytes: default_max_frame_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_bundle_dir")]
    pub bundle_dir: PathBuf,
    #[serde(default = "default_finalized_dir")]
    pub finalized_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogConfig {
    #[serde(default = "default_catalog_path")]
    pub path: PathBuf,
    #[serde(default = "default_preview_chars")]
    pub prompt_preview_chars: usize,
    #[serde(default = "default_preview_chars")]
    pub output_preview_chars: usize,
    #[serde(default = "default_true")]
    pub full_text_search: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    #[serde(default = "ProviderConfig::openai")]
    pub openai: ProviderConfig,
    #[serde(default = "ProviderConfig::anthropic")]
    pub anthropic: ProviderConfig,
    #[serde(default = "ProviderConfig::deepseek")]
    pub deepseek: ProviderConfig,
    #[serde(default = "ProviderConfig::openrouter")]
    pub openrouter: ProviderConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub route_prefix: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            format: CONFIG_FORMAT.to_owned(),
            proxy: ProxyConfig::default(),
            notary: NotaryConfig::default(),
            storage: StorageConfig::default(),
            catalog: CatalogConfig::default(),
            providers: ProvidersConfig::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_attestable_http_bytes: default_max_attestable_http_bytes(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            bundle_dir: default_bundle_dir(),
            finalized_dir: default_finalized_dir(),
        }
    }
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            path: default_catalog_path(),
            prompt_preview_chars: default_preview_chars(),
            output_preview_chars: default_preview_chars(),
            full_text_search: true,
        }
    }
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            openai: ProviderConfig::openai(),
            anthropic: ProviderConfig::anthropic(),
            deepseek: ProviderConfig::deepseek(),
            openrouter: ProviderConfig::openrouter(),
        }
    }
}

impl ProviderConfig {
    fn openai() -> Self {
        Self {
            enabled: true,
            route_prefix: "/openai".to_owned(),
        }
    }

    fn anthropic() -> Self {
        Self {
            enabled: true,
            route_prefix: "/anthropic".to_owned(),
        }
    }

    fn deepseek() -> Self {
        Self {
            enabled: true,
            route_prefix: "/deepseek".to_owned(),
        }
    }

    fn openrouter() -> Self {
        Self {
            enabled: true,
            route_prefix: "/openrouter".to_owned(),
        }
    }
}

impl AgentConfig {
    /// Loads and validates one versioned TOML configuration file.
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("reading agent configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("parsing agent configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Creates an editable default configuration when the file does not yet
    /// exist. Returns whether this invocation created the file.
    pub fn ensure_default(path: &Path) -> Result<bool> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| anyhow::anyhow!("agent configuration path has no parent"))?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        let contents = format!(
            "# LLM Notary local agent configuration.\n# This file is created automatically on first use. Edit it to change local behavior.\n\n{}",
            toml::to_string_pretty(&Self::default())?
        );
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating agent configuration {}", path.display()));
            }
        };
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing agent configuration {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing agent configuration {}", path.display()))?;
        Ok(true)
    }

    /// Loads a configuration, first materializing the standard defaults when
    /// the requested file does not exist.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        let created = Self::ensure_default(path)?;
        Ok((Self::load(path)?, created))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == CONFIG_FORMAT,
            "unsupported agent configuration format: {}",
            self.format
        );
        ensure!(
            self.proxy.max_attestable_http_bytes > 0,
            "proxy.max_attestable_http_bytes must be non-zero"
        );
        if let Some(endpoint) = &self.notary.endpoint {
            endpoint
                .parse::<NotaryEndpoint>()
                .context("notary.endpoint is invalid")?;
        }
        ensure!(
            self.notary.max_frame_bytes > 0 && self.notary.max_frame_bytes <= u32::MAX as usize,
            "notary.max_frame_bytes must be between 1 and {}",
            u32::MAX
        );
        ensure!(
            !self.catalog.path.as_os_str().is_empty(),
            "catalog.path must not be empty"
        );
        ensure!(
            !self.storage.bundle_dir.as_os_str().is_empty(),
            "storage.bundle_dir must not be empty"
        );
        ensure!(
            !self.storage.finalized_dir.as_os_str().is_empty(),
            "storage.finalized_dir must not be empty"
        );

        let routes = [
            ("openai", &self.providers.openai),
            ("anthropic", &self.providers.anthropic),
            ("deepseek", &self.providers.deepseek),
            ("openrouter", &self.providers.openrouter),
        ];
        let mut prefixes: Vec<(&str, &str)> = Vec::new();
        for (name, provider) in routes {
            ensure!(
                provider.route_prefix.starts_with('/'),
                "providers.{name}.route_prefix must start with /"
            );
            ensure!(
                provider.route_prefix.len() > 1,
                "providers.{name}.route_prefix must not be /"
            );
            ensure!(
                !provider.route_prefix.ends_with('/'),
                "providers.{name}.route_prefix must not end with /"
            );
            ensure!(
                provider
                    .route_prefix
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || character == '-'
                        || character == '_'
                        || character == '/'),
                "providers.{name}.route_prefix contains an invalid character"
            );
            if provider.enabled {
                for (other_name, other_prefix) in &prefixes {
                    ensure!(
                        !route_prefixes_overlap(&provider.route_prefix, other_prefix),
                        "enabled provider route prefixes overlap: providers.{name}.route_prefix ({}) and providers.{other_name}.route_prefix ({other_prefix})",
                        provider.route_prefix,
                    );
                }
                prefixes.push((name, provider.route_prefix.as_str()));
            }
        }
        Ok(())
    }

    /// Returns a stable identifier for the complete, non-secret configuration
    /// that governed a capture.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(format!(
            "sha256:{}",
            sha256_hex(toml::to_string(self)?.as_bytes())
        ))
    }

    pub fn notary_endpoint(&self) -> Result<Option<NotaryEndpoint>> {
        self.notary.endpoint.as_deref().map(str::parse).transpose()
    }
}

fn route_prefixes_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Finds the usual user-editable configuration location.
pub fn default_config_path() -> Result<PathBuf> {
    let base = if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("APPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("HOME") {
        let home = PathBuf::from(path);
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join(".config")
        }
    } else {
        bail!("could not determine a configuration directory")
    };
    Ok(base.join("llm-notary").join("agent.toml"))
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787"
        .parse()
        .expect("valid default listen address")
}

fn default_max_attestable_http_bytes() -> usize {
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES
}

fn default_max_frame_bytes() -> usize {
    DEFAULT_NOTARY_MAX_FRAME_BYTES
}

fn default_preview_chars() -> usize {
    1_000
}

fn default_true() -> bool {
    true
}

fn default_data_dir() -> PathBuf {
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path).join("llm-notary")
    } else if let Some(path) = env::var_os("LOCALAPPDATA") {
        PathBuf::from(path).join("llm-notary")
    } else if let Some(path) = env::var_os("HOME") {
        let home = PathBuf::from(path);
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/llm-notary")
        } else {
            home.join(".local/share/llm-notary")
        }
    } else {
        PathBuf::from("llm-notary-data")
    }
}

fn default_bundle_dir() -> PathBuf {
    default_data_dir().join("bundles")
}

fn default_finalized_dir() -> PathBuf {
    default_data_dir().join("traces")
}

fn default_catalog_path() -> PathBuf {
    default_data_dir().join("catalog.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_enables_the_built_in_providers() {
        let config = AgentConfig::default();
        config.validate().unwrap();
        assert!(config.providers.openai.enabled);
        assert!(config.providers.anthropic.enabled);
        assert!(config.providers.deepseek.enabled);
        assert!(config.providers.openrouter.enabled);
        assert_eq!(config.catalog.prompt_preview_chars, 1_000);
        assert!(config.catalog.full_text_search);
    }

    #[test]
    fn duplicate_enabled_routes_are_rejected() {
        let mut config = AgentConfig::default();
        config.providers.anthropic.route_prefix = "/openai".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn overlapping_enabled_routes_are_rejected() {
        let mut config = AgentConfig::default();
        config.providers.openai.route_prefix = "/ai".to_owned();
        config.providers.anthropic.route_prefix = "/ai/anthropic".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn creating_a_default_configuration_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        let (config, created) = AgentConfig::load_or_create(&path).unwrap();
        assert!(created);
        config.validate().unwrap();
        assert!(!AgentConfig::ensure_default(&path).unwrap());
    }

    #[test]
    fn default_configuration_round_trips_as_toml() {
        let config = AgentConfig::default();
        let parsed: AgentConfig =
            toml::from_str(&toml::to_string_pretty(&config).unwrap()).unwrap();
        parsed.validate().unwrap();
    }
}
