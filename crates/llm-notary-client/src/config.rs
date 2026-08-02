//! Versioned local configuration for the proxy and capture catalog.

use std::{
    env, fs,
    io::{ErrorKind, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use argon2::PasswordHash;
use k256::ecdsa::VerifyingKey;
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
    pub admin: AdminConfig,
    #[serde(default)]
    pub notary: NotaryConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub catalog: CatalogConfig,
    #[serde(default)]
    pub providers: ProvidersConfig,
}

/// Local administration listener. It is deliberately separate from the
/// provider proxy so proxy callers cannot reach privileged routes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default = "default_admin_listen")]
    pub listen: SocketAddr,
    /// Optional HTTP Basic authentication for the loopback administration
    /// listener. The listener is open to local processes when omitted.
    pub auth: Option<AdminAuthConfig>,
}

/// Optional password authentication for the local administration listener.
/// The password is stored only as an Argon2id PHC string.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthConfig {
    pub username: String,
    pub password_hash: String,
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
    /// Explicit SEC1 secp256k1 trust anchor for `endpoint`. The endpoint and
    /// key are configured together so a self-hosted connection cannot become
    /// an implicit trust decision.
    pub public_key: Option<String>,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            public_key: None,
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
            admin: AdminConfig::default(),
            notary: NotaryConfig::default(),
            storage: StorageConfig::default(),
            catalog: CatalogConfig::default(),
            providers: ProvidersConfig::default(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            auth: None,
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
        ensure!(
            self.proxy.listen.ip().is_loopback(),
            "proxy.listen must use a loopback address"
        );
        ensure!(
            self.admin.listen.ip().is_loopback(),
            "admin.listen must use a loopback address"
        );
        ensure!(
            self.admin.listen != self.proxy.listen,
            "admin.listen and proxy.listen must be different addresses"
        );
        if let Some(auth) = &self.admin.auth {
            ensure!(
                !auth.username.is_empty() && auth.username.len() <= 128,
                "admin.auth.username must contain between 1 and 128 bytes"
            );
            ensure!(
                !auth.username.contains(':'),
                "admin.auth.username must not contain a colon"
            );
            let password_hash = PasswordHash::new(&auth.password_hash)
                .map_err(|error| anyhow::anyhow!("admin.auth.password_hash is invalid: {error}"))?;
            ensure!(
                password_hash.algorithm.as_str() == "argon2id",
                "admin.auth.password_hash must use Argon2id"
            );
        }
        match (&self.notary.endpoint, &self.notary.public_key) {
            (Some(endpoint), Some(_)) => {
                endpoint
                    .parse::<NotaryEndpoint>()
                    .context("notary.endpoint is invalid")?;
                self.notary_public_key()?;
            }
            (None, None) => {}
            _ => bail!("notary.endpoint and notary.public_key must be configured together"),
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

    pub fn notary_public_key(&self) -> Result<Option<Vec<u8>>> {
        self.notary
            .public_key
            .as_deref()
            .map(|value| {
                let key = hex::decode(value).context("notary.public_key must be hexadecimal")?;
                VerifyingKey::from_sec1_bytes(&key)
                    .context("notary.public_key must be a SEC1 secp256k1 key")?;
                Ok(key)
            })
            .transpose()
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
    Ok(base.join("llm-notary").join("config.toml"))
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787"
        .parse()
        .expect("valid default listen address")
}

fn default_admin_listen() -> SocketAddr {
    "127.0.0.1:8788"
        .parse()
        .expect("valid default admin listen address")
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
        assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(config.admin.listen.to_string(), "127.0.0.1:8788");
        assert!(config.admin.auth.is_none());
    }

    #[test]
    fn non_loopback_or_shared_listeners_are_rejected() {
        let mut config = AgentConfig::default();
        config.admin.listen = "0.0.0.0:8788".parse().unwrap();
        assert!(config.validate().is_err());

        config.admin.listen = config.proxy.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn explicit_notary_endpoint_requires_a_valid_trust_anchor() {
        let mut config = AgentConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        assert!(config.validate().is_err());

        config.notary.public_key =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned());
        config.validate().unwrap();
        assert_eq!(config.notary_public_key().unwrap().unwrap().len(), 33);

        config.notary.endpoint = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn configured_admin_auth_requires_an_argon2id_hash() {
        let mut config = AgentConfig::default();
        config.admin.auth = Some(AdminAuthConfig {
            username: "local-admin".to_owned(),
            password_hash: "$2b$12$not-an-argon2id-hash".to_owned(),
        });
        assert!(config.validate().is_err());

        config.admin.auth.as_mut().unwrap().password_hash =
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$yJIR0lVleM2KSPdVmBvsQ9uhA06YIR8aPCbRDbNvXXQ".to_owned();
        config.validate().unwrap();
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
        let path = directory.path().join("config.toml");
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
