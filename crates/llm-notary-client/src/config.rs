//! Versioned local configuration for the proxy and capture catalog.

use std::{
    env,
    ffi::OsString,
    fmt, fs,
    io::{ErrorKind, Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use argon2::PasswordHash;
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    notary_directory::NotaryEndpoint, s3_artifact_store::S3ArtifactStoreConfig, sha256_hex,
};

/// The versioned identifier for an agent configuration file.
pub const CONFIG_FORMAT: &str = "llm-notary/agent-config/v1";

pub const METADATA_DATABASE_URL_ENV: &str = "LLM_NOTARY_METADATA_DATABASE_URL";
pub const METADATA_DATABASE_URL_FILE_ENV: &str = "LLM_NOTARY_METADATA_DATABASE_URL_FILE";
pub const METADATA_MIGRATION_URL_ENV: &str = "LLM_NOTARY_METADATA_MIGRATION_URL";
pub const METADATA_MIGRATION_URL_FILE_ENV: &str = "LLM_NOTARY_METADATA_MIGRATION_URL_FILE";
pub const ARTIFACT_S3_ACCESS_KEY_ID_ENV: &str = "LLM_NOTARY_ARTIFACT_S3_ACCESS_KEY_ID";
pub const ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV: &str = "LLM_NOTARY_ARTIFACT_S3_ACCESS_KEY_ID_FILE";
pub const ARTIFACT_S3_SECRET_ACCESS_KEY_ENV: &str = "LLM_NOTARY_ARTIFACT_S3_SECRET_ACCESS_KEY";
pub const ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV: &str =
    "LLM_NOTARY_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE";
pub const ARTIFACT_S3_SESSION_TOKEN_ENV: &str = "LLM_NOTARY_ARTIFACT_S3_SESSION_TOKEN";
pub const ARTIFACT_S3_SESSION_TOKEN_FILE_ENV: &str = "LLM_NOTARY_ARTIFACT_S3_SESSION_TOKEN_FILE";

/// Local proxy configuration. This is intentionally separate from the private
/// vault state, which contains key references and passphrase KDF parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub format: String,
    #[serde(default)]
    pub cluster: ClusterConfig,
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

/// Explicit multi-replica runtime profile. Merely selecting PostgreSQL and S3
/// never enables cluster semantics.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Stable, operator-readable name for one replica slot.
    pub instance_id: Option<String>,
    #[serde(default = "default_cluster_heartbeat_seconds")]
    pub heartbeat_interval_seconds: u64,
    #[serde(default = "default_cluster_lease_seconds")]
    pub lease_seconds: u64,
    /// Hard ceiling after which a work claim stops renewing even if its task
    /// is still pending, so a wedged provider/notary operation is recoverable.
    #[serde(default = "default_cluster_claim_max_runtime_seconds")]
    pub claim_max_runtime_seconds: u64,
    /// Time kept ready=false but live before listeners begin graceful shutdown.
    #[serde(default = "default_cluster_withdrawal_delay_seconds")]
    pub withdrawal_delay_seconds: u64,
    /// Bounded time for admitted streams and current work to finish on SIGTERM.
    #[serde(default = "default_cluster_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
    /// Confirms that non-loopback listeners sit behind authenticated,
    /// TLS-terminated infrastructure which does not replay provider requests.
    #[serde(default)]
    pub trusted_ingress: bool,
    /// Pre-provisioned SHA-256 identity of the exact shared vault config and
    /// verifier. Runtime replicas may compare it but never establish it.
    pub vault_compatibility_sha256: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            instance_id: None,
            heartbeat_interval_seconds: default_cluster_heartbeat_seconds(),
            lease_seconds: default_cluster_lease_seconds(),
            claim_max_runtime_seconds: default_cluster_claim_max_runtime_seconds(),
            withdrawal_delay_seconds: default_cluster_withdrawal_delay_seconds(),
            shutdown_grace_seconds: default_cluster_shutdown_grace_seconds(),
            trusted_ingress: false,
            vault_compatibility_sha256: None,
        }
    }
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
    #[serde(default)]
    pub backend: ArtifactStorageBackend,
    #[serde(default = "default_bundle_dir")]
    pub bundle_dir: PathBuf,
    #[serde(default = "default_finalized_dir")]
    pub finalized_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3StorageConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStorageBackend {
    #[default]
    Filesystem,
    S3,
}

impl ArtifactStorageBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::S3 => "s3",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    pub bucket: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub force_path_style: bool,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "default_s3_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_s3_operation_timeout_seconds")]
    pub operation_timeout_seconds: u64,
}

impl S3StorageConfig {
    pub(crate) fn artifact_store_config(&self) -> Result<S3ArtifactStoreConfig> {
        let endpoint = self
            .endpoint
            .as_deref()
            .map(url::Url::parse)
            .transpose()
            .context("storage.s3.endpoint must be an absolute URL")?;
        S3ArtifactStoreConfig::new(
            endpoint,
            self.region.clone(),
            self.bucket.clone(),
            self.prefix.clone(),
            self.force_path_style,
            self.allow_insecure_http,
            std::time::Duration::from_secs(self.connect_timeout_seconds),
            std::time::Duration::from_secs(self.operation_timeout_seconds),
        )
        .map_err(|error| anyhow::Error::new(error).context("storage.s3 configuration is invalid"))
    }
}

pub(crate) struct SecretS3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl SecretS3Credentials {
    pub(crate) fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub(crate) fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    pub(crate) fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

impl fmt::Debug for SecretS3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretS3Credentials([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogConfig {
    #[serde(default)]
    pub backend: MetadataBackend,
    #[serde(default = "default_catalog_path")]
    pub path: PathBuf,
    #[serde(default = "default_preview_chars")]
    pub prompt_preview_chars: usize,
    #[serde(default = "default_preview_chars")]
    pub output_preview_chars: usize,
    #[serde(default = "default_true")]
    pub full_text_search: bool,
    #[serde(default, skip_serializing_if = "PostgresCatalogConfig::is_default")]
    pub postgres: PostgresCatalogConfig,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataBackend {
    #[default]
    Sqlite,
    Postgres,
}

impl MetadataBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresCatalogConfig {
    #[serde(default)]
    pub ssl_mode: PostgresSslMode,
    #[serde(default = "default_postgres_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_postgres_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_postgres_acquire_timeout_seconds")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "default_postgres_migration_lock_timeout_seconds")]
    pub migration_lock_timeout_seconds: u64,
}

impl Default for PostgresCatalogConfig {
    fn default() -> Self {
        Self {
            ssl_mode: PostgresSslMode::VerifyFull,
            max_connections: default_postgres_max_connections(),
            connect_timeout_seconds: default_postgres_connect_timeout_seconds(),
            acquire_timeout_seconds: default_postgres_acquire_timeout_seconds(),
            migration_lock_timeout_seconds: default_postgres_migration_lock_timeout_seconds(),
        }
    }
}

impl PostgresCatalogConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    /// Test-only or explicitly trusted local networks. Bytes are plaintext.
    Disable,
    /// Encrypts the connection without validating the server hostname.
    Require,
    /// Encrypts and validates the server certificate and hostname.
    #[default]
    VerifyFull,
}

/// A PostgreSQL connection URL whose debug output never contains credentials.
pub(crate) struct SecretDatabaseUrl(String);

impl SecretDatabaseUrl {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretDatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretDatabaseUrl([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    #[serde(default = "ProviderConfig::openai")]
    pub openai: ProviderConfig,
    #[serde(default = "ProviderConfig::codex")]
    pub codex: ProviderConfig,
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
            cluster: ClusterConfig::default(),
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
            backend: ArtifactStorageBackend::Filesystem,
            bundle_dir: default_bundle_dir(),
            finalized_dir: default_finalized_dir(),
            s3: None,
        }
    }
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            backend: MetadataBackend::Sqlite,
            path: default_catalog_path(),
            prompt_preview_chars: default_preview_chars(),
            output_preview_chars: default_preview_chars(),
            full_text_search: true,
            postgres: PostgresCatalogConfig::default(),
        }
    }
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            openai: ProviderConfig::openai(),
            codex: ProviderConfig::codex(),
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

    fn codex() -> Self {
        Self {
            enabled: true,
            route_prefix: "/codex".to_owned(),
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

    /// Loads only enough configuration for the one-shot metadata migrator.
    /// Unrelated listener, vault, provider, and notary settings are neither
    /// initialized nor validated by that command.
    pub(crate) fn load_for_metadata_migration(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("reading agent configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("parsing agent configuration {}", path.display()))?;
        ensure!(
            config.format == CONFIG_FORMAT,
            "unsupported agent configuration format: {}",
            config.format
        );
        config.validate_metadata()?;
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
        if self.cluster.enabled {
            self.validate_cluster()?;
        } else {
            ensure!(
                self.proxy.listen.ip().is_loopback(),
                "proxy.listen must use a loopback address outside cluster mode"
            );
            ensure!(
                self.admin.listen.ip().is_loopback(),
                "admin.listen must use a loopback address outside cluster mode"
            );
            ensure!(
                self.cluster.instance_id.is_none()
                    && !self.cluster.trusted_ingress
                    && self.cluster.vault_compatibility_sha256.is_none(),
                "cluster-only settings require cluster.enabled = true"
            );
        }
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
        self.validate_metadata()?;
        self.validate_storage()?;

        let routes = [
            ("openai", &self.providers.openai),
            ("codex", &self.providers.codex),
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

    fn validate_cluster(&self) -> Result<()> {
        let instance_id =
            self.cluster.instance_id.as_deref().ok_or_else(|| {
                anyhow::anyhow!("cluster.instance_id is required in cluster mode")
            })?;
        ensure!(
            !instance_id.is_empty()
                && instance_id.len() <= 64
                && instance_id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                }),
            "cluster.instance_id must contain 1 to 64 safe ASCII bytes"
        );
        ensure!(
            (1..=60).contains(&self.cluster.heartbeat_interval_seconds),
            "cluster.heartbeat_interval_seconds must be between 1 and 60"
        );
        ensure!(
            (3..=300).contains(&self.cluster.lease_seconds)
                && self.cluster.lease_seconds
                    >= self.cluster.heartbeat_interval_seconds.saturating_mul(3),
            "cluster.lease_seconds must be between 3 and 300 and at least three heartbeat intervals"
        );
        ensure!(
            self.cluster.claim_max_runtime_seconds >= self.cluster.lease_seconds
                && self.cluster.claim_max_runtime_seconds <= 86_400,
            "cluster.claim_max_runtime_seconds must be at least the lease and no more than 86400"
        );
        ensure!(
            (1..=120).contains(&self.cluster.withdrawal_delay_seconds),
            "cluster.withdrawal_delay_seconds must be between 1 and 120"
        );
        ensure!(
            self.cluster.shutdown_grace_seconds >= self.cluster.withdrawal_delay_seconds
                && self.cluster.shutdown_grace_seconds <= 3_600,
            "cluster.shutdown_grace_seconds must be at least the withdrawal delay and no more than 3600"
        );
        ensure!(
            self.catalog.backend == MetadataBackend::Postgres,
            "cluster mode requires catalog.backend = \"postgres\""
        );
        ensure!(
            self.storage.backend == ArtifactStorageBackend::S3,
            "cluster mode requires storage.backend = \"s3\""
        );
        ensure!(
            self.admin.auth.is_some(),
            "cluster mode requires admin authentication"
        );
        ensure!(
            self.cluster.trusted_ingress,
            "cluster mode requires cluster.trusted_ingress = true"
        );
        let vault_identity = self
            .cluster
            .vault_compatibility_sha256
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("cluster.vault_compatibility_sha256 is required in cluster mode")
            })?;
        ensure!(
            vault_identity.len() == 64
                && vault_identity.bytes().all(|byte| byte.is_ascii_hexdigit())
                && vault_identity == vault_identity.to_ascii_lowercase(),
            "cluster.vault_compatibility_sha256 must be 64 lowercase hexadecimal bytes"
        );
        Ok(())
    }

    fn validate_storage(&self) -> Result<()> {
        ensure!(
            !self.storage.bundle_dir.as_os_str().is_empty(),
            "storage.bundle_dir must not be empty"
        );
        ensure!(
            !self.storage.finalized_dir.as_os_str().is_empty(),
            "storage.finalized_dir must not be empty"
        );
        if self.storage.backend == ArtifactStorageBackend::S3 {
            ensure!(
                self.storage.s3.is_some(),
                "storage.s3 is required when storage.backend = \"s3\""
            );
        }
        if let Some(s3) = &self.storage.s3 {
            s3.artifact_store_config()?;
        }
        Ok(())
    }

    fn validate_metadata(&self) -> Result<()> {
        match self.catalog.backend {
            MetadataBackend::Sqlite => {
                ensure!(
                    !self.catalog.path.as_os_str().is_empty(),
                    "catalog.path must not be empty for the SQLite backend"
                );
                ensure!(
                    self.catalog.postgres.is_default(),
                    "non-default catalog.postgres settings require catalog.backend = \"postgres\""
                );
            }
            MetadataBackend::Postgres => {
                let postgres = &self.catalog.postgres;
                ensure!(
                    (1..=64).contains(&postgres.max_connections),
                    "catalog.postgres.max_connections must be between 1 and 64"
                );
                ensure!(
                    (1..=300).contains(&postgres.connect_timeout_seconds),
                    "catalog.postgres.connect_timeout_seconds must be between 1 and 300"
                );
                ensure!(
                    (1..=300).contains(&postgres.acquire_timeout_seconds),
                    "catalog.postgres.acquire_timeout_seconds must be between 1 and 300"
                );
                ensure!(
                    (1..=300).contains(&postgres.migration_lock_timeout_seconds),
                    "catalog.postgres.migration_lock_timeout_seconds must be between 1 and 300"
                );
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

    /// Returns the non-secret compatibility identity pinned by the cluster
    /// migrator. The replica slot name is intentionally excluded; every other
    /// configured trust, storage, listener, and lease setting must agree.
    pub fn cluster_compatibility_sha256(&self) -> Result<String> {
        self.cluster_compatibility_sha256_for_api_origin(crate::cli::DEFAULT_PUBLIC_ORIGIN)
    }

    /// Includes the normalized hosted API origin because it is the authority
    /// from which replicas advance shared notary trust and request admission.
    pub fn cluster_compatibility_sha256_for_api_origin(&self, api_origin: &str) -> Result<String> {
        ensure!(self.cluster.enabled, "cluster mode is not enabled");
        let mut normalized = self.clone();
        normalized.cluster.instance_id = None;
        let normalized = toml::to_string(&normalized)?;
        Ok(sha256_hex(
            format!("llm-notary-cluster/v1\n{normalized}\napi-origin={api_origin}\n").as_bytes(),
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

    pub(crate) fn s3_credentials(&self) -> Result<SecretS3Credentials> {
        ensure!(
            self.storage.s3.is_some(),
            "S3 artifact storage is not configured"
        );
        let access_key_id = resolve_secret_value(
            env::var_os(ARTIFACT_S3_ACCESS_KEY_ID_ENV),
            env::var_os(ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV),
            ARTIFACT_S3_ACCESS_KEY_ID_ENV,
            ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV,
        )?;
        let secret_access_key = resolve_secret_value(
            env::var_os(ARTIFACT_S3_SECRET_ACCESS_KEY_ENV),
            env::var_os(ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV),
            ARTIFACT_S3_SECRET_ACCESS_KEY_ENV,
            ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV,
        )?;
        let session_token = resolve_optional_secret_value(
            env::var_os(ARTIFACT_S3_SESSION_TOKEN_ENV),
            env::var_os(ARTIFACT_S3_SESSION_TOKEN_FILE_ENV),
            ARTIFACT_S3_SESSION_TOKEN_ENV,
            ARTIFACT_S3_SESSION_TOKEN_FILE_ENV,
        )?;
        Ok(SecretS3Credentials {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
    pub(crate) fn postgres_runtime_url(&self) -> Result<SecretDatabaseUrl> {
        ensure!(
            self.catalog.backend == MetadataBackend::Postgres,
            "PostgreSQL metadata is not selected"
        );
        resolve_database_url(
            env::var_os(METADATA_DATABASE_URL_ENV),
            env::var_os(METADATA_DATABASE_URL_FILE_ENV),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
    }

    pub(crate) fn postgres_migration_url(&self) -> Result<SecretDatabaseUrl> {
        ensure!(
            self.catalog.backend == MetadataBackend::Postgres,
            "PostgreSQL metadata is not selected"
        );
        resolve_migration_database_url(
            env::var_os(METADATA_DATABASE_URL_ENV),
            env::var_os(METADATA_DATABASE_URL_FILE_ENV),
            env::var_os(METADATA_MIGRATION_URL_ENV),
            env::var_os(METADATA_MIGRATION_URL_FILE_ENV),
        )
    }
}

fn resolve_migration_database_url(
    runtime_inline: Option<OsString>,
    runtime_file: Option<OsString>,
    migration_inline: Option<OsString>,
    migration_file: Option<OsString>,
) -> Result<SecretDatabaseUrl> {
    if migration_inline.is_none() && migration_file.is_none() {
        return resolve_database_url(
            runtime_inline,
            runtime_file,
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        );
    }
    resolve_database_url(
        migration_inline,
        migration_file,
        METADATA_MIGRATION_URL_ENV,
        METADATA_MIGRATION_URL_FILE_ENV,
    )
}

fn resolve_database_url(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<SecretDatabaseUrl> {
    let value = resolve_secret_value(inline, file, inline_name, file_name)?;
    let parsed = url::Url::parse(&value).context("PostgreSQL metadata URL is invalid")?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql"),
        "PostgreSQL metadata URL must use postgres:// or postgresql://"
    );
    Ok(SecretDatabaseUrl(value))
}

fn resolve_optional_secret_value(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<Option<String>> {
    if inline.is_none() && file.is_none() {
        return Ok(None);
    }
    resolve_secret_value(inline, file, inline_name, file_name).map(Some)
}

fn resolve_secret_value(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<String> {
    const MAX_SECRET_BYTES: usize = 16 * 1024;

    // The direct value intentionally wins and prevents the file path from
    // being opened. This also makes mounted-secret rotations deterministic.
    let value = if let Some(value) = inline {
        value
            .into_string()
            .map_err(|_| anyhow::anyhow!("{inline_name} is not valid UTF-8"))?
    } else if let Some(path) = file {
        let path = PathBuf::from(path);
        let file = fs::File::open(&path)
            .with_context(|| format!("reading secret file from {file_name}"))?;
        ensure!(
            file.metadata()
                .with_context(|| format!("inspecting secret file from {file_name}"))?
                .is_file(),
            "secret source from {file_name} must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_SECRET_BYTES + 1).expect("secret limit fits in u64"))
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading secret file from {file_name}"))?;
        ensure!(bytes.len() <= MAX_SECRET_BYTES, "secret file is too large");
        let mut value = String::from_utf8(bytes).context("secret file is not UTF-8")?;
        if value.ends_with("\r\n") {
            value.truncate(value.len() - 2);
        } else if value.ends_with('\n') {
            value.pop();
        }
        value
    } else {
        bail!("set {inline_name} or {file_name}");
    };
    ensure!(!value.is_empty(), "secret value is empty");
    ensure!(value.len() <= MAX_SECRET_BYTES, "secret value is too large");
    ensure!(
        !value
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0')),
        "secret value contains invalid control characters"
    );
    Ok(value)
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

fn default_cluster_heartbeat_seconds() -> u64 {
    5
}

fn default_cluster_lease_seconds() -> u64 {
    20
}

fn default_cluster_claim_max_runtime_seconds() -> u64 {
    3_600
}

fn default_cluster_withdrawal_delay_seconds() -> u64 {
    8
}

fn default_cluster_shutdown_grace_seconds() -> u64 {
    120
}

fn default_postgres_max_connections() -> u32 {
    8
}

fn default_postgres_connect_timeout_seconds() -> u64 {
    10
}

fn default_postgres_acquire_timeout_seconds() -> u64 {
    10
}

fn default_postgres_migration_lock_timeout_seconds() -> u64 {
    60
}

fn default_s3_prefix() -> String {
    "llm-notary".to_owned()
}

fn default_s3_region() -> String {
    "us-east-1".to_owned()
}

fn default_s3_connect_timeout_seconds() -> u64 {
    10
}

fn default_s3_operation_timeout_seconds() -> u64 {
    30
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
        assert!(config.providers.codex.enabled);
        assert!(config.providers.anthropic.enabled);
        assert!(config.providers.deepseek.enabled);
        assert!(config.providers.openrouter.enabled);
        assert_eq!(config.catalog.prompt_preview_chars, 1_000);
        assert!(config.catalog.full_text_search);
        assert_eq!(config.catalog.backend, MetadataBackend::Sqlite);
        assert_eq!(config.catalog.postgres, PostgresCatalogConfig::default());
        assert_eq!(config.storage.backend, ArtifactStorageBackend::Filesystem);
        assert!(config.storage.s3.is_none());
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
    fn cluster_profile_is_explicit_and_rejects_unsafe_combinations() {
        let mut config = AgentConfig::default();
        config.cluster.enabled = true;
        config.cluster.instance_id = Some("daemon-a".into());
        config.cluster.trusted_ingress = true;
        config.cluster.vault_compatibility_sha256 = Some("11".repeat(32));
        config.proxy.listen = "0.0.0.0:8787".parse().unwrap();
        config.admin.listen = "0.0.0.0:8788".parse().unwrap();
        config.admin.auth = Some(AdminAuthConfig {
            username: "cluster-admin".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$yJIR0lVleM2KSPdVmBvsQ9uhA06YIR8aPCbRDbNvXXQ".into(),
        });
        config.catalog.backend = MetadataBackend::Postgres;
        config.catalog.postgres = Some(PostgresCatalogConfig::default());
        config.storage.backend = ArtifactStorageBackend::S3;
        config.storage.s3 = Some(S3StorageConfig {
            bucket: "private-artifacts".into(),
            region: "us-east-1".into(),
            endpoint: "https://s3.example.test".into(),
            prefix: "cluster".into(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 5,
            operation_timeout_seconds: 10,
        });
        config.notary.endpoint = Some("tcp://notary.internal:7047".into());
        config.notary.public_key =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        config.validate().unwrap();

        let valid = config.clone();
        let compatibility = valid.cluster_compatibility_sha256().unwrap();
        let mut peer = valid.clone();
        peer.cluster.instance_id = Some("daemon-b".into());
        assert_eq!(peer.cluster_compatibility_sha256().unwrap(), compatibility);
        peer.storage.s3.as_mut().unwrap().prefix = "different".into();
        assert_ne!(peer.cluster_compatibility_sha256().unwrap(), compatibility);
        config.catalog.backend = MetadataBackend::Sqlite;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.storage.backend = ArtifactStorageBackend::Filesystem;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.admin.auth = None;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.cluster.trusted_ingress = false;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.notary.endpoint = None;
        config.notary.public_key = None;
        config.validate().unwrap();
        assert_ne!(
            config.cluster_compatibility_sha256().unwrap(),
            valid.cluster_compatibility_sha256().unwrap()
        );
        config = valid;
        config.cluster.lease_seconds = config.cluster.heartbeat_interval_seconds * 2;
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
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert!(!encoded.contains("[catalog.postgres]"));
        let parsed: AgentConfig = toml::from_str(&encoded).unwrap();
        parsed.validate().unwrap();
    }

    #[test]
    fn postgres_configuration_is_explicit_and_bounded() {
        let mut config = AgentConfig::default();
        config.catalog.backend = MetadataBackend::Postgres;
        config.validate().unwrap();
        assert_eq!(
            config.catalog.postgres.ssl_mode,
            PostgresSslMode::VerifyFull,
            "remote PostgreSQL connections must verify certificates and hostnames by default"
        );
        config.catalog.postgres.max_connections = 0;
        assert!(config.validate().is_err());

        config.catalog.backend = MetadataBackend::Sqlite;
        assert!(config.validate().is_err());
    }

    #[test]
    fn minimal_postgres_configuration_uses_safe_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            format!("format = {CONFIG_FORMAT:?}\n\n[catalog]\nbackend = \"postgres\"\n"),
        )
        .unwrap();

        let config = AgentConfig::load_for_metadata_migration(&path).unwrap();
        assert_eq!(config.catalog.backend, MetadataBackend::Postgres);
        assert_eq!(config.catalog.postgres, PostgresCatalogConfig::default());
    }

    #[test]
    fn s3_configuration_is_explicit_secure_and_bounded() {
        let mut config = AgentConfig::default();
        config.storage.backend = ArtifactStorageBackend::S3;
        assert!(config.validate().is_err());

        config.storage.s3 = Some(S3StorageConfig {
            bucket: "llm-notary-artifacts".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint: None,
            prefix: "tenant/daemon".to_owned(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 10,
            operation_timeout_seconds: 30,
        });
        config.validate().unwrap();

        let s3 = config.storage.s3.as_mut().unwrap();
        s3.endpoint = Some("http://minio:9000".to_owned());
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().allow_insecure_http = true;
        config.validate().unwrap();

        config.storage.s3.as_mut().unwrap().prefix = "../other-tenant".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = "tenant/daemon/".to_owned();
        config.validate().unwrap();
        config.storage.s3.as_mut().unwrap().prefix = "tenant//daemon".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = "tenant daemon".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = String::new();
        config.validate().unwrap();
        config.storage.s3.as_mut().unwrap().prefix = "tenant/daemon".to_owned();
        config.storage.s3.as_mut().unwrap().bucket = "bucket/escape".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().bucket = "llm-notary-artifacts".to_owned();
        config.storage.s3.as_mut().unwrap().region = "region\nother".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().region = "us-east-1".to_owned();
        config
            .storage
            .s3
            .as_mut()
            .unwrap()
            .operation_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn minimal_s3_configuration_uses_aws_defaults() {
        let encoded = format!(
            "format = {CONFIG_FORMAT:?}\n\n[storage]\nbackend = \"s3\"\n\n[storage.s3]\nbucket = \"private-artifacts\"\n"
        );
        let config: AgentConfig = toml::from_str(&encoded).unwrap();
        config.validate().unwrap();
        let s3 = config.storage.s3.unwrap();
        assert_eq!(s3.region, "us-east-1");
        assert!(s3.endpoint.is_none());
        assert_eq!(s3.prefix, "llm-notary");
        assert!(!s3.force_path_style);
        assert!(!s3.allow_insecure_http);
    }

    #[test]
    fn filesystem_can_retain_an_s3_read_profile() {
        let mut config = AgentConfig::default();
        config.storage.s3 = Some(S3StorageConfig {
            bucket: "llm-notary-artifacts".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint: Some("https://s3.example.test".to_owned()),
            prefix: "llm-notary".to_owned(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 10,
            operation_timeout_seconds: 30,
        });
        config.validate().unwrap();
    }

    #[test]
    fn inline_database_url_precedes_the_file_source_and_debug_is_redacted() {
        let secret = resolve_database_url(
            Some("postgres://operator:secret@database/daemon".into()),
            Some("/a/path/that/must/not/be/read".into()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap();
        assert_eq!(
            secret.expose(),
            "postgres://operator:secret@database/daemon"
        );
        assert_eq!(format!("{secret:?}"), "SecretDatabaseUrl([REDACTED])");
    }

    #[test]
    fn migration_url_defaults_to_runtime_and_allows_a_privileged_override() {
        let shared = resolve_migration_database_url(
            Some("postgres://runtime/database".into()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(shared.expose(), "postgres://runtime/database");

        let separate = resolve_migration_database_url(
            Some("postgres://runtime/database".into()),
            None,
            Some("postgres://migrator/database".into()),
            Some("/a/path/that/must/not/be/read".into()),
        )
        .unwrap();
        assert_eq!(separate.expose(), "postgres://migrator/database");
    }

    #[test]
    fn artifact_credentials_are_redacted_and_inline_values_skip_files() {
        let access_key = resolve_secret_value(
            Some("access-canary".into()),
            Some("/a/path/that/must/not/be/read".into()),
            ARTIFACT_S3_ACCESS_KEY_ID_ENV,
            ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV,
        )
        .unwrap();
        let credentials = SecretS3Credentials {
            access_key_id: access_key,
            secret_access_key: "secret-canary".to_owned(),
            session_token: Some("session-canary".to_owned()),
        };
        assert_eq!(credentials.access_key_id(), "access-canary");
        assert_eq!(credentials.secret_access_key(), "secret-canary");
        assert_eq!(credentials.session_token(), Some("session-canary"));
        let debug = format!("{credentials:?}");
        assert_eq!(debug, "SecretS3Credentials([REDACTED])");
        assert!(!debug.contains("canary"));
        assert!(
            resolve_optional_secret_value(None, None, "DIRECT", "FILE")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn database_url_file_trims_only_one_line_ending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database-url");
        fs::write(&path, b"postgres://database/daemon\r\n").unwrap();
        let secret = resolve_database_url(
            None,
            Some(path.into_os_string()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap();
        assert_eq!(secret.expose(), "postgres://database/daemon");
    }

    #[test]
    fn database_url_failures_do_not_echo_secrets_or_secret_paths() {
        let inline_canary = "postgres://operator:canary-password@[invalid";
        let inline_error = resolve_database_url(
            Some(inline_canary.into()),
            None,
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap_err();
        assert!(!format!("{inline_error:#}").contains(inline_canary));

        let path_canary = "/does/not/exist/canary-database-secret";
        let file_error = resolve_database_url(
            None,
            Some(path_canary.into()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap_err();
        assert!(!format!("{file_error:#}").contains(path_canary));
    }
}
