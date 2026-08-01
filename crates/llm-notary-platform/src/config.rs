use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use sqlx::postgres::PgConnectOptions;
use url::Url;

use llm_notary_core::notary_directory::{
    DIRECTORY_FORMAT_V3, NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus, NotaryTransport,
    key_id, parse_directory,
};

pub(crate) const DEFAULT_DATABASE_MAX_CONNECTIONS: u32 = 5;
const MAX_DATABASE_CONNECTIONS: u32 = 64;
pub(crate) const DEFAULT_MAX_ARCHIVE_BYTES: i64 = 128 * 1024 * 1024;
pub(crate) const DEFAULT_UPLOAD_TTL_SECS: i64 = 15 * 60;
pub(crate) const DEFAULT_METADATA_MODEL: &str = "gpt-5.6-luna";
pub(crate) const DEFAULT_METADATA_WEEKLY_BUDGET_CENTS: i64 = 1_000;
pub(crate) const DEFAULT_METADATA_INPUT_NANOUSD_PER_TOKEN: i64 = 200;
pub(crate) const DEFAULT_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN: i64 = 20;
pub(crate) const DEFAULT_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN: i64 = 250;
pub(crate) const DEFAULT_METADATA_OUTPUT_NANOUSD_PER_TOKEN: i64 = 1_200;
pub(crate) const NANOUSD_PER_CENT: i64 = 10_000_000;

/// Validated runtime configuration for the hosted platform API.
///
/// Configuration is read from the environment exactly once, before startup
/// opens network connections or starts background workers.
pub struct PlatformConfig {
    pub listen: SocketAddr,
    pub idle_shutdown_secs: Option<u64>,
    pub auth: AuthConfig,
    pub database: DatabaseConfig,
    pub notary_directory: NotaryDirectoryConfig,
    pub storage: StorageConfig,
    pub metadata: Option<MetadataConfig>,
}

/// GitHub OAuth and public-origin configuration.
pub struct AuthConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    pub app_url: Url,
    pub callback_url: Url,
}

/// PostgreSQL connection-pool configuration for the API.
pub struct DatabaseConfig {
    pub connect_options: PgConnectOptions,
    pub max_connections: u32,
}

/// The verified notary directory advertised by the API.
pub struct NotaryDirectoryConfig {
    pub directory: NotaryDirectory,
}

/// Publication intake and public-artifact storage configuration.
pub struct StorageConfig {
    pub max_archive_bytes: i64,
    pub upload_ttl_secs: i64,
    pub s3: Option<S3StorageConfig>,
    pub platform_signing_key_file: Option<PathBuf>,
}

/// Settings for an S3-compatible intake bucket.
pub struct S3StorageConfig {
    pub bucket: String,
    pub endpoint: Url,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub prefix: String,
    pub force_path_style: bool,
}

/// Optional OpenAI configuration for generating Library metadata.
pub struct MetadataConfig {
    pub api_key: String,
    pub model: String,
    pub weekly_budget_nanousd: i64,
    pub input_nanousd_per_token: i64,
    pub cached_input_nanousd_per_token: i64,
    pub cache_write_nanousd_per_token: i64,
    pub output_nanousd_per_token: i64,
}

impl PlatformConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen: socket_addr_or_default("LLM_NOTARY_API_LISTEN", "127.0.0.1:8080")?,
            idle_shutdown_secs: optional_idle_shutdown_secs()?,
            auth: AuthConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            notary_directory: NotaryDirectoryConfig::from_env()?,
            storage: StorageConfig::from_env()?,
            metadata: MetadataConfig::from_env()?,
        })
    }
}

impl AuthConfig {
    fn from_env() -> Result<Self> {
        let app_url = Url::parse(&env_or_default(
            "LLM_NOTARY_PUBLIC_ORIGIN",
            "http://localhost:4173",
        )?)
        .context("LLM_NOTARY_PUBLIC_ORIGIN must be an absolute URL")?;
        if app_url.path() != "/" || app_url.query().is_some() || app_url.fragment().is_some() {
            bail!("LLM_NOTARY_PUBLIC_ORIGIN must be an origin without a path, query, or fragment");
        }
        let callback_url = app_url
            .join("/api/auth/github/callback")
            .context("building GitHub OAuth callback URL")?;
        Ok(Self {
            github_client_id: required_env("GITHUB_OAUTH_CLIENT_ID")?,
            github_client_secret: required_env("GITHUB_OAUTH_CLIENT_SECRET")?,
            app_url,
            callback_url,
        })
    }
}

impl DatabaseConfig {
    fn from_env() -> Result<Self> {
        let connect_options = required_env("DATABASE_URL")?
            .parse::<PgConnectOptions>()
            .context("DATABASE_URL must be a PostgreSQL connection URL")?;
        Ok(Self {
            connect_options,
            max_connections: database_max_connections()?,
        })
    }
}

impl NotaryDirectoryConfig {
    fn from_env() -> Result<Self> {
        if let Some(value) = optional_env("LLM_NOTARY_NOTARY_DIRECTORY_JSON")? {
            let directory = parse_directory(value.as_bytes())
                .context("LLM_NOTARY_NOTARY_DIRECTORY_JSON is invalid")?;
            if let Ok(expected) = env::var("LLM_NOTARY_NOTARY_PUBLIC_KEY")
                && !directory
                    .active()?
                    .public_key
                    .eq_ignore_ascii_case(expected.trim())
            {
                bail!("the active directory key does not match LLM_NOTARY_NOTARY_PUBLIC_KEY");
            }
            return Ok(Self { directory });
        }

        let public_key = hex::decode(required_env("LLM_NOTARY_NOTARY_PUBLIC_KEY")?)
            .context("LLM_NOTARY_NOTARY_PUBLIC_KEY must be hexadecimal")?;
        let key_id = key_id(&public_key);
        let directory = NotaryDirectory {
            format: DIRECTORY_FORMAT_V3.to_owned(),
            generation: env_or_default("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION", "1")?
                .parse()
                .context("LLM_NOTARY_NOTARY_DIRECTORY_GENERATION must be a u64")?,
            active_key_id: key_id.clone(),
            notaries: vec![NotaryDirectoryRecord {
                host: env_or_default("LLM_NOTARY_NOTARY_HOST", "127.0.0.1")?,
                port: env_or_default("LLM_NOTARY_NOTARY_PORT", "7047")?
                    .parse::<u16>()
                    .context("LLM_NOTARY_NOTARY_PORT must be a valid TCP port")?,
                transport: env_or_default("LLM_NOTARY_NOTARY_TRANSPORT", "tcp")?
                    .parse::<NotaryTransport>()
                    .context("LLM_NOTARY_NOTARY_TRANSPORT must be tcp or tls")?,
                key_id,
                public_key: hex::encode(public_key),
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: env_or_default("LLM_NOTARY_NOTARY_VALID_FROM_UNIX_MS", "0")?
                    .parse()
                    .context("LLM_NOTARY_NOTARY_VALID_FROM_UNIX_MS must be a u64")?,
                valid_until_unix_ms: None,
                finalize_until_unix_ms: None,
            }],
        };
        directory.validate()?;
        Ok(Self { directory })
    }
}

impl StorageConfig {
    pub(crate) fn from_env() -> Result<Self> {
        let max_archive_bytes =
            integer_or_default("LLM_NOTARY_INTAKE_MAX_BYTES", DEFAULT_MAX_ARCHIVE_BYTES)?;
        if max_archive_bytes <= 0 {
            bail!("LLM_NOTARY_INTAKE_MAX_BYTES must be positive");
        }
        let upload_ttl_secs =
            integer_or_default("LLM_NOTARY_INTAKE_UPLOAD_TTL_SECS", DEFAULT_UPLOAD_TTL_SECS)?;
        if !(60..=24 * 60 * 60).contains(&upload_ttl_secs) {
            bail!("LLM_NOTARY_INTAKE_UPLOAD_TTL_SECS must be between 60 and 86400 seconds");
        }

        // The LLM_NOTARY_* names are portable production configuration. The
        // AWS names support Fly Tigris buckets without copying credentials.
        let s3 = first_env(&["LLM_NOTARY_S3_BUCKET", "BUCKET_NAME"])?
            .map(|bucket| {
                validate_bucket(&bucket)?;
                let endpoint =
                    required_first_env(&["LLM_NOTARY_S3_ENDPOINT", "AWS_ENDPOINT_URL_S3"])?;
                let endpoint = validate_endpoint(&endpoint)?;
                let prefix = env_or_default("LLM_NOTARY_S3_PREFIX", "llm-notary")?;
                validate_prefix(&prefix)?;
                Ok::<_, anyhow::Error>(S3StorageConfig {
                    bucket,
                    endpoint,
                    region: required_first_env(&["LLM_NOTARY_S3_REGION", "AWS_REGION"])?,
                    access_key_id: required_first_env(&[
                        "LLM_NOTARY_S3_ACCESS_KEY_ID",
                        "AWS_ACCESS_KEY_ID",
                    ])?,
                    secret_access_key: required_first_env(&[
                        "LLM_NOTARY_S3_SECRET_ACCESS_KEY",
                        "AWS_SECRET_ACCESS_KEY",
                    ])?,
                    prefix: prefix.trim_matches('/').to_owned(),
                    force_path_style: bool_or_default("LLM_NOTARY_S3_FORCE_PATH_STYLE", true)?,
                })
            })
            .transpose()?;
        let platform_signing_key_file = s3
            .is_some()
            .then(|| required_env("LLM_NOTARY_PLATFORM_SIGNING_KEY_FILE").map(PathBuf::from))
            .transpose()?;

        Ok(Self {
            max_archive_bytes,
            upload_ttl_secs,
            s3,
            platform_signing_key_file,
        })
    }
}

impl MetadataConfig {
    fn from_env() -> Result<Option<Self>> {
        let model = env_or_default("LLM_NOTARY_LIBRARY_METADATA_MODEL", DEFAULT_METADATA_MODEL)?;
        if model.trim().is_empty() {
            bail!("LLM_NOTARY_LIBRARY_METADATA_MODEL must not be empty");
        }
        let weekly_budget_nanousd = positive_integer_or_default(
            "LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS",
            DEFAULT_METADATA_WEEKLY_BUDGET_CENTS,
        )?
        .saturating_mul(NANOUSD_PER_CENT);
        let input_nanousd_per_token = positive_integer_or_default(
            "LLM_NOTARY_LIBRARY_METADATA_INPUT_NANOUSD_PER_TOKEN",
            DEFAULT_METADATA_INPUT_NANOUSD_PER_TOKEN,
        )?;
        let cached_input_nanousd_per_token = positive_integer_or_default(
            "LLM_NOTARY_LIBRARY_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN",
            DEFAULT_METADATA_CACHED_INPUT_NANOUSD_PER_TOKEN,
        )?;
        let cache_write_nanousd_per_token = positive_integer_or_default(
            "LLM_NOTARY_LIBRARY_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN",
            DEFAULT_METADATA_CACHE_WRITE_NANOUSD_PER_TOKEN,
        )?;
        let output_nanousd_per_token = positive_integer_or_default(
            "LLM_NOTARY_LIBRARY_METADATA_OUTPUT_NANOUSD_PER_TOKEN",
            DEFAULT_METADATA_OUTPUT_NANOUSD_PER_TOKEN,
        )?;
        let Some(api_key) = optional_env("OPENAI_API_KEY")? else {
            return Ok(None);
        };
        Ok(Some(Self {
            api_key,
            model,
            weekly_budget_nanousd,
            input_nanousd_per_token,
            cached_input_nanousd_per_token,
            cache_write_nanousd_per_token,
            output_nanousd_per_token,
        }))
    }
}

fn required_env(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} must be set"))?;
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn env_or_default(name: &str, default: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(error) => Err(error).with_context(|| format!("reading {name}")),
    }
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok((!value.trim().is_empty()).then(|| value.trim().to_owned())),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {name}")),
    }
}

fn first_env(names: &[&str]) -> Result<Option<String>> {
    for name in names {
        if let Some(value) = optional_env(name)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn required_first_env(names: &[&str]) -> Result<String> {
    first_env(names)?.ok_or_else(|| {
        anyhow!(
            "one of {} must be set when S3-compatible intake storage is enabled",
            names.join(", ")
        )
    })
}

fn socket_addr_or_default(name: &str, default: &str) -> Result<SocketAddr> {
    env_or_default(name, default)?
        .parse()
        .with_context(|| format!("{name} must be a socket address"))
}

fn optional_idle_shutdown_secs() -> Result<Option<u64>> {
    optional_env("LLM_NOTARY_IDLE_SHUTDOWN_SECS")?
        .map(|value| parse_idle_shutdown_secs(&value))
        .transpose()
}

fn parse_idle_shutdown_secs(value: &str) -> Result<u64> {
    let seconds = value
        .parse::<u64>()
        .context("LLM_NOTARY_IDLE_SHUTDOWN_SECS must be a positive integer")?;
    if seconds == 0 {
        bail!("LLM_NOTARY_IDLE_SHUTDOWN_SECS must be a positive integer");
    }
    Ok(seconds)
}

fn database_max_connections() -> Result<u32> {
    let connections = env_or_default(
        "LLM_NOTARY_DATABASE_MAX_CONNECTIONS",
        &DEFAULT_DATABASE_MAX_CONNECTIONS.to_string(),
    )?
    .parse::<u32>()
    .context("LLM_NOTARY_DATABASE_MAX_CONNECTIONS must be an integer")?;
    if connections == 0 || connections > MAX_DATABASE_CONNECTIONS {
        bail!(
            "LLM_NOTARY_DATABASE_MAX_CONNECTIONS must be between 1 and {MAX_DATABASE_CONNECTIONS}"
        );
    }
    Ok(connections)
}

fn integer_or_default(name: &str, default: i64) -> Result<i64> {
    env_or_default(name, &default.to_string())?
        .parse::<i64>()
        .with_context(|| format!("{name} must be an integer"))
}

fn positive_integer_or_default(name: &str, default: i64) -> Result<i64> {
    let value = env_or_default(name, &default.to_string())?;
    parse_positive_integer(name, &value)
}

fn parse_positive_integer(name: &str, value: &str) -> Result<i64> {
    let value = value
        .parse::<i64>()
        .with_context(|| format!("{name} must be an integer"))?;
    if value <= 0 {
        bail!("{name} must be positive");
    }
    Ok(value)
}

fn bool_or_default(name: &str, default: bool) -> Result<bool> {
    let Some(value) = optional_env(name)? else {
        return Ok(default);
    };
    match value.as_str() {
        "1" | "true" | "TRUE" => Ok(true),
        "0" | "false" | "FALSE" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

fn validate_endpoint(value: &str) -> Result<Url> {
    let endpoint = Url::parse(value).context("LLM_NOTARY_S3_ENDPOINT must be a URL")?;
    if endpoint.scheme() != "https"
        && !(endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost")))
    {
        bail!("LLM_NOTARY_S3_ENDPOINT must use HTTPS except for local test services");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("LLM_NOTARY_S3_ENDPOINT must not contain a query or fragment");
    }
    Ok(endpoint)
}

fn validate_bucket(bucket: &str) -> Result<()> {
    if !(3..=63).contains(&bucket.len())
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
    {
        bail!("LLM_NOTARY_S3_BUCKET is not a valid lowercase bucket name");
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<()> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty()
        || trimmed.len() > 120
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "..")
    {
        bail!("LLM_NOTARY_S3_PREFIX must be a safe, non-empty object prefix");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_numbers_must_be_positive_integers() {
        assert_eq!(
            parse_positive_integer("LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS", "5")
                .expect("positive number"),
            5
        );
        assert!(
            parse_positive_integer("LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS", "0").is_err()
        );
        assert!(
            parse_positive_integer("LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS", "-1")
                .is_err()
        );
        assert!(
            parse_positive_integer("LLM_NOTARY_LIBRARY_METADATA_WEEKLY_BUDGET_CENTS", "nope")
                .is_err()
        );
    }

    #[test]
    fn idle_shutdown_seconds_must_be_a_positive_integer() {
        assert_eq!(parse_idle_shutdown_secs("45").expect("valid duration"), 45);
        assert!(parse_idle_shutdown_secs("0").is_err());
        assert!(parse_idle_shutdown_secs("-1").is_err());
        assert!(parse_idle_shutdown_secs("soon").is_err());
    }
}
