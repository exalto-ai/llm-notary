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
pub(crate) const DEFAULT_MAX_ARCHIVE_BYTES: i64 =
    llm_notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64;
pub(crate) const DEFAULT_UPLOAD_TTL_SECS: i64 = 15 * 60;
pub(crate) const DEFAULT_ADMISSION_TICKET_TTL_SECS: i64 = 45;
pub(crate) const DEFAULT_ADMISSION_LEASE_TTL_SECS: i64 = 30;

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
    pub admission: AdmissionConfig,
}

/// Admission coordinator authentication and effective hosted-service policy.
#[derive(Clone)]
pub struct AdmissionConfig {
    pub service_token: String,
    pub ticket_ttl_secs: i64,
    pub lease_ttl_secs: i64,
    pub global_capture_concurrency: i64,
    pub global_finalize_concurrency: i64,
    pub public: TierPolicy,
    pub free: TierPolicy,
    pub paid_preview: TierPolicy,
}

#[derive(Clone, Debug)]
pub struct TierPolicy {
    pub capture_concurrency: i64,
    pub finalize_concurrency: i64,
    pub account_concurrency: Option<i64>,
    pub starts_per_minute: i64,
    pub session_timeout_secs: i64,
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub monthly_finalization_bytes: i64,
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

impl PlatformConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen: socket_addr_or_default("LLM_NOTARY_API_LISTEN", "127.0.0.1:8080")?,
            idle_shutdown_secs: optional_idle_shutdown_secs()?,
            auth: AuthConfig::from_env()?,
            database: DatabaseConfig::from_env()?,
            notary_directory: NotaryDirectoryConfig::from_env()?,
            storage: StorageConfig::from_env()?,
            admission: AdmissionConfig::from_env()?,
        })
    }
}

impl AdmissionConfig {
    fn from_env() -> Result<Self> {
        let service_token_file =
            PathBuf::from(required_env("LLM_NOTARY_ADMISSION_SERVICE_TOKEN_FILE")?);
        let service_token = std::fs::read_to_string(&service_token_file)
            .with_context(|| format!("reading {}", service_token_file.display()))?
            .trim()
            .to_owned();
        if service_token.len() < 32 || service_token.len() > 512 {
            bail!("admission service token must contain between 32 and 512 bytes");
        }
        let ticket_ttl_secs = positive_integer_or_default(
            "LLM_NOTARY_ADMISSION_TICKET_TTL_SECS",
            DEFAULT_ADMISSION_TICKET_TTL_SECS,
        )?;
        if !(10..=300).contains(&ticket_ttl_secs) {
            bail!("LLM_NOTARY_ADMISSION_TICKET_TTL_SECS must be between 10 and 300");
        }
        let lease_ttl_secs = positive_integer_or_default(
            "LLM_NOTARY_ADMISSION_LEASE_TTL_SECS",
            DEFAULT_ADMISSION_LEASE_TTL_SECS,
        )?;
        if !(10..=300).contains(&lease_ttl_secs) {
            bail!("LLM_NOTARY_ADMISSION_LEASE_TTL_SECS must be between 10 and 300");
        }
        Ok(Self {
            service_token,
            ticket_ttl_secs,
            lease_ttl_secs,
            global_capture_concurrency: positive_integer_or_default(
                "LLM_NOTARY_ADMISSION_GLOBAL_CAPTURE_CONCURRENCY",
                16,
            )?,
            global_finalize_concurrency: positive_integer_or_default(
                "LLM_NOTARY_ADMISSION_GLOBAL_FINALIZE_CONCURRENCY",
                4,
            )?,
            public: TierPolicy::from_env("PUBLIC", TierPolicy::public())?,
            free: TierPolicy::from_env("FREE", TierPolicy::free())?,
            paid_preview: TierPolicy::from_env("PAID_PREVIEW", TierPolicy::paid_preview())?,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            service_token: "test-service-token-that-is-long-enough".to_owned(),
            ticket_ttl_secs: DEFAULT_ADMISSION_TICKET_TTL_SECS,
            lease_ttl_secs: DEFAULT_ADMISSION_LEASE_TTL_SECS,
            global_capture_concurrency: 2,
            global_finalize_concurrency: 2,
            public: TierPolicy::public(),
            free: TierPolicy::free(),
            paid_preview: TierPolicy::paid_preview(),
        }
    }
}

impl TierPolicy {
    pub(crate) fn public() -> Self {
        Self {
            capture_concurrency: 1,
            finalize_concurrency: 1,
            account_concurrency: None,
            starts_per_minute: 12,
            session_timeout_secs: 5 * 60,
            max_attestable_http_bytes: 1 << 20,
            max_frame_bytes: 16 << 20,
            max_private_chunk_bytes: 64 << 10,
            max_private_chunk_commitments: 32,
            monthly_finalization_bytes: 64 << 20,
        }
    }

    pub(crate) fn free() -> Self {
        Self {
            capture_concurrency: 4,
            finalize_concurrency: 2,
            account_concurrency: Some(2),
            starts_per_minute: 60,
            session_timeout_secs: 15 * 60,
            max_attestable_http_bytes: 8 << 20,
            max_frame_bytes: 64 << 20,
            max_private_chunk_bytes: 128 << 10,
            max_private_chunk_commitments: 64,
            monthly_finalization_bytes: 512 << 20,
        }
    }

    pub(crate) fn paid_preview() -> Self {
        Self {
            capture_concurrency: 12,
            finalize_concurrency: 4,
            account_concurrency: Some(4),
            starts_per_minute: 240,
            session_timeout_secs: 30 * 60,
            max_attestable_http_bytes: 15 << 20,
            max_frame_bytes: 128 << 20,
            max_private_chunk_bytes: 128 << 10,
            max_private_chunk_commitments: 128,
            monthly_finalization_bytes: 5_i64 << 30,
        }
    }

    fn from_env(prefix: &str, defaults: Self) -> Result<Self> {
        let value = |suffix: &str, default: i64| {
            positive_integer_or_default(&format!("LLM_NOTARY_ADMISSION_{prefix}_{suffix}"), default)
        };
        let account_concurrency = defaults
            .account_concurrency
            .map(|default| value("ACCOUNT_CONCURRENCY", default))
            .transpose()?;
        Ok(Self {
            capture_concurrency: value("CAPTURE_CONCURRENCY", defaults.capture_concurrency)?,
            finalize_concurrency: value("FINALIZE_CONCURRENCY", defaults.finalize_concurrency)?,
            account_concurrency,
            starts_per_minute: value("STARTS_PER_MINUTE", defaults.starts_per_minute)?,
            session_timeout_secs: value("SESSION_TIMEOUT_SECS", defaults.session_timeout_secs)?,
            max_attestable_http_bytes: value(
                "MAX_ATTESTABLE_HTTP_BYTES",
                defaults.max_attestable_http_bytes,
            )?,
            max_frame_bytes: value("MAX_FRAME_BYTES", defaults.max_frame_bytes)?,
            max_private_chunk_bytes: value(
                "MAX_PRIVATE_CHUNK_BYTES",
                defaults.max_private_chunk_bytes,
            )?,
            max_private_chunk_commitments: value(
                "MAX_PRIVATE_CHUNK_COMMITMENTS",
                defaults.max_private_chunk_commitments,
            )?,
            monthly_finalization_bytes: value(
                "MONTHLY_FINALIZATION_BYTES",
                defaults.monthly_finalization_bytes,
            )?,
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
        validate_max_archive_bytes(max_archive_bytes)?;
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
        Ok(Self {
            max_archive_bytes,
            upload_ttl_secs,
            s3,
        })
    }
}

fn validate_max_archive_bytes(value: i64) -> Result<()> {
    if value <= 0 || value > llm_notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64 {
        bail!(
            "LLM_NOTARY_INTAKE_MAX_BYTES must be positive and no greater than {}",
            llm_notary_core::archive::MAX_ARCHIVE_WIRE_BYTES
        );
    }
    Ok(())
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
    fn idle_shutdown_seconds_must_be_a_positive_integer() {
        assert_eq!(parse_idle_shutdown_secs("45").expect("valid duration"), 45);
        assert!(parse_idle_shutdown_secs("0").is_err());
        assert!(parse_idle_shutdown_secs("-1").is_err());
        assert!(parse_idle_shutdown_secs("soon").is_err());
    }

    #[test]
    fn archive_limit_can_be_lower_but_never_exceed_the_wire_ceiling() {
        assert!(validate_max_archive_bytes(1).is_ok());
        assert!(validate_max_archive_bytes(DEFAULT_MAX_ARCHIVE_BYTES).is_ok());
        assert!(validate_max_archive_bytes(0).is_err());
        assert!(validate_max_archive_bytes(DEFAULT_MAX_ARCHIVE_BYTES + 1).is_err());
    }
}
