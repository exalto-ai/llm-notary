use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
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
    pub billing: BillingConfig,
}

/// Optional hosted-purchase configuration.
pub struct BillingConfig {
    pub stripe: Option<StripeConfig>,
}

/// Stripe secrets and the authoritative recurring-plan and credit Prices.
#[derive(Clone)]
pub struct StripeConfig {
    pub(crate) secret_key: String,
    pub(crate) webhook_secret: String,
    pub(crate) credit_price_id: String,
    pub(crate) one_gb_price_id: Option<String>,
    pub(crate) ten_gb_price_id: Option<String>,
    pub(crate) livemode: bool,
}

/// Admission coordinator authentication and effective hosted-service policy.
#[derive(Clone)]
pub struct AdmissionConfig {
    pub service_token: String,
    pub anonymous_subject_hmac_key: Vec<u8>,
    pub anonymous_subject_key_version: u32,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub ticket_ttl_secs: i64,
    pub public: AdmissionPolicy,
    pub free: AdmissionPolicy,
    pub one_gb: AdmissionPolicy,
    pub ten_gb: AdmissionPolicy,
}

#[derive(Clone, Debug)]
pub struct AdmissionPolicy {
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub monthly_notarization_bytes: i64,
    pub monthly_capture_bytes: i64,
}

/// Browser OAuth providers and public-origin configuration.
pub struct AuthConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub app_url: Url,
    pub github_callback_url: Url,
    pub google_callback_url: Url,
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
            billing: BillingConfig::from_env()?,
        })
    }
}

impl BillingConfig {
    fn from_env() -> Result<Self> {
        let secret_key = read_secret_setting(
            "LLM_NOTARY_STRIPE_SECRET_KEY",
            "LLM_NOTARY_STRIPE_SECRET_KEY_FILE",
        )?;
        let webhook_secret = read_secret_setting(
            "LLM_NOTARY_STRIPE_WEBHOOK_SECRET",
            "LLM_NOTARY_STRIPE_WEBHOOK_SECRET_FILE",
        )?;
        Self::from_settings(
            secret_key,
            webhook_secret,
            optional_env("LLM_NOTARY_STRIPE_CREDIT_PRICE_ID")?,
            optional_env("LLM_NOTARY_STRIPE_ONE_GB_PRICE_ID")?,
            optional_env("LLM_NOTARY_STRIPE_TEN_GB_PRICE_ID")?,
        )
    }

    fn from_settings(
        secret_key: Option<String>,
        webhook_secret: Option<String>,
        credit_price_id: Option<String>,
        one_gb_price_id: Option<String>,
        ten_gb_price_id: Option<String>,
    ) -> Result<Self> {
        if secret_key.is_none()
            && webhook_secret.is_none()
            && credit_price_id.is_none()
            && one_gb_price_id.is_none()
            && ten_gb_price_id.is_none()
        {
            return Ok(Self { stripe: None });
        }
        let secret_key = secret_key.ok_or_else(|| {
            anyhow!("LLM_NOTARY_STRIPE_SECRET_KEY or LLM_NOTARY_STRIPE_SECRET_KEY_FILE must be set")
        })?;
        let webhook_secret = webhook_secret.ok_or_else(|| {
            anyhow!(
                "LLM_NOTARY_STRIPE_WEBHOOK_SECRET or LLM_NOTARY_STRIPE_WEBHOOK_SECRET_FILE must be set"
            )
        })?;
        let credit_price_id = credit_price_id
            .ok_or_else(|| anyhow!("LLM_NOTARY_STRIPE_CREDIT_PRICE_ID must be set"))?;
        if one_gb_price_id.is_some() != ten_gb_price_id.is_some() {
            bail!(
                "LLM_NOTARY_STRIPE_ONE_GB_PRICE_ID and LLM_NOTARY_STRIPE_TEN_GB_PRICE_ID must be set together"
            );
        }
        let livemode = if secret_key.starts_with("sk_test_") {
            false
        } else if secret_key.starts_with("sk_live_") {
            true
        } else {
            bail!("Stripe secret key must be an sk_test_ or sk_live_ key");
        };
        if secret_key.len() > 256 {
            bail!("Stripe secret key is too long");
        }
        if !webhook_secret.starts_with("whsec_") || webhook_secret.len() > 256 {
            bail!("Stripe webhook secret must be a bounded whsec_ secret");
        }
        for (name, price_id) in [
            (
                "LLM_NOTARY_STRIPE_CREDIT_PRICE_ID",
                Some(credit_price_id.as_str()),
            ),
            (
                "LLM_NOTARY_STRIPE_ONE_GB_PRICE_ID",
                one_gb_price_id.as_deref(),
            ),
            (
                "LLM_NOTARY_STRIPE_TEN_GB_PRICE_ID",
                ten_gb_price_id.as_deref(),
            ),
        ] {
            if let Some(price_id) = price_id
                && (!price_id.starts_with("price_") || price_id.len() > 255)
            {
                bail!("{name} must be a bounded Stripe Price identifier");
            }
        }
        Ok(Self {
            stripe: Some(StripeConfig {
                secret_key,
                webhook_secret,
                credit_price_id,
                one_gb_price_id,
                ten_gb_price_id,
                livemode,
            }),
        })
    }
}

fn read_secret_setting(value_name: &str, file_name: &str) -> Result<Option<String>> {
    let value = optional_env(value_name)?;
    let path = optional_env(file_name)?;
    if value.is_some() && path.is_some() {
        bail!("{value_name} and {file_name} are mutually exclusive");
    }
    if value.is_some() {
        return Ok(value);
    }
    let Some(path) = path else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    let secret = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_owned();
    if secret.is_empty() {
        bail!("{} must not be empty", path.display());
    }
    Ok(Some(secret))
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
        let subject_key_file =
            PathBuf::from(required_env("LLM_NOTARY_ANONYMOUS_SUBJECT_HMAC_KEY_FILE")?);
        let anonymous_subject_hmac_key = std::fs::read(&subject_key_file)
            .with_context(|| format!("reading {}", subject_key_file.display()))?;
        if anonymous_subject_hmac_key.len() < 32 || anonymous_subject_hmac_key.len() > 512 {
            bail!("anonymous subject HMAC key must contain between 32 and 512 bytes");
        }
        let anonymous_subject_key_version =
            env_or_default("LLM_NOTARY_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION", "1")?
                .parse::<u32>()
                .context(
                    "LLM_NOTARY_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION must be a positive integer",
                )?;
        if anonymous_subject_key_version == 0 {
            bail!("LLM_NOTARY_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION must be positive");
        }
        let trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs(optional_env("LLM_NOTARY_TRUSTED_PROXY_CIDRS")?.as_deref())?;
        let ticket_ttl_secs = positive_integer_or_default(
            "LLM_NOTARY_ADMISSION_TICKET_TTL_SECS",
            DEFAULT_ADMISSION_TICKET_TTL_SECS,
        )?;
        if !(10..=300).contains(&ticket_ttl_secs) {
            bail!("LLM_NOTARY_ADMISSION_TICKET_TTL_SECS must be between 10 and 300");
        }
        Ok(Self {
            service_token,
            anonymous_subject_hmac_key,
            anonymous_subject_key_version,
            trusted_proxy_cidrs,
            ticket_ttl_secs,
            public: AdmissionPolicy::from_env("PUBLIC", AdmissionPolicy::public())?,
            free: AdmissionPolicy::from_env("FREE", AdmissionPolicy::free())?,
            one_gb: AdmissionPolicy::from_env("ONE_GB", AdmissionPolicy::one_gb())?,
            ten_gb: AdmissionPolicy::from_env("TEN_GB", AdmissionPolicy::ten_gb())?,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            service_token: "test-service-token-that-is-long-enough".to_owned(),
            anonymous_subject_hmac_key: b"test-anonymous-subject-key-that-is-long-enough".to_vec(),
            anonymous_subject_key_version: 1,
            trusted_proxy_cidrs: vec!["127.0.0.0/8".parse().expect("test CIDR")],
            ticket_ttl_secs: DEFAULT_ADMISSION_TICKET_TTL_SECS,
            public: AdmissionPolicy::public(),
            free: AdmissionPolicy::free(),
            one_gb: AdmissionPolicy::one_gb(),
            ten_gb: AdmissionPolicy::ten_gb(),
        }
    }
}

impl AdmissionPolicy {
    pub(crate) fn public() -> Self {
        Self {
            max_attestable_http_bytes: 1 << 20,
            max_frame_bytes: 16 << 20,
            max_private_chunk_bytes: 64 << 10,
            max_private_chunk_commitments: 32,
            monthly_notarization_bytes: 50_000_000,
            monthly_capture_bytes: 50_000_000,
        }
    }

    pub(crate) fn free() -> Self {
        Self {
            max_attestable_http_bytes: 8 << 20,
            max_frame_bytes: 64 << 20,
            max_private_chunk_bytes: 128 << 10,
            max_private_chunk_commitments: 64,
            monthly_notarization_bytes: 50_000_000,
            monthly_capture_bytes: 50_000_000,
        }
    }

    pub(crate) fn one_gb() -> Self {
        Self {
            max_attestable_http_bytes: 32 << 20,
            max_frame_bytes: 128 << 20,
            max_private_chunk_bytes: 256 << 10,
            max_private_chunk_commitments: 128,
            monthly_notarization_bytes: 1_000_000_000,
            monthly_capture_bytes: 1_000_000_000,
        }
    }

    pub(crate) fn ten_gb() -> Self {
        Self {
            max_attestable_http_bytes: 64 << 20,
            max_frame_bytes: 256 << 20,
            max_private_chunk_bytes: 256 << 10,
            max_private_chunk_commitments: 128,
            monthly_notarization_bytes: 10_000_000_000,
            monthly_capture_bytes: 10_000_000_000,
        }
    }

    fn from_env(prefix: &str, defaults: Self) -> Result<Self> {
        let value = |suffix: &str, default: i64| {
            positive_integer_or_default(&format!("LLM_NOTARY_ADMISSION_{prefix}_{suffix}"), default)
        };
        Ok(Self {
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
            monthly_notarization_bytes: value(
                "MONTHLY_NOTARIZATION_BYTES",
                defaults.monthly_notarization_bytes,
            )?,
            monthly_capture_bytes: value("MONTHLY_CAPTURE_BYTES", defaults.monthly_capture_bytes)?,
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
        let github_callback_url = app_url
            .join("/api/auth/github/callback")
            .context("building GitHub OAuth callback URL")?;
        let google_callback_url = app_url
            .join("/api/auth/google/callback")
            .context("building Google OAuth callback URL")?;
        let (github_client_id, github_client_secret) = oauth_client_pair(
            "GITHUB_OAUTH_CLIENT_ID",
            "GITHUB_OAUTH_CLIENT_SECRET",
            "GitHub",
        )?;
        let (google_client_id, google_client_secret) = oauth_client_pair(
            "GOOGLE_OAUTH_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_SECRET",
            "Google",
        )?;
        if github_client_id.is_empty() && google_client_id.is_empty() {
            bail!("at least one browser OAuth provider must be configured");
        }
        Ok(Self {
            github_client_id,
            github_client_secret,
            google_client_id,
            google_client_secret,
            app_url,
            github_callback_url,
            google_callback_url,
        })
    }
}

fn oauth_client_pair(id_name: &str, secret_name: &str, provider: &str) -> Result<(String, String)> {
    let id = optional_env(id_name)?.unwrap_or_default();
    let secret = optional_env(secret_name)?.unwrap_or_default();
    if id.is_empty() != secret.is_empty() {
        bail!("{provider} OAuth requires both {id_name} and {secret_name}");
    }
    Ok((id, secret))
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

fn parse_trusted_proxy_cidrs(value: Option<&str>) -> Result<Vec<IpNet>> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpNet>()
                .with_context(|| format!("invalid trusted proxy CIDR {value}"))
        })
        .collect()
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

    #[test]
    fn trusted_proxy_cidrs_are_explicit_and_validated() {
        assert!(parse_trusted_proxy_cidrs(None).unwrap().is_empty());
        let parsed = parse_trusted_proxy_cidrs(Some("127.0.0.0/8, fdaa::/16")).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parse_trusted_proxy_cidrs(Some("not-a-network")).is_err());
    }

    #[test]
    fn credit_price_setting_is_required() {
        let result = BillingConfig::from_settings(
            Some("sk_test_fixture".to_owned()),
            Some("whsec_fixture".to_owned()),
            None,
            None,
            None,
        );
        let error = match result {
            Ok(_) => panic!("missing credit Price must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "LLM_NOTARY_STRIPE_CREDIT_PRICE_ID must be set"
        );
    }

    #[test]
    fn subscription_price_settings_must_be_complete() {
        let result = BillingConfig::from_settings(
            Some("sk_test_fixture".to_owned()),
            Some("whsec_fixture".to_owned()),
            Some("price_credit".to_owned()),
            Some("price_one_gb".to_owned()),
            None,
        );
        assert!(result.is_err());
    }
}
