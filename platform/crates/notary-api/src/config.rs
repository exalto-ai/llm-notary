use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use sqlx::postgres::PgConnectOptions;
use url::{Host, Url};

use notary_core::registry::{Registry, parse_registry};

pub(crate) const DEFAULT_DATABASE_MAX_CONNECTIONS: u32 = 5;
const MAX_DATABASE_CONNECTIONS: u32 = 64;
pub(crate) const DEFAULT_MAX_PACKAGE_BYTES: i64 =
    notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64;
pub(crate) const DEFAULT_UPLOAD_TTL_SECS: i64 = 15 * 60;
pub(crate) const DEFAULT_ADMISSION_TICKET_TTL_SECS: i64 = 45;

/// Validated runtime configuration for the hosted platform API.
///
/// Configuration is read from the environment exactly once, before startup
/// opens network connections or starts background workers.
pub struct NotaryApiConfig {
    pub listen: SocketAddr,
    pub public_origin: Url,
    pub database: DatabaseConfig,
    pub storage: TraceStorageConfig,
    pub browser_auth: BrowserAuthConfig,
    pub registry: RegistryConfig,
    pub admission: NotaryAdmissionConfig,
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
pub struct NotaryAdmissionConfig {
    pub service_token: String,
    pub anonymous_subject_hmac_key: Vec<u8>,
    pub anonymous_subject_key_version: u32,
    pub trusted_proxy_cidrs: Vec<IpNet>,
    pub ticket_ttl_secs: i64,
    pub public: AdmissionTierLimits,
    pub free: AdmissionTierLimits,
    pub one_gb: AdmissionTierLimits,
    pub ten_gb: AdmissionTierLimits,
}

#[derive(Clone, Debug)]
pub struct AdmissionTierLimits {
    pub max_attestable_http_bytes: i64,
    pub max_frame_bytes: i64,
    pub max_private_chunk_bytes: i64,
    pub max_private_chunk_commitments: i64,
    pub monthly_notarization_bytes: i64,
    pub monthly_capture_bytes: i64,
}

/// Browser OAuth providers and callback configuration.
pub struct BrowserAuthConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_callback_url: Url,
    pub google_callback_url: Url,
}

/// PostgreSQL connection-pool configuration for the API.
pub struct DatabaseConfig {
    pub connect_options: PgConnectOptions,
    pub max_connections: u32,
}

/// The verified notary directory advertised by the API.
pub struct RegistryConfig {
    pub registry: Registry,
}

/// Publication intake and public-artifact storage configuration.
pub struct TraceStorageConfig {
    pub max_package_bytes: i64,
    pub upload_ttl_secs: i64,
    pub s3: Option<S3TraceStorageConfig>,
}

/// Settings for an S3-compatible intake bucket.
pub struct S3TraceStorageConfig {
    pub bucket: String,
    pub endpoint: Url,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub prefix: String,
    pub force_path_style: bool,
}

impl NotaryApiConfig {
    pub fn from_env() -> Result<Self> {
        let public_origin = public_origin()?;
        Ok(Self {
            listen: socket_addr_or_default("NOTARY_API_LISTEN", "127.0.0.1:8080")?,
            public_origin: public_origin.clone(),
            database: DatabaseConfig::from_env()?,
            storage: TraceStorageConfig::from_env()?,
            browser_auth: BrowserAuthConfig::from_env(&public_origin)?,
            registry: RegistryConfig::from_env()?,
            admission: NotaryAdmissionConfig::from_env()?,
            billing: BillingConfig::from_env()?,
        })
    }
}

impl BillingConfig {
    fn from_env() -> Result<Self> {
        let secret_key = read_optional_secret_file("NOTARY_API_STRIPE_SECRET_KEY_FILE")?;
        let webhook_secret = read_optional_secret_file("NOTARY_API_STRIPE_WEBHOOK_SECRET_FILE")?;
        Self::from_settings(
            secret_key,
            webhook_secret,
            optional_env("NOTARY_API_STRIPE_CREDIT_PRICE_ID")?,
            optional_env("NOTARY_API_STRIPE_ONE_GB_PRICE_ID")?,
            optional_env("NOTARY_API_STRIPE_TEN_GB_PRICE_ID")?,
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
        let secret_key =
            secret_key.ok_or_else(|| anyhow!("NOTARY_API_STRIPE_SECRET_KEY_FILE must be set"))?;
        let webhook_secret = webhook_secret
            .ok_or_else(|| anyhow!("NOTARY_API_STRIPE_WEBHOOK_SECRET_FILE must be set"))?;
        let credit_price_id = credit_price_id
            .ok_or_else(|| anyhow!("NOTARY_API_STRIPE_CREDIT_PRICE_ID must be set"))?;
        if one_gb_price_id.is_some() != ten_gb_price_id.is_some() {
            bail!(
                "NOTARY_API_STRIPE_ONE_GB_PRICE_ID and NOTARY_API_STRIPE_TEN_GB_PRICE_ID must be set together"
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
                "NOTARY_API_STRIPE_CREDIT_PRICE_ID",
                Some(credit_price_id.as_str()),
            ),
            (
                "NOTARY_API_STRIPE_ONE_GB_PRICE_ID",
                one_gb_price_id.as_deref(),
            ),
            (
                "NOTARY_API_STRIPE_TEN_GB_PRICE_ID",
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

fn read_optional_secret_file(file_name: &str) -> Result<Option<String>> {
    let path = optional_env(file_name)?;
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

impl NotaryAdmissionConfig {
    fn from_env() -> Result<Self> {
        let service_token_file =
            PathBuf::from(required_env("NOTARY_API_ADMISSION_SERVICE_TOKEN_FILE")?);
        let service_token = std::fs::read_to_string(&service_token_file)
            .with_context(|| format!("reading {}", service_token_file.display()))?
            .trim()
            .to_owned();
        if service_token.len() < 32 || service_token.len() > 512 {
            bail!("admission service token must contain between 32 and 512 bytes");
        }
        let subject_key_file = PathBuf::from(required_env(
            "NOTARY_API_ADMISSION_ANONYMOUS_SUBJECT_HMAC_KEY_FILE",
        )?);
        let anonymous_subject_hmac_key = std::fs::read(&subject_key_file)
            .with_context(|| format!("reading {}", subject_key_file.display()))?;
        if anonymous_subject_hmac_key.len() < 32 || anonymous_subject_hmac_key.len() > 512 {
            bail!("anonymous subject HMAC key must contain between 32 and 512 bytes");
        }
        let anonymous_subject_key_version = env_or_default(
            "NOTARY_API_ADMISSION_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION",
            "1",
        )?
        .parse::<u32>()
        .context(
            "NOTARY_API_ADMISSION_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION must be a positive integer",
        )?;
        if anonymous_subject_key_version == 0 {
            bail!("NOTARY_API_ADMISSION_ANONYMOUS_SUBJECT_HMAC_KEY_VERSION must be positive");
        }
        let trusted_proxy_cidrs = parse_trusted_proxy_cidrs(
            optional_env("NOTARY_API_ADMISSION_TRUSTED_PROXY_CIDRS")?.as_deref(),
        )?;
        let ticket_ttl_secs = positive_integer_or_default(
            "NOTARY_API_ADMISSION_TICKET_TTL_SECS",
            DEFAULT_ADMISSION_TICKET_TTL_SECS,
        )?;
        if !(10..=300).contains(&ticket_ttl_secs) {
            bail!("NOTARY_API_ADMISSION_TICKET_TTL_SECS must be between 10 and 300");
        }
        Ok(Self {
            service_token,
            anonymous_subject_hmac_key,
            anonymous_subject_key_version,
            trusted_proxy_cidrs,
            ticket_ttl_secs,
            public: AdmissionTierLimits::from_env("PUBLIC", AdmissionTierLimits::public())?,
            free: AdmissionTierLimits::from_env("FREE", AdmissionTierLimits::free())?,
            one_gb: AdmissionTierLimits::from_env("ONE_GB", AdmissionTierLimits::one_gb())?,
            ten_gb: AdmissionTierLimits::from_env("TEN_GB", AdmissionTierLimits::ten_gb())?,
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
            public: AdmissionTierLimits::public(),
            free: AdmissionTierLimits::free(),
            one_gb: AdmissionTierLimits::one_gb(),
            ten_gb: AdmissionTierLimits::ten_gb(),
        }
    }
}

impl AdmissionTierLimits {
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
            positive_integer_or_default(&format!("NOTARY_API_ADMISSION_{prefix}_{suffix}"), default)
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

fn public_origin() -> Result<Url> {
    parse_public_origin(&env_or_default(
        "NOTARY_PUBLIC_ORIGIN",
        "http://localhost:4173",
    )?)
}

fn parse_public_origin(value: &str) -> Result<Url> {
    let origin = Url::parse(value).context("NOTARY_PUBLIC_ORIGIN must be an absolute URL")?;
    if origin.username() != ""
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("NOTARY_PUBLIC_ORIGIN must be an origin without a path, query, or fragment");
    }
    let loopback = match origin.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => return Err(anyhow!("NOTARY_PUBLIC_ORIGIN must include a host")),
    };
    if origin.scheme() != "https" && !(origin.scheme() == "http" && loopback) {
        bail!("NOTARY_PUBLIC_ORIGIN must use HTTPS except on loopback");
    }
    Ok(origin)
}

impl BrowserAuthConfig {
    fn from_env(public_origin: &Url) -> Result<Self> {
        let github_callback_url = public_origin
            .join("/api/auth/github/callback")
            .context("building GitHub OAuth callback URL")?;
        let google_callback_url = public_origin
            .join("/api/auth/google/callback")
            .context("building Google OAuth callback URL")?;
        let (github_client_id, github_client_secret) = oauth_client_pair(
            "NOTARY_API_GITHUB_CLIENT_ID",
            "NOTARY_API_GITHUB_CLIENT_SECRET_FILE",
            "GitHub",
        )?;
        let (google_client_id, google_client_secret) = oauth_client_pair(
            "NOTARY_API_GOOGLE_CLIENT_ID",
            "NOTARY_API_GOOGLE_CLIENT_SECRET_FILE",
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
            github_callback_url,
            google_callback_url,
        })
    }
}

fn oauth_client_pair(id_name: &str, secret_name: &str, provider: &str) -> Result<(String, String)> {
    let id = optional_env(id_name)?.unwrap_or_default();
    let secret = read_optional_secret_file(secret_name)?.unwrap_or_default();
    if id.is_empty() != secret.is_empty() {
        bail!("{provider} OAuth requires both {id_name} and {secret_name}");
    }
    Ok((id, secret))
}

impl DatabaseConfig {
    fn from_env() -> Result<Self> {
        let connect_options = required_env("NOTARY_API_DATABASE_URL")?
            .parse::<PgConnectOptions>()
            .context("NOTARY_API_DATABASE_URL must be a PostgreSQL connection URL")?;
        Ok(Self {
            connect_options,
            max_connections: database_max_connections()?,
        })
    }
}

impl RegistryConfig {
    fn from_env() -> Result<Self> {
        let path = PathBuf::from(required_env("NOTARY_API_REGISTRY_FILE")?);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading Registry file {}", path.display()))?;
        let registry = parse_registry(&bytes)
            .with_context(|| format!("parsing Registry file {}", path.display()))?;
        Ok(Self { registry })
    }
}

impl TraceStorageConfig {
    pub(crate) fn from_env() -> Result<Self> {
        let max_package_bytes = integer_or_default(
            "NOTARY_API_STORAGE_MAX_PACKAGE_BYTES",
            DEFAULT_MAX_PACKAGE_BYTES,
        )?;
        validate_max_package_bytes(max_package_bytes)?;
        let upload_ttl_secs = integer_or_default(
            "NOTARY_API_STORAGE_UPLOAD_TTL_SECS",
            DEFAULT_UPLOAD_TTL_SECS,
        )?;
        if !(60..=24 * 60 * 60).contains(&upload_ttl_secs) {
            bail!("NOTARY_API_STORAGE_UPLOAD_TTL_SECS must be between 60 and 86400 seconds");
        }

        let s3 = optional_env("NOTARY_API_S3_BUCKET")?
            .map(|bucket| {
                validate_bucket(&bucket)?;
                let endpoint = required_env("NOTARY_API_S3_ENDPOINT")?;
                let endpoint = validate_endpoint(&endpoint)?;
                let prefix = env_or_default("NOTARY_API_S3_PREFIX", "notary-api")?;
                validate_prefix(&prefix)?;
                Ok::<_, anyhow::Error>(S3TraceStorageConfig {
                    bucket,
                    endpoint,
                    region: required_env("NOTARY_API_S3_REGION")?,
                    access_key_id: required_env("NOTARY_API_S3_ACCESS_KEY_ID")?,
                    secret_access_key: required_env("NOTARY_API_S3_SECRET_ACCESS_KEY")?,
                    prefix: prefix.trim_matches('/').to_owned(),
                    force_path_style: bool_or_default("NOTARY_API_S3_FORCE_PATH_STYLE", true)?,
                })
            })
            .transpose()?;
        Ok(Self {
            max_package_bytes,
            upload_ttl_secs,
            s3,
        })
    }
}

fn validate_max_package_bytes(value: i64) -> Result<()> {
    if value <= 0 || value > notary_core::archive::MAX_ARCHIVE_WIRE_BYTES as i64 {
        bail!(
            "NOTARY_API_STORAGE_MAX_PACKAGE_BYTES must be positive and no greater than {}",
            notary_core::archive::MAX_ARCHIVE_WIRE_BYTES
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

fn socket_addr_or_default(name: &str, default: &str) -> Result<SocketAddr> {
    env_or_default(name, default)?
        .parse()
        .with_context(|| format!("{name} must be a socket address"))
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

fn database_max_connections() -> Result<u32> {
    let connections = env_or_default(
        "NOTARY_API_DATABASE_MAX_CONNECTIONS",
        &DEFAULT_DATABASE_MAX_CONNECTIONS.to_string(),
    )?
    .parse::<u32>()
    .context("NOTARY_API_DATABASE_MAX_CONNECTIONS must be an integer")?;
    if connections == 0 || connections > MAX_DATABASE_CONNECTIONS {
        bail!(
            "NOTARY_API_DATABASE_MAX_CONNECTIONS must be between 1 and {MAX_DATABASE_CONNECTIONS}"
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
    let endpoint = Url::parse(value).context("NOTARY_API_S3_ENDPOINT must be a URL")?;
    if endpoint.scheme() != "https"
        && !(endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost")))
    {
        bail!("NOTARY_API_S3_ENDPOINT must use HTTPS except for local test services");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        bail!("NOTARY_API_S3_ENDPOINT must not contain a query or fragment");
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
        bail!("NOTARY_API_S3_BUCKET is not a valid lowercase bucket name");
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
        bail!("NOTARY_API_S3_PREFIX must be a safe, non-empty object prefix");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, sync::Mutex};

    use super::*;

    static ENVIRONMENT: Mutex<()> = Mutex::new(());

    struct EnvironmentGuard(Vec<(String, Option<OsString>)>);

    impl EnvironmentGuard {
        fn set(settings: &[(&str, Option<&str>)]) -> Self {
            let previous = settings
                .iter()
                .map(|(name, _)| ((*name).to_owned(), env::var_os(name)))
                .collect();
            for (name, value) in settings {
                // SAFETY: every environment-mutating config test holds
                // `ENVIRONMENT`, and production configuration is immutable.
                unsafe {
                    if let Some(value) = value {
                        env::set_var(name, value);
                    } else {
                        env::remove_var(name);
                    }
                }
            }
            Self(previous)
        }
    }

    impl Drop for EnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in self.0.drain(..) {
                // SAFETY: the creating test still holds `ENVIRONMENT` while
                // this guard restores the process environment.
                unsafe {
                    if let Some(value) = value {
                        env::set_var(name, value);
                    } else {
                        env::remove_var(name);
                    }
                }
            }
        }
    }

    #[test]
    fn package_limit_can_be_lower_but_never_exceed_the_wire_ceiling() {
        assert!(validate_max_package_bytes(1).is_ok());
        assert!(validate_max_package_bytes(DEFAULT_MAX_PACKAGE_BYTES).is_ok());
        assert!(validate_max_package_bytes(0).is_err());
        assert!(validate_max_package_bytes(DEFAULT_MAX_PACKAGE_BYTES + 1).is_err());
    }

    #[test]
    fn public_origin_requires_https_except_for_loopback_development() {
        for accepted in [
            "https://notary.exalto.ai",
            "https://notary.exalto.ai:8443",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
            "http://[::1]:4173",
        ] {
            assert!(parse_public_origin(accepted).is_ok(), "{accepted}");
        }
        for rejected in [
            "http://notary.exalto.ai",
            "ftp://notary.exalto.ai",
            "https://user:not-secret@notary.exalto.ai",
            "https://notary.exalto.ai/path",
            "https://notary.exalto.ai?query=yes",
            "https://notary.exalto.ai/#fragment",
        ] {
            assert!(parse_public_origin(rejected).is_err(), "{rejected}");
        }
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
            "NOTARY_API_STRIPE_CREDIT_PRICE_ID must be set"
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

    #[test]
    fn database_configuration_does_not_fall_back_to_database_url() {
        let _lock = ENVIRONMENT.lock().unwrap();
        let _environment = EnvironmentGuard::set(&[
            ("NOTARY_API_DATABASE_URL", None),
            ("DATABASE_URL", Some("postgres://legacy.invalid/notary")),
        ]);
        assert_eq!(
            DatabaseConfig::from_env().err().unwrap().to_string(),
            "NOTARY_API_DATABASE_URL must be set"
        );
    }

    #[test]
    fn oauth_secret_files_are_trimmed() {
        let _lock = ENVIRONMENT.lock().unwrap();
        let secret_path =
            env::temp_dir().join(format!("notary-api-oauth-{}", uuid::Uuid::new_v4()));
        std::fs::write(&secret_path, "fixture-secret\n").unwrap();
        let secret_path = secret_path.to_string_lossy().into_owned();
        let _environment = EnvironmentGuard::set(&[
            ("NOTARY_API_GITHUB_CLIENT_ID", Some("client-id")),
            ("NOTARY_API_GITHUB_CLIENT_SECRET_FILE", Some(&secret_path)),
            ("LLM_NOTARY_GITHUB_CLIENT_SECRET", Some("legacy-secret")),
        ]);
        assert_eq!(
            oauth_client_pair(
                "NOTARY_API_GITHUB_CLIENT_ID",
                "NOTARY_API_GITHUB_CLIENT_SECRET_FILE",
                "GitHub",
            )
            .unwrap(),
            ("client-id".to_owned(), "fixture-secret".to_owned())
        );
        std::fs::remove_file(secret_path).unwrap();
    }

    #[test]
    fn oauth_configuration_does_not_read_legacy_inline_secrets() {
        let _lock = ENVIRONMENT.lock().unwrap();
        let _environment = EnvironmentGuard::set(&[
            ("NOTARY_API_GITHUB_CLIENT_ID", Some("client-id")),
            ("NOTARY_API_GITHUB_CLIENT_SECRET_FILE", None),
            ("LLM_NOTARY_GITHUB_CLIENT_SECRET", Some("legacy-secret")),
        ]);
        assert_eq!(
            oauth_client_pair(
                "NOTARY_API_GITHUB_CLIENT_ID",
                "NOTARY_API_GITHUB_CLIENT_SECRET_FILE",
                "GitHub",
            )
            .err()
            .unwrap()
            .to_string(),
            "GitHub OAuth requires both NOTARY_API_GITHUB_CLIENT_ID and NOTARY_API_GITHUB_CLIENT_SECRET_FILE"
        );
    }

    #[test]
    fn registry_configuration_has_no_inline_directory_fallback() {
        let _lock = ENVIRONMENT.lock().unwrap();
        let _environment = EnvironmentGuard::set(&[
            ("NOTARY_API_REGISTRY_FILE", None),
            ("LLM_NOTARY_NOTARY_DIRECTORY_JSON", Some("{}")),
        ]);
        assert_eq!(
            RegistryConfig::from_env().err().unwrap().to_string(),
            "NOTARY_API_REGISTRY_FILE must be set"
        );
    }

    #[test]
    fn s3_configuration_does_not_read_aws_credentials() {
        let _lock = ENVIRONMENT.lock().unwrap();
        let _environment = EnvironmentGuard::set(&[
            ("NOTARY_API_S3_BUCKET", Some("fixture-bucket")),
            ("NOTARY_API_S3_ENDPOINT", Some("http://localhost:9000")),
            ("NOTARY_API_S3_REGION", Some("us-east-1")),
            ("NOTARY_API_S3_ACCESS_KEY_ID", None),
            ("NOTARY_API_S3_SECRET_ACCESS_KEY", None),
            ("AWS_ACCESS_KEY_ID", Some("legacy-access")),
            ("AWS_SECRET_ACCESS_KEY", Some("legacy-secret")),
        ]);
        assert_eq!(
            TraceStorageConfig::from_env().err().unwrap().to_string(),
            "NOTARY_API_S3_ACCESS_KEY_ID must be set"
        );
    }
}
