//! Short-lived command client for the versioned loopback administration API.

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use url::Url;

use crate::{
    bundle::{
        trace_package_created_at_unix_ms_bytes, trace_package_notary_key_bytes,
        verify_trace_package_bytes,
    },
    cli::{notary, publish::ShareVisibility},
    config::{AgentConfig, default_config_path},
};

const API_VERSION: &str = "v1";
const EXIT_ERROR: i32 = 1;
const EXIT_INVALID_INPUT: i32 = 2;
const EXIT_UNAVAILABLE: i32 = 3;
const EXIT_AUTHENTICATION: i32 = 4;
const EXIT_NOT_FOUND: i32 = 5;
const EXIT_CONFLICT: i32 = 6;
const EXIT_RETRYABLE: i32 = 7;
const EXIT_VERSION_MISMATCH: i32 = 8;

#[derive(Debug)]
pub struct CliError {
    exit_code: i32,
    message: String,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(EXIT_INVALID_INPUT, message)
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(EXIT_UNAVAILABLE, message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

#[derive(Parser, Debug)]
#[command(
    name = "llm-notary",
    about = "Inspect and operate the local LLM Notary daemon",
    version,
    arg_required_else_help = true
)]
struct Cli {
    /// Print one stable JSON value to standard output.
    #[arg(long, global = true)]
    json: bool,

    /// Configuration used by llm-notaryd. The CLI reads only the admin listener and username.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Read the local admin password from a private UTF-8 file instead of prompting.
    #[arg(long, global = true, value_name = "PATH")]
    admin_password_file: Option<PathBuf>,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Show daemon health, listeners, and capture counts.
    Status,
    /// Search or inspect captures.
    Captures {
        #[command(subcommand)]
        command: CapturesCommand,
    },
    /// Queue proof generation for a capture.
    Finalize(IdArgs),
    /// List, inspect, or retry daemon-owned operations.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Inspect or verify a finalized trace.
    Traces {
        #[command(subcommand)]
        command: TracesCommand,
    },
    /// Connect this daemon to an LLM Notary account.
    Login,
    /// Disconnect this daemon from its LLM Notary account.
    Logout,
    /// Show the LLM Notary account connected to this daemon.
    Whoami,
    /// Create a public link for a finalized verified session.
    #[command(alias = "publish")]
    Share(ShareArgs),
    /// List redacted daemon events.
    Events(EventListArgs),
    /// Inspect configured notary trust.
    Notaries {
        #[command(subcommand)]
        command: NotariesCommand,
    },
    /// Open the local dashboard in the default browser.
    Open,
}

#[derive(Subcommand, Debug)]
enum CapturesCommand {
    /// List captures using server-side filters.
    List(CaptureListArgs),
    /// Show one capture and its retained artifact metadata.
    Show(IdArgs),
}

#[derive(Subcommand, Debug)]
enum OperationsCommand {
    /// List durable operations using server-side filters.
    List(OperationListArgs),
    /// Show one operation and its attempt history.
    Show(IdArgs),
    /// Requeue a failed or interrupted operation.
    Retry(IdArgs),
}

#[derive(Subcommand, Debug)]
enum TracesCommand {
    /// Show the canonical trace and manifest for a finalized capture.
    Show(IdArgs),
    /// Verify a finalized capture against the daemon's trust source.
    Verify(TraceVerifyArgs),
}

#[derive(Args, Debug)]
struct TraceVerifyArgs {
    /// A capture identifier in the daemon, or a portable `.llmtrace` path.
    target: String,

    /// Hex-encoded notary public key for a path-based verification.
    #[arg(long)]
    trusted_notary_key: Option<String>,
}

#[derive(Subcommand, Debug)]
enum NotariesCommand {
    /// List the daemon's pinned or explicitly configured notary keys.
    List,
}

#[derive(Args, Debug)]
struct IdArgs {
    /// Opaque capture or operation identifier.
    id: String,
}

#[derive(Args, Debug)]
struct ShareArgs {
    /// Opaque finalized capture identifier.
    id: String,

    /// Whether the share appears in the public Library index.
    #[arg(long, value_enum, default_value_t = ShareVisibility::Unlisted)]
    visibility: ShareVisibility,
}

#[derive(Args, Debug, Default)]
struct CaptureListArgs {
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    provider: Option<String>,
    #[arg(long)]
    capture_state: Option<String>,
    #[arg(long)]
    finalization_state: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long)]
    offset: Option<usize>,
}

#[derive(Args, Debug, Default)]
struct OperationListArgs {
    #[arg(long)]
    state: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    capture_id: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args, Debug, Default)]
struct EventListArgs {
    #[arg(long)]
    cursor: Option<u64>,
    #[arg(long)]
    severity: Option<String>,
    #[arg(long)]
    event_type: Option<String>,
    #[arg(long)]
    capture_id: Option<String>,
    #[arg(long)]
    operation_id: Option<String>,
    #[arg(long)]
    created_after_unix_ms: Option<u64>,
    #[arg(long)]
    limit: Option<usize>,
}

struct AdminCredentials {
    username: String,
    password: String,
}

struct AdminClient {
    origin: Url,
    client: reqwest::Client,
    credentials: Option<AdminCredentials>,
}

pub async fn run() -> Result<(), CliError> {
    let cli = Cli::parse();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    run_parsed(cli, &mut stdout, &mut stderr).await
}

async fn run_parsed(
    cli: Cli,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), CliError> {
    if let CliCommand::Traces {
        command: TracesCommand::Verify(args),
    } = &cli.command
        && verify_target_is_file(&args.target)
    {
        let value = verify_trace_file(args)?;
        let output = if cli.json {
            serde_json::to_string_pretty(&value)
                .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command output"))?
        } else {
            human_output(&cli.command, &value)?
        };
        writeln!(stdout, "{output}")
            .map_err(|_| CliError::new(EXIT_ERROR, "could not write command output"))?;
        return Ok(());
    }
    let config = load_config_for_cli(cli.config.as_deref())?;
    let mut client = AdminClient::new(config.admin.listen, None)?;
    client.verify_version().await?;
    if matches!(&cli.command, CliCommand::Open) {
        if cli.admin_password_file.is_some() {
            return Err(CliError::invalid(
                "--admin-password-file is not used by llm-notary open",
            ));
        }
    } else {
        client.credentials = load_admin_credentials(&config, cli.admin_password_file.as_deref())?;
    }
    let value = execute(&client, &cli.command, stderr).await?;
    let output = if cli.json {
        serde_json::to_string_pretty(&value)
            .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command output"))?
    } else {
        human_output(&cli.command, &value)?
    };
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command output"))?;
    Ok(())
}

fn load_config_for_cli(path: Option<&Path>) -> Result<AgentConfig, CliError> {
    let explicit = path.is_some();
    let path = match path {
        Some(path) => path.to_owned(),
        None => default_config_path().map_err(|error| {
            CliError::invalid(format!(
                "could not locate the daemon configuration: {error}"
            ))
        })?,
    };
    if !path.exists() && !explicit {
        return Ok(AgentConfig::default());
    }
    AgentConfig::load(&path).map_err(|error| {
        CliError::invalid(format!(
            "could not read daemon configuration {}: {error}",
            path.display()
        ))
    })
}

fn load_admin_credentials(
    config: &AgentConfig,
    password_file: Option<&Path>,
) -> Result<Option<AdminCredentials>, CliError> {
    let Some(auth) = &config.admin.auth else {
        if password_file.is_some() {
            return Err(CliError::invalid(
                "--admin-password-file requires admin.auth in the daemon configuration",
            ));
        }
        return Ok(None);
    };
    let password = match password_file {
        Some(path) => read_password_file(path)?,
        None => rpassword::prompt_password(format!("Admin password for {}: ", auth.username))
            .map_err(|_| {
                CliError::new(
                    EXIT_AUTHENTICATION,
                    "could not read the admin password from the terminal",
                )
            })?,
    };
    if password.is_empty() {
        return Err(CliError::new(
            EXIT_AUTHENTICATION,
            "the admin password must not be empty",
        ));
    }
    Ok(Some(AdminCredentials {
        username: auth.username.clone(),
        password,
    }))
}

fn read_password_file(path: &Path) -> Result<String, CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::metadata(path).map_err(|_| {
            CliError::new(
                EXIT_AUTHENTICATION,
                format!("could not read admin password file {}", path.display()),
            )
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::new(
                EXIT_AUTHENTICATION,
                "the admin password file must not be accessible by group or other users",
            ));
        }
    }
    let mut password = fs::read_to_string(path).map_err(|_| {
        CliError::new(
            EXIT_AUTHENTICATION,
            format!("could not read admin password file {}", path.display()),
        )
    })?;
    if password.len() > 4096 {
        return Err(CliError::new(
            EXIT_AUTHENTICATION,
            "the admin password file is unexpectedly large",
        ));
    }
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    Ok(password)
}

impl AdminClient {
    fn new(
        address: std::net::SocketAddr,
        credentials: Option<AdminCredentials>,
    ) -> Result<Self, CliError> {
        if !address.ip().is_loopback() {
            return Err(CliError::invalid(
                "the admin listener must use a loopback address",
            ));
        }
        let origin = Url::parse(&format!("http://{address}/")).map_err(|_| {
            CliError::invalid("the configured admin listener could not be converted to a URL")
        })?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("llm-notary-cli/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| CliError::new(EXIT_ERROR, "could not initialize the HTTP client"))?;
        Ok(Self {
            origin,
            client,
            credentials,
        })
    }

    fn url(&self, path: &str, query: &[(String, String)]) -> Result<Url, CliError> {
        let mut url = self
            .origin
            .join(path.trim_start_matches('/'))
            .map_err(|_| CliError::invalid("the local administration request path is invalid"))?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (key, value)));
        }
        Ok(url)
    }

    async fn verify_version(&self) -> Result<(), CliError> {
        let health = self
            .request_with_auth(Method::GET, "/healthz", &[], false, None)
            .await?;
        let service = health
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if service != "llm-notaryd" {
            return Err(CliError::new(
                EXIT_VERSION_MISMATCH,
                format!("unexpected local service {service}; this CLI requires llm-notaryd"),
            ));
        }
        let actual = health
            .get("api_version")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if actual != API_VERSION {
            return Err(CliError::new(
                EXIT_VERSION_MISMATCH,
                format!("unsupported local API version {actual}; this CLI requires {API_VERSION}"),
            ));
        }
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
    ) -> Result<Value, CliError> {
        self.request_with_auth(method, path, query, true, None)
            .await
    }

    async fn request_json(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &Value,
    ) -> Result<Value, CliError> {
        self.request_with_auth(method, path, query, true, Some(body))
            .await
    }

    async fn request_with_auth(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        include_credentials: bool,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        let url = self.url(path, query)?;
        let mut request = self.client.request(method, url);
        if include_credentials && let Some(credentials) = &self.credentials {
            request = request.basic_auth(&credentials.username, Some(&credentials.password));
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| {
            CliError::unavailable(format!(
                "llm-notaryd is unavailable at {}; start the daemon and try again",
                self.origin
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon response ended before it could be read; try again",
            )
        })?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        if status == StatusCode::NO_CONTENT || bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an invalid JSON response; check that the CLI and daemon versions match",
            )
        })
    }
}

fn api_error(status: StatusCode, bytes: &[u8]) -> CliError {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str);
    let message = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/message"))
        .and_then(Value::as_str);
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => CliError::new(
            EXIT_INVALID_INPUT,
            message.unwrap_or("the daemon rejected the command input"),
        ),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => CliError::new(
            EXIT_AUTHENTICATION,
            "local admin authentication failed; check the configured username and password",
        ),
        StatusCode::NOT_FOUND => CliError::new(
            EXIT_NOT_FOUND,
            message.unwrap_or("the requested local resource was not found"),
        ),
        StatusCode::CONFLICT => CliError::new(
            EXIT_CONFLICT,
            message.unwrap_or("the requested operation conflicts with current daemon state"),
        ),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => CliError::new(
            EXIT_RETRYABLE,
            message.unwrap_or("the daemon is temporarily unable to accept this operation"),
        ),
        status if status.is_server_error() => CliError::new(
            EXIT_RETRYABLE,
            match code {
                Some(code) => {
                    format!("the daemon could not complete the request ({code}); try again")
                }
                None => "the daemon could not complete the request; try again".to_owned(),
            },
        ),
        _ => CliError::new(
            EXIT_ERROR,
            message.unwrap_or("the daemon rejected the command"),
        ),
    }
}

async fn execute(
    client: &AdminClient,
    command: &CliCommand,
    stderr: &mut dyn io::Write,
) -> Result<Value, CliError> {
    match command {
        CliCommand::Status => client.request(Method::GET, "/v1/status", &[]).await,
        CliCommand::Captures { command } => match command {
            CapturesCommand::List(args) => {
                client
                    .request(Method::GET, "/v1/captures", &capture_query(args))
                    .await
            }
            CapturesCommand::Show(args) => {
                validate_identifier(&args.id, "cap-")?;
                client
                    .request(Method::GET, &format!("/v1/captures/{}", args.id), &[])
                    .await
            }
        },
        CliCommand::Finalize(args) => {
            validate_identifier(&args.id, "cap-")?;
            client
                .request(
                    Method::POST,
                    &format!("/v1/captures/{}/finalizations", args.id),
                    &[],
                )
                .await
        }
        CliCommand::Operations { command } => match command {
            OperationsCommand::List(args) => {
                client
                    .request(Method::GET, "/v1/operations", &operation_query(args))
                    .await
            }
            OperationsCommand::Show(args) => {
                validate_identifier(&args.id, "op-")?;
                client
                    .request(Method::GET, &format!("/v1/operations/{}", args.id), &[])
                    .await
            }
            OperationsCommand::Retry(args) => {
                validate_identifier(&args.id, "op-")?;
                client
                    .request(
                        Method::POST,
                        &format!("/v1/operations/{}/retry", args.id),
                        &[],
                    )
                    .await
            }
        },
        CliCommand::Traces { command } => match command {
            TracesCommand::Show(args) => {
                validate_identifier(&args.id, "cap-")?;
                client
                    .request(Method::GET, &format!("/v1/captures/{}/trace", args.id), &[])
                    .await
            }
            TracesCommand::Verify(args) => {
                validate_identifier(&args.target, "cap-")?;
                if args.trusted_notary_key.is_some() {
                    return Err(CliError::invalid(
                        "--trusted-notary-key is only valid when verifying a .llmtrace path",
                    ));
                }
                client
                    .request(
                        Method::POST,
                        &format!("/v1/captures/{}/trace:verify", args.target),
                        &[],
                    )
                    .await
            }
        },
        CliCommand::Login => login(client, stderr).await,
        CliCommand::Logout => {
            client.request(Method::DELETE, "/v1/account", &[]).await?;
            Ok(json!({ "signed_in": false }))
        }
        CliCommand::Whoami => client.request(Method::GET, "/v1/account", &[]).await,
        CliCommand::Share(args) => {
            validate_identifier(&args.id, "cap-")?;
            client
                .request_json(
                    Method::POST,
                    &format!("/v1/captures/{}/shares", args.id),
                    &[],
                    &json!({ "visibility": args.visibility.as_str() }),
                )
                .await
        }
        CliCommand::Events(args) => {
            client
                .request(Method::GET, "/v1/events", &event_query(args))
                .await
        }
        CliCommand::Notaries { .. } => client.request(Method::GET, "/v1/notaries", &[]).await,
        CliCommand::Open => {
            open_dashboard(client.origin.as_str())?;
            Ok(json!({ "opened": client.origin.as_str() }))
        }
    }
}

fn verify_target_is_file(target: &str) -> bool {
    Path::new(target).is_file() || validate_identifier(target, "cap-").is_err()
}

fn verify_trace_file(args: &TraceVerifyArgs) -> Result<Value, CliError> {
    let path = Path::new(&args.target);
    if path
        .extension()
        .is_some_and(|extension| extension == "llmbundle")
    {
        return Err(CliError::new(
            EXIT_ERROR,
            "encrypted .llmbundle files are private retry state and cannot be verified as finalized packages",
        ));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::new(
            EXIT_ERROR,
            "verified trace package must be one regular .llmtrace file",
        ));
    }
    // Snapshot once so the key, authenticated timestamp, and full verifier
    // cannot observe different packages if the source path changes.
    let package = fs::read(path).map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
    let embedded_key = trace_package_notary_key_bytes(&package)
        .map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
    let (trusted_key, notary_key_id, trust_source) = match args.trusted_notary_key.as_deref() {
        Some(value) => {
            let (key, key_id) = notary::explicit_key(value)
                .map_err(|error| CliError::invalid(error.to_string()))?;
            (key, key_id, "explicit_key".to_owned())
        }
        None => {
            let created_at = trace_package_created_at_unix_ms_bytes(&package)
                .map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
            let (key_id, trust_source) = notary::cached_key_at(&embedded_key, created_at)
                .map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
            (embedded_key, key_id, trust_source)
        }
    };
    let verified = verify_trace_package_bytes(&package, &trusted_key)
        .map_err(|error| CliError::new(EXIT_ERROR, error.to_string()))?;
    Ok(json!({
        "capture_id": verified.manifest.capture_id(),
        "verified": true,
        "notary_key_id": notary_key_id,
        "trust_source": trust_source,
    }))
}

fn validate_identifier(value: &str, prefix: &str) -> Result<(), CliError> {
    if value.starts_with(prefix)
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        Ok(())
    } else {
        Err(CliError::invalid(format!(
            "invalid identifier; expected an opaque {prefix} identifier"
        )))
    }
}

async fn login(client: &AdminClient, stderr: &mut dyn io::Write) -> Result<Value, CliError> {
    let started = client
        .request_json(Method::POST, "/v1/account", &[], &json!({}))
        .await?;
    let request_id = required_string(&started, "/request_id")?;
    let verification_url = required_string(&started, "/verification_uri_complete")?;
    let user_code = required_string(&started, "/user_code")?;
    let expires_in = started
        .get("expires_in_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(600);
    let poll_interval = started
        .get("poll_interval_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(5)
        .clamp(1, 10);
    writeln!(stderr, "Open {verification_url}").ok();
    writeln!(stderr, "Approval code: {user_code}").ok();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(expires_in);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::new(
                EXIT_AUTHENTICATION,
                "LLM Notary account connection expired; run llm-notary login again",
            ));
        }
        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
        let status = client
            .request(Method::GET, &format!("/v1/account/{request_id}"), &[])
            .await?;
        if status
            .get("signed_in")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(status);
        }
    }
}

fn required_string<'value>(value: &'value Value, pointer: &str) -> Result<&'value str, CliError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an incomplete response; check that the CLI and daemon versions match",
            )
        })
}

fn capture_query(args: &CaptureListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "query", args.query.as_deref());
    push_string(&mut query, "model", args.model.as_deref());
    push_string(&mut query, "provider", args.provider.as_deref());
    push_string(&mut query, "capture_state", args.capture_state.as_deref());
    push_string(
        &mut query,
        "finalization_state",
        args.finalization_state.as_deref(),
    );
    push_number(&mut query, "limit", args.limit);
    push_number(&mut query, "offset", args.offset);
    query
}

fn operation_query(args: &OperationListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "state", args.state.as_deref());
    push_string(&mut query, "kind", args.kind.as_deref());
    push_string(&mut query, "capture_id", args.capture_id.as_deref());
    push_number(&mut query, "limit", args.limit);
    query
}

fn event_query(args: &EventListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_number(&mut query, "cursor", args.cursor);
    push_string(&mut query, "severity", args.severity.as_deref());
    push_string(&mut query, "event_type", args.event_type.as_deref());
    push_string(&mut query, "capture_id", args.capture_id.as_deref());
    push_string(&mut query, "operation_id", args.operation_id.as_deref());
    push_number(
        &mut query,
        "created_after_unix_ms",
        args.created_after_unix_ms,
    );
    push_number(&mut query, "limit", args.limit);
    query
}

fn push_string(query: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        query.push((key.to_owned(), value.to_owned()));
    }
}

fn push_number<T: ToString>(query: &mut Vec<(String, String)>, key: &str, value: Option<T>) {
    if let Some(value) = value {
        query.push((key.to_owned(), value.to_string()));
    }
}

fn human_output(command: &CliCommand, value: &Value) -> Result<String, CliError> {
    match command {
        CliCommand::Status => Ok(format!(
            "llm-notaryd {}\nproxy {}\nadmin {}\ncaptures {} total, {} pending, {} finalized, {} failed\noperations {} active",
            value_string(value, "/version"),
            value_string(value, "/proxy_listener"),
            value_string(value, "/admin_listener"),
            value_string(value, "/counts/total_captures"),
            value_string(value, "/counts/pending"),
            value_string(value, "/counts/finalized"),
            value_string(value, "/counts/failed"),
            value_string(value, "/counts/active_operations"),
        )),
        CliCommand::Captures {
            command: CapturesCommand::List(_),
        } => list_lines(value, "/items", |item| {
            format!(
                "{}\t{}\t{}\t{} / {}",
                value_string(item, "/capture_id"),
                value_string(item, "/provider"),
                value_string(item, "/requested_model"),
                value_string(item, "/capture_state"),
                value_string(item, "/finalization_state"),
            )
        }),
        CliCommand::Captures {
            command: CapturesCommand::Show(_),
        } => Ok(format!(
            "capture {}\nprovider {}\nmodel {}\nstate {} / {}\nrequest {} bytes; response {} bytes",
            value_string(value, "/capture/capture_id"),
            value_string(value, "/capture/provider"),
            value_string(value, "/capture/requested_model"),
            value_string(value, "/capture/capture_state"),
            value_string(value, "/capture/finalization_state"),
            value_string(value, "/capture/request_bytes"),
            value_string(value, "/capture/response_bytes"),
        )),
        CliCommand::Finalize(_) => Ok(format!(
            "{} operation {} ({})",
            if value
                .get("deduplicated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "Existing"
            } else {
                "Queued"
            },
            value_string(value, "/operation/operation_id"),
            value_string(value, "/operation/state"),
        )),
        CliCommand::Operations {
            command: OperationsCommand::List(_),
        } => list_lines(value, "/items", |item| {
            format!(
                "{}\t{}\t{}\t{}",
                value_string(item, "/operation_id"),
                value_string(item, "/kind"),
                value_string(item, "/state"),
                value_string(item, "/capture_id"),
            )
        }),
        CliCommand::Operations {
            command: OperationsCommand::Show(_) | OperationsCommand::Retry(_),
        } => Ok(format!(
            "operation {}\nkind {}\ncapture {}\nstate {}\nattempt {}",
            value_string(value, "/operation_id"),
            value_string(value, "/kind"),
            value_string(value, "/capture_id"),
            value_string(value, "/state"),
            value_string(value, "/attempt"),
        )),
        CliCommand::Traces {
            command: TracesCommand::Show(_),
        } => serde_json::to_string_pretty(value)
            .map_err(|_| CliError::new(EXIT_ERROR, "could not encode trace output")),
        CliCommand::Traces {
            command: TracesCommand::Verify(_),
        } => Ok(format!(
            "Verified capture {} with {} ({})",
            value_string(value, "/capture_id"),
            value_string(value, "/notary_key_id"),
            value_string(value, "/trust_source"),
        )),
        CliCommand::Login | CliCommand::Whoami => {
            if value
                .get("signed_in")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                Ok(format!(
                    "Connected to LLM Notary as {} ({}: {})",
                    value_string(value, "/github_login"),
                    value_string(value, "/credential_kind"),
                    value_string(value, "/credential_name"),
                ))
            } else {
                Ok("No LLM Notary account is connected.".to_owned())
            }
        }
        CliCommand::Logout => Ok(
            "Disconnected from LLM Notary. Future hosted sessions use public access.".to_owned(),
        ),
        CliCommand::Share(_) => Ok(format!(
            "Queued {} share {} for capture {} ({})",
            value_string(value, "/visibility"),
            value_string(value, "/share_id"),
            value_string(value, "/capture_id"),
            value_string(value, "/state"),
        )),
        CliCommand::Events(_) => list_lines(value, "/items", |item| {
            format!(
                "{}\t{}\t{}\t{}",
                value_string(item, "/event_id"),
                value_string(item, "/severity"),
                value_string(item, "/event_type"),
                value_string(item, "/message"),
            )
        }),
        CliCommand::Notaries { .. } => list_lines(value, "/notaries", |item| {
            format!(
                "{}\t{}\t{}",
                value_string(item, "/status"),
                value_string(item, "/endpoint"),
                value_string(item, "/key_id"),
            )
        }),
        CliCommand::Open => Ok(format!("Opened {}", value_string(value, "/opened"))),
    }
}

fn list_lines(
    value: &Value,
    pointer: &str,
    format_item: impl Fn(&Value) -> String,
) -> Result<String, CliError> {
    let items = value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an incomplete response; check that the CLI and daemon versions match",
            )
        })?;
    if items.is_empty() {
        return Ok("No results.".to_owned());
    }
    Ok(items.iter().map(format_item).collect::<Vec<_>>().join("\n"))
}

fn value_string(value: &Value, pointer: &str) -> String {
    match value.pointer(pointer) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => "-".to_owned(),
    }
}

fn open_dashboard(url: &str) -> Result<(), CliError> {
    #[cfg(target_os = "macos")]
    let result = ProcessCommand::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let result = ProcessCommand::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = ProcessCommand::new("xdg-open").arg(url).spawn();
    result.map_err(|_| {
        CliError::new(
            EXIT_ERROR,
            format!("could not open the browser; visit {url} directly"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        http::StatusCode as AxumStatus,
        routing::{get, post},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use std::sync::Arc;

    #[test]
    fn every_initial_command_parses_and_the_cli_never_has_an_implicit_daemon_mode() {
        assert!(Cli::try_parse_from(["llm-notary"]).is_err());
        for arguments in [
            vec!["llm-notary", "status"],
            vec!["llm-notary", "captures", "list"],
            vec!["llm-notary", "captures", "show", "cap-example"],
            vec!["llm-notary", "finalize", "cap-example"],
            vec!["llm-notary", "operations", "list"],
            vec!["llm-notary", "operations", "show", "op-example"],
            vec!["llm-notary", "operations", "retry", "op-example"],
            vec!["llm-notary", "traces", "show", "cap-example"],
            vec!["llm-notary", "traces", "verify", "cap-example"],
            vec!["llm-notary", "traces", "verify", "capture.llmtrace"],
            vec!["llm-notary", "login"],
            vec!["llm-notary", "logout"],
            vec!["llm-notary", "whoami"],
            vec!["llm-notary", "share", "cap-example"],
            vec![
                "llm-notary",
                "share",
                "cap-example",
                "--visibility",
                "listed",
            ],
            vec!["llm-notary", "publish", "cap-example"],
            vec!["llm-notary", "events"],
            vec!["llm-notary", "notaries", "list"],
            vec!["llm-notary", "open"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }

    #[tokio::test]
    async fn trace_file_verification_bypasses_the_daemon_and_rejects_private_bundles() {
        let directory = tempfile::tempdir().unwrap();
        let bundle = directory.path().join("capture.llmbundle");
        fs::write(&bundle, b"encrypted private retry state").unwrap();
        let cli = Cli::try_parse_from(["llm-notary", "traces", "verify", bundle.to_str().unwrap()])
            .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = run_parsed(cli, &mut stdout, &mut stderr).await.unwrap_err();

        assert!(error.to_string().contains("private retry state"));
        assert!(!error.to_string().contains("start the daemon"));
        assert!(stdout.is_empty());
    }

    #[test]
    fn human_and_json_output_are_deterministic() {
        let command = CliCommand::Finalize(IdArgs {
            id: "cap-example".to_owned(),
        });
        let value = json!({
            "operation": { "operation_id": "op-example", "state": "queued" },
            "deduplicated": false
        });
        assert_eq!(
            human_output(&command, &value).unwrap(),
            "Queued operation op-example (queued)"
        );
        assert_eq!(
            serde_json::to_string_pretty(&value).unwrap(),
            "{\n  \"deduplicated\": false,\n  \"operation\": {\n    \"operation_id\": \"op-example\",\n    \"state\": \"queued\"\n  }\n}"
        );

        let connected = json!({
            "signed_in": true,
            "github_login": "octocat",
            "device_name": "workstation",
            "credential_kind": "cli_session",
            "credential_name": "workstation"
        });
        assert_eq!(
            human_output(&CliCommand::Whoami, &connected).unwrap(),
            "Connected to LLM Notary as octocat (cli_session: workstation)"
        );
        assert_eq!(
            human_output(&CliCommand::Whoami, &json!({ "signed_in": false })).unwrap(),
            "No LLM Notary account is connected."
        );
        assert_eq!(
            human_output(&CliCommand::Logout, &json!({ "signed_in": false })).unwrap(),
            "Disconnected from LLM Notary. Future hosted sessions use public access."
        );
    }

    #[test]
    fn api_errors_have_documented_exit_classes_and_safe_messages() {
        let cases = [
            (StatusCode::BAD_REQUEST, EXIT_INVALID_INPUT),
            (StatusCode::UNAUTHORIZED, EXIT_AUTHENTICATION),
            (StatusCode::NOT_FOUND, EXIT_NOT_FOUND),
            (StatusCode::CONFLICT, EXIT_CONFLICT),
            (StatusCode::TOO_MANY_REQUESTS, EXIT_RETRYABLE),
            (StatusCode::INTERNAL_SERVER_ERROR, EXIT_RETRYABLE),
        ];
        for (status, expected) in cases {
            let error = api_error(
                status,
                br#"{"error":{"code":"safe_code","message":"safe message"}}"#,
            );
            assert_eq!(error.exit_code(), expected);
            assert!(!error.to_string().contains("credential"));
        }
    }

    #[test]
    fn rejects_non_loopback_admin_addresses() {
        let error = AdminClient::new("0.0.0.0:8788".parse().unwrap(), None)
            .err()
            .unwrap();
        assert_eq!(error.exit_code(), EXIT_INVALID_INPUT);
    }

    #[cfg(unix)]
    #[test]
    fn password_files_must_be_private_and_trim_one_line_ending() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin-password");
        fs::write(&path, b"local secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_password_file(&path).unwrap_err();
        assert_eq!(error.exit_code(), EXIT_AUTHENTICATION);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_password_file(&path).unwrap(), "local secret");
    }

    #[tokio::test]
    async fn checks_version_and_maps_safe_status_specific_errors() {
        let router = Router::new()
            .route(
                "/healthz",
                get(|| async { Json(json!({ "service": "llm-notaryd", "api_version": "v1" })) }),
            )
            .route(
                "/v1/status",
                get(|| async {
                    (
                        AxumStatus::CONFLICT,
                        Json(json!({
                            "error": { "code": "busy", "message": "operation is already active" }
                        })),
                    )
                }),
            );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();
        client.verify_version().await.unwrap();
        let error = client
            .request(Method::GET, "/v1/status", &[])
            .await
            .unwrap_err();
        assert_eq!(error.exit_code(), EXIT_CONFLICT);
        assert_eq!(error.to_string(), "operation is already active");
        server.abort();
    }

    #[tokio::test]
    async fn basic_secret_is_sent_only_to_protected_api_calls() {
        let expected = format!("Basic {}", BASE64_STANDARD.encode("local-admin:secret"));
        let router = Router::new()
            .route(
                "/healthz",
                get(|headers: axum::http::HeaderMap| async move {
                    assert!(!headers.contains_key(axum::http::header::AUTHORIZATION));
                    Json(json!({ "service": "llm-notaryd", "api_version": "v1" }))
                }),
            )
            .route(
                "/v1/status",
                get(move |headers: axum::http::HeaderMap| {
                    let expected = expected.clone();
                    async move {
                        assert_eq!(
                            headers
                                .get(axum::http::header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok()),
                            Some(expected.as_str())
                        );
                        Json(json!({ "version": "test" }))
                    }
                }),
            );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(
            address,
            Some(AdminCredentials {
                username: "local-admin".to_owned(),
                password: "secret".to_owned(),
            }),
        )
        .unwrap();
        client.verify_version().await.unwrap();
        client
            .request(Method::GET, "/v1/status", &[])
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn json_requests_send_the_body_and_content_type() {
        let router = Router::new().route(
            "/v1/account",
            post(|Json(body): Json<Value>| async move {
                assert_eq!(body, json!({}));
                (AxumStatus::ACCEPTED, Json(json!({ "state": "pending" })))
            }),
        );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();
        let response = client
            .request_json(Method::POST, "/v1/account", &[], &json!({}))
            .await
            .unwrap();
        assert_eq!(response["state"], "pending");
        server.abort();
    }

    #[tokio::test]
    async fn rejects_api_version_mismatch_before_commands() {
        let router = Router::new().route(
            "/healthz",
            get(|| async { Json(json!({ "service": "llm-notaryd", "api_version": "v2" })) }),
        );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();
        let error = client.verify_version().await.unwrap_err();
        assert_eq!(error.exit_code(), EXIT_VERSION_MISMATCH);
        assert!(error.to_string().contains("requires v1"));
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_daemon_has_an_actionable_exit_class() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = AdminClient::new(address, None).unwrap();
        let error = client.verify_version().await.unwrap_err();
        assert_eq!(error.exit_code(), EXIT_UNAVAILABLE);
        assert!(error.to_string().contains("start the daemon"));
    }

    #[tokio::test]
    async fn real_admin_api_exercises_read_and_mutation_commands() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = AgentConfig::default();
        config.catalog.path = directory.path().join("catalog.db");
        config.storage.bundle_dir = directory.path().join("bundles");
        config.storage.finalized_dir = directory.path().join("traces");
        let catalog = Arc::new(crate::catalog::Catalog::open_for_config(&config).unwrap());
        catalog
            .begin_capture(&crate::catalog::NewCapture {
                capture_id: "cap-cli-e2e".to_owned(),
                created_at_unix_ms: 1,
                provider: "openai".to_owned(),
                operation: "/v1/responses".to_owned(),
                requested_model: Some("gpt-test".to_owned()),
                streaming: false,
                request_bytes: 10,
                prompt_preview: "safe fixture".to_owned(),
                prompt_preview_truncated: false,
                config_fingerprint: "sha256:fixture".to_owned(),
            })
            .unwrap();
        fs::create_dir_all(&config.storage.bundle_dir).unwrap();
        let bundle = config.storage.bundle_dir.join("cap-cli-e2e.llmbundle");
        fs::write(&bundle, b"encrypted fixture").unwrap();
        catalog
            .complete_capture(
                "cap-cli-e2e",
                2,
                1,
                200,
                20,
                Some("gpt-test"),
                "safe output",
                false,
                &bundle,
            )
            .unwrap();
        let state = crate::admin::AdminState::new(catalog, Arc::new(config)).unwrap();
        let router = crate::admin::router(state).unwrap();
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();

        client.verify_version().await.unwrap();
        let captures = client
            .request(
                Method::GET,
                "/v1/captures",
                &[("provider".to_owned(), "openai".to_owned())],
            )
            .await
            .unwrap();
        assert_eq!(captures["items"][0]["capture_id"], "cap-cli-e2e");
        let finalization = client
            .request(Method::POST, "/v1/captures/cap-cli-e2e/finalizations", &[])
            .await
            .unwrap();
        assert_eq!(finalization["operation"]["state"], "queued");
        assert!(
            finalization["operation"]["operation_id"]
                .as_str()
                .unwrap()
                .starts_with("op-")
        );
        server.abort();
    }

    async fn serve(router: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (address, server)
    }
}
