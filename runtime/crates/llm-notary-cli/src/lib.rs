//! Short-lived command client for the versioned loopback administration API.

use std::{
    ffi::OsString,
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use llm_notary_updater::{self as update, BUILD_ID, write_private_file_atomically};

const API_VERSION: &str = "v1";
const AGENT_SKILL_NAME: &str = "llm-notary";
const CLAUDE_SKILL_ACTIVATION_NOTE: &str = "restart Claude Code if its top-level skills directory did not exist when the current session started";
const AGENT_SKILL_FILES: &[(&str, &str)] = &[
    (
        "SKILL.md",
        include_str!("../../../skills/llm-notary/SKILL.md"),
    ),
    (
        "agents/openai.yaml",
        include_str!("../../../skills/llm-notary/agents/openai.yaml"),
    ),
    (
        "references/workflows.md",
        include_str!("../../../skills/llm-notary/references/workflows.md"),
    ),
];
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
    code: String,
    message: String,
    reported: bool,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn is_reported(&self) -> bool {
        self.reported
    }

    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self::coded(exit_code, default_error_code(exit_code), message)
    }

    fn coded(exit_code: i32, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            code: code.into(),
            message: message.into(),
            reported: false,
        }
    }

    fn json_value(&self) -> Value {
        json!({
            "error": {
                "code": &self.code,
                "message": &self.message,
            }
        })
    }

    fn reported(mut self) -> Self {
        self.reported = true;
        self
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(EXIT_INVALID_INPUT, message)
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(EXIT_UNAVAILABLE, message)
    }
}

fn default_error_code(exit_code: i32) -> &'static str {
    match exit_code {
        EXIT_INVALID_INPUT => "invalid_input",
        EXIT_UNAVAILABLE => "daemon_unavailable",
        EXIT_AUTHENTICATION => "authentication_failed",
        EXIT_NOT_FOUND => "not_found",
        EXIT_CONFLICT => "conflict",
        EXIT_RETRYABLE => "retryable",
        EXIT_VERSION_MISMATCH => "version_mismatch",
        _ => "command_failed",
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
    long_version = format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION")),
    arg_required_else_help = true
)]
struct Cli {
    /// Print one stable JSON value to standard output.
    #[arg(long, global = true)]
    json: bool,

    /// Configuration used by notaryd. The CLI reads only the admin listener and username.
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
    /// Show this command-line client's exact release identity.
    Version,
    /// Check for or install the current signed release.
    Update(UpdateArgs),
    #[command(name = "__apply-update", hide = true)]
    ApplyUpdate(ApplyUpdateArgs),
    /// Install the portable LLM Notary agent skill.
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    /// Show daemon health, listeners, and capture counts.
    Status,
    /// Search or inspect captures.
    Captures {
        #[command(subcommand)]
        command: CapturesCommand,
    },
    /// Queue proof generation for a capture.
    Notarization(NotarizeArgs),
    /// List, inspect, or retry daemon-owned operations.
    Operations {
        #[command(subcommand)]
        command: OperationsCommand,
    },
    /// Inspect or verify a notarized trace.
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
    /// Create a public link for a notarized verified session.
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

#[derive(Args, Debug)]
struct UpdateArgs {
    /// Check the signed release channel without changing installed files.
    #[arg(long)]
    check: bool,
}

#[derive(Args, Debug)]
struct ApplyUpdateArgs {
    #[arg(long)]
    parent_pid: u32,
    #[arg(long)]
    install_directory: PathBuf,
    #[arg(long)]
    staging_directory: PathBuf,
    #[arg(long)]
    build_id: String,
}

#[derive(Subcommand, Debug)]
enum SkillCommand {
    /// Install or update the skill for a supported agent.
    Install(SkillInstallArgs),
}

#[derive(Args, Debug)]
struct SkillInstallArgs {
    /// Install for Codex, Claude Code, or both.
    #[arg(
        long,
        value_enum,
        required_unless_present = "skills_dir",
        conflicts_with = "skills_dir"
    )]
    target: Option<SkillTarget>,

    /// Install under this custom skills directory for another compatible agent.
    #[arg(long, value_name = "DIR", conflicts_with = "target")]
    skills_dir: Option<PathBuf>,

    /// Replace an existing skill whose bundled files differ.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SkillTarget {
    Codex,
    Claude,
    All,
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
    /// Show the canonical trace and manifest for a notarized capture.
    Show(IdArgs),
    /// Verify a notarized capture against the daemon's trust source.
    Verify(TraceVerifyArgs),
}

#[derive(Args, Debug)]
struct TraceVerifyArgs {
    /// A capture identifier in the daemon, or a portable `.llmtrace` path.
    target: String,

    /// Hex-encoded notary public key for path-based verification.
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
struct NotarizeArgs {
    /// Opaque capture identifier.
    id: String,

    /// Follow the operation and print proof-work progress until it finishes.
    #[arg(long)]
    wait: bool,
}

#[derive(Args, Debug)]
struct ShareArgs {
    /// Opaque notarized capture identifier.
    id: String,

    /// Whether the share appears in the public Library index.
    #[arg(long, value_enum, default_value_t = ShareVisibility::Unlisted)]
    visibility: ShareVisibility,

    /// Accept unexplained high-entropy values after reviewing the disclosure.
    /// Concrete secret detections and verification failures remain blocked.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ShareVisibility {
    Unlisted,
    Listed,
}

impl ShareVisibility {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
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
    capture_status: Option<String>,
    #[arg(long)]
    notarization_status: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    /// Continue from an opaque cursor returned by the daemon.
    #[arg(long)]
    cursor: Option<String>,
    /// Traverse every remaining page and emit one combined result.
    #[arg(long)]
    all: bool,
    /// Omit prompt and output previews from structured output.
    #[arg(long)]
    metadata_only: bool,
}

#[derive(Args, Debug, Default)]
struct OperationListArgs {
    #[arg(long)]
    state: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    trace_id: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    /// Continue from an opaque cursor returned by the daemon.
    #[arg(long)]
    cursor: Option<String>,
    /// Traverse every remaining page and emit one combined result.
    #[arg(long)]
    all: bool,
}

#[derive(Args, Debug, Default)]
struct EventListArgs {
    #[arg(long)]
    cursor: Option<String>,
    /// Follow events after a high-water cursor returned by an earlier request.
    #[arg(long)]
    after: Option<String>,
    #[arg(long)]
    severity: Option<String>,
    #[arg(long)]
    event_type: Option<String>,
    #[arg(long)]
    trace_id: Option<String>,
    #[arg(long)]
    operation_id: Option<String>,
    #[arg(long)]
    created_after_unix_ms: Option<u64>,
    #[arg(long)]
    limit: Option<usize>,
    /// Traverse every remaining page and emit one combined result.
    #[arg(long)]
    all: bool,
}

struct AdminCredentials {
    username: String,
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct DaemonClientConfig {
    #[serde(default)]
    admin: DaemonAdminConfig,
}

#[derive(Debug, Deserialize)]
struct DaemonAdminConfig {
    #[serde(default = "default_admin_listen")]
    listen: SocketAddr,
    #[serde(default)]
    auth: Option<DaemonAdminAuth>,
}

impl Default for DaemonAdminConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            auth: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DaemonAdminAuth {
    username: String,
}

struct AdminClient {
    origin: Url,
    client: reqwest::Client,
    credentials: Option<AdminCredentials>,
}

pub async fn run() -> Result<(), CliError> {
    let json_requested = std::env::args_os().any(|argument| argument == "--json");
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error
                .print()
                .map_err(|_| CliError::new(EXIT_ERROR, "could not write command help"))?;
            return Ok(());
        }
        Err(error) => {
            let error = CliError::coded(EXIT_INVALID_INPUT, "invalid_arguments", error.to_string());
            if json_requested {
                return report_json_error(error, &mut stdout);
            }
            return Err(error);
        }
    };
    run_with_output(cli, &mut stdout, &mut stderr).await
}

fn report_json_error(error: CliError, stdout: &mut dyn io::Write) -> Result<(), CliError> {
    let output = serde_json::to_string_pretty(&error.json_value())
        .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command error"))?;
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command error"))?;
    Err(error.reported())
}

async fn run_with_output(
    cli: Cli,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), CliError> {
    let json = cli.json;
    match run_parsed(cli, stdout, stderr).await {
        Err(error) if json => report_json_error(error, stdout),
        result => result,
    }
}

async fn run_parsed(
    cli: Cli,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write,
) -> Result<(), CliError> {
    if matches!(&cli.command, CliCommand::Version) {
        let windows_update = update::windows_update_result();
        let value = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "build_id": BUILD_ID,
            "official_build": update::is_official_build(),
            "last_windows_update": windows_update,
        });
        let windows_suffix = windows_update
            .as_ref()
            .map(|result| format!("; last Windows update: {}", result.state))
            .unwrap_or_default();
        return write_direct_output(
            cli.json,
            &value,
            format!(
                "LLM Notary {} ({}){}",
                env!("CARGO_PKG_VERSION"),
                BUILD_ID,
                windows_suffix,
            ),
            stdout,
        );
    }
    if let CliCommand::Update(args) = &cli.command {
        let value = if args.check {
            let check = update::check_latest().await.map_err(update_error)?;
            serde_json::to_value(&check)
                .map_err(|_| CliError::new(EXIT_ERROR, "could not encode update status"))?
        } else {
            let outcome = update::install_latest().await.map_err(update_error)?;
            serde_json::to_value(&outcome)
                .map_err(|_| CliError::new(EXIT_ERROR, "could not encode update result"))?
        };
        let human = update_human_output(&value, args.check)?;
        return write_direct_output(cli.json, &value, human, stdout);
    }
    if let CliCommand::ApplyUpdate(args) = &cli.command {
        update::run_windows_apply_helper(
            args.parent_pid,
            &args.install_directory,
            &args.staging_directory,
            &args.build_id,
        )
        .map_err(update_error)?;
        return Ok(());
    }
    if let CliCommand::Skill {
        command: SkillCommand::Install(args),
    } = &cli.command
    {
        let value = install_agent_skill(args)?;
        let human = skill_install_human_output(&value)?;
        return write_direct_output(cli.json, &value, human, stdout);
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
    let value = execute(&client, &cli.command, stderr, !cli.json).await?;
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

fn write_direct_output(
    json: bool,
    value: &Value,
    human: String,
    stdout: &mut dyn io::Write,
) -> Result<(), CliError> {
    let output = if json {
        serde_json::to_string_pretty(value)
            .map_err(|_| CliError::new(EXIT_ERROR, "could not encode command output"))?
    } else {
        human
    };
    writeln!(stdout, "{output}")
        .map_err(|_| CliError::new(EXIT_ERROR, "could not write command output"))
}

fn update_error(error: anyhow::Error) -> CliError {
    let message = error.to_string();
    let invalid = message.contains("source and development builds")
        || message.contains("package manager")
        || message.contains("desktop app")
        || message.contains("not available for");
    CliError::coded(
        if invalid {
            EXIT_INVALID_INPUT
        } else {
            EXIT_RETRYABLE
        },
        if invalid {
            "update_not_supported"
        } else {
            "update_failed"
        },
        message,
    )
}

fn update_human_output(value: &Value, check: bool) -> Result<String, CliError> {
    if check {
        let current = value
            .get("current_build_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let latest = value
            .get("latest_build_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let available = value
            .get("update_available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let official = value
            .get("official_build")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !official {
            return Ok(format!(
                "Latest signed build: {latest}\nThis source build ({current}) can check releases but cannot replace itself."
            ));
        }
        return Ok(if available {
            format!(
                "Update available: {current} → {latest}\nRun `llm-notary update` to install it."
            )
        } else {
            format!("LLM Notary is up to date ({current}).")
        });
    }
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new(EXIT_ERROR, "the update result is incomplete"))?;
    let build = value
        .get("new_build_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Ok(match state {
        "current" => format!("LLM Notary is already up to date ({build})."),
        "staged" => format!(
            "Update {build} is staged and will finish after this command exits. Restart notaryd when no capture or notarization is active."
        ),
        _ => format!(
            "Updated llm-notary and notaryd to {build}. Restart notaryd when no capture or notarization is active."
        ),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SkillInstallState {
    Current,
    Installed,
    Updated,
}

impl SkillInstallState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Installed => "installed",
            Self::Updated => "updated",
        }
    }
}

struct SkillDestination {
    agent: &'static str,
    path: PathBuf,
}

fn install_agent_skill(args: &SkillInstallArgs) -> Result<Value, CliError> {
    let destinations = skill_destinations(args)?;
    install_agent_skill_at(&destinations, args.force)
}

fn skill_destinations(args: &SkillInstallArgs) -> Result<Vec<SkillDestination>, CliError> {
    if let Some(skills_dir) = &args.skills_dir {
        return Ok(vec![SkillDestination {
            agent: "custom",
            path: skills_dir.join(AGENT_SKILL_NAME),
        }]);
    }

    let claude_config_dir = first_nonempty_path([std::env::var_os("CLAUDE_CONFIG_DIR")]);
    let target = args
        .target
        .ok_or_else(|| CliError::invalid("skill install requires --target or --skills-dir"))?;
    let home = if target == SkillTarget::Claude && claude_config_dir.is_some() {
        None
    } else {
        Some(user_home_directory()?)
    };
    skill_target_destinations(target, home.as_deref(), claude_config_dir.as_deref())
}

fn skill_target_destinations(
    target: SkillTarget,
    home: Option<&Path>,
    claude_config_dir: Option<&Path>,
) -> Result<Vec<SkillDestination>, CliError> {
    let home = || home.ok_or_else(|| CliError::invalid("could not locate the user home directory"));
    let claude_config_dir = match claude_config_dir {
        Some(path) => path.to_path_buf(),
        None => home()?.join(".claude"),
    };
    let mut destinations = Vec::new();
    match target {
        SkillTarget::Codex => destinations.push(SkillDestination {
            agent: "codex",
            path: home()?.join(".agents/skills").join(AGENT_SKILL_NAME),
        }),
        SkillTarget::Claude => destinations.push(SkillDestination {
            agent: "claude",
            path: claude_config_dir.join("skills").join(AGENT_SKILL_NAME),
        }),
        SkillTarget::All => {
            destinations.push(SkillDestination {
                agent: "codex",
                path: home()?.join(".agents/skills").join(AGENT_SKILL_NAME),
            });
            destinations.push(SkillDestination {
                agent: "claude",
                path: claude_config_dir.join("skills").join(AGENT_SKILL_NAME),
            });
        }
    }
    Ok(destinations)
}

fn user_home_directory() -> Result<PathBuf, CliError> {
    #[cfg(windows)]
    let candidates = [std::env::var_os("USERPROFILE"), std::env::var_os("HOME")];
    #[cfg(not(windows))]
    let candidates = [std::env::var_os("HOME")];

    first_nonempty_path(candidates)
        .ok_or_else(|| CliError::invalid("could not locate the user home directory"))
}

fn first_nonempty_path<const N: usize>(candidates: [Option<OsString>; N]) -> Option<PathBuf> {
    candidates
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn install_agent_skill_at(
    destinations: &[SkillDestination],
    force: bool,
) -> Result<Value, CliError> {
    let states = destinations
        .iter()
        .map(|destination| inspect_skill_destination(destination, force))
        .collect::<Result<Vec<_>, _>>()?;

    for (destination, state) in destinations.iter().zip(states.iter()) {
        if *state == SkillInstallState::Current {
            continue;
        }
        for (relative, contents) in AGENT_SKILL_FILES {
            let path = destination.path.join(relative);
            write_private_file_atomically(&path, contents.as_bytes()).map_err(|_| {
                CliError::new(
                    EXIT_ERROR,
                    format!("could not write agent skill file {}", path.display()),
                )
            })?;
        }
    }

    Ok(json!({
        "skill": AGENT_SKILL_NAME,
        "targets": destinations
            .iter()
            .zip(states)
            .map(|(destination, state)| json!({
                "agent": destination.agent,
                "activation_note": (destination.agent == "claude")
                    .then_some(CLAUDE_SKILL_ACTIVATION_NOTE),
                "path": destination.path.display().to_string(),
                "state": state.as_str(),
            }))
            .collect::<Vec<_>>(),
    }))
}

fn inspect_skill_destination(
    destination: &SkillDestination,
    force: bool,
) -> Result<SkillInstallState, CliError> {
    match fs::symlink_metadata(&destination.path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(skill_conflict(&destination.path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SkillInstallState::Installed);
        }
        Err(_) => {
            return Err(CliError::new(
                EXIT_ERROR,
                format!(
                    "could not inspect existing agent skill {}",
                    destination.path.display()
                ),
            ));
        }
    }

    let mut current = true;
    for (relative, expected) in AGENT_SKILL_FILES {
        let path = destination.path.join(relative);
        validate_managed_skill_path(&destination.path, relative)?;
        match fs::read(&path) {
            Ok(actual) if actual == expected.as_bytes() => {}
            Ok(_) => current = false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => current = false,
            Err(_) => {
                return Err(CliError::new(
                    EXIT_ERROR,
                    format!(
                        "could not read existing agent skill file {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    if current {
        Ok(SkillInstallState::Current)
    } else if force {
        Ok(SkillInstallState::Updated)
    } else {
        Err(skill_conflict(&destination.path))
    }
}

fn validate_managed_skill_path(root: &Path, relative: &str) -> Result<(), CliError> {
    let mut path = root.to_path_buf();
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(skill_conflict(&path));
            }
            Ok(metadata) if components.peek().is_some() && !metadata.is_dir() => {
                return Err(skill_conflict(&path));
            }
            Ok(metadata) if components.peek().is_none() && !metadata.is_file() => {
                return Err(skill_conflict(&path));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => {
                return Err(CliError::new(
                    EXIT_ERROR,
                    format!(
                        "could not inspect existing agent skill path {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn skill_conflict(path: &Path) -> CliError {
    CliError::coded(
        EXIT_CONFLICT,
        "skill_install_conflict",
        format!(
            "an existing skill at {} differs from this release; inspect it, then rerun with --force to replace the bundled files",
            path.display()
        ),
    )
}

fn skill_install_human_output(value: &Value) -> Result<String, CliError> {
    let targets = value
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill install result is incomplete"))?;
    targets
        .iter()
        .map(|target| {
            let agent = target
                .get("agent")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill target is incomplete"))?;
            let path = target
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill path is incomplete"))?;
            let state = target
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::new(EXIT_ERROR, "the skill state is incomplete"))?;
            let mut line = format!("{agent}: {state} at {path}");
            if let Some(note) = target.get("activation_note").and_then(Value::as_str) {
                line.push_str(&format!("\n{agent}: {note}"));
            }
            Ok(line)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
}

fn load_config_for_cli(path: Option<&Path>) -> Result<DaemonClientConfig, CliError> {
    let explicit = path.is_some();
    let path = match path {
        Some(path) => path.to_owned(),
        None => update::default_config_path().map_err(|error| {
            CliError::invalid(format!(
                "could not locate the daemon configuration: {error}"
            ))
        })?,
    };
    if !path.exists() && !explicit {
        return Ok(DaemonClientConfig::default());
    }
    let contents = fs::read_to_string(&path).map_err(|error| {
        CliError::invalid(format!(
            "could not read daemon configuration {}: {error}",
            path.display()
        ))
    })?;
    toml::from_str(&contents).map_err(|error| {
        CliError::invalid(format!(
            "could not parse daemon configuration {}: {error}",
            path.display()
        ))
    })
}

fn default_admin_listen() -> SocketAddr {
    "127.0.0.1:8788"
        .parse()
        .expect("valid default administration listener")
}

fn load_admin_credentials(
    config: &DaemonClientConfig,
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
        if service != "notaryd" {
            return Err(CliError::new(
                EXIT_VERSION_MISMATCH,
                format!("unexpected local service {service}; this CLI requires notaryd"),
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

    async fn verify_package(
        &self,
        path: &Path,
        trusted_notary_key: Option<&str>,
    ) -> Result<Value, CliError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| CliError::invalid("the .llmtrace path could not be read"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError::invalid(
                "the .llmtrace path must name one regular file",
            ));
        }
        let bytes = fs::read(path)
            .map_err(|_| CliError::invalid("the .llmtrace path could not be read"))?;
        let url = self.url("/v1/traces:verify", &[])?;
        let mut request = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/vnd.exalto.notary.trace-package+zip",
            )
            .body(bytes);
        if let Some(credentials) = &self.credentials {
            request = request.basic_auth(&credentials.username, Some(&credentials.password));
        }
        if let Some(key) = trusted_notary_key {
            request = request.header("x-notary-trusted-notary-key", key);
        }
        let response = request.send().await.map_err(|_| {
            CliError::unavailable(format!(
                "notaryd is unavailable at {}; start the daemon and try again",
                self.origin
            ))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon verification response ended early",
            )
        })?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                EXIT_RETRYABLE,
                "the daemon returned an invalid verification response",
            )
        })
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
                "notaryd is unavailable at {}; start the daemon and try again",
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
    let (exit_code, fallback_code, message) = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => (
            EXIT_INVALID_INPUT,
            "invalid_input",
            message
                .unwrap_or("the daemon rejected the command input")
                .to_owned(),
        ),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            EXIT_AUTHENTICATION,
            "authentication_failed",
            "local admin authentication failed; check the configured username and password"
                .to_owned(),
        ),
        StatusCode::NOT_FOUND => (
            EXIT_NOT_FOUND,
            "not_found",
            message
                .unwrap_or("the requested local resource was not found")
                .to_owned(),
        ),
        StatusCode::CONFLICT => (
            EXIT_CONFLICT,
            "conflict",
            message
                .unwrap_or("the requested operation conflicts with current daemon state")
                .to_owned(),
        ),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => (
            EXIT_RETRYABLE,
            "retryable",
            message
                .unwrap_or("the daemon is temporarily unable to accept this operation")
                .to_owned(),
        ),
        status if status.is_server_error() => (
            EXIT_RETRYABLE,
            "daemon_error",
            match code {
                Some(code) => {
                    format!("the daemon could not complete the request ({code}); try again")
                }
                None => "the daemon could not complete the request; try again".to_owned(),
            },
        ),
        _ => (
            EXIT_ERROR,
            "command_rejected",
            message
                .unwrap_or("the daemon rejected the command")
                .to_owned(),
        ),
    };
    CliError::coded(exit_code, code.unwrap_or(fallback_code), message)
}

async fn execute(
    client: &AdminClient,
    command: &CliCommand,
    stderr: &mut dyn io::Write,
    show_progress: bool,
) -> Result<Value, CliError> {
    match command {
        CliCommand::Version
        | CliCommand::Update(_)
        | CliCommand::ApplyUpdate(_)
        | CliCommand::Skill { .. } => {
            unreachable!("direct commands are handled before daemon configuration")
        }
        CliCommand::Status => client.request(Method::GET, "/v1/status", &[]).await,
        CliCommand::Captures { command } => match command {
            CapturesCommand::List(args) => {
                let mut response =
                    list_request(client, "/v1/traces", capture_query(args), args.all).await?;
                if args.metadata_only {
                    remove_capture_previews(&mut response)?;
                }
                Ok(response)
            }
            CapturesCommand::Show(args) => {
                validate_identifier(&args.id, "trc-")?;
                client
                    .request(Method::GET, &format!("/v1/traces/{}", args.id), &[])
                    .await
            }
        },
        CliCommand::Notarization(args) => {
            validate_identifier(&args.id, "trc-")?;
            let mut response = client
                .request(
                    Method::POST,
                    &format!("/v1/traces/{}/notarizations", args.id),
                    &[],
                )
                .await?;
            if args.wait {
                let operation_id =
                    required_string(&response, "/operation/operation_id")?.to_owned();
                let operation = wait_for_notarization(
                    client,
                    &operation_id,
                    stderr,
                    show_progress,
                    response.get("operation").cloned(),
                )
                .await?;
                response
                    .as_object_mut()
                    .ok_or_else(incomplete_page_error)?
                    .insert("operation".to_owned(), operation);
            }
            Ok(response)
        }
        CliCommand::Operations { command } => match command {
            OperationsCommand::List(args) => {
                list_request(client, "/v1/operations", operation_query(args), args.all).await
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
                validate_identifier(&args.id, "trc-")?;
                client
                    .request(Method::GET, &format!("/v1/traces/{}/trace", args.id), &[])
                    .await
            }
            TracesCommand::Verify(args) => {
                if verify_target_is_file(&args.target) {
                    return client
                        .verify_package(Path::new(&args.target), args.trusted_notary_key.as_deref())
                        .await;
                }
                validate_identifier(&args.target, "trc-")?;
                if args.trusted_notary_key.is_some() {
                    return Err(CliError::invalid(
                        "--trusted-notary-key is only valid with a .llmtrace path",
                    ));
                }
                client
                    .request(
                        Method::POST,
                        &format!("/v1/traces/{}/trace:verify", args.target),
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
            validate_identifier(&args.id, "trc-")?;
            client
                .request_json(
                    Method::POST,
                    &format!("/v1/traces/{}/shares", args.id),
                    &[],
                    &json!({ "visibility": args.visibility.as_str(), "force": args.force }),
                )
                .await
        }
        CliCommand::Events(args) => {
            list_request(client, "/v1/events", event_query(args), args.all).await
        }
        CliCommand::Notaries { .. } => client.request(Method::GET, "/v1/notaries", &[]).await,
        CliCommand::Open => {
            open_dashboard(client.origin.as_str())?;
            Ok(json!({ "opened": client.origin.as_str() }))
        }
    }
}

fn verify_target_is_file(target: &str) -> bool {
    Path::new(target).is_file() || validate_identifier(target, "trc-").is_err()
}

async fn wait_for_notarization(
    client: &AdminClient,
    operation_id: &str,
    stderr: &mut dyn io::Write,
    show_progress: bool,
    mut operation: Option<Value>,
) -> Result<Value, CliError> {
    let mut last_progress = String::new();
    loop {
        let current = match operation.take() {
            Some(operation) => operation,
            None => {
                client
                    .request(Method::GET, &format!("/v1/operations/{operation_id}"), &[])
                    .await?
            }
        };
        let state = required_string(&current, "/state")?;
        let progress = operation_progress(&current);
        if show_progress && progress != last_progress {
            writeln!(stderr, "{progress}").ok();
            last_progress = progress;
        }
        if notarization_is_terminal_state(state) {
            return Ok(current);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn notarization_is_terminal_state(state: &str) -> bool {
    ["succeeded", "failed", "interrupted"].contains(&state)
}

fn operation_progress(value: &Value) -> String {
    let phase = value_string(value, "/progress/phase");
    if phase == "proving" {
        let bytes_completed = value_i64(value, "/progress/proof/bytes_completed");
        let bytes_total = value_i64(value, "/progress/proof/bytes_total");
        let commitments_completed = value_i64(value, "/progress/proof/commitments_completed");
        let commitments_total = value_i64(value, "/progress/proof/commitments_total");
        if bytes_total > 0 && commitments_total > 0 {
            return format!(
                "Private proof: {} / {} authenticated; {commitments_completed} / {commitments_total} commitments sealed",
                format_bytes(bytes_completed),
                format_bytes(bytes_total),
            );
        }
    }
    match phase.as_str() {
        "queued" => "Notarization queued".to_owned(),
        "preparing" => "Preparing proof inputs".to_owned(),
        "signing" => "Requesting notary signature".to_owned(),
        "packaging" => "Building verified package".to_owned(),
        "complete" => "Verified package complete".to_owned(),
        _ => format!("Notarization {phase}"),
    }
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
    push_string(&mut query, "capture_status", args.capture_status.as_deref());
    push_string(
        &mut query,
        "notarization_status",
        args.notarization_status.as_deref(),
    );
    push_number(&mut query, "limit", args.limit);
    push_string(&mut query, "cursor", args.cursor.as_deref());
    query
}

fn remove_capture_previews(value: &mut Value) -> Result<(), CliError> {
    let items = value
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(incomplete_page_error)?;
    for item in items {
        let item = item.as_object_mut().ok_or_else(incomplete_page_error)?;
        for field in [
            "prompt_preview",
            "prompt_preview_truncated",
            "output_preview",
            "output_preview_truncated",
        ] {
            item.remove(field);
        }
    }
    Ok(())
}

fn operation_query(args: &OperationListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "state", args.state.as_deref());
    push_string(&mut query, "kind", args.kind.as_deref());
    push_string(&mut query, "trace_id", args.trace_id.as_deref());
    push_number(&mut query, "limit", args.limit);
    push_string(&mut query, "cursor", args.cursor.as_deref());
    query
}

fn event_query(args: &EventListArgs) -> Vec<(String, String)> {
    let mut query = Vec::new();
    push_string(&mut query, "cursor", args.cursor.as_deref());
    push_string(&mut query, "after", args.after.as_deref());
    push_string(&mut query, "severity", args.severity.as_deref());
    push_string(&mut query, "event_type", args.event_type.as_deref());
    push_string(&mut query, "trace_id", args.trace_id.as_deref());
    push_string(&mut query, "operation_id", args.operation_id.as_deref());
    push_number(
        &mut query,
        "created_after_unix_ms",
        args.created_after_unix_ms,
    );
    push_number(&mut query, "limit", args.limit);
    query
}

async fn list_request(
    client: &AdminClient,
    path: &str,
    mut query: Vec<(String, String)>,
    all: bool,
) -> Result<Value, CliError> {
    let mut response = client.request(Method::GET, path, &query).await?;
    if !all {
        return Ok(response);
    }
    let mut items = response
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .ok_or_else(incomplete_page_error)?;
    while let Some(cursor) = response
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        set_query_value(&mut query, "cursor", cursor);
        response = client.request(Method::GET, path, &query).await?;
        let page = response
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .map(std::mem::take)
            .ok_or_else(incomplete_page_error)?;
        items.extend(page);
    }
    let object = response.as_object_mut().ok_or_else(incomplete_page_error)?;
    object.insert("items".to_owned(), Value::Array(items));
    object.insert("next_cursor".to_owned(), Value::Null);
    Ok(response)
}

fn incomplete_page_error() -> CliError {
    CliError::new(
        EXIT_RETRYABLE,
        "the daemon returned an incomplete page; check that the CLI and daemon versions match",
    )
}

fn set_query_value(query: &mut Vec<(String, String)>, key: &str, value: String) {
    if let Some((_, current)) = query.iter_mut().find(|(name, _)| name == key) {
        *current = value;
    } else {
        query.push((key.to_owned(), value));
    }
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
        CliCommand::Version
        | CliCommand::Update(_)
        | CliCommand::ApplyUpdate(_)
        | CliCommand::Skill { .. } => {
            unreachable!("direct commands provide their own human output")
        }
        CliCommand::Status => Ok(format!(
            "notaryd {} ({})\nproxy {}\nadmin {}\nmetadata {} ({})\nartifacts {} ({})\ncaptures {} total, {} ready to notarize, {} notarized, {} failed\noperations {} active\nupdates {}",
            value_string(value, "/version"),
            value_string(value, "/build_id"),
            value_string(value, "/proxy_listener"),
            value_string(value, "/admin_listener"),
            value_string(value, "/metadata_backend"),
            value_string(value, "/metadata_status"),
            value_string(value, "/artifact_backend"),
            value_string(value, "/artifact_status"),
            value_string(value, "/counts/total_traces"),
            value_string(value, "/counts/ready_to_notarize"),
            value_string(value, "/counts/notarized"),
            value_string(value, "/counts/failed"),
            value_string(value, "/counts/active_operations"),
            if value.pointer("/updates/enabled").and_then(Value::as_bool) == Some(false) {
                "disabled for this source build".to_owned()
            } else if value
                .pointer("/updates/update_available")
                .and_then(Value::as_bool)
                == Some(true)
            {
                format!(
                    "available ({})",
                    value_string(value, "/updates/latest_build_id")
                )
            } else if value
                .pointer("/updates/error_code")
                .is_some_and(|value| !value.is_null())
            {
                "check failed".to_owned()
            } else if value
                .pointer("/updates/last_checked_unix_ms")
                .is_some_and(|value| !value.is_null())
            {
                "up to date".to_owned()
            } else {
                "not checked yet".to_owned()
            },
        )),
        CliCommand::Captures {
            command: CapturesCommand::List(_),
        } => list_lines(value, "/items", |item| {
            format!(
                "{}\t{}\t{}\t{} / {}",
                value_string(item, "/trace_id"),
                value_string(item, "/provider"),
                value_string(item, "/requested_model"),
                value_string(item, "/capture_status"),
                value_string(item, "/notarization_status"),
            )
        }),
        CliCommand::Captures {
            command: CapturesCommand::Show(_),
        } => Ok(format!(
            "capture {}\nprovider {}\nmodel {}\nstate {} / {}\nrequest {} bytes; response {} bytes",
            value_string(value, "/capture/trace_id"),
            value_string(value, "/capture/provider"),
            value_string(value, "/capture/requested_model"),
            value_string(value, "/capture/capture_status"),
            value_string(value, "/capture/notarization_status"),
            value_string(value, "/capture/request_bytes"),
            value_string(value, "/capture/response_bytes"),
        )),
        CliCommand::Notarization(args) => Ok(format!(
            "{} operation {} ({})",
            if args.wait {
                "Notarization"
            } else if value
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
                "{}\t{}\t{}\t{}\t{}",
                value_string(item, "/operation_id"),
                value_string(item, "/kind"),
                value_string(item, "/state"),
                value_string(item, "/progress/phase"),
                value_string(item, "/trace_id"),
            )
        }),
        CliCommand::Operations {
            command: OperationsCommand::Show(_) | OperationsCommand::Retry(_),
        } => Ok(format!(
            "operation {}\nkind {}\ncapture {}\nstate {}\nprogress {}\nattempt {}",
            value_string(value, "/operation_id"),
            value_string(value, "/kind"),
            value_string(value, "/trace_id"),
            value_string(value, "/state"),
            operation_progress(value),
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
            value_string(value, "/trace_id"),
            value_string(value, "/notary_key_id"),
            value_string(value, "/trust_source"),
        )),
        CliCommand::Login | CliCommand::Whoami => {
            if value
                .get("signed_in")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let display_name = match value_string(value, "/display_name").as_str() {
                    "-" => value_string(value, "/provider_display_name"),
                    name => name.to_owned(),
                };
                let provider = value_string(value, "/auth_provider");
                let credential = format!(
                    "{}: {}",
                    value_string(value, "/credential_kind"),
                    value_string(value, "/credential_name"),
                );
                let mut output = if provider == "-" {
                    format!("Connected to LLM Notary as {display_name} ({credential})")
                } else {
                    format!("Connected to LLM Notary as {display_name} ({provider}; {credential})")
                };
                if let Some(billing) = value.get("billing") {
                    output.push_str(&format!(
                        "\nplan {} ({}, purchase mode {})",
                        value_string(billing, "/service_plan"),
                        value_string(billing, "/billing_status"),
                        value_string(billing, "/purchase_mode"),
                    ));
                }
                if let Some(credits) = value.get("credits") {
                    output.push_str(&format!(
                        "\nnotarization used {} / {} granted; {} remaining ({} included, {} additional)",
                        format_bytes(value_i64(credits, "/notarization/total_used_bytes")),
                        format_bytes(value_i64(credits, "/notarization/total_granted_bytes")),
                        format_bytes(value_i64(credits, "/notarization/total_remaining_bytes")),
                        format_bytes(value_i64(credits, "/notarization/included_monthly_remaining_bytes")),
                        format_bytes(value_i64(credits, "/notarization/supplemental_remaining_bytes")),
                    ));
                    output.push_str(&format!(
                        "\ncapture used {} / {} granted; {} remaining",
                        format_bytes(value_i64(credits, "/capture/total_used_bytes")),
                        format_bytes(value_i64(credits, "/capture/total_granted_bytes")),
                        format_bytes(value_i64(credits, "/capture/total_remaining_bytes")),
                    ));
                    output.push_str(&format!(
                        "\nreset at {}",
                        value_string(credits, "/reset_at"),
                    ));
                    if credits
                        .pointer("/notarization/next_grant_expiration")
                        .is_some_and(|value| !value.is_null())
                    {
                        output.push_str(&format!(
                            "\nnext notarization expiration {}",
                            value_string(credits, "/notarization/next_grant_expiration"),
                        ));
                    }
                }
                if let Some(links) = value.get("links") {
                    output.push_str(&format!(
                        "\naccount {}\nusage {}\nplans {}\nsettings {}",
                        value_string(links, "/account"),
                        value_string(links, "/usage"),
                        value_string(links, "/plans"),
                        value_string(links, "/settings"),
                    ));
                }
                Ok(output)
            } else {
                match value_string(value, "/connection_state").as_str() {
                    "reauthorization_required" => Ok(
                        "LLM Notary account authorization has expired or was revoked; reconnect it."
                            .to_owned(),
                    ),
                    "unavailable" => Ok(
                        "LLM Notary account status is temporarily unavailable; local work remains available."
                            .to_owned(),
                    ),
                    _ => Ok("No LLM Notary account is connected.".to_owned()),
                }
            }
        }
        CliCommand::Logout => Ok(
            "Disconnected from LLM Notary. Future hosted sessions use public access.".to_owned(),
        ),
        CliCommand::Share(_) => Ok(format!(
            "Queued {} share {} for capture {} ({})",
            value_string(value, "/visibility"),
            value_string(value, "/share_id"),
            value_string(value, "/trace_id"),
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

fn value_i64(value: &Value, pointer: &str) -> i64 {
    value.pointer(pointer).and_then(Value::as_i64).unwrap_or(0)
}

fn format_bytes(bytes: i64) -> String {
    const MIB: f64 = (1 << 20) as f64;
    const GIB: f64 = (1 << 30) as f64;
    if bytes >= 1 << 30 {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else if bytes >= 1 << 20 {
        format!("{:.1} MiB", bytes as f64 / MIB)
    } else if bytes >= 1 << 10 {
        format!("{:.1} KiB", bytes as f64 / (1 << 10) as f64)
    } else {
        format!("{bytes} B")
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

    #[test]
    fn every_initial_command_parses_and_the_cli_never_has_an_implicit_daemon_mode() {
        assert!(Cli::try_parse_from(["llm-notary"]).is_err());
        for arguments in [
            vec!["llm-notary", "version"],
            vec!["llm-notary", "update", "--check"],
            vec!["llm-notary", "skill", "install", "--target", "codex"],
            vec!["llm-notary", "skill", "install", "--target", "claude"],
            vec!["llm-notary", "skill", "install", "--target", "all"],
            vec![
                "llm-notary",
                "skill",
                "install",
                "--skills-dir",
                "/tmp/agent-skills",
            ],
            vec!["llm-notary", "status"],
            vec!["llm-notary", "captures", "list"],
            vec!["llm-notary", "captures", "list", "--all"],
            vec!["llm-notary", "captures", "list", "--metadata-only"],
            vec![
                "llm-notary",
                "captures",
                "list",
                "--cursor",
                "opaque-cursor",
            ],
            vec!["llm-notary", "captures", "show", "trc-example"],
            vec!["llm-notary", "notarization", "trc-example"],
            vec!["llm-notary", "notarization", "trc-example", "--wait"],
            vec!["llm-notary", "operations", "list"],
            vec!["llm-notary", "operations", "list", "--all"],
            vec!["llm-notary", "operations", "show", "op-example"],
            vec!["llm-notary", "operations", "retry", "op-example"],
            vec!["llm-notary", "traces", "show", "trc-example"],
            vec!["llm-notary", "traces", "verify", "trc-example"],
            vec!["llm-notary", "login"],
            vec!["llm-notary", "logout"],
            vec!["llm-notary", "whoami"],
            vec!["llm-notary", "share", "trc-example"],
            vec![
                "llm-notary",
                "share",
                "trc-example",
                "--visibility",
                "listed",
            ],
            vec!["llm-notary", "events"],
            vec!["llm-notary", "events", "--all"],
            vec!["llm-notary", "events", "--after", "high-water"],
            vec!["llm-notary", "notaries", "list"],
            vec!["llm-notary", "open"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
        assert!(Cli::try_parse_from(["llm-notary", "publish", "trc-example"]).is_err());
    }

    #[test]
    fn version_flag_reports_the_exact_build_identity() {
        let error = Cli::try_parse_from(["llm-notary", "--version"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert!(
            error
                .to_string()
                .contains(&format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION")))
        );
    }

    #[tokio::test]
    async fn version_bypasses_configuration_and_the_daemon() {
        let missing = tempfile::tempdir().unwrap().path().join("missing.toml");
        let cli = Cli::try_parse_from([
            "llm-notary",
            "--json",
            "--config",
            missing.to_str().unwrap(),
            "version",
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_parsed(cli, &mut stdout, &mut stderr).await.unwrap();

        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value["build_id"], BUILD_ID);
        assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn skill_install_bypasses_configuration_and_the_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.toml");
        let skills = directory.path().join("skills");
        let cli = Cli::try_parse_from([
            "llm-notary",
            "--json",
            "--config",
            missing.to_str().unwrap(),
            "skill",
            "install",
            "--skills-dir",
            skills.to_str().unwrap(),
        ])
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        run_parsed(cli, &mut stdout, &mut stderr).await.unwrap();

        let value: Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(value["skill"], AGENT_SKILL_NAME);
        assert_eq!(value["targets"][0]["agent"], "custom");
        assert_eq!(value["targets"][0]["state"], "installed");
        for (relative, expected) in AGENT_SKILL_FILES {
            assert_eq!(
                fs::read_to_string(skills.join(AGENT_SKILL_NAME).join(relative)).unwrap(),
                *expected
            );
        }
        assert!(stderr.is_empty());
    }

    #[test]
    fn skill_install_preserves_modified_files_without_force() {
        let directory = tempfile::tempdir().unwrap();
        let codex = SkillDestination {
            agent: "codex",
            path: directory.path().join("codex/llm-notary"),
        };
        let claude = SkillDestination {
            agent: "claude",
            path: directory.path().join("claude/llm-notary"),
        };
        fs::create_dir_all(&claude.path).unwrap();
        fs::write(claude.path.join("SKILL.md"), "user-owned instructions\n").unwrap();

        let error = install_agent_skill_at(&[codex, claude], false).unwrap_err();

        assert_eq!(error.exit_code(), EXIT_CONFLICT);
        assert_eq!(error.code, "skill_install_conflict");
        assert!(!directory.path().join("codex/llm-notary").exists());
        assert_eq!(
            fs::read_to_string(directory.path().join("claude/llm-notary/SKILL.md")).unwrap(),
            "user-owned instructions\n"
        );
    }

    #[test]
    fn skill_install_is_repeatable_and_force_updates_bundled_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/llm-notary");

        let installed = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            false,
        )
        .unwrap();
        assert_eq!(installed["targets"][0]["state"], "installed");

        let current = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            false,
        )
        .unwrap();
        assert_eq!(current["targets"][0]["state"], "current");

        fs::write(path.join("SKILL.md"), "modified\n").unwrap();
        fs::write(path.join("personal-notes.md"), "keep me\n").unwrap();
        let updated = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            true,
        )
        .unwrap();

        assert_eq!(updated["targets"][0]["state"], "updated");
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            AGENT_SKILL_FILES[0].1
        );
        assert_eq!(
            fs::read_to_string(path.join("personal-notes.md")).unwrap(),
            "keep me\n"
        );
    }

    #[test]
    fn skill_install_force_recovers_an_invalid_utf8_file_and_rejects_a_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/llm-notary");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("SKILL.md"), [0xff, 0xfe]).unwrap();

        let updated = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path: path.clone(),
            }],
            true,
        )
        .unwrap();

        assert_eq!(updated["targets"][0]["state"], "updated");
        assert_eq!(
            fs::read_to_string(path.join("SKILL.md")).unwrap(),
            AGENT_SKILL_FILES[0].1
        );

        fs::remove_file(path.join("SKILL.md")).unwrap();
        fs::create_dir(path.join("SKILL.md")).unwrap();
        let error = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path,
            }],
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, "skill_install_conflict");
    }

    #[test]
    fn skill_install_human_output_explains_claude_activation() {
        let value = json!({
            "skill": AGENT_SKILL_NAME,
            "targets": [{
                "agent": "claude",
                "activation_note": CLAUDE_SKILL_ACTIVATION_NOTE,
                "path": "/user/.claude/skills/llm-notary",
                "state": "installed",
            }],
        });

        let output = skill_install_human_output(&value).unwrap();

        assert!(output.contains(CLAUDE_SKILL_ACTIVATION_NOTE));
    }

    #[test]
    fn skill_install_target_paths_and_home_fallback_are_portable() {
        let home = PathBuf::from("user-home");
        let destinations = skill_target_destinations(
            SkillTarget::All,
            Some(&home),
            Some(Path::new("claude-config")),
        )
        .unwrap();

        assert_eq!(destinations[0].agent, "codex");
        assert_eq!(destinations[0].path, home.join(".agents/skills/llm-notary"));
        assert_eq!(destinations[1].agent, "claude");
        assert_eq!(
            destinations[1].path,
            PathBuf::from("claude-config/skills/llm-notary")
        );
        assert_eq!(
            first_nonempty_path([Some(OsString::new()), Some(OsString::from("fallback-home")),]),
            Some(PathBuf::from("fallback-home"))
        );
        let default_claude =
            skill_target_destinations(SkillTarget::Claude, Some(&home), None).unwrap();
        assert_eq!(
            default_claude[0].path,
            home.join(".claude/skills/llm-notary")
        );
        let override_without_home =
            skill_target_destinations(SkillTarget::Claude, None, Some(Path::new("claude-config")))
                .unwrap();
        assert_eq!(
            override_without_home[0].path,
            PathBuf::from("claude-config/skills/llm-notary")
        );
    }

    #[test]
    fn capture_metadata_only_omits_preview_fields() {
        let mut value = json!({
            "items": [{
                "trace_id": "trc-example",
                "created_at_unix_ms": 123,
                "prompt_preview": "private prompt",
                "prompt_preview_truncated": false,
                "output_preview": "private output",
                "output_preview_truncated": false,
            }],
            "next_cursor": null,
        });

        remove_capture_previews(&mut value).unwrap();

        assert_eq!(value["items"][0]["trace_id"], "trc-example");
        assert_eq!(value["items"][0]["created_at_unix_ms"], 123);
        assert!(value["items"][0].get("prompt_preview").is_none());
        assert!(value["items"][0].get("output_preview").is_none());
    }

    #[tokio::test]
    async fn capture_metadata_only_is_applied_to_daemon_output() {
        let router = Router::new().route(
            "/v1/traces",
            get(|| async {
                Json(json!({
                    "items": [{
                        "trace_id": "trc-example",
                        "prompt_preview": "private prompt",
                        "prompt_preview_truncated": false,
                        "output_preview": "private output",
                        "output_preview_truncated": false,
                    }],
                    "next_cursor": null,
                }))
            }),
        );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();
        let command = CliCommand::Captures {
            command: CapturesCommand::List(CaptureListArgs {
                metadata_only: true,
                ..CaptureListArgs::default()
            }),
        };

        let response = execute(&client, &command, &mut Vec::new(), false)
            .await
            .unwrap();

        assert!(response["items"][0].get("prompt_preview").is_none());
        assert!(response["items"][0].get("output_preview").is_none());
        server.abort();
    }

    #[cfg(unix)]
    #[test]
    fn skill_install_force_never_follows_a_managed_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("skills/llm-notary");
        let unrelated = directory.path().join("unrelated");
        fs::create_dir_all(&path).unwrap();
        fs::write(&unrelated, "leave me alone\n").unwrap();
        symlink(&unrelated, path.join("SKILL.md")).unwrap();

        let error = install_agent_skill_at(
            &[SkillDestination {
                agent: "custom",
                path,
            }],
            true,
        )
        .unwrap_err();

        assert_eq!(error.code, "skill_install_conflict");
        assert_eq!(fs::read_to_string(unrelated).unwrap(), "leave me alone\n");
    }

    #[test]
    fn human_and_json_output_are_deterministic() {
        let command = CliCommand::Notarization(NotarizeArgs {
            id: "trc-example".to_owned(),
            wait: false,
        });
        let value = json!({
            "operation": {
                "operation_id": "op-example",
                "state": "queued",
                "progress": { "phase": "queued", "updated_at_unix_ms": 1 }
            },
            "deduplicated": false
        });
        assert_eq!(
            human_output(&command, &value).unwrap(),
            "Queued operation op-example (queued)"
        );
        assert_eq!(
            serde_json::to_string_pretty(&value).unwrap(),
            "{\n  \"deduplicated\": false,\n  \"operation\": {\n    \"operation_id\": \"op-example\",\n    \"progress\": {\n      \"phase\": \"queued\",\n      \"updated_at_unix_ms\": 1\n    },\n    \"state\": \"queued\"\n  }\n}"
        );

        let connected = json!({
            "signed_in": true,
            "provider_display_name": "octocat",
            "device_name": "workstation",
            "credential_kind": "cli_session",
            "credential_name": "workstation"
        });
        assert_eq!(
            human_output(&CliCommand::Whoami, &connected).unwrap(),
            "Connected to LLM Notary as octocat (cli_session: workstation)"
        );
        let rich_connected = json!({
            "signed_in": true,
            "connection_state": "connected",
            "display_name": "Example Person",
            "auth_provider": "google",
            "credential_kind": "cli_session",
            "credential_name": "workstation",
            "billing": { "service_plan": "one_gb", "billing_status": "active", "purchase_mode": "live" },
            "credits": {
                "reset_at": 1_700_000_000,
                "capture": { "total_granted_bytes": 10_000_000, "total_used_bytes": 1_000_000, "total_remaining_bytes": 9_000_000 },
                "notarization": { "total_granted_bytes": 20_000_000, "total_used_bytes": 2_000_000, "total_remaining_bytes": 18_000_000, "included_monthly_remaining_bytes": 8_000_000, "supplemental_remaining_bytes": 10_000_000, "next_grant_expiration": 1_800_000_000 }
            },
            "links": {
                "account": "https://example.test/#/dashboard",
                "usage": "https://example.test/#/dashboard/credits",
                "plans": "https://example.test/#/pricing",
                "settings": "https://example.test/#/dashboard/settings"
            }
        });
        let rich_output = human_output(&CliCommand::Whoami, &rich_connected).unwrap();
        assert!(rich_output.contains("Example Person (google; cli_session: workstation)"));
        assert!(rich_output.contains("plan one_gb (active, purchase mode live)"));
        assert!(rich_output.contains("notarization used 1.9 MiB / 19.1 MiB granted"));
        assert!(rich_output.contains("capture used 976.6 KiB / 9.5 MiB granted"));
        assert!(rich_output.contains("next notarization expiration 1800000000"));
        assert!(rich_output.contains("settings https://example.test/#/dashboard/settings"));
        assert_eq!(
            human_output(&CliCommand::Whoami, &json!({ "signed_in": false })).unwrap(),
            "No LLM Notary account is connected."
        );
        assert_eq!(
            human_output(
                &CliCommand::Whoami,
                &json!({ "signed_in": false, "connection_state": "reauthorization_required" })
            )
            .unwrap(),
            "LLM Notary account authorization has expired or was revoked; reconnect it."
        );
        assert_eq!(
            human_output(&CliCommand::Logout, &json!({ "signed_in": false })).unwrap(),
            "Disconnected from LLM Notary. Future hosted sessions use public access."
        );
    }

    #[test]
    fn proof_progress_reports_concrete_work_without_an_elapsed_time_guess() {
        let value = json!({
            "state": "running",
            "progress": {
                "phase": "proving",
                "proof": {
                    "bytes_completed": 614_400,
                    "bytes_total": 1_258_291,
                    "commitments_completed": 4,
                    "commitments_total": 10
                }
            }
        });

        assert_eq!(
            operation_progress(&value),
            "Private proof: 600.0 KiB / 1.2 MiB authenticated; 4 / 10 commitments sealed"
        );
    }

    #[test]
    fn notarization_wait_uses_the_operation_terminal_states() {
        for state in ["succeeded", "failed", "interrupted"] {
            assert!(notarization_is_terminal_state(state));
        }
        for state in ["queued", "running", "notarized"] {
            assert!(!notarization_is_terminal_state(state));
        }
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
            assert_eq!(error.code, "safe_code");
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
                get(|| async { Json(json!({ "service": "notaryd", "api_version": "v1" })) }),
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
                    Json(json!({ "service": "notaryd", "api_version": "v1" }))
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
    async fn all_mode_combines_pages_and_preserves_final_page_metadata() {
        let router = Router::new().route(
            "/v1/traces",
            get(
                |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    if query.get("cursor").map(String::as_str) == Some("page-two") {
                        Json(json!({
                            "items": [{"trace_id": "trc-b"}],
                            "next_cursor": null,
                            "high_water_cursor": "watermark-two"
                        }))
                    } else {
                        Json(json!({
                            "items": [{"trace_id": "trc-a"}],
                            "next_cursor": "page-two",
                            "high_water_cursor": "watermark-one"
                        }))
                    }
                },
            ),
        );
        let (address, server) = serve(router).await;
        let client = AdminClient::new(address, None).unwrap();

        let response = list_request(
            &client,
            "/v1/traces",
            vec![("limit".into(), "1".into())],
            true,
        )
        .await
        .unwrap();

        assert_eq!(response["items"][0]["trace_id"], "trc-a");
        assert_eq!(response["items"][1]["trace_id"], "trc-b");
        assert!(response["next_cursor"].is_null());
        assert_eq!(response["high_water_cursor"], "watermark-two");
        server.abort();
    }

    #[tokio::test]
    async fn rejects_api_version_mismatch_before_commands() {
        let router = Router::new().route(
            "/healthz",
            get(|| async { Json(json!({ "service": "notaryd", "api_version": "v2" })) }),
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

    async fn serve(router: Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (address, server)
    }
}
