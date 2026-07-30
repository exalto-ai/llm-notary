use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::{io::Write, process::Stdio};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use super::storage;

const DEFAULT_API_ORIGIN: &str = "https://llmnotary.exalto.ai";
const KEYCHAIN_SERVICE: &str = "llm-notary";
const KEYCHAIN_ACCOUNT: &str = "publish-refresh-token";

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// LLM Notary website origin. Intended for local development and self-hosting.
    #[arg(long, default_value = DEFAULT_API_ORIGIN)]
    api: String,
    /// A recognizable name for this CLI session.
    #[arg(long, default_value = "LLM Notary CLI")]
    device_name: String,
}

#[derive(Serialize)]
struct StartAuthorization<'a> {
    device_name: &'a str,
}

#[derive(Deserialize)]
struct AuthorizationStarted {
    request_id: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
    poll_secret: String,
}

#[derive(Deserialize)]
struct AuthorizationComplete {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct WhoamiResponse {
    user: CliUser,
    session: CliSession,
}

#[derive(Deserialize)]
struct CliUser {
    github_login: String,
}

#[derive(Deserialize)]
struct CliSession {
    device_name: String,
}

#[derive(Serialize, Deserialize)]
struct FileCredentials {
    api_origin: String,
    refresh_token: String,
}

pub(crate) struct AuthenticatedApi {
    pub(crate) origin: String,
    pub(crate) access_token: String,
}

pub async fn login(args: LoginArgs) -> Result<()> {
    let api_origin = normalize_origin(&args.api)?;
    let client = reqwest::Client::builder()
        .user_agent("llm-notary-cli/0.1")
        .build()
        .context("building API client")?;
    let started = client
        .post(format!("{api_origin}/api/cli/authorizations"))
        .json(&StartAuthorization {
            device_name: &args.device_name,
        })
        .send()
        .await
        .context("starting CLI authorization")?
        .error_for_status()
        .context("starting CLI authorization")?
        .json::<AuthorizationStarted>()
        .await
        .context("reading CLI authorization response")?;

    println!("Open this URL in a browser and approve the request:");
    println!("{}", started.verification_uri_complete);
    println!("\nCode: {}", started.user_code);
    println!(
        "Waiting for approval (expires in {} minutes)…",
        started.expires_in / 60
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(started.expires_in);
    let interval = Duration::from_secs(started.interval.clamp(1, 10));
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("CLI authorization expired; run `llm-notary login` again")
        }
        let response = client
            .post(format!(
                "{api_origin}/api/cli/authorizations/{}/token",
                started.request_id
            ))
            .header("X-LLM-Notary-Poll-Secret", &started.poll_secret)
            .send()
            .await
            .context("polling CLI authorization")?;
        if response.status() == StatusCode::PRECONDITION_REQUIRED {
            tokio::time::sleep(interval).await;
            continue;
        }
        if response.status() == StatusCode::GONE {
            bail!("CLI authorization expired or was already used; run `llm-notary login` again")
        }
        let tokens = response
            .error_for_status()
            .context("completing CLI authorization")?
            .json::<AuthorizationComplete>()
            .await
            .context("reading CLI credentials")?;
        save_credentials(&FileCredentials {
            api_origin,
            refresh_token: tokens.refresh_token,
        })?;
        // Deliberately do not retain or print the short-lived access token.
        let _ = tokens.access_token;
        println!(
            "Signed in. Publish access expires in {} minutes and refreshes automatically.",
            tokens.expires_in / 60
        );
        return Ok(());
    }
}

pub async fn logout() -> Result<()> {
    let credentials = load_credentials()?;
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/cli/logout", credentials.api_origin))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .context("revoking CLI session")?;
    if !response.status().is_success() && response.status() != StatusCode::UNAUTHORIZED {
        response
            .error_for_status()
            .context("revoking CLI session")?;
    }
    delete_credentials()?;
    println!("Signed out.");
    Ok(())
}

pub async fn whoami() -> Result<()> {
    let authenticated = authenticate().await?;
    let response = reqwest::Client::new()
        .get(format!("{}/api/cli/me", authenticated.origin))
        .bearer_auth(authenticated.access_token)
        .send()
        .await
        .context("looking up CLI session")?
        .error_for_status()
        .context("looking up CLI session")?
        .json::<WhoamiResponse>()
        .await
        .context("reading CLI session")?;
    println!(
        "{} ({})",
        response.user.github_login, response.session.device_name
    );
    Ok(())
}

pub(crate) async fn authenticate() -> Result<AuthenticatedApi> {
    let mut credentials =
        load_credentials().context("CLI authentication required; run `llm-notary login`")?;
    let (access_token, rotated_refresh_token) = refresh(&credentials).await?;
    credentials.refresh_token = rotated_refresh_token;
    save_credentials(&credentials)?;
    Ok(AuthenticatedApi {
        origin: credentials.api_origin,
        access_token,
    })
}

async fn refresh(credentials: &FileCredentials) -> Result<(String, String)> {
    let response = reqwest::Client::new()
        .post(format!("{}/api/cli/token", credentials.api_origin))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .context("refreshing CLI credentials")?
        .error_for_status()
        .context("refreshing CLI credentials")?
        .json::<RefreshResponse>()
        .await
        .context("reading refreshed CLI credentials")?;
    let _ = response.expires_in;
    Ok((response.access_token, response.refresh_token))
}

fn normalize_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value).context("--api must be an absolute URL")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("--api must be an HTTP(S) origin without a query or fragment")
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn credentials_path() -> Result<PathBuf> {
    storage::config_file("credentials.json")
}

fn save_credentials(credentials: &FileCredentials) -> Result<()> {
    if keychain_store(&credentials.refresh_token).is_ok() {
        write_file_credentials(&FileCredentials {
            api_origin: credentials.api_origin.clone(),
            refresh_token: String::new(),
        })
    } else {
        write_file_credentials(credentials)
    }
}

fn load_credentials() -> Result<FileCredentials> {
    let path = credentials_path()?;
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut credentials: FileCredentials =
        serde_json::from_slice(&data).context("parse CLI credentials")?;
    if credentials.refresh_token.is_empty() {
        credentials.refresh_token = keychain_load()?
            .ok_or_else(|| anyhow!("CLI credentials are missing; run `llm-notary login`"))?;
    }
    Ok(credentials)
}

fn delete_credentials() -> Result<()> {
    let path = credentials_path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    let _ = keychain_delete();
    Ok(())
}

fn write_file_credentials(credentials: &FileCredentials) -> Result<()> {
    let path = credentials_path()?;
    write_file_credentials_at(&path, credentials)
}

fn write_file_credentials_at(path: &Path, credentials: &FileCredentials) -> Result<()> {
    storage::write_private_file_atomically(
        path,
        &serde_json::to_vec(credentials).context("encode CLI credentials")?,
    )
}

#[cfg(target_os = "macos")]
fn keychain_store(token: &str) -> Result<()> {
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
            token,
        ])
        .status()
        .context("store refresh token in macOS Keychain")?;
    if status.success() {
        Ok(())
    } else {
        bail!("macOS Keychain did not accept refresh token")
    }
}

#[cfg(target_os = "macos")]
fn keychain_load() -> Result<Option<String>> {
    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-w",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
        .context("read macOS Keychain")?;
    if output.status.success() {
        Ok(Some(
            String::from_utf8(output.stdout)
                .context("decode Keychain token")?
                .trim()
                .to_owned(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn keychain_delete() -> Result<()> {
    let _ = Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
        ])
        .status();
    Ok(())
}

#[cfg(target_os = "linux")]
fn keychain_store(token: &str) -> Result<()> {
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label=LLM Notary publish refresh token",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .stdin(Stdio::piped())
        .spawn()
        .context("store refresh token in the OS keychain")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("OS keychain did not provide stdin"))?;
    stdin
        .write_all(token.as_bytes())
        .context("write refresh token to OS keychain")?;
    drop(stdin);
    let status = child
        .wait()
        .context("store refresh token in the OS keychain")?;
    if status.success() {
        Ok(())
    } else {
        bail!("OS keychain did not accept refresh token")
    }
}

#[cfg(target_os = "linux")]
fn keychain_load() -> Result<Option<String>> {
    let output = match Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(None),
    };
    if output.status.success() {
        Ok(Some(
            String::from_utf8(output.stdout)
                .context("decode OS keychain token")?
                .trim()
                .to_owned(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn keychain_delete() -> Result<()> {
    let _ = Command::new("secret-tool")
        .args([
            "clear",
            "service",
            KEYCHAIN_SERVICE,
            "account",
            KEYCHAIN_ACCOUNT,
        ])
        .status();
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_store(_token: &str) -> Result<()> {
    bail!("OS keychain unavailable")
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_load() -> Result<Option<String>> {
    Ok(None)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_delete() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_http_origins() {
        assert_eq!(
            normalize_origin("https://example.com/").unwrap(),
            "https://example.com"
        );
        assert!(normalize_origin("https://example.com/path?x=1").is_err());
        assert!(normalize_origin("file:///tmp/auth").is_err());
    }

    #[test]
    fn credential_updates_are_atomic_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        let first = FileCredentials {
            api_origin: "https://first.example".to_owned(),
            refresh_token: "first-token".to_owned(),
        };
        let second = FileCredentials {
            api_origin: "https://second.example".to_owned(),
            refresh_token: "second-token".to_owned(),
        };

        write_file_credentials_at(&path, &first).unwrap();
        write_file_credentials_at(&path, &second).unwrap();
        let stored: FileCredentials = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored.api_origin, second.api_origin);
        assert_eq!(stored.refresh_token, second.refresh_token);
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".partial")
        }));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn failed_credential_replacement_cleans_up_staging_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        fs::create_dir_all(&path).unwrap();
        let credentials = FileCredentials {
            api_origin: "https://example.com".to_owned(),
            refresh_token: "token".to_owned(),
        };

        assert!(write_file_credentials_at(&path, &credentials).is_err());
        assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".partial")
        }));
        assert!(path.is_dir());
    }
}
