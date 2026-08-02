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

use super::{DEFAULT_PUBLIC_ORIGIN, api_origin::ApiOrigin, http_client_builder, storage};

const KEYCHAIN_SERVICE: &str = "llm-notary";
const KEYCHAIN_ACCOUNT: &str = "publish-refresh-token";

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// LLM Notary website origin. Intended for local development and self-hosting.
    #[arg(long, default_value = DEFAULT_PUBLIC_ORIGIN)]
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

#[derive(Clone)]
pub(crate) struct PendingAuthorization {
    pub(crate) request_id: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri_complete: String,
    pub(crate) expires_in: u64,
    pub(crate) interval: u64,
    poll_secret: String,
    api_origin: ApiOrigin,
}

pub(crate) enum AuthorizationPoll {
    Pending,
    Complete,
}

pub(crate) struct PublicationAuthStatus {
    pub(crate) signed_in: bool,
    pub(crate) github_login: Option<String>,
    pub(crate) device_name: Option<String>,
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
    api_origin: ApiOrigin,
    refresh_token: String,
}

pub(crate) struct AuthenticatedApi {
    pub(crate) origin: ApiOrigin,
    pub(crate) access_token: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublicationAuthenticationError {
    Required,
    Unavailable,
}

pub async fn login(args: LoginArgs) -> Result<()> {
    let pending = start_authorization(&args.api, &args.device_name).await?;
    println!("Open this URL in a browser and approve the request:");
    println!("{}", pending.verification_uri_complete);
    println!("\nCode: {}", pending.user_code);
    println!(
        "Waiting for approval (expires in {} minutes)…",
        pending.expires_in / 60
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(pending.expires_in);
    let interval = Duration::from_secs(pending.interval.clamp(1, 10));
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("authorization expired; start it again")
        }
        if matches!(
            poll_authorization(&pending).await?,
            AuthorizationPoll::Complete
        ) {
            println!("Signed in for publication.");
            return Ok(());
        }
        tokio::time::sleep(interval).await;
    }
}

pub(crate) async fn start_authorization(
    api: &str,
    device_name: &str,
) -> Result<PendingAuthorization> {
    let api_origin = ApiOrigin::parse(api)?;
    let client = http_client_builder()
        .build()
        .context("building API client")?;
    let started = client
        .post(api_origin.api_url("/api/cli/authorizations"))
        .json(&StartAuthorization { device_name })
        .send()
        .await
        .context("starting CLI authorization")?
        .error_for_status()
        .context("starting CLI authorization")?
        .json::<AuthorizationStarted>()
        .await
        .context("reading CLI authorization response")?;
    Ok(PendingAuthorization {
        request_id: started.request_id,
        user_code: started.user_code,
        verification_uri_complete: started.verification_uri_complete,
        expires_in: started.expires_in,
        interval: started.interval,
        poll_secret: started.poll_secret,
        api_origin,
    })
}

pub(crate) async fn poll_authorization(
    pending: &PendingAuthorization,
) -> Result<AuthorizationPoll> {
    let response = http_client_builder()
        .build()
        .context("building API client")?
        .post(pending.api_origin.api_url(&format!(
            "/api/cli/authorizations/{}/token",
            pending.request_id
        )))
        .header("X-LLM-Notary-Poll-Secret", &pending.poll_secret)
        .send()
        .await
        .context("polling publication authorization")?;
    if response.status() == StatusCode::PRECONDITION_REQUIRED {
        return Ok(AuthorizationPoll::Pending);
    }
    if response.status() == StatusCode::GONE {
        bail!("publication authorization expired or was already used")
    }
    let tokens = response
        .error_for_status()
        .context("completing publication authorization")?
        .json::<AuthorizationComplete>()
        .await
        .context("reading publication credentials")?;
    save_credentials(&FileCredentials {
        api_origin: pending.api_origin.clone(),
        refresh_token: tokens.refresh_token,
    })?;
    let _ = (tokens.access_token, tokens.expires_in);
    Ok(AuthorizationPoll::Complete)
}

pub async fn logout() -> Result<()> {
    logout_for_service().await?;
    println!("Signed out.");
    Ok(())
}

pub(crate) async fn logout_for_service() -> Result<()> {
    if !credentials_path()?.exists() {
        return Ok(());
    }
    let credentials = load_credentials()?;
    let client = http_client_builder()
        .build()
        .context("building API client")?;
    let response = client
        .post(credentials.api_origin.api_url("/api/cli/logout"))
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
    Ok(())
}

pub async fn whoami() -> Result<()> {
    let status = publication_auth_status().await?;
    println!(
        "{} ({})",
        status.github_login.unwrap_or_default(),
        status.device_name.unwrap_or_default()
    );
    Ok(())
}

pub(crate) async fn publication_auth_status() -> Result<PublicationAuthStatus> {
    if !credentials_path()?.exists() {
        return Ok(PublicationAuthStatus {
            signed_in: false,
            github_login: None,
            device_name: None,
        });
    }
    let authenticated = authenticate().await?;
    let response = http_client_builder()
        .build()
        .context("building API client")?
        .get(authenticated.origin.api_url("/api/cli/me"))
        .bearer_auth(authenticated.access_token)
        .send()
        .await
        .context("looking up CLI session")?
        .error_for_status()
        .context("looking up CLI session")?
        .json::<WhoamiResponse>()
        .await
        .context("reading CLI session")?;
    Ok(PublicationAuthStatus {
        signed_in: true,
        github_login: Some(response.user.github_login),
        device_name: Some(response.session.device_name),
    })
}

pub(crate) async fn authenticate() -> Result<AuthenticatedApi> {
    let mut credentials = load_credentials()
        .context("publication authorization is required through the local admin API")?;
    let (access_token, rotated_refresh_token) = refresh(&credentials).await?;
    credentials.refresh_token = rotated_refresh_token;
    save_credentials(&credentials)?;
    Ok(AuthenticatedApi {
        origin: credentials.api_origin,
        access_token,
    })
}

pub(crate) async fn authenticate_for_publication_status()
-> std::result::Result<AuthenticatedApi, PublicationAuthenticationError> {
    let mut credentials =
        load_credentials().map_err(|_| PublicationAuthenticationError::Required)?;
    let (access_token, rotated_refresh_token) =
        refresh_for_publication_status(&credentials).await?;
    credentials.refresh_token = rotated_refresh_token;
    save_credentials(&credentials).map_err(|_| PublicationAuthenticationError::Unavailable)?;
    Ok(AuthenticatedApi {
        origin: credentials.api_origin,
        access_token,
    })
}

async fn refresh(credentials: &FileCredentials) -> Result<(String, String)> {
    let response = http_client_builder()
        .build()
        .context("building API client")?
        .post(credentials.api_origin.api_url("/api/cli/token"))
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

async fn refresh_for_publication_status(
    credentials: &FileCredentials,
) -> std::result::Result<(String, String), PublicationAuthenticationError> {
    let client = http_client_builder()
        .build()
        .map_err(|_| PublicationAuthenticationError::Unavailable)?;
    let response = client
        .post(credentials.api_origin.api_url("/api/cli/token"))
        .json(&RefreshRequest {
            refresh_token: &credentials.refresh_token,
        })
        .send()
        .await
        .map_err(|_| PublicationAuthenticationError::Unavailable)?;
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return Err(PublicationAuthenticationError::Required);
    }
    if !response.status().is_success() {
        return Err(PublicationAuthenticationError::Unavailable);
    }
    let response = response
        .json::<RefreshResponse>()
        .await
        .map_err(|_| PublicationAuthenticationError::Unavailable)?;
    let _ = response.expires_in;
    Ok((response.access_token, response.refresh_token))
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
        credentials.refresh_token = keychain_load()?.ok_or_else(|| {
            anyhow!("publication credentials are missing; authorize through the local admin API")
        })?;
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

    async fn publication_status_refresh_result(
        status: StatusCode,
        body: &'static str,
    ) -> std::result::Result<(String, String), PublicationAuthenticationError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/api/cli/token",
            axum::routing::post(move || async move {
                (status, [("content-type", "application/json")], body)
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credentials = FileCredentials {
            api_origin: ApiOrigin::parse(&origin).unwrap(),
            refresh_token: "refresh-token".to_owned(),
        };
        let result = refresh_for_publication_status(&credentials).await;
        server.abort();
        result
    }

    #[test]
    fn api_origin_uses_the_shared_trust_policy() {
        assert_eq!(
            ApiOrigin::parse("https://example.com/")
                .unwrap()
                .to_string(),
            "https://example.com"
        );
        assert!(ApiOrigin::parse("http://example.com").is_err());
        assert!(ApiOrigin::parse("http://localhost:3000").is_ok());
    }

    #[tokio::test]
    async fn publication_status_refresh_distinguishes_reauthorization_from_outages() {
        assert_eq!(
            publication_status_refresh_result(StatusCode::UNAUTHORIZED, "{}")
                .await
                .unwrap_err(),
            PublicationAuthenticationError::Required
        );
        assert_eq!(
            publication_status_refresh_result(StatusCode::SERVICE_UNAVAILABLE, "{}")
                .await
                .unwrap_err(),
            PublicationAuthenticationError::Unavailable
        );
        assert_eq!(
            publication_status_refresh_result(StatusCode::OK, "not-json")
                .await
                .unwrap_err(),
            PublicationAuthenticationError::Unavailable
        );
    }

    #[test]
    fn credential_updates_are_atomic_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config").join("credentials.json");
        let first = FileCredentials {
            api_origin: ApiOrigin::parse("https://first.example").unwrap(),
            refresh_token: "first-token".to_owned(),
        };
        let second = FileCredentials {
            api_origin: ApiOrigin::parse("https://second.example").unwrap(),
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
            api_origin: ApiOrigin::parse("https://example.com").unwrap(),
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
