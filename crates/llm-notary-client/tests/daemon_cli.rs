#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt as _,
    process::{Child, Command, Stdio},
    time::Duration,
};

use llm_notary_client::{
    catalog::{Catalog, NewCapture},
    config::AgentConfig,
};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn daemon_and_cli_use_the_versioned_loopback_api_for_reads_and_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let (proxy, admin) = unused_loopback_addresses();
    let mut config = AgentConfig::default();
    config.proxy.listen = proxy;
    config.admin.listen = admin;
    config.catalog.path = directory.path().join("data/catalog.db");
    config.storage.bundle_dir = directory.path().join("data/bundles");
    config.storage.finalized_dir = directory.path().join("data/traces");
    config.notary.endpoint = Some("tcp://127.0.0.1:9".to_owned());
    let signing_key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    config.notary.public_key = Some(hex::encode(
        signing_key.verifying_key().to_sec1_bytes().as_ref(),
    ));
    config.validate().unwrap();

    fs::create_dir_all(&config.storage.bundle_dir).unwrap();
    let bundle = config.storage.bundle_dir.join("cap-daemon-cli.llmbundle");
    fs::write(&bundle, b"encrypted test fixture").unwrap();
    let catalog = Catalog::open_for_config(&config).unwrap();
    catalog
        .begin_capture(&NewCapture {
            capture_id: "cap-daemon-cli".to_owned(),
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
    catalog
        .complete_capture(
            "cap-daemon-cli",
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
    drop(catalog);

    let config_path = directory.path().join("config.toml");
    fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let passphrase_path = directory.path().join("vault-passphrase");
    fs::write(&passphrase_path, b"test-only-passphrase").unwrap();
    fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o600)).unwrap();
    let isolated_config = directory.path().join("xdg-config");
    let isolated_data = directory.path().join("xdg-data");
    let daemon = Command::new(env!("CARGO_BIN_EXE_llm-notaryd"))
        .args(["--config", config_path.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", &isolated_config)
        .env("XDG_DATA_HOME", &isolated_data)
        .env("LLM_NOTARY_VAULT_PASSPHRASE_FILE", &passphrase_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _daemon = Daemon(daemon);

    let health_url = format!("http://{admin}/healthz");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..100 {
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "llm-notaryd did not become healthy");

    let status = cli(&config_path, &["status", "--json"]);
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["admin_listener"], admin.to_string());
    assert_eq!(status["counts"]["total_captures"], 1);
    assert_eq!(status["counts"]["ready_to_finalize"], 1);

    let capture = cli(
        &config_path,
        &["captures", "show", "cap-daemon-cli", "--json"],
    );
    assert!(capture.status.success());
    let capture: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    assert_eq!(capture["capture"]["capture_state"], "captured");

    let finalize = cli(&config_path, &["finalize", "cap-daemon-cli", "--json"]);
    assert!(finalize.status.success());
    let finalize: serde_json::Value = serde_json::from_slice(&finalize.stdout).unwrap();
    assert_eq!(finalize["operation"]["capture_id"], "cap-daemon-cli");
    assert!(
        finalize["operation"]["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("op-")
    );
}

fn cli(config: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_llm-notary"))
        .arg("--config")
        .arg(config)
        .args(arguments)
        .output()
        .unwrap()
}

fn unused_loopback_addresses() -> (SocketAddr, SocketAddr) {
    let first = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();
    drop((first, second));
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), first_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), second_port),
    )
}
