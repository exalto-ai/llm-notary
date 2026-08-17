use std::{
    io::Write as _,
    process::{Command, Stdio},
};

#[cfg(feature = "test-utils")]
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[test]
fn worker_rejects_malformed_packages_with_a_stable_code() {
    let registry = serde_json::to_vec(&serde_json::json!({
        "format": "notary/registry/v1",
        "generation": 0,
        "active_key_id": "unused",
        "notaries": []
    }))
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_notary-api"))
        .arg("verification-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&(registry.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&registry).unwrap();
    let package = b"not a ZIP archive";
    stdin
        .write_all(&(package.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(package).unwrap();
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout[0], b'R');
    let body_length = u64::from_be_bytes(output.stdout[1..9].try_into().unwrap()) as usize;
    assert_eq!(body_length, output.stdout.len() - 9);
    assert_eq!(&output.stdout[9..], b"malformed_package");
}

#[cfg(feature = "test-utils")]
#[test]
fn sanitized_valid_package_traverses_the_isolated_worker() {
    const NOTARY_KEY: &str = "0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967";
    let key_id = notary_core::registry::key_id(&hex::decode(NOTARY_KEY).unwrap());
    let registry = serde_json::to_vec(&serde_json::json!({
        "format": "notary/registry/v1",
        "generation": 42,
        "active_key_id": key_id,
        "notaries": [{
            "name": "Fixture notary",
            "operator": "Exalto",
            "host": "fixture-notary.example",
            "port": 443,
            "transport": "tls",
            "key_id": key_id,
            "public_key": NOTARY_KEY,
            "status": "active",
            "valid_from_unix_ms": 0,
            "valid_until_unix_ms": null,
            "notarize_until_unix_ms": null
        }]
    }))
    .unwrap();
    let package = STANDARD
        .decode(include_str!("fixtures/sanitized-valid.llmtrace.b64").trim())
        .unwrap();
    assert!(!package.windows(14).any(|bytes| bytes == b"fixture-secret"));
    assert!(!package.windows(14).any(|bytes| bytes == b"fixture-cookie"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_notary-api-verification-fixture-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&(registry.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&registry).unwrap();
    stdin
        .write_all(&(package.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&package).unwrap();
    drop(stdin);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout[0],
        b'V',
        "worker returned {}: {}; stderr: {}",
        output.stdout[0] as char,
        String::from_utf8_lossy(output.stdout.get(9..).unwrap_or_default()),
        String::from_utf8_lossy(&output.stderr)
    );
    let body_length = u64::from_be_bytes(output.stdout[1..9].try_into().unwrap()) as usize;
    assert_eq!(body_length, output.stdout.len() - 9);
    let body: serde_json::Value = serde_json::from_slice(&output.stdout[9..]).unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["source_trace_id"], "trc-test");
    assert_eq!(body["provider"], "test-server.io");
    assert_eq!(body["host"], "test-server.io");
    assert_eq!(body["notary_key_id"], key_id);
    assert_eq!(body["registry_generation"], 42);
    assert_eq!(body["trust_source"], "hosted_registry");
    assert_eq!(
        body["package_sha256"],
        "c2b5159f0a7cbdc4a9a24e1fdec14b125e83ae32393704af20885796c86da3dd"
    );
    assert_eq!(
        body["content_sha256"],
        "cf53f483fe8f438c2660323f1b0a4332394299aa2bb2b38beda24da0607342fa"
    );
    assert_eq!(
        body["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "gen_ai.inference"
    );
}
