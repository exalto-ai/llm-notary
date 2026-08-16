use std::{
    io::Write as _,
    process::{Command, Stdio},
};

#[cfg(feature = "test-utils")]
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[test]
fn worker_rejects_malformed_packages_with_a_stable_code() {
    let directory = serde_json::to_vec(&serde_json::json!({
        "format": "llm-notary/notary-directory/v3",
        "generation": 0,
        "active_key_id": "unused",
        "notaries": []
    }))
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_llm-notary-api"))
        .arg("--verification-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&(directory.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&directory).unwrap();
    let archive = b"not a ZIP archive";
    stdin
        .write_all(&(archive.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(archive).unwrap();
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
    let key_id = llm_notary_core::notary_directory::key_id(&hex::decode(NOTARY_KEY).unwrap());
    let directory = serde_json::to_vec(&serde_json::json!({
        "format": "llm-notary/notary-directory/v3",
        "generation": 42,
        "active_key_id": key_id,
        "notaries": [{
            "host": "fixture-notary.example",
            "port": 443,
            "transport": "tls",
            "key_id": key_id,
            "public_key": NOTARY_KEY,
            "status": "active",
            "valid_from_unix_ms": 0,
            "valid_until_unix_ms": null,
            "finalize_until_unix_ms": null
        }]
    }))
    .unwrap();
    let archive = STANDARD
        .decode(include_str!("fixtures/sanitized-valid.llmtrace.b64").trim())
        .unwrap();
    assert!(!archive.windows(14).any(|bytes| bytes == b"fixture-secret"));
    assert!(!archive.windows(14).any(|bytes| bytes == b"fixture-cookie"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_llm-notary-verification-fixture-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&(directory.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&directory).unwrap();
    stdin
        .write_all(&(archive.len() as u64).to_be_bytes())
        .unwrap();
    stdin.write_all(&archive).unwrap();
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
    assert_eq!(body["capture_id"], "cap-test");
    assert_eq!(body["provider"], "test-server.io");
    assert_eq!(body["host"], "test-server.io");
    assert_eq!(body["notary_key_id"], key_id);
    assert_eq!(body["directory_generation"], 42);
    assert_eq!(body["trust_source"], "hosted_notary_directory");
    assert_eq!(
        body["package_sha256"],
        "08332885cddbeb56c1de73ef51d4235b26d429b479dc0fb208d7de32fee55ac7"
    );
    assert_eq!(
        body["trace_sha256"],
        "fba27116746e356a3d42805e6a991c37c2abbb13dbf2c0c4d2d49f3aa1c53466"
    );
    assert_eq!(
        body["trace"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "gen_ai.inference"
    );
}
