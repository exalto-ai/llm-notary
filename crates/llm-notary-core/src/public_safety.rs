//! Fail-closed validation for a `.llmtrace` that will be made public.
//!
//! Cryptographic verification proves where disclosed bytes came from. This
//! validator answers a different question: whether the exact portable archive
//! is safe to make reachable. Errors intentionally expose only a bounded rule
//! and location class, never the value that matched.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::{archive::read_trace_package_archive, validate_disclosed_http_redactions};

/// The admission record stores this value so an older share is never silently
/// claimed to satisfy a newer public-package contract.
pub const PUBLIC_PACKAGE_SAFETY_VERSION: &str = "llm-notary/public-package-safety/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicPackageLocation {
    Archive,
    Manifest,
    Evidence,
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Trace,
}

impl PublicPackageLocation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Manifest => "manifest",
            Self::Evidence => "evidence",
            Self::RequestHeaders => "request_headers",
            Self::RequestBody => "request_body",
            Self::ResponseHeaders => "response_headers",
            Self::ResponseBody => "response_body",
            Self::Trace => "trace",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublicPackageSafetyError {
    pub code: &'static str,
    pub location: PublicPackageLocation,
}

impl PublicPackageSafetyError {
    const fn new(code: &'static str, location: PublicPackageLocation) -> Self {
        Self { code, location }
    }

    /// A bounded admission code suitable for a database row or API response.
    pub fn admission_code(self) -> String {
        format!("{}_{}", self.code, self.location.as_str())
    }
}

impl fmt::Display for PublicPackageSafetyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "public package rejected by {} in {}",
            self.code,
            self.location.as_str()
        )
    }
}

impl std::error::Error for PublicPackageSafetyError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PublicPackageSafetyResult {
    pub version: &'static str,
}

/// Validates the exact canonical archive that admission intends to retain.
///
/// The archive parser provides the entry, format, size, encoding, and hash
/// allowlist. The checks below then enforce header redaction, inspect structured
/// bodies (including nested JSON strings), scan every entry, and finally scan
/// the serialized ZIP bytes as defense in depth.
pub fn validate_public_trace_package(
    bytes: &[u8],
) -> Result<PublicPackageSafetyResult, PublicPackageSafetyError> {
    let archive = read_trace_package_archive(bytes).map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    let request = archive.file("request.disclosed.http").map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    let response = archive.file("response.disclosed.http").map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    validate_disclosed_http_redactions(request, b"HTTP/1.1 200 OK\r\n\r\n").map_err(|_| {
        PublicPackageSafetyError::new(
            "credential_header_disclosed",
            PublicPackageLocation::RequestHeaders,
        )
    })?;
    validate_disclosed_http_redactions(b"GET / HTTP/1.1\r\n\r\n", response).map_err(|_| {
        PublicPackageSafetyError::new(
            "credential_header_disclosed",
            PublicPackageLocation::ResponseHeaders,
        )
    })?;

    let (request_head, request_body) = split_http(request, PublicPackageLocation::RequestHeaders)?;
    let (response_head, response_body) =
        split_http(response, PublicPackageLocation::ResponseHeaders)?;
    scan_request_target(request_head)?;
    scan_public_bytes(request_head, PublicPackageLocation::RequestHeaders)?;
    scan_public_bytes(response_head, PublicPackageLocation::ResponseHeaders)?;
    scan_body(request_body, PublicPackageLocation::RequestBody)?;
    scan_body(response_body, PublicPackageLocation::ResponseBody)?;

    let archive_manifest = serde_json::to_vec(&archive.manifest).map_err(|_| {
        PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
    })?;
    scan_json(&archive_manifest, PublicPackageLocation::Manifest)?;
    for (name, location) in [
        ("manifest.json", PublicPackageLocation::Manifest),
        ("evidence.tlsn", PublicPackageLocation::Evidence),
        ("trace.otlp.json", PublicPackageLocation::Trace),
    ] {
        let entry = archive.file(name).map_err(|_| {
            PublicPackageSafetyError::new("archive_invalid", PublicPackageLocation::Archive)
        })?;
        if name.ends_with(".json") {
            scan_json(entry, location)?;
        } else {
            scan_public_bytes(entry, location)?;
        }
    }

    // The canonical archive uses stored ZIP entries. Scanning the final bytes
    // catches patterns that cross read buffers and remains useful if the entry
    // inspection above changes in a later validator version.
    scan_public_bytes(bytes, PublicPackageLocation::Archive)?;

    Ok(PublicPackageSafetyResult {
        version: PUBLIC_PACKAGE_SAFETY_VERSION,
    })
}

fn split_http(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(&[u8], &[u8]), PublicPackageSafetyError> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| PublicPackageSafetyError::new("http_invalid", location))?;
    Ok(bytes.split_at(boundary + 4))
}

fn scan_request_target(head: &[u8]) -> Result<(), PublicPackageSafetyError> {
    let first_line = head
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or_else(|| {
            PublicPackageSafetyError::new("http_invalid", PublicPackageLocation::RequestHeaders)
        })?;
    let target = first_line.split_ascii_whitespace().nth(1).ok_or_else(|| {
        PublicPackageSafetyError::new("http_invalid", PublicPackageLocation::RequestHeaders)
    })?;
    let Some((_, query)) = target.split_once('?') else {
        return Ok(());
    };
    for pair in query.split('&') {
        let key = pair.split_once('=').map_or(pair, |(key, _)| key);
        if is_credential_key(key) || is_signed_query_key(key) {
            return Err(PublicPackageSafetyError::new(
                "credential_query_value",
                PublicPackageLocation::RequestHeaders,
            ));
        }
    }
    Ok(())
}

fn scan_body(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(), PublicPackageSafetyError> {
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        return Ok(());
    }
    if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
        scan_json(bytes, location)
    } else {
        scan_public_bytes(bytes, location)?;
        scan_entropy_tokens(bytes, None, location)
    }
}

fn scan_json(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(), PublicPackageSafetyError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| PublicPackageSafetyError::new("public_json_invalid", location))?;
    let mut nested = BTreeSet::new();
    scan_json_value(&value, None, location, &mut nested)
}

fn scan_json_value(
    value: &serde_json::Value,
    key: Option<&str>,
    location: PublicPackageLocation,
    nested: &mut BTreeSet<String>,
) -> Result<(), PublicPackageSafetyError> {
    if key.is_some_and(is_credential_key) && has_public_value(value) {
        return Err(PublicPackageSafetyError::new("credential_field", location));
    }
    match value {
        serde_json::Value::Object(values) => {
            let semantic_key = values
                .get("key")
                .and_then(serde_json::Value::as_str)
                .filter(|_| values.contains_key("value"));
            for (child_key, value) in values {
                let context = if child_key == "value" {
                    semantic_key.or(key).or(Some(child_key.as_str()))
                } else if matches!(
                    child_key.as_str(),
                    "stringValue" | "intValue" | "doubleValue" | "boolValue" | "arrayValue"
                ) {
                    key.or(Some(child_key.as_str()))
                } else {
                    Some(child_key.as_str())
                };
                scan_json_value(value, context, location, nested)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                scan_json_value(value, key, location, nested)?;
            }
        }
        serde_json::Value::String(value) => {
            scan_public_bytes(value.as_bytes(), location)?;
            scan_entropy_tokens(value.as_bytes(), key, location)?;
            let trimmed = value.trim();
            if trimmed.len() <= 1_048_576
                && matches!(trimmed.as_bytes().first(), Some(b'{') | Some(b'['))
                && nested.insert(trimmed.to_owned())
                && let Ok(inner) = serde_json::from_str::<serde_json::Value>(trimmed)
            {
                scan_json_value(&inner, key, location, nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn has_public_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(_) => true,
        serde_json::Value::String(value) => !value.trim().is_empty(),
        serde_json::Value::Array(values) => !values.is_empty(),
        serde_json::Value::Object(values) => !values.is_empty(),
    }
}

fn normalized_key(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn is_credential_key(value: &str) -> bool {
    matches!(
        normalized_key(value).as_str(),
        "authorization"
            | "proxyauthorization"
            | "apikey"
            | "xapikey"
            | "accesskey"
            | "accesskeyid"
            | "secretaccesskey"
            | "clientsecret"
            | "secret"
            | "password"
            | "passwd"
            | "cookie"
            | "setcookie"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "privatekey"
            | "credential"
            | "credentials"
    )
}

fn is_signed_query_key(value: &str) -> bool {
    matches!(
        normalized_key(value).as_str(),
        "signature"
            | "sig"
            | "xamzsignature"
            | "xgoogsignature"
            | "googlesignature"
            | "signedtoken"
    )
}

fn is_intentionally_public_crypto_key(value: &str) -> bool {
    let key = normalized_key(value);
    key.contains("sha256")
        || key.ends_with("hash")
        || key.contains("signature")
        || key.contains("publickey")
        || key.ends_with("keyid")
        || key == "digest"
}

/// Entropy is only a defense-in-depth signal. It runs on structured string
/// values (and non-JSON public bodies), while documented hashes, signatures,
/// public keys, and key identifiers are exempt by field name.
fn scan_entropy_tokens(
    bytes: &[u8],
    key: Option<&str>,
    location: PublicPackageLocation,
) -> Result<(), PublicPackageSafetyError> {
    if key.is_some_and(is_intentionally_public_crypto_key) {
        return Ok(());
    }
    let suspicious = bytes
        .split(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'='))
        })
        .any(|token| {
            (32..=512).contains(&token.len())
                && !looks_like_public_hex(token)
                && character_classes(token) >= 3
                && shannon_entropy(token) >= 4.35
        });
    if suspicious {
        return Err(PublicPackageSafetyError::new(
            "high_entropy_value",
            location,
        ));
    }
    Ok(())
}

fn looks_like_public_hex(value: &[u8]) -> bool {
    matches!(value.len(), 40 | 64 | 96 | 128) && value.iter().all(u8::is_ascii_hexdigit)
}

fn character_classes(value: &[u8]) -> usize {
    [
        value.iter().any(u8::is_ascii_lowercase),
        value.iter().any(u8::is_ascii_uppercase),
        value.iter().any(u8::is_ascii_digit),
        value
            .iter()
            .any(|byte| matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
}

fn shannon_entropy(value: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for byte in value {
        counts[*byte as usize] += 1;
    }
    let length = value.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn scan_public_bytes(
    bytes: &[u8],
    location: PublicPackageLocation,
) -> Result<(), PublicPackageSafetyError> {
    let lower = bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let patterns: &[&[u8]] = &[
        b"authorization: bearer ",
        b"authorization: basic ",
        b"proxy-authorization:",
        b"x-api-key:",
        b"-----begin private key-----",
        b"-----begin rsa private key-----",
        b"-----begin ec private key-----",
        b"aws_secret_access_key",
    ];
    if patterns.iter().any(|pattern| contains(&lower, pattern))
        || contains_prefixed_token(bytes, b"sk-ant-")
        || contains_prefixed_token(bytes, b"sk-or-v1-")
        || contains_prefixed_token(bytes, b"sk-proj-")
        || contains_prefixed_token(bytes, b"sk-")
        || contains_aws_access_key(bytes)
        || contains_jwt(bytes)
    {
        return Err(PublicPackageSafetyError::new("secret_pattern", location));
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_prefixed_token(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(index, window)| {
            if !window.eq_ignore_ascii_case(prefix) {
                return false;
            }
            bytes[index + prefix.len()..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                .take(20)
                .count()
                >= 20
        })
}

fn contains_aws_access_key(bytes: &[u8]) -> bool {
    bytes.windows(20).any(|window| {
        matches!(&window[..4], b"AKIA" | b"ASIA")
            && window[4..].iter().all(u8::is_ascii_alphanumeric)
    })
}

fn contains_jwt(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b',' | b';'))
        .any(|token| {
            let mut segments = token.split(|byte| *byte == b'.');
            let parts = [segments.next(), segments.next(), segments.next()];
            segments.next().is_none()
                && parts.iter().all(|part| {
                    part.is_some_and(|part| {
                        part.len() >= 16
                            && part.iter().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'=')
                            })
                    })
                })
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::archive::{PACKAGE_FILES, build_trace_package_archive};

    use super::*;

    fn package_with(request_body: &str, response_body: &str, trace: serde_json::Value) -> Vec<u8> {
        let directory = tempfile::tempdir().unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => br#"{"format":"llm-notary/verified-trace-package/v2","notary_public_key":"04cafe"}"#.to_vec(),
                "request.disclosed.http" => format!(
                    "POST /v1/responses HTTP/1.1\r\nAuthorization: \0\0\0\0\r\nContent-Type: \0\0\0\r\n\r\n{request_body}"
                )
                .into_bytes(),
                "response.disclosed.http" => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: \0\0\0\r\n\r\n{response_body}"
                )
                .into_bytes(),
                "trace.otlp.json" => serde_json::to_vec(&trace).unwrap(),
                _ => b"public TLSNotary evidence".to_vec(),
            };
            fs::write(directory.path().join(name), bytes).unwrap();
        }
        build_trace_package_archive(directory.path()).unwrap()
    }

    fn safe_trace() -> serde_json::Value {
        serde_json::json!({
            "resourceSpans": [{"scopeSpans": [{"spans": [{
                "attributes": [
                    {"key": "gen_ai.input.messages", "value": {"stringValue": "[{\"role\":\"user\",\"parts\":[{\"type\":\"text\",\"content\":\"Explain reproducible evaluation.\"}]}]"}},
                    {"key": "llmnotary.trace.sha256", "value": {"stringValue": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
                    {"key": "llmnotary.notary.signature", "value": {"stringValue": "MEUCIQDXm8Kq2u3W7bcCNSYo97vaB8DxDwIdXfW1hT60pAIgB0iYzTt9Ez"}}
                ]
            }]}]}]
        })
    }

    #[test]
    fn accepts_public_hashes_signatures_and_ordinary_model_content() {
        let archive = package_with(
            r#"{"model":"gpt-test","messages":[{"role":"user","content":"Explain reproducible evaluation."}]}"#,
            r#"{"output":[{"content":"Use a fixed dataset and report the full digest."}]}"#,
            safe_trace(),
        );
        assert_eq!(
            validate_public_trace_package(&archive).unwrap().version,
            PUBLIC_PACKAGE_SAFETY_VERSION
        );
    }

    #[test]
    fn rejects_hostile_secret_categories_without_echoing_the_value() {
        let fixtures = [
            ("openai", "sk-proj-1234567890abcdefghijklmnop"),
            ("openrouter", "sk-or-v1-1234567890abcdefghijklmnop"),
            ("anthropic", "sk-ant-1234567890abcdefghijklmnop"),
            ("aws", "AKIA1234567890ABCDEF"),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.signaturevalue1234",
            ),
            ("pem", "-----BEGIN PRIVATE KEY-----"),
        ];
        for (name, secret) in fixtures {
            let archive = package_with(
                &serde_json::json!({"messages": [{"content": secret}]}).to_string(),
                r#"{"ok":true}"#,
                safe_trace(),
            );
            let error = validate_public_trace_package(&archive).unwrap_err();
            let rendered = error.to_string();
            assert!(
                !rendered.contains(secret),
                "{name} leaked through the error"
            );
            assert_eq!(error.code, "secret_pattern", "{name}");
        }
    }

    #[test]
    fn rejects_nested_tool_credentials_and_signed_queries() {
        let nested = serde_json::json!({
            "messages": [{"role": "tool", "content": "{\"api_key\":\"fixture-value\"}"}]
        });
        let archive = package_with(&nested.to_string(), r#"{"ok":true}"#, safe_trace());
        assert_eq!(
            validate_public_trace_package(&archive).unwrap_err().code,
            "credential_field"
        );

        let directory = tempfile::tempdir().unwrap();
        for name in PACKAGE_FILES {
            let bytes = match name {
                "manifest.json" => br#"{"format":"llm-notary/verified-trace-package/v2"}"#.to_vec(),
                "request.disclosed.http" => {
                    b"POST /v1?X-Amz-Signature=fixture HTTP/1.1\r\nAuthorization: \0\0\0\r\n\r\n{}"
                        .to_vec()
                }
                "response.disclosed.http" => b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(),
                "trace.otlp.json" => serde_json::to_vec(&safe_trace()).unwrap(),
                _ => b"evidence".to_vec(),
            };
            fs::write(directory.path().join(name), bytes).unwrap();
        }
        let signed = build_trace_package_archive(directory.path()).unwrap();
        assert_eq!(
            validate_public_trace_package(&signed).unwrap_err().code,
            "credential_query_value"
        );
    }

    #[test]
    fn entropy_scanner_exempts_named_public_crypto_and_rejects_opaque_values() {
        let public = serde_json::json!({
            "signature": "MEUCIQDXm8Kq2u3W7bcCNSYo97vaB8DxDwIdXfW1hT60pAIgB0iYzTt9Ez",
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        let archive = package_with(&public.to_string(), r#"{"ok":true}"#, safe_trace());
        validate_public_trace_package(&archive).unwrap();

        let opaque = "Q2xvdWRDcmVkZW50aWFsX0ZpeHR1cmVfMTIzNDU2Nzg5MC1hYmNkZWY=";
        let archive = package_with(
            &serde_json::json!({"tool_result": opaque}).to_string(),
            r#"{"ok":true}"#,
            safe_trace(),
        );
        let error = validate_public_trace_package(&archive).unwrap_err();
        assert_eq!(error.code, "high_entropy_value");
        assert!(!error.to_string().contains(opaque));
    }

    #[test]
    fn rejects_visible_header_values_and_split_buffer_patterns() {
        let visible = package_with(r#"{"ok":true}"#, r#"{"ok":true}"#, safe_trace());
        let archive = read_trace_package_archive(&visible).unwrap();
        assert!(archive.file("request.disclosed.http").unwrap().contains(&0));

        let mut split = b"prefix sk-proj-1234567890".to_vec();
        split.extend_from_slice(b"abcdefghijklmnop suffix");
        let error = scan_public_bytes(&split, PublicPackageLocation::Archive).unwrap_err();
        assert_eq!(error.code, "secret_pattern");
    }
}
