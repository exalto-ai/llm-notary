//! The shareable trace and platform-stamp contract.
//!
//! Unlike a private TLSNotary presentation, a platform stamp is a signed
//! admission statement.  It is deliberately small enough to verify from the
//! two public files alone.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, anyhow, ensure};
use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CAPTURE_FORMAT, sha256_hex};

pub const PUBLIC_TRACE_FORMAT: &str = "llm-notary/otlp-trace/v1";
pub const PLATFORM_STAMP_FORMAT: &str = "llm-notary/platform-stamp/v1";
pub const NORMALIZER_VERSION: &str = "llm-notary/normalizer/v1";
pub const OTEL_SEMCONV_VERSION: &str = "1.37.0";
pub const CANONICALIZATION_ID: &str = "llm-notary/json-lexicographic-v1";
pub const PLATFORM_SIGNATURE_ALGORITHM: &str = "secp256k1-ecdsa-sha256";
pub const TLSNOTARY_PROVENANCE: &str = "tlsnotary-presentation/v1";

/// The provenance facts that the admission service derived from its private
/// source-capture check. They are a platform claim, not TLSNotary evidence.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderProvenance {
    pub evidence: String,
    pub host: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StampSignature {
    pub algorithm: String,
    pub value: String,
}

/// The complete signed public admission statement.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicStamp {
    pub canonicalization: String,
    pub capture_format: String,
    pub format: String,
    pub issued_at_unix_ms: u64,
    pub issuer: String,
    pub key_id: String,
    pub normalizer_version: String,
    pub otel_semconv_version: String,
    pub provider: ProviderProvenance,
    pub signature: StampSignature,
    pub trace_sha256: String,
}

#[derive(Serialize)]
struct StampPayload<'a> {
    canonicalization: &'a str,
    capture_format: &'a str,
    format: &'a str,
    issued_at_unix_ms: u64,
    issuer: &'a str,
    key_id: &'a str,
    normalizer_version: &'a str,
    otel_semconv_version: &'a str,
    provider: &'a ProviderProvenance,
    trace_sha256: &'a str,
}

impl PublicStamp {
    fn payload(&self) -> StampPayload<'_> {
        StampPayload {
            canonicalization: &self.canonicalization,
            capture_format: &self.capture_format,
            format: &self.format,
            issued_at_unix_ms: self.issued_at_unix_ms,
            issuer: &self.issuer,
            key_id: &self.key_id,
            normalizer_version: &self.normalizer_version,
            otel_semconv_version: &self.otel_semconv_version,
            provider: &self.provider,
            trace_sha256: &self.trace_sha256,
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(&serde_json::to_value(self.payload())?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPublicTrace {
    pub stamp: PublicStamp,
    pub trace_sha256: String,
}

/// Create a platform stamp after the caller has admitted the trace against a
/// private source capture. The signing key belongs only to that service.
pub fn stamp_trace(
    trace: &[u8],
    issuer: String,
    issued_at_unix_ms: u64,
    provider: ProviderProvenance,
    signing_key: &SigningKey,
) -> Result<PublicStamp> {
    let metadata = validate_canonical_trace(trace)?;
    validate_provenance(&provider)?;
    ensure!(
        metadata.provider == provider.name,
        "provider provenance does not match the trace"
    );
    ensure!(!issuer.trim().is_empty(), "stamp issuer must not be empty");
    ensure!(issued_at_unix_ms != 0, "stamp issued time must not be zero");

    let mut stamp = PublicStamp {
        canonicalization: CANONICALIZATION_ID.to_owned(),
        capture_format: CAPTURE_FORMAT.to_owned(),
        format: PLATFORM_STAMP_FORMAT.to_owned(),
        issued_at_unix_ms,
        issuer,
        key_id: platform_key_id(signing_key.verifying_key()),
        normalizer_version: metadata.normalizer_version,
        otel_semconv_version: metadata.otel_semconv_version,
        provider,
        signature: StampSignature {
            algorithm: PLATFORM_SIGNATURE_ALGORITHM.to_owned(),
            value: String::new(),
        },
        trace_sha256: sha256_hex(trace),
    };
    let digest = Sha256::digest(stamp.signing_bytes()?);
    let signature: Signature = signing_key
        .sign_prehash(&digest)
        .map_err(|error| anyhow!("signing platform stamp: {error}"))?;
    stamp.signature.value = hex::encode(signature.to_bytes());
    Ok(stamp)
}

/// Verify a shareable artifact pair without a private capture or network.
pub fn verify_public_trace(
    trace_path: &Path,
    stamp_path: &Path,
    trusted_platform_key: &[u8],
) -> Result<VerifiedPublicTrace> {
    let trace = fs::read(trace_path)
        .with_context(|| format!("reading public trace {}", trace_path.display()))?;
    let stamp_bytes = fs::read(stamp_path)
        .with_context(|| format!("reading platform stamp {}", stamp_path.display()))?;
    verify_public_trace_bytes(&trace, &stamp_bytes, trusted_platform_key)
}

/// Byte-oriented variant used by the server and deterministic fixtures.
pub fn verify_public_trace_bytes(
    trace: &[u8],
    stamp_bytes: &[u8],
    trusted_platform_key: &[u8],
) -> Result<VerifiedPublicTrace> {
    let metadata = validate_canonical_trace(trace)?;
    let stamp: PublicStamp =
        serde_json::from_slice(stamp_bytes).context("parsing platform stamp")?;
    validate_stamp(&stamp, &metadata)?;

    let trace_sha256 = sha256_hex(trace);
    ensure!(
        stamp.trace_sha256 == trace_sha256,
        "trace SHA-256 does not match the platform stamp"
    );
    let trusted_platform_key = VerifyingKey::from_sec1_bytes(trusted_platform_key)
        .context("trusted platform key is not a valid secp256k1 SEC1 key")?;
    ensure!(
        stamp.key_id == platform_key_id(&trusted_platform_key),
        "platform stamp key ID does not match the trusted platform key"
    );
    let signature_bytes = hex::decode(&stamp.signature.value)
        .context("platform stamp signature is not hexadecimal")?;
    let signature = Signature::from_slice(&signature_bytes)
        .context("platform stamp signature is not a compact secp256k1 signature")?;
    ensure!(
        signature.normalize_s().is_none(),
        "platform stamp signature is not low-S"
    );
    let digest = Sha256::digest(stamp.signing_bytes()?);
    trusted_platform_key
        .verify_prehash(&digest, &signature)
        .map_err(|_| anyhow!("platform stamp signature is invalid"))?;

    Ok(VerifiedPublicTrace {
        stamp,
        trace_sha256,
    })
}

pub fn platform_key_id(key: &VerifyingKey) -> String {
    format!(
        "sha256:{}",
        sha256_hex(key.to_encoded_point(true).as_bytes())
    )
}

struct TraceMetadata {
    normalizer_version: String,
    otel_semconv_version: String,
    provider: String,
}

/// The public trace must already use the contract's deterministic byte form.
/// Objects are sorted by UTF-8 key bytes, arrays preserve order, and scalar
/// values use `serde_json`'s compact JSON representation followed by one LF.
/// This identifier is intentionally not called RFC 8785: its precise behavior
/// is this function.
pub fn canonical_trace_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut canonical = canonical_json(value)?;
    canonical.push(b'\n');
    Ok(canonical)
}

/// Check the canonical bytes and the supported provider-inference OTLP shape.
/// This is useful for unsigned local previews before platform admission.
pub fn validate_public_trace_bytes(bytes: &[u8]) -> Result<()> {
    validate_canonical_trace(bytes).map(|_| ())
}

fn validate_canonical_trace(bytes: &[u8]) -> Result<TraceMetadata> {
    let value: Value = serde_json::from_slice(bytes).context("parsing public trace JSON")?;
    let canonical = canonical_trace_bytes(&value)?;
    ensure!(
        canonical == bytes,
        "public trace is not canonical {}; serialize it with the contract's deterministic JSON rule",
        CANONICALIZATION_ID
    );
    validate_trace_shape(&value)
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(output, value)?;
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_trace_shape(value: &Value) -> Result<TraceMetadata> {
    let root = object_with_fields(value, &["resourceSpans"], "trace")?;
    let resource_spans = array(root["resourceSpans"].clone(), "trace.resourceSpans")?;
    ensure!(
        resource_spans.len() == 1,
        "a public trace must contain exactly one resource span"
    );
    let resource_span = object_with_fields(
        &resource_spans[0],
        &["resource", "scopeSpans"],
        "resource span",
    )?;
    let resource = object_with_fields(&resource_span["resource"], &["attributes"], "resource")?;
    let resource_attributes = attributes(&resource["attributes"], "resource attributes")?;
    let normalizer_version =
        string_attribute(&resource_attributes, "llmnotary.normalizer.version")?;
    let otel_semconv_version = string_attribute(&resource_attributes, "otel.semconv.version")?;
    ensure!(
        string_attribute(&resource_attributes, "llmnotary.format")? == PUBLIC_TRACE_FORMAT,
        "public trace format is unsupported"
    );
    ensure!(
        normalizer_version == NORMALIZER_VERSION,
        "public trace normalizer version is unsupported"
    );
    ensure!(
        otel_semconv_version == OTEL_SEMCONV_VERSION,
        "public trace OpenTelemetry semantic-convention version is unsupported"
    );
    ensure!(
        string_attribute(&resource_attributes, "service.name")? == "llm-notary",
        "public trace service.name must be llm-notary"
    );
    ensure!(
        resource_attributes.len() == 4,
        "public trace resource has unsupported attributes"
    );

    let scope_spans = array(
        resource_span["scopeSpans"].clone(),
        "resource span scopeSpans",
    )?;
    ensure!(
        scope_spans.len() == 1,
        "a public trace must contain exactly one scope span"
    );
    let scope_span = object_with_fields(&scope_spans[0], &["scope", "spans"], "scope span")?;
    let scope = object_with_fields(
        &scope_span["scope"],
        &["name", "version"],
        "instrumentation scope",
    )?;
    ensure!(
        scope["name"] == "llm-notary.normalizer",
        "unexpected instrumentation scope"
    );
    ensure!(
        scope["version"] == NORMALIZER_VERSION,
        "unexpected instrumentation scope version"
    );
    let spans = array(scope_span["spans"].clone(), "scope span spans")?;
    ensure!(
        !spans.is_empty(),
        "a public trace must contain an inference span"
    );
    let mut trace_id = None;
    let mut span_ids = std::collections::BTreeSet::new();
    let mut provider = None;
    for span in &spans {
        let span = object_with_fields(
            span,
            &[
                "attributes",
                "endTimeUnixNano",
                "kind",
                "name",
                "spanId",
                "startTimeUnixNano",
                "traceId",
            ],
            "inference span",
        )?;
        ensure!(
            span["name"] == "gen_ai.inference",
            "public span must be gen_ai.inference"
        );
        ensure!(
            span["kind"] == 3,
            "public span must use OpenTelemetry CLIENT kind"
        );
        hexadecimal_id(&span["traceId"], 32, "traceId")?;
        hexadecimal_id(&span["spanId"], 16, "spanId")?;
        let span_trace_id = span["traceId"].as_str().expect("validated trace ID");
        if let Some(trace_id) = trace_id {
            ensure!(
                trace_id == span_trace_id,
                "all inference spans must share a traceId"
            );
        } else {
            trace_id = Some(span_trace_id);
        }
        ensure!(
            span_ids.insert(span["spanId"].as_str().expect("validated span ID")),
            "public trace has duplicate spanId"
        );
        let start = unix_nanos(&span["startTimeUnixNano"], "startTimeUnixNano")?;
        let end = unix_nanos(&span["endTimeUnixNano"], "endTimeUnixNano")?;
        ensure!(end >= start, "span end time precedes start time");

        let span_attributes = attributes(&span["attributes"], "inference span attributes")?;
        let span_provider = string_attribute(&span_attributes, "gen_ai.provider.name")?;
        string_attribute(&span_attributes, "gen_ai.operation.name")?;
        string_attribute(&span_attributes, "gen_ai.request.model")?;
        for key in ["gen_ai.response.model"] {
            if let Some(value) = span_attributes.get(key) {
                string_value(value, key)?;
            }
        }
        for key in ["gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"] {
            if let Some(value) = span_attributes.get(key) {
                integer_value(value, key)?;
            }
        }
        for key in ["gen_ai.input.messages", "gen_ai.output.messages"] {
            if let Some(value) = span_attributes.get(key) {
                let messages = string_value(value, key)?;
                let parsed: Value = serde_json::from_str(&messages)
                    .map_err(|_| anyhow!("attribute {key} must contain JSON messages"))?;
                ensure!(
                    parsed.is_array(),
                    "attribute {key} must contain a JSON array"
                );
            }
        }
        if let Some(value) = span_attributes.get("gen_ai.response.finish_reasons") {
            string_array_value(value, "gen_ai.response.finish_reasons")?;
        }
        for key in ["gen_ai.conversation.id", "server.address"] {
            if let Some(value) = span_attributes.get(key) {
                string_value(value, key)?;
            }
        }
        let supported = [
            "gen_ai.provider.name",
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "gen_ai.usage.input_tokens",
            "gen_ai.usage.output_tokens",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.response.finish_reasons",
            "gen_ai.conversation.id",
            "server.address",
        ];
        ensure!(
            span_attributes.keys().all(|key| supported.contains(key)),
            "public trace has unsupported inference attributes"
        );
        if let Some(provider) = &provider {
            ensure!(
                provider == &span_provider,
                "all inference spans must use the same provider"
            );
        } else {
            provider = Some(span_provider);
        }
    }
    Ok(TraceMetadata {
        normalizer_version,
        otel_semconv_version,
        provider: provider.expect("non-empty spans have a provider"),
    })
}

fn validate_stamp(stamp: &PublicStamp, trace: &TraceMetadata) -> Result<()> {
    ensure!(
        stamp.format == PLATFORM_STAMP_FORMAT,
        "platform stamp format is unsupported"
    );
    ensure!(
        stamp.capture_format == CAPTURE_FORMAT,
        "platform stamp capture format is unsupported"
    );
    ensure!(
        stamp.canonicalization == CANONICALIZATION_ID,
        "platform stamp canonicalization is unsupported"
    );
    ensure!(
        stamp.normalizer_version == trace.normalizer_version,
        "platform stamp normalizer version does not match the trace"
    );
    ensure!(
        stamp.otel_semconv_version == trace.otel_semconv_version,
        "platform stamp semantic-convention version does not match the trace"
    );
    ensure!(
        stamp.signature.algorithm == PLATFORM_SIGNATURE_ALGORITHM,
        "platform stamp signature algorithm is unsupported"
    );
    ensure!(
        !stamp.issuer.trim().is_empty(),
        "platform stamp issuer must not be empty"
    );
    ensure!(
        stamp.issued_at_unix_ms != 0,
        "platform stamp issued time must not be zero"
    );
    validate_provenance(&stamp.provider)?;
    ensure!(
        stamp.provider.name == trace.provider,
        "platform stamp provider does not match the trace"
    );
    ensure!(
        stamp.trace_sha256.len() == 64
            && stamp
                .trace_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "platform stamp trace SHA-256 is invalid"
    );
    Ok(())
}

fn validate_provenance(provenance: &ProviderProvenance) -> Result<()> {
    ensure!(
        provenance.evidence == TLSNOTARY_PROVENANCE,
        "platform stamp provenance evidence is unsupported"
    );
    ensure!(
        !provenance.name.trim().is_empty(),
        "platform stamp provider name must not be empty"
    );
    ensure!(
        !provenance.host.trim().is_empty() && !provenance.host.chars().any(char::is_whitespace),
        "platform stamp provider host is invalid"
    );
    Ok(())
}

fn object_with_fields<'a>(
    value: &'a Value,
    fields: &[&str],
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{name} must be a JSON object"))?;
    ensure!(
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field)),
        "{name} has unsupported or missing fields"
    );
    Ok(object)
}

fn array(value: Value, name: &str) -> Result<Vec<Value>> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))
}

fn attributes<'a>(value: &'a Value, name: &str) -> Result<BTreeMap<&'a str, &'a Value>> {
    let values = value
        .as_array()
        .ok_or_else(|| anyhow!("{name} must be a JSON array"))?;
    let mut result = BTreeMap::new();
    for attribute in values {
        let attribute = object_with_fields(attribute, &["key", "value"], "attribute")?;
        let key = attribute["key"]
            .as_str()
            .ok_or_else(|| anyhow!("attribute key must be a string"))?;
        ensure!(
            result.insert(key, &attribute["value"]).is_none(),
            "duplicate attribute {key}"
        );
    }
    Ok(result)
}

fn string_attribute(attributes: &BTreeMap<&str, &Value>, key: &str) -> Result<String> {
    string_value(
        attributes
            .get(key)
            .ok_or_else(|| anyhow!("missing required attribute {key}"))?,
        key,
    )
}

fn string_value(value: &Value, key: &str) -> Result<String> {
    let object = object_with_fields(value, &["stringValue"], &format!("attribute {key} value"))?;
    let value = object["stringValue"]
        .as_str()
        .ok_or_else(|| anyhow!("attribute {key} must have a stringValue"))?;
    ensure!(!value.is_empty(), "attribute {key} must not be empty");
    Ok(value.to_owned())
}

fn integer_value(value: &Value, key: &str) -> Result<()> {
    let object = object_with_fields(value, &["intValue"], &format!("attribute {key} value"))?;
    let value = object["intValue"]
        .as_str()
        .ok_or_else(|| anyhow!("attribute {key} must have an intValue string"))?;
    ensure!(
        value.parse::<u64>().is_ok(),
        "attribute {key} must be a non-negative integer"
    );
    Ok(())
}

fn string_array_value(value: &Value, key: &str) -> Result<()> {
    let object = object_with_fields(value, &["arrayValue"], &format!("attribute {key} value"))?;
    let values = object["arrayValue"]
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("attribute {key} must have an arrayValue.values array"))?;
    for value in values {
        string_value(value, key)?;
    }
    Ok(())
}

fn hexadecimal_id(value: &Value, length: usize, name: &str) -> Result<()> {
    let value = value
        .as_str()
        .ok_or_else(|| anyhow!("{name} must be a string"))?;
    ensure!(
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{name} must be {length} lowercase hexadecimal characters"
    );
    Ok(())
}

fn unix_nanos(value: &Value, name: &str) -> Result<u64> {
    let value = value
        .as_str()
        .ok_or_else(|| anyhow!("{name} must be a decimal string"))?;
    let value = value
        .parse::<u64>()
        .map_err(|_| anyhow!("{name} must be an unsigned decimal string"))?;
    ensure!(value != 0, "{name} must not be zero");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TRACE: &[u8] = include_bytes!("../tests/fixtures/public-trace/trace.otlp.json");
    const FIXTURE_STAMP: &[u8] = include_bytes!("../tests/fixtures/public-trace/stamp.json");
    const TAMPERED_TRACE: &[u8] =
        include_bytes!("../tests/fixtures/public-trace/trace.tampered.otlp.json");
    const TAMPERED_STAMP: &[u8] =
        include_bytes!("../tests/fixtures/public-trace/stamp.tampered.json");
    const PUBLIC_KEY: &str = "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f";

    #[test]
    fn valid_public_fixture_verifies_and_tampering_fails() {
        let public_key = hex::decode(PUBLIC_KEY).expect("fixture public key is hexadecimal");
        let verified = verify_public_trace_bytes(FIXTURE_TRACE, FIXTURE_STAMP, &public_key)
            .expect("valid fixture must verify");
        assert_eq!(verified.stamp.normalizer_version, NORMALIZER_VERSION);
        assert!(verify_public_trace_bytes(TAMPERED_TRACE, FIXTURE_STAMP, &public_key).is_err());
        assert!(verify_public_trace_bytes(FIXTURE_TRACE, TAMPERED_STAMP, &public_key).is_err());
    }

    #[test]
    fn trace_requires_canonical_bytes_and_explicit_versions() {
        let mut noncanonical = FIXTURE_TRACE.to_vec();
        noncanonical.push(b'\n');
        assert!(validate_canonical_trace(&noncanonical).is_err());
        let mut without_version: Value = serde_json::from_slice(FIXTURE_TRACE).expect("trace JSON");
        without_version["resourceSpans"][0]["resource"]["attributes"]
            .as_array_mut()
            .expect("resource attributes")
            .retain(|attribute| attribute["key"] != "llmnotary.normalizer.version");
        assert!(validate_trace_shape(&without_version).is_err());
    }

    #[test]
    fn stamp_trace_binds_provider_and_uses_contract_versions() {
        let signing_key = SigningKey::from_slice(&[7; 32]).expect("test signing key");
        let stamp = stamp_trace(
            FIXTURE_TRACE,
            "test issuer".to_owned(),
            1,
            ProviderProvenance {
                evidence: TLSNOTARY_PROVENANCE.to_owned(),
                host: "api.openai.com".to_owned(),
                name: "openai".to_owned(),
            },
            &signing_key,
        )
        .expect("stamp trace");
        assert_eq!(stamp.format, PLATFORM_STAMP_FORMAT);
        assert_eq!(stamp.normalizer_version, NORMALIZER_VERSION);
        assert_eq!(stamp.otel_semconv_version, OTEL_SEMCONV_VERSION);
    }
}
