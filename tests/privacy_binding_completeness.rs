//! Non-cryptographic attack harness for the privacy-binding design.
//!
//! These tests deliberately model an inadequate field-level disclosure
//! scheme. They show that authenticating a chosen output string is not enough
//! to prove complete canonical normalization.

use serde_json::{Value, json};

fn naive_disclosed_text(response: &Value) -> Option<&str> {
    response
        .get("output")?
        .as_array()?
        .iter()
        .find(|item| item.get("type").and_then(Value::as_str) == Some("message"))?
        .pointer("/content/0/text")?
        .as_str()
}

fn complete_output_types(response: &Value) -> Vec<&str> {
    response["output"]
        .as_array()
        .expect("output array")
        .iter()
        .map(|item| item["type"].as_str().expect("output type"))
        .collect()
}

#[test]
fn a_hidden_tool_call_preserves_a_naively_disclosed_text_fact() {
    let honest = json!({
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": "The answer is 7."}]
        }]
    });
    let attacked = json!({
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": "The answer is 7."}]
            },
            {
                "type": "function_call",
                "call_id": "call-hidden",
                "name": "exfiltrate",
                "arguments": "{\"target\":\"secret\"}"
            }
        ]
    });

    assert_eq!(
        naive_disclosed_text(&honest),
        naive_disclosed_text(&attacked)
    );
    assert_ne!(
        complete_output_types(&honest),
        complete_output_types(&attacked)
    );
}

#[test]
fn duplicate_json_keys_are_parser_ambiguous() {
    let raw = br#"{"model":"allowed","model":"hidden"}"#;
    let parsed: Value = serde_json::from_slice(raw).expect("host parser accepts duplicates");
    assert_eq!(parsed["model"], "hidden");
    assert_eq!(
        raw.windows(b"model".len())
            .filter(|w| *w == b"model")
            .count(),
        2
    );
}

#[test]
fn trace_hash_binding_detects_mutation_but_not_transcript_completeness() {
    let trace = b"{\"resourceSpans\":[]}\n";
    let digest = certified::sha256_hex(trace);
    let mut changed = trace.to_vec();
    changed[2] ^= 1;
    assert_ne!(digest, certified::sha256_hex(&changed));
}
