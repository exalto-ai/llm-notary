use std::env;

const DEFAULT_PUBLIC_ORIGIN: &str = "https://llmnotary.exalto.ai";

fn main() {
    println!("cargo:rerun-if-env-changed=LLM_NOTARY_PUBLIC_ORIGIN");
    let origin =
        env::var("LLM_NOTARY_PUBLIC_ORIGIN").unwrap_or_else(|_| DEFAULT_PUBLIC_ORIGIN.to_owned());
    let origin = origin.trim_end_matches('/');
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    assert!(
        authority.is_some(),
        "LLM_NOTARY_PUBLIC_ORIGIN must start with http:// or https://"
    );
    assert!(
        authority
            .is_some_and(|value| !value.is_empty() && !value.contains(['/', '?', '#', '\n', '\r'])),
        "LLM_NOTARY_PUBLIC_ORIGIN must be an origin without a path, query, fragment, or newline"
    );
    println!("cargo:rustc-env=LLM_NOTARY_PUBLIC_ORIGIN={origin}");
}
