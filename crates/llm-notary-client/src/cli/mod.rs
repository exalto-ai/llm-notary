mod api_origin;
pub mod auth;
pub mod bundle;
pub mod capture;
pub mod config;
pub mod download;
pub mod notary;
pub mod proxy;
pub mod public;
pub mod publish;
pub(crate) mod storage;
pub mod vault;

/// Public API origin compiled into released clients. Override it at build time
/// with `LLM_NOTARY_PUBLIC_ORIGIN` when producing a self-hosted distribution.
pub const DEFAULT_PUBLIC_ORIGIN: &str = env!("LLM_NOTARY_PUBLIC_ORIGIN");

pub(crate) const CLI_USER_AGENT: &str =
    concat!("llm-notary-local-service/", env!("CARGO_PKG_VERSION"));

pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(CLI_USER_AGENT)
}
