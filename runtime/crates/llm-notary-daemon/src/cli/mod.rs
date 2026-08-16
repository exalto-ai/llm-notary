mod api_origin;
pub mod auth;
pub mod config;
pub mod notary;
pub mod proxy;
pub mod publish;
pub(crate) mod storage;

/// Public API origin compiled into released clients. Override it at build time
/// with `LLM_NOTARY_PUBLIC_ORIGIN` when producing a self-hosted distribution.
pub use llm_notary_updater::{BUILD_ID, DEFAULT_PUBLIC_ORIGIN, UPDATES_ENABLED};

pub(crate) const CLI_USER_AGENT: &str = concat!("llm-notaryd/", env!("CARGO_PKG_VERSION"));

pub(crate) fn http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(CLI_USER_AGENT)
}
