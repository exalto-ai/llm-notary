pub mod auth;
pub mod bundle;
pub mod download;
pub mod notary;
pub mod proxy;
pub mod public;
pub mod publish;
mod storage;
pub mod vault;
pub mod verify;

/// Public API origin compiled into released clients. Override it at build time
/// with `LLM_NOTARY_PUBLIC_ORIGIN` when producing a self-hosted distribution.
pub const DEFAULT_PUBLIC_ORIGIN: &str = env!("LLM_NOTARY_PUBLIC_ORIGIN");
