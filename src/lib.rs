//! Compatibility facade for the current LLM Notary application package.
//!
//! The reusable protocol, capture, and evidence logic lives in
//! `llm-notary-core`. Keeping this facade preserves the existing crate name
//! while the local client and hosted services are extracted in later layers.

pub use llm_notary_core::*;
