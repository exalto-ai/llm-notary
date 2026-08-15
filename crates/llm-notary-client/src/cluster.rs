//! Explicit multi-replica runtime identity and lifecycle.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::{
    config::ClusterConfig,
    metadata_store::{CaptureClaim, MetadataResult, MetadataStoreError, ReplicaIdentity},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle {
    Starting = 0,
    Ready = 1,
    Draining = 2,
}

#[derive(Debug)]
pub(crate) struct ClusterRuntime {
    identity: ReplicaIdentity,
    heartbeat_interval_seconds: u64,
    lease_seconds: u64,
    lifecycle: AtomicU8,
}

impl ClusterRuntime {
    pub(crate) fn from_config(config: &ClusterConfig) -> MetadataResult<Self> {
        let identity = ReplicaIdentity::new(
            config
                .instance_id
                .clone()
                .ok_or(MetadataStoreError::InvalidInput("missing_instance_id"))?,
        )?;
        Ok(Self {
            identity,
            heartbeat_interval_seconds: config.heartbeat_interval_seconds,
            lease_seconds: config.lease_seconds,
            lifecycle: AtomicU8::new(Lifecycle::Starting as u8),
        })
    }

    pub(crate) fn identity(&self) -> &ReplicaIdentity {
        &self.identity
    }

    pub(crate) const fn heartbeat_interval_seconds(&self) -> u64 {
        self.heartbeat_interval_seconds
    }

    pub(crate) const fn lease_seconds(&self) -> u64 {
        self.lease_seconds
    }

    pub(crate) fn capture_claim(&self, capture_id: impl Into<String>) -> CaptureClaim {
        CaptureClaim::new(capture_id, self.identity.clone())
    }

    pub(crate) fn new_fence_token(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub(crate) fn mark_ready(&self) {
        self.lifecycle
            .store(Lifecycle::Ready as u8, Ordering::Release);
    }

    pub(crate) fn mark_draining(&self) {
        self.lifecycle
            .store(Lifecycle::Draining as u8, Ordering::Release);
    }

    pub(crate) fn lifecycle(&self) -> Lifecycle {
        match self.lifecycle.load(Ordering::Acquire) {
            1 => Lifecycle::Ready,
            2 => Lifecycle::Draining,
            _ => Lifecycle::Starting,
        }
    }
}
