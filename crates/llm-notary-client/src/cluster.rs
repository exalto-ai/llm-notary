//! Explicit multi-replica runtime identity and lifecycle.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;

use crate::{
    config::ClusterConfig,
    metadata_store::{
        CaptureClaim, FinalizationClaim, MetadataResult, MetadataStore, MetadataStoreError,
        ReplicaIdentity,
    },
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
    claim_max_runtime_seconds: u64,
    withdrawal_delay_seconds: u64,
    shutdown_grace_seconds: u64,
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
            claim_max_runtime_seconds: config.claim_max_runtime_seconds,
            withdrawal_delay_seconds: config.withdrawal_delay_seconds,
            shutdown_grace_seconds: config.shutdown_grace_seconds,
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

    pub(crate) const fn withdrawal_delay_seconds(&self) -> u64 {
        self.withdrawal_delay_seconds
    }

    pub(crate) const fn shutdown_grace_seconds(&self) -> u64 {
        self.shutdown_grace_seconds
    }

    pub(crate) fn keep_capture_claim_alive(
        &self,
        metadata: Arc<dyn MetadataStore>,
        claim: CaptureClaim,
    ) -> ClaimLeaseGuard {
        self.keep_claim_alive(metadata, ClaimToRenew::Capture(claim))
    }

    pub(crate) fn keep_finalization_claim_alive(
        &self,
        metadata: Arc<dyn MetadataStore>,
        claim: FinalizationClaim,
    ) -> ClaimLeaseGuard {
        self.keep_claim_alive(metadata, ClaimToRenew::Finalization(Box::new(claim)))
    }

    fn keep_claim_alive(
        &self,
        metadata: Arc<dyn MetadataStore>,
        claim: ClaimToRenew,
    ) -> ClaimLeaseGuard {
        let (shutdown, mut stopped) = watch::channel(false);
        let renewal_interval = Duration::from_secs(self.heartbeat_interval_seconds);
        let maximum_runtime = Duration::from_secs(self.claim_max_runtime_seconds);
        let lease_seconds = self.lease_seconds;
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            loop {
                tokio::select! {
                    result = stopped.changed() => {
                        if result.is_err() || *stopped.borrow() { return; }
                    }
                    () = tokio::time::sleep(renewal_interval) => {}
                }
                if started.elapsed() >= maximum_runtime {
                    tracing::warn!(
                        "cluster work claim reached its maximum runtime; allowing lease expiry"
                    );
                    return;
                }
                let result = match &claim {
                    ClaimToRenew::Capture(claim) => {
                        metadata.renew_capture_claim(claim, lease_seconds).await
                    }
                    ClaimToRenew::Finalization(claim) => {
                        metadata
                            .renew_finalization_claim(claim, lease_seconds)
                            .await
                    }
                };
                match result {
                    Ok(()) => {}
                    Err(MetadataStoreError::Fenced) => return,
                    Err(error) => {
                        tracing::warn!(error = %error, "cluster work claim renewal failed; retrying until the lease expires")
                    }
                }
            }
        });
        ClaimLeaseGuard { shutdown }
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

enum ClaimToRenew {
    Capture(CaptureClaim),
    Finalization(Box<FinalizationClaim>),
}

pub(crate) struct ClaimLeaseGuard {
    shutdown: watch::Sender<bool>,
}

impl Drop for ClaimLeaseGuard {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
