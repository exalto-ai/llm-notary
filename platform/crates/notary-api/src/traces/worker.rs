//! Durable hosted Trace verification worker lifecycle.

use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::watch;

use crate::{NotaryApiState, unix_timestamp};

use super::public::{
    claim_next_job, process_claim, purge_expired_share_rate_limits, purge_verified_private_objects,
    recover_stale_claims,
};

const VERIFICATION_INTERVAL_SECS: u64 = 2;
const MAX_JOBS_PER_TICK: usize = 4;
const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 10 * 60;

pub(crate) async fn run_worker(state: NotaryApiState, mut shutdown: watch::Receiver<bool>) {
    if !state.traces.enabled() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(VERIFICATION_INTERVAL_SECS));
    let mut next_rate_limit_cleanup = Instant::now();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {}
        }
        if let Err(error) = recover_stale_claims(&state).await {
            tracing::error!(%error, "recovering stale Trace verification claims failed");
        }
        for _ in 0..MAX_JOBS_PER_TICK {
            match claim_next_job(&state).await {
                Ok(Some((job, claim))) => process_claim(&state, job, claim).await,
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "claiming a Trace verification failed");
                    break;
                }
            }
        }
        if let Err(error) = purge_verified_private_objects(&state).await {
            tracing::error!(%error, "purging shared Trace intake objects failed");
        }
        if let Err(error) = update_queue_metrics(&state).await {
            tracing::error!(%error, "updating Trace verification metrics failed");
        }
        if Instant::now() >= next_rate_limit_cleanup {
            if let Err(error) = purge_expired_share_rate_limits(&state).await {
                tracing::error!(%error, "purging expired share rate limits failed");
            }
            next_rate_limit_cleanup =
                Instant::now() + Duration::from_secs(RATE_LIMIT_CLEANUP_INTERVAL_SECS);
        }
    }
}

async fn update_queue_metrics(state: &NotaryApiState) -> Result<()> {
    let now = unix_timestamp().map_err(|error| anyhow::anyhow!(error.message))?;
    let (depth, oldest): (i64, Option<i64>) =
        sqlx::query_as("SELECT COUNT(*), MIN(queued_at) FROM traces WHERE status = 'queued'")
            .fetch_one(&state.database)
            .await?;
    metrics::gauge!("notary_api_trace_verification_queue_depth").set(depth as f64);
    metrics::gauge!("notary_api_trace_verification_oldest_queued_seconds")
        .set(oldest.map_or(0, |queued| now.saturating_sub(queued)) as f64);
    Ok(())
}
