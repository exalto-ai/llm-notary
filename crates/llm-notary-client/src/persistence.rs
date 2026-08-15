//! Composition and cross-store recovery for local daemon persistence.

use std::sync::Arc;

use anyhow::Result;

use crate::{
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactStore, FileSystemArtifactStore},
    config::AgentConfig,
    metadata::{CaptureCompletion, CaptureSummary},
    metadata_store::{MetadataStore, SqliteMetadataStore},
};

/// The result of reconciling captures that were active when the prior process
/// stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub recovered_bundles: usize,
    pub interrupted_captures: usize,
}

/// The metadata and byte stores used by one daemon process.
#[derive(Clone)]
pub struct Persistence {
    pub metadata: Arc<dyn MetadataStore>,
    pub artifacts: Arc<dyn ArtifactStore>,
}

impl Persistence {
    /// Opens the default SQLite and filesystem adapters from the unchanged
    /// desktop configuration shape.
    pub async fn open(config: &AgentConfig) -> Result<Self> {
        let metadata =
            SqliteMetadataStore::open(config.catalog.path.clone(), config.catalog.full_text_search)
                .await?;
        let artifacts = FileSystemArtifactStore::new(
            config.storage.bundle_dir.clone(),
            config.storage.finalized_dir.clone(),
        );
        Ok(Self {
            metadata: Arc::new(metadata),
            artifacts: Arc::new(artifacts),
        })
    }

    /// Reconciles captures left active by an earlier single-daemon process.
    /// Bytes are inspected by the artifact backend before metadata advertises
    /// them as available.
    pub async fn reconcile_incomplete_captures(&self) -> Result<RecoverySummary> {
        let mut summary = RecoverySummary::default();
        for capture_id in self.metadata.capturing_ids().await? {
            let key = ArtifactKey::new(&capture_id, ArtifactKind::DeferredBundle)?;
            if let Some(artifact) = self.artifacts.find(&key, MAX_ARCHIVE_WIRE_BYTES).await? {
                let capture =
                    self.metadata.capture(&capture_id).await?.ok_or_else(|| {
                        anyhow::anyhow!("active capture disappeared during recovery")
                    })?;
                if let Some(completion) = prepared_completion(&capture) {
                    self.metadata.complete_capture(completion, artifact).await?;
                } else {
                    // Compatibility for captures left by schema-v6 daemons
                    // which predate staged completion descriptors.
                    self.metadata.recover_capture(&capture_id, artifact).await?;
                }
                summary.recovered_bundles += 1;
            } else {
                self.metadata
                    .mark_capture_failed(&capture_id, "interrupted")
                    .await?;
                summary.interrupted_captures += 1;
            }
        }
        Ok(summary)
    }
}

fn prepared_completion(capture: &CaptureSummary) -> Option<CaptureCompletion> {
    Some(CaptureCompletion {
        capture_id: capture.capture_id.clone(),
        completed_at_unix_ms: capture.completed_at_unix_ms?,
        duration_ms: capture.duration_ms?,
        http_status: capture.http_status?,
        response_bytes: capture.response_bytes?,
        response_model: capture.response_model.clone(),
        output_preview: capture.output_preview.clone(),
        output_preview_truncated: capture.output_preview_truncated,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        archive::MAX_ARCHIVE_WIRE_BYTES,
        artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource},
        config::AgentConfig,
        metadata::{CaptureCompletion, NewCapture},
    };

    use super::{Persistence, RecoverySummary};

    fn config(directory: &std::path::Path) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.catalog.path = directory.join("catalog.db");
        config.storage.bundle_dir = directory.join("bundles");
        config.storage.finalized_dir = directory.join("traces");
        config
    }

    fn new_capture(capture_id: &str) -> NewCapture {
        NewCapture {
            capture_id: capture_id.to_owned(),
            created_at_unix_ms: 1,
            provider: "openai".to_owned(),
            operation: "/v1/responses".to_owned(),
            requested_model: Some("gpt-test".to_owned()),
            streaming: false,
            request_bytes: 12,
            prompt_preview: "safe prompt".to_owned(),
            prompt_preview_truncated: false,
            config_fingerprint: "sha256:test".to_owned(),
        }
    }

    #[tokio::test]
    async fn recovery_uses_the_artifact_contract_for_present_and_missing_bundles() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
        for capture_id in ["cap-present", "cap-missing"] {
            persistence
                .metadata
                .begin_capture(new_capture(capture_id))
                .await
                .unwrap();
        }
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("cap-present", ArtifactKind::DeferredBundle).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_bundles: 1,
                interrupted_captures: 1,
            }
        );
        assert_eq!(
            persistence
                .metadata
                .capture("cap-present")
                .await
                .unwrap()
                .unwrap()
                .capture_state,
            "captured"
        );
        assert_eq!(
            persistence
                .metadata
                .capture("cap-missing")
                .await
                .unwrap()
                .unwrap()
                .failure_code
                .as_deref(),
            Some("interrupted")
        );
    }

    #[tokio::test]
    async fn recovery_preserves_legacy_llmbundle_compatibility() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let persistence = Persistence::open(&config).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("cap-legacy"))
            .await
            .unwrap();
        fs::create_dir_all(&config.storage.bundle_dir).unwrap();
        let legacy = config.storage.bundle_dir.join("cap-legacy.llmbundle");
        fs::write(&legacy, b"legacy encrypted fixture").unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_bundles: 1,
                interrupted_captures: 0,
            }
        );
        let artifact = persistence
            .metadata
            .artifacts("cap-legacy")
            .await
            .unwrap()
            .remove(0);
        assert_eq!(artifact.locator.as_stored(), legacy.to_string_lossy());
    }

    #[tokio::test]
    async fn recovery_commits_a_prepared_completion_after_artifact_publication() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let persistence = Persistence::open(&config).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("cap-prepared"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                capture_id: "cap-prepared".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
            })
            .await
            .unwrap();
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("cap-prepared", ArtifactKind::DeferredBundle).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        drop(persistence);
        let persistence = Persistence::open(&config).await.unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_bundles: 1,
                interrupted_captures: 0,
            }
        );
        let capture = persistence
            .metadata
            .capture("cap-prepared")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capture.capture_state, "captured");
        assert_eq!(capture.http_status, Some(200));
        assert_eq!(capture.response_bytes, Some(24));
        assert_eq!(capture.output_preview, "safe response");
        assert!(
            persistence
                .metadata
                .enqueue_finalization("cap-prepared", 3)
                .await
                .unwrap()
                .is_some()
        );
    }
}
