//! Composition and cross-store recovery for local daemon persistence.

use std::sync::Arc;

use anyhow::Result;

use crate::{
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_router::RoutedArtifactStore,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactStore, FileSystemArtifactStore},
    cluster::ClusterRuntime,
    config::{AgentConfig, MetadataBackend},
    metadata_store::MetadataStore,
    postgres_metadata_store::PostgresMetadataStore,
    s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
    sqlite_metadata_store::SqliteMetadataStore,
};

/// The result of reconciling captures that were active when the prior process
/// stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoverySummary {
    pub recovered_bundles: usize,
    pub interrupted_captures: usize,
    pub pending_publications: usize,
}

/// The metadata and byte stores used by one daemon process.
#[derive(Clone)]
pub struct Persistence {
    pub metadata: Arc<dyn MetadataStore>,
    pub artifacts: Arc<RoutedArtifactStore>,
}

impl Persistence {
    /// Opens the default SQLite and filesystem adapters from the unchanged
    /// desktop configuration shape.
    pub async fn open(config: &AgentConfig) -> Result<Self> {
        let metadata: Arc<dyn MetadataStore> = match config.catalog.backend {
            MetadataBackend::Sqlite => Arc::new(
                SqliteMetadataStore::open(
                    config.catalog.path.clone(),
                    config.catalog.full_text_search,
                )
                .await?,
            ),
            MetadataBackend::Postgres => {
                let postgres = &config.catalog.postgres;
                let database_url = config.postgres_runtime_url()?;
                Arc::new(
                    if config.server.is_some() {
                        PostgresMetadataStore::connect_clustered(
                            database_url.expose(),
                            postgres.max_connections,
                            std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                            std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                            postgres.ssl_mode,
                            config.catalog.full_text_search,
                        )
                        .await
                    } else {
                        PostgresMetadataStore::connect(
                        database_url.expose(),
                        postgres.max_connections,
                        std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                        std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                        postgres.ssl_mode,
                        config.catalog.full_text_search,
                        )
                        .await
                    }
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "PostgreSQL metadata database is unavailable or its daemon schema is not current; run `llm-notaryd migrate --config <path>`"
                        )
                    })?,
                )
            }
        };
        let filesystem = FileSystemArtifactStore::new(
            config.storage.bundle_dir.clone(),
            config.storage.finalized_dir.clone(),
        );
        let s3 = if let Some(s3) = &config.storage.s3 {
            let credentials = config.s3_credentials()?;
            Some(
                S3ArtifactStore::new(
                    s3.artifact_store_config()?,
                    S3ArtifactStoreCredentials::new(
                        credentials.access_key_id(),
                        credentials.secret_access_key(),
                        credentials.session_token().map(str::to_owned),
                    ),
                )
                .map_err(|_| anyhow::anyhow!("S3 artifact storage configuration is invalid"))?,
            )
        } else {
            None
        };
        let artifacts = RoutedArtifactStore::new(config.storage.backend, filesystem, s3)
            .map_err(|_| anyhow::anyhow!("selected artifact storage backend is not configured"))?;
        Ok(Self {
            metadata,
            artifacts: Arc::new(artifacts),
        })
    }

    /// Reconciles captures left active by an earlier single-daemon process.
    /// Bytes are inspected by the artifact backend before metadata advertises
    /// them as available.
    pub async fn reconcile_incomplete_captures(&self) -> Result<RecoverySummary> {
        self.reconcile_captures(true).await
    }

    /// Retries only captures whose completion descriptor was durably staged.
    /// Unlike startup recovery, this periodic pass never interrupts or adopts
    /// an unprepared capture which may still be active in this process.
    pub async fn reconcile_pending_publications(&self) -> Result<RecoverySummary> {
        self.reconcile_captures(false).await
    }

    /// Atomically adopts at most one capture whose PostgreSQL lease and owner
    /// heartbeat are both expired. The original publication ID is retained so
    /// an ambiguous S3 PUT can only be attached after exact size/hash checks.
    pub(crate) async fn reconcile_cluster_capture(
        &self,
        cluster: &ClusterRuntime,
    ) -> Result<RecoverySummary> {
        let Some(recovery) = self
            .metadata
            .claim_next_stale_capture(
                cluster.identity(),
                &cluster.new_fence_token(),
                cluster.lease_seconds(),
            )
            .await?
        else {
            return Ok(RecoverySummary::default());
        };
        let mut summary = RecoverySummary::default();
        let Some(completion) = recovery.completion else {
            self.metadata
                .fail_capture_claimed(&recovery.claim, "claim_expired")
                .await?;
            summary.interrupted_captures = 1;
            return Ok(summary);
        };
        let key = ArtifactKey::new(&recovery.claim.capture_id, ArtifactKind::DeferredBundle)?;
        match self
            .artifacts
            .find_scoped(&key, &recovery.claim.publication_id, MAX_ARCHIVE_WIRE_BYTES)
            .await
        {
            Ok(Some(artifact))
                if artifact.size_bytes == completion.expected_artifact_size_bytes
                    && artifact.sha256 == completion.expected_artifact_sha256 =>
            {
                self.metadata
                    .complete_capture_claimed(completion, artifact, &recovery.claim)
                    .await?;
                summary.recovered_bundles = 1;
            }
            Ok(Some(_)) => {
                self.metadata
                    .fail_capture_claimed(&recovery.claim, "artifact_integrity")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Ok(None) => {
                self.metadata
                    .fail_capture_claimed(&recovery.claim, "artifact_missing")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Err(
                crate::artifact_store::ArtifactStoreError::Integrity { .. }
                | crate::artifact_store::ArtifactStoreError::TooLarge { .. }
                | crate::artifact_store::ArtifactStoreError::Conflict { .. },
            ) => {
                self.metadata
                    .fail_capture_claimed(&recovery.claim, "artifact_integrity")
                    .await?;
                summary.interrupted_captures = 1;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(summary)
    }

    async fn reconcile_captures(&self, interrupt_unprepared: bool) -> Result<RecoverySummary> {
        let mut summary = RecoverySummary::default();
        for incomplete in self.metadata.incomplete_captures().await? {
            let capture_id = incomplete.capture_id;
            let key = ArtifactKey::new(&capture_id, ArtifactKind::DeferredBundle)?;
            let completion = incomplete.completion;
            if completion.is_none() && !interrupt_unprepared {
                continue;
            }
            if let Some(artifact) = self.artifacts.find(&key, MAX_ARCHIVE_WIRE_BYTES).await? {
                if let Some(completion) = completion {
                    anyhow::ensure!(
                        artifact.size_bytes == completion.expected_artifact_size_bytes
                            && artifact.sha256 == completion.expected_artifact_sha256,
                        "stored artifact does not match the prepared capture publication"
                    );
                    self.metadata.complete_capture(completion, artifact).await?;
                } else {
                    // Compatibility for captures left by schema-v6 daemons
                    // which predate staged completion descriptors.
                    self.metadata.recover_capture(&capture_id, artifact).await?;
                }
                summary.recovered_bundles += 1;
            } else if completion.is_some() {
                // A storage timeout can be ambiguous: the conditional PUT may
                // become visible after the process restarts. Keep the staged
                // completion recoverable and let the bounded background pass
                // attach exact bytes when they appear.
                summary.pending_publications += 1;
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
#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        archive::MAX_ARCHIVE_WIRE_BYTES,
        artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore},
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
                pending_publications: 0,
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
                pending_publications: 0,
            }
        );
        let artifact = persistence
            .metadata
            .artifacts("cap-legacy")
            .await
            .unwrap()
            .remove(0);
        assert!(crate::artifact_store::is_filesystem_artifact_locator(
            &artifact.locator
        ));
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
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
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
                pending_publications: 0,
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

    #[tokio::test]
    async fn recovery_keeps_a_prepared_capture_pending_until_bytes_appear() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("cap-delayed"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                capture_id: "cap-delayed".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
            })
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_bundles: 0,
                interrupted_captures: 0,
                pending_publications: 1,
            }
        );
        assert_eq!(
            persistence
                .metadata
                .capture("cap-delayed")
                .await
                .unwrap()
                .unwrap()
                .capture_state,
            "capturing"
        );

        persistence
            .artifacts
            .put(
                &ArtifactKey::new("cap-delayed", ArtifactKind::DeferredBundle).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(
            persistence.reconcile_incomplete_captures().await.unwrap(),
            RecoverySummary {
                recovered_bundles: 1,
                interrupted_captures: 0,
                pending_publications: 0,
            }
        );
    }

    #[tokio::test]
    async fn recovery_rejects_a_same_key_object_that_differs_from_the_prepared_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("cap-mismatched-publication"))
            .await
            .unwrap();
        persistence
            .metadata
            .prepare_capture_completion(CaptureCompletion {
                capture_id: "cap-mismatched-publication".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 24,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe response".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: 17,
                expected_artifact_sha256:
                    "45cae64a8ff5cc76f484e8aa131fdd0cd2182a386529c561cb1e500326093391".to_owned(),
            })
            .await
            .unwrap();
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("cap-mismatched-publication", ArtifactKind::DeferredBundle)
                    .unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixturE".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();

        assert!(persistence.reconcile_incomplete_captures().await.is_err());
        let capture = persistence
            .metadata
            .capture("cap-mismatched-publication")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(capture.capture_state, "capturing");
        assert!(
            persistence
                .metadata
                .artifacts("cap-mismatched-publication")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn periodic_recovery_never_interrupts_or_adopts_an_unprepared_live_capture() {
        let directory = tempfile::tempdir().unwrap();
        let persistence = Persistence::open(&config(directory.path())).await.unwrap();
        persistence
            .metadata
            .begin_capture(new_capture("cap-live"))
            .await
            .unwrap();

        assert_eq!(
            persistence.reconcile_pending_publications().await.unwrap(),
            RecoverySummary::default()
        );
        persistence
            .artifacts
            .put(
                &ArtifactKey::new("cap-live", ArtifactKind::DeferredBundle).unwrap(),
                ArtifactSource::from_bytes(b"encrypted fixture".to_vec()),
                MAX_ARCHIVE_WIRE_BYTES,
            )
            .await
            .unwrap();
        assert_eq!(
            persistence.reconcile_pending_publications().await.unwrap(),
            RecoverySummary::default()
        );
        assert_eq!(
            persistence
                .metadata
                .capture("cap-live")
                .await
                .unwrap()
                .unwrap()
                .capture_state,
            "capturing"
        );
        assert!(
            persistence
                .metadata
                .artifacts("cap-live")
                .await
                .unwrap()
                .is_empty()
        );
    }
}
