//! Backend conformance tests for [`MetadataStore`](super::MetadataStore).
//!
//! Every backend supplies an asynchronous factory for isolated stores and runs
//! [`run`] unchanged. Keeping the scenarios backend-neutral prevents a new
//! backend from weakening lifecycle, pagination, or concurrency guarantees.

use std::{
    collections::HashSet,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Barrier;

use crate::{
    FinalizationPhase, FinalizationProofProgress,
    artifact_store::{
        ArtifactAvailability, ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord,
    },
    metadata::{
        CaptureCompletion, CapturePagePosition, NewCapture, OperationAttempt, OperationPagePosition,
    },
};

use super::{
    CaptureFilters, EventFilters, MetadataResult, MetadataStore, MetadataStoreError,
    OperationFilters, TerminalOperationResult,
};

/// Runs the complete metadata contract against isolated stores from `make_store`.
pub(crate) async fn run<F, Fut>(make_store: F, full_text_search: bool)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<dyn MetadataStore>>,
{
    capture_lifecycle(make_store().await).await;
    preview_search(make_store().await, full_text_search).await;
    capture_filters_pagination_and_counts(make_store().await).await;
    operation_filters_and_pagination(make_store().await).await;
    finalization_lifecycle(make_store().await).await;
    concurrent_enqueue_is_deduplicated(make_store().await).await;
    concurrent_retry_is_deduplicated(make_store().await).await;
    event_page_and_high_water_are_atomic(make_store().await).await;
    invalid_limits_and_ranges(make_store().await).await;
}

pub(super) fn new_capture(id: &str, created_at_unix_ms: u64) -> NewCapture {
    NewCapture {
        capture_id: id.to_owned(),
        created_at_unix_ms,
        provider: "openai".to_owned(),
        operation: "responses".to_owned(),
        requested_model: Some("gpt-5".to_owned()),
        streaming: false,
        request_bytes: 12,
        prompt_preview: "Explain quarterly pricing".to_owned(),
        prompt_preview_truncated: false,
        config_fingerprint: "sha256:test".to_owned(),
    }
}

pub(super) fn completion(
    id: &str,
    completed_at_unix_ms: u64,
    http_status: u16,
) -> CaptureCompletion {
    CaptureCompletion {
        capture_id: id.to_owned(),
        completed_at_unix_ms,
        duration_ms: 7,
        http_status,
        response_bytes: 24,
        response_model: Some("gpt-5-verified".to_owned()),
        output_preview: "Quarterly pricing is available.".to_owned(),
        output_preview_truncated: false,
    }
}

pub(super) fn artifact(id: &str, kind: ArtifactKind, marker: u8) -> ArtifactRecord {
    ArtifactRecord::new(
        ArtifactKey::new(id, kind).unwrap(),
        ArtifactLocator::from_stored(format!("fixture://{id}/{}", kind.as_str())).unwrap(),
        u64::from(marker) + 10,
        format!("{marker:064x}"),
        ArtifactAvailability::Available,
    )
    .unwrap()
}

async fn insert_completed(store: &Arc<dyn MetadataStore>, capture: NewCapture, http_status: u16) {
    let id = capture.capture_id.clone();
    let completed_at = capture.created_at_unix_ms + 1;
    store.begin_capture(capture).await.unwrap();
    let completion = completion(&id, completed_at, http_status);
    store
        .prepare_capture_completion(completion.clone())
        .await
        .unwrap();
    store
        .complete_capture(completion, artifact(&id, ArtifactKind::DeferredBundle, 1))
        .await
        .unwrap();
}

fn ids<T>(values: &[T], get: impl Fn(&T) -> &str) -> Vec<String> {
    values.iter().map(|value| get(value).to_owned()).collect()
}

fn assert_invalid<T>(result: MetadataResult<T>, expected: &'static str) {
    match result {
        Err(MetadataStoreError::InvalidInput(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("expected invalid input {expected}, got {error}"),
        Ok(_) => panic!("expected invalid input {expected}"),
    }
}

async fn capture_lifecycle(store: Arc<dyn MetadataStore>) {
    assert!(store.capture("missing").await.unwrap().is_none());
    assert!(store.artifacts("missing").await.unwrap().is_empty());
    assert!(store.capturing_ids().await.unwrap().is_empty());
    assert!(
        store
            .mark_capture_failed("missing", "notary_error")
            .await
            .is_err()
    );

    let first = new_capture("lifecycle-complete", 10);
    store.begin_capture(first.clone()).await.unwrap();
    assert!(store.begin_capture(first).await.is_err());
    let pending = store.capture("lifecycle-complete").await.unwrap().unwrap();
    assert_eq!(pending.capture_state, "capturing");
    assert_eq!(pending.finalization_state, "not_requested");
    assert_eq!(pending.requested_model.as_deref(), Some("gpt-5"));
    assert_eq!(pending.request_bytes, 12);
    assert_eq!(pending.prompt_preview, "Explain quarterly pricing");

    store
        .begin_capture(new_capture("lifecycle-failed", 20))
        .await
        .unwrap();
    store
        .mark_capture_failed("lifecycle-failed", "notary_error")
        .await
        .unwrap();
    store
        .mark_capture_failed("lifecycle-failed", "notary_error")
        .await
        .unwrap();
    let failed = store.capture("lifecycle-failed").await.unwrap().unwrap();
    assert_eq!(failed.capture_state, "failed");
    assert_eq!(failed.failure_code.as_deref(), Some("notary_error"));

    store
        .begin_capture(new_capture("lifecycle-recovered", 30))
        .await
        .unwrap();
    let mut capturing = store.capturing_ids().await.unwrap();
    capturing.sort();
    assert_eq!(capturing, vec!["lifecycle-complete", "lifecycle-recovered"]);

    let recovered_artifact = artifact("lifecycle-recovered", ArtifactKind::DeferredBundle, 2);
    store
        .recover_capture("lifecycle-recovered", recovered_artifact.clone())
        .await
        .unwrap();
    assert!(
        store
            .recover_capture("lifecycle-recovered", recovered_artifact.clone())
            .await
            .is_err()
    );
    assert_eq!(
        store.artifacts("lifecycle-recovered").await.unwrap(),
        vec![recovered_artifact]
    );

    let bundle = artifact("lifecycle-complete", ArtifactKind::DeferredBundle, 3);
    let completed = completion("lifecycle-complete", 40, 200);
    store
        .prepare_capture_completion(completed.clone())
        .await
        .unwrap();
    store
        .prepare_capture_completion(completed.clone())
        .await
        .unwrap();
    let staged = store.capture("lifecycle-complete").await.unwrap().unwrap();
    assert_eq!(staged.capture_state, "capturing");
    assert_eq!(staged.completed_at_unix_ms, Some(40));
    assert_eq!(staged.http_status, Some(200));
    assert!(
        store
            .artifacts("lifecycle-complete")
            .await
            .unwrap()
            .is_empty()
    );
    let mut conflicting_staged = completed.clone();
    conflicting_staged.response_bytes += 1;
    assert!(
        store
            .prepare_capture_completion(conflicting_staged)
            .await
            .is_err()
    );
    store
        .complete_capture(completed.clone(), bundle.clone())
        .await
        .unwrap();
    store
        .complete_capture(completed, bundle.clone())
        .await
        .unwrap();
    let mut conflicting_completion = completion("lifecycle-complete", 40, 200);
    conflicting_completion.response_bytes += 1;
    assert!(
        store
            .prepare_capture_completion(completion("missing", 50, 200))
            .await
            .is_err()
    );
    assert!(
        store
            .complete_capture(conflicting_completion, bundle.clone())
            .await
            .is_err()
    );
    assert!(
        store
            .mark_capture_failed("lifecycle-complete", "late_failure")
            .await
            .is_err()
    );
    let captured = store.capture("lifecycle-complete").await.unwrap().unwrap();
    assert_eq!(captured.capture_state, "captured");
    assert_eq!(captured.completed_at_unix_ms, Some(40));
    assert_eq!(captured.http_status, Some(200));
    assert_eq!(captured.response_bytes, Some(24));
    assert_eq!(captured.response_model.as_deref(), Some("gpt-5-verified"));
    assert_eq!(
        store.artifacts("lifecycle-complete").await.unwrap(),
        vec![bundle]
    );

    assert!(
        store
            .complete_capture(
                completion("missing", 50, 200),
                artifact("missing", ArtifactKind::DeferredBundle, 5),
            )
            .await
            .is_err()
    );
    assert!(
        store
            .recover_capture(
                "missing",
                artifact("missing", ArtifactKind::DeferredBundle, 6),
            )
            .await
            .is_err()
    );
    assert!(store.artifacts("missing").await.unwrap().is_empty());
}

async fn preview_search(store: Arc<dyn MetadataStore>, full_text_search: bool) {
    let first = new_capture("search-adjacent", 10);
    insert_completed(&store, first, 200).await;

    let mut separated = new_capture("search-separated", 20);
    separated.prompt_preview = "Quarterly enterprise notes about pricing".to_owned();
    let separated_id = separated.capture_id.clone();
    store.begin_capture(separated).await.unwrap();
    let mut separated_completion = completion(&separated_id, 21, 200);
    separated_completion.output_preview = "No repeated phrase here.".to_owned();
    store
        .complete_capture(
            separated_completion,
            artifact(&separated_id, ArtifactKind::DeferredBundle, 8),
        )
        .await
        .unwrap();

    let query = |value: &str| CaptureFilters {
        query: Some(value.to_owned()),
        limit: 20,
        ..CaptureFilters::default()
    };
    if !full_text_search {
        for value in [
            "quarterly-pricing",
            "**quarterly**",
            "\"quarterly pricing\"",
        ] {
            assert_invalid(
                store.captures(query(value)).await,
                "preview_search_disabled",
            );
        }
        return;
    }

    for value in ["quarterly-pricing", "**quarterly**"] {
        assert_eq!(store.captures(query(value)).await.unwrap().len(), 2);
    }
    assert_eq!(
        ids(
            &store
                .captures(query("\"quarterly pricing\""))
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["search-adjacent"]
    );
    for value in ["\"pricing quarterly\"", "definitely-not-present-xyz", "**"] {
        assert!(store.captures(query(value)).await.unwrap().is_empty());
    }
}

async fn capture_filters_pagination_and_counts(store: Arc<dyn MetadataStore>) {
    let mut a = new_capture("filter-a", 100);
    a.streaming = true;
    insert_completed(&store, a, 200).await;

    let mut b = new_capture("filter-b", 200);
    b.provider = "anthropic".to_owned();
    b.requested_model = Some("claude-sonnet".to_owned());
    insert_completed(&store, b, 503).await;

    let mut c = new_capture("filter-c", 200);
    c.requested_model = Some("gpt-4.1".to_owned());
    store.begin_capture(c).await.unwrap();
    store
        .mark_capture_failed("filter-c", "capture_error")
        .await
        .unwrap();

    let mut d = new_capture("filter-d", 300);
    d.provider = "openrouter".to_owned();
    d.requested_model = None;
    d.streaming = true;
    store.begin_capture(d).await.unwrap();

    assert_eq!(
        ids(
            &store
                .captures(CaptureFilters {
                    provider: Some("openai".to_owned()),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["filter-c", "filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .captures(CaptureFilters {
                    model: Some("gpt-5".to_owned()),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .captures(CaptureFilters {
                    capture_state: Some("captured".to_owned()),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["filter-b", "filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .captures(CaptureFilters {
                    finalization_state: Some("not_requested".to_owned()),
                    streaming: Some(true),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["filter-d", "filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .captures(CaptureFilters {
                    created_after_unix_ms: Some(200),
                    limit: 20,
                    ..CaptureFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.capture_id,
        ),
        vec!["filter-d", "filter-c", "filter-b"]
    );

    let all = store
        .captures(CaptureFilters {
            limit: 20,
            ..CaptureFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ids(&all, |capture| &capture.capture_id),
        vec!["filter-d", "filter-c", "filter-b", "filter-a"]
    );
    let first_page = store
        .captures(CaptureFilters {
            limit: 2,
            ..CaptureFilters::default()
        })
        .await
        .unwrap();
    let second_page = store
        .captures(CaptureFilters {
            cursor: Some(CapturePagePosition::from(first_page.last().unwrap())),
            limit: 2,
            ..CaptureFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page, all[..2]);
    assert_eq!(second_page, all[2..]);

    let counts = store.counts().await.unwrap();
    assert_eq!(counts.total_captures, 4);
    assert_eq!(counts.capturing, 1);
    assert_eq!(counts.ready_to_finalize, 1);
    assert_eq!(counts.finalized, 0);
    assert_eq!(counts.failed, 1);
    assert_eq!(counts.active_operations, 0);
}

async fn operation_filters_and_pagination(store: Arc<dyn MetadataStore>) {
    for (id, created) in [("ops-a", 1), ("ops-b", 2), ("ops-c", 3)] {
        insert_completed(&store, new_capture(id, created), 200).await;
    }
    let op_a = store
        .enqueue_finalization("ops-a", 10)
        .await
        .unwrap()
        .unwrap()
        .0;
    store.enqueue_finalization("ops-b", 20).await.unwrap();
    store.enqueue_finalization("ops-c", 20).await.unwrap();

    let all = store
        .operations(OperationFilters {
            limit: 20,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    let first_page = store
        .operations(OperationFilters {
            limit: 2,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    let second_page = store
        .operations(OperationFilters {
            cursor: Some(OperationPagePosition::from(first_page.last().unwrap())),
            limit: 2,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page, all[..2]);
    assert_eq!(second_page, all[2..]);
    assert_eq!(
        store
            .operations(OperationFilters {
                state: Some("queued".to_owned()),
                kind: Some("finalization".to_owned()),
                capture_id: Some("ops-a".to_owned()),
                limit: 20,
                ..OperationFilters::default()
            })
            .await
            .unwrap(),
        vec![op_a.clone()]
    );
    assert_eq!(
        store.operations_for_capture("ops-a").await.unwrap(),
        vec![op_a.clone()]
    );
    assert!(
        store
            .operations_for_capture("missing")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.operation(&op_a.operation_id).await.unwrap(),
        Some(op_a)
    );
    assert!(store.operation("missing").await.unwrap().is_none());
    assert_eq!(store.counts().await.unwrap().active_operations, 3);

    let claimed = store.claim_next_finalization(30).await.unwrap().unwrap();
    assert_eq!(claimed.capture_id.as_deref(), Some("ops-a"));
    assert_eq!(store.counts().await.unwrap().active_operations, 3);
}

async fn finalization_lifecycle(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("finalize-ok", 1), 200).await;
    insert_completed(&store, new_capture("finalize-http-error", 2), 401).await;
    assert!(
        store
            .enqueue_finalization("finalize-http-error", 3)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .enqueue_finalization("missing", 3)
            .await
            .unwrap()
            .is_none()
    );

    let (queued, duplicate) = store
        .enqueue_finalization("finalize-ok", 4)
        .await
        .unwrap()
        .unwrap();
    assert!(!duplicate);
    let (same, duplicate) = store
        .enqueue_finalization("finalize-ok", 5)
        .await
        .unwrap()
        .unwrap();
    assert!(duplicate);
    assert_eq!(same.operation_id, queued.operation_id);
    let package = artifact("finalize-ok", ArtifactKind::FinalizedPackage, 4);
    assert_eq!(
        store
            .complete_finalization(&queued.operation_id, package.clone(), 6)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "queued".to_owned()
        }
    );
    assert_eq!(
        store
            .fail_operation(&queued.operation_id, 6, "too_early")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "queued".to_owned()
        }
    );
    assert!(
        store
            .operation_attempts(&queued.operation_id)
            .await
            .unwrap()
            .is_empty()
    );

    let running = store.claim_next_finalization(7).await.unwrap().unwrap();
    assert_eq!(running.operation_id, queued.operation_id);
    assert_eq!(running.state, "running");
    assert_eq!(running.attempt, 1);
    assert!(
        store
            .update_operation_progress(&running.operation_id, FinalizationPhase::Signing, 8)
            .await
            .unwrap()
    );
    assert!(
        !store
            .update_operation_progress(&running.operation_id, FinalizationPhase::Signing, 9)
            .await
            .unwrap()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                FinalizationProofProgress {
                    bytes_completed: 2_048,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                10,
            )
            .await
            .unwrap()
    );
    let after_proof = store
        .operation(&running.operation_id)
        .await
        .unwrap()
        .unwrap();
    let progress_events_before = store
        .events_snapshot(EventFilters {
            event_type: Some("finalization_progress".to_owned()),
            operation_id: Some(running.operation_id.clone()),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap()
        .events
        .len();
    assert!(
        !store
            .update_operation_proof_progress(
                &running.operation_id,
                FinalizationProofProgress {
                    bytes_completed: 2_048,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .operation(&running.operation_id)
            .await
            .unwrap()
            .unwrap()
            .progress_updated_at_unix_ms,
        after_proof.progress_updated_at_unix_ms,
        "an identical proof update must not churn its timestamp"
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("finalization_progress".to_owned()),
                operation_id: Some(running.operation_id.clone()),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        progress_events_before,
        "an identical proof update must not emit an event"
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                FinalizationProofProgress {
                    bytes_completed: 1_024,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                FinalizationProofProgress {
                    bytes_completed: 4_096,
                    bytes_total: 16_384,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                FinalizationProofProgress {
                    bytes_completed: 4_096,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 3,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_progress(&running.operation_id, FinalizationPhase::Packaging, 11)
            .await
            .unwrap()
    );
    let progressed = store
        .operation(&running.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(progressed.progress_phase, "packaging");
    assert_eq!(progressed.proof_bytes_completed, 2_048);
    assert_eq!(progressed.proof_bytes_total, 8_192);
    assert_eq!(progressed.proof_commitments_completed, 1);
    assert_eq!(progressed.proof_commitments_total, 2);

    assert_eq!(store.interrupt_running_operations(12).await.unwrap(), 1);
    assert_eq!(store.interrupt_running_operations(13).await.unwrap(), 0);
    assert_eq!(
        store
            .complete_finalization(&running.operation_id, package.clone(), 13)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "interrupted".to_owned()
        }
    );
    assert_eq!(
        store
            .fail_operation(&running.operation_id, 13, "too_late")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "interrupted".to_owned()
        }
    );
    assert!(
        !store
            .update_operation_progress(&running.operation_id, FinalizationPhase::Signing, 13)
            .await
            .unwrap()
    );

    let retried = store
        .retry_operation(&running.operation_id, 14)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried.state, "queued");
    assert_eq!(retried.progress_phase, "queued");
    assert_eq!(retried.proof_bytes_total, 0);
    assert!(
        store
            .retry_operation(&running.operation_id, 14)
            .await
            .unwrap()
            .is_none()
    );
    let second = store.claim_next_finalization(15).await.unwrap().unwrap();
    assert_eq!(second.attempt, 2);
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 16, "proof_generation_failed")
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 17, "proof_generation_failed")
            .await
            .unwrap(),
        TerminalOperationResult::AlreadyApplied
    );
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 17, "different_failure")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "failed".to_owned()
        }
    );
    assert_eq!(
        store
            .complete_finalization(&second.operation_id, package.clone(), 17)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "failed".to_owned()
        }
    );

    store
        .retry_operation(&second.operation_id, 18)
        .await
        .unwrap()
        .unwrap();
    let third = store.claim_next_finalization(19).await.unwrap().unwrap();
    assert_eq!(third.attempt, 3);
    assert!(
        store
            .complete_finalization(
                &third.operation_id,
                artifact("different-capture", ArtifactKind::FinalizedPackage, 4),
                20,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .complete_finalization(&third.operation_id, package.clone(), 20)
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );
    assert_eq!(
        store
            .complete_finalization(&third.operation_id, package.clone(), 21)
            .await
            .unwrap(),
        TerminalOperationResult::AlreadyApplied
    );
    assert!(
        store
            .complete_finalization(
                &third.operation_id,
                artifact("finalize-ok", ArtifactKind::FinalizedPackage, 9),
                21,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .fail_operation(&third.operation_id, 21, "too_late")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "finalized".to_owned()
        }
    );
    assert!(
        store
            .retry_operation(&third.operation_id, 21)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .complete_finalization(
                "missing",
                artifact("missing", ArtifactKind::FinalizedPackage, 4),
                22,
            )
            .await
            .unwrap(),
        TerminalOperationResult::NotFound
    );
    assert_eq!(
        store
            .fail_operation("missing", 22, "missing")
            .await
            .unwrap(),
        TerminalOperationResult::NotFound
    );
    assert!(
        !store
            .update_operation_progress("missing", FinalizationPhase::Signing, 22)
            .await
            .unwrap()
    );
    assert!(
        !store
            .update_operation_proof_progress("missing", FinalizationProofProgress::default(), 22,)
            .await
            .unwrap()
    );
    assert!(
        store
            .retry_operation("missing", 22)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        store.artifacts("finalize-ok").await.unwrap().len(),
        2,
        "the deferred bundle and finalized package are both retained"
    );
    assert_eq!(
        store
            .capture("finalize-ok")
            .await
            .unwrap()
            .unwrap()
            .finalization_state,
        "finalized"
    );

    assert_eq!(
        store.operation_attempts(&third.operation_id).await.unwrap(),
        vec![
            OperationAttempt {
                attempt: 3,
                state: "finalized".to_owned(),
                started_at_unix_ms: 19,
                completed_at_unix_ms: Some(20),
                failure_code: None,
            },
            OperationAttempt {
                attempt: 2,
                state: "failed".to_owned(),
                started_at_unix_ms: 15,
                completed_at_unix_ms: Some(16),
                failure_code: Some("proof_generation_failed".to_owned()),
            },
            OperationAttempt {
                attempt: 1,
                state: "interrupted".to_owned(),
                started_at_unix_ms: 7,
                completed_at_unix_ms: Some(12),
                failure_code: Some("service_restarted".to_owned()),
            },
        ]
    );

    let failed_events = store
        .events_snapshot(EventFilters {
            severity: Some("error".to_owned()),
            event_type: Some("finalization_failed".to_owned()),
            capture_id: Some("finalize-ok".to_owned()),
            operation_id: Some(third.operation_id.clone()),
            created_after_unix_ms: Some(16),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(failed_events.events.len(), 1);
    assert_eq!(
        failed_events.high_water,
        Some(failed_events.events[0].event_id)
    );
    let completed_events = store
        .events_snapshot(EventFilters {
            event_type: Some("finalization_completed".to_owned()),
            operation_id: Some(third.operation_id),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(completed_events.events.len(), 1);
}

async fn concurrent_enqueue_is_deduplicated(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("concurrent-enqueue", 1), 200).await;
    const CONCURRENCY: usize = 12;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENCY {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .enqueue_finalization("concurrent-enqueue", 10)
                .await
                .unwrap()
                .unwrap()
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    assert_eq!(
        results.iter().filter(|(_, duplicate)| !duplicate).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .map(|(operation, _)| operation.operation_id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        1
    );
    assert_eq!(
        store
            .operations_for_capture("concurrent-enqueue")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("finalization_queued".to_owned()),
                capture_id: Some("concurrent-enqueue".to_owned()),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

async fn concurrent_retry_is_deduplicated(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("concurrent-retry", 1), 200).await;
    let operation = store
        .enqueue_finalization("concurrent-retry", 2)
        .await
        .unwrap()
        .unwrap()
        .0;
    let running = store.claim_next_finalization(3).await.unwrap().unwrap();
    assert_eq!(running.operation_id, operation.operation_id);
    assert_eq!(running.attempt, 1);
    assert_eq!(
        store
            .fail_operation(&running.operation_id, 4, "fixture_failure")
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );

    const CONCURRENCY: usize = 12;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENCY {
        let store = store.clone();
        let barrier = barrier.clone();
        let operation_id = running.operation_id.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.retry_operation(&operation_id, 5).await.unwrap()
        }));
    }
    let mut applied = Vec::new();
    for task in tasks {
        if let Some(operation) = task.await.unwrap() {
            applied.push(operation);
        }
    }
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].operation_id, running.operation_id);
    assert_eq!(applied[0].state, "queued");
    assert_eq!(applied[0].attempt, 1, "retry does not start an attempt");
    assert_eq!(
        store
            .operation_attempts(&running.operation_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("finalization_retried".to_owned()),
                operation_id: Some(running.operation_id),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

async fn event_page_and_high_water_are_atomic(store: Arc<dyn MetadataStore>) {
    const WRITERS: usize = 24;
    for index in 0..WRITERS {
        let id = format!("event-atomic-{index:02}");
        insert_completed(&store, new_capture(&id, index as u64 + 1), 200).await;
    }

    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let complete = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for index in 0..WRITERS {
        let store = store.clone();
        let barrier = barrier.clone();
        let complete = complete.clone();
        tasks.push(tokio::spawn(async move {
            let id = format!("event-atomic-{index:02}");
            barrier.wait().await;
            store.enqueue_finalization(&id, 100).await.unwrap();
            complete.fetch_add(1, Ordering::Release);
        }));
    }
    barrier.wait().await;

    loop {
        let snapshot = store
            .events_snapshot(EventFilters {
                event_type: Some("finalization_queued".to_owned()),
                limit: 201,
                ..EventFilters::default()
            })
            .await
            .unwrap();
        match snapshot.high_water {
            Some(high_water) => {
                assert!(!snapshot.events.is_empty());
                assert_eq!(
                    snapshot.events.iter().map(|event| event.event_id).max(),
                    Some(high_water),
                    "the high-water mark must come from the same snapshot as the complete page"
                );
            }
            None => assert!(snapshot.events.is_empty()),
        }
        if complete.load(Ordering::Acquire) == WRITERS {
            break;
        }
        tokio::task::yield_now().await;
    }
    for task in tasks {
        task.await.unwrap();
    }

    let snapshot = store
        .events_snapshot(EventFilters {
            event_type: Some("finalization_queued".to_owned()),
            limit: 201,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(snapshot.events.len(), WRITERS);
    assert_eq!(snapshot.high_water, Some(snapshot.events[0].event_id));
    let high_water = snapshot.high_water.unwrap();
    assert!(
        store
            .events_snapshot(EventFilters {
                after: Some(high_water),
                event_type: Some("finalization_queued".to_owned()),
                limit: 201,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .is_empty()
    );
    let history = store
        .events_snapshot(EventFilters {
            before: Some(high_water),
            event_type: Some("finalization_queued".to_owned()),
            limit: 201,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(history.events.len(), WRITERS - 1);
    assert_eq!(history.high_water, Some(high_water));
}

async fn invalid_limits_and_ranges(store: Arc<dyn MetadataStore>) {
    for limit in [0, 202] {
        assert_invalid(
            store
                .captures(CaptureFilters {
                    limit,
                    ..CaptureFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
        assert_invalid(
            store
                .operations(OperationFilters {
                    limit,
                    ..OperationFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
        assert_invalid(
            store
                .events_snapshot(EventFilters {
                    limit,
                    ..EventFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
    }
    assert_invalid(
        store
            .captures(CaptureFilters {
                created_after_unix_ms: Some(u64::MAX),
                limit: 1,
                ..CaptureFilters::default()
            })
            .await,
        "created_after_out_of_range",
    );
    assert_invalid(
        store
            .captures(CaptureFilters {
                cursor: Some(CapturePagePosition {
                    created_at_unix_ms: u64::MAX,
                    capture_id: "cursor".to_owned(),
                }),
                limit: 1,
                ..CaptureFilters::default()
            })
            .await,
        "cursor_out_of_range",
    );
    assert_invalid(
        store
            .operations(OperationFilters {
                cursor: Some(OperationPagePosition {
                    created_at_unix_ms: u64::MAX,
                    operation_id: "cursor".to_owned(),
                }),
                limit: 1,
                ..OperationFilters::default()
            })
            .await,
        "cursor_out_of_range",
    );
    assert_invalid(
        store
            .events_snapshot(EventFilters {
                before: Some(1),
                after: Some(1),
                limit: 1,
                ..EventFilters::default()
            })
            .await,
        "conflicting_event_positions",
    );
    for filters in [
        EventFilters {
            before: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
        EventFilters {
            after: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
        EventFilters {
            created_after_unix_ms: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
    ] {
        assert_invalid(
            store.events_snapshot(filters).await,
            "event_position_out_of_range",
        );
    }

    assert_invalid(
        store.enqueue_finalization("missing", u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.claim_next_finalization(u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_progress("missing", FinalizationPhase::Signing, u64::MAX)
            .await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "missing",
                FinalizationProofProgress {
                    bytes_completed: u64::MAX,
                    ..FinalizationProofProgress::default()
                },
                1,
            )
            .await,
        "proof_progress_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "missing",
                FinalizationProofProgress {
                    bytes_completed: 2,
                    bytes_total: 1,
                    commitments_completed: 0,
                    commitments_total: 1,
                },
                1,
            )
            .await,
        "invalid_proof_progress",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "missing",
                FinalizationProofProgress {
                    bytes_completed: 0,
                    bytes_total: 1,
                    commitments_completed: 2,
                    commitments_total: 1,
                },
                1,
            )
            .await,
        "invalid_proof_progress",
    );
    assert_invalid(
        store
            .complete_finalization(
                "missing",
                artifact("missing", ArtifactKind::FinalizedPackage, 1),
                u64::MAX,
            )
            .await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.fail_operation("missing", u64::MAX, "failure").await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.interrupt_running_operations(u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.retry_operation("missing", u64::MAX).await,
        "timestamp_out_of_range",
    );

    let mut invalid_capture = new_capture("invalid-capture", u64::MAX);
    assert_invalid(
        store.begin_capture(invalid_capture.clone()).await,
        "capture_created_at_out_of_range",
    );
    invalid_capture.created_at_unix_ms = 1;
    invalid_capture.request_bytes = usize::MAX;
    if usize::BITS > 63 {
        assert_invalid(
            store.begin_capture(invalid_capture).await,
            "request_bytes_out_of_range",
        );
    }

    store
        .begin_capture(new_capture("invalid-completion", 1))
        .await
        .unwrap();
    let valid_artifact = artifact("invalid-completion", ArtifactKind::DeferredBundle, 10);
    let mut invalid_completion = completion("invalid-completion", u64::MAX, 200);
    assert_invalid(
        store
            .complete_capture(invalid_completion.clone(), valid_artifact.clone())
            .await,
        "capture_completed_at_out_of_range",
    );
    invalid_completion.completed_at_unix_ms = 2;
    invalid_completion.duration_ms = u64::MAX;
    assert_invalid(
        store
            .complete_capture(invalid_completion.clone(), valid_artifact.clone())
            .await,
        "duration_out_of_range",
    );
    invalid_completion.duration_ms = 1;
    invalid_completion.response_bytes = u64::MAX;
    assert_invalid(
        store
            .complete_capture(invalid_completion, valid_artifact.clone())
            .await,
        "response_bytes_out_of_range",
    );
    let mut oversized_artifact = valid_artifact;
    let mut invalid_digest = oversized_artifact.clone();
    invalid_digest.size_bytes = 10;
    invalid_digest.sha256 = "not-a-digest".to_owned();
    assert_invalid(
        store
            .complete_capture(completion("invalid-completion", 2, 200), invalid_digest)
            .await,
        "invalid_artifact_record",
    );
    oversized_artifact.size_bytes = u64::MAX;
    assert_invalid(
        store
            .complete_capture(
                completion("invalid-completion", 2, 200),
                oversized_artifact.clone(),
            )
            .await,
        "artifact_size_out_of_range",
    );
    assert_invalid(
        store
            .recover_capture("invalid-completion", oversized_artifact.clone())
            .await,
        "artifact_size_out_of_range",
    );
    oversized_artifact.key =
        ArtifactKey::new("invalid-completion", ArtifactKind::FinalizedPackage).unwrap();
    assert_invalid(
        store
            .complete_finalization("missing", oversized_artifact, 1)
            .await,
        "artifact_size_out_of_range",
    );
}
