//! Backend conformance scenarios for [`ArtifactStore`](super::ArtifactStore).

use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use super::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore, ArtifactStoreError};

fn key(capture_id: &str, kind: ArtifactKind) -> ArtifactKey {
    ArtifactKey::new(capture_id, kind).unwrap()
}

async fn read(store: &dyn ArtifactStore, record: &super::ArtifactRecord, limit: u64) -> Vec<u8> {
    store
        .read_verified(record, limit)
        .await
        .unwrap()
        .into_bytes()
        .await
        .unwrap()
}

/// Runs the immutable-write, bounded-read, integrity, and concurrency contract.
pub(crate) async fn run(store: Arc<dyn ArtifactStore>) {
    let round_trip_key = key("cap-conformance-roundtrip", ArtifactKind::DeferredBundle);
    let content = b"vault-encrypted checkpoint".to_vec();
    let limit = content.len() as u64;
    let first = store
        .put(
            &round_trip_key,
            ArtifactSource::from_bytes(content.clone()),
            limit,
        )
        .await
        .unwrap();
    let second = store
        .put(
            &round_trip_key,
            ArtifactSource::from_bytes(content.clone()),
            limit,
        )
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.size_bytes, limit);
    assert_eq!(first.sha256, hex::encode(Sha256::digest(&content)));
    assert_eq!(
        store.find(&round_trip_key, limit).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(read(store.as_ref(), &first, limit).await, content);
    assert!(matches!(
        store.read_verified(&first, limit - 1).await.unwrap_err(),
        ArtifactStoreError::TooLarge { .. }
    ));

    assert_eq!(
        store
            .find(
                &key("cap-conformance-missing", ArtifactKind::DeferredBundle),
                1024,
            )
            .await
            .unwrap(),
        None
    );

    let collision_key = key("cap-conformance-collision", ArtifactKind::FinalizedPackage);
    let collision_record = store
        .put(
            &collision_key,
            ArtifactSource::from_bytes(b"first".to_vec()),
            5,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .put(
                &collision_key,
                ArtifactSource::from_bytes(b"other".to_vec()),
                5,
            )
            .await
            .unwrap_err(),
        ArtifactStoreError::Conflict { .. }
    ));
    assert_eq!(read(store.as_ref(), &collision_record, 5).await, b"first");

    for (capture_id, bytes, declared) in [
        ("cap-conformance-short", b"short".as_slice(), 6),
        ("cap-conformance-long", b"longer".as_slice(), 5),
    ] {
        let stream_key = key(capture_id, ArtifactKind::DeferredBundle);
        let source = ArtifactSource::new(std::io::Cursor::new(bytes.to_vec()), declared);
        assert!(matches!(
            store.put(&stream_key, source, 10).await.unwrap_err(),
            ArtifactStoreError::Integrity { .. }
        ));
        assert_eq!(store.find(&stream_key, 10).await.unwrap(), None);
    }

    let mut corrupt_record = first.clone();
    corrupt_record.sha256 = "00".repeat(32);
    assert!(matches!(
        store
            .read_verified(&corrupt_record, limit)
            .await
            .unwrap_err(),
        ArtifactStoreError::Integrity { .. }
    ));
    let concurrent_key = key("cap-conformance-concurrent", ArtifactKind::FinalizedPackage);
    let concurrent_content = b"one immutable object".to_vec();
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        let key = concurrent_key.clone();
        let content = concurrent_content.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(
                    &key,
                    ArtifactSource::from_bytes(content.clone()),
                    content.len() as u64,
                )
                .await
                .unwrap()
        }));
    }
    let mut records = Vec::new();
    for task in tasks {
        records.push(task.await.unwrap());
    }
    assert!(records.iter().all(|record| record == &records[0]));
    assert_eq!(
        read(store.as_ref(), &records[0], concurrent_content.len() as u64).await,
        concurrent_content
    );
}
