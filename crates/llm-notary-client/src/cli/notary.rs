use std::{
    collections::BTreeMap,
    fs,
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    DeferredBundle,
    metadata::SharedNotaryTrust,
    notary_directory::{
        DIRECTORY_FORMAT_V3, NotaryDirectory, NotaryDirectoryRecord, NotaryKeyStatus, key_id,
    },
};

use super::storage;

pub use crate::notary_directory::parse_directory;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStore {
    format: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    directory_sha256: Option<String>,
    #[serde(default)]
    directory_source: Option<String>,
    active_key_id: Option<String>,
    records: Vec<NotaryDirectoryRecord>,
}

#[derive(Clone, Debug)]
pub(crate) struct PinnedNotaryState {
    pub directory_source: Option<String>,
    pub generation: u64,
    pub active_key_id: String,
    pub records: Vec<NotaryDirectoryRecord>,
}

impl From<SharedNotaryTrust> for PinnedNotaryState {
    fn from(value: SharedNotaryTrust) -> Self {
        Self {
            directory_source: Some(value.directory_source),
            generation: value.generation,
            active_key_id: value.active_key_id,
            records: value.records,
        }
    }
}

pub fn pin(directory: NotaryDirectory, directory_source: &str) -> Result<()> {
    let path = trust_store_path()?;
    pin_at_path(&path, directory, directory_source)
}

fn pin_at_path(path: &Path, directory: NotaryDirectory, directory_source: &str) -> Result<()> {
    directory.validate()?;
    let parent = path.parent().expect("trust store has a parent");
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let lock_path = path.with_extension("json.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("lock {}", lock_path.display()))?;
    // The read must happen after acquiring the cross-process lock. Otherwise a
    // slower process could overwrite a newer generation or cached revocation.
    let mut store = merge_store(load_store(path)?, directory)?;
    store.directory_source = Some(directory_source.to_owned());
    validate_trust_store(&store)?;
    write_store(path, &store)
}

fn merge_store(mut store: TrustStore, directory: NotaryDirectory) -> Result<TrustStore> {
    let directory_sha256 = crate::sha256_hex(
        &serde_json::to_vec(&directory).context("encode notary directory revision")?,
    );
    if directory.generation < store.generation {
        bail!(
            "notary directory generation {} is older than cached generation {}",
            directory.generation,
            store.generation
        );
    }
    if directory.generation == store.generation
        && store
            .directory_sha256
            .as_ref()
            .is_some_and(|cached| cached != &directory_sha256)
    {
        bail!(
            "notary directory generation {} conflicts with the cached revision",
            directory.generation
        );
    }
    let mut records = store
        .records
        .drain(..)
        .map(|record| (record.key_id.clone(), record))
        .collect::<BTreeMap<_, _>>();

    // A planned removal becomes historical trust. Compromise revocation must
    // be explicit in a directory response before the record is removed.
    for record in records.values_mut() {
        if matches!(
            record.status,
            NotaryKeyStatus::Active | NotaryKeyStatus::Retiring
        ) {
            record.status = NotaryKeyStatus::Retired;
        }
    }
    for record in directory.notaries {
        if records
            .get(&record.key_id)
            .is_some_and(|cached| cached.status == NotaryKeyStatus::Revoked)
            && record.status != NotaryKeyStatus::Revoked
        {
            continue;
        }
        records.insert(record.key_id.clone(), record);
    }
    store.format = DIRECTORY_FORMAT_V3.to_owned();
    store.generation = directory.generation;
    store.directory_sha256 = Some(directory_sha256);
    store.active_key_id = Some(directory.active_key_id);
    store.records = records.into_values().collect();
    Ok(store)
}

pub(crate) fn merge_shared_trust(
    current: Option<SharedNotaryTrust>,
    directory: NotaryDirectory,
    directory_source: &str,
) -> Result<SharedNotaryTrust> {
    let source_url =
        url::Url::parse(directory_source).context("notary directory source is invalid")?;
    if directory_source.len() > 2048
        || !matches!(source_url.scheme(), "http" | "https")
        || !source_url.username().is_empty()
        || source_url.password().is_some()
        || source_url.path() != "/api/notary"
        || source_url.query().is_some()
        || source_url.fragment().is_some()
    {
        bail!("notary directory source is not a public directory URL");
    }
    if current
        .as_ref()
        .is_some_and(|current| current.directory_source != directory_source)
    {
        bail!("notary directory source differs from the pinned cluster authority");
    }
    let store = current.map_or_else(TrustStore::default, |current| TrustStore {
        format: DIRECTORY_FORMAT_V3.to_owned(),
        generation: current.generation,
        directory_sha256: Some(current.directory_sha256),
        directory_source: Some(current.directory_source),
        active_key_id: Some(current.active_key_id),
        records: current.records,
    });
    let mut store = merge_store(store, directory)?;
    store.directory_source = Some(directory_source.to_owned());
    validate_trust_store(&store)?;
    Ok(shared_from_store(store))
}

pub(crate) fn validate_shared_trust(trust: &SharedNotaryTrust) -> Result<()> {
    validate_trust_store(&TrustStore {
        format: DIRECTORY_FORMAT_V3.to_owned(),
        generation: trust.generation,
        directory_sha256: Some(trust.directory_sha256.clone()),
        directory_source: Some(trust.directory_source.clone()),
        active_key_id: Some(trust.active_key_id.clone()),
        records: trust.records.clone(),
    })
}

pub(crate) fn shared_key_at(
    trust: &SharedNotaryTrust,
    public_key: &[u8],
    authenticated_unix_ms: u64,
) -> Result<(String, String)> {
    validate_shared_trust(trust)?;
    let requested_id = key_id(public_key);
    let record = trust
        .records
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(public_key))
        })
        .ok_or_else(|| anyhow!("notary key {requested_id} is not present in shared trust"))?;
    if !record.trusted_at(authenticated_unix_ms) {
        bail!(
            "notary key {} was not trusted at the authenticated connection time",
            record.key_id
        );
    }
    Ok((record.key_id.clone(), "directory".to_owned()))
}

pub(crate) fn shared_record_for_bundle(
    trust: &SharedNotaryTrust,
    bundle: &DeferredBundle,
) -> Result<(Vec<u8>, NotaryDirectoryRecord)> {
    validate_shared_trust(trust)?;
    let connection_time = bundle.authenticated_connection_time_unix_ms()?;
    let now = unix_time_ms()?;
    for record in &trust.records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connection_time)
            && record.accepts_finalization_at(now)
            && bundle.verify_notary_key(&key).is_ok()
        {
            return Ok((key, record.clone()));
        }
    }
    bail!("no shared active or retiring notary can finalize this bundle")
}

fn shared_from_store(store: TrustStore) -> SharedNotaryTrust {
    SharedNotaryTrust {
        generation: store.generation,
        directory_sha256: store
            .directory_sha256
            .expect("validated trust has a digest"),
        directory_source: store
            .directory_source
            .expect("validated trust has a source"),
        active_key_id: store
            .active_key_id
            .expect("validated trust has an active key"),
        records: store.records,
    }
}

pub fn cached_key_at(public_key: &[u8], authenticated_unix_ms: u64) -> Result<(String, String)> {
    let requested_id = key_id(public_key);
    let store = validated_store()?;
    let record = store
        .records
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(public_key))
        })
        .ok_or_else(|| {
            anyhow!(
                "notary key {requested_id} is not present in the local trust store; configure notary.public_key with an explicit endpoint for a self-hosted notary"
            )
        })?;
    if !record.trusted_at(authenticated_unix_ms) {
        bail!(
            "notary key {} was not trusted at the authenticated connection time",
            record.key_id
        );
    }
    Ok((record.key_id.clone(), "directory".to_owned()))
}

pub fn cached_record_for_key(public_key: &[u8]) -> Result<NotaryDirectoryRecord> {
    let requested_id = key_id(public_key);
    validated_store()?
        .records
        .into_iter()
        .find(|record| record.key_id == requested_id)
        .ok_or_else(|| anyhow!("notary key {requested_id} has no cached endpoint"))
}

pub fn cached_record_for_bundle(
    bundle: &DeferredBundle,
) -> Result<(Vec<u8>, NotaryDirectoryRecord)> {
    let connection_time = bundle.authenticated_connection_time_unix_ms()?;
    let now = unix_time_ms()?;
    for record in validated_store()?.records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connection_time)
            && record.accepts_finalization_at(now)
            && bundle.verify_notary_key(&key).is_ok()
        {
            return Ok((key, record));
        }
    }
    bail!(
        "no cached active or retiring notary can finalize this bundle; refresh the directory or configure notary.endpoint and notary.public_key together"
    )
}

pub fn explicit_key(value: &str) -> Result<(Vec<u8>, String)> {
    let key = hex::decode(value).context("trusted notary key must be hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&key)
        .context("trusted notary key must be a SEC1 secp256k1 key")?;
    Ok((key.clone(), key_id(&key)))
}

pub(crate) fn pinned_state() -> Result<Option<PinnedNotaryState>> {
    let path = trust_store_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let store = load_store(&path)?;
    validate_trust_store(&store)?;
    Ok(Some(PinnedNotaryState {
        directory_source: store.directory_source,
        generation: store.generation,
        active_key_id: store
            .active_key_id
            .expect("validated trust store has an active key"),
        records: store.records,
    }))
}

fn validated_store() -> Result<TrustStore> {
    let store = load_store(&trust_store_path()?)?;
    validate_trust_store(&store)?;
    Ok(store)
}

fn validate_trust_store(store: &TrustStore) -> Result<()> {
    if store.format != DIRECTORY_FORMAT_V3 {
        bail!("unsupported local notary trust store format");
    }
    if store.records.is_empty() || store.records.len() > 4096 {
        bail!("local notary trust store must contain between 1 and 4096 historical records");
    }
    if let Some(source) = &store.directory_source {
        let source_url =
            url::Url::parse(source).context("cached notary directory source is invalid")?;
        if source.len() > 2048
            || !matches!(source_url.scheme(), "http" | "https")
            || !source_url.username().is_empty()
            || source_url.password().is_some()
            || source_url.path() != "/api/notary"
            || source_url.query().is_some()
            || source_url.fragment().is_some()
        {
            bail!("cached notary directory source is not a public directory URL");
        }
    }
    let active_key_id = store
        .active_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("local notary trust store has no active key"))?;
    let mut ids = std::collections::BTreeSet::new();
    for record in &store.records {
        record.public_key_bytes()?;
        if record
            .valid_until_unix_ms
            .is_some_and(|until| until < record.valid_from_unix_ms)
            || record
                .finalize_until_unix_ms
                .is_some_and(|until| until < record.valid_from_unix_ms)
        {
            bail!("cached notary key has an inverted lifecycle window");
        }
        if !ids.insert(record.key_id.as_str()) {
            bail!("local notary trust store contains a duplicate key ID");
        }
    }
    let active = store
        .records
        .iter()
        .find(|record| record.key_id == active_key_id)
        .ok_or_else(|| anyhow!("local notary trust store is missing its active key"))?;
    if active.status != NotaryKeyStatus::Active {
        bail!("local notary trust store selected a non-active key");
    }
    Ok(())
}

fn trust_store_path() -> Result<PathBuf> {
    storage::config_file("notary-trust.json")
}

fn load_store(path: &Path) -> Result<TrustStore> {
    if !path.exists() {
        return Ok(TrustStore::default());
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse local notary trust store")?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(DIRECTORY_FORMAT_V3) => {
            serde_json::from_value(value).context("parse v3 local notary trust store")
        }
        Some(format) => bail!(
            "unsupported local notary trust store format: {format}; remove the cache and refresh the notary directory"
        ),
        None => bail!(
            "local notary trust store format is missing; remove the cache and refresh the notary directory"
        ),
    }
}

fn write_store(path: &Path, store: &TrustStore) -> Result<()> {
    storage::write_private_file_atomically(path, &serde_json::to_vec_pretty(store)?)
}

fn unix_time_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use crate::notary_directory::NotaryTransport;

    use super::*;

    fn record(seed: u8, status: NotaryKeyStatus) -> NotaryDirectoryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        NotaryDirectoryRecord {
            host: "notary.example".into(),
            port: 7047,
            transport: NotaryTransport::Tcp,
            key_id: key_id(&public),
            public_key: hex::encode(public),
            status,
            valid_from_unix_ms: 0,
            valid_until_unix_ms: None,
            finalize_until_unix_ms: None,
        }
    }

    #[test]
    fn merge_preserves_missing_keys_as_retired_and_applies_revocation() {
        let old = record(7, NotaryKeyStatus::Active);
        let new = record(8, NotaryKeyStatus::Active);
        let store = TrustStore {
            format: DIRECTORY_FORMAT_V3.into(),
            generation: 1,
            directory_sha256: None,
            directory_source: None,
            active_key_id: Some(old.key_id.clone()),
            records: vec![old.clone()],
        };
        let updated = merge_store(
            store,
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V3.into(),
                generation: 2,
                active_key_id: new.key_id.clone(),
                notaries: vec![new],
            },
        )
        .unwrap();
        assert_eq!(
            updated
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mut revoked = old;
        revoked.status = NotaryKeyStatus::Revoked;
        let replaced = merge_store(
            updated,
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V3.into(),
                generation: 3,
                active_key_id: record(8, NotaryKeyStatus::Active).key_id,
                notaries: vec![record(8, NotaryKeyStatus::Active), revoked.clone()],
            },
        )
        .unwrap();
        assert!(
            !replaced
                .records
                .iter()
                .find(|record| record.key_id == revoked.key_id)
                .unwrap()
                .trusted_at(1)
        );

        let attempted_restore = merge_store(
            replaced,
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V3.into(),
                generation: 4,
                active_key_id: record(8, NotaryKeyStatus::Active).key_id,
                notaries: vec![
                    record(8, NotaryKeyStatus::Active),
                    record(7, NotaryKeyStatus::Retired),
                ],
            },
        )
        .unwrap();
        assert_eq!(
            attempted_restore
                .records
                .iter()
                .find(|record| record.key_id == revoked.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
    }

    #[test]
    fn write_store_atomically_replaces_an_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("notary-trust.json");
        fs::write(&path, b"old directory").unwrap();
        let active = record(8, NotaryKeyStatus::Active);
        let store = TrustStore {
            format: DIRECTORY_FORMAT_V3.into(),
            generation: 2,
            directory_sha256: Some("directory-sha".into()),
            directory_source: Some("https://example.test/api/notary".into()),
            active_key_id: Some(active.key_id.clone()),
            records: vec![active],
        };

        write_store(&path, &store).unwrap();

        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.generation, 2);
        assert_eq!(loaded.directory_sha256.as_deref(), Some("directory-sha"));
        assert_eq!(
            loaded.directory_source.as_deref(),
            Some("https://example.test/api/notary")
        );
    }

    #[test]
    fn trust_store_rejects_a_non_public_directory_source() {
        let active = record(8, NotaryKeyStatus::Active);
        let mut store = TrustStore {
            format: DIRECTORY_FORMAT_V3.into(),
            generation: 2,
            directory_sha256: Some("directory-sha".into()),
            directory_source: Some("https://user:secret@example.test/api/notary".into()),
            active_key_id: Some(active.key_id.clone()),
            records: vec![active],
        };
        assert!(validate_trust_store(&store).is_err());
        store.directory_source = Some("/Users/example/private/notary.json".into());
        assert!(validate_trust_store(&store).is_err());
    }

    #[test]
    fn rejects_directory_rollback_and_conflicting_same_generation() {
        let active = record(8, NotaryKeyStatus::Active);
        let initial = merge_store(
            TrustStore::default(),
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V3.into(),
                generation: 10,
                active_key_id: active.key_id.clone(),
                notaries: vec![active.clone()],
            },
        )
        .unwrap();
        assert!(
            merge_store(
                initial.clone(),
                NotaryDirectory {
                    format: DIRECTORY_FORMAT_V3.into(),
                    generation: 9,
                    active_key_id: active.key_id.clone(),
                    notaries: vec![active.clone()],
                }
            )
            .is_err()
        );
        let mut conflicting = active.clone();
        conflicting.host = "rollback.example".into();
        assert!(
            merge_store(
                initial,
                NotaryDirectory {
                    format: DIRECTORY_FORMAT_V3.into(),
                    generation: 10,
                    active_key_id: conflicting.key_id.clone(),
                    notaries: vec![conflicting],
                }
            )
            .is_err()
        );
    }

    #[test]
    fn historical_cache_can_retain_more_than_the_live_directory_limit() {
        let active = record(1, NotaryKeyStatus::Active);
        let mut store = merge_store(
            TrustStore::default(),
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V3.into(),
                generation: 1,
                active_key_id: active.key_id.clone(),
                notaries: vec![active],
            },
        )
        .unwrap();
        for generation in 2u64..=40 {
            let next = record(generation as u8, NotaryKeyStatus::Active);
            store = merge_store(
                store,
                NotaryDirectory {
                    format: DIRECTORY_FORMAT_V3.into(),
                    generation,
                    active_key_id: next.key_id.clone(),
                    notaries: vec![next],
                },
            )
            .unwrap();
        }
        assert_eq!(store.records.len(), 40);
        validate_trust_store(&store).unwrap();
    }

    #[test]
    fn concurrent_pins_cannot_overwrite_a_newer_generation() {
        let root = std::env::temp_dir().join(format!(
            "llm-notary-trust-lock-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("notary-trust.json");
        let older = record(7, NotaryKeyStatus::Active);
        let newer = record(8, NotaryKeyStatus::Active);
        let barrier = Arc::new(Barrier::new(3));
        let spawn_pin = |generation: u64,
                         active: NotaryDirectoryRecord,
                         barrier: Arc<Barrier>,
                         path: PathBuf| {
            std::thread::spawn(move || {
                barrier.wait();
                pin_at_path(
                    &path,
                    NotaryDirectory {
                        format: DIRECTORY_FORMAT_V3.into(),
                        generation,
                        active_key_id: active.key_id.clone(),
                        notaries: vec![active],
                    },
                    "https://example.test/api/notary",
                )
            })
        };
        let old_thread = spawn_pin(1, older, Arc::clone(&barrier), path.clone());
        let new_key_id = newer.key_id.clone();
        let new_thread = spawn_pin(2, newer, Arc::clone(&barrier), path.clone());
        barrier.wait();
        let old_result = old_thread.join().unwrap();
        let new_result = new_thread.join().unwrap();
        assert!(new_result.is_ok());
        let _ = old_result;

        let store = load_store(&path).unwrap();
        assert_eq!(store.generation, 2);
        assert_eq!(store.active_key_id.as_deref(), Some(new_key_id.as_str()));
        validate_trust_store(&store).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_store_rejects_legacy_cache_formats() {
        let path = std::env::temp_dir().join(format!(
            "llm-notary-legacy-trust-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        for format in [
            "llm-notary/notary-directory/v1",
            "llm-notary/notary-directory/v2",
        ] {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({ "format": format })).unwrap(),
            )
            .unwrap();
            assert!(load_store(&path).is_err());
        }
        let _ = std::fs::remove_file(path);
    }
}
