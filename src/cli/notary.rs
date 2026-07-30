use std::{
    collections::BTreeMap,
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{
    DeferredBundle,
    notary_directory::{
        DIRECTORY_FORMAT_V1, DIRECTORY_FORMAT_V2, LegacyNotaryDirectory, NotaryDirectory,
        NotaryDirectoryRecord, NotaryKeyStatus, key_id,
    },
};

pub use crate::notary_directory::parse_directory;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStore {
    format: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    directory_sha256: Option<String>,
    active_key_id: Option<String>,
    records: Vec<NotaryDirectoryRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTrustStore {
    #[serde(rename = "format")]
    _format: String,
    record: Option<LegacyNotaryDirectory>,
}

pub fn pin(directory: NotaryDirectory) -> Result<()> {
    let path = trust_store_path()?;
    pin_at_path(&path, directory)
}

fn pin_at_path(path: &Path, directory: NotaryDirectory) -> Result<()> {
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
    let store = merge_store(load_store(path)?, directory)?;
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
    store.format = DIRECTORY_FORMAT_V2.to_owned();
    store.generation = directory.generation;
    store.directory_sha256 = Some(directory_sha256);
    store.active_key_id = Some(directory.active_key_id);
    store.records = records.into_values().collect();
    Ok(store)
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
                "notary key {requested_id} is not present in the local trust store; supply --trusted-notary-key to override"
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
        "no cached active or retiring notary can finalize this bundle; refresh the directory or supply --notary and --trusted-notary-key"
    )
}

pub fn explicit_key(value: &str) -> Result<(Vec<u8>, String)> {
    let key = hex::decode(value).context("trusted notary key must be hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&key)
        .context("trusted notary key must be a SEC1 secp256k1 key")?;
    Ok((key.clone(), key_id(&key)))
}

fn validated_store() -> Result<TrustStore> {
    let store = load_store(&trust_store_path()?)?;
    validate_trust_store(&store)?;
    Ok(store)
}

fn validate_trust_store(store: &TrustStore) -> Result<()> {
    if store.format != DIRECTORY_FORMAT_V2 {
        bail!("unsupported local notary trust store format");
    }
    if store.records.is_empty() || store.records.len() > 4096 {
        bail!("local notary trust store must contain between 1 and 4096 historical records");
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
    let base = if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("APPDATA") {
        PathBuf::from(path)
    } else if let Some(path) = env::var_os("HOME") {
        PathBuf::from(path).join(".config")
    } else {
        bail!("could not determine a configuration directory")
    };
    Ok(base.join("llm-notary").join("notary-trust.json"))
}

fn load_store(path: &Path) -> Result<TrustStore> {
    if !path.exists() {
        return Ok(TrustStore::default());
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse local notary trust store")?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(DIRECTORY_FORMAT_V2) => {
            serde_json::from_value(value).context("parse v2 local notary trust store")
        }
        Some(DIRECTORY_FORMAT_V1) | Some("") | None => {
            let legacy: LegacyTrustStore =
                serde_json::from_value(value).context("parse v1 local notary trust store")?;
            let Some(record) = legacy.record else {
                return Ok(TrustStore::default());
            };
            let directory = NotaryDirectory::from_legacy(record)?;
            Ok(TrustStore {
                format: DIRECTORY_FORMAT_V2.to_owned(),
                generation: 0,
                directory_sha256: None,
                active_key_id: Some(directory.active_key_id),
                records: directory.notaries,
            })
        }
        Some(format) => bail!("unsupported local notary trust store format: {format}"),
    }
}

fn write_store(path: &Path, store: &TrustStore) -> Result<()> {
    let parent = path.parent().expect("trust store has a parent");
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let partial = parent.join(format!(
        ".notary-trust.{}.{}.partial",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<()> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&partial)
            .with_context(|| format!("create {}", partial.display()))?;
        output
            .write_all(&serde_json::to_vec_pretty(store)?)
            .with_context(|| format!("write {}", partial.display()))?;
        output
            .sync_all()
            .with_context(|| format!("sync {}", partial.display()))?;
        replace_file(&partial, path)
            .with_context(|| format!("atomically replace {}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that stay
    // alive for the duration of the call.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
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

    use super::*;

    fn record(seed: u8, status: NotaryKeyStatus) -> NotaryDirectoryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        NotaryDirectoryRecord {
            host: "notary.example".into(),
            port: 7047,
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
            format: DIRECTORY_FORMAT_V2.into(),
            generation: 1,
            directory_sha256: None,
            active_key_id: Some(old.key_id.clone()),
            records: vec![old.clone()],
        };
        let updated = merge_store(
            store,
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V2.into(),
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
                format: DIRECTORY_FORMAT_V2.into(),
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
                format: DIRECTORY_FORMAT_V2.into(),
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
            format: DIRECTORY_FORMAT_V2.into(),
            generation: 2,
            directory_sha256: Some("directory-sha".into()),
            active_key_id: Some(active.key_id.clone()),
            records: vec![active],
        };

        write_store(&path, &store).unwrap();

        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.generation, 2);
        assert_eq!(loaded.directory_sha256.as_deref(), Some("directory-sha"));
    }

    #[test]
    fn rejects_directory_rollback_and_conflicting_same_generation() {
        let active = record(8, NotaryKeyStatus::Active);
        let initial = merge_store(
            TrustStore::default(),
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V2.into(),
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
                    format: DIRECTORY_FORMAT_V2.into(),
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
                    format: DIRECTORY_FORMAT_V2.into(),
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
                format: DIRECTORY_FORMAT_V2.into(),
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
                    format: DIRECTORY_FORMAT_V2.into(),
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
                        format: DIRECTORY_FORMAT_V2.into(),
                        generation,
                        active_key_id: active.key_id.clone(),
                        notaries: vec![active],
                    },
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
    fn load_store_migrates_a_v1_cache() {
        let active = record(9, NotaryKeyStatus::Active);
        let path = std::env::temp_dir().join(format!(
            "llm-notary-v1-trust-{}-{}.json",
            std::process::id(),
            active.key_id.replace(':', "-")
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "format": DIRECTORY_FORMAT_V1,
                "record": {
                    "format": DIRECTORY_FORMAT_V1,
                    "host": active.host,
                    "port": active.port,
                    "key_id": active.key_id,
                    "public_key": active.public_key
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let migrated = load_store(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(migrated.format, DIRECTORY_FORMAT_V2);
        assert_eq!(migrated.records.len(), 1);
        assert_eq!(migrated.active_key_id, Some(active.key_id));
    }
}
