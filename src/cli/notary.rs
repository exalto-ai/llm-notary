use std::{
    collections::BTreeMap,
    env, fs,
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

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustStore {
    format: String,
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
    directory.validate()?;
    let path = trust_store_path()?;
    let store = merge_store(load_store(&path)?, directory);
    write_store(&path, &store)
}

fn merge_store(mut store: TrustStore, directory: NotaryDirectory) -> TrustStore {
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
        records.insert(record.key_id.clone(), record);
    }
    store.format = DIRECTORY_FORMAT_V2.to_owned();
    store.active_key_id = Some(directory.active_key_id);
    store.records = records.into_values().collect();
    store
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
    if store.format != DIRECTORY_FORMAT_V2 {
        bail!("unsupported local notary trust store format");
    }
    let directory = NotaryDirectory {
        format: DIRECTORY_FORMAT_V2.to_owned(),
        active_key_id: store
            .active_key_id
            .clone()
            .ok_or_else(|| anyhow!("local notary trust store has no active key"))?,
        notaries: store.records.clone(),
    };
    directory.validate()?;
    Ok(store)
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
    let partial = path.with_extension("json.partial");
    fs::write(&partial, serde_json::to_vec_pretty(store)?)
        .with_context(|| format!("write {}", partial.display()))?;
    fs::rename(&partial, path).with_context(|| format!("finalize {}", path.display()))
}

fn unix_time_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")?)
}

#[cfg(test)]
mod tests {
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
        }
    }

    #[test]
    fn merge_preserves_missing_keys_as_retired_and_applies_revocation() {
        let old = record(7, NotaryKeyStatus::Active);
        let new = record(8, NotaryKeyStatus::Active);
        let store = TrustStore {
            format: DIRECTORY_FORMAT_V2.into(),
            active_key_id: Some(old.key_id.clone()),
            records: vec![old.clone()],
        };
        let updated = merge_store(
            store,
            NotaryDirectory {
                format: DIRECTORY_FORMAT_V2.into(),
                active_key_id: new.key_id.clone(),
                notaries: vec![new],
            },
        );
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
                active_key_id: record(8, NotaryKeyStatus::Active).key_id,
                notaries: vec![record(8, NotaryKeyStatus::Active), revoked.clone()],
            },
        );
        assert!(
            !replaced
                .records
                .iter()
                .find(|record| record.key_id == revoked.key_id)
                .unwrap()
                .trusted_at(1)
        );
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
