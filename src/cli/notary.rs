use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

pub const DIRECTORY_FORMAT: &str = "llm-notary/notary-directory/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRecord {
    pub format: String,
    pub active: DirectoryKey,
    #[serde(default)]
    pub previous: Vec<DirectoryKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryKey {
    pub host: String,
    pub port: u16,
    pub key_id: String,
    pub public_key: String,
    pub status: String,
    pub valid_from_unix: u64,
    pub valid_until_unix: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct TrustStore {
    format: String,
    records: Vec<DirectoryRecord>,
}

pub fn key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key))
}

pub fn validate_directory(record: &DirectoryRecord, now: u64) -> Result<()> {
    if record.format != DIRECTORY_FORMAT {
        bail!("unsupported notary directory format: {}", record.format);
    }
    validate_key(&record.active, "active", now)?;
    if record.active.status != "active" {
        bail!("directory active key must have status active");
    }
    for key in &record.previous {
        validate_key(key, "previous", now)?;
        if key.status != "previous" {
            bail!("directory previous key {} has invalid status", key.key_id);
        }
    }
    Ok(())
}

fn validate_key(key: &DirectoryKey, name: &str, now: u64) -> Result<Vec<u8>> {
    if key.host.is_empty() || key.host.chars().any(char::is_whitespace) || key.port == 0 {
        bail!("directory {name} key has an invalid endpoint");
    }
    let public_key = hex::decode(&key.public_key)
        .with_context(|| format!("directory {name} key is not hexadecimal"))?;
    VerifyingKey::from_sec1_bytes(&public_key)
        .with_context(|| format!("directory {name} key is not a SEC1 secp256k1 key"))?;
    if key.key_id != key_id(&public_key) {
        bail!("directory {name} key ID does not match its public key");
    }
    if now < key.valid_from_unix || key.valid_until_unix.is_some_and(|until| now > until) {
        bail!(
            "directory {name} key {} is outside its validity interval",
            key.key_id
        );
    }
    Ok(public_key)
}

pub fn pin(record: DirectoryRecord) -> Result<()> {
    let now = now()?;
    validate_directory(&record, now)?;
    let path = trust_store_path()?;
    let mut store = load_store(&path)?;
    store
        .records
        .retain(|old| old.active.key_id != record.active.key_id);
    store.records.push(record);
    store.format = DIRECTORY_FORMAT.to_owned();
    write_store(&path, &store)
}

pub fn cached_key(public_key: &[u8]) -> Result<(String, String)> {
    let now = now()?;
    let requested_id = key_id(public_key);
    let store = load_store(&trust_store_path()?)?;
    if store.format != DIRECTORY_FORMAT {
        bail!("unsupported local notary trust store format");
    }
    for record in &store.records {
        if validate_directory(record, now).is_err() {
            continue;
        }
        for key in std::iter::once(&record.active).chain(record.previous.iter()) {
            if key
                .public_key
                .eq_ignore_ascii_case(&hex::encode(public_key))
            {
                return Ok((key.key_id.clone(), key.status.clone()));
            }
        }
    }
    Err(anyhow!(
        "notary key {requested_id} is not present in the local trust store; supply --trusted-notary-key to override"
    ))
}

pub fn explicit_key(value: &str) -> Result<(Vec<u8>, String)> {
    let key = hex::decode(value).context("trusted notary key must be hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&key)
        .context("trusted notary key must be a SEC1 secp256k1 key")?;
    Ok((key.clone(), key_id(&key)))
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before the Unix epoch"))?
        .as_secs())
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
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .context("parse local notary trust store")
}

fn write_store(path: &Path, store: &TrustStore) -> Result<()> {
    let parent = path.parent().expect("trust store has a parent");
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let partial = path.with_extension("json.partial");
    fs::write(&partial, serde_json::to_vec_pretty(store)?)
        .with_context(|| format!("write {}", partial.display()))?;
    fs::rename(&partial, path).with_context(|| format!("finalize {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DirectoryKey {
        let signing = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        DirectoryKey {
            host: "notary.example".into(),
            port: 7047,
            key_id: key_id(&public),
            public_key: hex::encode(public),
            status: "active".into(),
            valid_from_unix: 10,
            valid_until_unix: Some(20),
        }
    }

    #[test]
    fn rejects_expired_and_mismatched_directory_keys() {
        let active = key();
        let record = DirectoryRecord {
            format: DIRECTORY_FORMAT.into(),
            active: active.clone(),
            previous: vec![],
        };
        assert!(validate_directory(&record, 21).is_err());
        let mut mismatched = active;
        mismatched.key_id = "sha256:wrong".into();
        assert!(
            validate_directory(
                &DirectoryRecord {
                    format: DIRECTORY_FORMAT.into(),
                    active: mismatched,
                    previous: vec![]
                },
                15
            )
            .is_err()
        );
    }
}
