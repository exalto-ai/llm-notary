use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

pub const DIRECTORY_FORMAT: &str = "llm-notary/notary-directory/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryRecord {
    pub format: String,
    pub host: String,
    pub port: u16,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Default, Serialize, Deserialize)]
struct TrustStore {
    format: String,
    record: Option<DirectoryRecord>,
}

pub fn key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key))
}

pub fn validate_directory(record: &DirectoryRecord) -> Result<()> {
    if record.format != DIRECTORY_FORMAT {
        bail!("unsupported notary directory format: {}", record.format);
    }
    validate_key(record)?;
    Ok(())
}

fn validate_key(key: &DirectoryRecord) -> Result<Vec<u8>> {
    if key.host.is_empty() || key.host.chars().any(char::is_whitespace) || key.port == 0 {
        bail!("directory key has an invalid endpoint");
    }
    let public_key = hex::decode(&key.public_key).context("directory key is not hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&public_key)
        .context("directory key is not a SEC1 secp256k1 key")?;
    if key.key_id != key_id(&public_key) {
        bail!("directory key ID does not match its public key");
    }
    Ok(public_key)
}

pub fn pin(record: DirectoryRecord) -> Result<()> {
    validate_directory(&record)?;
    let path = trust_store_path()?;
    let mut store = load_store(&path)?;
    store.format = DIRECTORY_FORMAT.to_owned();
    store.record = Some(record);
    write_store(&path, &store)
}

pub fn cached_key(public_key: &[u8]) -> Result<(String, String)> {
    let requested_id = key_id(public_key);
    let store = load_store(&trust_store_path()?)?;
    if store.format != DIRECTORY_FORMAT {
        bail!("unsupported local notary trust store format");
    }
    if let Some(record) = store.record {
        validate_directory(&record)?;
        if record
            .public_key
            .eq_ignore_ascii_case(&hex::encode(public_key))
        {
            return Ok((record.key_id, "directory".to_owned()));
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

    fn key() -> DirectoryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        DirectoryRecord {
            format: DIRECTORY_FORMAT.into(),
            host: "notary.example".into(),
            port: 7047,
            key_id: key_id(&public),
            public_key: hex::encode(public),
        }
    }

    #[test]
    fn rejects_mismatched_directory_key_ids() {
        let mut mismatched = key();
        mismatched.key_id = "sha256:wrong".into();
        assert!(validate_directory(&mismatched).is_err());
    }
}
