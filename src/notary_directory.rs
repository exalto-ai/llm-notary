//! Versioned notary discovery and signing-key lifecycle.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

pub const DIRECTORY_FORMAT_V1: &str = "llm-notary/notary-directory/v1";
pub const DIRECTORY_FORMAT_V2: &str = "llm-notary/notary-directory/v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotaryKeyStatus {
    Active,
    Retiring,
    Retired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryDirectoryRecord {
    pub host: String,
    pub port: u16,
    pub key_id: String,
    pub public_key: String,
    pub status: NotaryKeyStatus,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryDirectory {
    pub format: String,
    pub active_key_id: String,
    pub notaries: Vec<NotaryDirectoryRecord>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyNotaryDirectory {
    pub format: String,
    pub host: String,
    pub port: u16,
    pub key_id: String,
    pub public_key: String,
}

impl NotaryDirectoryRecord {
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let public_key =
            hex::decode(&self.public_key).context("directory key is not hexadecimal")?;
        VerifyingKey::from_sec1_bytes(&public_key)
            .context("directory key is not a SEC1 secp256k1 key")?;
        if self.key_id != key_id(&public_key) {
            bail!("directory key ID does not match its public key");
        }
        Ok(public_key)
    }

    pub fn trusted_at(&self, unix_ms: u64) -> bool {
        self.status != NotaryKeyStatus::Revoked
            && unix_ms >= self.valid_from_unix_ms
            && self
                .valid_until_unix_ms
                .is_none_or(|until| unix_ms <= until)
    }

    pub fn accepts_finalization_at(&self, unix_ms: u64) -> bool {
        matches!(
            self.status,
            NotaryKeyStatus::Active | NotaryKeyStatus::Retiring
        ) && unix_ms >= self.valid_from_unix_ms
            && self
                .valid_until_unix_ms
                .is_none_or(|until| unix_ms <= until)
    }
}

impl NotaryDirectory {
    pub fn validate(&self) -> Result<()> {
        if self.format != DIRECTORY_FORMAT_V2 {
            bail!("unsupported notary directory format: {}", self.format);
        }
        if self.notaries.is_empty() || self.notaries.len() > 32 {
            bail!("notary directory must contain between 1 and 32 records");
        }
        let mut ids = BTreeSet::new();
        for record in &self.notaries {
            validate_record(record)?;
            if !ids.insert(record.key_id.as_str()) {
                bail!("notary directory contains a duplicate key ID");
            }
        }
        let active = self
            .notaries
            .iter()
            .find(|record| record.key_id == self.active_key_id)
            .ok_or_else(|| anyhow::anyhow!("active notary key is missing from the directory"))?;
        if active.status != NotaryKeyStatus::Active {
            bail!("the selected active notary key is not marked active");
        }
        Ok(())
    }

    pub fn active(&self) -> Result<&NotaryDirectoryRecord> {
        self.validate()?;
        Ok(self
            .notaries
            .iter()
            .find(|record| record.key_id == self.active_key_id)
            .expect("validated directory has its active key"))
    }

    pub fn active_at(&self, unix_ms: u64) -> Result<&NotaryDirectoryRecord> {
        let active = self.active()?;
        if !active.accepts_finalization_at(unix_ms) {
            bail!("the active notary key is outside its validity window");
        }
        Ok(active)
    }

    pub fn from_legacy(legacy: LegacyNotaryDirectory) -> Result<Self> {
        if legacy.format != DIRECTORY_FORMAT_V1 {
            bail!("unsupported notary directory format: {}", legacy.format);
        }
        let directory = Self {
            format: DIRECTORY_FORMAT_V2.to_owned(),
            active_key_id: legacy.key_id.clone(),
            notaries: vec![NotaryDirectoryRecord {
                host: legacy.host,
                port: legacy.port,
                key_id: legacy.key_id,
                public_key: legacy.public_key,
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: 0,
                valid_until_unix_ms: None,
            }],
        };
        directory.validate()?;
        Ok(directory)
    }
}

pub fn parse_directory(bytes: &[u8]) -> Result<NotaryDirectory> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("decoding notary directory")?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(DIRECTORY_FORMAT_V2) => {
            let directory: NotaryDirectory =
                serde_json::from_value(value).context("decoding v2 notary directory")?;
            directory.validate()?;
            Ok(directory)
        }
        Some(DIRECTORY_FORMAT_V1) => NotaryDirectory::from_legacy(
            serde_json::from_value(value).context("decoding v1 notary directory")?,
        ),
        Some(format) => bail!("unsupported notary directory format: {format}"),
        None => bail!("notary directory format is missing"),
    }
}

pub fn key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key))
}

fn validate_record(record: &NotaryDirectoryRecord) -> Result<()> {
    if record.host.is_empty() || record.host.chars().any(char::is_whitespace) || record.port == 0 {
        bail!("directory key has an invalid endpoint");
    }
    if record
        .valid_until_unix_ms
        .is_some_and(|until| until < record.valid_from_unix_ms)
    {
        bail!("directory key validity window is inverted");
    }
    record.public_key_bytes()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seed: u8, status: NotaryKeyStatus) -> NotaryDirectoryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        NotaryDirectoryRecord {
            host: format!("notary-{seed}.example"),
            port: 7047,
            key_id: key_id(&public),
            public_key: hex::encode(public),
            status,
            valid_from_unix_ms: 100,
            valid_until_unix_ms: None,
        }
    }

    #[test]
    fn validates_rotation_and_time_scoped_historical_trust() {
        let mut old = record(7, NotaryKeyStatus::Retired);
        old.valid_until_unix_ms = Some(199);
        let active = record(8, NotaryKeyStatus::Active);
        let directory = NotaryDirectory {
            format: DIRECTORY_FORMAT_V2.into(),
            active_key_id: active.key_id.clone(),
            notaries: vec![old.clone(), active],
        };
        directory.validate().unwrap();
        assert!(directory.active_at(100).is_ok());
        assert!(directory.active_at(99).is_err());
        assert!(old.trusted_at(150));
        assert!(!old.trusted_at(200));
        assert!(!old.accepts_finalization_at(150));
    }

    #[test]
    fn rejects_revoked_or_missing_active_selection() {
        let revoked = record(7, NotaryKeyStatus::Revoked);
        let mut directory = NotaryDirectory {
            format: DIRECTORY_FORMAT_V2.into(),
            active_key_id: revoked.key_id.clone(),
            notaries: vec![revoked],
        };
        assert!(directory.validate().is_err());
        directory.active_key_id = "sha256:missing".into();
        assert!(directory.validate().is_err());
    }

    #[test]
    fn migrates_the_single_key_v1_document() {
        let active = record(9, NotaryKeyStatus::Active);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "format": DIRECTORY_FORMAT_V1,
            "host": active.host,
            "port": active.port,
            "key_id": active.key_id,
            "public_key": active.public_key,
        }))
        .unwrap();
        let migrated = parse_directory(&bytes).unwrap();
        assert_eq!(migrated.format, DIRECTORY_FORMAT_V2);
        assert_eq!(migrated.notaries.len(), 1);
    }
}
