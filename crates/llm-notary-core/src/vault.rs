//! Local encryption-key management for private LLM Notary bundles.

use std::{
    env, fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const CONFIG_FORMAT: &str = "llm-notary/vault/v1";
const BUNDLE_MAGIC: &[u8] = b"LLMNB1";
const SERVICE: &str = "LLM Notary";
const PASSPHRASE_FILE_ENV: &str = "LLM_NOTARY_VAULT_PASSPHRASE_FILE";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultConfig {
    format: String,
    mode: VaultMode,
    salt_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VaultMode {
    Os,
    Passphrase,
}

/// Local bundle-encryption key material.
pub struct Vault {
    key: [u8; 32],
    config_path: PathBuf,
}

impl Vault {
    /// Opens a vault, prompting for a passphrase only when that mode was
    /// explicitly configured.
    pub fn open_interactive() -> Result<Self> {
        let config = read_config(&config_path()?)?;
        match config.mode {
            VaultMode::Os => Self::open(None),
            VaultMode::Passphrase => {
                let passphrase = match passphrase_from_file_env()? {
                    Some(passphrase) => passphrase,
                    None => rpassword::prompt_password("LLM Notary vault passphrase: ")?,
                };
                Self::open(Some(&passphrase))
            }
        }
    }

    /// Opens an existing vault or creates an OS-vault-backed one.
    pub fn open_or_init_interactive() -> Result<Self> {
        if config_path()?.exists() {
            Self::open_interactive()
        } else if let Some(passphrase) = passphrase_from_file_env()? {
            Self::init_passphrase(&passphrase)
        } else {
            Self::init_os()
        }
    }

    /// Opens an initialized vault. Passphrase vaults require the passphrase.
    pub fn open(passphrase: Option<&str>) -> Result<Self> {
        let config_path = config_path()?;
        let config = read_config(&config_path)?;
        let key = match config.mode {
            VaultMode::Os => read_os_key()?,
            VaultMode::Passphrase => derive_passphrase_key(
                passphrase.ok_or_else(|| anyhow::anyhow!("this vault requires a passphrase"))?,
                &config
                    .salt_hex
                    .ok_or_else(|| anyhow::anyhow!("passphrase vault is missing a salt"))?,
            )?,
        };
        Ok(Self { key, config_path })
    }

    /// Initializes an OS-vault-backed key. Existing vaults are left alone.
    pub fn init_os() -> Result<Self> {
        let config_path = config_path()?;
        if config_path.exists() {
            return Self::open(None);
        }
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        write_os_key(&key)?;
        write_config(
            &config_path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Os,
                salt_hex: None,
            },
        )?;
        Ok(Self { key, config_path })
    }

    /// Initializes a passphrase-backed vault. An empty passphrase is allowed
    /// intentionally, but does not protect bundle confidentiality.
    pub fn init_passphrase(passphrase: &str) -> Result<Self> {
        let config_path = config_path()?;
        if config_path.exists() {
            bail!(
                "a vault is already initialized at {}",
                config_path.display()
            );
        }
        let mut salt = [0; 16];
        rand::rng().fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt);
        let key = derive_passphrase_key(passphrase, &salt_hex)?;
        write_config(
            &config_path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Passphrase,
                salt_hex: Some(salt_hex),
            },
        )?;
        Ok(Self { key, config_path })
    }

    /// Encrypts a complete local bundle before it is written to disk.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("encrypting bundle failed"))?;
        let mut output = BUNDLE_MAGIC.to_vec();
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypts bytes written by [`encrypt`](Self::encrypt).
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if !encrypted.starts_with(BUNDLE_MAGIC) || encrypted.len() < BUNDLE_MAGIC.len() + 24 {
            bail!("bundle is not encrypted with an LLM Notary vault");
        }
        let (nonce, ciphertext) = encrypted[BUNDLE_MAGIC.len()..].split_at(24);
        XChaCha20Poly1305::new((&self.key).into())
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("could not decrypt bundle with this local vault"))
    }

    /// Returns where the local vault configuration is stored.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Returns the configured local vault mode without exposing key material.
    pub fn status() -> Result<&'static str> {
        match read_config(&config_path()?)?.mode {
            VaultMode::Os => Ok("OS vault"),
            VaultMode::Passphrase => Ok("passphrase vault"),
        }
    }
}

/// Reads an automation passphrase from the configured private file, if any.
///
/// This is deliberately file-based rather than an environment variable so a
/// CI runner does not expose the vault key in process listings or command
/// output.  Interactive commands retain their prompt when it is unset.
/// Returns an automation passphrase from the configured private file, if any.
pub fn passphrase_from_file_env() -> Result<Option<String>> {
    let Some(path) = env::var_os(PASSPHRASE_FILE_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    read_passphrase_file(&path).map(Some)
}

fn read_passphrase_file(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading vault passphrase file {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "vault passphrase path {} is not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "vault passphrase file {} must not be readable by group or others",
                path.display()
            );
        }
    }
    let value = String::from_utf8(
        fs::read(path)
            .with_context(|| format!("reading vault passphrase file {}", path.display()))?,
    )
    .context("vault passphrase file is not UTF-8")?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.contains('\0') {
        bail!("vault passphrase file contains a NUL byte");
    }
    Ok(value)
}

fn config_path() -> Result<PathBuf> {
    if let Some(directory) = env::var_os("LLM_NOTARY_CONFIG_DIR") {
        return Ok(PathBuf::from(directory).join("vault.json"));
    }
    let dirs = ProjectDirs::from("ai", "Exalto", "LLM Notary")
        .ok_or_else(|| anyhow::anyhow!("could not locate a platform configuration directory"))?;
    Ok(dirs.config_dir().join("vault.json"))
}

fn read_config(path: &Path) -> Result<VaultConfig> {
    let config: VaultConfig = serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("reading vault configuration {}", path.display()))?,
    )?;
    if config.format != CONFIG_FORMAT {
        bail!("unsupported vault configuration format");
    }
    Ok(config)
}

fn write_config(path: &Path, config: VaultConfig) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vault config path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating vault configuration {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(&config)?)
        .with_context(|| format!("writing vault configuration {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing vault configuration {}", path.display()))?;
    Ok(())
}

fn read_os_key() -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(SERVICE, "bundle-key")?;
    let bytes = hex::decode(
        entry
            .get_password()
            .context("reading LLM Notary key from the OS vault")?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("OS vault returned an invalid LLM Notary key"))
}

fn write_os_key(key: &[u8; 32]) -> Result<()> {
    keyring::Entry::new(SERVICE, "bundle-key")?
        .set_password(&hex::encode(key))
        .context("storing the LLM Notary key in the OS vault")
}

fn derive_passphrase_key(passphrase: &str, salt_hex: &str) -> Result<[u8; 32]> {
    let salt = hex::decode(salt_hex)?;
    let mut key = [0; 32];
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid vault KDF parameters: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow::anyhow!("deriving vault key failed: {e}"))?;
    Ok(key)
}

#[cfg(any(test, feature = "test-utils"))]
impl Vault {
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self {
            key: [7; 32],
            config_path: PathBuf::from("test-vault"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn automation_passphrase_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"test passphrase\n").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_passphrase_file(file.path()).unwrap(),
            "test passphrase"
        );

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_passphrase_file(file.path()).is_err());
    }

    #[test]
    fn ciphertext_requires_the_same_vault_key() {
        let vault = Vault::test_only();
        let encrypted = vault.encrypt(b"private bundle").unwrap();
        assert_ne!(encrypted, b"private bundle");
        assert_eq!(vault.decrypt(&encrypted).unwrap(), b"private bundle");

        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vault.decrypt(&tampered).is_err());

        let other = Vault {
            key: [8; 32],
            config_path: PathBuf::from("other-test-vault"),
        };
        assert!(other.decrypt(&encrypted).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn vault_config_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "llm-notary-vault-permissions-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join("vault.json");
        write_config(
            &path,
            VaultConfig {
                format: CONFIG_FORMAT.to_owned(),
                mode: VaultMode::Passphrase,
                salt_hex: Some("00".repeat(16)),
            },
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            write_config(
                &path,
                VaultConfig {
                    format: CONFIG_FORMAT.to_owned(),
                    mode: VaultMode::Os,
                    salt_hex: None,
                },
            )
            .is_err(),
            "vault creation must not overwrite an existing config"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
