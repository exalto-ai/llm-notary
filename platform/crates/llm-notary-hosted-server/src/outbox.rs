use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use notary_core::NotarySessionMode;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(super) struct UsageOutbox {
    pub(super) directory: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
    next_temp_id: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UsageMode {
    Capture,
    Finalize,
}

impl UsageMode {
    pub(super) fn for_session(mode: NotarySessionMode) -> Self {
        match mode {
            NotarySessionMode::Capture => Self::Capture,
            NotarySessionMode::Notarization => Self::Finalize,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UsageSettlementOutcome {
    Completed,
    ClientFailed,
    ServiceFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct PendingUsageSettlement {
    pub(super) operation_id: String,
    pub(super) notary_instance_id: String,
    pub(super) mode: UsageMode,
    pub(super) authenticated_bytes: i64,
    pub(super) outcome: Option<UsageSettlementOutcome>,
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

impl UsageOutbox {
    pub(super) fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() {
            bail!("usage settlement outbox directory must not be empty");
        }
        fs::create_dir_all(&directory)
            .with_context(|| format!("creating usage settlement outbox {}", directory.display()))?;
        let outbox = Self {
            directory: Arc::new(directory),
            write_lock: Arc::new(Mutex::new(())),
            next_temp_id: Arc::new(AtomicU64::new(0)),
        };
        outbox.cleanup_temporary_files()?;
        Ok(outbox)
    }

    pub(super) fn recover_after_restart(&self) -> Result<()> {
        for mut pending in self.entries()? {
            if pending.outcome.is_none() {
                pending.outcome = Some(UsageSettlementOutcome::ServiceFailed);
                self.write(&pending)?;
            }
        }
        Ok(())
    }

    pub(super) fn stage(&self, pending: &PendingUsageSettlement) -> Result<()> {
        validate_usage_entry(pending)?;
        if pending.authenticated_bytes != 0 || pending.outcome.is_some() {
            bail!("new usage outbox entry must be staged and unmeasured");
        }
        let path = self.path(&pending.operation_id)?;
        if path.exists() {
            let existing = self.read(&path)?;
            if existing == *pending {
                return Ok(());
            }
            bail!("usage outbox operation already exists with different data");
        }
        self.write(pending)
    }

    pub(super) fn record_authenticated_bytes(
        &self,
        operation_id: &str,
        bytes: usize,
    ) -> Result<()> {
        let path = self.path(operation_id)?;
        let mut pending = self.read(&path)?;
        let bytes = i64::try_from(bytes).context("authenticated usage does not fit in i64")?;
        if pending.outcome.is_some() {
            if pending.authenticated_bytes == bytes {
                return Ok(());
            }
            bail!("terminal usage outbox entry has different measured bytes");
        }
        if pending.authenticated_bytes != 0 && pending.authenticated_bytes != bytes {
            bail!("usage outbox entry has conflicting measured bytes");
        }
        pending.authenticated_bytes = bytes;
        self.write(&pending)
    }

    pub(super) fn finish(
        &self,
        operation_id: &str,
        outcome: UsageSettlementOutcome,
        fallback_bytes: usize,
    ) -> Result<()> {
        let path = self.path(operation_id)?;
        let mut pending = self.read(&path)?;
        let fallback_bytes =
            i64::try_from(fallback_bytes).context("authenticated usage does not fit in i64")?;
        if pending.authenticated_bytes == 0 {
            pending.authenticated_bytes = fallback_bytes;
        } else if fallback_bytes != 0 && pending.authenticated_bytes != fallback_bytes {
            bail!("terminal usage conflicts with its staged measurement");
        }
        if let Some(previous) = pending.outcome {
            if previous == outcome {
                return Ok(());
            }
            bail!("usage outbox entry already has a different terminal outcome");
        }
        pending.outcome = Some(outcome);
        self.write(&pending)
    }

    pub(super) fn ready(&self) -> Result<Vec<PendingUsageSettlement>> {
        Ok(self
            .entries()?
            .into_iter()
            .filter(|pending| pending.outcome.is_some())
            .collect())
    }

    pub(super) fn entries(&self) -> Result<Vec<PendingUsageSettlement>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(self.directory.as_ref()).with_context(|| {
            format!(
                "reading usage settlement outbox {}",
                self.directory.display()
            )
        })? {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
                entries.push(self.read(&path)?);
            }
        }
        Ok(entries)
    }

    pub(super) fn read(&self, path: &Path) -> Result<PendingUsageSettlement> {
        let pending: PendingUsageSettlement = serde_json::from_slice(
            &fs::read(path)
                .with_context(|| format!("reading usage outbox entry {}", path.display()))?,
        )
        .with_context(|| format!("parsing usage outbox entry {}", path.display()))?;
        validate_usage_entry(&pending)?;
        if self.path(&pending.operation_id)? != path {
            bail!("usage outbox filename does not match its operation");
        }
        Ok(pending)
    }

    pub(super) fn write(&self, pending: &PendingUsageSettlement) -> Result<()> {
        validate_usage_entry(pending)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("usage outbox write lock was poisoned"))?;
        let destination = self.path(&pending.operation_id)?;
        let temporary = self.directory.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            self.next_temp_id.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = serde_json::to_vec(pending).context("serializing usage outbox entry")?;
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .with_context(|| format!("creating usage outbox entry {}", temporary.display()))?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            sync_directory(self.directory.as_ref())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(super) fn remove(&self, operation_id: &str) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("usage outbox write lock was poisoned"))?;
        let path = self.path(operation_id)?;
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(self.directory.as_ref()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn path(&self, operation_id: &str) -> Result<PathBuf> {
        validate_usage_identifier(operation_id)?;
        Ok(self.directory.join(format!("{operation_id}.json")))
    }

    pub(super) fn cleanup_temporary_files(&self) -> Result<()> {
        for entry in fs::read_dir(self.directory.as_ref())? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp-"))
            {
                fs::remove_file(path)?;
            }
        }
        sync_directory(self.directory.as_ref())
    }
}

fn validate_usage_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("usage outbox contains an invalid identifier");
    }
    Ok(())
}

fn validate_usage_entry(pending: &PendingUsageSettlement) -> Result<()> {
    validate_usage_identifier(&pending.operation_id)?;
    validate_usage_identifier(&pending.notary_instance_id)?;
    if pending.authenticated_bytes < 0 {
        bail!("usage outbox contains negative authenticated bytes");
    }
    Ok(())
}
