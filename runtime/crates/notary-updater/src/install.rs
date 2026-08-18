//! Rollback-safe installation transaction for the notaryctl/notaryd pair.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(not(any(unix, windows)))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[cfg(windows)]
use crate::platform::ensure_windows_daemon_stopped;
use crate::{
    BUILD_ID, InstallOutcome,
    channel::{VerifiedRelease, check_latest},
    is_official_build,
    platform::{cli_file_name, daemon_file_name, make_executable, replace_file, sync_directory},
    release::{download_artifact, platform_name, update_http_client, validate_identifier},
    storage,
};
const JOURNAL_NAME: &str = ".notary-runtime-update.json";

const CLI_BACKUP_NAME: &str = ".notaryctl.update-backup";

const DAEMON_BACKUP_NAME: &str = ".notaryd.update-backup";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateJournal {
    schema_version: String,
    build_id: String,
    phase: JournalPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    ReplacingNotaryd,
    NotarydReplaced,
    ReplacingNotaryctl,
    NotaryctlReplaced,
}

#[derive(Debug)]
pub(crate) struct InstallPaths {
    pub(crate) directory: PathBuf,
    pub(crate) cli: PathBuf,
    pub(crate) daemon: PathBuf,
    pub(crate) journal: PathBuf,
    pub(crate) cli_backup: PathBuf,
    pub(crate) daemon_backup: PathBuf,
}

impl InstallPaths {
    pub(crate) fn discover() -> Result<Self> {
        let cli = std::env::current_exe().context("locating the running notaryctl executable")?;
        let directory = cli
            .parent()
            .context("the running executable has no parent directory")?
            .to_owned();
        ensure!(
            cli.file_name().and_then(|name| name.to_str()) == Some(cli_file_name()),
            "automatic updates require an executable named {}",
            cli_file_name()
        );
        let display = cli.to_string_lossy().to_ascii_lowercase();
        ensure!(
            !display.contains(".app/contents/macos/"),
            "the desktop app must update its bundled service as part of the whole app"
        );
        ensure!(
            !display.contains("/cellar/")
                && !display.contains("/nix/store/")
                && !display.starts_with("/usr/bin/")
                && !display.contains("/opt/local/"),
            "this installation is managed by a package manager; update it with that package manager"
        );
        let daemon = directory.join(daemon_file_name());
        for path in [&cli, &daemon] {
            let metadata = fs::symlink_metadata(path)
                .with_context(|| format!("inspecting {}", path.display()))?;
            ensure!(
                metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
                "{} is not a regular installed file",
                path.display()
            );
        }
        Ok(Self {
            journal: directory.join(JOURNAL_NAME),
            cli_backup: directory.join(CLI_BACKUP_NAME),
            daemon_backup: directory.join(DAEMON_BACKUP_NAME),
            directory,
            cli,
            daemon,
        })
    }

    #[cfg(any(test, windows))]
    pub(crate) fn from_directory(directory: &Path) -> Self {
        Self {
            directory: directory.to_owned(),
            cli: directory.join(cli_file_name()),
            daemon: directory.join(daemon_file_name()),
            journal: directory.join(JOURNAL_NAME),
            cli_backup: directory.join(CLI_BACKUP_NAME),
            daemon_backup: directory.join(DAEMON_BACKUP_NAME),
        }
    }
}

pub async fn install_latest() -> Result<InstallOutcome> {
    ensure!(
        is_official_build(),
        "source and development builds cannot replace themselves; install an official build first"
    );
    let install = InstallPaths::discover()?;
    recover_interrupted_update(&install)?;
    ensure_current_pair(&install)?;
    let check = check_latest().await?;
    if !check.update_available {
        return Ok(InstallOutcome {
            state: "current".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: BUILD_ID.into(),
            updated_on_disk: false,
            daemon_restart_required: false,
        });
    }
    let release = check
        .release
        .context("the verified release is unavailable")?;
    install_verified_release(&install, &release).await
}

async fn install_verified_release(
    install: &InstallPaths,
    release: &VerifiedRelease,
) -> Result<InstallOutcome> {
    #[cfg(windows)]
    ensure_windows_daemon_stopped(install)?;
    let platform = platform_name()?;
    let artifacts = release
        .manifest
        .artifacts
        .get(platform)
        .with_context(|| format!("the release has no payloads for {platform}"))?;
    let staging = tempfile::Builder::new()
        .prefix(".notary-runtime-update-")
        .tempdir_in(&install.directory)
        .with_context(|| {
            format!(
                "creating an update staging directory in {}",
                install.directory.display()
            )
        })?;
    let cli_candidate = staging.path().join(cli_file_name());
    let daemon_candidate = staging.path().join(daemon_file_name());
    let client = update_http_client()?;
    download_artifact(&client, &artifacts.notaryctl, &cli_candidate).await?;
    download_artifact(&client, &artifacts.notaryd, &daemon_candidate).await?;
    make_executable(&cli_candidate)?;
    make_executable(&daemon_candidate)?;
    ensure_candidate_build(&cli_candidate, &release.manifest.build_id, "notaryctl")?;
    ensure_candidate_build(&daemon_candidate, &release.manifest.build_id, "notaryd")?;

    #[cfg(unix)]
    {
        apply_update_transaction(
            install,
            &cli_candidate,
            &daemon_candidate,
            &release.manifest.build_id,
        )?;
        Ok(InstallOutcome {
            state: "updated".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: release.manifest.build_id.clone(),
            updated_on_disk: true,
            daemon_restart_required: true,
        })
    }
    #[cfg(windows)]
    {
        let staging = staging.keep();
        let helper = staging.join("notaryctl-update-helper.exe");
        fs::copy(&cli_candidate, &helper).context("creating the Windows update helper")?;
        let mut command = Command::new(&helper);
        command
            .arg("__apply-update")
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .arg("--install-directory")
            .arg(&install.directory)
            .arg("--staging-directory")
            .arg(&staging)
            .arg("--build-id")
            .arg(&release.manifest.build_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x08000000);
        command
            .spawn()
            .context("starting the Windows update helper")?;
        Ok(InstallOutcome {
            state: "staged".into(),
            previous_build_id: BUILD_ID.into(),
            new_build_id: release.manifest.build_id.clone(),
            updated_on_disk: false,
            daemon_restart_required: true,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("automatic installation is not implemented on this operating system")
    }
}

fn ensure_current_pair(install: &InstallPaths) -> Result<()> {
    ensure_candidate_build(&install.cli, BUILD_ID, "notaryctl")?;
    ensure_candidate_build(&install.daemon, BUILD_ID, "notaryd")
}

pub(crate) fn ensure_candidate_build(path: &Path, build_id: &str, program: &str) -> Result<()> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running staged {program}"))?;
    ensure!(
        output.status.success(),
        "the staged {program} did not report its version"
    );
    let stdout =
        String::from_utf8(output.stdout).context("the staged program version is not UTF-8")?;
    ensure!(
        stdout.contains(&format!("({build_id})")),
        "the staged {program} build ID does not match the signed release"
    );
    Ok(())
}

pub(crate) fn apply_update_transaction(
    install: &InstallPaths,
    cli_candidate: &Path,
    daemon_candidate: &Path,
    build_id: &str,
) -> Result<()> {
    ensure!(
        path_is_absent(&install.cli_backup)?
            && path_is_absent(&install.daemon_backup)?
            && path_is_absent(&install.journal)?,
        "a previous update has not been recovered"
    );
    write_journal(install, build_id, JournalPhase::Prepared)?;
    hard_link_backup(&install.daemon, &install.daemon_backup)?;
    write_journal(install, build_id, JournalPhase::ReplacingNotaryd)?;
    if let Err(error) = replace_file(daemon_candidate, &install.daemon) {
        let _ = recover_interrupted_update(install);
        return Err(error).context("installing the new notaryd");
    }
    sync_directory(&install.directory)?;
    write_journal(install, build_id, JournalPhase::NotarydReplaced)?;
    hard_link_backup(&install.cli, &install.cli_backup)?;
    write_journal(install, build_id, JournalPhase::ReplacingNotaryctl)?;
    if let Err(error) = replace_file(cli_candidate, &install.cli) {
        let _ = recover_interrupted_update(install);
        return Err(error).context("installing the new notaryctl");
    }
    sync_directory(&install.directory)?;
    write_journal(install, build_id, JournalPhase::NotaryctlReplaced)?;
    if let Err(error) = ensure_candidate_build(&install.cli, build_id, "notaryctl")
        .and_then(|_| ensure_candidate_build(&install.daemon, build_id, "notaryd"))
    {
        let rollback = rollback_to_backups(install);
        return match rollback {
            Ok(()) => Err(error).context("validating the installed update; restored the old pair"),
            Err(rollback_error) => Err(error).context(format!(
                "validating the installed update; rollback also failed: {rollback_error:#}"
            )),
        };
    }
    finish_transaction(install)
}

fn hard_link_backup(source: &Path, backup: &Path) -> Result<()> {
    ensure!(
        path_is_absent(backup)?,
        "the rollback path {} already exists",
        backup.display()
    );
    if let Err(link_error) = fs::hard_link(source, backup) {
        let mut input = fs::File::open(source)
            .with_context(|| format!("opening installed file {}", source.display()))?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o700);
        }
        let mut output = options.open(backup).with_context(|| {
            format!(
                "creating rollback copy {} after hard-link failure: {link_error}",
                backup.display()
            )
        })?;
        std::io::copy(&mut input, &mut output)
            .with_context(|| format!("writing rollback copy {}", backup.display()))?;
        output
            .sync_all()
            .with_context(|| format!("syncing rollback copy {}", backup.display()))?;
    }
    sync_directory(
        source
            .parent()
            .context("installed file has no parent directory")?,
    )
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn rollback_to_backups(install: &InstallPaths) -> Result<()> {
    restore_backup(&install.cli_backup, &install.cli)?;
    restore_backup(&install.daemon_backup, &install.daemon)?;
    remove_if_exists(&install.cli_backup)?;
    remove_if_exists(&install.daemon_backup)?;
    remove_if_exists(&install.journal)?;
    sync_directory(&install.directory)
}

fn write_journal(install: &InstallPaths, build_id: &str, phase: JournalPhase) -> Result<()> {
    let bytes = serde_json::to_vec(&UpdateJournal {
        schema_version: "notary/update-journal/v1".into(),
        build_id: build_id.into(),
        phase,
    })?;
    storage::write_private_file_atomically(&install.journal, &bytes)?;
    sync_directory(&install.directory)
}

pub(crate) fn recover_interrupted_update(install: &InstallPaths) -> Result<()> {
    if path_is_absent(&install.journal)? {
        ensure!(
            path_is_absent(&install.cli_backup)? && path_is_absent(&install.daemon_backup)?,
            "orphaned update rollback files require manual inspection"
        );
        return Ok(());
    }
    let journal: UpdateJournal =
        serde_json::from_slice(&fs::read(&install.journal).context("reading the update journal")?)
            .context("the update journal is malformed")?;
    ensure!(
        journal.schema_version == "notary/update-journal/v1",
        "the update journal schema is unsupported"
    );
    validate_identifier(&journal.build_id, "journal build ID")?;
    match journal.phase {
        JournalPhase::Prepared => {}
        JournalPhase::ReplacingNotaryd | JournalPhase::NotarydReplaced => {
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
        JournalPhase::ReplacingNotaryctl => {
            restore_backup(&install.cli_backup, &install.cli)?;
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
        JournalPhase::NotaryctlReplaced => {
            if ensure_candidate_build(&install.cli, &journal.build_id, "notaryctl").is_ok()
                && ensure_candidate_build(&install.daemon, &journal.build_id, "notaryd").is_ok()
            {
                return finish_transaction(install);
            }
            restore_backup(&install.cli_backup, &install.cli)?;
            restore_backup(&install.daemon_backup, &install.daemon)?;
        }
    }
    finish_transaction(install)
}

fn restore_backup(backup: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(backup)
        .with_context(|| format!("inspecting update rollback copy {}", backup.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "the update rollback copy {} is missing",
        backup.display()
    );
    if target.is_file() && files_match(backup, target)? {
        return remove_if_exists(backup);
    }
    replace_file(backup, target).with_context(|| format!("restoring {}", target.display()))
}

fn files_match(left: &Path, right: &Path) -> Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = fs::metadata(right)?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }
    Ok(file_sha256(left)? == file_sha256(right)?)
}

fn file_sha256(path: &Path) -> Result<[u8; 32]> {
    let mut input = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(hash.finalize().into())
}

fn finish_transaction(install: &InstallPaths) -> Result<()> {
    remove_if_exists(&install.cli_backup)?;
    remove_if_exists(&install.daemon_backup)?;
    remove_if_exists(&install.journal)?;
    sync_directory(&install.directory)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    fn executable(path: &Path, program: &str, build_id: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::write(
            path,
            format!("#!/bin/sh\necho '{program} 0.1.0 ({build_id})'\n"),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaces_both_programs_and_removes_the_journal() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "notaryctl", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        let cli_candidate = directory.path().join("new-cli");
        let daemon_candidate = directory.path().join("new-daemon");
        executable(&cli_candidate, "notaryctl", "new-build");
        executable(&daemon_candidate, "notaryd", "new-build");

        apply_update_transaction(&install, &cli_candidate, &daemon_candidate, "new-build").unwrap();

        ensure_candidate_build(&install.cli, "new-build", "notaryctl").unwrap();
        ensure_candidate_build(&install.daemon, "new-build", "notaryd").unwrap();
        assert!(!install.journal.exists());
        assert!(!install.cli_backup.exists());
        assert!(!install.daemon_backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn restores_the_old_pair_when_the_second_replace_fails() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "notaryctl", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        let missing_cli_candidate = directory.path().join("missing-cli");
        let daemon_candidate = directory.path().join("new-daemon");
        executable(&daemon_candidate, "notaryd", "new-build");

        assert!(
            apply_update_transaction(
                &install,
                &missing_cli_candidate,
                &daemon_candidate,
                "new-build",
            )
            .is_err()
        );

        ensure_candidate_build(&install.cli, "old-build", "notaryctl").unwrap();
        ensure_candidate_build(&install.daemon, "old-build", "notaryd").unwrap();
        assert!(!install.journal.exists());
        assert!(!install.cli_backup.exists());
        assert!(!install.daemon_backup.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovers_a_crash_between_pair_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "notaryctl", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        hard_link_backup(&install.cli, &install.cli_backup).unwrap();
        hard_link_backup(&install.daemon, &install.daemon_backup).unwrap();
        let new_cli = directory.path().join("new-cli");
        let new_daemon = directory.path().join("new-daemon");
        executable(&new_cli, "notaryctl", "new-build");
        executable(&new_daemon, "notaryd", "new-build");
        replace_file(&new_cli, &install.cli).unwrap();
        replace_file(&new_daemon, &install.daemon).unwrap();
        write_journal(&install, "new-build", JournalPhase::ReplacingNotaryctl).unwrap();

        recover_interrupted_update(&install).unwrap();

        ensure_candidate_build(&install.cli, "old-build", "notaryctl").unwrap();
        ensure_candidate_build(&install.daemon, "old-build", "notaryd").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recovery_finishes_a_fully_replaced_current_pair() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "notaryctl", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        hard_link_backup(&install.cli, &install.cli_backup).unwrap();
        hard_link_backup(&install.daemon, &install.daemon_backup).unwrap();
        let new_cli = directory.path().join("new-cli");
        let new_daemon = directory.path().join("new-daemon");
        executable(&new_cli, "notaryctl", "new-build");
        executable(&new_daemon, "notaryd", "new-build");
        replace_file(&new_cli, &install.cli).unwrap();
        replace_file(&new_daemon, &install.daemon).unwrap();
        write_journal(&install, "new-build", JournalPhase::NotaryctlReplaced).unwrap();

        recover_interrupted_update(&install).unwrap();

        ensure_candidate_build(&install.cli, "new-build", "notaryctl").unwrap();
        ensure_candidate_build(&install.daemon, "new-build", "notaryd").unwrap();
        assert!(path_is_absent(&install.journal).unwrap());
        assert!(path_is_absent(&install.cli_backup).unwrap());
        assert!(path_is_absent(&install.daemon_backup).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_rejects_a_retired_update_journal() {
        let directory = tempfile::tempdir().unwrap();
        let install = InstallPaths::from_directory(directory.path());
        executable(&install.cli, "notaryctl", "old-build");
        executable(&install.daemon, "notaryd", "old-build");
        fs::write(
            &install.journal,
            br#"{"schema_version":"llm-notary/update-journal/v1","build_id":"build","phase":"prepared"}"#,
        )
        .unwrap();

        let error = recover_interrupted_update(&install).unwrap_err();
        assert!(error.to_string().contains("journal schema is unsupported"));
    }

    #[cfg(unix)]
    #[test]
    fn journal_phases_use_the_canonical_runtime_names() {
        let phases = [
            JournalPhase::Prepared,
            JournalPhase::ReplacingNotaryd,
            JournalPhase::NotarydReplaced,
            JournalPhase::ReplacingNotaryctl,
            JournalPhase::NotaryctlReplaced,
        ]
        .map(|phase| serde_json::to_string(&phase).unwrap());
        assert_eq!(
            phases,
            [
                "\"prepared\"",
                "\"replacing_notaryd\"",
                "\"notaryd_replaced\"",
                "\"replacing_notaryctl\"",
                "\"notaryctl_replaced\"",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn backup_creation_never_follows_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let backup = directory.path().join("backup");
        let outside = directory.path().join("outside");
        fs::write(&source, b"installed").unwrap();
        symlink(&outside, &backup).unwrap();

        assert!(hard_link_backup(&source, &backup).is_err());
        assert!(!outside.exists());
        assert_eq!(fs::read(&source).unwrap(), b"installed");
    }
}
