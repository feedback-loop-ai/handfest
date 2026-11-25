//! Portable pre-open read-only file/header/sidecar checks and in-process writer tracking.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::LedgerError;

const SQLITE_HEADER_LEN: usize = 100;
const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const ROLLBACK_JOURNAL_HDR_LEN: usize = 28;
const HOT_JOURNAL_RETRY_BUDGET: Duration = Duration::from_millis(500);
const HOT_JOURNAL_INITIAL_BACKOFF: Duration = Duration::from_millis(2);
const HOT_JOURNAL_MAX_BACKOFF: Duration = Duration::from_millis(25);

static OPEN_WRITER_PATHS: OnceLock<Mutex<BTreeMap<PathBuf, usize>>> = OnceLock::new();

fn open_writer_paths() -> &'static Mutex<BTreeMap<PathBuf, usize>> {
    OPEN_WRITER_PATHS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// RAII registration of an open writable [`crate::SqliteLedger`] canonical path in this process.
///
/// While at least one writable `SqliteLedger` is open for a canonical path, we already verified
/// that the file is a rollback-journal (`DELETE`) SQLite ledger, so `open_read_only` skips raw
/// `std::fs::File::open` on the main DB inode and avoids POSIX `close()` releasing this process's
/// `fcntl` locks.
pub(crate) struct ActiveWriterGuard(PathBuf);

impl ActiveWriterGuard {
    pub(crate) fn acquire(canonical: PathBuf) -> Self {
        let mut map = open_writer_paths()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *map.entry(canonical.clone()).or_insert(0) += 1;
        Self(canonical)
    }
}

impl Drop for ActiveWriterGuard {
    fn drop(&mut self) {
        let mut map = open_writer_paths()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.0);
            }
        }
    }
}

pub(crate) fn has_active_in_process_writer(canonical: &Path) -> bool {
    let map = open_writer_paths()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    map.get(canonical).copied().unwrap_or(0) > 0
}

pub(crate) fn validate_read_only_files(canonical: &Path) -> Result<(), LedgerError> {
    let meta = fs::metadata(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to stat read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(LedgerError::Integrity(format!(
            "read-only ledger '{}' is not a regular file",
            canonical.display()
        )));
    }
    if meta.len() < SQLITE_HEADER_LEN as u64 {
        return Err(LedgerError::Integrity(format!(
            "read-only ledger '{}' is truncated ({} bytes; minimum {SQLITE_HEADER_LEN})",
            canonical.display(),
            meta.len()
        )));
    }

    check_wal_sidecar(&append_suffix(canonical, "-wal"))?;
    check_rollback_journal_sidecar(&append_suffix(canonical, "-journal"))?;

    if !has_active_in_process_writer(canonical) {
        inspect_sqlite_header(canonical)?;
    }
    Ok(())
}

fn inspect_sqlite_header(canonical: &Path) -> Result<(), LedgerError> {
    let mut file = File::open(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to open read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    let mut header = [0u8; SQLITE_HEADER_LEN];
    file.read_exact(&mut header).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to read 100-byte SQLite header of '{}': {err}",
            canonical.display()
        ))
    })?;
    if &header[..SQLITE_HEADER_MAGIC.len()] != SQLITE_HEADER_MAGIC {
        return Err(LedgerError::Integrity(format!(
            "read-only ledger '{}' does not start with SQLite header magic",
            canonical.display()
        )));
    }
    if header[18] == 2 || header[19] == 2 {
        return Err(LedgerError::Integrity(format!(
            "read-only ledger '{}' uses WAL format header (versions {}/{}); rollback-journal mode required",
            canonical.display(),
            header[18],
            header[19]
        )));
    }
    Ok(())
}

fn check_wal_sidecar(wal_path: &Path) -> Result<(), LedgerError> {
    let meta = match fs::metadata(wal_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot inspect WAL sidecar '{}': {err}",
                wal_path.display()
            )));
        }
    };
    if !meta.is_file() || meta.len() > 0 {
        return Err(LedgerError::Integrity(format!(
            "non-empty or invalid WAL sidecar '{}' requires recovery before read-only audit",
            wal_path.display()
        )));
    }
    Ok(())
}

enum JournalProbe {
    Clean,
    Hot,
}

fn check_rollback_journal_sidecar(journal_path: &Path) -> Result<(), LedgerError> {
    check_rollback_journal_sidecar_with_budget(journal_path, HOT_JOURNAL_RETRY_BUDGET)
}

fn check_rollback_journal_sidecar_with_budget(
    journal_path: &Path,
    budget: Duration,
) -> Result<(), LedgerError> {
    let deadline = Instant::now() + budget;
    let mut backoff = HOT_JOURNAL_INITIAL_BACKOFF;
    loop {
        match probe_rollback_journal_once(journal_path)? {
            JournalProbe::Clean => return Ok(()),
            JournalProbe::Hot => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(LedgerError::Integrity(format!(
                        "hot rollback journal '{}' requires recovery before read-only audit",
                        journal_path.display()
                    )));
                }
                let remaining = deadline.saturating_duration_since(now);
                std::thread::sleep(backoff.min(remaining));
                backoff = (backoff * 2).min(HOT_JOURNAL_MAX_BACKOFF);
            }
        }
    }
}

fn probe_rollback_journal_once(journal_path: &Path) -> Result<JournalProbe, LedgerError> {
    let meta = match fs::metadata(journal_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(JournalProbe::Clean),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot inspect rollback journal '{}': {err}",
                journal_path.display()
            )));
        }
    };
    if !meta.is_file() {
        return Err(LedgerError::Integrity(format!(
            "invalid non-file rollback journal '{}'",
            journal_path.display()
        )));
    }
    if meta.len() == 0 {
        return Ok(JournalProbe::Clean);
    }
    let mut file = match File::open(journal_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(JournalProbe::Clean),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot read non-empty rollback journal '{}': {err}",
                journal_path.display()
            )));
        }
    };
    let mut hdr = [0u8; ROLLBACK_JOURNAL_HDR_LEN];
    if file.read_exact(&mut hdr).is_err() || hdr.iter().any(|&b| b != 0) {
        return Ok(JournalProbe::Hot);
    }
    Ok(JournalProbe::Clean)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn read_only_header_and_sidecar_helpers_fail_closed_on_invalid_inputs() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.sqlite");
        assert!(matches!(
            validate_read_only_files(&missing),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            inspect_sqlite_header(&missing),
            Err(LedgerError::Integrity(_))
        ));

        let short = dir.path().join("short.sqlite");
        fs::write(&short, b"short").unwrap();
        assert!(matches!(
            inspect_sqlite_header(&short),
            Err(LedgerError::Integrity(_))
        ));

        let bad_magic = dir.path().join("bad_magic.sqlite");
        fs::write(&bad_magic, [0u8; 128]).unwrap();
        assert!(matches!(
            inspect_sqlite_header(&bad_magic),
            Err(LedgerError::Integrity(_))
        ));

        let dir_sidecar = dir.path().join("dir-journal");
        fs::create_dir(&dir_sidecar).unwrap();
        assert!(matches!(
            check_wal_sidecar(&dir_sidecar),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            check_rollback_journal_sidecar(&dir_sidecar),
            Err(LedgerError::Integrity(_))
        ));

        let empty_journal = dir.path().join("empty-journal");
        fs::write(&empty_journal, b"").unwrap();
        check_rollback_journal_sidecar(&empty_journal).unwrap();

        let short_journal = dir.path().join("short-journal");
        fs::write(&short_journal, [0u8; 10]).unwrap();
        assert!(matches!(
            check_rollback_journal_sidecar_with_budget(&short_journal, Duration::ZERO),
            Err(LedgerError::Integrity(_))
        ));

        // Non-NotFound metadata error (regular file as parent directory -> ENOTDIR).
        let impossible = short_journal.join("child");
        assert!(matches!(
            check_wal_sidecar(&impossible),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            check_rollback_journal_sidecar(&impossible),
            Err(LedgerError::Integrity(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = dir.path().join("unreadable-journal");
            fs::write(&unreadable, [0u8; 32]).unwrap();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
            let res = check_rollback_journal_sidecar(&unreadable);
            let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
            assert!(matches!(res, Err(LedgerError::Integrity(_))));
        }
    }

    #[test]
    fn active_writer_guard_refcounts_and_clears_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("guard.sqlite");
        assert!(!has_active_in_process_writer(&path));

        let g1 = ActiveWriterGuard::acquire(path.clone());
        assert!(has_active_in_process_writer(&path));
        let g2 = ActiveWriterGuard::acquire(path.clone());
        assert!(has_active_in_process_writer(&path));

        drop(g1);
        assert!(has_active_in_process_writer(&path));
        drop(g2);
        assert!(!has_active_in_process_writer(&path));
    }

    #[test]
    fn transient_rollback_journal_retry_succeeds_when_journal_clears_and_fails_when_stuck() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("transient.sqlite-journal");
        fs::write(
            &journal,
            b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7hot-commit-payload",
        )
        .unwrap();

        let journal_bg = journal.clone();
        let clearer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            fs::remove_file(&journal_bg).unwrap();
        });
        check_rollback_journal_sidecar_with_budget(&journal, Duration::from_millis(500)).unwrap();
        clearer.join().unwrap();

        let stuck = dir.path().join("stuck.sqlite-journal");
        fs::write(
            &stuck,
            b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7crashed-hot-journal",
        )
        .unwrap();
        assert!(matches!(
            check_rollback_journal_sidecar_with_budget(&stuck, Duration::from_millis(15)),
            Err(LedgerError::Integrity(_))
        ));
    }
}
