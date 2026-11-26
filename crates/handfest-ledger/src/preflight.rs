//! Portable pre-open read-only file/header/sidecar checks and inode-keyed in-process handle
//! tracking.

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

/// Process-local file identity for POSIX `fcntl` lock preservation.
///
/// On Unix, POSIX `fcntl` locks are associated with `(st_dev, st_ino)` across all pathnames and
/// hard links pointing to the same inode. On non-Unix platforms, falls back to the canonical path.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIdentity {
    dev: u64,
    ino: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIdentity {
    canonical: PathBuf,
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_metadata(_canonical: &Path, meta: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(canonical: &Path, _meta: &fs::Metadata) -> Self {
        Self {
            canonical: canonical.to_path_buf(),
        }
    }

    fn from_path(canonical: &Path) -> io::Result<Self> {
        let meta = fs::metadata(canonical)?;
        Ok(Self::from_metadata(canonical, &meta))
    }
}

static ACTIVE_HANDLES: OnceLock<Mutex<BTreeMap<FileIdentity, usize>>> = OnceLock::new();

fn active_handles() -> &'static Mutex<BTreeMap<FileIdentity, usize>> {
    ACTIVE_HANDLES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// RAII registration of any open file-backed [`crate::SqliteLedger`] handle (writable OR read-only)
/// in this process, keyed by [`FileIdentity`].
///
/// While at least one handle is open on a given inode in this process (`refcount > 0`),
/// `open_read_only_guarded` skips raw `std::fs::File::open` on the main DB inode so POSIX
/// `close()` never drops in-process `fcntl` SHARED/RESERVED/EXCLUSIVE locks across hard links or
/// concurrent readers.
pub(crate) struct ActiveHandleGuard(FileIdentity);

impl Drop for ActiveHandleGuard {
    fn drop(&mut self) {
        let mut map = active_handles()
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

#[cfg(test)]
pub(crate) fn active_handle_count(canonical: &Path) -> usize {
    let Ok(id) = FileIdentity::from_path(canonical) else {
        return 0;
    };
    let map = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    map.get(&id).copied().unwrap_or(0)
}

/// Opens a writable ledger connection while holding the process-local active-handle registry lock
/// so its [`ActiveHandleGuard`] is registered atomically before any concurrent `open_read_only`
/// call in this process can inspect the raw file header.
pub(crate) fn open_writable_guarded<T, F>(
    path: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce() -> Result<T, LedgerError>,
{
    let mut map = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let conn = open_conn()?;
    let canonical = fs::canonicalize(path).map_err(|err| {
        LedgerError::Storage(format!(
            "failed to canonicalize ledger path '{}': {err}",
            path.display()
        ))
    })?;
    let id = FileIdentity::from_path(&canonical).map_err(|err| {
        LedgerError::Storage(format!(
            "failed to stat ledger path '{}': {err}",
            canonical.display()
        ))
    })?;
    *map.entry(id.clone()).or_insert(0) += 1;
    Ok((conn, ActiveHandleGuard(id)))
}

/// Validates that an existing ledger path resolves to a regular SQLite rollback-journal file
/// (`>= 100` bytes with valid header magic) and opens a writable connection while holding the
/// process-local active-handle registry lock.
///
/// Never creates missing files; skips raw `File::open` header inspection when `refcount > 0` on
/// the same inode so POSIX `fcntl` locks held by active handles in this process are preserved.
pub(crate) fn open_existing_writable_guarded<T, F>(
    path: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce(&Path) -> Result<T, LedgerError>,
{
    let mut map = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let canonical = fs::canonicalize(path).map_err(|err| {
        LedgerError::Storage(format!(
            "existing ledger '{}' not found or inaccessible: {err}",
            path.display()
        ))
    })?;
    let meta = stat_existing_regular_file(&canonical, "existing ledger")?;
    let id = FileIdentity::from_metadata(&canonical, &meta);
    if map.get(&id).copied().unwrap_or(0) == 0 {
        inspect_sqlite_header(&canonical)?;
    }
    let conn = open_conn(&canonical)?;
    let post_id = match FileIdentity::from_path(&canonical) {
        Ok(post_id) => post_id,
        Err(err) => {
            drop(conn);
            return Err(LedgerError::Integrity(format!(
                "existing ledger '{}' disappeared or became inaccessible after open: {err}",
                canonical.display()
            )));
        }
    };
    if post_id != id {
        drop(conn);
        return Err(LedgerError::Integrity(format!(
            "existing ledger '{}' was replaced concurrently during open",
            canonical.display()
        )));
    }
    *map.entry(id.clone()).or_insert(0) += 1;
    Ok((conn, ActiveHandleGuard(id)))
}

/// Validates read-only sidecars and opens a read-only ledger connection while holding the
/// process-local active-handle registry lock across the `refcount == 0` check, header inspection,
/// SQLite open, and refcount increment.
///
/// Sidecar checks (`-wal` and `-journal`, including bounded hot-journal backoff) run outside the
/// registry mutex so waiting on an external writer never stalls unrelated handle opens or drops.
pub(crate) fn open_read_only_guarded<T, F>(
    canonical: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce(&Path) -> Result<T, LedgerError>,
{
    stat_existing_regular_file(canonical, "read-only ledger")?;
    check_wal_sidecar(&append_suffix(canonical, "-wal"))?;
    check_rollback_journal_sidecar(&append_suffix(canonical, "-journal"))?;

    let mut map = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let meta = stat_existing_regular_file(canonical, "read-only ledger")?;
    let id = FileIdentity::from_metadata(canonical, &meta);
    if map.get(&id).copied().unwrap_or(0) == 0 {
        inspect_sqlite_header(canonical)?;
    }
    let conn = open_conn(canonical)?;
    *map.entry(id.clone()).or_insert(0) += 1;
    Ok((conn, ActiveHandleGuard(id)))
}

fn stat_existing_regular_file(canonical: &Path, label: &str) -> Result<fs::Metadata, LedgerError> {
    let meta = fs::metadata(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to stat {label} '{}': {err}",
            canonical.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(LedgerError::Integrity(format!(
            "{label} '{}' is not a regular file",
            canonical.display()
        )));
    }
    if meta.len() < SQLITE_HEADER_LEN as u64 {
        return Err(LedgerError::Integrity(format!(
            "{label} '{}' is truncated ({} bytes; minimum {SQLITE_HEADER_LEN})",
            canonical.display(),
            meta.len()
        )));
    }
    Ok(meta)
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
            open_read_only_guarded(&missing, |_| Ok(())),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            open_read_only_guarded(dir.path(), |_| Ok(())),
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
    fn active_handle_guard_refcounts_by_inode_across_hard_links_and_clears_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("guard.sqlite");
        let mut fake_sqlite = [0u8; SQLITE_HEADER_LEN];
        fake_sqlite[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);
        fake_sqlite[18] = 1;
        fake_sqlite[19] = 1;
        fs::write(&path, fake_sqlite).unwrap();
        let canonical = fs::canonicalize(&path).unwrap();
        assert_eq!(active_handle_count(&canonical), 0);

        let ((), g1) = open_writable_guarded(&canonical, || Ok(())).unwrap();
        assert_eq!(active_handle_count(&canonical), 1);

        #[cfg(unix)]
        {
            let alias = dir.path().join("guard_hardlink.sqlite");
            fs::hard_link(&canonical, &alias).unwrap();
            let canonical_alias = fs::canonicalize(&alias).unwrap();
            assert_ne!(canonical, canonical_alias);
            assert_eq!(
                active_handle_count(&canonical_alias),
                1,
                "hard link must share the same inode entry in active-handle registry"
            );

            let ((), g2) = open_read_only_guarded(&canonical_alias, |_| Ok(())).unwrap();
            assert_eq!(active_handle_count(&canonical), 2);
            assert_eq!(active_handle_count(&canonical_alias), 2);
            drop(g1);
            assert_eq!(active_handle_count(&canonical), 1);
            drop(g2);
            assert_eq!(active_handle_count(&canonical), 0);
            assert_eq!(active_handle_count(&canonical_alias), 0);
        }

        #[cfg(not(unix))]
        {
            let ((), g2) = open_read_only_guarded(&canonical, |_| Ok(())).unwrap();
            assert_eq!(active_handle_count(&canonical), 2);
            drop(g1);
            assert_eq!(active_handle_count(&canonical), 1);
            drop(g2);
            assert_eq!(active_handle_count(&canonical), 0);
        }
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

    #[test]
    fn open_existing_writable_guarded_rejects_concurrent_replacement_and_unlink() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct DropTracker(Arc<AtomicBool>);
        impl Drop for DropTracker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let write_fake_sqlite = |path: &Path| {
            let mut fake = [0u8; SQLITE_HEADER_LEN];
            fake[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);
            fake[18] = 1;
            fake[19] = 1;
            fs::write(path, fake).unwrap();
        };

        let dir = TempDir::new().unwrap();

        #[cfg(unix)]
        {
            let target = dir.path().join("replaced.sqlite");
            let old_alias = dir.path().join("replaced_old_inode.sqlite");
            let replacement = dir.path().join("replacement.sqlite");
            write_fake_sqlite(&target);
            fs::hard_link(&target, &old_alias).unwrap();
            write_fake_sqlite(&replacement);

            let dropped = Arc::new(AtomicBool::new(false));
            let dropped_for_cb = Arc::clone(&dropped);
            let res = open_existing_writable_guarded(&target, |canonical| {
                fs::rename(&replacement, canonical).unwrap();
                Ok(DropTracker(dropped_for_cb))
            });
            assert!(
                matches!(res, Err(LedgerError::Integrity(_))),
                "concurrent pathname replacement must fail closed with LedgerError::Integrity"
            );
            assert!(
                dropped.load(Ordering::SeqCst),
                "connection handle must be dropped immediately on inode mismatch"
            );
            assert_eq!(active_handle_count(&fs::canonicalize(&target).unwrap()), 0);
            assert_eq!(
                active_handle_count(&fs::canonicalize(&old_alias).unwrap()),
                0
            );
        }

        let vanished = dir.path().join("vanished.sqlite");
        write_fake_sqlite(&vanished);
        #[cfg(unix)]
        let vanished_old_alias = {
            let alias = dir.path().join("vanished_old_inode.sqlite");
            fs::hard_link(&vanished, &alias).unwrap();
            alias
        };

        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_cb = Arc::clone(&dropped);
        let res = open_existing_writable_guarded(&vanished, |canonical| {
            fs::remove_file(canonical).unwrap();
            Ok(DropTracker(dropped_for_cb))
        });
        assert!(
            matches!(res, Err(LedgerError::Integrity(_))),
            "concurrent unlink during open must fail closed with LedgerError::Integrity"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "connection handle must be dropped immediately when path disappears"
        );
        #[cfg(unix)]
        assert_eq!(
            active_handle_count(&fs::canonicalize(&vanished_old_alias).unwrap()),
            0
        );
    }
}
