//! Portable pre-open read-only file/header/sidecar checks and inode-keyed in-process handle
//! tracking.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::LedgerError;

const SQLITE_HEADER_LEN: usize = 100;
const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const ROLLBACK_JOURNAL_HDR_LEN: usize = 28;
const HOT_JOURNAL_RETRY_BUDGET: Duration = Duration::from_millis(500);
const HOT_JOURNAL_INITIAL_BACKOFF: Duration = Duration::from_millis(2);
const HOT_JOURNAL_MAX_BACKOFF: Duration = Duration::from_millis(25);
const MAX_DEFERRED_HEADER_FDS: usize = 64;

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

#[derive(Default)]
struct ActiveHandleRegistry {
    counts: BTreeMap<FileIdentity, usize>,
    active_writers: usize,
    deferred_header_fds: BTreeMap<FileIdentity, File>,
}

impl ActiveHandleRegistry {
    fn decrement_writer(&mut self) {
        self.active_writers = self.active_writers.saturating_sub(1);
        if self.active_writers == 0 {
            self.deferred_header_fds.clear();
        }
    }
}

static ACTIVE_HANDLES: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();

fn active_handles() -> &'static Mutex<ActiveHandleRegistry> {
    ACTIVE_HANDLES.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()))
}

struct PendingWriterGuard {
    registry: &'static Mutex<ActiveHandleRegistry>,
    state: MutexGuard<'static, ActiveHandleRegistry>,
    committed: bool,
}

impl PendingWriterGuard {
    fn acquire(registry: &'static Mutex<ActiveHandleRegistry>) -> Self {
        let mut state = registry.lock().unwrap_or_else(PoisonError::into_inner);
        state.active_writers += 1;
        Self {
            registry,
            state,
            committed: false,
        }
    }

    fn commit(mut self, id: FileIdentity) -> ActiveHandleGuard {
        *self.state.counts.entry(id.clone()).or_insert(0) += 1;
        self.committed = true;
        ActiveHandleGuard {
            registry: self.registry,
            id,
            is_writer: true,
        }
    }
}

impl Drop for PendingWriterGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.state.decrement_writer();
        }
    }
}

/// RAII registration of any open file-backed [`crate::SqliteLedger`] handle (writable OR read-only)
/// in this process, keyed by [`FileIdentity`].
///
/// While at least one handle is open on a given inode in this process (`refcount > 0`),
/// `open_read_only_guarded` skips raw `std::fs::File::open` on the main DB inode so POSIX
/// `close()` never drops in-process `fcntl` SHARED/RESERVED/EXCLUSIVE locks across hard links or
/// concurrent readers. While any writable handle is active (`active_writers > 0`), any raw header
/// inspection fd opened for an unindexed inode (e.g. after concurrent rename/ABA) is retained in
/// `deferred_header_fds` and only closed once `active_writers` drops to `0`.
pub(crate) struct ActiveHandleGuard {
    registry: &'static Mutex<ActiveHandleRegistry>,
    id: FileIdentity,
    is_writer: bool,
}

impl Drop for ActiveHandleGuard {
    fn drop(&mut self) {
        let mut state = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = state.counts.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                state.counts.remove(&self.id);
            }
        }
        if self.is_writer {
            state.decrement_writer();
        }
    }
}

#[cfg(test)]
pub(crate) fn active_handle_count(canonical: &Path) -> usize {
    let Ok(id) = FileIdentity::from_path(canonical) else {
        return 0;
    };
    let state = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    state.counts.get(&id).copied().unwrap_or(0)
}

/// Opens a writable ledger connection while holding the process-local active-handle registry lock
/// so `active_writers` is incremented before `open_conn` runs and its [`ActiveHandleGuard`] is
/// registered atomically before any concurrent `open_read_only` call can inspect a raw header.
pub(crate) fn open_writable_guarded<T, F>(
    path: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce() -> Result<T, LedgerError>,
{
    open_writable_guarded_in(active_handles(), path, open_conn)
}

fn open_writable_guarded_in<T, F>(
    registry: &'static Mutex<ActiveHandleRegistry>,
    path: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce() -> Result<T, LedgerError>,
{
    let pending = PendingWriterGuard::acquire(registry);
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
    let guard = pending.commit(id);
    Ok((conn, guard))
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
    open_read_only_guarded_in(active_handles(), canonical, open_conn)
}

fn open_read_only_guarded_in<T, F>(
    registry: &'static Mutex<ActiveHandleRegistry>,
    canonical: &Path,
    open_conn: F,
) -> Result<(T, ActiveHandleGuard), LedgerError>
where
    F: FnOnce(&Path) -> Result<T, LedgerError>,
{
    stat_read_only_regular_file(canonical)?;
    check_wal_sidecar(&append_suffix(canonical, "-wal"))?;
    check_rollback_journal_sidecar(&append_suffix(canonical, "-journal"))?;

    let mut state = registry.lock().unwrap_or_else(PoisonError::into_inner);
    let meta = stat_read_only_regular_file(canonical)?;
    let id = FileIdentity::from_metadata(canonical, &meta);
    if state.counts.get(&id).copied().unwrap_or(0) == 0 {
        inspect_sqlite_header_locked(&mut state, canonical, &id)?;
    }
    let conn = open_conn(canonical)?;
    *state.counts.entry(id.clone()).or_insert(0) += 1;
    Ok((
        conn,
        ActiveHandleGuard {
            registry,
            id,
            is_writer: false,
        },
    ))
}

fn stat_read_only_regular_file(canonical: &Path) -> Result<fs::Metadata, LedgerError> {
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
    Ok(meta)
}

fn inspect_sqlite_header_locked(
    state: &mut ActiveHandleRegistry,
    canonical: &Path,
    id: &FileIdentity,
) -> Result<(), LedgerError> {
    if state.active_writers == 0 {
        return inspect_sqlite_header(canonical);
    }
    if let Some(existing) = state.deferred_header_fds.get_mut(id) {
        return inspect_sqlite_header_from_file(existing, canonical);
    }
    if state.deferred_header_fds.len() >= MAX_DEFERRED_HEADER_FDS {
        return Err(LedgerError::Storage(format!(
            "deferred read-only header fd cap ({MAX_DEFERRED_HEADER_FDS}) reached while writable ledger handles are active"
        )));
    }
    let file = File::open(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to open read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    let entry = state.deferred_header_fds.entry(id.clone()).or_insert(file);
    inspect_sqlite_header_from_file(entry, canonical)
}

fn inspect_sqlite_header(canonical: &Path) -> Result<(), LedgerError> {
    let mut file = File::open(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to open read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    inspect_sqlite_header_from_file(&mut file, canonical)
}

fn inspect_sqlite_header_from_file(file: &mut File, canonical: &Path) -> Result<(), LedgerError> {
    file.seek(SeekFrom::Start(0)).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to seek read-only ledger '{}': {err}",
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

    fn write_valid_header_file(path: &Path) -> PathBuf {
        let mut fake_sqlite = [0u8; SQLITE_HEADER_LEN];
        fake_sqlite[..SQLITE_HEADER_MAGIC.len()].copy_from_slice(SQLITE_HEADER_MAGIC);
        fake_sqlite[18] = 1;
        fake_sqlite[19] = 1;
        fs::write(path, fake_sqlite).unwrap();
        fs::canonicalize(path).unwrap()
    }

    #[test]
    fn deferred_header_fds_handle_aba_rename_dedup_error_retention_and_cleanup() {
        static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
        let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

        let dir = TempDir::new().unwrap();
        let orig = dir.path().join("orig.sqlite");
        let moved = dir.path().join("moved.sqlite");
        write_valid_header_file(&orig);

        let ((), writer_guard) = open_writable_guarded_in(reg, &orig, || {
            fs::rename(&orig, &moved).unwrap();
            write_valid_header_file(&orig);
            Ok(())
        })
        .unwrap();
        {
            let state = reg.lock().unwrap();
            assert_eq!(state.active_writers, 1);
            assert!(state.deferred_header_fds.is_empty());
        }

        let canonical_moved = fs::canonicalize(&moved).unwrap();
        let ((), ro1) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
        assert_eq!(reg.lock().unwrap().deferred_header_fds.len(), 1);
        drop(ro1);

        let ((), ro2) = open_read_only_guarded_in(reg, &canonical_moved, |_| Ok(())).unwrap();
        assert_eq!(reg.lock().unwrap().deferred_header_fds.len(), 1);
        drop(ro2);

        let bad_magic = dir.path().join("bad_magic_deferred.sqlite");
        fs::write(&bad_magic, [0u8; SQLITE_HEADER_LEN]).unwrap();
        let canonical_bad = fs::canonicalize(&bad_magic).unwrap();
        assert!(matches!(
            open_read_only_guarded_in(reg, &canonical_bad, |_| Ok(())),
            Err(LedgerError::Integrity(_))
        ));
        assert_eq!(reg.lock().unwrap().deferred_header_fds.len(), 2);

        drop(writer_guard);
        {
            let state = reg.lock().unwrap();
            assert_eq!(state.active_writers, 0);
            assert!(state.deferred_header_fds.is_empty());
        }
    }

    #[test]
    fn open_writable_guarded_error_and_deferred_fd_cap_fail_closed() {
        static REG: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();
        let reg = REG.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()));

        let dir = TempDir::new().unwrap();
        let writer_path = write_valid_header_file(&dir.path().join("writer.sqlite"));
        let missing_path = dir.path().join("does_not_exist.sqlite");

        let err: Result<((), ActiveHandleGuard), LedgerError> =
            open_writable_guarded_in(reg, &writer_path, || {
                Err(LedgerError::Storage("simulated open failure".into()))
            });
        assert!(matches!(err, Err(LedgerError::Storage(_))));
        assert_eq!(reg.lock().unwrap().active_writers, 0);

        let err = open_writable_guarded_in(reg, &missing_path, || Ok(()));
        assert!(matches!(err, Err(LedgerError::Storage(_))));
        assert_eq!(reg.lock().unwrap().active_writers, 0);

        let ((), writer_guard) = open_writable_guarded_in(reg, &writer_path, || Ok(())).unwrap();
        let mut first_ro = None;
        for idx in 0..MAX_DEFERRED_HEADER_FDS {
            let fp = write_valid_header_file(&dir.path().join(format!("ro_{idx}.sqlite")));
            let ((), ro) = open_read_only_guarded_in(reg, &fp, |_| Ok(())).unwrap();
            drop(ro);
            if idx == 0 {
                first_ro = Some(fp);
            }
        }
        assert_eq!(
            reg.lock().unwrap().deferred_header_fds.len(),
            MAX_DEFERRED_HEADER_FDS
        );

        let ((), ro_reuse) =
            open_read_only_guarded_in(reg, first_ro.as_ref().unwrap(), |_| Ok(())).unwrap();
        drop(ro_reuse);
        assert_eq!(
            reg.lock().unwrap().deferred_header_fds.len(),
            MAX_DEFERRED_HEADER_FDS
        );

        let extra = write_valid_header_file(&dir.path().join("ro_overflow.sqlite"));
        assert!(matches!(
            open_read_only_guarded_in(reg, &extra, |_| Ok(())),
            Err(LedgerError::Storage(_))
        ));

        drop(writer_guard);
        assert_eq!(reg.lock().unwrap().active_writers, 0);
        assert!(reg.lock().unwrap().deferred_header_fds.is_empty());
        let ((), ro_extra) = open_read_only_guarded_in(reg, &extra, |_| Ok(())).unwrap();
        drop(ro_extra);
        assert!(reg.lock().unwrap().deferred_header_fds.is_empty());
    }
}
