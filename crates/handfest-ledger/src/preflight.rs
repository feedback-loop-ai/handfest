//! Portable pre-open read-only file/header/sidecar checks and inode-keyed in-process handle
//! tracking.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
#[cfg(unix)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::LedgerError;

const SQLITE_HEADER_LEN: usize = 100;
const SQLITE_HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const ROLLBACK_JOURNAL_HDR_LEN: usize = 28;
const HOT_JOURNAL_RETRY_BUDGET: Duration = Duration::from_millis(500);
const HOT_JOURNAL_INITIAL_BACKOFF: Duration = Duration::from_millis(2);
const HOT_JOURNAL_MAX_BACKOFF: Duration = Duration::from_millis(100);
#[cfg(unix)]
const MAX_DEFERRED_FDS: usize = 64;

#[cfg(unix)]
const UNIX_O_NOFOLLOW: Option<i32> = if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "m68k"
    )
)) {
    Some(0o100_000) // 0x8000
} else if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "loongarch64",
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    )
)) {
    Some(0o400_000) // 0x20000
} else if cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)) {
    Some(0x0100)
} else {
    None
};

#[cfg(unix)]
const UNIX_O_NONBLOCK: Option<i32> = if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x",
        target_arch = "loongarch64",
        target_arch = "m68k"
    )
)) {
    Some(0o4000) // 0x800
} else if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6"
    )
)) {
    Some(0x0080)
} else if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "sparc", target_arch = "sparc64")
)) {
    Some(0x4000)
} else if cfg!(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)) {
    Some(0x0004)
} else {
    None
};

#[cfg(unix)]
const fn combine_unix_open_flags(no_follow: Option<i32>, non_block: Option<i32>) -> i32 {
    let nf = if let Some(flag) = no_follow { flag } else { 0 };
    let nb = if let Some(flag) = non_block { flag } else { 0 };
    nf | nb
}

/// Process-local file identity for POSIX `fcntl` lock preservation and post-open identity checks.
///
/// On Unix, keys by immutable `(st_dev, st_ino)`. On non-Unix platforms (including Windows), keys
/// solely by `canonical` (`PathBuf`) — never by mutable metadata such as `file_size` or
/// `creation_time`, which would break `ActiveHandleRegistry` refcounting across schema init or
/// page growth. Under `#![forbid(unsafe_code)]`, `rusqlite` opens by pathname and Windows uses
/// handle-based mandatory locks rather than POSIX `fcntl` close-drops-locks, while in-place file
/// replacement during SQLite open is outside SQLite's documented concurrency contract
/// ("How To Corrupt An SQLite Database File" §2.1 & §2.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
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
    #[cfg(unix)]
    deferred_fds: HashMap<(u64, u64), Vec<File>>,
}

impl ActiveHandleRegistry {
    #[cfg(test)]
    fn active_count_by_id(&self, id: &FileIdentity) -> usize {
        self.counts.get(id).copied().unwrap_or(0)
    }

    #[cfg(unix)]
    fn has_active_handles(&self) -> bool {
        self.active_writers > 0 || !self.counts.is_empty()
    }

    #[cfg(unix)]
    fn total_deferred_fds(&self) -> usize {
        self.deferred_fds.values().map(Vec::len).sum()
    }

    #[cfg(unix)]
    fn should_defer_inode(&self, (dev, ino): (u64, u64)) -> bool {
        self.active_writers > 0 || self.counts.contains_key(&FileIdentity { dev, ino })
    }

    #[cfg(unix)]
    fn cached_deferred_fd(&mut self, key: (u64, u64)) -> Option<&mut File> {
        self.deferred_fds
            .get_mut(&key)
            .and_then(|files| files.first_mut())
    }

    #[cfg(unix)]
    fn ensure_deferred_fd_capacity(&self, key: Option<(u64, u64)>) -> Result<(), LedgerError> {
        let will_defer = match key {
            Some(id) => self.should_defer_inode(id),
            None => self.active_writers > 0,
        };
        if will_defer && self.total_deferred_fds() >= MAX_DEFERRED_FDS {
            return Err(LedgerError::Storage(format!(
                "deferred raw-open fd cap ({MAX_DEFERRED_FDS}) reached while ledger handles are active"
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn maybe_defer_fd(&mut self, key: (u64, u64), file: File) {
        if self.should_defer_inode(key) {
            self.deferred_fds.entry(key).or_default().push(file);
        }
    }

    #[cfg(unix)]
    fn maybe_defer_regular_file(&mut self, file: File) {
        use std::os::unix::fs::MetadataExt;
        if self.has_active_handles() {
            if let Some(fstat) = file.metadata().ok().filter(fs::Metadata::is_file) {
                self.maybe_defer_fd((fstat.dev(), fstat.ino()), file);
            }
        }
    }
}

static ACTIVE_HANDLES: OnceLock<Mutex<ActiveHandleRegistry>> = OnceLock::new();

fn active_handles() -> &'static Mutex<ActiveHandleRegistry> {
    ACTIVE_HANDLES.get_or_init(|| Mutex::new(ActiveHandleRegistry::default()))
}

fn lock_registry(registry: &Mutex<ActiveHandleRegistry>) -> MutexGuard<'_, ActiveHandleRegistry> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

struct PendingWriterGuard {
    registry: &'static Mutex<ActiveHandleRegistry>,
    state: MutexGuard<'static, ActiveHandleRegistry>,
    committed: bool,
}

impl PendingWriterGuard {
    fn acquire(registry: &'static Mutex<ActiveHandleRegistry>) -> Self {
        let mut state = lock_registry(registry);
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
            self.state.active_writers = self.state.active_writers.saturating_sub(1);
        }
    }
}

/// RAII registration of any open file-backed [`crate::SqliteLedger`] handle (writable OR read-only)
/// in this process, keyed by [`FileIdentity`].
///
/// While `counts[id] > 0`, `open_read_only_guarded` skips raw `File::open` on that inode so POSIX
/// `close()` never drops in-process `fcntl` locks. On Unix, raw header/journal `File` handles are
/// deferred in `deferred_fds` by `(st_dev, st_ino)` (reusing the first retained `File` via
/// `SeekFrom::Start(0)` and appending duplicates) whenever `active_writers > 0` or the probed inode
/// is currently tracked in `counts`. With `active_writers == 0`, uncounted header/journal probes
/// close immediately so a long-lived reader never exhausts the fd cap. `deferred_fds` is cleared
/// only when BOTH `active_writers == 0` and `counts.is_empty()` (never removing individual entries
/// while any handle remains active, so an fd retained for an inode holding an external POSIX lock
/// is never closed prematurely by a subsequent reader open/drop).
pub(crate) struct ActiveHandleGuard {
    registry: &'static Mutex<ActiveHandleRegistry>,
    id: FileIdentity,
    is_writer: bool,
}

impl Drop for ActiveHandleGuard {
    fn drop(&mut self) {
        let mut state = lock_registry(self.registry);
        if let Some(count) = state.counts.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                state.counts.remove(&self.id);
            }
        }
        if self.is_writer {
            state.active_writers = state.active_writers.saturating_sub(1);
        }
        #[cfg(unix)]
        if state.active_writers == 0 && state.counts.is_empty() {
            state.deferred_fds.clear();
        }
    }
}

#[cfg(test)]
pub(crate) fn active_handle_count(canonical: &Path) -> usize {
    let Ok(id) = FileIdentity::from_path(canonical) else {
        return 0;
    };
    lock_registry(active_handles()).active_count_by_id(&id)
}

#[cfg(all(test, unix))]
pub(crate) fn active_writer_count() -> usize {
    lock_registry(active_handles()).active_writers
}

#[cfg(all(test, unix))]
pub(crate) fn deferred_fd_count() -> usize {
    lock_registry(active_handles()).total_deferred_fds()
}

#[cfg(all(test, unix))]
pub(crate) fn defer_fd_for_test(key: (u64, u64), file: File) {
    lock_registry(active_handles()).maybe_defer_fd(key, file);
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

/// Opens a read-only handle inside `registry` and verifies post-open canonical file state.
///
/// Trust boundary: under `#![forbid(unsafe_code)]`, `rusqlite::Connection::open_with_flags` opens
/// by pathname (not fd). Post-open verification rejects concurrent unlink or symlink/non-file
/// substitution (and on Unix, replacement with a different `(st_dev, st_ino)`), whereas in-place
/// file replacement during `sqlite3_open_v2` is outside SQLite's documented concurrency contract
/// ("How To Corrupt An SQLite Database File" §2.1 & §2.4).
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
    check_rollback_journal_sidecar_in(registry, &append_suffix(canonical, "-journal"))?;

    let mut state = lock_registry(registry);
    let meta = stat_read_only_regular_file(canonical)?;
    let mut id = FileIdentity::from_metadata(canonical, &meta);
    if state.counts.get(&id).copied().unwrap_or(0) == 0 {
        id = inspect_sqlite_header_locked(&mut state, canonical)?;
    }
    let conn = open_conn(canonical)?;
    if let Err(err) = verify_post_open_canonical_identity(canonical, &id) {
        drop(conn);
        return Err(err);
    }
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

/// Verifies post-open that `canonical` is still a regular non-symlink file (and on Unix, matches
/// immutable `(st_dev, st_ino)`). On non-Unix/Windows, never compares mutable file size or claims
/// inode identity: under `#![forbid(unsafe_code)]`, `rusqlite` opens by pathname and Windows uses
/// handle-based mandatory locks rather than POSIX `fcntl` close-drops-locks; in-place replacement
/// during SQLite open is outside SQLite's documented concurrency contract (§2.1 & §2.4).
fn verify_post_open_canonical_identity(
    canonical: &Path,
    expected_id: &FileIdentity,
) -> Result<(), LedgerError> {
    const CHANGED: &str = "read-only ledger path changed concurrently during open";
    let post_meta =
        fs::symlink_metadata(canonical).map_err(|_| LedgerError::Integrity(CHANGED.to_string()))?;
    let unchanged = !post_meta.file_type().is_symlink() && post_meta.is_file();
    #[cfg(unix)]
    let unchanged = unchanged && FileIdentity::from_metadata(canonical, &post_meta) == *expected_id;
    #[cfg(not(unix))]
    let _ = expected_id;
    if !unchanged {
        return Err(LedgerError::Integrity(CHANGED.to_string()));
    }
    Ok(())
}

fn stat_read_only_regular_file(canonical: &Path) -> Result<fs::Metadata, LedgerError> {
    let meta = fs::symlink_metadata(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to stat read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    validate_regular_ledger_metadata(&meta, canonical)?;
    Ok(meta)
}

#[cfg(unix)]
fn regular_file_key(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).ok()?;
    meta.file_type().is_file().then(|| (meta.dev(), meta.ino()))
}

fn validate_regular_ledger_metadata(
    meta: &fs::Metadata,
    canonical: &Path,
) -> Result<(), LedgerError> {
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
    Ok(())
}

fn inspect_sqlite_header_locked(
    state: &mut ActiveHandleRegistry,
    canonical: &Path,
) -> Result<FileIdentity, LedgerError> {
    #[cfg(unix)]
    {
        let key = regular_file_key(canonical);
        if let Some(cached) = key.and_then(|k| state.cached_deferred_fd(k)) {
            cached.seek(SeekFrom::Start(0)).map_err(|err| {
                LedgerError::Integrity(format!(
                    "failed to rewind cached read-only ledger '{}': {err}",
                    canonical.display()
                ))
            })?;
            return inspect_sqlite_header_from_file(cached, canonical);
        }
        state.ensure_deferred_fd_capacity(key)?;
    }
    #[cfg(not(unix))]
    let _ = state;

    let mut file = open_no_follow_read_only(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to open read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    let res = inspect_sqlite_header_from_file(&mut file, canonical);
    #[cfg(unix)]
    state.maybe_defer_regular_file(file);
    res
}

fn inspect_sqlite_header_from_file(
    file: &mut File,
    canonical: &Path,
) -> Result<FileIdentity, LedgerError> {
    let meta = file.metadata().map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to stat open read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    validate_regular_ledger_metadata(&meta, canonical)?;
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
    Ok(FileIdentity::from_metadata(canonical, &meta))
}

fn check_wal_sidecar(wal_path: &Path) -> Result<(), LedgerError> {
    let meta = match fs::symlink_metadata(wal_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot inspect WAL sidecar '{}': {err}",
                wal_path.display()
            )));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(LedgerError::Integrity(format!(
            "symlink WAL sidecar '{}' is forbidden",
            wal_path.display()
        )));
    }
    if !meta.file_type().is_file() || meta.len() > 0 {
        return Err(LedgerError::Integrity(format!(
            "non-empty or invalid WAL sidecar '{}' requires recovery before read-only audit",
            wal_path.display()
        )));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum JournalProbe {
    Clean,
    Hot,
}

fn check_rollback_journal_sidecar_in(
    registry: &Mutex<ActiveHandleRegistry>,
    journal_path: &Path,
) -> Result<(), LedgerError> {
    check_rollback_journal_sidecar_with_budget_in(registry, journal_path, HOT_JOURNAL_RETRY_BUDGET)
}

fn check_rollback_journal_sidecar_with_budget_in(
    registry: &Mutex<ActiveHandleRegistry>,
    journal_path: &Path,
    budget: Duration,
) -> Result<(), LedgerError> {
    let deadline = Instant::now() + budget;
    let mut backoff = HOT_JOURNAL_INITIAL_BACKOFF;
    loop {
        match probe_rollback_journal_once(registry, journal_path)? {
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

#[cfg(all(test, unix))]
thread_local! {
    static RAW_OPEN_CALLS: std::sync::atomic::AtomicUsize =
        const { std::sync::atomic::AtomicUsize::new(0) };
}

#[cfg(all(test, unix))]
fn raw_open_calls() -> usize {
    RAW_OPEN_CALLS.with(|c| c.load(std::sync::atomic::Ordering::SeqCst))
}

fn open_no_follow_read_only(path: &Path) -> io::Result<File> {
    #[cfg(all(test, unix))]
    RAW_OPEN_CALLS.with(|c| c.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(combine_unix_open_flags(UNIX_O_NOFOLLOW, UNIX_O_NONBLOCK));
    }
    opts.open(path)
}

fn reject_symlink_without_o_nofollow(
    has_o_nofollow: bool,
    is_symlink: bool,
    journal_path: &Path,
) -> Result<(), LedgerError> {
    if !has_o_nofollow && is_symlink {
        return Err(LedgerError::Integrity(format!(
            "symlink rollback journal '{}' is forbidden",
            journal_path.display()
        )));
    }
    Ok(())
}

fn probe_rollback_journal_once(
    registry: &Mutex<ActiveHandleRegistry>,
    journal_path: &Path,
) -> Result<JournalProbe, LedgerError> {
    let meta = match fs::symlink_metadata(journal_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(JournalProbe::Clean),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot inspect rollback journal '{}': {err}",
                journal_path.display()
            )));
        }
    };
    let is_symlink = meta.file_type().is_symlink();
    if meta.file_type().is_file() && meta.len() == 0 {
        return Ok(JournalProbe::Clean);
    }
    #[cfg(unix)]
    let has_o_nofollow = UNIX_O_NOFOLLOW.is_some();
    #[cfg(not(unix))]
    let has_o_nofollow = false;
    reject_symlink_without_o_nofollow(has_o_nofollow, is_symlink, journal_path)?;
    if !is_symlink && !meta.file_type().is_file() {
        return Err(LedgerError::Integrity(format!(
            "invalid non-file rollback journal '{}'",
            journal_path.display()
        )));
    }
    probe_rollback_journal_open(registry, journal_path, is_symlink)
}

fn probe_rollback_journal_open(
    registry: &Mutex<ActiveHandleRegistry>,
    journal_path: &Path,
    is_symlink: bool,
) -> Result<JournalProbe, LedgerError> {
    #[cfg(unix)]
    let mut state = lock_registry(registry);
    #[cfg(not(unix))]
    let _ = registry;

    #[cfg(unix)]
    {
        let key = (!is_symlink)
            .then(|| regular_file_key(journal_path))
            .flatten();
        if let Some(cached) = key.and_then(|k| state.cached_deferred_fd(k)) {
            cached.seek(SeekFrom::Start(0)).map_err(|err| {
                LedgerError::Integrity(format!(
                    "cannot rewind cached rollback journal '{}': {err}",
                    journal_path.display()
                ))
            })?;
            return read_rollback_journal_from_file(cached, journal_path);
        }
        state.ensure_deferred_fd_capacity(key)?;
    }
    let mut file = match open_no_follow_read_only(journal_path) {
        Ok(file) => file,
        Err(err) if !is_symlink && err.kind() == io::ErrorKind::NotFound => {
            return Ok(JournalProbe::Clean);
        }
        Err(err) if is_symlink => {
            return Err(LedgerError::Integrity(format!(
                "symlink rollback journal '{}' is forbidden: {err}",
                journal_path.display()
            )));
        }
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot read non-empty rollback journal '{}': {err}",
                journal_path.display()
            )));
        }
    };
    let probe = read_rollback_journal_from_file(&mut file, journal_path);
    #[cfg(unix)]
    state.maybe_defer_regular_file(file);
    probe
}

fn read_rollback_journal_from_file(
    file: &mut File,
    journal_path: &Path,
) -> Result<JournalProbe, LedgerError> {
    let meta = file.metadata().map_err(|err| {
        LedgerError::Integrity(format!(
            "cannot stat open rollback journal '{}': {err}",
            journal_path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(LedgerError::Integrity(format!(
            "invalid non-file rollback journal '{}'",
            journal_path.display()
        )));
    }
    let mut hdr = [0u8; ROLLBACK_JOURNAL_HDR_LEN];
    if file.read_exact(&mut hdr).is_err() {
        return Ok(JournalProbe::Hot);
    }
    if &hdr[..SQLITE_HEADER_MAGIC.len()] == SQLITE_HEADER_MAGIC {
        return Err(LedgerError::Integrity(format!(
            "rollback journal '{}' contains a SQLite database header",
            journal_path.display()
        )));
    }
    if hdr.iter().any(|&b| b != 0) {
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
#[path = "preflight_tests.rs"]
mod tests;
