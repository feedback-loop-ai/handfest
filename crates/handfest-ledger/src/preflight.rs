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
        target_arch = "mips64",
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
        target_arch = "loongarch64"
    )
)) {
    Some(0o4000) // 0x800
} else if cfg!(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "mips", target_arch = "mips64")
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
    let nf = match no_follow {
        Some(flag) => flag,
        None => 0,
    };
    let nb = match non_block {
        Some(flag) => flag,
        None => 0,
    };
    nf | nb
}

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
    #[cfg(unix)]
    deferred_fds: HashMap<(u64, u64), Vec<File>>,
}

impl ActiveHandleRegistry {
    #[cfg(unix)]
    fn has_active_handles(&self) -> bool {
        self.active_writers > 0 || !self.counts.is_empty()
    }

    #[cfg(unix)]
    fn total_deferred_fds(&self) -> usize {
        self.deferred_fds.values().map(Vec::len).sum()
    }

    fn maybe_clear_deferred_fds(&mut self) {
        #[cfg(unix)]
        if !self.has_active_handles() {
            self.deferred_fds.clear();
        }
    }

    #[cfg(unix)]
    fn ensure_deferred_fd_capacity(&self) -> Result<(), LedgerError> {
        if self.has_active_handles() && self.total_deferred_fds() >= MAX_DEFERRED_FDS {
            return Err(LedgerError::Storage(format!(
                "deferred raw-open fd cap ({MAX_DEFERRED_FDS}) reached while ledger handles are active"
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn maybe_defer_fd(&mut self, key: (u64, u64), file: File) {
        if !self.has_active_handles() {
            drop(file);
            return;
        }
        self.deferred_fds.entry(key).or_default().push(file);
    }

    #[cfg(unix)]
    fn maybe_defer_regular_file(&mut self, file: File) {
        use std::os::unix::fs::MetadataExt;
        if !self.has_active_handles() {
            drop(file);
            return;
        }
        let Ok(fstat) = file.metadata() else {
            drop(file);
            return;
        };
        if !fstat.is_file() {
            drop(file);
            return;
        }
        self.maybe_defer_fd((fstat.dev(), fstat.ino()), file);
    }

    fn decrement_writer(&mut self) {
        self.active_writers = self.active_writers.saturating_sub(1);
        self.maybe_clear_deferred_fds();
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
/// concurrent readers. On Unix, while ANY writable OR read-only handle is active
/// (`active_writers > 0 || !counts.is_empty()`), every regular-file `File` opened for header
/// inspection or rollback-journal probing is retained in `deferred_fds` keyed by `(st_dev, st_ino)`
/// (reusing the first retained `File` via `SeekFrom::Start(0)` on repeated inspections of the same
/// live inode, and pushing any additional `File` opened on an occupied key rather than dropping it)
/// and only closed once BOTH `active_writers == 0` and `counts.is_empty()`.
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
        } else {
            state.maybe_clear_deferred_fds();
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

#[cfg(all(test, unix))]
pub(crate) fn active_writer_count() -> usize {
    let state = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    state.active_writers
}

#[cfg(all(test, unix))]
pub(crate) fn deferred_fd_count() -> usize {
    let state = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    state.total_deferred_fds()
}

#[cfg(all(test, unix))]
pub(crate) fn defer_fd_for_test(key: (u64, u64), file: File) {
    let mut state = active_handles()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    state.maybe_defer_fd(key, file);
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
    check_rollback_journal_sidecar_in(registry, &append_suffix(canonical, "-journal"))?;

    let mut state = registry.lock().unwrap_or_else(PoisonError::into_inner);
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

fn verify_post_open_canonical_identity(
    canonical: &Path,
    expected_id: &FileIdentity,
) -> Result<(), LedgerError> {
    let Ok(post_meta) = fs::symlink_metadata(canonical) else {
        return Err(LedgerError::Integrity(
            "read-only ledger path changed concurrently during open".to_string(),
        ));
    };
    if post_meta.file_type().is_symlink()
        || !post_meta.file_type().is_file()
        || FileIdentity::from_metadata(canonical, &post_meta) != *expected_id
    {
        return Err(LedgerError::Integrity(
            "read-only ledger path changed concurrently during open".to_string(),
        ));
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
fn cached_deferred_fd<'a>(
    state: &'a mut ActiveHandleRegistry,
    path: &Path,
) -> Option<&'a mut File> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    state
        .deferred_fds
        .get_mut(&(meta.dev(), meta.ino()))
        .and_then(|files| files.first_mut())
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
    if let Some(cached) = cached_deferred_fd(state, canonical) {
        cached.seek(SeekFrom::Start(0)).map_err(|err| {
            LedgerError::Integrity(format!(
                "failed to rewind cached read-only ledger '{}': {err}",
                canonical.display()
            ))
        })?;
        return inspect_sqlite_header_from_file(cached, canonical);
    }

    #[cfg(unix)]
    state.ensure_deferred_fd_capacity()?;
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

fn open_no_follow_read_only(path: &Path) -> io::Result<File> {
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
    let mut state = registry.lock().unwrap_or_else(PoisonError::into_inner);
    #[cfg(not(unix))]
    let _ = registry;

    #[cfg(unix)]
    if !is_symlink {
        if let Some(cached) = cached_deferred_fd(&mut state, journal_path) {
            cached.seek(SeekFrom::Start(0)).map_err(|err| {
                LedgerError::Integrity(format!(
                    "cannot rewind cached rollback journal '{}': {err}",
                    journal_path.display()
                ))
            })?;
            return read_rollback_journal_from_file(cached, journal_path);
        }
    }

    #[cfg(unix)]
    state.ensure_deferred_fd_capacity()?;
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
