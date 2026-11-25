//! Read-only SQLite ledger opening, sidecar recovery validation, and direct immutable snapshot checks.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use handfest_core::ast::MandateId;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

use crate::LedgerError;

const OPEN_MAX_ATTEMPTS: usize = 5;
const ROLLBACK_JOURNAL_HDR_LEN: usize = 28;

/// Tracks how a read-only [`crate::SqliteLedger`] connection was opened.
#[derive(Debug)]
pub(crate) enum ReadOnlyMode {
    /// Live SQLite connection participating in SQLite's own locking (WAL or rollback journal),
    /// or a normal read-write ledger connection.
    Live,
    /// Direct `immutable=1` SQLite connection on a cleanly closed ledger file.
    ///
    /// Never creates `-wal`/`-shm` sidecars, never copies the database into temporary storage, and
    /// opens the database through SQLite's VFS so closing it never releases another in-process
    /// SQLite connection's POSIX locks. Callers must verify via
    /// [`verify_immutable_snapshot_unchanged`] that no concurrent writer mutated the file across a
    /// read operation.
    ImmutableDirect {
        canonical: PathBuf,
        open_fingerprint: FileFingerprint,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidecarState {
    Absent,
    Empty,
    NonEmpty,
}

impl SidecarState {
    fn exists(self) -> bool {
        !matches!(self, Self::Absent)
    }

    fn is_clean(self) -> bool {
        matches!(self, Self::Absent | Self::Empty)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalState {
    Clean,
    Hot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SidecarMeta {
    state: SidecarState,
    fingerprint: Option<FileFingerprint>,
}

#[derive(Debug, Clone)]
struct SidecarSummary {
    wal: SidecarMeta,
    shm: SidecarMeta,
    journal: JournalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

impl FileFingerprint {
    fn from_metadata(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                len: meta.len(),
                modified: meta.modified().ok(),
                dev: meta.dev(),
                ino: meta.ino(),
                ctime: meta.ctime(),
                ctime_nsec: meta.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: meta.len(),
                modified: meta.modified().ok(),
            }
        }
    }
}

pub(crate) fn open_read_only_connection(
    path: &Path,
) -> Result<(Connection, ReadOnlyMode), LedgerError> {
    let canonical = fs::canonicalize(path).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to resolve read-only ledger path '{}': {err}",
            path.display()
        ))
    })?;
    open_read_only_connection_with_hook(&canonical, || {})
}

fn open_read_only_connection_with_hook(
    canonical: &Path,
    mut before_live_open: impl FnMut(),
) -> Result<(Connection, ReadOnlyMode), LedgerError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;

    for _ in 0..OPEN_MAX_ATTEMPTS {
        let sidecars = inspect_sidecars(canonical)?;
        if sidecars.journal == JournalState::Hot {
            return Err(LedgerError::Integrity(format!(
                "cannot audit '{}' in read-only mode: hot rollback journal requires recovery",
                canonical.display()
            )));
        }

        match (sidecars.wal.state, sidecars.shm.state) {
            (SidecarState::NonEmpty, SidecarState::Absent) => {
                return Err(LedgerError::Integrity(format!(
                    "cannot audit '{}' in read-only mode: uncheckpointed WAL requires recovery",
                    canonical.display()
                )));
            }
            (
                wal_state @ (SidecarState::Empty | SidecarState::NonEmpty),
                SidecarState::Empty | SidecarState::NonEmpty,
            ) => {
                before_live_open();
                if let Some(pair) = try_open_live_or_fallback(
                    canonical,
                    flags,
                    wal_state,
                    sidecars.wal.fingerprint.as_ref(),
                )? {
                    return Ok(pair);
                }
            }
            (_, SidecarState::Absent) | (SidecarState::Absent, _) => {
                if let Some(pair) = try_open_immutable_direct(canonical, flags)? {
                    return Ok(pair);
                }
            }
        }
    }

    Err(LedgerError::Integrity(format!(
        "ledger '{}' changed concurrently while opening in read-only mode",
        canonical.display()
    )))
}

fn try_open_live_or_fallback(
    canonical: &Path,
    flags: OpenFlags,
    wal_state: SidecarState,
    pre_wal_fp: Option<&FileFingerprint>,
) -> Result<Option<(Connection, ReadOnlyMode)>, LedgerError> {
    match open_live_read_only(canonical, flags) {
        Ok(conn) => Ok(Some((conn, ReadOnlyMode::Live))),
        Err(err) if is_sidecar_open_fallback_error(&err) => {
            cleanup_orphan_readonly_wal(canonical, pre_wal_fp);
            if wal_state == SidecarState::Empty {
                let recheck = inspect_sidecars(canonical)?;
                if recheck.journal == JournalState::Clean && recheck.wal.state.is_clean() {
                    return try_open_immutable_direct(canonical, flags);
                }
            }
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

fn open_live_read_only(canonical: &Path, flags: OpenFlags) -> Result<Connection, rusqlite::Error> {
    let uri = build_ro_uri(canonical, "mode=ro&readonly_shm=1")
        .map_err(|err| rusqlite::Error::InvalidParameterName(err.to_string()))?;
    let conn = Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    probe_read_only(&conn)?;
    Ok(conn)
}

fn try_open_immutable_direct(
    canonical: &Path,
    flags: OpenFlags,
) -> Result<Option<(Connection, ReadOnlyMode)>, LedgerError> {
    let pre_fp = path_fingerprint(canonical)?;
    let uri = build_ro_uri(canonical, "mode=ro&immutable=1")?;
    let conn = Connection::open_with_flags(uri, flags | OpenFlags::SQLITE_OPEN_URI)?;
    conn.busy_timeout(Duration::from_millis(5_000))?;
    probe_read_only(&conn)?;

    let post_fp = path_fingerprint(canonical)?;
    let post_sidecars = inspect_sidecars(canonical)?;
    if post_fp == pre_fp
        && post_sidecars.wal.state.is_clean()
        && post_sidecars.journal == JournalState::Clean
    {
        Ok(Some((
            conn,
            ReadOnlyMode::ImmutableDirect {
                canonical: canonical.to_path_buf(),
                open_fingerprint: post_fp,
            },
        )))
    } else {
        Ok(None)
    }
}

pub(crate) fn path_fingerprint(canonical: &Path) -> Result<FileFingerprint, LedgerError> {
    let meta = fs::metadata(canonical).map_err(|err| {
        LedgerError::Integrity(format!(
            "failed to stat read-only ledger '{}': {err}",
            canonical.display()
        ))
    })?;
    Ok(FileFingerprint::from_metadata(&meta))
}

pub(crate) fn has_clean_sidecars(canonical: &Path) -> Result<bool, LedgerError> {
    let sidecars = inspect_sidecars(canonical)?;
    Ok(sidecars.journal == JournalState::Clean
        && sidecars.wal.state.is_clean()
        && !sidecars.shm.state.exists())
}

/// Verifies that an `ImmutableDirect` ledger file was not modified or raced by a concurrent writer
/// across a read operation.
pub(crate) fn verify_immutable_snapshot_unchanged(
    canonical: &Path,
    expected_fp: &FileFingerprint,
    expected_tip: Option<Option<(i64, MandateId)>>,
) -> Result<bool, LedgerError> {
    let post_fp = path_fingerprint(canonical)?;
    if post_fp != *expected_fp {
        return Ok(false);
    }
    let post_sidecars = inspect_sidecars(canonical)?;
    if post_sidecars.journal != JournalState::Clean || !post_sidecars.wal.state.is_clean() {
        return Ok(false);
    }

    if let Some(expected_tip) = expected_tip {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let uri = build_ro_uri(canonical, "mode=ro&immutable=1")?;
        let Ok(probe) = Connection::open_with_flags(uri, flags) else {
            return Ok(false);
        };
        let Ok(actual_tip) = query_receipt_tip(&probe) else {
            return Ok(false);
        };
        if actual_tip != expected_tip {
            return Ok(false);
        }
    }

    Ok(true)
}

fn query_receipt_tip(conn: &Connection) -> Result<Option<(i64, MandateId)>, LedgerError> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, receipt_hash FROM receipts ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((seq, hash_raw)) => {
            let hash = MandateId::parse(&hash_raw).map_err(|err| {
                LedgerError::Integrity(format!(
                    "seq {seq}: invalid receipt_hash '{hash_raw}': {err}"
                ))
            })?;
            Ok(Some((seq, hash)))
        }
        None => Ok(None),
    }
}

/// If `open_live_read_only` raced with the last writer closing on a read-only (`0444`) database
/// file in a writable directory, `sqlite3WalOpen` may have created an empty read-only `-wal` right
/// before `readonly_shm=1` failed on the now-absent `-shm`. Removing that newly created 0-byte
/// read-only orphan prevents it from blocking the next writer.
#[cfg(unix)]
fn cleanup_orphan_readonly_wal(canonical: &Path, pre_wal_fp: Option<&FileFingerprint>) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(db_meta) = fs::metadata(canonical) else {
        return;
    };
    if db_meta.permissions().mode() & 0o222 != 0 {
        return;
    }
    let shm_path = sidecar_path(canonical, "-shm");
    if fs::metadata(&shm_path).is_ok() {
        return;
    }
    let wal_path = sidecar_path(canonical, "-wal");
    let Ok(wal_meta) = fs::metadata(&wal_path) else {
        return;
    };
    if wal_meta.len() != 0 || (wal_meta.permissions().mode() & 0o222 != 0) {
        return;
    }
    let post_wal_fp = FileFingerprint::from_metadata(&wal_meta);
    let is_new_inode =
        pre_wal_fp.is_none_or(|pre| pre.dev != post_wal_fp.dev || pre.ino != post_wal_fp.ino);
    if is_new_inode {
        let _ = fs::remove_file(&wal_path);
    }
}

#[cfg(not(unix))]
fn cleanup_orphan_readonly_wal(_canonical: &Path, _pre_wal_fp: Option<&FileFingerprint>) {}

fn sidecar_path(canonical: &Path, suffix: &str) -> PathBuf {
    let mut os = canonical.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn inspect_sidecar_meta(path: &Path) -> Result<SidecarMeta, LedgerError> {
    match fs::metadata(path) {
        Ok(meta) => {
            let state = if meta.len() > 0 {
                SidecarState::NonEmpty
            } else {
                SidecarState::Empty
            };
            Ok(SidecarMeta {
                state,
                fingerprint: Some(FileFingerprint::from_metadata(&meta)),
            })
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(SidecarMeta {
            state: SidecarState::Absent,
            fingerprint: None,
        }),
        Err(err) => Err(LedgerError::Integrity(format!(
            "cannot inspect ledger sidecar '{}': {err}",
            path.display()
        ))),
    }
}

/// Inspects a rollback `-journal` sidecar without ever touching the main database inode.
///
/// SQLite never holds POSIX advisory locks on `-journal` files. In `PERSIST` journal mode,
/// SQLite leaves a non-empty `-journal` file on disk after commit with its 28-byte header zeroed;
/// a non-empty journal whose leading header bytes are all zero is inactive and safe to audit.
fn inspect_rollback_journal(path: &Path) -> Result<JournalState, LedgerError> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(JournalState::Clean),
        Err(err) => {
            return Err(LedgerError::Integrity(format!(
                "cannot inspect ledger sidecar '{}': {err}",
                path.display()
            )));
        }
    };
    if meta.len() == 0 {
        return Ok(JournalState::Clean);
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(JournalState::Clean),
        Err(_) => return Ok(JournalState::Hot),
    };
    let mut header = [0u8; ROLLBACK_JOURNAL_HDR_LEN];
    let mut read_total = 0usize;
    while read_total < header.len() {
        match file.read(&mut header[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(_) => return Ok(JournalState::Hot),
        }
    }
    if header[..read_total].iter().all(|&b| b == 0) {
        Ok(JournalState::Clean)
    } else {
        Ok(JournalState::Hot)
    }
}

fn inspect_sidecars(canonical: &Path) -> Result<SidecarSummary, LedgerError> {
    let journal = inspect_rollback_journal(&sidecar_path(canonical, "-journal"))?;
    let wal = inspect_sidecar_meta(&sidecar_path(canonical, "-wal"))?;
    let shm = inspect_sidecar_meta(&sidecar_path(canonical, "-shm"))?;
    Ok(SidecarSummary { wal, shm, journal })
}

fn probe_read_only(conn: &Connection) -> Result<(), rusqlite::Error> {
    let _: Option<i64> = conn
        .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |row| row.get(0))
        .optional()?;
    Ok(())
}

fn is_sidecar_open_fallback_error(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(ffi, _)
            if matches!(
                ffi.code,
                rusqlite::ErrorCode::ReadOnly | rusqlite::ErrorCode::CannotOpen
            )
    )
}

fn build_ro_uri(path: &Path, query: &str) -> Result<String, LedgerError> {
    #[cfg(unix)]
    let encoded = {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes();
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            if b == 0 {
                return Err(LedgerError::Integrity(
                    "read-only ledger path contains NUL byte".to_string(),
                ));
            }
            if matches!(b, b'%' | b'?' | b'#') || !b.is_ascii() || b.is_ascii_control() {
                let _ = write!(out, "%{b:02X}");
            } else {
                out.push(char::from(b));
            }
        }
        out
    };

    #[cfg(not(unix))]
    let encoded = {
        let Some(path_str) = path.to_str() else {
            return Err(LedgerError::Integrity(format!(
                "read-only ledger path '{}' is not valid UTF-8",
                path.display()
            )));
        };
        let mut out = String::with_capacity(path_str.len());
        for ch in path_str.chars() {
            match ch {
                '%' => out.push_str("%25"),
                '?' => out.push_str("%3F"),
                '#' => out.push_str("%23"),
                other => out.push(other),
            }
        }
        out
    };

    if encoded.starts_with('/') {
        Ok(format!("file://{encoded}?{query}"))
    } else {
        Ok(format!("file:{encoded}?{query}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sidecar_open_fallback_recognizes_readonly_and_cantopen() {
        let ro_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ReadOnly,
                extended_code: rusqlite::ffi::SQLITE_READONLY,
            },
            None,
        );
        let cantopen_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::CannotOpen,
                extended_code: rusqlite::ffi::SQLITE_CANTOPEN,
            },
            None,
        );
        let corrupt_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseCorrupt,
                extended_code: rusqlite::ffi::SQLITE_CORRUPT,
            },
            None,
        );

        assert!(is_sidecar_open_fallback_error(&ro_err));
        assert!(is_sidecar_open_fallback_error(&cantopen_err));
        assert!(!is_sidecar_open_fallback_error(&corrupt_err));
    }

    #[cfg(unix)]
    #[test]
    fn ro_uri_percent_encodes_non_utf8_unix_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let raw = Path::new(OsStr::from_bytes(b"/tmp/dir-\xff-a%b?c#d/ledger.sqlite"));
        let uri = build_ro_uri(raw, "mode=ro&immutable=1").unwrap();
        assert_eq!(
            uri,
            "file:///tmp/dir-%FF-a%25b%3Fc%23d/ledger.sqlite?mode=ro&immutable=1"
        );
    }

    #[test]
    fn inspect_rollback_journal_distinguishes_zeroed_persist_header_from_hot_journal() {
        let dir = TempDir::new().unwrap();
        let journal = dir.path().join("ledger.sqlite-journal");

        // Absent -> Clean.
        assert_eq!(
            inspect_rollback_journal(&journal).unwrap(),
            JournalState::Clean
        );

        // Empty -> Clean.
        fs::write(&journal, b"").unwrap();
        assert_eq!(
            inspect_rollback_journal(&journal).unwrap(),
            JournalState::Clean
        );

        // Non-empty with 28 zeroed header bytes followed by old page data (PERSIST mode) -> Clean.
        let mut persist_bytes = vec![0u8; ROLLBACK_JOURNAL_HDR_LEN];
        persist_bytes.extend_from_slice(b"stale-committed-page-data");
        fs::write(&journal, &persist_bytes).unwrap();
        assert_eq!(
            inspect_rollback_journal(&journal).unwrap(),
            JournalState::Clean
        );

        // Non-empty with SQLite hot-journal magic -> Hot.
        fs::write(&journal, b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7active-tx").unwrap();
        assert_eq!(
            inspect_rollback_journal(&journal).unwrap(),
            JournalState::Hot
        );
    }

    #[cfg(unix)]
    #[test]
    fn writer_close_between_sidecar_inspect_and_probe_recovers_in_readonly_and_writable_dirs() {
        use std::os::unix::fs::PermissionsExt;

        struct RestorePerms(Vec<(PathBuf, u32)>);
        impl Drop for RestorePerms {
            fn drop(&mut self) {
                for (p, mode) in self.0.iter().rev() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(*mode));
                }
            }
        }

        // Case 1: Writable directory with 0444 database file where the last writer closes right
        // between sidecar inspection and the SQLite probe. Audit must succeed without leaving
        // read-only sidecars that block the next writer.
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("race_writable.sqlite");
        let wal_path = dir.path().join("race_writable.sqlite-wal");
        let shm_path = dir.path().join("race_writable.sqlite-shm");

        let mut live_writer = Some(crate::SqliteLedger::open(&db_path).unwrap());
        {
            let writer = live_writer.as_ref().unwrap();
            writer
                .conn
                .execute("CREATE TABLE IF NOT EXISTS t(x INT)", [])
                .unwrap();
            writer.conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
            writer.conn.execute("INSERT INTO t VALUES (2)", []).unwrap();
            assert!(fs::metadata(&wal_path).unwrap().len() > 0);
            assert!(shm_path.exists());
        }
        let canonical = fs::canonicalize(&db_path).unwrap();
        let _restore1 = RestorePerms(vec![(db_path.clone(), 0o644)]);

        let (conn, mode) = open_read_only_connection_with_hook(&canonical, || {
            drop(live_writer.take());
            fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).unwrap();
        })
        .expect("audit must fall back cleanly when last writer closes mid-open");
        assert!(matches!(mode, ReadOnlyMode::ImmutableDirect { .. }));
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        drop(conn);

        assert!(!wal_path.exists(), "must not leave stray 0444 -wal sidecar");
        assert!(!shm_path.exists(), "must not leave stray 0444 -shm sidecar");

        // Restoring write permissions on the DB file alone must allow the next writer cleanly.
        fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();
        let next_writer = crate::SqliteLedger::open(&db_path).unwrap();
        next_writer
            .conn
            .execute("INSERT INTO t VALUES (3)", [])
            .unwrap();
        drop(next_writer);

        // Case 2: Read-only directory (0555) where the last writer closes between sidecar
        // inspection and the SQLite probe. Audit must fall back instead of failing.
        let ro_dir = dir.path().join("race_ro_dir");
        fs::create_dir(&ro_dir).unwrap();
        let ro_db = ro_dir.join("ledger.sqlite");
        let mut ro_writer = Some(crate::SqliteLedger::open(&ro_db).unwrap());
        {
            let writer = ro_writer.as_ref().unwrap();
            writer
                .conn
                .execute("CREATE TABLE IF NOT EXISTS t(x INT)", [])
                .unwrap();
            writer
                .conn
                .execute("INSERT INTO t VALUES (10)", [])
                .unwrap();
        }
        let ro_canonical = fs::canonicalize(&ro_db).unwrap();
        let _restore2 = RestorePerms(vec![(ro_dir.clone(), 0o755), (ro_db.clone(), 0o644)]);

        let (ro_conn, ro_mode) = open_read_only_connection_with_hook(&ro_canonical, || {
            drop(ro_writer.take());
            fs::set_permissions(&ro_db, fs::Permissions::from_mode(0o444)).unwrap();
            fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();
        })
        .expect("audit must fall back cleanly in read-only dir when last writer closes mid-open");
        assert!(matches!(ro_mode, ReadOnlyMode::ImmutableDirect { .. }));
        let v: i64 = ro_conn
            .query_row("SELECT x FROM t LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 10);
    }
}
