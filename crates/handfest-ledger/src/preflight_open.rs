//! Platform-specific non-following, non-blocking read-only file opener for ledger preflight.

use std::fs::{self, File};
use std::io;
use std::path::Path;

#[cfg(unix)]
pub(crate) const UNIX_O_NOFOLLOW: Option<i32> = if cfg!(all(
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
pub(crate) const UNIX_O_NONBLOCK: Option<i32> = if cfg!(all(
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
pub(crate) const fn combine_unix_open_flags(no_follow: Option<i32>, non_block: Option<i32>) -> i32 {
    let nf = if let Some(flag) = no_follow { flag } else { 0 };
    let nb = if let Some(flag) = non_block { flag } else { 0 };
    nf | nb
}

#[cfg(all(test, unix))]
thread_local! {
    static RAW_OPEN_CALLS: std::sync::atomic::AtomicUsize =
        const { std::sync::atomic::AtomicUsize::new(0) };
}

#[cfg(all(test, unix))]
pub(crate) fn raw_open_calls() -> usize {
    RAW_OPEN_CALLS.with(|c| c.load(std::sync::atomic::Ordering::SeqCst))
}

pub(crate) fn open_no_follow_read_only(path: &Path) -> io::Result<File> {
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

pub(crate) const HAS_UNIX_O_NOFOLLOW: bool = {
    #[cfg(unix)]
    {
        UNIX_O_NOFOLLOW.is_some()
    }
    #[cfg(not(unix))]
    {
        false
    }
};

pub(crate) fn open_no_follow_append_0600(path: &Path) -> io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(combine_unix_open_flags(UNIX_O_NOFOLLOW, UNIX_O_NONBLOCK));
    }
    opts.open(path)
}

/// Opens (or creates) `path` for writing without following a trailing symlink and without
/// truncating on open, so callers can inspect `File::metadata()` / inode identity before
/// truncating and writing.
pub fn open_no_follow_write_no_trunc(path: &Path) -> io::Result<File> {
    if !HAS_UNIX_O_NOFOLLOW {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing to follow symlink '{}'", path.display()),
                ));
            }
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(combine_unix_open_flags(UNIX_O_NOFOLLOW, UNIX_O_NONBLOCK));
    }
    opts.open(path)
}

pub(crate) fn map_read_only_canonicalize_error(path: &Path, err: &io::Error) -> crate::LedgerError {
    match err.kind() {
        io::ErrorKind::NotFound => crate::LedgerError::NotFound(format!(
            "read-only ledger '{}' not found: {err}",
            path.display()
        )),
        io::ErrorKind::PermissionDenied => crate::LedgerError::Storage(format!(
            "permission denied resolving read-only ledger path '{}': {err}",
            path.display()
        )),
        _ => crate::LedgerError::Integrity(format!(
            "failed to resolve read-only ledger path '{}': {err}",
            path.display()
        )),
    }
}

pub(crate) fn map_open_existing_error(path: &Path, err: rusqlite::Error) -> crate::LedgerError {
    if let rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: rusqlite::ErrorCode::CannotOpen,
            extended_code,
        },
        _,
    ) = err
    {
        if extended_code != rusqlite::ffi::SQLITE_CANTOPEN_ISDIR
            && matches!(fs::metadata(path), Err(ref io_err) if io_err.kind() == io::ErrorKind::NotFound)
        {
            return crate::LedgerError::NotFound(err.to_string());
        }
        return crate::LedgerError::Storage(err.to_string());
    }
    crate::LedgerError::from(err)
}

pub(crate) fn validate_file_path(path: &Path, caller: &str) -> Result<(), crate::LedgerError> {
    let raw_os = path.as_os_str();
    if raw_os.is_empty() || raw_os == ":memory:" || is_sqlite_uri_path(raw_os) {
        return Err(crate::LedgerError::Storage(format!(
            "empty, ':memory:', or 'file:' URI path rejected by {caller}; use open_in_memory() for ephemeral ledgers"
        )));
    }
    Ok(())
}

fn is_sqlite_uri_path(raw: &std::ffi::OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        raw.as_bytes().starts_with(b"file:")
    }
    #[cfg(not(unix))]
    {
        raw.to_str().is_some_and(|s| s.starts_with("file:"))
    }
}
