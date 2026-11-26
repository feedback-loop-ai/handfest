//! Platform-specific non-following, non-blocking read-only file opener for ledger preflight.

use std::fs::{self, File};
use std::io;
use std::path::Path;

#[cfg(unix)]
pub(super) const UNIX_O_NOFOLLOW: Option<i32> = if cfg!(all(
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
pub(super) const UNIX_O_NONBLOCK: Option<i32> = if cfg!(all(
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
pub(super) const fn combine_unix_open_flags(no_follow: Option<i32>, non_block: Option<i32>) -> i32 {
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
pub(super) fn raw_open_calls() -> usize {
    RAW_OPEN_CALLS.with(|c| c.load(std::sync::atomic::Ordering::SeqCst))
}

pub(super) fn open_no_follow_read_only(path: &Path) -> io::Result<File> {
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
