//! Restricted Unix domain socket binding, parent permission enforcement, and safe stale cleanup.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::daemon::DaemonError;

/// Allowed restricted Unix socket permission modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketMode {
    /// Owner read/write only (`0600`), requiring an owner-only parent directory (`mode & 0077 == 0`).
    #[default]
    OwnerOnly,
    /// Owner and group read/write (`0660`), requiring a non-world, non-group-writable parent directory (`mode & 0027 == 0`).
    GroupControlled,
}

impl SocketMode {
    /// Returns the Unix permission mode bits enforced on the bound socket.
    #[must_use]
    pub const fn file_mode(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o600,
            Self::GroupControlled => 0o660,
        }
    }

    #[must_use]
    const fn forbidden_parent_mask(self) -> u32 {
        match self {
            Self::OwnerOnly => 0o077,
            Self::GroupControlled => 0o027,
        }
    }
}

/// A bound Unix domain socket with enforced restricted permissions and safe drop cleanup.
#[derive(Debug)]
pub struct BoundSocket {
    listener: UnixListener,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone, Copy)]
struct PostBindMeta {
    is_symlink: bool,
    is_socket: bool,
    dev: u64,
    ino: u64,
}

trait SocketBindOps {
    fn current_dir(&self) -> io::Result<PathBuf>;
    fn current_euid(&self) -> Result<u32, DaemonError>;
    fn inspect_dir(&self, path: &Path) -> Result<DirPrefixInfo, DaemonError>;
    fn post_bind_metadata(&self, path: &Path) -> Result<PostBindMeta, DaemonError>;
    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), DaemonError>;
}

struct RealSocketBindOps;

impl SocketBindOps for RealSocketBindOps {
    fn current_dir(&self) -> io::Result<PathBuf> {
        std::env::current_dir()
    }

    fn current_euid(&self) -> Result<u32, DaemonError> {
        current_euid()
    }

    fn inspect_dir(&self, path: &Path) -> Result<DirPrefixInfo, DaemonError> {
        inspect_dir_prefix(path)
    }

    fn post_bind_metadata(&self, path: &Path) -> Result<PostBindMeta, DaemonError> {
        let meta = fs::symlink_metadata(path).map_err(|source| DaemonError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        Ok(PostBindMeta {
            is_symlink: meta.file_type().is_symlink(),
            is_socket: meta.file_type().is_socket(),
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), DaemonError> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
            DaemonError::Io {
                path: Some(path.to_path_buf()),
                source,
            }
        })
    }
}

impl BoundSocket {
    /// Validates parent directory permissions and ownership, safely cleans up a stale socket
    /// (refusing symlinks or active sockets), binds `socket_path`, and sets restricted permissions.
    ///
    /// Relative `socket_path` values are resolved once against the current working directory into
    /// an absolute path before validation and binding, so the expanded absolute path must fit
    /// within the platform Unix domain socket address (`sun_path`) length limit.
    pub fn bind(socket_path: &Path, socket_mode: SocketMode) -> Result<Self, DaemonError> {
        Self::bind_with_ops(socket_path, socket_mode, &RealSocketBindOps)
    }

    fn bind_with_ops(
        socket_path: &Path,
        socket_mode: SocketMode,
        ops: &dyn SocketBindOps,
    ) -> Result<Self, DaemonError> {
        validate_socket_path(socket_path)?;
        let (abs_socket_path, abs_parent) = resolve_socket_and_parent(socket_path, ops)?;
        validate_socket_path(&abs_socket_path)?;
        let euid = ops.current_euid()?;
        validate_parent_dir(&abs_parent, socket_mode, euid, ops)?;
        clean_stale_socket_if_present(&abs_socket_path)?;

        let listener = UnixListener::bind(&abs_socket_path).map_err(|source| DaemonError::Io {
            path: Some(abs_socket_path.clone()),
            source,
        })?;

        let meta = match ops.post_bind_metadata(&abs_socket_path) {
            Ok(meta) => meta,
            Err(err) => {
                // Close our listener first so our own socket becomes stale (`ConnectionRefused`)
                // while any live replacement listener remains active and is preserved.
                drop(listener);
                if !matches!(
                    &err,
                    DaemonError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound
                ) {
                    cleanup_post_bind_error_socket(&abs_socket_path);
                }
                return Err(err);
            }
        };
        if meta.is_symlink || !meta.is_socket {
            return Err(DaemonError::PathExistsNotSocket(abs_socket_path));
        }

        let bound = Self {
            listener,
            path: abs_socket_path,
            dev: meta.dev,
            ino: meta.ino,
        };

        ops.set_permissions(&bound.path, socket_mode.file_mode())?;

        let recheck = ops.post_bind_metadata(&bound.path)?;
        if !is_same_bound_socket(recheck, bound.dev, bound.ino) {
            return Err(DaemonError::PathExistsNotSocket(bound.path.clone()));
        }

        Ok(bound)
    }

    /// Returns the underlying [`UnixListener`].
    #[must_use]
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Returns the bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if !meta.file_type().is_symlink()
                && meta.file_type().is_socket()
                && meta.dev() == self.dev
                && meta.ino() == self.ino
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn validate_socket_path(socket_path: &Path) -> Result<(), DaemonError> {
    let Some(raw) = socket_path.to_str() else {
        return Err(DaemonError::InvalidConfig(
            "socket path must be valid UTF-8".to_string(),
        ));
    };
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err(DaemonError::InvalidConfig(
            "socket path must be non-empty and free of control characters".to_string(),
        ));
    }
    if raw.ends_with('/') {
        return Err(DaemonError::InvalidConfig(
            "socket path must not end with '/'".to_string(),
        ));
    }
    if raw.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(DaemonError::InvalidConfig(
            "socket path must not contain '.' or '..' components".to_string(),
        ));
    }
    Ok(())
}

fn resolve_socket_and_parent(
    socket_path: &Path,
    ops: &dyn SocketBindOps,
) -> Result<(PathBuf, PathBuf), DaemonError> {
    let abs_socket_path = if socket_path.is_absolute() {
        socket_path.to_path_buf()
    } else {
        let cwd = ops.current_dir().map_err(|source| DaemonError::Io {
            path: Some(socket_path.to_path_buf()),
            source,
        })?;
        if !cwd.is_absolute() {
            return Err(DaemonError::InvalidConfig(
                "working directory must be an absolute path".to_string(),
            ));
        }
        cwd.join(socket_path)
    };
    let Some(parent) = abs_socket_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
    else {
        return Err(DaemonError::InvalidConfig(
            "socket path must have a parent directory".to_string(),
        ));
    };
    let abs_parent = parent.to_path_buf();
    Ok((abs_socket_path, abs_parent))
}

fn cleanup_post_bind_error_socket(socket_path: &Path) {
    let Ok(meta) = fs::symlink_metadata(socket_path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
        return;
    }
    let orig_dev = meta.dev();
    let orig_ino = meta.ino();
    // Under restrictive umask (e.g. 0777 before chmod), our freshly bound socket has
    // mode 0000 so connect() would return PermissionDenied; no live replacement listener
    // serves clients on a 0000 socket, so remove if identity still matches.
    let should_remove = if meta.permissions().mode() & 0o777 == 0 {
        true
    } else {
        let probe_deadline =
            std::time::Instant::now().checked_add(std::time::Duration::from_millis(50));
        matches!(
            crate::client::connect_unix_with_deadline_for_probe(socket_path, probe_deadline),
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused
        )
    };
    if !should_remove {
        return;
    }
    if let Ok(recheck) = fs::symlink_metadata(socket_path) {
        if !recheck.file_type().is_symlink()
            && recheck.file_type().is_socket()
            && recheck.dev() == orig_dev
            && recheck.ino() == orig_ino
        {
            let _ = fs::remove_file(socket_path);
        }
    }
}

const fn is_same_bound_socket(recheck: PostBindMeta, dev: u64, ino: u64) -> bool {
    !recheck.is_symlink && recheck.is_socket && recheck.dev == dev && recheck.ino == ino
}

fn validate_parent_dir(
    abs_parent: &Path,
    socket_mode: SocketMode,
    current_euid: u32,
    ops: &dyn SocketBindOps,
) -> Result<(), DaemonError> {
    let prefixes = ancestor_prefixes(abs_parent);
    let Some((immediate_parent, ancestors)) = prefixes.split_last() else {
        return Err(DaemonError::InvalidConfig(
            "socket parent path is empty".to_string(),
        ));
    };

    let mut ancestor_infos = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let info = ops.inspect_dir(ancestor)?;
        // Reject any non-sticky ancestor that is group- or world-writable.
        if (info.mode & 0o022 != 0) && (info.mode & 0o1000 == 0) {
            return Err(DaemonError::InsecureParentPermissions {
                path: ancestor.clone(),
                mode: info.mode,
            });
        }
        ancestor_infos.push((ancestor, info));
    }

    let parent_info = ops.inspect_dir(immediate_parent)?;
    if parent_info.mode & socket_mode.forbidden_parent_mask() != 0 {
        return Err(DaemonError::InsecureParentPermissions {
            path: immediate_parent.clone(),
            mode: parent_info.mode,
        });
    }
    verify_parent_owner(immediate_parent, parent_info.uid, current_euid)?;

    for (ancestor, info) in ancestor_infos {
        verify_ancestor_owner(ancestor, info.uid, current_euid)?;
    }
    Ok(())
}

fn verify_parent_owner(
    parent: &Path,
    parent_uid: u32,
    expected_euid: u32,
) -> Result<(), DaemonError> {
    if parent_uid != 0 && parent_uid != expected_euid {
        return Err(DaemonError::UntrustedParentOwner {
            path: parent.to_path_buf(),
            parent_uid,
            expected_uid: expected_euid,
        });
    }
    Ok(())
}

const TRUSTED_ID_PATHS: [&str; 2] = ["/usr/bin/id", "/bin/id"];

fn parse_proc_status_euid(contents: &[u8]) -> Option<u32> {
    for raw_line in contents.split(|&b| b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if let Some(rest) = line.strip_prefix(b"Uid:") {
            let rest_str = std::str::from_utf8(rest).ok()?;
            let mut fields = rest_str.split_whitespace();
            let _real = fields.next()?;
            return fields.next()?.parse::<u32>().ok();
        }
    }
    None
}

fn parse_id_u_output(stdout: &[u8]) -> Option<u32> {
    std::str::from_utf8(stdout).ok()?.trim().parse::<u32>().ok()
}

fn run_trusted_id_at<F>(paths: &[&str], mut exec: F) -> io::Result<std::process::Output>
where
    F: FnMut(&str) -> io::Result<std::process::Output>,
{
    let mut last_not_found = None;
    for path in paths {
        match exec(path) {
            Ok(output) => return Ok(output),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                last_not_found = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_not_found.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no trusted 'id' executable found at /usr/bin/id or /bin/id",
        )
    }))
}

fn build_trusted_id_command(path: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(path);
    cmd.env_clear().arg("-u");
    cmd
}

fn run_trusted_id_from_paths(paths: &[&str]) -> io::Result<std::process::Output> {
    run_trusted_id_at(paths, |path| build_trusted_id_command(path).output())
}

fn run_trusted_id() -> io::Result<std::process::Output> {
    run_trusted_id_from_paths(&TRUSTED_ID_PATHS)
}

fn resolve_euid_with<R, I>(read_proc_status: R, run_trusted_id: I) -> Result<u32, DaemonError>
where
    R: FnOnce() -> io::Result<Vec<u8>>,
    I: FnOnce() -> io::Result<std::process::Output>,
{
    match read_proc_status() {
        Ok(bytes) => parse_proc_status_euid(&bytes).ok_or_else(|| DaemonError::Io {
            path: Some(PathBuf::from("/proc/self/status")),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "failed to parse effective UID from /proc/self/status",
            ),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let output =
                run_trusted_id().map_err(|source| DaemonError::Io { path: None, source })?;
            if !output.status.success() {
                return Err(DaemonError::Io {
                    path: None,
                    source: io::Error::other(format!(
                        "trusted 'id -u' exited with status {}",
                        output.status
                    )),
                });
            }
            parse_id_u_output(&output.stdout).ok_or_else(|| DaemonError::Io {
                path: None,
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to parse effective UID from trusted 'id -u'",
                ),
            })
        }
        Err(source) => Err(DaemonError::Io {
            path: Some(PathBuf::from("/proc/self/status")),
            source,
        }),
    }
}

fn current_euid() -> Result<u32, DaemonError> {
    resolve_euid_with(|| fs::read("/proc/self/status"), run_trusted_id)
}

#[derive(Debug, Clone, Copy)]
struct DirPrefixInfo {
    mode: u32,
    uid: u32,
}

fn verify_ancestor_owner(
    ancestor: &Path,
    ancestor_uid: u32,
    expected_euid: u32,
) -> Result<(), DaemonError> {
    if ancestor_uid != 0 && ancestor_uid != expected_euid {
        return Err(DaemonError::UntrustedAncestorOwner {
            path: ancestor.to_path_buf(),
            ancestor_uid,
            expected_uid: expected_euid,
        });
    }
    Ok(())
}

fn ancestor_prefixes(abs_path: &Path) -> Vec<PathBuf> {
    let mut prefixes = Vec::new();
    let mut current = PathBuf::new();
    for component in abs_path.components() {
        match component {
            Component::CurDir => continue,
            Component::RootDir
            | Component::Prefix(_)
            | Component::Normal(_)
            | Component::ParentDir => {
                current.push(component.as_os_str());
                prefixes.push(current.clone());
            }
        }
    }
    prefixes
}

fn inspect_dir_prefix(path: &Path) -> Result<DirPrefixInfo, DaemonError> {
    let meta = fs::symlink_metadata(path).map_err(|source| DaemonError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(DaemonError::SymlinkRejected(path.to_path_buf()));
    }
    if !meta.file_type().is_dir() {
        return Err(DaemonError::NotADirectory(path.to_path_buf()));
    }
    Ok(DirPrefixInfo {
        mode: meta.permissions().mode() & 0o7777,
        uid: meta.uid(),
    })
}

fn clean_stale_socket_if_present(socket_path: &Path) -> Result<(), DaemonError> {
    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(DaemonError::Io {
                path: Some(socket_path.to_path_buf()),
                source,
            });
        }
    };
    if meta.file_type().is_symlink() {
        return Err(DaemonError::SymlinkRejected(socket_path.to_path_buf()));
    }
    if !meta.file_type().is_socket() {
        return Err(DaemonError::PathExistsNotSocket(socket_path.to_path_buf()));
    }
    let orig_dev = meta.dev();
    let orig_ino = meta.ino();

    match UnixStream::connect(socket_path) {
        Ok(_) => Err(DaemonError::SocketAlreadyActive(socket_path.to_path_buf())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            let recheck = match fs::symlink_metadata(socket_path) {
                Ok(meta) => meta,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(source) => {
                    return Err(DaemonError::Io {
                        path: Some(socket_path.to_path_buf()),
                        source,
                    });
                }
            };
            verify_stale_socket_unchanged(socket_path, &recheck, orig_dev, orig_ino)?;
            fs::remove_file(socket_path).map_err(|source| DaemonError::Io {
                path: Some(socket_path.to_path_buf()),
                source,
            })
        }
        Err(source) => Err(DaemonError::Io {
            path: Some(socket_path.to_path_buf()),
            source,
        }),
    }
}

fn verify_stale_socket_unchanged(
    socket_path: &Path,
    recheck: &fs::Metadata,
    orig_dev: u64,
    orig_ino: u64,
) -> Result<(), DaemonError> {
    if recheck.file_type().is_symlink() {
        return Err(DaemonError::SymlinkRejected(socket_path.to_path_buf()));
    }
    if !recheck.file_type().is_socket() {
        return Err(DaemonError::PathExistsNotSocket(socket_path.to_path_buf()));
    }
    if recheck.dev() != orig_dev || recheck.ino() != orig_ino {
        return Err(DaemonError::SocketAlreadyActive(socket_path.to_path_buf()));
    }
    Ok(())
}

/// Internal bidirectional stream seam supporting per-operation read/write timeouts.
pub(crate) trait ClientIoStream: Read + Write {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()>;
}

impl ClientIoStream for UnixStream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }
}

impl ClientIoStream for &UnixStream {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }
}

impl<S: ClientIoStream> ClientIoStream for &mut S {
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(dur)
    }
}

/// Internal monotonic clock seam for deterministic deadline enforcement.
pub(crate) trait DeadlineClock {
    fn now(&self) -> Instant;
}

/// Real monotonic clock backed by [`Instant::now`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SystemDeadlineClock;

impl DeadlineClock for SystemDeadlineClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl<C: DeadlineClock + ?Sized> DeadlineClock for &C {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// Wraps a [`ClientIoStream`] so every `read()` call enforces a single overall wall-clock deadline
/// rather than resetting the socket read timeout per received chunk.
pub(crate) struct DeadlineStreamReader<S, C = SystemDeadlineClock> {
    stream: S,
    deadline: Option<Instant>,
    clock: C,
}

impl<S, C> DeadlineStreamReader<S, C> {
    pub(crate) const fn with_clock(stream: S, deadline: Option<Instant>, clock: C) -> Self {
        Self {
            stream,
            deadline,
            clock,
        }
    }
}

pub(crate) fn remaining_until(deadline: Instant, now: Instant, op: &str) -> io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("stream exceeded overall {op} deadline"),
            )
        })
}

impl<S: ClientIoStream, C: DeadlineClock> Read for DeadlineStreamReader<S, C> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let remaining = remaining_until(deadline, self.clock.now(), "read")?;
            self.stream.set_read_timeout(Some(remaining))?;
        }
        self.stream.read(buf)
    }
}

/// Wraps a [`ClientIoStream`] so every `write()` call enforces a single overall wall-clock deadline
/// shared with [`DeadlineStreamReader`] rather than granting a fresh timeout per syscall.
pub(crate) struct DeadlineStreamWriter<S, C = SystemDeadlineClock> {
    stream: S,
    deadline: Option<Instant>,
    clock: C,
}

impl<S, C> DeadlineStreamWriter<S, C> {
    pub(crate) const fn with_clock(stream: S, deadline: Option<Instant>, clock: C) -> Self {
        Self {
            stream,
            deadline,
            clock,
        }
    }
}

impl<S: ClientIoStream, C: DeadlineClock> Write for DeadlineStreamWriter<S, C> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let remaining = remaining_until(deadline, self.clock.now(), "write")?;
            self.stream.set_write_timeout(Some(remaining))?;
        }
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Returns an [`Instant`] within one second of the platform monotonic clock's upper bound
/// so unit tests can deterministically exercise `checked_add` overflow guards with accepted
/// durations (`<= MAX_TIMEOUT`).
#[cfg(test)]
pub(crate) fn near_max_instant() -> Instant {
    near_max_instant_from(Instant::now())
}

#[cfg(test)]
fn near_max_instant_from(start: Instant) -> Instant {
    let mut cur = start;
    // Exact powers of two (`2^63, 2^62, ..., 2^0`) form a complete binary basis for every
    // distance in `0..=u64::MAX` seconds, avoiding the 1-second-per-step loss of `u64::MAX / 2`
    // that falls short of the upper bound when monotonic uptime is `< 63s` (e.g. fresh namespaces).
    let mut step = 1u64 << 63;
    while step > 0 {
        if let Some(next) = cur.checked_add(Duration::from_secs(step)) {
            cur = next;
        }
        step >>= 1;
    }
    assert!(
        cur.checked_add(Duration::from_secs(1)).is_none(),
        "binary search must reach monotonic clock upper bound"
    );
    cur
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
