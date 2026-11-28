//! Fail-closed on-disk mandate chain hot-reloader for long-lived [`crate::McpProxy`] sessions.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use handfest_anchors::{AnchorVerifier, SignedMandate};
use handfest_core::ast::KeyId;
#[cfg(any(not(unix), test))]
use handfest_core::ast::MandateId;
use handfest_core::gate::VerifiedMandate;
use handfest_pep::parse_signed_mandate_json;

use crate::adapters::{verify_mandate_chain_with, ProxyError};

/// Maximum accepted size of a single signed mandate JSON file on disk (4 MiB).
const MAX_CHAIN_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))
))]
compile_error!("unsupported Unix target for O_NONBLOCK");

/// Platform `O_NONBLOCK` bitmask resolved at compile time from [`handfest_pep::UNIX_O_NONBLOCK`].
#[cfg(unix)]
const RELOADER_O_NONBLOCK: i32 = match handfest_pep::UNIX_O_NONBLOCK {
    Some(flag) if flag != 0 => flag,
    _ => 0,
};

#[cfg(any(not(unix), test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ContentDigestFingerprint {
    len: u64,
    modified: SystemTime,
    content_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    len: u64,
    #[cfg(unix)]
    modified: SystemTime,
    #[cfg(unix)]
    ctime_sec: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
    #[cfg(not(unix))]
    content: ContentDigestFingerprint,
}

fn ensure_regular_metadata(path: &Path, meta: &Metadata) -> Result<SystemTime, io::Error> {
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("chain path '{}' is not a regular file", path.display()),
        ));
    }
    meta.modified().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to read modified timestamp for '{}': {err}",
                path.display()
            ),
        )
    })
}

fn stat_regular_path(path: &Path) -> Result<Metadata, io::Error> {
    let meta = fs::metadata(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to stat chain file '{}': {err}", path.display()),
        )
    })?;
    let _ = ensure_regular_metadata(path, &meta)?;
    Ok(meta)
}

fn open_chain_file_nonblocking(path: &Path) -> io::Result<File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(RELOADER_O_NONBLOCK);
    opts.open(path)
}

fn read_bounded_chain_bytes(path: &Path, file: File) -> Result<Vec<u8>, ProxyError> {
    let mut raw = Vec::new();
    file.take(MAX_CHAIN_FILE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to read chain file '{}': {err}", path.display()),
            )
        })?;
    if raw.len() as u64 > MAX_CHAIN_FILE_BYTES {
        return Err(ProxyError::InvalidChain(format!(
            "chain file '{}' exceeded maximum size of {MAX_CHAIN_FILE_BYTES} bytes",
            path.display()
        )));
    }
    Ok(raw)
}

/// Verifies `fstat(fd).is_file()` BEFORE reading any bytes from `file`.
fn read_regular_open_file(path: &Path, file: File) -> Result<(Metadata, Vec<u8>), ProxyError> {
    let fd_meta = file.metadata().map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to stat open chain file '{}': {err}", path.display()),
        )
    })?;
    let _ = ensure_regular_metadata(path, &fd_meta)?;
    let raw = read_bounded_chain_bytes(path, file)?;
    Ok((fd_meta, raw))
}

#[cfg(any(not(unix), test))]
fn sha256_file_bytes(raw: &[u8]) -> [u8; 32] {
    *MandateId::sha256(raw).as_bytes()
}

#[cfg(any(not(unix), test))]
impl ContentDigestFingerprint {
    fn from_metadata_and_bytes(
        path: &Path,
        meta: &Metadata,
        raw: &[u8],
    ) -> Result<Self, io::Error> {
        let modified = ensure_regular_metadata(path, meta)?;
        Ok(Self {
            len: meta.len(),
            modified,
            content_sha256: sha256_file_bytes(raw),
        })
    }

    fn from_path(path: &Path) -> Result<Self, ProxyError> {
        let _pre_meta = stat_regular_path(path)?;
        let file = open_chain_file_nonblocking(path).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("failed to open chain file '{}': {err}", path.display()),
            )
        })?;
        let (fd_meta, raw) = read_regular_open_file(path, file)?;
        Ok(Self::from_metadata_and_bytes(path, &fd_meta, &raw)?)
    }
}

impl FileFingerprint {
    #[cfg(unix)]
    fn from_metadata(path: &Path, meta: &Metadata) -> Result<Self, io::Error> {
        let modified = ensure_regular_metadata(path, meta)?;
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            len: meta.len(),
            modified,
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        })
    }

    #[cfg(not(unix))]
    fn from_metadata_and_bytes(
        path: &Path,
        meta: &Metadata,
        raw: &[u8],
    ) -> Result<Self, io::Error> {
        Ok(Self {
            content: ContentDigestFingerprint::from_metadata_and_bytes(path, meta, raw)?,
        })
    }

    fn from_path(path: &Path) -> Result<Self, ProxyError> {
        #[cfg(unix)]
        {
            let meta = stat_regular_path(path)?;
            Ok(Self::from_metadata(path, &meta)?)
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                content: ContentDigestFingerprint::from_path(path)?,
            })
        }
    }
}

fn fingerprint_paths(paths: &[PathBuf]) -> Result<Vec<FileFingerprint>, ProxyError> {
    let mut fps = Vec::with_capacity(paths.len());
    for path in paths {
        fps.push(FileFingerprint::from_path(path)?);
    }
    Ok(fps)
}

fn read_and_fingerprint_chain_file_with_hook<F>(
    path: &Path,
    on_after_read: F,
) -> Result<(SignedMandate, FileFingerprint), ProxyError>
where
    F: FnOnce(),
{
    let _pre_meta = stat_regular_path(path)?;
    let file = open_chain_file_nonblocking(path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to open chain file '{}': {err}", path.display()),
        )
    })?;
    let (fd_meta, raw) = read_regular_open_file(path, file)?;

    #[cfg(unix)]
    let fd_fp = FileFingerprint::from_metadata(path, &fd_meta)?;
    #[cfg(not(unix))]
    let fd_fp = FileFingerprint::from_metadata_and_bytes(path, &fd_meta, &raw)?;

    on_after_read();

    // Re-check path metadata after reading from the open fd to catch symlink swaps or in-place
    // rewrites racing with the read.
    let path_fp = FileFingerprint::from_path(path)?;
    if path_fp != fd_fp {
        return Err(ProxyError::InvalidChain(format!(
            "chain file '{}' changed while reading",
            path.display()
        )));
    }

    let source_label = path.display().to_string();
    let signed = parse_signed_mandate_json(&raw, &source_label)?;
    Ok((signed, fd_fp))
}

fn read_and_fingerprint_chain_file(
    path: &Path,
) -> Result<(SignedMandate, FileFingerprint), ProxyError> {
    read_and_fingerprint_chain_file_with_hook(path, || {})
}

fn load_and_verify_chain_atomic(
    paths: &[PathBuf],
    verifier: &dyn AnchorVerifier,
    expected_actor_key: &KeyId,
) -> Result<(Vec<VerifiedMandate>, Vec<FileFingerprint>), ProxyError> {
    let mut signed = Vec::with_capacity(paths.len());
    let mut fingerprints = Vec::with_capacity(paths.len());
    for path in paths {
        let (envelope, fp) = read_and_fingerprint_chain_file(path)?;
        signed.push(envelope);
        fingerprints.push(fp);
    }

    let verified = verify_mandate_chain_with(verifier, &signed)?;
    let Some(leaf) = verified.last() else {
        return Err(ProxyError::InvalidChain(
            "reloaded mandate chain is empty".to_string(),
        ));
    };
    if leaf.ast.to().key() != expected_actor_key {
        return Err(ProxyError::InvalidChain(format!(
            "reloaded leaf mandate TO key '{}' does not match configured actor_key '{}'",
            leaf.ast.to().key(),
            expected_actor_key
        )));
    }

    // Verify no symlink swap or file replacement happened during cryptographic verification so
    // the cached fingerprint strictly matches the verified bytes currently bound at `paths`.
    let post_verify_fps = fingerprint_paths(paths)?;
    if post_verify_fps != fingerprints {
        return Err(ProxyError::InvalidChain(
            "mandate chain files changed during verification".to_string(),
        ));
    }

    Ok((verified, fingerprints))
}

/// Fail-closed hot-reloader watching on-disk `--chain` mandate files by fd-bound metadata
/// fingerprint.
///
/// Fast path: when all watched files keep identical `(dev, ino, mode, uid, gid, len, modified,
/// ctime)` metadata, zero file reads or cryptographic verifications occur.
///
/// Atomic & fail-closed invariant:
/// - Initial construction ([`ChainReloader::load_initial`]) and every subsequent reload open each
///   file once, capture `fstat` on the open descriptor, read bounded bytes from that exact handle,
///   verify `stat(path)` still matches the fd fingerprint, and cryptographically verify the chain
///   + leaf `TO == actor_key` BEFORE caching the fingerprint.
/// - Any failure clears `last_fingerprint` so callers never fall back to a stale chain.
pub struct ChainReloader {
    paths: Vec<PathBuf>,
    verifier: Box<dyn AnchorVerifier + Send>,
    last_fingerprint: Option<Vec<FileFingerprint>>,
}

impl std::fmt::Debug for ChainReloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainReloader")
            .field("paths", &self.paths)
            .field("healthy", &self.last_fingerprint.is_some())
            .finish_non_exhaustive()
    }
}

impl ChainReloader {
    /// Atomically loads, verifies, and fingerprints the initial on-disk mandate chain.
    ///
    /// Returns the verified chain paired with a [`ChainReloader`] whose baseline fingerprint is
    /// bound to the exact file descriptors just verified.
    pub fn load_initial<V: AnchorVerifier + Send + 'static>(
        paths: Vec<PathBuf>,
        verifier: V,
        expected_actor_key: &KeyId,
    ) -> Result<(Vec<VerifiedMandate>, Self), ProxyError> {
        if paths.is_empty() {
            return Err(ProxyError::InvalidChain(
                "chain reload paths must not be empty".to_string(),
            ));
        }
        expected_actor_key
            .validate()
            .map_err(|err| ProxyError::InvalidChain(format!("invalid actor_key: {err}")))?;
        let (verified, fingerprints) =
            load_and_verify_chain_atomic(&paths, &verifier, expected_actor_key)?;
        Ok((
            verified,
            Self {
                paths,
                verifier: Box::new(verifier),
                last_fingerprint: Some(fingerprints),
            },
        ))
    }

    /// Checks whether any watched chain file changed on disk and atomically reloads + verifies
    /// if needed.
    ///
    /// Returns:
    /// - `Ok(None)` when files are unchanged and the last reload succeeded (fast path).
    /// - `Ok(Some(chain))` when files changed and passed full fd-bound verification and
    ///   `actor_key` check.
    /// - `Err(detail)` when stat, open, read, symlink-swap check, JSON parse, signature/chain
    ///   verification, or `TO` key matching failed; clears `last_fingerprint` so callers never
    ///   fall back to a stale chain.
    pub(crate) fn reload_if_changed(
        &mut self,
        expected_actor_key: &KeyId,
    ) -> Result<Option<Vec<VerifiedMandate>>, String> {
        if let Some(cached) = self.last_fingerprint.as_ref() {
            match fingerprint_paths(&self.paths) {
                Ok(current) if &current == cached => return Ok(None),
                Ok(_) => {}
                Err(err) => {
                    self.last_fingerprint = None;
                    return Err(err.to_string());
                }
            }
        }
        match load_and_verify_chain_atomic(&self.paths, self.verifier.as_ref(), expected_actor_key)
        {
            Ok((verified, fingerprints)) => {
                self.last_fingerprint = Some(fingerprints);
                Ok(Some(verified))
            }
            Err(err) => {
                self.last_fingerprint = None;
                Err(err.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn nonblocking_open_never_blocks_on_fifo_and_rejects_via_fstat_and_pre_stat() {
        use std::process::Command;
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let fifo = dir.path().join("chain.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("invoke mkfifo");
        assert!(status.success(), "mkfifo must succeed");

        let fifo_clone = fifo.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let outcome =
                open_chain_file_nonblocking(&fifo_clone).map(|f| f.metadata().map(|m| m.is_file()));
            let _ = tx.send(outcome);
        });
        let opened = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("O_NONBLOCK open on writerless FIFO must never block")
            .expect("O_NONBLOCK open on FIFO should yield an fd")
            .expect("fstat on FIFO");
        assert!(!opened, "FIFO fstat must report !is_file()");

        let err = read_and_fingerprint_chain_file(&fifo).unwrap_err();
        assert!(
            matches!(err, ProxyError::Io(ref io_err) if io_err.to_string().contains("not a regular file")),
            "expected not a regular file Io error, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_read_fd_to_path_identity_check_rejects_mid_read_symlink_swap() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let target_a = dir.path().join("a.signed.json");
        let target_b = dir.path().join("b.signed.json");
        let link = dir.path().join("active.signed.json");
        let tmp_link = dir.path().join("active.link.tmp");

        fs::write(&target_a, b"{}").expect("write target a");
        fs::write(&target_b, b"{}").expect("write target b");
        std::os::unix::fs::symlink(&target_a, &link).expect("create symlink");

        let err = read_and_fingerprint_chain_file_with_hook(&link, || {
            std::os::unix::fs::symlink(&target_b, &tmp_link).expect("create temp symlink");
            fs::rename(&tmp_link, &link).expect("swap symlink");
        })
        .unwrap_err();

        assert!(
            matches!(err, ProxyError::InvalidChain(ref msg) if msg.contains("changed while reading")),
            "expected post-read fd-to-path identity mismatch, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_regular_open_file_rejects_pipe_fd_before_reading() {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // Child holds the write end of the pipe open for 5s; if `read_regular_open_file`
        // tried to read before checking `fstat(fd).is_file()`, this call would block for 5s.
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 5"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pipe writer");
        let stdout = child.stdout.take().expect("piped stdout");
        let pipe_file = File::from(OwnedFd::from(stdout));

        let started = Instant::now();
        let err = read_regular_open_file(Path::new("pipe-fd"), pipe_file).unwrap_err();
        let elapsed = started.elapsed();

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            matches!(
                err,
                ProxyError::Io(ref io_err)
                    if io_err.kind() == io::ErrorKind::InvalidInput
                        && io_err.to_string().contains("not a regular file")
            ),
            "expected pre-read InvalidInput regular-file rejection, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "pre-read fd guard must reject pipe immediately without reading, took {elapsed:?}"
        );
    }

    #[test]
    fn content_digest_fingerprint_detects_same_size_same_mtime_replacement() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("chain.signed.json");

        let initial_bytes = br#"{"version":1,"body":"aaaa"}"#;
        fs::write(&path, initial_bytes).expect("write initial");
        let fp1 = ContentDigestFingerprint::from_path(&path).expect("initial digest fingerprint");
        let meta1 = fs::metadata(&path).expect("stat initial");
        let fp1_from_fd =
            ContentDigestFingerprint::from_metadata_and_bytes(&path, &meta1, initial_bytes)
                .expect("fd-based digest fingerprint");
        assert_eq!(
            fp1, fp1_from_fd,
            "path and fd-based non-Unix content fingerprints must match for unchanged file"
        );

        fs::write(&path, br#"{"version":1,"body":"bbbb"}"#).expect("write replacement");
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for mtime restore")
            .set_modified(fp1.modified)
            .expect("restore identical mtime");

        let fp2 =
            ContentDigestFingerprint::from_path(&path).expect("replacement digest fingerprint");
        assert_eq!(fp1.len, fp2.len, "lengths must match");
        assert_eq!(fp1.modified, fp2.modified, "mtimes must match");
        assert_ne!(
            fp1.content_sha256, fp2.content_sha256,
            "content SHA-256 digest must differ on same-size same-mtime replacement"
        );
        assert_ne!(
            fp1, fp2,
            "ContentDigestFingerprint equality must detect same-size same-mtime replacement"
        );

        let dir_err = ContentDigestFingerprint::from_path(dir.path()).unwrap_err();
        assert!(
            matches!(dir_err, ProxyError::Io(ref io_err) if io_err.to_string().contains("not a regular file")),
            "non-Unix content fingerprint must reject non-regular path, got {dir_err:?}"
        );
    }
}
