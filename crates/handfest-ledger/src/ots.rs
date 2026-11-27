//! Zero-dependency OpenTimestamps (`ots`) [`CheckpointWitness`] adapter (opt-in feature
//! `witness-ots`).
//!
//! Anchors strictly the 32-byte canonical [`LedgerCheckpoint::checkpoint_digest`] via
//! `ots stamp <digest_file>` and verifies via `ots verify -f <digest_file> <ots_file>`, never
//! exposing receipt payloads to the `ots` binary or external calendars.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use handfest_core::ast::is_valid_timestamp;
use handfest_core::base64::encode_standard;

use crate::witness::{
    validate_and_decode_witness_proof, validate_witness_proof, CheckpointWitness, LedgerCheckpoint,
    WitnessError, WitnessProof,
};

/// Canonical witness kind identifier for OpenTimestamps proofs.
pub const OTS_WITNESS_KIND: &str = "ots";

/// Maximum accepted OpenTimestamps `.ots` proof size (1 MiB) to bound memory on corrupt inputs.
pub const MAX_OTS_PROOF_BYTES: usize = 1024 * 1024;

/// Standard 31-byte OpenTimestamps `.ots` proof file magic header.
pub const OTS_PROOF_MAGIC: &[u8] =
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Captured stdout and stderr from a successfully completed external witness command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Audited subprocess execution seam for external witness CLIs (such as `ots`).
///
/// Implementations must fail closed on spawn/I/O failures and non-zero exit statuses.
pub trait CommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, WitnessError>;
}

/// Production [`CommandRunner`] backed by [`std::process::Command`] with piped stdio.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<CommandOutput, WitnessError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| WitnessError::CommandIo {
                program: program.to_string(),
                detail: err.to_string(),
            })?;

        let mut child_stdin = child
            .stdin
            .take()
            .expect("child stdin was configured with Stdio::piped()");

        let (write_res, output_res) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || child_stdin.write_all(stdin));
            let output_res = child.wait_with_output();
            let write_res = writer.join().expect("stdin writer thread does not panic");
            (write_res, output_res)
        });

        let output = output_res.map_err(|err| WitnessError::CommandIo {
            program: program.to_string(),
            detail: err.to_string(),
        })?;

        if !output.status.success() {
            return Err(WitnessError::CommandFailed {
                program: program.to_string(),
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        if let Err(err) = write_res {
            return Err(WitnessError::CommandIo {
                program: program.to_string(),
                detail: err.to_string(),
            });
        }

        Ok(CommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

/// Zero-dependency OpenTimestamps witness adapter invoking `ots stamp` / `ots verify` over an
/// audited [`CommandRunner`] with strictly 32-byte digest temp files.
#[derive(Debug, Clone)]
pub struct OtsWitness<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    program: String,
    fixed_anchored_at: Option<i64>,
}

impl Default for OtsWitness<SystemCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

impl OtsWitness<SystemCommandRunner> {
    /// Creates an [`OtsWitness`] invoking `ots` via [`SystemCommandRunner`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_runner(SystemCommandRunner)
    }
}

impl<R: CommandRunner> OtsWitness<R> {
    /// Creates an [`OtsWitness`] backed by a custom [`CommandRunner`] (e.g. mock in tests).
    #[must_use]
    pub fn with_runner(runner: R) -> Self {
        Self {
            runner,
            program: "ots".to_string(),
            fixed_anchored_at: None,
        }
    }

    /// Overrides the `ots` binary name or path, rejecting empty or control-character strings.
    pub fn with_program(mut self, program: impl Into<String>) -> Result<Self, WitnessError> {
        let program = program.into();
        if program.is_empty() || program.bytes().any(|b| b.is_ascii_control()) {
            return Err(WitnessError::InvalidConfig(
                "ots program path must be non-empty without control characters".to_string(),
            ));
        }
        self.program = program;
        Ok(self)
    }

    /// Pins `WitnessProof::anchored_at` to a deterministic UTC Unix timestamp (validated against
    /// the RFC 3339 range), primarily for deterministic replay and testing.
    pub fn with_anchored_at(mut self, timestamp: i64) -> Result<Self, WitnessError> {
        if !is_valid_timestamp(timestamp) {
            return Err(WitnessError::InvalidConfig(format!(
                "anchored_at {timestamp} outside valid RFC 3339 range"
            )));
        }
        self.fixed_anchored_at = Some(timestamp);
        Ok(self)
    }

    fn resolve_anchored_at(&self) -> Result<i64, WitnessError> {
        if let Some(ts) = self.fixed_anchored_at {
            return Ok(ts);
        }
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                WitnessError::Backend(format!("system clock before Unix epoch: {err}"))
            })?;
        let ts = i64::try_from(dur.as_secs())
            .map_err(|_| WitnessError::Backend("system clock exceeds i64 range".to_string()))?;
        if !is_valid_timestamp(ts) {
            return Err(WitnessError::Backend(format!(
                "system clock timestamp {ts} outside valid RFC 3339 range"
            )));
        }
        Ok(ts)
    }
}

impl<R: CommandRunner> CheckpointWitness for OtsWitness<R> {
    fn witness_kind(&self) -> &str {
        OTS_WITNESS_KIND
    }

    fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
        cp.validate()?;
        let digest = cp.checkpoint_digest();
        let digest_hex = cp.checkpoint_digest_hex();

        let workdir = TempOtsDir::create()?;
        let digest_path = workdir.path().join("checkpoint.bin");
        let ots_path = workdir.path().join("checkpoint.bin.ots");
        write_0600(&digest_path, &digest)?;

        let digest_arg = path_to_utf8(&digest_path)?;
        self.runner
            .run(&self.program, &["stamp", digest_arg], &[])?;

        let ots_bytes = read_bounded_ots_file(&ots_path)?;
        let anchored_at = self.resolve_anchored_at()?;
        let proof = WitnessProof {
            witness_kind: OTS_WITNESS_KIND.to_string(),
            checkpoint_digest_hex: digest_hex,
            proof_bytes_b64: encode_standard(&ots_bytes),
            anchored_at,
        };
        validate_witness_proof(cp, &proof, OTS_WITNESS_KIND)?;
        Ok(proof)
    }

    fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError> {
        let ots_bytes = validate_and_decode_witness_proof(cp, proof, OTS_WITNESS_KIND)?;
        validate_ots_proof_bytes(&ots_bytes, "ots proof")?;

        let workdir = TempOtsDir::create()?;
        let digest_path = workdir.path().join("checkpoint.bin");
        let ots_path = workdir.path().join("checkpoint.bin.ots");
        write_0600(&digest_path, &cp.checkpoint_digest())?;
        write_0600(&ots_path, &ots_bytes)?;

        let digest_arg = path_to_utf8(&digest_path)?;
        let ots_arg = path_to_utf8(&ots_path)?;
        self.runner
            .run(&self.program, &["verify", "-f", digest_arg, ots_arg], &[])?;
        Ok(())
    }
}

struct TempOtsDir {
    path: PathBuf,
}

impl TempOtsDir {
    fn create() -> Result<Self, WitnessError> {
        let base = std::env::temp_dir();
        Self::create_in(&base)
    }

    fn create_in(base: &Path) -> Result<Self, WitnessError> {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        for attempt in 0..64u32 {
            let seq = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = base.join(format!("handfest-ots-{pid}-{nanos}-{seq}-{attempt}"));
            match create_private_dir(&dir) {
                Ok(()) => {
                    let canonical = fs::canonicalize(&dir).map_err(|err| {
                        let _ = fs::remove_dir_all(&dir);
                        WitnessError::TempFileIo(format!(
                            "canonicalize temp dir '{}': {err}",
                            dir.display()
                        ))
                    })?;
                    let guard = Self { path: canonical };
                    let _ = path_to_utf8(&guard.path)?;
                    return Ok(guard);
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(WitnessError::TempFileIo(format!(
                        "create temp dir '{}': {err}",
                        dir.display()
                    )));
                }
            }
        }
        Err(WitnessError::TempFileIo(
            "failed to allocate unique temp directory after 64 attempts".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempOtsDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), WitnessError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|err| WitnessError::TempFileIo(format!("create '{}': {err}", path.display())))?;
    file.write_all(bytes)
        .map_err(|err| WitnessError::TempFileIo(format!("write '{}': {err}", path.display())))?;
    file.flush()
        .map_err(|err| WitnessError::TempFileIo(format!("flush '{}': {err}", path.display())))?;
    Ok(())
}

fn validate_ots_proof_bytes(bytes: &[u8], context: &str) -> Result<(), WitnessError> {
    if bytes.is_empty() {
        return Err(WitnessError::InvalidProof(format!("{context} is empty")));
    }
    if bytes.len() > MAX_OTS_PROOF_BYTES {
        return Err(WitnessError::InvalidProof(format!(
            "{context} exceeds maximum size of {MAX_OTS_PROOF_BYTES} bytes"
        )));
    }
    if !bytes.starts_with(OTS_PROOF_MAGIC) {
        return Err(WitnessError::InvalidProof(format!(
            "{context} does not start with OpenTimestamps proof magic header"
        )));
    }
    let min_len = OTS_PROOF_MAGIC.len() + 34;
    if bytes.len() < min_len {
        return Err(WitnessError::InvalidProof(format!(
            "{context} is truncated: expected at least {min_len} bytes (magic + version + hash-op + 32-byte digest + attestation), got {} bytes",
            bytes.len()
        )));
    }
    Ok(())
}

fn read_bounded_ots_file(path: &Path) -> Result<Vec<u8>, WitnessError> {
    let file = crate::preflight_open::open_no_follow_read_only(path).map_err(|err| {
        WitnessError::Backend(format!(
            "ots did not produce expected proof file '{}': {err}",
            path.display()
        ))
    })?;
    let meta = file
        .metadata()
        .map_err(|err| WitnessError::TempFileIo(format!("fstat '{}': {err}", path.display())))?;
    if !meta.is_file() {
        return Err(WitnessError::InvalidProof(format!(
            "ots proof file '{}' must be a regular file",
            path.display()
        )));
    }
    let mut out = Vec::new();
    let limit = u64::try_from(MAX_OTS_PROOF_BYTES + 1).expect("MAX_OTS_PROOF_BYTES fits in u64");
    file.take(limit)
        .read_to_end(&mut out)
        .map_err(|err| WitnessError::TempFileIo(format!("read '{}': {err}", path.display())))?;
    validate_ots_proof_bytes(&out, &format!("ots proof file '{}'", path.display()))?;
    Ok(out)
}

fn path_to_utf8(path: &Path) -> Result<&str, WitnessError> {
    if !path.is_absolute() {
        return Err(WitnessError::TempFileIo(format!(
            "temporary path '{}' must be absolute",
            path.display()
        )));
    }
    let text = path.to_str().ok_or_else(|| {
        WitnessError::TempFileIo(format!(
            "temporary path '{}' is not valid UTF-8",
            path.display()
        ))
    })?;
    if text.starts_with('-') || text.bytes().any(|b| b.is_ascii_control()) {
        return Err(WitnessError::TempFileIo(format!(
            "temporary path '{text}' is unsafe for subprocess arguments"
        )));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_ots_dir_canonicalizes_dash_prefixed_relative_base_dir() {
        let holder = tempfile::TempDir::new().unwrap();
        let dash_base = holder.path().join("-v");
        fs::create_dir(&dash_base).unwrap();

        let dir = TempOtsDir::create_in(&dash_base).unwrap();
        let arg = path_to_utf8(dir.path()).unwrap();
        assert!(
            Path::new(arg).is_absolute(),
            "expected absolute path, got {arg}"
        );
        assert!(!arg.starts_with('-'), "arg must not start with '-': {arg}");

        assert!(matches!(
            path_to_utf8(Path::new("-v/checkpoint.bin")),
            Err(WitnessError::TempFileIo(_))
        ));
        assert!(matches!(
            path_to_utf8(Path::new("relative/checkpoint.bin")),
            Err(WitnessError::TempFileIo(_))
        ));
    }
}
