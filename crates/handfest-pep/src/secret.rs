//! Fail-closed, redacted broker credential loading outside agent-writable workspaces.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use handfest_core::ast::is_valid_quoted_str;
use handfest_core::exact_json::{reject_unknown_keys, ExactJson};

use serde::{Deserialize, Serialize};

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

/// Opaque wrapper for a loaded secret string.
///
/// Deliberately redacts its value in [`fmt::Debug`] and does not implement [`fmt::Display`] or
/// [`Serialize`] so secrets cannot be accidentally logged or serialized into receipts.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Borrows the raw secret string for narrow credential injection (e.g. HTTP header or child
    /// process environment).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Errors returned when loading a [`CredentialSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    Io(String),
    InvalidPath(String),
    SymlinkRejected(PathBuf),
    InsecurePermissions { path: PathBuf, mode: u32 },
    InvalidEnvVarName(String),
    MissingEnvVar(String),
    EmptySecret(String),
    InvalidSecretValue(String),
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "failed to read credential source: {msg}"),
            Self::InvalidPath(msg) => write!(f, "invalid credential file path: {msg}"),
            Self::SymlinkRejected(path) => {
                write!(
                    f,
                    "credential file '{}' must not be a symlink or traverse a symlinked directory",
                    path.display()
                )
            }
            Self::InsecurePermissions { path, mode } => write!(
                f,
                "credential file '{}' has insecure permissions {mode:04o}; expected owner-only (0600 or 0400)",
                path.display()
            ),
            Self::InvalidEnvVarName(var) => {
                write!(f, "invalid credential environment variable name '{var}'")
            }
            Self::MissingEnvVar(var) => {
                write!(f, "credential environment variable '{var}' is not set")
            }
            Self::EmptySecret(src) => write!(f, "credential from {src} is empty"),
            Self::InvalidSecretValue(src) => {
                write!(
                    f,
                    "credential from {src} contains control characters or embedded newlines"
                )
            }
        }
    }
}

impl std::error::Error for SecretError {}

/// Declarative source for an operator-held credential injected by a PEP only on `Permit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialSource {
    /// Reads a UTF-8 secret from an owner-only (`0600`/`0400`), non-symlink file on disk.
    File { path: PathBuf },
    /// Reads a UTF-8 secret from the broker process's own environment.
    Env { var: String },
}

impl CredentialSource {
    /// Validates static credential source invariants without performing I/O.
    ///
    /// - [`Self::File`]: path must be valid UTF-8, non-empty, free of control characters,
    ///   absolute, and contain no `..` parent-directory components.
    /// - [`Self::Env`]: variable name must satisfy [`is_valid_env_var_name`].
    pub fn validate(&self) -> Result<(), SecretError> {
        match self {
            Self::File { path } => validate_absolute_clean_path(path, "credential file")
                .map_err(SecretError::InvalidPath),
            Self::Env { var } => {
                if !is_valid_env_var_name(var) {
                    return Err(SecretError::InvalidEnvVarName(var.clone()));
                }
                Ok(())
            }
        }
    }

    /// Loads and validates the secret fail-closed.
    pub fn load(&self) -> Result<SecretString, SecretError> {
        self.validate()?;
        match self {
            Self::File { path } => load_secret_file(path),
            Self::Env { var } => load_secret_env(var),
        }
    }
}

/// Validates that `path` is valid UTF-8, non-empty, free of control characters, absolute, and
/// contains no `..` parent-directory components.
pub fn validate_absolute_clean_path(path: &Path, context: &str) -> Result<(), String> {
    let Some(raw) = path.to_str() else {
        return Err(format!("{context} path must be valid UTF-8"));
    };
    if raw.is_empty() || !is_valid_quoted_str(raw) {
        return Err(format!(
            "{context} path must be non-empty and contain no control characters"
        ));
    }
    if !path.is_absolute() {
        return Err(format!("{context} path '{raw}' must be absolute"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "{context} path '{raw}' must not contain '..' components"
        ));
    }
    Ok(())
}

/// Decodes a [`CredentialSource`] from a duplicate-checked [`ExactJson`] object (`file` or `env`).
pub fn decode_credential_source(
    val: &ExactJson,
    context: &str,
) -> Result<CredentialSource, String> {
    let obj = val
        .as_object()
        .ok_or_else(|| format!("{context}: expected JSON object"))?;
    let mut iter = obj.iter();
    let (Some((tag, inner)), None) = (iter.next(), iter.next()) else {
        return Err(format!(
            "{context}: expected single-key JSON object ('file' or 'env')"
        ));
    };
    let inner_ctx = format!("{context}.{tag}");
    let inner_obj = inner
        .as_object()
        .ok_or_else(|| format!("{inner_ctx}: expected JSON object"))?;
    match tag.as_str() {
        "file" => {
            reject_unknown_keys(inner_obj, &["path"], &inner_ctx).map_err(|err| err.to_string())?;
            let path = expect_json_str(inner_obj, "path", &inner_ctx)?;
            Ok(CredentialSource::File {
                path: PathBuf::from(path),
            })
        }
        "env" => {
            reject_unknown_keys(inner_obj, &["var"], &inner_ctx).map_err(|err| err.to_string())?;
            let var = expect_json_str(inner_obj, "var", &inner_ctx)?;
            Ok(CredentialSource::Env { var })
        }
        other => Err(format!("{context}: unknown credential source '{other}'")),
    }
}

fn expect_json_str(
    obj: &BTreeMap<String, ExactJson>,
    key: &str,
    ctx: &str,
) -> Result<String, String> {
    let val = obj
        .get(key)
        .ok_or_else(|| format!("{ctx}: missing required field '{key}'"))?;
    val.as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{ctx}.{key}: expected JSON string"))
}

fn check_no_symlink_ancestors_and_leaf(path: &Path) -> Result<fs::Metadata, SecretError> {
    let mut prefix = PathBuf::new();
    let mut leaf_meta = None;
    for comp in path.components() {
        prefix.push(comp);
        let meta = fs::symlink_metadata(&prefix)
            .map_err(|err| SecretError::Io(format!("'{}': {err}", prefix.display())))?;
        if meta.file_type().is_symlink() {
            return Err(SecretError::SymlinkRejected(prefix));
        }
        leaf_meta = Some(meta);
    }
    leaf_meta.ok_or_else(|| SecretError::InvalidPath("path must not be empty".to_string()))
}

#[cfg(unix)]
fn check_unix_secret_mode(path: &Path, meta: &fs::Metadata) -> Result<(), SecretError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o7777;
    if !matches!(mode, 0o400 | 0o600) {
        return Err(SecretError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

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

fn open_secret_file_nonblocking(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(combine_unix_open_flags(UNIX_O_NOFOLLOW, UNIX_O_NONBLOCK));
    }
    opts.open(path)
}

fn verify_opened_secret_file(
    path: &Path,
    leaf_meta: &fs::Metadata,
    file: &fs::File,
) -> Result<(), SecretError> {
    let opened_meta = file
        .metadata()
        .map_err(|err| SecretError::Io(format!("'{}': {err}", path.display())))?;
    if !opened_meta.is_file() {
        return Err(SecretError::Io(format!(
            "'{}': credential source must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_meta.dev() != leaf_meta.dev() || opened_meta.ino() != leaf_meta.ino() {
            return Err(SecretError::Io(format!(
                "'{}': credential file changed concurrently during open",
                path.display()
            )));
        }
        check_unix_secret_mode(path, &opened_meta)?;
    }
    #[cfg(not(unix))]
    let _ = leaf_meta;
    Ok(())
}

fn load_secret_file(path: &Path) -> Result<SecretString, SecretError> {
    let leaf_meta = check_no_symlink_ancestors_and_leaf(path)?;
    if !leaf_meta.is_file() {
        return Err(SecretError::Io(format!(
            "'{}': credential source must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    check_unix_secret_mode(path, &leaf_meta)?;

    let file = open_secret_file_nonblocking(path)
        .map_err(|err| SecretError::Io(format!("'{}': {err}", path.display())))?;
    verify_opened_secret_file(path, &leaf_meta, &file)?;

    let mut raw_bytes = Vec::new();
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut raw_bytes)
        .map_err(|err| SecretError::Io(format!("'{}': {err}", path.display())))?;
    if raw_bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(SecretError::Io(format!(
            "'{}': credential file exceeds maximum size of {MAX_SECRET_FILE_BYTES} bytes",
            path.display()
        )));
    }
    let raw = String::from_utf8(raw_bytes)
        .map_err(|err| SecretError::Io(format!("'{}': invalid UTF-8: {err}", path.display())))?;
    let trimmed = strip_single_trailing_newline(&raw);
    validate_secret_value(trimmed, &format!("file '{}'", path.display()))
}

fn load_secret_env(var: &str) -> Result<SecretString, SecretError> {
    let val = std::env::var(var).map_err(|_| SecretError::MissingEnvVar(var.to_string()))?;
    validate_secret_value(&val, &format!("env '{var}'"))
}

/// Returns `true` if `var` is a valid ASCII POSIX environment variable identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`).
#[must_use]
pub fn is_valid_env_var_name(var: &str) -> bool {
    let mut bytes = var.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn strip_single_trailing_newline(raw: &str) -> &str {
    if let Some(stripped) = raw.strip_suffix("\r\n") {
        stripped
    } else if let Some(stripped) = raw.strip_suffix('\n') {
        stripped
    } else {
        raw
    }
}

fn validate_secret_value(value: &str, source_desc: &str) -> Result<SecretString, SecretError> {
    if value.is_empty() {
        return Err(SecretError::EmptySecret(source_desc.to_string()));
    }
    if value.chars().any(char::is_control) {
        return Err(SecretError::InvalidSecretValue(source_desc.to_string()));
    }
    Ok(SecretString(value.to_string()))
}

#[cfg(all(test, unix))]
mod unix_open_tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn nonblocking_no_follow_open_rejects_symlinks_and_never_blocks_on_fifo() {
        assert_ne!(
            combine_unix_open_flags(UNIX_O_NOFOLLOW, UNIX_O_NONBLOCK),
            0,
            "expected non-zero O_NOFOLLOW | O_NONBLOCK flags on Unix"
        );
        let dir = std::env::temp_dir().join(format!(
            "handfest-pep-secret-open-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");

        let reg = dir.join("token.secret");
        fs::write(&reg, "secret-value\n").expect("write regular");
        fs::set_permissions(&reg, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        let file = open_secret_file_nonblocking(&reg).expect("regular file must open");
        assert!(file.metadata().expect("fstat").is_file());

        let link = dir.join("link.secret");
        symlink(&reg, &link).expect("create symlink");
        let err = open_secret_file_nonblocking(&link)
            .expect_err("O_NOFOLLOW must reject direct symlink open");
        assert!(
            err.raw_os_error().is_some(),
            "expected OS error from O_NOFOLLOW, got {err}"
        );

        let fifo = dir.join("toctou.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("invoke mkfifo");
        assert!(status.success(), "mkfifo must succeed");
        let fifo_clone = fifo.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let res = open_secret_file_nonblocking(&fifo_clone)
                .map(|f| f.metadata().map(|m| m.is_file()));
            let _ = tx.send(res);
        });
        let outcome = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("O_NONBLOCK open on writerless FIFO must never block");
        let is_file = outcome
            .expect("O_NONBLOCK open on FIFO should return fd")
            .expect("fstat on FIFO");
        assert!(!is_file, "FIFO fstat must report !is_file()");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_open_fstat_verification_rejects_mode_widening_inode_swap_and_fifo() {
        let dir = std::env::temp_dir().join(format!(
            "handfest-pep-secret-post-open-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");

        let reg = dir.join("token.secret");
        fs::write(&reg, "secret-value\n").expect("write regular");
        fs::set_permissions(&reg, fs::Permissions::from_mode(0o600)).expect("chmod 0600");

        let leaf_meta = fs::symlink_metadata(&reg).expect("lstat");
        let file = open_secret_file_nonblocking(&reg).expect("open regular");
        verify_opened_secret_file(&reg, &leaf_meta, &file)
            .expect("0600 file matching lstat must pass post-open verification");

        // Widen permissions on the SAME inode after lstat: post-open fstat mode check must reject.
        fs::set_permissions(&reg, fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        let mode_err = verify_opened_secret_file(&reg, &leaf_meta, &file)
            .expect_err("post-open fstat must reject 0644 mode widening");
        assert_eq!(
            mode_err,
            SecretError::InsecurePermissions {
                path: reg.clone(),
                mode: 0o644,
            }
        );

        // Opening a distinct 0600 inode against reg's lstat must fail the dev/ino identity check.
        let other = dir.join("other.secret");
        fs::write(&other, "other-secret\n").expect("write other");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).expect("chmod other 0600");
        let other_file = open_secret_file_nonblocking(&other).expect("open other");
        let swap_err = verify_opened_secret_file(&reg, &leaf_meta, &other_file)
            .expect_err("post-open dev/ino check must reject swapped inode");
        assert!(
            matches!(swap_err, SecretError::Io(ref msg) if msg.contains("changed concurrently")),
            "expected concurrent swap error, got {swap_err:?}"
        );

        // Opening a FIFO fd against reg's lstat must fail the post-open regular-file check.
        let fifo = dir.join("post_open.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("invoke mkfifo");
        assert!(status.success(), "mkfifo must succeed");
        let (tx, rx) = mpsc::channel();
        let fifo_clone = fifo.clone();
        let reg_clone = reg.clone();
        let handle = std::thread::spawn(move || {
            let fifo_file =
                open_secret_file_nonblocking(&fifo_clone).expect("open FIFO nonblocking");
            let err = verify_opened_secret_file(&reg_clone, &leaf_meta, &fifo_file)
                .expect_err("post-open fstat must reject non-regular FIFO fd");
            let _ = tx.send(err);
        });
        let fifo_err = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("nonblocking FIFO open/verify must complete within 2s without hanging");
        handle.join().expect("FIFO test thread must not panic");
        assert!(
            matches!(fifo_err, SecretError::Io(ref msg) if msg.contains("regular file")),
            "expected regular file error, got {fifo_err:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
