//! YubiKey PIV smartcard Ed25519 (`piv-ed25519`, slot `9c`) signer and pure-Rust verifier.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use handfest_core::ast::KeyId;
use handfest_core::gate::VerifiedMandate;
use rand_core::{OsRng, RngCore};

use crate::{
    verify_ed25519_for_scheme, AnchorError, AnchorVerifier, AssuranceLevel, CommandRunner,
    MandateSigner, SignedMandate, SystemCommandRunner,
};

/// Canonical `KeyId` scheme for YubiKey PIV Ed25519 smartcard keys.
pub const PIV_ED25519_SCHEME: &str = "piv-ed25519";

/// Default OpenSC / Yubico PKCS#11 shared library path on Debian/Ubuntu Linux.
pub const DEFAULT_PKCS11_MODULE: &str = "/usr/lib/x86_64-linux-gnu/libykcs11.so";

/// Default PKCS#11 object ID corresponding to YubiKey PIV slot `9c` (Digital Signature).
pub const DEFAULT_PIV_KEY_ID: &str = "02";

/// Default environment variable consulted by the CLI for a PIV token PIN.
pub const DEFAULT_PIV_PIN_ENV: &str = "HANDFEST_PIV_PIN";

/// Exact 12-byte RFC 8410 DER SubjectPublicKeyInfo (SPKI) prefix for Ed25519 public keys.
pub const ED25519_SPKI_DER_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const ED25519_SPKI_DER_LEN: usize = ED25519_SPKI_DER_PREFIX.len() + 32;
const PEM_PUBLIC_KEY_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_PUBLIC_KEY_END: &str = "-----END PUBLIC KEY-----";
const PKCS11_TOOL_PROGRAM: &str = "pkcs11-tool";

/// Derives the canonical `piv-ed25519:<64-lowercase-hex>` [`KeyId`] from raw 32-byte Ed25519
/// public key bytes.
#[must_use]
pub fn piv_ed25519_key_id(public_key: &[u8; 32]) -> KeyId {
    let pub_hex = hex::encode(public_key);
    KeyId::new(PIV_ED25519_SCHEME, pub_hex)
        .expect("hex-encoded piv-ed25519 key is always a valid KeyId")
}

/// Pure-Rust YubiKey PIV Ed25519 trust-anchor verifier (`AssuranceLevel::Passkey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct PivEd25519Verifier;

impl AnchorVerifier for PivEd25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_piv_ed25519(signed)
    }
}

/// Verifies a single PIV Ed25519 (`piv-ed25519:<hex>`) [`SignedMandate`] envelope and returns a
/// [`VerifiedMandate`] with [`AssuranceLevel::Passkey`].
pub fn verify_piv_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    verify_ed25519_for_scheme(signed, PIV_ED25519_SCHEME, AssuranceLevel::Passkey)
}

/// Parses a strict RFC 8410 Ed25519 SubjectPublicKeyInfo (SPKI) DER byte slice into a raw
/// 32-byte Ed25519 public key.
pub fn parse_ed25519_spki_der(der: &[u8]) -> Result<[u8; 32], AnchorError> {
    if der.len() != ED25519_SPKI_DER_LEN {
        return Err(AnchorError::InvalidPublicKey(format!(
            "expected {ED25519_SPKI_DER_LEN}-byte RFC 8410 Ed25519 SPKI DER, got {} bytes",
            der.len()
        )));
    }
    if der[..ED25519_SPKI_DER_PREFIX.len()] != ED25519_SPKI_DER_PREFIX {
        return Err(AnchorError::InvalidPublicKey(
            "invalid RFC 8410 Ed25519 SPKI DER header or OID".to_string(),
        ));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[ED25519_SPKI_DER_PREFIX.len()..]);
    let _ = VerifyingKey::from_bytes(&raw).map_err(|err| {
        AnchorError::InvalidPublicKey(format!("invalid Ed25519 public key point: {err}"))
    })?;
    Ok(raw)
}

/// Parses a strict PEM-encoded RFC 8410 Ed25519 SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`)
/// into a raw 32-byte Ed25519 public key.
pub fn parse_ed25519_spki_pem(pem: &str) -> Result<[u8; 32], AnchorError> {
    let lines = split_pem_lines(pem)?;
    let first = lines.first().copied().unwrap_or_default();
    let last = lines.last().copied().unwrap_or_default();
    if lines.len() < 3 || first != PEM_PUBLIC_KEY_BEGIN || last != PEM_PUBLIC_KEY_END {
        return Err(AnchorError::InvalidPublicKey(
            "expected PEM block delimited by -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----"
                .to_string(),
        ));
    }

    let mut b64 = String::new();
    for line in &lines[1..lines.len() - 1] {
        if line.is_empty() {
            return Err(AnchorError::InvalidPublicKey(
                "unexpected empty line inside PEM body".to_string(),
            ));
        }
        b64.push_str(line);
    }

    let der = decode_base64_strict(b64.as_bytes()).map_err(AnchorError::InvalidPublicKey)?;
    parse_ed25519_spki_der(&der)
}

fn split_pem_lines(pem: &str) -> Result<Vec<&str>, AnchorError> {
    if pem.ends_with('\r') {
        return Err(AnchorError::InvalidPublicKey(
            "PEM input contains bare carriage return".to_string(),
        ));
    }
    let mut lines = Vec::new();
    for raw_line in pem.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.contains('\r') {
            return Err(AnchorError::InvalidPublicKey(
                "PEM input contains bare carriage return".to_string(),
            ));
        }
        lines.push(line);
    }
    while lines.first().is_some_and(|line| line.is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    Ok(lines)
}

fn decode_base64_char(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(format!("invalid base64 byte 0x{byte:02x}")),
    }
}

fn decode_base64_strict(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return Err(format!(
            "base64 length {} must be a positive multiple of 4",
            input.len()
        ));
    }
    let chunk_count = input.len() / 4;
    let mut out = Vec::with_capacity(chunk_count * 3);
    for (idx, chunk) in input.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == chunk_count;
        decode_base64_quartet(chunk, is_last, &mut out)?;
    }
    Ok(out)
}

fn decode_base64_quartet(chunk: &[u8; 4], is_last: bool, out: &mut Vec<u8>) -> Result<(), String> {
    let a = decode_base64_char(chunk[0])?;
    let b = decode_base64_char(chunk[1])?;
    match (chunk[2], chunk[3]) {
        (b'=', b'=') if is_last => {
            if b & 0x0f != 0 {
                return Err("non-canonical base64 padding bits".to_string());
            }
            out.push((a << 2) | (b >> 4));
            Ok(())
        }
        (c_byte, b'=') if is_last => {
            let c = decode_base64_char(c_byte)?;
            if c & 0x03 != 0 {
                return Err("non-canonical base64 padding bits".to_string());
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
            Ok(())
        }
        (b'=', _) | (_, b'=') => Err("misplaced base64 padding".to_string()),
        (c_byte, d_byte) => {
            let c = decode_base64_char(c_byte)?;
            let d = decode_base64_char(d_byte)?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
            out.push((c << 6) | d);
            Ok(())
        }
    }
}

/// How `pkcs11-tool` authenticates to the PIV token during signing.
///
/// PIN values are never passed on `argv` where other local processes can inspect them via `ps`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PivPinSource {
    /// Prompt interactively via `--login` (no `--pin` argument).
    #[default]
    Interactive,
    /// Read the PIN from an environment variable via `--login --pin env:<VAR>`.
    EnvVar(String),
}

/// Validated configuration for [`PivEd25519Signer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivSignerConfig {
    pub pkcs11_module: String,
    pub key_id: String,
    pub pin_source: PivPinSource,
}

impl Default for PivSignerConfig {
    fn default() -> Self {
        Self {
            pkcs11_module: DEFAULT_PKCS11_MODULE.to_string(),
            key_id: DEFAULT_PIV_KEY_ID.to_string(),
            pin_source: PivPinSource::Interactive,
        }
    }
}

/// Hardware-backed YubiKey PIV Ed25519 signer delegating `EDDSA` signing to `pkcs11-tool`
/// through an injectable [`CommandRunner`].
#[derive(Clone)]
pub struct PivEd25519Signer<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    config: PivSignerConfig,
    public_key: [u8; 32],
}

impl<R: CommandRunner> std::fmt::Debug for PivEd25519Signer<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PivEd25519Signer")
            .field("key_id", &self.key_id().to_string())
            .field("config", &self.config)
            .finish()
    }
}

impl<R: CommandRunner> PivEd25519Signer<R> {
    /// Constructs a validated PIV Ed25519 signer from raw 32-byte public key bytes.
    pub fn new(
        runner: R,
        config: PivSignerConfig,
        public_key: [u8; 32],
    ) -> Result<Self, AnchorError> {
        validate_piv_config(&config)?;
        let _ = VerifyingKey::from_bytes(&public_key).map_err(|err| {
            AnchorError::InvalidPublicKey(format!("invalid Ed25519 public key point: {err}"))
        })?;
        Ok(Self {
            runner,
            config,
            public_key,
        })
    }

    /// Constructs a validated PIV Ed25519 signer by parsing an RFC 8410 SPKI PEM public key.
    pub fn from_spki_pem(
        runner: R,
        config: PivSignerConfig,
        pem: &str,
    ) -> Result<Self, AnchorError> {
        let public_key = parse_ed25519_spki_pem(pem)?;
        Self::new(runner, config, public_key)
    }

    /// Returns the raw 32-byte Ed25519 public key configured for this signer.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the validated PKCS#11 configuration.
    #[must_use]
    pub fn config(&self) -> &PivSignerConfig {
        &self.config
    }

    /// Derives the canonical `piv-ed25519:<64-lowercase-hex>` [`KeyId`].
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        piv_ed25519_key_id(&self.public_key)
    }
}

impl<R: CommandRunner> MandateSigner for PivEd25519Signer<R> {
    fn key_id(&self) -> KeyId {
        PivEd25519Signer::key_id(self)
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let temp_dir = PrivateTempDir::create_in(&std::env::temp_dir())?;
        let payload_path = temp_dir.path().join("payload.bin");
        let sig_path = temp_dir.path().join("signature.bin");
        create_private_file(&payload_path, Some(payload))?;
        create_private_file(&sig_path, None)?;

        let payload_arg = path_as_utf8(&payload_path)?;
        let sig_arg = path_as_utf8(&sig_path)?;
        let pin_arg = match &self.config.pin_source {
            PivPinSource::Interactive => None,
            PivPinSource::EnvVar(var) => Some(format!("env:{var}")),
        };

        let mut args = vec!["--module", self.config.pkcs11_module.as_str(), "--login"];
        if let Some(pin) = pin_arg.as_deref() {
            args.push("--pin");
            args.push(pin);
        }
        args.extend([
            "--sign",
            "--mechanism",
            "EDDSA",
            "--id",
            self.config.key_id.as_str(),
            "--input-file",
            payload_arg,
            "--output-file",
            sig_arg,
        ]);

        let _ = self.runner.run(PKCS11_TOOL_PROGRAM, &args, &[])?;

        let sig_bytes = fs::read(&sig_path).map_err(|err| AnchorError::CommandIo {
            program: PKCS11_TOOL_PROGRAM.to_string(),
            detail: format!("failed to read signature output: {err}"),
        })?;
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            AnchorError::InvalidSignature(format!(
                "{PKCS11_TOOL_PROGRAM} produced {} signature bytes, expected 64",
                sig_bytes.len()
            ))
        })?;

        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .expect("public key was validated during PivEd25519Signer::new");
        let signature = Signature::from_bytes(&sig_array);
        verifying_key
            .verify_strict(payload, &signature)
            .map_err(|err| {
                AnchorError::InvalidSignature(format!(
                    "{PKCS11_TOOL_PROGRAM} signature failed verification against configured PIV public key: {err}"
                ))
            })?;

        Ok(sig_bytes)
    }
}

fn validate_piv_config(config: &PivSignerConfig) -> Result<(), AnchorError> {
    validate_module_path(&config.pkcs11_module)?;
    validate_piv_key_id(&config.key_id)?;
    validate_pin_source(&config.pin_source)?;
    Ok(())
}

fn validate_module_path(path: &str) -> Result<(), AnchorError> {
    if path.trim().is_empty() {
        return Err(AnchorError::InvalidConfig(
            "pkcs11_module path must not be empty".to_string(),
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(AnchorError::InvalidConfig(
            "pkcs11_module path must not contain control characters".to_string(),
        ));
    }
    if path.starts_with('-') {
        return Err(AnchorError::InvalidConfig(
            "pkcs11_module path must not start with '-'".to_string(),
        ));
    }
    Ok(())
}

fn validate_piv_key_id(key_id: &str) -> Result<(), AnchorError> {
    if key_id.is_empty() || key_id.len() > 64 || !key_id.len().is_multiple_of(2) {
        return Err(AnchorError::InvalidConfig(format!(
            "PIV key id '{key_id}' must be an even-length hex string (2..=64 chars)"
        )));
    }
    if !key_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AnchorError::InvalidConfig(format!(
            "PIV key id '{key_id}' must contain ASCII hex digits only"
        )));
    }
    Ok(())
}

fn validate_pin_source(pin_source: &PivPinSource) -> Result<(), AnchorError> {
    match pin_source {
        PivPinSource::Interactive => Ok(()),
        PivPinSource::EnvVar(var) => {
            let mut bytes = var.bytes();
            let valid = bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
                && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !valid {
                return Err(AnchorError::InvalidConfig(format!(
                    "PIV PIN env var '{var}' must be a valid identifier ([A-Za-z_][A-Za-z0-9_]*)"
                )));
            }
            Ok(())
        }
    }
}

fn path_as_utf8(path: &Path) -> Result<&str, AnchorError> {
    path.to_str().ok_or_else(|| AnchorError::CommandIo {
        program: PKCS11_TOOL_PROGRAM.to_string(),
        detail: "temporary path is not valid UTF-8".to_string(),
    })
}

struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    fn create_in(base: &Path) -> Result<Self, AnchorError> {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let dir_name = format!("handfest-piv-{}-{}", std::process::id(), hex::encode(nonce));
        let path = base.join(dir_name);
        create_private_dir(&path).map_err(|err| AnchorError::CommandIo {
            program: PKCS11_TOOL_PROGRAM.to_string(),
            detail: format!(
                "failed to create private temp dir '{}': {err}",
                path.display()
            ),
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_private_file(path: &Path, contents: Option<&[u8]>) -> Result<(), AnchorError> {
    let io_res = (|| -> std::io::Result<()> {
        let mut file = open_new_private_file(path)?;
        if let Some(bytes) = contents {
            file.write_all(bytes)?;
        }
        Ok(())
    })();
    io_res.map_err(|err| AnchorError::CommandIo {
        program: PKCS11_TOOL_PROGRAM.to_string(),
        detail: format!("failed to prepare temp file '{}': {err}", path.display()),
    })
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn open_new_private_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_new_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piv_signer_debug_and_temp_helpers_cover_error_paths() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]);
        let pk = sk.verifying_key().to_bytes();
        let signer =
            PivEd25519Signer::new(SystemCommandRunner, PivSignerConfig::default(), pk).unwrap();
        let dbg = format!("{signer:?}");
        assert!(dbg.contains("PivEd25519Signer"));
        assert!(dbg.contains(PIV_ED25519_SCHEME));

        let missing_parent = Path::new("/nonexistent-handfest-piv-parent-dir-xyz");
        assert!(matches!(
            PrivateTempDir::create_in(missing_parent),
            Err(AnchorError::CommandIo { program, detail })
                if program == PKCS11_TOOL_PROGRAM && detail.contains("private temp dir")
        ));
        assert!(matches!(
            create_private_file(&missing_parent.join("payload.bin"), Some(b"x")),
            Err(AnchorError::CommandIo { program, detail })
                if program == PKCS11_TOOL_PROGRAM && detail.contains("prepare temp file")
        ));

        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = Path::new(OsStr::from_bytes(b"/tmp/\xff/payload.bin"));
            assert!(matches!(
                path_as_utf8(non_utf8),
                Err(AnchorError::CommandIo { program, detail })
                    if program == PKCS11_TOOL_PROGRAM && detail.contains("UTF-8")
            ));
        }
    }
}
