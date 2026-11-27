//! OpenSSH FIDO2 hardware security key (`sk-ssh-ed25519@openssh.com` / `SSHSIG`)
//! signing and pure-Rust verification.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use handfest_core::ast::KeyId;
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate, VerifiedRevocation};
use sha2::{Digest, Sha256, Sha512};

use crate::{
    decode_lower_hex_vec, parse_canonical_ed25519_verifying_key,
    revocation::{
        revocation_signing_payload, validate_revocation_header, REVOCATION_SIGNING_DOMAIN_PREFIX,
    },
    signing_payload, validate_envelope_header, AnchorError, AnchorVerifier, AssuranceLevel,
    CommandRunner, MandateSigner, SignedMandate, SignedRevocation, SIGNING_DOMAIN_PREFIX,
};

/// `KeyId` scheme for OpenSSH FIDO2 hardware-backed Ed25519 keys.
pub const SSH_SK_ED25519_SCHEME: &str = "ssh-sk-ed25519";

/// OpenSSH key and signature type identifier for FIDO2 Ed25519 hardware keys.
pub const SSH_SK_ED25519_SSH_TYPE: &str = "sk-ssh-ed25519@openssh.com";

/// Domain-separated `SSHSIG` namespace required for all `handfest` envelope signatures.
pub const SSHSIG_NAMESPACE: &str = "handfest-v1-envelope";

const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";
const SSHSIG_VERSION: u32 = 1;
const SSHSIG_HASH_ALG: &str = "sha512";
pub(crate) const SSH_SK_USER_PRESENCE_FLAG: u8 = 0x01;
const SSH_SK_APPLICATION_PREFIX: &str = "ssh:";
const SSHSIG_PEM_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const SSHSIG_PEM_END: &str = "-----END SSH SIGNATURE-----";

/// Parsed OpenSSH `sk-ssh-ed25519@openssh.com` hardware security public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSkPublicKey {
    verifying_key: VerifyingKey,
    application: String,
}

impl SshSkPublicKey {
    /// Parses a single OpenSSH `.pub` line (`sk-ssh-ed25519@openssh.com <base64> [comment]`).
    pub fn parse_openssh_pub(content: &str) -> Result<Self, AnchorError> {
        Self::parse_openssh_pub_bytes(content.as_bytes())
    }

    /// Parses raw bytes of an OpenSSH `.pub` file, rejecting bare `\r` and ASCII control
    /// characters (preventing terminal WYSIWYS spoofing) while permitting non-UTF-8 bytes in
    /// the optional trailing comment field (matching OpenSSH).
    pub fn parse_openssh_pub_bytes(content: &[u8]) -> Result<Self, AnchorError> {
        let (key_type, blob) = parse_openssh_pub_line_fields(content)?;
        if key_type != SSH_SK_ED25519_SSH_TYPE {
            return Err(AnchorError::InvalidPublicKey(format!(
                "expected OpenSSH key type '{SSH_SK_ED25519_SSH_TYPE}', got '{key_type}'"
            )));
        }
        parse_ssh_sk_public_key_blob(&blob).map_err(AnchorError::InvalidPublicKey)
    }

    /// Loads an [`SshSkPublicKey`] from a `.pub` file or the companion `<key_path>.pub`
    /// alongside an OpenSSH key handle, never reading private key material.
    pub fn from_key_path(key_path: &Path) -> Result<Self, AnchorError> {
        let pub_path = resolve_pub_key_path(key_path)?;
        let raw = fs::read(&pub_path).map_err(|err| {
            AnchorError::InvalidPublicKey(format!(
                "failed to read OpenSSH public key '{}': {err}",
                pub_path.display()
            ))
        })?;
        Self::parse_openssh_pub_bytes(&raw)
    }

    /// Returns the raw 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }

    /// Returns the bound OpenSSH FIDO2 application string (e.g. `"ssh:"`).
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Derives the canonical `KeyId` (`ssh-sk-ed25519:<64-lowercase-hex>`).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let pub_hex = hex::encode(self.public_key_bytes());
        KeyId::new(SSH_SK_ED25519_SCHEME, pub_hex)
            .expect("hex-encoded ssh-sk-ed25519 key is always a valid KeyId")
    }
}

/// Hardware-backed [`MandateSigner`] delegating to `ssh-keygen -Y sign` for OpenSSH FIDO2
/// (`sk-ssh-ed25519@openssh.com`) keys.
#[derive(Debug, Clone)]
pub struct SshSkSigner<R> {
    sign_key_path: String,
    public_key: SshSkPublicKey,
    runner: R,
}

impl<R: CommandRunner> SshSkSigner<R> {
    /// Constructs a signer from an OpenSSH signing key path (`.pub` or key handle) and the
    /// already-loaded `.pub` file contents.
    pub fn from_pub_str(
        sign_key_path: impl Into<PathBuf>,
        pub_key_content: &str,
        runner: R,
    ) -> Result<Self, AnchorError> {
        let path_buf = sign_key_path.into();
        let sign_key_path = validate_utf8_key_path(&path_buf)?;
        let public_key = SshSkPublicKey::parse_openssh_pub(pub_key_content)?;
        Ok(Self {
            sign_key_path,
            public_key,
            runner,
        })
    }

    /// Loads the public key from `key_path` (if `.pub`) or companion `<key_path>.pub` without
    /// reading private key material, and prepares `ssh-keygen -Y sign -f <key_path>`.
    pub fn from_key_path(key_path: impl AsRef<Path>, runner: R) -> Result<Self, AnchorError> {
        let path = key_path.as_ref();
        let sign_key_path = validate_utf8_key_path(path)?;
        let public_key = SshSkPublicKey::from_key_path(path)?;
        Ok(Self {
            sign_key_path,
            public_key,
            runner,
        })
    }

    pub(crate) fn from_parsed(
        sign_key_path: String,
        public_key: SshSkPublicKey,
        runner: R,
    ) -> Self {
        Self {
            sign_key_path,
            public_key,
            runner,
        }
    }

    /// Returns the parsed OpenSSH FIDO2 public key bound to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &SshSkPublicKey {
        &self.public_key
    }
}

impl<R: CommandRunner> MandateSigner for SshSkSigner<R> {
    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        if !payload.starts_with(SIGNING_DOMAIN_PREFIX)
            && !payload.starts_with(REVOCATION_SIGNING_DOMAIN_PREFIX)
        {
            return Err(AnchorError::InvalidSignature(
                "payload does not start with a recognized handfest signing domain prefix"
                    .to_string(),
            ));
        }
        let output = self.runner.run(
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-f",
                self.sign_key_path.as_str(),
                "-n",
                SSHSIG_NAMESPACE,
            ],
            payload,
        )?;
        let raw_sshsig = decode_sshsig_pem(&output.stdout)?;
        let verified = verify_sshsig_blob(&raw_sshsig, &self.public_key.verifying_key, payload)?;
        if verified.public_key.application != self.public_key.application {
            return Err(AnchorError::InvalidSignature(format!(
                "SSHSIG application '{}' does not match public key application '{}'",
                verified.public_key.application, self.public_key.application
            )));
        }
        Ok(raw_sshsig)
    }
}

/// Pure-Rust `SSHSIG` verifier for OpenSSH hardware FIDO2 Ed25519 keys
/// (`sk-ssh-ed25519@openssh.com`, `AssuranceLevel::Passkey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SshSkEd25519Verifier;

impl AnchorVerifier for SshSkEd25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_ssh_sk_ed25519(signed)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        verify_revocation_ssh_sk_ed25519(signed)
    }
}

/// Verifies a single OpenSSH `sk-ssh-ed25519@openssh.com` `SSHSIG` [`SignedRevocation`] envelope
/// and returns a [`VerifiedRevocation`] with `AssuranceLevel::Passkey`.
pub fn verify_revocation_ssh_sk_ed25519(
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    let header =
        validate_revocation_header(signed, SSH_SK_ED25519_SCHEME, AssuranceLevel::Passkey)?;
    let sshsig_bytes =
        decode_lower_hex_vec(&signed.signature_hex).map_err(AnchorError::InvalidSignature)?;
    let payload = revocation_signing_payload(signed);
    let _parsed = verify_sshsig_blob(&sshsig_bytes, &header.verifying_key, &payload)?;

    Ok(VerifiedRevocation {
        ast: header.ast,
        proof: VerifiedAnchorProof {
            anchor_id: signed.anchor_id.clone(),
            assurance: header.assurance,
            signer_key: header.signer_key,
            actor_kind: header.actor_kind,
            valid_from: signed.valid_from,
            valid_until: signed.valid_until,
        },
    })
}

/// Verifies a single OpenSSH `sk-ssh-ed25519@openssh.com` `SSHSIG` [`SignedMandate`] envelope
/// and returns a [`VerifiedMandate`] with `AssuranceLevel::Passkey`.
pub fn verify_ssh_sk_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    let header = validate_envelope_header(signed, SSH_SK_ED25519_SCHEME, AssuranceLevel::Passkey)?;
    let sshsig_bytes =
        decode_lower_hex_vec(&signed.signature_hex).map_err(AnchorError::InvalidSignature)?;
    let payload = signing_payload(signed);
    let _parsed = verify_sshsig_blob(&sshsig_bytes, &header.verifying_key, &payload)?;

    let proof = VerifiedAnchorProof {
        anchor_id: signed.anchor_id.clone(),
        assurance: header.assurance,
        signer_key: header.signer_key,
        actor_kind: header.actor_kind,
        valid_from: signed.valid_from,
        valid_until: signed.valid_until,
    };

    Ok(VerifiedMandate {
        ast: header.ast,
        proof,
    })
}

struct ParsedSshSig {
    public_key: SshSkPublicKey,
    signature_bytes: [u8; 64],
    flags: u8,
    counter: u32,
}

fn verify_sshsig_blob(
    sshsig_bytes: &[u8],
    expected_key: &VerifyingKey,
    payload: &[u8],
) -> Result<ParsedSshSig, AnchorError> {
    let parsed = parse_sshsig_blob(sshsig_bytes).map_err(AnchorError::InvalidSignature)?;
    if parsed.public_key.verifying_key != *expected_key {
        return Err(AnchorError::InvalidSignature(format!(
            "SSHSIG public key '{}' does not match expected signer key '{}'",
            hex::encode(parsed.public_key.public_key_bytes()),
            hex::encode(expected_key.as_bytes()),
        )));
    }
    if (parsed.flags & SSH_SK_USER_PRESENCE_FLAG) == 0 {
        return Err(AnchorError::InvalidSignature(format!(
            "SSHSIG FIDO2 user-presence (UP) flag bit 0x01 is not set (flags=0x{:02x})",
            parsed.flags
        )));
    }

    let signature = Signature::from_bytes(&parsed.signature_bytes);
    let signed_data = build_sk_signed_data(
        SSHSIG_NAMESPACE,
        &parsed.public_key.application,
        parsed.flags,
        parsed.counter,
        payload,
    );
    expected_key
        .verify_strict(&signed_data, &signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;

    Ok(parsed)
}

fn parse_sshsig_blob(bytes: &[u8]) -> Result<ParsedSshSig, String> {
    let (pk_blob, sig_blob) = parse_sshsig_outer(bytes, SSHSIG_NAMESPACE)?;
    let public_key = parse_ssh_sk_public_key_blob(pk_blob)?;
    let (signature_bytes, flags, counter) = parse_ssh_sk_signature_blob(sig_blob)?;
    Ok(ParsedSshSig {
        public_key,
        signature_bytes,
        flags,
        counter,
    })
}

pub(crate) fn parse_openssh_pub_line_fields(
    content: &[u8],
) -> Result<(&str, Vec<u8>), AnchorError> {
    if content.contains(&0) {
        return Err(AnchorError::InvalidPublicKey(
            "OpenSSH public key must not contain NUL bytes".to_string(),
        ));
    }
    let mut selected_line: Option<&[u8]> = None;
    for raw_line in content.split_inclusive(|&b| b == b'\n') {
        let line = match raw_line.strip_suffix(b"\n") {
            Some(before_lf) => before_lf.strip_suffix(b"\r").unwrap_or(before_lf),
            None => raw_line,
        };
        if line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(AnchorError::InvalidPublicKey(
                "OpenSSH public key must not contain control characters or bare CR".to_string(),
            ));
        }
        let trimmed = trim_ssh_spaces(line);
        if trimmed.is_empty() {
            continue;
        }
        if selected_line.is_some() {
            return Err(AnchorError::InvalidPublicKey(
                "OpenSSH public key must contain exactly one key entry".to_string(),
            ));
        }
        selected_line = Some(trimmed);
    }

    let line = selected_line.ok_or_else(|| {
        AnchorError::InvalidPublicKey("OpenSSH public key input is empty".to_string())
    })?;

    let (key_type_bytes, rest) = split_next_ssh_field(line);
    let key_type = std::str::from_utf8(key_type_bytes).map_err(|_| {
        AnchorError::InvalidPublicKey("OpenSSH key type is not valid UTF-8".to_string())
    })?;

    let rest = trim_leading_ssh_spaces(rest);
    if rest.is_empty() {
        return Err(AnchorError::InvalidPublicKey(
            "missing base64 key blob in OpenSSH .pub file".to_string(),
        ));
    }
    let (b64_bytes, _comment) = split_next_ssh_field(rest);
    let b64_blob = std::str::from_utf8(b64_bytes).map_err(|_| {
        AnchorError::InvalidPublicKey("base64 key blob is not valid UTF-8".to_string())
    })?;
    let blob = handfest_core::base64::decode_standard(b64_blob)
        .map_err(|err| AnchorError::InvalidPublicKey(format!("invalid base64 key blob: {err}")))?;

    Ok((key_type, blob))
}

pub(crate) fn parse_sshsig_outer<'a>(
    bytes: &'a [u8],
    expected_namespace: &str,
) -> Result<(&'a [u8], &'a [u8]), String> {
    let mut reader = SshWireReader::new(bytes);

    let magic = reader.read_exact_slice(SSHSIG_MAGIC.len(), "SSHSIG magic")?;
    if magic != SSHSIG_MAGIC {
        return Err("invalid SSHSIG magic header".to_string());
    }

    let version = reader.read_u32("SSHSIG version")?;
    if version != SSHSIG_VERSION {
        return Err(format!(
            "unsupported SSHSIG version {version}, expected {SSHSIG_VERSION}"
        ));
    }

    let pk_blob = reader.read_bytes("SSHSIG publickey")?;

    let namespace = reader.read_utf8("SSHSIG namespace")?;
    if namespace != expected_namespace {
        return Err(format!(
            "invalid SSHSIG namespace '{namespace}', expected '{expected_namespace}'"
        ));
    }

    let reserved = reader.read_bytes("SSHSIG reserved")?;
    if !reserved.is_empty() {
        return Err(format!(
            "SSHSIG reserved field must be empty, got {} byte(s)",
            reserved.len()
        ));
    }

    let hash_algorithm = reader.read_utf8("SSHSIG hash_algorithm")?;
    if hash_algorithm != SSHSIG_HASH_ALG {
        return Err(format!(
            "unsupported SSHSIG hash algorithm '{hash_algorithm}', expected '{SSHSIG_HASH_ALG}'"
        ));
    }

    let sig_blob = reader.read_bytes("SSHSIG signature")?;
    reader.finish("SSHSIG blob")?;
    Ok((pk_blob, sig_blob))
}

pub(crate) fn parse_ssh_sk_public_key_blob(blob: &[u8]) -> Result<SshSkPublicKey, String> {
    let mut reader = SshWireReader::new(blob);
    let key_type = reader.read_utf8("publickey type")?;
    if key_type != SSH_SK_ED25519_SSH_TYPE {
        return Err(format!(
            "expected publickey type '{SSH_SK_ED25519_SSH_TYPE}', got '{key_type}'"
        ));
    }

    let pk_slice = reader.read_bytes("Ed25519 public key")?;
    let public_key_bytes: [u8; 32] = pk_slice.try_into().map_err(|_| {
        format!(
            "expected 32-byte Ed25519 public key, got {} byte(s)",
            pk_slice.len()
        )
    })?;
    let verifying_key = parse_canonical_ed25519_verifying_key(&public_key_bytes)
        .map_err(|err| format!("invalid Ed25519 public key: {err}"))?;

    let application = reader.read_utf8("FIDO2 application")?;
    validate_ssh_sk_application(application)?;
    reader.finish("publickey blob")?;

    Ok(SshSkPublicKey {
        verifying_key,
        application: application.to_string(),
    })
}

fn parse_ssh_sk_signature_blob(blob: &[u8]) -> Result<([u8; 64], u8, u32), String> {
    let mut reader = SshWireReader::new(blob);
    let sig_type = reader.read_utf8("signature type")?;
    if sig_type != SSH_SK_ED25519_SSH_TYPE {
        return Err(format!(
            "expected signature type '{SSH_SK_ED25519_SSH_TYPE}', got '{sig_type}'"
        ));
    }

    let sig_slice = reader.read_bytes("Ed25519 signature")?;
    let signature_bytes: [u8; 64] = sig_slice.try_into().map_err(|_| {
        format!(
            "expected 64-byte Ed25519 signature, got {} byte(s)",
            sig_slice.len()
        )
    })?;

    let flags = reader.read_u8("FIDO2 flags")?;
    let counter = reader.read_u32("FIDO2 counter")?;
    reader.finish("signature blob")?;

    Ok((signature_bytes, flags, counter))
}

pub(crate) fn validate_ssh_sk_application(application: &str) -> Result<(), String> {
    if !application.starts_with(SSH_SK_APPLICATION_PREFIX) {
        return Err(format!(
            "OpenSSH FIDO2 application '{application}' must start with '{SSH_SK_APPLICATION_PREFIX}'"
        ));
    }
    if application.chars().any(char::is_control) {
        return Err("OpenSSH FIDO2 application must not contain control characters".to_string());
    }
    Ok(())
}

pub(crate) fn build_sk_signed_data(
    namespace: &str,
    application: &str,
    flags: u8,
    counter: u32,
    payload: &[u8],
) -> [u8; 69] {
    let payload_sha512 = Sha512::digest(payload);
    let mut preimage = Vec::with_capacity(
        SSHSIG_MAGIC.len() + 4 + namespace.len() + 4 + 4 + SSHSIG_HASH_ALG.len() + 4 + 64,
    );
    preimage.extend_from_slice(SSHSIG_MAGIC);
    push_ssh_bytes(&mut preimage, namespace.as_bytes());
    push_ssh_bytes(&mut preimage, b"");
    push_ssh_bytes(&mut preimage, SSHSIG_HASH_ALG.as_bytes());
    push_ssh_bytes(&mut preimage, &payload_sha512);

    let app_sha256 = Sha256::digest(application.as_bytes());
    let preimage_sha256 = Sha256::digest(&preimage);

    let mut signed_data = [0u8; 69];
    signed_data[0..32].copy_from_slice(&app_sha256);
    signed_data[32] = flags;
    signed_data[33..37].copy_from_slice(&counter.to_be_bytes());
    signed_data[37..69].copy_from_slice(&preimage_sha256);
    signed_data
}

fn push_ssh_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("SSH wire slice length fits in u32");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn trim_leading_ssh_spaces(mut bytes: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = bytes.split_first() {
        if first == b' ' || first == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn trim_ssh_spaces(bytes: &[u8]) -> &[u8] {
    let mut bytes = trim_leading_ssh_spaces(bytes);
    while let Some((&last, rest)) = bytes.split_last() {
        if last == b' ' || last == b'\t' {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn split_next_ssh_field(bytes: &[u8]) -> (&[u8], &[u8]) {
    match bytes.iter().position(|&b| b == b' ' || b == b'\t') {
        Some(idx) => (&bytes[..idx], &bytes[idx..]),
        None => (bytes, b""),
    }
}

pub(crate) fn resolve_pub_key_path(key_path: &Path) -> Result<PathBuf, AnchorError> {
    if key_path.as_os_str().is_empty() {
        return Err(AnchorError::InvalidPublicKey(
            "SSH key path must not be empty".to_string(),
        ));
    }
    if key_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".pub"))
    {
        return Ok(key_path.to_path_buf());
    }

    let mut companion_os = OsString::from(key_path.as_os_str());
    companion_os.push(".pub");
    let companion = PathBuf::from(companion_os);
    if companion.is_file() {
        return Ok(companion);
    }

    Err(AnchorError::InvalidPublicKey(format!(
        "expected '.pub' file or companion '{}' alongside '{}'; handfest never reads private key files",
        companion.display(),
        key_path.display()
    )))
}

pub(crate) fn validate_utf8_key_path(path: &Path) -> Result<String, AnchorError> {
    let s = path.to_str().ok_or_else(|| {
        AnchorError::InvalidPublicKey(format!(
            "SSH key path '{}' is not valid UTF-8",
            path.display()
        ))
    })?;
    if s.is_empty() {
        return Err(AnchorError::InvalidPublicKey(
            "SSH key path must not be empty".to_string(),
        ));
    }
    if s.bytes().any(|b| b == 0) {
        return Err(AnchorError::InvalidPublicKey(
            "SSH key path must not contain NUL bytes".to_string(),
        ));
    }
    Ok(s.to_string())
}

pub(crate) fn decode_sshsig_pem(pem_bytes: &[u8]) -> Result<Vec<u8>, AnchorError> {
    let text = std::str::from_utf8(pem_bytes).map_err(|_| {
        AnchorError::InvalidSignature("ssh-keygen output is not valid UTF-8".to_string())
    })?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() < 3 || lines[0] != SSHSIG_PEM_BEGIN || lines[lines.len() - 1] != SSHSIG_PEM_END {
        return Err(AnchorError::InvalidSignature(
            "invalid SSHSIG PEM armor delimiters".to_string(),
        ));
    }

    let body_lines = &lines[1..lines.len() - 1];
    if body_lines.iter().any(|line| line.is_empty()) {
        return Err(AnchorError::InvalidSignature(
            "SSHSIG PEM body must not contain blank lines".to_string(),
        ));
    }
    let body: String = body_lines.concat();
    handfest_core::base64::decode_standard(&body)
        .map_err(|err| AnchorError::InvalidSignature(format!("invalid SSHSIG PEM base64: {err}")))
}

pub(crate) struct SshWireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SshWireReader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn read_exact_slice(
        &mut self,
        len: usize,
        context: &str,
    ) -> Result<&'a [u8], String> {
        let remaining = &self.bytes[self.offset..];
        let slice = remaining.get(..len).ok_or_else(|| {
            format!(
                "truncated {context}: needed {len} byte(s), {} remaining",
                remaining.len()
            )
        })?;
        self.offset += len;
        Ok(slice)
    }

    pub(crate) fn read_u8(&mut self, context: &str) -> Result<u8, String> {
        let slice = self.read_exact_slice(1, context)?;
        Ok(slice[0])
    }

    pub(crate) fn read_u32(&mut self, context: &str) -> Result<u32, String> {
        let slice = self.read_exact_slice(4, context)?;
        let arr: [u8; 4] = slice.try_into().expect("slice length is 4");
        Ok(u32::from_be_bytes(arr))
    }

    pub(crate) fn read_bytes(&mut self, context: &str) -> Result<&'a [u8], String> {
        let len = usize::try_from(self.read_u32(context)?).expect("u32 length fits in usize");
        self.read_exact_slice(len, context)
    }

    pub(crate) fn read_utf8(&mut self, context: &str) -> Result<&'a str, String> {
        let raw = self.read_bytes(context)?;
        std::str::from_utf8(raw).map_err(|_| format!("non-UTF-8 string in {context}"))
    }

    pub(crate) fn finish(&self, context: &str) -> Result<(), String> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining != 0 {
            return Err(format!(
                "unexpected {remaining} trailing byte(s) in {context}"
            ));
        }
        Ok(())
    }
}
