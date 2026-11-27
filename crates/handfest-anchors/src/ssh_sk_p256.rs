//! OpenSSH FIDO2 hardware security key (`sk-ecdsa-sha2-nistp256@openssh.com` / `SSHSIG`)
//! signing and pure-Rust NIST P-256 verification, plus unified SSH-SK key/signer dispatch.

use std::fs;
use std::path::{Path, PathBuf};

use handfest_core::ast::KeyId;
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate, VerifiedRevocation};
use sha2::{Digest, Sha256};

use crate::p256::{P256PublicKey, P256_UNCOMPRESSED_KEY_LEN};
use crate::revocation::{
    revocation_signing_payload, validate_revocation_metadata, REVOCATION_SIGNING_DOMAIN_PREFIX,
};
use crate::ssh_sk::{
    build_sk_signed_data, decode_sshsig_pem, parse_openssh_pub_line_fields,
    parse_ssh_sk_public_key_blob, parse_sshsig_outer, resolve_pub_key_path,
    validate_ssh_sk_application, validate_utf8_key_path, SshWireReader, SSH_SK_USER_PRESENCE_FLAG,
};
use crate::{
    decode_lower_hex_fixed, decode_lower_hex_vec, signing_payload, validate_envelope_metadata,
    AnchorError, AnchorVerifier, AssuranceLevel, CommandRunner, MandateSigner, SignedMandate,
    SignedRevocation, SshSkPublicKey, SshSkSigner, SIGNING_DOMAIN_PREFIX, SSHSIG_NAMESPACE,
    SSH_SK_ED25519_SSH_TYPE,
};

/// `KeyId` scheme for OpenSSH FIDO2 hardware-backed NIST P-256 keys.
pub const SSH_SK_P256_SCHEME: &str = "ssh-sk-p256";

/// OpenSSH key and signature type identifier for FIDO2 ECDSA NIST P-256 hardware keys.
pub const SSH_SK_P256_SSH_TYPE: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// OpenSSH curve identifier inside `sk-ecdsa-sha2-nistp256@openssh.com` public key blobs.
pub const SSH_SK_P256_CURVE_NAME: &str = "nistp256";

/// Domain-separated `SSHSIG` namespace required for `HANDFEST REVOKE v1` revocation signatures.
pub const SSHSIG_REVOCATION_NAMESPACE: &str = "handfest-v1-revoke";

/// Parsed OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` hardware security public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSkP256PublicKey {
    public_key: P256PublicKey,
    application: String,
}

impl SshSkP256PublicKey {
    /// Parses a single OpenSSH `.pub` line (`sk-ecdsa-sha2-nistp256@openssh.com <base64> [comment]`).
    pub fn parse_openssh_pub(content: &str) -> Result<Self, AnchorError> {
        Self::parse_openssh_pub_bytes(content.as_bytes())
    }

    /// Parses raw bytes of an OpenSSH `.pub` file, rejecting bare `\r`, NUL, and ASCII control
    /// characters while permitting non-UTF-8 bytes in the optional trailing comment field.
    pub fn parse_openssh_pub_bytes(content: &[u8]) -> Result<Self, AnchorError> {
        let (key_type, blob) = parse_openssh_pub_line_fields(content)?;
        if key_type != SSH_SK_P256_SSH_TYPE {
            return Err(AnchorError::InvalidPublicKey(format!(
                "expected OpenSSH key type '{SSH_SK_P256_SSH_TYPE}', got '{key_type}'"
            )));
        }
        parse_ssh_sk_p256_public_key_blob(&blob).map_err(AnchorError::InvalidPublicKey)
    }

    /// Loads an [`SshSkP256PublicKey`] from a `.pub` file or companion `<key_path>.pub`,
    /// never reading private key material.
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

    /// Returns the strictly validated [`P256PublicKey`].
    #[must_use]
    pub const fn public_key(&self) -> P256PublicKey {
        self.public_key
    }

    /// Returns the raw 65-byte uncompressed SEC1 public key (`0x04 || X || Y`).
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8; P256_UNCOMPRESSED_KEY_LEN] {
        self.public_key.as_sec1_bytes()
    }

    /// Returns the bound OpenSSH FIDO2 application string (e.g. `"ssh:"`).
    #[must_use]
    pub fn application(&self) -> &str {
        &self.application
    }

    /// Derives the canonical `KeyId` (`ssh-sk-p256:<130-lowercase-hex>`).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let pub_hex = hex::encode(self.public_key_bytes());
        KeyId::new(SSH_SK_P256_SCHEME, pub_hex)
            .expect("hex-encoded ssh-sk-p256 key is always a valid KeyId")
    }
}

/// Hardware-backed [`MandateSigner`] delegating to `ssh-keygen -Y sign` for OpenSSH FIDO2
/// (`sk-ecdsa-sha2-nistp256@openssh.com`) keys.
#[derive(Debug, Clone)]
pub struct SshSkP256Signer<R> {
    sign_key_path: String,
    public_key: SshSkP256PublicKey,
    runner: R,
}

impl<R: CommandRunner> SshSkP256Signer<R> {
    /// Constructs a signer from an OpenSSH signing key path (`.pub` or key handle) and the
    /// already-loaded `.pub` file contents.
    pub fn from_pub_str(
        sign_key_path: impl Into<PathBuf>,
        pub_key_content: &str,
        runner: R,
    ) -> Result<Self, AnchorError> {
        let path_buf = sign_key_path.into();
        let sign_key_path = validate_utf8_key_path(&path_buf)?;
        let public_key = SshSkP256PublicKey::parse_openssh_pub(pub_key_content)?;
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
        let public_key = SshSkP256PublicKey::from_key_path(path)?;
        Ok(Self {
            sign_key_path,
            public_key,
            runner,
        })
    }

    pub(crate) fn from_parsed(
        sign_key_path: String,
        public_key: SshSkP256PublicKey,
        runner: R,
    ) -> Self {
        Self {
            sign_key_path,
            public_key,
            runner,
        }
    }

    /// Returns the parsed OpenSSH FIDO2 P-256 public key bound to this signer.
    #[must_use]
    pub const fn public_key(&self) -> &SshSkP256PublicKey {
        &self.public_key
    }
}

impl<R: CommandRunner> MandateSigner for SshSkP256Signer<R> {
    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let namespace = select_p256_sshsig_namespace(payload)?;
        let output = self.runner.run(
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-f",
                self.sign_key_path.as_str(),
                "-n",
                namespace,
            ],
            payload,
        )?;
        let raw_sshsig = decode_sshsig_pem(&output.stdout)?;
        let verified_pk =
            verify_sshsig_p256_blob(&raw_sshsig, &self.public_key.public_key, payload, namespace)?;
        if verified_pk.application != self.public_key.application {
            return Err(AnchorError::InvalidSignature(format!(
                "SSHSIG application '{}' does not match public key application '{}'",
                verified_pk.application, self.public_key.application
            )));
        }
        Ok(raw_sshsig)
    }
}

fn select_p256_sshsig_namespace(payload: &[u8]) -> Result<&'static str, AnchorError> {
    if payload.starts_with(SIGNING_DOMAIN_PREFIX) {
        Ok(SSHSIG_NAMESPACE)
    } else if payload.starts_with(REVOCATION_SIGNING_DOMAIN_PREFIX) {
        Ok(SSHSIG_REVOCATION_NAMESPACE)
    } else {
        Err(AnchorError::InvalidSignature(
            "payload does not start with a recognized handfest signing domain prefix".to_string(),
        ))
    }
}

/// Pure-Rust `SSHSIG` verifier for OpenSSH hardware FIDO2 NIST P-256 keys
/// (`sk-ecdsa-sha2-nistp256@openssh.com`, `AssuranceLevel::Passkey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SshSkP256Verifier;

impl AnchorVerifier for SshSkP256Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_ssh_sk_p256(signed)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        verify_revocation_ssh_sk_p256(signed)
    }
}

/// Verifies a single OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` `SSHSIG` [`SignedMandate`]
/// envelope and returns a [`VerifiedMandate`] with `AssuranceLevel::Passkey`.
pub fn verify_ssh_sk_p256(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    let header = validate_envelope_metadata(signed, SSH_SK_P256_SCHEME, AssuranceLevel::Passkey)?;
    let expected_key = parse_p256_key_from_key_id(&header.signer_key)?;
    let sshsig_bytes =
        decode_lower_hex_vec(&signed.signature_hex).map_err(AnchorError::InvalidSignature)?;
    let payload = signing_payload(signed);
    let _parsed =
        verify_sshsig_p256_blob(&sshsig_bytes, &expected_key, &payload, SSHSIG_NAMESPACE)?;

    Ok(VerifiedMandate {
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

/// Verifies a single OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` `SSHSIG` [`SignedRevocation`]
/// envelope and returns a [`VerifiedRevocation`] with `AssuranceLevel::Passkey`.
pub fn verify_revocation_ssh_sk_p256(
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    let header = validate_revocation_metadata(signed, SSH_SK_P256_SCHEME, AssuranceLevel::Passkey)?;
    let expected_key = parse_p256_key_from_key_id(&header.signer_key)?;
    let sshsig_bytes =
        decode_lower_hex_vec(&signed.signature_hex).map_err(AnchorError::InvalidSignature)?;
    let payload = revocation_signing_payload(signed);
    let _parsed = verify_sshsig_p256_blob(
        &sshsig_bytes,
        &expected_key,
        &payload,
        SSHSIG_REVOCATION_NAMESPACE,
    )?;

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

fn parse_p256_key_from_key_id(key_id: &KeyId) -> Result<P256PublicKey, AnchorError> {
    let raw = decode_lower_hex_fixed::<P256_UNCOMPRESSED_KEY_LEN>(key_id.value())
        .map_err(AnchorError::InvalidPublicKey)?;
    P256PublicKey::from_sec1_uncompressed(&raw)
        .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))
}

fn verify_sshsig_p256_blob(
    sshsig_bytes: &[u8],
    expected_key: &P256PublicKey,
    payload: &[u8],
    expected_namespace: &str,
) -> Result<SshSkP256PublicKey, AnchorError> {
    let (pk_blob, sig_blob) = parse_sshsig_outer(sshsig_bytes, expected_namespace)
        .map_err(AnchorError::InvalidSignature)?;
    let public_key =
        parse_ssh_sk_p256_public_key_blob(pk_blob).map_err(AnchorError::InvalidSignature)?;
    if public_key.public_key != *expected_key {
        return Err(AnchorError::InvalidSignature(format!(
            "SSHSIG public key '{}' does not match expected signer key '{}'",
            hex::encode(public_key.public_key_bytes()),
            hex::encode(expected_key.as_sec1_bytes()),
        )));
    }

    let (r, s, flags, counter) =
        parse_ssh_sk_p256_signature_blob(sig_blob).map_err(AnchorError::InvalidSignature)?;
    if (flags & SSH_SK_USER_PRESENCE_FLAG) == 0 {
        return Err(AnchorError::InvalidSignature(format!(
            "SSHSIG FIDO2 user-presence (UP) flag bit 0x01 is not set (flags=0x{flags:02x})"
        )));
    }

    let signed_data = build_sk_signed_data(
        expected_namespace,
        &public_key.application,
        flags,
        counter,
        payload,
    );
    let digest: [u8; 32] = Sha256::digest(signed_data).into();
    expected_key
        .verify_prehash(&digest, &r, &s)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))?;

    Ok(public_key)
}

fn parse_ssh_sk_p256_public_key_blob(blob: &[u8]) -> Result<SshSkP256PublicKey, String> {
    let mut reader = SshWireReader::new(blob);
    let key_type = reader.read_utf8("publickey type")?;
    if key_type != SSH_SK_P256_SSH_TYPE {
        return Err(format!(
            "expected publickey type '{SSH_SK_P256_SSH_TYPE}', got '{key_type}'"
        ));
    }

    let curve_name = reader.read_utf8("ECDSA curve name")?;
    if curve_name != SSH_SK_P256_CURVE_NAME {
        return Err(format!(
            "expected ECDSA curve '{SSH_SK_P256_CURVE_NAME}', got '{curve_name}'"
        ));
    }

    let point_slice = reader.read_bytes("P-256 public key point")?;
    let public_key = P256PublicKey::from_sec1_uncompressed(point_slice)
        .map_err(|err| format!("invalid P-256 public key: {err}"))?;

    let application = reader.read_utf8("FIDO2 application")?;
    validate_ssh_sk_application(application)?;
    reader.finish("publickey blob")?;

    Ok(SshSkP256PublicKey {
        public_key,
        application: application.to_string(),
    })
}

fn parse_ssh_sk_p256_signature_blob(blob: &[u8]) -> Result<([u8; 32], [u8; 32], u8, u32), String> {
    let mut reader = SshWireReader::new(blob);
    let sig_type = reader.read_utf8("signature type")?;
    if sig_type != SSH_SK_P256_SSH_TYPE {
        return Err(format!(
            "expected signature type '{SSH_SK_P256_SSH_TYPE}', got '{sig_type}'"
        ));
    }

    let inner_sig = reader.read_bytes("ECDSA signature")?;
    let flags = reader.read_u8("FIDO2 flags")?;
    let counter = reader.read_u32("FIDO2 counter")?;
    reader.finish("signature blob")?;

    let mut inner = SshWireReader::new(inner_sig);
    let r_raw = inner.read_bytes("ECDSA r mpint")?;
    let r = decode_ssh_mpint_u256(r_raw, "r")?;
    let s_raw = inner.read_bytes("ECDSA s mpint")?;
    let s = decode_ssh_mpint_u256(s_raw, "s")?;
    inner.finish("ECDSA signature blob")?;

    Ok((r, s, flags, counter))
}

/// Strictly decodes an RFC 4251 positive canonical OpenSSH `mpint` into a 32-byte big-endian
/// unsigned integer, rejecting zero, negative two's-complement values, non-canonical leading
/// zero bytes, and values exceeding 256 bits.
fn decode_ssh_mpint_u256(raw: &[u8], label: &str) -> Result<[u8; 32], String> {
    if raw.is_empty() {
        return Err(format!("ECDSA {label} mpint must be positive (got zero)"));
    }
    if (raw[0] & 0x80) != 0 {
        return Err(format!("ECDSA {label} mpint must not be negative"));
    }
    let magnitude = if raw[0] == 0x00 {
        if raw.len() == 1 || (raw[1] & 0x80) == 0 {
            return Err(format!(
                "non-canonical leading zero byte in ECDSA {label} mpint"
            ));
        }
        &raw[1..]
    } else {
        raw
    };
    if magnitude.len() > 32 {
        return Err(format!(
            "ECDSA {label} mpint exceeds 32 bytes (got {})",
            magnitude.len()
        ));
    }
    let mut out = [0u8; 32];
    let offset = 32 - magnitude.len();
    out[offset..].copy_from_slice(magnitude);
    Ok(out)
}

/// Unified parsed OpenSSH FIDO2 hardware public key (`sk-ssh-ed25519@openssh.com` or
/// `sk-ecdsa-sha2-nistp256@openssh.com`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSkAnyPublicKey {
    Ed25519(SshSkPublicKey),
    P256(SshSkP256PublicKey),
}

impl SshSkAnyPublicKey {
    /// Parses a single OpenSSH FIDO2 `.pub` line for either Ed25519 or NIST P-256.
    pub fn parse_openssh_pub(content: &str) -> Result<Self, AnchorError> {
        Self::parse_openssh_pub_bytes(content.as_bytes())
    }

    /// Parses raw bytes of an OpenSSH FIDO2 `.pub` file for either Ed25519 or NIST P-256.
    pub fn parse_openssh_pub_bytes(content: &[u8]) -> Result<Self, AnchorError> {
        let (key_type, blob) = parse_openssh_pub_line_fields(content)?;
        match key_type {
            SSH_SK_ED25519_SSH_TYPE => parse_ssh_sk_public_key_blob(&blob)
                .map(Self::Ed25519)
                .map_err(AnchorError::InvalidPublicKey),
            SSH_SK_P256_SSH_TYPE => parse_ssh_sk_p256_public_key_blob(&blob)
                .map(Self::P256)
                .map_err(AnchorError::InvalidPublicKey),
            other => Err(AnchorError::InvalidPublicKey(format!(
                "expected OpenSSH key type '{SSH_SK_ED25519_SSH_TYPE}' or '{SSH_SK_P256_SSH_TYPE}', got '{other}'"
            ))),
        }
    }

    /// Loads an [`SshSkAnyPublicKey`] from a `.pub` file or companion `<key_path>.pub`,
    /// never reading private key material.
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

    /// Derives the canonical `KeyId` (`ssh-sk-ed25519:<hex>` or `ssh-sk-p256:<hex>`).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        match self {
            Self::Ed25519(pk) => pk.key_id(),
            Self::P256(pk) => pk.key_id(),
        }
    }

    /// Returns the bound OpenSSH FIDO2 application string (e.g. `"ssh:"`).
    #[must_use]
    pub fn application(&self) -> &str {
        match self {
            Self::Ed25519(pk) => pk.application(),
            Self::P256(pk) => pk.application(),
        }
    }
}

/// Unified hardware-backed [`MandateSigner`] dispatching seamlessly across
/// `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`.
#[derive(Debug, Clone)]
pub enum SshSkAnySigner<R> {
    Ed25519(SshSkSigner<R>),
    P256(SshSkP256Signer<R>),
}

impl<R: CommandRunner> SshSkAnySigner<R> {
    /// Constructs a unified SSH-SK signer from a key path and already-loaded `.pub` contents.
    pub fn from_pub_str(
        sign_key_path: impl Into<PathBuf>,
        pub_key_content: &str,
        runner: R,
    ) -> Result<Self, AnchorError> {
        let path_buf = sign_key_path.into();
        let sign_key_path = validate_utf8_key_path(&path_buf)?;
        match SshSkAnyPublicKey::parse_openssh_pub(pub_key_content)? {
            SshSkAnyPublicKey::Ed25519(pk) => Ok(Self::Ed25519(SshSkSigner::from_parsed(
                sign_key_path,
                pk,
                runner,
            ))),
            SshSkAnyPublicKey::P256(pk) => Ok(Self::P256(SshSkP256Signer::from_parsed(
                sign_key_path,
                pk,
                runner,
            ))),
        }
    }

    /// Loads the public key from `key_path` (if `.pub`) or companion `<key_path>.pub` once without
    /// reading private key material, and returns the matching SSH-SK signer.
    pub fn from_key_path(key_path: impl AsRef<Path>, runner: R) -> Result<Self, AnchorError> {
        let path = key_path.as_ref();
        let sign_key_path = validate_utf8_key_path(path)?;
        match SshSkAnyPublicKey::from_key_path(path)? {
            SshSkAnyPublicKey::Ed25519(pk) => Ok(Self::Ed25519(SshSkSigner::from_parsed(
                sign_key_path,
                pk,
                runner,
            ))),
            SshSkAnyPublicKey::P256(pk) => Ok(Self::P256(SshSkP256Signer::from_parsed(
                sign_key_path,
                pk,
                runner,
            ))),
        }
    }
}

impl<R: CommandRunner> MandateSigner for SshSkAnySigner<R> {
    fn key_id(&self) -> KeyId {
        match self {
            Self::Ed25519(s) => s.key_id(),
            Self::P256(s) => s.key_id(),
        }
    }

    fn assurance(&self) -> AssuranceLevel {
        match self {
            Self::Ed25519(s) => s.assurance(),
            Self::P256(s) => s.assurance(),
        }
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        match self {
            Self::Ed25519(s) => s.sign_payload(payload),
            Self::P256(s) => s.sign_payload(payload),
        }
    }
}

#[cfg(test)]
#[path = "ssh_sk_p256_tests.rs"]
mod tests;
