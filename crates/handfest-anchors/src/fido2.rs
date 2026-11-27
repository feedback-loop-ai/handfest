//! FIDO2 / WebAuthn Ed25519 (`COSE alg = -8`, `fido2-ed25519`) hardware signer and pure-Rust
//! assertion verifier (`AssuranceLevel::Passkey`).

use ed25519_dalek::{Signature, VerifyingKey};
use handfest_core::ast::KeyId;
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate, VerifiedRevocation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::base64::{decode_standard, encode_standard};
use crate::{
    decode_lower_hex_var, parse_hex32_key_id,
    revocation::{revocation_signing_payload, validate_revocation_header},
    signing_payload, validate_envelope_header, AnchorError, AnchorVerifier, AssuranceLevel,
    CommandRunner, MandateSigner, SignedMandate, SignedRevocation,
};

/// Canonical `KeyId` scheme for FIDO2 / WebAuthn Ed25519 (`COSE alg = -8`) keys.
pub const FIDO2_ED25519_SCHEME: &str = "fido2-ed25519";

/// Default WebAuthn Relying Party ID used when enrolling FIDO2 credentials for `handfest`.
pub const DEFAULT_FIDO2_RP_ID: &str = "handfest.local";

/// Wire format version byte for [`Fido2AssertionEnvelope`].
pub const FIDO2_ENVELOPE_VERSION: u8 = 1;

/// CTAP2 / WebAuthn `authenticatorData` User Presence (`UP`) flag bit (bit 0).
pub const FIDO2_FLAG_UP: u8 = 0x01;

/// Minimum byte length of raw CTAP2 / WebAuthn `authenticatorData`:
/// 32-byte `rpIdHash` + 1-byte `flags` + 4-byte `signCount`.
pub const MIN_AUTH_DATA_LEN: usize = 37;

const MAX_RP_ID_LEN: usize = 255;
const MAX_AUTH_DATA_LEN: usize = 16_384;
const MAX_CREDENTIAL_ID_LEN: usize = 1_024;
const ED25519_SIG_LEN: usize = 64;
const MAX_ENVELOPE_BYTES: usize = 1 + 2 + MAX_RP_ID_LEN + 4 + MAX_AUTH_DATA_LEN + ED25519_SIG_LEN;

/// JSON metadata describing an enrolled FIDO2 / WebAuthn Ed25519 (`COSE alg = -8`) credential.
///
/// Closed schema (`#[serde(deny_unknown_fields)]`):
/// ```json
/// {
///   "rp_id": "handfest.local",
///   "credential_id_b64": "<standard-RFC4648-base64-credential-id>",
///   "key_id": "fido2-ed25519:<64-lowercase-hex-ed25519-pubkey>"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2CredentialFile {
    /// WebAuthn Relying Party ID bound at enrollment (e.g. `"handfest.local"`).
    pub rp_id: String,
    /// Standard RFC 4648 Base64-encoded WebAuthn credential ID passed to `fido2-assert -G`.
    pub credential_id_b64: String,
    /// Canonical `KeyId` (`fido2-ed25519:<64-lowercase-hex-ed25519-pubkey>`).
    pub key_id: String,
}

/// Canonical binary payload carried (as lowercase hex) inside [`SignedMandate::signature_hex`]
/// for `fido2-ed25519` assertions.
///
/// Big-endian wire layout:
/// - `version: u8` (`1`)
/// - `rp_id_len: u16` (`1..=255`)
/// - `rp_id: [u8; rp_id_len]` (UTF-8, non-empty, no control or whitespace characters)
/// - `auth_data_len: u32` (`37..=16384`)
/// - `auth_data: [u8; auth_data_len]` (raw CTAP2 / WebAuthn `authenticatorData`)
/// - `signature: [u8; 64]` (raw Ed25519 signature over `auth_data || SHA-256(signing_payload)`)
/// - Exact EOF (no trailing bytes permitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2AssertionEnvelope {
    pub rp_id: String,
    pub auth_data: Vec<u8>,
    pub signature: [u8; ED25519_SIG_LEN],
}

impl Fido2AssertionEnvelope {
    /// Serializes this assertion envelope into its canonical length-prefixed binary representation.
    pub fn encode(&self) -> Result<Vec<u8>, AnchorError> {
        validate_rp_id(&self.rp_id).map_err(AnchorError::InvalidSignature)?;
        let _ = validate_auth_data_len(u64::try_from(self.auth_data.len()).unwrap_or(u64::MAX))
            .map_err(AnchorError::InvalidSignature)?;

        let rp_len = u16::try_from(self.rp_id.len())
            .expect("validated rp_id length <= 255 always fits in u16");
        let auth_len = u32::try_from(self.auth_data.len())
            .expect("validated auth_data length <= 16384 always fits in u32");

        let total = 1 + 2 + self.rp_id.len() + 4 + self.auth_data.len() + ED25519_SIG_LEN;
        let mut out = Vec::with_capacity(total);
        out.push(FIDO2_ENVELOPE_VERSION);
        out.extend_from_slice(&rp_len.to_be_bytes());
        out.extend_from_slice(self.rp_id.as_bytes());
        out.extend_from_slice(&auth_len.to_be_bytes());
        out.extend_from_slice(&self.auth_data);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Parses and validates a canonical binary [`Fido2AssertionEnvelope`], rejecting truncated
    /// fields, invalid `rp_id`, out-of-range `auth_data`, unknown versions, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AnchorError> {
        let mut cursor = bytes;
        let version = take_u8(&mut cursor)?;
        if version != FIDO2_ENVELOPE_VERSION {
            return Err(AnchorError::InvalidSignature(format!(
                "unsupported FIDO2 assertion envelope version {version}"
            )));
        }

        let rp_len = usize::from(take_u16_be(&mut cursor)?);
        let rp_bytes = take_slice(&mut cursor, rp_len, "rp_id")?;
        let rp_id = std::str::from_utf8(rp_bytes)
            .map_err(|_| AnchorError::InvalidSignature("FIDO2 rp_id is not valid UTF-8".into()))?;
        validate_rp_id(rp_id).map_err(AnchorError::InvalidSignature)?;

        let auth_len_u32 = take_u32_be(&mut cursor)?;
        let auth_len = validate_auth_data_len(u64::from(auth_len_u32))
            .map_err(AnchorError::InvalidSignature)?;
        let auth_data = take_slice(&mut cursor, auth_len, "auth_data")?.to_vec();

        let sig_slice = take_slice(&mut cursor, ED25519_SIG_LEN, "signature")?;
        let mut signature = [0u8; ED25519_SIG_LEN];
        signature.copy_from_slice(sig_slice);

        if !cursor.is_empty() {
            return Err(AnchorError::InvalidSignature(format!(
                "FIDO2 assertion envelope has {} trailing byte(s)",
                cursor.len()
            )));
        }

        Ok(Self {
            rp_id: rp_id.to_string(),
            auth_data,
            signature,
        })
    }
}

/// Formats a validated 32-byte Ed25519 public key into its canonical `fido2-ed25519:<hex>` [`KeyId`].
pub fn format_fido2_ed25519_key_id(public_key: &[u8; 32]) -> Result<KeyId, AnchorError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;
    Ok(key_id_from_verifying_key(&verifying_key))
}

fn key_id_from_verifying_key(verifying_key: &VerifyingKey) -> KeyId {
    let pub_hex = hex::encode(verifying_key.to_bytes());
    KeyId::new(FIDO2_ED25519_SCHEME, pub_hex)
        .expect("hex-encoded fido2-ed25519 key is always a valid KeyId")
}

/// Pure-Rust FIDO2 / WebAuthn Ed25519 (`COSE alg = -8`) verifier (`AssuranceLevel::Passkey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct Fido2Ed25519Verifier;

impl AnchorVerifier for Fido2Ed25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_fido2_ed25519(signed)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        verify_revocation_fido2_ed25519(signed)
    }
}

/// Verifies a single FIDO2 / WebAuthn Ed25519 [`SignedRevocation`] envelope offline in pure Rust.
pub fn verify_revocation_fido2_ed25519(
    signed: &SignedRevocation,
) -> Result<VerifiedRevocation, AnchorError> {
    let header = validate_revocation_header(signed, FIDO2_ED25519_SCHEME, AssuranceLevel::Passkey)?;
    let raw_envelope = decode_lower_hex_var(&signed.signature_hex, MAX_ENVELOPE_BYTES)
        .map_err(AnchorError::InvalidSignature)?;
    let envelope = Fido2AssertionEnvelope::decode(&raw_envelope)?;
    verify_auth_data_invariants(&envelope.auth_data, &envelope.rp_id)?;

    let client_data_hash = sha256_bytes(&revocation_signing_payload(signed));
    verify_assertion_signature(
        &header.verifying_key,
        &envelope.auth_data,
        &client_data_hash,
        &envelope.signature,
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

/// Verifies a single FIDO2 / WebAuthn Ed25519 [`SignedMandate`] envelope offline in pure Rust.
pub fn verify_fido2_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    let header = validate_envelope_header(signed, FIDO2_ED25519_SCHEME, AssuranceLevel::Passkey)?;

    let raw_envelope = decode_lower_hex_var(&signed.signature_hex, MAX_ENVELOPE_BYTES)
        .map_err(AnchorError::InvalidSignature)?;
    let envelope = Fido2AssertionEnvelope::decode(&raw_envelope)?;

    verify_auth_data_invariants(&envelope.auth_data, &envelope.rp_id)?;

    let client_data_hash = sha256_bytes(&signing_payload(signed));
    verify_assertion_signature(
        &header.verifying_key,
        &envelope.auth_data,
        &client_data_hash,
        &envelope.signature,
    )?;

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

/// Auto-discovers a single connected FIDO2 authenticator device via `fido2-token -L`.
///
/// Fails closed if zero devices or multiple devices are detected, or if the reported path is
/// malformed.
pub fn discover_fido2_device<R: CommandRunner + ?Sized>(runner: &R) -> Result<String, AnchorError> {
    let output = runner.run("fido2-token", &["-L"], &[])?;
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| {
        AnchorError::InvalidCredential("'fido2-token -L' output is not valid UTF-8".to_string())
    })?;

    let mut devices: Vec<&str> = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let path = match line.split_once(": ") {
            Some((prefix, _rest)) => prefix,
            None => line,
        };
        devices.push(path);
    }

    match devices.as_slice() {
        [] => Err(AnchorError::InvalidCredential(
            "no FIDO2 authenticator devices found via 'fido2-token -L'; connect a token or pass --fido2-device"
                .to_string(),
        )),
        [single] => {
            validate_device_path(single)?;
            Ok((*single).to_string())
        }
        many => Err(AnchorError::InvalidCredential(format!(
            "multiple FIDO2 authenticator devices found ({}); specify --fido2-device explicitly",
            many.len()
        ))),
    }
}

/// Hardware-backed [`MandateSigner`] invoking `fido2-assert -G -t up=true <device>` via a
/// pluggable [`CommandRunner`].
#[derive(Debug, Clone)]
pub struct Fido2Ed25519Signer<R: CommandRunner> {
    runner: R,
    device_path: Option<String>,
    rp_id: String,
    credential_id_b64: String,
    key_id: KeyId,
    verifying_key: VerifyingKey,
}

impl<R: CommandRunner> Fido2Ed25519Signer<R> {
    /// Constructs a validated FIDO2 Ed25519 hardware signer from explicit parameters.
    ///
    /// When `device_path` is `None`, the authenticator path is auto-discovered at signing time
    /// via `fido2-token -L`.
    pub fn new(
        runner: R,
        device_path: Option<String>,
        rp_id: impl Into<String>,
        credential_id_b64: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, AnchorError> {
        let rp_id = rp_id.into();
        validate_rp_id(&rp_id).map_err(AnchorError::InvalidCredential)?;

        let credential_id_b64 = credential_id_b64.into();
        validate_credential_id_b64(&credential_id_b64)?;

        if let Some(ref path) = device_path {
            validate_device_path(path)?;
        }

        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;
        let key_id = key_id_from_verifying_key(&verifying_key);

        Ok(Self {
            runner,
            device_path,
            rp_id,
            credential_id_b64,
            key_id,
            verifying_key,
        })
    }

    /// Loads and validates a [`Fido2Ed25519Signer`] from a [`Fido2CredentialFile`].
    pub fn from_credential_file(
        runner: R,
        file: &Fido2CredentialFile,
        device_path: Option<String>,
    ) -> Result<Self, AnchorError> {
        let (_key_id, public_key) = parse_hex32_key_id(&file.key_id, FIDO2_ED25519_SCHEME)?;
        Self::new(
            runner,
            device_path,
            file.rp_id.clone(),
            file.credential_id_b64.clone(),
            public_key,
        )
    }

    /// Returns the WebAuthn Relying Party ID bound to this signer.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
}

impl<R: CommandRunner> MandateSigner for Fido2Ed25519Signer<R> {
    fn key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let device = match &self.device_path {
            Some(path) => path.clone(),
            None => discover_fido2_device(&self.runner)?,
        };

        let client_data_hash = sha256_bytes(payload);
        let cdh_b64 = encode_standard(&client_data_hash);
        let stdin = format!("{cdh_b64}\n{}\n{}\n", self.rp_id, self.credential_id_b64);

        let output = self.runner.run(
            "fido2-assert",
            &["-G", "-t", "up=true", &device],
            stdin.as_bytes(),
        )?;

        let (auth_data, signature) =
            parse_fido2_assert_stdout(&output.stdout, &client_data_hash, &self.rp_id)?;

        verify_assertion_signature(
            &self.verifying_key,
            &auth_data,
            &client_data_hash,
            &signature,
        )?;

        let envelope = Fido2AssertionEnvelope {
            rp_id: self.rp_id.clone(),
            auth_data,
            signature,
        };
        envelope.encode()
    }
}

fn parse_fido2_assert_stdout(
    stdout: &[u8],
    expected_client_data_hash: &[u8; 32],
    expected_rp_id: &str,
) -> Result<(Vec<u8>, [u8; ED25519_SIG_LEN]), AnchorError> {
    let text = std::str::from_utf8(stdout).map_err(|_| {
        AnchorError::InvalidSignature("'fido2-assert' stdout is not valid UTF-8".to_string())
    })?;
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = trimmed
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();

    let [cdh_line, rp_line, auth_line, sig_line] = lines.as_slice() else {
        return Err(AnchorError::InvalidSignature(format!(
            "expected 4 lines from 'fido2-assert', got {}",
            lines.len()
        )));
    };

    let echoed_cdh = decode_standard(cdh_line).map_err(|err| {
        AnchorError::InvalidSignature(format!(
            "invalid base64 client_data_hash from 'fido2-assert': {err}"
        ))
    })?;
    if echoed_cdh.as_slice() != expected_client_data_hash {
        return Err(AnchorError::InvalidSignature(
            "'fido2-assert' echoed mismatched client_data_hash".to_string(),
        ));
    }

    if *rp_line != expected_rp_id {
        return Err(AnchorError::InvalidSignature(format!(
            "'fido2-assert' echoed mismatched rp_id: expected '{expected_rp_id}', got '{rp_line}'"
        )));
    }

    let auth_blob = decode_standard(auth_line).map_err(|err| {
        AnchorError::InvalidSignature(format!(
            "invalid base64 auth_data from 'fido2-assert': {err}"
        ))
    })?;
    let expected_rp_id_hash = sha256_bytes(expected_rp_id.as_bytes());
    let auth_data = extract_raw_auth_data(&auth_blob, &expected_rp_id_hash)?;
    verify_auth_data_invariants(&auth_data, expected_rp_id)?;

    let sig_vec = decode_standard(sig_line).map_err(|err| {
        AnchorError::InvalidSignature(format!(
            "invalid base64 signature from 'fido2-assert': {err}"
        ))
    })?;
    let signature: [u8; ED25519_SIG_LEN] = sig_vec.try_into().map_err(|bad: Vec<u8>| {
        AnchorError::InvalidSignature(format!(
            "expected {ED25519_SIG_LEN}-byte Ed25519 signature from 'fido2-assert', got {}",
            bad.len()
        ))
    })?;

    Ok((auth_data, signature))
}

/// Extracts raw CTAP2/WebAuthn `authenticatorData` from `fido2-assert -G` stdout.
///
/// Upstream `libfido2` prints `fido_assert_authdata_ptr()` (a canonical CBOR byte string wrapping
/// the raw `authenticatorData`), while wrappers/fixtures may emit raw `authenticatorData` directly.
/// Both forms are verified strictly against `expected_rp_id_hash` and length bounds.
fn extract_raw_auth_data(
    blob: &[u8],
    expected_rp_id_hash: &[u8; 32],
) -> Result<Vec<u8>, AnchorError> {
    if let Some(unwrapped) = decode_canonical_cbor_bstr(blob) {
        if unwrapped.len() >= MIN_AUTH_DATA_LEN
            && unwrapped.len() <= MAX_AUTH_DATA_LEN
            && &unwrapped[..32] == expected_rp_id_hash
        {
            return Ok(unwrapped.to_vec());
        }
    }

    if blob.len() >= MIN_AUTH_DATA_LEN
        && blob.len() <= MAX_AUTH_DATA_LEN
        && &blob[..32] == expected_rp_id_hash
    {
        return Ok(blob.to_vec());
    }

    Err(AnchorError::InvalidSignature(
        "invalid FIDO2 auth_data from 'fido2-assert': length or rpIdHash mismatch".to_string(),
    ))
}

/// Decodes a canonical RFC 8949 CBOR byte string (major type 2) of length >= 24 bytes.
fn decode_canonical_cbor_bstr(blob: &[u8]) -> Option<&[u8]> {
    let (&header, rest) = blob.split_first()?;
    match header {
        0x58 => {
            let (&len_byte, payload) = rest.split_first()?;
            let len = usize::from(len_byte);
            if len >= 24 && payload.len() == len {
                Some(payload)
            } else {
                None
            }
        }
        0x59 => {
            if rest.len() < 2 {
                return None;
            }
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let payload = &rest[2..];
            if len >= 256 && payload.len() == len {
                Some(payload)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn verify_auth_data_invariants(auth_data: &[u8], rp_id: &str) -> Result<(), AnchorError> {
    debug_assert!(auth_data.len() >= MIN_AUTH_DATA_LEN);

    let expected_rp_hash = sha256_bytes(rp_id.as_bytes());
    if auth_data[..32] != expected_rp_hash {
        return Err(AnchorError::InvalidSignature(
            "FIDO2 authenticatorData rpIdHash does not match rp_id".to_string(),
        ));
    }

    let flags = auth_data[32];
    if (flags & FIDO2_FLAG_UP) == 0 {
        return Err(AnchorError::InvalidSignature(
            "FIDO2 authenticatorData missing UP (user presence) flag".to_string(),
        ));
    }

    Ok(())
}

fn verify_assertion_signature(
    verifying_key: &VerifyingKey,
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
    signature_bytes: &[u8; ED25519_SIG_LEN],
) -> Result<(), AnchorError> {
    let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed_data.extend_from_slice(auth_data);
    signed_data.extend_from_slice(client_data_hash);

    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(&signed_data, &signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))
}

fn validate_rp_id(rp_id: &str) -> Result<(), String> {
    if rp_id.is_empty() {
        return Err("FIDO2 rp_id must not be empty".to_string());
    }
    if rp_id.len() > MAX_RP_ID_LEN {
        return Err(format!(
            "FIDO2 rp_id length {} exceeds maximum {MAX_RP_ID_LEN}",
            rp_id.len()
        ));
    }
    if rp_id
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("FIDO2 rp_id must not contain control or whitespace characters".to_string());
    }
    Ok(())
}

fn validate_auth_data_len(len: u64) -> Result<usize, String> {
    let min = u64::try_from(MIN_AUTH_DATA_LEN).expect("MIN_AUTH_DATA_LEN fits in u64");
    let max = u64::try_from(MAX_AUTH_DATA_LEN).expect("MAX_AUTH_DATA_LEN fits in u64");
    if len < min {
        return Err(format!(
            "FIDO2 auth_data length {len} is shorter than minimum {MIN_AUTH_DATA_LEN} bytes"
        ));
    }
    if len > max {
        return Err(format!(
            "FIDO2 auth_data length {len} exceeds maximum {MAX_AUTH_DATA_LEN} bytes"
        ));
    }
    Ok(usize::try_from(len).expect("validated auth_data length <= 16384 fits in usize"))
}

fn validate_credential_id_b64(credential_id_b64: &str) -> Result<(), AnchorError> {
    let decoded = decode_standard(credential_id_b64).map_err(|err| {
        AnchorError::InvalidCredential(format!("invalid credential_id_b64: {err}"))
    })?;
    if decoded.is_empty() {
        return Err(AnchorError::InvalidCredential(
            "credential_id_b64 must not be empty".to_string(),
        ));
    }
    if decoded.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(AnchorError::InvalidCredential(format!(
            "credential_id length {} exceeds maximum {MAX_CREDENTIAL_ID_LEN} bytes",
            decoded.len()
        )));
    }
    Ok(())
}

fn validate_device_path(path: &str) -> Result<(), AnchorError> {
    if path.is_empty() {
        return Err(AnchorError::InvalidCredential(
            "FIDO2 device path must not be empty".to_string(),
        ));
    }
    if path.starts_with('-') {
        return Err(AnchorError::InvalidCredential(format!(
            "FIDO2 device path '{path}' must not start with '-'"
        )));
    }
    if path.chars().any(char::is_control) {
        return Err(AnchorError::InvalidCredential(
            "FIDO2 device path must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn take_u8(cursor: &mut &[u8]) -> Result<u8, AnchorError> {
    let (&byte, rest) = cursor.split_first().ok_or_else(|| {
        AnchorError::InvalidSignature("truncated FIDO2 assertion envelope version".to_string())
    })?;
    *cursor = rest;
    Ok(byte)
}

fn take_u16_be(cursor: &mut &[u8]) -> Result<u16, AnchorError> {
    let slice = take_slice(cursor, 2, "rp_id length")?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn take_u32_be(cursor: &mut &[u8]) -> Result<u32, AnchorError> {
    let slice = take_slice(cursor, 4, "auth_data length")?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn take_slice<'a>(cursor: &mut &'a [u8], len: usize, field: &str) -> Result<&'a [u8], AnchorError> {
    if cursor.len() < len {
        return Err(AnchorError::InvalidSignature(format!(
            "truncated FIDO2 assertion envelope while reading {field}: need {len} bytes, have {}",
            cursor.len()
        )));
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}
