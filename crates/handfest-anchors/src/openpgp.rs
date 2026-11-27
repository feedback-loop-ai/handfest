//! OpenPGP / GPG smartcard Ed25519 trust-anchor verifier and hardware signer.
//!
//! Implements a pure-Rust, zero-new-dependency RFC 4880 / RFC 6637 / RFC 9580 v4 EdDSA
//! (Ed25519) detached signature verifier, OpenPGP public-key packet extractor (`gpg --export`),
//! and [`MandateSigner`] backed by `gpg --detach-sign` over [`CommandRunner`].

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use handfest_core::ast::KeyId;
use handfest_core::gate::{VerifiedAnchorProof, VerifiedMandate, VerifiedRevocation};
use sha2::{Digest, Sha256, Sha512};

use crate::{
    decode_lower_hex_vec, signing_payload, validate_envelope_header, AnchorError, AnchorVerifier,
    AssuranceLevel, CommandRunner, MandateSigner, SignedMandate, SignedRevocation,
    SystemCommandRunner,
};

/// Canonical `KeyId` scheme for OpenPGP / GPG smartcard Ed25519 trust anchors.
pub const OPENPGP_ED25519_SCHEME: &str = "openpgp-ed25519";

const PACKET_TAG_SIGNATURE: u8 = 2;
const PACKET_TAG_PUBLIC_KEY: u8 = 6;
const PACKET_TAG_PUBLIC_SUBKEY: u8 = 14;

const OPENPGP_VERSION_4: u8 = 4;
const SIG_TYPE_BINARY_DOCUMENT: u8 = 0x00;
const PUBKEY_ALG_EDDSA: u8 = 22;
const HASH_ALG_SHA256: u8 = 8;
const HASH_ALG_SHA512: u8 = 10;

/// DER-encoded OID value for Ed25519 (`1.3.6.1.4.1.11591.15.1`, RFC 6637 / RFC 9580).
const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const ED25519_NATIVE_POINT_PREFIX: u8 = 0x40;

/// Derives the canonical `KeyId` (`openpgp-ed25519:<64-lowercase-hex>`) from a 32-byte Ed25519
/// public key.
#[must_use]
pub fn openpgp_ed25519_key_id(public_key: &[u8; 32]) -> KeyId {
    let pub_hex = hex::encode(public_key);
    KeyId::new(OPENPGP_ED25519_SCHEME, pub_hex)
        .expect("hex-encoded openpgp-ed25519 key is always a valid KeyId")
}

/// Strict pure-Rust RFC 4880 / RFC 9580 OpenPGP Ed25519 detached signature verifier
/// (`AssuranceLevel::Passkey`).
#[derive(Debug, Default, Clone, Copy)]
pub struct OpenPgpEd25519Verifier;

impl AnchorVerifier for OpenPgpEd25519Verifier {
    fn verify(&self, signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
        verify_openpgp_ed25519(signed)
    }

    fn verify_revocation(
        &self,
        signed: &SignedRevocation,
    ) -> Result<VerifiedRevocation, AnchorError> {
        crate::verify_revocation_openpgp_ed25519(signed)
    }
}

/// Verifies a single OpenPGP Ed25519 (`openpgp-ed25519:<hex>`) [`SignedMandate`] envelope and
/// returns a [`VerifiedMandate`].
pub fn verify_openpgp_ed25519(signed: &SignedMandate) -> Result<VerifiedMandate, AnchorError> {
    let header = validate_envelope_header(signed, OPENPGP_ED25519_SCHEME, AssuranceLevel::Passkey)?;
    let sig_packet =
        decode_lower_hex_vec(&signed.signature_hex).map_err(AnchorError::InvalidSignature)?;
    let payload = signing_payload(signed);
    verify_openpgp_detached_signature(&header.verifying_key, &payload, &sig_packet)?;

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

/// Hardware-backed OpenPGP / GPG smartcard [`MandateSigner`] (`AssuranceLevel::Passkey`).
///
/// Invokes `gpg --batch --yes --status-fd 2 --local-user <fpr> --digest-algo SHA256 --detach-sign`
/// through [`CommandRunner`] so signing delegates to `gpg-agent` / `scdaemon` (and physical YubiKey
/// touch) while keeping tests 100% offline and deterministic.
#[derive(Clone)]
pub struct OpenPgpEd25519Signer<R: CommandRunner = SystemCommandRunner> {
    runner: R,
    gpg_key_fingerprint: String,
    verifying_key: VerifyingKey,
}

impl<R: CommandRunner> fmt::Debug for OpenPgpEd25519Signer<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPgpEd25519Signer")
            .field("gpg_key_fingerprint", &self.gpg_key_fingerprint)
            .field("key_id", &self.key_id().to_string())
            .finish()
    }
}

impl OpenPgpEd25519Signer<SystemCommandRunner> {
    /// Exports `gpg_key_fingerprint` via `gpg --batch --export <fpr>`, extracts the matching
    /// Ed25519 public key packet, and constructs a production [`OpenPgpEd25519Signer`].
    pub fn from_gpg_export(gpg_key_fingerprint: impl Into<String>) -> Result<Self, AnchorError> {
        Self::from_gpg_export_with(SystemCommandRunner, gpg_key_fingerprint)
    }
}

impl<R: CommandRunner> OpenPgpEd25519Signer<R> {
    /// Constructs an [`OpenPgpEd25519Signer`] from a [`CommandRunner`], validated GPG key
    /// fingerprint/keygrip, and raw 32-byte Ed25519 public key.
    pub fn new(
        runner: R,
        gpg_key_fingerprint: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, AnchorError> {
        let gpg_key_fingerprint = gpg_key_fingerprint.into();
        let _ = normalize_gpg_fingerprint(&gpg_key_fingerprint)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;
        Ok(Self {
            runner,
            gpg_key_fingerprint,
            verifying_key,
        })
    }

    /// Exports `gpg_key_fingerprint` via `gpg --batch --export <fpr>` using `runner`, extracts the
    /// matching Ed25519 public key packet, and constructs an [`OpenPgpEd25519Signer`].
    pub fn from_gpg_export_with(
        runner: R,
        gpg_key_fingerprint: impl Into<String>,
    ) -> Result<Self, AnchorError> {
        let gpg_key_fingerprint = gpg_key_fingerprint.into();
        let _ = normalize_gpg_fingerprint(&gpg_key_fingerprint)?;
        let output = runner.run("gpg", &["--batch", "--export", &gpg_key_fingerprint], &[])?;
        let public_key =
            extract_ed25519_public_key_for_fingerprint(&output.stdout, &gpg_key_fingerprint)?;
        Self::new(runner, gpg_key_fingerprint, public_key)
    }

    /// Returns the configured GPG key fingerprint or keygrip.
    #[must_use]
    pub fn gpg_key_fingerprint(&self) -> &str {
        &self.gpg_key_fingerprint
    }

    /// Returns the raw 32-byte Ed25519 public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Returns the canonical `openpgp-ed25519:<64-lowercase-hex>` [`KeyId`].
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        openpgp_ed25519_key_id(&self.public_key_bytes())
    }
}

impl<R: CommandRunner> MandateSigner for OpenPgpEd25519Signer<R> {
    fn key_id(&self) -> KeyId {
        OpenPgpEd25519Signer::key_id(self)
    }

    fn assurance(&self) -> AssuranceLevel {
        AssuranceLevel::Passkey
    }

    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, AnchorError> {
        let output = self.runner.run(
            "gpg",
            &[
                "--batch",
                "--yes",
                "--status-fd",
                "2",
                "--local-user",
                &self.gpg_key_fingerprint,
                "--digest-algo",
                "SHA256",
                "--detach-sign",
            ],
            payload,
        )?;
        if output.stdout.is_empty() {
            return Err(AnchorError::InvalidSignature(
                "gpg produced an empty detached signature".to_string(),
            ));
        }
        verify_openpgp_detached_signature(&self.verifying_key, payload, &output.stdout)?;
        Ok(output.stdout)
    }
}

/// Extracts a single unambiguous Ed25519 public key (OID `1.3.6.1.4.1.11591.15.1`, stripping the
/// `0x40` native-point compression prefix) from raw binary `gpg --export` output.
pub fn extract_ed25519_public_key(exported: &[u8]) -> Result<[u8; 32], AnchorError> {
    if exported.is_empty() {
        return Err(AnchorError::InvalidPublicKey(
            "empty OpenPGP public key export".to_string(),
        ));
    }
    let mut rest = exported;
    let mut found: Option<[u8; 32]> = None;

    while !rest.is_empty() {
        let (packet, next) = parse_packet(rest).map_err(AnchorError::InvalidPublicKey)?;
        rest = next;
        if packet.tag != PACKET_TAG_PUBLIC_KEY && packet.tag != PACKET_TAG_PUBLIC_SUBKEY {
            continue;
        }
        if let Some(key) = try_parse_ed25519_public_key_packet(packet.body)? {
            if found.replace(key).is_some() {
                return Err(AnchorError::InvalidPublicKey(
                    "multiple OpenPGP Ed25519 public keys found; specify a key fingerprint"
                        .to_string(),
                ));
            }
        }
    }

    found.ok_or_else(|| {
        AnchorError::InvalidPublicKey("no OpenPGP Ed25519 public key packet found".to_string())
    })
}

/// Extracts the Ed25519 public key whose RFC 4880 Section 12.2 v4 fingerprint matches
/// `fingerprint` (full 40-hex v4 fingerprint or 16-hex long key ID, with optional trailing `!`)
/// from raw binary `gpg --export` output.
pub fn extract_ed25519_public_key_for_fingerprint(
    exported: &[u8],
    fingerprint: &str,
) -> Result<[u8; 32], AnchorError> {
    let target = normalize_gpg_fingerprint(fingerprint)?;
    if exported.is_empty() {
        return Err(AnchorError::InvalidPublicKey(
            "empty OpenPGP public key export".to_string(),
        ));
    }

    let mut rest = exported;
    let mut matched: Option<[u8; 32]> = None;

    while !rest.is_empty() {
        let (packet, next) = parse_packet(rest).map_err(AnchorError::InvalidPublicKey)?;
        rest = next;
        if packet.tag != PACKET_TAG_PUBLIC_KEY && packet.tag != PACKET_TAG_PUBLIC_SUBKEY {
            continue;
        }
        let Some(body_after_version) = packet.body.strip_prefix(&[OPENPGP_VERSION_4]) else {
            continue;
        };
        let pkt_fpr = hex::encode(v4_public_key_fingerprint(packet.body)?);
        let is_match = if target.len() == 40 {
            pkt_fpr == target
        } else {
            pkt_fpr.ends_with(&target)
        };
        if !is_match {
            continue;
        }
        let key = parse_v4_ed25519_public_key_body(body_after_version)?;
        if matched.replace(key).is_some() {
            return Err(AnchorError::InvalidPublicKey(format!(
                "multiple OpenPGP public keys matched fingerprint '{fingerprint}'"
            )));
        }
    }

    matched.ok_or_else(|| {
        AnchorError::InvalidPublicKey(format!(
            "no OpenPGP public key packet matched fingerprint '{fingerprint}'"
        ))
    })
}

fn normalize_gpg_fingerprint(raw: &str) -> Result<String, AnchorError> {
    let stripped = raw.strip_suffix('!').unwrap_or(raw);
    if stripped.len() != 40 && stripped.len() != 16 {
        return Err(AnchorError::InvalidPublicKey(format!(
            "invalid GPG key fingerprint '{raw}': expected 16 or 40 hex characters (optional trailing '!')"
        )));
    }
    if !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AnchorError::InvalidPublicKey(format!(
            "invalid GPG key fingerprint '{raw}': must contain ASCII hexadecimal digits only"
        )));
    }
    Ok(stripped.to_ascii_lowercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenPgpHashAlg {
    Sha256,
    Sha512,
}

struct OpenPgpPacket<'a> {
    tag: u8,
    body: &'a [u8],
}

struct ParsedV4Signature<'a> {
    hash_alg: OpenPgpHashAlg,
    hashed_header: &'a [u8],
    hash_prefix: [u8; 2],
    signature: Signature,
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "OpenPGP packet length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated OpenPGP packet".to_string());
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn take_u16_be(&mut self) -> Result<u16, String> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

fn parse_packet(input: &[u8]) -> Result<(OpenPgpPacket<'_>, &[u8]), String> {
    let Some(&ptag) = input.first() else {
        return Err("empty OpenPGP packet".to_string());
    };
    if (ptag & 0x80) == 0 {
        return Err("invalid OpenPGP packet header: bit 7 must be set".to_string());
    }

    let (tag, header_len, body_len) = if (ptag & 0x40) != 0 {
        parse_new_packet_header(ptag, input)?
    } else {
        parse_old_packet_header(ptag, input)?
    };

    let end = header_len
        .checked_add(body_len)
        .ok_or_else(|| "OpenPGP packet length overflow".to_string())?;
    if end > input.len() {
        return Err("truncated OpenPGP packet body".to_string());
    }

    Ok((
        OpenPgpPacket {
            tag,
            body: &input[header_len..end],
        },
        &input[end..],
    ))
}

fn parse_new_packet_header(ptag: u8, input: &[u8]) -> Result<(u8, usize, usize), String> {
    let tag = ptag & 0x3f;
    let Some(&first) = input.get(1) else {
        return Err("truncated new-format OpenPGP packet header".to_string());
    };
    match first {
        0..=191 => Ok((tag, 2, usize::from(first))),
        192..=223 => {
            let Some(&second) = input.get(2) else {
                return Err("truncated 2-octet new-format OpenPGP packet length".to_string());
            };
            let len = ((usize::from(first) - 192) << 8) + usize::from(second) + 192;
            Ok((tag, 3, len))
        }
        255 => {
            if input.len() < 6 {
                return Err("truncated 5-octet new-format OpenPGP packet length".to_string());
            }
            let raw = u32::from_be_bytes([input[2], input[3], input[4], input[5]]);
            let len = usize::try_from(raw)
                .map_err(|_| "OpenPGP packet length exceeds usize".to_string())?;
            Ok((tag, 6, len))
        }
        224..=254 => Err("unsupported OpenPGP partial body length".to_string()),
    }
}

fn parse_old_packet_header(ptag: u8, input: &[u8]) -> Result<(u8, usize, usize), String> {
    let tag = (ptag >> 2) & 0x0f;
    match ptag & 0x03 {
        0 => {
            let Some(&len) = input.get(1) else {
                return Err("truncated 1-octet old-format OpenPGP packet length".to_string());
            };
            Ok((tag, 2, usize::from(len)))
        }
        1 => {
            if input.len() < 3 {
                return Err("truncated 2-octet old-format OpenPGP packet length".to_string());
            }
            let len = usize::from(u16::from_be_bytes([input[1], input[2]]));
            Ok((tag, 3, len))
        }
        2 => {
            if input.len() < 5 {
                return Err("truncated 4-octet old-format OpenPGP packet length".to_string());
            }
            let raw = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
            let len = usize::try_from(raw)
                .map_err(|_| "OpenPGP packet length exceeds usize".to_string())?;
            Ok((tag, 5, len))
        }
        _ => Err("unsupported OpenPGP indeterminate packet length".to_string()),
    }
}

fn parse_mpi_raw<'a>(cur: &mut ByteCursor<'a>, max_bits: usize) -> Result<&'a [u8], String> {
    let bit_len = usize::from(cur.take_u16_be()?);
    if bit_len > max_bits {
        return Err(format!(
            "OpenPGP MPI bit length {bit_len} exceeds maximum {max_bits}"
        ));
    }
    if bit_len == 0 {
        return Ok(&[]);
    }
    let byte_len = bit_len.div_ceil(8);
    let raw = cur.take(byte_len)?;
    if raw[0] == 0 {
        return Err("non-canonical OpenPGP MPI with leading zero byte".to_string());
    }
    let msb_bits = usize::try_from(8 - raw[0].leading_zeros()).expect("u8 leading_zeros <= 8");
    let actual_bits = (byte_len - 1) * 8 + msb_bits;
    if actual_bits != bit_len {
        return Err(format!(
            "non-canonical OpenPGP MPI: declared {bit_len} bits, encoded {actual_bits} bits"
        ));
    }
    Ok(raw)
}

fn parse_mpi_32(cur: &mut ByteCursor<'_>) -> Result<[u8; 32], String> {
    let raw = parse_mpi_raw(cur, 256)?;
    let mut padded = [0u8; 32];
    padded[32 - raw.len()..].copy_from_slice(raw);
    Ok(padded)
}

fn parse_v4_eddsa_signature(packet_bytes: &[u8]) -> Result<ParsedV4Signature<'_>, AnchorError> {
    let (packet, trailing) = parse_packet(packet_bytes).map_err(AnchorError::InvalidSignature)?;
    if !trailing.is_empty() {
        return Err(AnchorError::InvalidSignature(
            "trailing bytes after OpenPGP signature packet".to_string(),
        ));
    }
    if packet.tag != PACKET_TAG_SIGNATURE {
        return Err(AnchorError::InvalidSignature(format!(
            "expected OpenPGP signature packet tag {PACKET_TAG_SIGNATURE}, got {}",
            packet.tag
        )));
    }

    let mut cur = ByteCursor::new(packet.body);
    let version = cur.take_u8().map_err(AnchorError::InvalidSignature)?;
    if version != OPENPGP_VERSION_4 {
        return Err(AnchorError::InvalidSignature(format!(
            "unsupported OpenPGP signature version {version} (expected 4)"
        )));
    }
    let sig_type = cur.take_u8().map_err(AnchorError::InvalidSignature)?;
    if sig_type != SIG_TYPE_BINARY_DOCUMENT {
        return Err(AnchorError::InvalidSignature(format!(
            "unsupported OpenPGP signature type 0x{sig_type:02x} (expected 0x00 binary document)"
        )));
    }
    let pubkey_alg = cur.take_u8().map_err(AnchorError::InvalidSignature)?;
    if pubkey_alg != PUBKEY_ALG_EDDSA {
        return Err(AnchorError::InvalidSignature(format!(
            "unsupported OpenPGP public-key algorithm {pubkey_alg} (expected {PUBKEY_ALG_EDDSA} EdDSA)"
        )));
    }
    let hash_alg = match cur.take_u8().map_err(AnchorError::InvalidSignature)? {
        HASH_ALG_SHA256 => OpenPgpHashAlg::Sha256,
        HASH_ALG_SHA512 => OpenPgpHashAlg::Sha512,
        other => {
            return Err(AnchorError::InvalidSignature(format!(
                "unsupported OpenPGP hash algorithm {other} (expected 8 SHA-256 or 10 SHA-512)"
            )));
        }
    };

    let hashed_len = usize::from(cur.take_u16_be().map_err(AnchorError::InvalidSignature)?);
    let _hashed_subpackets = cur
        .take(hashed_len)
        .map_err(AnchorError::InvalidSignature)?;
    let hashed_header = &packet.body[..6 + hashed_len];

    let unhashed_len = usize::from(cur.take_u16_be().map_err(AnchorError::InvalidSignature)?);
    let _unhashed_subpackets = cur
        .take(unhashed_len)
        .map_err(AnchorError::InvalidSignature)?;

    let hash_prefix = cur
        .take_array::<2>()
        .map_err(AnchorError::InvalidSignature)?;
    let r = parse_mpi_32(&mut cur).map_err(AnchorError::InvalidSignature)?;
    let s = parse_mpi_32(&mut cur).map_err(AnchorError::InvalidSignature)?;

    if cur.remaining() != 0 {
        return Err(AnchorError::InvalidSignature(
            "trailing bytes inside OpenPGP signature packet".to_string(),
        ));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r);
    sig_bytes[32..].copy_from_slice(&s);

    Ok(ParsedV4Signature {
        hash_alg,
        hashed_header,
        hash_prefix,
        signature: Signature::from_bytes(&sig_bytes),
    })
}

pub(crate) fn verify_openpgp_detached_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    packet_bytes: &[u8],
) -> Result<(), AnchorError> {
    let parsed = parse_v4_eddsa_signature(packet_bytes)?;
    let header_len = u32::try_from(parsed.hashed_header.len())
        .expect("v4 hashed header length <= 65541 always fits in u32");
    let [b0, b1, b2, b3] = header_len.to_be_bytes();
    let trailer = [OPENPGP_VERSION_4, 0xff, b0, b1, b2, b3];

    match parsed.hash_alg {
        OpenPgpHashAlg::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            hasher.update(parsed.hashed_header);
            hasher.update(trailer);
            let digest = hasher.finalize();
            verify_digest_and_signature(
                verifying_key,
                &digest,
                parsed.hash_prefix,
                &parsed.signature,
            )
        }
        OpenPgpHashAlg::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(payload);
            hasher.update(parsed.hashed_header);
            hasher.update(trailer);
            let digest = hasher.finalize();
            verify_digest_and_signature(
                verifying_key,
                &digest,
                parsed.hash_prefix,
                &parsed.signature,
            )
        }
    }
}

fn verify_digest_and_signature(
    verifying_key: &VerifyingKey,
    digest: &[u8],
    expected_prefix: [u8; 2],
    signature: &Signature,
) -> Result<(), AnchorError> {
    if digest[0] != expected_prefix[0] || digest[1] != expected_prefix[1] {
        return Err(AnchorError::InvalidSignature(
            "OpenPGP signature hash prefix mismatch".to_string(),
        ));
    }
    verifying_key
        .verify_strict(digest, signature)
        .map_err(|err| AnchorError::InvalidSignature(err.to_string()))
}

fn try_parse_ed25519_public_key_packet(body: &[u8]) -> Result<Option<[u8; 32]>, AnchorError> {
    if body.len() < 7 || body[0] != OPENPGP_VERSION_4 || body[5] != PUBKEY_ALG_EDDSA {
        return Ok(None);
    }
    let oid_len = usize::from(body[6]);
    let oid_end = 7 + oid_len;
    if oid_end > body.len() {
        return Err(AnchorError::InvalidPublicKey(
            "truncated OpenPGP EdDSA OID in public key packet".to_string(),
        ));
    }
    if &body[7..oid_end] != ED25519_OID {
        return Ok(None);
    }
    parse_v4_ed25519_public_key_body(&body[1..]).map(Some)
}

fn parse_v4_ed25519_public_key_body(body_after_version: &[u8]) -> Result<[u8; 32], AnchorError> {
    let mut cur = ByteCursor::new(body_after_version);
    let _creation_time = cur.take(4).map_err(AnchorError::InvalidPublicKey)?;
    let alg = cur.take_u8().map_err(AnchorError::InvalidPublicKey)?;
    if alg != PUBKEY_ALG_EDDSA {
        return Err(AnchorError::InvalidPublicKey(format!(
            "unsupported OpenPGP public-key algorithm {alg} (expected {PUBKEY_ALG_EDDSA} EdDSA)"
        )));
    }
    let oid_len = usize::from(cur.take_u8().map_err(AnchorError::InvalidPublicKey)?);
    let oid = cur.take(oid_len).map_err(AnchorError::InvalidPublicKey)?;
    if oid != ED25519_OID {
        return Err(AnchorError::InvalidPublicKey(
            "OpenPGP EdDSA key OID is not Ed25519 (1.3.6.1.4.1.11591.15.1)".to_string(),
        ));
    }

    let point = parse_mpi_raw(&mut cur, 264).map_err(AnchorError::InvalidPublicKey)?;
    if cur.remaining() != 0 {
        return Err(AnchorError::InvalidPublicKey(
            "trailing bytes inside OpenPGP Ed25519 public key packet".to_string(),
        ));
    }
    if point.len() != 33 || point[0] != ED25519_NATIVE_POINT_PREFIX {
        return Err(AnchorError::InvalidPublicKey(
            "invalid OpenPGP Ed25519 public key point encoding (expected 0x40 prefix + 32 bytes)"
                .to_string(),
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&point[1..33]);
    let _ = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| AnchorError::InvalidPublicKey(err.to_string()))?;
    Ok(key_bytes)
}

/// Computes the RFC 4880 Section 12.2 v4 public-key fingerprint:
/// `SHA-1(0x99 || be16(body.len()) || body)`.
fn v4_public_key_fingerprint(body: &[u8]) -> Result<[u8; 20], AnchorError> {
    let body_len = u16::try_from(body.len()).map_err(|_| {
        AnchorError::InvalidPublicKey("OpenPGP v4 public key packet exceeds 65535 bytes".into())
    })?;
    let mut preimage = Vec::with_capacity(3 + body.len());
    preimage.push(0x99);
    preimage.extend_from_slice(&body_len.to_be_bytes());
    preimage.extend_from_slice(body);
    Ok(sha1_digest(&preimage))
}

/// Pure-Rust FIPS 180-4 / RFC 3174 SHA-1 used exclusively for RFC 4880 Section 12.2 v4 key
/// fingerprint identification (never for signature hashing).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let bit_len = u64::try_from(data.len())
        .expect("input length fits in u64")
        .checked_mul(8)
        .expect("input bit length fits in u64");

    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];

    let (blocks, remainder) = padded.as_chunks::<64>();
    debug_assert!(remainder.is_empty());
    for block in blocks {
        sha1_compress_block(&mut state, block);
    }

    let mut out = [0u8; 20];
    for (idx, word) in state.iter().enumerate() {
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha1_compress_block(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    let (word_chunks, remainder) = block.as_chunks::<4>();
    debug_assert!(remainder.is_empty());
    for (i, &word_bytes) in word_chunks.iter().enumerate() {
        w[i] = u32::from_be_bytes(word_bytes);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &word) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_rfc3174_vectors() {
        assert_eq!(
            hex::encode(sha1_digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(sha1_digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn parse_packet_rejects_empty_slice() {
        let err = parse_packet(&[]).err().expect("empty slice must fail");
        assert!(err.contains("empty OpenPGP packet"), "{err}");
    }
}
