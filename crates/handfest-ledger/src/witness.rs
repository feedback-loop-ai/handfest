//! External checkpoint witnessing types, [`CheckpointWitness`] seam, and [`WitnessRegistry`].
//!
//! Checkpoints contain strictly public digest/sequence metadata (32-byte SHA-256 tips, sequence
//! counters, and UTC timestamps) — never private receipt payloads (`actor_key`, `action`,
//! `resource_id`, `deny_reason`, or mandate/revocation prose).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use handfest_core::ast::{decode_lower_hex_32, encode_lower_hex, is_valid_timestamp, MandateId};
use handfest_core::base64::decode_standard;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for canonical [`LedgerCheckpoint::checkpoint_digest`] hashing.
pub const CHECKPOINT_DIGEST_DOMAIN_PREFIX: &[u8] = b"handfest-v1-checkpoint\0";

/// Domain-separation prefix for append-only [`StoredCheckpoint`] hash-chain records.
const CHECKPOINT_RECORD_HASH_PREFIX: &[u8] = b"handfest-v1-checkpoint-record\0";

/// Maximum length in bytes of a [`WitnessProof::witness_kind`] identifier.
const MAX_WITNESS_KIND_LEN: usize = 64;

/// Zero-valued 32-byte digest used exclusively when `receipt_seq == 0` (no receipts recorded yet).
pub const EMPTY_RECEIPT_TIP_HASH: [u8; 32] = [0u8; 32];

/// Public, privacy-preserving snapshot of a ledger's hash-chain tips suitable for external
/// anchoring.
///
/// Contains only sequence numbers, 32-byte SHA-256 digests, and a UTC Unix timestamp — zero
/// private receipt or revocation payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCheckpoint {
    pub receipt_seq: u64,
    #[serde(with = "hex_32_serde")]
    pub receipt_hash: [u8; 32],
    pub revocation_seq: u64,
    #[serde(with = "opt_hex_32_serde")]
    pub revocation_tip_hash: Option<[u8; 32]>,
    pub timestamp: i64,
}

impl LedgerCheckpoint {
    /// Validates structural invariants of this checkpoint, failing closed on invalid timestamps
    /// or inconsistent empty-chain tips.
    pub fn validate(&self) -> Result<(), WitnessError> {
        if self.receipt_seq == 0 && self.receipt_hash != EMPTY_RECEIPT_TIP_HASH {
            return Err(WitnessError::InvalidCheckpoint(
                "receipt_seq == 0 requires all-zero receipt_hash".to_string(),
            ));
        }
        if self.receipt_seq > 0 && self.receipt_hash == EMPTY_RECEIPT_TIP_HASH {
            return Err(WitnessError::InvalidCheckpoint(
                "receipt_seq > 0 requires non-zero receipt_hash".to_string(),
            ));
        }
        if self.revocation_seq == 0 && self.revocation_tip_hash.is_some() {
            return Err(WitnessError::InvalidCheckpoint(
                "revocation_seq == 0 requires revocation_tip_hash == None".to_string(),
            ));
        }
        if self.revocation_seq > 0 && self.revocation_tip_hash.is_none() {
            return Err(WitnessError::InvalidCheckpoint(
                "revocation_seq > 0 requires Some(revocation_tip_hash)".to_string(),
            ));
        }
        if !is_valid_timestamp(self.timestamp) {
            return Err(WitnessError::InvalidCheckpoint(format!(
                "timestamp {} outside valid RFC 3339 range",
                self.timestamp
            )));
        }
        Ok(())
    }

    /// Computes the canonical 32-byte SHA-256 digest of this checkpoint:
    /// `SHA-256("handfest-v1-checkpoint\0" || receipt_seq || receipt_hash || revocation_seq ||
    ///  revocation_tip_tag || [revocation_tip_hash] || timestamp)`.
    #[must_use]
    pub fn checkpoint_digest(&self) -> [u8; 32] {
        let mut buf =
            Vec::with_capacity(CHECKPOINT_DIGEST_DOMAIN_PREFIX.len() + 8 + 32 + 8 + 33 + 8);
        buf.extend_from_slice(CHECKPOINT_DIGEST_DOMAIN_PREFIX);
        buf.extend_from_slice(&self.receipt_seq.to_be_bytes());
        buf.extend_from_slice(&self.receipt_hash);
        buf.extend_from_slice(&self.revocation_seq.to_be_bytes());
        match self.revocation_tip_hash {
            None => buf.push(0u8),
            Some(tip) => {
                buf.push(1u8);
                buf.extend_from_slice(&tip);
            }
        }
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        *MandateId::sha256(&buf).as_bytes()
    }

    /// Returns [`Self::checkpoint_digest`] encoded as 64 lowercase hexadecimal ASCII characters.
    #[must_use]
    pub fn checkpoint_digest_hex(&self) -> String {
        encode_lower_hex(&self.checkpoint_digest())
    }
}

/// Cryptographic or transparency-log proof returned by a [`CheckpointWitness`] anchoring a
/// [`LedgerCheckpoint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessProof {
    pub witness_kind: String,
    pub checkpoint_digest_hex: String,
    pub proof_bytes_b64: String,
    pub anchored_at: i64,
}

/// Runtime policy controlling when [`crate::AnchoredLedger`] invokes external checkpoint
/// witnessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WitnessPolicy {
    /// Default: zero witness invocations, zero sidecar I/O, zero overhead.
    #[default]
    Disabled,
    /// Fail closed if anchoring fails on every `Permit` receipt or `record_revocation`.
    SyncStrict,
    /// Anchor on `Permit` once at least `every_n_receipts` receipts have accumulated since the
    /// last anchored receipt sequence, and optionally anchor synchronously on `record_revocation`.
    BatchEvery {
        every_n_receipts: u64,
        sync_revocations: bool,
    },
}

impl WitnessPolicy {
    /// Validates policy invariants (`every_n_receipts >= 1`).
    pub fn validate(self) -> Result<(), WitnessError> {
        match self {
            Self::Disabled | Self::SyncStrict => Ok(()),
            Self::BatchEvery {
                every_n_receipts, ..
            } => {
                if every_n_receipts == 0 {
                    return Err(WitnessError::InvalidConfig(
                        "BatchEvery::every_n_receipts must be at least 1".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Structured errors returned by [`CheckpointWitness`] backends and proof validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    InvalidCheckpoint(String),
    InvalidProof(String),
    InvalidConfig(String),
    KindMismatch {
        expected: String,
        actual: String,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
    UnsupportedWitnessKind(String),
    VerificationFailed(String),
    CommandIo {
        program: String,
        detail: String,
    },
    CommandFailed {
        program: String,
        status: Option<i32>,
        stderr: String,
    },
    TempFileIo(String),
    Backend(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCheckpoint(msg) => write!(f, "invalid ledger checkpoint: {msg}"),
            Self::InvalidProof(msg) => write!(f, "invalid witness proof: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid witness configuration: {msg}"),
            Self::KindMismatch { expected, actual } => write!(
                f,
                "witness kind mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "checkpoint digest mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::UnsupportedWitnessKind(kind) => {
                if kind == "ots" && !cfg!(feature = "witness-ots") {
                    write!(
                        f,
                        "unsupported witness kind 'ots' (rebuild with feature 'witness-ots' to verify OpenTimestamps proofs)"
                    )
                } else {
                    write!(f, "unsupported witness kind '{kind}'")
                }
            }
            Self::VerificationFailed(msg) => write!(f, "witness verification failed: {msg}"),
            Self::CommandIo { program, detail } => {
                write!(f, "witness command '{program}' I/O error: {detail}")
            }
            Self::CommandFailed {
                program,
                status,
                stderr,
            } => write!(
                f,
                "witness command '{program}' failed (status {status:?}): {stderr}"
            ),
            Self::TempFileIo(msg) => write!(f, "witness temporary file error: {msg}"),
            Self::Backend(msg) => write!(f, "witness backend error: {msg}"),
        }
    }
}

impl std::error::Error for WitnessError {}

/// Pluggable external checkpoint witness seam (OpenTimestamps, transparency logs, RFC 3161, mocks).
///
/// Every implementation must uphold the same fail-closed contract:
/// - Anchor only the canonical 32-byte digest from [`LedgerCheckpoint::checkpoint_digest`].
/// - Return a [`WitnessProof`] whose `witness_kind` matches [`Self::witness_kind`] and whose
///   `checkpoint_digest_hex` matches [`LedgerCheckpoint::checkpoint_digest_hex`].
/// - Reject mutated digests, invalid proof encodings, or unverified proofs in [`Self::verify`].
pub trait CheckpointWitness {
    /// Canonical lowercase identifier for this witness backend (e.g. `"ots"`, `"http-log"`).
    fn witness_kind(&self) -> &str;

    /// Anchors `cp` to the external witness and returns the resulting [`WitnessProof`].
    fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError>;

    /// Verifies that `proof` authentically witnesses `cp`.
    fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError>;
}

/// Composable registry mapping `witness_kind` identifiers to [`CheckpointWitness`] verifiers.
#[derive(Default)]
pub struct WitnessRegistry {
    witnesses: BTreeMap<String, Box<dyn CheckpointWitness>>,
}

impl fmt::Debug for WitnessRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kinds: Vec<&str> = self.witnesses.keys().map(String::as_str).collect();
        f.debug_struct("WitnessRegistry")
            .field("kinds", &kinds)
            .finish()
    }
}

impl WitnessRegistry {
    /// Creates an empty [`WitnessRegistry`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`WitnessRegistry`] populated with all compiled-in witness adapters
    /// (currently `"ots"` when feature `witness-ots` is enabled).
    #[must_use]
    pub fn with_defaults() -> Self {
        #[cfg(feature = "witness-ots")]
        {
            let mut registry = Self::new();
            registry
                .register(crate::OtsWitness::new())
                .expect("built-in OtsWitness kind is valid");
            registry
        }
        #[cfg(not(feature = "witness-ots"))]
        {
            Self::new()
        }
    }

    /// Registers a [`CheckpointWitness`] verifier under its [`CheckpointWitness::witness_kind`].
    pub fn register<W: CheckpointWitness + 'static>(
        &mut self,
        witness: W,
    ) -> Result<(), WitnessError> {
        let kind = witness.witness_kind().to_string();
        validate_witness_kind(&kind)?;
        self.witnesses.insert(kind, Box::new(witness));
        Ok(())
    }

    /// Returns `true` if a verifier for `kind` is registered.
    #[must_use]
    pub fn contains(&self, kind: &str) -> bool {
        self.witnesses.contains_key(kind)
    }

    /// Dispatches verification of `(cp, proof)` to the registered witness matching
    /// `proof.witness_kind`, failing closed if the kind is unknown or proof validation fails.
    pub fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError> {
        validate_proof_shape(cp, proof)?;
        let Some(witness) = self.witnesses.get(&proof.witness_kind) else {
            return Err(WitnessError::UnsupportedWitnessKind(
                proof.witness_kind.clone(),
            ));
        };
        witness.verify(cp, proof)
    }
}

/// Append-only hash-chained checkpoint record persisted in the dedicated sidecar log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCheckpoint {
    pub seq: u64,
    pub prev_record_hash: Option<String>,
    pub record_hash: String,
    pub checkpoint: LedgerCheckpoint,
    pub proof: WitnessProof,
}

impl StoredCheckpoint {
    /// Computes the canonical `sha256:<64-lowercase-hex>` hash binding `seq`, `prev_record_hash`,
    /// `checkpoint`, and `proof`.
    #[must_use]
    pub fn compute_record_hash(
        seq: u64,
        prev_record_hash: Option<&str>,
        checkpoint: &LedgerCheckpoint,
        proof: &WitnessProof,
    ) -> String {
        let mut buf = Vec::with_capacity(
            CHECKPOINT_RECORD_HASH_PREFIX.len()
                + 8
                + 65
                + 32
                + proof.witness_kind.len()
                + proof.checkpoint_digest_hex.len()
                + proof.proof_bytes_b64.len()
                + 32,
        );
        buf.extend_from_slice(CHECKPOINT_RECORD_HASH_PREFIX);
        buf.extend_from_slice(&seq.to_be_bytes());
        match prev_record_hash {
            None => buf.push(0u8),
            Some(prev) => {
                buf.push(1u8);
                push_len_prefixed(&mut buf, prev.as_bytes());
            }
        }
        buf.extend_from_slice(&checkpoint.checkpoint_digest());
        push_len_prefixed(&mut buf, proof.witness_kind.as_bytes());
        push_len_prefixed(&mut buf, proof.checkpoint_digest_hex.as_bytes());
        push_len_prefixed(&mut buf, proof.proof_bytes_b64.as_bytes());
        buf.extend_from_slice(&proof.anchored_at.to_be_bytes());
        MandateId::sha256(&buf).to_string()
    }
}

/// Derives the canonical checkpoint sidecar path (`<ledger_path>.checkpoints.jsonl`) for a
/// file-backed ledger.
#[must_use]
pub fn default_checkpoint_sidecar_path(ledger_path: &Path) -> PathBuf {
    let mut os = ledger_path.as_os_str().to_os_string();
    os.push(".checkpoints.jsonl");
    PathBuf::from(os)
}

/// Canonically resolves `ledger_path` (matching [`crate::SqliteLedger::open_read_only`]) and
/// derives `<canonical_ledger_path>.checkpoints.jsonl` so symlinks to a ledger resolve the
/// canonical ledger's checkpoint sidecar.
pub fn canonical_checkpoint_sidecar_path(
    ledger_path: &Path,
) -> Result<PathBuf, crate::LedgerError> {
    let canonical = std::fs::canonicalize(ledger_path).map_err(|err| {
        crate::preflight_open::map_read_only_canonicalize_error(ledger_path, &err)
    })?;
    Ok(default_checkpoint_sidecar_path(&canonical))
}

/// Validates a witness kind identifier (`[a-z0-9][a-z0-9_-]*`, 1..=64 bytes).
pub fn validate_witness_kind(kind: &str) -> Result<(), WitnessError> {
    if kind.is_empty() || kind.len() > MAX_WITNESS_KIND_LEN {
        return Err(WitnessError::InvalidConfig(format!(
            "witness kind '{kind}' must be 1..={MAX_WITNESS_KIND_LEN} bytes"
        )));
    }
    let mut bytes = kind.bytes();
    let first = bytes.next().expect("non-empty checked above");
    if !(first.is_ascii_lowercase() || first.is_ascii_digit())
        || !bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(WitnessError::InvalidConfig(format!(
            "witness kind '{kind}' must match [a-z0-9][a-z0-9_-]*"
        )));
    }
    Ok(())
}

/// Validates `cp`, `proof` formatting/encoding, digest match, and exact `expected_kind` match.
pub fn validate_witness_proof(
    cp: &LedgerCheckpoint,
    proof: &WitnessProof,
    expected_kind: &str,
) -> Result<(), WitnessError> {
    let _ = validate_and_decode_witness_proof(cp, proof, expected_kind)?;
    Ok(())
}

/// Validates `cp`, `proof`, and `expected_kind` and returns the decoded raw proof bytes.
pub(crate) fn validate_and_decode_witness_proof(
    cp: &LedgerCheckpoint,
    proof: &WitnessProof,
    expected_kind: &str,
) -> Result<Vec<u8>, WitnessError> {
    validate_witness_kind(expected_kind)?;
    if proof.witness_kind != expected_kind {
        return Err(WitnessError::KindMismatch {
            expected: expected_kind.to_string(),
            actual: proof.witness_kind.clone(),
        });
    }
    validate_and_decode_proof_shape(cp, proof)
}

/// Validates `cp`, `proof.witness_kind` syntax, digest match, strict non-empty RFC 4648 base64
/// proof bytes, and `anchored_at` RFC 3339 range.
pub(crate) fn validate_proof_shape(
    cp: &LedgerCheckpoint,
    proof: &WitnessProof,
) -> Result<(), WitnessError> {
    let _ = validate_and_decode_proof_shape(cp, proof)?;
    Ok(())
}

fn validate_and_decode_proof_shape(
    cp: &LedgerCheckpoint,
    proof: &WitnessProof,
) -> Result<Vec<u8>, WitnessError> {
    cp.validate()?;
    validate_witness_kind(&proof.witness_kind).map_err(|_| {
        WitnessError::InvalidProof(format!("invalid witness_kind '{}'", proof.witness_kind))
    })?;

    let expected_hex = cp.checkpoint_digest_hex();
    if decode_lower_hex_32(&proof.checkpoint_digest_hex).is_err() {
        return Err(WitnessError::InvalidProof(format!(
            "invalid checkpoint_digest_hex '{}': expected 64 lowercase hex chars",
            proof.checkpoint_digest_hex
        )));
    }
    if proof.checkpoint_digest_hex != expected_hex {
        return Err(WitnessError::DigestMismatch {
            expected: expected_hex,
            actual: proof.checkpoint_digest_hex.clone(),
        });
    }

    let decoded = decode_standard(&proof.proof_bytes_b64)
        .map_err(|err| WitnessError::InvalidProof(format!("invalid proof_bytes_b64: {err}")))?;
    if decoded.is_empty() {
        return Err(WitnessError::InvalidProof(
            "proof_bytes_b64 must decode to non-empty proof bytes".to_string(),
        ));
    }

    if !is_valid_timestamp(proof.anchored_at) {
        return Err(WitnessError::InvalidProof(format!(
            "anchored_at {} outside valid RFC 3339 range",
            proof.anchored_at
        )));
    }
    Ok(decoded)
}

fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("slice byte length fits in u64");
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

mod hex_32_serde {
    use handfest_core::ast::{decode_lower_hex_32, encode_lower_hex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_lower_hex(bytes))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        decode_lower_hex_32(&raw).map_err(serde::de::Error::custom)
    }
}

mod opt_hex_32_serde {
    use handfest_core::ast::{decode_lower_hex_32, encode_lower_hex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(raw) => serializer.serialize_some(&encode_lower_hex(raw)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(raw) => decode_lower_hex_32(&raw)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}
