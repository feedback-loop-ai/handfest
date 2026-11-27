//! Hash-chained receipt ledger abstraction, transactional SQLite store, atomic chain-wide quota
//! tracking, and offline audit replay.

mod anchored;
mod audit;
mod checkpoint_store;
mod codec;
#[cfg(all(test, unix))]
mod lock_probe_test_util;
#[cfg(feature = "witness-ots")]
mod ots;
mod preflight;
mod preflight_open;
mod quotas;
mod revocations;
mod schema;
mod sqlite;
mod witness;

use std::fmt;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    check_chain_revocations, verify_chain_runtime, ActionRequest, DecisionReceipt,
    RevocationSnapshot, VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::RevocationId;
use serde::{Deserialize, Serialize};

pub use anchored::{
    verify_audit_snapshot_with_witness, verify_ledger_witness_checkpoints, AnchoredLedger,
};
pub use handfest_core::Verdict;
#[cfg(feature = "witness-ots")]
pub use ots::{
    CommandOutput, CommandRunner, OtsWitness, SystemCommandRunner, MAX_OTS_PROOF_BYTES,
    OTS_PROOF_MAGIC, OTS_WITNESS_KIND,
};
pub use preflight_open::open_no_follow_write_no_trunc;
pub use revocations::StoredRevocation;
pub use sqlite::SqliteLedger;
pub use witness::{
    canonical_checkpoint_sidecar_path, default_checkpoint_sidecar_path, validate_witness_kind,
    validate_witness_proof, CheckpointWitness, LedgerCheckpoint, StoredCheckpoint, WitnessError,
    WitnessPolicy, WitnessProof, WitnessRegistry, CHECKPOINT_DIGEST_DOMAIN_PREFIX,
    EMPTY_RECEIPT_TIP_HASH,
};

use crate::codec::key_id_serde;

/// Errors returned by [`ReceiptLedger`] implementations.
#[derive(Debug)]
pub enum LedgerError {
    NotFound(String),
    Storage(String),
    Json(serde_json::Error),
    Integrity(String),
    QuotaAccounting(String),
    Witness(WitnessError),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "ledger not found: {msg}"),
            Self::Storage(msg) => write!(f, "ledger storage error: {msg}"),
            Self::Json(err) => write!(f, "json serialization error: {err}"),
            Self::Integrity(msg) => write!(f, "ledger integrity error: {msg}"),
            Self::QuotaAccounting(msg) => write!(f, "quota accounting error: {msg}"),
            Self::Witness(err) => write!(f, "witness error: {err}"),
        }
    }
}

impl std::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::Witness(err) => Some(err),
            Self::NotFound(_)
            | Self::Storage(_)
            | Self::Integrity(_)
            | Self::QuotaAccounting(_) => None,
        }
    }
}

impl From<rusqlite::Error> for LedgerError {
    fn from(err: rusqlite::Error) -> Self {
        if matches!(
            err,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase,
                    ..
                },
                _,
            )
        ) {
            return Self::Integrity(err.to_string());
        }
        Self::Storage(err.to_string())
    }
}

impl From<serde_json::Error> for LedgerError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<WitnessError> for LedgerError {
    fn from(err: WitnessError) -> Self {
        Self::Witness(err)
    }
}

/// Ordered 32-byte SHA-256 hash-chain entries returned by [`ReceiptLedger::verified_chain_hashes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerChainHashes {
    pub receipt_hashes: Vec<[u8; 32]>,
    pub revocation_hashes: Vec<[u8; 32]>,
    /// 1-based receipt sequence number of the latest persisted `Verdict::Permit` receipt, or
    /// `None` if the ledger has zero `Permit` receipts (empty or `Deny`-only ledger).
    pub last_permit_seq: Option<u64>,
}

/// Complete integrity-verified audit snapshot captured inside a single consistent read transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSnapshot {
    pub verified_receipts: usize,
    pub track_record: Option<TrackRecord>,
    pub stored_revocations: Vec<StoredRevocation>,
    pub chain_hashes: Option<LedgerChainHashes>,
}

/// Actor track-record projection derived from persisted [`DecisionReceipt`] rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackRecord {
    #[serde(with = "key_id_serde")]
    pub actor_key: KeyId,
    pub total_decisions: u64,
    pub permits: u64,
    pub denies: u64,
    /// Number of distinct leaf mandates (`chain_ids.last()`) executed by this actor across its
    /// persisted `Permit` and `Deny` receipts (excluding intermediate delegator/root mandates).
    pub distinct_mandates: u64,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
}

/// Backend-agnostic seam for hash-chained decision receipt storage, atomic chain-wide quota
/// accounting, and offline integrity replay.
///
/// Every implementation must uphold the same fail-closed contract:
/// - `evaluate_and_record` atomically loads prior quotas, evaluates via
///   `handfest_core::gate::authorize`, persists the hash-chained receipt, and updates quotas
///   across every `MandateId` in `chain` only on `Verdict::Permit`.
/// - `record_denial` atomically persists a hash-chained pre-gate denial receipt constructed via
///   `handfest_core::gate::build_denial_receipt` without modifying quota counters.
/// - `verify_integrity`, `track_record`, and `audit_snapshot` verify full cryptographic hash-chain
///   continuity, exact `quota_calls` reconciliation, and structural `quota_sums` validity inside a
///   single atomic read snapshot, failing closed on any tamper or corruption.
pub trait ReceiptLedger {
    /// Atomically evaluates `chain` against `request` and `facts` at timestamp `now`, records the
    /// resulting hash-chained [`DecisionReceipt`], and on `Verdict::Permit` increments quotas
    /// across every `MandateId` in `chain`.
    fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        self.evaluate_and_record_with_revocations(
            chain,
            request,
            facts,
            &RevocationSnapshot::new(),
            now,
        )
    }

    /// Atomically loads persisted revocations and prior quotas, merges `extra_revocations`,
    /// evaluates `chain` via `handfest_core::gate::authorize_with_revocations`, records the
    /// resulting hash-chained [`DecisionReceipt`], and on `Verdict::Permit` increments quotas
    /// across every `MandateId` in `chain`.
    fn evaluate_and_record_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        extra_revocations: &RevocationSnapshot,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError>;

    /// Atomically persists a verified revocation into the tamper-evident ledger store without
    /// modifying any mandate quota counters.
    fn record_revocation(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
    ) -> Result<RevocationId, LedgerError>;

    /// Loads and integrity-verifies all persisted revocations as a [`RevocationSnapshot`].
    fn load_revocations(&self) -> Result<RevocationSnapshot, LedgerError>;

    /// Loads and integrity-verifies all persisted [`StoredRevocation`] records in canonical order.
    fn list_stored_revocations(&self) -> Result<Vec<StoredRevocation>, LedgerError>;

    /// Atomically builds a pre-gate denial receipt via
    /// `handfest_core::gate::build_denial_receipt` linked to the current hash-chain tip and
    /// persists it without modifying persisted quota counters.
    fn record_denial(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
    ) -> Result<DecisionReceipt, LedgerError>;

    /// Atomically verifies persisted revocations, merges `extra_revocations`, resolves the
    /// effective pre-gate denial reason (`verify_chain_runtime(chain, actor_key, now)` error >
    /// active revocation > `fallback_reason`), derives `chain_ids` directly from `chain`, and
    /// persists a hash-chained denial receipt inside a single atomic transaction without modifying
    /// quota counters.
    ///
    /// Postcondition: the persisted and returned [`DecisionReceipt`] always binds
    /// `receipt.actor_key` to `actor_key` (never to a mismatched `request.actor_key`), while
    /// preserving `request.action`, `request.resource_kind`, and `request.resource_id`.
    fn record_denial_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        actor_key: &KeyId,
        request: &ActionRequest,
        extra_revocations: &RevocationSnapshot,
        now: i64,
        fallback_reason: String,
    ) -> Result<(String, DecisionReceipt), LedgerError>;

    /// Verifies schema integrity, contiguous receipt ordering, full cryptographic hash-chain
    /// continuity from genesis to tip, every receipt hash, non-empty `chain_ids` on `Permit`
    /// receipts, exact `quota_calls` reconciliation against persisted `Permit` receipts, and
    /// structural `quota_sums` validation inside a single read snapshot.
    ///
    /// Note: `quota_sums` validation checks structural invariants (valid `MandateId` backed by at
    /// least one persisted `Permit`, valid `unit`/`field` syntax, non-negative canonical `Decimal`
    /// total, and no duplicate keys); exact sum totals depend on per-call runtime facts not stored
    /// in receipts.
    fn verify_integrity(&self) -> Result<usize, LedgerError> {
        self.audit_snapshot(None).map(|(count, _)| count)
    }

    /// Computes an integrity-verified [`TrackRecord`] projection for `actor_key` from persisted
    /// receipts inside a single consistent read snapshot.
    fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError>;

    /// Verifies ledger integrity and optionally computes a [`TrackRecord`] projection for
    /// `actor_key` inside a single consistent read snapshot.
    fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError>;

    /// Integrity-verifies the ledger inside a single consistent read snapshot and returns the
    /// ordered 32-byte SHA-256 receipt hashes (`seq = 1..=N`) and revocation entry hashes
    /// (`seq = 1..=M`) without exposing private receipt payloads.
    fn verified_chain_hashes(&self) -> Result<LedgerChainHashes, LedgerError>;
}

/// Bundled inputs for [`TransactionalLedger::evaluate_and_record_atomic`].
#[derive(Debug, Clone, Copy)]
pub struct AtomicEvalRequest<'a> {
    pub chain: &'a [VerifiedMandate],
    pub request: &'a ActionRequest,
    pub facts: &'a VerifiedFacts,
    pub extra_revocations: &'a RevocationSnapshot,
    pub now: i64,
}

/// Bundled inputs for [`TransactionalLedger::record_denial_with_revocations_atomic`].
#[derive(Debug)]
pub struct AtomicDenialWithRevocations<'a> {
    pub chain: &'a [VerifiedMandate],
    pub actor_key: &'a KeyId,
    pub request: &'a ActionRequest,
    pub extra_revocations: &'a RevocationSnapshot,
    pub now: i64,
    pub fallback_reason: String,
}

/// Synchronized read-snapshot seam for ledger backends (including read-only handles) that can hold
/// a consistent read lock/transaction across an external sidecar read.
///
/// Every implementation must keep its read lock/transaction (such as SQLite's `SHARED` lock) open
/// until `with_hashes` returns so external sidecar reads observe a writer-synchronized pair.
pub trait ReadSnapshotLedger {
    /// Integrity-verifies the ledger inside a single consistent read snapshot and invokes
    /// `with_hashes(&chain_hashes)` while the underlying read lock/snapshot is still held.
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>;
}

/// Transactional pre-insert and pre-commit hook seam for [`ReceiptLedger`] backends supporting
/// atomic rollback and serialized write locks across external sidecar coordination (such as
/// [`AnchoredLedger`]).
///
/// Every implementation must uphold the exact same fail-closed atomicity contract:
/// - Acquire an exclusive write lock (e.g. SQLite `BEGIN EXCLUSIVE`) before running
///   `before_insert` or mutating state, and hold it across `before_commit` and commit/rollback.
/// - Run `before_insert` BEFORE inserting any receipt, quota, or revocation rows so pre-insert
///   external sidecar checks catch even 1-row rollbacks + identical replays before any mutation.
/// - Drop any rollback guard `G` returned by `before_commit` INSIDE the exclusive lock scope
///   BEFORE releasing the transaction lock if `COMMIT` fails.
/// - On idempotent [`ReceiptLedger::record_revocation`] replay (no new row inserted), pass
///   `inserted_entry_hash = None` to `before_commit`.
pub trait TransactionalLedger: ReceiptLedger + ReadSnapshotLedger {
    /// Executes [`ReceiptLedger::evaluate_and_record_with_revocations`] inside an exclusive write
    /// transaction, invoking `before_insert` prior to any mutation and `before_commit` prior to
    /// `COMMIT`. Drops `G` inside the exclusive lock if `COMMIT` fails.
    fn evaluate_and_record_atomic<P, G, FPre, FPost>(
        &mut self,
        eval: AtomicEvalRequest<'_>,
        before_insert: FPre,
        before_commit: FPost,
    ) -> Result<((Verdict, DecisionReceipt), G), LedgerError>
    where
        FPre: FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<P, LedgerError>,
        FPost: FnOnce(
            P,
            &Verdict,
            &DecisionReceipt,
            &dyn Fn() -> Result<LedgerChainHashes, LedgerError>,
        ) -> Result<G, LedgerError>;

    /// Executes [`ReceiptLedger::record_revocation`] inside an exclusive write transaction,
    /// invoking `before_insert` prior to any mutation and
    /// `before_commit(pre_state, inserted_entry_hash, &load_post_hashes)` prior to `COMMIT`.
    /// Drops `G` inside the exclusive lock if `COMMIT` fails.
    fn record_revocation_atomic<P, G, FPre, FPost>(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
        before_insert: FPre,
        before_commit: FPost,
    ) -> Result<(RevocationId, G), LedgerError>
    where
        FPre: FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<P, LedgerError>,
        FPost: FnOnce(
            P,
            Option<[u8; 32]>,
            &dyn Fn() -> Result<LedgerChainHashes, LedgerError>,
        ) -> Result<G, LedgerError>;

    /// Executes [`ReceiptLedger::record_denial`] inside an exclusive write transaction, invoking
    /// `before_insert` prior to inserting the denial receipt.
    fn record_denial_atomic<FPre>(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
        before_insert: FPre,
    ) -> Result<DecisionReceipt, LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>;

    /// Executes [`ReceiptLedger::record_denial_with_revocations`] inside an exclusive write
    /// transaction, invoking `before_insert` prior to inserting the denial receipt.
    fn record_denial_with_revocations_atomic<FPre>(
        &mut self,
        denial: AtomicDenialWithRevocations<'_>,
        before_insert: FPre,
    ) -> Result<(String, DecisionReceipt), LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>;
}

/// Resolves the effective pre-gate denial reason with strict fail-closed precedence:
/// runtime chain verification error > active revocation > `fallback_reason`.
#[must_use]
pub fn resolve_pre_gate_denial_reason(
    chain: &[VerifiedMandate],
    actor_key: &KeyId,
    revocations: &RevocationSnapshot,
    now: i64,
    fallback_reason: String,
) -> String {
    match verify_chain_runtime(chain, actor_key, now) {
        Ok(()) => match check_chain_revocations(chain, revocations, now) {
            Ok(()) => fallback_reason,
            Err(rev_deny) => rev_deny.to_string(),
        },
        Err(chain_err) => chain_err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rusqlite_corrupt_and_notadb_errors_map_to_integrity_while_others_map_to_storage() {
        let corrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            Some("database disk image is malformed".to_string()),
        );
        assert!(matches!(
            LedgerError::from(corrupt),
            LedgerError::Integrity(_)
        ));

        let notadb = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
            Some("file is not a database".to_string()),
        );
        assert!(matches!(
            LedgerError::from(notadb),
            LedgerError::Integrity(_)
        ));

        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database is locked".to_string()),
        );
        assert!(matches!(LedgerError::from(busy), LedgerError::Storage(_)));
    }

    #[test]
    fn track_record_deserialization_rejects_unknown_fields() {
        let rec = TrackRecord {
            actor_key: KeyId::parse(
                "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            total_decisions: 1,
            permits: 1,
            denies: 0,
            distinct_mandates: 1,
            first_timestamp: Some(1_700_000_000),
            last_timestamp: Some(1_700_000_000),
        };
        let encoded = serde_json::to_string(&rec).unwrap();
        assert_eq!(serde_json::from_str::<TrackRecord>(&encoded).unwrap(), rec);

        let with_extra = format!(
            r#"{},"unexpected_field":true}}"#,
            &encoded[..encoded.len() - 1]
        );
        let err = serde_json::from_str::<TrackRecord>(&with_extra).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown field rejection, got: {err}"
        );
    }
}
