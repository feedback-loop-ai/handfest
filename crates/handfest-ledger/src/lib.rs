//! Hash-chained receipt ledger abstraction, transactional SQLite store, atomic chain-wide quota
//! tracking, and offline audit replay.

mod audit;
mod codec;
#[cfg(all(test, unix))]
mod lock_probe_test_util;
mod preflight;
mod quotas;
mod schema;
mod sqlite;

use std::fmt;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate};
use serde::{Deserialize, Serialize};

pub use handfest_core::Verdict;
pub use sqlite::SqliteLedger;

use crate::codec::key_id_serde;

/// Errors returned by [`ReceiptLedger`] implementations.
#[derive(Debug)]
pub enum LedgerError {
    NotFound(String),
    Storage(String),
    Json(serde_json::Error),
    Integrity(String),
    QuotaAccounting(String),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "ledger not found: {msg}"),
            Self::Storage(msg) => write!(f, "ledger storage error: {msg}"),
            Self::Json(err) => write!(f, "json serialization error: {err}"),
            Self::Integrity(msg) => write!(f, "ledger integrity error: {msg}"),
            Self::QuotaAccounting(msg) => write!(f, "quota accounting error: {msg}"),
        }
    }
}

impl std::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
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
    ) -> Result<(Verdict, DecisionReceipt), LedgerError>;

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
