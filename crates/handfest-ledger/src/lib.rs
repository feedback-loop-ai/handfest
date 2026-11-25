//! Hash-chained receipt ledger abstraction, transactional SQLite store, atomic chain-wide quota
//! tracking, and offline audit replay.

mod audit;
mod codec;
mod quotas;
mod sqlite;

use std::fmt;

use handfest_core::ast::KeyId;
use handfest_core::gate::{ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate};
use serde::{Deserialize, Serialize};

pub use handfest_core::Verdict;
pub use sqlite::SqliteLedger;

use crate::codec::key_id_serde;

/// Errors returned by [`ReceiptLedger`] implementations.
#[derive(Debug)]
pub enum LedgerError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Integrity(String),
    QuotaAccounting(String),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(f, "sqlite error: {err}"),
            Self::Json(err) => write!(f, "json serialization error: {err}"),
            Self::Integrity(msg) => write!(f, "ledger integrity error: {msg}"),
            Self::QuotaAccounting(msg) => write!(f, "quota accounting error: {msg}"),
        }
    }
}

impl std::error::Error for LedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Integrity(_) | Self::QuotaAccounting(_) => None,
        }
    }
}

impl From<rusqlite::Error> for LedgerError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for LedgerError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

/// Actor track-record projection derived from persisted [`DecisionReceipt`] rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// - `verify_integrity` and `audit_snapshot` verify receipt continuity, receipt hashes, and
///   quota state consistency inside a single atomic read snapshot, failing closed on any tamper
///   or corruption.
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

    /// Verifies receipt ordering, hash-chain continuity from genesis to tip, every receipt hash,
    /// and persisted quota consistency inside a single read snapshot.
    fn verify_integrity(&self) -> Result<usize, LedgerError> {
        self.audit_snapshot(None).map(|(count, _)| count)
    }

    /// Computes a [`TrackRecord`] projection for `actor_key` from persisted receipts.
    fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError>;

    /// Verifies ledger integrity and optionally computes a [`TrackRecord`] projection for
    /// `actor_key` inside a single consistent read snapshot.
    fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError>;
}
