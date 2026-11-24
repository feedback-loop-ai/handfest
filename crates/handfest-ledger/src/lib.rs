//! Hash-chained SQLite receipt store, atomic chain-wide quota tracking, and offline audit replay.

mod codec;
mod quotas;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    authorize, ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub use handfest_core::Verdict;

use crate::codec::{
    format_resource, key_id_serde, parse_chain_ids_json, parse_optional_mandate_id, parse_verdict,
};
use crate::quotas::{apply_quota_updates, compute_quota_updates, load_quota_snapshot};

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS receipts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_receipt_hash TEXT,
    receipt_hash TEXT NOT NULL UNIQUE,
    chain_ids_json TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    deny_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_receipts_actor_key ON receipts(actor_key);

CREATE TABLE IF NOT EXISTS quota_calls (
    mandate_id TEXT PRIMARY KEY,
    calls INTEGER NOT NULL CHECK (calls >= 0)
);

CREATE TABLE IF NOT EXISTS quota_sums (
    mandate_id TEXT NOT NULL,
    unit TEXT NOT NULL,
    field TEXT NOT NULL,
    total TEXT NOT NULL,
    PRIMARY KEY (mandate_id, unit, field)
);
";

/// Errors returned by [`SqliteLedger`] operations.
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
    /// Number of distinct leaf mandates (`chain_ids.last()`) recorded across this actor's decisions.
    pub distinct_mandates: u64,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
}

/// Transactional SQLite receipt ledger with atomic chain-wide quota tracking.
pub struct SqliteLedger {
    conn: Connection,
}

impl fmt::Debug for SqliteLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteLedger").finish_non_exhaustive()
    }
}

impl SqliteLedger {
    /// Opens (or creates) a WAL-mode SQLite ledger at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Opens an in-memory SQLite ledger for testing or ephemeral execution.
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, LedgerError> {
        conn.pragma_update(None, "busy_timeout", 5_000i64)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self { conn })
    }

    /// Atomically loads prior quotas, evaluates `chain` via `handfest_core::gate::authorize`,
    /// persists the hash-chained `DecisionReceipt`, and on `Permit` increments quotas across
    /// every `MandateId` in `chain`.
    pub fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let prev_receipt_hash = load_latest_receipt_hash(&tx)?;
        let chain_ids = collect_valid_chain_ids(chain);
        let usage = load_quota_snapshot(&tx, &chain_ids)?;

        let (verdict, receipt) = authorize(chain, request, facts, &usage, now, prev_receipt_hash);

        let quota_updates = if verdict == Verdict::Permit {
            Some(compute_quota_updates(chain, &chain_ids, facts, &usage)?)
        } else {
            None
        };

        insert_receipt(&tx, &receipt, &request.resource_kind, &request.resource_id)?;

        if let Some(updates) = quota_updates {
            apply_quota_updates(&tx, &updates)?;
        }

        tx.commit()?;
        Ok((verdict, receipt))
    }

    /// Verifies hash-chain continuity from genesis (`None`) to tip and recomputes every
    /// `DecisionReceipt` hash, returning the total number of verified receipts.
    pub fn verify_integrity(&self) -> Result<usize, LedgerError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, prev_receipt_hash, receipt_hash, chain_ids_json, actor_key,
                    action, resource_kind, resource_id, timestamp, verdict, deny_reason
             FROM receipts
             ORDER BY seq ASC",
        )?;

        let mut rows = stmt.query([])?;
        let mut expected_prev: Option<MandateId> = None;
        let mut count = 0usize;

        while let Some(row) = rows.next()? {
            let receipt = reconstruct_receipt(row, expected_prev)?;
            if !receipt.verify_hash() {
                let seq: i64 = row.get(0)?;
                return Err(LedgerError::Integrity(format!(
                    "seq {seq}: receipt_hash mismatch (stored {}, computed {})",
                    receipt.receipt_hash,
                    receipt.compute_hash()
                )));
            }
            expected_prev = Some(receipt.receipt_hash);
            count += 1;
        }

        Ok(count)
    }

    /// Computes a [`TrackRecord`] projection for `actor_key` from persisted receipts.
    pub fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        let actor_str = actor_key.to_string();
        let mut stmt = self.conn.prepare(
            "SELECT seq, chain_ids_json, timestamp, verdict, deny_reason
             FROM receipts
             WHERE actor_key = ?1
             ORDER BY seq ASC",
        )?;

        let mut rows = stmt.query(params![actor_str])?;
        let mut total_decisions = 0u64;
        let mut permits = 0u64;
        let mut denies = 0u64;
        let mut distinct_leaves: BTreeSet<MandateId> = BTreeSet::new();
        let mut first_timestamp: Option<i64> = None;
        let mut last_timestamp: Option<i64> = None;

        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let chain_ids_json: String = row.get(1)?;
            let timestamp: i64 = row.get(2)?;
            let verdict_raw: String = row.get(3)?;
            let deny_reason: Option<String> = row.get(4)?;

            let verdict = parse_verdict(seq, &verdict_raw, deny_reason)?;
            let chain_ids = parse_chain_ids_json(seq, &chain_ids_json)?;

            total_decisions += 1;
            match verdict {
                Verdict::Permit => permits += 1,
                Verdict::Deny { .. } => denies += 1,
            }
            if let Some(leaf_id) = chain_ids.last() {
                distinct_leaves.insert(*leaf_id);
            }
            first_timestamp = Some(first_timestamp.map_or(timestamp, |cur| cur.min(timestamp)));
            last_timestamp = Some(last_timestamp.map_or(timestamp, |cur| cur.max(timestamp)));
        }

        Ok(TrackRecord {
            actor_key: actor_key.clone(),
            total_decisions,
            permits,
            denies,
            distinct_mandates: u64::try_from(distinct_leaves.len()).unwrap_or(u64::MAX),
            first_timestamp,
            last_timestamp,
        })
    }
}

fn reconstruct_receipt(
    row: &rusqlite::Row<'_>,
    expected_prev: Option<MandateId>,
) -> Result<DecisionReceipt, LedgerError> {
    let seq: i64 = row.get(0)?;
    let prev_raw: Option<String> = row.get(1)?;
    let hash_raw: String = row.get(2)?;
    let chain_ids_json: String = row.get(3)?;
    let actor_key_raw: String = row.get(4)?;
    let action: String = row.get(5)?;
    let resource_kind: String = row.get(6)?;
    let resource_id: String = row.get(7)?;
    let timestamp: i64 = row.get(8)?;
    let verdict_raw: String = row.get(9)?;
    let deny_reason: Option<String> = row.get(10)?;

    let prev_receipt_hash = parse_optional_mandate_id(seq, "prev_receipt_hash", prev_raw)?;
    if prev_receipt_hash != expected_prev {
        return Err(LedgerError::Integrity(format!(
            "seq {seq}: broken prev_receipt_hash link (expected {expected_prev:?}, got {prev_receipt_hash:?})"
        )));
    }

    let receipt_hash = MandateId::parse(&hash_raw)
        .map_err(|err| LedgerError::Integrity(format!("seq {seq}: invalid receipt_hash: {err}")))?;
    let chain_ids = parse_chain_ids_json(seq, &chain_ids_json)?;
    let actor_key = KeyId::parse(&actor_key_raw)
        .map_err(|err| LedgerError::Integrity(format!("seq {seq}: invalid actor_key: {err}")))?;
    let verdict = parse_verdict(seq, &verdict_raw, deny_reason)?;

    Ok(DecisionReceipt {
        chain_ids,
        actor_key,
        action,
        resource: format_resource(&resource_kind, &resource_id),
        timestamp,
        verdict,
        receipt_hash,
        prev_receipt_hash,
    })
}

fn load_latest_receipt_hash(tx: &Transaction<'_>) -> Result<Option<MandateId>, LedgerError> {
    let raw: Option<String> = tx
        .query_row(
            "SELECT receipt_hash FROM receipts ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match raw {
        None => Ok(None),
        Some(s) => MandateId::parse(&s)
            .map(Some)
            .map_err(|err| LedgerError::Integrity(format!("corrupt latest receipt_hash: {err}"))),
    }
}

fn collect_valid_chain_ids(chain: &[VerifiedMandate]) -> Vec<MandateId> {
    let mut ids = Vec::with_capacity(chain.len());
    for vm in chain {
        match vm.ast.try_mandate_id() {
            Ok(id) => ids.push(id),
            Err(_) => break,
        }
    }
    ids
}

fn insert_receipt(
    tx: &Transaction<'_>,
    receipt: &DecisionReceipt,
    resource_kind: &str,
    resource_id: &str,
) -> Result<(), LedgerError> {
    let prev_str = receipt.prev_receipt_hash.map(|id| id.to_string());
    let hash_str = receipt.receipt_hash.to_string();
    let chain_id_strings: Vec<String> = receipt.chain_ids.iter().map(ToString::to_string).collect();
    let chain_ids_json = serde_json::to_string(&chain_id_strings)?;
    let actor_key_str = receipt.actor_key.to_string();
    let (verdict_str, deny_reason) = match &receipt.verdict {
        Verdict::Permit => ("permit", None),
        Verdict::Deny { reason } => ("deny", Some(reason.as_str())),
    };

    tx.execute(
        "INSERT INTO receipts (
            prev_receipt_hash, receipt_hash, chain_ids_json, actor_key,
            action, resource_kind, resource_id, timestamp, verdict, deny_reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            prev_str,
            hash_str,
            chain_ids_json,
            actor_key_str,
            receipt.action,
            resource_kind,
            resource_id,
            receipt.timestamp,
            verdict_str,
            deny_reason,
        ],
    )?;
    Ok(())
}
