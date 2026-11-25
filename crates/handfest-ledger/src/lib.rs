//! Hash-chained SQLite receipt store, atomic chain-wide quota tracking, and offline audit replay.

mod codec;
mod quotas;
mod readonly;

use std::collections::{BTreeMap, BTreeSet};
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
use crate::readonly::{
    has_clean_sidecars, open_read_only_connection, path_fingerprint,
    verify_immutable_snapshot_unchanged, ReadOnlyMode,
};

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
    /// Number of distinct leaf mandates (`chain_ids.last()`) executed by this actor across its
    /// persisted `Permit` and `Deny` receipts (excluding intermediate delegator/root mandates).
    pub distinct_mandates: u64,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
}

/// Transactional SQLite receipt ledger with atomic chain-wide quota tracking.
pub struct SqliteLedger {
    conn: Connection,
    read_only_mode: ReadOnlyMode,
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

    /// Opens an existing SQLite ledger in strict read-only mode.
    ///
    /// Never creates missing database files, never runs write PRAGMAs, never executes DDL, and
    /// never creates persistent `-wal` or `-shm` sidecar files in the ledger directory.
    ///
    /// Symlinks are resolved before inspecting `-wal`, `-shm`, and `-journal` recovery state;
    /// ledgers with a hot rollback journal or an uncheckpointed `-wal` without an active `-shm`
    /// are rejected rather than audited over stale data. Cleanly closed ledgers are audited
    /// directly via SQLite's `immutable=1` read-only mode (without copying to temporary storage
    /// and without opening raw descriptors on the database inode), with post-read stability checks
    /// and bounded retry if a concurrent writer modifies the file mid-audit.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let (conn, read_only_mode) = open_read_only_connection(path.as_ref())?;
        Ok(Self {
            conn,
            read_only_mode,
        })
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
        Ok(Self {
            conn,
            read_only_mode: ReadOnlyMode::Live,
        })
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

    /// Verifies receipt `seq` contiguity (`1..=count`), hash-chain continuity from genesis
    /// (`None`) to tip, every `DecisionReceipt` hash, `sqlite_sequence` high-water mark, and
    /// `quota_calls` consistency against persisted `Permit` receipts inside a single read
    /// transaction.
    pub fn verify_integrity(&self) -> Result<usize, LedgerError> {
        self.audit_snapshot(None).map(|(count, _)| count)
    }

    /// Computes a [`TrackRecord`] projection for `actor_key` from persisted receipts.
    ///
    /// [`TrackRecord::distinct_mandates`] counts distinct leaf mandates (`chain_ids.last()`)
    /// across all `Permit` and `Deny` receipts for `actor_key` (excluding intermediate delegator
    /// and root mandates).
    pub fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        match &self.read_only_mode {
            ReadOnlyMode::Live => track_record_in_conn(&self.conn, actor_key),
            ReadOnlyMode::ImmutableDirect {
                canonical,
                open_fingerprint,
            } => self.track_record_immutable(canonical, open_fingerprint, actor_key),
        }
    }

    fn track_record_immutable(
        &self,
        canonical: &Path,
        open_fingerprint: &crate::readonly::FileFingerprint,
        actor_key: &KeyId,
    ) -> Result<TrackRecord, LedgerError> {
        for attempt in 0..3 {
            let retry_pair = self.maybe_reopen_for_attempt(attempt, canonical, open_fingerprint)?;
            let (conn, mode) = match &retry_pair {
                Some((c, m)) => (c, m),
                None => (&self.conn, &self.read_only_mode),
            };
            let ReadOnlyMode::ImmutableDirect {
                canonical: target, ..
            } = mode
            else {
                return track_record_in_conn(conn, actor_key);
            };
            let pre_fp = path_fingerprint(target)?;
            let res = track_record_in_conn(conn, actor_key);
            if verify_immutable_snapshot_unchanged(target, &pre_fp, None)? {
                return res;
            }
        }
        Err(LedgerError::Integrity(format!(
            "ledger '{}' changed concurrently during read-only track_record",
            canonical.display()
        )))
    }

    /// Runs [`Self::verify_integrity`] and an optional [`Self::track_record`] projection inside a
    /// single read transaction so concurrent writers cannot split the verified receipt count and
    /// the actor projection across two snapshots.
    pub fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        self.audit_snapshot_inner(actor_key, || {})
    }

    fn audit_snapshot_inner(
        &self,
        actor_key: Option<&KeyId>,
        after_verify: impl FnOnce(),
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        let mut after_verify = Some(after_verify);
        match &self.read_only_mode {
            ReadOnlyMode::Live => {
                let (verified, _tip, record) =
                    run_audit_tx(&self.conn, actor_key, &mut after_verify)?;
                Ok((verified, record))
            }
            ReadOnlyMode::ImmutableDirect {
                canonical,
                open_fingerprint,
            } => self.audit_snapshot_immutable(
                canonical,
                open_fingerprint,
                actor_key,
                &mut after_verify,
            ),
        }
    }

    fn audit_snapshot_immutable<F: FnOnce()>(
        &self,
        canonical: &Path,
        open_fingerprint: &crate::readonly::FileFingerprint,
        actor_key: Option<&KeyId>,
        after_verify: &mut Option<F>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        for attempt in 0..3 {
            let retry_pair = self.maybe_reopen_for_attempt(attempt, canonical, open_fingerprint)?;
            let (conn, mode) = match &retry_pair {
                Some((c, m)) => (c, m),
                None => (&self.conn, &self.read_only_mode),
            };
            let ReadOnlyMode::ImmutableDirect {
                canonical: target, ..
            } = mode
            else {
                let (verified, _tip, record) = run_audit_tx(conn, actor_key, after_verify)?;
                return Ok((verified, record));
            };
            let pre_fp = path_fingerprint(target)?;
            match run_audit_tx(conn, actor_key, after_verify) {
                Ok((verified, tip, record))
                    if verify_immutable_snapshot_unchanged(target, &pre_fp, Some(tip))? =>
                {
                    return Ok((verified, record));
                }
                Ok(_) => {}
                Err(err) if verify_immutable_snapshot_unchanged(target, &pre_fp, None)? => {
                    return Err(err);
                }
                Err(_) => {}
            }
        }
        Err(LedgerError::Integrity(format!(
            "ledger '{}' changed concurrently during read-only audit",
            canonical.display()
        )))
    }

    fn maybe_reopen_for_attempt(
        &self,
        attempt: usize,
        canonical: &Path,
        open_fingerprint: &crate::readonly::FileFingerprint,
    ) -> Result<Option<(Connection, ReadOnlyMode)>, LedgerError> {
        let reuse_self = attempt == 0
            && path_fingerprint(canonical).ok().as_ref() == Some(open_fingerprint)
            && has_clean_sidecars(canonical).unwrap_or(false);
        if reuse_self {
            Ok(None)
        } else {
            Ok(Some(open_read_only_connection(canonical)?))
        }
    }
}

type ReceiptTip = Option<(i64, MandateId)>;

fn run_audit_tx<F: FnOnce()>(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    after_verify: &mut Option<F>,
) -> Result<(usize, ReceiptTip, Option<TrackRecord>), LedgerError> {
    let tx = conn.unchecked_transaction()?;
    let (verified_receipts, tip) = verify_integrity_in_conn(&tx)?;
    if let Some(hook) = after_verify.take() {
        hook();
    }
    let record = match actor_key {
        Some(key) => Some(track_record_in_conn(&tx, key)?),
        None => None,
    };
    tx.commit()?;
    Ok((verified_receipts, tip, record))
}

fn verify_integrity_in_conn(conn: &Connection) -> Result<(usize, ReceiptTip), LedgerError> {
    let mut stmt = conn.prepare(
        "SELECT seq, prev_receipt_hash, receipt_hash, chain_ids_json, actor_key,
                action, resource_kind, resource_id, timestamp, verdict, deny_reason
         FROM receipts
         ORDER BY seq ASC",
    )?;

    let mut rows = stmt.query([])?;
    let mut expected_prev: Option<MandateId> = None;
    let mut expected_seq: i64 = 1;
    let mut expected_calls: BTreeMap<MandateId, u64> = BTreeMap::new();
    let mut count = 0usize;

    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        if seq != expected_seq {
            return Err(LedgerError::Integrity(format!(
                "non-contiguous receipt seq: expected {expected_seq}, got {seq}"
            )));
        }
        let receipt = reconstruct_receipt(row, expected_prev)?;
        if !receipt.verify_hash() {
            return Err(LedgerError::Integrity(format!(
                "seq {seq}: receipt_hash mismatch (stored {}, computed {})",
                receipt.receipt_hash,
                receipt.compute_hash()
            )));
        }
        if receipt.verdict == Verdict::Permit {
            record_expected_permit_calls(&mut expected_calls, &receipt.chain_ids)?;
        }
        expected_prev = Some(receipt.receipt_hash);
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| LedgerError::Integrity("receipt seq overflow".to_string()))?;
        count += 1;
    }

    verify_sqlite_sequence_hwm(conn, count)?;
    verify_quota_calls_consistency(conn, &expected_calls)?;
    let tip = expected_prev.map(|hash| (expected_seq - 1, hash));
    Ok((count, tip))
}

fn record_expected_permit_calls(
    expected_calls: &mut BTreeMap<MandateId, u64>,
    chain_ids: &[MandateId],
) -> Result<(), LedgerError> {
    let unique: BTreeSet<MandateId> = chain_ids.iter().copied().collect();
    for mid in unique {
        let entry = expected_calls.entry(mid).or_insert(0);
        *entry = entry.checked_add(1).ok_or_else(|| {
            LedgerError::Integrity(format!("permit count overflow while auditing {mid}"))
        })?;
    }
    Ok(())
}

fn verify_sqlite_sequence_hwm(conn: &Connection, count: usize) -> Result<(), LedgerError> {
    let count_i64 = i64::try_from(count)
        .map_err(|_| LedgerError::Integrity("receipt count exceeds i64 range".to_string()))?;
    let has_seq_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !has_seq_table {
        if count > 0 {
            return Err(LedgerError::Integrity(format!(
                "missing sqlite_sequence table for non-empty receipts ledger ({count} rows)"
            )));
        }
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'receipts'")?;
    let mut rows = stmt.query([])?;
    let mut hwms = Vec::new();
    while let Some(row) = rows.next()? {
        let seq: Option<i64> = row.get(0)?;
        hwms.push(seq);
    }

    match hwms.as_slice() {
        [] if count == 0 => Ok(()),
        [] => Err(LedgerError::Integrity(format!(
            "missing sqlite_sequence row for receipts ({count} rows present)"
        ))),
        [Some(seq)] if *seq == count_i64 => Ok(()),
        [Some(seq)] => Err(LedgerError::Integrity(format!(
            "sqlite_sequence high-water mark mismatch for receipts: expected {count_i64}, got {seq}"
        ))),
        [None] => Err(LedgerError::Integrity(
            "invalid NULL sqlite_sequence high-water mark for receipts".to_string(),
        )),
        _ => Err(LedgerError::Integrity(format!(
            "duplicate sqlite_sequence rows for receipts: expected at most 1, found {}",
            hwms.len()
        ))),
    }
}

fn verify_quota_calls_consistency(
    conn: &Connection,
    expected_calls: &BTreeMap<MandateId, u64>,
) -> Result<(), LedgerError> {
    let mut stmt = conn.prepare("SELECT mandate_id, calls FROM quota_calls")?;
    let mut rows = stmt.query([])?;
    let mut actual_calls: BTreeMap<MandateId, u64> = BTreeMap::new();

    while let Some(row) = rows.next()? {
        let mid_raw: String = row.get(0)?;
        let calls_i64: i64 = row.get(1)?;
        let mid = MandateId::parse(&mid_raw).map_err(|err| {
            LedgerError::Integrity(format!(
                "invalid mandate_id '{mid_raw}' in quota_calls: {err}"
            ))
        })?;
        let calls = u64::try_from(calls_i64).map_err(|_| {
            LedgerError::Integrity(format!(
                "negative calls count {calls_i64} in quota_calls for {mid}"
            ))
        })?;
        actual_calls.insert(mid, calls);
    }

    for (mid, expected) in expected_calls {
        match actual_calls.get(mid) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                return Err(LedgerError::Integrity(format!(
                    "quota_calls mismatch for {mid}: expected {expected}, got {actual}"
                )));
            }
            None => {
                return Err(LedgerError::Integrity(format!(
                    "missing quota_calls row for {mid}: expected {expected} permits"
                )));
            }
        }
    }

    for (mid, actual) in &actual_calls {
        if !expected_calls.contains_key(mid) {
            return Err(LedgerError::Integrity(format!(
                "unexpected quota_calls row for {mid} (calls={actual}) with no persisted permits"
            )));
        }
    }
    Ok(())
}

fn track_record_in_conn(conn: &Connection, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
    let actor_str = actor_key.to_string();
    let mut stmt = conn.prepare(
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

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::ast::{parse_rfc3339_utc, Scalar};
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedAnchorProof;
    use handfest_core::AssuranceLevel;
    use tempfile::TempDir;

    fn sample_chain_and_req() -> (Vec<VerifiedMandate>, ActionRequest, VerifiedFacts, i64) {
        let ast = parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"dispatcher\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE resource.author == \"valentin\"\n",
            "LIMIT 10 calls\n",
        ))
        .unwrap();
        let proof = VerifiedAnchorProof {
            anchor_id: "test-anchor".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: ast.from().key().clone(),
            actor_kind: ast.from().kind(),
            valid_from: parse_rfc3339_utc("2026-11-24T00:00:00Z").unwrap(),
            valid_until: parse_rfc3339_utc("2026-11-26T00:00:00Z").unwrap(),
        };
        let req = ActionRequest {
            actor_key: ast.to().key().clone(),
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id: "feedback-loop-ai/handfest".to_string(),
        };
        let mut facts = VerifiedFacts::new();
        facts.insert(
            "resource.author".to_string(),
            Scalar::Str("valentin".to_string()),
        );
        let now = parse_rfc3339_utc("2026-11-24T12:00:00Z").unwrap();
        (vec![VerifiedMandate { ast, proof }], req, facts, now)
    }

    #[test]
    fn audit_snapshot_isolates_live_concurrent_write_between_verify_and_track_record() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("live_snapshot.sqlite");
        let (chain, req, facts, now) = sample_chain_and_req();

        let mut writer = SqliteLedger::open(&db_path).unwrap();
        writer
            .evaluate_and_record(&chain, &req, &facts, now)
            .unwrap();

        let ro = SqliteLedger::open_read_only(&db_path).unwrap();
        assert!(matches!(ro.read_only_mode, ReadOnlyMode::Live));

        let (verified, maybe_rec) = ro
            .audit_snapshot_inner(Some(&req.actor_key), || {
                writer
                    .evaluate_and_record(&chain, &req, &facts, now + 60)
                    .unwrap();
            })
            .unwrap();

        let rec = maybe_rec.expect("expected TrackRecord");
        assert_eq!(verified, 1);
        assert_eq!(
            rec.total_decisions, 1,
            "track_record must read the same read transaction snapshot as verify_integrity"
        );

        let (after_verified, after_rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        assert_eq!(after_verified, 2);
        assert_eq!(after_rec.unwrap().total_decisions, 2);
    }

    #[test]
    fn audit_snapshot_isolates_checkpoint_on_clean_snapshot_reader() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("checkpoint_snapshot.sqlite");
        let (chain, req, facts, now) = sample_chain_and_req();

        {
            let mut writer = SqliteLedger::open(&db_path).unwrap();
            writer
                .evaluate_and_record(&chain, &req, &facts, now)
                .unwrap();
        }

        let ro = SqliteLedger::open_read_only(&db_path).unwrap();
        assert!(matches!(
            ro.read_only_mode,
            ReadOnlyMode::ImmutableDirect { .. }
        ));

        let (verified, maybe_rec) = ro
            .audit_snapshot_inner(Some(&req.actor_key), || {
                let mut writer = SqliteLedger::open(&db_path).unwrap();
                for step in 1..=5 {
                    writer
                        .evaluate_and_record(&chain, &req, &facts, now + step * 60)
                        .unwrap();
                }
            })
            .unwrap();

        let rec = maybe_rec.expect("expected TrackRecord");
        assert_eq!(verified, 6);
        assert_eq!(
            rec.total_decisions, 6,
            "concurrent checkpoint during direct immutable audit must retry to a consistent snapshot"
        );
    }
}
