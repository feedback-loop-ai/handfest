//! Transactional rollback-journal SQLite implementation of [`ReceiptLedger`].

use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    authorize, ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate,
};
use handfest_core::Verdict;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::audit::{run_audit_tx, track_record_in_conn};
use crate::quotas::{apply_quota_updates, compute_quota_updates, load_quota_snapshot};
use crate::{LedgerError, ReceiptLedger, TrackRecord};

const BUSY_TIMEOUT_MS: u64 = 5_000;

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

/// Transactional SQLite receipt ledger with atomic chain-wide quota tracking.
///
/// Uses standard SQLite rollback-journal mode (`PRAGMA journal_mode = DELETE`,
/// `PRAGMA synchronous = FULL`) so read-only auditing works natively on `0444` files in `0555`
/// directories and across concurrent OS processes with zero `-wal`/`-shm` sidecars.
pub struct SqliteLedger {
    conn: Connection,
}

impl fmt::Debug for SqliteLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteLedger").finish_non_exhaustive()
    }
}

impl SqliteLedger {
    /// Opens (or creates) a rollback-journal SQLite ledger at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Opens an existing SQLite ledger in strict read-only mode.
    ///
    /// Never creates missing database files, never runs write PRAGMAs, never executes DDL, and
    /// never creates `-wal` or `-shm` sidecar files. Symlinks are resolved before opening, and a
    /// read-only schema probe rejects corrupt files, uncheckpointed WAL snapshots, and hot
    /// unrecovered rollback journals immediately.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let canonical = fs::canonicalize(path).map_err(|err| {
            LedgerError::Integrity(format!(
                "failed to resolve read-only ledger path '{}': {err}",
                path.display()
            ))
        })?;
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&canonical, flags)?;
        conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
        conn.pragma_update(None, "query_only", "ON")?;
        let _: Option<i64> = conn
            .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |row| row.get(0))
            .optional()?;
        Ok(Self { conn })
    }

    /// Opens an in-memory SQLite ledger for testing or ephemeral execution.
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, LedgerError> {
        conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
        conn.pragma_update(None, "journal_mode", "DELETE")?;
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

    /// Verifies receipt `seq` contiguity (`1..=count`), hash-chain continuity from genesis
    /// (`None`) to tip, every `DecisionReceipt` hash, `sqlite_sequence` high-water mark,
    /// `quota_calls` consistency, and `quota_sums` structural validity inside a single read
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
        track_record_in_conn(&self.conn, actor_key)
    }

    /// Runs [`Self::verify_integrity`] and an optional [`Self::track_record`] projection inside a
    /// single read transaction so concurrent writers cannot split the verified receipt count and
    /// the actor projection across two snapshots.
    pub fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        run_audit_tx(&self.conn, actor_key, || {})
    }
}

impl ReceiptLedger for SqliteLedger {
    fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        Self::evaluate_and_record(self, chain, request, facts, now)
    }

    fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        Self::track_record(self, actor_key)
    }

    fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        Self::audit_snapshot(self, actor_key)
    }
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
    use std::sync::mpsc;

    use handfest_core::ast::{parse_rfc3339_utc, Scalar};
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedAnchorProof;
    use handfest_core::AssuranceLevel;
    use tempfile::TempDir;

    use super::*;

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
    fn audit_snapshot_isolates_concurrent_writer_between_verify_and_track_record() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("snapshot_isolation.sqlite");
        let (chain, req, facts, now) = sample_chain_and_req();

        let mut writer = SqliteLedger::open(&db_path).unwrap();
        writer
            .evaluate_and_record(&chain, &req, &facts, now)
            .unwrap();

        let ro = SqliteLedger::open_read_only(&db_path).unwrap();
        let (start_tx, start_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();

        let writer_req = req.clone();
        let writer_handle = std::thread::spawn(move || {
            start_rx.recv().unwrap();
            started_tx.send(()).unwrap();
            let res = writer.evaluate_and_record(&chain, &writer_req, &facts, now + 60);
            done_tx.send(()).unwrap();
            res.unwrap()
        });

        let (verified, maybe_rec) = run_audit_tx(&ro.conn, Some(&req.actor_key), || {
            start_tx.send(()).unwrap();
            started_rx.recv().unwrap();
            assert!(
                done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
                "concurrent writer must not commit while audit read transaction holds SHARED lock"
            );
        })
        .unwrap();

        let rec = maybe_rec.expect("expected TrackRecord");
        assert_eq!(verified, 1);
        assert_eq!(
            rec.total_decisions, 1,
            "track_record must read the same read transaction snapshot as verify_integrity"
        );

        writer_handle.join().unwrap();

        let (after_verified, after_rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        assert_eq!(after_verified, 2);
        assert_eq!(after_rec.unwrap().total_decisions, 2);
    }

    #[test]
    fn open_configures_delete_journal_full_sync_and_read_only_rejects_writes() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("pragmas.sqlite");
        let (chain, req, facts, now) = sample_chain_and_req();

        let mut writer = SqliteLedger::open(&db_path).unwrap();
        let mode: String = writer
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let sync: i64 = writer
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        let fk: i64 = writer
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "delete");
        assert_eq!(sync, 2, "expected PRAGMA synchronous = FULL (2)");
        assert_eq!(fk, 1, "expected PRAGMA foreign_keys = ON (1)");

        writer
            .evaluate_and_record(&chain, &req, &facts, now)
            .unwrap();

        let mut ro = SqliteLedger::open_read_only(&db_path).unwrap();
        let query_only: i64 = ro
            .conn
            .query_row("PRAGMA query_only", [], |r| r.get(0))
            .unwrap();
        assert_eq!(query_only, 1, "expected PRAGMA query_only = ON (1)");

        let err = ro
            .evaluate_and_record(&chain, &req, &facts, now + 60)
            .unwrap_err();
        assert!(
            matches!(err, LedgerError::Sqlite(_)),
            "expected Sqlite read-only refusal, got: {err}"
        );
        assert!(std::error::Error::source(&err).is_some());
    }
}
