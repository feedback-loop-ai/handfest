//! Transactional rollback-journal SQLite implementation of [`ReceiptLedger`].

use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    authorize, build_denial_receipt, ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate,
};
use handfest_core::Verdict;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::audit::{run_audit_tx, run_verified_track_record};
use crate::preflight::{open_read_only_guarded, open_writable_guarded, ActiveHandleGuard};
use crate::quotas::{apply_quota_updates, compute_quota_updates, load_quota_snapshot};
use crate::schema::{initialize_or_verify_schema, verify_existing_schema};
use crate::{LedgerError, ReceiptLedger, TrackRecord};

const BUSY_TIMEOUT_MS: u64 = 5_000;
pub(crate) const EXISTING_LEDGER_OPEN_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Transactional SQLite receipt ledger with atomic chain-wide quota tracking.
///
/// Uses standard SQLite rollback-journal mode (`PRAGMA journal_mode = DELETE`,
/// `PRAGMA synchronous = FULL`) so read-only auditing works natively on `0444` files in `0555`
/// directories and across concurrent OS processes with zero `-wal`/`-shm` sidecars.
pub struct SqliteLedger {
    // Field order matters: `conn` drops before `_handle_guard` so the in-process handle entry
    // remains registered until SQLite finishes closing the connection and releasing POSIX locks.
    conn: Connection,
    _handle_guard: Option<ActiveHandleGuard>,
}

impl fmt::Debug for SqliteLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteLedger").finish_non_exhaustive()
    }
}

impl SqliteLedger {
    /// Opens (or creates) a rollback-journal SQLite ledger at `path`.
    ///
    /// Rejects empty or `":memory:"` paths (use [`Self::open_in_memory`] for ephemeral execution),
    /// disables SQLite URI parsing, and verifies `PRAGMA journal_mode = DELETE`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        validate_file_path(path, "SqliteLedger::open")?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let (conn, handle_guard) = open_writable_guarded(path, || {
            Connection::open_with_flags(path, flags).map_err(LedgerError::from)
        })?;
        Self::init(conn, Some(handle_guard), "delete", true)
    }

    /// Opens an already-initialized rollback-journal SQLite ledger at `path` without creating
    /// missing files or running `CREATE TABLE` on empty schemas.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        validate_file_path(path, "SqliteLedger::open_existing")?;
        let (conn, handle_guard) = open_writable_guarded(path, || {
            Connection::open_with_flags(path, EXISTING_LEDGER_OPEN_FLAGS).map_err(LedgerError::from)
        })?;
        Self::init(conn, Some(handle_guard), "delete", false)
    }

    /// Opens an existing SQLite ledger in strict read-only mode.
    ///
    /// Never creates missing database files, never runs write PRAGMAs, never executes DDL, and
    /// never creates `-wal` or `-shm` sidecar files. Symlinks are resolved before opening, and a
    /// pre-open 100-byte SQLite header + sidecar check rejects missing/truncated files, non-SQLite
    /// files, WAL-format headers, non-empty `-wal` files, and hot unrecovered rollback journals
    /// before SQLite opens the database.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        let canonical = fs::canonicalize(path).map_err(|err| {
            LedgerError::Integrity(format!(
                "failed to resolve read-only ledger path '{}': {err}",
                path.display()
            ))
        })?;

        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let (conn, handle_guard) = open_read_only_guarded(&canonical, |p| {
            Connection::open_with_flags(p, flags).map_err(LedgerError::from)
        })?;
        // Bind `Self` immediately so `conn` always drops before `_handle_guard` on any error.
        let ledger = Self {
            conn,
            _handle_guard: Some(handle_guard),
        };
        ledger
            .conn
            .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
        ledger.conn.pragma_update(None, "query_only", "ON")?;
        let journal_mode: String = ledger
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if journal_mode.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::Integrity(format!(
                "read-only ledger '{}' uses WAL mode; rollback-journal mode required",
                canonical.display()
            )));
        }
        let _: Option<i64> = ledger
            .conn
            .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |row| row.get(0))
            .optional()?;
        Ok(ledger)
    }

    /// Opens an in-memory SQLite ledger for testing or ephemeral execution.
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn, None, "memory", true)
    }

    fn init(
        conn: Connection,
        handle_guard: Option<ActiveHandleGuard>,
        expected_journal_mode: &str,
        allow_create_schema: bool,
    ) -> Result<Self, LedgerError> {
        // Bind `Self` immediately so `conn` always drops before `_handle_guard` on any error.
        let mut ledger = Self {
            conn,
            _handle_guard: handle_guard,
        };
        ledger
            .conn
            .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
        if !allow_create_schema {
            verify_existing_schema(&mut ledger.conn)?;
        }
        let actual_mode: String =
            ledger
                .conn
                .query_row("PRAGMA journal_mode = DELETE;", [], |row| row.get(0))?;
        if !actual_mode.eq_ignore_ascii_case(expected_journal_mode) {
            return Err(LedgerError::Storage(format!(
                "failed to set SQLite journal_mode to '{expected_journal_mode}'; got '{actual_mode}'"
            )));
        }
        ledger.conn.pragma_update(None, "synchronous", "FULL")?;
        ledger.conn.pragma_update(None, "foreign_keys", "ON")?;
        if allow_create_schema {
            initialize_or_verify_schema(&mut ledger.conn)?;
        }
        Ok(ledger)
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
        let chain_ids: Vec<MandateId> = chain.iter().map(|vm| vm.ast.mandate_id()).collect();
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

    /// Atomically builds a pre-gate denial [`DecisionReceipt`] via
    /// `handfest_core::gate::build_denial_receipt`, persists it linked to the current hash-chain
    /// tip without modifying quotas, and returns the persisted receipt.
    pub fn record_denial(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
    ) -> Result<DecisionReceipt, LedgerError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let prev_receipt_hash = load_latest_receipt_hash(&tx)?;
        let receipt = build_denial_receipt(
            chain_ids,
            request.actor_key.clone(),
            request.action.clone(),
            request.resource_kind.clone(),
            request.resource_id.clone(),
            now,
            reason,
            prev_receipt_hash,
        )
        .map_err(|err| LedgerError::Integrity(format!("invalid denial receipt: {err}")))?;

        insert_receipt(&tx, &receipt, &request.resource_kind, &request.resource_id)?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Computes an integrity-verified [`TrackRecord`] projection for `actor_key` from persisted
    /// receipts inside a single consistent read snapshot.
    ///
    /// [`TrackRecord::distinct_mandates`] counts distinct leaf mandates (`chain_ids.last()`)
    /// across all `Permit` and `Deny` receipts for `actor_key` (excluding intermediate delegator
    /// and root mandates).
    pub fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        run_verified_track_record(&self.conn, actor_key)
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

    fn record_denial(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
    ) -> Result<DecisionReceipt, LedgerError> {
        Self::record_denial(self, chain_ids, request, now, reason)
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

fn validate_file_path(path: &Path, caller: &str) -> Result<(), LedgerError> {
    let raw_os = path.as_os_str();
    if raw_os.is_empty() || raw_os == ":memory:" || is_sqlite_uri_path(raw_os) {
        return Err(LedgerError::Storage(format!(
            "empty, ':memory:', or 'file:' URI path rejected by {caller}; use open_in_memory() for ephemeral ledgers"
        )));
    }
    Ok(())
}

fn is_sqlite_uri_path(raw: &std::ffi::OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        raw.as_bytes().starts_with(b"file:")
    }
    #[cfg(not(unix))]
    {
        raw.to_str().is_some_and(|s| s.starts_with("file:"))
    }
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
#[path = "sqlite_tests.rs"]
mod tests;
