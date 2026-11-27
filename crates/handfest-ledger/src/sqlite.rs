//! Transactional rollback-journal SQLite implementation of [`ReceiptLedger`].

use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    authorize_with_revocations, build_denial_receipt, ActionRequest, DecisionReceipt,
    RevocationSnapshot, VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::RevocationId;
use handfest_core::Verdict;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::audit::{
    collect_verified_chain_hashes_in_conn, run_audit_tx, run_full_audit_tx, run_full_audit_tx_with,
    run_verified_chain_hashes, run_verified_chain_hashes_with, run_verified_list_receipts,
    run_verified_track_record,
};
use crate::preflight::{open_read_only_guarded, open_writable_guarded, ActiveHandleGuard};
use crate::preflight_open::{
    map_open_existing_error, map_read_only_canonicalize_error, validate_file_path,
};
use crate::quotas::{apply_quota_updates, compute_quota_updates, load_quota_snapshot};
use crate::revocations::{record_revocation_tx, verify_and_load_revocations};
use crate::schema::{initialize_or_verify_schema, verify_existing_schema, verify_schema_integrity};
use crate::{
    resolve_pre_gate_denial_reason, AtomicDenialWithRevocations, AtomicEvalRequest, AuditSnapshot,
    LedgerChainHashes, LedgerError, ReadSnapshotLedger, ReceiptLedger, StoredRevocation,
    TrackRecord, TransactionalLedger,
};

const BUSY_TIMEOUT_MS: u64 = 5_000;
pub(crate) const EXISTING_LEDGER_OPEN_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Transactional SQLite receipt ledger with atomic chain-wide quota tracking.
///
/// Uses standard SQLite rollback-journal mode (`PRAGMA journal_mode = DELETE`,
/// `PRAGMA synchronous = FULL`) so read-only auditing works natively on `0444` files in `0555`
/// directories and across concurrent OS processes with zero `-wal`/`-shm` sidecars.
pub struct SqliteLedger {
    // Field order matters: `conn` drops before `_handle_guard` so the in-process handle entry,
    // active-writer count, and any deferred raw header fds remain registered until SQLite finishes
    // closing the connection and releasing POSIX locks.
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
            Connection::open_with_flags(path, EXISTING_LEDGER_OPEN_FLAGS)
                .map_err(|err| map_open_existing_error(path, err))
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
        let canonical =
            fs::canonicalize(path).map_err(|err| map_read_only_canonicalize_error(path, &err))?;

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
        if expected_journal_mode == "delete"
            && ledger.conn.is_readonly(rusqlite::DatabaseName::Main)?
        {
            return Err(LedgerError::Storage(
                "ledger database opened read-only; writable access required".to_string(),
            ));
        }
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
        self.evaluate_and_record_with_revocations(
            chain,
            request,
            facts,
            &RevocationSnapshot::new(),
            now,
        )
    }

    /// Atomically loads persisted revocations (verifying their integrity), merges
    /// `extra_revocations`, loads prior quotas, evaluates `chain` via
    /// `handfest_core::gate::authorize_with_revocations`, persists the hash-chained
    /// `DecisionReceipt`, and on `Permit` increments quotas across every `MandateId` in `chain`.
    pub fn evaluate_and_record_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        extra_revocations: &RevocationSnapshot,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        self.evaluate_and_record_atomic(
            AtomicEvalRequest {
                chain,
                request,
                facts,
                extra_revocations,
                now,
            },
            |_| Ok(()),
            |(), _, _, _| Ok(()),
        )
        .map(|(res, ())| res)
    }

    /// Executes [`Self::evaluate_and_record_with_revocations`] inside a `BEGIN EXCLUSIVE`
    /// transaction, invoking `before_insert` prior to any mutation and `before_commit` prior to
    /// committing. Drops `G` inside the exclusive lock if `COMMIT` fails.
    pub fn evaluate_and_record_atomic<P, G, FPre, FPost>(
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
        ) -> Result<G, LedgerError>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        verify_schema_integrity(&tx)?;
        let load_hashes = || collect_verified_chain_hashes_in_conn(&tx);
        let pre_state = before_insert(&load_hashes)?;

        let prev_receipt_hash = load_latest_receipt_hash(&tx)?;
        let chain_ids: Vec<MandateId> = eval.chain.iter().map(|vm| vm.ast.mandate_id()).collect();
        let usage = load_quota_snapshot(&tx, &chain_ids)?;
        let (_, mut revocations) = verify_and_load_revocations(&tx)?;
        revocations.extend_from(eval.extra_revocations);

        let (verdict, receipt) = authorize_with_revocations(
            eval.chain,
            eval.request,
            eval.facts,
            &usage,
            &revocations,
            eval.now,
            prev_receipt_hash,
        );

        let quota_updates = if verdict == Verdict::Permit {
            Some(compute_quota_updates(
                eval.chain, &chain_ids, eval.facts, &usage,
            )?)
        } else {
            None
        };

        insert_receipt(
            &tx,
            &receipt,
            &eval.request.resource_kind,
            &eval.request.resource_id,
        )?;

        if let Some(updates) = quota_updates {
            apply_quota_updates(&tx, &updates)?;
        }

        let guard = before_commit(pre_state, &verdict, &receipt, &load_hashes)?;
        let guard = commit_tx_or_rollback_guard(tx, guard)?;
        Ok(((verdict, receipt), guard))
    }

    /// Atomically persists a verified revocation into the tamper-evident `revocations` hash chain
    /// without modifying any quota counters or receipts.
    pub fn record_revocation(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
    ) -> Result<RevocationId, LedgerError> {
        self.record_revocation_atomic(revocation, signature_hex, |_| Ok(()), |(), _, _| Ok(()))
            .map(|(rev_id, ())| rev_id)
    }

    /// Executes [`Self::record_revocation`] inside a `BEGIN EXCLUSIVE` transaction, invoking
    /// `before_insert` prior to any mutation and `before_commit` prior to committing. Drops `G`
    /// inside the exclusive lock if `COMMIT` fails.
    pub fn record_revocation_atomic<P, G, FPre, FPost>(
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
        ) -> Result<G, LedgerError>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;
        verify_schema_integrity(&tx)?;
        let load_hashes = || collect_verified_chain_hashes_in_conn(&tx);
        let pre_state = before_insert(&load_hashes)?;
        let (revocation_id, inserted_hash) = record_revocation_tx(&tx, revocation, signature_hex)?;
        let guard = before_commit(pre_state, inserted_hash, &load_hashes)?;
        let guard = commit_tx_or_rollback_guard(tx, guard)?;
        Ok((revocation_id, guard))
    }

    /// Loads and integrity-verifies all persisted revocations as a [`RevocationSnapshot`] inside
    /// a single read transaction.
    pub fn load_revocations(&self) -> Result<RevocationSnapshot, LedgerError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_schema_integrity(&tx)?;
        let (_, snapshot) = verify_and_load_revocations(&tx)?;
        tx.commit()?;
        Ok(snapshot)
    }

    /// Loads and integrity-verifies all persisted [`StoredRevocation`] records inside a single
    /// read transaction.
    pub fn list_stored_revocations(&self) -> Result<Vec<StoredRevocation>, LedgerError> {
        let tx = self.conn.unchecked_transaction()?;
        verify_schema_integrity(&tx)?;
        let (stored, _) = verify_and_load_revocations(&tx)?;
        tx.commit()?;
        Ok(stored)
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
        self.record_denial_atomic(chain_ids, request, now, reason, |_| Ok(()))
    }

    /// Executes [`Self::record_denial`] inside a `BEGIN EXCLUSIVE` transaction and invokes
    /// `before_insert` prior to inserting the denial receipt.
    pub fn record_denial_atomic<FPre>(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
        before_insert: FPre,
    ) -> Result<DecisionReceipt, LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        verify_schema_integrity(&tx)?;
        let load_hashes = || collect_verified_chain_hashes_in_conn(&tx);
        before_insert(&load_hashes)?;

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

    /// Atomically verifies schema and persisted revocations, merges `extra_revocations`, resolves
    /// the effective pre-gate denial reason (`verify_chain_runtime` error > active revocation >
    /// `fallback_reason`), and persists the hash-chained denial receipt inside a single
    /// `BEGIN EXCLUSIVE` transaction without modifying quota counters.
    pub fn record_denial_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        actor_key: &KeyId,
        request: &ActionRequest,
        extra_revocations: &RevocationSnapshot,
        now: i64,
        fallback_reason: String,
    ) -> Result<(String, DecisionReceipt), LedgerError> {
        self.record_denial_with_revocations_atomic(
            AtomicDenialWithRevocations {
                chain,
                actor_key,
                request,
                extra_revocations,
                now,
                fallback_reason,
            },
            |_| Ok(()),
        )
    }

    /// Executes [`Self::record_denial_with_revocations`] inside a `BEGIN EXCLUSIVE` transaction
    /// and invokes `before_insert` prior to inserting the denial receipt.
    pub fn record_denial_with_revocations_atomic<FPre>(
        &mut self,
        denial: AtomicDenialWithRevocations<'_>,
        before_insert: FPre,
    ) -> Result<(String, DecisionReceipt), LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        let chain_ids: Vec<MandateId> = denial.chain.iter().map(|vm| vm.ast.mandate_id()).collect();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        verify_schema_integrity(&tx)?;
        let load_hashes = || collect_verified_chain_hashes_in_conn(&tx);
        before_insert(&load_hashes)?;

        let (_, mut revocations) = verify_and_load_revocations(&tx)?;
        revocations.extend_from(denial.extra_revocations);
        let reason = resolve_pre_gate_denial_reason(
            denial.chain,
            denial.actor_key,
            &revocations,
            denial.now,
            denial.fallback_reason,
        );
        let prev_receipt_hash = load_latest_receipt_hash(&tx)?;
        let bound_request = ActionRequest {
            actor_key: denial.actor_key.clone(),
            action: denial.request.action.clone(),
            resource_kind: denial.request.resource_kind.clone(),
            resource_id: denial.request.resource_id.clone(),
        };
        let receipt = build_denial_receipt(
            chain_ids,
            bound_request.actor_key,
            bound_request.action,
            bound_request.resource_kind.clone(),
            bound_request.resource_id.clone(),
            denial.now,
            reason.clone(),
            prev_receipt_hash,
        )
        .map_err(|err| LedgerError::Integrity(format!("invalid denial receipt: {err}")))?;

        insert_receipt(
            &tx,
            &receipt,
            &bound_request.resource_kind,
            &bound_request.resource_id,
        )?;
        tx.commit()?;
        Ok((reason, receipt))
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

    /// Integrity-verifies the entire ledger and returns all persisted [`DecisionReceipt`] records
    /// in ascending `seq` order inside a single consistent read transaction.
    pub fn list_receipts(&self) -> Result<Vec<DecisionReceipt>, LedgerError> {
        run_verified_list_receipts(&self.conn)
    }

    /// Integrity-verifies the entire ledger inside a single consistent read snapshot and returns
    /// the ordered 32-byte receipt hashes (`seq = 1..=N`) and revocation entry hashes
    /// (`seq = 1..=M`).
    pub fn verified_chain_hashes(&self) -> Result<LedgerChainHashes, LedgerError> {
        run_verified_chain_hashes(&self.conn)
    }

    /// Integrity-verifies the entire ledger inside a single read transaction (`SHARED` lock) and
    /// invokes `with_hashes` before committing/releasing the read lock.
    pub fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        run_verified_chain_hashes_with(&self.conn, with_hashes)
    }

    /// Integrity-verifies the entire ledger and returns verified receipt count, optional actor
    /// [`TrackRecord`], stored revocations, and optional [`LedgerChainHashes`] inside a single
    /// consistent read transaction.
    pub fn audit_full_snapshot(
        &self,
        actor_key: Option<&KeyId>,
        include_chain_hashes: bool,
    ) -> Result<AuditSnapshot, LedgerError> {
        run_full_audit_tx(&self.conn, actor_key, include_chain_hashes)
    }

    pub(crate) fn audit_full_snapshot_in_read_tx<T, F>(
        &self,
        actor_key: Option<&KeyId>,
        include_chain_hashes: bool,
        inside_tx: F,
    ) -> Result<(AuditSnapshot, T), LedgerError>
    where
        F: FnOnce() -> Result<T, LedgerError>,
    {
        run_full_audit_tx_with(&self.conn, actor_key, include_chain_hashes, inside_tx)
    }
}

impl ReceiptLedger for SqliteLedger {
    fn evaluate_and_record_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        extra_revocations: &RevocationSnapshot,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        Self::evaluate_and_record_with_revocations(
            self,
            chain,
            request,
            facts,
            extra_revocations,
            now,
        )
    }

    fn record_revocation(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
    ) -> Result<RevocationId, LedgerError> {
        Self::record_revocation(self, revocation, signature_hex)
    }

    fn load_revocations(&self) -> Result<RevocationSnapshot, LedgerError> {
        Self::load_revocations(self)
    }

    fn list_stored_revocations(&self) -> Result<Vec<StoredRevocation>, LedgerError> {
        Self::list_stored_revocations(self)
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

    fn record_denial_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        actor_key: &KeyId,
        request: &ActionRequest,
        extra_revocations: &RevocationSnapshot,
        now: i64,
        fallback_reason: String,
    ) -> Result<(String, DecisionReceipt), LedgerError> {
        Self::record_denial_with_revocations(
            self,
            chain,
            actor_key,
            request,
            extra_revocations,
            now,
            fallback_reason,
        )
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

    fn verified_chain_hashes(&self) -> Result<LedgerChainHashes, LedgerError> {
        Self::verified_chain_hashes(self)
    }
}

impl ReadSnapshotLedger for SqliteLedger {
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        Self::with_read_snapshot(self, with_hashes)
    }
}

impl TransactionalLedger for SqliteLedger {
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
        ) -> Result<G, LedgerError>,
    {
        Self::evaluate_and_record_atomic(self, eval, before_insert, before_commit)
    }

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
        ) -> Result<G, LedgerError>,
    {
        Self::record_revocation_atomic(
            self,
            revocation,
            signature_hex,
            before_insert,
            before_commit,
        )
    }

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
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        Self::record_denial_atomic(self, chain_ids, request, now, reason, before_insert)
    }

    fn record_denial_with_revocations_atomic<FPre>(
        &mut self,
        denial: AtomicDenialWithRevocations<'_>,
        before_insert: FPre,
    ) -> Result<(String, DecisionReceipt), LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        Self::record_denial_with_revocations_atomic(self, denial, before_insert)
    }
}

pub(crate) fn commit_tx_or_rollback_guard<G>(
    tx: Transaction<'_>,
    guard: G,
) -> Result<G, LedgerError> {
    if let Err(err) = tx.execute_batch("COMMIT") {
        // Drop `guard` (e.g. sidecar truncate + sync_all) BEFORE dropping `tx` so no waiting
        // writer or reader can acquire SQLite's lock and observe an aborted sidecar record before
        // rollback completes.
        drop(guard);
        drop(tx);
        return Err(LedgerError::from(err));
    }
    Ok(guard)
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
