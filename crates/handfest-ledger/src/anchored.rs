//! [`AnchoredLedger<L, W>`] decorator transparently anchoring [`ReceiptLedger`] tips to a
//! [`CheckpointWitness`] and persisting proofs in a dedicated append-only checkpoint store.

use std::path::{Path, PathBuf};

use handfest_core::ast::{KeyId, MandateId};
use handfest_core::gate::{
    ActionRequest, DecisionReceipt, RevocationSnapshot, VerifiedFacts, VerifiedMandate,
    VerifiedRevocation,
};
use handfest_core::revocation::RevocationId;
use handfest_core::Verdict;

use crate::checkpoint_store::{
    append_checkpoint_to_file, build_checkpoint_from_hashes, ensure_monotonic_checkpoint,
    load_checkpoints_from_file_status, validate_stored_checkpoint_chain,
    verify_checkpoint_matches_chain, PendingSidecarAppend, SidecarLoad,
};
use crate::witness::{
    validate_witness_kind, validate_witness_proof, CheckpointWitness, LedgerCheckpoint,
    StoredCheckpoint, WitnessPolicy, WitnessProof, WitnessRegistry,
};
use crate::{
    AtomicDenialWithRevocations, AtomicEvalRequest, AuditSnapshot, LedgerChainHashes, LedgerError,
    ReadSnapshotLedger, ReceiptLedger, SqliteLedger, StoredRevocation, TrackRecord,
    TransactionalLedger,
};

#[derive(Debug)]
enum CheckpointStorage {
    InMemory(Vec<StoredCheckpoint>),
    AppendOnlyFile(PathBuf),
}

enum StagedCheckpointWrite {
    InMemory(StoredCheckpoint),
    Sidecar(PendingSidecarAppend),
}

struct PreWriteState {
    existing: Vec<StoredCheckpoint>,
    pre_hashes: LedgerChainHashes,
}

#[derive(Clone, Copy)]
struct SidecarVerifyOptions<'a> {
    require_non_empty: bool,
    require_strict_tail: bool,
    expected_checkpoint_head: Option<&'a MandateId>,
}

/// Transparent [`ReceiptLedger`] decorator that optionally anchors ledger tip digests via a
/// [`CheckpointWitness`] without modifying the inner ledger's `receipts`, `quota_calls`,
/// `quota_sums`, or `revocations` hash chains.
///
/// When configured with [`WitnessPolicy::Disabled`] (the default), zero witness calls and zero
/// checkpoint sidecar I/O occur.
#[derive(Debug)]
pub struct AnchoredLedger<L: TransactionalLedger, W: CheckpointWitness> {
    inner: L,
    witness: W,
    policy: WitnessPolicy,
    storage: CheckpointStorage,
}

impl<L: TransactionalLedger, W: CheckpointWitness> AnchoredLedger<L, W> {
    /// Wraps `inner` with an in-memory append-only checkpoint store.
    ///
    /// Fails closed if `policy` or (when enabled) `witness.witness_kind()` is invalid.
    pub fn new(inner: L, witness: W, policy: WitnessPolicy) -> Result<Self, LedgerError> {
        policy.validate()?;
        if policy != WitnessPolicy::Disabled {
            validate_witness_kind(witness.witness_kind())?;
        }
        Ok(Self {
            inner,
            witness,
            policy,
            storage: CheckpointStorage::InMemory(Vec::new()),
        })
    }

    /// Wraps `inner` with a dedicated append-only JSONL sidecar checkpoint file at
    /// `sidecar_path` (typically derived via [`crate::canonical_checkpoint_sidecar_path`]).
    ///
    /// Fails closed if `policy`, (when enabled) `witness.witness_kind()`, or `sidecar_path` is
    /// invalid.
    pub fn with_checkpoint_file(
        inner: L,
        witness: W,
        policy: WitnessPolicy,
        sidecar_path: impl Into<PathBuf>,
    ) -> Result<Self, LedgerError> {
        policy.validate()?;
        if policy != WitnessPolicy::Disabled {
            validate_witness_kind(witness.witness_kind())?;
        }
        let sidecar_path = sidecar_path.into();
        if sidecar_path.as_os_str().is_empty() {
            return Err(LedgerError::Storage(
                "checkpoint sidecar path must not be empty".to_string(),
            ));
        }
        Ok(Self {
            inner,
            witness,
            policy,
            storage: CheckpointStorage::AppendOnlyFile(sidecar_path),
        })
    }

    /// Returns the active [`WitnessPolicy`].
    #[must_use]
    pub const fn policy(&self) -> WitnessPolicy {
        self.policy
    }

    /// Returns the number of currently persisted checkpoint records after validating their
    /// append-only hash chain and policy-required presence/tail coverage inside the ledger's
    /// `SHARED` read lock.
    pub fn checkpoint_count(&self) -> Result<usize, LedgerError> {
        let (chain_hashes, loaded) = self.inner.with_read_snapshot(|hashes| {
            let loaded = load_checkpoints_from_storage_status(&self.storage)?;
            Ok((hashes.clone(), loaded))
        })?;
        let records = resolve_loaded_sidecar_for_policy(self.policy, loaded, &chain_hashes)?;
        if let Some(last) = records.last() {
            verify_policy_tail_coverage(self.policy, last, &chain_hashes)?;
        }
        Ok(records.len())
    }

    /// Verifies the inner ledger's full hash chains and every persisted [`WitnessProof`] against
    /// the local receipt and revocation tips and `self.witness`.
    ///
    /// Reads the checkpoint sidecar while holding SQLite's `SHARED` read lock so concurrent
    /// `BEGIN EXCLUSIVE` writers never expose a half-written or out-of-sync pair.
    pub fn verify_witness_checkpoints(&self) -> Result<usize, LedgerError> {
        let (chain_hashes, loaded) = self.inner.with_read_snapshot(|hashes| {
            let loaded = load_checkpoints_from_storage_status(&self.storage)?;
            Ok((hashes.clone(), loaded))
        })?;
        let records = resolve_loaded_sidecar_for_policy(self.policy, loaded, &chain_hashes)?;
        if records.is_empty() {
            return Ok(0);
        }

        let verified = verify_records_against_chain(&records, &chain_hashes, |cp, proof| {
            validate_witness_proof(cp, proof, self.witness.witness_kind())?;
            self.witness.verify(cp, proof)?;
            Ok(())
        })?;

        if let Some(last) = records.last() {
            verify_policy_tail_coverage(self.policy, last, &chain_hashes)?;
        }

        Ok(verified)
    }
}

impl<L: TransactionalLedger, W: CheckpointWitness> ReceiptLedger for AnchoredLedger<L, W> {
    fn evaluate_and_record_with_revocations(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        extra_revocations: &RevocationSnapshot,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), LedgerError> {
        if self.policy == WitnessPolicy::Disabled {
            return self.inner.evaluate_and_record_with_revocations(
                chain,
                request,
                facts,
                extra_revocations,
                now,
            );
        }

        let Self {
            inner,
            witness,
            policy,
            storage,
        } = self;
        let active_policy = *policy;

        let (result, staged) = inner.evaluate_and_record_atomic(
            AtomicEvalRequest {
                chain,
                request,
                facts,
                extra_revocations,
                now,
            },
            |load_pre_hashes| {
                load_and_validate_existing_for_write(storage, active_policy, load_pre_hashes)
            },
            |mut pre_state, verdict, receipt, _load_post_hashes| {
                if *verdict != Verdict::Permit {
                    return Ok(None);
                }

                pre_state
                    .pre_hashes
                    .receipt_hashes
                    .push(*receipt.receipt_hash.as_bytes());
                let receipt_seq = u64::try_from(pre_state.pre_hashes.receipt_hashes.len())
                    .map_err(|_| LedgerError::Integrity("receipt_seq overflow".to_string()))?;
                pre_state.pre_hashes.last_permit_seq = Some(receipt_seq);

                let should_anchor = match active_policy {
                    WitnessPolicy::Disabled => false,
                    WitnessPolicy::SyncStrict => true,
                    WitnessPolicy::BatchEvery {
                        every_n_receipts, ..
                    } => {
                        let last_seq = pre_state
                            .existing
                            .last()
                            .map_or(0, |r| r.checkpoint.receipt_seq);
                        let delta = receipt_seq.checked_sub(last_seq).ok_or_else(|| {
                            LedgerError::Integrity(format!(
                                "ledger rollback detected under BatchEvery: local receipt_seq {receipt_seq} < last anchored receipt_seq {last_seq}"
                            ))
                        })?;
                        delta >= every_n_receipts
                    }
                };

                if should_anchor {
                    Ok(Some(anchor_with_validated_existing(
                        storage,
                        witness,
                        &pre_state.existing,
                        &pre_state.pre_hashes,
                        receipt.timestamp,
                    )?))
                } else {
                    Ok(None)
                }
            },
        )?;

        commit_staged_write(storage, staged);
        Ok(result)
    }

    fn record_revocation(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
    ) -> Result<RevocationId, LedgerError> {
        if self.policy == WitnessPolicy::Disabled {
            return self.inner.record_revocation(revocation, signature_hex);
        }

        let active_policy = self.policy;
        let should_anchor = matches!(
            active_policy,
            WitnessPolicy::SyncStrict
                | WitnessPolicy::BatchEvery {
                    sync_revocations: true,
                    ..
                }
        );

        let Self {
            inner,
            witness,
            storage,
            ..
        } = self;

        let (rev_id, staged) = inner.record_revocation_atomic(
            revocation,
            signature_hex,
            |load_pre_hashes| {
                load_and_validate_existing_for_write(storage, active_policy, load_pre_hashes)
            },
            |mut pre_state, inserted_entry_hash, _load_post_hashes| {
                let Some(entry_hash) = inserted_entry_hash else {
                    return Ok(None);
                };
                if !should_anchor {
                    return Ok(None);
                }

                pre_state.pre_hashes.revocation_hashes.push(entry_hash);
                Ok(Some(anchor_with_validated_existing(
                    storage,
                    witness,
                    &pre_state.existing,
                    &pre_state.pre_hashes,
                    revocation.ast.effective_at(),
                )?))
            },
        )?;

        commit_staged_write(storage, staged);
        Ok(rev_id)
    }

    fn load_revocations(&self) -> Result<RevocationSnapshot, LedgerError> {
        self.inner.load_revocations()
    }

    fn list_stored_revocations(&self) -> Result<Vec<StoredRevocation>, LedgerError> {
        self.inner.list_stored_revocations()
    }

    fn record_denial(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
    ) -> Result<DecisionReceipt, LedgerError> {
        if self.policy == WitnessPolicy::Disabled {
            return self.inner.record_denial(chain_ids, request, now, reason);
        }
        let Self {
            inner,
            policy,
            storage,
            ..
        } = self;
        let active_policy = *policy;
        inner.record_denial_atomic(chain_ids, request, now, reason, |load_pre_hashes| {
            load_and_validate_existing_for_write(storage, active_policy, load_pre_hashes)?;
            Ok(())
        })
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
        if self.policy == WitnessPolicy::Disabled {
            return self.inner.record_denial_with_revocations(
                chain,
                actor_key,
                request,
                extra_revocations,
                now,
                fallback_reason,
            );
        }
        let Self {
            inner,
            policy,
            storage,
            ..
        } = self;
        let active_policy = *policy;
        inner.record_denial_with_revocations_atomic(
            AtomicDenialWithRevocations {
                chain,
                actor_key,
                request,
                extra_revocations,
                now,
                fallback_reason,
            },
            |load_pre_hashes| {
                load_and_validate_existing_for_write(storage, active_policy, load_pre_hashes)?;
                Ok(())
            },
        )
    }

    fn track_record(&self, actor_key: &KeyId) -> Result<TrackRecord, LedgerError> {
        self.inner.track_record(actor_key)
    }

    fn audit_snapshot(
        &self,
        actor_key: Option<&KeyId>,
    ) -> Result<(usize, Option<TrackRecord>), LedgerError> {
        self.inner.audit_snapshot(actor_key)
    }

    fn verified_chain_hashes(&self) -> Result<LedgerChainHashes, LedgerError> {
        self.inner.verified_chain_hashes()
    }
}

impl<L: TransactionalLedger, W: CheckpointWitness> ReadSnapshotLedger for AnchoredLedger<L, W> {
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        self.inner.with_read_snapshot(with_hashes)
    }
}

/// Offline, read-only verifier checking all persisted [`StoredCheckpoint`] records in
/// `sidecar_path` against `ledger`'s verified receipt/revocation hash chains and `registry`.
///
/// Acquires the ledger's synchronized read lock FIRST ([`ReadSnapshotLedger::with_read_snapshot`])
/// and reads `sidecar_path` INSIDE that open read snapshot before releasing the lock.
pub fn verify_ledger_witness_checkpoints<L: ReadSnapshotLedger>(
    ledger: &L,
    sidecar_path: &Path,
    registry: &WitnessRegistry,
    require_non_empty: bool,
    require_strict_tail: bool,
    expected_checkpoint_head: Option<&MandateId>,
) -> Result<usize, LedgerError> {
    let (chain_hashes, loaded) = ledger.with_read_snapshot(|hashes| {
        let loaded = load_checkpoints_from_file_status(sidecar_path)?;
        Ok((hashes.clone(), loaded))
    })?;
    verify_loaded_sidecar_against_chain(
        sidecar_path,
        loaded,
        &chain_hashes,
        SidecarVerifyOptions {
            require_non_empty,
            require_strict_tail,
            expected_checkpoint_head,
        },
        |cp, proof| registry.verify(cp, proof).map_err(LedgerError::from),
    )
}

/// Atomically captures a single consistent [`AuditSnapshot`] from `ledger` while holding SQLite's
/// `SHARED` read lock, reads `sidecar_path` INSIDE that open read transaction, and verifies all
/// persisted witness checkpoints against that exact snapshot.
pub fn verify_audit_snapshot_with_witness(
    ledger: &SqliteLedger,
    actor_key: Option<&KeyId>,
    sidecar_path: &Path,
    registry: &WitnessRegistry,
    require_strict_tail: bool,
    expected_checkpoint_head: Option<&MandateId>,
) -> Result<(AuditSnapshot, usize), LedgerError> {
    let (snapshot, loaded) = ledger.audit_full_snapshot_in_read_tx(actor_key, true, || {
        load_checkpoints_from_file_status(sidecar_path)
    })?;
    let chain_hashes = snapshot
        .chain_hashes
        .as_ref()
        .expect("audit_full_snapshot_in_read_tx(true) always populates chain_hashes");
    let verified_checkpoints = verify_loaded_sidecar_against_chain(
        sidecar_path,
        loaded,
        chain_hashes,
        SidecarVerifyOptions {
            require_non_empty: true,
            require_strict_tail,
            expected_checkpoint_head,
        },
        |cp, proof| registry.verify(cp, proof).map_err(LedgerError::from),
    )?;
    Ok((snapshot, verified_checkpoints))
}

fn policy_requires_checkpoint(policy: WitnessPolicy, chain: &LedgerChainHashes) -> bool {
    match policy {
        WitnessPolicy::Disabled => false,
        WitnessPolicy::SyncStrict => {
            chain.last_permit_seq.is_some() || !chain.revocation_hashes.is_empty()
        }
        WitnessPolicy::BatchEvery {
            every_n_receipts,
            sync_revocations,
        } => {
            chain.last_permit_seq.is_some_and(|s| s >= every_n_receipts)
                || (sync_revocations && !chain.revocation_hashes.is_empty())
        }
    }
}

fn resolve_loaded_sidecar_for_policy(
    policy: WitnessPolicy,
    loaded: SidecarLoad,
    chain: &LedgerChainHashes,
) -> Result<Vec<StoredCheckpoint>, LedgerError> {
    match loaded {
        SidecarLoad::Missing | SidecarLoad::Empty => {
            if policy_requires_checkpoint(policy, chain) {
                return Err(LedgerError::Integrity(
                    "checkpoint sidecar is missing or empty while ledger requires a checkpoint under active policy"
                        .to_string(),
                ));
            }
            Ok(Vec::new())
        }
        SidecarLoad::Records(records) => Ok(records),
    }
}

fn load_and_validate_existing_for_write(
    storage: &CheckpointStorage,
    policy: WitnessPolicy,
    load_pre_hashes: &dyn Fn() -> Result<LedgerChainHashes, LedgerError>,
) -> Result<PreWriteState, LedgerError> {
    let loaded = load_checkpoints_from_storage_status(storage)?;
    let pre_hashes = load_pre_hashes()?;
    let existing = resolve_loaded_sidecar_for_policy(policy, loaded, &pre_hashes)?;

    for record in &existing {
        verify_checkpoint_matches_chain(record.seq, &record.checkpoint, &pre_hashes)?;
    }
    if let Some(last) = existing.last() {
        verify_policy_tail_coverage(policy, last, &pre_hashes)?;
    }

    Ok(PreWriteState {
        existing,
        pre_hashes,
    })
}

fn verify_loaded_sidecar_against_chain<F>(
    sidecar_path: &Path,
    loaded: SidecarLoad,
    chain_hashes: &LedgerChainHashes,
    opts: SidecarVerifyOptions<'_>,
    verify_proof_fn: F,
) -> Result<usize, LedgerError>
where
    F: FnMut(&LedgerCheckpoint, &WitnessProof) -> Result<(), LedgerError>,
{
    let has_anchorable = policy_requires_checkpoint(WitnessPolicy::SyncStrict, chain_hashes);
    let records = match loaded {
        SidecarLoad::Missing => {
            if opts.expected_checkpoint_head.is_some()
                || ((opts.require_non_empty || opts.require_strict_tail) && has_anchorable)
            {
                return Err(LedgerError::NotFound(format!(
                    "checkpoint sidecar '{}' not found",
                    sidecar_path.display()
                )));
            }
            return Ok(0);
        }
        SidecarLoad::Empty => {
            if opts.expected_checkpoint_head.is_some() || has_anchorable {
                return Err(LedgerError::Integrity(format!(
                    "checkpoint sidecar '{}' is empty (possible truncation)",
                    sidecar_path.display()
                )));
            }
            return Ok(0);
        }
        SidecarLoad::Records(records) => records,
    };

    let count = verify_records_against_chain(&records, chain_hashes, verify_proof_fn)?;
    if opts.require_strict_tail {
        if let Some(last) = records.last() {
            verify_policy_tail_coverage(WitnessPolicy::SyncStrict, last, chain_hashes)?;
        }
    }
    verify_expected_checkpoint_head(&records, opts.expected_checkpoint_head)?;
    Ok(count)
}

fn verify_expected_checkpoint_head(
    records: &[StoredCheckpoint],
    expected_head: Option<&MandateId>,
) -> Result<(), LedgerError> {
    let Some(expected) = expected_head else {
        return Ok(());
    };
    let Some(last) = records.last() else {
        return Err(LedgerError::Integrity(format!(
            "expected checkpoint head {expected} not found: checkpoint sidecar has no records"
        )));
    };
    let record_hash_matches = last.record_hash == expected.to_string();
    let digest_matches = &last.checkpoint.checkpoint_digest() == expected.as_bytes();
    if !record_hash_matches && !digest_matches {
        return Err(LedgerError::Integrity(format!(
            "expected checkpoint head mismatch: expected {expected}, latest record_hash is {} (checkpoint_digest sha256:{})",
            last.record_hash,
            last.checkpoint.checkpoint_digest_hex()
        )));
    }
    Ok(())
}

fn verify_policy_tail_coverage(
    policy: WitnessPolicy,
    last: &StoredCheckpoint,
    chain_hashes: &LedgerChainHashes,
) -> Result<(), LedgerError> {
    let local_receipts = u64::try_from(chain_hashes.receipt_hashes.len())
        .map_err(|_| LedgerError::Integrity("local receipt count overflow".to_string()))?;
    if local_receipts < last.checkpoint.receipt_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {}: ledger rollback or truncation detected (anchored receipt_seq {}, local receipt count {local_receipts})",
            last.seq, last.checkpoint.receipt_seq
        )));
    }
    let latest_permit_seq = chain_hashes.last_permit_seq.unwrap_or(0);
    let latest_revocation_seq = u64::try_from(chain_hashes.revocation_hashes.len())
        .map_err(|_| LedgerError::Integrity("local revocation count overflow".to_string()))?;
    if latest_revocation_seq < last.checkpoint.revocation_seq {
        return Err(LedgerError::Integrity(format!(
            "checkpoint seq {}: revocation rollback or truncation detected (anchored revocation_seq {}, local revocation count {latest_revocation_seq})",
            last.seq, last.checkpoint.revocation_seq
        )));
    }

    match policy {
        WitnessPolicy::Disabled => Ok(()),
        WitnessPolicy::SyncStrict => {
            if last.checkpoint.receipt_seq < latest_permit_seq {
                return Err(LedgerError::Integrity(format!(
                    "checkpoint sidecar tail-truncation detected: latest checkpoint covers receipt_seq {}, but ledger has Permit at receipt_seq {latest_permit_seq}",
                    last.checkpoint.receipt_seq
                )));
            }
            if last.checkpoint.revocation_seq < latest_revocation_seq {
                return Err(LedgerError::Integrity(format!(
                    "checkpoint sidecar tail-truncation detected: latest checkpoint covers revocation_seq {}, but ledger has revocation_seq {latest_revocation_seq}",
                    last.checkpoint.revocation_seq
                )));
            }
            Ok(())
        }
        WitnessPolicy::BatchEvery {
            every_n_receipts,
            sync_revocations,
        } => {
            if latest_permit_seq.saturating_sub(last.checkpoint.receipt_seq) >= every_n_receipts {
                return Err(LedgerError::Integrity(format!(
                    "checkpoint sidecar tail-truncation detected under BatchEvery({every_n_receipts}): latest checkpoint covers receipt_seq {}, but ledger has Permit at receipt_seq {latest_permit_seq}",
                    last.checkpoint.receipt_seq
                )));
            }
            if sync_revocations && last.checkpoint.revocation_seq < latest_revocation_seq {
                return Err(LedgerError::Integrity(format!(
                    "checkpoint sidecar tail-truncation detected under BatchEvery(sync_revocations=true): latest checkpoint covers revocation_seq {}, but ledger has revocation_seq {latest_revocation_seq}",
                    last.checkpoint.revocation_seq
                )));
            }
            Ok(())
        }
    }
}

fn commit_staged_write(storage: &mut CheckpointStorage, staged: Option<StagedCheckpointWrite>) {
    match staged {
        Some(StagedCheckpointWrite::InMemory(record)) => {
            if let CheckpointStorage::InMemory(records) = storage {
                records.push(record);
            }
        }
        Some(StagedCheckpointWrite::Sidecar(pending)) => pending.commit(),
        None => {}
    }
}

fn load_checkpoints_from_storage_status(
    storage: &CheckpointStorage,
) -> Result<SidecarLoad, LedgerError> {
    match storage {
        CheckpointStorage::InMemory(records) => {
            if records.is_empty() {
                return Ok(SidecarLoad::Missing);
            }
            validate_stored_checkpoint_chain(records)?;
            Ok(SidecarLoad::Records(records.clone()))
        }
        CheckpointStorage::AppendOnlyFile(path) => load_checkpoints_from_file_status(path),
    }
}

fn anchor_with_validated_existing<W: CheckpointWitness>(
    storage: &CheckpointStorage,
    witness: &W,
    existing: &[StoredCheckpoint],
    chain_hashes: &LedgerChainHashes,
    timestamp: i64,
) -> Result<StagedCheckpointWrite, LedgerError> {
    let cp = build_checkpoint_from_hashes(chain_hashes, timestamp)?;
    cp.validate()?;

    if let Some(prev) = existing.last() {
        ensure_monotonic_checkpoint(prev.seq + 1, &prev.checkpoint, &cp)?;
    }

    let proof = witness.anchor(&cp)?;
    validate_witness_proof(&cp, &proof, witness.witness_kind())?;

    let seq = u64::try_from(existing.len())
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| LedgerError::Integrity("checkpoint sequence overflow".to_string()))?;
    let prev_record_hash = existing.last().map(|r| r.record_hash.clone());
    let record_hash =
        StoredCheckpoint::compute_record_hash(seq, prev_record_hash.as_deref(), &cp, &proof);
    let record = StoredCheckpoint {
        seq,
        prev_record_hash,
        record_hash,
        checkpoint: cp,
        proof,
    };

    match storage {
        CheckpointStorage::InMemory(_) => Ok(StagedCheckpointWrite::InMemory(record)),
        CheckpointStorage::AppendOnlyFile(path) => {
            let pending = append_checkpoint_to_file(path, &record)?;
            Ok(StagedCheckpointWrite::Sidecar(pending))
        }
    }
}

fn verify_records_against_chain<F>(
    records: &[StoredCheckpoint],
    chain_hashes: &LedgerChainHashes,
    mut verify_proof_fn: F,
) -> Result<usize, LedgerError>
where
    F: FnMut(&LedgerCheckpoint, &WitnessProof) -> Result<(), LedgerError>,
{
    validate_stored_checkpoint_chain(records)?;
    for record in records {
        verify_checkpoint_matches_chain(record.seq, &record.checkpoint, chain_hashes)?;
        verify_proof_fn(&record.checkpoint, &record.proof)?;
    }
    Ok(records.len())
}
