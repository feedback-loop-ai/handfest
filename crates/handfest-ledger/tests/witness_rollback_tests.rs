use std::fs;

use handfest_core::ast::{ActorDecl, KeyId, MandateId};
use handfest_core::base64::encode_standard;
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{
    ActionRequest, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::{RevocationAst, RevocationTarget};
use handfest_core::{ActorKind, AssuranceLevel, Verdict};
use handfest_ledger::{
    default_checkpoint_sidecar_path, verify_audit_snapshot_with_witness,
    verify_ledger_witness_checkpoints, AnchoredLedger, AtomicDenialWithRevocations,
    AtomicEvalRequest, CheckpointWitness, LedgerChainHashes, LedgerCheckpoint, LedgerError,
    ReadSnapshotLedger, ReceiptLedger, SqliteLedger, StoredCheckpoint, TransactionalLedger,
    WitnessError, WitnessPolicy, WitnessProof, WitnessRegistry, EMPTY_RECEIPT_TIP_HASH,
};
use tempfile::TempDir;

const NOW: i64 = 1_764_000_000;

#[derive(Clone)]
struct SimpleMockWitness;

impl CheckpointWitness for SimpleMockWitness {
    fn witness_kind(&self) -> &str {
        "mock"
    }
    fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
        Ok(WitnessProof {
            witness_kind: "mock".to_string(),
            checkpoint_digest_hex: cp.checkpoint_digest_hex(),
            proof_bytes_b64: encode_standard(&cp.checkpoint_digest()),
            anchored_at: cp.timestamp,
        })
    }
    fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError> {
        if proof.proof_bytes_b64 == encode_standard(&cp.checkpoint_digest()) {
            Ok(())
        } else {
            Err(WitnessError::VerificationFailed("mismatch".to_string()))
        }
    }
}

fn fixture_chain_and_req() -> (Vec<VerifiedMandate>, ActionRequest, KeyId, KeyId) {
    let root_key =
        KeyId::parse("ed25519:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let actor_key =
        KeyId::parse("ed25519:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {root_key})\nTO agent \"bot\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\n"
    );
    let chain = vec![VerifiedMandate {
        ast: parse_mandate(&raw).unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: root_key.clone(),
            actor_kind: ActorKind::Human,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
        },
    }];
    let req = ActionRequest {
        actor_key: actor_key.clone(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/app".to_string(),
    };
    (chain, req, root_key, actor_key)
}

fn make_revocation(
    signer: &KeyId,
    seed: &[u8],
    effective_at: i64,
    reason: &str,
) -> VerifiedRevocation {
    VerifiedRevocation {
        ast: RevocationAst::new(
            ActorDecl::new(
                ActorKind::Human,
                "alice".to_string(),
                signer.clone(),
                Default::default(),
            )
            .unwrap(),
            RevocationTarget::Mandate(MandateId::sha256(seed)),
            effective_at,
            Some(reason.to_string()),
        )
        .unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: signer.clone(),
            actor_kind: ActorKind::Human,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
        },
    }
}

struct CommitFailingLedger {
    inner: SqliteLedger,
    fail_next_commit: bool,
}

impl ReceiptLedger for CommitFailingLedger {
    fn evaluate_and_record_with_revocations(
        &mut self,
        _: &[VerifiedMandate],
        _: &ActionRequest,
        _: &VerifiedFacts,
        _: &handfest_core::gate::RevocationSnapshot,
        _: i64,
    ) -> Result<(Verdict, handfest_core::gate::DecisionReceipt), LedgerError> {
        unimplemented!()
    }
    fn record_revocation(
        &mut self,
        _: &VerifiedRevocation,
        _: &str,
    ) -> Result<handfest_core::revocation::RevocationId, LedgerError> {
        unimplemented!()
    }
    fn load_revocations(&self) -> Result<handfest_core::gate::RevocationSnapshot, LedgerError> {
        unimplemented!()
    }
    fn list_stored_revocations(
        &self,
    ) -> Result<Vec<handfest_ledger::StoredRevocation>, LedgerError> {
        unimplemented!()
    }
    fn record_denial(
        &mut self,
        _: Vec<MandateId>,
        _: &ActionRequest,
        _: i64,
        _: String,
    ) -> Result<handfest_core::gate::DecisionReceipt, LedgerError> {
        unimplemented!()
    }
    fn record_denial_with_revocations(
        &mut self,
        _: &[VerifiedMandate],
        _: &KeyId,
        _: &ActionRequest,
        _: &handfest_core::gate::RevocationSnapshot,
        _: i64,
        _: String,
    ) -> Result<(String, handfest_core::gate::DecisionReceipt), LedgerError> {
        unimplemented!()
    }
    fn track_record(&self, _: &KeyId) -> Result<handfest_ledger::TrackRecord, LedgerError> {
        unimplemented!()
    }
    fn audit_snapshot(
        &self,
        _: Option<&KeyId>,
    ) -> Result<(usize, Option<handfest_ledger::TrackRecord>), LedgerError> {
        unimplemented!()
    }
    fn verified_chain_hashes(&self) -> Result<handfest_ledger::LedgerChainHashes, LedgerError> {
        self.inner.verified_chain_hashes()
    }
}

impl ReadSnapshotLedger for CommitFailingLedger {
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        self.inner.with_read_snapshot(with_hashes)
    }
}

impl TransactionalLedger for CommitFailingLedger {
    fn evaluate_and_record_atomic<P, G, FPre, FPost>(
        &mut self,
        eval: AtomicEvalRequest<'_>,
        before_insert: FPre,
        before_commit: FPost,
    ) -> Result<((Verdict, handfest_core::gate::DecisionReceipt), G), LedgerError>
    where
        FPre: FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<P, LedgerError>,
        FPost: FnOnce(
            P,
            &Verdict,
            &handfest_core::gate::DecisionReceipt,
            &dyn Fn() -> Result<LedgerChainHashes, LedgerError>,
        ) -> Result<G, LedgerError>,
    {
        let fail = self.fail_next_commit;
        self.fail_next_commit = false;
        self.inner
            .evaluate_and_record_atomic(eval, before_insert, |pre, v, r, load| {
                let guard = before_commit(pre, v, r, load)?;
                if fail {
                    drop(guard);
                    return Err(LedgerError::Storage("simulated tx.commit() failure".into()));
                }
                Ok(guard)
            })
    }

    fn record_revocation_atomic<P, G, FPre, FPost>(
        &mut self,
        revocation: &VerifiedRevocation,
        signature_hex: &str,
        before_insert: FPre,
        before_commit: FPost,
    ) -> Result<(handfest_core::revocation::RevocationId, G), LedgerError>
    where
        FPre: FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<P, LedgerError>,
        FPost: FnOnce(
            P,
            Option<[u8; 32]>,
            &dyn Fn() -> Result<LedgerChainHashes, LedgerError>,
        ) -> Result<G, LedgerError>,
    {
        let fail = self.fail_next_commit;
        self.fail_next_commit = false;
        self.inner.record_revocation_atomic(
            revocation,
            signature_hex,
            before_insert,
            |pre, ins, load| {
                let guard = before_commit(pre, ins, load)?;
                if fail {
                    drop(guard);
                    return Err(LedgerError::Storage(
                        "simulated rev tx.commit() failure".into(),
                    ));
                }
                Ok(guard)
            },
        )
    }

    fn record_denial_atomic<FPre>(
        &mut self,
        chain_ids: Vec<MandateId>,
        request: &ActionRequest,
        now: i64,
        reason: String,
        before_insert: FPre,
    ) -> Result<handfest_core::gate::DecisionReceipt, LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        self.inner
            .record_denial_atomic(chain_ids, request, now, reason, before_insert)
    }

    fn record_denial_with_revocations_atomic<FPre>(
        &mut self,
        denial: AtomicDenialWithRevocations<'_>,
        before_insert: FPre,
    ) -> Result<(String, handfest_core::gate::DecisionReceipt), LedgerError>
    where
        FPre:
            FnOnce(&dyn Fn() -> Result<LedgerChainHashes, LedgerError>) -> Result<(), LedgerError>,
    {
        self.inner
            .record_denial_with_revocations_atomic(denial, before_insert)
    }
}

#[test]
fn sidecar_rolls_back_cleanly_when_tx_commit_fails_leaving_no_orphan_record() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("commit_rollback.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();
    let witness = SimpleMockWitness;

    // 1. Fresh sidecar (orig_len == 0): commit failure removes newly created sidecar file.
    let mut ledger1 = AnchoredLedger::with_checkpoint_file(
        CommitFailingLedger {
            inner: SqliteLedger::open(&db_path).unwrap(),
            fail_next_commit: true,
        },
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let err = ledger1
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap_err();
    assert!(matches!(err, LedgerError::Storage(_)));
    assert!(!sidecar.exists());

    // 2. Healthy write succeeds and creates checkpoint #1.
    let (v, _) = ledger1
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    assert_eq!(v, Verdict::Permit);
    let orig_bytes = fs::read(&sidecar).unwrap();
    assert_eq!(ledger1.checkpoint_count().unwrap(), 1);
    drop(ledger1);

    // 3. Existing sidecar (orig_len > 0): failed Permit & Revocation commits truncate to orig_len.
    let mut ledger2 = AnchoredLedger::with_checkpoint_file(
        CommitFailingLedger {
            inner: SqliteLedger::open(&db_path).unwrap(),
            fail_next_commit: true,
        },
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    assert!(matches!(
        ledger2.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 2),
        Err(LedgerError::Storage(_))
    ));
    assert_eq!(fs::read(&sidecar).unwrap(), orig_bytes);

    let mut ledger3 = AnchoredLedger::with_checkpoint_file(
        CommitFailingLedger {
            inner: SqliteLedger::open(&db_path).unwrap(),
            fail_next_commit: true,
        },
        witness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let rev = make_revocation(&root_key, b"commit-fail-rev", NOW + 3, "fail");
    assert!(matches!(
        ledger3.record_revocation(&rev, "deadbeef"),
        Err(LedgerError::Storage(_))
    ));
    assert_eq!(fs::read(&sidecar).unwrap(), orig_bytes);
    assert_eq!(ledger3.verify_witness_checkpoints().unwrap(), 1);
}

#[test]
fn atomic_write_acquires_begin_exclusive_before_running_before_commit_hook() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::time::Duration;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("exclusive_lock.sqlite");
    let (chain, req, _, _) = fixture_chain_and_req();

    // Initialize schema and insert 1 receipt so reader can acquire a SHARED lock.
    let mut writer = SqliteLedger::open(&db_path).unwrap();
    writer
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();

    // Hold a SHARED read lock on a separate SQLite connection.
    let reader = rusqlite::Connection::open(&db_path).unwrap();
    reader
        .execute_batch("BEGIN DEFERRED; SELECT count(*) FROM receipts;")
        .unwrap();

    let hook_entered = Arc::new(AtomicBool::new(false));
    let hook_entered_bg = Arc::clone(&hook_entered);
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let writer_handle = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let res = writer.evaluate_and_record_atomic(
            AtomicEvalRequest {
                chain: &chain,
                request: &req,
                facts: &VerifiedFacts::new(),
                extra_revocations: &handfest_core::gate::RevocationSnapshot::new(),
                now: NOW + 1,
            },
            |_| Ok(()),
            |(), _, _, _| {
                hook_entered_bg.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        done_tx.send(()).unwrap();
        res.unwrap().0
    });

    started_rx.recv().unwrap();
    // Wait briefly while holding SHARED lock: under BEGIN EXCLUSIVE the writer must block at
    // BEGIN before running before_commit (under BEGIN IMMEDIATE it would enter before_commit!).
    assert!(
        done_rx.recv_timeout(Duration::from_millis(80)).is_err(),
        "writer must block while reader holds SHARED lock"
    );
    assert!(
        !hook_entered.load(Ordering::SeqCst),
        "before_commit must NOT run while another connection holds SHARED lock (BEGIN EXCLUSIVE required)"
    );

    // Release SHARED lock; writer now acquires EXCLUSIVE, runs before_commit, and commits cleanly.
    reader.execute_batch("COMMIT;").unwrap();
    let (verdict, _) = writer_handle.join().unwrap();
    assert_eq!(verdict, Verdict::Permit);
    assert!(hook_entered.load(Ordering::SeqCst));
}

#[test]
fn batch_every_10_pre_insert_rejects_single_row_rollback_and_identical_10th_replay() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("batch10_single_row_replay.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();

    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {root_key})\nTO agent \"bot\" (key: {})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\nLIMIT 10 calls\n",
        req.actor_key
    );
    let limit10_chain = vec![VerifiedMandate {
        ast: parse_mandate(&raw).unwrap(),
        proof: chain[0].proof.clone(),
    }];
    let mid_str = limit10_chain[0].ast.mandate_id().to_string();

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 10,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();

    for i in 0..10i64 {
        let (v, _) = ledger
            .evaluate_and_record(&limit10_chain, &req, &VerifiedFacts::new(), NOW + i)
            .unwrap();
        assert_eq!(v, Verdict::Permit);
    }
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);
    drop(ledger);

    // Roll back EXACTLY 1 row (10 -> 9) and repair sqlite_sequence & quota_calls = 9.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM receipts WHERE seq > 9", [])
            .unwrap();
        conn.execute(
            "UPDATE sqlite_sequence SET seq = 9 WHERE name = 'receipts'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE quota_calls SET calls = 9 WHERE mandate_id = ?1",
            [&mid_str],
        )
        .unwrap();
    }

    // Replay the IDENTICAL 10th request at the EXACT SAME timestamp (NOW + 9):
    // Post-insert validation would see receipt_seq == 10 with the identical receipt_hash and
    // silently allow an 11th call; pre-insert validation MUST reject BEFORE writing!
    let mut reopened = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 10,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();
    let err = reopened
        .evaluate_and_record(&limit10_chain, &req, &VerifiedFacts::new(), NOW + 9)
        .unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "expected pre-insert rollback rejection on 10->9 identical replay, got: {err}"
    );
    assert_eq!(
        reopened.verify_integrity().unwrap(),
        9,
        "pre-insert failure must leave 9 rows untouched (zero rows written)"
    );
}

#[test]
fn record_revocation_pre_insert_rejects_single_row_rollback_and_identical_replay() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("rev_single_row_replay.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (_, _, root_key, _) = fixture_chain_and_req();

    let rev = make_revocation(&root_key, b"rev-replay-1", NOW + 1, "compromised");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);
    drop(ledger);

    // Roll back the 1 revocation row in SQLite (1 -> 0).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM revocations", []).unwrap();
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'revocations'", [])
            .unwrap();
    }

    // Replaying the EXACT same revocation must be rejected BEFORE inserting!
    let mut reopened = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let err = reopened.record_revocation(&rev, "deadbeef").unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("revocation rollback or truncation")),
        "expected pre-insert revocation rollback rejection on identical replay, got: {err}"
    );
    assert!(
        reopened.list_stored_revocations().unwrap().is_empty(),
        "failed pre-insert record_revocation must leave 0 revocations written"
    );
}

#[test]
fn anchored_record_denial_paths_fail_closed_on_rolled_back_db_and_truncated_sidecar() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("denial_preinsert.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, actor_key) = fixture_chain_and_req();

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    let backup_db = fs::read(&db_path).unwrap();
    let backup_sidecar = fs::read_to_string(&sidecar).unwrap();
    drop(ledger);

    // Case 1: Replace SQLite with an empty DB -> both record_denial* fail with Integrity & 0 rows!
    let fresh_path = dir.path().join("fresh_empty_denial.sqlite");
    let _ = SqliteLedger::open(&fresh_path).unwrap();
    fs::copy(&fresh_path, &db_path).unwrap();

    let mut empty_anchored = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let err1 = empty_anchored
        .record_denial(Vec::new(), &req, NOW + 2, "pre-gate".to_string())
        .unwrap_err();
    assert!(
        matches!(err1, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "record_denial must fail closed on rolled-back empty DB, got: {err1}"
    );
    assert_eq!(empty_anchored.verify_integrity().unwrap(), 0);

    let err2 = empty_anchored
        .record_denial_with_revocations(
            &chain,
            &actor_key,
            &req,
            &handfest_core::gate::RevocationSnapshot::new(),
            NOW + 3,
            "fallback".to_string(),
        )
        .unwrap_err();
    assert!(
        matches!(err2, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "record_denial_with_revocations must fail closed on rolled-back empty DB, got: {err2}"
    );
    assert_eq!(empty_anchored.verify_integrity().unwrap(), 0);
    drop(empty_anchored);

    assert_denial_sidecar_truncation_and_recovery(
        &db_path,
        &sidecar,
        &backup_db,
        &backup_sidecar,
        &chain,
        &req,
        &actor_key,
    );
}

fn assert_denial_sidecar_truncation_and_recovery(
    db_path: &std::path::Path,
    sidecar: &std::path::Path,
    backup_db: &[u8],
    backup_sidecar: &str,
    chain: &[VerifiedMandate],
    req: &ActionRequest,
    actor_key: &KeyId,
) {
    let first_line = format!("{}\n", backup_sidecar.lines().next().unwrap());
    // Case 2: Restore DB (2 Permits), truncate sidecar to 0 bytes -> both record_denial* fail closed!
    fs::write(db_path, backup_db).unwrap();
    fs::write(sidecar, b"").unwrap();
    let mut trunc_anchored = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        sidecar,
    )
    .unwrap();
    assert!(matches!(
        trunc_anchored.record_denial(Vec::new(), req, NOW + 4, "pre-gate".to_string()),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("empty")
    ));
    assert!(matches!(
        trunc_anchored.record_denial_with_revocations(
            chain,
            actor_key,
            req,
            &handfest_core::gate::RevocationSnapshot::new(),
            NOW + 5,
            "fallback".to_string(),
        ),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("empty")
    ));
    assert_eq!(trunc_anchored.verify_integrity().unwrap(), 2);

    // Case 3: Tail-truncate sidecar to line 1 -> both record_denial* fail closed!
    fs::write(sidecar, &first_line).unwrap();
    assert!(matches!(
        trunc_anchored.record_denial(Vec::new(), req, NOW + 6, "pre-gate".to_string()),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
    ));
    assert!(matches!(
        trunc_anchored.record_denial_with_revocations(
            chain,
            actor_key,
            req,
            &handfest_core::gate::RevocationSnapshot::new(),
            NOW + 7,
            "fallback".to_string(),
        ),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
    ));
    assert_eq!(trunc_anchored.verify_integrity().unwrap(), 2);

    // Case 4: Intact sidecar -> both record_denial* succeed cleanly!
    fs::write(sidecar, backup_sidecar).unwrap();
    trunc_anchored
        .record_denial(Vec::new(), req, NOW + 8, "valid-denial".to_string())
        .unwrap();
    trunc_anchored
        .record_denial_with_revocations(
            chain,
            actor_key,
            req,
            &handfest_core::gate::RevocationSnapshot::new(),
            NOW + 9,
            "valid-denial-rev".to_string(),
        )
        .unwrap();
    assert_eq!(trunc_anchored.verify_integrity().unwrap(), 4);
    assert_eq!(trunc_anchored.verify_witness_checkpoints().unwrap(), 2);
}

fn assert_exclusive_lock_contended(db_path: &std::path::Path) {
    let probe = rusqlite::Connection::open(db_path).unwrap();
    probe.busy_timeout(std::time::Duration::ZERO).unwrap();
    let err = probe.execute_batch("BEGIN EXCLUSIVE;").expect_err(
        "BEGIN EXCLUSIVE must fail with SQLITE_BUSY while SHARED snapshot lock is held",
    );
    assert!(
        matches!(
            err,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::DatabaseBusy,
                    ..
                },
                _
            )
        ),
        "expected SQLITE_BUSY under active read snapshot lock, got: {err}"
    );
}

struct HookedReadSnapshotLedger<'a, FBefore, FInside, FAfter> {
    inner: &'a SqliteLedger,
    before_snapshot: FBefore,
    inside_snapshot: FInside,
    after_snapshot: FAfter,
}

impl<FBefore, FInside, FAfter> ReadSnapshotLedger
    for HookedReadSnapshotLedger<'_, FBefore, FInside, FAfter>
where
    FBefore: Fn(),
    FInside: Fn(&LedgerChainHashes),
    FAfter: Fn(),
{
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        (self.before_snapshot)();
        let result = self.inner.with_read_snapshot(|hashes| {
            (self.inside_snapshot)(hashes);
            let out = with_hashes(hashes)?;
            (self.inside_snapshot)(hashes);
            Ok(out)
        })?;
        (self.after_snapshot)();
        Ok(result)
    }
}

#[test]
fn shared_read_lock_synchronizes_sidecar_read_with_concurrent_exclusive_writer() {
    use std::cell::{Cell, RefCell};

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("shared_lock_sync.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();

    let writer = RefCell::new(
        AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open(&db_path).unwrap(),
            SimpleMockWitness,
            WitnessPolicy::SyncStrict,
            &sidecar,
        )
        .unwrap(),
    );
    writer
        .borrow_mut()
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();

    let mut reg = WitnessRegistry::new();
    reg.register(SimpleMockWitness).unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();

    // 1. Deterministically prove SHARED lock contention during `verify_ledger_witness_checkpoints`
    //    AND bind that its sidecar read happens INSIDE `with_read_snapshot` (not after): committing
    //    Permit #2 immediately after `with_read_snapshot` releases SHARED would cause an unsynchronized
    //    post-snapshot sidecar read to observe receipt_seq=2 against a 1-receipt snapshot and fail.
    let inside_checks = Cell::new(0usize);
    let after_committed = Cell::new(false);
    let hooked_after = HookedReadSnapshotLedger {
        inner: &ro,
        before_snapshot: || {},
        inside_snapshot: |hashes: &LedgerChainHashes| {
            assert_eq!(hashes.receipt_hashes.len(), 1);
            assert_exclusive_lock_contended(&db_path);
            assert_eq!(fs::read_to_string(&sidecar).unwrap().lines().count(), 1);
            inside_checks.set(inside_checks.get() + 1);
        },
        after_snapshot: || {
            let probe = rusqlite::Connection::open(&db_path).unwrap();
            probe.busy_timeout(std::time::Duration::ZERO).unwrap();
            probe
                .execute_batch("BEGIN EXCLUSIVE; ROLLBACK;")
                .expect("BEGIN EXCLUSIVE must succeed once read snapshot lock is released");
            drop(probe);
            writer
                .borrow_mut()
                .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
                .unwrap();
            after_committed.set(true);
        },
    };
    assert_eq!(
        verify_ledger_witness_checkpoints(&hooked_after, &sidecar, &reg, true, true, None).unwrap(),
        1
    );
    assert_eq!(inside_checks.get(), 2);
    assert!(after_committed.get());

    // 2. Bind that `verify_ledger_witness_checkpoints` does NOT read the sidecar BEFORE acquiring
    //    the snapshot: committing Permit #3 in `before_snapshot` causes a pre-snapshot sidecar read
    //    (2 checkpoints) to fail strict tail coverage against the 3-receipt snapshot.
    let before_checks = Cell::new(0usize);
    let hooked_before = HookedReadSnapshotLedger {
        inner: &ro,
        before_snapshot: || {
            writer
                .borrow_mut()
                .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 2)
                .unwrap();
        },
        inside_snapshot: |hashes: &LedgerChainHashes| {
            assert_eq!(hashes.receipt_hashes.len(), 3);
            assert_exclusive_lock_contended(&db_path);
            before_checks.set(before_checks.get() + 1);
        },
        after_snapshot: || {},
    };
    assert_eq!(
        verify_ledger_witness_checkpoints(&hooked_before, &sidecar, &reg, true, true, None)
            .unwrap(),
        3
    );
    assert_eq!(before_checks.get(), 2);

    let (snap, cps) =
        verify_audit_snapshot_with_witness(&ro, None, &sidecar, &reg, true, None).unwrap();
    assert_eq!((snap.verified_receipts, cps), (3, 3));
}

#[test]
fn empty_zero_byte_sidecar_on_deny_only_ledger_allows_first_witnessed_permit() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("deny_only_zero_byte.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    let (v_deny, _) = ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert!(matches!(v_deny, Verdict::Deny { .. }));
    fs::write(&sidecar, b"").unwrap();
    assert_eq!(ledger.checkpoint_count().unwrap(), 0);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 0);

    let (v_permit, _) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    assert_eq!(v_permit, Verdict::Permit);
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 1);

    let mut reg = WitnessRegistry::new();
    reg.register(SimpleMockWitness).unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let (snap, cps) =
        verify_audit_snapshot_with_witness(&ro, None, &sidecar, &reg, true, None).unwrap();
    assert_eq!((snap.verified_receipts, cps), (2, 1));
}

struct BatchTamperFixture<'a> {
    chain: &'a [VerifiedMandate],
    req: &'a ActionRequest,
    deny_req: &'a ActionRequest,
    actor_key: &'a KeyId,
}

fn assert_batch_every_tampered_reads_and_writes_fail_closed(
    ledger: &mut AnchoredLedger<SqliteLedger, SimpleMockWitness>,
    fx: &BatchTamperFixture<'_>,
    expected_msg: &str,
    expected_receipts: usize,
    ts_base: i64,
) {
    assert!(matches!(
        ledger.verify_witness_checkpoints(),
        Err(LedgerError::Integrity(ref msg)) if msg.contains(expected_msg)
    ));
    assert!(matches!(
        ledger.checkpoint_count(),
        Err(LedgerError::Integrity(ref msg)) if msg.contains(expected_msg)
    ));
    assert!(matches!(
        ledger.record_denial(Vec::new(), fx.deny_req, ts_base, "deny".to_string()),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        ledger.record_denial_with_revocations(
            fx.chain,
            fx.actor_key,
            fx.deny_req,
            &Default::default(),
            ts_base + 1,
            "fallback".to_string(),
        ),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        ledger.evaluate_and_record(fx.chain, fx.req, &VerifiedFacts::new(), ts_base + 2),
        Err(LedgerError::Integrity(_))
    ));
    assert_eq!(ledger.verify_integrity().unwrap(), expected_receipts);
}

#[test]
fn batch_every_policy_enforces_tail_coverage_and_sidecar_presence_on_reads_and_writes() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("batch_tail_presence.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, actor_key) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();

    // 4 Permits + 1 Revocation -> 3 checkpoints: (2,0), (4,0), (4,1).
    for i in 0..4 {
        let (v, _) = ledger
            .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + i)
            .unwrap();
        assert_eq!(v, Verdict::Permit);
    }
    let rev = make_revocation(&root_key, b"batch-tail-rev", NOW + 10, "sync rev");
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.checkpoint_count().unwrap(), 3);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 3);

    let full_sidecar = fs::read_to_string(&sidecar).unwrap();
    let lines: Vec<&str> = full_sidecar.lines().collect();
    assert_eq!(lines.len(), 3);

    let fx = BatchTamperFixture {
        chain: &chain,
        req: &req,
        deny_req: &deny_req,
        actor_key: &actor_key,
    };

    // 1. Truncate sidecar to 2 lines (missing sync_revocations checkpoint (4,1)) -> fails closed.
    fs::write(&sidecar, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "sync_revocations=true",
        4,
        NOW + 20,
    );

    // 2. Truncate sidecar to line 1 ((2,0)) -> fails closed on reads, denials, and Permit #5.
    fs::write(&sidecar, format!("{}\n", lines[0])).unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "BatchEvery(2)",
        4,
        NOW + 30,
    );

    // 3. Delete sidecar completely -> fails closed on reads, denials, and Permit #5.
    fs::remove_file(&sidecar).unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "missing or empty",
        4,
        NOW + 40,
    );

    // 4. Restore full sidecar against a fresh empty SQLite DB -> checkpoint_count() catches DB rollback.
    fs::write(&sidecar, &full_sidecar).unwrap();
    let rolled_db = dir.path().join("batch_rolled_empty.sqlite");
    let rolled_ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&rolled_db).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();
    assert!(matches!(
        rolled_ledger.checkpoint_count(),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("rollback or truncation")
    ));
}

#[test]
fn healthy_batch_every_below_threshold_allows_missing_and_zero_byte_sidecar() {
    let dir = TempDir::new().unwrap();
    let (chain, req, _, _) = fixture_chain_and_req();

    // Case A: Missing sidecar with 1 Permit under BatchEvery(2, sync_revocations=false).
    let db_a = dir.path().join("batch_missing_ok.sqlite");
    let sc_a = default_checkpoint_sidecar_path(&db_a);
    let mut ledger_a = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_a).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: false,
        },
        &sc_a,
    )
    .unwrap();
    let (v1, _) = ledger_a
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert_eq!(v1, Verdict::Permit);
    assert!(!sc_a.exists());
    assert_eq!(ledger_a.checkpoint_count().unwrap(), 0);
    assert_eq!(ledger_a.verify_witness_checkpoints().unwrap(), 0);

    // Case B: Pre-existing 0-byte sidecar before Permit #1 -> Permit #1 and Permit #2 succeed cleanly.
    let db_b = dir.path().join("batch_zero_byte_ok.sqlite");
    let sc_b = default_checkpoint_sidecar_path(&db_b);
    fs::write(&sc_b, b"").unwrap();
    let mut ledger_b = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_b).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: false,
        },
        &sc_b,
    )
    .unwrap();
    let (vb1, _) = ledger_b
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 10)
        .unwrap();
    assert_eq!(vb1, Verdict::Permit);
    assert_eq!(ledger_b.checkpoint_count().unwrap(), 0);
    assert_eq!(ledger_b.verify_witness_checkpoints().unwrap(), 0);

    let (vb2, _) = ledger_b
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 11)
        .unwrap();
    assert_eq!(vb2, Verdict::Permit);
    assert_eq!(ledger_b.checkpoint_count().unwrap(), 1);
    assert_eq!(ledger_b.verify_witness_checkpoints().unwrap(), 1);
}

#[test]
fn rejects_empty_zero_zero_and_stationary_duplicate_checkpoints() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("stationary_dup.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();

    let mut reg = WitnessRegistry::new();
    reg.register(SimpleMockWitness).unwrap();

    // 1. Craft an unanchorable (0, 0) checkpoint with valid proof shape and valid record_hash.
    let empty_db = dir.path().join("empty_zero_zero.sqlite");
    let empty_sc = default_checkpoint_sidecar_path(&empty_db);
    let _ = SqliteLedger::open(&empty_db).unwrap();
    let zero_cp = LedgerCheckpoint {
        receipt_seq: 0,
        receipt_hash: EMPTY_RECEIPT_TIP_HASH,
        revocation_seq: 0,
        revocation_tip_hash: None,
        timestamp: NOW,
    };
    let zero_proof = SimpleMockWitness.anchor(&zero_cp).unwrap();
    let zero_hash = StoredCheckpoint::compute_record_hash(1, None, &zero_cp, &zero_proof);
    let zero_rec = StoredCheckpoint {
        seq: 1,
        prev_record_hash: None,
        record_hash: zero_hash,
        checkpoint: zero_cp,
        proof: zero_proof,
    };
    fs::write(
        &empty_sc,
        format!("{}\n", serde_json::to_string(&zero_rec).unwrap()),
    )
    .unwrap();
    let ro_empty = SqliteLedger::open_read_only(&empty_db).unwrap();
    let zero_err = verify_ledger_witness_checkpoints(&ro_empty, &empty_sc, &reg, true, true, None)
        .unwrap_err();
    assert!(
        matches!(zero_err, LedgerError::Integrity(ref msg) if msg.contains("empty (0, 0)")),
        "expected empty (0, 0) checkpoint rejection, got: {zero_err}"
    );

    // 2. Record 1 Permit -> rec1 (receipt_seq=1, revocation_seq=0), then clone rec1 as rec2
    //    with seq=2, prev_record_hash=Some(rec1.record_hash), and recomputed record_hash.
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 1);

    let line1 = fs::read_to_string(&sidecar).unwrap();
    let rec1: StoredCheckpoint = serde_json::from_str(line1.trim()).unwrap();
    assert_eq!(
        (rec1.checkpoint.receipt_seq, rec1.checkpoint.revocation_seq),
        (1, 0)
    );
    let rec2_hash = StoredCheckpoint::compute_record_hash(
        2,
        Some(&rec1.record_hash),
        &rec1.checkpoint,
        &rec1.proof,
    );
    let rec2 = StoredCheckpoint {
        seq: 2,
        prev_record_hash: Some(rec1.record_hash.clone()),
        record_hash: rec2_hash,
        checkpoint: rec1.checkpoint.clone(),
        proof: rec1.proof.clone(),
    };
    let dup_sidecar = format!("{}{}\n", line1, serde_json::to_string(&rec2).unwrap());
    fs::write(&sidecar, dup_sidecar).unwrap();

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let dup_err =
        verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(dup_err, LedgerError::Integrity(ref msg) if msg.contains("zero-progress duplicate")),
        "expected zero-progress duplicate rejection, got: {dup_err}"
    );
    assert!(matches!(
        ledger.verify_witness_checkpoints(),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("zero-progress duplicate")
    ));
}

#[test]
fn batch_every_receipt_threshold_only_fails_closed_for_missing_and_empty_sidecar() {
    let dir = TempDir::new().unwrap();
    let (chain, req, _, actor_key) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };
    let fx = BatchTamperFixture {
        chain: &chain,
        req: &req,
        deny_req: &deny_req,
        actor_key: &actor_key,
    };

    // Receipt threshold reached (2 Permits >= 2) with sync_revocations=false and 0 revocations.
    let db = dir.path().join("batch_receipt_only.sqlite");
    let sc = default_checkpoint_sidecar_path(&db);
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: false,
        },
        &sc,
    )
    .unwrap();
    for i in 0..2 {
        assert_eq!(
            ledger
                .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + i)
                .unwrap()
                .0,
            Verdict::Permit
        );
    }
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);

    fs::remove_file(&sc).unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "missing or empty",
        2,
        NOW + 10,
    );
    fs::write(&sc, b"").unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "missing or empty",
        2,
        NOW + 20,
    );
}

#[test]
fn batch_every_sync_revocations_only_fails_closed_for_missing_and_empty_sidecar() {
    let dir = TempDir::new().unwrap();
    let (chain, req, root_key, actor_key) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };
    let fx = BatchTamperFixture {
        chain: &chain,
        req: &req,
        deny_req: &deny_req,
        actor_key: &actor_key,
    };
    let rev = make_revocation(&root_key, b"batch-rev-only", NOW + 30, "sync rev");

    // sync_revocations=true with 1 revocation and 0 Permits (below every_n_receipts=2).
    let db = dir.path().join("batch_rev_only.sqlite");
    let sc = default_checkpoint_sidecar_path(&db);
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sc,
    )
    .unwrap();
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);

    fs::remove_file(&sc).unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "missing or empty",
        0,
        NOW + 40,
    );
    fs::write(&sc, b"").unwrap();
    assert_batch_every_tampered_reads_and_writes_fail_closed(
        &mut ledger,
        &fx,
        "missing or empty",
        0,
        NOW + 50,
    );

    // Negative control: sync_revocations=false with 1 Permit (< 2) + 1 revocation needs no checkpoint.
    let db_ctrl = dir.path().join("batch_unsynced_rev_ctrl.sqlite");
    let sc_ctrl = default_checkpoint_sidecar_path(&db_ctrl);
    let mut ctrl = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_ctrl).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: false,
        },
        &sc_ctrl,
    )
    .unwrap();
    ctrl.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 60)
        .unwrap();
    ctrl.record_revocation(&rev, "deadbeef").unwrap();
    assert!(!sc_ctrl.exists());
    assert_eq!(ctrl.checkpoint_count().unwrap(), 0);
    fs::write(&sc_ctrl, b"").unwrap();
    assert_eq!(ctrl.checkpoint_count().unwrap(), 0);
    assert_eq!(ctrl.verify_witness_checkpoints().unwrap(), 0);
}

#[test]
fn checkpoint_count_detects_revocation_only_rollback_with_intact_receipts() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("rev_rollback_live.sqlite");
    let rev_rolled_db = dir.path().join("rev_rollback_copy.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();
    for i in 0..2 {
        assert_eq!(
            ledger
                .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + i)
                .unwrap()
                .0,
            Verdict::Permit
        );
    }
    fs::copy(&db_path, &rev_rolled_db).unwrap();

    let rev = make_revocation(&root_key, b"rev-only-rollback", NOW + 10, "sync rev");
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.checkpoint_count().unwrap(), 2);

    // Intact receipt history (2 == 2) with revocation history behind checkpoint (0 < 1).
    let rolled = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open_read_only(&rev_rolled_db).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();
    let err = rolled.checkpoint_count().unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("revocation rollback or truncation")),
        "expected revocation rollback Integrity error from checkpoint_count(), got: {err}"
    );
}

/// Minimal read-only snapshot backend implementing ONLY [`ReadSnapshotLedger`] (no [`ReceiptLedger`] writes).
struct ReadOnlySnapshotWrapper(SqliteLedger);

impl ReadSnapshotLedger for ReadOnlySnapshotWrapper {
    fn with_read_snapshot<T, F>(&self, with_hashes: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
    {
        ReadSnapshotLedger::with_read_snapshot(&self.0, with_hashes)
    }
}

#[test]
fn verify_ledger_witness_checkpoints_accepts_anchored_and_read_only_snapshot_ledgers() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("anchored_verifier_bound.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();

    let mut anchored = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SimpleMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    anchored
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();

    let line = fs::read_to_string(&sidecar).unwrap();
    let rec: StoredCheckpoint = serde_json::from_str(line.trim()).unwrap();
    let expected_head = MandateId::parse(&rec.record_hash).unwrap();
    let wrong_head = MandateId::sha256(b"wrong-expected-head");

    let mut reg = WitnessRegistry::new();
    reg.register(SimpleMockWitness).unwrap();

    // AnchoredLedger directly satisfies ReadSnapshotLedger without implementing TransactionalLedger.
    assert_eq!(
        verify_ledger_witness_checkpoints(
            &anchored,
            &sidecar,
            &reg,
            true,
            true,
            Some(&expected_head)
        )
        .unwrap(),
        1
    );
    assert!(matches!(
        verify_ledger_witness_checkpoints(&anchored, &sidecar, &reg, true, true, Some(&wrong_head)),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("expected checkpoint head mismatch")
    ));

    // A read-only synchronized snapshot backend (no write hooks) also works directly.
    let ro_wrapper = ReadOnlySnapshotWrapper(SqliteLedger::open_read_only(&db_path).unwrap());
    assert_eq!(
        verify_ledger_witness_checkpoints(
            &ro_wrapper,
            &sidecar,
            &reg,
            true,
            true,
            Some(&expected_head),
        )
        .unwrap(),
        1
    );
}
