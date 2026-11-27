use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::rc::Rc;

use handfest_core::ast::{
    encode_lower_hex, ActorDecl, KeyId, MandateId, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::base64::encode_standard;
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{
    ActionRequest, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate, VerifiedRevocation,
};
use handfest_core::revocation::{RevocationAst, RevocationTarget};
use handfest_core::{ActorKind, AssuranceLevel, Verdict};
use handfest_ledger::{
    canonical_checkpoint_sidecar_path, default_checkpoint_sidecar_path, validate_witness_kind,
    validate_witness_proof, verify_audit_snapshot_with_witness, verify_ledger_witness_checkpoints,
    AnchoredLedger, CheckpointWitness, LedgerCheckpoint, LedgerError, ReceiptLedger, SqliteLedger,
    StoredCheckpoint, WitnessError, WitnessPolicy, WitnessProof, WitnessRegistry,
    CHECKPOINT_DIGEST_DOMAIN_PREFIX, EMPTY_RECEIPT_TIP_HASH,
};
use tempfile::TempDir;

const NOW: i64 = 1_764_000_000;

#[derive(Clone)]
struct RecordingWitness {
    kind: String,
    anchored: Rc<RefCell<Vec<LedgerCheckpoint>>>,
    verified: Rc<RefCell<Vec<LedgerCheckpoint>>>,
    fail_anchor: Rc<RefCell<Option<WitnessError>>>,
    fail_verify: Rc<RefCell<Option<WitnessError>>>,
    override_proof: Rc<RefCell<Option<WitnessProof>>>,
}

impl RecordingWitness {
    fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_string(),
            anchored: Rc::new(RefCell::new(Vec::new())),
            verified: Rc::new(RefCell::new(Vec::new())),
            fail_anchor: Rc::new(RefCell::new(None)),
            fail_verify: Rc::new(RefCell::new(None)),
            override_proof: Rc::new(RefCell::new(None)),
        }
    }

    fn anchor_count(&self) -> usize {
        self.anchored.borrow().len()
    }

    fn anchored_checkpoints(&self) -> Vec<LedgerCheckpoint> {
        self.anchored.borrow().clone()
    }

    fn verified_count(&self) -> usize {
        self.verified.borrow().len()
    }

    fn set_fail_anchor(&self, err: Option<WitnessError>) {
        *self.fail_anchor.borrow_mut() = err;
    }

    fn set_fail_verify(&self, err: Option<WitnessError>) {
        *self.fail_verify.borrow_mut() = err;
    }

    fn set_override_proof(&self, proof: Option<WitnessProof>) {
        *self.override_proof.borrow_mut() = proof;
    }
}

impl CheckpointWitness for RecordingWitness {
    fn witness_kind(&self) -> &str {
        &self.kind
    }

    fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
        self.anchored.borrow_mut().push(cp.clone());
        if let Some(err) = self.fail_anchor.borrow().clone() {
            return Err(err);
        }
        if let Some(proof) = self.override_proof.borrow().clone() {
            return Ok(proof);
        }
        let mut proof_bytes = b"mock-proof:".to_vec();
        proof_bytes.extend_from_slice(&cp.checkpoint_digest());
        Ok(WitnessProof {
            witness_kind: self.kind.clone(),
            checkpoint_digest_hex: cp.checkpoint_digest_hex(),
            proof_bytes_b64: encode_standard(&proof_bytes),
            anchored_at: cp.timestamp,
        })
    }

    fn verify(&self, cp: &LedgerCheckpoint, proof: &WitnessProof) -> Result<(), WitnessError> {
        self.verified.borrow_mut().push(cp.clone());
        if let Some(err) = self.fail_verify.borrow().clone() {
            return Err(err);
        }
        let mut expected = b"mock-proof:".to_vec();
        expected.extend_from_slice(&cp.checkpoint_digest());
        if proof.proof_bytes_b64 != encode_standard(&expected) {
            return Err(WitnessError::VerificationFailed(
                "mock proof bytes do not match checkpoint digest".to_string(),
            ));
        }
        Ok(())
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
        "HANDFEST v1\nFROM human \"alice\" (key: {root_key})\nTO agent \"bot\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\nLIMIT 10 calls\n"
    );
    let ast = parse_mandate(&raw).unwrap();
    let verified = vec![VerifiedMandate {
        ast,
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
    (verified, req, root_key, actor_key)
}

fn make_revocation(
    root_key: &KeyId,
    tag: &[u8],
    effective_at: i64,
    reason: &str,
) -> VerifiedRevocation {
    VerifiedRevocation {
        ast: RevocationAst::new(
            ActorDecl::new(
                ActorKind::Human,
                "alice".to_string(),
                root_key.clone(),
                BTreeMap::new(),
            )
            .unwrap(),
            RevocationTarget::Mandate(MandateId::sha256(tag)),
            effective_at,
            Some(reason.to_string()),
        )
        .unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: root_key.clone(),
            actor_kind: ActorKind::Human,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
        },
    }
}

#[test]
fn checkpoint_digest_is_canonical_domain_separated_and_sensitive_to_every_field() {
    let base = LedgerCheckpoint {
        receipt_seq: 1,
        receipt_hash: [0x11; 32],
        revocation_seq: 0,
        revocation_tip_hash: None,
        timestamp: NOW,
    };
    base.validate().unwrap();

    // Verify exact canonical framing: SHA-256("handfest-v1-checkpoint\0" || ...).
    let mut expected_preimage = Vec::new();
    expected_preimage.extend_from_slice(CHECKPOINT_DIGEST_DOMAIN_PREFIX);
    expected_preimage.extend_from_slice(&1u64.to_be_bytes());
    expected_preimage.extend_from_slice(&[0x11; 32]);
    expected_preimage.extend_from_slice(&0u64.to_be_bytes());
    expected_preimage.push(0u8);
    expected_preimage.extend_from_slice(&NOW.to_be_bytes());
    let expected = *MandateId::sha256(&expected_preimage).as_bytes();
    assert_eq!(base.checkpoint_digest(), expected);
    assert_eq!(base.checkpoint_digest_hex(), encode_lower_hex(&expected));

    let diff_receipt_seq = LedgerCheckpoint {
        receipt_seq: 2,
        ..base.clone()
    };
    let diff_receipt_hash = LedgerCheckpoint {
        receipt_hash: [0x12; 32],
        ..base.clone()
    };
    let diff_rev_some = LedgerCheckpoint {
        revocation_seq: 1,
        revocation_tip_hash: Some([0x22; 32]),
        ..base.clone()
    };
    let diff_ts = LedgerCheckpoint {
        timestamp: NOW + 1,
        ..base.clone()
    };
    assert_ne!(
        base.checkpoint_digest(),
        diff_receipt_seq.checkpoint_digest()
    );
    assert_ne!(
        base.checkpoint_digest(),
        diff_receipt_hash.checkpoint_digest()
    );
    assert_ne!(base.checkpoint_digest(), diff_rev_some.checkpoint_digest());
    assert_ne!(base.checkpoint_digest(), diff_ts.checkpoint_digest());

    // Invalid checkpoints fail closed.
    let bad_empty_receipt = LedgerCheckpoint {
        receipt_seq: 0,
        receipt_hash: [0x01; 32],
        ..base.clone()
    };
    assert!(matches!(
        bad_empty_receipt.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));
    let bad_rev_zero_with_tip = LedgerCheckpoint {
        revocation_seq: 0,
        revocation_tip_hash: Some([0x01; 32]),
        ..base.clone()
    };
    assert!(matches!(
        bad_rev_zero_with_tip.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));
    let bad_rev_nonzero_none = LedgerCheckpoint {
        revocation_seq: 1,
        revocation_tip_hash: None,
        ..base.clone()
    };
    assert!(matches!(
        bad_rev_nonzero_none.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));
    let bad_ts_low = LedgerCheckpoint {
        timestamp: MIN_RFC3339_TIMESTAMP - 1,
        ..base.clone()
    };
    let bad_ts_high = LedgerCheckpoint {
        timestamp: MAX_RFC3339_TIMESTAMP + 1,
        ..base
    };
    assert!(matches!(
        bad_ts_low.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));
    assert!(matches!(
        bad_ts_high.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));
}

#[test]
fn disabled_policy_performs_zero_witness_calls_and_creates_no_sidecar() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("disabled.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, actor_key) = fixture_chain_and_req();

    let witness = RecordingWitness::new("mock");
    let sql = SqliteLedger::open(&db_path).unwrap();
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        sql,
        witness.clone(),
        WitnessPolicy::default(),
        &sidecar,
    )
    .unwrap();
    assert_eq!(ledger.policy(), WitnessPolicy::Disabled);

    let (v1, _) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert_eq!(v1, Verdict::Permit);

    let deny_req = ActionRequest {
        action: "git.branch.delete".to_string(),
        ..req.clone()
    };
    let (v2, _) = ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    assert!(matches!(v2, Verdict::Deny { .. }));

    ledger
        .record_denial(Vec::new(), &deny_req, NOW + 2, "pre-gate deny".to_string())
        .unwrap();
    ledger
        .record_denial_with_revocations(
            &chain,
            &actor_key,
            &deny_req,
            &Default::default(),
            NOW + 3,
            "fallback".to_string(),
        )
        .unwrap();

    let rev = make_revocation(&root_key, b"m1", NOW + 4, "retired");
    ledger.record_revocation(&rev, "aabbccdd").unwrap();

    assert_eq!(witness.anchor_count(), 0);
    assert_eq!(witness.verified_count(), 0);
    assert!(
        !sidecar.exists(),
        "Disabled policy must never create sidecar"
    );
    assert_eq!(ledger.checkpoint_count().unwrap(), 0);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 0);
    assert_eq!(ledger.verify_integrity().unwrap(), 4);
    assert_eq!(ledger.track_record(&actor_key).unwrap().permits, 1);
    assert_eq!(ledger.load_revocations().unwrap().len(), 1);
    assert_eq!(ledger.list_stored_revocations().unwrap().len(), 1);
}

#[test]
fn sync_strict_anchors_permits_and_revocations_and_fails_closed_on_witness_errors() {
    let (chain, req, root_key, _actor_key) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");
    let sql = SqliteLedger::open_in_memory().unwrap();
    let mut ledger = AnchoredLedger::new(sql, witness.clone(), WitnessPolicy::SyncStrict).unwrap();

    // Pre-receipt revocation anchors with receipt_seq == 0 and EMPTY_RECEIPT_TIP_HASH.
    let rev0 = make_revocation(&root_key, b"rev0", NOW - 10, "before any receipt");
    ledger.record_revocation(&rev0, "deadbeef").unwrap();
    assert_eq!(witness.anchor_count(), 1);
    let cp0 = &witness.anchored_checkpoints()[0];
    assert_eq!(cp0.receipt_seq, 0);
    assert_eq!(cp0.receipt_hash, EMPTY_RECEIPT_TIP_HASH);
    assert_eq!(cp0.revocation_seq, 1);
    assert!(cp0.revocation_tip_hash.is_some());

    // Deny does NOT anchor.
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };
    let (v_deny, _) = ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert!(matches!(v_deny, Verdict::Deny { .. }));
    assert_eq!(witness.anchor_count(), 1);

    // Permit anchors.
    let (v_permit, r_permit) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    assert_eq!(v_permit, Verdict::Permit);
    assert_eq!(witness.anchor_count(), 2);
    let cp1 = &witness.anchored_checkpoints()[1];
    assert_eq!(cp1.receipt_seq, 2);
    assert_eq!(cp1.receipt_hash, *r_permit.receipt_hash.as_bytes());
    assert_eq!(cp1.revocation_seq, 1);

    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 2);
    assert_eq!(witness.verified_count(), 2);

    // Witness failure on Permit fails closed.
    witness.set_fail_anchor(Some(WitnessError::Backend("calendar down".to_string())));
    let err = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 2)
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerError::Witness(WitnessError::Backend(_))
    ));

    // Witness failure on record_revocation fails closed.
    let rev1 = make_revocation(&root_key, b"rev1", NOW + 3, "failed witness");
    let rev_err = ledger.record_revocation(&rev1, "00112233").unwrap_err();
    assert!(matches!(
        rev_err,
        LedgerError::Witness(WitnessError::Backend(_))
    ));
    witness.set_fail_anchor(None);

    // Witness returning mismatched kind fails closed without persisting.
    let bad_kind = WitnessProof {
        witness_kind: "wrong-kind".to_string(),
        checkpoint_digest_hex: "0".repeat(64),
        proof_bytes_b64: encode_standard(b"x"),
        anchored_at: NOW,
    };
    witness.set_override_proof(Some(bad_kind));
    let kind_err = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 4)
        .unwrap_err();
    assert!(matches!(
        kind_err,
        LedgerError::Witness(WitnessError::KindMismatch { .. })
    ));
    assert_eq!(ledger.checkpoint_count().unwrap(), 2);

    // Verify failure propagates cleanly.
    witness.set_override_proof(None);
    witness.set_fail_verify(Some(WitnessError::VerificationFailed("tampered".into())));
    assert!(matches!(
        ledger.verify_witness_checkpoints(),
        Err(LedgerError::Witness(WitnessError::VerificationFailed(_)))
    ));
}

#[test]
fn batch_every_policy_batches_permits_handles_revocations_and_persists_across_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("batch.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "nope.action".to_string(),
        ..req.clone()
    };

    let bad_sql = SqliteLedger::open_in_memory().unwrap();
    assert!(matches!(
        AnchoredLedger::new(
            bad_sql,
            RecordingWitness::new("mock"),
            WitnessPolicy::BatchEvery {
                every_n_receipts: 0,
                sync_revocations: true,
            }
        ),
        Err(LedgerError::Witness(WitnessError::InvalidConfig(_)))
    ));

    assert!(matches!(
        AnchoredLedger::new(
            SqliteLedger::open_in_memory().unwrap(),
            RecordingWitness::new("BAD KIND"),
            WitnessPolicy::SyncStrict,
        ),
        Err(LedgerError::Witness(WitnessError::InvalidConfig(_)))
    ));
    assert!(matches!(
        AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open_in_memory().unwrap(),
            RecordingWitness::new("mock"),
            WitnessPolicy::SyncStrict,
            "",
        ),
        Err(LedgerError::Storage(_))
    ));

    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: false,
        },
        &sidecar,
    )
    .unwrap();

    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert_eq!(witness.anchor_count(), 0);

    let rev1 = make_revocation(&root_key, b"b1", NOW + 1, "batch deferred");
    ledger.record_revocation(&rev1, "aabb").unwrap();
    assert_eq!(witness.anchor_count(), 0);

    ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW + 2)
        .unwrap();
    assert_eq!(witness.anchor_count(), 0);

    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 3)
        .unwrap();
    assert_eq!(witness.anchor_count(), 1);
    assert_eq!(witness.anchored_checkpoints()[0].receipt_seq, 3);
    assert_eq!(witness.anchored_checkpoints()[0].revocation_seq, 1);

    drop(ledger);
    let witness2 = RecordingWitness::new("mock");
    let mut reopened = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness2.clone(),
        WitnessPolicy::BatchEvery {
            every_n_receipts: 2,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();

    reopened
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 4)
        .unwrap();
    assert_eq!(witness2.anchor_count(), 0);

    let rev2 = make_revocation(&root_key, b"b2", NOW + 5, "sync rev");
    reopened.record_revocation(&rev2, "ccdd").unwrap();
    assert_eq!(witness2.anchor_count(), 1);
    assert_eq!(witness2.anchored_checkpoints()[0].receipt_seq, 4);
    assert_eq!(witness2.anchored_checkpoints()[0].revocation_seq, 2);

    assert_eq!(reopened.verify_witness_checkpoints().unwrap(), 2);
}

#[test]
fn detects_sqlite_truncation_rewrite_and_revocation_rollback() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("rollback.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    let (_, r1) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    let (_, r2) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    let rev = make_revocation(&root_key, b"r-rollback", NOW + 2, "revoked");
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 3);
    let backup_db = fs::read(&db_path).unwrap();
    let mid_str = chain[0].ast.mandate_id().to_string();
    drop(ledger);

    // Attack 1: Host-level DB truncation where plain SqliteLedger::verify_integrity() PASSES!
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM receipts WHERE seq = 2", [])
            .unwrap();
        conn.execute(
            "UPDATE sqlite_sequence SET seq = 1 WHERE name = 'receipts'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE quota_calls SET calls = 1 WHERE mandate_id = ?1",
            [&mid_str],
        )
        .unwrap();
    }
    let truncated_sql = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(truncated_sql.verify_integrity().unwrap(), 1);
    let mut reg = WitnessRegistry::new();
    reg.register(witness.clone()).unwrap();
    let trunc_err =
        verify_ledger_witness_checkpoints(&truncated_sql, &sidecar, &reg, true, true, None)
            .unwrap_err();
    assert!(
        matches!(trunc_err, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "expected rollback/truncation error, got: {trunc_err}"
    );
    drop(truncated_sql);

    // Attack 2: Rewrite receipt #2 with forged valid hash (local verify_integrity passes!).
    fs::write(&db_path, &backup_db).unwrap();
    {
        let forged_req = ActionRequest {
            resource_id: "org/forged".to_string(),
            ..req.clone()
        };
        let (_, forged_r2) = handfest_core::gate::authorize(
            &chain,
            &forged_req,
            &VerifiedFacts::new(),
            &handfest_core::gate::QuotaSnapshot::new(),
            NOW + 99,
            Some(r1.receipt_hash),
        );
        assert_ne!(forged_r2.receipt_hash, r2.receipt_hash);
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE receipts SET receipt_hash = ?1, resource_id = ?2, timestamp = ?3 WHERE seq = 2",
            rusqlite::params![
                forged_r2.receipt_hash.to_string(),
                forged_req.resource_id,
                forged_r2.timestamp,
            ],
        )
        .unwrap();
    }
    let rewritten_sql = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(rewritten_sql.verify_integrity().unwrap(), 2);
    let rewrite_err =
        verify_ledger_witness_checkpoints(&rewritten_sql, &sidecar, &reg, true, true, None)
            .unwrap_err();
    assert!(
        matches!(rewrite_err, LedgerError::Integrity(ref msg) if msg.contains("receipt hash mismatch")),
        "expected receipt hash mismatch, got: {rewrite_err}"
    );
    drop(rewritten_sql);

    assert_revocation_rollback_detected(&db_path, &sidecar, &backup_db, &reg);
}

fn assert_revocation_rollback_detected(
    db_path: &std::path::Path,
    sidecar: &std::path::Path,
    backup_db: &[u8],
    reg: &WitnessRegistry,
) {
    fs::write(db_path, backup_db).unwrap();
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute("DELETE FROM revocations", []).unwrap();
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'revocations'", [])
        .unwrap();
    drop(conn);
    let rev_trunc_sql = SqliteLedger::open_read_only(db_path).unwrap();
    assert_eq!(rev_trunc_sql.verify_integrity().unwrap(), 2);
    let rev_err = verify_ledger_witness_checkpoints(&rev_trunc_sql, sidecar, reg, true, true, None)
        .unwrap_err();
    assert!(
        matches!(rev_err, LedgerError::Integrity(ref msg) if msg.contains("revocation rollback or truncation")),
        "expected revocation rollback error, got: {rev_err}"
    );
}

#[test]
fn detects_sidecar_tampering_and_missing_sidecar() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("sidecar_tamper.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
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
    let backup_sidecar = fs::read(&sidecar).unwrap();
    drop(ledger);
    let mut reg = WitnessRegistry::new();
    reg.register(witness).unwrap();
    let intact = SqliteLedger::open_read_only(&db_path).unwrap();
    let raw_str = String::from_utf8(backup_sidecar).unwrap();
    let lines: Vec<&str> = raw_str.lines().collect();

    fs::write(&sidecar, b"").unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Integrity(_))
    ));

    fs::write(&sidecar, raw_str.trim_end_matches('\n')).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Integrity(_))
    ));

    fs::write(&sidecar, format!("\n{raw_str}")).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Integrity(_))
    ));

    fs::write(&sidecar, [0xff, 0xfe, b'\n']).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Integrity(_))
    ));

    fs::write(&sidecar, format!("{}\n", lines[1])).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Integrity(_))
    ));

    let mut rec1: StoredCheckpoint = serde_json::from_str(lines[0]).unwrap();
    rec1.proof.proof_bytes_b64 = encode_standard(b"forged-witness-proof");
    rec1.record_hash = StoredCheckpoint::compute_record_hash(
        rec1.seq,
        rec1.prev_record_hash.as_deref(),
        &rec1.checkpoint,
        &rec1.proof,
    );
    fs::write(
        &sidecar,
        format!("{}\n", serde_json::to_string(&rec1).unwrap()),
    )
    .unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::Witness(WitnessError::VerificationFailed(_)))
    ));

    fs::remove_file(&sidecar).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&intact, &sidecar, &reg, true, true, None),
        Err(LedgerError::NotFound(_))
    ));
}

#[test]
fn zero_private_receipt_or_revocation_fields_leak_to_witness_or_sidecar() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("privacy.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);

    let root_key =
        KeyId::parse("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    let actor_key =
        KeyId::parse("ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"secret-principal-canary\" (key: {root_key})\nTO agent \"secret-agent-canary\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW secret_action_canary\nON secret_kind_canary \"*\"\n"
    );
    let ast = parse_mandate(&raw).unwrap();
    let verified = vec![VerifiedMandate {
        ast,
        proof: VerifiedAnchorProof {
            anchor_id: "secret-anchor-canary".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: root_key.clone(),
            actor_kind: ActorKind::Human,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
        },
    }];
    let permit_req = ActionRequest {
        actor_key: actor_key.clone(),
        action: "secret_action_canary".to_string(),
        resource_kind: "secret_kind_canary".to_string(),
        resource_id: "secret-resource-id-canary-98765".to_string(),
    };
    let deny_req = ActionRequest {
        actor_key: actor_key.clone(),
        action: "secret_denied_action_canary".to_string(),
        resource_kind: "secret_kind_canary".to_string(),
        resource_id: "secret-denied-resource-canary".to_string(),
    };
    let rev = make_revocation(
        &root_key,
        b"rev-privacy",
        NOW + 10,
        "secret-revocation-reason-canary",
    );

    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    ledger
        .evaluate_and_record(&verified, &permit_req, &VerifiedFacts::new(), NOW)
        .unwrap();
    ledger
        .record_denial(
            Vec::new(),
            &deny_req,
            NOW + 1,
            "secret-deny-reason-canary".to_string(),
        )
        .unwrap();
    ledger
        .record_revocation(&rev, "cafebabedeadbeef0123456789abcdef")
        .unwrap();

    let sidecar_text = fs::read_to_string(&sidecar).unwrap();
    let witness_debug = format!("{:?}", witness.anchored_checkpoints());
    let private_canaries = [
        root_key.to_string(),
        actor_key.to_string(),
        "secret-principal-canary".to_string(),
        "secret-agent-canary".to_string(),
        "secret_action_canary".to_string(),
        "secret_denied_action_canary".to_string(),
        "secret_kind_canary".to_string(),
        "secret-resource-id-canary-98765".to_string(),
        "secret-denied-resource-canary".to_string(),
        "secret-deny-reason-canary".to_string(),
        "secret-revocation-reason-canary".to_string(),
        "secret-anchor-canary".to_string(),
        "cafebabedeadbeef0123456789abcdef".to_string(),
    ];
    for canary in &private_canaries {
        assert!(
            !sidecar_text.contains(canary),
            "sidecar leaked private field '{canary}'"
        );
        assert!(
            !witness_debug.contains(canary),
            "LedgerCheckpoint leaked private field '{canary}'"
        );
    }
}

#[test]
fn witness_kind_and_proof_validation_rejects_malformed_inputs() {
    let cp = LedgerCheckpoint {
        receipt_seq: 1,
        receipt_hash: [0x11; 32],
        revocation_seq: 0,
        revocation_tip_hash: None,
        timestamp: NOW,
    };
    assert!(validate_witness_kind("ots").is_ok());
    assert!(validate_witness_kind("http-log").is_ok());
    assert!(validate_witness_kind("").is_err());
    assert!(validate_witness_kind("UPPER").is_err());
    assert!(validate_witness_kind("-bad").is_err());

    let bad_b64 = WitnessProof {
        witness_kind: "mock".to_string(),
        checkpoint_digest_hex: cp.checkpoint_digest_hex(),
        proof_bytes_b64: "not-base64!".to_string(),
        anchored_at: NOW,
    };
    assert!(matches!(
        validate_witness_proof(&cp, &bad_b64, "mock"),
        Err(WitnessError::InvalidProof(_))
    ));
    let empty_b64 = WitnessProof {
        proof_bytes_b64: String::new(),
        ..bad_b64.clone()
    };
    assert!(matches!(
        validate_witness_proof(&cp, &empty_b64, "mock"),
        Err(WitnessError::InvalidProof(_))
    ));
    let bad_hex = WitnessProof {
        checkpoint_digest_hex: "not-hex".to_string(),
        proof_bytes_b64: encode_standard(b"ok"),
        ..bad_b64.clone()
    };
    assert!(matches!(
        validate_witness_proof(&cp, &bad_hex, "mock"),
        Err(WitnessError::InvalidProof(_))
    ));
    let bad_ts = WitnessProof {
        proof_bytes_b64: encode_standard(b"ok"),
        anchored_at: MAX_RFC3339_TIMESTAMP + 1,
        ..bad_b64
    };
    assert!(matches!(
        validate_witness_proof(&cp, &bad_ts, "mock"),
        Err(WitnessError::InvalidProof(_))
    ));
}

#[test]
fn disabled_policy_does_not_invoke_witness_kind_and_empty_ledger_verifies_zero() {
    struct PanicKindWitness;
    impl CheckpointWitness for PanicKindWitness {
        fn witness_kind(&self) -> &str {
            panic!("WitnessPolicy::Disabled must not call witness_kind()")
        }
        fn anchor(&self, _: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
            panic!("WitnessPolicy::Disabled must not call anchor()")
        }
        fn verify(&self, _: &LedgerCheckpoint, _: &WitnessProof) -> Result<(), WitnessError> {
            panic!("WitnessPolicy::Disabled must not call verify()")
        }
    }

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("empty_disabled.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let ledger_mem = AnchoredLedger::new(
        SqliteLedger::open_in_memory().unwrap(),
        PanicKindWitness,
        WitnessPolicy::Disabled,
    )
    .unwrap();
    assert_eq!(ledger_mem.verify_witness_checkpoints().unwrap(), 0);

    let ledger_file = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        PanicKindWitness,
        WitnessPolicy::Disabled,
        &sidecar,
    )
    .unwrap();
    assert_eq!(ledger_file.verify_witness_checkpoints().unwrap(), 0);
}

#[test]
fn sync_strict_and_batch_roll_back_sqlite_receipt_quota_and_revocation_on_witness_failure() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("rollback.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);

    let root_key =
        KeyId::parse("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    let actor_key =
        KeyId::parse("ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
    let raw = format!(
        "HANDFEST v1\nFROM human \"alice\" (key: {root_key})\nTO agent \"bot\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\nLIMIT 1 calls\n"
    );
    let ast = parse_mandate(&raw).unwrap();
    let chain = vec![VerifiedMandate {
        ast,
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

    let witness = RecordingWitness::new("mock");
    witness.set_fail_anchor(Some(WitnessError::Backend("calendar offline".to_string())));

    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    // 1. Failed SyncStrict anchor rolls back Permit receipt AND quota burn.
    let err = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap_err();
    assert!(matches!(
        err,
        LedgerError::Witness(WitnessError::Backend(_))
    ));
    assert_eq!(ledger.verify_integrity().unwrap(), 0);
    assert_eq!(ledger.track_record(&actor_key).unwrap().permits, 0);
    assert!(!sidecar.exists());

    // 2. Failed SyncStrict anchor on record_revocation rolls back revocation row.
    let rev = make_revocation(&root_key, b"rollback-rev", NOW + 5, "should roll back");
    let rev_err = ledger.record_revocation(&rev, "deadbeef").unwrap_err();
    assert!(matches!(
        rev_err,
        LedgerError::Witness(WitnessError::Backend(_))
    ));
    assert!(ledger.load_revocations().unwrap().is_empty());
    assert!(!sidecar.exists());

    // 3. Once witness recovers, retrying the LIMIT 1 calls Permit succeeds with full quota.
    witness.set_fail_anchor(None);
    let (verdict, _) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 10)
        .unwrap();
    assert_eq!(verdict, Verdict::Permit);
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 1);

    // 4. Subsequent call hits LIMIT 1 calls (Deny, no extra checkpoint).
    let (v2, _) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 11)
        .unwrap();
    assert!(matches!(v2, Verdict::Deny { .. }));
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);

    // 5. Deleting sidecar causes AnchoredLedger::verify_witness_checkpoints to fail closed.
    fs::remove_file(&sidecar).unwrap();
    assert!(matches!(
        ledger.verify_witness_checkpoints(),
        Err(LedgerError::Integrity(_))
    ));

    // 6. BatchEvery boundary failure also rolls back receipt + quota cleanly.
    let batch_db = dir.path().join("batch_rollback.sqlite");
    let batch_sc = default_checkpoint_sidecar_path(&batch_db);
    let batch_w = RecordingWitness::new("mock");
    batch_w.set_fail_anchor(Some(WitnessError::Backend(
        "batch witness down".to_string(),
    )));
    let mut batch = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&batch_db).unwrap(),
        batch_w.clone(),
        WitnessPolicy::BatchEvery {
            every_n_receipts: 1,
            sync_revocations: true,
        },
        &batch_sc,
    )
    .unwrap();
    assert!(matches!(
        batch.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 20),
        Err(LedgerError::Witness(WitnessError::Backend(_)))
    ));
    assert_eq!(batch.verify_integrity().unwrap(), 0);
    batch_w.set_fail_anchor(None);
    let (v3, _) = batch
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 21)
        .unwrap();
    assert_eq!(v3, Verdict::Permit);
    assert_eq!(batch.verify_witness_checkpoints().unwrap(), 1);
}

#[test]
fn idempotent_revocation_replay_performs_zero_redundant_witness_calls() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("idempotent_rev.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (_chain, _req, root_key, _) = fixture_chain_and_req();

    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    let rev = make_revocation(&root_key, b"idem-rev", NOW, "idempotent");
    let id1 = ledger.record_revocation(&rev, "aabbccdd").unwrap();
    assert_eq!(witness.anchor_count(), 1);
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);

    let id2 = ledger.record_revocation(&rev, "aabbccdd").unwrap();
    assert_eq!(id1, id2);
    assert_eq!(witness.anchor_count(), 1);
    assert_eq!(ledger.checkpoint_count().unwrap(), 1);
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 1);
}

#[cfg(unix)]
#[test]
fn symlinked_ledger_resolves_canonical_sidecar_and_rejects_symlink_or_fifo_sidecars() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;

    let dir = TempDir::new().unwrap();
    let real_db = dir.path().join("real.sqlite");
    let link_db = dir.path().join("link.sqlite");
    let _ = SqliteLedger::open(&real_db).unwrap();
    symlink(&real_db, &link_db).unwrap();

    let real_sidecar = canonical_checkpoint_sidecar_path(&real_db).unwrap();
    let link_sidecar = canonical_checkpoint_sidecar_path(&link_db).unwrap();
    assert_eq!(real_sidecar, link_sidecar);

    let (chain, req, _, _) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&link_db).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &link_sidecar,
    )
    .unwrap();
    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();

    let mode = fs::metadata(&real_sidecar).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "sidecar must be created with 0o600 mode");

    let mut reg = WitnessRegistry::new();
    reg.register(witness.clone()).unwrap();
    let ro = SqliteLedger::open_read_only(&link_db).unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(&ro, &link_sidecar, &reg, true, true, None).unwrap(),
        1
    );
    drop(ledger);
    drop(ro);

    // 1. Symlink sidecar is rejected on both read and append (rolling back SQLite write).
    let target_file = dir.path().join("decoy.jsonl");
    fs::write(&target_file, fs::read(&real_sidecar).unwrap()).unwrap();
    fs::remove_file(&real_sidecar).unwrap();
    symlink(&target_file, &real_sidecar).unwrap();

    let ro = SqliteLedger::open_read_only(&real_db).unwrap();
    let sym_read_err =
        verify_ledger_witness_checkpoints(&ro, &real_sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(sym_read_err, LedgerError::Integrity(ref msg) if msg.contains("must not be a symlink")),
        "expected symlink rejection on read, got: {sym_read_err}"
    );
    drop(ro);

    let mut sym_writer = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&real_db).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &real_sidecar,
    )
    .unwrap();
    let sym_write_err = sym_writer
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap_err();
    assert!(
        matches!(sym_write_err, LedgerError::Integrity(ref msg) if msg.contains("must not be a symlink")),
        "expected symlink rejection on append, got: {sym_write_err}"
    );
    assert_eq!(sym_writer.verify_integrity().unwrap(), 1);
    drop(sym_writer);

    // 2. FIFO sidecar is rejected immediately via fstat is_file() without blocking on read/append.
    fs::remove_file(&real_sidecar).unwrap();
    let status = Command::new("mkfifo").arg(&real_sidecar).status().unwrap();
    assert!(status.success(), "mkfifo failed");

    let ro = SqliteLedger::open_read_only(&real_db).unwrap();
    let fifo_read_err =
        verify_ledger_witness_checkpoints(&ro, &real_sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(fifo_read_err, LedgerError::Integrity(ref msg) if msg.contains("must be a regular file")),
        "expected non-regular file rejection on FIFO read, got: {fifo_read_err}"
    );
    drop(ro);

    // Open a non-blocking reader on the FIFO so O_WRONLY|O_NONBLOCK open succeeds and fstat is_file()
    // is the exact guard rejecting the append before any byte is written!
    let _fifo_reader = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&real_sidecar)
        .unwrap();
    let mut fifo_writer = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&real_db).unwrap(),
        witness,
        WitnessPolicy::SyncStrict,
        &real_sidecar,
    )
    .unwrap();
    let fifo_write_err = fifo_writer
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 2)
        .unwrap_err();
    assert!(
        matches!(fifo_write_err, LedgerError::Integrity(ref msg) if msg.contains("must be a regular file")),
        "expected non-regular file rejection on FIFO append, got: {fifo_write_err}"
    );
    assert_eq!(fifo_writer.verify_integrity().unwrap(), 1);
}

#[derive(Clone)]
struct SyncMockWitness;
impl CheckpointWitness for SyncMockWitness {
    fn witness_kind(&self) -> &str {
        "sync-mock"
    }
    fn anchor(&self, cp: &LedgerCheckpoint) -> Result<WitnessProof, WitnessError> {
        Ok(WitnessProof {
            witness_kind: "sync-mock".to_string(),
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

#[test]
fn concurrent_writers_preserve_contiguous_checkpoint_chain_and_consistent_reader_audit() {
    use std::sync::{Arc, Barrier};

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.sqlite");
    let _ = SqliteLedger::open(&db_path).unwrap();
    let sidecar = canonical_checkpoint_sidecar_path(&db_path).unwrap();

    let (chain, req, _, actor_key) = fixture_chain_and_req();
    let mut seed = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        SyncMockWitness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();
    seed.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    drop(seed);

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for tid in 0..3u64 {
        let db = db_path.clone();
        let sc = sidecar.clone();
        let bar = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let (c, r, _, _) = fixture_chain_and_req();
            let mut writer = AnchoredLedger::with_checkpoint_file(
                SqliteLedger::open(&db).unwrap(),
                SyncMockWitness,
                WitnessPolicy::SyncStrict,
                &sc,
            )
            .unwrap();
            bar.wait();
            for step in 0..3u64 {
                let ts = NOW + 10 + i64::try_from(tid * 10 + step).unwrap();
                let (v, _) = writer
                    .evaluate_and_record(&c, &r, &VerifiedFacts::new(), ts)
                    .unwrap();
                assert_eq!(v, Verdict::Permit);
            }
        }));
    }

    let reader_db = db_path.clone();
    let reader_sc = sidecar.clone();
    let reader_actor = actor_key.clone();
    let bar = Arc::clone(&barrier);
    let reader = std::thread::spawn(move || {
        let mut reg = WitnessRegistry::new();
        reg.register(SyncMockWitness).unwrap();
        bar.wait();
        for _ in 0..12 {
            let ro = SqliteLedger::open_read_only(&reader_db).unwrap();
            let (snap, cps) = verify_audit_snapshot_with_witness(
                &ro,
                Some(&reader_actor),
                &reader_sc,
                &reg,
                true,
                None,
            )
            .expect("concurrent reader must never see false rollback or torn snapshot");
            assert_eq!(
                snap.verified_receipts, cps,
                "SHARED-lock SyncStrict must match"
            );
            let tr = snap.track_record.unwrap();
            assert_eq!(tr.permits, u64::try_from(snap.verified_receipts).unwrap());
        }
    });

    for h in handles {
        h.join().unwrap();
    }
    reader.join().unwrap();

    let mut reg = WitnessRegistry::new();
    reg.register(SyncMockWitness).unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let (snap, cps) =
        verify_audit_snapshot_with_witness(&ro, Some(&actor_key), &sidecar, &reg, true, None)
            .unwrap();
    assert_eq!((snap.verified_receipts, cps), (10, 10));
}

#[test]
fn tampered_prev_record_hash_record_hash_non_monotonic_and_zero_receipt_hash_fail_closed() {
    let zero_hash_cp = LedgerCheckpoint {
        receipt_seq: 1,
        receipt_hash: EMPTY_RECEIPT_TIP_HASH,
        revocation_seq: 0,
        revocation_tip_hash: None,
        timestamp: NOW,
    };
    assert!(matches!(
        zero_hash_cp.validate(),
        Err(WitnessError::InvalidCheckpoint(_))
    ));

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("chain_tamper.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
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
    let rev = make_revocation(&root_key, b"mono-rev", NOW + 2, "revocation");
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    drop(ledger);

    let orig = fs::read_to_string(&sidecar).unwrap();
    let lines: Vec<&str> = orig.lines().collect();
    assert_eq!(lines.len(), 3);
    let rec1: StoredCheckpoint = serde_json::from_str(lines[0]).unwrap();
    let rec2: StoredCheckpoint = serde_json::from_str(lines[1]).unwrap();
    let rec3: StoredCheckpoint = serde_json::from_str(lines[2]).unwrap();

    let mut reg = WitnessRegistry::new();
    reg.register(witness).unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();

    // 1. Tampered prev_record_hash fails closed.
    let mut bad_prev = rec2.clone();
    bad_prev.prev_record_hash = Some(format!("sha256:{}", "f".repeat(64)));
    bad_prev.record_hash = StoredCheckpoint::compute_record_hash(
        bad_prev.seq,
        bad_prev.prev_record_hash.as_deref(),
        &bad_prev.checkpoint,
        &bad_prev.proof,
    );
    fs::write(
        &sidecar,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&rec1).unwrap(),
            serde_json::to_string(&bad_prev).unwrap()
        ),
    )
    .unwrap();
    let err = verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("broken prev_record_hash")),
        "expected broken prev_record_hash, got: {err}"
    );

    // 2. Tampered record_hash fails closed.
    let mut bad_hash = rec2.clone();
    bad_hash.record_hash = format!("sha256:{}", "e".repeat(64));
    fs::write(
        &sidecar,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&rec1).unwrap(),
            serde_json::to_string(&bad_hash).unwrap()
        ),
    )
    .unwrap();
    let err = verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("record_hash mismatch")),
        "expected record_hash mismatch, got: {err}"
    );

    // 3. Non-monotonic receipt_seq and revocation_seq fail closed.
    write_rechained_pair(&sidecar, rec2.clone(), rec1);
    let err = verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("non-monotonic receipt_seq")),
        "expected non-monotonic receipt_seq, got: {err}"
    );

    write_rechained_pair(&sidecar, rec3, rec2);
    let err = verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(err, LedgerError::Integrity(ref msg) if msg.contains("non-monotonic revocation_seq")),
        "expected non-monotonic revocation_seq, got: {err}"
    );
}

fn write_rechained_pair(
    sidecar: &std::path::Path,
    mut first: StoredCheckpoint,
    mut second: StoredCheckpoint,
) {
    first.seq = 1;
    first.prev_record_hash = None;
    first.record_hash =
        StoredCheckpoint::compute_record_hash(1, None, &first.checkpoint, &first.proof);
    second.seq = 2;
    second.prev_record_hash = Some(first.record_hash.clone());
    second.record_hash = StoredCheckpoint::compute_record_hash(
        2,
        second.prev_record_hash.as_deref(),
        &second.checkpoint,
        &second.proof,
    );
    fs::write(
        sidecar,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        ),
    )
    .unwrap();
}

#[test]
fn batch_every_rejects_db_rollback_or_truncation_on_every_write_without_writing_row() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("batch_rollback_guard.sqlite");
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

    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
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
    assert_eq!(witness.anchor_count(), 1);
    assert_eq!(witness.anchored_checkpoints()[0].receipt_seq, 10);
    let backup_10 = fs::read(&db_path).unwrap();
    drop(ledger);

    // Attack A: Truncate SQLite back to 7 receipts (repaired sqlite_sequence + quota_calls = 7).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM receipts WHERE seq > 7", [])
            .unwrap();
        conn.execute(
            "UPDATE sqlite_sequence SET seq = 7 WHERE name = 'receipts'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE quota_calls SET calls = 7 WHERE mandate_id = ?1",
            [&mid_str],
        )
        .unwrap();
    }
    let mut reopened_7 = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::BatchEvery {
            every_n_receipts: 10,
            sync_revocations: true,
        },
        &sidecar,
    )
    .unwrap();
    let err7 = reopened_7
        .evaluate_and_record(&limit10_chain, &req, &VerifiedFacts::new(), NOW + 20)
        .unwrap_err();
    assert!(
        matches!(err7, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "expected BatchEvery rollback error on 7-receipt DB, got: {err7}"
    );
    assert_eq!(
        reopened_7.verify_integrity().unwrap(),
        7,
        "failed BatchEvery write must not insert any receipt row"
    );
    drop(reopened_7);

    // Attack B: Replace SQLite with a completely empty DB (0 receipts).
    let fresh_path = dir.path().join("fresh_empty.sqlite");
    let _ = SqliteLedger::open(&fresh_path).unwrap();
    fs::copy(&fresh_path, &db_path).unwrap();
    let mut reopened_0 = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::BatchEvery {
            every_n_receipts: 10,
            sync_revocations: false,
        },
        &sidecar,
    )
    .unwrap();
    let err0 = reopened_0
        .evaluate_and_record(&limit10_chain, &req, &VerifiedFacts::new(), NOW + 30)
        .unwrap_err();
    assert!(
        matches!(err0, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "expected BatchEvery rollback error on empty DB, got: {err0}"
    );
    assert_eq!(
        reopened_0.verify_integrity().unwrap(),
        0,
        "failed BatchEvery write on empty DB must leave 0 rows"
    );
    // Even record_revocation with sync_revocations: false must fail closed on rolled-back DB!
    let rev = make_revocation(&root_key, b"batch-no-sync-rev", NOW + 31, "rollback");
    let rev_err = reopened_0.record_revocation(&rev, "deadbeef").unwrap_err();
    assert!(
        matches!(rev_err, LedgerError::Integrity(ref msg) if msg.contains("rollback or truncation")),
        "expected BatchEvery record_revocation rollback error, got: {rev_err}"
    );
    assert!(reopened_0.list_stored_revocations().unwrap().is_empty());

    drop(reopened_0);
    fs::write(&db_path, backup_10).unwrap();
    let restored = SqliteLedger::open_read_only(&db_path).unwrap();
    let mut reg = WitnessRegistry::new();
    reg.register(witness).unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(&restored, &sidecar, &reg, true, true, None).unwrap(),
        1
    );
}

#[test]
fn deny_only_ledger_accepts_absent_or_empty_sidecar_unless_pinned() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("deny_and_tail.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };
    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    // 1. Deny-only ledger (0 Permits, 0 Revocations): absent or empty sidecar is valid (Ok(0)).
    let (v_deny, _) = ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW)
        .unwrap();
    assert!(matches!(v_deny, Verdict::Deny { .. }));
    assert!(!sidecar.exists());
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 0);

    let mut reg = WitnessRegistry::new();
    reg.register(witness.clone()).unwrap();
    let ro_deny = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(&ro_deny, &sidecar, &reg, true, true, None).unwrap(),
        0
    );
    let (snap_deny, cps_deny) =
        verify_audit_snapshot_with_witness(&ro_deny, None, &sidecar, &reg, true, None).unwrap();
    assert_eq!(snap_deny.verified_receipts, 1);
    assert_eq!(cps_deny, 0);

    // 0-byte empty sidecar on Deny-only ledger also returns Ok(0) when unpinned,
    // but fails closed if expected_checkpoint_head is pinned.
    fs::write(&sidecar, b"").unwrap();
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 0);
    assert_eq!(
        verify_ledger_witness_checkpoints(&ro_deny, &sidecar, &reg, true, true, None).unwrap(),
        0
    );
    let dummy_head = MandateId::sha256(b"pinned");
    assert!(matches!(
        verify_ledger_witness_checkpoints(&ro_deny, &sidecar, &reg, true, true, Some(&dummy_head)),
        Err(LedgerError::Integrity(_))
    ));
    fs::remove_file(&sidecar).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&ro_deny, &sidecar, &reg, true, true, Some(&dummy_head)),
        Err(LedgerError::NotFound(_))
    ));
    drop(ro_deny);
}

#[test]
fn sync_strict_tail_truncation_and_expected_checkpoint_head() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("tail_and_head.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, root_key, _) = fixture_chain_and_req();
    let deny_req = ActionRequest {
        action: "forbidden.action".to_string(),
        ..req.clone()
    };
    let witness = RecordingWitness::new("mock");
    let mut reg = WitnessRegistry::new();
    reg.register(witness.clone()).unwrap();
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness,
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    // 1. SyncStrict tail-truncation detection (Permit + Permit, then truncate sidecar to line 1).
    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 1)
        .unwrap();
    let snap1_db = fs::read(&db_path).unwrap();
    let snap1_sc = fs::read(&sidecar).unwrap();

    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW + 2)
        .unwrap();
    // Trailing Deny after Permit #2 does not require a new checkpoint.
    ledger
        .evaluate_and_record(&chain, &deny_req, &VerifiedFacts::new(), NOW + 3)
        .unwrap();
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 2);

    let full_2 = fs::read_to_string(&sidecar).unwrap();
    let lines_2: Vec<&str> = full_2.lines().collect();
    assert_eq!(lines_2.len(), 2);
    let head2: StoredCheckpoint = serde_json::from_str(lines_2[1]).unwrap();

    // Truncate sidecar back to line 1 -> SyncStrict verify_witness_checkpoints,
    // verify_ledger_witness_checkpoints(strict=true), and verify_audit_snapshot_with_witness(strict=true)
    // ALL detect permit tail-truncation!
    fs::write(&sidecar, format!("{}\n", lines_2[0])).unwrap();
    let tail_err = ledger.verify_witness_checkpoints().unwrap_err();
    assert!(
        matches!(tail_err, LedgerError::Integrity(ref msg) if msg.contains("tail-truncation")),
        "expected SyncStrict permit tail-truncation error, got: {tail_err}"
    );
    {
        let ro_p = SqliteLedger::open_read_only(&db_path).unwrap();
        assert!(matches!(
            verify_ledger_witness_checkpoints(&ro_p, &sidecar, &reg, true, true, None),
            Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
        ));
        assert!(matches!(
            verify_audit_snapshot_with_witness(&ro_p, None, &sidecar, &reg, true, None),
            Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
        ));
    }
    fs::write(&sidecar, &full_2).unwrap();

    // Also test revocation tail-truncation under SyncStrict and strict offline audit.
    let rev = make_revocation(&root_key, b"tail-rev", NOW + 4, "tail test");
    ledger.record_revocation(&rev, "deadbeef").unwrap();
    assert_eq!(ledger.verify_witness_checkpoints().unwrap(), 3);
    let full_3 = fs::read_to_string(&sidecar).unwrap();
    fs::write(&sidecar, &full_2).unwrap();
    let rev_tail_err = ledger.verify_witness_checkpoints().unwrap_err();
    assert!(
        matches!(rev_tail_err, LedgerError::Integrity(ref msg) if msg.contains("tail-truncation")),
        "expected SyncStrict revocation tail-truncation error, got: {rev_tail_err}"
    );
    drop(ledger);

    assert_offline_strict_tail_and_pinned_head(
        &db_path,
        &sidecar,
        &reg,
        &head2,
        &full_3,
        (&snap1_db, &snap1_sc),
    );
}

fn assert_offline_strict_tail_and_pinned_head(
    db_path: &std::path::Path,
    sidecar: &std::path::Path,
    reg: &WitnessRegistry,
    head2: &StoredCheckpoint,
    full_3: &str,
    snap1: (&[u8], &[u8]),
) {
    let head3: StoredCheckpoint = serde_json::from_str(full_3.lines().last().unwrap()).unwrap();
    // Offline strict audit catches revocation tail-truncation; non-strict (BatchEvery) accepts full_2.
    let ro_full = SqliteLedger::open_read_only(db_path).unwrap();
    assert!(matches!(
        verify_ledger_witness_checkpoints(&ro_full, sidecar, reg, true, true, None),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
    ));
    assert!(matches!(
        verify_audit_snapshot_with_witness(&ro_full, None, sidecar, reg, true, None),
        Err(LedgerError::Integrity(ref msg)) if msg.contains("tail-truncation")
    ));
    let head2_record_id = MandateId::parse(&head2.record_hash).unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(
            &ro_full,
            sidecar,
            reg,
            true,
            false,
            Some(&head2_record_id)
        )
        .unwrap(),
        2
    );

    // 3. Restore full_3: operator-pinned expected_checkpoint_head accepts record_hash AND
    //    checkpoint_digest under strict tail, and defeats simultaneous DB + sidecar rollback!
    fs::write(sidecar, full_3).unwrap();
    let head3_record_id = MandateId::parse(&head3.record_hash).unwrap();
    let head3_digest_id = MandateId::parse(&format!(
        "sha256:{}",
        head3.checkpoint.checkpoint_digest_hex()
    ))
    .unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(
            &ro_full,
            sidecar,
            reg,
            true,
            true,
            Some(&head3_record_id)
        )
        .unwrap(),
        3
    );
    assert_eq!(
        verify_ledger_witness_checkpoints(
            &ro_full,
            sidecar,
            reg,
            true,
            true,
            Some(&head3_digest_id)
        )
        .unwrap(),
        3
    );
    drop(ro_full);

    // Jointly roll back BOTH SQLite DB and sidecar back to checkpoint #1!
    fs::write(db_path, snap1.0).unwrap();
    fs::write(sidecar, snap1.1).unwrap();
    let ro_rolled = SqliteLedger::open_read_only(db_path).unwrap();
    assert_eq!(
        verify_ledger_witness_checkpoints(&ro_rolled, sidecar, reg, true, true, None).unwrap(),
        1
    );
    let pinned_err = verify_ledger_witness_checkpoints(
        &ro_rolled,
        sidecar,
        reg,
        true,
        true,
        Some(&head3_record_id),
    )
    .unwrap_err();
    assert!(
        matches!(pinned_err, LedgerError::Integrity(ref msg) if msg.contains("expected checkpoint head mismatch")),
        "expected head mismatch on joint rollback, got: {pinned_err}"
    );
}

#[test]
fn detects_revocation_tip_hash_mismatch_duplicate_seq_and_invalid_record_hash() {
    use handfest_core::revocation::parse_canonical_revocation;

    // Real Ed25519 keypair and genuine domain-separated Ed25519 signatures produced by
    // `handfest revoke` (`handfest-anchors::Ed25519Keypair::sign_revocation`), both passing full
    // `verify_revocation` cryptographic verification.
    let signer_key =
        KeyId::parse("ed25519:a6a32aff7ef30ebc4ac9d63d942c0f1b5973deb30d4ee3c7078e1135ecc1d312")
            .unwrap();
    let rev_a_words = "HANDFEST REVOKE v1\nBY human \"alice\" (key: ed25519:a6a32aff7ef30ebc4ac9d63d942c0f1b5973deb30d4ee3c7078e1135ecc1d312)\nTARGET mandate sha256:1b3f949f14d56a084f15cfb203a7ab28c5776982ef2131f5f3f06369332ed988\nEFFECTIVE 2025-11-24T18:00:01Z\nREASON \"original rev\"\n";
    let rev_a_sig = "fbd4a450f7cf4202a4f98cb1d8aaab36da2713b83ef73aeb01b62110e5f47f0ea064c4d09e77554dcb707863d7868a953afbfb5ec92bcb0ed6f4149ff9d56f0c";
    let rev_b_words = "HANDFEST REVOKE v1\nBY human \"alice\" (key: ed25519:a6a32aff7ef30ebc4ac9d63d942c0f1b5973deb30d4ee3c7078e1135ecc1d312)\nTARGET mandate sha256:065152af6de3457a08258e2921862fabda441108423760ec6c2f6bfcb194f867\nEFFECTIVE 2025-11-24T18:00:01Z\nREASON \"signed replacement rev\"\n";
    let rev_b_sig = "a2c881b317579417961967cc34718db977e2f80f0ae9a84936d65e8191371390e81c06e0b915d910eb1dd1d8197dbc48fd2c6366f8b209b7f5660940709f100a";
    let make_real_rev = |words: &str| VerifiedRevocation {
        ast: parse_canonical_revocation(words).unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: signer_key.clone(),
            actor_kind: ActorKind::Human,
            valid_from: 1_764_007_201,
            valid_until: 253_402_300_799,
        },
    };

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("r2_tamper.sqlite");
    let sidecar = default_checkpoint_sidecar_path(&db_path);
    let (chain, req, _, _) = fixture_chain_and_req();
    let witness = RecordingWitness::new("mock");
    let mut ledger = AnchoredLedger::with_checkpoint_file(
        SqliteLedger::open(&db_path).unwrap(),
        witness.clone(),
        WitnessPolicy::SyncStrict,
        &sidecar,
    )
    .unwrap();

    ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
        .unwrap();
    let rev_a = make_real_rev(rev_a_words);
    ledger.record_revocation(&rev_a, rev_a_sig).unwrap();
    let orig_sidecar = fs::read_to_string(&sidecar).unwrap();
    let lines: Vec<&str> = orig_sidecar.lines().collect();
    let rec1: StoredCheckpoint = serde_json::from_str(lines[0]).unwrap();
    let rec2: StoredCheckpoint = serde_json::from_str(lines[1]).unwrap();
    drop(ledger);

    let mut reg = WitnessRegistry::new();
    reg.register(witness).unwrap();

    // 1. Duplicate StoredCheckpoint.seq (seq = 1, seq = 1) with repaired prev_record_hash/record_hash.
    let mut dup = rec2.clone();
    dup.seq = 1;
    dup.prev_record_hash = Some(rec1.record_hash.clone());
    dup.record_hash = StoredCheckpoint::compute_record_hash(
        dup.seq,
        dup.prev_record_hash.as_deref(),
        &dup.checkpoint,
        &dup.proof,
    );
    fs::write(
        &sidecar,
        format!(
            "{}\n{}\n",
            serde_json::to_string(&rec1).unwrap(),
            serde_json::to_string(&dup).unwrap()
        ),
    )
    .unwrap();
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let dup_err =
        verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(dup_err, LedgerError::Integrity(ref msg) if msg.contains("non-contiguous checkpoint seq")),
        "expected non-contiguous seq error on duplicate seq, got: {dup_err}"
    );

    // 2. Invalid MandateId::parse(&record.record_hash).
    let mut bad_id = rec1.clone();
    bad_id.record_hash = "not-a-valid-sha256-id".to_string();
    fs::write(
        &sidecar,
        format!("{}\n", serde_json::to_string(&bad_id).unwrap()),
    )
    .unwrap();
    let id_err =
        verify_ledger_witness_checkpoints(&ro, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(id_err, LedgerError::Integrity(ref msg) if msg.contains("invalid record_hash")),
        "expected invalid record_hash error, got: {id_err}"
    );
    drop(ro);

    // 3. Revocation tip hash mismatch (actual != expected_rev) when revocation row 1 is replaced
    //    with another genuinely Ed25519-signed revocation so local verify_integrity() still passes!
    fs::write(&sidecar, &orig_sidecar).unwrap();
    let rev_b = make_real_rev(rev_b_words);
    let alt_db_path = dir.path().join("alt_rev.sqlite");
    {
        let mut alt = SqliteLedger::open(&alt_db_path).unwrap();
        alt.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), NOW)
            .unwrap();
        alt.record_revocation(&rev_b, rev_b_sig).unwrap();
    }
    let alt_sql = SqliteLedger::open_read_only(&alt_db_path).unwrap();
    assert_eq!(alt_sql.verify_integrity().unwrap(), 1);
    let rev_mismatch_err =
        verify_ledger_witness_checkpoints(&alt_sql, &sidecar, &reg, true, true, None).unwrap_err();
    assert!(
        matches!(rev_mismatch_err, LedgerError::Integrity(ref msg) if msg.contains("revocation tip hash mismatch")),
        "expected revocation tip hash mismatch error, got: {rev_mismatch_err}"
    );
}

#[cfg(feature = "witness-ots")]
#[test]
fn ots_witness_anchor_rejects_truncated_31_byte_magic_only_proof() {
    use handfest_ledger::{CommandOutput, CommandRunner, OtsWitness, OTS_PROOF_MAGIC};

    struct TruncatedMagicOtsRunner;
    impl CommandRunner for TruncatedMagicOtsRunner {
        fn run(
            &self,
            _program: &str,
            args: &[&str],
            _stdin: &[u8],
        ) -> Result<CommandOutput, WitnessError> {
            assert_eq!(args[0], "stamp");
            let ots_path = format!("{}.ots", args[1]);
            fs::write(&ots_path, OTS_PROOF_MAGIC).unwrap();
            Ok(CommandOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    let witness = OtsWitness::with_runner(TruncatedMagicOtsRunner)
        .with_anchored_at(NOW)
        .unwrap();
    let cp = LedgerCheckpoint {
        receipt_seq: 1,
        receipt_hash: [0x11; 32],
        revocation_seq: 0,
        revocation_tip_hash: None,
        timestamp: NOW,
    };
    let err = witness.anchor(&cp).unwrap_err();
    assert!(
        matches!(err, WitnessError::InvalidProof(ref msg) if msg.contains("truncated")),
        "expected truncated OTS proof rejection, got: {err}"
    );
}

#[test]
fn canonical_checkpoint_sidecar_path_classifies_missing_permission_and_symlink_loop_errors() {
    let dir = TempDir::new().unwrap();
    let missing_err =
        canonical_checkpoint_sidecar_path(&dir.path().join("missing.sqlite")).unwrap_err();
    assert!(
        matches!(missing_err, LedgerError::NotFound(_)),
        "got: {missing_err:?}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct RestoreMode(std::path::PathBuf, u32);
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
            }
        }
        let loop_a = dir.path().join("loop_a.sqlite");
        let loop_b = dir.path().join("loop_b.sqlite");
        symlink(&loop_b, &loop_a).unwrap();
        symlink(&loop_a, &loop_b).unwrap();
        let loop_err = canonical_checkpoint_sidecar_path(&loop_a).unwrap_err();
        assert!(
            matches!(loop_err, LedgerError::Integrity(_)),
            "got: {loop_err:?}"
        );

        let restricted = dir.path().join("no_exec_dir");
        fs::create_dir(&restricted).unwrap();
        let db_path = restricted.join("ledger.sqlite");
        let _ = SqliteLedger::open(&db_path).unwrap();
        let _restore = RestoreMode(restricted.clone(), 0o700);
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::canonicalize(&db_path).is_err() {
            let perm_err = canonical_checkpoint_sidecar_path(&db_path).unwrap_err();
            assert!(
                matches!(perm_err, LedgerError::Storage(_)),
                "got: {perm_err:?}"
            );
        }
    }
}
