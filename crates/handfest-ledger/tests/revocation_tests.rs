//! Transactional revocation enforcement, quota isolation, and tamper-evident audit tests.

use std::collections::BTreeMap;

use handfest_core::ast::{
    parse_rfc3339_utc, ActionPat, ActorDecl, HandfestAstBuilder, KeyId, MandateId, Quota,
    ResourceSel,
};
use handfest_core::gate::{
    ActionRequest, RevocationSnapshot, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate,
    VerifiedRevocation,
};
use handfest_core::revocation::{RevocationAst, RevocationTarget};
use handfest_core::{ActorKind, AssuranceLevel, Verdict};
use handfest_ledger::{LedgerError, SqliteLedger};
use rusqlite::Connection;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid timestamp")
}

fn key(hex_char: char) -> KeyId {
    KeyId::new("ed25519", hex_char.to_string().repeat(64)).expect("valid key")
}

fn actor(kind: ActorKind, name: &str, key: KeyId) -> ActorDecl {
    ActorDecl::new(kind, name, key, BTreeMap::new()).expect("valid actor")
}

fn proof_for(actor: &ActorDecl, vf: i64, vu: i64) -> VerifiedAnchorProof {
    VerifiedAnchorProof {
        anchor_id: "local-ed25519".to_string(),
        assurance: AssuranceLevel::LocalKey,
        signer_key: actor.key().clone(),
        actor_kind: actor.kind(),
        valid_from: vf,
        valid_until: vu,
    }
}

fn build_chain_with_quota() -> (ActorDecl, ActorDecl, Vec<VerifiedMandate>, ActionRequest) {
    let alice = actor(ActorKind::Human, "Alice", key('a'));
    let agent = actor(ActorKind::Agent, "Bot", key('b'));
    let vf = ts("2026-11-26T10:00:00Z");
    let vu = ts("2026-11-26T20:00:00Z");

    let ast = HandfestAstBuilder {
        parent: None,
        from: alice.clone(),
        to: agent.clone(),
        max_hops: 1,
        allow: vec![ActionPat::parse("git.pr.merge").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/*").unwrap()],
        where_clauses: vec![],
        limits: vec![Quota::Calls(5)],
    }
    .build()
    .unwrap();
    let vm = VerifiedMandate {
        proof: proof_for(&alice, vf, vu),
        ast,
    };
    let req = ActionRequest {
        actor_key: agent.key().clone(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    (alice, agent, vec![vm], req)
}

fn build_verified_revocation(
    by: ActorDecl,
    target: RevocationTarget,
    effective_at: i64,
    reason: Option<&str>,
) -> VerifiedRevocation {
    let proof = proof_for(&by, effective_at, ts("2026-11-26T23:59:59Z"));
    let ast = RevocationAst::new(by, target, effective_at, reason.map(str::to_string)).unwrap();
    VerifiedRevocation { ast, proof }
}

#[test]
fn persisted_revocation_enforces_atomically_without_consuming_quota() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("ledger.sqlite");
    let mut ledger = SqliteLedger::open(&db_path).unwrap();

    let (alice, _agent, chain, req) = build_chain_with_quota();
    let m0_id = chain[0].ast.mandate_id();
    let t1 = ts("2026-11-26T12:00:00Z");
    let eff = ts("2026-11-26T13:00:00Z");

    // 1. First call permits (consumes 1/5 calls).
    let (v1, r1) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), t1)
        .unwrap();
    assert_eq!(v1, Verdict::Permit);
    assert!(r1.verify_hash());

    // 2. Record revocation effective at 13:00:00Z (idempotent on duplicate, does not consume quota).
    let rev = build_verified_revocation(
        alice,
        RevocationTarget::Mandate(m0_id),
        eff,
        Some("finished early"),
    );
    let sig_hex = "ab".repeat(64);
    let rev_id = ledger.record_revocation(&rev, &sig_hex).unwrap();
    assert_eq!(rev_id, rev.ast.revocation_id());
    assert_eq!(ledger.record_revocation(&rev, &sig_hex).unwrap(), rev_id);

    // Conflicting envelope for same RevocationId fails closed.
    let conflict = ledger.record_revocation(&rev, &"cd".repeat(64));
    assert!(matches!(conflict, Err(LedgerError::Integrity(_))));

    // 3. Before effective_at (12:59:59Z) -> still Permit (consumes 2/5 calls).
    let (v2, _) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), eff - 1)
        .unwrap();
    assert_eq!(v2, Verdict::Permit);

    // 4. At effective_at (13:00:00Z) -> Deny due to revocation, records Deny receipt, quota stays 2!
    let (v3, r3) = ledger
        .evaluate_and_record(&chain, &req, &VerifiedFacts::new(), eff)
        .unwrap();
    match &v3 {
        Verdict::Deny { reason } => {
            assert!(
                reason.contains(&m0_id.to_string()) && reason.contains(&rev_id.to_string()),
                "unexpected deny reason: {reason}"
            );
        }
        Verdict::Permit => panic!("expected Deny after revocation"),
    }
    assert!(r3.verify_hash());
    assert_eq!(ledger.verify_integrity().unwrap(), 3);
    assert_eq!(ledger.list_stored_revocations().unwrap().len(), 1);
    assert_eq!(ledger.load_revocations().unwrap().len(), 1);

    // Verify quota_calls stayed at 2 (neither recording revocation nor denied attempt incremented it).
    let raw = Connection::open(&db_path).unwrap();
    let calls: i64 = raw
        .query_row(
            "SELECT calls FROM quota_calls WHERE mandate_id = ?1",
            [m0_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(calls, 2);

    // Read-only audit also succeeds.
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(ro.verify_integrity().unwrap(), 3);
    assert_eq!(ro.list_stored_revocations().unwrap().len(), 1);
}

#[test]
fn extra_revocations_merge_with_persisted_revocations() {
    let mut ledger = SqliteLedger::open_in_memory().unwrap();
    let (alice, _agent, chain, req) = build_chain_with_quota();
    let m0_id = chain[0].ast.mandate_id();
    let eff = ts("2026-11-26T13:00:00Z");

    let rev = build_verified_revocation(alice, RevocationTarget::Mandate(m0_id), eff, None);
    let mut extra = RevocationSnapshot::new();
    let rev_id = extra.insert(rev).unwrap();

    let (verdict, receipt) = ledger
        .evaluate_and_record_with_revocations(&chain, &req, &VerifiedFacts::new(), &extra, eff)
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { ref reason } if reason.contains(&rev_id.to_string()))
    );
    assert!(receipt.verify_hash());
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
}

#[test]
fn deleting_or_tampering_revocations_fails_audit_and_subsequent_authorization() {
    let dir = tempfile::TempDir::new().unwrap();
    let (alice, agent, chain, req) = build_chain_with_quota();
    let m0_id = chain[0].ast.mandate_id();
    let eff = ts("2026-11-26T13:00:00Z");

    // Case 1: DELETE FROM revocations fails verify_integrity, evaluate_and_record, and record_revocation.
    let db_delete = dir.path().join("delete_rev.sqlite");
    {
        let mut ledger = SqliteLedger::open(&db_delete).unwrap();
        let rev = build_verified_revocation(
            alice.clone(),
            RevocationTarget::Mandate(m0_id),
            eff,
            Some("kill"),
        );
        ledger.record_revocation(&rev, &"aa".repeat(64)).unwrap();
        assert_eq!(ledger.verify_integrity().unwrap(), 0);
    }
    {
        let raw = Connection::open(&db_delete).unwrap();
        raw.execute("DELETE FROM revocations", []).unwrap();
    }
    let ro = SqliteLedger::open_read_only(&db_delete).unwrap();
    assert!(matches!(
        ro.verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        ro.load_revocations(),
        Err(LedgerError::Integrity(_))
    ));
    drop(ro);

    let mut rw = SqliteLedger::open(&db_delete).unwrap();
    assert!(matches!(
        rw.evaluate_and_record(&chain, &req, &VerifiedFacts::new(), eff),
        Err(LedgerError::Integrity(_))
    ));
    let rev2 = build_verified_revocation(
        alice.clone(),
        RevocationTarget::Key(agent.key().clone()),
        eff,
        None,
    );
    assert!(matches!(
        rw.record_revocation(&rev2, &"bb".repeat(64)),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn updating_or_deleting_revocation_rows_fails_audit() {
    let dir = tempfile::TempDir::new().unwrap();
    let (alice, _agent, chain, _req) = build_chain_with_quota();
    let m0_id = chain[0].ast.mandate_id();
    let eff = ts("2026-11-26T13:00:00Z");
    for (name, sql) in [
        ("sig", "UPDATE revocations SET signature_hex = 'deadbeef' WHERE seq = 1"),
        ("window", "UPDATE revocations SET valid_until = valid_until + 1 WHERE seq = 1"),
        ("anchor", "UPDATE revocations SET anchor_id = 'tampered' WHERE seq = 1"),
        ("words", "UPDATE revocations SET canonical_words = 'HANDFEST REVOKE v1\n' WHERE seq = 1"),
        ("prev", "UPDATE revocations SET prev_entry_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE seq = 1"),
    ] {
        let db_upd = dir.path().join(format!("tamper_{name}.sqlite"));
        {
            let mut ledger = SqliteLedger::open(&db_upd).unwrap();
            let rev = build_verified_revocation(
                alice.clone(),
                RevocationTarget::Mandate(m0_id),
                eff,
                Some("original"),
            );
            ledger.record_revocation(&rev, &"aa".repeat(64)).unwrap();
        }
        {
            let raw = Connection::open(&db_upd).unwrap();
            raw.execute(sql, []).unwrap();
        }
        let ro = SqliteLedger::open_read_only(&db_upd).unwrap();
        assert!(
            matches!(ro.verify_integrity(), Err(LedgerError::Integrity(_))),
            "expected Integrity error for tamper case '{name}'"
        );
    }

    // Case 3: Deleting row 1 of 2 breaks seq contiguity & hash chain.
    let db_mid = dir.path().join("delete_mid.sqlite");
    {
        let mut ledger = SqliteLedger::open(&db_mid).unwrap();
        let r1 = build_verified_revocation(
            alice.clone(),
            RevocationTarget::Mandate(m0_id),
            eff,
            Some("first"),
        );
        let r2 = build_verified_revocation(
            alice,
            RevocationTarget::Mandate(MandateId::sha256(b"second")),
            eff,
            Some("second"),
        );
        ledger.record_revocation(&r1, &"aa".repeat(64)).unwrap();
        ledger.record_revocation(&r2, &"bb".repeat(64)).unwrap();
        assert_eq!(ledger.verify_integrity().unwrap(), 0);
    }
    {
        let raw = Connection::open(&db_mid).unwrap();
        raw.execute("DELETE FROM revocations WHERE seq = 1", [])
            .unwrap();
    }
    let ro = SqliteLedger::open_read_only(&db_mid).unwrap();
    assert!(matches!(
        ro.verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
}
