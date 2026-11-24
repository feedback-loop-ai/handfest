use handfest_core::ast::{
    parse_rfc3339_utc, Decimal, HandfestAst, KeyId, MandateId, Quota, Scalar,
};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{
    authorize, ActionRequest, QuotaSnapshot, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate,
};
use handfest_core::{AssuranceLevel, Verdict};

fn k(s: &str) -> KeyId {
    KeyId::parse(s).expect("valid key id")
}

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 UTC timestamp")
}

fn dec(s: &str) -> Decimal {
    Decimal::parse(s).expect("valid decimal")
}

fn valentin_root() -> HandfestAst {
    parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0, anchor: \"eidas-qes\", github: \"valentin\")\n",
        "TO agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"feedback-loop-ai/*\"\n",
        "WHERE context.time >= 2026-11-24T17:10:00Z\n",
        "  AND context.time < 2026-11-25T01:10:00Z\n",
        "  AND resource.author == \"valentin\"\n",
        "  AND resource.ci_status == \"passing\"\n",
        "LIMIT 5 calls\n",
    ))
    .unwrap()
}

fn seat_child(parent_id: MandateId) -> HandfestAst {
    parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent_id}\n",
            "FROM agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
            "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T18:03:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "  AND resource.ci_status == \"passing\"\n",
            "  AND resource.pr_number == 42\n",
            "LIMIT 1 call\n",
        ),
        parent_id = parent_id
    ))
    .unwrap()
}

fn proof_for(
    ast: &HandfestAst,
    assurance: AssuranceLevel,
    from: &str,
    until: &str,
) -> VerifiedAnchorProof {
    VerifiedAnchorProof {
        anchor_id: "test-anchor".to_string(),
        assurance,
        signer_key: ast.from.key.clone(),
        actor_kind: ast.from.kind,
        valid_from: ts(from),
        valid_until: ts(until),
    }
}

fn fixture_chain_req_facts() -> (
    Vec<VerifiedMandate>,
    MandateId,
    MandateId,
    ActionRequest,
    VerifiedFacts,
    i64,
) {
    let root = valentin_root();
    let root_id = root.mandate_id();
    let child = seat_child(root_id);
    let child_id = child.mandate_id();
    let chain = vec![
        VerifiedMandate {
            proof: proof_for(
                &root,
                AssuranceLevel::QualifiedQes,
                "2026-11-24T17:00:00Z",
                "2026-11-25T02:00:00Z",
            ),
            ast: root,
        },
        VerifiedMandate {
            proof: proof_for(
                &child,
                AssuranceLevel::LocalKey,
                "2026-11-24T17:59:00Z",
                "2026-11-24T18:05:00Z",
            ),
            ast: child,
        },
    ];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "git.pr.merge".into(),
        resource_kind: "repo".into(),
        resource_id: "feedback-loop-ai/handfest".into(),
    };
    let facts = VerifiedFacts::new()
        .with("resource.author", Scalar::Str("valentin".into()))
        .with("resource.ci_status", Scalar::Str("passing".into()))
        .with("resource.pr_number", Scalar::Int(42));
    let now = ts("2026-11-24T18:01:30Z");
    (chain, root_id, child_id, req, facts, now)
}

#[test]
fn gate_chain_permit_and_deterministic_receipt_chaining() {
    let (chain, root_id, child_id, req, facts, now) = fixture_chain_req_facts();

    let (verdict, receipt1) = authorize(&chain, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert_eq!(verdict, Verdict::Permit);
    assert_eq!(receipt1.chain_ids, vec![root_id, child_id]);
    assert_eq!(receipt1.prev_receipt_hash, None);
    assert!(receipt1.verify_hash());

    let (_, receipt1_replay) = authorize(&chain, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert_eq!(receipt1.receipt_hash, receipt1_replay.receipt_hash);

    let (_, receipt2) = authorize(
        &chain,
        &req,
        &facts,
        &QuotaSnapshot::new(),
        now,
        Some(receipt1.receipt_hash),
    );
    assert_eq!(receipt2.prev_receipt_hash, Some(receipt1.receipt_hash));
    assert_ne!(receipt2.receipt_hash, receipt1.receipt_hash);
    assert!(receipt2.verify_hash());

    let mut tampered = receipt2;
    tampered.timestamp += 1;
    assert!(!tampered.verify_hash());
}

#[test]
fn gate_chain_denials() {
    let (chain, _root_id, _child_id, req, facts, now) = fixture_chain_req_facts();

    let wrong_author = facts
        .clone()
        .with("resource.author", Scalar::Str("bob".into()));
    assert!(matches!(
        authorize(
            &chain,
            &req,
            &wrong_author,
            &QuotaSnapshot::new(),
            now,
            None
        )
        .0,
        Verdict::Deny { .. }
    ));

    let failing_ci = facts
        .clone()
        .with("resource.ci_status", Scalar::Str("failed".into()));
    assert!(matches!(
        authorize(&chain, &req, &failing_ci, &QuotaSnapshot::new(), now, None).0,
        Verdict::Deny { .. }
    ));

    // Expired mandate time cannot be bypassed by spoofing context.time in facts
    let expired_now = ts("2026-11-24T18:03:00Z");
    let spoofed = facts.clone().with("context.time", Scalar::Timestamp(now));
    assert!(matches!(
        authorize(
            &chain,
            &req,
            &spoofed,
            &QuotaSnapshot::new(),
            expired_now,
            None
        )
        .0,
        Verdict::Deny { .. }
    ));

    // Expired anchor proof
    let mut bad_proof_chain = chain.clone();
    bad_proof_chain[1].proof.valid_until = now;
    assert!(matches!(
        authorize(
            &bad_proof_chain,
            &req,
            &facts,
            &QuotaSnapshot::new(),
            now,
            None
        )
        .0,
        Verdict::Deny { .. }
    ));

    // Wrong leaf key
    let mut wrong_actor = req.clone();
    wrong_actor.actor_key = k("ed25519:deadbeef");
    assert!(matches!(
        authorize(
            &chain,
            &wrong_actor,
            &facts,
            &QuotaSnapshot::new(),
            now,
            None
        )
        .0,
        Verdict::Deny { .. }
    ));

    // Missing fact & type mismatch
    let mut missing_facts = facts.clone();
    missing_facts.0.remove("resource.ci_status");
    assert!(matches!(
        authorize(
            &chain,
            &req,
            &missing_facts,
            &QuotaSnapshot::new(),
            now,
            None
        )
        .0,
        Verdict::Deny { .. }
    ));
    let bad_type = facts
        .clone()
        .with("resource.pr_number", Scalar::Str("42".into()));
    assert!(matches!(
        authorize(&chain, &req, &bad_type, &QuotaSnapshot::new(), now, None).0,
        Verdict::Deny { .. }
    ));

    // Truncated chain (child passed alone without root)
    assert!(matches!(
        authorize(&chain[1..], &req, &facts, &QuotaSnapshot::new(), now, None).0,
        Verdict::Deny { .. }
    ));
}

#[test]
fn gate_chain_call_anti_splitting() {
    let (chain, root_id, child_id, req, facts, now) = fixture_chain_req_facts();

    // Anti-splitting: root M0 already hit 5 calls -> child M1 (0 calls) MUST be denied
    let mut usage = QuotaSnapshot::new();
    usage.set_calls(root_id, 5);
    usage.set_calls(child_id, 0);
    let (v, r) = authorize(&chain, &req, &facts, &usage, now, None);
    assert!(matches!(v, Verdict::Deny { ref reason } if reason.contains("quota")));
    assert_eq!(r.verdict, v);
    assert!(r.verify_hash());

    // Root at 4 calls and child at 0 calls -> Permitted
    usage.set_calls(root_id, 4);
    assert_eq!(
        authorize(&chain, &req, &facts, &usage, now, None).0,
        Verdict::Permit
    );
}

#[test]
fn gate_sum_quota_anti_splitting_and_fail_closed() {
    let mut root = valentin_root();
    root.limits.push(Quota::Sum {
        max: dec("100.0"),
        unit: "USD".into(),
        field: "tx.amount".into(),
    });
    let root_id = root.mandate_id();
    let mut child = seat_child(root_id);
    child.limits.push(Quota::Sum {
        max: dec("40.0"),
        unit: "USD".into(),
        field: "tx.amount".into(),
    });

    let chain = vec![
        VerifiedMandate {
            proof: proof_for(
                &root,
                AssuranceLevel::QualifiedQes,
                "2026-11-24T17:00:00Z",
                "2026-11-25T02:00:00Z",
            ),
            ast: root,
        },
        VerifiedMandate {
            proof: proof_for(
                &child,
                AssuranceLevel::LocalKey,
                "2026-11-24T17:59:00Z",
                "2026-11-24T18:05:00Z",
            ),
            ast: child,
        },
    ];

    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "git.pr.merge".into(),
        resource_kind: "repo".into(),
        resource_id: "feedback-loop-ai/handfest".into(),
    };
    let facts = VerifiedFacts::new()
        .with("resource.author", Scalar::Str("valentin".into()))
        .with("resource.ci_status", Scalar::Str("passing".into()))
        .with("resource.pr_number", Scalar::Int(42))
        .with("tx.amount", Scalar::Decimal(dec("25.0")));
    let now = ts("2026-11-24T18:01:30Z");

    let mut usage = QuotaSnapshot::new();
    usage.set_sum(root_id, "USD", "tx.amount", dec("80.0"));
    let (v, _) = authorize(&chain, &req, &facts, &usage, now, None);
    assert!(matches!(v, Verdict::Deny { ref reason } if reason.contains("sum quota exceeded")));

    usage.set_sum(root_id, "USD", "tx.amount", dec("75.0"));
    let (v, _) = authorize(&chain, &req, &facts, &usage, now, None);
    assert_eq!(v, Verdict::Permit);

    let neg_facts = facts.with("tx.amount", Scalar::Decimal(dec("-10.0")));
    let (v, _) = authorize(&chain, &req, &neg_facts, &usage, now, None);
    assert!(matches!(v, Verdict::Deny { .. }));
}
