use handfest_core::ast::{
    parse_rfc3339_utc, AstError, Decimal, HandfestAst, KeyId, MandateId, Quota, ResourceSel,
    Scalar, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::{parse_canonical, parse_mandate, render_canonical};
use handfest_core::gate::{
    authorize, build_denial_receipt, ActionRequest, QuotaSnapshot, VerifiedAnchorProof,
    VerifiedFacts, VerifiedMandate,
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
        signer_key: ast.from().key().clone(),
        actor_kind: ast.from().kind(),
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
    let mut rb = valentin_root().into_builder();
    rb.limits
        .push(Quota::sum(dec("100.0"), "USD", "tx.amount").unwrap());
    let root = rb.build().unwrap();
    let root_id = root.mandate_id();
    let mut cb = seat_child(root_id).into_builder();
    cb.limits
        .push(Quota::sum(dec("40.0"), "USD", "tx.amount").unwrap());
    let child = cb.build().unwrap();

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

#[test]
fn gate_rejects_negative_prior_quota_snapshot_sums() {
    // Finding 2: negative prior usage MUST fail closed and never create quota headroom
    let root = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:pay\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.charge\n",
        "ON account \"acct-1\"\n",
        "LIMIT 100.0 USD sum(tx.amount)\n",
    ))
    .unwrap();
    let root_id = root.mandate_id();
    let chain = vec![VerifiedMandate {
        proof: proof_for(
            &root,
            AssuranceLevel::QualifiedQes,
            "2026-11-24T17:00:00Z",
            "2026-11-25T02:00:00Z",
        ),
        ast: root,
    }];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "billing.charge".into(),
        resource_kind: "account".into(),
        resource_id: "acct-1".into(),
    };
    let now = ts("2026-11-24T18:00:00Z");

    // Case 1: prior -500.0 with delta 550.0 (naive sum 50.0 <= 100.0) MUST deny
    let mut usage1 = QuotaSnapshot::new();
    usage1.set_sum(root_id, "USD", "tx.amount", dec("-500.0"));
    let facts1 = VerifiedFacts::new().with("tx.amount", Scalar::Decimal(dec("550.0")));
    let (v1, r1) = authorize(&chain, &req, &facts1, &usage1, now, None);
    assert!(matches!(v1, Verdict::Deny { ref reason } if reason.contains("negative prior")));
    assert!(r1.verify_hash());

    // Case 2: prior -10.0 with delta 105.0 (naive sum 95.0 <= 100.0) MUST deny
    let mut usage2 = QuotaSnapshot::new();
    usage2.set_sum(root_id, "USD", "tx.amount", dec("-10.0"));
    let facts2 = VerifiedFacts::new().with("tx.amount", Scalar::Decimal(dec("105.0")));
    let (v2, r2) = authorize(&chain, &req, &facts2, &usage2, now, None);
    assert!(matches!(v2, Verdict::Deny { ref reason } if reason.contains("negative prior")));
    assert!(r2.verify_hash());
}

#[test]
fn gate_rejects_actor_kind_reclassification_on_handoff() {
    // Finding 3: M0 delegates TO human "alice" (key: K); M1 declares FROM agent "bot" (key: K)
    let m0 = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM org \"acme\" (key: ed25519:org1)\n",
        "TO human \"alice\" (key: ed25519:3c8d19f2)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"feedback-loop-ai/*\"\n",
    ))
    .unwrap();
    let m0_id = m0.mandate_id();
    let m1 = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {m0_id}\n",
            "FROM agent \"bot\" (key: ed25519:3c8d19f2)\n",
            "TO agent \"worker\" (key: ed25519:7f01aa99)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
        ),
        m0_id = m0_id
    ))
    .unwrap();

    let chain = vec![
        VerifiedMandate {
            proof: proof_for(
                &m0,
                AssuranceLevel::QualifiedQes,
                "2026-11-24T17:00:00Z",
                "2026-11-25T02:00:00Z",
            ),
            ast: m0,
        },
        VerifiedMandate {
            proof: proof_for(
                &m1,
                AssuranceLevel::LocalKey,
                "2026-11-24T17:59:00Z",
                "2026-11-24T18:05:00Z",
            ),
            ast: m1,
        },
    ];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "git.pr.merge".into(),
        resource_kind: "repo".into(),
        resource_id: "feedback-loop-ai/handfest".into(),
    };
    let now = ts("2026-11-24T18:01:30Z");

    let (v, r) = authorize(
        &chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        now,
        None,
    );
    assert!(matches!(
        v,
        Verdict::Deny { ref reason } if reason.contains("handoff actor kind mismatch")
    ));
    assert!(r.verify_hash());
}

#[test]
fn gate_canonical_determinism_and_byte_for_byte_receipt_replay() {
    // Finding 4: non-canonical predicate ordering yields exact same deny reason & receipt_hash
    // as evaluating the canonical re-parsed AST
    let raw_doc = concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"feedback-loop-ai/handfest\"\n",
        "WHERE z == true\n",
        "  AND a == true\n",
    );
    let raw_ast = parse_mandate(raw_doc).unwrap();
    let canon_text = render_canonical(&raw_ast);
    let canon_ast = parse_canonical(&canon_text).unwrap();

    let raw_chain = vec![VerifiedMandate {
        proof: proof_for(
            &raw_ast,
            AssuranceLevel::QualifiedQes,
            "2026-11-24T17:00:00Z",
            "2026-11-25T02:00:00Z",
        ),
        ast: raw_ast,
    }];
    let canon_chain = vec![VerifiedMandate {
        proof: proof_for(
            &canon_ast,
            AssuranceLevel::QualifiedQes,
            "2026-11-24T17:00:00Z",
            "2026-11-25T02:00:00Z",
        ),
        ast: canon_ast,
    }];

    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "git.pr.merge".into(),
        resource_kind: "repo".into(),
        resource_id: "feedback-loop-ai/handfest".into(),
    };
    let now = ts("2026-11-24T18:01:30Z");

    let (v_raw, r_raw) = authorize(
        &raw_chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        now,
        None,
    );
    let (v_canon, r_canon) = authorize(
        &canon_chain,
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        now,
        None,
    );

    assert!(matches!(
        v_raw,
        Verdict::Deny { ref reason } if reason.contains("missing required verified fact 'a'")
    ));
    assert_eq!(v_raw, v_canon);
    assert_eq!(r_raw.chain_ids, r_canon.chain_ids);
    assert_eq!(r_raw.receipt_hash, r_canon.receipt_hash);
    assert!(r_raw.verify_hash());
}

#[test]
fn gate_denies_leaf_proof_signer_mismatch_and_broken_attenuation() {
    // Finding 6: explicit chain-denial tests for signer_key mismatch & broken adjacent attenuation
    let (chain, root_id, _child_id, req, facts, now) = fixture_chain_req_facts();

    // (a) Leaf proof signer_key mismatch
    let mut bad_signer = chain.clone();
    bad_signer[1].proof.signer_key = k("ed25519:deadbeef");
    let (v_signer, r_signer) =
        authorize(&bad_signer, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        v_signer,
        Verdict::Deny { ref reason } if reason.contains("proof signer key")
    ));
    assert!(r_signer.verify_hash());

    // (b1) Broken adjacent attenuation: tampered child PARENT digest
    let mut bad_parent = chain.clone();
    let mut cb = bad_parent[1].ast.clone().into_builder();
    cb.parent = Some(MandateId([0xbb; 32]));
    bad_parent[1].ast = cb.build().unwrap();
    let (v_parent, r_parent) =
        authorize(&bad_parent, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        v_parent,
        Verdict::Deny { ref reason } if reason.contains("attenuation check failed")
    ));
    assert!(r_parent.verify_hash());

    // (b2) Broken adjacent attenuation: widened child quota bound with valid PARENT digest
    let mut widened = chain;
    let mut cb = seat_child(root_id).into_builder();
    cb.limits = vec![Quota::Calls(10)];
    widened[1].ast = cb.build().unwrap();
    let (v_wide, r_wide) = authorize(&widened, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        v_wide,
        Verdict::Deny { ref reason } if reason.contains("attenuation check failed")
    ));
    assert!(r_wide.verify_hash());
}

#[test]
fn gate_permits_exact_representable_boundary_sum_quota() {
    let root = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:pay\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.charge\n",
        "ON account \"acct-1\"\n",
        "LIMIT 1701411834604692317316873037158841057.3 USD sum(tx.amount)\n",
    ))
    .unwrap();
    let root_id = root.mandate_id();
    let chain = vec![VerifiedMandate {
        proof: proof_for(
            &root,
            AssuranceLevel::QualifiedQes,
            "2026-11-24T17:00:00Z",
            "2026-11-25T02:00:00Z",
        ),
        ast: root,
    }];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "billing.charge".into(),
        resource_kind: "account".into(),
        resource_id: "acct-1".into(),
    };
    let mut usage = QuotaSnapshot::new();
    usage.set_sum(
        root_id,
        "USD",
        "tx.amount",
        dec("1701411834604692317316873037158841057.27"),
    );
    let facts = VerifiedFacts::new().with("tx.amount", Scalar::Decimal(dec("0.03")));
    let now = ts("2026-11-24T18:00:00Z");

    let (v, r) = authorize(&chain, &req, &facts, &usage, now, None);
    assert_eq!(v, Verdict::Permit);
    assert!(r.verify_hash());
}

#[test]
fn gate_rejects_resource_control_characters_and_escapes_receipts() {
    let wildcard = ResourceSel::new("repo", "feedback-loop-ai/*").unwrap();
    for bad_id in [
        "feedback-loop-ai/handfest\nforged",
        "feedback-loop-ai/handfest\rforged",
        "feedback-loop-ai/handfest\0forged",
        "feedback-loop-ai/handfest\x1b[31m",
    ] {
        assert!(!wildcard.matches(bad_id));
    }

    let (chain, _root_id, _child_id, mut req, facts, now) = fixture_chain_req_facts();
    // Root has ON repo "feedback-loop-ai/*"; evaluate root directly so wildcard matching is exercised
    let root_only = vec![chain[0].clone()];
    req.actor_key = chain[0].ast.to().key().clone();
    req.resource_id = "feedback-loop-ai/handfest\nforged\0\x1b".into();

    let (verdict, receipt) = authorize(&root_only, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        verdict,
        Verdict::Deny { ref reason }
            if reason.contains("invalid resource id") && !reason.chars().any(char::is_control)
    ));
    assert!(!receipt.resource.chars().any(char::is_control));
    assert_eq!(
        receipt.resource,
        r#"repo "feedback-loop-ai/handfest\nforged\u{0}\u{1b}""#
    );
    assert!(receipt.verify_hash());

    // Even on early denials (e.g. empty chain), receipt formatting escapes control chars
    let mut nl_req = req.clone();
    nl_req.resource_kind = "repo\nforged".into();
    nl_req.resource_id = "a\nb".into();
    let (v_nl, r_nl) = authorize(&[], &nl_req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(v_nl, Verdict::Deny { .. }));
    assert!(!r_nl.resource.chars().any(char::is_control));
    assert_eq!(r_nl.resource, r#"repo\nforged "a\nb""#);
    assert!(r_nl.verify_hash());

    // Escaped control chars do not collide with literal backslash sequences
    let mut lit_req = nl_req.clone();
    lit_req.resource_id = "a\\nb".into();
    let (_v_lit, r_lit) = authorize(&[], &lit_req, &facts, &QuotaSnapshot::new(), now, None);
    assert_ne!(r_nl.resource, r_lit.resource);
    assert_ne!(r_nl.receipt_hash, r_lit.receipt_hash);
    assert!(r_lit.verify_hash());
}

#[test]
fn gate_decimal_predicate_denial_replays_identically_across_scales() {
    let root = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:pay\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.charge\n",
        "ON account \"acct-1\"\n",
        "WHERE tx.amount <= 10.0\n",
    ))
    .unwrap();
    let chain = vec![VerifiedMandate {
        proof: proof_for(
            &root,
            AssuranceLevel::QualifiedQes,
            "2026-11-24T17:00:00Z",
            "2026-11-25T02:00:00Z",
        ),
        ast: root,
    }];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "billing.charge".into(),
        resource_kind: "account".into(),
        resource_id: "acct-1".into(),
    };
    let now = ts("2026-11-24T18:00:00Z");

    let facts_scale2 =
        VerifiedFacts::new().with("tx.amount", Scalar::Decimal(Decimal::new(1500, 2).unwrap()));
    let facts_scale1 =
        VerifiedFacts::new().with("tx.amount", Scalar::Decimal(Decimal::new(150, 1).unwrap()));
    let facts_scale0 =
        VerifiedFacts::new().with("tx.amount", Scalar::Decimal(Decimal::new(15, 0).unwrap()));

    let (v2, r2) = authorize(
        &chain,
        &req,
        &facts_scale2,
        &QuotaSnapshot::new(),
        now,
        None,
    );
    let (v1, r1) = authorize(
        &chain,
        &req,
        &facts_scale1,
        &QuotaSnapshot::new(),
        now,
        None,
    );
    let (v0, r0) = authorize(
        &chain,
        &req,
        &facts_scale0,
        &QuotaSnapshot::new(),
        now,
        None,
    );

    assert!(matches!(
        v2,
        Verdict::Deny { ref reason } if reason.contains("15.0")
    ));
    assert_eq!(v2, v1);
    assert_eq!(v1, v0);
    assert_eq!(r2.receipt_hash, r1.receipt_hash);
    assert_eq!(r1.receipt_hash, r0.receipt_hash);
    assert!(r2.verify_hash());
}

#[test]
fn gate_rejects_action_control_characters_and_escapes_receipts() {
    let (chain, _root_id, _child_id, mut req, facts, now) = fixture_chain_req_facts();
    req.action = "git.pr.merge\nforged\r\0\x1b[31m".into();

    let (verdict, receipt) = authorize(&chain, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        verdict,
        Verdict::Deny { ref reason }
            if reason.contains("invalid concrete action")
                && reason.contains(r"git.pr.merge\nforged\r\u{0}\u{1b}[31m")
                && !reason.chars().any(char::is_control)
    ));
    assert!(!receipt.action.chars().any(char::is_control));
    assert_eq!(receipt.action, r"git.pr.merge\nforged\r\u{0}\u{1b}[31m");
    assert!(receipt.verify_hash());

    // Early denials (e.g. empty chain) must also escape control characters in DecisionReceipt.action
    let mut nl_req = req.clone();
    nl_req.action = "git.pr.merge\nforged".into();
    let (v_nl, r_nl) = authorize(&[], &nl_req, &facts, &QuotaSnapshot::new(), now, None);
    assert!(matches!(v_nl, Verdict::Deny { .. }));
    assert!(!r_nl.action.chars().any(char::is_control));
    assert_eq!(r_nl.action, r"git.pr.merge\nforged");
    assert!(r_nl.verify_hash());

    // Escaped control characters do not collide with literal backslash sequences
    let mut lit_req = req.clone();
    lit_req.action = r"git.pr.merge\nforged".into();
    let (v_lit, r_lit) = authorize(&chain, &lit_req, &facts, &QuotaSnapshot::new(), now, None);
    let (v_ctrl, r_ctrl) = authorize(&chain, &nl_req, &facts, &QuotaSnapshot::new(), now, None);
    assert_ne!(r_ctrl.action, r_lit.action);
    assert_ne!(v_ctrl, v_lit);
    assert_ne!(r_ctrl.receipt_hash, r_lit.receipt_hash);
    assert!(r_ctrl.verify_hash());
    assert!(r_lit.verify_hash());
}

#[test]
fn gate_fails_closed_on_out_of_range_timestamps() {
    let root = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:settle\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.settle\n",
        "ON account \"acct-1\"\n",
        "WHERE tx.settled_at >= 2026-01-01T00:00:00Z\n",
    ))
    .unwrap();
    let proof_wide = VerifiedAnchorProof {
        anchor_id: "test-anchor".to_string(),
        assurance: AssuranceLevel::QualifiedQes,
        signer_key: root.from().key().clone(),
        actor_kind: root.from().kind(),
        valid_from: MIN_RFC3339_TIMESTAMP,
        valid_until: MAX_RFC3339_TIMESTAMP,
    };
    let chain = vec![VerifiedMandate {
        ast: root,
        proof: proof_wide,
    }];
    let req = ActionRequest {
        actor_key: k("ed25519:7f01aa99"),
        action: "billing.settle".into(),
        resource_kind: "account".into(),
        resource_id: "acct-1".into(),
    };
    let now = ts("2026-11-24T18:00:00Z");

    // Fact timestamp above 9999-12-31T23:59:59Z (253_402_300_800) must fail closed
    let bad_hi_fact =
        VerifiedFacts::new().with("tx.settled_at", Scalar::Timestamp(253_402_300_800));
    let (v_hi, r_hi) = authorize(&chain, &req, &bad_hi_fact, &QuotaSnapshot::new(), now, None);
    assert!(matches!(
        v_hi,
        Verdict::Deny { ref reason } if reason.contains("outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z")
    ));
    assert!(r_hi.verify_hash());

    // Fact timestamp below 0000-01-01T00:00:00Z must also fail closed even when predicate is <=
    let root_lte = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:settle\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.settle\n",
        "ON account \"acct-1\"\n",
        "WHERE tx.settled_at <= 2026-01-01T00:00:00Z\n",
    ))
    .unwrap();
    let chain_lte = vec![VerifiedMandate {
        proof: chain[0].proof.clone(),
        ast: root_lte,
    }];
    let bad_lo_fact = VerifiedFacts::new().with(
        "tx.settled_at",
        Scalar::Timestamp(MIN_RFC3339_TIMESTAMP - 1),
    );
    let (v_lo, r_lo) = authorize(
        &chain_lte,
        &req,
        &bad_lo_fact,
        &QuotaSnapshot::new(),
        now,
        None,
    );
    assert!(matches!(v_lo, Verdict::Deny { .. }));
    assert!(r_lo.verify_hash());

    // Out-of-range `now` fails closed even when the anchor proof covers i64::MIN..i64::MAX
    let ok_fact =
        VerifiedFacts::new().with("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP));
    let (v_now_hi, r_now_hi) = authorize(
        &chain,
        &req,
        &ok_fact,
        &QuotaSnapshot::new(),
        253_402_300_800,
        None,
    );
    assert!(matches!(
        v_now_hi,
        Verdict::Deny { ref reason } if reason.contains("outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z")
    ));
    assert!(r_now_hi.verify_hash());

    let (v_now_lo, r_now_lo) = authorize(
        &chain,
        &req,
        &ok_fact,
        &QuotaSnapshot::new(),
        MIN_RFC3339_TIMESTAMP - 1,
        None,
    );
    assert!(matches!(v_now_lo, Verdict::Deny { .. }));
    assert!(r_now_lo.verify_hash());

    // In-range 4-digit-year boundary timestamp succeeds (`[valid_from..valid_until)` half-open)
    let (v_ok, r_ok) = authorize(
        &chain,
        &req,
        &ok_fact,
        &QuotaSnapshot::new(),
        MAX_RFC3339_TIMESTAMP - 1,
        None,
    );
    assert_eq!(v_ok, Verdict::Permit);
    assert!(r_ok.verify_hash());
}

#[test]
fn gate_permits_bounded_discrete_interval_attenuated_from_parent_in_set() {
    let parent = parse_mandate(concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"feedback-loop-ai/*\"\n",
        "WHERE resource.pr_number IN {41, 42, 43}\n",
        "  AND tx.amount IN {0.0, 0.0000000000000000000000000001}\n",
    ))
    .unwrap();
    let parent_id = parent.mandate_id();
    let child = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent_id}\n",
            "FROM agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
            "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE resource.pr_number >= 41\n",
            "  AND resource.pr_number <= 42\n",
            "  AND tx.amount >= 0.0\n",
            "  AND tx.amount <= 0.0000000000000000000000000001\n",
        ),
        parent_id = parent_id
    ))
    .unwrap();

    let chain = vec![
        VerifiedMandate {
            proof: proof_for(
                &parent,
                AssuranceLevel::QualifiedQes,
                "2026-11-24T17:00:00Z",
                "2026-11-25T02:00:00Z",
            ),
            ast: parent.clone(),
        },
        VerifiedMandate {
            proof: proof_for(
                &child,
                AssuranceLevel::LocalKey,
                "2026-11-24T17:59:00Z",
                "2026-11-24T18:10:00Z",
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
    let now = ts("2026-11-24T18:01:30Z");
    let facts = VerifiedFacts::new()
        .with("resource.pr_number", Scalar::Int(42))
        .with(
            "tx.amount",
            Scalar::Decimal(dec("0.0000000000000000000000000001")),
        );

    let (v, r) = authorize(&chain, &req, &facts, &QuotaSnapshot::new(), now, None);
    assert_eq!(v, Verdict::Permit);
    assert!(r.verify_hash());

    // Widened interval (`<= 44`) fails attenuation check at gate
    let widened_child = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent_id}\n",
            "FROM agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
            "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE resource.pr_number >= 41\n",
            "  AND resource.pr_number <= 44\n",
            "  AND tx.amount >= 0.0\n",
            "  AND tx.amount <= 0.0000000000000000000000000001\n",
        ),
        parent_id = parent_id
    ))
    .unwrap();
    let widened_chain = vec![
        chain[0].clone(),
        VerifiedMandate {
            proof: proof_for(
                &widened_child,
                AssuranceLevel::LocalKey,
                "2026-11-24T17:59:00Z",
                "2026-11-24T18:10:00Z",
            ),
            ast: widened_child,
        },
    ];
    let (v_wide, r_wide) = authorize(
        &widened_chain,
        &req,
        &facts,
        &QuotaSnapshot::new(),
        now,
        None,
    );
    assert!(matches!(
        v_wide,
        Verdict::Deny { ref reason } if reason.contains("attenuation check failed")
    ));
    assert!(r_wide.verify_hash());
}

#[test]
fn build_denial_receipt_matches_authorize_hash_and_escapes_fields() {
    let actor = k("ed25519:7f01aa99");
    let now = ts("2026-11-24T18:01:30Z");

    let req = ActionRequest {
        actor_key: actor.clone(),
        action: "mcp.tool.unknown".into(),
        resource_kind: "tool".into(),
        resource_id: "exec\"\n\x07".into(),
    };
    let (auth_verdict, auth_receipt) = authorize(
        &[],
        &req,
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        now,
        None,
    );
    let Verdict::Deny { reason } = auth_verdict else {
        panic!("expected empty-chain denial");
    };

    let built = build_denial_receipt(
        vec![],
        actor.clone(),
        req.action.clone(),
        req.resource_kind.clone(),
        req.resource_id.clone(),
        now,
        reason,
        None,
    )
    .expect("valid timestamp must build denial receipt");
    assert!(built.verify_hash());
    assert_eq!(built, auth_receipt);

    let mid = valentin_root().mandate_id();
    let chained = build_denial_receipt(
        vec![mid],
        actor,
        "tool.run\n\\bad".into(),
        "repo\\x\x07".into(),
        "org/\"repo\"\n".into(),
        now + 10,
        "unknown tool".into(),
        Some(built.receipt_hash),
    )
    .expect("chained denial receipt");
    assert!(chained.verify_hash());
    assert_eq!(chained.prev_receipt_hash, Some(built.receipt_hash));
    assert_eq!(chained.chain_ids, vec![mid]);
    assert_eq!(
        chained.verdict,
        Verdict::Deny {
            reason: "unknown tool".into()
        }
    );
    assert_eq!(chained.action, "tool.run\\n\\\\bad");
    assert_eq!(chained.resource, "repo\\\\x\\u{7} \"org/\\\"repo\\\"\\n\"");
}

#[test]
fn build_denial_receipt_enforces_rfc3339_timestamp_bounds() {
    let actor = k("ed25519:7f01aa99");

    let min_ok = build_denial_receipt(
        vec![],
        actor.clone(),
        "a.b".into(),
        "repo".into(),
        "id".into(),
        MIN_RFC3339_TIMESTAMP,
        "min".into(),
        None,
    )
    .expect("MIN_RFC3339_TIMESTAMP must be accepted");
    assert!(min_ok.verify_hash());

    let max_ok = build_denial_receipt(
        vec![],
        actor.clone(),
        "a.b".into(),
        "repo".into(),
        "id".into(),
        MAX_RFC3339_TIMESTAMP,
        "max".into(),
        Some(min_ok.receipt_hash),
    )
    .expect("MAX_RFC3339_TIMESTAMP must be accepted");
    assert!(max_ok.verify_hash());

    assert!(matches!(
        build_denial_receipt(
            vec![],
            actor.clone(),
            "a.b".into(),
            "repo".into(),
            "id".into(),
            MIN_RFC3339_TIMESTAMP - 1,
            "too early".into(),
            None,
        ),
        Err(AstError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        build_denial_receipt(
            vec![],
            actor,
            "a.b".into(),
            "repo".into(),
            "id".into(),
            MAX_RFC3339_TIMESTAMP + 1,
            "too late".into(),
            None,
        ),
        Err(AstError::InvalidTimestamp(_))
    ));
}

#[test]
fn verify_chain_runtime_and_structure_typed_errors_and_precedence() {
    use handfest_core::gate::{verify_chain_runtime, verify_chain_structure, ChainStructureError};
    use handfest_core::lattice::NarrowError;
    use handfest_core::ActorKind;
    use std::error::Error as _;

    let make_vm = |text: &str, signer: &str, kind: ActorKind, win: (i64, i64)| VerifiedMandate {
        ast: parse_mandate(text).unwrap(),
        proof: VerifiedAnchorProof {
            anchor_id: "test-anchor".into(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: k(&format!("ed25519:{signer}")),
            actor_kind: kind,
            valid_from: win.0,
            valid_until: win.1,
        },
    };

    let root_text = "HANDFEST v1\n\
         FROM human \"Root\" (key: ed25519:aaaa)\n\
         TO agent \"Leaf\" (key: ed25519:bbbb)\n\
         DELEGATION max 1 hops\n\
         ALLOW git.pr.*\n\
         ON repo \"org/*\"\n";
    let vm = make_vm(root_text, "aaaa", ActorKind::Human, (100, 200));
    let single = std::slice::from_ref(&vm);
    let leaf = k("ed25519:bbbb");
    let sub = k("ed25519:cccc");

    assert_eq!(verify_chain_runtime(single, &leaf, 150), Ok(()));
    assert_eq!(
        verify_chain_runtime(&[], &leaf, 150),
        Err("empty mandate chain".into())
    );
    for bad_ts in [MIN_RFC3339_TIMESTAMP - 1, MAX_RFC3339_TIMESTAMP + 1] {
        let err = verify_chain_runtime(single, &leaf, bad_ts).unwrap_err();
        assert!(err.contains("outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"));
    }
    assert!(verify_chain_runtime(single, &sub, 150)
        .unwrap_err()
        .contains("does not match leaf mandate TO key"));
    assert!(verify_chain_runtime(single, &leaf, 200)
        .unwrap_err()
        .contains("outside anchor proof validity window"));

    let bad_signer = make_vm(root_text, "dddd", ActorKind::Human, (100, 200));
    assert!(verify_chain_runtime(&[bad_signer], &leaf, 150)
        .unwrap_err()
        .contains("proof signer key"));
    let bad_kind = make_vm(root_text, "aaaa", ActorKind::Agent, (100, 200));
    assert!(verify_chain_runtime(&[bad_kind], &leaf, 150)
        .unwrap_err()
        .contains("proof actor kind"));
    let bad_window = make_vm(root_text, "aaaa", ActorKind::Human, (200, 200));
    assert!(verify_chain_runtime(&[bad_window], &leaf, 200)
        .unwrap_err()
        .contains("invalid anchor proof validity window"));

    // Out-of-range proof validity bounds must be rejected by gate::verify_proofs even when `now` is valid.
    for out_of_range_win in [
        (MIN_RFC3339_TIMESTAMP - 1, 200),
        (100, MAX_RFC3339_TIMESTAMP + 1),
        (i64::MIN, i64::MAX),
    ] {
        let bad_bounds = make_vm(root_text, "aaaa", ActorKind::Human, out_of_range_win);
        let err = verify_chain_runtime(std::slice::from_ref(&bad_bounds), &leaf, 150).unwrap_err();
        assert!(
            err.contains("outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"),
            "unexpected error: {err}"
        );
        let (verdict, _) = authorize(
            &[bad_bounds],
            &ActionRequest {
                actor_key: leaf.clone(),
                action: "git.pr.merge".into(),
                resource_kind: "repo".into(),
                resource_id: "org/app".into(),
            },
            &VerifiedFacts::new(),
            &QuotaSnapshot::new(),
            150,
            None,
        );
        assert!(matches!(
            verdict,
            Verdict::Deny { ref reason } if reason.contains("outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z")
        ));
    }

    let pid = vm.ast.mandate_id();
    let child_vm = |allow: &str, max_hops: u32| {
        let text = format!(
            "HANDFEST v1\nPARENT {pid}\nFROM agent \"Leaf\" (key: ed25519:bbbb)\n\
             TO agent \"Sub\" (key: ed25519:cccc)\nDELEGATION max {max_hops} hops\n\
             ALLOW {allow}\nON repo \"org/app\"\n"
        );
        make_vm(&text, "bbbb", ActorKind::Agent, (100, 200))
    };
    let valid_child = child_vm("git.pr.merge", 0);
    let widened_child = child_vm("git.*", 0);
    let hop_overflow_child = child_vm("git.pr.merge", 1);

    // Typed ChainStructureError checks
    assert_eq!(
        verify_chain_structure(&[]),
        Err(ChainStructureError::EmptyChain)
    );
    assert_eq!(
        verify_chain_structure(std::slice::from_ref(&valid_child)),
        Err(ChainStructureError::RootHasParent)
    );
    assert_eq!(
        verify_chain_structure(&[vm.clone(), valid_child.clone()]),
        Ok(vec![pid, valid_child.ast.mandate_id()])
    );
    let wide_err = verify_chain_structure(&[vm.clone(), widened_child.clone()]).unwrap_err();
    assert!(matches!(
        wide_err,
        ChainStructureError::AttenuationFailed {
            hop: 0,
            ref source,
        } if matches!(source.as_ref(), NarrowError::ActionWidening { .. })
    ));
    assert!(wide_err.source().is_some());
    assert!(wide_err.to_string().contains("attenuation check failed"));

    let hop_err = verify_chain_structure(&[vm.clone(), hop_overflow_child]).unwrap_err();
    assert_eq!(
        hop_err,
        ChainStructureError::MaxHopsExceeded {
            hop: 0,
            parent_max_hops: 1,
            child_max_hops: 1,
        }
    );
    assert!(hop_err.source().is_none());
    assert!(hop_err.to_string().contains("delegation hop overflow"));

    assert_eq!(
        verify_chain_runtime(&[vm.clone(), valid_child], &sub, 150),
        Ok(())
    );
    assert!(
        verify_chain_runtime(&[vm.clone(), widened_child.clone()], &sub, 150)
            .unwrap_err()
            .contains("attenuation check failed")
    );

    // Precedence regression: expired hop-0 proof [100, 200) at now = 200 AND widened hop-1 `ALLOW git.*`
    // MUST deny with the expired-proof reason (matching pre-round-9 60f105e/a2e28b9 precedence).
    let chain = [vm, widened_child];
    let runtime_err = verify_chain_runtime(&chain, &sub, 200).unwrap_err();
    assert_eq!(
        runtime_err,
        "hop 0: timestamp 200 outside anchor proof validity window [100..200)"
    );
    let (verdict, receipt) = authorize(
        &chain,
        &ActionRequest {
            actor_key: sub,
            action: "git.pr.merge".into(),
            resource_kind: "repo".into(),
            resource_id: "org/app".into(),
        },
        &VerifiedFacts::new(),
        &QuotaSnapshot::new(),
        200,
        None,
    );
    assert_eq!(
        verdict,
        Verdict::Deny {
            reason: "hop 0: timestamp 200 outside anchor proof validity window [100..200)".into(),
        }
    );
    assert!(receipt.verify_hash());
}
