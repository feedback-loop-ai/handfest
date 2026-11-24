use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{
    parse_rfc3339_utc, ActionPat, ActorDecl, AstError, Decimal, HandfestAst, HandfestAstBuilder,
    KeyId, MandateId, Predicate, PredicateOp, Quota, ResourceSel, Scalar, MAX_RFC3339_TIMESTAMP,
    MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::parse_mandate;
use handfest_core::lattice::{subsumes, NarrowError};
use handfest_core::ActorKind;

fn k(s: &str) -> KeyId {
    KeyId::parse(s).expect("valid key id")
}

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 UTC timestamp")
}

fn dec(s: &str) -> Decimal {
    Decimal::parse(s).expect("valid decimal")
}

fn actor(kind: ActorKind, name: &str, key: &str) -> ActorDecl {
    ActorDecl::new(kind, name, k(key), BTreeMap::new()).expect("valid actor")
}

fn base_parent_child() -> (HandfestAst, HandfestAst) {
    let parent = parse_mandate(concat!(
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
            "WHERE context.time >= 2026-11-24T18:00:00Z\n",
            "  AND context.time < 2026-11-24T18:03:00Z\n",
            "  AND resource.author == \"valentin\"\n",
            "  AND resource.ci_status == \"passing\"\n",
            "  AND resource.pr_number == 42\n",
            "LIMIT 1 call\n",
        ),
        parent_id = parent_id
    ))
    .unwrap();
    (parent, child)
}

#[test]
fn lattice_valid_narrowing_all_five_laws() {
    let (parent, child) = base_parent_child();
    assert!(subsumes(&parent, &child).is_ok());

    let mut p = HandfestAstBuilder {
        parent: None,
        from: actor(ActorKind::Org, "acme", "ed25519:org1"),
        to: actor(ActorKind::Agent, "disp", "ed25519:disp1"),
        max_hops: 2,
        allow: vec![ActionPat::parse("git.*").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/*").unwrap()],
        where_clauses: vec![
            Predicate::in_set(
                "resource.author",
                BTreeSet::from([Scalar::Str("alice".into()), Scalar::Str("bob".into())]),
            )
            .unwrap(),
            Predicate::prefix("resource.branch", "feat/").unwrap(),
            Predicate::gte("tx.count", Scalar::Int(1)).unwrap(),
            Predicate::lt("tx.count", Scalar::Int(10)).unwrap(),
            Predicate::gt("tx.amount", Scalar::Decimal(dec("0.0"))).unwrap(),
            Predicate::lte("tx.amount", Scalar::Decimal(dec("100.0"))).unwrap(),
        ],
        limits: vec![
            Quota::Calls(10),
            Quota::sum(dec("500.0"), "USD", "tx.amount").unwrap(),
        ],
    }
    .build()
    .unwrap();
    p.canonicalize();

    let c = HandfestAstBuilder {
        parent: Some(p.mandate_id()),
        from: actor(ActorKind::Agent, "disp", "ed25519:disp1"),
        to: actor(ActorKind::Agent, "worker", "ed25519:work1"),
        max_hops: 1,
        allow: vec![ActionPat::parse("git.pr.*").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/handfest*").unwrap()],
        where_clauses: vec![
            Predicate::eq("resource.author", Scalar::Str("alice".into())).unwrap(),
            Predicate::prefix("resource.branch", "feat/slice-1").unwrap(),
            Predicate::gt("tx.count", Scalar::Int(1)).unwrap(),
            Predicate::lte("tx.count", Scalar::Int(9)).unwrap(),
            Predicate::gte("tx.amount", Scalar::Decimal(dec("1.0"))).unwrap(),
            Predicate::lt("tx.amount", Scalar::Decimal(dec("50.0"))).unwrap(),
            Predicate::eq("extra.guard", Scalar::Bool(true)).unwrap(),
        ],
        limits: vec![
            Quota::Calls(3),
            Quota::sum(dec("100.0"), "USD", "tx.amount").unwrap(),
        ],
    }
    .build()
    .unwrap();
    assert!(subsumes(&p, &c).is_ok());
}

#[test]
fn lattice_rejects_handoff_hop_action_and_resource_widenings() {
    let (parent, child) = base_parent_child();

    let mut b = child.clone().into_builder();
    b.parent = None;
    assert_eq!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::MissingParent)
    );

    let mut b = child.clone().into_builder();
    b.parent = Some(MandateId([0xaa; 32]));
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ParentDigestMismatch { .. })
    ));

    let mut b = child.clone().into_builder();
    b.from = actor(ActorKind::Agent, "brokkr:dispatcher", "ed25519:impostor");
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::HandoffKeyMismatch { .. })
    ));

    let mut b = child.clone().into_builder();
    b.max_hops = 1;
    assert_eq!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::HopOverflow {
            parent_max_hops: 1,
            child_max_hops: 1
        })
    );

    let mut pb = parent.clone().into_builder();
    pb.max_hops = 0;
    let p0 = pb.build().unwrap();
    let mut cb = child.clone().into_builder();
    cb.parent = Some(p0.mandate_id());
    cb.max_hops = 0;
    assert_eq!(
        subsumes(&p0, &cb.build().unwrap()),
        Err(NarrowError::HopOverflow {
            parent_max_hops: 0,
            child_max_hops: 0
        })
    );

    let mut b = child.clone().into_builder();
    b.allow.clear();
    assert_eq!(b.build(), Err(AstError::EmptyActions));

    let mut b = child.clone().into_builder();
    b.allow = vec![ActionPat::parse("git.pr.*").unwrap()];
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ActionWidening { .. })
    ));

    let mut b = child.clone().into_builder();
    b.on.clear();
    assert_eq!(b.build(), Err(AstError::EmptyResources));

    let mut b = child.clone().into_builder();
    b.on = vec![ResourceSel::new("bucket", "feedback-loop-ai/handfest").unwrap()];
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ResourceWidening { .. })
    ));

    let mut b = child.clone().into_builder();
    b.on = vec![ResourceSel::new("repo", "other-org/*").unwrap()];
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ResourceWidening { .. })
    ));
}

#[test]
fn lattice_enforces_actor_kind_preservation_on_handoff() {
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

    assert_eq!(
        subsumes(&m0, &m1),
        Err(NarrowError::HandoffActorKindMismatch {
            expected: ActorKind::Human,
            actual: ActorKind::Agent,
        })
    );
}

#[test]
fn lattice_rejects_predicate_widenings_and_contradictions() {
    let (parent, child) = base_parent_child();

    let mut b = child.clone().into_builder();
    b.where_clauses = b
        .where_clauses
        .into_iter()
        .map(|pred| {
            if pred.field_path() == "context.time" && matches!(pred.op(), PredicateOp::Gte(_)) {
                Predicate::gte(
                    "context.time",
                    Scalar::Timestamp(ts("2026-11-24T17:09:59Z")),
                )
                .unwrap()
            } else {
                pred
            }
        })
        .collect();
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut b = child.clone().into_builder();
    b.where_clauses = b
        .where_clauses
        .into_iter()
        .map(|pred| {
            if pred.field_path() == "context.time" && matches!(pred.op(), PredicateOp::Lt(_)) {
                Predicate::lte(
                    "context.time",
                    Scalar::Timestamp(ts("2026-11-25T01:10:00Z")),
                )
                .unwrap()
            } else {
                pred
            }
        })
        .collect();
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut b = child.clone().into_builder();
    b.where_clauses
        .retain(|p| p.field_path() != "resource.ci_status");
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut b = child.clone().into_builder();
    b.where_clauses
        .push(Predicate::eq("resource.author", Scalar::Str("mallory".into())).unwrap());
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut b = child.clone().into_builder();
    b.where_clauses
        .push(Predicate::gt("x", Scalar::Int(5)).unwrap());
    b.where_clauses
        .push(Predicate::lt("x", Scalar::Int(6)).unwrap());
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut pb = parent.clone().into_builder();
    pb.where_clauses.push(
        Predicate::in_set(
            "resource.env",
            BTreeSet::from([Scalar::Str("staging".into())]),
        )
        .unwrap(),
    );
    pb.where_clauses
        .push(Predicate::prefix("resource.branch", "feat/").unwrap());
    let p_set = pb.build().unwrap();

    let mut cb = child.clone().into_builder();
    cb.parent = Some(p_set.mandate_id());
    cb.where_clauses.push(
        Predicate::in_set(
            "resource.env",
            BTreeSet::from([Scalar::Str("staging".into()), Scalar::Str("prod".into())]),
        )
        .unwrap(),
    );
    cb.where_clauses
        .push(Predicate::prefix("resource.branch", "feat/ok").unwrap());
    assert!(matches!(
        subsumes(&p_set, &cb.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut cb = child.into_builder();
    cb.parent = Some(p_set.mandate_id());
    cb.where_clauses
        .push(Predicate::eq("resource.env", Scalar::Str("staging".into())).unwrap());
    cb.where_clauses
        .push(Predicate::prefix("resource.branch", "fe").unwrap());
    assert!(matches!(
        subsumes(&p_set, &cb.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));
}

#[test]
fn lattice_prefix_lower_contradictions_and_prefix_bound_implication() {
    let (parent, child) = base_parent_child();

    let mut pb = parent.clone().into_builder();
    pb.where_clauses
        .push(Predicate::prefix("resource.branch", "feat/").unwrap());
    let p_pfx = pb.build().unwrap();

    let mut cb = child.clone().into_builder();
    cb.parent = Some(p_pfx.mandate_id());
    cb.where_clauses
        .push(Predicate::prefix("resource.branch", "feat/").unwrap());
    cb.where_clauses
        .push(Predicate::gte("resource.branch", Scalar::Str("g".into())).unwrap());
    assert!(matches!(
        subsumes(&p_pfx, &cb.build().unwrap()),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut cb2 = child.clone().into_builder();
    cb2.where_clauses
        .push(Predicate::gte("tag", Scalar::Str("b".into())).unwrap());
    cb2.where_clauses
        .push(Predicate::prefix("tag", "a").unwrap());
    assert!(matches!(
        subsumes(&parent, &cb2.build().unwrap()),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut cb_ok = child.clone().into_builder();
    cb_ok.parent = Some(p_pfx.mandate_id());
    cb_ok
        .where_clauses
        .push(Predicate::prefix("resource.branch", "feat/").unwrap());
    cb_ok
        .where_clauses
        .push(Predicate::gte("resource.branch", Scalar::Str("feat/m".into())).unwrap());
    assert!(subsumes(&p_pfx, &cb_ok.build().unwrap()).is_ok());

    let mut pb_lt = parent.clone().into_builder();
    pb_lt
        .where_clauses
        .push(Predicate::lt("tag", Scalar::Str("b".into())).unwrap());
    let p_lt = pb_lt.build().unwrap();
    let mut cb_pfx = child.clone().into_builder();
    cb_pfx.parent = Some(p_lt.mandate_id());
    cb_pfx
        .where_clauses
        .push(Predicate::prefix("tag", "a").unwrap());
    assert!(subsumes(&p_lt, &cb_pfx.build().unwrap()).is_ok());

    let mut pb_lte = parent.clone().into_builder();
    pb_lte
        .where_clauses
        .push(Predicate::lte("tag", Scalar::Str("b".into())).unwrap());
    let p_lte = pb_lte.build().unwrap();
    let mut cb_pfx_lte = child.clone().into_builder();
    cb_pfx_lte.parent = Some(p_lte.mandate_id());
    cb_pfx_lte
        .where_clauses
        .push(Predicate::prefix("tag", "a").unwrap());
    assert!(subsumes(&p_lte, &cb_pfx_lte.build().unwrap()).is_ok());

    let mut pb_ab = parent.clone().into_builder();
    pb_ab
        .where_clauses
        .push(Predicate::lt("tag", Scalar::Str("ab".into())).unwrap());
    let p_ab = pb_ab.build().unwrap();
    let mut cb_ab = child.clone().into_builder();
    cb_ab.parent = Some(p_ab.mandate_id());
    cb_ab
        .where_clauses
        .push(Predicate::prefix("tag", "a").unwrap());
    assert!(matches!(
        subsumes(&p_ab, &cb_ab.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut pb_eq_a = parent.into_builder();
    pb_eq_a
        .where_clauses
        .push(Predicate::lte("tag", Scalar::Str("a".into())).unwrap());
    let p_eq_a = pb_eq_a.build().unwrap();
    let mut cb_eq_a = child.into_builder();
    cb_eq_a.parent = Some(p_eq_a.mandate_id());
    cb_eq_a
        .where_clauses
        .push(Predicate::prefix("tag", "a").unwrap());
    assert!(matches!(
        subsumes(&p_eq_a, &cb_eq_a.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));
}

#[test]
fn lattice_rejects_quota_widenings() {
    let (parent, child) = base_parent_child();

    let mut b = child.clone().into_builder();
    b.limits = vec![Quota::Calls(6)];
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut b = child.clone().into_builder();
    b.limits.clear();
    assert!(matches!(
        subsumes(&parent, &b.build().unwrap()),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut pb = parent.into_builder();
    pb.limits
        .push(Quota::sum(dec("100.0"), "USD", "tx.amount").unwrap());
    let p_sum = pb.build().unwrap();

    let mut cb = child.clone().into_builder();
    cb.parent = Some(p_sum.mandate_id());
    cb.limits
        .push(Quota::sum(dec("100.0"), "EUR", "tx.amount").unwrap());
    assert!(matches!(
        subsumes(&p_sum, &cb.build().unwrap()),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut cb_high = child.into_builder();
    cb_high.parent = Some(p_sum.mandate_id());
    cb_high
        .limits
        .push(Quota::sum(dec("100.01"), "USD", "tx.amount").unwrap());
    assert!(matches!(
        subsumes(&p_sum, &cb_high.build().unwrap()),
        Err(NarrowError::QuotaWidening { .. })
    ));
}

#[test]
fn lattice_string_interval_implies_prefix() {
    let (parent, child) = base_parent_child();
    let gte = |v: &str| Predicate::gte("tag", Scalar::Str(v.into())).unwrap();
    let gt = |v: &str| Predicate::gt("tag", Scalar::Str(v.into())).unwrap();
    let lte = |v: &str| Predicate::lte("tag", Scalar::Str(v.into())).unwrap();
    let lt = |v: &str| Predicate::lt("tag", Scalar::Str(v.into())).unwrap();

    let cases: Vec<(&str, Vec<Predicate>, bool)> = vec![
        // Positive cases: interval implies parent PREFIX
        ("a", vec![gte("a"), lt("b")], true),
        ("a", vec![gt("a"), lt("b")], true),
        ("a", vec![gte("a"), lte("az")], true),
        ("feat/", vec![gte("feat/"), lt("feat0")], true),
        ("a\u{10FFFF}", vec![gte("a\u{10FFFF}"), lt("b")], true),
        ("\u{10FFFF}", vec![gte("\u{10FFFF}")], true),
        ("\u{D7FF}", vec![gte("\u{D7FF}"), lt("\u{E000}")], true),
        ("", vec![gte("x")], true),
        // Negative cases: interval admits values outside PREFIX or wrong type
        ("a", vec![gte("a"), lte("b")], false),
        ("a", vec![gte("a"), lt("ba")], false),
        ("a", vec![gte("a")], false),
        ("a", vec![lt("b")], false),
        ("a", vec![gte("0"), lt("b")], false),
        (
            "",
            vec![Predicate::gte("tag", Scalar::Int(1)).unwrap()],
            false,
        ),
    ];

    for (parent_pfx, child_preds, expect_ok) in cases {
        let mut pb = parent.clone().into_builder();
        pb.where_clauses
            .push(Predicate::prefix("tag", parent_pfx).unwrap());
        let p_ast = pb.build().unwrap();

        let mut cb = child.clone().into_builder();
        cb.parent = Some(p_ast.mandate_id());
        cb.where_clauses.extend(child_preds);
        let c_ast = cb.build().unwrap();

        let res = subsumes(&p_ast, &c_ast);
        if expect_ok {
            assert!(
                res.is_ok(),
                "expected subsumes ok for PREFIX {parent_pfx:?}, got {res:?}"
            );
        } else {
            assert!(
                matches!(res, Err(NarrowError::PredicateNotImplied { .. })),
                "expected PredicateNotImplied for PREFIX {parent_pfx:?}, got {res:?}"
            );
        }
    }
}

#[test]
fn lattice_prefix_with_lower_bound_implies_shared_upper_prefix() {
    let (parent, child) = base_parent_child();
    let pfx = |v: &str| Predicate::prefix("tag", v).unwrap();
    let gte = |v: &str| Predicate::gte("tag", Scalar::Str(v.into())).unwrap();
    let gt = |v: &str| Predicate::gt("tag", Scalar::Str(v.into())).unwrap();

    let cases: Vec<(&str, Vec<Predicate>, bool)> = vec![
        // Child PREFIX "a" supplies exclusive upper bound "b" shared with PREFIX "a\u{10FFFF}"
        ("a\u{10FFFF}", vec![pfx("a"), gte("a\u{10FFFF}")], true),
        ("a\u{10FFFF}", vec![pfx("a"), gt("a\u{10FFFF}")], true),
        (
            "a\u{10FFFF}\u{10FFFF}",
            vec![pfx("a"), gte("a\u{10FFFF}\u{10FFFF}")],
            true,
        ),
        // Upper bound "b" is strictly wider than PREFIX "a\u{10FFFF}a" or PREFIX "ab"
        ("a\u{10FFFF}a", vec![pfx("a"), gte("a\u{10FFFF}")], false),
        ("ab", vec![pfx("a"), gte("ab")], false),
    ];

    for (parent_pfx, child_preds, expect_ok) in cases {
        let mut pb = parent.clone().into_builder();
        pb.where_clauses.push(pfx(parent_pfx));
        let p_ast = pb.build().unwrap();

        let mut cb = child.clone().into_builder();
        cb.parent = Some(p_ast.mandate_id());
        cb.where_clauses.extend(child_preds);
        let c_ast = cb.build().unwrap();

        let res = subsumes(&p_ast, &c_ast);
        if expect_ok {
            assert!(
                res.is_ok(),
                "expected subsumes ok for parent PREFIX {parent_pfx:?}, got {res:?}"
            );
        } else {
            assert!(
                matches!(res, Err(NarrowError::PredicateNotImplied { .. })),
                "expected PredicateNotImplied for parent PREFIX {parent_pfx:?}, got {res:?}"
            );
        }
    }
}

#[test]
fn lattice_rejects_unsatisfiable_scalar_boundary_predicates() {
    let (parent, child) = base_parent_child();
    let max_dec = dec("170141183460469231731687303715884105727.0");
    let min_dec = dec("-170141183460469231731687303715884105728.0");
    let eps = dec("0.0000000000000000000000000001");
    let two_eps = dec("0.0000000000000000000000000002");
    let max_s28 = dec("17014118346.0469231731687303715884105727");
    let next_s27 = dec("17014118346.046923173168730371588410573");

    let impossible_cases: Vec<Vec<Predicate>> = vec![
        vec![Predicate::lt("tag", Scalar::Str(String::new())).unwrap()],
        vec![Predicate::gt("tx.amount", Scalar::Decimal(max_dec)).unwrap()],
        vec![Predicate::lt("tx.amount", Scalar::Decimal(min_dec)).unwrap()],
        vec![
            Predicate::gt("tx.amount", Scalar::Decimal(dec("0.0"))).unwrap(),
            Predicate::lt("tx.amount", Scalar::Decimal(eps)).unwrap(),
        ],
        vec![
            Predicate::gt("tx.amount", Scalar::Decimal(max_s28)).unwrap(),
            Predicate::lt("tx.amount", Scalar::Decimal(next_s27)).unwrap(),
        ],
    ];

    for child_preds in impossible_cases {
        let mut cb = child.clone().into_builder();
        cb.parent = Some(parent.mandate_id());
        cb.where_clauses.extend(child_preds.clone());
        let c_ast = cb.build().unwrap();
        assert!(
            matches!(
                subsumes(&parent, &c_ast),
                Err(NarrowError::ContradictoryPredicates { .. })
            ),
            "expected ContradictoryPredicates for {child_preds:?}"
        );
    }

    // Tightest satisfiable decimal and string boundaries are still accepted and exact
    let mut pb_eps = parent.clone().into_builder();
    pb_eps
        .where_clauses
        .push(Predicate::eq("tx.amount", Scalar::Decimal(eps)).unwrap());
    let p_eps = pb_eps.build().unwrap();
    let mut cb_eps = child.clone().into_builder();
    cb_eps.parent = Some(p_eps.mandate_id());
    cb_eps
        .where_clauses
        .push(Predicate::gt("tx.amount", Scalar::Decimal(dec("0.0"))).unwrap());
    cb_eps
        .where_clauses
        .push(Predicate::lt("tx.amount", Scalar::Decimal(two_eps)).unwrap());
    assert!(subsumes(&p_eps, &cb_eps.build().unwrap()).is_ok());

    let mut pb_empty = parent.into_builder();
    pb_empty
        .where_clauses
        .push(Predicate::eq("tag", Scalar::Str(String::new())).unwrap());
    let p_empty = pb_empty.build().unwrap();
    let mut cb_empty = child.into_builder();
    cb_empty.parent = Some(p_empty.mandate_id());
    cb_empty
        .where_clauses
        .push(Predicate::lte("tag", Scalar::Str(String::new())).unwrap());
    assert!(subsumes(&p_empty, &cb_empty.build().unwrap()).is_ok());
}

#[test]
fn lattice_enforces_rfc3339_timestamp_domain_bounds() {
    let (parent, child) = base_parent_child();

    let impossible_cases: Vec<Vec<Predicate>> = vec![
        vec![Predicate::gt("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP)).unwrap()],
        vec![Predicate::lt("tx.settled_at", Scalar::Timestamp(MIN_RFC3339_TIMESTAMP)).unwrap()],
    ];

    for child_preds in impossible_cases {
        let mut cb = child.clone().into_builder();
        cb.parent = Some(parent.mandate_id());
        cb.where_clauses.extend(child_preds.clone());
        let c_ast = cb.build().unwrap();
        assert!(
            matches!(
                subsumes(&parent, &c_ast),
                Err(NarrowError::ContradictoryPredicates { .. })
            ),
            "expected ContradictoryPredicates for {child_preds:?}"
        );
    }

    // Tightest satisfiable 4-digit-year endpoints collapse to exact equality
    let mut pb_max = parent.clone().into_builder();
    pb_max
        .where_clauses
        .push(Predicate::eq("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP)).unwrap());
    let p_max = pb_max.build().unwrap();
    let mut cb_max = child.clone().into_builder();
    cb_max.parent = Some(p_max.mandate_id());
    cb_max
        .where_clauses
        .push(Predicate::gte("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP)).unwrap());
    assert!(subsumes(&p_max, &cb_max.build().unwrap()).is_ok());

    let mut pb_min = parent.clone().into_builder();
    pb_min
        .where_clauses
        .push(Predicate::eq("tx.settled_at", Scalar::Timestamp(MIN_RFC3339_TIMESTAMP)).unwrap());
    let p_min = pb_min.build().unwrap();
    let mut cb_min = child.clone().into_builder();
    cb_min.parent = Some(p_min.mandate_id());
    cb_min
        .where_clauses
        .push(Predicate::lte("tx.settled_at", Scalar::Timestamp(MIN_RFC3339_TIMESTAMP)).unwrap());
    assert!(subsumes(&p_min, &cb_min.build().unwrap()).is_ok());

    // Unsatisfiable parent `> MAX_RFC3339_TIMESTAMP` cannot be implied by any valid child
    let mut pb_un = parent.into_builder();
    pb_un
        .where_clauses
        .push(Predicate::gt("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP)).unwrap());
    let p_un = pb_un.build().unwrap();
    let mut cb_un = child.into_builder();
    cb_un.parent = Some(p_un.mandate_id());
    cb_un
        .where_clauses
        .push(Predicate::eq("tx.settled_at", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP)).unwrap());
    assert!(matches!(
        subsumes(&p_un, &cb_un.build().unwrap()),
        Err(NarrowError::PredicateNotImplied { .. })
    ));
}

fn assert_interval_implies_in(
    parent: &HandfestAst,
    child: &HandfestAst,
    field: &str,
    parent_set: &[Scalar],
    child_preds: Vec<Predicate>,
    expect_ok: bool,
) {
    let mut pb = parent.clone().into_builder();
    pb.where_clauses
        .push(Predicate::in_set(field, parent_set.iter().cloned().collect()).unwrap());
    let p_ast = pb.build().unwrap();
    let mut cb = child.clone().into_builder();
    cb.parent = Some(p_ast.mandate_id());
    cb.where_clauses.extend(child_preds);
    let res = subsumes(&p_ast, &cb.build().unwrap());
    if expect_ok {
        assert!(res.is_ok(), "expected subsumes ok on {field}, got {res:?}");
    } else {
        assert!(
            matches!(res, Err(NarrowError::PredicateNotImplied { .. })),
            "expected PredicateNotImplied on {field}, got {res:?}"
        );
    }
}

#[test]
fn lattice_bounded_int_and_timestamp_interval_implies_in_set() {
    let (p, c) = base_parent_child();
    let gte = |f: &str, v: Scalar| Predicate::gte(f, v).unwrap();
    let gt = |f: &str, v: Scalar| Predicate::gt(f, v).unwrap();
    let lte = |f: &str, v: Scalar| Predicate::lte(f, v).unwrap();
    let lt = |f: &str, v: Scalar| Predicate::lt(f, v).unwrap();

    let ints = [Scalar::Int(41), Scalar::Int(42), Scalar::Int(43)];
    let gapped = [Scalar::Int(41), Scalar::Int(43), Scalar::Int(99)];
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &ints,
        vec![gte("n", Scalar::Int(41)), lte("n", Scalar::Int(42))],
        true,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &ints,
        vec![gt("n", Scalar::Int(40)), lt("n", Scalar::Int(44))],
        true,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &ints,
        vec![gte("n", Scalar::Int(41)), lte("n", Scalar::Int(44))],
        false,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &gapped,
        vec![gte("n", Scalar::Int(41)), lte("n", Scalar::Int(43))],
        false,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &ints,
        vec![
            gte("n", Scalar::Int(0)),
            lte("n", Scalar::Int(1_000_000_000)),
        ],
        false,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "n",
        &ints,
        vec![
            gte("n", Scalar::Int(i64::MIN)),
            lte("n", Scalar::Int(i64::MAX)),
        ],
        false,
    );

    let t0 = Scalar::Timestamp(ts("2026-11-24T18:00:00Z"));
    let t1 = Scalar::Timestamp(ts("2026-11-24T18:00:01Z"));
    let t2 = Scalar::Timestamp(ts("2026-11-24T18:00:02Z"));
    let t3 = Scalar::Timestamp(ts("2026-11-24T18:00:03Z"));
    let ts_set = [t0.clone(), t1.clone(), t2];
    assert_interval_implies_in(
        &p,
        &c,
        "tx.settled_at",
        &ts_set,
        vec![gte("tx.settled_at", t0.clone()), lte("tx.settled_at", t1)],
        true,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "tx.settled_at",
        &ts_set,
        vec![gte("tx.settled_at", t0), lte("tx.settled_at", t3)],
        false,
    );
}

#[test]
fn lattice_bounded_decimal_interval_implies_in_set() {
    let (p, c) = base_parent_child();
    let gte = |v: &Scalar| Predicate::gte("tx.amount", v.clone()).unwrap();
    let lte = |v: &Scalar| Predicate::lte("tx.amount", v.clone()).unwrap();

    let zero = Scalar::Decimal(dec("0.0"));
    let eps = Scalar::Decimal(dec("0.0000000000000000000000000001"));
    let two_eps = Scalar::Decimal(dec("0.0000000000000000000000000002"));
    let one = Scalar::Decimal(dec("1.0"));
    let max_s28 = Scalar::Decimal(dec("17014118346.0469231731687303715884105727"));
    let next_s27 = Scalar::Decimal(dec("17014118346.046923173168730371588410573"));
    let dec_set = [zero.clone(), eps.clone()];
    let band_set = [max_s28.clone(), next_s27.clone()];

    assert_interval_implies_in(
        &p,
        &c,
        "tx.amount",
        &dec_set,
        vec![gte(&zero), lte(&eps)],
        true,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "tx.amount",
        &dec_set,
        vec![gte(&zero), lte(&two_eps)],
        false,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "tx.amount",
        &band_set,
        vec![gte(&max_s28), lte(&next_s27)],
        true,
    );
    assert_interval_implies_in(
        &p,
        &c,
        "tx.amount",
        &dec_set,
        vec![gte(&zero), lte(&one)],
        false,
    );
}
