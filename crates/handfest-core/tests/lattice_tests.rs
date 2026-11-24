use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{
    parse_rfc3339_utc, ActionPat, ActorDecl, Decimal, HandfestAst, KeyId, MandateId, Predicate,
    PredicateOp, Quota, ResourceSel, Scalar,
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

    let mut p = HandfestAst {
        parent: None,
        from: ActorDecl {
            kind: ActorKind::Org,
            name: "acme".into(),
            key: k("ed25519:org1"),
            attrs: BTreeMap::new(),
        },
        to: ActorDecl {
            kind: ActorKind::Agent,
            name: "disp".into(),
            key: k("ed25519:disp1"),
            attrs: BTreeMap::new(),
        },
        max_hops: 2,
        allow: vec![ActionPat::parse("git.*").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/*").unwrap()],
        where_clauses: vec![
            Predicate::in_set(
                "resource.author",
                BTreeSet::from([Scalar::Str("alice".into()), Scalar::Str("bob".into())]),
            ),
            Predicate::prefix("resource.branch", "feat/"),
            Predicate::gte("tx.count", Scalar::Int(1)),
            Predicate::lt("tx.count", Scalar::Int(10)),
            Predicate::gt("tx.amount", Scalar::Decimal(dec("0.0"))),
            Predicate::lte("tx.amount", Scalar::Decimal(dec("100.0"))),
        ],
        limits: vec![
            Quota::Calls(10),
            Quota::Sum {
                max: dec("500.0"),
                unit: "USD".into(),
                field: "tx.amount".into(),
            },
        ],
    };
    p.canonicalize();

    let c = HandfestAst {
        parent: Some(p.mandate_id()),
        from: ActorDecl {
            kind: ActorKind::Agent,
            name: "disp".into(),
            key: k("ed25519:disp1"),
            attrs: BTreeMap::new(),
        },
        to: ActorDecl {
            kind: ActorKind::Agent,
            name: "worker".into(),
            key: k("ed25519:work1"),
            attrs: BTreeMap::new(),
        },
        max_hops: 1,
        allow: vec![ActionPat::parse("git.pr.*").unwrap()],
        on: vec![ResourceSel::new("repo", "feedback-loop-ai/handfest*").unwrap()],
        where_clauses: vec![
            Predicate::eq("resource.author", Scalar::Str("alice".into())),
            Predicate::prefix("resource.branch", "feat/slice-1"),
            Predicate::gt("tx.count", Scalar::Int(1)),
            Predicate::lte("tx.count", Scalar::Int(9)),
            Predicate::gte("tx.amount", Scalar::Decimal(dec("1.0"))),
            Predicate::lt("tx.amount", Scalar::Decimal(dec("50.0"))),
            Predicate::eq("extra.guard", Scalar::Bool(true)),
        ],
        limits: vec![
            Quota::Calls(3),
            Quota::Sum {
                max: dec("100.0"),
                unit: "USD".into(),
                field: "tx.amount".into(),
            },
        ],
    };
    assert!(subsumes(&p, &c).is_ok());
}

#[test]
fn lattice_rejects_handoff_hop_action_and_resource_widenings() {
    let (parent, child) = base_parent_child();

    let mut c = child.clone();
    c.parent = None;
    assert_eq!(subsumes(&parent, &c), Err(NarrowError::MissingParent));

    let mut c = child.clone();
    c.parent = Some(MandateId([0xaa; 32]));
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ParentDigestMismatch { .. })
    ));

    let mut c = child.clone();
    c.from.key = k("ed25519:impostor");
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::HandoffKeyMismatch { .. })
    ));

    let mut c = child.clone();
    c.max_hops = 1;
    assert_eq!(
        subsumes(&parent, &c),
        Err(NarrowError::HopOverflow {
            parent_max_hops: 1,
            child_max_hops: 1
        })
    );

    let mut p0 = parent.clone();
    p0.max_hops = 0;
    let mut c0 = child.clone();
    c0.parent = Some(p0.mandate_id());
    c0.max_hops = 0;
    assert_eq!(
        subsumes(&p0, &c0),
        Err(NarrowError::HopOverflow {
            parent_max_hops: 0,
            child_max_hops: 0
        })
    );

    let mut c = child.clone();
    c.allow.clear();
    assert_eq!(subsumes(&parent, &c), Err(NarrowError::EmptyActions));

    let mut c = child.clone();
    c.allow = vec![ActionPat::parse("git.pr.*").unwrap()];
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ActionWidening { .. })
    ));

    let mut c = child.clone();
    c.on.clear();
    assert_eq!(subsumes(&parent, &c), Err(NarrowError::EmptyResources));

    let mut c = child.clone();
    c.on = vec![ResourceSel::new("bucket", "feedback-loop-ai/handfest").unwrap()];
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ResourceWidening { .. })
    ));

    let mut c = child.clone();
    c.on = vec![ResourceSel::new("repo", "other-org/*").unwrap()];
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ResourceWidening { .. })
    ));
}

#[test]
fn lattice_rejects_predicate_widenings_and_contradictions() {
    let (parent, child) = base_parent_child();

    let mut c = child.clone();
    for pred in &mut c.where_clauses {
        if pred.field_path == "context.time" && matches!(pred.op, PredicateOp::Gte(_)) {
            pred.op = PredicateOp::Gte(Scalar::Timestamp(ts("2026-11-24T17:09:59Z")));
        }
    }
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut c = child.clone();
    for pred in &mut c.where_clauses {
        if pred.field_path == "context.time" && matches!(pred.op, PredicateOp::Lt(_)) {
            pred.op = PredicateOp::Lte(Scalar::Timestamp(ts("2026-11-25T01:10:00Z")));
        }
    }
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut c = child.clone();
    c.where_clauses
        .retain(|p| p.field_path != "resource.ci_status");
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut c = child.clone();
    c.where_clauses.push(Predicate::eq(
        "resource.author",
        Scalar::Str("mallory".into()),
    ));
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut c = child.clone();
    c.where_clauses.push(Predicate::gt("x", Scalar::Int(5)));
    c.where_clauses.push(Predicate::lt("x", Scalar::Int(6)));
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::ContradictoryPredicates { .. })
    ));

    let mut p_set = parent.clone();
    p_set.where_clauses.push(Predicate::in_set(
        "resource.env",
        BTreeSet::from([Scalar::Str("staging".into())]),
    ));
    p_set
        .where_clauses
        .push(Predicate::prefix("resource.branch", "feat/"));
    let mut c_set = child.clone();
    c_set.parent = Some(p_set.mandate_id());
    c_set.where_clauses.push(Predicate::in_set(
        "resource.env",
        BTreeSet::from([Scalar::Str("staging".into()), Scalar::Str("prod".into())]),
    ));
    c_set
        .where_clauses
        .push(Predicate::prefix("resource.branch", "feat/ok"));
    assert!(matches!(
        subsumes(&p_set, &c_set),
        Err(NarrowError::PredicateNotImplied { .. })
    ));

    let mut c_pfx = child;
    c_pfx.parent = Some(p_set.mandate_id());
    c_pfx
        .where_clauses
        .push(Predicate::eq("resource.env", Scalar::Str("staging".into())));
    c_pfx
        .where_clauses
        .push(Predicate::prefix("resource.branch", "fe"));
    assert!(matches!(
        subsumes(&p_set, &c_pfx),
        Err(NarrowError::PredicateNotImplied { .. })
    ));
}

#[test]
fn lattice_rejects_quota_widenings() {
    let (parent, child) = base_parent_child();

    let mut c = child.clone();
    c.limits = vec![Quota::Calls(6)];
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut c = child.clone();
    c.limits.clear();
    assert!(matches!(
        subsumes(&parent, &c),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut p_sum = parent;
    p_sum.limits.push(Quota::Sum {
        max: dec("100.0"),
        unit: "USD".into(),
        field: "tx.amount".into(),
    });
    let mut c_sum = child.clone();
    c_sum.parent = Some(p_sum.mandate_id());
    c_sum.limits.push(Quota::Sum {
        max: dec("100.0"),
        unit: "EUR".into(),
        field: "tx.amount".into(),
    });
    assert!(matches!(
        subsumes(&p_sum, &c_sum),
        Err(NarrowError::QuotaWidening { .. })
    ));

    let mut c_sum_high = child;
    c_sum_high.parent = Some(p_sum.mandate_id());
    c_sum_high.limits.push(Quota::Sum {
        max: dec("100.01"),
        unit: "USD".into(),
        field: "tx.amount".into(),
    });
    assert!(matches!(
        subsumes(&p_sum, &c_sum_high),
        Err(NarrowError::QuotaWidening { .. })
    ));
}
