use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{
    format_rfc3339_utc, glob_matches, glob_subsumes, parse_rfc3339_utc, try_format_rfc3339_utc,
    ActionPat, ActorDecl, AstError, Decimal, HandfestAstBuilder, KeyId, MandateId, Predicate,
    Quota, ResourceSel, Scalar, MAX_DECIMAL_SCALE, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::{
    parse_canonical, parse_mandate, render_canonical, try_render_canonical, ParseError,
};
use handfest_core::ActorKind;

fn dec(s: &str) -> Decimal {
    Decimal::parse(s).expect("valid decimal")
}

fn build_valentin_root_text() -> &'static str {
    concat!(
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
    )
}

#[test]
fn canonical_round_trip_and_idempotence() {
    let raw = build_valentin_root_text();
    let parsed = parse_mandate(raw).expect("root mandate parses");
    let canon = render_canonical(&parsed);
    let reparsed = parse_canonical(&canon).expect("canonical text parses strictly");
    assert_eq!(render_canonical(&reparsed), canon);
    assert_eq!(parsed.mandate_id(), reparsed.mandate_id());

    let id_str = parsed.mandate_id().to_string();
    assert!(id_str.starts_with("sha256:"));
    assert_eq!(id_str.len(), 7 + 64);
    assert_eq!(MandateId::parse(&id_str).unwrap(), parsed.mandate_id());
    assert!(MandateId::parse(&id_str.to_uppercase()).is_err());
}

#[test]
fn parse_canonical_rejects_non_canonical_order_whitespace_and_pluralization() {
    let valid_ast = parse_mandate(build_valentin_root_text()).unwrap();
    let canon = render_canonical(&valid_ast);
    assert!(parse_canonical(&canon).is_ok());

    let no_nl = canon.trim_end_matches('\n');
    assert!(matches!(
        parse_mandate(no_nl),
        Err(ParseError::Syntax { .. })
    ));
    assert!(matches!(
        parse_canonical(no_nl),
        Err(ParseError::Syntax { .. })
    ));

    let extra_space = canon.replace("context.time < ", "context.time <  ");
    assert!(parse_mandate(&extra_space).is_ok());
    assert!(matches!(
        parse_canonical(&extra_space),
        Err(ParseError::NonCanonical { .. })
    ));

    let unsorted_where = concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"feedback-loop-ai/*\"\n",
        "WHERE resource.ci_status == \"passing\"\n",
        "  AND resource.author == \"valentin\"\n",
        "LIMIT 5 calls\n",
    );
    assert!(parse_mandate(unsorted_where).is_ok());
    assert!(matches!(
        parse_canonical(unsorted_where),
        Err(ParseError::NonCanonical { .. })
    ));

    let bad_plural = canon.replace("max 1 hop", "max 1 hops");
    assert!(parse_mandate(&bad_plural).is_ok());
    assert!(matches!(
        parse_canonical(&bad_plural),
        Err(ParseError::NonCanonical { .. })
    ));

    let messy = concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0, z: 1, a: 2.50)\n",
        "TO agent \"brokkr:dispatcher\" (key: ed25519:3c8d19f2)\n",
        "DELEGATION max 2 hops\n",
        "ALLOW git.pr.merge, git.branch.create\n",
        "ON repo \"org/b\", repo \"org/a\"\n",
        "WHERE resource.tag IN {\"beta\", \"alpha\"}\n",
        "LIMIT 100.00 USD sum(tx.amount)\n",
    );
    let ast = parse_mandate(messy).expect("messy parses permissively");
    assert!(matches!(
        parse_canonical(messy),
        Err(ParseError::NonCanonical { .. })
    ));
    let fixed = render_canonical(&ast);
    assert!(fixed.contains("a: 2.5, z: 1"));
    assert!(fixed.contains("ALLOW git.branch.create, git.pr.merge"));
    assert!(fixed.contains("IN {\"alpha\", \"beta\"}"));
    assert!(fixed.contains("LIMIT 100.0 USD sum(tx.amount)"));
    assert!(parse_canonical(&fixed).is_ok());
}

#[test]
fn cnl_escapes_timestamps_and_error_rejections() {
    let escaped_doc = concat!(
        "HANDFEST v1\n",
        "FROM org \"Acme \\\"Corp\\\" \\\\ Labs\" (key: ed25519:aa11)\n",
        "TO service \"worker \\\"1\\\"\" (key: ed25519:bb22)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.charge\n",
        "ON account \"acct-*\"\n",
        "WHERE resource.note PREFIX \"inv\\\\\\\"2026\"\n",
        "  AND resource.active == true\n",
    );
    let ast = parse_mandate(escaped_doc).expect("escaped quotes/backslashes parse");
    assert_eq!(ast.from().name(), "Acme \"Corp\" \\ Labs");
    assert_eq!(ast.to().name(), "worker \"1\"");
    let canon = render_canonical(&ast);
    let mut expected_ast = ast.clone();
    expected_ast.canonicalize();
    assert_eq!(parse_canonical(&canon).unwrap(), expected_ast);

    assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(
        format_rfc3339_utc(parse_rfc3339_utc("2024-02-29T23:59:59Z").unwrap()),
        "2024-02-29T23:59:59Z"
    );
    assert!(parse_rfc3339_utc("2026-02-29T00:00:00Z").is_err());
    assert!(parse_rfc3339_utc("2026-13-01T00:00:00Z").is_err());
    assert!(parse_rfc3339_utc("2026-11-24T17:10:00+02:00").is_err());

    let trailing = format!("{canon}EXTRA foo\n");
    assert!(parse_mandate(&trailing).is_err());

    let bad_in = canon.replace("resource.active == true", "resource.tag IN {}");
    assert!(parse_mandate(&bad_in).is_err());
}

#[test]
fn glob_matching_and_subsumption_laws() {
    assert!(glob_matches(
        "feedback-loop-ai/*",
        "feedback-loop-ai/handfest"
    ));
    assert!(!glob_matches("feedback-loop-ai/*", "other-org/handfest"));
    assert!(glob_matches("a*bc*d", "axxxbcyyyd"));
    assert!(!glob_matches("a*bc*d", "abXcd"));

    assert!(glob_subsumes("*", "feedback-loop-ai/*"));
    assert!(glob_subsumes(
        "feedback-loop-ai/*",
        "feedback-loop-ai/handfest"
    ));
    assert!(glob_subsumes(
        "feedback-loop-ai/*",
        "feedback-loop-ai/handfest-*"
    ));
    assert!(!glob_subsumes(
        "feedback-loop-ai/handfest",
        "feedback-loop-ai/*"
    ));
    assert!(glob_subsumes("a*bc*d", "abc*d"));
    assert!(!glob_subsumes("a*bc*d", "ab*cd"));
    assert!(glob_subsumes("a*b*c*d", "a*bc*d"));
    assert!(!glob_subsumes("a*b*b*d", "a*b*d"));
    assert!(!glob_subsumes("a*b", "ab*"));
    assert!(!glob_subsumes("a*b", "*ab"));
}

#[test]
fn decimal_ordering_and_arithmetic() {
    assert_eq!(dec("10.50"), dec("10.5"));
    assert_eq!(dec("0.00"), dec("-0.0"));
    assert!(dec("0.12") < dec("0.123"));
    assert!(dec("0.2") > dec("0.19"));
    assert!(dec("1.02") < dec("1.1"));
    assert!(dec("-1.5") < dec("-1.05"));
    assert!(dec("-0.01") < dec("0.0"));
    assert_eq!(dec("10.25").checked_add(&dec("0.75")), Some(dec("11.0")));
    assert_eq!(dec("100.00").to_string(), "100.0");
    assert_eq!(dec("0.0050").to_string(), "0.005");
}

#[test]
fn ast_rejects_injection_control_chars_and_invalid_invariants() {
    let key_a = KeyId::parse("ed25519:aa11").unwrap();
    let key_b = KeyId::parse("ed25519:bb22").unwrap();

    // Finding 1: exact ResourceSel.kind newline-injection attack MUST be rejected at construction
    let evil_sel = ResourceSel::new("z_pad \"x\"\nWHERE resource.author ==", "valentin");
    assert!(matches!(evil_sel, Err(AstError::InvalidResourceKind(_))));

    // Control characters (NUL, LF, CR, TAB) in quoted strings MUST be rejected
    assert!(matches!(
        ActorDecl::new(
            ActorKind::Human,
            "alice\0bob",
            key_a.clone(),
            BTreeMap::new()
        ),
        Err(AstError::InvalidString(_))
    ));
    assert!(matches!(
        ActorDecl::new(
            ActorKind::Human,
            "alice\nbob",
            key_a.clone(),
            BTreeMap::new()
        ),
        Err(AstError::InvalidString(_))
    ));
    assert!(matches!(
        ActorDecl::new(
            ActorKind::Human,
            "alice\tbob",
            key_a.clone(),
            BTreeMap::new()
        ),
        Err(AstError::InvalidString(_))
    ));
    assert!(matches!(
        ResourceSel::new("repo", "org/\nrepo"),
        Err(AstError::InvalidString(_))
    ));
    assert!(matches!(
        Predicate::prefix("resource.branch", "feat/\0x"),
        Err(AstError::InvalidString(_))
    ));
    assert!(matches!(
        Predicate::eq("resource.author", Scalar::Str("val\nentin".into())),
        Err(AstError::InvalidString(_))
    ));

    // Reserved or non-ident actor attr keys, invalid field paths, invalid quota unit/field/negative max
    let mut bad_attrs = BTreeMap::new();
    bad_attrs.insert("key".to_string(), Scalar::Str("dup".into()));
    assert!(matches!(
        ActorDecl::new(ActorKind::Human, "alice", key_a.clone(), bad_attrs),
        Err(AstError::InvalidActorAttr(_))
    ));
    let mut bad_attr_ident = BTreeMap::new();
    bad_attr_ident.insert("bad key".to_string(), Scalar::Bool(true));
    assert!(matches!(
        ActorDecl::new(ActorKind::Human, "alice", key_a.clone(), bad_attr_ident),
        Err(AstError::InvalidIdent(_))
    ));
    assert!(matches!(
        Predicate::eq("bad field", Scalar::Bool(true)),
        Err(AstError::InvalidFieldPath(_))
    ));
    assert!(matches!(
        Predicate::in_set("resource.tag", BTreeSet::new()),
        Err(AstError::InvalidPredicate(_))
    ));
    assert!(matches!(
        Quota::sum(dec("10.0"), "USD\nEXTRA", "tx.amount"),
        Err(AstError::InvalidIdent(_))
    ));
    assert!(matches!(
        Quota::sum(dec("10.0"), "USD", "tx..amount"),
        Err(AstError::InvalidFieldPath(_))
    ));
    assert!(matches!(
        Quota::sum(dec("-1.0"), "USD", "tx.amount"),
        Err(AstError::InvalidQuota(_))
    ));

    // Out-of-range Decimal scale (> 28) and out-of-4-digit-year Timestamp
    assert!(matches!(
        Decimal::new(1, MAX_DECIMAL_SCALE + 1),
        Err(AstError::InvalidDecimal(_))
    ));
    assert!(matches!(
        Predicate::gte("context.time", Scalar::Timestamp(MIN_RFC3339_TIMESTAMP - 1)),
        Err(AstError::InvalidTimestamp(_))
    ));
    assert!(matches!(
        Predicate::lte("context.time", Scalar::Timestamp(MAX_RFC3339_TIMESTAMP + 1)),
        Err(AstError::InvalidTimestamp(_))
    ));

    // Empty allow / on rejected by HandfestAstBuilder::build
    let from = ActorDecl::new(ActorKind::Human, "alice", key_a, BTreeMap::new()).unwrap();
    let to = ActorDecl::new(ActorKind::Agent, "bot", key_b, BTreeMap::new()).unwrap();
    let empty_allow = HandfestAstBuilder {
        parent: None,
        from: from.clone(),
        to: to.clone(),
        max_hops: 0,
        allow: vec![],
        on: vec![ResourceSel::new("repo", "org/*").unwrap()],
        where_clauses: vec![],
        limits: vec![],
    }
    .build();
    assert_eq!(empty_allow, Err(AstError::EmptyActions));

    let empty_on = HandfestAstBuilder {
        parent: None,
        from: from.clone(),
        to: to.clone(),
        max_hops: 0,
        allow: vec![ActionPat::parse("git.pr.merge").unwrap()],
        on: vec![],
        where_clauses: vec![],
        limits: vec![],
    }
    .build();
    assert_eq!(empty_on, Err(AstError::EmptyResources));

    // Unvalidated Quota::Sum passed directly to HandfestAstBuilder::build is rejected too
    let evil_quota_ast = HandfestAstBuilder {
        parent: None,
        from,
        to,
        max_hops: 0,
        allow: vec![ActionPat::parse("git.pr.merge").unwrap()],
        on: vec![ResourceSel::new("repo", "org/*").unwrap()],
        where_clauses: vec![],
        limits: vec![Quota::Sum {
            max: dec("10.0"),
            unit: "USD\nWHERE x == true".into(),
            field: "tx.amount".into(),
        }],
    }
    .build();
    assert!(matches!(evil_quota_ast, Err(AstError::InvalidIdent(_))));

    // Control escapes like \n or \t in CNL input are rejected
    let tab_in_cnl = concat!(
        "HANDFEST v1\n",
        "FROM human \"alice\\t1\" (key: ed25519:aa11)\n",
        "TO agent \"bot\" (key: ed25519:bb22)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"org/*\"\n",
    );
    assert!(parse_mandate(tab_in_cnl).is_err());

    // Valid AST passes validate() and try_render_canonical()
    let valid = parse_mandate(build_valentin_root_text()).unwrap();
    assert!(valid.validate().is_ok());
    assert_eq!(
        try_render_canonical(&valid).unwrap(),
        render_canonical(&valid)
    );
    assert_eq!(valid.try_mandate_id().unwrap(), valid.mandate_id());
}

#[test]
fn decimal_and_timestamp_boundary_round_trips() {
    // Finding 5: exact representable sum near i128::MAX reduces trailing zeros before overflow check
    let high = dec("1701411834604692317316873037158841057.27");
    let step = dec("0.03");
    let exact_sum = high
        .checked_add(&step)
        .expect("representable sum must not spuriously overflow");
    let expected = dec("1701411834604692317316873037158841057.3");
    assert_eq!(exact_sum, expected);
    assert_eq!(Decimal::parse(&exact_sum.to_string()).unwrap(), expected);

    // Boundary integer-valued Decimal produced by checked_add must round-trip through parse
    let nine = dec("9000000000000000000000000000000000000.0");
    let doubled = nine.checked_add(&nine).expect("1.8e37 fits in i128");
    let formatted = doubled.to_string();
    assert_eq!(formatted, "18000000000000000000000000000000000000.0");
    assert_eq!(Decimal::parse(&formatted).unwrap(), doubled);

    // Extreme i128::MAX and i128::MIN integer decimals round-trip
    let max_int = Decimal::new(i128::MAX, 0).unwrap();
    assert_eq!(Decimal::parse(&max_int.to_string()).unwrap(), max_int);
    let min_int = Decimal::new(i128::MIN, 0).unwrap();
    assert_eq!(Decimal::parse(&min_int.to_string()).unwrap(), min_int);
    assert_eq!(max_int.checked_add(&dec("1.0")), None);
    assert_eq!(min_int.checked_add(&dec("-1.0")), None);

    // Cancellation from huge intermediate scale back to small exact value
    let big = dec("17014118346046923173168730371588410573.0");
    let neg_almost = dec("-17014118346046923173168730371588410572.7");
    assert_eq!(big.checked_add(&neg_almost), Some(dec("0.3")));

    // 4-digit-year RFC 3339 timestamp boundaries round-trip; out-of-range rejected
    assert_eq!(
        parse_rfc3339_utc("0000-01-01T00:00:00Z").unwrap(),
        MIN_RFC3339_TIMESTAMP
    );
    assert_eq!(
        try_format_rfc3339_utc(MIN_RFC3339_TIMESTAMP).unwrap(),
        "0000-01-01T00:00:00Z"
    );
    assert_eq!(
        parse_rfc3339_utc("9999-12-31T23:59:59Z").unwrap(),
        MAX_RFC3339_TIMESTAMP
    );
    assert_eq!(
        try_format_rfc3339_utc(MAX_RFC3339_TIMESTAMP).unwrap(),
        "9999-12-31T23:59:59Z"
    );
    assert!(try_format_rfc3339_utc(MIN_RFC3339_TIMESTAMP - 1).is_err());
    assert!(try_format_rfc3339_utc(MAX_RFC3339_TIMESTAMP + 1).is_err());
}

#[test]
fn parse_mandate_requires_terminal_lf_after_every_final_clause() {
    let min_no_lf = concat!(
        "HANDFEST v1\n",
        "FROM human \"alice\" (key: ed25519:aa11)\n",
        "TO agent \"bot\" (key: ed25519:bb22)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW git.pr.merge\n",
        "ON repo \"org/*\"",
    );
    assert!(matches!(
        parse_mandate(min_no_lf),
        Err(ParseError::Syntax { .. })
    ));
    let with_lf = format!("{min_no_lf}\n");
    assert!(parse_mandate(&with_lf).is_ok());
}

#[test]
fn ast_equality_is_canonical_and_order_independent() {
    let doc_a = concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.pr.merge, git.branch.create\n",
        "ON repo \"org/b\", repo \"org/a\"\n",
        "WHERE z == true\n",
        "  AND a == true\n",
        "  AND z == true\n",
        "LIMIT 100.00 USD sum(tx.amount)\n",
        "  AND 5 calls\n",
    );
    let doc_b = concat!(
        "HANDFEST v1\n",
        "FROM human \"valentin\" (key: ed25519:9b1e44a0)\n",
        "TO agent \"brokkr:seat:ship\" (key: ed25519:7f01aa99)\n",
        "DELEGATION max 1 hop\n",
        "ALLOW git.branch.create, git.pr.merge\n",
        "ON repo \"org/a\", repo \"org/b\"\n",
        "WHERE a == true\n",
        "  AND z == true\n",
        "LIMIT 5 calls\n",
        "  AND 100.0 USD sum(tx.amount)\n",
    );

    let ast_a = parse_mandate(doc_a).unwrap();
    let ast_b = parse_mandate(doc_b).unwrap();
    assert_eq!(ast_a, ast_b);
    assert_eq!(render_canonical(&ast_a), render_canonical(&ast_b));
    assert_eq!(ast_a.mandate_id(), ast_b.mandate_id());

    let canon = parse_canonical(&render_canonical(&ast_a)).unwrap();
    assert_eq!(ast_a, canon);

    // Reordering WHERE clauses via HandfestAstBuilder produces an equal HandfestAst
    let mut b = ast_a.clone().into_builder();
    b.where_clauses.reverse();
    let rebuilt = b.build().unwrap();
    assert_eq!(rebuilt, ast_a);
    assert_eq!(rebuilt.mandate_id(), ast_a.mandate_id());
}
