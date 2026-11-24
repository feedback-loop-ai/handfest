use handfest_core::ast::{
    format_rfc3339_utc, glob_matches, glob_subsumes, parse_rfc3339_utc, Decimal, MandateId,
};
use handfest_core::cnl::{parse_canonical, parse_mandate, render_canonical, ParseError};

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
    assert!(parse_mandate(no_nl).is_ok());
    assert!(matches!(
        parse_canonical(no_nl),
        Err(ParseError::NonCanonical { .. })
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
        "TO service \"worker\\t1\" (key: ed25519:bb22)\n",
        "DELEGATION max 0 hops\n",
        "ALLOW billing.charge\n",
        "ON account \"acct-*\"\n",
        "WHERE resource.note PREFIX \"inv\\\\\\\"2026\"\n",
        "  AND resource.active == true\n",
    );
    let ast = parse_mandate(escaped_doc).expect("escaped quotes/backslashes parse");
    assert_eq!(ast.from.name, "Acme \"Corp\" \\ Labs");
    assert_eq!(ast.to.name, "worker\t1");
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
