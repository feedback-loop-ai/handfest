use super::*;

fn test_actor() -> KeyId {
    KeyId::parse("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .unwrap()
}

#[test]
fn rejects_wrong_types_missing_facts_and_invalid_policy_configs() {
    let json = r#"{
        "tools": {
            "pay": {
                "action": "finance.pay",
                "resource_kind": "account",
                "resource_id_arg": "acct",
                "arg_facts": {
                    "count": { "field": "resource.count", "type": "int" }
                }
            }
        }
    }"#;
    let map = ToolPolicyMap::from_json_str(json).unwrap();

    // Wrong type: float and negative zero given for int
    assert!(matches!(
        map.map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1","count":1.5}"#)),
        Err(MappingError::InvalidArgumentFact { .. })
    ));
    assert!(matches!(
        map.map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1","count":-0}"#)),
        Err(MappingError::InvalidArgumentFact { .. })
    ));
    let (_, zero_facts) = map
        .map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1","count":0}"#))
        .unwrap();
    assert_eq!(zero_facts.get("resource.count"), Some(&Scalar::Int(0)));
    // Missing arg fact
    assert!(matches!(
        map.map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1"}"#)),
        Err(MappingError::MissingArgumentFact { .. })
    ));
    // Unmapped tool
    assert!(matches!(
        map.map_call_json(&test_actor(), "unknown", Some("{}")),
        Err(MappingError::UnmappedTool(_))
    ));
    // Duplicate JSON keys rejected
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1"},"a":{"action":"x.z","resource_kind":"r","static_resource_id":"2"}}}"#
        ),
        Err(MappingError::InvalidJson(msg)) if msg.contains("duplicate JSON object key")
    ));
    // Both resource_id_arg and static_resource_id rejected
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","resource_id_arg":"id","static_resource_id":"1"}}}"#
        ),
        Err(MappingError::InvalidPolicy(msg)) if msg.contains("cannot declare both")
    ));
    // Wildcard action rejected via handfest_core::ast::ActionPat delegation
    assert!(matches!(
        ToolPolicyMap::from_json_str(
            r#"{"tools":{"a":{"action":"x.*","resource_kind":"r","static_resource_id":"1"}}}"#
        ),
        Err(MappingError::InvalidPolicy(msg)) if msg.contains("invalid concrete action")
    ));
}

#[test]
fn denial_resource_id_preserves_supplied_strings_and_uses_empty_when_missing() {
    let arg_policy = ToolPolicy {
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_arg: Some("repo".to_string()),
        static_resource_id: None,
        arg_facts: BTreeMap::new(),
        static_facts: BTreeMap::new(),
    };
    assert_eq!(denial_resource_id(&arg_policy, None), "");
    let missing = parse_exact_json(r#"{}"#).unwrap();
    assert_eq!(denial_resource_id(&arg_policy, Some(&missing)), "");
    let non_str = parse_exact_json(r#"{"repo":42}"#).unwrap();
    assert_eq!(denial_resource_id(&arg_policy, Some(&non_str)), "");
    let valid = parse_exact_json(r#"{"repo":"acme/app"}"#).unwrap();
    assert_eq!(denial_resource_id(&arg_policy, Some(&valid)), "acme/app");
    let ctrl = parse_exact_json(r#"{"repo":"acme/app\ninjected"}"#).unwrap();
    assert_eq!(
        denial_resource_id(&arg_policy, Some(&ctrl)),
        "acme/app\ninjected"
    );

    let static_policy = ToolPolicy {
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_arg: None,
        static_resource_id: Some("prod-main".to_string()),
        arg_facts: BTreeMap::new(),
        static_facts: BTreeMap::new(),
    };
    assert_eq!(denial_resource_id(&static_policy, None), "prod-main");

    let unconfigured = ToolPolicy {
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_arg: None,
        static_resource_id: None,
        arg_facts: BTreeMap::new(),
        static_facts: BTreeMap::new(),
    };
    assert_eq!(denial_resource_id(&unconfigured, None), "");
    assert!(matches!(
        resolve_resource_id("merge_pr", &unconfigured, &BTreeMap::new()),
        Err(MappingError::InvalidPolicy(msg)) if msg.contains("missing resource_id configuration")
    ));
}

#[test]
fn typed_scalar_parses_decimal_and_timestamp_at_boundary_and_roundtrips_json() {
    let json = r#"{
        "tools": {
            "quote": {
                "action": "finance.quote",
                "resource_kind": "ledger",
                "static_resource_id": "main",
                "static_facts": {
                    "pricing.fee": { "decimal": "12.50" },
                    "policy.approved_at": { "timestamp": "2026-06-01T00:00:00Z" },
                    "context.time": { "timestamp": "2026-06-01T00:00:00Z" },
                    "env": { "str": "prod" },
                    "tier": { "int": 3 },
                    "audited": { "bool": true }
                }
            }
        }
    }"#;
    let map = ToolPolicyMap::from_json_str(json).unwrap();
    let policy = map.get("quote").unwrap();
    let expected_dec = Decimal::parse("12.50").unwrap();
    let expected_ts = parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap();
    assert_eq!(
        policy.static_facts.get("pricing.fee"),
        Some(&TypedScalar::Decimal(expected_dec))
    );
    assert_eq!(
        policy.static_facts.get("policy.approved_at"),
        Some(&TypedScalar::Timestamp(expected_ts))
    );

    let encoded = serde_json::to_string(&map).unwrap();
    let decoded = ToolPolicyMap::from_json_str(&encoded).unwrap();
    assert_eq!(decoded, map);

    let compiled = map.clone().compile().unwrap();
    assert_eq!(compiled.policy_map(), &map);
    assert!(compiled.static_facts_for("missing").is_none());
    let static_facts = compiled.static_facts_for("quote").unwrap();
    assert_eq!(
        static_facts.get("pricing.fee"),
        Some(&Scalar::Decimal(expected_dec))
    );
    assert_eq!(
        static_facts.get("policy.approved_at"),
        Some(&Scalar::Timestamp(expected_ts))
    );
    assert!(static_facts.get("context.time").is_none());

    let (_, call_facts) = compiled
        .map_call_exact(&test_actor(), "quote", None)
        .unwrap();
    assert_eq!(
        call_facts.get("pricing.fee"),
        Some(&Scalar::Decimal(expected_dec))
    );
    assert_eq!(
        call_facts.get("policy.approved_at"),
        Some(&Scalar::Timestamp(expected_ts))
    );
    assert!(matches!(
        compiled.map_call_exact(&test_actor(), "missing", None),
        Err(MappingError::UnmappedTool(ref name)) if name == "missing"
    ));

    for bad_json in [
        r#"{"tools":{"q":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"fee":{"decimal":"-0.0"}}}}}"#,
        r#"{"tools":{"q":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"fee":{"decimal":"01"}}}}}"#,
        r#"{"tools":{"q":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"ts":{"timestamp":"2026-13-01T00:00:00Z"}}}}}"#,
    ] {
        assert!(
            matches!(
                ToolPolicyMap::from_json_str(bad_json),
                Err(MappingError::InvalidJson(_))
            ),
            "expected InvalidJson for {bad_json}"
        );
    }

    let bad_ts = TypedScalar::Timestamp(i64::MAX);
    assert!(matches!(
        bad_ts.to_scalar(),
        Err(MappingError::InvalidPolicy(_))
    ));
    assert!(serde_json::to_string(&bad_ts).is_err());
}

#[test]
fn single_pass_exact_json_decoder_accepts_aliases_and_null_optionals() {
    let alias_json = r#"{
        "tools": {
            "t": {
                "action": "ops.run",
                "resource_kind": "target",
                "resource_id_arg": null,
                "static_resource_id": "staging",
                "arg_facts": {
                    "s": { "field": "f.s", "type": "Str" },
                    "i": { "field": "f.i", "type": "Int" },
                    "d": { "field": "f.d", "type": "Decimal" },
                    "b": { "field": "f.b", "type": "Bool" },
                    "ts": { "field": "f.ts", "type": "Timestamp" }
                },
                "static_facts": {
                    "k.s": { "Str": "ok" },
                    "k.i": { "Int": -42 },
                    "k.d": { "Decimal": "1.25" },
                    "k.b": { "Bool": false },
                    "k.ts": { "Timestamp": "2026-06-01T00:00:00Z" }
                }
            }
        }
    }"#;
    let map = ToolPolicyMap::from_json_str(alias_json).expect("aliases and null optional decode");
    let pol = map.get("t").unwrap();
    assert_eq!(pol.resource_id_arg, None);
    assert_eq!(pol.static_resource_id.as_deref(), Some("staging"));
    assert_eq!(pol.arg_facts["s"].fact_type, FactType::Str);
    assert_eq!(pol.arg_facts["i"].fact_type, FactType::Int);
    assert_eq!(pol.arg_facts["d"].fact_type, FactType::Decimal);
    assert_eq!(pol.arg_facts["b"].fact_type, FactType::Bool);
    assert_eq!(pol.arg_facts["ts"].fact_type, FactType::Timestamp);
    assert_eq!(pol.static_facts["k.s"], TypedScalar::Str("ok".to_string()));
    assert_eq!(pol.static_facts["k.i"], TypedScalar::Int(-42));
    assert_eq!(
        pol.static_facts["k.d"],
        TypedScalar::Decimal(Decimal::parse("1.25").unwrap())
    );
    assert_eq!(pol.static_facts["k.b"], TypedScalar::Bool(false));
    assert_eq!(
        pol.static_facts["k.ts"],
        TypedScalar::Timestamp(parse_rfc3339_utc("2026-06-01T00:00:00Z").unwrap())
    );
}

#[test]
fn single_pass_exact_json_decoder_rejects_malformed_shapes() {
    let malformed_cases = [
        ("non-object root", "[]"),
        ("missing tools", "{}"),
        ("unknown root field", r#"{"tools":{},"extra":1}"#),
        ("non-object tools", r#"{"tools":[]}"#),
        ("non-object policy", r#"{"tools":{"a":1}}"#),
        (
            "unknown policy field",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","extra":true}}}"#,
        ),
        (
            "missing action",
            r#"{"tools":{"a":{"resource_kind":"r","static_resource_id":"1"}}}"#,
        ),
        (
            "non-string action",
            r#"{"tools":{"a":{"action":1,"resource_kind":"r","static_resource_id":"1"}}}"#,
        ),
        (
            "non-string optional resource_id_arg",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","resource_id_arg":123}}}"#,
        ),
        (
            "non-object arg_facts",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","arg_facts":[]}}}"#,
        ),
        (
            "unknown arg_facts spec field",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","arg_facts":{"x":{"field":"f.x","type":"str","extra":1}}}}}"#,
        ),
        (
            "unknown fact type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","arg_facts":{"x":{"field":"f.x","type":"float"}}}}}"#,
        ),
        (
            "non-object static_facts",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":[]}}}"#,
        ),
        (
            "empty typed scalar",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{}}}}}"#,
        ),
        (
            "multi-key typed scalar",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"str":"a","int":1}}}}}"#,
        ),
        (
            "unknown scalar tag",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"float":1.5}}}}}"#,
        ),
        (
            "str wrong type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"str":1}}}}}"#,
        ),
        (
            "int wrong type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"int":"1"}}}}}"#,
        ),
        (
            "int negative zero",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"int":-0}}}}}"#,
        ),
        (
            "int float",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"int":1.5}}}}}"#,
        ),
        (
            "decimal wrong type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"decimal":1.5}}}}}"#,
        ),
        (
            "bool wrong type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"bool":"true"}}}}}"#,
        ),
        (
            "timestamp wrong type",
            r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"x":{"timestamp":12345}}}}}"#,
        ),
    ];
    for (label, raw) in malformed_cases {
        assert!(
            matches!(
                ToolPolicyMap::from_json_str(raw),
                Err(MappingError::InvalidJson(_))
            ),
            "expected InvalidJson for {label}: {raw}"
        );
    }
}

#[test]
fn serde_deserialize_rejects_duplicate_map_keys() {
    let valid = r#"{
        "tools": {
            "pay": {
                "action": "finance.pay",
                "resource_kind": "account",
                "resource_id_arg": "acct",
                "arg_facts": {
                    "amount": { "field": "resource.amount", "type": "decimal" }
                },
                "static_facts": {
                    "context.env": { "str": "prod" }
                }
            }
        }
    }"#;
    let parsed: ToolPolicyMap = serde_json::from_str(valid).expect("unique keys deserialize");
    assert_eq!(parsed.tools.len(), 1);
    assert_eq!(parsed.tools["pay"].arg_facts.len(), 1);
    assert_eq!(parsed.tools["pay"].static_facts.len(), 1);

    let dup_tools = r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1"},"a":{"action":"x.z","resource_kind":"r","static_resource_id":"2"}}}"#;
    let err = serde_json::from_str::<ToolPolicyMap>(dup_tools).unwrap_err();
    assert!(
        err.to_string().contains("duplicate key 'a'"),
        "expected duplicate key error for tools, got: {err}"
    );

    let dup_arg_facts = r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","arg_facts":{"x":{"field":"f.x","type":"str"},"x":{"field":"f.y","type":"int"}}}}}"#;
    let err = serde_json::from_str::<ToolPolicyMap>(dup_arg_facts).unwrap_err();
    assert!(
        err.to_string().contains("duplicate key 'x'"),
        "expected duplicate key error for arg_facts, got: {err}"
    );

    let dup_static_facts = r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1","static_facts":{"env":{"str":"prod"},"env":{"str":"dev"}}}}}"#;
    let err = serde_json::from_str::<ToolPolicyMap>(dup_static_facts).unwrap_err();
    assert!(
        err.to_string().contains("duplicate key 'env'"),
        "expected duplicate key error for static_facts, got: {err}"
    );

    let non_object = r#"{"tools":[]}"#;
    let err = serde_json::from_str::<ToolPolicyMap>(non_object).unwrap_err();
    assert!(
        err.to_string().contains("a JSON object with unique keys"),
        "expected map visitor expecting message, got: {err}"
    );
}

#[test]
fn mapping_error_display_formats_every_variant() {
    let cases = [
        (
            MappingError::Io("read failed".into()),
            "policy map I/O error: read failed",
        ),
        (
            MappingError::InvalidJson("bad".into()),
            "invalid policy map JSON: bad",
        ),
        (
            MappingError::InvalidPolicy("pol".into()),
            "invalid policy map: pol",
        ),
        (
            MappingError::UnmappedTool("bash".into()),
            "unmapped MCP tool 'bash'",
        ),
        (
            MappingError::NonObjectArguments { tool: "t".into() },
            "tool 't': arguments must be a JSON object",
        ),
        (
            MappingError::MissingResourceId {
                tool: "t".into(),
                arg: "r".into(),
            },
            "tool 't': missing required resource_id argument 'r'",
        ),
        (
            MappingError::InvalidResourceId {
                tool: "t".into(),
                arg: "r".into(),
                detail: "bad".into(),
            },
            "tool 't': invalid resource_id argument 'r': bad",
        ),
        (
            MappingError::MissingArgumentFact {
                tool: "t".into(),
                arg: "a".into(),
            },
            "tool 't': missing required argument fact 'a'",
        ),
        (
            MappingError::InvalidArgumentFact {
                tool: "t".into(),
                arg: "a".into(),
                detail: "bad".into(),
            },
            "tool 't': invalid argument fact 'a': bad",
        ),
        (
            MappingError::CaseCollidingArgumentKey {
                tool: "t".into(),
                key: "A".into(),
                collides_with: "a".into(),
            },
            "tool 't': argument key 'A' collides case-insensitively with 'a'",
        ),
        (
            MappingError::NonAsciiArgumentKey {
                tool: "t".into(),
                key: "é".into(),
            },
            "tool 't': argument key 'é' must be ASCII",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn compile_rejects_deserialized_invalid_policy_map() {
    let dup_target_json = r#"{
        "tools": {
            "pay": {
                "action": "finance.pay",
                "resource_kind": "account",
                "static_resource_id": "acct-1",
                "arg_facts": {
                    "a": { "field": "resource.amount", "type": "decimal" },
                    "b": { "field": "resource.amount", "type": "decimal" }
                }
            }
        }
    }"#;
    let deserialized: ToolPolicyMap = serde_json::from_str(dup_target_json).unwrap();
    assert!(matches!(
        deserialized.compile(),
        Err(MappingError::InvalidPolicy(ref msg)) if msg.contains("duplicate arg_facts target field")
    ));
}

#[cfg(feature = "std")]
#[test]
fn from_file_loads_valid_json_and_reports_io_error_for_missing_file() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let valid_path = dir.join(format!("handfest-core-policy-test-{pid}.json"));
    let missing_path = dir.join(format!("handfest-core-policy-missing-{pid}.json"));
    let _ = std::fs::remove_file(&missing_path);

    let json = r#"{
        "tools": {
            "merge_pr": {
                "action": "git.pr.merge",
                "resource_kind": "repo",
                "resource_id_arg": "repo"
            }
        }
    }"#;
    std::fs::write(&valid_path, json).unwrap();
    let loaded = ToolPolicyMap::from_file(&valid_path);
    let _ = std::fs::remove_file(&valid_path);

    let map = loaded.unwrap();
    assert_eq!(map.tools.len(), 1);
    assert_eq!(
        map.get("merge_pr").map(|p| p.action.as_str()),
        Some("git.pr.merge")
    );

    assert!(matches!(
        ToolPolicyMap::from_file(&missing_path),
        Err(MappingError::Io(ref msg)) if msg.contains("failed to read")
    ));
}
