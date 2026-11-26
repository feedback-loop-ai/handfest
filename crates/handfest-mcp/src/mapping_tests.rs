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

    let compiled = map.compile_static_facts().unwrap();
    let static_facts = compiled.get("quote").unwrap();
    assert_eq!(
        static_facts.get("pricing.fee"),
        Some(&Scalar::Decimal(expected_dec))
    );
    assert_eq!(
        static_facts.get("policy.approved_at"),
        Some(&Scalar::Timestamp(expected_ts))
    );
    assert!(static_facts.get("context.time").is_none());

    let (_, call_facts) = map
        .map_call_exact_prevalidated(&test_actor(), "quote", None, Some(static_facts))
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
        map.map_call_exact_prevalidated(&test_actor(), "quote", None, None),
        Err(MappingError::UnmappedTool(ref name)) if name == "quote"
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
