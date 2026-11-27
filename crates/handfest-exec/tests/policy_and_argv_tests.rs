use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use handfest_core::ast::{parse_rfc3339_utc, Decimal, KeyId, Scalar};
use handfest_core::policy::{FactType, TypedScalar};
use handfest_exec::{
    denial_resource_id, load_cli_policy_map_file, parse_and_map_argv, ArgvError, CliPolicyMap,
    CommandPolicy, CredentialSource, FlagKind, FlagSpec, PolicyError,
};
use tempfile::tempdir;

fn test_actor() -> KeyId {
    KeyId::parse("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .expect("valid test key id")
}

fn sample_policy_json() -> &'static str {
    r#"{
      "commands": {
        "gh-pr-merge": {
          "executable": "/usr/bin/gh",
          "fixed_args": ["pr", "merge"],
          "action": "git.pr.merge",
          "resource_kind": "repo",
          "resource_id_flag": "--repo",
          "allowed_flags": {
            "--repo": { "kind": { "value": "str" }, "fact_field": "request.repo", "required": true },
            "--pr": { "kind": { "value": "int" }, "fact_field": "request.pr", "required": true },
            "--amount": { "kind": { "value": "decimal" }, "fact_field": "request.amount" },
            "--draft": { "kind": { "value": "bool" }, "fact_field": "request.draft" },
            "--deadline": { "kind": { "value": "timestamp" }, "fact_field": "request.deadline" },
            "--squash": { "kind": "bool_switch", "fact_field": "request.squash" },
            "--env": { "kind": { "value": "str" }, "fact_field": "resource.environment" },
            "--spoof-time": { "kind": { "value": "timestamp" }, "fact_field": "context.time" },
            "--note": { "kind": { "value": "str" } }
          },
          "static_facts": {
            "resource.environment": { "str": "staging" },
            "context.time": { "timestamp": "2026-06-01T00:00:00Z" },
            "policy.tier": { "int": 2 },
            "policy.fee": { "decimal": "12.50" },
            "policy.audited": { "bool": true }
          },
          "pass_env": ["PATH"],
          "env_secrets": {
            "GH_TOKEN": { "file": { "path": "/run/secrets/gh_token" } },
            "BACKUP_TOKEN": { "env": { "var": "BROKER_BACKUP_TOKEN" } }
          }
        },
        "static-status": {
          "executable": "/usr/bin/true",
          "action": "sys.status.read",
          "resource_kind": "service",
          "static_resource_id": "health-check",
          "allowed_flags": {
            "--verbose": { "kind": "bool_switch", "fact_field": "request.verbose", "required": true }
          }
        }
      }
    }"#
}

#[test]
fn policy_json_round_trip_compilation_and_file_loading() {
    let parsed = CliPolicyMap::from_json_str(sample_policy_json()).expect("valid policy");
    let serialized = serde_json::to_string(&parsed).expect("serialize policy");
    let reparsed = CliPolicyMap::from_json_str(&serialized).expect("reparse policy");
    assert_eq!(parsed, reparsed);

    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("policy.json");
    fs::write(&path, sample_policy_json()).expect("write policy");
    let from_file = load_cli_policy_map_file(&path).expect("load policy file");
    assert_eq!(from_file, parsed);

    let missing_err = load_cli_policy_map_file(dir.path().join("missing.json")).unwrap_err();
    assert!(matches!(missing_err, PolicyError::Io(_)));

    let compiled = parsed.compile().expect("compile policy");
    let static_facts = compiled
        .static_facts_for("gh-pr-merge")
        .expect("static facts present");
    assert_eq!(
        static_facts.get("resource.environment"),
        Some(&Scalar::Str("staging".to_string()))
    );
    assert_eq!(static_facts.get("policy.tier"), Some(&Scalar::Int(2)));
    assert_eq!(
        static_facts.get("policy.fee"),
        Some(&Scalar::Decimal(Decimal::parse("12.50").unwrap()))
    );
    assert_eq!(
        static_facts.get("policy.audited"),
        Some(&Scalar::Bool(true))
    );
    assert!(static_facts.get("context.time").is_none());
}

#[test]
fn policy_rejects_duplicate_keys_and_unknown_fields() {
    let cases = [
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1"},"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"2"}}}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","allowed_flags":{"--x":{"kind":"bool_switch"},"--x":{"kind":"bool_switch"}}}}}"#,
        r#"{"commands":{},"extra":1}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","shell":true}}}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","allowed_flags":{"--x":{"kind":"bool_switch","unknown":1}}}}}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","allowed_flags":{"--x":{"kind":{"other":"str"}}}}}}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","env_secrets":{"TOK":{"file":{"path":"/etc/tok","extra":1}}}}}}"#,
        r#"{"commands":{"a":{"executable":"/bin/true","action":"a.b","resource_kind":"r","static_resource_id":"1","env_secrets":{"TOK":{"vault":{"path":"/etc/tok"}}}}}}"#,
        r#"{}"#,
    ];
    for raw in cases {
        let err = CliPolicyMap::from_json_str(raw).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidJson(_)),
            "expected InvalidJson for {raw}, got {err:?}"
        );
    }
}

#[test]
fn policy_rejects_invalid_security_invariants() {
    let base = || CommandPolicy {
        executable: PathBuf::from("/usr/bin/gh"),
        fixed_args: vec!["pr".to_string()],
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_flag: Some("--repo".to_string()),
        static_resource_id: None,
        allowed_flags: BTreeMap::from([(
            "--repo".to_string(),
            FlagSpec {
                kind: FlagKind::Value(FactType::Str),
                fact_field: None,
                required: true,
            },
        )]),
        static_facts: BTreeMap::new(),
        pass_env: Vec::new(),
        env_secrets: BTreeMap::new(),
    };

    for bad_exec in ["gh", "./gh", "/usr/bin/../bin/gh", "/usr/bin/gh\n"] {
        let mut p = base();
        p.executable = PathBuf::from(bad_exec);
        assert!(
            matches!(p.validate("cmd"), Err(PolicyError::InvalidPolicy(_))),
            "expected InvalidPolicy for executable '{bad_exec}'"
        );
    }

    let mut p = base();
    p.fixed_args.push("merge\x00".to_string());
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    assert!(matches!(
        base().validate(""),
        Err(PolicyError::InvalidPolicy(_))
    ));
    assert!(matches!(
        base().validate("bad\ncmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.action = "git.*".to_string();
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.resource_kind = "bad kind".to_string();
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));
}

#[test]
fn policy_rejects_bad_resource_id_flags_and_env_secrets() {
    let base = || CommandPolicy {
        executable: PathBuf::from("/usr/bin/gh"),
        fixed_args: vec!["pr".to_string()],
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_flag: Some("--repo".to_string()),
        static_resource_id: None,
        allowed_flags: BTreeMap::from([(
            "--repo".to_string(),
            FlagSpec {
                kind: FlagKind::Value(FactType::Str),
                fact_field: None,
                required: true,
            },
        )]),
        static_facts: BTreeMap::new(),
        pass_env: Vec::new(),
        env_secrets: BTreeMap::new(),
    };

    let mut p = base();
    p.resource_id_flag = None;
    p.static_resource_id = None;
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.static_resource_id = Some("org/app".to_string());
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.resource_id_flag = Some("--other".to_string());
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.allowed_flags.insert(
        "--repo".to_string(),
        FlagSpec {
            kind: FlagKind::BoolSwitch,
            fact_field: None,
            required: false,
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.allowed_flags.insert(
        "--Repo".to_string(),
        FlagSpec {
            kind: FlagKind::Value(FactType::Str),
            fact_field: None,
            required: false,
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    for bad_flag in ["-r", "repo", "--", "---repo", "--a=b", "--répo", "--a\nb"] {
        let mut p = base();
        p.allowed_flags.insert(
            bad_flag.to_string(),
            FlagSpec {
                kind: FlagKind::BoolSwitch,
                fact_field: None,
                required: false,
            },
        );
        assert!(
            matches!(p.validate("cmd"), Err(PolicyError::InvalidPolicy(_))),
            "expected invalid flag '{bad_flag}' to fail validation"
        );
    }

    let mut p = base();
    p.allowed_flags.get_mut("--repo").unwrap().fact_field = Some("req.x".to_string());
    p.allowed_flags.insert(
        "--dup".to_string(),
        FlagSpec {
            kind: FlagKind::BoolSwitch,
            fact_field: Some("req.x".to_string()),
            required: false,
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));
}

#[test]
fn policy_rejects_bad_pass_env_env_secrets_and_static_facts() {
    let base = || CommandPolicy {
        executable: PathBuf::from("/usr/bin/gh"),
        fixed_args: vec!["pr".to_string()],
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id_flag: Some("--repo".to_string()),
        static_resource_id: None,
        allowed_flags: BTreeMap::from([(
            "--repo".to_string(),
            FlagSpec {
                kind: FlagKind::Value(FactType::Str),
                fact_field: None,
                required: true,
            },
        )]),
        static_facts: BTreeMap::new(),
        pass_env: Vec::new(),
        env_secrets: BTreeMap::new(),
    };

    let mut p = base();
    p.pass_env = vec!["1BAD".to_string()];
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.pass_env = vec!["PATH".to_string(), "PATH".to_string()];
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.pass_env = vec!["GH_TOKEN".to_string()];
    p.env_secrets.insert(
        "GH_TOKEN".to_string(),
        CredentialSource::File {
            path: PathBuf::from("/run/secrets/gh"),
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.env_secrets.insert(
        "GH_TOKEN".to_string(),
        CredentialSource::File {
            path: PathBuf::from("secrets/gh"),
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.env_secrets.insert(
        "GH_TOKEN".to_string(),
        CredentialSource::Env {
            var: "BAD-VAR".to_string(),
        },
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));

    let mut p = base();
    p.static_facts.insert(
        "resource.note".to_string(),
        TypedScalar::Str("a\nb".to_string()),
    );
    assert!(matches!(
        p.validate("cmd"),
        Err(PolicyError::InvalidPolicy(_))
    ));
}

#[test]
fn argv_parsing_maps_all_scalar_types_bool_switches_and_static_fact_precedence() {
    let compiled = CliPolicyMap::from_json_str(sample_policy_json())
        .expect("valid policy")
        .compile()
        .expect("compile");
    let actor = test_actor();

    let args: Vec<String> = [
        "--repo=org/app",
        "--pr",
        "-42",
        "--amount=12345678901234567890.12345678",
        "--draft=false",
        "--deadline",
        "2026-07-01T12:00:00Z",
        "--squash",
        "--env=production",
        "--spoof-time=2020-01-01T00:00:00Z",
        "--note",
        "ship it",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    let mapped = parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &args).expect("map argv");
    assert_eq!(mapped.request.actor_key, actor);
    assert_eq!(mapped.request.action, "git.pr.merge");
    assert_eq!(mapped.request.resource_kind, "repo");
    assert_eq!(mapped.request.resource_id, "org/app");
    assert_eq!(
        mapped.validated_argv,
        vec![
            "--repo=org/app",
            "--pr=-42",
            "--amount=12345678901234567890.12345678",
            "--draft=false",
            "--deadline=2026-07-01T12:00:00Z",
            "--squash",
            "--env=production",
            "--spoof-time=2020-01-01T00:00:00Z",
            "--note=ship it",
        ]
    );

    assert_eq!(
        mapped.facts.get("request.repo"),
        Some(&Scalar::Str("org/app".to_string()))
    );
    assert_eq!(mapped.facts.get("request.pr"), Some(&Scalar::Int(-42)));
    assert_eq!(
        mapped.facts.get("request.amount"),
        Some(&Scalar::Decimal(
            Decimal::parse("12345678901234567890.12345678").unwrap()
        ))
    );
    assert_eq!(
        mapped.facts.get("request.draft"),
        Some(&Scalar::Bool(false))
    );
    assert_eq!(
        mapped.facts.get("request.deadline"),
        Some(&Scalar::Timestamp(
            parse_rfc3339_utc("2026-07-01T12:00:00Z").unwrap()
        ))
    );
    assert_eq!(
        mapped.facts.get("request.squash"),
        Some(&Scalar::Bool(true))
    );
    assert_eq!(
        mapped.facts.get("resource.environment"),
        Some(&Scalar::Str("staging".to_string()))
    );
    assert!(mapped.facts.get("context.time").is_none());

    let minimal_args: Vec<String> = ["--repo", "org/app", "--pr=7"]
        .into_iter()
        .map(String::from)
        .collect();
    let minimal =
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &minimal_args).expect("minimal argv");
    // Omitted optional BoolSwitch must NOT fabricate false (fail-closed if child defaults true).
    assert!(minimal.facts.get("request.squash").is_none());
    assert!(minimal.facts.get("request.amount").is_none());

    let status = parse_and_map_argv(
        &compiled,
        &actor,
        "static-status",
        &["--verbose".to_string()],
    )
    .expect("static-status");
    assert_eq!(status.request.resource_id, "health-check");
    assert_eq!(
        status.facts.get("request.verbose"),
        Some(&Scalar::Bool(true))
    );
}

#[test]
fn argv_parsing_rejects_all_adversarial_and_malformed_inputs() {
    let compiled = CliPolicyMap::from_json_str(sample_policy_json())
        .expect("valid policy")
        .compile()
        .expect("compile");
    let actor = test_actor();
    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };

    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "no-such-cmd", &[]),
        Err(ArgvError::UnmappedCommand("no-such-cmd".to_string()))
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo=org/app", "--pr=1", "--", "--evil"])
        ),
        Err(ArgvError::SeparatorSmuggling {
            command: "gh-pr-merge".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["--repo", "--"])),
        Err(ArgvError::SeparatorSmuggling {
            command: "gh-pr-merge".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["positional"])),
        Err(ArgvError::PositionalOrUnsupportedArg {
            command: "gh-pr-merge".to_string(),
            arg: "positional".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["-r", "org/app"])),
        Err(ArgvError::PositionalOrUnsupportedArg {
            command: "gh-pr-merge".to_string(),
            arg: "-r".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["--répo=org/app"])),
        Err(ArgvError::NonAsciiFlag {
            command: "gh-pr-merge".to_string(),
            flag: "--répo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--Repo=org/app", "--pr=1"])
        ),
        Err(ArgvError::CaseCollidingFlag {
            command: "gh-pr-merge".to_string(),
            flag: "--Repo".to_string(),
            collides_with: "--repo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo=org/app", "--pr=1", "--admin"])
        ),
        Err(ArgvError::UnknownFlag {
            command: "gh-pr-merge".to_string(),
            flag: "--admin".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo=org/a", "--repo", "org/b", "--pr=1"])
        ),
        Err(ArgvError::DuplicateFlag {
            command: "gh-pr-merge".to_string(),
            flag: "--repo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo=org/a", "--pr=1", "--squash=true"])
        ),
        Err(ArgvError::UnexpectedFlagValue {
            command: "gh-pr-merge".to_string(),
            flag: "--squash".to_string()
        })
    );
}

#[test]
fn argv_parsing_rejects_missing_values_control_chars_and_invalid_scalars() {
    let compiled = CliPolicyMap::from_json_str(sample_policy_json())
        .expect("valid policy")
        .compile()
        .expect("compile");
    let actor = test_actor();
    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };

    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["--repo"])),
        Err(ArgvError::MissingFlagValue {
            command: "gh-pr-merge".to_string(),
            flag: "--repo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo", "--squash"])
        ),
        Err(ArgvError::MissingFlagValue {
            command: "gh-pr-merge".to_string(),
            flag: "--repo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo=org/a\n--evil", "--pr=1"])
        ),
        Err(ArgvError::ControlCharacter {
            command: "gh-pr-merge".to_string(),
            arg_index: 0
        })
    );
    assert_eq!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &s(&["--repo", "org/a\x00", "--pr=1"])
        ),
        Err(ArgvError::ControlCharacter {
            command: "gh-pr-merge".to_string(),
            arg_index: 1
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["--pr=1"])),
        Err(ArgvError::MissingResourceId {
            command: "gh-pr-merge".to_string(),
            flag: "--repo".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "gh-pr-merge", &s(&["--repo=org/app"])),
        Err(ArgvError::MissingRequiredFlag {
            command: "gh-pr-merge".to_string(),
            flag: "--pr".to_string()
        })
    );
    assert_eq!(
        parse_and_map_argv(&compiled, &actor, "static-status", &[]),
        Err(ArgvError::MissingRequiredFlag {
            command: "static-status".to_string(),
            flag: "--verbose".to_string()
        })
    );
}

#[test]
fn argv_parsing_rejects_invalid_scalar_types() {
    let compiled = CliPolicyMap::from_json_str(sample_policy_json())
        .expect("valid policy")
        .compile()
        .expect("compile");
    let actor = test_actor();
    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };

    for bad_int in ["-0", "01", "+1", "1.5", "99999999999999999999999"] {
        assert!(
            matches!(
                parse_and_map_argv(
                    &compiled,
                    &actor,
                    "gh-pr-merge",
                    &s(&["--repo=org/app", "--pr", bad_int])
                ),
                Err(ArgvError::InvalidFlagValue { ref flag, .. }) if flag == "--pr"
            ),
            "expected InvalidFlagValue for --pr {bad_int}"
        );
    }
    for bad_dec in [
        "-0",
        "-0.0",
        "010",
        "1e5",
        "1.2.3",
        "0.00000000000000000000000000001",
    ] {
        assert!(
            matches!(
                parse_and_map_argv(
                    &compiled,
                    &actor,
                    "gh-pr-merge",
                    &s(&["--repo=org/app", "--pr=1", "--amount", bad_dec])
                ),
                Err(ArgvError::InvalidFlagValue { ref flag, .. }) if flag == "--amount"
            ),
            "expected InvalidFlagValue for --amount {bad_dec}"
        );
    }
    for bad_bool in ["1", "0", "TRUE", "yes", ""] {
        assert!(
            matches!(
                parse_and_map_argv(
                    &compiled,
                    &actor,
                    "gh-pr-merge",
                    &s(&["--repo=org/app", "--pr=1", "--draft", bad_bool])
                ),
                Err(ArgvError::InvalidFlagValue { ref flag, .. }) if flag == "--draft"
            ),
            "expected InvalidFlagValue for --draft {bad_bool}"
        );
    }
    for bad_ts in ["2026-06-01", "not-a-ts"] {
        assert!(
            matches!(
                parse_and_map_argv(
                    &compiled,
                    &actor,
                    "gh-pr-merge",
                    &s(&["--repo=org/app", "--pr=1", "--deadline", bad_ts])
                ),
                Err(ArgvError::InvalidFlagValue { ref flag, .. }) if flag == "--deadline"
            ),
            "expected InvalidFlagValue for --deadline {bad_ts}"
        );
    }
}

#[test]
fn denial_resource_id_extracts_honestly_without_trusting_duplicates_or_smuggled_args() {
    let compiled = CliPolicyMap::from_json_str(sample_policy_json())
        .expect("valid policy")
        .compile()
        .expect("compile");
    let gh = compiled.get("gh-pr-merge").unwrap();
    let status = compiled.get("static-status").unwrap();
    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };

    assert_eq!(denial_resource_id(status, &[]), "health-check");
    assert_eq!(denial_resource_id(gh, &s(&["--repo=org/app"])), "org/app");
    assert_eq!(
        denial_resource_id(gh, &s(&["--repo", "org/app"])),
        "org/app"
    );
    assert_eq!(
        denial_resource_id(gh, &s(&["--repo=org/app", "--evil"])),
        ""
    );
    assert_eq!(
        denial_resource_id(gh, &s(&["--repo", "org/app", "--evil"])),
        ""
    );
    assert_eq!(
        denial_resource_id(gh, &s(&["--evil", "--repo=org/spoofed"])),
        ""
    );
    assert_eq!(
        denial_resource_id(gh, &s(&["--repo=org/a", "--repo=org/b"])),
        ""
    );
    assert_eq!(denial_resource_id(gh, &s(&["--", "--repo=org/app"])), "");
    assert_eq!(denial_resource_id(gh, &s(&["--repo"])), "");
    assert_eq!(denial_resource_id(gh, &s(&["--repo", "--evil"])), "");
}

#[test]
fn security_remediation_regressions_fail_closed() {
    let map = CliPolicyMap::from_json_str(sample_policy_json()).expect("valid policy");
    let compiled = map.compile().expect("compile");
    let actor = KeyId::parse(&format!("ed25519:{}", "a".repeat(64))).expect("actor key");

    // Short-flag smuggling via space-separated `--flag -v` is rejected fail-closed.
    assert!(matches!(
        parse_and_map_argv(
            &compiled,
            &actor,
            "gh-pr-merge",
            &[
                "--repo".into(),
                "org/app".into(),
                "--pr=7".into(),
                "--note".into(),
                "-v".into(),
            ]
        ),
        Err(ArgvError::MissingFlagValue { flag, .. }) if flag == "--note"
    ));

    // Public serde::Deserialize rejects duplicate JSON keys.
    let dup_serde = r#"{"commands":{"deploy":{"executable":"/usr/bin/true","action":"ops.deploy","resource_kind":"env","static_resource_id":"staging","static_facts":{"resource.env":{"str":"production"},"resource.env":{"str":"staging"}}}}}"#;
    assert!(serde_json::from_str::<CliPolicyMap>(dup_serde).is_err());

    // fixed_args colliding with allowed_flags is rejected.
    let mut bad_fixed = compiled.get("gh-pr-merge").unwrap().clone();
    bad_fixed.fixed_args.push("--repo=pinned".to_string());
    assert!(bad_fixed.validate("bad-fixed").is_err());

    // Case-colliding resource_id_flag returns empty denial_resource_id.
    let cmd = compiled.get("gh-pr-merge").unwrap();
    assert_eq!(
        denial_resource_id(cmd, &["--Repo=evil/repo".into(), "--repo=safe/repo".into()]),
        ""
    );
}

#[test]
fn fixed_args_rejects_double_dash_separator_and_denial_id_handles_value_flags() {
    let map = CliPolicyMap::from_json_str(sample_policy_json()).expect("valid policy");
    let compiled = map.compile().expect("compile");

    let mut bad_sep = compiled.get("gh-pr-merge").unwrap().clone();
    bad_sep.fixed_args.push("--".to_string());
    assert!(matches!(
        bad_sep.validate("bad-sep"),
        Err(PolicyError::InvalidPolicy(ref msg)) if msg.contains("'--'")
    ));

    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };
    let gh = compiled.get("gh-pr-merge").unwrap();

    for rejected in [
        &["--note", "--repo=org/spoofed"][..],
        &["--repo=org/benign", "--note", "--repo=org/evil"][..],
        &["--note", "--note", "--repo=org/spoofed"][..],
        &["--note", "--", "--repo=org/spoofed"][..],
        &["--note", "-v", "--repo=org/spoofed"][..],
        &["--pr", "-5oops", "--repo=org/spoofed"][..],
        &["--NOTE", "hello", "--repo=org/spoofed"][..],
        &["--repo", "-5"][..],
    ] {
        assert_eq!(
            denial_resource_id(gh, &s(rejected)),
            "",
            "expected empty denial_resource_id for {rejected:?}"
        );
    }

    assert_eq!(
        denial_resource_id(gh, &s(&["--note", "hello", "--repo=org/real"])),
        "org/real"
    );
    assert_eq!(
        denial_resource_id(gh, &s(&["--squash", "--repo=org/real"])),
        "org/real"
    );
}

#[test]
fn denial_resource_id_validates_numeric_space_and_inline_values() {
    let numeric_policy_json = r#"{
        "commands": {
            "int-cmd": {
                "executable": "/usr/bin/true",
                "action": "num.adjust",
                "resource_kind": "slot",
                "resource_id_flag": "--id",
                "allowed_flags": {
                    "--id": { "kind": { "value": "int" }, "required": true }
                }
            },
            "dec-cmd": {
                "executable": "/usr/bin/true",
                "action": "num.adjust",
                "resource_kind": "slot",
                "resource_id_flag": "--delta",
                "allowed_flags": {
                    "--delta": { "kind": { "value": "decimal" }, "required": true }
                }
            }
        }
    }"#;
    let s = |items: &[&str]| -> Vec<String> { items.iter().map(|x| (*x).to_string()).collect() };
    let num_compiled = CliPolicyMap::from_json_str(numeric_policy_json)
        .expect("numeric policy")
        .compile()
        .expect("compile numeric");
    let int_cmd = num_compiled.get("int-cmd").unwrap();
    let dec_cmd = num_compiled.get("dec-cmd").unwrap();

    assert_eq!(denial_resource_id(int_cmd, &s(&["--id", "-5"])), "-5");
    assert_eq!(denial_resource_id(int_cmd, &s(&["--id=-5"])), "-5");
    assert_eq!(denial_resource_id(int_cmd, &s(&["--id", "-v"])), "");
    assert_eq!(denial_resource_id(int_cmd, &s(&["--id", "-5oops"])), "");
    assert_eq!(denial_resource_id(int_cmd, &s(&["--id=-5oops"])), "");

    assert_eq!(
        denial_resource_id(dec_cmd, &s(&["--delta", "-5.25"])),
        "-5.25"
    );
    assert_eq!(denial_resource_id(dec_cmd, &s(&["--delta=-5.25"])), "-5.25");
    assert_eq!(
        denial_resource_id(dec_cmd, &s(&["--delta", "-5.25oops"])),
        ""
    );
    assert_eq!(denial_resource_id(dec_cmd, &s(&["--delta=-5.25oops"])), "");
}
