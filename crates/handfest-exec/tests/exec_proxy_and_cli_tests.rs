use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use handfest_anchors::{Ed25519Keypair, SignedMandate, SignedRevocation};
use handfest_core::ast::{ActorDecl, KeyId, MandateId};
use handfest_core::cnl::{parse_mandate, render_canonical};
use handfest_core::exact_json::{parse_exact_json, ExactJson};
use handfest_core::policy::{FactType, TypedScalar};
use handfest_core::revocation::{render_canonical_revocation, RevocationAst, RevocationTarget};
use handfest_core::ActorKind;
use handfest_exec::{
    verify_mandate_chain, verify_revocations, CliPolicyMap, CommandExecutor, CommandPolicy,
    CredentialSource, ExecError, ExecOutcome, ExecOutput, ExecProxy, ExecSpec, FixedClock,
    FlagKind, FlagSpec, GateEngine, OsCommandExecutor, ProxyError, SecretError,
};
use handfest_ledger::SqliteLedger;
use tempfile::tempdir;

const VALID_FROM: i64 = 1_760_000_000;
const VALID_UNTIL: i64 = 1_760_086_400;
const NOW: i64 = 1_760_000_500;
const NOW_RFC3339: &str = "2025-10-09T09:01:40Z";

#[derive(Default)]
struct RecordingExecutor {
    calls: RefCell<Vec<ExecSpec>>,
    exit_code: i32,
}

impl RecordingExecutor {
    fn with_exit_code(exit_code: i32) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            exit_code,
        }
    }

    fn recorded(&self) -> Vec<ExecSpec> {
        self.calls.borrow().clone()
    }
}

impl CommandExecutor for RecordingExecutor {
    fn exec(&self, spec: &ExecSpec) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push(spec.clone());
        Ok(ExecOutput {
            exit_code: self.exit_code,
            stdout: b"ok\n".to_vec(),
            stderr: Vec::new(),
        })
    }
}

fn sign_mandate(signer: &Ed25519Keypair, text: &str) -> (MandateId, SignedMandate) {
    let ast = parse_mandate(text).expect("valid mandate");
    let id = ast.mandate_id();
    let canonical = render_canonical(&ast);
    let signed = signer
        .sign_mandate(&canonical, "local-ed25519", VALID_FROM, VALID_UNTIL)
        .expect("sign mandate");
    (id, signed)
}

fn sign_revocation(signer: &Ed25519Keypair, mandate_id: MandateId) -> SignedRevocation {
    let by = ActorDecl::new(
        ActorKind::Human,
        "Valentin",
        signer.key_id(),
        BTreeMap::new(),
    )
    .expect("actor");
    let rev_ast = RevocationAst::new(
        by,
        RevocationTarget::Mandate(mandate_id),
        VALID_FROM,
        Some("kill switch".to_string()),
    )
    .expect("revocation ast");
    let canonical = render_canonical_revocation(&rev_ast);
    signer
        .sign_revocation(&canonical, "local-ed25519", VALID_FROM, VALID_UNTIL)
        .expect("sign revocation")
}

fn write_secret_file(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, content).expect("write secret");
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
    let _ = mode;
    path
}

fn make_merge_policy(secret_path: PathBuf, pass_env: Vec<String>) -> CliPolicyMap {
    let mut commands = BTreeMap::new();
    commands.insert(
        "gh-pr-merge".to_string(),
        CommandPolicy {
            executable: PathBuf::from("/usr/bin/gh"),
            fixed_args: vec!["pr".to_string(), "merge".to_string()],
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_flag: Some("--repo".to_string()),
            static_resource_id: None,
            allowed_flags: BTreeMap::from([
                (
                    "--repo".to_string(),
                    FlagSpec {
                        kind: FlagKind::Value(FactType::Str),
                        fact_field: None,
                        required: true,
                    },
                ),
                (
                    "--amount".to_string(),
                    FlagSpec {
                        kind: FlagKind::Value(FactType::Decimal),
                        fact_field: Some("request.amount".to_string()),
                        required: false,
                    },
                ),
                (
                    "--squash".to_string(),
                    FlagSpec {
                        kind: FlagKind::BoolSwitch,
                        fact_field: Some("request.squash".to_string()),
                        required: false,
                    },
                ),
            ]),
            static_facts: BTreeMap::from([(
                "resource.environment".to_string(),
                TypedScalar::Str("staging".to_string()),
            )]),
            pass_env,
            env_secrets: BTreeMap::from([(
                "GH_TOKEN".to_string(),
                CredentialSource::File { path: secret_path },
            )]),
        },
    );
    CliPolicyMap { commands }
}

fn make_standard_mandate_text(human: &KeyId, agent: &KeyId, limit_clause: &str) -> String {
    format!(
        "HANDFEST v1\n\
         FROM human \"Valentin\" (key: {human})\n\
         TO agent \"Builder\" (key: {agent})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n\
         WHERE resource.environment == \"staging\"\n\
         AND request.squash == true\n\
         LIMIT {limit_clause}\n"
    )
}

#[test]
fn permit_injects_secrets_prepends_fixed_args_and_redacts_debug() {
    let dir = tempdir().expect("tempdir");
    let secret_path = write_secret_file(dir.path(), "gh.token", "ghp_topsecret_999\n", 0o600);
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("ledger");

    let human = Ed25519Keypair::from_secret_bytes([1u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([2u8; 32]);
    let (_, signed) = sign_mandate(
        &human,
        &make_standard_mandate_text(&human.key_id(), &agent.key_id(), "2 calls"),
    );
    let verified = verify_mandate_chain(&[signed]).expect("verify");
    let engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    let compiled = make_merge_policy(secret_path, vec!["PATH".to_string()])
        .compile()
        .expect("compile");

    let mut proxy = ExecProxy::new(engine, compiled, RecordingExecutor::with_exit_code(0));
    let outcome = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--squash".to_string()],
        )
        .expect("execute");

    let ExecOutcome::Permitted { output, .. } = outcome else {
        panic!("expected Permitted, got {outcome:?}");
    };
    assert_eq!(output.exit_code, 0);

    let specs = proxy.executor().recorded();
    assert_eq!(specs.len(), 1);
    let spec = &specs[0];
    assert_eq!(spec.executable, PathBuf::from("/usr/bin/gh"));
    assert_eq!(spec.args, vec!["pr", "merge", "--repo=org/app", "--squash"]);
    assert_eq!(
        spec.env.get("GH_TOKEN").map(String::as_str),
        Some("ghp_topsecret_999")
    );
    assert!(spec.env.contains_key("PATH"));
    assert!(!spec.env.contains_key("HOME"));

    let debug_str = format!("{spec:?}");
    assert!(!debug_str.contains("ghp_topsecret_999"));
    assert!(debug_str.contains("[REDACTED]"));

    assert_eq!(proxy.ledger().verify_integrity().expect("integrity"), 1);
}

#[test]
fn permit_with_unreadable_or_insecure_secret_fails_closed_without_executing() {
    let dir = tempdir().expect("tempdir");
    let bad_secret = write_secret_file(dir.path(), "open.token", "secret123\n", 0o644);
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("ledger");

    let human = Ed25519Keypair::from_secret_bytes([3u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([4u8; 32]);
    let (_, signed) = sign_mandate(
        &human,
        &make_standard_mandate_text(&human.key_id(), &agent.key_id(), "2 calls"),
    );
    let verified = verify_mandate_chain(&[signed]).expect("verify");
    let engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    let compiled = make_merge_policy(bad_secret, Vec::new())
        .compile()
        .expect("compile");

    let mut proxy = ExecProxy::new(engine, compiled, RecordingExecutor::default());
    let err = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--squash".to_string()],
        )
        .unwrap_err();

    #[cfg(unix)]
    assert!(matches!(
        err,
        ProxyError::Secret(SecretError::InsecurePermissions { mode: 0o644, .. })
    ));
    #[cfg(not(unix))]
    assert!(matches!(err, ProxyError::Secret(_)));

    assert!(proxy.executor().recorded().is_empty());
}

#[test]
fn deny_and_pre_gate_refusals_never_load_secrets_never_exec_and_preserve_quota() {
    let dir = tempdir().expect("tempdir");
    // Deliberately point at a missing secret file: if Deny ever tried to load secrets, we would
    // get Err(ProxyError::Secret(_)) instead of Ok(ExecOutcome::Denied { .. }).
    let missing_secret = dir.path().join("does_not_exist.token");
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("ledger");

    let human = Ed25519Keypair::from_secret_bytes([5u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([6u8; 32]);
    let (_, signed) = sign_mandate(
        &human,
        &make_standard_mandate_text(&human.key_id(), &agent.key_id(), "1 calls"),
    );
    let verified = verify_mandate_chain(&[signed]).expect("verify");
    let engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    let compiled = make_merge_policy(missing_secret, Vec::new())
        .compile()
        .expect("compile");

    let mut proxy = ExecProxy::new(engine, compiled, RecordingExecutor::default());

    let d1 = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--admin".to_string()],
        )
        .expect("pre-gate deny unknown flag");
    assert!(
        matches!(d1, ExecOutcome::Denied { ref reason, .. } if reason.contains("unknown flag"))
    );

    let d2 = proxy
        .execute(
            "gh-pr-merge",
            &[
                "--repo=org/app".to_string(),
                "--".to_string(),
                "--squash".to_string(),
            ],
        )
        .expect("pre-gate deny smuggling");
    assert!(matches!(d2, ExecOutcome::Denied { ref reason, .. } if reason.contains("smuggling")));

    let d3 = proxy
        .execute("rm-rf", &[])
        .expect("pre-gate deny unmapped command");
    assert!(matches!(d3, ExecOutcome::Denied { ref reason, .. } if reason.contains("unmapped")));

    let d4 = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=evil/repo".to_string(), "--squash".to_string()],
        )
        .expect("gate deny resource");
    assert!(matches!(d4, ExecOutcome::Denied { .. }));

    let d5 = proxy
        .execute("gh-pr-merge", &["--repo=org/app".to_string()])
        .expect("gate deny predicate");
    assert!(matches!(d5, ExecOutcome::Denied { .. }));

    assert!(proxy.executor().recorded().is_empty());

    // Create secret file now; 1-call quota must still be intact.
    write_secret_file(dir.path(), "does_not_exist.token", "ghp_fresh\n", 0o600);
    let p1 = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--squash".to_string()],
        )
        .expect("permitted call");
    assert!(matches!(p1, ExecOutcome::Permitted { .. }));
    assert_eq!(proxy.executor().recorded().len(), 1);

    let d6 = proxy
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--squash".to_string()],
        )
        .expect("quota deny");
    assert!(matches!(d6, ExecOutcome::Denied { .. }));
    assert_eq!(proxy.executor().recorded().len(), 1);

    assert_eq!(proxy.ledger().verify_integrity().expect("integrity"), 7);
}

#[test]
fn decimal_sum_quota_and_revocation_precedence_enforced() {
    let dir = tempdir().expect("tempdir");
    let secret_path = write_secret_file(dir.path(), "tok", "tok_val\n", 0o600);
    let ledger = SqliteLedger::open(dir.path().join("ledger.sqlite")).expect("ledger");

    let human = Ed25519Keypair::from_secret_bytes([7u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([8u8; 32]);
    let (mandate_id, signed) = sign_mandate(
        &human,
        &make_standard_mandate_text(
            &human.key_id(),
            &agent.key_id(),
            "100.00 USD sum(request.amount)",
        ),
    );
    let verified = verify_mandate_chain(&[signed]).expect("verify");
    let engine =
        GateEngine::new(verified, agent.key_id(), ledger, FixedClock::new(NOW)).expect("engine");
    let compiled = make_merge_policy(secret_path, Vec::new())
        .compile()
        .expect("compile");

    let mut proxy = ExecProxy::new(engine, compiled, RecordingExecutor::default());

    let p1 = proxy
        .execute(
            "gh-pr-merge",
            &[
                "--repo=org/app".to_string(),
                "--squash".to_string(),
                "--amount=40.50".to_string(),
            ],
        )
        .expect("p1");
    assert!(matches!(p1, ExecOutcome::Permitted { .. }));

    let p2 = proxy
        .execute(
            "gh-pr-merge",
            &[
                "--repo=org/app".to_string(),
                "--squash".to_string(),
                "--amount=59.50".to_string(),
            ],
        )
        .expect("p2");
    assert!(matches!(p2, ExecOutcome::Permitted { .. }));

    let d_over = proxy
        .execute(
            "gh-pr-merge",
            &[
                "--repo=org/app".to_string(),
                "--squash".to_string(),
                "--amount=0.01".to_string(),
            ],
        )
        .expect("over quota");
    assert!(matches!(d_over, ExecOutcome::Denied { .. }));
    assert_eq!(proxy.executor().recorded().len(), 2);

    // Revocation enforcement + pre-gate precedence.
    let _ = mandate_id;
    let (mandate_id2, signed2) = sign_mandate(
        &human,
        &make_standard_mandate_text(&human.key_id(), &agent.key_id(), "5 calls"),
    );
    let rev = sign_revocation(&human, mandate_id2);
    let rev_snapshot = verify_revocations(&[rev]).expect("verify rev");
    let verified2 = verify_mandate_chain(&[signed2]).expect("verify2");
    let ledger2 = SqliteLedger::open(dir.path().join("ledger2.sqlite")).expect("ledger2");
    let engine2 = GateEngine::new(verified2, agent.key_id(), ledger2, FixedClock::new(NOW))
        .expect("engine2")
        .with_revocations(rev_snapshot);
    let missing = dir.path().join("never_loaded.tok");
    let compiled2 = make_merge_policy(missing, Vec::new())
        .compile()
        .expect("compile2");
    let mut proxy2 = ExecProxy::new(engine2, compiled2, RecordingExecutor::default());

    let d_rev = proxy2
        .execute(
            "gh-pr-merge",
            &["--repo=org/app".to_string(), "--squash".to_string()],
        )
        .expect("revoked deny");
    assert!(matches!(d_rev, ExecOutcome::Denied { ref reason, .. } if reason.contains("revoked")));

    let d_rev_pregate = proxy2
        .execute("gh-pr-merge", &["--unknown".to_string()])
        .expect("revoked pre-gate");
    assert!(
        matches!(d_rev_pregate, ExecOutcome::Denied { ref reason, .. } if reason.contains("revoked"))
    );
    assert!(proxy2.executor().recorded().is_empty());
}

#[test]
fn os_command_executor_enforces_absolute_path_and_env_clear() {
    let exec = OsCommandExecutor;

    let rel_err = exec
        .exec(&ExecSpec {
            executable: PathBuf::from("env"),
            args: Vec::new(),
            env: BTreeMap::new(),
        })
        .unwrap_err();
    assert_eq!(rel_err, ExecError::RelativeExecutable(PathBuf::from("env")));

    let missing_err = exec
        .exec(&ExecSpec {
            executable: PathBuf::from("/nonexistent/handfest/binary"),
            args: Vec::new(),
            env: BTreeMap::new(),
        })
        .unwrap_err();
    assert!(matches!(missing_err, ExecError::SpawnFailed { .. }));

    let out = exec
        .exec(&ExecSpec {
            executable: PathBuf::from("/usr/bin/env"),
            args: Vec::new(),
            env: BTreeMap::from([("ONLY_THIS".to_string(), "exact_value".to_string())]),
        })
        .expect("run /usr/bin/env");
    assert_eq!(out.exit_code, 0);
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf8").trim(),
        "ONLY_THIS=exact_value"
    );

    let fail_out = exec
        .exec(&ExecSpec {
            executable: PathBuf::from("/bin/false"),
            args: Vec::new(),
            env: BTreeMap::new(),
        })
        .expect("run /bin/false");
    assert_eq!(fail_out.exit_code, 1);
}

struct E2eFixture {
    _dir: tempfile::TempDir,
    ledger_path: PathBuf,
    chain_path: PathBuf,
    rev_path: PathBuf,
    policy_path: PathBuf,
    agent_key: KeyId,
}

fn setup_e2e_fixture(limit_clause: &str) -> E2eFixture {
    let dir = tempdir().expect("tempdir");
    let ledger_path = dir.path().join("ledger.sqlite");
    let chain_path = dir.path().join("mandate.json");
    let rev_path = dir.path().join("revocation.json");
    let policy_path = dir.path().join("policy.json");
    let secret_path = write_secret_file(dir.path(), "api.secret", "super_secret_token\n", 0o600);

    let human = Ed25519Keypair::from_secret_bytes([21u8; 32]);
    let agent = Ed25519Keypair::from_secret_bytes([22u8; 32]);
    let (mandate_id, signed) = sign_mandate(
        &human,
        &make_standard_mandate_text(&human.key_id(), &agent.key_id(), limit_clause),
    );
    fs::write(&chain_path, serde_json::to_string_pretty(&signed).unwrap()).expect("write mandate");

    let signed_rev = sign_revocation(&human, mandate_id);
    fs::write(
        &rev_path,
        serde_json::to_string_pretty(&signed_rev).unwrap(),
    )
    .expect("write rev");

    let probe_script = "import json, os, sys; \
        print(json.dumps({'argv': sys.argv[1:], 'env': dict(os.environ)})); \
        sys.stderr.write('child-stderr\\n'); \
        sys.exit(7)";
    let policy = CliPolicyMap {
        commands: BTreeMap::from([(
            "probe".to_string(),
            CommandPolicy {
                executable: PathBuf::from("/usr/bin/python3"),
                fixed_args: vec!["-c".to_string(), probe_script.to_string()],
                action: "git.pr.merge".to_string(),
                resource_kind: "repo".to_string(),
                resource_id_flag: Some("--repo".to_string()),
                static_resource_id: None,
                allowed_flags: BTreeMap::from([
                    (
                        "--repo".to_string(),
                        FlagSpec {
                            kind: FlagKind::Value(FactType::Str),
                            fact_field: None,
                            required: true,
                        },
                    ),
                    (
                        "--squash".to_string(),
                        FlagSpec {
                            kind: FlagKind::BoolSwitch,
                            fact_field: Some("request.squash".to_string()),
                            required: false,
                        },
                    ),
                ]),
                static_facts: BTreeMap::from([(
                    "resource.environment".to_string(),
                    TypedScalar::Str("staging".to_string()),
                )]),
                pass_env: vec!["ALLOWED_PASS".to_string()],
                env_secrets: BTreeMap::from([(
                    "INJECTED_SECRET".to_string(),
                    CredentialSource::File { path: secret_path },
                )]),
            },
        )]),
    };
    fs::write(&policy_path, serde_json::to_string_pretty(&policy).unwrap()).expect("write policy");

    E2eFixture {
        _dir: dir,
        ledger_path,
        chain_path,
        rev_path,
        policy_path,
        agent_key: agent.key_id(),
    }
}

#[test]
fn handfest_exec_binary_e2e_permit_env_isolation_and_quota_deny() {
    let fx = setup_e2e_fixture("1 calls");
    let bin = env!("CARGO_BIN_EXE_handfest-exec");

    let out = Command::new(bin)
        .env("AMBIENT_LEAK", "must_not_reach_child")
        .env("ALLOWED_PASS", "passed_value")
        .args([
            "--ledger",
            fx.ledger_path.to_str().unwrap(),
            "--chain",
            fx.chain_path.to_str().unwrap(),
            "--actor-key",
            &fx.agent_key.to_string(),
            "--policy-map",
            fx.policy_path.to_str().unwrap(),
            "--now",
            NOW_RFC3339,
            "--command",
            "probe",
            "--",
            "--repo",
            "org/app",
            "--squash",
        ])
        .output()
        .expect("spawn handfest-exec");

    assert_eq!(out.status.code(), Some(7));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "child-stderr\n");
    let parsed = parse_exact_json(String::from_utf8(out.stdout).unwrap().trim()).expect("json");
    let root = parsed.as_object().expect("probe object");
    assert_eq!(
        root.get("argv"),
        Some(&ExactJson::Array(vec![
            ExactJson::Str("--repo=org/app".to_string()),
            ExactJson::Str("--squash".to_string()),
        ]))
    );
    let env_obj = root
        .get("env")
        .and_then(ExactJson::as_object)
        .expect("env object");
    assert_eq!(
        env_obj.get("INJECTED_SECRET"),
        Some(&ExactJson::Str("super_secret_token".to_string()))
    );
    assert_eq!(
        env_obj.get("ALLOWED_PASS"),
        Some(&ExactJson::Str("passed_value".to_string()))
    );
    assert!(!env_obj.contains_key("AMBIENT_LEAK"));

    // Second invocation hits 1-call quota -> non-zero exit + structured JSON on stderr.
    let denied = Command::new(bin)
        .args([
            "--ledger",
            fx.ledger_path.to_str().unwrap(),
            "--chain",
            fx.chain_path.to_str().unwrap(),
            "--actor-key",
            &fx.agent_key.to_string(),
            "--policy-map",
            fx.policy_path.to_str().unwrap(),
            "--now",
            NOW_RFC3339,
            "--command",
            "probe",
            "--",
            "--repo=org/app",
            "--squash",
        ])
        .output()
        .expect("spawn quota denied");
    assert_eq!(denied.status.code(), Some(1));
    assert!(denied.stdout.is_empty());
    let denied_json =
        parse_exact_json(String::from_utf8(denied.stderr).unwrap().trim()).expect("denied json");
    let denied_obj = denied_json.as_object().expect("denied object");
    assert_eq!(
        denied_obj.get("error"),
        Some(&ExactJson::Str("handfest_denied".to_string()))
    );
    let denied_reason = denied_obj
        .get("reason")
        .and_then(ExactJson::as_str)
        .expect("denial reason string");
    assert!(
        denied_reason.to_ascii_lowercase().contains("quota"),
        "expected quota denial reason, got '{denied_reason}'"
    );
    let denied_hash = denied_obj
        .get("receipt_hash")
        .and_then(ExactJson::as_str)
        .expect("denial receipt_hash string");
    assert!(denied_hash.starts_with("sha256:"));

    assert_persisted_deny(&fx.ledger_path, 2, 1, denied_hash, denied_reason);
}

#[test]
fn handfest_exec_binary_e2e_revocation_and_cli_error_surfaces() {
    let fx = setup_e2e_fixture("5 calls");
    let bin = env!("CARGO_BIN_EXE_handfest-exec");

    let revoked = Command::new(bin)
        .args([
            "--ledger",
            fx.ledger_path.to_str().unwrap(),
            "--chain",
            fx.chain_path.to_str().unwrap(),
            "--actor-key",
            &fx.agent_key.to_string(),
            "--policy-map",
            fx.policy_path.to_str().unwrap(),
            "--revocation",
            fx.rev_path.to_str().unwrap(),
            "--now",
            NOW_RFC3339,
            "--command",
            "probe",
            "--",
            "--repo=org/app",
            "--squash",
        ])
        .output()
        .expect("spawn revoked");
    assert_eq!(revoked.status.code(), Some(1));
    assert!(revoked.stdout.is_empty());
    let rev_json =
        parse_exact_json(String::from_utf8(revoked.stderr).unwrap().trim()).expect("rev json");
    let rev_obj = rev_json.as_object().expect("rev object");
    assert_eq!(
        rev_obj.get("error"),
        Some(&ExactJson::Str("handfest_denied".to_string()))
    );
    assert!(rev_obj
        .get("reason")
        .and_then(ExactJson::as_str)
        .is_some_and(|r| r.contains("revoked")));

    let ledger = SqliteLedger::open(&fx.ledger_path).expect("reopen ledger");
    assert_eq!(ledger.verify_integrity().expect("integrity"), 1);

    let help = Command::new(bin).arg("--help").output().expect("help");
    assert_eq!(help.status.code(), Some(0));

    let bad_cli = Command::new(bin).output().expect("missing args");
    assert_eq!(bad_cli.status.code(), Some(1));
    let bad_json =
        parse_exact_json(String::from_utf8_lossy(&bad_cli.stderr).trim()).expect("cli error json");
    assert_eq!(
        bad_json.as_object().and_then(|o| o.get("code")),
        Some(&ExactJson::Str("cli_args".to_string()))
    );
}

#[test]
fn env_credential_source_through_exec_proxy_injects_and_fails_closed_when_missing() {
    let dir = tempdir().expect("tempdir");
    let human = Ed25519Keypair::generate();
    let agent = Ed25519Keypair::generate();
    let mandate_text = make_standard_mandate_text(&human.key_id(), &agent.key_id(), "5 calls");
    let (_, signed) = sign_mandate(&human, &mandate_text);
    let verified = verify_mandate_chain(&[signed]).expect("verify chain");

    let env_var_name = "HANDFEST_EXEC_TEST_CRED_ENV_SOURCE";
    std::env::set_var(env_var_name, "env_secret_value_42");

    let mut policy = make_merge_policy(dir.path().join("unused.secret"), vec![]);
    policy
        .commands
        .get_mut("gh-pr-merge")
        .unwrap()
        .env_secrets
        .insert(
            "GH_TOKEN".to_string(),
            CredentialSource::Env {
                var: env_var_name.to_string(),
            },
        );
    let compiled = policy.compile().expect("compile policy with env source");

    let ledger = SqliteLedger::open(dir.path().join("env.sqlite")).expect("open ledger");
    let engine = GateEngine::new(
        verified.clone(),
        agent.key_id(),
        ledger,
        FixedClock::new(NOW),
    )
    .expect("engine");
    let mut proxy = ExecProxy::new(engine, compiled, RecordingExecutor::default());

    let outcome = proxy
        .execute("gh-pr-merge", &["--repo=org/app".into(), "--squash".into()])
        .expect("permit with env secret");
    assert!(matches!(outcome, ExecOutcome::Permitted { .. }));
    let calls = proxy.executor().recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].env.get("GH_TOKEN").map(String::as_str),
        Some("env_secret_value_42")
    );

    // Removing the env var causes fail-closed SecretError::MissingEnvVar without invoking executor.
    std::env::remove_var(env_var_name);
    let err = proxy
        .execute("gh-pr-merge", &["--repo=org/app".into(), "--squash".into()])
        .expect_err("missing env secret must fail closed");
    assert!(matches!(
        err,
        ProxyError::Secret(SecretError::MissingEnvVar(ref v)) if v == env_var_name
    ));
    assert_eq!(proxy.executor().recorded().len(), 1);
}

#[test]
fn handfest_exec_binary_e2e_system_clock_denies_expired_mandate() {
    let fx = setup_e2e_fixture("5 calls");
    // Overwrite mandate with one expired in 2001 so SystemClock always denies without --now.
    let human = Ed25519Keypair::generate();
    let agent = Ed25519Keypair::generate();
    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Alice\" (key: {})\n\
         TO agent \"Bot\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW git.pr.merge\n\
         ON repo \"org/*\"\n\
         LIMIT 5 calls\n",
        human.key_id(),
        agent.key_id()
    );
    let ast = parse_mandate(&text).expect("valid mandate");
    let expired_signed = human
        .sign_mandate(
            &render_canonical(&ast),
            "anchor:local-ed25519",
            1_000_000_000,
            1_000_086_400,
        )
        .expect("sign expired mandate");
    fs::write(
        &fx.chain_path,
        serde_json::to_string_pretty(&expired_signed).unwrap(),
    )
    .expect("write expired mandate");

    let bin = env!("CARGO_BIN_EXE_handfest-exec");
    let out = Command::new(bin)
        .args([
            "--ledger",
            fx.ledger_path.to_str().unwrap(),
            "--chain",
            fx.chain_path.to_str().unwrap(),
            "--actor-key",
            &agent.key_id().to_string(),
            "--policy-map",
            fx.policy_path.to_str().unwrap(),
            "--command",
            "probe",
            "--",
            "--repo=org/app",
            "--squash",
        ])
        .output()
        .expect("spawn expired system-clock run");

    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let parsed = parse_exact_json(String::from_utf8_lossy(&out.stderr).trim()).expect("json");
    let obj = parsed.as_object().expect("object");
    assert_eq!(
        obj.get("error"),
        Some(&ExactJson::Str("handfest_denied".to_string()))
    );
    let reason = obj
        .get("reason")
        .and_then(ExactJson::as_str)
        .expect("reason");
    assert!(
        reason.contains("outside anchor proof validity window"),
        "expected expired reason, got '{reason}'"
    );
    let hash = obj
        .get("receipt_hash")
        .and_then(ExactJson::as_str)
        .expect("receipt_hash");
    assert_persisted_deny(&fx.ledger_path, 1, 0, hash, reason);
}

fn assert_persisted_deny(
    ledger_path: &Path,
    expected_len: usize,
    idx: usize,
    expected_hash: &str,
    expected_reason: &str,
) {
    let receipts = SqliteLedger::open_existing(ledger_path)
        .expect("reopen ledger")
        .list_receipts()
        .expect("list receipts");
    assert_eq!(receipts.len(), expected_len);
    assert_eq!(receipts[idx].receipt_hash.to_string(), expected_hash);
    assert_eq!(
        receipts[idx].verdict,
        handfest_core::Verdict::Deny {
            reason: expected_reason.to_string()
        }
    );
}
