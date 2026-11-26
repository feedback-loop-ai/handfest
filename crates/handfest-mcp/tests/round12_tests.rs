//! Round 12 integration tests: structured JSON startup errors on `stderr` in `handfest-mcp`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use handfest_anchors::Ed25519Keypair;
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::exact_json::{parse_exact_json, ExactJson};
use tempfile::tempdir;

struct Fixtures {
    chain: PathBuf,
    policy: PathBuf,
    ledger: PathBuf,
    actor_key: String,
}

fn parse_startup_error_json(stderr: &[u8]) -> (String, String) {
    let text = String::from_utf8(stderr.to_vec()).expect("stderr must be valid UTF-8");
    let trimmed = text.trim();
    assert!(
        !trimmed.contains('\n'),
        "startup error on stderr must be a single JSON line, got: {trimmed:?}"
    );
    let parsed = parse_exact_json(trimmed)
        .unwrap_or_else(|err| panic!("stderr must be valid JSON ({err}): {trimmed:?}"));
    let obj = parsed
        .as_object()
        .expect("startup error JSON must be an object");
    assert_eq!(obj.len(), 3, "unexpected extra keys in {trimmed}");
    assert_eq!(
        obj.get("error"),
        Some(&ExactJson::Str("startup_failed".to_string())),
        "unexpected error field in {trimmed}"
    );
    let code = obj
        .get("code")
        .and_then(ExactJson::as_str)
        .expect("code must be a string")
        .to_string();
    let message = obj
        .get("message")
        .and_then(ExactJson::as_str)
        .expect("message must be a string")
        .to_string();
    assert!(!message.is_empty(), "message must not be empty");
    (code, message)
}

fn write_valid_fixtures(dir: &Path) -> Fixtures {
    let root_kp = Ed25519Keypair::generate();
    let agent_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let text = format!(
        "HANDFEST v1\n\
         FROM human \"Root\" (key: {})\n\
         TO agent \"Agent\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW ops.run\n\
         ON target \"staging\"\n",
        root_kp.key_id(),
        agent_kp.key_id(),
    );
    let signed = root_kp
        .sign_mandate(&text, "r12-test", valid_from, valid_until)
        .unwrap();
    let chain = dir.join("root.signed.json");
    fs::write(&chain, serde_json::to_string(&signed).unwrap()).unwrap();

    let policy = dir.join("policy.json");
    fs::write(&policy, r#"{"tools":{}}"#).unwrap();

    let ledger = dir.join("ledger.sqlite");
    Fixtures {
        chain,
        policy,
        ledger,
        actor_key: agent_kp.key_id().to_string(),
    }
}

fn run_expect_failure(args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args(args)
        .output()
        .expect("run handfest-mcp");
    assert!(!out.status.success(), "expected non-zero exit for {args:?}");
    parse_startup_error_json(&out.stderr)
}

#[test]
fn handfest_mcp_emits_structured_json_for_cli_args_errors() {
    let dir = tempdir().unwrap();
    let f = write_valid_fixtures(dir.path());
    let chain = f.chain.to_str().unwrap();
    let policy = f.policy.to_str().unwrap();
    let ledger = f.ledger.to_str().unwrap();

    // --version still exits cleanly without emitting an error payload.
    let version_out = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version_out.status.success());

    let (code, _) = run_expect_failure(&[]);
    assert_eq!(code, "cli_args");

    let (code, msg) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        ledger,
        "--actor-key",
        "not-a-key",
        "--policy-map",
        policy,
        "--",
        "true",
    ]);
    assert_eq!(code, "cli_args");
    assert!(msg.contains("--actor-key"));

    let (code, msg) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        policy,
        "--now",
        "not-a-timestamp",
        "--",
        "true",
    ]);
    assert_eq!(code, "cli_args");
    assert!(msg.contains("--now"));
}

#[test]
fn handfest_mcp_emits_structured_json_for_chain_and_policy_errors() {
    let dir = tempdir().unwrap();
    let f = write_valid_fixtures(dir.path());
    let chain = f.chain.to_str().unwrap();
    let policy = f.policy.to_str().unwrap();
    let ledger = f.ledger.to_str().unwrap();
    let mut codes = BTreeSet::new();

    let missing_chain = dir.path().join("missing.signed.json");
    let (code, _) = run_expect_failure(&[
        "--chain",
        missing_chain.to_str().unwrap(),
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        policy,
        "--",
        "true",
    ]);
    assert_eq!(code, "chain_io");
    codes.insert(code);

    let bad_chain = dir.path().join("bad.signed.json");
    fs::write(&bad_chain, "{not json").unwrap();
    let (code, _) = run_expect_failure(&[
        "--chain",
        bad_chain.to_str().unwrap(),
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        policy,
        "--",
        "true",
    ]);
    assert_eq!(code, "chain_invalid");
    codes.insert(code);

    let missing_policy = dir.path().join("missing-policy.json");
    let (code, _) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        missing_policy.to_str().unwrap(),
        "--",
        "true",
    ]);
    assert_eq!(code, "policy_io");
    codes.insert(code);

    let bad_policy = dir.path().join("bad-policy.json");
    fs::write(&bad_policy, r#"{"tools":{"x":{"action":"bad.*"}}}"#).unwrap();
    let (code, _) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        bad_policy.to_str().unwrap(),
        "--",
        "true",
    ]);
    assert_eq!(code, "policy_invalid");
    codes.insert(code);

    assert_eq!(codes.len(), 4);
}

#[test]
fn handfest_mcp_emits_structured_json_for_ledger_spawn_and_runtime_errors() {
    let dir = tempdir().unwrap();
    let f = write_valid_fixtures(dir.path());
    let chain = f.chain.to_str().unwrap();
    let policy = f.policy.to_str().unwrap();
    let ledger = f.ledger.to_str().unwrap();
    let mut codes = BTreeSet::new();

    // Directory passed as SQLite ledger path -> "ledger_open".
    let dir_ledger = dir.path().join("ledger_dir");
    fs::create_dir(&dir_ledger).unwrap();
    let (code, _) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        dir_ledger.to_str().unwrap(),
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        policy,
        "--",
        "true",
    ]);
    assert_eq!(code, "ledger_open");
    codes.insert(code);

    // Missing upstream executable -> "upstream_spawn".
    let (code, _) = run_expect_failure(&[
        "--chain",
        chain,
        "--ledger",
        ledger,
        "--actor-key",
        &f.actor_key,
        "--policy-map",
        policy,
        "--",
        "/nonexistent/handfest-mcp-missing-upstream-binary",
    ]);
    assert_eq!(code, "upstream_spawn");
    codes.insert(code);

    // Malformed upstream response during active session -> "runtime_error".
    let mut child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
        .args([
            "--chain",
            chain,
            "--ledger",
            ledger,
            "--actor-key",
            &f.actor_key,
            "--policy-map",
            policy,
            "--",
            "sh",
            "-c",
            "read line; printf 'not-valid-json\\n'",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let (code, _) = parse_startup_error_json(&out.stderr);
    assert_eq!(code, "runtime_error");
    codes.insert(code);

    assert_eq!(codes.len(), 3);
}
