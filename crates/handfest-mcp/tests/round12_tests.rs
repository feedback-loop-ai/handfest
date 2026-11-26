//! Round 12 integration tests: structured JSON startup errors on `stderr` in `handfest-mcp`.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_core::ast::parse_rfc3339_utc;
use handfest_core::cnl::parse_canonical;
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

fn wait_for_child_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let mut stdout_pipe = child.stdout.take().expect("child stdout must be piped");
    let mut stderr_pipe = child.stderr.take().expect("child stderr must be piped");
    let stdout_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout_pipe
            .read_to_end(&mut buf)
            .expect("read child stdout");
        buf
    });
    let stderr_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr_pipe
            .read_to_end(&mut buf)
            .expect("read child stderr");
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll child exit status") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            drop(child.stdin.take());
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            panic!(
                "handfest-mcp did not exit within {}s on malformed upstream output",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(20));
    };

    drop(child.stdin.take());
    let stdout_bytes = stdout_thread.join().expect("join stdout reader thread");
    let stderr_bytes = stderr_thread.join().expect("join stderr reader thread");
    (status, stdout_bytes, stderr_bytes)
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
    let child = Command::new(env!("CARGO_BIN_EXE_handfest-mcp"))
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
            env!("CARGO_BIN_EXE_handfest-mcp"),
            "--help",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep child stdin open without writing so the test neither races with BrokenPipe
    // after the proxy exits on malformed upstream output nor triggers clean client EOF.
    // Bound the wait so a regression that discards malformed upstream lines fails fast
    // and reaps the child instead of hanging indefinitely.
    let (status, _stdout_bytes, stderr_bytes) =
        wait_for_child_with_timeout(child, Duration::from_secs(5));
    assert!(!status.success());
    let (code, msg) = parse_startup_error_json(&stderr_bytes);
    assert_eq!(code, "runtime_error");
    assert!(
        msg.contains("upstream MCP protocol error: invalid upstream JSON"),
        "expected malformed upstream JSON error, got: {msg}"
    );
    codes.insert(code);

    assert_eq!(codes.len(), 3);
}

#[test]
fn handfest_mcp_emits_chain_invalid_for_tampered_signature() {
    let dir = tempdir().unwrap();
    let f = write_valid_fixtures(dir.path());
    let policy = f.policy.to_str().unwrap();
    let ledger = f.ledger.to_str().unwrap();

    // Valid SignedMandate JSON with tampered signature -> fails in verify_mandate_chain_with.
    let mut tampered: SignedMandate =
        serde_json::from_str(&fs::read_to_string(&f.chain).unwrap()).unwrap();
    let flipped = if tampered.signature_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered.signature_hex.replace_range(0..1, flipped);
    let tampered_chain = dir.path().join("tampered.signed.json");
    fs::write(&tampered_chain, serde_json::to_string(&tampered).unwrap()).unwrap();
    let (code, msg) = run_expect_failure(&[
        "--chain",
        tampered_chain.to_str().unwrap(),
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
    assert!(
        msg.contains("startup mandate chain verification failed")
            && msg.contains("invalid anchor signature"),
        "expected verifier failure detail, got: {msg}"
    );
}

#[test]
fn handfest_mcp_emits_chain_invalid_for_broken_attenuation() {
    let dir = tempdir().unwrap();
    let f = write_valid_fixtures(dir.path());
    let policy = f.policy.to_str().unwrap();
    let ledger = f.ledger.to_str().unwrap();

    // Validly signed 2-hop chain with widened child action -> fails attenuation in verify_mandate_chain_with.
    let root_kp = Ed25519Keypair::generate();
    let mid_kp = Ed25519Keypair::generate();
    let leaf_kp = Ed25519Keypair::generate();
    let valid_from = parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap();
    let valid_until = parse_rfc3339_utc("2027-01-01T00:00:00Z").unwrap();
    let root_text = format!(
        "HANDFEST v1\n\
         FROM human \"Root\" (key: {})\n\
         TO agent \"Mid\" (key: {})\n\
         DELEGATION max 1 hop\n\
         ALLOW ops.run\n\
         ON target \"staging\"\n",
        root_kp.key_id(),
        mid_kp.key_id(),
    );
    let root_id = parse_canonical(&root_text)
        .unwrap()
        .try_mandate_id()
        .unwrap();
    let root_signed = root_kp
        .sign_mandate(&root_text, "r13-attenuation-root", valid_from, valid_until)
        .unwrap();
    let widened_child_text = format!(
        "HANDFEST v1\n\
         PARENT {root_id}\n\
         FROM agent \"Mid\" (key: {})\n\
         TO agent \"Leaf\" (key: {})\n\
         DELEGATION max 0 hops\n\
         ALLOW ops.*\n\
         ON target \"staging\"\n",
        mid_kp.key_id(),
        leaf_kp.key_id(),
    );
    let child_signed = mid_kp
        .sign_mandate(
            &widened_child_text,
            "r13-attenuation-child",
            valid_from,
            valid_until,
        )
        .unwrap();
    let atten_root_path = dir.path().join("atten-root.signed.json");
    let atten_child_path = dir.path().join("atten-child.signed.json");
    fs::write(
        &atten_root_path,
        serde_json::to_string(&root_signed).unwrap(),
    )
    .unwrap();
    fs::write(
        &atten_child_path,
        serde_json::to_string(&child_signed).unwrap(),
    )
    .unwrap();
    let leaf_actor = leaf_kp.key_id().to_string();
    let (code, msg) = run_expect_failure(&[
        "--chain",
        atten_root_path.to_str().unwrap(),
        atten_child_path.to_str().unwrap(),
        "--ledger",
        ledger,
        "--actor-key",
        &leaf_actor,
        "--policy-map",
        policy,
        "--",
        "true",
    ]);
    assert_eq!(code, "chain_invalid");
    assert_eq!(
        msg,
        "startup mandate chain verification failed: invalid mandate chain: hop 0 -> 1: attenuation check failed: action 'ops.*' is not subsumed by parent ALLOW list",
        "expected hop 0 -> 1 action-widening detail for ops.*, got: {msg}"
    );
}
