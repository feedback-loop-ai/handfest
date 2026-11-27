//! End-to-end binary tests for `handfest request` talking to a live `ApproverDaemon` Unix socket.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

use handfest_anchors::{Ed25519Keypair, SignedMandate};
use handfest_approver::daemon::{ApproverDaemon, BoundSocket, SocketMode};
use handfest_approver::prompt::{ApprovalOutcome, ApprovalPrompt, PromptError, WysiwysPromptView};
use handfest_core::ast::KeyId;
use handfest_core::cnl::{parse_mandate, try_render_canonical};

struct FixedPrompt(ApprovalOutcome);

impl ApprovalPrompt for FixedPrompt {
    fn prompt(&mut self, _view: &WysiwysPromptView) -> Result<ApprovalOutcome, PromptError> {
        Ok(self.0.clone())
    }
}

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn draft_for(from_key: &KeyId) -> String {
    let agent = KeyId::new("ed25519", "b".repeat(64)).unwrap();
    format!(
        "HANDFEST v1  \nFROM human \"Valentin\" (key: {from_key})\nTO agent \"Bot\" (key: {agent})\nDELEGATION max 0 hops\nALLOW git.pr.merge, git.branch.create\nON repo \"org/app\"\n"
    )
}

fn restricted_tempdir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn handfest_request_writes_verified_signed_mandate_on_approval() {
    let dir = restricted_tempdir();
    let sock_path = dir.path().join("approver.sock");
    let draft_path = dir.path().join("draft.hf");
    let out_path = dir.path().join("signed.json");

    let kp = Ed25519Keypair::from_secret_bytes([0x88; 32]);
    let draft = draft_for(&kp.key_id());
    fs::write(&draft_path, &draft).unwrap();

    let expected_ast = parse_mandate(&draft).unwrap();
    let expected_canonical = try_render_canonical(&expected_ast).unwrap();
    let expected_id = expected_ast.try_mandate_id().unwrap();

    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let mut daemon = ApproverDaemon::new(
        kp,
        FixedPrompt(ApprovalOutcome::Approved),
        "local-ed25519",
        Duration::from_secs(10),
    )
    .unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
    });

    let output = handfest_bin()
        .args([
            "request",
            "--socket",
            sock_path.to_str().unwrap(),
            "--mandate",
            draft_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("run handfest request");
    server.join().unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        expected_id.to_string()
    );

    let signed: SignedMandate =
        serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(signed.canonical_words, expected_canonical);

    // Written SignedMandate also verifies cleanly with `handfest verify`.
    let verify = handfest_bin()
        .args(["verify", out_path.to_str().unwrap()])
        .output()
        .expect("run handfest verify");
    assert!(
        verify.status.success(),
        "verify stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn handfest_request_exits_nonzero_on_denial_and_never_writes_out_file() {
    let dir = restricted_tempdir();
    let sock_path = dir.path().join("approver.sock");
    let draft_path = dir.path().join("draft.hf");
    let out_path = dir.path().join("signed.json");

    let kp = Ed25519Keypair::from_secret_bytes([0x99; 32]);
    fs::write(&draft_path, draft_for(&kp.key_id())).unwrap();

    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let mut daemon = ApproverDaemon::new(
        kp,
        FixedPrompt(ApprovalOutcome::Denied {
            reason: "operator said no".to_string(),
        }),
        "local-ed25519",
        Duration::from_secs(10),
    )
    .unwrap();

    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
    });

    let output = handfest_bin()
        .args([
            "request",
            "--socket",
            sock_path.to_str().unwrap(),
            "--mandate",
            draft_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("run handfest request");
    server.join().unwrap();

    assert!(!output.status.success());
    assert!(!out_path.exists());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("operator said no"), "stderr was: {stderr}");
}

#[test]
fn handfest_request_prints_json_to_stdout_when_out_omitted_and_rejects_zero_timeout() {
    let dir = restricted_tempdir();
    let sock_path = dir.path().join("approver.sock");
    let draft_path = dir.path().join("draft.hf");

    let kp = Ed25519Keypair::from_secret_bytes([0xaa; 32]);
    let draft = draft_for(&kp.key_id());
    fs::write(&draft_path, &draft).unwrap();

    // Zero timeout rejected cleanly without connecting.
    let bad = handfest_bin()
        .args([
            "request",
            "--socket",
            sock_path.to_str().unwrap(),
            "--mandate",
            draft_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--timeout-secs",
            "0",
        ])
        .output()
        .expect("run zero timeout");
    assert!(!bad.status.success());
    assert!(String::from_utf8(bad.stderr)
        .unwrap()
        .contains("--timeout-secs must be greater than 0"));

    // Over-limit --timeout-secs fails closed before connecting.
    let too_large = handfest_bin()
        .args([
            "request",
            "--socket",
            sock_path.to_str().unwrap(),
            "--mandate",
            draft_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
            "--timeout-secs",
            "86401",
        ])
        .output()
        .expect("run over-limit timeout");
    assert!(!too_large.status.success());
    assert!(String::from_utf8(too_large.stderr)
        .unwrap()
        .contains("--timeout-secs must not exceed 86400"));

    // Stdout mode prints pretty verified SignedMandate JSON.
    let bound = BoundSocket::bind(&sock_path, SocketMode::OwnerOnly).unwrap();
    let mut daemon = ApproverDaemon::new(
        kp,
        FixedPrompt(ApprovalOutcome::Approved),
        "local-ed25519",
        Duration::from_secs(10),
    )
    .unwrap();
    let server = thread::spawn(move || {
        daemon.serve_one(bound.listener()).unwrap();
    });

    let ok = handfest_bin()
        .args([
            "request",
            "--socket",
            sock_path.to_str().unwrap(),
            "--mandate",
            draft_path.to_str().unwrap(),
            "--valid-from",
            "2026-11-24T17:00:00Z",
            "--valid-until",
            "2026-11-25T01:00:00Z",
        ])
        .output()
        .expect("run stdout request");
    server.join().unwrap();

    assert!(ok.status.success());
    let signed: SignedMandate = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(signed.anchor_id, "local-ed25519");
}
