//! End-to-end CLI tests for `handfest revoke`, `verify --revocation`, `check --revocation`, and `audit`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use handfest_anchors::{Ed25519Keypair, SignedRevocation};
use handfest_core::ast::MandateId;
use handfest_core::cnl::parse_mandate;
use serde_json::Value;

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn write_keypair(dir: &Path, name: &str, seed: [u8; 32]) -> (Ed25519Keypair, PathBuf) {
    let kp = Ed25519Keypair::from_secret_bytes(seed);
    let path = dir.join(format!("{name}.key.json"));
    fs::write(
        &path,
        serde_json::to_string_pretty(&kp.to_key_file()).unwrap(),
    )
    .unwrap();
    (kp, path)
}

struct CliFixture {
    _dir: tempfile::TempDir,
    root_id: MandateId,
    alice_key_path: PathBuf,
    eve_key_path: PathBuf,
    agent: Ed25519Keypair,
    root_signed: PathBuf,
    child_signed: PathBuf,
    ledger_path: PathBuf,
}

impl CliFixture {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let (alice, alice_key_path) = write_keypair(dir.path(), "alice", [0x11; 32]);
        let (bob, bob_key_path) = write_keypair(dir.path(), "bob", [0x22; 32]);
        let (agent, _) = write_keypair(dir.path(), "agent", [0x33; 32]);
        let (_, eve_key_path) = write_keypair(dir.path(), "eve", [0x44; 32]);

        let root_words = format!(
            "HANDFEST v1\n\
             FROM human \"Alice\" (key: {})\n\
             TO org \"Bob\" (key: {})\n\
             DELEGATION max 1 hop\n\
             ALLOW git.pr.merge\n\
             ON repo \"feedback-loop-ai/*\"\n\
             LIMIT 5 calls\n",
            alice.key_id(),
            bob.key_id()
        );
        let root_id = parse_mandate(&root_words).unwrap().mandate_id();
        let root_txt = dir.path().join("root.hf");
        fs::write(&root_txt, &root_words).unwrap();

        let child_words = format!(
            "HANDFEST v1\n\
             PARENT {root_id}\n\
             FROM org \"Bob\" (key: {})\n\
             TO agent \"Agent\" (key: {})\n\
             DELEGATION max 0 hops\n\
             ALLOW git.pr.merge\n\
             ON repo \"feedback-loop-ai/handfest\"\n\
             LIMIT 3 calls\n",
            bob.key_id(),
            agent.key_id()
        );
        let child_txt = dir.path().join("child.hf");
        fs::write(&child_txt, &child_words).unwrap();

        let root_signed = dir.path().join("root.signed.json");
        let child_signed = dir.path().join("child.signed.json");
        for (m_txt, k_path, out_path) in [
            (&root_txt, &alice_key_path, &root_signed),
            (&child_txt, &bob_key_path, &child_signed),
        ] {
            let out = handfest_bin()
                .args([
                    "sign",
                    "--mandate",
                    m_txt.to_str().unwrap(),
                    "--key",
                    k_path.to_str().unwrap(),
                    "--valid-from",
                    "2026-11-26T10:00:00Z",
                    "--valid-until",
                    "2026-11-26T20:00:00Z",
                    "--out",
                    out_path.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "sign failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let ledger_path = dir.path().join("ledger.sqlite");
        Self {
            _dir: dir,
            root_id,
            alice_key_path,
            eve_key_path,
            agent,
            root_signed,
            child_signed,
            ledger_path,
        }
    }

    fn run_check(
        &self,
        ledger: &Path,
        now: &str,
        extra_rev: Option<&Path>,
    ) -> std::process::Output {
        let mut cmd = handfest_bin();
        cmd.args([
            "check",
            "--ledger",
            ledger.to_str().unwrap(),
            "--chain",
            self.root_signed.to_str().unwrap(),
            self.child_signed.to_str().unwrap(),
            "--actor-key",
            &self.agent.key_id().to_string(),
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "feedback-loop-ai/handfest",
            "--now",
            now,
        ]);
        if let Some(rev) = extra_rev {
            cmd.args(["--revocation", rev.to_str().unwrap()]);
        }
        cmd.output().unwrap()
    }
}

#[test]
fn cli_revoke_verify_check_and_audit_end_to_end() {
    let f = CliFixture::new();

    // 1. Check before revocation -> Permit.
    let c1 = f.run_check(&f.ledger_path, "2026-11-26T12:00:00Z", None);
    assert!(c1.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&c1.stdout).unwrap()["verdict"],
        "permit"
    );

    // 2. Alice revokes root effective 14:00:00Z into ledger AND portable file.
    let rev_file = f._dir.path().join("alice.rev.json");
    let rev_out = handfest_bin()
        .args([
            "revoke",
            "--mandate",
            f.root_signed.to_str().unwrap(),
            "--key",
            f.alice_key_path.to_str().unwrap(),
            "--effective",
            "2026-11-26T14:00:00Z",
            "--reason",
            "Task finished early",
            "--ledger",
            f.ledger_path.to_str().unwrap(),
            "--out",
            rev_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        rev_out.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );
    let summary: Value = serde_json::from_slice(&rev_out.stdout).unwrap();
    assert_eq!(summary["status"], "revoked");
    assert_eq!(summary["recorded_in_ledger"], true);
    let rev_id = summary["revocation_id"].as_str().unwrap().to_string();

    let portable: SignedRevocation =
        serde_json::from_str(&fs::read_to_string(&rev_file).unwrap()).unwrap();
    assert!(portable.canonical_words.contains("BY human \"Alice\""));

    // 3. Check after effective_at against ledger -> Deny (cascades to leaf!).
    let c2 = f.run_check(&f.ledger_path, "2026-11-26T14:00:00Z", None);
    assert!(!c2.status.success());
    let c2_json: Value = serde_json::from_slice(&c2.stdout).unwrap();
    assert_eq!(c2_json["verdict"], "deny");
    assert!(c2_json["reason"].as_str().unwrap().contains(&rev_id));

    // 4. Check on fresh ledger with --revocation portable file -> Deny!
    let fresh = f._dir.path().join("fresh.sqlite");
    let c3 = f.run_check(&fresh, "2026-11-26T14:00:00Z", Some(&rev_file));
    assert!(!c3.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&c3.stdout).unwrap()["verdict"],
        "deny"
    );

    // 5. Audit passes with 2 verified receipts (1 permit + 1 deny).
    let audit = handfest_bin()
        .args(["audit", "--ledger", f.ledger_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let audit_json: Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 2);
}

#[test]
fn cli_verify_effective_time_third_party_dos_and_target_key_stdout() {
    let f = CliFixture::new();

    // Unauthorized Eve revocation must not fail verify.
    let eve_rev = f._dir.path().join("eve.rev.json");
    assert!(handfest_bin()
        .args([
            "revoke",
            "--target-mandate",
            &f.root_id.to_string(),
            "--key",
            f.eve_key_path.to_str().unwrap(),
            "--effective",
            "2026-11-26T11:00:00Z",
            "--out",
            eve_rev.to_str().unwrap(),
        ])
        .output()
        .unwrap()
        .status
        .success());

    assert!(handfest_bin()
        .args([
            "verify",
            f.root_signed.to_str().unwrap(),
            f.child_signed.to_str().unwrap(),
            "--revocation",
            eve_rev.to_str().unwrap(),
            "--now",
            "2026-11-26T12:30:00Z",
        ])
        .output()
        .unwrap()
        .status
        .success());

    // Authoritative Alice revocation: verify passes before effective_at, fails at effective_at.
    let alice_rev = f._dir.path().join("alice.rev.json");
    assert!(handfest_bin()
        .args([
            "revoke",
            "--mandate",
            f.root_signed.to_str().unwrap(),
            "--key",
            f.alice_key_path.to_str().unwrap(),
            "--effective",
            "2026-11-26T14:00:00Z",
            "--ledger",
            f.ledger_path.to_str().unwrap(),
            "--out",
            alice_rev.to_str().unwrap(),
        ])
        .output()
        .unwrap()
        .status
        .success());

    assert!(handfest_bin()
        .args([
            "verify",
            f.root_signed.to_str().unwrap(),
            f.child_signed.to_str().unwrap(),
            "--revocation",
            alice_rev.to_str().unwrap(),
            "--now",
            "2026-11-26T13:59:59Z",
        ])
        .output()
        .unwrap()
        .status
        .success());

    assert!(!handfest_bin()
        .args([
            "verify",
            f.root_signed.to_str().unwrap(),
            f.child_signed.to_str().unwrap(),
            "--revocation",
            alice_rev.to_str().unwrap(),
            "--now",
            "2026-11-26T14:00:00Z",
        ])
        .output()
        .unwrap()
        .status
        .success());

    assert!(!handfest_bin()
        .args([
            "verify",
            f.root_signed.to_str().unwrap(),
            f.child_signed.to_str().unwrap(),
            "--ledger",
            f.ledger_path.to_str().unwrap(),
            "--now",
            "2026-11-26T14:00:00Z",
        ])
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn cli_revoke_target_key_effective_now_stdout() {
    let f = CliFixture::new();
    let key_out = handfest_bin()
        .args([
            "revoke",
            "--target-key",
            &f.agent.key_id().to_string(),
            "--key",
            f.alice_key_path.to_str().unwrap(),
            "--effective",
            "now",
            "--reason",
            "key compromise",
        ])
        .output()
        .unwrap();
    assert!(key_out.status.success());
    let key_env: SignedRevocation = serde_json::from_slice(&key_out.stdout).unwrap();
    assert!(key_env
        .canonical_words
        .contains(&format!("TARGET key {}", f.agent.key_id())));
}
