use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn run_ok(args: &[&str]) -> String {
    let out = handfest_bin().args(args).output().expect("spawn handfest");
    assert!(
        out.status.success(),
        "handfest {:?} failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

fn run_raw(args: &[&str]) -> Output {
    handfest_bin().args(args).output().expect("spawn handfest")
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

fn keygen_to(dir: &Path, name: &str) -> (PathBuf, String) {
    let key_path = dir.join(name);
    let key_id = run_ok(&["keygen", "--out", path_str(&key_path)])
        .trim()
        .to_string();
    assert!(key_id.starts_with("ed25519:"));
    assert_eq!(key_id.len(), "ed25519:".len() + 64);
    (key_path, key_id)
}

fn sign_to(
    mandate_path: &Path,
    key_path: &Path,
    valid_from: &str,
    valid_until: &str,
    out_path: &Path,
) -> String {
    let id = run_ok(&[
        "sign",
        "--mandate",
        path_str(mandate_path),
        "--key",
        path_str(key_path),
        "--valid-from",
        valid_from,
        "--valid-until",
        valid_until,
        "--out",
        path_str(out_path),
    ])
    .trim()
    .to_string();
    assert!(id.starts_with("sha256:"));
    id
}

#[test]
fn end_to_end_keygen_fmt_sign_verify_check_and_audit() {
    let dir = TempDir::new().unwrap();

    let stdout_key_json = run_ok(&["keygen"]);
    let parsed_stdout_key: Value = serde_json::from_str(&stdout_key_json).unwrap();
    assert!(parsed_stdout_key["key_id"]
        .as_str()
        .unwrap()
        .starts_with("ed25519:"));
    assert_eq!(
        parsed_stdout_key["secret_key_hex"].as_str().unwrap().len(),
        64
    );

    let (root_key_path, root_key) = keygen_to(dir.path(), "root.key.json");
    let (disp_key_path, disp_key) = keygen_to(dir.path(), "disp.key.json");
    let (_seat_key_path, seat_key) = keygen_to(dir.path(), "seat.key.json");

    let root_raw_path = dir.path().join("root.hf");
    fs::write(
        &root_raw_path,
        format!(
            concat!(
                "HANDFEST v1\n",
                "FROM human \"valentin\" (key: {root_key})\n",
                "TO agent \"brokkr:dispatcher\" (key: {disp_key})\n",
                "DELEGATION max 1 hops\n",
                "ALLOW git.pr.merge\n",
                "ON repo \"feedback-loop-ai/*\"\n",
                "WHERE resource.author == \"valentin\"\n",
                "  AND context.time >= 2026-11-24T17:00:00Z\n",
                "  AND context.time < 2026-11-25T01:00:00Z\n",
                "LIMIT 2 calls\n",
            ),
            root_key = root_key,
            disp_key = disp_key
        ),
    )
    .unwrap();

    let formatted_root = run_ok(&["fmt", path_str(&root_raw_path)]);
    assert!(formatted_root.contains("DELEGATION max 1 hop\n"));
    assert!(
        formatted_root.find("context.time").unwrap()
            < formatted_root.find("resource.author").unwrap()
    );

    let root_signed_path = dir.path().join("root.signed.json");
    let root_id = sign_to(
        &root_raw_path,
        &root_key_path,
        "2026-11-24T17:00:00Z",
        "2026-11-25T01:00:00Z",
        &root_signed_path,
    );

    let child_raw_path = dir.path().join("child.hf");
    fs::write(
        &child_raw_path,
        format!(
            concat!(
                "HANDFEST v1\n",
                "PARENT {root_id}\n",
                "FROM agent \"brokkr:dispatcher\" (key: {disp_key})\n",
                "TO agent \"brokkr:seat:ship\" (key: {seat_key})\n",
                "DELEGATION max 0 hops\n",
                "ALLOW git.pr.merge\n",
                "ON repo \"feedback-loop-ai/handfest\"\n",
                "WHERE context.time >= 2026-11-24T18:00:00Z\n",
                "  AND context.time < 2026-11-24T19:00:00Z\n",
                "  AND resource.author == \"valentin\"\n",
                "  AND resource.pr_number == 42\n",
                "LIMIT 1 call\n",
            ),
            root_id = root_id,
            disp_key = disp_key,
            seat_key = seat_key
        ),
    )
    .unwrap();

    let child_signed_path = dir.path().join("child.signed.json");
    let _child_id = sign_to(
        &child_raw_path,
        &disp_key_path,
        "2026-11-24T17:30:00Z",
        "2026-11-24T20:00:00Z",
        &child_signed_path,
    );

    let verify_out = run_ok(&[
        "verify",
        path_str(&root_signed_path),
        path_str(&child_signed_path),
    ]);
    let verify_json: Value = serde_json::from_str(&verify_out).unwrap();
    assert_eq!(verify_json["status"], "verified");
    assert_eq!(verify_json["hops"], 2);

    let tampered_child_path = dir.path().join("child.tampered.json");
    let tampered_json = fs::read_to_string(&child_signed_path)
        .unwrap()
        .replace("LIMIT 1 call", "LIMIT 2 calls");
    fs::write(&tampered_child_path, tampered_json).unwrap();
    let bad_verify = run_raw(&[
        "verify",
        path_str(&root_signed_path),
        path_str(&tampered_child_path),
    ]);
    assert!(!bad_verify.status.success());

    let ledger_path = dir.path().join("ledger.sqlite");
    let facts_json = r#"{"resource.author":"valentin","resource.pr_number":42}"#;
    let check_args = |now: &'static str| {
        vec![
            "check",
            "--ledger",
            path_str(&ledger_path),
            "--chain",
            path_str(&root_signed_path),
            path_str(&child_signed_path),
            "--actor-key",
            &seat_key,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "feedback-loop-ai/handfest",
            "--facts",
            facts_json,
            "--now",
            now,
        ]
    };

    let check1_json: Value =
        serde_json::from_str(&run_ok(&check_args("2026-11-24T18:10:00Z"))).unwrap();
    assert_eq!(check1_json["verdict"], "permit");
    assert!(check1_json["receipt_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let check2 = run_raw(&check_args("2026-11-24T18:11:00Z"));
    assert!(!check2.status.success());
    let check2_json: Value = serde_json::from_slice(&check2.stdout).unwrap();
    assert_eq!(check2_json["verdict"], "deny");
    assert!(check2_json["reason"]
        .as_str()
        .unwrap()
        .contains("call quota exhausted"));

    let audit_out = run_ok(&[
        "audit",
        "--ledger",
        path_str(&ledger_path),
        "--actor-key",
        &seat_key,
    ]);
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 2);
    assert_eq!(audit_json["track_record"]["actor_key"], seat_key);
    assert_eq!(audit_json["track_record"]["total_decisions"], 2);
    assert_eq!(audit_json["track_record"]["permits"], 1);
    assert_eq!(audit_json["track_record"]["denies"], 1);
    assert_eq!(audit_json["track_record"]["distinct_mandates"], 1);
}

#[test]
fn verify_rejects_widened_child_and_audit_without_actor_key_succeeds() {
    let dir = TempDir::new().unwrap();
    let (root_key_path, root_key) = keygen_to(dir.path(), "root.key.json");
    let (disp_key_path, disp_key) = keygen_to(dir.path(), "disp.key.json");
    let (_seat_key_path, seat_key) = keygen_to(dir.path(), "seat.key.json");

    let root_hf = dir.path().join("root.hf");
    fs::write(
        &root_hf,
        format!(
            concat!(
                "HANDFEST v1\n",
                "FROM human \"valentin\" (key: {root_key})\n",
                "TO agent \"dispatcher\" (key: {disp_key})\n",
                "DELEGATION max 1 hop\n",
                "ALLOW pay.transfer\n",
                "ON account \"ops-*\"\n",
                "LIMIT 50.0 USD sum(resource.amount)\n",
            ),
            root_key = root_key,
            disp_key = disp_key
        ),
    )
    .unwrap();
    let root_signed = dir.path().join("root.signed.json");
    let root_id = sign_to(
        &root_hf,
        &root_key_path,
        "2026-11-24T00:00:00Z",
        "2026-11-25T00:00:00Z",
        &root_signed,
    );

    let wide_hf = dir.path().join("wide.hf");
    fs::write(
        &wide_hf,
        format!(
            concat!(
                "HANDFEST v1\n",
                "PARENT {root_id}\n",
                "FROM agent \"dispatcher\" (key: {disp_key})\n",
                "TO agent \"seat\" (key: {seat_key})\n",
                "DELEGATION max 0 hops\n",
                "ALLOW pay.transfer\n",
                "ON account \"ops-main\"\n",
                "LIMIT 60.0 USD sum(resource.amount)\n",
            ),
            root_id = root_id,
            disp_key = disp_key,
            seat_key = seat_key
        ),
    )
    .unwrap();
    let wide_signed = dir.path().join("wide.signed.json");
    let _ = sign_to(
        &wide_hf,
        &disp_key_path,
        "2026-11-24T00:00:00Z",
        "2026-11-25T00:00:00Z",
        &wide_signed,
    );

    let bad = run_raw(&["verify", path_str(&root_signed), path_str(&wide_signed)]);
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("attenuation check failed"));

    let ledger_path = dir.path().join("sum.sqlite");
    let check_out = run_ok(&[
        "check",
        "--ledger",
        path_str(&ledger_path),
        "--chain",
        path_str(&root_signed),
        "--actor-key",
        &disp_key,
        "--action",
        "pay.transfer",
        "--resource-kind",
        "account",
        "--resource-id",
        "ops-main",
        "--facts",
        r#"{"resource.amount": 25.50}"#,
        "--now",
        "2026-11-24T12:00:00Z",
    ]);
    let check_json: Value = serde_json::from_str(&check_out).unwrap();
    assert_eq!(check_json["verdict"], "permit");

    let audit_out = run_ok(&["audit", "--ledger", path_str(&ledger_path)]);
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 1);
    assert!(audit_json.get("track_record").is_none());
}
