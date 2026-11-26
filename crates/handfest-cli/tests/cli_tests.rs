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

fn setup_budget_mandate(dir: &Path) -> (PathBuf, String) {
    let (root_key_path, root_key) = keygen_to(dir, "root.key.json");
    let (_disp_key_path, disp_key) = keygen_to(dir, "disp.key.json");
    let root_hf = dir.join("budget.hf");
    fs::write(
        &root_hf,
        format!(
            concat!(
                "HANDFEST v1\n",
                "FROM human \"valentin\" (key: {root_key})\n",
                "TO agent \"treasury\" (key: {disp_key})\n",
                "DELEGATION max 0 hops\n",
                "ALLOW pay.transfer\n",
                "ON account \"ops-main\"\n",
                "LIMIT 100.00 USD sum(resource.amount)\n",
            ),
            root_key = root_key,
            disp_key = disp_key
        ),
    )
    .unwrap();
    let root_signed = dir.join("budget.signed.json");
    let _ = sign_to(
        &root_hf,
        &root_key_path,
        "2026-11-24T00:00:00Z",
        "2026-11-25T00:00:00Z",
        &root_signed,
    );
    (root_signed, disp_key)
}

fn run_budget_check(
    ledger: &Path,
    root_signed: &Path,
    disp_key: &str,
    facts_arg: &str,
    now: &str,
) -> Output {
    run_raw(&[
        "check",
        "--ledger",
        path_str(ledger),
        "--chain",
        path_str(root_signed),
        "--actor-key",
        disp_key,
        "--action",
        "pay.transfer",
        "--resource-kind",
        "account",
        "--resource-id",
        "ops-main",
        "--facts",
        facts_arg,
        "--now",
        now,
    ])
}

/// Brackets a single charge on a fresh 100.00 USD budget to 1e-28 precision (MAX_DECIMAL_SCALE):
/// `(100 - expected + 1e-28)` MUST Deny and `(100 - expected)` MUST Permit.
fn assert_exact_budget_charge(
    ledger: &Path,
    root_signed: &Path,
    disp_key: &str,
    amount_json: &str,
    over_rem: &str,
    exact_rem: &str,
) {
    let first = run_budget_check(
        ledger,
        root_signed,
        disp_key,
        amount_json,
        "2026-11-24T12:01:00Z",
    );
    assert!(first.status.success(), "expected permit for {amount_json}");
    let first_json: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_json["verdict"], "permit");

    let over_facts = format!(r#"{{"resource.amount": {over_rem}}}"#);
    let over = run_budget_check(
        ledger,
        root_signed,
        disp_key,
        &over_facts,
        "2026-11-24T12:02:00Z",
    );
    assert!(
        !over.status.success(),
        "expected deny for {over_rem} after charging {amount_json}"
    );
    let over_json: Value = serde_json::from_slice(&over.stdout).unwrap();
    assert_eq!(over_json["verdict"], "deny");
    assert!(over_json["reason"]
        .as_str()
        .unwrap()
        .contains("sum quota exceeded"));

    let exact_facts = format!(r#"{{"resource.amount": {exact_rem}}}"#);
    let exact = run_budget_check(
        ledger,
        root_signed,
        disp_key,
        &exact_facts,
        "2026-11-24T12:03:00Z",
    );
    assert!(
        exact.status.success(),
        "expected permit for exact remainder {exact_rem} after charging {amount_json}"
    );
    let exact_json: Value = serde_json::from_slice(&exact.stdout).unwrap();
    assert_eq!(exact_json["verdict"], "permit");
}

#[test]
fn exact_decimal_facts_and_fifo_path_support() {
    let dir = TempDir::new().unwrap();
    let (root_signed, disp_key) = setup_budget_mandate(dir.path());

    // 100.000000000000001 rounds to 100.0 in IEEE-754 f64, so exact decimal parsing MUST Deny it.
    let over_out = run_budget_check(
        &dir.path().join("over.sqlite"),
        &root_signed,
        &disp_key,
        r#"{"resource.amount": 100.000000000000001}"#,
        "2026-11-24T12:00:00Z",
    );
    assert!(!over_out.status.success());
    let over_json: Value = serde_json::from_slice(&over_out.stdout).unwrap();
    assert_eq!(over_json["verdict"], "deny");
    assert!(over_json["reason"]
        .as_str()
        .unwrap()
        .contains("sum quota exceeded"));

    // 0.00000001 and scientific notation 1e-8 must each charge exactly 0.00000001 (not 0).
    for (name, facts_json) in [
        ("tiny_plain.sqlite", r#"{"resource.amount": 0.00000001}"#),
        ("tiny_sci.sqlite", r#"{"resource.amount": 1e-8}"#),
    ] {
        assert_exact_budget_charge(
            &dir.path().join(name),
            &root_signed,
            &disp_key,
            facts_json,
            "99.9999999900000000000000000001",
            "99.99999999",
        );
    }

    // Plain decimals with redundant fractional zeros beyond 28 lexical digits must match e0.
    for (name, facts_json) in [
        (
            "trailing_zeros_plain.sqlite",
            r#"{"resource.amount": 1.500000000000000000000000000000}"#,
        ),
        (
            "trailing_zeros_sci.sqlite",
            r#"{"resource.amount": 1.500000000000000000000000000000e0}"#,
        ),
    ] {
        assert_exact_budget_charge(
            &dir.path().join(name),
            &root_signed,
            &disp_key,
            facts_json,
            "98.5000000000000000000000000001",
            "98.5",
        );
    }

    // Non-regular readable path (FIFO) must work for --facts without hanging on regression.
    #[cfg(unix)]
    assert_fifo_facts_roundtrip(dir.path(), &root_signed, &disp_key);
}

#[cfg(unix)]
fn assert_fifo_facts_roundtrip(dir: &Path, root_signed: &Path, disp_key: &str) {
    use std::fs::OpenOptions;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    let fifo_ledger = dir.join("fifo.sqlite");
    let fifo_path = dir.join("facts.fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo failed");

    let (done_tx, done_rx) = mpsc::channel();
    let fifo_writer_path = fifo_path.clone();
    let writer = std::thread::spawn(move || {
        let res = fs::write(&fifo_writer_path, r#"{"resource.amount": 0.00000001}"#);
        let _ = done_tx.send(());
        res
    });

    let fifo_out = run_budget_check(
        &fifo_ledger,
        root_signed,
        disp_key,
        path_str(&fifo_path),
        "2026-11-24T12:03:00Z",
    );

    let writer_still_blocked = matches!(
        done_rx.recv_timeout(Duration::from_secs(2)),
        Err(RecvTimeoutError::Timeout)
    );
    // Open the FIFO O_RDWR to unblock a stuck writer without ever blocking if the writer
    // already closed the FIFO and its completion message was merely delayed.
    let _unblock_guard = if writer_still_blocked {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo_path)
            .ok()
    } else {
        None
    };
    let write_res = writer.join().expect("fifo writer thread panicked");
    drop(_unblock_guard);
    assert!(
        !writer_still_blocked,
        "CLI exited without opening FIFO read end (stderr: {})",
        String::from_utf8_lossy(&fifo_out.stderr)
    );
    write_res.expect("write to fifo");
    assert!(fifo_out.status.success());
    let fifo_json: Value = serde_json::from_slice(&fifo_out.stdout).unwrap();
    assert_eq!(fifo_json["verdict"], "permit");

    let over_after_fifo = run_budget_check(
        &fifo_ledger,
        root_signed,
        disp_key,
        r#"{"resource.amount": 99.9999999900000000000000000001}"#,
        "2026-11-24T12:04:00Z",
    );
    assert!(!over_after_fifo.status.success());
}

#[test]
fn audit_missing_ledger_does_not_create_file_and_reads_readonly_dir() {
    let dir = TempDir::new().unwrap();

    // Auditing a missing ledger must fail and must NOT create the file.
    let missing_path = dir.path().join("missing.sqlite");
    let missing_out = run_raw(&["audit", "--ledger", path_str(&missing_path)]);
    assert!(!missing_out.status.success());
    assert!(
        !missing_path.exists(),
        "handfest audit must never create a missing ledger file"
    );

    // Populate a real ledger inside a dedicated subdirectory.
    let ro_dir = dir.path().join("readonly_dir");
    fs::create_dir(&ro_dir).unwrap();
    let (root_key_path, root_key) = keygen_to(dir.path(), "root.key.json");
    let (_disp_key_path, disp_key) = keygen_to(dir.path(), "disp.key.json");
    let root_hf = dir.path().join("root.hf");
    fs::write(
        &root_hf,
        format!(
            concat!(
                "HANDFEST v1\n",
                "FROM human \"valentin\" (key: {root_key})\n",
                "TO agent \"dispatcher\" (key: {disp_key})\n",
                "DELEGATION max 0 hops\n",
                "ALLOW git.pr.merge\n",
                "ON repo \"feedback-loop-ai/handfest\"\n",
                "LIMIT 5 calls\n",
            ),
            root_key = root_key,
            disp_key = disp_key
        ),
    )
    .unwrap();
    let root_signed = dir.path().join("root.signed.json");
    let _ = sign_to(
        &root_hf,
        &root_key_path,
        "2026-11-24T00:00:00Z",
        "2026-11-25T00:00:00Z",
        &root_signed,
    );

    let ledger_path = ro_dir.join("ledger.sqlite");
    let _ = run_ok(&[
        "check",
        "--ledger",
        path_str(&ledger_path),
        "--chain",
        path_str(&root_signed),
        "--actor-key",
        &disp_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "feedback-loop-ai/handfest",
        "--now",
        "2026-11-24T12:00:00Z",
    ]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        struct RestorePerms {
            dir: PathBuf,
            file: PathBuf,
        }
        impl Drop for RestorePerms {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o755));
                let _ = fs::set_permissions(&self.file, fs::Permissions::from_mode(0o644));
            }
        }

        let _guard = RestorePerms {
            dir: ro_dir.clone(),
            file: ledger_path.clone(),
        };
        fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();

        let audit_out = run_ok(&[
            "audit",
            "--ledger",
            path_str(&ledger_path),
            "--actor-key",
            &disp_key,
        ]);
        let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
        assert_eq!(audit_json["status"], "ok");
        assert_eq!(audit_json["verified_receipts"], 1);
        assert_eq!(audit_json["track_record"]["permits"], 1);

        assert_audit_succeeds_with_readonly_tmpdir(dir.path(), &ledger_path, &disp_key);
    }
}

#[cfg(unix)]
fn assert_audit_succeeds_with_readonly_tmpdir(dir: &Path, ledger_path: &Path, disp_key: &str) {
    use std::os::unix::fs::PermissionsExt;

    let ro_tmp = dir.join("readonly_tmp");
    fs::create_dir(&ro_tmp).unwrap();
    struct RestoreTmp(PathBuf);
    impl Drop for RestoreTmp {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
        }
    }
    let _tmp_guard = RestoreTmp(ro_tmp.clone());
    fs::set_permissions(&ro_tmp, fs::Permissions::from_mode(0o555)).unwrap();

    let ro_tmp_out = handfest_bin()
        .env("TMPDIR", &ro_tmp)
        .args([
            "audit",
            "--ledger",
            path_str(ledger_path),
            "--actor-key",
            disp_key,
        ])
        .output()
        .expect("spawn handfest audit with read-only TMPDIR");
    assert!(
        ro_tmp_out.status.success(),
        "audit failed with read-only TMPDIR: {}",
        String::from_utf8_lossy(&ro_tmp_out.stderr)
    );
    let ro_tmp_json: Value = serde_json::from_slice(&ro_tmp_out.stdout).unwrap();
    assert_eq!(ro_tmp_json["status"], "ok");
    assert_eq!(ro_tmp_json["verified_receipts"], 1);
    assert_eq!(ro_tmp_json["track_record"]["permits"], 1);
}

#[cfg(unix)]
#[test]
fn keygen_overwriting_world_readable_file_enforces_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let key_path = dir.path().join("existing.key.json");
    fs::write(&key_path, "stale-placeholder").unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o644
    );

    let key_id = run_ok(&["keygen", "--out", path_str(&key_path)])
        .trim()
        .to_string();
    assert!(key_id.starts_with("ed25519:"));

    let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "overwritten secret key file must have 0o600 permissions, got {mode:#o}"
    );
}

fn minimal_empty_sqlite_db_bytes() -> Vec<u8> {
    // Valid 4096-byte single-page SQLite 3 rollback-journal database with empty sqlite_master.
    let mut page = vec![0u8; 4096];
    page[0..16].copy_from_slice(b"SQLite format 3\0");
    page[16..18].copy_from_slice(&4096u16.to_be_bytes());
    page[18] = 1; // legacy rollback write version
    page[19] = 1; // legacy rollback read version
    page[21] = 64;
    page[22] = 32;
    page[23] = 32;
    page[24..28].copy_from_slice(&1u32.to_be_bytes()); // file change counter
    page[28..32].copy_from_slice(&1u32.to_be_bytes()); // database size = 1 page
    page[40..44].copy_from_slice(&1u32.to_be_bytes()); // schema cookie
    page[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding = UTF-8
    page[92..96].copy_from_slice(&1u32.to_be_bytes()); // version-valid-for
    page[96..100].copy_from_slice(&3_045_000u32.to_be_bytes());
    page[100] = 0x0d; // leaf table B-tree page (0 cells)
    page[105..107].copy_from_slice(&4096u16.to_be_bytes()); // start of cell content area
    page
}

fn setup_merge_mandate_fixture(dir: &Path) -> (PathBuf, String) {
    let (root_key_path, root_key) = keygen_to(dir, "root.key.json");
    let (_agent_key_path, agent_key) = keygen_to(dir, "agent.key.json");

    let mandate_path = dir.join("root.hf");
    fs::write(
        &mandate_path,
        format!(
            concat!(
                "HANDFEST v1\n",
                "FROM human \"valentin\" (key: {root_key})\n",
                "TO agent \"brokkr:agent\" (key: {agent_key})\n",
                "DELEGATION max 0 hops\n",
                "ALLOW git.pr.merge\n",
                "ON repo \"feedback-loop-ai/*\"\n",
                "LIMIT 2 calls\n",
            ),
            root_key = root_key,
            agent_key = agent_key
        ),
    )
    .unwrap();
    let signed_path = dir.join("root.signed.json");
    sign_to(
        &mandate_path,
        &root_key_path,
        "2026-11-24T00:00:00Z",
        "2026-11-26T00:00:00Z",
        &signed_path,
    );
    (signed_path, agent_key)
}

fn run_check_on_ledger(
    signed_path: &Path,
    agent_key: &str,
    ledger: &Path,
    require_existing: bool,
) -> Output {
    let mut args = vec![
        "check",
        "--ledger",
        path_str(ledger),
        "--chain",
        path_str(signed_path),
        "--actor-key",
        agent_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "feedback-loop-ai/handfest",
        "--now",
        "2026-11-24T12:00:00Z",
    ];
    if require_existing {
        args.push("--require-existing-ledger");
    }
    run_raw(&args)
}

fn assert_failed_without_stdout(out: &Output, label: &str) {
    assert!(!out.status.success(), "{label}: expected non-zero exit");
    assert!(
        out.stdout.is_empty(),
        "{label}: expected empty stdout on open failure, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.stderr.is_empty(),
        "{label}: expected non-empty stderr on failure"
    );
}

fn assert_existing_ledger_open_error(out: &Output, expected_code: &str, label: &str) {
    assert_failed_without_stdout(out, label);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let parsed: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|err| {
        panic!(
            "{label}: expected structured JSON on stderr, got parse error {err}; stderr={stderr}"
        )
    });
    assert_eq!(
        parsed["error"], "ledger_open_failed",
        "{label}: unexpected error field in {parsed}"
    );
    assert_eq!(
        parsed["code"], expected_code,
        "{label}: unexpected code field in {parsed}"
    );
    assert!(
        parsed["message"]
            .as_str()
            .is_some_and(|msg| !msg.is_empty()),
        "{label}: expected non-empty message string in {parsed}"
    );
}

#[test]
fn check_require_existing_ledger_rejects_missing_zero_byte_and_empty_schema() {
    let dir = TempDir::new().unwrap();
    let (signed_path, agent_key) = setup_merge_mandate_fixture(dir.path());

    // 1. Missing ledger fails closed with `missing_ledger` without creating the file.
    let missing = dir.path().join("missing.sqlite");
    let out = run_check_on_ledger(&signed_path, &agent_key, &missing, true);
    assert_existing_ledger_open_error(&out, "missing_ledger", "missing ledger");
    assert!(!missing.exists(), "missing ledger must not be created");

    // 2. 0-byte ledger fails closed with `invalid_ledger` without initializing tables.
    let zero_byte = dir.path().join("zero.sqlite");
    fs::write(&zero_byte, b"").unwrap();
    let out = run_check_on_ledger(&signed_path, &agent_key, &zero_byte, true);
    assert_existing_ledger_open_error(&out, "invalid_ledger", "0-byte ledger");
    assert_eq!(
        fs::metadata(&zero_byte).unwrap().len(),
        0,
        "0-byte ledger must remain 0 bytes"
    );
    let zero_audit = run_raw(&["audit", "--ledger", path_str(&zero_byte)]);
    assert_failed_without_stdout(&zero_audit, "audit 0-byte ledger");

    // 3. Empty-schema SQLite DB fails closed with `invalid_ledger` without creating tables.
    let empty_schema = dir.path().join("empty_schema.sqlite");
    let empty_bytes = minimal_empty_sqlite_db_bytes();
    fs::write(&empty_schema, &empty_bytes).unwrap();
    let out = run_check_on_ledger(&signed_path, &agent_key, &empty_schema, true);
    assert_existing_ledger_open_error(&out, "invalid_ledger", "empty-schema SQLite DB");
    let after_bytes = fs::read(&empty_schema).unwrap();
    assert_eq!(
        after_bytes, empty_bytes,
        "empty-schema SQLite DB must not be modified or initialized"
    );
    assert!(
        !after_bytes
            .windows(b"receipts".len())
            .any(|w| w == b"receipts"),
        "empty-schema SQLite DB must still have no receipts table"
    );
    let empty_audit = run_raw(&["audit", "--ledger", path_str(&empty_schema)]);
    assert_failed_without_stdout(&empty_audit, "audit empty-schema SQLite DB");

    // 4. Corrupt non-SQLite file fails closed with `invalid_ledger` without modification.
    let corrupt = dir.path().join("corrupt.sqlite");
    let garbage = b"not a valid sqlite database header at all!";
    fs::write(&corrupt, garbage).unwrap();
    let out = run_check_on_ledger(&signed_path, &agent_key, &corrupt, true);
    assert_existing_ledger_open_error(&out, "invalid_ledger", "corrupt non-SQLite ledger");
    assert_eq!(fs::read(&corrupt).unwrap(), garbage);

    // 5. Existing non-openable directory path fails closed with `storage_error`.
    let out = run_check_on_ledger(&signed_path, &agent_key, dir.path(), true);
    assert_existing_ledger_open_error(&out, "storage_error", "directory path as ledger");
}

#[test]
fn check_require_existing_ledger_accepts_initialized_ledger_and_prevents_quota_reset() {
    let dir = TempDir::new().unwrap();
    let (signed_path, agent_key) = setup_merge_mandate_fixture(dir.path());
    let ledger = dir.path().join("ledger.sqlite");
    let empty_bytes = minimal_empty_sqlite_db_bytes();
    fs::write(&ledger, &empty_bytes).unwrap();

    // Without --require-existing-ledger, an empty-schema SQLite DB initializes cleanly,
    // and subsequent --require-existing-ledger checks succeed up to LIMIT 2 calls.
    let init_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, false);
    assert!(init_out.status.success(), "initial check must succeed");
    let init_json: Value = serde_json::from_slice(&init_out.stdout).unwrap();
    assert_eq!(init_json["verdict"], "permit");

    let second_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, true);
    assert!(second_out.status.success(), "second check must succeed");
    let second_json: Value = serde_json::from_slice(&second_out.stdout).unwrap();
    assert_eq!(second_json["verdict"], "permit");

    // Third call exhausts LIMIT 2 calls and yields a structured deny verdict on stdout.
    let third_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, true);
    assert!(!third_out.status.success(), "third call must be denied");
    let third_json: Value = serde_json::from_slice(&third_out.stdout).unwrap();
    assert_eq!(third_json["verdict"], "deny");

    let audit_out = run_ok(&[
        "audit",
        "--ledger",
        path_str(&ledger),
        "--actor-key",
        &agent_key,
    ]);
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 3);
    assert_eq!(audit_json["track_record"]["permits"], 2);
    assert_eq!(audit_json["track_record"]["denies"], 1);

    // Exhausted quota must NOT reset when ledger is truncated, replaced with an empty schema, or deleted.
    fs::write(&ledger, b"").unwrap();
    let trunc_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, true);
    assert_existing_ledger_open_error(&trunc_out, "invalid_ledger", "truncated exhausted ledger");
    assert_eq!(fs::metadata(&ledger).unwrap().len(), 0);

    fs::write(&ledger, &empty_bytes).unwrap();
    let empty_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, true);
    assert_existing_ledger_open_error(
        &empty_out,
        "invalid_ledger",
        "empty-schema replacement of exhausted ledger",
    );
    assert_eq!(fs::read(&ledger).unwrap(), empty_bytes);

    fs::remove_file(&ledger).unwrap();
    let deleted_out = run_check_on_ledger(&signed_path, &agent_key, &ledger, true);
    assert_existing_ledger_open_error(&deleted_out, "missing_ledger", "deleted exhausted ledger");
    assert!(!ledger.exists());
}
