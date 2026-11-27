use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

fn handfest_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_handfest"))
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
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

struct TestFixtures {
    _dir: TempDir,
    root_key_path: PathBuf,
    actor_key: String,
    signed_path: PathBuf,
    ledger_path: PathBuf,
    sidecar_path: PathBuf,
}

fn setup_fixtures() -> TestFixtures {
    let dir = TempDir::new().unwrap();
    let root_key_path = dir.path().join("root.key.json");
    let root_key = run_ok(&["keygen", "--out", path_str(&root_key_path)])
        .trim()
        .to_string();
    let actor_key_path = dir.path().join("actor.key.json");
    let actor_key = run_ok(&["keygen", "--out", path_str(&actor_key_path)])
        .trim()
        .to_string();

    let mandate_path = dir.path().join("root.hf");
    fs::write(
        &mandate_path,
        format!(
            "HANDFEST v1\nFROM human \"valentin\" (key: {root_key})\nTO agent \"bot\" (key: {actor_key})\nDELEGATION max 0 hops\nALLOW git.pr.merge\nON repo \"org/*\"\nLIMIT 5 calls\n"
        ),
    )
    .unwrap();

    let signed_path = dir.path().join("root.signed.json");
    run_ok(&[
        "sign",
        "--mandate",
        path_str(&mandate_path),
        "--key",
        path_str(&root_key_path),
        "--valid-from",
        "2026-11-24T00:00:00Z",
        "--valid-until",
        "2026-11-26T00:00:00Z",
        "--out",
        path_str(&signed_path),
    ]);

    let ledger_path = dir.path().join("ledger.sqlite");
    let sidecar_path = handfest_ledger::default_checkpoint_sidecar_path(&ledger_path);
    TestFixtures {
        _dir: dir,
        root_key_path,
        actor_key,
        signed_path,
        ledger_path,
        sidecar_path,
    }
}

#[test]
fn default_witness_none_creates_no_sidecar_and_verify_witness_fails_closed_when_missing() {
    let f = setup_fixtures();

    let out = run_ok(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
        "--witness",
        "none",
    ]);
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["verdict"], "permit");
    assert!(
        !f.sidecar_path.exists(),
        "--witness none must not create checkpoint sidecar"
    );

    // Plain `handfest audit` succeeds without sidecar and omits `verified_checkpoints`.
    let audit_out = run_ok(&["audit", "--ledger", path_str(&f.ledger_path)]);
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 1);
    assert!(audit_json.get("verified_checkpoints").is_none());

    // `handfest audit --verify-witness` fails closed when sidecar is missing!
    let verify_fail = run_raw(&[
        "audit",
        "--ledger",
        path_str(&f.ledger_path),
        "--verify-witness",
    ]);
    assert!(!verify_fail.status.success());
    let stderr = String::from_utf8_lossy(&verify_fail.stderr);
    let err_json: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on audit --verify-witness failure ({e}): {stderr}")
    });
    assert_eq!(err_json["error"], "witness_verification_failed");
    assert_eq!(err_json["code"], "missing_sidecar");
    assert!(
        err_json["message"].as_str().unwrap().contains("not found"),
        "expected missing sidecar message, got: {err_json}"
    );

    // `handfest revoke --witness ots` without `--ledger` fails closed.
    let revoke_no_ledger = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--witness",
        "ots",
    ]);
    assert!(!revoke_no_ledger.status.success());
    let rev_stderr = String::from_utf8_lossy(&revoke_no_ledger.stderr);
    assert!(
        rev_stderr.contains("--witness requires --ledger"),
        "expected --witness requires --ledger error, got: {rev_stderr}"
    );
}

#[cfg(not(feature = "witness-ots"))]
#[test]
fn ots_witness_flags_fail_closed_when_feature_not_compiled() {
    let f = setup_fixtures();
    let rev_out_path = f.ledger_path.with_extension("rev.json");
    let missing_key = f.ledger_path.with_extension("does-not-exist.key.json");

    let check_out = run_raw(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
        "--witness",
        "ots",
    ]);
    assert!(!check_out.status.success());
    assert!(
        String::from_utf8_lossy(&check_out.stderr).contains("witness-ots"),
        "expected witness-ots feature hint"
    );
    assert!(
        !f.ledger_path.exists(),
        "early --witness ots check must fail BEFORE creating SQLite ledger"
    );

    // Even with a missing signing key and --out, revoke must reject --witness ots BEFORE
    // resolving/signing or writing --out or creating --ledger.
    let rev_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&missing_key),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--ledger",
        path_str(&f.ledger_path),
        "--out",
        path_str(&rev_out_path),
        "--witness",
        "ots",
    ]);
    assert!(!rev_out.status.success());
    assert!(
        String::from_utf8_lossy(&rev_out.stderr).contains("witness-ots"),
        "expected witness-ots feature hint, got: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );
    assert!(
        !rev_out_path.exists(),
        "early --witness ots failure must not write --out"
    );
    assert!(
        !f.ledger_path.exists(),
        "early --witness ots failure must not create --ledger"
    );
}

#[cfg(all(feature = "witness-ots", unix))]
fn install_fake_ots_path() -> (TempDir, String) {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = TempDir::new().unwrap();
    let fake_ots = bin_dir.path().join("ots");
    let script = r#"#!/bin/sh
set -eu
cmd="$1"
shift
if [ "$cmd" = "stamp" ]; then
    target="$1"
    size=$(wc -c < "$target" | tr -d ' ')
    if [ "$size" != "32" ]; then
        echo "expected 32-byte digest, got $size" >&2
        exit 2
    fi
    if [ "${FAKE_OTS_FAIL:-0}" = "1" ]; then
        echo "simulated calendar error" >&2
        exit 1
    fi
    case "$target" in
        -*) echo "flag injection detected: $target" >&2; exit 3 ;;
        /*) ;;
        *) echo "expected absolute path, got: $target" >&2; exit 3 ;;
    esac
    if [ "${FAKE_OTS_BAD_MAGIC:-0}" = "1" ]; then
        printf 'x' > "${target}.ots"
        exit 0
    fi
    printf '\000OpenTimestamps\000\000Proof\000\277\211\342\350\204\350\222\224\001\010' > "${target}.ots"
    cat "$target" >> "${target}.ots"
    printf '\000' >> "${target}.ots"
    exit 0
elif [ "$cmd" = "verify" ]; then
    if [ "$1" != "-f" ]; then
        echo "expected -f" >&2
        exit 2
    fi
    target="$2"
    ots_file="$3"
    case "$target" in
        /*) ;;
        *) echo "expected absolute digest path, got: $target" >&2; exit 3 ;;
    esac
    case "$ots_file" in
        /*) ;;
        *) echo "expected absolute ots path, got: $ots_file" >&2; exit 3 ;;
    esac
    expected_tmp="${target}.expected"
    printf '\000OpenTimestamps\000\000Proof\000\277\211\342\350\204\350\222\224\001\010' > "$expected_tmp"
    cat "$target" >> "$expected_tmp"
    printf '\000' >> "$expected_tmp"
    cmp -s "$expected_tmp" "$ots_file"
    status=$?
    rm -f "$expected_tmp"
    exit $status
fi
echo "unknown subcommand $cmd" >&2
exit 2
"#;
    fs::write(&fake_ots, script).unwrap();
    fs::set_permissions(&fake_ots, fs::Permissions::from_mode(0o755)).unwrap();
    let orig_path = std::env::var("PATH").unwrap_or_default();
    let test_path = format!("{}:{orig_path}", bin_dir.path().display());
    (bin_dir, test_path)
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn ots_cli_end_to_end_anchor_verify_and_detect_sqlite_rollback() {
    let f = setup_fixtures();
    let (bin_dir, test_path) = install_fake_ots_path();

    // 1. Check with `--witness ots` anchors checkpoint #1.
    let check_out = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "check",
            "--ledger",
            path_str(&f.ledger_path),
            "--chain",
            path_str(&f.signed_path),
            "--actor-key",
            &f.actor_key,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "org/app",
            "--now",
            "2026-11-24T18:00:00Z",
            "--witness",
            "ots",
        ])
        .output()
        .unwrap();
    assert!(
        check_out.status.success(),
        "check --witness ots failed: {}",
        String::from_utf8_lossy(&check_out.stderr)
    );
    assert!(f.sidecar_path.exists());

    // 2. Revoke with `--ledger ... --witness ots` anchors checkpoint #2.
    let rev_out = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "revoke",
            "--mandate",
            path_str(&f.signed_path),
            "--key",
            path_str(&f.root_key_path),
            "--effective",
            "2026-11-24T19:00:00Z",
            "--ledger",
            path_str(&f.ledger_path),
            "--witness",
            "ots",
        ])
        .output()
        .unwrap();
    assert!(
        rev_out.status.success(),
        "revoke --witness ots failed: {}",
        String::from_utf8_lossy(&rev_out.stderr)
    );

    // 3. `handfest audit --ledger <path> --verify-witness` succeeds with 2 verified checkpoints.
    let audit_out = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--actor-key",
            &f.actor_key,
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        audit_out.status.success(),
        "audit --verify-witness failed: {}",
        String::from_utf8_lossy(&audit_out.stderr)
    );
    let audit_json: Value = serde_json::from_slice(&audit_out.stdout).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 1);
    assert_eq!(audit_json["verified_checkpoints"], 2);
    assert_eq!(audit_json["track_record"]["permits"], 1);

    assert_ots_stamp_failure_and_db_rollback(&f, &bin_dir, &test_path);
}

#[cfg(all(feature = "witness-ots", unix))]
fn assert_ots_stamp_failure_and_db_rollback(f: &TestFixtures, bin_dir: &TempDir, test_path: &str) {
    // 4. Failing `ots stamp` fails closed on `handfest check --witness ots`.
    let fail_check = handfest_bin()
        .env("PATH", test_path)
        .env("FAKE_OTS_FAIL", "1")
        .args([
            "check",
            "--ledger",
            path_str(&f.ledger_path),
            "--chain",
            path_str(&f.signed_path),
            "--actor-key",
            &f.actor_key,
            "--action",
            "git.pr.merge",
            "--resource-kind",
            "repo",
            "--resource-id",
            "org/app",
            "--now",
            "2026-11-24T18:05:00Z",
            "--witness",
            "ots",
        ])
        .output()
        .unwrap();
    assert!(!fail_check.status.success());
    assert!(String::from_utf8_lossy(&fail_check.stderr).contains("simulated calendar error"));

    // 5. Host-level DB rollback: replace ledger with a fresh empty SQLite DB (plain `audit` passes!).
    let fresh_db = bin_dir.path().join("fresh.sqlite");
    let _ = handfest_ledger::SqliteLedger::open(&fresh_db).unwrap();
    fs::copy(&fresh_db, &f.ledger_path).unwrap();

    let plain_audit = run_ok(&["audit", "--ledger", path_str(&f.ledger_path)]);
    let plain_json: Value = serde_json::from_str(&plain_audit).unwrap();
    assert_eq!(plain_json["verified_receipts"], 0);

    let rollback_audit = handfest_bin()
        .env("PATH", test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        !rollback_audit.status.success(),
        "audit --verify-witness MUST fail closed on host-level DB rollback"
    );
    let rollback_stderr = String::from_utf8_lossy(&rollback_audit.stderr);
    let rollback_json: Value = serde_json::from_str(rollback_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on rollback ({e}): {rollback_stderr}")
    });
    assert_eq!(rollback_json["error"], "witness_verification_failed");
    assert_eq!(rollback_json["code"], "integrity_or_rollback_mismatch");
    assert!(rollback_json["message"]
        .as_str()
        .unwrap()
        .contains("rollback or truncation"));
}

#[test]
fn revoke_out_rejects_ledger_and_all_sidecar_paths_without_clobbering() {
    let f = setup_fixtures();
    // Create ledger + sentinel checkpoint sidecar content.
    run_ok(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
    ]);
    let sentinel = "SENTINEL-DO-NOT-CLOBBER\n";
    fs::write(&f.sidecar_path, sentinel).unwrap();

    let mut forbidden_paths = vec![
        f.ledger_path.clone(),
        f.sidecar_path.clone(),
        PathBuf::from(format!("{}-wal", f.ledger_path.display())),
        PathBuf::from(format!("{}-shm", f.ledger_path.display())),
        PathBuf::from(format!("{}-journal", f.ledger_path.display())),
    ];
    #[cfg(unix)]
    {
        let link_ledger = f.ledger_path.with_file_name("ledger-link.sqlite");
        std::os::unix::fs::symlink(&f.ledger_path, &link_ledger).unwrap();
        // Passing symlinked ledger with real sidecar as --out must also be rejected!
        let out = run_raw(&[
            "revoke",
            "--mandate",
            path_str(&f.signed_path),
            "--key",
            path_str(&f.root_key_path),
            "--effective",
            "2026-11-24T19:00:00Z",
            "--ledger",
            path_str(&link_ledger),
            "--out",
            path_str(&f.sidecar_path),
        ]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("sidecar"));
        assert_eq!(fs::read_to_string(&f.sidecar_path).unwrap(), sentinel);
    }

    for target in forbidden_paths.drain(..) {
        let out = run_raw(&[
            "revoke",
            "--mandate",
            path_str(&f.signed_path),
            "--key",
            path_str(&f.root_key_path),
            "--effective",
            "2026-11-24T19:00:00Z",
            "--ledger",
            path_str(&f.ledger_path),
            "--out",
            path_str(&target),
        ]);
        assert!(
            !out.status.success(),
            "revoke --out '{}' MUST be rejected",
            target.display()
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must not point to --ledger"),
            "unexpected stderr for '{}': {stderr}",
            target.display()
        );
    }
    assert_eq!(
        fs::read_to_string(&f.sidecar_path).unwrap(),
        sentinel,
        "checkpoint sidecar must remain completely untouched"
    );
}

#[cfg(all(feature = "witness-ots", unix))]
fn run_ots_check(
    f: &TestFixtures,
    ledger_path: &Path,
    now: &str,
    test_path: &str,
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = handfest_bin();
    cmd.env("PATH", test_path);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.args([
        "check",
        "--ledger",
        path_str(ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        now,
        "--witness",
        "ots",
    ])
    .output()
    .unwrap()
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn ots_cli_hardens_tmpdir_dash_v_rejects_bad_magic_and_resolves_symlinked_ledger() {
    let f = setup_fixtures();
    let (_bin_dir, test_path) = install_fake_ots_path();

    let cwd = TempDir::new().unwrap();
    fs::create_dir(cwd.path().join("-v")).unwrap();

    // 1. `check --witness ots` with `TMPDIR=-v` passes canonical absolute path (no flag injection).
    let ok = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:00:00Z",
        &test_path,
        Some(cwd.path()),
        &[("TMPDIR", "-v")],
    );
    assert!(
        ok.status.success(),
        "check with TMPDIR=-v failed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // 2. Invalid-magic 1-byte garbage from `ots stamp` fails closed and rolls back receipt/quota.
    let bad = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:01:00Z",
        &test_path,
        None,
        &[("FAKE_OTS_BAD_MAGIC", "1")],
    );
    assert!(!bad.status.success());
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("OpenTimestamps proof magic header"),
        "expected magic header rejection, got: {}",
        String::from_utf8_lossy(&bad.stderr)
    );

    // 3. Symlinked ledger path resolves canonical ledger sidecar for both check and audit.
    let link_ledger = f.ledger_path.with_file_name("alias.sqlite");
    std::os::unix::fs::symlink(&f.ledger_path, &link_ledger).unwrap();
    let link_check = run_ots_check(
        &f,
        &link_ledger,
        "2026-11-24T18:02:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(
        link_check.status.success(),
        "check via symlinked ledger failed: {}",
        String::from_utf8_lossy(&link_check.stderr)
    );
    assert!(
        !handfest_ledger::default_checkpoint_sidecar_path(&link_ledger).exists(),
        "symlinked ledger must append to canonical ledger sidecar, not create split-brain sidecar"
    );

    let audit = handfest_bin()
        .current_dir(cwd.path())
        .env("TMPDIR", "-v")
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&link_ledger),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        audit.status.success(),
        "audit via symlinked ledger failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let parsed: Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(parsed["verified_receipts"], 2);
    assert_eq!(parsed["verified_checkpoints"], 2);
}

#[test]
fn audit_verify_witness_accepts_deny_only_ledger_without_sidecar() {
    let f = setup_fixtures();

    // Record a Deny receipt (disallowed action); no Permit or Revocation exists.
    let deny_out = run_raw(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "forbidden.action",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
    ]);
    assert!(!deny_out.status.success());
    let deny_json: Value = serde_json::from_slice(&deny_out.stdout).unwrap();
    assert_eq!(deny_json["verdict"], "deny");
    assert!(!f.sidecar_path.exists());

    // `handfest audit --verify-witness` succeeds with verified_checkpoints == 0 on Deny-only ledger.
    let audit_out = run_ok(&[
        "audit",
        "--ledger",
        path_str(&f.ledger_path),
        "--verify-witness",
    ]);
    let audit_json: Value = serde_json::from_str(&audit_out).unwrap();
    assert_eq!(audit_json["status"], "ok");
    assert_eq!(audit_json["verified_receipts"], 1);
    assert_eq!(audit_json["verified_checkpoints"], 0);

    // Pinning --expected-checkpoint on a Deny-only ledger without sidecar MUST fail closed!
    let pinned_fail = run_raw(&[
        "audit",
        "--ledger",
        path_str(&f.ledger_path),
        "--verify-witness",
        "--expected-checkpoint",
        &format!("sha256:{}", "a".repeat(64)),
    ]);
    assert!(!pinned_fail.status.success());
    let err_json: Value = serde_json::from_slice(&pinned_fail.stderr).unwrap();
    assert_eq!(err_json["error"], "witness_verification_failed");
    assert_eq!(err_json["code"], "missing_sidecar");
}

#[cfg(all(feature = "witness-ots", unix))]
fn assert_corrupt_ots_proof_reports_json_failure(
    f: &TestFixtures,
    test_path: &str,
    line1: &str,
    head_rec: &handfest_ledger::StoredCheckpoint,
) {
    let mut bad_proof_rec = head_rec.clone();
    let mut forged_ots = handfest_ledger::OTS_PROOF_MAGIC.to_vec();
    forged_ots.extend_from_slice(&[0x01, 0x08]);
    forged_ots.extend_from_slice(&[0xff; 32]);
    forged_ots.push(0x00);
    bad_proof_rec.proof.proof_bytes_b64 = handfest_core::base64::encode_standard(&forged_ots);
    bad_proof_rec.record_hash = handfest_ledger::StoredCheckpoint::compute_record_hash(
        bad_proof_rec.seq,
        bad_proof_rec.prev_record_hash.as_deref(),
        &bad_proof_rec.checkpoint,
        &bad_proof_rec.proof,
    );
    fs::write(
        &f.sidecar_path,
        format!(
            "{line1}\n{}\n",
            serde_json::to_string(&bad_proof_rec).unwrap()
        ),
    )
    .unwrap();
    let bad_proof_audit = handfest_bin()
        .env("PATH", test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(!bad_proof_audit.status.success());
    let proof_err: Value = serde_json::from_slice(&bad_proof_audit.stderr).unwrap();
    assert_eq!(proof_err["error"], "witness_verification_failed");
    assert_eq!(proof_err["code"], "proof_verification_failed");
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn audit_verify_witness_expected_checkpoint_defeats_joint_rollback_and_reports_proof_failure_json()
{
    let f = setup_fixtures();
    let (_bin_dir, test_path) = install_fake_ots_path();

    // Anchor checkpoint #1 and capture a snapshot of DB + sidecar.
    let c1 = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:00:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(c1.status.success());
    let db_snap_1 = fs::read(&f.ledger_path).unwrap();
    let sidecar_snap_1 = fs::read(&f.sidecar_path).unwrap();

    // Anchor checkpoint #2 and read operator-pinned head hash.
    let c2 = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:01:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(c2.status.success());
    let sidecar_text_2 = fs::read_to_string(&f.sidecar_path).unwrap();
    let head_rec: handfest_ledger::StoredCheckpoint =
        serde_json::from_str(sidecar_text_2.lines().last().unwrap()).unwrap();
    let pinned_head = head_rec.record_hash.clone();

    // Pinned audit passes against intact checkpoint #2.
    let ok_pinned = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
            "--expected-checkpoint",
            &pinned_head,
        ])
        .output()
        .unwrap();
    assert!(
        ok_pinned.status.success(),
        "pinned audit failed: {}",
        String::from_utf8_lossy(&ok_pinned.stderr)
    );

    assert_corrupt_ots_proof_reports_json_failure(
        &f,
        &test_path,
        sidecar_text_2.lines().next().unwrap(),
        &head_rec,
    );

    // Simultaneous DB + sidecar rollback back to checkpoint #1:
    // unpinned audit passes, but --expected-checkpoint fails closed!
    fs::write(&f.ledger_path, &db_snap_1).unwrap();
    fs::write(&f.sidecar_path, &sidecar_snap_1).unwrap();
    let unpinned_after_joint_rollback = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(unpinned_after_joint_rollback.status.success());

    let pinned_after_joint_rollback = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
            "--expected-checkpoint",
            &pinned_head,
        ])
        .output()
        .unwrap();
    assert!(!pinned_after_joint_rollback.status.success());
    let rollback_err: Value = serde_json::from_slice(&pinned_after_joint_rollback.stderr).unwrap();
    assert_eq!(rollback_err["error"], "witness_verification_failed");
    assert_eq!(rollback_err["code"], "integrity_or_rollback_mismatch");
    assert!(rollback_err["message"]
        .as_str()
        .unwrap()
        .contains("expected checkpoint head mismatch"));
}

#[cfg(unix)]
#[test]
fn revoke_out_rejects_hardlink_and_two_hop_symlinks() {
    let f = setup_fixtures();
    run_ok(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
    ]);
    let sentinel = "SENTINEL-CHECKPOINT-SIDECAR\n";
    fs::write(&f.sidecar_path, sentinel).unwrap();

    // 1. Hardlink alias (`ln ledger.sqlite.checkpoints.jsonl alias.json`) rejected before any write.
    let hardlink_alias = f.ledger_path.with_file_name("alias.json");
    fs::hard_link(&f.sidecar_path, &hardlink_alias).unwrap();
    let hl_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--ledger",
        path_str(&f.ledger_path),
        "--out",
        path_str(&hardlink_alias),
    ]);
    assert!(!hl_out.status.success());
    let hl_stderr = String::from_utf8_lossy(&hl_out.stderr);
    assert!(
        hl_stderr.contains("hardlink alias"),
        "expected hardlink alias error, got: {hl_stderr}"
    );
    assert_eq!(
        fs::read_to_string(&f.sidecar_path).unwrap(),
        sentinel,
        "hardlink rejection must not clobber sidecar"
    );

    // 2. 2-hop symlink (`link1 -> link2 -> ledger.sqlite.checkpoints.jsonl`) rejected before write.
    let link2 = f.ledger_path.with_file_name("link2.json");
    let link1 = f.ledger_path.with_file_name("link1.json");
    std::os::unix::fs::symlink(&f.sidecar_path, &link2).unwrap();
    std::os::unix::fs::symlink(&link2, &link1).unwrap();
    let sym2_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--ledger",
        path_str(&f.ledger_path),
        "--out",
        path_str(&link1),
    ]);
    assert!(!sym2_out.status.success());
    let sym2_stderr = String::from_utf8_lossy(&sym2_out.stderr);
    assert!(
        sym2_stderr.contains("must not point to --ledger"),
        "expected 2-hop symlink guard error, got: {sym2_stderr}"
    );
    assert_eq!(
        fs::read_to_string(&f.sidecar_path).unwrap(),
        sentinel,
        "2-hop symlink rejection must not clobber sidecar"
    );

    // 3. Dangling 2-hop symlink to non-existent `-wal` sidecar rejected BEFORE creation!
    let wal_path = PathBuf::from(format!("{}-wal", f.ledger_path.display()));
    assert!(!wal_path.exists());
    let dlink2 = f.ledger_path.with_file_name("dlink2.json");
    let dlink1 = f.ledger_path.with_file_name("dlink1.json");
    std::os::unix::fs::symlink(&wal_path, &dlink2).unwrap();
    std::os::unix::fs::symlink(&dlink2, &dlink1).unwrap();
    let dsym_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--ledger",
        path_str(&f.ledger_path),
        "--out",
        path_str(&dlink1),
    ]);
    assert!(!dsym_out.status.success());
    assert!(
        !wal_path.exists(),
        "dangling 2-hop symlink must not create target"
    );
}

#[cfg(unix)]
#[test]
fn revoke_out_rejects_symlink_cycle_and_standalone_nofollow_symlink() {
    let f = setup_fixtures();

    // 1. Symlink cycle (`cyc1 -> cyc2 -> cyc1`) rejected cleanly.
    let cyc1 = f.ledger_path.with_file_name("cyc1.json");
    let cyc2 = f.ledger_path.with_file_name("cyc2.json");
    std::os::unix::fs::symlink(&cyc2, &cyc1).unwrap();
    std::os::unix::fs::symlink(&cyc1, &cyc2).unwrap();
    let cyc_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--ledger",
        path_str(&f.ledger_path),
        "--out",
        path_str(&cyc1),
    ]);
    assert!(!cyc_out.status.success());
    assert!(
        String::from_utf8_lossy(&cyc_out.stderr).contains("symlink"),
        "expected symlink cycle error, got: {}",
        String::from_utf8_lossy(&cyc_out.stderr)
    );

    // 5. Standalone `--out` symlink (no `--ledger`) rejected at write time via O_NOFOLLOW.
    let target_file = f.ledger_path.with_file_name("innocent.txt");
    let innocent_sentinel = "DO-NOT-OVERWRITE\n";
    fs::write(&target_file, innocent_sentinel).unwrap();
    let standalone_link = f.ledger_path.with_file_name("standalone-link.json");
    std::os::unix::fs::symlink(&target_file, &standalone_link).unwrap();
    let nofollow_out = run_raw(&[
        "revoke",
        "--mandate",
        path_str(&f.signed_path),
        "--key",
        path_str(&f.root_key_path),
        "--effective",
        "2026-11-24T19:00:00Z",
        "--out",
        path_str(&standalone_link),
    ]);
    assert!(!nofollow_out.status.success());
    assert!(
        String::from_utf8_lossy(&nofollow_out.stderr).contains("symlink"),
        "expected O_NOFOLLOW symlink rejection, got: {}",
        String::from_utf8_lossy(&nofollow_out.stderr)
    );
    assert_eq!(
        fs::read_to_string(&target_file).unwrap(),
        innocent_sentinel,
        "O_NOFOLLOW must never truncate or overwrite symlink target"
    );
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn audit_verify_witness_detects_sidecar_tail_truncation_after_two_ots_permits() {
    let f = setup_fixtures();
    let (_bin_dir, test_path) = install_fake_ots_path();

    // 1. Record 2 witnessed Permits -> 2 checkpoint lines in `.checkpoints.jsonl`.
    let c1 = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:00:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(
        c1.status.success(),
        "permit 1 failed: {}",
        String::from_utf8_lossy(&c1.stderr)
    );
    let c2 = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:01:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(
        c2.status.success(),
        "permit 2 failed: {}",
        String::from_utf8_lossy(&c2.stderr)
    );

    let full_sidecar = fs::read_to_string(&f.sidecar_path).unwrap();
    let lines: Vec<&str> = full_sidecar.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected 2 checkpoint lines after 2 Permits"
    );

    // Intact audit succeeds with verified_checkpoints == 2.
    let ok_audit = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        ok_audit.status.success(),
        "intact audit failed: {}",
        String::from_utf8_lossy(&ok_audit.stderr)
    );
    let ok_json: Value = serde_json::from_slice(&ok_audit.stdout).unwrap();
    assert_eq!(ok_json["verified_receipts"], 2);
    assert_eq!(ok_json["verified_checkpoints"], 2);

    // 2. Truncate `.checkpoints.jsonl` to line 1 while Permit #2 exists in SQLite -> MUST fail closed!
    fs::write(&f.sidecar_path, format!("{}\n", lines[0])).unwrap();
    let tail_fail = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        !tail_fail.status.success(),
        "audit --verify-witness MUST fail closed when sidecar is tail-truncated to line 1"
    );
    let stderr_str = String::from_utf8_lossy(&tail_fail.stderr);
    let err_json: Value = serde_json::from_str(stderr_str.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on tail-truncation ({e}): {stderr_str}")
    });
    assert_eq!(err_json["error"], "witness_verification_failed");
    assert_eq!(err_json["code"], "integrity_or_rollback_mismatch");
    assert!(
        err_json["message"]
            .as_str()
            .unwrap()
            .contains("tail-truncation"),
        "expected tail-truncation message, got: {err_json}"
    );
}

#[test]
fn audit_verify_witness_malformed_expected_checkpoint_emits_structured_json_error() {
    let f = setup_fixtures();
    // Create a minimal Deny-only ledger so --ledger exists.
    let _ = run_raw(&[
        "check",
        "--ledger",
        path_str(&f.ledger_path),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "forbidden.action",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
    ]);

    let bad_head = run_raw(&[
        "audit",
        "--ledger",
        path_str(&f.ledger_path),
        "--verify-witness",
        "--expected-checkpoint",
        "not-a-valid-sha256",
    ]);
    assert!(!bad_head.status.success());
    let stderr_str = String::from_utf8_lossy(&bad_head.stderr);
    let err_json: Value = serde_json::from_str(stderr_str.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on malformed --expected-checkpoint ({e}): {stderr_str}")
    });
    assert_eq!(err_json["error"], "witness_verification_failed");
    assert_eq!(err_json["code"], "invalid_expected_checkpoint");
    assert!(
        err_json["message"]
            .as_str()
            .unwrap()
            .contains("invalid --expected-checkpoint"),
        "expected invalid --expected-checkpoint message, got: {err_json}"
    );
}

#[test]
fn audit_verify_witness_emits_structured_json_for_missing_truncated_and_invalid_actor_key() {
    let f = setup_fixtures();

    // 1. Missing ledger DB -> structured JSON error on stderr with code `missing_ledger`.
    let missing_path = f._dir.path().join("nonexistent.sqlite");
    let missing_out = run_raw(&[
        "audit",
        "--ledger",
        path_str(&missing_path),
        "--verify-witness",
    ]);
    assert!(
        !missing_out.status.success(),
        "audit --verify-witness on nonexistent DB must exit non-zero"
    );
    let missing_stderr = String::from_utf8_lossy(&missing_out.stderr);
    let missing_json: Value = serde_json::from_str(missing_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on nonexistent DB ({e}): {missing_stderr}")
    });
    assert_eq!(missing_json["error"], "witness_verification_failed");
    assert_eq!(missing_json["code"], "missing_ledger");

    // 2. Truncated 0-byte ledger DB -> structured JSON error on stderr with distinct code.
    let truncated_path = f._dir.path().join("truncated_0byte.sqlite");
    fs::write(&truncated_path, b"").unwrap();
    let trunc_out = run_raw(&[
        "audit",
        "--ledger",
        path_str(&truncated_path),
        "--verify-witness",
    ]);
    assert!(
        !trunc_out.status.success(),
        "audit --verify-witness on truncated 0-byte DB must exit non-zero"
    );
    let trunc_stderr = String::from_utf8_lossy(&trunc_out.stderr);
    let trunc_json: Value = serde_json::from_str(trunc_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on truncated 0-byte DB ({e}): {trunc_stderr}")
    });
    assert_eq!(trunc_json["error"], "witness_verification_failed");
    assert_eq!(trunc_json["code"], "invalid_or_corrupt_ledger");
    assert_ne!(
        missing_json["code"], trunc_json["code"],
        "nonexistent DB and truncated 0-byte DB must report distinct error codes"
    );

    // 3. Invalid --actor-key with --verify-witness -> structured JSON error (`invalid_actor_key`).
    let bad_actor_out = run_raw(&[
        "audit",
        "--ledger",
        path_str(&missing_path),
        "--actor-key",
        "not-a-valid-key-id",
        "--verify-witness",
    ]);
    assert!(!bad_actor_out.status.success());
    let actor_stderr = String::from_utf8_lossy(&bad_actor_out.stderr);
    let actor_json: Value = serde_json::from_str(actor_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on invalid --actor-key ({e}): {actor_stderr}")
    });
    assert_eq!(actor_json["error"], "witness_verification_failed");
    assert_eq!(actor_json["code"], "invalid_actor_key");
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn audit_verify_witness_rejects_stationary_duplicate_checkpoint_as_json() {
    use handfest_ledger::StoredCheckpoint;

    let f = setup_fixtures();
    let (_bin_dir, test_path) = install_fake_ots_path();

    // Record 1 witnessed Permit -> rec1 (receipt_seq=1, revocation_seq=0).
    let c1 = run_ots_check(
        &f,
        &f.ledger_path,
        "2026-11-24T18:00:00Z",
        &test_path,
        None,
        &[],
    );
    assert!(
        c1.status.success(),
        "permit 1 failed: {}",
        String::from_utf8_lossy(&c1.stderr)
    );

    // Clone rec1 as rec2 with seq=2, prev_record_hash=Some(rec1.record_hash), recomputed record_hash.
    let line1 = fs::read_to_string(&f.sidecar_path).unwrap();
    let rec1: StoredCheckpoint = serde_json::from_str(line1.trim()).unwrap();
    let rec2_hash = StoredCheckpoint::compute_record_hash(
        2,
        Some(&rec1.record_hash),
        &rec1.checkpoint,
        &rec1.proof,
    );
    let rec2 = StoredCheckpoint {
        seq: 2,
        prev_record_hash: Some(rec1.record_hash.clone()),
        record_hash: rec2_hash,
        checkpoint: rec1.checkpoint.clone(),
        proof: rec1.proof.clone(),
    };
    fs::write(
        &f.sidecar_path,
        format!("{}{}\n", line1, serde_json::to_string(&rec2).unwrap()),
    )
    .unwrap();

    let dup_out = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&f.ledger_path),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        !dup_out.status.success(),
        "audit --verify-witness MUST fail closed on stationary duplicate checkpoint"
    );
    let dup_stderr = String::from_utf8_lossy(&dup_out.stderr);
    let dup_json: Value = serde_json::from_str(dup_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on duplicate checkpoint ({e}): {dup_stderr}")
    });
    assert_eq!(dup_json["error"], "witness_verification_failed");
    assert_eq!(dup_json["code"], "integrity_or_rollback_mismatch");
    assert!(
        dup_json["message"]
            .as_str()
            .unwrap()
            .contains("zero-progress duplicate"),
        "expected zero-progress duplicate message, got: {dup_json}"
    );
}

#[cfg(all(feature = "witness-ots", unix))]
#[test]
fn audit_verify_witness_rejects_forged_revocation_signature_as_json() {
    use handfest_core::ast::{ActorDecl, KeyId, MandateId};
    use handfest_core::gate::{VerifiedAnchorProof, VerifiedRevocation};
    use handfest_core::revocation::{RevocationAst, RevocationTarget};
    use handfest_core::{ActorKind, AssuranceLevel};
    use handfest_ledger::{AnchoredLedger, OtsWitness, ReceiptLedger, SqliteLedger, WitnessPolicy};

    let dir = TempDir::new().unwrap();
    let (_bin_dir, test_path) = install_fake_ots_path();
    let forged_db = dir.path().join("forged_rev_sig.sqlite");
    let forged_sc = dir.path().join("forged_rev_sig.sqlite.checkpoints.jsonl");
    let fake_ots_bin = test_path
        .split(':')
        .next()
        .map(|d| PathBuf::from(d).join("ots"))
        .unwrap();
    let issuer_key =
        KeyId::parse("ed25519:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let rev_ast = RevocationAst::new(
        ActorDecl::new(
            ActorKind::Human,
            "alice".to_string(),
            issuer_key.clone(),
            Default::default(),
        )
        .unwrap(),
        RevocationTarget::Mandate(MandateId::sha256(b"forged-sig-rev")),
        1_764_000_000,
        Some("forged sig".to_string()),
    )
    .unwrap();
    let verified_rev = VerifiedRevocation {
        ast: rev_ast,
        proof: VerifiedAnchorProof {
            anchor_id: "local-ed25519".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: issuer_key,
            actor_kind: ActorKind::Human,
            valid_from: 1_763_999_000,
            valid_until: 1_764_010_000,
        },
    };
    {
        let mut anchored = AnchoredLedger::with_checkpoint_file(
            SqliteLedger::open(&forged_db).unwrap(),
            OtsWitness::new()
                .with_program(path_str(&fake_ots_bin))
                .unwrap(),
            WitnessPolicy::SyncStrict,
            &forged_sc,
        )
        .unwrap();
        anchored
            .record_revocation(&verified_rev, "deadbeef")
            .unwrap();
    }

    let sig_out = handfest_bin()
        .env("PATH", &test_path)
        .args([
            "audit",
            "--ledger",
            path_str(&forged_db),
            "--verify-witness",
        ])
        .output()
        .unwrap();
    assert!(
        !sig_out.status.success(),
        "audit --verify-witness MUST fail closed on forged revocation signature"
    );
    let sig_stderr = String::from_utf8_lossy(&sig_out.stderr);
    let sig_json: Value = serde_json::from_str(sig_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on forged revocation sig ({e}): {sig_stderr}")
    });
    assert_eq!(sig_json["error"], "witness_verification_failed");
    assert_eq!(sig_json["code"], "invalid_revocation_signature");
}

#[cfg(unix)]
#[test]
fn audit_verify_witness_maps_permission_denied_ledger_to_storage_error_json() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreMode(PathBuf, u32);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(self.1));
        }
    }

    let f = setup_fixtures();

    // 1. Inaccessible 0o000 parent directory -> structured JSON `storage_error` (not `invalid_or_corrupt_ledger`).
    let restricted_dir = f._dir.path().join("restricted_audit_dir");
    fs::create_dir(&restricted_dir).unwrap();
    let restricted_db = restricted_dir.join("ledger.sqlite");
    run_ok(&[
        "check",
        "--ledger",
        path_str(&restricted_db),
        "--chain",
        path_str(&f.signed_path),
        "--actor-key",
        &f.actor_key,
        "--action",
        "git.pr.merge",
        "--resource-kind",
        "repo",
        "--resource-id",
        "org/app",
        "--now",
        "2026-11-24T18:00:00Z",
    ]);
    let _restore_dir = RestoreMode(restricted_dir.clone(), 0o700);
    fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::canonicalize(&restricted_db).is_ok() {
        return; // Root / CAP_DAC_OVERRIDE bypasses 0o000 directory permissions.
    }

    let dir_out = run_raw(&[
        "audit",
        "--ledger",
        path_str(&restricted_db),
        "--verify-witness",
    ]);
    assert!(!dir_out.status.success());
    let dir_stderr = String::from_utf8_lossy(&dir_out.stderr);
    let dir_json: Value = serde_json::from_str(dir_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on inaccessible dir ({e}): {dir_stderr}")
    });
    assert_eq!(dir_json["error"], "witness_verification_failed");
    assert_eq!(dir_json["code"], "storage_error");
    drop(_restore_dir);

    // 2. Unreadable 0o000 ledger file -> structured JSON `storage_error` (not `invalid_or_corrupt_ledger`).
    let _restore_file = RestoreMode(restricted_db.clone(), 0o600);
    fs::set_permissions(&restricted_db, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&restricted_db).is_ok() {
        return;
    }

    let file_out = run_raw(&[
        "audit",
        "--ledger",
        path_str(&restricted_db),
        "--verify-witness",
    ]);
    assert!(!file_out.status.success());
    let file_stderr = String::from_utf8_lossy(&file_out.stderr);
    let file_json: Value = serde_json::from_str(file_stderr.trim()).unwrap_or_else(|e| {
        panic!("expected structured JSON stderr on 0o000 file ({e}): {file_stderr}")
    });
    assert_eq!(file_json["error"], "witness_verification_failed");
    assert_eq!(file_json["code"], "storage_error");
}
