use std::sync::mpsc;

use handfest_core::ast::{parse_rfc3339_utc, Scalar};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::VerifiedAnchorProof;
use handfest_core::AssuranceLevel;
use tempfile::TempDir;

use crate::preflight::active_handle_count;
#[cfg(unix)]
use crate::preflight::{active_writer_count, defer_fd_for_test, deferred_fd_count};

use super::*;

fn sample_chain_and_req() -> (Vec<VerifiedMandate>, ActionRequest, VerifiedFacts, i64) {
    sample_chain_and_req_with_limit(10)
}

fn sample_chain_and_req_with_limit(
    max_calls: u64,
) -> (Vec<VerifiedMandate>, ActionRequest, VerifiedFacts, i64) {
    let mandate_text = format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"dispatcher\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE resource.author == \"valentin\"\n",
            "LIMIT {max_calls} calls\n",
        ),
        max_calls = max_calls
    );
    let ast = parse_mandate(&mandate_text).unwrap();
    let proof = VerifiedAnchorProof {
        anchor_id: "test-anchor".to_string(),
        assurance: AssuranceLevel::LocalKey,
        signer_key: ast.from().key().clone(),
        actor_kind: ast.from().kind(),
        valid_from: parse_rfc3339_utc("2026-11-24T00:00:00Z").unwrap(),
        valid_until: parse_rfc3339_utc("2026-11-26T00:00:00Z").unwrap(),
    };
    let req = ActionRequest {
        actor_key: ast.to().key().clone(),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    };
    let mut facts = VerifiedFacts::new();
    facts.insert(
        "resource.author".to_string(),
        Scalar::Str("valentin".to_string()),
    );
    let now = parse_rfc3339_utc("2026-11-24T12:00:00Z").unwrap();
    (vec![VerifiedMandate { ast, proof }], req, facts, now)
}

#[test]
fn audit_snapshot_isolates_concurrent_writer_between_verify_and_track_record() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("snapshot_isolation.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();

    let mut writer = SqliteLedger::open(&db_path).unwrap();
    writer
        .evaluate_and_record(&chain, &req, &facts, now)
        .unwrap();

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let (start_tx, start_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let writer_req = req.clone();
    let writer_handle = std::thread::spawn(move || {
        start_rx.recv().unwrap();
        started_tx.send(()).unwrap();
        let res = writer.evaluate_and_record(&chain, &writer_req, &facts, now + 60);
        done_tx.send(()).unwrap();
        res.unwrap()
    });

    let (verified, maybe_rec) = run_audit_tx(&ro.conn, Some(&req.actor_key), || {
        start_tx.send(()).unwrap();
        started_rx.recv().unwrap();
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "concurrent writer must not commit while audit read transaction holds SHARED lock"
        );
    })
    .unwrap();

    let rec = maybe_rec.expect("expected TrackRecord");
    assert_eq!(verified, 1);
    assert_eq!(
        rec.total_decisions, 1,
        "track_record must read the same read transaction snapshot as verify_integrity"
    );

    writer_handle.join().unwrap();

    let (after_verified, after_rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
    assert_eq!(after_verified, 2);
    assert_eq!(after_rec.unwrap().total_decisions, 2);
}

#[test]
fn open_configures_delete_journal_full_sync_and_read_only_rejects_writes() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("pragmas.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();

    let mut writer = SqliteLedger::open(&db_path).unwrap();
    let mode: String = writer
        .conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    let sync: i64 = writer
        .conn
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    let fk: i64 = writer
        .conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_ascii_lowercase(), "delete");
    assert_eq!(sync, 2, "expected PRAGMA synchronous = FULL (2)");
    assert_eq!(fk, 1, "expected PRAGMA foreign_keys = ON (1)");

    writer
        .evaluate_and_record(&chain, &req, &facts, now)
        .unwrap();

    let mut ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let query_only: i64 = ro
        .conn
        .query_row("PRAGMA query_only", [], |r| r.get(0))
        .unwrap();
    assert_eq!(query_only, 1, "expected PRAGMA query_only = ON (1)");

    let err = ro
        .evaluate_and_record(&chain, &req, &facts, now + 60)
        .unwrap_err();
    assert!(
        matches!(err, LedgerError::Storage(_)),
        "expected Storage read-only refusal, got: {err}"
    );
    assert!(err.to_string().contains("ledger storage error"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn init_rejects_unexpected_journal_mode_and_corrupt_latest_hash() {
    let mem = Connection::open_in_memory().unwrap();
    let err = SqliteLedger::init(mem, None, "delete", true).unwrap_err();
    assert!(matches!(err, LedgerError::Storage(_)));
    assert!(err.to_string().contains("ledger storage error"));
    assert!(std::error::Error::source(&err).is_none());

    let mut ledger = SqliteLedger::open_in_memory().unwrap();
    let (chain, req, facts, now) = sample_chain_and_req();
    ledger
        .evaluate_and_record(&chain, &req, &facts, now)
        .unwrap();
    ledger
        .conn
        .execute("UPDATE receipts SET receipt_hash = 'not-a-hash'", [])
        .unwrap();
    assert!(matches!(
        ledger.evaluate_and_record(&chain, &req, &facts, now + 1),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn active_handle_tracker_refcounts_both_open_and_open_read_only_and_cleans_up_on_drop() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("tracked.sqlite");
    let l1 = SqliteLedger::open(&db_path).unwrap();
    let canonical = fs::canonicalize(&db_path).unwrap();
    assert_eq!(active_handle_count(&canonical), 1);

    let ro1 = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(active_handle_count(&canonical), 2);
    let ro2 = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(active_handle_count(&canonical), 3);

    drop(l1);
    assert_eq!(
        active_handle_count(&canonical),
        2,
        "open read-only handles must keep inode registered after writer drops"
    );
    drop(ro1);
    assert_eq!(active_handle_count(&canonical), 1);
    drop(ro2);
    assert_eq!(
        active_handle_count(&canonical),
        0,
        "dropping all handles must clear inode from tracker"
    );
}

#[test]
fn open_read_only_rejects_wal_via_pragma_even_if_writer_guard_is_active() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("flipped_to_wal.sqlite");
    let _idle_writer = SqliteLedger::open(&db_path).unwrap();

    // Simulate an external connection switching an idle DB to WAL mode while an in-process
    // SqliteLedger writer is registered: post-open PRAGMA journal_mode must still fail closed.
    let raw = Connection::open(&db_path).unwrap();
    raw.pragma_update(None, "journal_mode", "WAL").unwrap();
    drop(raw);

    let err = SqliteLedger::open_read_only(&db_path).unwrap_err();
    assert!(
        matches!(&err, LedgerError::Integrity(msg) if msg.contains("uses WAL mode")),
        "expected post-open WAL mode rejection, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn hardlink_limit_one_child_helper() {
    let Ok(db_path) = std::env::var("HANDFEST_HARDLINK_RACE_DB") else {
        return;
    };
    let mode = std::env::var("HANDFEST_HARDLINK_RACE_MODE").unwrap();
    if mode == "probe" {
        let conn = Connection::open(&db_path).expect("probe open");
        conn.busy_timeout(Duration::ZERO).unwrap();
        let res = conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;");
        assert!(
            res.is_err(),
            "parent POSIX RESERVED lock was dropped after hard-link open_read_only!"
        );
        return;
    }
    let (chain, req, facts, now) = sample_chain_and_req_with_limit(1);
    let mut ledger = SqliteLedger::open(&db_path).expect("child open");
    let (verdict, _) = ledger
        .evaluate_and_record(&chain, &req, &facts, now + 1)
        .expect("child evaluate_and_record");
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "expected LIMIT 1 calls Deny after parent committed Permit, got: {verdict:?}"
    );
}

#[cfg(unix)]
#[test]
fn hardlink_open_read_only_preserves_writer_lock_and_limit_one_across_processes() {
    use std::process::Command;

    let dir = TempDir::new().unwrap();
    let orig = dir.path().join("orig_limit_one.sqlite");
    let alias = dir.path().join("alias_limit_one.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req_with_limit(1);

    let mut writer = SqliteLedger::open(&orig).unwrap();
    fs::hard_link(&orig, &alias).unwrap();

    let tx = writer
        .conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let prev = load_latest_receipt_hash(&tx).unwrap();
    let chain_ids: Vec<MandateId> = chain.iter().map(|vm| vm.ast.mandate_id()).collect();
    let usage = load_quota_snapshot(&tx, &chain_ids).unwrap();
    let (verdict, receipt) = authorize(&chain, &req, &facts, &usage, now, prev);
    assert_eq!(verdict, Verdict::Permit);
    let updates = compute_quota_updates(&chain, &chain_ids, &facts, &usage).unwrap();

    // Open and close a read-only handle via the hard-link alias while `tx` holds RESERVED lock.
    {
        let ro = SqliteLedger::open_read_only(&alias).unwrap();
        assert_eq!(ro.verify_integrity().unwrap(), 0);
    }

    // Cross-process probe must fail immediately (kernel POSIX lock intact).
    let exe = std::env::current_exe().expect("current test exe");
    let probe = Command::new(&exe)
        .args([
            "--exact",
            "sqlite::tests::hardlink_limit_one_child_helper",
            "--quiet",
        ])
        .env("HANDFEST_HARDLINK_RACE_DB", &orig)
        .env("HANDFEST_HARDLINK_RACE_MODE", "probe")
        .status()
        .expect("spawn probe");
    assert!(
        probe.success(),
        "hard-link open_read_only dropped parent POSIX lock"
    );

    // Concurrent child writer attempting the same LIMIT 1 calls mandate must wait for commit
    // and then be denied rather than double-permitting.
    let mut child = Command::new(&exe)
        .args([
            "--exact",
            "sqlite::tests::hardlink_limit_one_child_helper",
            "--quiet",
        ])
        .env("HANDFEST_HARDLINK_RACE_DB", &orig)
        .env("HANDFEST_HARDLINK_RACE_MODE", "evaluate")
        .spawn()
        .expect("spawn child writer");

    insert_receipt(&tx, &receipt, &req.resource_kind, &req.resource_id).unwrap();
    apply_quota_updates(&tx, &updates).unwrap();
    tx.commit().unwrap();

    assert!(
        child.wait().expect("wait child").success(),
        "child process violated LIMIT 1 calls or failed"
    );
    assert_eq!(writer.verify_integrity().unwrap(), 2);
    let rec = writer.track_record(&req.actor_key).unwrap();
    assert_eq!(rec.permits, 1);
    assert_eq!(rec.denies, 1);
}

#[cfg(unix)]
use crate::lock_probe_test_util::assert_cross_process_exclusive_lock;

#[cfg(unix)]
#[test]
fn concurrent_open_read_only_handles_preserve_posix_shared_lock_and_snapshot_isolation() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent_ro_snapshot.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();

    {
        let mut writer = SqliteLedger::open(&db_path).unwrap();
        writer
            .evaluate_and_record(&chain, &req, &facts, now)
            .unwrap();
    }
    let canonical = fs::canonicalize(&db_path).unwrap();
    assert_eq!(active_handle_count(&canonical), 0);

    let ro1 = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(active_handle_count(&canonical), 1);

    let (start_tx, start_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let writer_path = db_path.clone();
    let writer_req = req.clone();
    let writer_handle = std::thread::spawn(move || {
        start_rx.recv().unwrap();
        let mut w = SqliteLedger::open(&writer_path).unwrap();
        let res = w.evaluate_and_record(&chain, &writer_req, &facts, now + 60);
        done_tx.send(()).unwrap();
        res.unwrap()
    });

    let (verified, maybe_rec) = run_audit_tx(&ro1.conn, Some(&req.actor_key), || {
        // Opening and closing a second read-only handle on the same path (with no writer open)
        // must hit refcount > 0 and preserve ro1's POSIX SHARED lock.
        {
            let ro2 = SqliteLedger::open_read_only(&db_path).unwrap();
            assert_eq!(active_handle_count(&canonical), 2);
            let (c2, r2) = ro2.audit_snapshot(Some(&req.actor_key)).unwrap();
            assert_eq!(c2, 1);
            assert_eq!(r2.unwrap().total_decisions, 1);
        }
        assert_eq!(active_handle_count(&canonical), 1);

        assert_cross_process_exclusive_lock(&db_path, true);

        start_tx.send(()).unwrap();
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "writer must not commit while ro1 holds its audit read snapshot"
        );
    })
    .unwrap();

    assert_eq!(verified, 1);
    assert_eq!(maybe_rec.unwrap().total_decisions, 1);
    writer_handle.join().unwrap();

    assert_cross_process_exclusive_lock(&db_path, false);

    let (after_count, after_rec) = ro1.audit_snapshot(Some(&req.actor_key)).unwrap();
    assert_eq!(after_count, 2);
    assert_eq!(after_rec.unwrap().total_decisions, 2);
}

#[test]
fn existing_ledger_open_flags_forbid_create_and_fail_on_missing_path() {
    assert!(
        !EXISTING_LEDGER_OPEN_FLAGS.contains(OpenFlags::SQLITE_OPEN_CREATE),
        "EXISTING_LEDGER_OPEN_FLAGS must never include SQLITE_OPEN_CREATE"
    );

    let dir = TempDir::new().unwrap();
    let missing_path = dir.path().join("must_not_create.sqlite");
    let err = Connection::open_with_flags(&missing_path, EXISTING_LEDGER_OPEN_FLAGS).unwrap_err();
    assert!(
        matches!(
            err,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::CannotOpen,
                    ..
                },
                _
            )
        ),
        "opening a missing path with EXISTING_LEDGER_OPEN_FLAGS must fail with CannotOpen, got: {err:?}"
    );
    assert!(
        !missing_path.exists(),
        "EXISTING_LEDGER_OPEN_FLAGS must never create a missing database file"
    );
}

#[cfg(unix)]
#[test]
fn audit_snapshot_shared_lock_survives_unrelated_writer_drop_with_deferred_fd() {
    let dir = TempDir::new().unwrap();
    let ledger_a = dir.path().join("audit_a.sqlite");
    let ledger_b = dir.path().join("writer_b.sqlite");
    let victim_c = dir.path().join("victim_c.sqlite");
    let victim_c_journal = dir.path().join("victim_c.sqlite-journal");
    let (chain, req, facts, now) = sample_chain_and_req();

    for path in [&ledger_a, &ledger_b, &victim_c] {
        let mut w = SqliteLedger::open(path).unwrap();
        w.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }

    let ro1 = SqliteLedger::open_read_only(&ledger_a).unwrap();

    let (verified, maybe_rec) = run_audit_tx(&ro1.conn, Some(&req.actor_key), || {
        {
            let _writer_b = SqliteLedger::open_existing(&ledger_b).unwrap();
            fs::hard_link(&ledger_a, &victim_c_journal).unwrap();
            let err = SqliteLedger::open_read_only(&victim_c).unwrap_err();
            assert!(matches!(err, LedgerError::Integrity(_)));
            fs::remove_file(&victim_c_journal).unwrap();
        }
        assert_cross_process_exclusive_lock(&ledger_a, true);
    })
    .unwrap();

    assert_eq!(verified, 1);
    assert_eq!(maybe_rec.unwrap().total_decisions, 1);
    drop(ro1);

    assert_cross_process_exclusive_lock(&ledger_a, false);
}

#[cfg(unix)]
#[test]
fn open_existing_and_open_reject_read_only_0444_file_at_open_time() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreMode(std::path::PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o644));
        }
    }

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("readonly_0444.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    {
        let mut init = SqliteLedger::open(&db_path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }

    let _restore = RestoreMode(db_path.clone());
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).unwrap();
    if fs::OpenOptions::new().write(true).open(&db_path).is_ok() {
        return;
    }

    let err_existing = SqliteLedger::open_existing(&db_path).unwrap_err();
    assert!(
        matches!(&err_existing, LedgerError::Storage(msg) if msg.contains("read-only")),
        "expected Storage read-only error from open_existing on 0444 file, got: {err_existing:?}"
    );

    let err_open = SqliteLedger::open(&db_path).unwrap_err();
    assert!(
        matches!(&err_open, LedgerError::Storage(msg) if msg.contains("read-only")),
        "expected Storage read-only error from open on 0444 file, got: {err_open:?}"
    );
}

#[cfg(unix)]
#[test]
fn reader_only_deferred_fd_child_helper() {
    let Ok(dir_str) = std::env::var("HANDFEST_READER_ONLY_DEFERRED_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir_str);
    let db_a = dir.join("reader_only_a.sqlite");
    let db_b = dir.join("reader_only_b.sqlite");
    let victim_c = dir.join("victim_c.sqlite");
    let victim_c_journal = dir.join("victim_c.sqlite-journal");
    let (_, req, _, _) = sample_chain_and_req();
    let canonical_a = fs::canonicalize(&db_a).unwrap();

    // Isolated subprocess: zero writers exist for the entire process lifetime.
    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);

    let ro1 = SqliteLedger::open_read_only(&db_a).unwrap();
    assert_eq!(active_writer_count(), 0);
    assert_eq!(active_handle_count(&canonical_a), 1);
    assert_eq!(deferred_fd_count(), 0);

    let (verified, maybe_rec) = run_audit_tx(&ro1.conn, Some(&req.actor_key), || {
        // 1. Fresh raw header open on an unrelated DB while active_writers == 0 closes immediately
        //    before open_conn (never occupying deferred_fds for an uncounted inode).
        {
            let ro_b = SqliteLedger::open_read_only(&db_b).unwrap();
            assert_eq!(deferred_fd_count(), 0);
            assert_eq!(ro_b.verify_integrity().unwrap(), 1);
        }
        assert_eq!(active_writer_count(), 0);
        assert_eq!(deferred_fd_count(), 0);

        // 2. Hard-linked journal probe on db_a's own inode while active_writers == 0 must still
        //    retain its fd rather than closing it and dropping ro1's POSIX SHARED lock.
        fs::hard_link(&db_a, &victim_c_journal).unwrap();
        let err = SqliteLedger::open_read_only(&victim_c).unwrap_err();
        assert!(matches!(err, LedgerError::Integrity(_)));
        fs::remove_file(&victim_c_journal).unwrap();
        assert_eq!(active_writer_count(), 0);
        assert_eq!(deferred_fd_count(), 1);

        assert_cross_process_exclusive_lock(&db_a, true);
    })
    .unwrap();

    assert_eq!(verified, 1);
    assert_eq!(maybe_rec.unwrap().total_decisions, 1);
    assert_eq!(active_writer_count(), 0);
    assert_eq!(
        deferred_fd_count(),
        1,
        "db_a deferred fd must remain retained while ro1 is still open"
    );

    drop(ro1);
    assert_eq!(active_handle_count(&canonical_a), 0);
    assert_eq!(active_writer_count(), 0);
    assert_eq!(
        deferred_fd_count(),
        0,
        "deferred_fds must clear as soon as the last reader drops"
    );
    assert_cross_process_exclusive_lock(&db_a, false);
}

#[cfg(unix)]
fn run_isolated_child_test(test_name: &str, env_key: &str, dir: &Path) {
    use std::process::Command;

    let exe = std::env::current_exe().expect("current test exe");
    let output = Command::new(&exe)
        .args(["--exact", test_name, "--quiet"])
        .env(env_key, dir)
        .output()
        .expect("spawn isolated child test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{test_name} child failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed"),
        "{test_name} child did not execute helper test; stdout:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn reader_only_deferred_fd_retains_and_preserves_shared_lock_with_zero_writers() {
    let dir = TempDir::new().unwrap();
    let (chain, req, facts, now) = sample_chain_and_req();
    for name in [
        "reader_only_a.sqlite",
        "reader_only_b.sqlite",
        "victim_c.sqlite",
    ] {
        let mut w = SqliteLedger::open(dir.path().join(name)).unwrap();
        w.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    run_isolated_child_test(
        "sqlite::tests::reader_only_deferred_fd_child_helper",
        "HANDFEST_READER_ONLY_DEFERRED_DIR",
        dir.path(),
    );
}

#[cfg(unix)]
#[test]
fn tracked_open_existing_rename_child_helper() {
    let Ok(dir_str) = std::env::var("HANDFEST_TRACKED_RENAME_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir_str);
    let db_path = dir.join("tracked_rename.sqlite");
    let renamed = dir.join("tracked_rename_moved.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();

    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    {
        let writer = SqliteLedger::open_existing(&db_path).unwrap();
        assert_eq!(active_writer_count(), 1);
        writer.conn.execute_batch("BEGIN IMMEDIATE;").unwrap();

        fs::rename(&db_path, &renamed).unwrap();
        {
            let mut replacement = SqliteLedger::open(&db_path).unwrap();
            replacement
                .evaluate_and_record(&chain, &req, &facts, now)
                .unwrap();
        }

        let ro_moved = SqliteLedger::open_read_only(&renamed).unwrap();
        assert_eq!(ro_moved.verify_integrity().unwrap(), 1);
        drop(ro_moved);

        let ro_replaced = SqliteLedger::open_read_only(&db_path).unwrap();
        assert_eq!(ro_replaced.verify_integrity().unwrap(), 1);
        drop(ro_replaced);

        assert_cross_process_exclusive_lock(&renamed, true);
        writer.conn.execute_batch("ROLLBACK;").unwrap();
    }
    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    assert_cross_process_exclusive_lock(&renamed, false);
}

#[cfg(unix)]
#[test]
fn tracked_open_existing_conn_preserves_lock_across_rename() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("tracked_rename.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    {
        let mut init = SqliteLedger::open(&db_path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    run_isolated_child_test(
        "sqlite::tests::tracked_open_existing_rename_child_helper",
        "HANDFEST_TRACKED_RENAME_DIR",
        dir.path(),
    );
}

#[cfg(unix)]
#[test]
fn tracked_open_existing_sidecar_child_helper() {
    use std::os::unix::fs::symlink;

    let Ok(dir_str) = std::env::var("HANDFEST_TRACKED_SIDECAR_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir_str);
    let active_db = dir.join("tracked_sidecar_active.sqlite");
    let victim_db = dir.join("tracked_sidecar_victim.sqlite");
    let victim_journal = dir.join("tracked_sidecar_victim.sqlite-journal");
    let victim_wal = dir.join("tracked_sidecar_victim.sqlite-wal");

    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    {
        let writer = SqliteLedger::open_existing(&active_db).unwrap();
        assert_eq!(active_writer_count(), 1);
        writer.conn.execute_batch("BEGIN IMMEDIATE;").unwrap();

        symlink(&active_db, &victim_journal).unwrap();
        let sym_j_err = SqliteLedger::open_read_only(&victim_db).unwrap_err();
        assert!(
            matches!(&sym_j_err, LedgerError::Integrity(msg) if msg.contains("symlink")),
            "expected symlink journal Integrity error, got: {sym_j_err:?}"
        );
        assert_cross_process_exclusive_lock(&active_db, true);
        fs::remove_file(&victim_journal).unwrap();

        symlink(&active_db, &victim_wal).unwrap();
        let sym_w_err = SqliteLedger::open_read_only(&victim_db).unwrap_err();
        assert!(
            matches!(&sym_w_err, LedgerError::Integrity(msg) if msg.contains("symlink")),
            "expected symlink WAL Integrity error, got: {sym_w_err:?}"
        );
        assert_cross_process_exclusive_lock(&active_db, true);
        fs::remove_file(&victim_wal).unwrap();

        fs::hard_link(&active_db, &victim_journal).unwrap();
        let hl_err = SqliteLedger::open_read_only(&victim_db).unwrap_err();
        assert!(
            matches!(hl_err, LedgerError::Integrity(_)),
            "expected hard-linked journal Integrity error, got: {hl_err:?}"
        );
        assert_cross_process_exclusive_lock(&active_db, true);
        fs::remove_file(&victim_journal).unwrap();

        writer.conn.execute_batch("ROLLBACK;").unwrap();
    }
    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    assert_cross_process_exclusive_lock(&active_db, false);
}

#[cfg(unix)]
#[test]
fn tracked_open_existing_conn_preserves_lock_across_journal_sidecars() {
    let dir = TempDir::new().unwrap();
    let active_db = dir.path().join("tracked_sidecar_active.sqlite");
    let victim_db = dir.path().join("tracked_sidecar_victim.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    for path in [&active_db, &victim_db] {
        let mut init = SqliteLedger::open(path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    run_isolated_child_test(
        "sqlite::tests::tracked_open_existing_sidecar_child_helper",
        "HANDFEST_TRACKED_SIDECAR_DIR",
        dir.path(),
    );
}

#[cfg(unix)]
#[test]
fn repeated_audits_dedup_child_helper() {
    let Ok(dir_str) = std::env::var("HANDFEST_REPEATED_AUDIT_DEDUP_DIR") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir_str);
    let db_a = dir.join("dedup_a.sqlite");
    let db_b = dir.join("dedup_b.sqlite");

    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    {
        let _writer_a = SqliteLedger::open_existing(&db_a).unwrap();
        assert_eq!(active_writer_count(), 1);
        for i in 0..70 {
            let ro_b = SqliteLedger::open_read_only(&db_b)
                .unwrap_or_else(|err| panic!("audit #{i} on db_b failed: {err:?}"));
            assert_eq!(ro_b.verify_integrity().unwrap(), 1);
            assert_eq!(
                deferred_fd_count(),
                1,
                "repeated audits on db_b must deduplicate to 1 deferred fd (iteration {i})"
            );
        }
        assert_eq!(deferred_fd_count(), 1);
    }
    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
}

#[cfg(unix)]
#[test]
fn repeated_audits_on_ledger_b_while_writer_a_open_deduplicate_deferred_fd() {
    let dir = TempDir::new().unwrap();
    let (chain, req, facts, now) = sample_chain_and_req();
    for name in ["dedup_a.sqlite", "dedup_b.sqlite"] {
        let mut init = SqliteLedger::open(dir.path().join(name)).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    run_isolated_child_test(
        "sqlite::tests::repeated_audits_dedup_child_helper",
        "HANDFEST_REPEATED_AUDIT_DEDUP_DIR",
        dir.path(),
    );
}

#[cfg(unix)]
#[test]
fn duplicate_deferred_fd_preserves_writer_lock_child_helper() {
    use std::os::unix::fs::MetadataExt;

    let Ok(dir_str) = std::env::var("HANDFEST_DUP_DEFERRED_FD_DIR") else {
        return;
    };
    let db_path = std::path::PathBuf::from(dir_str).join("dup_deferred.sqlite");

    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    {
        let writer = SqliteLedger::open_existing(&db_path).unwrap();
        assert_eq!(active_writer_count(), 1);
        writer.conn.execute_batch("BEGIN IMMEDIATE;").unwrap();

        let meta = fs::metadata(&db_path).unwrap();
        let key = (meta.dev(), meta.ino());

        let first = fs::File::open(&db_path).unwrap();
        defer_fd_for_test(key, first);
        assert_eq!(deferred_fd_count(), 1);

        // Deferring a second File on the same occupied (dev, ino) MUST push it onto Vec<File>
        // rather than dropping it (dropping would close() and release writer's POSIX lock).
        let second = fs::File::open(&db_path).unwrap();
        defer_fd_for_test(key, second);
        assert_cross_process_exclusive_lock(&db_path, true);
        assert_eq!(deferred_fd_count(), 2);
        writer.conn.execute_batch("ROLLBACK;").unwrap();
    }
    assert_eq!(active_writer_count(), 0);
    assert_eq!(deferred_fd_count(), 0);
    assert_cross_process_exclusive_lock(&db_path, false);
}

#[cfg(unix)]
#[test]
fn duplicate_deferred_fd_on_same_inode_preserves_writer_lock() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("dup_deferred.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    {
        let mut init = SqliteLedger::open(&db_path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    run_isolated_child_test(
        "sqlite::tests::duplicate_deferred_fd_preserves_writer_lock_child_helper",
        "HANDFEST_DUP_DEFERRED_FD_DIR",
        dir.path(),
    );
}

#[test]
fn open_existing_classifies_directory_cannot_open_as_storage_and_missing_as_not_found() {
    let dir = TempDir::new().unwrap();
    let missing_path = dir.path().join("does_not_exist.sqlite");

    // End-to-end SqliteLedger::open_existing: directory -> Storage, missing -> NotFound.
    let dir_err = SqliteLedger::open_existing(dir.path()).unwrap_err();
    assert!(
        matches!(dir_err, LedgerError::Storage(_)),
        "existing directory must map to LedgerError::Storage, got: {dir_err:?}"
    );
    let missing_err = SqliteLedger::open_existing(&missing_path).unwrap_err();
    assert!(
        matches!(missing_err, LedgerError::NotFound(_)),
        "missing file must map to LedgerError::NotFound, got: {missing_err:?}"
    );

    // Direct branch-binding tests for map_open_existing_error:
    let cantopen_err = || {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::CannotOpen,
                extended_code: rusqlite::ffi::SQLITE_CANTOPEN,
            },
            None,
        )
    };

    // 1. extended_code == rusqlite::ffi::SQLITE_CANTOPEN_ISDIR -> Storage even if path is missing.
    let isdir_code_err = map_open_existing_error(
        &missing_path,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::CannotOpen,
                extended_code: rusqlite::ffi::SQLITE_CANTOPEN_ISDIR,
            },
            None,
        ),
    );
    assert!(
        matches!(isdir_code_err, LedgerError::Storage(_)),
        "rusqlite::ffi::SQLITE_CANTOPEN_ISDIR must map to Storage, got: {isdir_code_err:?}"
    );

    // 2. Generic CannotOpen on an existing directory -> Storage (metadata is Ok).
    let dir_fallback_err = map_open_existing_error(dir.path(), cantopen_err());
    assert!(
        matches!(dir_fallback_err, LedgerError::Storage(_)),
        "generic CannotOpen on existing directory must map to Storage, got: {dir_fallback_err:?}"
    );

    // 3. Generic CannotOpen on an existing regular file -> Storage (metadata is Ok).
    let existing_file = dir.path().join("existing.sqlite");
    fs::write(&existing_file, b"placeholder").unwrap();
    let existing_file_err = map_open_existing_error(&existing_file, cantopen_err());
    assert!(
        matches!(existing_file_err, LedgerError::Storage(_)),
        "generic CannotOpen on existing file must map to Storage, got: {existing_file_err:?}"
    );

    // 4. Generic CannotOpen when path traverses a regular file (NotADirectory) -> Storage.
    let not_a_dir_child = existing_file.join("nested.sqlite");
    let not_a_dir_err = map_open_existing_error(&not_a_dir_child, cantopen_err());
    assert!(
        matches!(not_a_dir_err, LedgerError::Storage(_)),
        "generic CannotOpen on NotADirectory path must map to Storage, got: {not_a_dir_err:?}"
    );

    // 5. Generic CannotOpen on genuinely missing path (ErrorKind::NotFound) -> NotFound.
    let generic_missing_err = map_open_existing_error(&missing_path, cantopen_err());
    assert!(
        matches!(generic_missing_err, LedgerError::NotFound(_)),
        "generic CannotOpen on missing path must map to NotFound, got: {generic_missing_err:?}"
    );

    // 6. Non-CannotOpen SQLite error passes through as Storage.
    let other_err = map_open_existing_error(
        &missing_path,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy,
                extended_code: rusqlite::ffi::SQLITE_BUSY,
            },
            None,
        ),
    );
    assert!(
        matches!(other_err, LedgerError::Storage(_)),
        "non-CannotOpen error must map to Storage, got: {other_err:?}"
    );
}

#[cfg(unix)]
#[test]
fn open_existing_maps_symlink_cycle_and_0000_ledger_to_storage_not_not_found() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct RestoreMode(std::path::PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o644));
        }
    }

    let dir = TempDir::new().unwrap();

    // 1. 2-symlink cycle (ELOOP): metadata fails with non-NotFound error -> LedgerError::Storage.
    let loop_a = dir.path().join("cycle_a.sqlite");
    let loop_b = dir.path().join("cycle_b.sqlite");
    symlink(&loop_b, &loop_a).unwrap();
    symlink(&loop_a, &loop_b).unwrap();
    let cycle_err = SqliteLedger::open_existing(&loop_a).unwrap_err();
    assert!(
        matches!(cycle_err, LedgerError::Storage(_)),
        "2-symlink cycle must map to LedgerError::Storage, got: {cycle_err:?}"
    );

    // 2. Existing 0o000 ledger file: metadata succeeds (Ok), open fails -> LedgerError::Storage.
    let db_path = dir.path().join("mode_0000.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    {
        let mut init = SqliteLedger::open(&db_path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }
    let _restore = RestoreMode(db_path.clone());
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&db_path).is_ok() || fs::OpenOptions::new().write(true).open(&db_path).is_ok()
    {
        return;
    }

    let mode000_err = SqliteLedger::open_existing(&db_path).unwrap_err();
    assert!(
        matches!(mode000_err, LedgerError::Storage(_)),
        "existing 0o000 ledger must map to LedgerError::Storage, got: {mode000_err:?}"
    );
}

#[cfg(unix)]
#[test]
fn open_existing_maps_permission_denied_parent_dir_to_storage_not_not_found() {
    use std::os::unix::fs::PermissionsExt;

    struct RestoreDirMode(std::path::PathBuf);
    impl Drop for RestoreDirMode {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    let dir = TempDir::new().unwrap();
    let restricted_dir = dir.path().join("restricted_dir");
    fs::create_dir(&restricted_dir).unwrap();
    let db_path = restricted_dir.join("ledger.sqlite");
    let (chain, req, facts, now) = sample_chain_and_req();
    {
        let mut init = SqliteLedger::open(&db_path).unwrap();
        init.evaluate_and_record(&chain, &req, &facts, now).unwrap();
    }

    let _restore = RestoreDirMode(restricted_dir.clone());
    fs::set_permissions(&restricted_dir, fs::Permissions::from_mode(0o000)).unwrap();
    match fs::metadata(&db_path) {
        // Root / CAP_DAC_OVERRIDE bypasses 0o000 directory permissions.
        Ok(_) => return,
        Err(err) => assert_eq!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied,
            "expected PermissionDenied probing ledger inside 0o000 parent dir, got: {err:?}"
        ),
    }

    let err = SqliteLedger::open_existing(&db_path).unwrap_err();
    assert!(
        matches!(err, LedgerError::Storage(_)),
        "ledger inside 0o000 parent dir must map to LedgerError::Storage, got: {err:?}"
    );
}
