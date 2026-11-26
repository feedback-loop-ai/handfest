use std::sync::mpsc;

use handfest_core::ast::{parse_rfc3339_utc, Scalar};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::VerifiedAnchorProof;
use handfest_core::AssuranceLevel;
use tempfile::TempDir;

use crate::preflight::active_handle_count;

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
#[test]
fn ro_snapshot_exclusive_probe_helper() {
    let Ok(db_path) = std::env::var("HANDFEST_RO_SNAPSHOT_DB") else {
        return;
    };
    let conn = Connection::open(&db_path).expect("probe open");
    conn.busy_timeout(Duration::ZERO).unwrap();
    let res = conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;");
    let expect_locked = std::env::var("HANDFEST_RO_SNAPSHOT_EXPECT_LOCKED").as_deref() == Ok("1");
    if expect_locked {
        assert!(
            res.is_err(),
            "expected parent read-only POSIX SHARED lock to remain held, but child acquired EXCLUSIVE"
        );
    } else {
        res.expect("expected child EXCLUSIVE lock to succeed after parent read tx ended");
    }
}

#[cfg(unix)]
#[test]
fn concurrent_open_read_only_handles_preserve_posix_shared_lock_and_snapshot_isolation() {
    use std::process::Command;

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

    let exe = std::env::current_exe().expect("current test exe");
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

        let locked = Command::new(&exe)
            .args([
                "--exact",
                "sqlite::tests::ro_snapshot_exclusive_probe_helper",
                "--quiet",
            ])
            .env("HANDFEST_RO_SNAPSHOT_DB", &db_path)
            .env("HANDFEST_RO_SNAPSHOT_EXPECT_LOCKED", "1")
            .status()
            .expect("spawn locked probe");
        assert!(
            locked.success(),
            "second open_read_only dropped first reader's POSIX SHARED lock!"
        );

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

    let unlocked = Command::new(&exe)
        .args([
            "--exact",
            "sqlite::tests::ro_snapshot_exclusive_probe_helper",
            "--quiet",
        ])
        .env("HANDFEST_RO_SNAPSHOT_DB", &db_path)
        .env("HANDFEST_RO_SNAPSHOT_EXPECT_LOCKED", "0")
        .status()
        .expect("spawn unlocked probe");
    assert!(unlocked.success());

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
    use std::process::Command;

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
    let exe = std::env::current_exe().expect("current test exe");

    let (verified, maybe_rec) = run_audit_tx(&ro1.conn, Some(&req.actor_key), || {
        {
            let _writer_b = SqliteLedger::open_existing(&ledger_b).unwrap();
            fs::hard_link(&ledger_a, &victim_c_journal).unwrap();
            let err = SqliteLedger::open_read_only(&victim_c).unwrap_err();
            assert!(matches!(err, LedgerError::Integrity(_)));
            fs::remove_file(&victim_c_journal).unwrap();
        }
        let locked = Command::new(&exe)
            .args([
                "--exact",
                "sqlite::tests::ro_snapshot_exclusive_probe_helper",
                "--quiet",
            ])
            .env("HANDFEST_RO_SNAPSHOT_DB", &ledger_a)
            .env("HANDFEST_RO_SNAPSHOT_EXPECT_LOCKED", "1")
            .status()
            .expect("spawn locked probe");
        assert!(
            locked.success(),
            "dropping writer B while ro1 held audit_snapshot SHARED lock dropped ro1's POSIX lock!"
        );
    })
    .unwrap();

    assert_eq!(verified, 1);
    assert_eq!(maybe_rec.unwrap().total_decisions, 1);
    drop(ro1);

    let unlocked = Command::new(&exe)
        .args([
            "--exact",
            "sqlite::tests::ro_snapshot_exclusive_probe_helper",
            "--quiet",
        ])
        .env("HANDFEST_RO_SNAPSHOT_DB", &ledger_a)
        .env("HANDFEST_RO_SNAPSHOT_EXPECT_LOCKED", "0")
        .status()
        .expect("spawn unlocked probe");
    assert!(unlocked.success());
}
