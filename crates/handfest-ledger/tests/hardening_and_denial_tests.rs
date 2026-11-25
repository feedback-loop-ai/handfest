use std::fs;

use handfest_core::ast::{
    parse_rfc3339_utc, Decimal, HandfestAst, KeyId, MandateId, Scalar, MAX_RFC3339_TIMESTAMP,
    MIN_RFC3339_TIMESTAMP,
};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{
    ActionRequest, DecisionReceipt, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate,
};
use handfest_core::{AssuranceLevel, Verdict};
use handfest_ledger::{LedgerError, ReceiptLedger, SqliteLedger};
use rusqlite::Connection;
use tempfile::TempDir;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid RFC 3339 UTC timestamp")
}

fn key(s: &str) -> KeyId {
    KeyId::parse(s).expect("valid key id")
}

fn dec(s: &str) -> Decimal {
    Decimal::parse(s).expect("valid decimal")
}

fn verified(ast: HandfestAst) -> VerifiedMandate {
    let proof = VerifiedAnchorProof {
        anchor_id: "test-anchor".to_string(),
        assurance: AssuranceLevel::LocalKey,
        signer_key: ast.from().key().clone(),
        actor_kind: ast.from().kind(),
        valid_from: ts("2026-11-24T00:00:00Z"),
        valid_until: ts("2026-11-26T00:00:00Z"),
    };
    VerifiedMandate { ast, proof }
}

fn sum_and_calls_mandate() -> (VerifiedMandate, ActionRequest, VerifiedFacts) {
    let vm = verified(
        parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"bot\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 100.0 USD sum(resource.amount)\n",
        ))
        .unwrap(),
    );
    let req = ActionRequest {
        actor_key: key("ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        action: "pay.transfer".to_string(),
        resource_kind: "account".to_string(),
        resource_id: "ops-main".to_string(),
    };
    let facts = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("25.0")));
    (vm, req, facts)
}

#[cfg(unix)]
#[test]
fn open_read_only_rejects_wal_and_truncated_files_with_zero_sidecars() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (vm, req, facts) = sum_and_calls_mandate();

    // (a) Uncheckpointed WAL without -shm in a writable 0755 directory -> rejected, zero -shm created.
    let unchk_src = dir.path().join("unchk_src");
    let unchk_dir = dir.path().join("unchk_0755");
    fs::create_dir_all(&unchk_src).unwrap();
    fs::create_dir_all(&unchk_dir).unwrap();
    let src_db = unchk_src.join("ledger.sqlite");
    let src_wal = unchk_src.join("ledger.sqlite-wal");
    {
        let mut ledger = SqliteLedger::open(&src_db).unwrap();
        ledger
            .evaluate_and_record(
                std::slice::from_ref(&vm),
                &req,
                &facts,
                ts("2026-11-24T18:00:00Z"),
            )
            .unwrap();
        drop(ledger);
        let wal_conn = Connection::open(&src_db).unwrap();
        wal_conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        wal_conn
            .execute("INSERT INTO quota_calls VALUES ('x', 1)", [])
            .unwrap();
        assert!(fs::metadata(&src_wal).unwrap().len() > 0);
        fs::copy(&src_db, unchk_dir.join("ledger.sqlite")).unwrap();
        fs::copy(&src_wal, unchk_dir.join("ledger.sqlite-wal")).unwrap();
    }
    fs::set_permissions(&unchk_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let unchk_db = unchk_dir.join("ledger.sqlite");
    let unchk_shm = unchk_dir.join("ledger.sqlite-shm");
    assert!(!unchk_shm.exists());
    let err = SqliteLedger::open_read_only(&unchk_db).unwrap_err();
    assert!(matches!(err, LedgerError::Integrity(_)));
    assert!(
        !unchk_shm.exists(),
        "open_read_only must not create -shm in a 0755 directory"
    );

    // (b) Cleanly closed 0444 WAL-header DB in a writable 0755 directory -> rejected, zero -wal/-shm created.
    let closed_dir = dir.path().join("closed_wal_0755");
    fs::create_dir_all(&closed_dir).unwrap();
    let closed_db = closed_dir.join("ledger.sqlite");
    let closed_wal = closed_dir.join("ledger.sqlite-wal");
    let closed_shm = closed_dir.join("ledger.sqlite-shm");
    {
        let mut ledger = SqliteLedger::open(&closed_db).unwrap();
        ledger
            .evaluate_and_record(&[vm], &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        drop(ledger);
        let wal_conn = Connection::open(&closed_db).unwrap();
        wal_conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        wal_conn
            .execute("UPDATE quota_calls SET calls = calls", [])
            .unwrap();
    }
    assert!(!closed_wal.exists());
    assert!(!closed_shm.exists());
    let hdr = fs::read(&closed_db).unwrap();
    assert_eq!(hdr[18], 2);
    assert_eq!(hdr[19], 2);

    fs::set_permissions(&closed_db, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&closed_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let err = SqliteLedger::open_read_only(&closed_db).unwrap_err();
    assert!(matches!(err, LedgerError::Integrity(_)));
    assert!(
        !closed_wal.exists(),
        "open_read_only must not create -wal on a 0444 WAL-header DB in a 0755 directory"
    );
    assert!(
        !closed_shm.exists(),
        "open_read_only must not create -shm on a 0444 WAL-header DB in a 0755 directory"
    );
    fs::set_permissions(&closed_db, fs::Permissions::from_mode(0o644)).unwrap();

    // (c) Truncated 0-byte file, directory, non-SQLite file, and live locked WAL are tested below.
}

#[cfg(unix)]
#[test]
fn open_read_only_rejects_truncated_non_sqlite_and_live_locked_wal() {
    let dir = TempDir::new().unwrap();

    // Truncated 0-byte file, directory, and non-SQLite file are rejected.
    let zero_file = dir.path().join("truncated.sqlite");
    fs::write(&zero_file, b"").unwrap();
    assert!(matches!(
        SqliteLedger::open_read_only(&zero_file),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        SqliteLedger::open_read_only(dir.path()),
        Err(LedgerError::Integrity(_))
    ));
    let garbage = dir.path().join("garbage.sqlite");
    fs::write(&garbage, vec![b'X'; 4096]).unwrap();
    assert!(matches!(
        SqliteLedger::open_read_only(&garbage),
        Err(LedgerError::Integrity(_))
    ));

    // (d) Live in-process WAL reader holding a POSIX lock on main DB inode with 0-byte -wal
    // still fails closed via the post-open PRAGMA journal_mode check.
    let live_wal_db = dir.path().join("live_wal_locked.sqlite");
    let live_conn = Connection::open(&live_wal_db).unwrap();
    live_conn
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    live_conn.execute("CREATE TABLE t(x INT)", []).unwrap();
    let _: (i64, i64, i64) = live_conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    live_conn.execute_batch("BEGIN; SELECT * FROM t;").unwrap();
    assert!(matches!(
        SqliteLedger::open_read_only(&live_wal_db),
        Err(LedgerError::Integrity(_))
    ));
    live_conn.execute_batch("END;").unwrap();
}

#[test]
fn verify_integrity_rejects_rogue_triggers_duplicate_quota_keys_blob_and_empty_permit_chain() {
    let dir = TempDir::new().unwrap();
    let (vm, req, facts) = sum_and_calls_mandate();
    let mid = vm.ast.mandate_id();

    let make_db = |name: &str| {
        let path = dir.path().join(name);
        let mut ledger = SqliteLedger::open(&path).unwrap();
        let (v, _) = ledger
            .evaluate_and_record(
                std::slice::from_ref(&vm),
                &req,
                &facts,
                ts("2026-11-24T18:00:00Z"),
            )
            .unwrap();
        assert_eq!(v, Verdict::Permit);
        path
    };

    // 1. Rogue CREATE TRIGGER quota reset.
    let trig_db = make_db("rogue_trigger.sqlite");
    {
        let raw = Connection::open(&trig_db).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER reset_quota AFTER INSERT ON receipts BEGIN UPDATE quota_calls SET calls = 0; END;",
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&trig_db)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 2. Duplicate quota_calls rows (table rebuilt without PRIMARY KEY).
    let dup_calls_db = make_db("dup_calls.sqlite");
    {
        let raw = Connection::open(&dup_calls_db).unwrap();
        raw.execute_batch(
            "DROP TABLE quota_calls;
             CREATE TABLE quota_calls (mandate_id TEXT NOT NULL, calls INTEGER NOT NULL);",
        )
        .unwrap();
        raw.execute(
            "INSERT INTO quota_calls (mandate_id, calls) VALUES (?1, 1)",
            [mid.to_string()],
        )
        .unwrap();
        raw.execute(
            "INSERT INTO quota_calls (mandate_id, calls) VALUES (?1, 1)",
            [mid.to_string()],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&dup_calls_db)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 3. Duplicate quota_sums rows (table rebuilt without PRIMARY KEY).
    let dup_sums_db = make_db("dup_sums.sqlite");
    {
        let raw = Connection::open(&dup_sums_db).unwrap();
        raw.execute_batch(
            "DROP TABLE quota_sums;
             CREATE TABLE quota_sums (mandate_id TEXT NOT NULL, unit TEXT NOT NULL, field TEXT NOT NULL, total TEXT NOT NULL);",
        )
        .unwrap();
        for _ in 0..2 {
            raw.execute(
                "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, 'USD', 'resource.amount', '25.0')",
                [mid.to_string()],
            )
            .unwrap();
        }
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&dup_sums_db)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn verify_integrity_rejects_blob_quota_total_and_empty_permit_chain() {
    let dir = TempDir::new().unwrap();
    let (vm, req, facts) = sum_and_calls_mandate();

    // 4. BLOB stored in quota_sums.total.
    let blob_db = dir.path().join("blob_total.sqlite");
    {
        let mut ledger = SqliteLedger::open(&blob_db).unwrap();
        let (v, _) = ledger
            .evaluate_and_record(&[vm], &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        assert_eq!(v, Verdict::Permit);
    }
    {
        let raw = Connection::open(&blob_db).unwrap();
        raw.execute("UPDATE quota_sums SET total = X'32352E30'", [])
            .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&blob_db)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 5. Permit receipt with empty chain_ids_json = '[]' (even with valid recomputed receipt_hash).
    let empty_chain_db = dir.path().join("empty_permit_chain.sqlite");
    {
        let _init = SqliteLedger::open(&empty_chain_db).unwrap();
        let mut forged = DecisionReceipt {
            chain_ids: vec![],
            actor_key: req.actor_key.clone(),
            action: req.action.clone(),
            resource: format!("{} \"{}\"", req.resource_kind, req.resource_id),
            timestamp: ts("2026-11-24T18:00:00Z"),
            verdict: Verdict::Permit,
            receipt_hash: MandateId([0u8; 32]),
            prev_receipt_hash: None,
        };
        forged.receipt_hash = forged.compute_hash();
        let raw = Connection::open(&empty_chain_db).unwrap();
        raw.execute(
            "INSERT INTO receipts (
                prev_receipt_hash, receipt_hash, chain_ids_json, actor_key,
                action, resource_kind, resource_id, timestamp, verdict, deny_reason
             ) VALUES (NULL, ?1, '[]', ?2, ?3, ?4, ?5, ?6, 'permit', NULL)",
            rusqlite::params![
                forged.receipt_hash.to_string(),
                forged.actor_key.to_string(),
                forged.action,
                req.resource_kind,
                req.resource_id,
                forged.timestamp,
            ],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&empty_chain_db)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn open_rejects_ephemeral_or_uri_paths_and_transitions_existing_wal_db_to_delete() {
    let dir = TempDir::new().unwrap();

    // Reject empty and ":memory:" paths in SqliteLedger::open.
    assert!(matches!(
        SqliteLedger::open(""),
        Err(LedgerError::Storage(_))
    ));
    assert!(matches!(
        SqliteLedger::open(":memory:"),
        Err(LedgerError::Storage(_))
    ));

    // SQLite URI paths must be rejected cleanly (even though bundled SQLite enables SQLITE_USE_URI).
    let uri_target = dir.path().join("should_not_exist.sqlite");
    let uri_path = format!("file:{}?mode=rwc", uri_target.display());
    assert!(matches!(
        SqliteLedger::open(&uri_path),
        Err(LedgerError::Storage(_))
    ));
    assert!(matches!(
        SqliteLedger::open("file::memory:?cache=shared"),
        Err(LedgerError::Storage(_))
    ));
    assert!(!uri_target.exists());

    // Create a genuine pre-existing WAL-mode SQLite database, prove it is WAL, then open with
    // SqliteLedger::open and verify it transitions cleanly to DELETE mode with zero sidecars.
    let wal_db = dir.path().join("preexisting_wal.sqlite");
    {
        let raw = Connection::open(&wal_db).unwrap();
        let mode: String = raw
            .query_row("PRAGMA journal_mode = WAL;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        raw.execute_batch(
            "CREATE TABLE _tmp(x INT); INSERT INTO _tmp VALUES (1); DROP TABLE _tmp;",
        )
        .unwrap();
    }
    let pre_hdr = fs::read(&wal_db).unwrap();
    assert_eq!(
        pre_hdr[18], 2,
        "pre-existing fixture must have WAL write version"
    );
    assert_eq!(
        pre_hdr[19], 2,
        "pre-existing fixture must have WAL read version"
    );

    {
        let ledger = SqliteLedger::open(&wal_db).unwrap();
        assert_eq!(ledger.verify_integrity().unwrap(), 0);
    }

    let post_hdr = fs::read(&wal_db).unwrap();
    assert_eq!(
        post_hdr[18], 1,
        "SqliteLedger::open must transition WAL header write version to 1"
    );
    assert_eq!(
        post_hdr[19], 1,
        "SqliteLedger::open must transition WAL header read version to 1"
    );
    assert!(!dir.path().join("preexisting_wal.sqlite-wal").exists());
    assert!(!dir.path().join("preexisting_wal.sqlite-shm").exists());

    let ro = SqliteLedger::open_read_only(&wal_db).unwrap();
    assert_eq!(ro.verify_integrity().unwrap(), 0);
}

#[test]
fn track_record_fails_closed_on_tampered_deny_row() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("tampered_track_record.sqlite");
    let (vm, mut req, facts) = sum_and_calls_mandate();
    req.action = "pay.forbidden".to_string();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        let (verdict, _) = ledger
            .evaluate_and_record(&[vm], &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        assert!(matches!(verdict, Verdict::Deny { .. }));
    }

    // Tamper the Deny receipt row to 'permit'.
    {
        let raw = Connection::open(&db_path).unwrap();
        raw.execute(
            "UPDATE receipts SET verdict = 'permit', deny_reason = NULL WHERE seq = 1",
            [],
        )
        .unwrap();
    }

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let dyn_ro: &dyn ReceiptLedger = &ro;
    assert!(matches!(
        dyn_ro.track_record(&req.actor_key),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn record_denial_chains_with_evaluate_and_record_preserves_quotas_and_updates_track_record() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("record_denial.sqlite");
    let (vm, req, facts) = sum_and_calls_mandate();
    let mid = vm.ast.mandate_id();

    let mut ledger = SqliteLedger::open(&db_path).unwrap();
    let dyn_ledger: &mut dyn ReceiptLedger = &mut ledger;

    // 1. Genesis pre-gate denial (empty chain_ids, control chars in action/resource).
    let pre_req = ActionRequest {
        actor_key: req.actor_key.clone(),
        action: "mcp.unknown\n\\tool".to_string(),
        resource_kind: "tool\\k".to_string(),
        resource_id: "shell\"exec\x07".to_string(),
    };
    let r1 = dyn_ledger
        .record_denial(
            vec![],
            &pre_req,
            ts("2026-11-24T18:00:00Z"),
            "unknown tool".to_string(),
        )
        .unwrap();
    assert!(r1.verify_hash());
    assert_eq!(r1.prev_receipt_hash, None);
    assert_eq!(
        r1.verdict,
        Verdict::Deny {
            reason: "unknown tool".to_string()
        }
    );

    // 2. Normal Permit via evaluate_and_record links to r1.
    let (v2, r2) = dyn_ledger
        .evaluate_and_record(&[vm], &req, &facts, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert_eq!(v2, Verdict::Permit);
    assert!(r2.verify_hash());
    assert_eq!(r2.prev_receipt_hash, Some(r1.receipt_hash));

    // 3. Chained pre-gate denial with explicit chain_ids links to r2 and does NOT modify quotas.
    let r3 = dyn_ledger
        .record_denial(
            vec![mid],
            &req,
            ts("2026-11-24T18:02:00Z"),
            "missing broker fact".to_string(),
        )
        .unwrap();
    assert!(r3.verify_hash());
    assert_eq!(r3.prev_receipt_hash, Some(r2.receipt_hash));
    assert_eq!(r3.chain_ids, vec![mid]);

    // 4. Out-of-range timestamps fail closed without mutating the ledger.
    assert!(matches!(
        dyn_ledger.record_denial(
            vec![],
            &req,
            MIN_RFC3339_TIMESTAMP - 1,
            "bad ts".to_string(),
        ),
        Err(LedgerError::Integrity(_))
    ));
    assert!(matches!(
        dyn_ledger.record_denial(
            vec![],
            &req,
            MAX_RFC3339_TIMESTAMP + 1,
            "bad ts".to_string(),
        ),
        Err(LedgerError::Integrity(_))
    ));

    // Verify integrity, quotas unchanged by record_denial, and track_record counts.
    assert_eq!(dyn_ledger.verify_integrity().unwrap(), 3);
    let rec = dyn_ledger.track_record(&req.actor_key).unwrap();
    assert_eq!(rec.total_decisions, 3);
    assert_eq!(rec.permits, 1);
    assert_eq!(rec.denies, 2);
    assert_eq!(rec.distinct_mandates, 1);
    assert_eq!(rec.first_timestamp, Some(ts("2026-11-24T18:00:00Z")));
    assert_eq!(rec.last_timestamp, Some(ts("2026-11-24T18:02:00Z")));

    // Read-only audit also verifies all 3 receipts cleanly.
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    assert_eq!(ro.verify_integrity().unwrap(), 3);
    assert_eq!(ro.track_record(&req.actor_key).unwrap(), rec);
}
