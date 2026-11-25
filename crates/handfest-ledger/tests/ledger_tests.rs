use handfest_core::ast::{parse_rfc3339_utc, Decimal, HandfestAst, KeyId, MandateId, Scalar};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{ActionRequest, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate};
use handfest_core::{AssuranceLevel, Verdict};
use handfest_ledger::{LedgerError, ReceiptLedger, SqliteLedger, TrackRecord};
use rusqlite::Connection;
use tempfile::TempDir;

fn ts(s: &str) -> i64 {
    parse_rfc3339_utc(s).expect("valid timestamp")
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

fn root_calls_mandate(limit_calls: u64) -> VerifiedMandate {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "FROM human \"valentin\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"dispatcher\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 1 hop\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/*\"\n",
            "WHERE resource.author == \"valentin\"\n",
            "LIMIT {limit_calls} calls\n",
        ),
        limit_calls = limit_calls
    ))
    .unwrap();
    verified(ast)
}

fn child_calls_mandate(parent: MandateId, label: &str, limit_calls: u64) -> VerifiedMandate {
    let ast = parse_mandate(&format!(
        concat!(
            "HANDFEST v1\n",
            "PARENT {parent}\n",
            "FROM agent \"dispatcher\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "TO agent \"{label}\" (key: ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW git.pr.merge\n",
            "ON repo \"feedback-loop-ai/handfest\"\n",
            "WHERE resource.author == \"valentin\"\n",
            "LIMIT {limit_calls} calls\n",
        ),
        parent = parent,
        label = label,
        limit_calls = limit_calls
    ))
    .unwrap();
    verified(ast)
}

fn merge_request() -> ActionRequest {
    ActionRequest {
        actor_key: key("ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        action: "git.pr.merge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "feedback-loop-ai/handfest".to_string(),
    }
}

fn valentin_facts() -> VerifiedFacts {
    VerifiedFacts::new().with("resource.author", Scalar::Str("valentin".to_string()))
}

#[test]
fn root_child_permit_and_deny_persistence_and_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("ledger.sqlite");

    let root = root_calls_mandate(2);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 2);
    let chain = [root, child];

    let mut ledger = SqliteLedger::open(&db_path).expect("open ledger");
    let (v1, r1) = ledger
        .evaluate_and_record(
            &chain,
            &merge_request(),
            &valentin_facts(),
            ts("2026-11-24T18:00:00Z"),
        )
        .expect("permit call");
    assert_eq!(v1, Verdict::Permit);
    assert!(r1.prev_receipt_hash.is_none());
    assert!(r1.verify_hash());

    let wrong_facts =
        VerifiedFacts::new().with("resource.author", Scalar::Str("mallory".to_string()));
    let (v2, r2) = ledger
        .evaluate_and_record(
            &chain,
            &merge_request(),
            &wrong_facts,
            ts("2026-11-24T18:01:00Z"),
        )
        .expect("deny call");
    assert!(matches!(v2, Verdict::Deny { .. }));
    assert_eq!(r2.prev_receipt_hash, Some(r1.receipt_hash));
    assert!(r2.verify_hash());
    drop(ledger);

    // Reopen from disk and confirm rollback-journal persistence + integrity.
    let reopened = SqliteLedger::open(&db_path).expect("reopen ledger");
    assert_eq!(reopened.verify_integrity().expect("integrity ok"), 2);
}

#[test]
fn anti_splitting_calls_across_distinct_child_mandates_in_sqlite() {
    let mut ledger = SqliteLedger::open_in_memory().expect("in-memory ledger");

    let root = root_calls_mandate(2);
    let root_id = root.ast.mandate_id();
    let m1 = child_calls_mandate(root_id, "seat-m1", 2);
    let m2 = child_calls_mandate(root_id, "seat-m2", 2);
    assert_ne!(m1.ast.mandate_id(), m2.ast.mandate_id());

    let chain_m1 = [root.clone(), m1];
    let chain_m2 = [root, m2];
    let req = merge_request();
    let facts = valentin_facts();

    // 1st call via M1: Permit (root=1/2, M1=1/2)
    let (v1, _) = ledger
        .evaluate_and_record(&chain_m1, &req, &facts, ts("2026-11-24T18:00:00Z"))
        .unwrap();
    assert_eq!(v1, Verdict::Permit);

    // 2nd call via M1: Permit (root=2/2, M1=2/2)
    let (v2, _) = ledger
        .evaluate_and_record(&chain_m1, &req, &facts, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert_eq!(v2, Verdict::Permit);

    // 3rd call via distinct child M2 (M2=0/2, but root=2/2): MUST be DENIED!
    let (v3, r3) = ledger
        .evaluate_and_record(&chain_m2, &req, &facts, ts("2026-11-24T18:02:00Z"))
        .unwrap();
    assert!(matches!(v3, Verdict::Deny { ref reason } if reason.contains("call quota exhausted")));
    assert!(r3.verify_hash());

    assert_eq!(ledger.verify_integrity().unwrap(), 3);

    let tr = ledger.track_record(&req.actor_key).unwrap();
    assert_eq!(tr.actor_key, req.actor_key);
    assert_eq!(tr.total_decisions, 3);
    assert_eq!(tr.permits, 2);
    assert_eq!(tr.denies, 1);
    // Counts distinct leaf mandates (m1 and m2), excluding the shared root mandate.
    assert_eq!(tr.distinct_mandates, 2);
    assert_eq!(tr.first_timestamp, Some(ts("2026-11-24T18:00:00Z")));
    assert_eq!(tr.last_timestamp, Some(ts("2026-11-24T18:02:00Z")));

    let unknown = ledger
        .track_record(&key(
            "ed25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ))
        .unwrap();
    assert_eq!(unknown.total_decisions, 0);
    assert_eq!(unknown.distinct_mandates, 0);
    assert_eq!(unknown.first_timestamp, None);
    assert_eq!(unknown.last_timestamp, None);
}

#[test]
fn sum_quota_atomic_accumulation_across_parent_and_children() {
    let mut ledger = SqliteLedger::open_in_memory().unwrap();

    let root = verified(
        parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 1 hop\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 100.0 USD sum(resource.amount)\n",
        ))
        .unwrap(),
    );
    let root_id = root.ast.mandate_id();

    let make_child = |name: &str| {
        verified(
            parse_mandate(&format!(
                concat!(
                    "HANDFEST v1\n",
                    "PARENT {root_id}\n",
                    "FROM agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
                    "TO agent \"{name}\" (key: ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)\n",
                    "DELEGATION max 0 hops\n",
                    "ALLOW pay.transfer\n",
                    "ON account \"ops-main\"\n",
                    "LIMIT 80.0 USD sum(resource.amount)\n",
                ),
                root_id = root_id,
                name = name
            ))
            .unwrap(),
        )
    };

    let c1 = [root.clone(), make_child("worker-1")];
    let c2 = [root, make_child("worker-2")];
    let req = ActionRequest {
        actor_key: key("ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        action: "pay.transfer".to_string(),
        resource_kind: "account".to_string(),
        resource_id: "ops-main".to_string(),
    };

    // 60.50 via worker-1 -> Permit (root=60.50, worker-1=60.50)
    let f1 = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("60.50")));
    let (v1, _) = ledger
        .evaluate_and_record(&c1, &req, &f1, ts("2026-11-24T18:00:00Z"))
        .unwrap();
    assert_eq!(v1, Verdict::Permit);

    // 39.50 via worker-2 -> Permit (root=100.00 exact boundary, worker-2=39.50)
    let f2 = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("39.50")));
    let (v2, _) = ledger
        .evaluate_and_record(&c2, &req, &f2, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert_eq!(v2, Verdict::Permit);

    // 0.01 via worker-2 -> Deny (root would be 100.01 > 100.0)
    let f3 = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("0.01")));
    let (v3, _) = ledger
        .evaluate_and_record(&c2, &req, &f3, ts("2026-11-24T18:02:00Z"))
        .unwrap();
    assert!(matches!(v3, Verdict::Deny { ref reason } if reason.contains("sum quota exceeded")));
    assert_eq!(ledger.verify_integrity().unwrap(), 3);
}

#[test]
fn verify_integrity_catches_sql_tampering_and_missing_rows() {
    let dir = TempDir::new().unwrap();
    let root = root_calls_mandate(1);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 1);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    let make_populated_db = |name: &str| {
        let path = dir.path().join(name);
        let mut ledger = SqliteLedger::open(&path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
            .unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:02:00Z"))
            .unwrap();
        assert_eq!(ledger.verify_integrity().unwrap(), 3);
        path
    };

    // 1. Tamper verdict from deny -> permit on seq 2.
    let db1 = make_populated_db("tamper_verdict.sqlite");
    {
        let raw = Connection::open(&db1).unwrap();
        raw.execute(
            "UPDATE receipts SET verdict = 'permit', deny_reason = NULL WHERE seq = 2",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open(&db1).unwrap().verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 2. Tamper prev_receipt_hash on seq 2.
    let db2 = make_populated_db("tamper_prev.sqlite");
    {
        let raw = Connection::open(&db2).unwrap();
        raw.execute(
            "UPDATE receipts SET prev_receipt_hash = ?1 WHERE seq = 2",
            [format!("sha256:{}", "0".repeat(64))],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open(&db2).unwrap().verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 3. Delete middle row (seq = 2).
    let db3 = make_populated_db("delete_mid.sqlite");
    {
        let raw = Connection::open(&db3).unwrap();
        raw.execute("DELETE FROM receipts WHERE seq = 2", [])
            .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open(&db3).unwrap().verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 4. Delete genesis row (seq = 1).
    let db4 = make_populated_db("delete_genesis.sqlite");
    {
        let raw = Connection::open(&db4).unwrap();
        raw.execute("DELETE FROM receipts WHERE seq = 1", [])
            .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open(&db4).unwrap().verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn denied_control_char_request_preserves_receipt_integrity_and_negative_quota_rolls_back() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("edge.sqlite");
    let mut ledger = SqliteLedger::open(&db_path).unwrap();

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];

    // Control characters in action and resource_id produce a Deny receipt that still hashes cleanly.
    let bad_req = ActionRequest {
        actor_key: key("ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        action: "git.pr\nmerge".to_string(),
        resource_kind: "repo".to_string(),
        resource_id: "org/\"bad\"\nrepo".to_string(),
    };
    let (verdict, receipt) = ledger
        .evaluate_and_record(
            &chain,
            &bad_req,
            &valentin_facts(),
            ts("2026-11-24T18:00:00Z"),
        )
        .unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    assert!(receipt.verify_hash());
    assert_eq!(ledger.verify_integrity().unwrap(), 1);

    // Inject corrupt negative quota_sums row; subsequent evaluation must fail & roll back cleanly.
    let root_id = chain[0].ast.mandate_id().to_string();
    {
        let raw = Connection::open(&db_path).unwrap();
        raw.execute(
            "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, 'USD', 'resource.amount', '-1.0')",
            [root_id],
        )
        .unwrap();
    }
    let err = ledger
        .evaluate_and_record(
            &chain,
            &merge_request(),
            &valentin_facts(),
            ts("2026-11-24T18:01:00Z"),
        )
        .unwrap_err();
    assert!(matches!(err, LedgerError::QuotaAccounting(_)));
    // Structural quota_sums validation must also reject the injected corrupt row.
    assert!(matches!(
        ledger.verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
    // Receipt count must remain 1 (rolled back); removing the corrupt row restores integrity.
    {
        let raw = Connection::open(&db_path).unwrap();
        let count: i64 = raw
            .query_row("SELECT COUNT(*) FROM receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        raw.execute("DELETE FROM quota_sums", []).unwrap();
    }
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
}

#[test]
fn concurrent_connections_enforce_delete_journal_and_atomic_quota_without_race() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.sqlite");

    // Initialize schema and verify rollback-journal DELETE mode on file-backed DB.
    let init_ledger = SqliteLedger::open(&db_path).unwrap();
    drop(init_ledger);
    {
        let raw = Connection::open(&db_path).unwrap();
        let mode: String = raw
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "delete");
        assert!(!dir.path().join("concurrent.sqlite-wal").exists());
        assert!(!dir.path().join("concurrent.sqlite-shm").exists());
        assert!(!dir.path().join("concurrent.sqlite-journal").exists());
    }

    let root = root_calls_mandate(2);
    let root_id = root.ast.mandate_id();
    let m1 = child_calls_mandate(root_id, "worker-a", 2);
    let m2 = child_calls_mandate(root_id, "worker-b", 2);
    let chain_a = vec![root.clone(), m1];
    let chain_b = vec![root, m2];

    let results: Vec<Verdict> = std::thread::scope(|s| {
        let h1 = s.spawn(|| {
            let mut l = SqliteLedger::open(&db_path).unwrap();
            let req = merge_request();
            let facts = valentin_facts();
            let (v1, _) = l
                .evaluate_and_record(&chain_a, &req, &facts, ts("2026-11-24T18:00:00Z"))
                .unwrap();
            let (v2, _) = l
                .evaluate_and_record(&chain_a, &req, &facts, ts("2026-11-24T18:00:01Z"))
                .unwrap();
            vec![v1, v2]
        });
        let h2 = s.spawn(|| {
            let mut l = SqliteLedger::open(&db_path).unwrap();
            let req = merge_request();
            let facts = valentin_facts();
            let (v1, _) = l
                .evaluate_and_record(&chain_b, &req, &facts, ts("2026-11-24T18:00:02Z"))
                .unwrap();
            let (v2, _) = l
                .evaluate_and_record(&chain_b, &req, &facts, ts("2026-11-24T18:00:03Z"))
                .unwrap();
            vec![v1, v2]
        });
        let mut all = h1.join().unwrap();
        all.extend(h2.join().unwrap());
        all
    });

    let permits = results
        .iter()
        .filter(|v| matches!(v, Verdict::Permit))
        .count();
    let denies = results
        .iter()
        .filter(|v| matches!(v, Verdict::Deny { .. }))
        .count();
    assert_eq!(permits, 2);
    assert_eq!(denies, 2);

    let audit = SqliteLedger::open(&db_path).unwrap();
    assert_eq!(audit.verify_integrity().unwrap(), 4);
}

#[test]
fn child_sum_quota_enforced_directly_below_root_limit() {
    let mut ledger = SqliteLedger::open_in_memory().unwrap();
    let root = verified(
        parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 1 hop\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 100.0 USD sum(resource.amount)\n",
        ))
        .unwrap(),
    );
    let root_id = root.ast.mandate_id();
    let child = verified(
        parse_mandate(&format!(
            concat!(
                "HANDFEST v1\n",
                "PARENT {root_id}\n",
                "FROM agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
                "TO agent \"worker-child\" (key: ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)\n",
                "DELEGATION max 0 hops\n",
                "ALLOW pay.transfer\n",
                "ON account \"ops-main\"\n",
                "LIMIT 60.0 USD sum(resource.amount)\n",
            ),
            root_id = root_id
        ))
        .unwrap(),
    );
    let chain = [root, child];
    let req = ActionRequest {
        actor_key: key("ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        action: "pay.transfer".to_string(),
        resource_kind: "account".to_string(),
        resource_id: "ops-main".to_string(),
    };

    // Call 1: 40.0 USD -> Permit (root=40.0/100.0, child=40.0/60.0).
    let f1 = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("40.0")));
    let (v1, _) = ledger
        .evaluate_and_record(&chain, &req, &f1, ts("2026-11-24T18:00:00Z"))
        .unwrap();
    assert_eq!(v1, Verdict::Permit);

    // Call 2: 25.0 USD on same child -> Deny (child 65.0 > 60.0, while root 65.0 <= 100.0).
    let f2 = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("25.0")));
    let (v2, _) = ledger
        .evaluate_and_record(&chain, &req, &f2, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert!(matches!(v2, Verdict::Deny { ref reason } if reason.contains("sum quota exceeded")));
}

#[test]
fn undeclared_descendant_sum_keys_not_charged_on_unconstrained_root() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("undeclared_root_sums.sqlite");
    let mut ledger = SqliteLedger::open(&db_path).unwrap();

    let no_sum_root = verified(
        parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 1 hop\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 5 calls\n",
        ))
        .unwrap(),
    );
    let no_sum_root_id = no_sum_root.ast.mandate_id();
    let sum_child = verified(
        parse_mandate(&format!(
            concat!(
                "HANDFEST v1\n",
                "PARENT {root_id}\n",
                "FROM agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
                "TO agent \"worker-sum\" (key: ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc)\n",
                "DELEGATION max 0 hops\n",
                "ALLOW pay.transfer\n",
                "ON account \"ops-main\"\n",
                "LIMIT 5 calls\n",
                "  AND 50.0 USD sum(resource.amount)\n",
            ),
            root_id = no_sum_root_id
        ))
        .unwrap(),
    );
    let sum_child_id = sum_child.ast.mandate_id();
    let chain = [no_sum_root, sum_child];
    let req = ActionRequest {
        actor_key: key("ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        action: "pay.transfer".to_string(),
        resource_kind: "account".to_string(),
        resource_id: "ops-main".to_string(),
    };

    let facts = VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("20.0")));
    let (v, _) = ledger
        .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:02:00Z"))
        .unwrap();
    assert_eq!(v, Verdict::Permit);
    drop(ledger);

    let raw = Connection::open(&db_path).unwrap();
    let root_rows: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM quota_sums WHERE mandate_id = ?1",
            [no_sum_root_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        root_rows, 0,
        "unconstrained root must not accumulate undeclared sum keys"
    );

    let child_total: String = raw
        .query_row(
            "SELECT total FROM quota_sums WHERE mandate_id = ?1 AND unit = 'USD' AND field = 'resource.amount'",
            [sum_child_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(child_total, "20.0");
}

#[test]
fn verify_integrity_catches_tail_deletion_seq_gaps_and_quota_tampering() {
    let dir = TempDir::new().unwrap();
    let root = root_calls_mandate(1);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 1);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    let make_two_row_db = |name: &str| {
        let path = dir.path().join(name);
        let mut ledger = SqliteLedger::open(&path).unwrap();
        // seq 1 = Permit, seq 2 = Deny (quota exhausted).
        let (v1, _) = ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        assert_eq!(v1, Verdict::Permit);
        let (v2, _) = ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
            .unwrap();
        assert!(matches!(v2, Verdict::Deny { .. }));
        assert_eq!(ledger.verify_integrity().unwrap(), 2);
        path
    };

    // 1. Tail deletion (DELETE FROM receipts WHERE seq = 2) caught by sqlite_sequence HWM check.
    let db_tail = make_two_row_db("tail_delete.sqlite");
    {
        let raw = Connection::open(&db_tail).unwrap();
        raw.execute("DELETE FROM receipts WHERE seq = 2", [])
            .unwrap();
    }
    let tail_err = SqliteLedger::open_read_only(&db_tail)
        .unwrap()
        .verify_integrity()
        .unwrap_err();
    assert!(
        matches!(tail_err, LedgerError::Integrity(_)),
        "expected sqlite_sequence integrity error, got: {tail_err}"
    );

    // 2. Non-contiguous seq gap (UPDATE receipts SET seq = 99 WHERE seq = 2).
    let db_seq = make_two_row_db("seq_gap.sqlite");
    {
        let raw = Connection::open(&db_seq).unwrap();
        raw.execute("UPDATE receipts SET seq = 99 WHERE seq = 2", [])
            .unwrap();
    }
    let seq_err = SqliteLedger::open_read_only(&db_seq)
        .unwrap()
        .verify_integrity()
        .unwrap_err();
    assert!(
        matches!(seq_err, LedgerError::Integrity(_)),
        "expected non-contiguous seq error, got: {seq_err}"
    );

    // 3. Tampered quota_calls (UPDATE quota_calls SET calls = 0).
    let db_quota = make_two_row_db("quota_tamper.sqlite");
    {
        let raw = Connection::open(&db_quota).unwrap();
        raw.execute("UPDATE quota_calls SET calls = 0", []).unwrap();
    }
    let quota_err = SqliteLedger::open_read_only(&db_quota)
        .unwrap()
        .verify_integrity()
        .unwrap_err();
    assert!(
        matches!(quota_err, LedgerError::Integrity(_)),
        "expected quota_calls integrity error, got: {quota_err}"
    );

    // 4. Deleted quota_calls row.
    let db_missing_quota = make_two_row_db("quota_deleted.sqlite");
    {
        let raw = Connection::open(&db_missing_quota).unwrap();
        raw.execute("DELETE FROM quota_calls", []).unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&db_missing_quota)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 5. Extra spurious quota_calls row.
    let db_extra_quota = make_two_row_db("quota_extra.sqlite");
    {
        let raw = Connection::open(&db_extra_quota).unwrap();
        raw.execute(
            "INSERT INTO quota_calls (mandate_id, calls) VALUES (?1, 1)",
            [format!("sha256:{}", "f".repeat(64))],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&db_extra_quota)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));
}

#[test]
fn open_read_only_never_creates_missing_file_and_audit_snapshot_works() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("does_not_exist.sqlite");
    assert!(SqliteLedger::open_read_only(&missing).is_err());
    assert!(
        !missing.exists(),
        "open_read_only must never create a missing database file"
    );

    let db_path = dir.path().join("snapshot.sqlite");
    let root = root_calls_mandate(1);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 1);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
            .unwrap();
    }

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let (count_only, none_rec) = ro.audit_snapshot(None).unwrap();
    assert_eq!(count_only, 2);
    assert!(none_rec.is_none());

    let (count_with_rec, maybe_rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
    assert_eq!(count_with_rec, 2);
    let rec = maybe_rec.expect("expected TrackRecord");
    assert_eq!(rec.total_decisions, 2);
    assert_eq!(rec.permits, 1);
    assert_eq!(rec.denies, 1);
    assert_eq!(rec.distinct_mandates, 1);
}

#[cfg(unix)]
#[test]
fn open_read_only_on_0444_file_creates_no_sidecars_and_writer_can_append() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("clean_wal.sqlite");
    let wal_path = dir.path().join("clean_wal.sqlite-wal");
    let shm_path = dir.path().join("clean_wal.sqlite-shm");

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        let (verdict, _) = ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        assert_eq!(verdict, Verdict::Permit);
    }
    assert!(!wal_path.exists());
    assert!(!shm_path.exists());

    // Make the database file 0444 inside a writable directory (the exact scenario where SQLite's
    // normal read-only open creates persistent 0444 -wal/-shm sidecars).
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).unwrap();

    {
        let ro = SqliteLedger::open_read_only(&db_path).unwrap();
        let (count, rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(rec.unwrap().permits, 1);
    }

    assert!(
        !wal_path.exists(),
        "open_read_only must not create a persistent -wal file in a writable directory"
    );
    assert!(
        !shm_path.exists(),
        "open_read_only must not create a persistent -shm file in a writable directory"
    );

    // Restoring write permissions on the DB file alone must allow the writer to append cleanly.
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut writer = SqliteLedger::open(&db_path).unwrap();
    let (verdict, _) = writer
        .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert_eq!(verdict, Verdict::Permit);
}

#[cfg(unix)]
#[test]
fn open_read_only_rejects_uncheckpointed_wal_through_symlink_and_hot_rollback_journal() {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct RestoreDir(PathBuf);
    impl Drop for RestoreDir {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
        }
    }

    let dir = TempDir::new().unwrap();
    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    // 1. Uncheckpointed -wal at a symlink target in a read-only directory must be rejected.
    let wal_src_dir = dir.path().join("wal_src");
    let wal_ro_dir = dir.path().join("wal_ro");
    fs::create_dir_all(&wal_src_dir).unwrap();
    fs::create_dir_all(&wal_ro_dir).unwrap();
    let src_db = wal_src_dir.join("ledger.sqlite");
    let src_wal = wal_src_dir.join("ledger.sqlite-wal");

    {
        let mut live = SqliteLedger::open(&src_db).unwrap();
        live.evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        drop(live);
        // Explicitly put a fixture DB into WAL mode and write a frame to produce a dirty -wal.
        let wal_conn = Connection::open(&src_db).unwrap();
        wal_conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        wal_conn
            .execute("CREATE TABLE _wal_dirty(x INT)", [])
            .unwrap();
        wal_conn
            .execute("INSERT INTO _wal_dirty VALUES (1)", [])
            .unwrap();
        assert!(fs::metadata(&src_wal).unwrap().len() > 0);
        // Copy main DB + non-empty -wal without -shm to simulate an uncheckpointed WAL snapshot.
        fs::copy(&src_db, wal_ro_dir.join("ledger.sqlite")).unwrap();
        fs::copy(&src_wal, wal_ro_dir.join("ledger.sqlite-wal")).unwrap();
    }

    let ro_target = wal_ro_dir.join("ledger.sqlite");
    let symlink_path = dir.path().join("symlink_to_dirty_wal.sqlite");
    symlink(&ro_target, &symlink_path).unwrap();

    let _restore_wal_dir = RestoreDir(wal_ro_dir.clone());
    fs::set_permissions(&wal_ro_dir, fs::Permissions::from_mode(0o555)).unwrap();

    assert!(
        SqliteLedger::open_read_only(&symlink_path).is_err(),
        "open_read_only must reject an uncheckpointed -wal at the resolved symlink target"
    );

    // 2. Hot rollback journal (-journal) must be rejected directly and via symlink.
    let rollback_dir = dir.path().join("rollback");
    fs::create_dir_all(&rollback_dir).unwrap();
    let rollback_db = rollback_dir.join("ledger.sqlite");
    {
        let mut ledger = SqliteLedger::open(&rollback_db).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
    }
    let hot_journal = rollback_dir.join("ledger.sqlite-journal");
    fs::write(
        &hot_journal,
        b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7hot-rollback-journal",
    )
    .unwrap();
    let rollback_symlink = dir.path().join("symlink_to_hot_journal.sqlite");
    symlink(&rollback_db, &rollback_symlink).unwrap();

    // Hot rollback journal must be rejected even in a writable directory.
    assert!(
        matches!(
            SqliteLedger::open_read_only(&rollback_db),
            Err(LedgerError::Integrity(_))
        ),
        "open_read_only must reject a hot rollback journal in a writable directory"
    );

    let _restore_rb_dir = RestoreDir(rollback_dir.clone());
    fs::set_permissions(&rollback_dir, fs::Permissions::from_mode(0o555)).unwrap();

    assert!(
        SqliteLedger::open_read_only(&rollback_db).is_err(),
        "open_read_only must reject a ledger with a hot rollback journal"
    );
    assert!(
        SqliteLedger::open_read_only(&rollback_symlink).is_err(),
        "open_read_only must reject a symlink whose target has a hot rollback journal"
    );
}

#[cfg(unix)]
#[test]
fn open_read_only_handles_readonly_dir_with_empty_sidecars_and_non_utf8_path() {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    struct RestorePerms(Vec<(PathBuf, u32)>);
    impl Drop for RestorePerms {
        fn drop(&mut self) {
            for (p, mode) in self.0.iter().rev() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(*mode));
            }
        }
    }

    let dir = TempDir::new().unwrap();
    let non_utf8_dir = dir.path().join(OsStr::from_bytes(b"ledger-\xFF-ro"));
    fs::create_dir(&non_utf8_dir).unwrap();
    let db_path = non_utf8_dir.join("audit.sqlite");

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
    }

    // Place empty read-only -wal and -shm files inside the 0555 directory to exercise the
    // ReadOnly/CannotOpen fallback path as well as non-UTF-8 canonical path handling.
    let empty_wal = non_utf8_dir.join("audit.sqlite-wal");
    let empty_shm = non_utf8_dir.join("audit.sqlite-shm");
    fs::write(&empty_wal, b"").unwrap();
    fs::write(&empty_shm, b"").unwrap();

    let utf8_link = dir.path().join("utf8_symlink.sqlite");
    symlink(&db_path, &utf8_link).unwrap();

    let _guard = RestorePerms(vec![
        (non_utf8_dir.clone(), 0o755),
        (db_path.clone(), 0o644),
        (empty_wal.clone(), 0o644),
        (empty_shm.clone(), 0o644),
    ]);
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&empty_wal, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&empty_shm, fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(&non_utf8_dir, fs::Permissions::from_mode(0o555)).unwrap();

    for candidate in [&db_path, &utf8_link] {
        let ro = SqliteLedger::open_read_only(candidate).unwrap();
        let (count, rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(rec.unwrap().permits, 1);
    }
}

#[test]
fn audit_snapshot_stays_consistent_under_concurrent_writes() {
    use std::time::{Duration, Instant};

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.sqlite");
    let root = root_calls_mandate(100);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 100);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    let mut writer = SqliteLedger::open(&db_path).unwrap();
    writer
        .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
        .unwrap();

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let req_writer = req.clone();
    let facts_writer = facts.clone();

    let handle = std::thread::spawn(move || {
        let base_ts = ts("2026-11-24T18:00:00Z");
        for i in 1..=30i64 {
            writer
                .evaluate_and_record(&chain, &req_writer, &facts_writer, base_ts + i * 60)
                .unwrap();
        }
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut iterations = 0usize;
    let mut last_count = 0usize;
    loop {
        let (verified, maybe_rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        let rec = maybe_rec.expect("expected TrackRecord");
        assert_eq!(
            u64::try_from(verified).unwrap(),
            rec.total_decisions,
            "verified_receipts and track_record.total_decisions diverged across snapshots"
        );
        assert_eq!(rec.permits + rec.denies, rec.total_decisions);
        assert!(verified >= last_count);
        last_count = verified;
        iterations += 1;

        if handle.is_finished() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for concurrent writer thread (last_count={last_count})"
        );
        std::thread::yield_now();
    }

    handle.join().expect("writer thread panicked");

    // A final audit after the writer joins must see all 31 receipts rather than staying pinned
    // on an initial snapshot.
    let (final_verified, maybe_final) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
    let final_rec = maybe_final.expect("expected final TrackRecord");
    assert_eq!(final_verified, 31);
    assert_eq!(final_rec.total_decisions, 31);
    assert_eq!(final_rec.permits + final_rec.denies, 31);
    assert!(final_verified >= last_count);
    assert!(iterations >= 1);
}

#[cfg(unix)]
#[test]
fn open_read_only_accepts_committed_persist_mode_zeroed_journal() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct RestorePerms(Vec<(PathBuf, u32)>);
    impl Drop for RestorePerms {
        fn drop(&mut self) {
            for (p, mode) in self.0.iter().rev() {
                let _ = fs::set_permissions(p, fs::Permissions::from_mode(*mode));
            }
        }
    }

    let dir = TempDir::new().unwrap();
    let persist_dir = dir.path().join("persist_ro");
    fs::create_dir(&persist_dir).unwrap();
    let db_path = persist_dir.join("ledger.sqlite");
    let journal_path = persist_dir.join("ledger.sqlite-journal");

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
    }
    {
        // Switch the ledger to PERSIST journal mode and commit a write so SQLite leaves an
        // inactive, non-empty rollback journal with a zeroed 28-byte header on disk.
        let raw = Connection::open(&db_path).unwrap();
        raw.pragma_update(None, "journal_mode", "PERSIST").unwrap();
        raw.execute_batch("CREATE TABLE _persist_touch(x INT); DROP TABLE _persist_touch;")
            .unwrap();
    }
    assert!(
        fs::metadata(&journal_path).unwrap().len() > 0,
        "PERSIST mode must leave a non-empty inactive -journal file on disk"
    );

    // Succeeds in writable dir.
    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let (count, rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
    assert_eq!(count, 1);
    assert_eq!(rec.unwrap().permits, 1);
    drop(ro);

    // Also succeeds when directory and files are read-only.
    let _guard = RestorePerms(vec![
        (persist_dir.clone(), 0o755),
        (db_path.clone(), 0o644),
        (journal_path.clone(), 0o644),
    ]);
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&persist_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let ro2 = SqliteLedger::open_read_only(&db_path).unwrap();
    let (count2, rec2) = ro2.audit_snapshot(Some(&req.actor_key)).unwrap();
    assert_eq!(count2, 1);
    assert_eq!(rec2.unwrap().permits, 1);
}

#[test]
fn verify_integrity_rejects_duplicate_sqlite_sequence_rows() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("dup_seq.sqlite");

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
            .unwrap();
    }

    // Tamper: delete the tail receipt (seq = 2) and prepend a spoofed ('receipts', 1) row ahead
    // of the real ('receipts', 2) high-water mark so a single-row query would see 1 and pass.
    {
        let raw = Connection::open(&db_path).unwrap();
        raw.execute("DELETE FROM receipts WHERE seq = 2", [])
            .unwrap();
        raw.execute("UPDATE quota_calls SET calls = 1", []).unwrap();
        raw.execute("DELETE FROM sqlite_sequence WHERE name = 'receipts'", [])
            .unwrap();
        raw.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES ('receipts', 1)",
            [],
        )
        .unwrap();
        raw.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES ('receipts', 2)",
            [],
        )
        .unwrap();
    }

    let ro = SqliteLedger::open_read_only(&db_path).unwrap();
    let err = ro
        .audit_snapshot(Some(&req.actor_key))
        .expect_err("duplicate sqlite_sequence rows for receipts must fail integrity audit");
    assert!(
        err.to_string().contains("duplicate sqlite_sequence"),
        "unexpected error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn posix_lock_probe_helper() {
    let Ok(db_path) = std::env::var("HANDFEST_LOCK_PROBE_DB") else {
        return;
    };
    let conn = Connection::open(&db_path).expect("probe open db");
    conn.busy_timeout(std::time::Duration::ZERO)
        .expect("probe busy_timeout");
    let res = conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;");
    let expect_locked = std::env::var("HANDFEST_LOCK_PROBE_EXPECT_LOCKED").as_deref() == Ok("1");
    if expect_locked {
        assert!(
            res.is_err(),
            "expected parent POSIX lock to remain held, but child acquired BEGIN IMMEDIATE"
        );
    } else {
        res.expect("expected child to acquire BEGIN IMMEDIATE after parent released lock");
    }
}

#[cfg(unix)]
#[test]
fn open_read_only_preserves_in_process_posix_locks_on_same_inode() {
    use std::process::Command;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("posix_lock.sqlite");

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    {
        let mut ledger = SqliteLedger::open(&db_path).unwrap();
        ledger
            .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
            .unwrap();
    }
    // Rollback (DELETE) mode holds POSIX fcntl locks directly on the main DB inode.
    // BEGIN IMMEDIATE acquires a RESERVED lock (blocking other writers while permitting readers).
    let lock_holder = Connection::open(&db_path).unwrap();
    lock_holder.execute_batch("BEGIN IMMEDIATE;").unwrap();

    // Opening and closing a read-only ledger on the same inode in this process must NEVER close a
    // raw descriptor on that inode and drop `lock_holder`'s POSIX fcntl lock.
    {
        let ro = SqliteLedger::open_read_only(&db_path).unwrap();
        let (count, rec) = ro.audit_snapshot(Some(&req.actor_key)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(rec.unwrap().permits, 1);
    }

    let exe = std::env::current_exe().expect("current test executable");
    let locked_status = Command::new(&exe)
        .args(["--exact", "posix_lock_probe_helper", "--quiet"])
        .env("HANDFEST_LOCK_PROBE_DB", &db_path)
        .env("HANDFEST_LOCK_PROBE_EXPECT_LOCKED", "1")
        .status()
        .expect("spawn posix_lock_probe_helper");
    assert!(
        locked_status.success(),
        "open_read_only dropped another in-process SQLite connection's POSIX lock!"
    );

    lock_holder.execute_batch("ROLLBACK;").unwrap();
    drop(lock_holder);

    // Sanity check: once the parent releases its lock, the child probe succeeds.
    let unlocked_status = Command::new(&exe)
        .args(["--exact", "posix_lock_probe_helper", "--quiet"])
        .env("HANDFEST_LOCK_PROBE_DB", &db_path)
        .env("HANDFEST_LOCK_PROBE_EXPECT_LOCKED", "0")
        .status()
        .expect("spawn unlocked posix_lock_probe_helper");
    assert!(
        unlocked_status.success(),
        "expected child probe to succeed after lock release"
    );
}

#[test]
fn cross_process_audit_helper() {
    let Ok(db_path) = std::env::var("HANDFEST_CROSS_PROC_AUDIT_DB") else {
        return;
    };
    let actor_raw = std::env::var("HANDFEST_CROSS_PROC_AUDIT_ACTOR").expect("actor env var");
    let expected: usize = std::env::var("HANDFEST_CROSS_PROC_AUDIT_EXPECT_COUNT")
        .expect("count env var")
        .parse()
        .expect("valid count");
    let actor = key(&actor_raw);

    let ro = SqliteLedger::open_read_only(&db_path).expect("child open_read_only");
    let (verified, maybe_rec) = ro
        .audit_snapshot(Some(&actor))
        .expect("child audit_snapshot");
    assert_eq!(verified, expected);
    let rec = maybe_rec.expect("child expected TrackRecord");
    assert_eq!(rec.total_decisions, u64::try_from(expected).unwrap());
    assert_eq!(rec.permits, u64::try_from(expected).unwrap());
}

#[test]
fn cross_process_read_only_audit_while_parent_holds_open_writer() {
    use std::process::Command;

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("cross_proc.sqlite");
    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-1", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    let mut writer = SqliteLedger::open(&db_path).unwrap();
    let (v1, _) = writer
        .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:00:00Z"))
        .unwrap();
    assert_eq!(v1, Verdict::Permit);

    let exe = std::env::current_exe().expect("current test executable");
    let run_child_audit = |expected_count: usize| {
        let output = Command::new(&exe)
            .args(["--exact", "cross_process_audit_helper", "--quiet"])
            .env("HANDFEST_CROSS_PROC_AUDIT_DB", &db_path)
            .env("HANDFEST_CROSS_PROC_AUDIT_ACTOR", req.actor_key.to_string())
            .env(
                "HANDFEST_CROSS_PROC_AUDIT_EXPECT_COUNT",
                expected_count.to_string(),
            )
            .output()
            .expect("spawn cross_process_audit_helper");
        assert!(
            output.status.success(),
            "child cross-process audit failed (expected {expected_count}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    // Child process audits cleanly while parent still holds open writer handle.
    run_child_audit(1);

    // Parent appends a second receipt on the same open handle; child immediately sees it.
    let (v2, _) = writer
        .evaluate_and_record(&chain, &req, &facts, ts("2026-11-24T18:01:00Z"))
        .unwrap();
    assert_eq!(v2, Verdict::Permit);
    run_child_audit(2);

    assert!(!dir.path().join("cross_proc.sqlite-wal").exists());
    assert!(!dir.path().join("cross_proc.sqlite-shm").exists());
    assert!(!dir.path().join("cross_proc.sqlite-journal").exists());
}

fn make_sum_ledger(dir: &TempDir, name: &str) -> (std::path::PathBuf, MandateId) {
    let path = dir.path().join(name);
    let root = verified(
        parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"treasury\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 100.0 USD sum(resource.amount)\n",
        ))
        .unwrap(),
    );
    let root_id = root.ast.mandate_id();
    let req = ActionRequest {
        actor_key: key("ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        action: "pay.transfer".to_string(),
        resource_kind: "account".to_string(),
        resource_id: "ops-main".to_string(),
    };
    let mut ledger = SqliteLedger::open(&path).unwrap();
    let (v1, _) = ledger
        .evaluate_and_record(
            &[root],
            &req,
            &VerifiedFacts::new().with("resource.amount", Scalar::Decimal(dec("60.5"))),
            ts("2026-11-24T18:00:00Z"),
        )
        .unwrap();
    assert_eq!(v1, Verdict::Permit);
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
    (path, root_id)
}

#[test]
fn verify_integrity_catches_quota_sums_structural_tampering() {
    let dir = TempDir::new().unwrap();

    let assert_tamper_fails = |name: &str, sql: &str| {
        let (path, _root_id) = make_sum_ledger(&dir, name);
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute(sql, []).unwrap();
        }
        let err = SqliteLedger::open_read_only(&path)
            .unwrap()
            .verify_integrity()
            .expect_err("tampered quota_sums must fail verify_integrity");
        assert!(
            matches!(err, LedgerError::Integrity(_)),
            "case '{name}': expected LedgerError::Integrity, got: {err}"
        );
    };

    // 1. Negative total.
    assert_tamper_fails("neg_total.sqlite", "UPDATE quota_sums SET total = '-50.0'");

    // 2. Unspent MandateId (no persisted permits).
    let unspent_id = format!("sha256:{}", "e".repeat(64));
    assert_tamper_fails(
        "unspent_mid.sqlite",
        &format!(
            "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES ('{unspent_id}', 'USD', 'resource.amount', '10.0')"
        ),
    );

    // 3. Invalid MandateId format.
    assert_tamper_fails(
        "bad_mid.sqlite",
        "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES ('not-a-mandate', 'USD', 'resource.amount', '10.0')",
    );

    // 4. Invalid unit identifier on a permitted MandateId.
    let (bad_unit_path, root_id) = make_sum_ledger(&dir, "bad_unit.sqlite");
    {
        let raw = Connection::open(&bad_unit_path).unwrap();
        raw.execute(
            "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, '123 bad', 'resource.amount', '1.0')",
            [root_id.to_string()],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&bad_unit_path)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 5. Invalid field path on a permitted MandateId.
    let (bad_field_path, root_id) = make_sum_ledger(&dir, "bad_field.sqlite");
    {
        let raw = Connection::open(&bad_field_path).unwrap();
        raw.execute(
            "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, 'USD', 'resource..amount', '1.0')",
            [root_id.to_string()],
        )
        .unwrap();
    }
    assert!(matches!(
        SqliteLedger::open_read_only(&bad_field_path)
            .unwrap()
            .verify_integrity(),
        Err(LedgerError::Integrity(_))
    ));

    // 6. Unparseable decimal total.
    assert_tamper_fails(
        "bad_dec.sqlite",
        "UPDATE quota_sums SET total = 'not-a-number'",
    );

    // 7. Non-canonical decimal spellings (trailing zero and -0.0).
    assert_tamper_fails(
        "non_canon_trailing.sqlite",
        "UPDATE quota_sums SET total = '60.50'",
    );
    assert_tamper_fails(
        "non_canon_neg_zero.sqlite",
        "UPDATE quota_sums SET total = '-0.0'",
    );

    // 8. Canonical zero total on a permitted MandateId is valid.
    let (zero_path, _) = make_sum_ledger(&dir, "canon_zero.sqlite");
    {
        let raw = Connection::open(&zero_path).unwrap();
        raw.execute("UPDATE quota_sums SET total = '0.0'", [])
            .unwrap();
    }
    assert_eq!(
        SqliteLedger::open_read_only(&zero_path)
            .unwrap()
            .verify_integrity()
            .unwrap(),
        1
    );
}

fn exercise_generic_ledger<L: ReceiptLedger>(
    ledger: &mut L,
    chain: &[VerifiedMandate],
    req: &ActionRequest,
    facts: &VerifiedFacts,
    now: i64,
) {
    let (verdict, receipt) = ledger
        .evaluate_and_record(chain, req, facts, now)
        .expect("generic evaluate_and_record");
    assert_eq!(verdict, Verdict::Permit);
    assert!(receipt.verify_hash());
    assert_eq!(ledger.verify_integrity().expect("generic verify"), 1);
    let rec = ledger
        .track_record(&req.actor_key)
        .expect("generic track_record");
    assert_eq!(rec.permits, 1);
    let (count, snap_rec) = ledger
        .audit_snapshot(Some(&req.actor_key))
        .expect("generic audit_snapshot");
    assert_eq!(count, 1);
    assert_eq!(snap_rec, Some(rec));
}

fn exercise_dyn_ledger(
    ledger: &mut dyn ReceiptLedger,
    chain: &[VerifiedMandate],
    req: &ActionRequest,
    facts: &VerifiedFacts,
    now: i64,
) {
    let (verdict, receipt) = ledger
        .evaluate_and_record(chain, req, facts, now)
        .expect("dyn evaluate_and_record");
    assert_eq!(verdict, Verdict::Permit);
    assert!(receipt.verify_hash());
    assert_eq!(ledger.verify_integrity().expect("dyn verify"), 2);
    let rec = ledger
        .track_record(&req.actor_key)
        .expect("dyn track_record");
    assert_eq!(rec.total_decisions, 2);
    assert_eq!(rec.permits, 2);
    let (count, snap_rec) = ledger
        .audit_snapshot(Some(&req.actor_key))
        .expect("dyn audit_snapshot");
    assert_eq!(count, 2);
    assert_eq!(snap_rec, Some(rec));
}

#[test]
fn receipt_ledger_trait_polymorphic_dyn_and_generic() {
    use std::error::Error as _;

    let root = root_calls_mandate(5);
    let child = child_calls_mandate(root.ast.mandate_id(), "seat-poly", 5);
    let chain = [root, child];
    let req = merge_request();
    let facts = valentin_facts();

    let mut ledger = SqliteLedger::open_in_memory().unwrap();
    assert!(format!("{ledger:?}").contains("SqliteLedger"));

    exercise_generic_ledger(
        &mut ledger,
        &chain,
        &req,
        &facts,
        ts("2026-11-24T18:00:00Z"),
    );
    exercise_dyn_ledger(
        &mut ledger,
        &chain,
        &req,
        &facts,
        ts("2026-11-24T18:01:00Z"),
    );

    // Verify TrackRecord JSON serde roundtrip and invalid key rejection.
    let rec = ledger.track_record(&req.actor_key).unwrap();
    let encoded = serde_json::to_string(&rec).unwrap();
    let decoded: TrackRecord = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, rec);
    let bad_json = encoded.replace(&req.actor_key.to_string(), "not-a-key");
    let json_err: LedgerError = serde_json::from_str::<TrackRecord>(&bad_json)
        .unwrap_err()
        .into();
    assert!(json_err.to_string().contains("json serialization error"));
    assert!(json_err.source().is_some());

    // Verify LedgerError Display + Error::source across variants.
    let int_err = LedgerError::Integrity("bad".to_string());
    assert!(int_err.to_string().contains("ledger integrity error"));
    assert!(int_err.source().is_none());
    let qa_err = LedgerError::QuotaAccounting("bad".to_string());
    assert!(qa_err.to_string().contains("quota accounting error"));
    assert!(qa_err.source().is_none());
}
