use handfest_core::ast::{parse_rfc3339_utc, Decimal, HandfestAst, KeyId, MandateId, Scalar};
use handfest_core::cnl::parse_mandate;
use handfest_core::gate::{ActionRequest, VerifiedAnchorProof, VerifiedFacts, VerifiedMandate};
use handfest_core::{AssuranceLevel, Verdict};
use handfest_ledger::{LedgerError, SqliteLedger};
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

    // Reopen from disk and confirm WAL persistence + integrity.
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
    // Receipt count must remain 1 (rolled back).
    assert_eq!(ledger.verify_integrity().unwrap(), 1);
}

#[test]
fn concurrent_connections_enforce_wal_and_atomic_quota_without_race() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.sqlite");

    // Initialize schema and verify WAL journal mode on file-backed DB.
    let init_ledger = SqliteLedger::open(&db_path).unwrap();
    drop(init_ledger);
    {
        let raw = Connection::open(&db_path).unwrap();
        let mode: String = raw
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
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
