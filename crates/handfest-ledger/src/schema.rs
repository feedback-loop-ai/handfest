//! Single source of truth for SQLite ledger schema DDL and strict schema / B-tree integrity checks.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::codec::{col_opt_text, col_text};
use crate::LedgerError;

const RECEIPTS_CREATE_SQL: &str = "\
CREATE TABLE IF NOT EXISTS receipts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_receipt_hash TEXT,
    receipt_hash TEXT NOT NULL UNIQUE,
    chain_ids_json TEXT NOT NULL,
    actor_key TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    deny_reason TEXT
)";

const IDX_RECEIPTS_ACTOR_KEY_CREATE_SQL: &str =
    "CREATE INDEX IF NOT EXISTS idx_receipts_actor_key ON receipts(actor_key)";

const QUOTA_CALLS_CREATE_SQL: &str = "\
CREATE TABLE IF NOT EXISTS quota_calls (
    mandate_id TEXT PRIMARY KEY,
    calls INTEGER NOT NULL CHECK (calls >= 0)
)";

const QUOTA_SUMS_CREATE_SQL: &str = "\
CREATE TABLE IF NOT EXISTS quota_sums (
    mandate_id TEXT NOT NULL,
    unit TEXT NOT NULL,
    field TEXT NOT NULL,
    total TEXT NOT NULL,
    PRIMARY KEY (mandate_id, unit, field)
)";

const SQLITE_SEQUENCE_DDL: &str = "CREATE TABLE sqlite_sequence(name,seq)";

const REQUIRED_SCHEMA_OBJECTS: [(&str, &str); 7] = [
    ("table", "receipts"),
    ("table", "quota_calls"),
    ("table", "quota_sums"),
    ("index", "idx_receipts_actor_key"),
    ("index", "sqlite_autoindex_receipts_1"),
    ("index", "sqlite_autoindex_quota_calls_1"),
    ("index", "sqlite_autoindex_quota_sums_1"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaRow {
    obj_type: String,
    name: String,
    tbl_name: String,
    sql: Option<String>,
}

/// Initializes a brand-new empty ledger database with the canonical schema, or strictly verifies
/// the schema and B-tree integrity of an existing non-empty database before any write executes.
///
/// Runs inside a single `BEGIN IMMEDIATE ... COMMIT` transaction so concurrent openers on a fresh
/// database path serialize cleanly without ever observing a partially initialized schema, and any
/// partial DDL or integrity failure rolls back cleanly rather than bricking the database file.
pub(crate) fn initialize_or_verify_schema(conn: &mut Connection) -> Result<(), LedgerError> {
    initialize_or_verify_schema_with_hook(conn, || Ok(()))
}

/// Strictly verifies the schema and B-tree integrity of an already-initialized ledger database
/// inside a single `BEGIN IMMEDIATE ... COMMIT` transaction without ever executing `CREATE TABLE`.
pub(crate) fn verify_existing_schema(conn: &mut Connection) -> Result<(), LedgerError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_schema_integrity(&tx)?;
    tx.commit()?;
    Ok(())
}

fn initialize_or_verify_schema_with_hook<F>(
    conn: &mut Connection,
    after_first_ddl: F,
) -> Result<(), LedgerError>
where
    F: FnOnce() -> Result<(), LedgerError>,
{
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let has_objects = tx
        .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if !has_objects {
        tx.execute_batch(RECEIPTS_CREATE_SQL)?;
        after_first_ddl()?;
        for ddl in [
            IDX_RECEIPTS_ACTOR_KEY_CREATE_SQL,
            QUOTA_CALLS_CREATE_SQL,
            QUOTA_SUMS_CREATE_SQL,
        ] {
            tx.execute_batch(ddl)?;
        }
    }
    verify_schema_integrity(&tx)?;
    tx.commit()?;
    Ok(())
}

/// Verifies exact canonical DDL in `sqlite_master` (rejecting any altered constraint/collation,
/// missing required object, or unexpected table/index/trigger/view) and runs `PRAGMA integrity_check` (which performs all `quick_check` B-tree checks plus index-to-table parity).
pub(crate) fn verify_schema_integrity(conn: &Connection) -> Result<(), LedgerError> {
    let rows = load_sqlite_master_rows(conn)?;
    validate_schema_rows(&rows)?;
    verify_integrity_check(conn)
}

fn load_sqlite_master_rows(conn: &Connection) -> Result<Vec<SchemaRow>, LedgerError> {
    let mut stmt = conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(SchemaRow {
            obj_type: col_text(row, 0, "sqlite_master.type")?,
            name: col_text(row, 1, "sqlite_master.name")?,
            tbl_name: col_text(row, 2, "sqlite_master.tbl_name")?,
            sql: col_opt_text(row, 3, "sqlite_master.sql")?,
        });
    }
    Ok(out)
}

fn validate_schema_rows(rows: &[SchemaRow]) -> Result<(), LedgerError> {
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for row in rows {
        if !seen.insert((row.obj_type.as_str(), row.name.as_str())) {
            return Err(LedgerError::Integrity(format!(
                "duplicate schema object {} '{}' in ledger schema",
                row.obj_type, row.name
            )));
        }
        validate_schema_object(row)?;
    }
    for (req_type, req_name) in REQUIRED_SCHEMA_OBJECTS {
        if !seen.contains(&(req_type, req_name)) {
            return Err(LedgerError::Integrity(format!(
                "missing required {req_type} '{req_name}' in ledger schema"
            )));
        }
    }
    Ok(())
}

fn validate_schema_object(row: &SchemaRow) -> Result<(), LedgerError> {
    let (expected_tbl, expected_sql) = match (row.obj_type.as_str(), row.name.as_str()) {
        ("table", "receipts") => ("receipts", Some(expected_ddl(RECEIPTS_CREATE_SQL))),
        ("table", "quota_calls") => ("quota_calls", Some(expected_ddl(QUOTA_CALLS_CREATE_SQL))),
        ("table", "quota_sums") => ("quota_sums", Some(expected_ddl(QUOTA_SUMS_CREATE_SQL))),
        ("table", "sqlite_sequence") => ("sqlite_sequence", Some(SQLITE_SEQUENCE_DDL.to_string())),
        ("index", "idx_receipts_actor_key") => (
            "receipts",
            Some(expected_ddl(IDX_RECEIPTS_ACTOR_KEY_CREATE_SQL)),
        ),
        ("index", "sqlite_autoindex_receipts_1") => ("receipts", None),
        ("index", "sqlite_autoindex_quota_calls_1") => ("quota_calls", None),
        ("index", "sqlite_autoindex_quota_sums_1") => ("quota_sums", None),
        (other, name) => {
            return Err(LedgerError::Integrity(format!(
                "unexpected {other} '{name}' in ledger schema"
            )));
        }
    };

    if row.tbl_name != expected_tbl {
        return Err(LedgerError::Integrity(format!(
            "schema object {} '{}' bound to unexpected table '{}' (expected '{expected_tbl}')",
            row.obj_type, row.name, row.tbl_name
        )));
    }

    let actual_sql = row.sql.as_deref().map(normalize_ddl);
    if actual_sql != expected_sql {
        return Err(LedgerError::Integrity(format!(
            "tampered DDL for {} '{}': expected {:?}, got {:?}",
            row.obj_type, row.name, expected_sql, actual_sql
        )));
    }
    Ok(())
}

fn verify_integrity_check(conn: &Connection) -> Result<(), LedgerError> {
    let mut stmt = conn.prepare("PRAGMA integrity_check")?;
    let mut rows = stmt.query([])?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        results.push(col_text(row, 0, "PRAGMA integrity_check")?);
    }
    validate_integrity_check_results(&results)
}

fn validate_integrity_check_results(results: &[String]) -> Result<(), LedgerError> {
    match results {
        [single] if single == "ok" => Ok(()),
        [] => Err(LedgerError::Integrity(
            "PRAGMA integrity_check returned no rows".to_string(),
        )),
        other => Err(LedgerError::Integrity(format!(
            "PRAGMA integrity_check failed: {}",
            other.join("; ")
        ))),
    }
}

fn expected_ddl(create_sql: &str) -> String {
    normalize_ddl(&create_sql.replacen("IF NOT EXISTS ", "", 1))
}

fn normalize_ddl(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut pending_space = false;
    for ch in sql.chars() {
        if ch.is_ascii_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space && !matches!(ch, ')' | ',') && !out.ends_with('(') {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_schema_initializes_and_validates_cleanly() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_or_verify_schema(&mut conn).unwrap();
        // Second call on existing DB verifies without modifying schema.
        initialize_or_verify_schema(&mut conn).unwrap();
    }

    #[test]
    fn schema_validation_rejects_missing_duplicate_rebound_and_tampered_objects() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_or_verify_schema(&mut conn).unwrap();
        let valid_rows = load_sqlite_master_rows(&conn).unwrap();
        validate_schema_rows(&valid_rows).unwrap();

        // Missing required object.
        assert!(matches!(
            validate_schema_rows(&[]),
            Err(LedgerError::Integrity(_))
        ));

        // Duplicate object row.
        let mut dup_rows = valid_rows.clone();
        dup_rows.push(valid_rows[0].clone());
        assert!(matches!(
            validate_schema_rows(&dup_rows),
            Err(LedgerError::Integrity(_))
        ));

        // Rebound index pointing at wrong table.
        let mut rebound = valid_rows.clone();
        let idx_row = rebound
            .iter_mut()
            .find(|r| r.name == "idx_receipts_actor_key")
            .unwrap();
        idx_row.tbl_name = "quota_calls".to_string();
        assert!(matches!(
            validate_schema_rows(&rebound),
            Err(LedgerError::Integrity(_))
        ));

        // Tampered DDL (COLLATE NOCASE).
        let mut tampered = valid_rows.clone();
        let sums_row = tampered
            .iter_mut()
            .find(|r| r.name == "quota_sums")
            .unwrap();
        sums_row.sql = Some(
            "CREATE TABLE quota_sums (mandate_id TEXT NOT NULL COLLATE NOCASE, unit TEXT NOT NULL, field TEXT NOT NULL, total TEXT NOT NULL, PRIMARY KEY (mandate_id, unit, field))".to_string(),
        );
        assert!(matches!(
            validate_schema_rows(&tampered),
            Err(LedgerError::Integrity(_))
        ));

        // Autoindex unexpectedly having SQL.
        let mut bad_auto = valid_rows;
        let auto_row = bad_auto
            .iter_mut()
            .find(|r| r.name == "sqlite_autoindex_receipts_1")
            .unwrap();
        auto_row.sql = Some("CREATE UNIQUE INDEX fake ON receipts(receipt_hash)".to_string());
        assert!(matches!(
            validate_schema_rows(&bad_auto),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn integrity_check_result_and_error_mapping_fail_closed() {
        validate_integrity_check_results(&["ok".to_string()]).unwrap();
        assert!(matches!(
            validate_integrity_check_results(&[]),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            validate_integrity_check_results(&["row 1 missing from index".to_string()]),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            validate_integrity_check_results(&["ok".to_string(), "extra".to_string()]),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn schema_initialization_is_atomic_on_partial_failure_and_invisible_mid_transaction() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("atomic_schema_init.sqlite");
        let mut conn = Connection::open(&db_path).unwrap();

        // 1. Mid-init failure after CREATE TABLE receipts must roll back completely rather than
        //    leaving a half-initialized database that bricks subsequent opens.
        let err = initialize_or_verify_schema_with_hook(&mut conn, || {
            let observer = Connection::open(&db_path).unwrap();
            let visible_rows: i64 = observer
                .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                visible_rows, 0,
                "other connections must not observe uncommitted half-initialized schema"
            );
            Err(LedgerError::Storage(
                "simulated mid-init failure".to_string(),
            ))
        })
        .unwrap_err();
        assert!(matches!(err, LedgerError::Storage(_)));

        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            remaining, 0,
            "partial schema initialization failure must roll back all DDL"
        );

        // 2. Subsequent initialization succeeds cleanly on the rolled-back database.
        initialize_or_verify_schema(&mut conn).unwrap();
    }

    #[test]
    fn verify_existing_schema_rejects_empty_db_without_initializing_and_accepts_initialized_db() {
        let mut conn = Connection::open_in_memory().unwrap();
        let err = verify_existing_schema(&mut conn).unwrap_err();
        assert!(matches!(err, LedgerError::Integrity(_)));
        let remaining: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            remaining, 0,
            "verify_existing_schema must never create tables in an empty database"
        );

        initialize_or_verify_schema(&mut conn).unwrap();
        verify_existing_schema(&mut conn).unwrap();
    }
}
