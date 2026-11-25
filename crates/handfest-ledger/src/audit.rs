//! SQLite integrity verification and [`TrackRecord`] projection helpers.

use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{is_valid_field_path, is_valid_ident, Decimal, KeyId, MandateId};
use handfest_core::gate::DecisionReceipt;
use handfest_core::Verdict;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::codec::{
    format_resource, parse_chain_ids_json, parse_optional_mandate_id, parse_verdict,
};
use crate::{LedgerError, TrackRecord};

pub(crate) fn run_audit_tx<F: FnOnce()>(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    after_verify: F,
) -> Result<(usize, Option<TrackRecord>), LedgerError> {
    run_audit_tx_with(conn, after_verify, |tx| match actor_key {
        Some(key) => track_record_in_conn(tx, key).map(Some),
        None => Ok(None),
    })
}

pub(crate) fn run_verified_track_record(
    conn: &Connection,
    actor_key: &KeyId,
) -> Result<TrackRecord, LedgerError> {
    run_audit_tx_with(conn, || {}, |tx| track_record_in_conn(tx, actor_key))
        .map(|(_, record)| record)
}

fn run_audit_tx_with<T, F, P>(
    conn: &Connection,
    after_verify: F,
    project: P,
) -> Result<(usize, T), LedgerError>
where
    F: FnOnce(),
    P: FnOnce(&Connection) -> Result<T, LedgerError>,
{
    let tx = conn.unchecked_transaction()?;
    let verified_receipts = verify_integrity_in_conn(&tx)?;
    after_verify();
    let projected = project(&tx)?;
    tx.commit()?;
    Ok((verified_receipts, projected))
}

pub(crate) fn verify_integrity_in_conn(conn: &Connection) -> Result<usize, LedgerError> {
    verify_schema_integrity(conn)?;

    let mut stmt = conn.prepare(
        "SELECT seq, prev_receipt_hash, receipt_hash, chain_ids_json, actor_key,
                action, resource_kind, resource_id, timestamp, verdict, deny_reason
         FROM receipts
         ORDER BY seq ASC",
    )?;

    let mut rows = stmt.query([])?;
    let mut expected_prev: Option<MandateId> = None;
    let mut expected_seq: i64 = 1;
    let mut expected_calls: BTreeMap<MandateId, u64> = BTreeMap::new();
    let mut count = 0usize;

    while let Some(row) = rows.next()? {
        let seq = col_i64(row, 0, "receipts.seq")?;
        if seq != expected_seq {
            return Err(LedgerError::Integrity(format!(
                "non-contiguous receipt seq: expected {expected_seq}, got {seq}"
            )));
        }
        let receipt = reconstruct_receipt(row, seq, expected_prev)?;
        if !receipt.verify_hash() {
            return Err(LedgerError::Integrity(format!(
                "seq {seq}: receipt_hash mismatch (stored {}, computed {})",
                receipt.receipt_hash,
                receipt.compute_hash()
            )));
        }
        if receipt.verdict == Verdict::Permit {
            if receipt.chain_ids.is_empty() {
                return Err(LedgerError::Integrity(format!(
                    "seq {seq}: permit receipt must have non-empty chain_ids"
                )));
            }
            record_expected_permit_calls(&mut expected_calls, &receipt.chain_ids)?;
        }
        expected_prev = Some(receipt.receipt_hash);
        expected_seq += 1;
        count += 1;
    }

    verify_sqlite_sequence_hwm(conn, expected_seq - 1)?;
    verify_quota_calls_consistency(conn, &expected_calls)?;
    verify_quota_sums_consistency(conn, &expected_calls)?;
    Ok(count)
}

fn verify_schema_integrity(conn: &Connection) -> Result<(), LedgerError> {
    let mut stmt = conn.prepare("SELECT type, name FROM sqlite_master")?;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let obj_type = col_text(row, 0, "sqlite_master.type")?;
        let name = col_text(row, 1, "sqlite_master.name")?;
        match obj_type.as_str() {
            "table" => {
                if !matches!(
                    name.as_str(),
                    "receipts" | "quota_calls" | "quota_sums" | "sqlite_sequence"
                ) {
                    return Err(LedgerError::Integrity(format!(
                        "unexpected table '{name}' in ledger schema"
                    )));
                }
            }
            "index" => {
                if !matches!(
                    name.as_str(),
                    "idx_receipts_actor_key"
                        | "sqlite_autoindex_receipts_1"
                        | "sqlite_autoindex_quota_calls_1"
                        | "sqlite_autoindex_quota_sums_1"
                ) {
                    return Err(LedgerError::Integrity(format!(
                        "unexpected index '{name}' in ledger schema"
                    )));
                }
            }
            other => {
                return Err(LedgerError::Integrity(format!(
                    "unexpected {other} '{name}' in ledger schema"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn track_record_in_conn(
    conn: &Connection,
    actor_key: &KeyId,
) -> Result<TrackRecord, LedgerError> {
    let actor_str = actor_key.to_string();
    let mut stmt = conn.prepare(
        "SELECT seq, chain_ids_json, timestamp, verdict, deny_reason
         FROM receipts
         WHERE actor_key = ?1
         ORDER BY seq ASC",
    )?;

    let mut rows = stmt.query(params![actor_str])?;
    let mut total_decisions = 0u64;
    let mut permits = 0u64;
    let mut denies = 0u64;
    let mut distinct_leaves: BTreeSet<MandateId> = BTreeSet::new();
    let mut first_timestamp: Option<i64> = None;
    let mut last_timestamp: Option<i64> = None;

    while let Some(row) = rows.next()? {
        let seq = col_i64(row, 0, "receipts.seq")?;
        let chain_ids_json = col_text(row, 1, "receipts.chain_ids_json")?;
        let timestamp = col_i64(row, 2, "receipts.timestamp")?;
        let verdict_raw = col_text(row, 3, "receipts.verdict")?;
        let deny_reason = col_opt_text(row, 4, "receipts.deny_reason")?;

        let verdict = parse_verdict(seq, &verdict_raw, deny_reason)?;
        let chain_ids = parse_chain_ids_json(seq, &chain_ids_json)?;

        total_decisions += 1;
        match verdict {
            Verdict::Permit => permits += 1,
            Verdict::Deny { .. } => denies += 1,
        }
        if let Some(leaf_id) = chain_ids.last() {
            distinct_leaves.insert(*leaf_id);
        }
        first_timestamp = Some(first_timestamp.map_or(timestamp, |cur| cur.min(timestamp)));
        last_timestamp = Some(last_timestamp.map_or(timestamp, |cur| cur.max(timestamp)));
    }

    Ok(TrackRecord {
        actor_key: actor_key.clone(),
        total_decisions,
        permits,
        denies,
        distinct_mandates: u64::try_from(distinct_leaves.len()).unwrap_or(u64::MAX),
        first_timestamp,
        last_timestamp,
    })
}

fn record_expected_permit_calls(
    expected_calls: &mut BTreeMap<MandateId, u64>,
    chain_ids: &[MandateId],
) -> Result<(), LedgerError> {
    let unique: BTreeSet<MandateId> = chain_ids.iter().copied().collect();
    for mid in unique {
        let entry = expected_calls.entry(mid).or_insert(0);
        *entry = entry.checked_add(1).ok_or_else(|| {
            LedgerError::Integrity(format!("permit count overflow while auditing {mid}"))
        })?;
    }
    Ok(())
}

fn verify_sqlite_sequence_hwm(conn: &Connection, count_i64: i64) -> Result<(), LedgerError> {
    let has_seq_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !has_seq_table {
        if count_i64 > 0 {
            return Err(LedgerError::Integrity(format!(
                "missing sqlite_sequence table for non-empty receipts ledger ({count_i64} rows)"
            )));
        }
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'receipts'")?;
    let mut rows = stmt.query([])?;
    let mut hwms = Vec::new();
    while let Some(row) = rows.next()? {
        let seq = col_opt_i64(row, 0, "sqlite_sequence.seq")?;
        hwms.push(seq);
    }

    match hwms.as_slice() {
        [] if count_i64 == 0 => Ok(()),
        [] => Err(LedgerError::Integrity(format!(
            "missing sqlite_sequence row for receipts ({count_i64} rows present)"
        ))),
        [Some(seq)] if *seq == count_i64 => Ok(()),
        [Some(seq)] => Err(LedgerError::Integrity(format!(
            "sqlite_sequence high-water mark mismatch for receipts: expected {count_i64}, got {seq}"
        ))),
        [None] => Err(LedgerError::Integrity(
            "invalid NULL sqlite_sequence high-water mark for receipts".to_string(),
        )),
        _ => Err(LedgerError::Integrity(format!(
            "duplicate sqlite_sequence rows for receipts: expected at most 1, found {}",
            hwms.len()
        ))),
    }
}

fn verify_quota_calls_consistency(
    conn: &Connection,
    expected_calls: &BTreeMap<MandateId, u64>,
) -> Result<(), LedgerError> {
    let mut stmt = conn.prepare("SELECT mandate_id, calls FROM quota_calls")?;
    let mut rows = stmt.query([])?;
    let mut actual_calls: BTreeMap<MandateId, u64> = BTreeMap::new();

    while let Some(row) = rows.next()? {
        let mid_raw = col_text(row, 0, "quota_calls.mandate_id")?;
        let calls_i64 = col_i64(row, 1, "quota_calls.calls")?;
        let mid = MandateId::parse(&mid_raw).map_err(|err| {
            LedgerError::Integrity(format!(
                "invalid mandate_id '{mid_raw}' in quota_calls: {err}"
            ))
        })?;
        let calls = u64::try_from(calls_i64).map_err(|_| {
            LedgerError::Integrity(format!(
                "negative calls count {calls_i64} in quota_calls for {mid}"
            ))
        })?;
        if actual_calls.insert(mid, calls).is_some() {
            return Err(LedgerError::Integrity(format!(
                "duplicate quota_calls row for {mid}"
            )));
        }
    }

    for (mid, expected) in expected_calls {
        match actual_calls.get(mid) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                return Err(LedgerError::Integrity(format!(
                    "quota_calls mismatch for {mid}: expected {expected}, got {actual}"
                )));
            }
            None => {
                return Err(LedgerError::Integrity(format!(
                    "missing quota_calls row for {mid}: expected {expected} permits"
                )));
            }
        }
    }

    for (mid, actual) in &actual_calls {
        if !expected_calls.contains_key(mid) {
            return Err(LedgerError::Integrity(format!(
                "unexpected quota_calls row for {mid} (calls={actual}) with no persisted permits"
            )));
        }
    }
    Ok(())
}

fn verify_quota_sums_consistency(
    conn: &Connection,
    expected_calls: &BTreeMap<MandateId, u64>,
) -> Result<(), LedgerError> {
    let mut stmt = conn.prepare("SELECT mandate_id, unit, field, total FROM quota_sums")?;
    let mut rows = stmt.query([])?;
    let mut seen_keys: BTreeSet<(MandateId, String, String)> = BTreeSet::new();

    while let Some(row) = rows.next()? {
        let mid_raw = col_text(row, 0, "quota_sums.mandate_id")?;
        let unit = col_text(row, 1, "quota_sums.unit")?;
        let field = col_text(row, 2, "quota_sums.field")?;
        let total_raw = col_text(row, 3, "quota_sums.total")?;
        let mid = validate_quota_sum_row(&mid_raw, &unit, &field, &total_raw, expected_calls)?;
        if !seen_keys.insert((mid, unit, field)) {
            return Err(LedgerError::Integrity(format!(
                "duplicate quota_sums row for {mid}"
            )));
        }
    }
    Ok(())
}

fn validate_quota_sum_row(
    mid_raw: &str,
    unit: &str,
    field: &str,
    total_raw: &str,
    expected_calls: &BTreeMap<MandateId, u64>,
) -> Result<MandateId, LedgerError> {
    let mid = MandateId::parse(mid_raw).map_err(|err| {
        LedgerError::Integrity(format!(
            "invalid mandate_id '{mid_raw}' in quota_sums: {err}"
        ))
    })?;
    if !expected_calls.contains_key(&mid) {
        return Err(LedgerError::Integrity(format!(
            "unexpected quota_sums row for {mid} ({unit}, {field}) with no persisted permits"
        )));
    }
    if !is_valid_ident(unit) {
        return Err(LedgerError::Integrity(format!(
            "invalid unit '{unit}' in quota_sums for {mid}"
        )));
    }
    if !is_valid_field_path(field) {
        return Err(LedgerError::Integrity(format!(
            "invalid field '{field}' in quota_sums for {mid}"
        )));
    }
    let total = Decimal::parse(total_raw).map_err(|err| {
        LedgerError::Integrity(format!(
            "invalid total '{total_raw}' in quota_sums for ({mid}, {unit}, {field}): {err}"
        ))
    })?;
    if total.is_negative() {
        return Err(LedgerError::Integrity(format!(
            "negative total '{total_raw}' in quota_sums for ({mid}, {unit}, {field})"
        )));
    }
    let canonical = total.to_string();
    if total_raw != canonical {
        return Err(LedgerError::Integrity(format!(
            "non-canonical total '{total_raw}' in quota_sums for ({mid}, {unit}, {field}); expected '{canonical}'"
        )));
    }
    Ok(mid)
}

fn reconstruct_receipt(
    row: &Row<'_>,
    seq: i64,
    expected_prev: Option<MandateId>,
) -> Result<DecisionReceipt, LedgerError> {
    let prev_raw = col_opt_text(row, 1, "receipts.prev_receipt_hash")?;
    let hash_raw = col_text(row, 2, "receipts.receipt_hash")?;
    let chain_ids_json = col_text(row, 3, "receipts.chain_ids_json")?;
    let actor_key_raw = col_text(row, 4, "receipts.actor_key")?;
    let action = col_text(row, 5, "receipts.action")?;
    let resource_kind = col_text(row, 6, "receipts.resource_kind")?;
    let resource_id = col_text(row, 7, "receipts.resource_id")?;
    let timestamp = col_i64(row, 8, "receipts.timestamp")?;
    let verdict_raw = col_text(row, 9, "receipts.verdict")?;
    let deny_reason = col_opt_text(row, 10, "receipts.deny_reason")?;

    let prev_receipt_hash = parse_optional_mandate_id(seq, "prev_receipt_hash", prev_raw)?;
    if prev_receipt_hash != expected_prev {
        return Err(LedgerError::Integrity(format!(
            "seq {seq}: broken prev_receipt_hash link (expected {expected_prev:?}, got {prev_receipt_hash:?})"
        )));
    }

    let receipt_hash = MandateId::parse(&hash_raw)
        .map_err(|err| LedgerError::Integrity(format!("seq {seq}: invalid receipt_hash: {err}")))?;
    let chain_ids = parse_chain_ids_json(seq, &chain_ids_json)?;
    let actor_key = KeyId::parse(&actor_key_raw)
        .map_err(|err| LedgerError::Integrity(format!("seq {seq}: invalid actor_key: {err}")))?;
    let verdict = parse_verdict(seq, &verdict_raw, deny_reason)?;

    Ok(DecisionReceipt {
        chain_ids,
        actor_key,
        action,
        resource: format_resource(&resource_kind, &resource_id),
        timestamp,
        verdict,
        receipt_hash,
        prev_receipt_hash,
    })
}

fn col_text(row: &Row<'_>, idx: usize, label: &str) -> Result<String, LedgerError> {
    row.get::<_, String>(idx)
        .map_err(|err| LedgerError::Integrity(format!("invalid TEXT value in {label}: {err}")))
}

fn col_opt_text(row: &Row<'_>, idx: usize, label: &str) -> Result<Option<String>, LedgerError> {
    row.get::<_, Option<String>>(idx).map_err(|err| {
        LedgerError::Integrity(format!("invalid nullable TEXT value in {label}: {err}"))
    })
}

fn col_i64(row: &Row<'_>, idx: usize, label: &str) -> Result<i64, LedgerError> {
    row.get::<_, i64>(idx)
        .map_err(|err| LedgerError::Integrity(format!("invalid INTEGER value in {label}: {err}")))
}

fn col_opt_i64(row: &Row<'_>, idx: usize, label: &str) -> Result<Option<i64>, LedgerError> {
    row.get::<_, Option<i64>>(idx).map_err(|err| {
        LedgerError::Integrity(format!("invalid nullable INTEGER value in {label}: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_expected_permit_calls_detects_overflow() {
        let mid = MandateId::sha256(b"overflow");
        let mut expected = BTreeMap::new();
        expected.insert(mid, u64::MAX);
        assert!(matches!(
            record_expected_permit_calls(&mut expected, &[mid]),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn audit_rejects_missing_tables_and_unexpected_schema_objects() {
        let empty_conn = Connection::open_in_memory().unwrap();
        let actor = KeyId::parse("ed25519:bbbb").unwrap();
        assert!(matches!(
            verify_integrity_in_conn(&empty_conn),
            Err(LedgerError::Sqlite(_))
        ));
        assert!(matches!(
            track_record_in_conn(&empty_conn, &actor),
            Err(LedgerError::Sqlite(_))
        ));

        empty_conn
            .execute_batch("CREATE TABLE rogue_table (x INT);")
            .unwrap();
        assert!(matches!(
            verify_schema_integrity(&empty_conn),
            Err(LedgerError::Integrity(_))
        ));

        let idx_conn = Connection::open_in_memory().unwrap();
        idx_conn
            .execute_batch(
                "CREATE TABLE quota_calls (mandate_id TEXT, calls INTEGER);
                 CREATE INDEX rogue_idx ON quota_calls(mandate_id);",
            )
            .unwrap();
        assert!(matches!(
            verify_schema_integrity(&idx_conn),
            Err(LedgerError::Integrity(_))
        ));

        let view_conn = Connection::open_in_memory().unwrap();
        view_conn
            .execute_batch("CREATE VIEW rogue_view AS SELECT 1;")
            .unwrap();
        assert!(matches!(
            verify_schema_integrity(&view_conn),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn sqlite_sequence_hwm_covers_missing_table_missing_row_and_null_seq() {
        let no_seq = Connection::open_in_memory().unwrap();
        verify_sqlite_sequence_hwm(&no_seq, 0).unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&no_seq, 1),
            Err(LedgerError::Integrity(_))
        ));

        let with_seq = Connection::open_in_memory().unwrap();
        with_seq
            .execute_batch("CREATE TABLE receipts (seq INTEGER PRIMARY KEY AUTOINCREMENT);")
            .unwrap();
        verify_sqlite_sequence_hwm(&with_seq, 0).unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, 1),
            Err(LedgerError::Integrity(_))
        ));

        with_seq
            .execute(
                "INSERT INTO sqlite_sequence (name, seq) VALUES ('receipts', NULL)",
                [],
            )
            .unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, 1),
            Err(LedgerError::Integrity(_))
        ));

        with_seq
            .execute(
                "UPDATE sqlite_sequence SET seq = X'01' WHERE name = 'receipts'",
                [],
            )
            .unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, 1),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn quota_calls_and_column_type_helpers_fail_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE quota_calls (mandate_id TEXT, calls INTEGER);")
            .unwrap();
        conn.execute("INSERT INTO quota_calls VALUES ('bad-mid', 1)", [])
            .unwrap();
        assert!(matches!(
            verify_quota_calls_consistency(&conn, &BTreeMap::new()),
            Err(LedgerError::Integrity(_))
        ));

        let mid = MandateId::sha256(b"neg");
        conn.execute("DELETE FROM quota_calls", []).unwrap();
        conn.execute(
            "INSERT INTO quota_calls VALUES (?1, -3)",
            params![mid.to_string()],
        )
        .unwrap();
        assert!(matches!(
            verify_quota_calls_consistency(&conn, &BTreeMap::new()),
            Err(LedgerError::Integrity(_))
        ));

        conn.execute("DELETE FROM quota_calls", []).unwrap();
        conn.execute(
            "INSERT INTO quota_calls VALUES (?1, X'01')",
            params![mid.to_string()],
        )
        .unwrap();
        assert!(matches!(
            verify_quota_calls_consistency(&conn, &BTreeMap::new()),
            Err(LedgerError::Integrity(_))
        ));

        let err = conn
            .query_row("SELECT X'01'", [], |row| Ok(col_opt_text(row, 0, "blob")))
            .unwrap();
        assert!(matches!(err, Err(LedgerError::Integrity(_))));
    }
}
