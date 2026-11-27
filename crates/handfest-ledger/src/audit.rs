//! SQLite integrity verification and [`TrackRecord`] projection helpers.

use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{is_valid_field_path, is_valid_ident, Decimal, KeyId, MandateId};
use handfest_core::gate::DecisionReceipt;
use handfest_core::Verdict;
use rusqlite::{Connection, OptionalExtension, Row};

use crate::codec::{
    col_i64, col_opt_i64, col_opt_text, col_text, format_resource, parse_chain_ids_json,
    parse_optional_mandate_id, parse_verdict,
};
use crate::revocations::verify_and_load_revocations_inner;
use crate::schema::verify_schema_integrity;
use crate::{AuditSnapshot, LedgerChainHashes, LedgerError, StoredRevocation, TrackRecord};

#[derive(Default)]
struct AuditProjection<'a> {
    track_record: Option<&'a mut TrackRecordBuilder>,
    receipts: Option<&'a mut Vec<DecisionReceipt>>,
    receipt_hashes: Option<&'a mut Vec<[u8; 32]>>,
    last_permit_seq: Option<&'a mut Option<u64>>,
    stored_revocations: Option<&'a mut Vec<StoredRevocation>>,
    revocation_hashes: Option<&'a mut Vec<[u8; 32]>>,
}

pub(crate) fn run_audit_tx<F: FnOnce()>(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    after_receipts_scan: F,
) -> Result<(usize, Option<TrackRecord>), LedgerError> {
    let tx = conn.unchecked_transaction()?;
    let mut builder = actor_key.cloned().map(TrackRecordBuilder::new);
    let mut proj = AuditProjection {
        track_record: builder.as_mut(),
        ..AuditProjection::default()
    };
    let verified_receipts = verify_and_project_in_conn(&tx, &mut proj, after_receipts_scan)?;
    tx.commit()?;
    Ok((verified_receipts, builder.map(TrackRecordBuilder::finish)))
}

pub(crate) fn run_full_audit_tx(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    include_chain_hashes: bool,
) -> Result<AuditSnapshot, LedgerError> {
    run_full_audit_tx_with(conn, actor_key, include_chain_hashes, || Ok(())).map(|(snap, ())| snap)
}

pub(crate) fn run_full_audit_tx_with<T, F>(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    include_chain_hashes: bool,
    inside_tx: F,
) -> Result<(AuditSnapshot, T), LedgerError>
where
    F: FnOnce() -> Result<T, LedgerError>,
{
    let tx = conn.unchecked_transaction()?;
    let mut builder = actor_key.cloned().map(TrackRecordBuilder::new);
    let mut stored_revocations = Vec::new();
    let mut receipt_hashes = Vec::new();
    let mut revocation_hashes = Vec::new();
    let mut last_permit_seq = None;
    let verified_receipts = {
        let mut proj = AuditProjection {
            track_record: builder.as_mut(),
            receipts: None,
            receipt_hashes: include_chain_hashes.then_some(&mut receipt_hashes),
            last_permit_seq: include_chain_hashes.then_some(&mut last_permit_seq),
            stored_revocations: Some(&mut stored_revocations),
            revocation_hashes: include_chain_hashes.then_some(&mut revocation_hashes),
        };
        verify_and_project_in_conn(&tx, &mut proj, || {})?
    };
    // `tx` now holds SQLite's SHARED read lock; run external sidecar read before releasing it.
    let extra = inside_tx()?;
    tx.commit()?;
    let chain_hashes = include_chain_hashes.then_some(LedgerChainHashes {
        receipt_hashes,
        revocation_hashes,
        last_permit_seq,
    });
    Ok((
        AuditSnapshot {
            verified_receipts,
            track_record: builder.map(TrackRecordBuilder::finish),
            stored_revocations,
            chain_hashes,
        },
        extra,
    ))
}

pub(crate) fn run_verified_track_record(
    conn: &Connection,
    actor_key: &KeyId,
) -> Result<TrackRecord, LedgerError> {
    let tx = conn.unchecked_transaction()?;
    let mut builder = TrackRecordBuilder::new(actor_key.clone());
    let mut proj = AuditProjection {
        track_record: Some(&mut builder),
        ..AuditProjection::default()
    };
    verify_and_project_in_conn(&tx, &mut proj, || {})?;
    tx.commit()?;
    Ok(builder.finish())
}

pub(crate) fn run_verified_list_receipts(
    conn: &Connection,
) -> Result<Vec<DecisionReceipt>, LedgerError> {
    let tx = conn.unchecked_transaction()?;
    let mut receipts = Vec::new();
    let mut proj = AuditProjection {
        receipts: Some(&mut receipts),
        ..AuditProjection::default()
    };
    verify_and_project_in_conn(&tx, &mut proj, || {})?;
    tx.commit()?;
    Ok(receipts)
}

pub(crate) fn collect_verified_chain_hashes_in_conn(
    conn: &Connection,
) -> Result<LedgerChainHashes, LedgerError> {
    let mut receipt_hashes = Vec::new();
    let mut revocation_hashes = Vec::new();
    let mut last_permit_seq = None;
    let mut proj = AuditProjection {
        receipt_hashes: Some(&mut receipt_hashes),
        last_permit_seq: Some(&mut last_permit_seq),
        revocation_hashes: Some(&mut revocation_hashes),
        ..AuditProjection::default()
    };
    verify_and_project_in_conn(conn, &mut proj, || {})?;
    Ok(LedgerChainHashes {
        receipt_hashes,
        revocation_hashes,
        last_permit_seq,
    })
}

pub(crate) fn run_verified_chain_hashes(
    conn: &Connection,
) -> Result<LedgerChainHashes, LedgerError> {
    run_verified_chain_hashes_with(conn, |hashes| Ok(hashes.clone()))
}

pub(crate) fn run_verified_chain_hashes_with<T, F>(
    conn: &Connection,
    with_hashes: F,
) -> Result<T, LedgerError>
where
    F: FnOnce(&LedgerChainHashes) -> Result<T, LedgerError>,
{
    let tx = conn.unchecked_transaction()?;
    let hashes = collect_verified_chain_hashes_in_conn(&tx)?;
    // `tx` holds SQLite's SHARED read lock across `with_hashes` before releasing on commit/drop.
    let out = with_hashes(&hashes)?;
    tx.commit()?;
    Ok(out)
}

struct TrackRecordBuilder {
    actor_key: KeyId,
    total_decisions: u64,
    permits: u64,
    denies: u64,
    distinct_leaves: BTreeSet<MandateId>,
    first_timestamp: Option<i64>,
    last_timestamp: Option<i64>,
}

impl TrackRecordBuilder {
    fn new(actor_key: KeyId) -> Self {
        Self {
            actor_key,
            total_decisions: 0,
            permits: 0,
            denies: 0,
            distinct_leaves: BTreeSet::new(),
            first_timestamp: None,
            last_timestamp: None,
        }
    }

    fn record(&mut self, receipt: &DecisionReceipt) {
        self.total_decisions += 1;
        match receipt.verdict {
            Verdict::Permit => self.permits += 1,
            Verdict::Deny { .. } => self.denies += 1,
        }
        if let Some(leaf_id) = receipt.chain_ids.last() {
            self.distinct_leaves.insert(*leaf_id);
        }
        self.first_timestamp = Some(
            self.first_timestamp
                .map_or(receipt.timestamp, |cur| cur.min(receipt.timestamp)),
        );
        self.last_timestamp = Some(
            self.last_timestamp
                .map_or(receipt.timestamp, |cur| cur.max(receipt.timestamp)),
        );
    }

    fn finish(self) -> TrackRecord {
        TrackRecord {
            actor_key: self.actor_key,
            total_decisions: self.total_decisions,
            permits: self.permits,
            denies: self.denies,
            distinct_mandates: u64::try_from(self.distinct_leaves.len()).unwrap_or(u64::MAX),
            first_timestamp: self.first_timestamp,
            last_timestamp: self.last_timestamp,
        }
    }
}

fn verify_and_project_in_conn<F: FnOnce()>(
    conn: &Connection,
    proj: &mut AuditProjection<'_>,
    after_receipts_scan: F,
) -> Result<usize, LedgerError> {
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
            if let Some(last_permit) = proj.last_permit_seq.as_deref_mut() {
                *last_permit = Some(u64::try_from(seq).map_err(|_| {
                    LedgerError::Integrity("permit receipt seq overflow".to_string())
                })?);
            }
        }
        if let Some(builder) = proj.track_record.as_deref_mut() {
            if receipt.actor_key == builder.actor_key {
                builder.record(&receipt);
            }
        }
        expected_prev = Some(receipt.receipt_hash);
        if let Some(hashes) = proj.receipt_hashes.as_deref_mut() {
            hashes.push(*receipt.receipt_hash.as_bytes());
        }
        if let Some(out) = proj.receipts.as_deref_mut() {
            out.push(receipt);
        }
        expected_seq += 1;
        count += 1;
    }

    after_receipts_scan();
    verify_sqlite_sequence_hwm(conn, "receipts", expected_seq - 1)?;
    verify_quota_calls_consistency(conn, &expected_calls)?;
    verify_quota_sums_consistency(conn, &expected_calls)?;
    let (stored, _) =
        verify_and_load_revocations_inner(conn, proj.revocation_hashes.as_deref_mut())?;
    if let Some(out) = proj.stored_revocations.as_deref_mut() {
        *out = stored;
    }
    Ok(count)
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

pub(crate) fn verify_sqlite_sequence_hwm(
    conn: &Connection,
    table: &str,
    count_i64: i64,
) -> Result<(), LedgerError> {
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
                "missing sqlite_sequence table for non-empty {table} table ({count_i64} rows)"
            )));
        }
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT seq FROM sqlite_sequence WHERE name = ?1")?;
    let mut rows = stmt.query([table])?;
    let mut hwms = Vec::new();
    while let Some(row) = rows.next()? {
        let seq = col_opt_i64(row, 0, "sqlite_sequence.seq")?;
        hwms.push(seq);
    }

    match hwms.as_slice() {
        [] if count_i64 == 0 => Ok(()),
        [] => Err(LedgerError::Integrity(format!(
            "missing sqlite_sequence row for {table} ({count_i64} rows present)"
        ))),
        [Some(seq)] if *seq == count_i64 => Ok(()),
        [Some(seq)] => Err(LedgerError::Integrity(format!(
            "sqlite_sequence high-water mark mismatch for {table}: expected {count_i64}, got {seq}"
        ))),
        [None] => Err(LedgerError::Integrity(format!(
            "invalid NULL sqlite_sequence high-water mark for {table}"
        ))),
        _ => Err(LedgerError::Integrity(format!(
            "duplicate sqlite_sequence rows for {table}: expected at most 1, found {}",
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

#[cfg(test)]
mod tests {
    use rusqlite::params;

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
            run_audit_tx(&empty_conn, None, || {}),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            run_verified_track_record(&empty_conn, &actor),
            Err(LedgerError::Integrity(_))
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
        verify_sqlite_sequence_hwm(&no_seq, "receipts", 0).unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&no_seq, "receipts", 1),
            Err(LedgerError::Integrity(_))
        ));

        let with_seq = Connection::open_in_memory().unwrap();
        with_seq
            .execute_batch("CREATE TABLE receipts (seq INTEGER PRIMARY KEY AUTOINCREMENT);")
            .unwrap();
        verify_sqlite_sequence_hwm(&with_seq, "receipts", 0).unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, "receipts", 1),
            Err(LedgerError::Integrity(_))
        ));

        with_seq
            .execute(
                "INSERT INTO sqlite_sequence (name, seq) VALUES ('receipts', NULL)",
                [],
            )
            .unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, "receipts", 1),
            Err(LedgerError::Integrity(_))
        ));

        with_seq
            .execute(
                "UPDATE sqlite_sequence SET seq = X'01' WHERE name = 'receipts'",
                [],
            )
            .unwrap();
        assert!(matches!(
            verify_sqlite_sequence_hwm(&with_seq, "receipts", 1),
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

        // Direct defense-in-depth coverage for duplicate quota_calls / quota_sums rows.
        conn.execute("DELETE FROM quota_calls", []).unwrap();
        for _ in 0..2 {
            conn.execute(
                "INSERT INTO quota_calls VALUES (?1, 1)",
                params![mid.to_string()],
            )
            .unwrap();
        }
        let mut expected = BTreeMap::new();
        expected.insert(mid, 1);
        assert!(matches!(
            verify_quota_calls_consistency(&conn, &expected),
            Err(LedgerError::Integrity(_))
        ));

        conn.execute_batch(
            "CREATE TABLE quota_sums (mandate_id TEXT, unit TEXT, field TEXT, total TEXT);",
        )
        .unwrap();
        for _ in 0..2 {
            conn.execute(
                "INSERT INTO quota_sums VALUES (?1, 'USD', 'resource.amount', '10.0')",
                params![mid.to_string()],
            )
            .unwrap();
        }
        assert!(matches!(
            verify_quota_sums_consistency(&conn, &expected),
            Err(LedgerError::Integrity(_))
        ));

        let err = conn
            .query_row("SELECT X'01'", [], |row| Ok(col_opt_text(row, 0, "blob")))
            .unwrap();
        assert!(matches!(err, Err(LedgerError::Integrity(_))));
    }
}
