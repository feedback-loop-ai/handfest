//! SQLite integrity verification and [`TrackRecord`] projection helpers.

use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{is_valid_field_path, is_valid_ident, Decimal, KeyId, MandateId};
use handfest_core::gate::DecisionReceipt;
use handfest_core::Verdict;
use rusqlite::{params, Connection, OptionalExtension};

use crate::codec::{
    format_resource, parse_chain_ids_json, parse_optional_mandate_id, parse_verdict,
};
use crate::{LedgerError, TrackRecord};

pub(crate) fn run_audit_tx<F: FnOnce()>(
    conn: &Connection,
    actor_key: Option<&KeyId>,
    after_verify: F,
) -> Result<(usize, Option<TrackRecord>), LedgerError> {
    let tx = conn.unchecked_transaction()?;
    let verified_receipts = verify_integrity_in_conn(&tx)?;
    after_verify();
    let record = match actor_key {
        Some(key) => Some(track_record_in_conn(&tx, key)?),
        None => None,
    };
    tx.commit()?;
    Ok((verified_receipts, record))
}

pub(crate) fn verify_integrity_in_conn(conn: &Connection) -> Result<usize, LedgerError> {
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
        let seq: i64 = row.get(0)?;
        if seq != expected_seq {
            return Err(LedgerError::Integrity(format!(
                "non-contiguous receipt seq: expected {expected_seq}, got {seq}"
            )));
        }
        let receipt = reconstruct_receipt(row, expected_prev)?;
        if !receipt.verify_hash() {
            return Err(LedgerError::Integrity(format!(
                "seq {seq}: receipt_hash mismatch (stored {}, computed {})",
                receipt.receipt_hash,
                receipt.compute_hash()
            )));
        }
        if receipt.verdict == Verdict::Permit {
            record_expected_permit_calls(&mut expected_calls, &receipt.chain_ids)?;
        }
        expected_prev = Some(receipt.receipt_hash);
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| LedgerError::Integrity("receipt seq overflow".to_string()))?;
        count += 1;
    }

    verify_sqlite_sequence_hwm(conn, count)?;
    verify_quota_calls_consistency(conn, &expected_calls)?;
    verify_quota_sums_consistency(conn, &expected_calls)?;
    Ok(count)
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
        let seq: i64 = row.get(0)?;
        let chain_ids_json: String = row.get(1)?;
        let timestamp: i64 = row.get(2)?;
        let verdict_raw: String = row.get(3)?;
        let deny_reason: Option<String> = row.get(4)?;

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

fn verify_sqlite_sequence_hwm(conn: &Connection, count: usize) -> Result<(), LedgerError> {
    let count_i64 = i64::try_from(count)
        .map_err(|_| LedgerError::Integrity("receipt count exceeds i64 range".to_string()))?;
    let has_seq_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);

    if !has_seq_table {
        if count > 0 {
            return Err(LedgerError::Integrity(format!(
                "missing sqlite_sequence table for non-empty receipts ledger ({count} rows)"
            )));
        }
        return Ok(());
    }

    let mut stmt = conn.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'receipts'")?;
    let mut rows = stmt.query([])?;
    let mut hwms = Vec::new();
    while let Some(row) = rows.next()? {
        let seq: Option<i64> = row.get(0)?;
        hwms.push(seq);
    }

    match hwms.as_slice() {
        [] if count == 0 => Ok(()),
        [] => Err(LedgerError::Integrity(format!(
            "missing sqlite_sequence row for receipts ({count} rows present)"
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
        let mid_raw: String = row.get(0)?;
        let calls_i64: i64 = row.get(1)?;
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
        actual_calls.insert(mid, calls);
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

    while let Some(row) = rows.next()? {
        let mid_raw: String = row.get(0)?;
        let unit: String = row.get(1)?;
        let field: String = row.get(2)?;
        let total_raw: String = row.get(3)?;
        validate_quota_sum_row(&mid_raw, &unit, &field, &total_raw, expected_calls)?;
    }
    Ok(())
}

fn validate_quota_sum_row(
    mid_raw: &str,
    unit: &str,
    field: &str,
    total_raw: &str,
    expected_calls: &BTreeMap<MandateId, u64>,
) -> Result<(), LedgerError> {
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
    Ok(())
}

fn reconstruct_receipt(
    row: &rusqlite::Row<'_>,
    expected_prev: Option<MandateId>,
) -> Result<DecisionReceipt, LedgerError> {
    let seq: i64 = row.get(0)?;
    let prev_raw: Option<String> = row.get(1)?;
    let hash_raw: String = row.get(2)?;
    let chain_ids_json: String = row.get(3)?;
    let actor_key_raw: String = row.get(4)?;
    let action: String = row.get(5)?;
    let resource_kind: String = row.get(6)?;
    let resource_id: String = row.get(7)?;
    let timestamp: i64 = row.get(8)?;
    let verdict_raw: String = row.get(9)?;
    let deny_reason: Option<String> = row.get(10)?;

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
