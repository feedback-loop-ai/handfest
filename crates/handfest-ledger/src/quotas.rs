//! Atomic chain-wide quota snapshot loading and update helpers for [`SqliteLedger`].

use std::collections::BTreeSet;

use handfest_core::ast::{Decimal, MandateId, Quota, Scalar};
use handfest_core::gate::{QuotaSnapshot, VerifiedFacts, VerifiedMandate};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::LedgerError;

pub(crate) struct QuotaUpdates {
    pub(crate) calls: Vec<(MandateId, i64)>,
    pub(crate) sums: Vec<(MandateId, String, String, Decimal)>,
}

pub(crate) fn load_quota_snapshot(
    tx: &Transaction<'_>,
    chain_ids: &[MandateId],
) -> Result<QuotaSnapshot, LedgerError> {
    let mut snapshot = QuotaSnapshot::new();
    let unique: BTreeSet<MandateId> = chain_ids.iter().copied().collect();

    let mut calls_stmt = tx.prepare("SELECT calls FROM quota_calls WHERE mandate_id = ?1")?;
    let mut sums_stmt =
        tx.prepare("SELECT unit, field, total FROM quota_sums WHERE mandate_id = ?1")?;

    for mid in unique {
        let mid_str = mid.to_string();
        if let Some(calls_i64) = calls_stmt
            .query_row(params![&mid_str], |row| row.get::<_, i64>(0))
            .optional()?
        {
            let calls = u64::try_from(calls_i64).map_err(|_| {
                LedgerError::QuotaAccounting(format!(
                    "negative stored call count {calls_i64} for {mid}"
                ))
            })?;
            snapshot.set_calls(mid, calls);
        }

        let mut rows = sums_stmt.query(params![&mid_str])?;
        while let Some(row) = rows.next()? {
            let unit: String = row.get(0)?;
            let field: String = row.get(1)?;
            let total_raw: String = row.get(2)?;
            let total = Decimal::parse(&total_raw).map_err(|err| {
                LedgerError::QuotaAccounting(format!(
                    "corrupt decimal total '{total_raw}' for ({mid}, {unit}, {field}): {err}"
                ))
            })?;
            if total.is_negative() {
                return Err(LedgerError::QuotaAccounting(format!(
                    "negative stored sum total '{total}' for ({mid}, {unit}, {field})"
                )));
            }
            snapshot.set_sum(mid, unit, field, total);
        }
    }

    Ok(snapshot)
}

pub(crate) fn compute_quota_updates(
    chain: &[VerifiedMandate],
    chain_ids: &[MandateId],
    facts: &VerifiedFacts,
    usage: &QuotaSnapshot,
) -> Result<QuotaUpdates, LedgerError> {
    if chain.len() != chain_ids.len() {
        return Err(LedgerError::QuotaAccounting(format!(
            "chain length ({}) does not match chain_ids length ({})",
            chain.len(),
            chain_ids.len()
        )));
    }

    let mut seen_ids: BTreeSet<MandateId> = BTreeSet::new();
    let mut calls = Vec::with_capacity(chain_ids.len());
    let mut sums = Vec::new();

    for (vm, &mid) in chain.iter().zip(chain_ids.iter()) {
        if !seen_ids.insert(mid) {
            continue;
        }
        let next_calls = usage
            .calls_for(&mid)
            .checked_add(1)
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(|| {
                LedgerError::QuotaAccounting(format!("call quota overflow for {mid}"))
            })?;
        calls.push((mid, next_calls));

        for (unit, field) in collect_mandate_sum_keys(vm) {
            let delta = extract_non_negative_decimal(facts, &field)?;
            let next = add_non_negative_sum(usage, &mid, &unit, &field, &delta)?;
            sums.push((mid, unit, field, next));
        }
    }

    Ok(QuotaUpdates { calls, sums })
}

pub(crate) fn apply_quota_updates(
    tx: &Transaction<'_>,
    updates: &QuotaUpdates,
) -> Result<(), LedgerError> {
    let mut calls_stmt = tx.prepare(
        "INSERT INTO quota_calls (mandate_id, calls) VALUES (?1, ?2)
         ON CONFLICT(mandate_id) DO UPDATE SET calls = excluded.calls",
    )?;
    for (mid, calls) in &updates.calls {
        calls_stmt.execute(params![mid.to_string(), calls])?;
    }

    let mut sums_stmt = tx.prepare(
        "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(mandate_id, unit, field) DO UPDATE SET total = excluded.total",
    )?;
    for (mid, unit, field, total) in &updates.sums {
        sums_stmt.execute(params![mid.to_string(), unit, field, total.to_string()])?;
    }
    Ok(())
}

fn collect_mandate_sum_keys(vm: &VerifiedMandate) -> BTreeSet<(String, String)> {
    let mut keys = BTreeSet::new();
    for quota in vm.ast.limits() {
        if let Quota::Sum { unit, field, .. } = quota {
            keys.insert((unit.clone(), field.clone()));
        }
    }
    keys
}

fn add_non_negative_sum(
    usage: &QuotaSnapshot,
    mid: &MandateId,
    unit: &str,
    field: &str,
    delta: &Decimal,
) -> Result<Decimal, LedgerError> {
    let prior = usage.sum_for(mid, unit, field);
    if prior.is_negative() {
        return Err(LedgerError::QuotaAccounting(format!(
            "negative prior sum total for ({mid}, {unit}, {field})"
        )));
    }
    prior.checked_add(delta).ok_or_else(|| {
        LedgerError::QuotaAccounting(format!(
            "decimal overflow adding {delta} to {prior} for ({mid}, {unit}, {field})"
        ))
    })
}

fn extract_non_negative_decimal(
    facts: &VerifiedFacts,
    field: &str,
) -> Result<Decimal, LedgerError> {
    let Some(val) = facts.get(field) else {
        return Err(LedgerError::QuotaAccounting(format!(
            "missing verified fact '{field}' for sum quota accounting"
        )));
    };
    let Scalar::Decimal(delta) = val else {
        return Err(LedgerError::QuotaAccounting(format!(
            "fact '{field}' is not a Decimal ({:?})",
            val.kind()
        )));
    };
    if delta.is_negative() {
        return Err(LedgerError::QuotaAccounting(format!(
            "negative delta '{delta}' for sum quota fact '{field}'"
        )));
    }
    Ok(*delta)
}

#[cfg(test)]
mod tests {
    use handfest_core::ast::parse_rfc3339_utc;
    use handfest_core::cnl::parse_mandate;
    use handfest_core::gate::VerifiedAnchorProof;
    use handfest_core::AssuranceLevel;
    use rusqlite::Connection;

    use super::*;

    fn sum_mandate() -> VerifiedMandate {
        let ast = parse_mandate(concat!(
            "HANDFEST v1\n",
            "FROM org \"acme\" (key: ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)\n",
            "TO agent \"bot\" (key: ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n",
            "DELEGATION max 0 hops\n",
            "ALLOW pay.transfer\n",
            "ON account \"ops-*\"\n",
            "LIMIT 100.0 USD sum(resource.amount)\n",
        ))
        .unwrap();
        let proof = VerifiedAnchorProof {
            anchor_id: "test".to_string(),
            assurance: AssuranceLevel::LocalKey,
            signer_key: ast.from().key().clone(),
            actor_kind: ast.from().kind(),
            valid_from: parse_rfc3339_utc("2026-11-24T00:00:00Z").unwrap(),
            valid_until: parse_rfc3339_utc("2026-11-26T00:00:00Z").unwrap(),
        };
        VerifiedMandate { ast, proof }
    }

    #[test]
    fn load_quota_snapshot_rejects_negative_calls_and_corrupt_sum() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE quota_calls (mandate_id TEXT PRIMARY KEY, calls INTEGER NOT NULL);
             CREATE TABLE quota_sums (mandate_id TEXT NOT NULL, unit TEXT NOT NULL, field TEXT NOT NULL, total TEXT NOT NULL, PRIMARY KEY (mandate_id, unit, field));",
        )
        .unwrap();
        let mid = MandateId::sha256(b"q1");
        conn.execute(
            "INSERT INTO quota_calls (mandate_id, calls) VALUES (?1, -1)",
            params![mid.to_string()],
        )
        .unwrap();
        {
            let tx = conn.transaction().unwrap();
            assert!(matches!(
                load_quota_snapshot(&tx, &[mid]),
                Err(LedgerError::QuotaAccounting(_))
            ));
        }

        conn.execute("UPDATE quota_calls SET calls = 1", [])
            .unwrap();
        conn.execute(
            "INSERT INTO quota_sums (mandate_id, unit, field, total) VALUES (?1, 'USD', 'resource.amount', 'not-a-decimal')",
            params![mid.to_string()],
        )
        .unwrap();
        {
            let tx = conn.transaction().unwrap();
            assert!(matches!(
                load_quota_snapshot(&tx, &[mid]),
                Err(LedgerError::QuotaAccounting(_))
            ));
        }
    }

    #[test]
    fn compute_quota_updates_covers_all_guard_and_dedup_paths() {
        let vm = sum_mandate();
        let mid = vm.ast.mandate_id();
        let ok_facts = VerifiedFacts::new().with(
            "resource.amount",
            Scalar::Decimal(Decimal::parse("10.0").unwrap()),
        );

        // Mismatched chain/chain_ids length.
        assert!(matches!(
            compute_quota_updates(
                std::slice::from_ref(&vm),
                &[],
                &ok_facts,
                &QuotaSnapshot::new()
            ),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Duplicate MandateId in chain is deduplicated (charged once).
        let dup_updates = compute_quota_updates(
            &[vm.clone(), vm.clone()],
            &[mid, mid],
            &ok_facts,
            &QuotaSnapshot::new(),
        )
        .unwrap();
        assert_eq!(dup_updates.calls.len(), 1);
        assert_eq!(dup_updates.calls[0].1, 1);

        // Call counter overflow past i64::MAX.
        let mut overflow_usage = QuotaSnapshot::new();
        overflow_usage.set_calls(mid, u64::try_from(i64::MAX).unwrap());
        assert!(matches!(
            compute_quota_updates(
                std::slice::from_ref(&vm),
                &[mid],
                &ok_facts,
                &overflow_usage
            ),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Missing fact.
        assert!(matches!(
            compute_quota_updates(
                std::slice::from_ref(&vm),
                &[mid],
                &VerifiedFacts::new(),
                &QuotaSnapshot::new()
            ),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Wrong fact type.
        let wrong_type = VerifiedFacts::new().with("resource.amount", Scalar::Int(5));
        assert!(matches!(
            compute_quota_updates(
                std::slice::from_ref(&vm),
                &[mid],
                &wrong_type,
                &QuotaSnapshot::new()
            ),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Negative delta fact.
        let neg_delta = VerifiedFacts::new().with(
            "resource.amount",
            Scalar::Decimal(Decimal::parse("-1.0").unwrap()),
        );
        assert!(matches!(
            compute_quota_updates(
                std::slice::from_ref(&vm),
                &[mid],
                &neg_delta,
                &QuotaSnapshot::new()
            ),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Negative prior sum in QuotaSnapshot.
        let mut neg_prior = QuotaSnapshot::new();
        neg_prior.set_sum(
            mid,
            "USD",
            "resource.amount",
            Decimal::parse("-1.0").unwrap(),
        );
        assert!(matches!(
            compute_quota_updates(std::slice::from_ref(&vm), &[mid], &ok_facts, &neg_prior),
            Err(LedgerError::QuotaAccounting(_))
        ));

        // Decimal addition overflow in prior + delta.
        let mut max_prior = QuotaSnapshot::new();
        max_prior.set_sum(
            mid,
            "USD",
            "resource.amount",
            Decimal::new(i128::MAX, 0).unwrap(),
        );
        assert!(matches!(
            compute_quota_updates(&[vm], &[mid], &ok_facts, &max_prior),
            Err(LedgerError::QuotaAccounting(_))
        ));
    }
}
