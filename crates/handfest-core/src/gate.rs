//! Deterministic chain evaluator and hash-chained `DecisionReceipt`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::ast::{
    is_valid_ident, is_valid_quoted_str, is_valid_timestamp, try_format_rfc3339_utc, Decimal,
    HandfestAst, KeyId, MandateId, Predicate, PredicateOp, Quota, Scalar,
};
use crate::lattice::{scalar_satisfies, subsumes};
use crate::{ActorKind, AssuranceLevel, Verdict};

/// Normalized cryptographic / regulatory verification proof supplied by an external trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAnchorProof {
    pub anchor_id: String,
    pub assurance: AssuranceLevel,
    pub signer_key: KeyId,
    pub actor_kind: ActorKind,
    pub valid_from: i64,
    pub valid_until: i64,
}

/// A mandate paired with its verified trust-anchor signature proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMandate {
    pub ast: HandfestAst,
    pub proof: VerifiedAnchorProof,
}

/// Concrete action request submitted to the deterministic gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    pub actor_key: KeyId,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: String,
}

/// Gate-verified runtime facts (never supplied by an untrusted agent/model).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedFacts(pub BTreeMap<String, Scalar>);

impl VerifiedFacts {
    /// Creates an empty fact map.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts a verified fact.
    pub fn insert(&mut self, key: impl Into<String>, value: Scalar) -> Option<Scalar> {
        self.0.insert(key.into(), value)
    }

    /// Builder-style fact insertion.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: Scalar) -> Self {
        self.insert(key, value);
        self
    }

    /// Looks up a verified fact by field path.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Scalar> {
        self.0.get(key)
    }
}

impl From<BTreeMap<String, Scalar>> for VerifiedFacts {
    fn from(map: BTreeMap<String, Scalar>) -> Self {
        Self(map)
    }
}

/// Prior quota consumption recorded for a single mandate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MandateUsage {
    pub calls: u64,
    pub sums: BTreeMap<(String, String), Decimal>,
}

/// Chain-wide snapshot of prior quota consumption indexed by `MandateId`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuotaSnapshot {
    pub per_mandate: BTreeMap<MandateId, MandateUsage>,
}

impl QuotaSnapshot {
    /// Creates an empty usage snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            per_mandate: BTreeMap::new(),
        }
    }

    /// Records prior call count for `mandate_id`.
    pub fn set_calls(&mut self, mandate_id: MandateId, calls: u64) {
        self.per_mandate.entry(mandate_id).or_default().calls = calls;
    }

    /// Records prior sum consumption for `(mandate_id, unit, field)`.
    pub fn set_sum(
        &mut self,
        mandate_id: MandateId,
        unit: impl Into<String>,
        field: impl Into<String>,
        amount: Decimal,
    ) {
        self.per_mandate
            .entry(mandate_id)
            .or_default()
            .sums
            .insert((unit.into(), field.into()), amount);
    }

    /// Returns prior calls consumed under `mandate_id`.
    #[must_use]
    pub fn calls_for(&self, mandate_id: &MandateId) -> u64 {
        self.per_mandate
            .get(mandate_id)
            .map_or(0, |usage| usage.calls)
    }

    /// Returns prior sum consumed under `(mandate_id, unit, field)`.
    #[must_use]
    pub fn sum_for(&self, mandate_id: &MandateId, unit: &str, field: &str) -> Decimal {
        self.per_mandate
            .get(mandate_id)
            .and_then(|usage| usage.sums.get(&(unit.to_string(), field.to_string())))
            .copied()
            .unwrap_or(Decimal::ZERO)
    }
}

/// Deterministic, hash-chained audit receipt emitted for every `Permit` or `Deny` ruling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionReceipt {
    pub chain_ids: Vec<MandateId>,
    pub actor_key: KeyId,
    pub action: String,
    pub resource: String,
    pub timestamp: i64,
    pub verdict: Verdict,
    pub receipt_hash: MandateId,
    pub prev_receipt_hash: Option<MandateId>,
}

impl DecisionReceipt {
    /// Recomputes the canonical SHA-256 hash over all receipt fields and `prev_receipt_hash`.
    #[must_use]
    pub fn compute_hash(&self) -> MandateId {
        let mut hasher = Sha256::new();
        hasher.update(b"HANDFEST-RECEIPT-v1\0");

        match self.prev_receipt_hash {
            None => hasher.update([0u8]),
            Some(prev) => {
                hasher.update([1u8]);
                hasher.update(prev.as_bytes());
            }
        }

        hasher.update((self.chain_ids.len() as u64).to_be_bytes());
        for id in &self.chain_ids {
            hasher.update(id.as_bytes());
        }

        hash_str(&mut hasher, self.actor_key.scheme());
        hash_str(&mut hasher, self.actor_key.value());
        hash_str(&mut hasher, &self.action);
        hash_str(&mut hasher, &self.resource);
        hasher.update(self.timestamp.to_be_bytes());

        match &self.verdict {
            Verdict::Permit => hasher.update([0u8]),
            Verdict::Deny { reason } => {
                hasher.update([1u8]);
                hash_str(&mut hasher, reason);
            }
        }

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        MandateId(out)
    }

    /// Returns true if `self.receipt_hash` matches `self.compute_hash()`.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        self.receipt_hash == self.compute_hash()
    }
}

fn hash_str(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

fn write_escaped_receipt_token(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                for esc in c.escape_default() {
                    out.push(esc);
                }
            }
            c => out.push(c),
        }
    }
}

fn write_escaped_receipt_quoted(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                for esc in c.escape_default() {
                    out.push(esc);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn format_action(action: &str) -> String {
    let mut out = String::with_capacity(action.len());
    write_escaped_receipt_token(&mut out, action);
    out
}

fn format_resource(kind: &str, id: &str) -> String {
    let mut out = String::with_capacity(kind.len() + id.len() + 3);
    write_escaped_receipt_token(&mut out, kind);
    out.push(' ');
    write_escaped_receipt_quoted(&mut out, id);
    out
}

fn format_fact_scalar(val: &Scalar) -> String {
    match val {
        Scalar::Str(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            write_escaped_receipt_quoted(&mut out, s);
            out
        }
        Scalar::Timestamp(ts) => {
            try_format_rfc3339_utc(*ts).unwrap_or_else(|_| format!("Timestamp({ts})"))
        }
        Scalar::Decimal(d) => format!("{d}"),
        Scalar::Int(n) => format!("{n}"),
        Scalar::Bool(b) => (if *b { "true" } else { "false" }).to_string(),
    }
}

/// Deterministically evaluates a full delegation chain against a concrete request, verified facts,
/// prior chain-wide quota usage, and explicit UTC timestamp `now`.
#[must_use]
pub fn authorize(
    chain: &[VerifiedMandate],
    request: &ActionRequest,
    facts: &VerifiedFacts,
    usage: &QuotaSnapshot,
    now: i64,
    prev_receipt_hash: Option<MandateId>,
) -> (Verdict, DecisionReceipt) {
    let mut chain_ids: Vec<MandateId> = Vec::with_capacity(chain.len());
    let mut ast_error: Option<String> = None;

    for (i, vm) in chain.iter().enumerate() {
        let mid = match vm.ast.try_mandate_id() {
            Ok(id) => id,
            Err(err) => {
                ast_error = Some(format!("hop {i}: invalid mandate AST: {err}"));
                break;
            }
        };
        chain_ids.push(mid);
    }

    let verdict = match ast_error {
        Some(reason) => Verdict::Deny { reason },
        None => match evaluate_chain(chain, &chain_ids, request, facts, usage, now) {
            Ok(()) => Verdict::Permit,
            Err(reason) => Verdict::Deny { reason },
        },
    };

    let mut receipt = DecisionReceipt {
        chain_ids,
        actor_key: request.actor_key.clone(),
        action: format_action(&request.action),
        resource: format_resource(&request.resource_kind, &request.resource_id),
        timestamp: now,
        verdict: verdict.clone(),
        receipt_hash: MandateId([0u8; 32]),
        prev_receipt_hash,
    };
    receipt.receipt_hash = receipt.compute_hash();

    (verdict, receipt)
}

fn evaluate_chain(
    chain: &[VerifiedMandate],
    chain_ids: &[MandateId],
    request: &ActionRequest,
    facts: &VerifiedFacts,
    usage: &QuotaSnapshot,
    now: i64,
) -> Result<(), String> {
    if chain.is_empty() {
        return Err("empty mandate chain".into());
    }
    if !is_valid_timestamp(now) {
        return Err(format!(
            "timestamp {now} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
        ));
    }
    if chain[0].ast.parent().is_some() {
        return Err("root mandate must not declare a PARENT digest".into());
    }

    verify_proofs(chain, now)?;
    verify_attenuation(chain)?;

    let leaf = &chain[chain.len() - 1];
    if leaf.ast.to().key() != &request.actor_key {
        return Err(format!(
            "request actor key {} does not match leaf mandate TO key {}",
            request.actor_key,
            leaf.ast.to().key()
        ));
    }

    if !is_valid_concrete_action(&request.action) {
        return Err(format!(
            "invalid concrete action '{}'",
            format_action(&request.action)
        ));
    }
    if !is_valid_ident(&request.resource_kind) {
        let mut escaped = String::with_capacity(request.resource_kind.len());
        write_escaped_receipt_token(&mut escaped, &request.resource_kind);
        return Err(format!("invalid resource kind '{escaped}'"));
    }
    if !is_valid_quoted_str(&request.resource_id) {
        let mut escaped = String::with_capacity(request.resource_id.len() + 2);
        write_escaped_receipt_quoted(&mut escaped, &request.resource_id);
        return Err(format!("invalid resource id {escaped}"));
    }

    for (i, (vm, mid)) in chain.iter().zip(chain_ids.iter()).enumerate() {
        evaluate_mandate(i, vm, *mid, request, facts, usage, now)?;
    }
    Ok(())
}

fn verify_proofs(chain: &[VerifiedMandate], now: i64) -> Result<(), String> {
    for (i, vm) in chain.iter().enumerate() {
        if &vm.proof.signer_key != vm.ast.from().key() {
            return Err(format!(
                "hop {i}: proof signer key {} does not match mandate FROM key {}",
                vm.proof.signer_key,
                vm.ast.from().key()
            ));
        }
        if vm.proof.actor_kind != vm.ast.from().kind() {
            return Err(format!(
                "hop {i}: proof actor kind {:?} does not match mandate FROM kind {:?}",
                vm.proof.actor_kind,
                vm.ast.from().kind()
            ));
        }
        if vm.proof.valid_from >= vm.proof.valid_until {
            return Err(format!(
                "hop {i}: invalid anchor proof validity window [{}..{})",
                vm.proof.valid_from, vm.proof.valid_until
            ));
        }
        if now < vm.proof.valid_from || now >= vm.proof.valid_until {
            return Err(format!(
                "hop {i}: timestamp {now} outside anchor proof validity window [{}..{})",
                vm.proof.valid_from, vm.proof.valid_until
            ));
        }
    }
    Ok(())
}

fn verify_attenuation(chain: &[VerifiedMandate]) -> Result<(), String> {
    for i in 0..chain.len().saturating_sub(1) {
        if let Err(err) = subsumes(&chain[i].ast, &chain[i + 1].ast) {
            return Err(format!(
                "hop {i} -> {}: attenuation check failed: {err}",
                i + 1
            ));
        }
    }
    Ok(())
}

fn evaluate_mandate(
    hop: usize,
    vm: &VerifiedMandate,
    mid: MandateId,
    request: &ActionRequest,
    facts: &VerifiedFacts,
    usage: &QuotaSnapshot,
    now: i64,
) -> Result<(), String> {
    if !vm
        .ast
        .allow()
        .iter()
        .any(|pat| pat.matches(&request.action))
    {
        return Err(format!(
            "hop {hop}: action '{}' not allowed",
            request.action
        ));
    }
    if !vm
        .ast
        .on()
        .iter()
        .any(|sel| sel.kind() == request.resource_kind && sel.matches(&request.resource_id))
    {
        return Err(format!(
            "hop {hop}: resource '{}' not matched",
            format_resource(&request.resource_kind, &request.resource_id)
        ));
    }
    for pred in vm.ast.where_clauses() {
        evaluate_predicate(hop, pred, facts, now)?;
    }
    for quota in vm.ast.limits() {
        evaluate_quota(hop, mid, quota, facts, usage)?;
    }
    Ok(())
}

fn evaluate_predicate(
    hop: usize,
    pred: &Predicate,
    facts: &VerifiedFacts,
    now: i64,
) -> Result<(), String> {
    let time_val = Scalar::Timestamp(now);
    let fact_val = if pred.field_path() == "context.time" {
        &time_val
    } else {
        facts.get(pred.field_path()).ok_or_else(|| {
            format!(
                "hop {hop}: missing required verified fact '{}'",
                pred.field_path()
            )
        })?
    };

    check_predicate_type(hop, pred, fact_val)?;
    if let Scalar::Timestamp(ts) = fact_val {
        if !is_valid_timestamp(*ts) {
            return Err(format!(
                "hop {hop}: timestamp fact '{}' value {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z",
                pred.field_path()
            ));
        }
    }

    if !scalar_satisfies(fact_val, pred.op()) {
        return Err(format!(
            "hop {hop}: predicate on '{}' failed for value {}",
            pred.field_path(),
            format_fact_scalar(fact_val)
        ));
    }
    Ok(())
}

fn check_predicate_type(hop: usize, pred: &Predicate, fact_val: &Scalar) -> Result<(), String> {
    match pred.op() {
        PredicateOp::Eq(expected) => {
            if fact_val.kind() != expected.kind() {
                return Err(format!(
                    "hop {hop}: type mismatch on '{}': expected {:?}, got {:?}",
                    pred.field_path(),
                    expected.kind(),
                    fact_val.kind()
                ));
            }
        }
        PredicateOp::Gte(expected)
        | PredicateOp::Gt(expected)
        | PredicateOp::Lte(expected)
        | PredicateOp::Lt(expected) => {
            if matches!(expected, Scalar::Bool(_)) || fact_val.kind() != expected.kind() {
                return Err(format!(
                    "hop {hop}: invalid ordered comparison on '{}': expected {:?}, got {:?}",
                    pred.field_path(),
                    expected.kind(),
                    fact_val.kind()
                ));
            }
        }
        PredicateOp::Prefix(_) => {
            if !matches!(fact_val, Scalar::Str(_)) {
                return Err(format!(
                    "hop {hop}: type mismatch on '{}': PREFIX requires Str, got {:?}",
                    pred.field_path(),
                    fact_val.kind()
                ));
            }
        }
        PredicateOp::In(set) => {
            if set.is_empty() {
                return Err(format!(
                    "hop {hop}: empty IN set on '{}'",
                    pred.field_path()
                ));
            }
            if !set.iter().any(|v| v.kind() == fact_val.kind()) {
                return Err(format!(
                    "hop {hop}: type mismatch on '{}': IN set has no {:?} elements",
                    pred.field_path(),
                    fact_val.kind()
                ));
            }
        }
    }
    Ok(())
}

fn evaluate_quota(
    hop: usize,
    mid: MandateId,
    quota: &Quota,
    facts: &VerifiedFacts,
    usage: &QuotaSnapshot,
) -> Result<(), String> {
    match quota {
        Quota::Calls(max) => {
            let used = usage.calls_for(&mid);
            let Some(next) = used.checked_add(1) else {
                return Err(format!("hop {hop} ({mid}): call counter overflow"));
            };
            if next > *max {
                return Err(format!(
                    "hop {hop} ({mid}): call quota exhausted ({used}/{max})"
                ));
            }
            Ok(())
        }
        Quota::Sum { max, unit, field } => {
            if max.is_negative() {
                return Err(format!(
                    "hop {hop} ({mid}): negative sum quota limit on '{field}'"
                ));
            }
            let fact_val = facts.get(field).ok_or_else(|| {
                format!("hop {hop} ({mid}): missing required fact '{field}' for sum quota")
            })?;
            let Scalar::Decimal(delta) = fact_val else {
                return Err(format!(
                    "hop {hop} ({mid}): type mismatch for sum quota fact '{field}': expected Decimal, got {:?}",
                    fact_val.kind()
                ));
            };
            if delta.is_negative() {
                return Err(format!(
                    "hop {hop} ({mid}): negative value for sum quota fact '{field}'"
                ));
            }
            let used = usage.sum_for(&mid, unit, field);
            if used.is_negative() {
                return Err(format!(
                    "hop {hop} ({mid}): negative prior sum quota usage for '{field}'"
                ));
            }
            let Some(next) = used.checked_add(delta) else {
                return Err(format!("hop {hop} ({mid}): sum quota arithmetic overflow"));
            };
            if next > *max {
                return Err(format!(
                    "hop {hop} ({mid}): sum quota exceeded for '{field}' ({next} {unit} > {max} {unit})"
                ));
            }
            Ok(())
        }
    }
}

fn is_valid_concrete_action(action: &str) -> bool {
    !action.is_empty() && action.split('.').all(is_valid_ident)
}
