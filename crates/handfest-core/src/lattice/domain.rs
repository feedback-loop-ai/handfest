//! Per-field predicate constraint domain normalization and subsumption checks.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};

use crate::ast::{
    Decimal, PredicateOp, Scalar, ScalarKind, MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};

use super::NarrowError;

/// Normalized satisfiable per-field constraint domain extracted from a conjunction of predicates.
pub(super) struct FieldDomain {
    kind: Option<ScalarKind>,
    lower: Option<(Scalar, bool)>,
    upper: Option<(Scalar, bool)>,
    eq: Option<Scalar>,
    finite: Option<BTreeSet<Scalar>>,
    prefix: Option<String>,
}

impl FieldDomain {
    pub(super) fn from_ops(field: &str, ops: &[&PredicateOp]) -> Result<Self, NarrowError> {
        let mut dom = Self {
            kind: None,
            lower: None,
            upper: None,
            eq: None,
            finite: None,
            prefix: None,
        };
        for op in ops {
            dom.apply(field, op)?;
        }
        dom.finalize(field)?;
        Ok(dom)
    }

    fn require_kind(&mut self, field: &str, k: ScalarKind) -> Result<(), NarrowError> {
        match self.kind {
            None => {
                self.kind = Some(k);
                Ok(())
            }
            Some(existing) if existing == k => Ok(()),
            Some(existing) => Err(contradiction(
                field,
                format!("conflicting scalar types {existing:?} vs {k:?}"),
            )),
        }
    }

    fn apply(&mut self, field: &str, op: &PredicateOp) -> Result<(), NarrowError> {
        match op {
            PredicateOp::Eq(val) => self.apply_eq(field, val),
            PredicateOp::Gte(val) => {
                reject_bool_order(field, val)?;
                self.require_kind(field, val.kind())?;
                self.tighten_lower(val.clone(), true);
                Ok(())
            }
            PredicateOp::Gt(val) => {
                reject_bool_order(field, val)?;
                self.require_kind(field, val.kind())?;
                let (norm, inc) = normalize_gt(field, val)?;
                self.tighten_lower(norm, inc);
                Ok(())
            }
            PredicateOp::Lte(val) => {
                reject_bool_order(field, val)?;
                self.require_kind(field, val.kind())?;
                self.tighten_upper(val.clone(), true);
                Ok(())
            }
            PredicateOp::Lt(val) => {
                reject_bool_order(field, val)?;
                self.require_kind(field, val.kind())?;
                let (norm, inc) = normalize_lt(field, val)?;
                self.tighten_upper(norm, inc);
                Ok(())
            }
            PredicateOp::In(set) => self.apply_in(field, set),
            PredicateOp::Prefix(pfx) => self.apply_prefix(field, pfx),
        }
    }

    fn apply_eq(&mut self, field: &str, val: &Scalar) -> Result<(), NarrowError> {
        self.require_kind(field, val.kind())?;
        if let Some(prev) = &self.eq {
            if prev != val {
                return Err(contradiction(field, "conflicting == values".into()));
            }
        } else {
            self.eq = Some(val.clone());
        }
        if !matches!(val, Scalar::Bool(_)) {
            self.tighten_lower(val.clone(), true);
            self.tighten_upper(val.clone(), true);
        }
        Ok(())
    }

    fn apply_in(&mut self, field: &str, set: &BTreeSet<Scalar>) -> Result<(), NarrowError> {
        if set.is_empty() {
            return Err(contradiction(field, "empty IN set".into()));
        }
        match &mut self.finite {
            None => self.finite = Some(set.clone()),
            Some(existing) => {
                existing.retain(|v| set.contains(v));
                if existing.is_empty() {
                    return Err(contradiction(field, "disjoint IN sets".into()));
                }
            }
        }
        Ok(())
    }

    fn apply_prefix(&mut self, field: &str, pfx: &str) -> Result<(), NarrowError> {
        self.require_kind(field, ScalarKind::Str)?;
        match &mut self.prefix {
            None => self.prefix = Some(pfx.to_string()),
            Some(existing) => {
                if pfx.starts_with(existing.as_str()) {
                    *existing = pfx.to_string();
                } else if !existing.starts_with(pfx) {
                    return Err(contradiction(
                        field,
                        format!("incompatible PREFIX '{existing}' and '{pfx}'"),
                    ));
                }
            }
        }
        self.tighten_lower(Scalar::Str(pfx.to_string()), true);
        if let Some(upper_bound) = prefix_upper_bound(pfx) {
            self.tighten_upper(Scalar::Str(upper_bound), false);
        }
        Ok(())
    }

    fn tighten_lower(&mut self, val: Scalar, inc: bool) {
        match &self.lower {
            None => self.lower = Some((val, inc)),
            Some((cur, cur_inc)) => {
                let replace = val > *cur || (val == *cur && !inc && *cur_inc);
                if replace {
                    self.lower = Some((val, inc));
                }
            }
        }
    }

    fn tighten_upper(&mut self, val: Scalar, inc: bool) {
        match &self.upper {
            None => self.upper = Some((val, inc)),
            Some((cur, cur_inc)) => {
                let replace = val < *cur || (val == *cur && !inc && *cur_inc);
                if replace {
                    self.upper = Some((val, inc));
                }
            }
        }
    }

    fn finalize(&mut self, field: &str) -> Result<(), NarrowError> {
        match self.kind {
            Some(ScalarKind::Str) => self.tighten_lower(Scalar::Str(String::new()), true),
            Some(ScalarKind::Int) => {
                self.tighten_lower(Scalar::Int(i64::MIN), true);
                self.tighten_upper(Scalar::Int(i64::MAX), true);
            }
            Some(ScalarKind::Timestamp) => {
                self.tighten_lower(Scalar::Timestamp(MIN_RFC3339_TIMESTAMP), true);
                self.tighten_upper(Scalar::Timestamp(MAX_RFC3339_TIMESTAMP), true);
            }
            Some(ScalarKind::Decimal) => {
                self.tighten_lower(Scalar::Decimal(Decimal::MIN), true);
                self.tighten_upper(Scalar::Decimal(Decimal::MAX), true);
            }
            Some(ScalarKind::Bool) | None => {}
        }

        if let (Some((lo, lo_inc)), Some((hi, hi_inc))) = (&self.lower, &self.upper) {
            if lo > hi || (lo == hi && !(*lo_inc && *hi_inc)) {
                return Err(contradiction(
                    field,
                    "empty numeric/timestamp interval".into(),
                ));
            }
            if lo == hi && *lo_inc && *hi_inc {
                let pinned = lo.clone();
                self.apply_eq(field, &pinned)?;
            }
        }

        if let (Some(pfx), Some(Scalar::Str(upper_s))) =
            (&self.prefix, self.upper.as_ref().map(|(s, _)| s))
        {
            let upper_inc = self.upper.as_ref().is_some_and(|(_, inc)| *inc);
            if upper_s.as_str() < pfx.as_str() || (upper_s == pfx && !upper_inc) {
                return Err(contradiction(
                    field,
                    "upper string bound excludes PREFIX".into(),
                ));
            }
        }

        if let (Some(pfx), Some(Scalar::Str(lower_s))) =
            (&self.prefix, self.lower.as_ref().map(|(s, _)| s))
        {
            if prefix_strictly_below(pfx, lower_s) {
                return Err(contradiction(
                    field,
                    "lower string bound excludes PREFIX".into(),
                ));
            }
        }

        if let (Some(eq_val), Some(pfx)) = (&self.eq, &self.prefix) {
            if !matches!(eq_val, Scalar::Str(s) if s.starts_with(pfx.as_str())) {
                return Err(contradiction(
                    field,
                    "equality value does not satisfy PREFIX".into(),
                ));
            }
        }

        if let Some(mut set) = self.finite.take() {
            set.retain(|v| self.candidate_satisfies(v));
            if set.is_empty() {
                return Err(contradiction(
                    field,
                    "no element in IN set satisfies combined constraints".into(),
                ));
            }
            self.finite = Some(set);
        }
        Ok(())
    }

    fn candidate_satisfies(&self, val: &Scalar) -> bool {
        if let Some(k) = self.kind {
            if val.kind() != k {
                return false;
            }
        }
        if let Some(eq_val) = &self.eq {
            if val != eq_val {
                return false;
            }
        }
        if let Some((lo, inc)) = &self.lower {
            if val.kind() != lo.kind() || (!inc && val <= lo) || (*inc && val < lo) {
                return false;
            }
        }
        if let Some((hi, inc)) = &self.upper {
            if val.kind() != hi.kind() || (!inc && val >= hi) || (*inc && val > hi) {
                return false;
            }
        }
        if let Some(pfx) = &self.prefix {
            if !matches!(val, Scalar::Str(s) if s.starts_with(pfx.as_str())) {
                return false;
            }
        }
        true
    }

    pub(super) fn implies(&self, parent_op: &PredicateOp) -> bool {
        if let Some(set) = self.finite.as_ref() {
            return set.iter().all(|v| scalar_satisfies(v, parent_op));
        }
        if let Some(eq_val) = &self.eq {
            return scalar_satisfies(eq_val, parent_op);
        }
        match parent_op {
            PredicateOp::Eq(_) => false,
            PredicateOp::In(parent_set) => self.implies_in(parent_set),
            PredicateOp::Prefix(p_pfx) => self.implies_prefix(p_pfx),
            PredicateOp::Gte(v) => {
                !matches!(v, Scalar::Bool(_))
                    && self
                        .lower
                        .as_ref()
                        .is_some_and(|(lo, _)| lo.kind() == v.kind() && lo >= v)
            }
            PredicateOp::Gt(v) => self.implies_gt(v),
            PredicateOp::Lte(v) => self.implies_lte(v),
            PredicateOp::Lt(v) => self.implies_lt(v),
        }
    }

    fn implies_in(&self, parent_set: &BTreeSet<Scalar>) -> bool {
        if parent_set.is_empty() {
            return false;
        }
        let (Some((lo, true)), Some((hi, true))) = (&self.lower, &self.upper) else {
            return false;
        };
        let max_len = u128::try_from(parent_set.len()).unwrap_or(u128::MAX);
        match (lo, hi) {
            (Scalar::Int(lo_n), Scalar::Int(hi_n)) => {
                if lo_n > hi_n {
                    return false;
                }
                let count = u128::from(hi_n.abs_diff(*lo_n)) + 1;
                if count > max_len {
                    return false;
                }
                (*lo_n..=*hi_n).all(|n| parent_set.contains(&Scalar::Int(n)))
            }
            (Scalar::Timestamp(lo_ts), Scalar::Timestamp(hi_ts)) => {
                if lo_ts > hi_ts {
                    return false;
                }
                let count = u128::from(hi_ts.abs_diff(*lo_ts)) + 1;
                if count > max_len {
                    return false;
                }
                (*lo_ts..=*hi_ts).all(|ts| parent_set.contains(&Scalar::Timestamp(ts)))
            }
            (Scalar::Decimal(lo_d), Scalar::Decimal(hi_d)) => {
                let Some(count) = lo_d.discrete_count_to(hi_d) else {
                    return false;
                };
                if count == 0 || count > max_len {
                    return false;
                }
                let mut cur = *lo_d;
                loop {
                    if !parent_set.contains(&Scalar::Decimal(cur)) {
                        return false;
                    }
                    if cur == *hi_d {
                        return true;
                    }
                    let Some(next) = cur.next_up() else {
                        return false;
                    };
                    cur = next;
                }
            }
            _ => false,
        }
    }

    fn implies_prefix(&self, p_pfx: &str) -> bool {
        if self
            .prefix
            .as_deref()
            .is_some_and(|c_pfx| c_pfx.starts_with(p_pfx))
        {
            return true;
        }
        if p_pfx.is_empty() {
            return self.kind == Some(ScalarKind::Str);
        }
        let lower_ok = match &self.lower {
            Some((Scalar::Str(lo), lo_inc)) => {
                lo.as_str() >= p_pfx || (!*lo_inc && p_pfx.strip_prefix(lo.as_str()) == Some("\0"))
            }
            _ => false,
        };
        if !lower_ok {
            return false;
        }
        match prefix_upper_bound(p_pfx) {
            None => true,
            Some(limit) => match &self.upper {
                Some((Scalar::Str(hi), hi_inc)) => {
                    hi.as_str() < limit.as_str() || (!*hi_inc && hi.as_str() == limit.as_str())
                }
                _ => false,
            },
        }
    }

    fn implies_gt(&self, v: &Scalar) -> bool {
        if matches!(v, Scalar::Bool(_)) {
            return false;
        }
        let Some((lo, lo_inc)) = &self.lower else {
            return false;
        };
        if lo.kind() != v.kind() {
            return false;
        }
        match v {
            Scalar::Int(n) => n
                .checked_add(1)
                .is_some_and(|min_req| *lo >= Scalar::Int(min_req)),
            Scalar::Timestamp(ts) => ts
                .checked_add(1)
                .filter(|&min_req| min_req <= MAX_RFC3339_TIMESTAMP)
                .is_some_and(|min_req| *lo >= Scalar::Timestamp(min_req)),
            Scalar::Decimal(d) => d
                .next_up()
                .is_some_and(|min_req| *lo >= Scalar::Decimal(min_req)),
            _ => lo > v || (lo == v && !lo_inc),
        }
    }

    fn implies_lte(&self, v: &Scalar) -> bool {
        if matches!(v, Scalar::Bool(_)) {
            return false;
        }
        if let (Some(pfx), Scalar::Str(bound)) = (&self.prefix, v) {
            if prefix_strictly_below(pfx, bound) {
                return true;
            }
        }
        self.upper
            .as_ref()
            .is_some_and(|(hi, _)| hi.kind() == v.kind() && hi <= v)
    }

    fn implies_lt(&self, v: &Scalar) -> bool {
        if matches!(v, Scalar::Bool(_)) {
            return false;
        }
        if let (Some(pfx), Scalar::Str(bound)) = (&self.prefix, v) {
            if prefix_strictly_below(pfx, bound) {
                return true;
            }
        }
        let Some((hi, hi_inc)) = &self.upper else {
            return false;
        };
        if hi.kind() != v.kind() {
            return false;
        }
        match v {
            Scalar::Int(n) => n
                .checked_sub(1)
                .is_some_and(|max_req| *hi <= Scalar::Int(max_req)),
            Scalar::Timestamp(ts) => ts
                .checked_sub(1)
                .filter(|&max_req| max_req >= MIN_RFC3339_TIMESTAMP)
                .is_some_and(|max_req| *hi <= Scalar::Timestamp(max_req)),
            Scalar::Decimal(d) => d
                .next_down()
                .is_some_and(|max_req| *hi <= Scalar::Decimal(max_req)),
            _ => hi < v || (hi == v && !hi_inc),
        }
    }
}

/// Returns true iff every string starting with `pfx` is strictly less than `bound`
/// in lexicographical (UTF-8 / code point) order.
fn prefix_strictly_below(pfx: &str, bound: &str) -> bool {
    pfx < bound && !bound.starts_with(pfx)
}

/// Returns the lexicographically smallest Rust `String` strictly greater than every string
/// starting with non-empty `pfx`, or `None` if every character in `pfx` is `char::MAX`.
fn prefix_upper_bound(pfx: &str) -> Option<String> {
    for (idx, ch) in pfx.char_indices().rev() {
        if let Some(next_ch) = next_char(ch) {
            let mut bound = String::with_capacity(idx + next_ch.len_utf8());
            bound.push_str(&pfx[..idx]);
            bound.push(next_ch);
            return Some(bound);
        }
    }
    None
}

fn next_char(ch: char) -> Option<char> {
    match ch as u32 {
        0xD7FF => char::from_u32(0xE000),
        0x10_FFFF => None,
        code => char::from_u32(code + 1),
    }
}

fn reject_bool_order(field: &str, val: &Scalar) -> Result<(), NarrowError> {
    if matches!(val, Scalar::Bool(_)) {
        return Err(contradiction(
            field,
            "ordering operator is not valid on boolean values".into(),
        ));
    }
    Ok(())
}

fn normalize_gt(field: &str, val: &Scalar) -> Result<(Scalar, bool), NarrowError> {
    match val {
        Scalar::Int(n) => n
            .checked_add(1)
            .map(|next| (Scalar::Int(next), true))
            .ok_or_else(|| contradiction(field, "integer > MAX is unsatisfiable".into())),
        Scalar::Timestamp(ts) => ts
            .checked_add(1)
            .filter(|&next| next <= MAX_RFC3339_TIMESTAMP)
            .map(|next| (Scalar::Timestamp(next), true))
            .ok_or_else(|| contradiction(field, "timestamp > MAX is unsatisfiable".into())),
        Scalar::Decimal(d) => d
            .next_up()
            .map(|next| (Scalar::Decimal(next), true))
            .ok_or_else(|| contradiction(field, "decimal > MAX is unsatisfiable".into())),
        Scalar::Str(s) => {
            let mut next = String::with_capacity(s.len() + 1);
            next.push_str(s);
            next.push('\0');
            Ok((Scalar::Str(next), true))
        }
        other => Ok((other.clone(), false)),
    }
}

fn normalize_lt(field: &str, val: &Scalar) -> Result<(Scalar, bool), NarrowError> {
    match val {
        Scalar::Int(n) => n
            .checked_sub(1)
            .map(|prev| (Scalar::Int(prev), true))
            .ok_or_else(|| contradiction(field, "integer < MIN is unsatisfiable".into())),
        Scalar::Timestamp(ts) => ts
            .checked_sub(1)
            .filter(|&prev| prev >= MIN_RFC3339_TIMESTAMP)
            .map(|prev| (Scalar::Timestamp(prev), true))
            .ok_or_else(|| contradiction(field, "timestamp < MIN is unsatisfiable".into())),
        Scalar::Decimal(d) => d
            .next_down()
            .map(|prev| (Scalar::Decimal(prev), true))
            .ok_or_else(|| contradiction(field, "decimal < MIN is unsatisfiable".into())),
        Scalar::Str(s) if s.is_empty() => Err(contradiction(
            field,
            "string < \"\" is unsatisfiable".into(),
        )),
        other => Ok((other.clone(), false)),
    }
}

fn contradiction(field: &str, detail: String) -> NarrowError {
    NarrowError::ContradictoryPredicates {
        field_path: field.to_string(),
        detail,
    }
}

pub(crate) fn scalar_satisfies(val: &Scalar, op: &PredicateOp) -> bool {
    match op {
        PredicateOp::Eq(target) => val == target,
        PredicateOp::Gte(target) => {
            !matches!(target, Scalar::Bool(_)) && val.kind() == target.kind() && val >= target
        }
        PredicateOp::Gt(target) => {
            !matches!(target, Scalar::Bool(_)) && val.kind() == target.kind() && val > target
        }
        PredicateOp::Lte(target) => {
            !matches!(target, Scalar::Bool(_)) && val.kind() == target.kind() && val <= target
        }
        PredicateOp::Lt(target) => {
            !matches!(target, Scalar::Bool(_)) && val.kind() == target.kind() && val < target
        }
        PredicateOp::In(set) => set.contains(val),
        PredicateOp::Prefix(pfx) => matches!(val, Scalar::Str(s) if s.starts_with(pfx.as_str())),
    }
}
