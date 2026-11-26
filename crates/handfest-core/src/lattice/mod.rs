//! Pure-Rust monotonic attenuation proofs (`subsumes(parent, child)`).

mod domain;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::ast::{
    ActionPat, AstError, HandfestAst, KeyId, MandateId, Predicate, PredicateOp, Quota, ResourceSel,
};
use crate::ActorKind;

pub(crate) use domain::scalar_satisfies;
use domain::FieldDomain;

/// Reason a child mandate fails monotonic attenuation against its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarrowError {
    InvalidAst(AstError),
    MissingParent,
    ParentDigestMismatch {
        expected: MandateId,
        actual: MandateId,
    },
    HandoffKeyMismatch {
        expected: KeyId,
        actual: KeyId,
    },
    HandoffActorKindMismatch {
        expected: ActorKind,
        actual: ActorKind,
    },
    HopOverflow {
        parent_max_hops: u32,
        child_max_hops: u32,
    },
    EmptyActions,
    ActionWidening {
        action: ActionPat,
    },
    EmptyResources,
    ResourceWidening {
        resource: ResourceSel,
    },
    ContradictoryPredicates {
        field_path: String,
        detail: String,
    },
    PredicateNotImplied {
        predicate: Predicate,
    },
    QuotaWidening {
        quota: Quota,
    },
    InvalidQuota {
        detail: String,
    },
}

impl fmt::Display for NarrowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAst(err) => write!(f, "invalid mandate AST: {err}"),
            Self::MissingParent => f.write_str("child mandate is missing PARENT digest"),
            Self::ParentDigestMismatch { expected, actual } => {
                write!(f, "PARENT digest mismatch: expected {expected}, got {actual}")
            }
            Self::HandoffKeyMismatch { expected, actual } => {
                write!(f, "handoff key mismatch: parent TO is {expected}, child FROM is {actual}")
            }
            Self::HandoffActorKindMismatch { expected, actual } => {
                write!(
                    f,
                    "handoff actor kind mismatch: parent TO is {expected:?}, child FROM is {actual:?}"
                )
            }
            Self::HopOverflow {
                parent_max_hops,
                child_max_hops,
            } => write!(
                f,
                "delegation hop overflow: parent allows max {parent_max_hops}, child claims {child_max_hops}"
            ),
            Self::EmptyActions => f.write_str("child mandate must declare at least one action"),
            Self::ActionWidening { action } => {
                write!(f, "action '{action}' is not subsumed by parent ALLOW list")
            }
            Self::EmptyResources => f.write_str("child mandate must declare at least one resource"),
            Self::ResourceWidening { resource } => write!(
                f,
                "resource '{} \"{}\"' is not subsumed by parent ON list",
                resource.kind(), resource.pattern()
            ),
            Self::ContradictoryPredicates { field_path, detail } => {
                write!(f, "contradictory predicates on '{field_path}': {detail}")
            }
            Self::PredicateNotImplied { predicate } => {
                write!(
                    f,
                    "parent predicate on '{}' is not implied by child WHERE clauses",
                    predicate.field_path()
                )
            }
            Self::QuotaWidening { quota } => {
                write!(f, "parent quota {quota:?} is not tightened by child LIMIT clauses")
            }
            Self::InvalidQuota { detail } => write!(f, "invalid quota: {detail}"),
        }
    }
}

impl core::error::Error for NarrowError {}

/// Proves that `child` is a valid monotonic attenuation of `parent` across all five invariants.
pub fn subsumes(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    parent.validate().map_err(NarrowError::InvalidAst)?;
    child.validate().map_err(NarrowError::InvalidAst)?;
    let expected_id = parent.try_mandate_id().map_err(NarrowError::InvalidAst)?;
    subsumes_with_parent_id(parent, expected_id, child)
}

/// Proves monotonic attenuation for already-validated `parent` and `child` using a precomputed
/// `parent_id`, avoiding redundant validation and SHA-256 rehashing across chain checks.
pub(crate) fn subsumes_with_parent_id(
    parent: &HandfestAst,
    parent_id: MandateId,
    child: &HandfestAst,
) -> Result<(), NarrowError> {
    check_handoff(parent, parent_id, child)?;
    check_hops(parent, child)?;
    check_actions(parent, child)?;
    check_resources(parent, child)?;
    check_predicates(parent, child)?;
    check_quotas(parent, child)?;
    Ok(())
}

fn check_handoff(
    parent: &HandfestAst,
    expected_id: MandateId,
    child: &HandfestAst,
) -> Result<(), NarrowError> {
    let Some(actual_id) = child.parent() else {
        return Err(NarrowError::MissingParent);
    };
    if actual_id != expected_id {
        return Err(NarrowError::ParentDigestMismatch {
            expected: expected_id,
            actual: actual_id,
        });
    }
    if child.from().key() != parent.to().key() {
        return Err(NarrowError::HandoffKeyMismatch {
            expected: parent.to().key().clone(),
            actual: child.from().key().clone(),
        });
    }
    if child.from().kind() != parent.to().kind() {
        return Err(NarrowError::HandoffActorKindMismatch {
            expected: parent.to().kind(),
            actual: child.from().kind(),
        });
    }
    Ok(())
}

fn check_hops(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    if parent.max_hops() == 0 || child.max_hops() > parent.max_hops() - 1 {
        return Err(NarrowError::HopOverflow {
            parent_max_hops: parent.max_hops(),
            child_max_hops: child.max_hops(),
        });
    }
    Ok(())
}

fn check_actions(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    if child.allow().is_empty() {
        return Err(NarrowError::EmptyActions);
    }
    for child_pat in child.allow() {
        if !parent.allow().iter().any(|p| p.subsumes(child_pat)) {
            return Err(NarrowError::ActionWidening {
                action: child_pat.clone(),
            });
        }
    }
    Ok(())
}

fn check_resources(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    if child.on().is_empty() {
        return Err(NarrowError::EmptyResources);
    }
    for child_sel in child.on() {
        if !parent.on().iter().any(|p| p.subsumes(child_sel)) {
            return Err(NarrowError::ResourceWidening {
                resource: child_sel.clone(),
            });
        }
    }
    Ok(())
}

fn check_predicates(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    let mut by_field: BTreeMap<&str, Vec<&PredicateOp>> = BTreeMap::new();
    for pred in child.where_clauses() {
        by_field
            .entry(pred.field_path())
            .or_default()
            .push(pred.op());
    }

    let mut domains: BTreeMap<&str, FieldDomain> = BTreeMap::new();
    for (field, ops) in by_field {
        let domain = FieldDomain::from_ops(field, &ops)?;
        domains.insert(field, domain);
    }

    for parent_pred in parent.where_clauses() {
        let Some(domain) = domains.get(parent_pred.field_path()) else {
            return Err(NarrowError::PredicateNotImplied {
                predicate: parent_pred.clone(),
            });
        };
        if !domain.implies(parent_pred.op()) {
            return Err(NarrowError::PredicateNotImplied {
                predicate: parent_pred.clone(),
            });
        }
    }
    Ok(())
}

fn check_quotas(parent: &HandfestAst, child: &HandfestAst) -> Result<(), NarrowError> {
    for q in parent.limits().iter().chain(child.limits().iter()) {
        if let Quota::Sum { max, field, .. } = q {
            if max.is_negative() {
                return Err(NarrowError::InvalidQuota {
                    detail: format!("negative sum limit on '{field}'"),
                });
            }
        }
    }

    for p_quota in parent.limits() {
        let implied = match p_quota {
            Quota::Calls(p_max) => child
                .limits()
                .iter()
                .any(|c| matches!(c, Quota::Calls(c_max) if c_max <= p_max)),
            Quota::Sum {
                max: p_max,
                unit: p_unit,
                field: p_field,
            } => child.limits().iter().any(|c| {
                matches!(
                    c,
                    Quota::Sum {
                        max: c_max,
                        unit: c_unit,
                        field: c_field,
                    } if c_unit == p_unit && c_field == p_field && c_max <= p_max
                )
            }),
        };
        if !implied {
            return Err(NarrowError::QuotaWidening {
                quota: p_quota.clone(),
            });
        }
    }
    Ok(())
}
