//! Scalar values, predicates, quotas, and the validated `HandfestAst` mandate representation.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::cnl::{render_canonical, try_render_canonical};

use super::{
    is_valid_field_path, is_valid_ident, is_valid_timestamp, validate_quoted_str, ActionPat,
    ActorDecl, AstError, Decimal, MandateId, ResourceSel,
};

/// Discriminant tag for scalar values, used for strict type checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScalarKind {
    Str,
    Timestamp,
    Decimal,
    Int,
    Bool,
}

/// Typed scalar literal in attributes, predicates, and verified facts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scalar {
    Str(String),
    /// RFC 3339 UTC timestamp in Unix seconds.
    Timestamp(i64),
    Decimal(Decimal),
    Int(i64),
    Bool(bool),
}

impl Scalar {
    /// Returns the runtime type tag of this scalar.
    #[must_use]
    pub const fn kind(&self) -> ScalarKind {
        match self {
            Self::Str(_) => ScalarKind::Str,
            Self::Timestamp(_) => ScalarKind::Timestamp,
            Self::Decimal(_) => ScalarKind::Decimal,
            Self::Int(_) => ScalarKind::Int,
            Self::Bool(_) => ScalarKind::Bool,
        }
    }

    /// Validates that this scalar can be canonically represented in a `HANDFEST v1` mandate.
    pub fn validate(&self) -> Result<(), AstError> {
        match self {
            Self::Str(s) => validate_quoted_str(s, "scalar string"),
            Self::Timestamp(ts) => {
                if !is_valid_timestamp(*ts) {
                    return Err(AstError::InvalidTimestamp(format!(
                        "timestamp {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
                    )));
                }
                Ok(())
            }
            Self::Decimal(d) => d.validate(),
            Self::Int(_) | Self::Bool(_) => Ok(()),
        }
    }

    /// Canonicalizes any inner `Decimal` representation.
    #[must_use]
    pub fn canonicalize_value(self) -> Self {
        match self {
            Self::Decimal(d) => Self::Decimal(d.canonical()),
            other => other,
        }
    }
}

/// Predicate operator applied to a `field_path`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PredicateOp {
    Eq(Scalar),
    Gte(Scalar),
    Gt(Scalar),
    Lte(Scalar),
    Lt(Scalar),
    In(BTreeSet<Scalar>),
    Prefix(String),
}

impl PredicateOp {
    /// Validates all inner scalar/string/set invariants of this operator.
    pub fn validate(&self) -> Result<(), AstError> {
        match self {
            Self::Eq(s) | Self::Gte(s) | Self::Gt(s) | Self::Lte(s) | Self::Lt(s) => s.validate(),
            Self::In(set) => {
                if set.is_empty() {
                    return Err(AstError::InvalidPredicate(
                        "IN set cannot be empty".to_string(),
                    ));
                }
                for item in set {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Prefix(pfx) => validate_quoted_str(pfx, "PREFIX string"),
        }
    }
}

/// Typed caveat predicate over a dot-separated `field_path`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Predicate {
    field_path: String,
    op: PredicateOp,
}

impl Predicate {
    /// Constructs a validated predicate.
    pub fn new(field_path: impl Into<String>, op: PredicateOp) -> Result<Self, AstError> {
        let pred = Self {
            field_path: field_path.into(),
            op,
        };
        pred.validate()?;
        Ok(pred)
    }

    /// Validates that `field_path` is a valid dot-separated path and `op` is valid.
    pub fn validate(&self) -> Result<(), AstError> {
        if !is_valid_field_path(&self.field_path) {
            return Err(AstError::InvalidFieldPath(self.field_path.clone()));
        }
        self.op.validate()
    }

    /// Returns the dot-separated field path.
    #[must_use]
    pub fn field_path(&self) -> &str {
        &self.field_path
    }

    /// Returns the predicate operator.
    #[must_use]
    pub const fn op(&self) -> &PredicateOp {
        &self.op
    }

    /// Constructs a validated equality predicate (`field == value`).
    pub fn eq(field_path: impl Into<String>, value: Scalar) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Eq(value))
    }

    /// Constructs a validated `>=` predicate.
    pub fn gte(field_path: impl Into<String>, value: Scalar) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Gte(value))
    }

    /// Constructs a validated `>` predicate.
    pub fn gt(field_path: impl Into<String>, value: Scalar) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Gt(value))
    }

    /// Constructs a validated `<=` predicate.
    pub fn lte(field_path: impl Into<String>, value: Scalar) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Lte(value))
    }

    /// Constructs a validated `<` predicate.
    pub fn lt(field_path: impl Into<String>, value: Scalar) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Lt(value))
    }

    /// Constructs a validated set membership predicate (`field IN { ... }`).
    pub fn in_set(
        field_path: impl Into<String>,
        values: BTreeSet<Scalar>,
    ) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::In(values))
    }

    /// Constructs a validated string prefix predicate (`field PREFIX "..."`).
    pub fn prefix(
        field_path: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Result<Self, AstError> {
        Self::new(field_path, PredicateOp::Prefix(prefix.into()))
    }

    fn canonicalize(&mut self) {
        match &mut self.op {
            PredicateOp::Eq(s)
            | PredicateOp::Gte(s)
            | PredicateOp::Gt(s)
            | PredicateOp::Lte(s)
            | PredicateOp::Lt(s) => {
                if let Scalar::Decimal(d) = s {
                    *d = d.canonical();
                }
            }
            PredicateOp::In(set) => {
                let normalized: BTreeSet<Scalar> = core::mem::take(set)
                    .into_iter()
                    .map(Scalar::canonicalize_value)
                    .collect();
                *set = normalized;
            }
            PredicateOp::Prefix(_) => {}
        }
    }
}

/// Resource consumption quota bound enforced across the mandate chain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quota {
    Calls(u64),
    Sum {
        max: Decimal,
        unit: String,
        field: String,
    },
}

impl Quota {
    /// Creates a validated `Quota::Sum`.
    pub fn sum(
        max: Decimal,
        unit: impl Into<String>,
        field: impl Into<String>,
    ) -> Result<Self, AstError> {
        let quota = Self::Sum {
            max,
            unit: unit.into(),
            field: field.into(),
        };
        quota.validate()?;
        Ok(quota)
    }

    /// Validates all lexical and numeric invariants of this quota.
    pub fn validate(&self) -> Result<(), AstError> {
        match self {
            Self::Calls(_) => Ok(()),
            Self::Sum { max, unit, field } => {
                max.validate()?;
                if max.is_negative() {
                    return Err(AstError::InvalidQuota(
                        "sum quota bound must be non-negative".to_string(),
                    ));
                }
                if !is_valid_ident(unit) {
                    return Err(AstError::InvalidIdent(unit.clone()));
                }
                if !is_valid_field_path(field) {
                    return Err(AstError::InvalidFieldPath(field.clone()));
                }
                Ok(())
            }
        }
    }

    fn canonicalize(&mut self) {
        if let Self::Sum { max, .. } = self {
            *max = max.canonical();
        }
    }
}

/// Unvalidated draft used to build a validated [`HandfestAst`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandfestAstBuilder {
    pub parent: Option<MandateId>,
    pub from: ActorDecl,
    pub to: ActorDecl,
    pub max_hops: u32,
    pub allow: Vec<ActionPat>,
    pub on: Vec<ResourceSel>,
    pub where_clauses: Vec<Predicate>,
    pub limits: Vec<Quota>,
}

impl HandfestAstBuilder {
    /// Validates all invariants and constructs a canonicalized [`HandfestAst`].
    pub fn build(self) -> Result<HandfestAst, AstError> {
        let mut ast = HandfestAst {
            parent: self.parent,
            from: self.from,
            to: self.to,
            max_hops: self.max_hops,
            allow: self.allow,
            on: self.on,
            where_clauses: self.where_clauses,
            limits: self.limits,
        };
        ast.validate()?;
        ast.canonicalize();
        Ok(ast)
    }
}

/// Complete typed, validated `HANDFEST v1` mandate AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandfestAst {
    parent: Option<MandateId>,
    from: ActorDecl,
    to: ActorDecl,
    max_hops: u32,
    allow: Vec<ActionPat>,
    on: Vec<ResourceSel>,
    where_clauses: Vec<Predicate>,
    limits: Vec<Quota>,
}

impl HandfestAst {
    /// Converts this AST into a mutable builder; calling [`HandfestAstBuilder::build`]
    /// re-validates all invariants.
    #[must_use]
    pub fn into_builder(self) -> HandfestAstBuilder {
        HandfestAstBuilder {
            parent: self.parent,
            from: self.from,
            to: self.to,
            max_hops: self.max_hops,
            allow: self.allow,
            on: self.on,
            where_clauses: self.where_clauses,
            limits: self.limits,
        }
    }

    /// Validates every lexical, structural, and value invariant required for canonical bijection.
    pub fn validate(&self) -> Result<(), AstError> {
        self.from.validate()?;
        self.to.validate()?;
        if self.allow.is_empty() {
            return Err(AstError::EmptyActions);
        }
        for pat in &self.allow {
            pat.validate()?;
        }
        if self.on.is_empty() {
            return Err(AstError::EmptyResources);
        }
        for sel in &self.on {
            sel.validate()?;
        }
        for pred in &self.where_clauses {
            pred.validate()?;
        }
        for quota in &self.limits {
            quota.validate()?;
        }
        Ok(())
    }

    /// Returns the optional `PARENT` mandate digest.
    #[must_use]
    pub const fn parent(&self) -> Option<MandateId> {
        self.parent
    }

    /// Returns the `FROM` delegator actor declaration.
    #[must_use]
    pub const fn from(&self) -> &ActorDecl {
        &self.from
    }

    /// Returns the `TO` delegatee actor declaration.
    #[must_use]
    pub const fn to(&self) -> &ActorDecl {
        &self.to
    }

    /// Returns the maximum remaining delegation hops.
    #[must_use]
    pub const fn max_hops(&self) -> u32 {
        self.max_hops
    }

    /// Returns the declared `ALLOW` action patterns.
    #[must_use]
    pub fn allow(&self) -> &[ActionPat] {
        &self.allow
    }

    /// Returns the declared `ON` resource selectors.
    #[must_use]
    pub fn on(&self) -> &[ResourceSel] {
        &self.on
    }

    /// Returns the declared `WHERE` predicates.
    #[must_use]
    pub fn where_clauses(&self) -> &[Predicate] {
        &self.where_clauses
    }

    /// Returns the declared `LIMIT` quotas.
    #[must_use]
    pub fn limits(&self) -> &[Quota] {
        &self.limits
    }

    /// Sorts and deduplicates `allow`, `on`, `where_clauses`, `limits`, and `In` sets deterministically,
    /// and normalizes all `Decimal` values to canonical form.
    pub fn canonicalize(&mut self) {
        self.from.canonicalize();
        self.to.canonicalize();
        self.allow.sort();
        self.allow.dedup();
        self.on.sort();
        self.on.dedup();
        for pred in &mut self.where_clauses {
            pred.canonicalize();
        }
        self.where_clauses.sort();
        self.where_clauses.dedup();
        for limit in &mut self.limits {
            limit.canonicalize();
        }
        self.limits.sort();
        self.limits.dedup();
    }

    /// Validates the AST and computes its content-addressed `MandateId`.
    pub fn try_mandate_id(&self) -> Result<MandateId, AstError> {
        let canonical = try_render_canonical(self)?;
        Ok(MandateId::sha256(canonical.as_bytes()))
    }

    /// Computes the content-addressed `MandateId` (`sha256` of `render_canonical(self)`).
    #[must_use]
    pub fn mandate_id(&self) -> MandateId {
        let canonical = render_canonical(self);
        MandateId::sha256(canonical.as_bytes())
    }
}
