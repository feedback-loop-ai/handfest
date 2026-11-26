//! Typed AST, value domain, glob matching/subsumption, and content-addressed digest for `HANDFEST v1`.

mod decimal;
mod mandate;
mod time;

pub use decimal::{Decimal, MAX_DECIMAL_SCALE};
pub use mandate::{
    HandfestAst, HandfestAstBuilder, Predicate, PredicateOp, Quota, Scalar, ScalarKind,
};
pub use time::{
    format_rfc3339_utc, is_valid_timestamp, parse_rfc3339_utc, try_format_rfc3339_utc,
    MAX_RFC3339_TIMESTAMP, MIN_RFC3339_TIMESTAMP,
};

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

use sha2::{Digest, Sha256};

use crate::ActorKind;

/// Error returned when constructing, validating, or parsing typed AST primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstError {
    InvalidMandateId(String),
    InvalidKeyId(String),
    InvalidActionPat(String),
    InvalidResourceKind(String),
    InvalidFieldPath(String),
    InvalidIdent(String),
    InvalidString(String),
    InvalidDecimal(String),
    InvalidTimestamp(String),
    InvalidActorAttr(String),
    InvalidPredicate(String),
    InvalidQuota(String),
    EmptyActions,
    EmptyResources,
}

impl fmt::Display for AstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMandateId(msg) => write!(f, "invalid mandate id: {msg}"),
            Self::InvalidKeyId(msg) => write!(f, "invalid key id: {msg}"),
            Self::InvalidActionPat(msg) => write!(f, "invalid action pattern: {msg}"),
            Self::InvalidResourceKind(msg) => write!(f, "invalid resource kind: {msg}"),
            Self::InvalidFieldPath(msg) => write!(f, "invalid field path: {msg}"),
            Self::InvalidIdent(msg) => write!(f, "invalid identifier: {msg}"),
            Self::InvalidString(msg) => write!(f, "invalid quoted string: {msg}"),
            Self::InvalidDecimal(msg) => write!(f, "invalid decimal: {msg}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid RFC 3339 UTC timestamp: {msg}"),
            Self::InvalidActorAttr(msg) => write!(f, "invalid actor attribute: {msg}"),
            Self::InvalidPredicate(msg) => write!(f, "invalid predicate: {msg}"),
            Self::InvalidQuota(msg) => write!(f, "invalid quota: {msg}"),
            Self::EmptyActions => f.write_str("ALLOW clause must declare at least one action"),
            Self::EmptyResources => f.write_str("ON clause must declare at least one resource"),
        }
    }
}

impl core::error::Error for AstError {}

/// Content-addressed SHA-256 digest (`sha256:<64-lowercase-hex>`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MandateId(pub [u8; 32]);

impl MandateId {
    /// Computes the SHA-256 digest of arbitrary bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Returns the raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses a strict `sha256:<64-lowercase-hex>` digest string.
    pub fn parse(input: &str) -> Result<Self, AstError> {
        let Some(hex) = input.strip_prefix("sha256:") else {
            return Err(AstError::InvalidMandateId(
                "must start with 'sha256:'".to_string(),
            ));
        };
        if hex.len() != 64 {
            return Err(AstError::InvalidMandateId(
                "expected 64 lowercase hex characters".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        let raw = hex.as_bytes();
        for (i, slot) in bytes.iter_mut().enumerate() {
            let hi = decode_lower_hex(raw[i * 2])?;
            let lo = decode_lower_hex(raw[i * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn decode_lower_hex(b: u8) -> Result<u8, AstError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(AstError::InvalidMandateId(
            "digest must contain only lowercase hex digits".to_string(),
        )),
    }
}

impl fmt::Display for MandateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for MandateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MandateId(\"{self}\")")
    }
}

impl FromStr for MandateId {
    type Err = AstError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Validates a `HANDFEST v1` identifier (`[A-Za-z_][A-Za-z0-9_-]*`).
#[must_use]
pub fn is_valid_ident(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validates a dot-separated field path (`ident ( "." ident )*`).
#[must_use]
pub fn is_valid_field_path(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_valid_ident)
}

/// Validates a quoted string value: control characters (including `\0`, `\n`, `\r`, `\t`) are rejected.
#[must_use]
pub fn is_valid_quoted_str(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

#[must_use]
pub(crate) fn is_valid_key_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'(' | b')' | b'"'))
}

pub(super) fn validate_quoted_str(value: &str, context: &str) -> Result<(), AstError> {
    if !is_valid_quoted_str(value) {
        return Err(AstError::InvalidString(format!(
            "{context} must not contain control characters"
        )));
    }
    Ok(())
}

/// Cryptographic key identifier (`<scheme>:<value>`, e.g. `ed25519:9b1e...44a0`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId {
    scheme: String,
    value: String,
}

impl KeyId {
    /// Creates a validated `KeyId` from scheme and value components.
    pub fn new(scheme: impl Into<String>, value: impl Into<String>) -> Result<Self, AstError> {
        let candidate = Self {
            scheme: scheme.into(),
            value: value.into(),
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// Validates that this `KeyId` satisfies all lexical invariants.
    pub fn validate(&self) -> Result<(), AstError> {
        if !is_valid_ident(&self.scheme) {
            return Err(AstError::InvalidKeyId(format!(
                "invalid key scheme '{}'",
                self.scheme
            )));
        }
        if !is_valid_key_value(&self.value) {
            return Err(AstError::InvalidKeyId(format!(
                "invalid key value '{}'",
                self.value
            )));
        }
        Ok(())
    }

    /// Parses `<scheme>:<value>`.
    pub fn parse(input: &str) -> Result<Self, AstError> {
        let Some((scheme, value)) = input.split_once(':') else {
            return Err(AstError::InvalidKeyId(
                "expected '<scheme>:<value>'".to_string(),
            ));
        };
        Self::new(scheme, value)
    }

    /// Returns the key scheme (e.g. `ed25519`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the scheme-specific key value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.value)
    }
}

impl FromStr for KeyId {
    type Err = AstError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Actor declaration appearing in `FROM` and `TO` clauses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActorDecl {
    kind: ActorKind,
    name: String,
    key: KeyId,
    attrs: BTreeMap<String, Scalar>,
}

impl ActorDecl {
    /// Creates a validated `ActorDecl`.
    pub fn new(
        kind: ActorKind,
        name: impl Into<String>,
        key: KeyId,
        attrs: BTreeMap<String, Scalar>,
    ) -> Result<Self, AstError> {
        let actor = Self {
            kind,
            name: name.into(),
            key,
            attrs,
        };
        actor.validate()?;
        Ok(actor)
    }

    /// Validates all lexical and value invariants on this `ActorDecl`.
    pub fn validate(&self) -> Result<(), AstError> {
        validate_quoted_str(&self.name, "actor name")?;
        self.key.validate()?;
        for (k, v) in &self.attrs {
            if !is_valid_ident(k) {
                return Err(AstError::InvalidIdent(k.clone()));
            }
            if k == "key" {
                return Err(AstError::InvalidActorAttr(
                    "reserved attribute 'key' cannot appear in attrs".to_string(),
                ));
            }
            v.validate()?;
        }
        Ok(())
    }

    /// Returns the actor kind.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        self.kind
    }

    /// Returns the actor display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the actor's cryptographic key identifier.
    #[must_use]
    pub const fn key(&self) -> &KeyId {
        &self.key
    }

    /// Returns the actor's attribute map.
    #[must_use]
    pub const fn attrs(&self) -> &BTreeMap<String, Scalar> {
        &self.attrs
    }

    fn canonicalize(&mut self) {
        for v in self.attrs.values_mut() {
            if let Scalar::Decimal(d) = v {
                *d = d.canonical();
            }
        }
    }
}

/// Dot-separated action pattern with optional trailing `.*` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionPat {
    segments: Vec<String>,
    wildcard: bool,
}

impl ActionPat {
    /// Parses an action pattern (`ident ( "." ident )* [ ".*" ]`).
    pub fn parse(input: &str) -> Result<Self, AstError> {
        if input.is_empty() {
            return Err(AstError::InvalidActionPat("empty action pattern".into()));
        }
        let (base, wildcard) = match input.strip_suffix(".*") {
            Some(prefix) => (prefix, true),
            None => (input, false),
        };
        if base.is_empty() {
            return Err(AstError::InvalidActionPat(
                "action pattern must start with an identifier".into(),
            ));
        }
        let mut segments = Vec::new();
        for seg in base.split('.') {
            if !is_valid_ident(seg) {
                return Err(AstError::InvalidActionPat(format!(
                    "invalid action segment '{seg}'"
                )));
            }
            segments.push(seg.to_string());
        }
        Ok(Self { segments, wildcard })
    }

    /// Validates all action pattern segments.
    pub fn validate(&self) -> Result<(), AstError> {
        if self.segments.is_empty() {
            return Err(AstError::InvalidActionPat("empty action pattern".into()));
        }
        for seg in &self.segments {
            if !is_valid_ident(seg) {
                return Err(AstError::InvalidActionPat(format!(
                    "invalid action segment '{seg}'"
                )));
            }
        }
        Ok(())
    }

    /// Returns the leading concrete identifier segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Returns true if this pattern ends with `.*`.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Returns true if `self` matches a concrete action name (no wildcards).
    #[must_use]
    pub fn matches(&self, concrete_action: &str) -> bool {
        let mut parts = concrete_action.split('.');
        for expected in &self.segments {
            if parts.next() != Some(expected.as_str()) {
                return false;
            }
        }
        if !self.wildcard {
            return parts.next().is_none();
        }
        let mut had_extra = false;
        for seg in parts {
            if !is_valid_ident(seg) {
                return false;
            }
            had_extra = true;
        }
        had_extra
    }

    /// Returns true if every action matched by `child` is also matched by `self`.
    #[must_use]
    pub fn subsumes(&self, child: &Self) -> bool {
        if !self.wildcard {
            return !child.wildcard && self.segments == child.segments;
        }
        if !child.segments.starts_with(&self.segments) {
            return false;
        }
        if child.wildcard {
            child.segments.len() >= self.segments.len()
        } else {
            child.segments.len() > self.segments.len()
        }
    }
}

impl fmt::Display for ActionPat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, seg) in self.segments.iter().enumerate() {
            if idx > 0 {
                f.write_str(".")?;
            }
            f.write_str(seg)?;
        }
        if self.wildcard {
            f.write_str(".*")?;
        }
        Ok(())
    }
}

impl Ord for ActionPat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.segments
            .cmp(&other.segments)
            .then_with(|| self.wildcard.cmp(&other.wildcard))
    }
}

impl PartialOrd for ActionPat {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for ActionPat {
    type Err = AstError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Typed resource glob selector (e.g. `repo "feedback-loop-ai/*"`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceSel {
    kind: String,
    pattern: String,
}

impl ResourceSel {
    /// Creates a validated `ResourceSel`.
    pub fn new(kind: impl Into<String>, pattern: impl Into<String>) -> Result<Self, AstError> {
        let sel = Self {
            kind: kind.into(),
            pattern: pattern.into(),
        };
        sel.validate()?;
        Ok(sel)
    }

    /// Validates that `kind` is an identifier and `pattern` contains no control characters.
    pub fn validate(&self) -> Result<(), AstError> {
        if !is_valid_ident(&self.kind) {
            return Err(AstError::InvalidResourceKind(self.kind.clone()));
        }
        validate_quoted_str(&self.pattern, "resource pattern")?;
        Ok(())
    }

    /// Returns the resource kind identifier.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the resource glob pattern.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns true if `resource_id` contains no control characters and matches this selector's glob pattern.
    #[must_use]
    pub fn matches(&self, resource_id: &str) -> bool {
        is_valid_quoted_str(resource_id) && glob_matches(&self.pattern, resource_id)
    }

    /// Returns true if this selector has the same `kind` and subsumes `child`'s glob pattern.
    #[must_use]
    pub fn subsumes(&self, child: &Self) -> bool {
        self.kind == child.kind && glob_subsumes(&self.pattern, &child.pattern)
    }
}

/// Matches a `*`-only glob pattern against a concrete string.
#[must_use]
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Sound and complete containment check for `*`-only globs:
/// returns true iff every string matched by `child` is also matched by `parent`.
#[must_use]
pub fn glob_subsumes(parent: &str, child: &str) -> bool {
    let p_parts = split_glob_collapsed(parent);
    let c_parts = split_glob_collapsed(child);

    if p_parts.len() == 1 {
        return c_parts.len() == 1 && p_parts[0] == c_parts[0];
    }
    if c_parts.len() == 1 {
        return glob_matches(parent, c_parts[0]);
    }

    let Some(c_first_rem) = c_parts[0].strip_prefix(p_parts[0]) else {
        return false;
    };
    let Some(c_last_rem) = c_parts[c_parts.len() - 1].strip_suffix(p_parts[p_parts.len() - 1])
    else {
        return false;
    };

    let middle_parent = &p_parts[1..p_parts.len() - 1];
    if middle_parent.is_empty() {
        return true;
    }

    let mut c_idx = 0usize;
    let mut c_slice = c_first_rem;
    let c_last_idx = c_parts.len() - 1;

    for needle in middle_parent {
        loop {
            if let Some(pos) = c_slice.find(needle) {
                c_slice = &c_slice[pos + needle.len()..];
                break;
            }
            c_idx += 1;
            if c_idx > c_last_idx {
                return false;
            }
            c_slice = if c_idx == c_last_idx {
                c_last_rem
            } else {
                c_parts[c_idx]
            };
        }
    }
    true
}

fn split_glob_collapsed(pattern: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let bytes = pattern.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            parts.push(&pattern[start..i]);
            while i < bytes.len() && bytes[i] == b'*' {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push(&pattern[start..]);
    parts
}
