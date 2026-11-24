//! Typed AST, value domain, glob matching/subsumption, and content-addressed digest for `HANDFEST v1`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use sha2::{Digest, Sha256};

use crate::cnl::{render_canonical, try_render_canonical};
use crate::ActorKind;

/// Maximum fractional scale accepted for a `Decimal` value.
pub const MAX_DECIMAL_SCALE: u8 = 28;

/// Minimum RFC 3339 4-digit-year UTC timestamp (`0000-01-01T00:00:00Z`).
pub const MIN_RFC3339_TIMESTAMP: i64 = -62_167_219_200;

/// Maximum RFC 3339 4-digit-year UTC timestamp (`9999-12-31T23:59:59Z`).
pub const MAX_RFC3339_TIMESTAMP: i64 = 253_402_300_799;

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

/// Returns true if `ts` is representable as a 4-digit-year RFC 3339 UTC timestamp
/// (`0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z`).
#[must_use]
pub const fn is_valid_timestamp(ts: i64) -> bool {
    ts >= MIN_RFC3339_TIMESTAMP && ts <= MAX_RFC3339_TIMESTAMP
}

#[must_use]
pub(crate) fn is_valid_key_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'(' | b')' | b'"'))
}

fn validate_quoted_str(value: &str, context: &str) -> Result<(), AstError> {
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

/// Fixed-width big-endian unsigned 256-bit integer for exact `Decimal` addition.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256([u64; 4]);

impl U256 {
    const fn from_u128(v: u128) -> Self {
        Self([0, 0, (v >> 64) as u64, v as u64])
    }

    const fn to_u128(self) -> Option<u128> {
        if self.0[0] == 0 && self.0[1] == 0 {
            Some(((self.0[2] as u128) << 64) | (self.0[3] as u128))
        } else {
            None
        }
    }

    fn mul_pow10(mut self, steps: u8) -> Self {
        for _ in 0..steps {
            let mut carry = 0u128;
            for limb in self.0.iter_mut().rev() {
                let prod = u128::from(*limb) * 10 + carry;
                *limb = prod as u64;
                carry = prod >> 64;
            }
        }
        self
    }

    fn div_rem_10(self) -> (Self, u8) {
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for (i, &limb) in self.0.iter().enumerate() {
            let cur = (rem << 64) | u128::from(limb);
            out[i] = (cur / 10) as u64;
            rem = cur % 10;
        }
        (Self(out), rem as u8)
    }

    fn add(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in (0..4).rev() {
            let sum = u128::from(self.0[i]) + u128::from(rhs.0[i]) + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        Self(out)
    }

    fn sub(self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = 0u128;
        for i in (0..4).rev() {
            let lhs = u128::from(self.0[i]);
            let sub = u128::from(rhs.0[i]) + borrow;
            if lhs >= sub {
                out[i] = (lhs - sub) as u64;
                borrow = 0;
            } else {
                out[i] = ((1u128 << 64) + lhs - sub) as u64;
                borrow = 1;
            }
        }
        Self(out)
    }
}

fn signed_from_u128(neg: bool, abs: u128) -> Option<i128> {
    if abs == 0 {
        return Some(0);
    }
    if neg {
        if abs == (i128::MAX as u128) + 1 {
            Some(i128::MIN)
        } else if abs <= i128::MAX as u128 {
            Some(-(abs as i128))
        } else {
            None
        }
    } else {
        i128::try_from(abs).ok()
    }
}

/// Exact base-10 fixed-point decimal number (`mantissa * 10^-scale`, `scale <= MAX_DECIMAL_SCALE`).
#[derive(Debug, Clone, Copy)]
pub struct Decimal {
    mantissa: i128,
    scale: u8,
}

impl Decimal {
    /// Zero (`0.0`).
    pub const ZERO: Self = Self {
        mantissa: 0,
        scale: 1,
    };

    /// Minimum representable `Decimal` (`i128::MIN * 10^0`).
    pub(crate) const MIN: Self = Self {
        mantissa: i128::MIN,
        scale: 0,
    };

    /// Maximum representable `Decimal` (`i128::MAX * 10^0`).
    pub(crate) const MAX: Self = Self {
        mantissa: i128::MAX,
        scale: 0,
    };

    /// Creates a validated `Decimal`, rejecting `scale > MAX_DECIMAL_SCALE`.
    pub fn new(mantissa: i128, scale: u8) -> Result<Self, AstError> {
        let dec = Self { mantissa, scale };
        dec.validate()?;
        Ok(dec)
    }

    /// Validates that `scale <= MAX_DECIMAL_SCALE`.
    pub fn validate(&self) -> Result<(), AstError> {
        if self.scale > MAX_DECIMAL_SCALE {
            return Err(AstError::InvalidDecimal(format!(
                "scale {} exceeds maximum {}",
                self.scale, MAX_DECIMAL_SCALE
            )));
        }
        Ok(())
    }

    /// Returns the signed base-10 mantissa.
    #[must_use]
    pub const fn mantissa(&self) -> i128 {
        self.mantissa
    }

    /// Returns the fractional scale (`0..=MAX_DECIMAL_SCALE`).
    #[must_use]
    pub const fn scale(&self) -> u8 {
        self.scale
    }

    /// Returns true if the decimal value is strictly negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.mantissa < 0
    }

    /// Normalizes trailing fractional zeros down to minimal scale (`scale >= 1` when representable).
    #[must_use]
    pub fn canonical(&self) -> Self {
        if self.mantissa == 0 {
            return Self::ZERO;
        }
        let mut m = self.mantissa;
        let mut s = self.scale;
        while s > 1 && m % 10 == 0 {
            m /= 10;
            s -= 1;
        }
        if s == 0 {
            if let Some(scaled) = m.checked_mul(10) {
                return Self {
                    mantissa: scaled,
                    scale: 1,
                };
            }
        }
        Self {
            mantissa: m,
            scale: s,
        }
    }

    fn minimal_form(&self) -> (i128, u8) {
        if self.mantissa == 0 {
            return (0, 0);
        }
        let mut m = self.mantissa;
        let mut s = self.scale;
        while s > 0 && m % 10 == 0 {
            m /= 10;
            s -= 1;
        }
        (m, s)
    }

    /// Returns the smallest representable `Decimal` strictly greater than `self`,
    /// or `None` if `self == Self::MAX` (or has an invalid scale).
    #[must_use]
    pub(crate) fn next_up(&self) -> Option<Self> {
        if self.scale > MAX_DECIMAL_SCALE {
            return None;
        }
        let (m0, s0) = self.minimal_form();
        let mut best: Option<Self> = None;
        for s in 0..=MAX_DECIMAL_SCALE {
            let cand_m = if s >= s0 {
                let p = 10_i128.pow(u32::from(s - s0));
                match m0.checked_mul(p) {
                    Some(prod) => prod.checked_add(1),
                    None if m0 < 0 => Some(i128::MIN),
                    None => None,
                }
            } else {
                let p = 10_i128.pow(u32::from(s0 - s));
                Some(m0.div_euclid(p) + 1)
            };
            if let Some(m) = cand_m {
                let cand = Self {
                    mantissa: m,
                    scale: s,
                }
                .canonical();
                if best.is_none_or(|cur| cand < cur) {
                    best = Some(cand);
                }
            }
        }
        best
    }

    /// Returns the largest representable `Decimal` strictly less than `self`,
    /// or `None` if `self == Self::MIN` (or has an invalid scale).
    #[must_use]
    pub(crate) fn next_down(&self) -> Option<Self> {
        if self.scale > MAX_DECIMAL_SCALE {
            return None;
        }
        let (m0, s0) = self.minimal_form();
        let mut best: Option<Self> = None;
        for s in 0..=MAX_DECIMAL_SCALE {
            let cand_m = if s >= s0 {
                let p = 10_i128.pow(u32::from(s - s0));
                match m0.checked_mul(p) {
                    Some(prod) => prod.checked_sub(1),
                    None if m0 > 0 => Some(i128::MAX),
                    None => None,
                }
            } else {
                let p = 10_i128.pow(u32::from(s0 - s));
                let q = m0.div_euclid(p);
                let r = m0.rem_euclid(p);
                Some(if r == 0 { q - 1 } else { q })
            };
            if let Some(m) = cand_m {
                let cand = Self {
                    mantissa: m,
                    scale: s,
                }
                .canonical();
                if best.is_none_or(|cur| cand > cur) {
                    best = Some(cand);
                }
            }
        }
        best
    }

    /// Checked addition returning a canonical decimal on success, or `None` on overflow.
    #[must_use]
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.scale > MAX_DECIMAL_SCALE || other.scale > MAX_DECIMAL_SCALE {
            return None;
        }
        let (m1, s1) = self.minimal_form();
        let (m2, s2) = other.minimal_form();
        let mut scale = s1.max(s2);
        let a = U256::from_u128(m1.unsigned_abs()).mul_pow10(scale - s1);
        let b = U256::from_u128(m2.unsigned_abs()).mul_pow10(scale - s2);
        let neg1 = m1 < 0;
        let neg2 = m2 < 0;

        let (neg, mut mag) = if neg1 == neg2 {
            (neg1, a.add(b))
        } else {
            match a.cmp(&b) {
                Ordering::Equal => return Some(Self::ZERO),
                Ordering::Greater => (neg1, a.sub(b)),
                Ordering::Less => (neg2, b.sub(a)),
            }
        };

        while scale > 0 {
            let (q, r) = mag.div_rem_10();
            if r != 0 {
                break;
            }
            mag = q;
            scale -= 1;
        }

        let abs = mag.to_u128()?;
        let mantissa = signed_from_u128(neg, abs)?;
        Some(Self { mantissa, scale }.canonical())
    }

    /// Parses a decimal literal (`-?[0-9]+\.[0-9]+`).
    pub fn parse(input: &str) -> Result<Self, AstError> {
        let Some((int_part, frac_part)) = input.split_once('.') else {
            return Err(AstError::InvalidDecimal(format!(
                "missing decimal point in '{input}'"
            )));
        };
        if frac_part.is_empty() || frac_part.len() > usize::from(MAX_DECIMAL_SCALE) {
            return Err(AstError::InvalidDecimal(format!(
                "invalid fractional part in '{input}'"
            )));
        }
        let (neg, int_digits) = match int_part.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, int_part),
        };
        if int_digits.is_empty()
            || !int_digits.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(AstError::InvalidDecimal(format!(
                "invalid digits in '{input}'"
            )));
        }
        let trimmed_frac = frac_part.trim_end_matches('0');
        let mut acc: u128 = 0;
        for b in int_digits.bytes().chain(trimmed_frac.bytes()) {
            acc = acc
                .checked_mul(10)
                .and_then(|v| v.checked_add(u128::from(b - b'0')))
                .ok_or_else(|| AstError::InvalidDecimal("decimal overflow".into()))?;
        }
        let mantissa = signed_from_u128(neg, acc).ok_or_else(|| {
            AstError::InvalidDecimal(if neg {
                "decimal underflow".into()
            } else {
                "decimal overflow".into()
            })
        })?;
        let scale = u8::try_from(trimmed_frac.len())
            .map_err(|_| AstError::InvalidDecimal("decimal scale overflow".into()))?;
        Ok(Self { mantissa, scale }.canonical())
    }
}

fn decimal_digits_u128(mut v: u128) -> u8 {
    let mut digits = 1u8;
    while v >= 10 {
        v /= 10;
        digits += 1;
    }
    digits
}

fn pow10_u128(exp: u8) -> Option<u128> {
    10u128.checked_pow(u32::from(exp))
}

fn cmp_pos_minimal(m1: u128, s1: u8, m2: u128, s2: u8) -> Ordering {
    let d1 = i32::from(decimal_digits_u128(m1)) - i32::from(s1);
    let d2 = i32::from(decimal_digits_u128(m2)) - i32::from(s2);
    if d1 != d2 {
        return d1.cmp(&d2);
    }
    let (int1, frac1) = split_int_frac(m1, s1);
    let (int2, frac2) = split_int_frac(m2, s2);
    if int1 != int2 {
        return int1.cmp(&int2);
    }
    cmp_fractional(frac1, s1, frac2, s2)
}

fn split_int_frac(m: u128, s: u8) -> (u128, u128) {
    if s == 0 {
        (m, 0)
    } else if let Some(div) = pow10_u128(s) {
        (m / div, m % div)
    } else {
        (0, m)
    }
}

fn cmp_fractional(f1: u128, s1: u8, f2: u128, s2: u8) -> Ordering {
    if f1 == 0 && f2 == 0 {
        return Ordering::Equal;
    }
    if f1 == 0 {
        return Ordering::Less;
    }
    if f2 == 0 {
        return Ordering::Greater;
    }
    let lead1 = i32::from(s1) - i32::from(decimal_digits_u128(f1));
    let lead2 = i32::from(s2) - i32::from(decimal_digits_u128(f2));
    if lead1 != lead2 {
        return lead2.cmp(&lead1);
    }
    let a = format!("{f1}");
    let b = format!("{f2}");
    a.as_bytes().cmp(b.as_bytes())
}

impl PartialEq for Decimal {
    fn eq(&self, other: &Self) -> bool {
        self.minimal_form() == other.minimal_form()
    }
}

impl Eq for Decimal {}

impl Hash for Decimal {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.minimal_form().hash(state);
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        let (m1, s1) = self.minimal_form();
        let (m2, s2) = other.minimal_form();
        match (m1.cmp(&0), m2.cmp(&0)) {
            (Ordering::Equal, Ordering::Equal) => Ordering::Equal,
            (Ordering::Less, Ordering::Equal | Ordering::Greater)
            | (Ordering::Equal, Ordering::Greater) => Ordering::Less,
            (Ordering::Greater, Ordering::Equal | Ordering::Less)
            | (Ordering::Equal, Ordering::Less) => Ordering::Greater,
            (Ordering::Greater, Ordering::Greater) => {
                cmp_pos_minimal(m1.unsigned_abs(), s1, m2.unsigned_abs(), s2)
            }
            (Ordering::Less, Ordering::Less) => {
                cmp_pos_minimal(m2.unsigned_abs(), s2, m1.unsigned_abs(), s1)
            }
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (m, s) = self.minimal_form();
        if m == 0 {
            return f.write_str("0.0");
        }
        if m < 0 {
            f.write_str("-")?;
        }
        let abs = m.unsigned_abs();
        if s == 0 {
            return write!(f, "{abs}.0");
        }
        let digits = format!("{abs}");
        let scale = usize::from(s);
        if digits.len() <= scale {
            f.write_str("0.")?;
            for _ in 0..(scale - digits.len()) {
                f.write_str("0")?;
            }
            f.write_str(&digits)
        } else {
            let split = digits.len() - scale;
            write!(f, "{}.{}", &digits[..split], &digits[split..])
        }
    }
}

impl FromStr for Decimal {
    type Err = AstError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

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

/// Parses a strict RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) into Unix epoch seconds.
pub fn parse_rfc3339_utc(input: &str) -> Result<i64, AstError> {
    let b = input.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(AstError::InvalidTimestamp(input.to_string()));
    }
    let year = parse_u32_digits(&input[0..4])?;
    let month = parse_u32_digits(&input[5..7])?;
    let day = parse_u32_digits(&input[8..10])?;
    let hour = parse_u32_digits(&input[11..13])?;
    let minute = parse_u32_digits(&input[14..16])?;
    let second = parse_u32_digits(&input[17..19])?;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(AstError::InvalidTimestamp(input.to_string()));
    }

    let days = days_from_civil(i64::from(year), month, day);
    Ok(days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
}

/// Formats Unix epoch seconds into strict 4-digit-year RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`),
/// rejecting timestamps outside `0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z`.
pub fn try_format_rfc3339_utc(ts: i64) -> Result<String, AstError> {
    if !is_valid_timestamp(ts) {
        return Err(AstError::InvalidTimestamp(format!(
            "timestamp {ts} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
        )));
    }
    Ok(format_rfc3339_utc(ts))
}

/// Formats Unix epoch seconds into strict RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
#[must_use]
pub fn format_rfc3339_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn parse_u32_digits(s: &str) -> Result<u32, AstError> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AstError::InvalidTimestamp(s.to_string()));
    }
    s.parse::<u32>()
        .map_err(|_| AstError::InvalidTimestamp(s.to_string()))
}

const fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}
