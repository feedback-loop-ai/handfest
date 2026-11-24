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

use crate::cnl::render_canonical;
use crate::ActorKind;

/// Maximum fractional scale accepted when parsing a decimal literal.
pub const MAX_DECIMAL_SCALE: u8 = 28;

/// Error returned when constructing or parsing typed AST primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstError {
    InvalidMandateId(String),
    InvalidKeyId(String),
    InvalidActionPat(String),
    InvalidResourceKind(String),
    InvalidFieldPath(String),
    InvalidIdent(String),
    InvalidDecimal(String),
    InvalidTimestamp(String),
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
            Self::InvalidDecimal(msg) => write!(f, "invalid decimal: {msg}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid RFC 3339 UTC timestamp: {msg}"),
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

#[must_use]
pub(crate) fn is_valid_key_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'(' | b')' | b'"'))
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
        let scheme = scheme.into();
        let value = value.into();
        if !is_valid_ident(&scheme) {
            return Err(AstError::InvalidKeyId(format!(
                "invalid key scheme '{scheme}'"
            )));
        }
        if !is_valid_key_value(&value) {
            return Err(AstError::InvalidKeyId(format!(
                "invalid key value '{value}'"
            )));
        }
        Ok(Self { scheme, value })
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
    pub kind: ActorKind,
    pub name: String,
    pub key: KeyId,
    pub attrs: BTreeMap<String, Scalar>,
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
    pub kind: String,
    pub pattern: String,
}

impl ResourceSel {
    /// Creates a validated `ResourceSel`.
    pub fn new(kind: impl Into<String>, pattern: impl Into<String>) -> Result<Self, AstError> {
        let kind = kind.into();
        if !is_valid_ident(&kind) {
            return Err(AstError::InvalidResourceKind(kind));
        }
        Ok(Self {
            kind,
            pattern: pattern.into(),
        })
    }

    /// Returns true if `resource_id` matches this selector's glob pattern.
    #[must_use]
    pub fn matches(&self, resource_id: &str) -> bool {
        glob_matches(&self.pattern, resource_id)
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

/// Exact base-10 fixed-point decimal number (`mantissa * 10^-scale`).
#[derive(Debug, Clone, Copy)]
pub struct Decimal {
    pub mantissa: i128,
    pub scale: u8,
}

impl Decimal {
    /// Zero (`0.0`).
    pub const ZERO: Self = Self {
        mantissa: 0,
        scale: 1,
    };

    /// Creates a new `Decimal`.
    #[must_use]
    pub const fn new(mantissa: i128, scale: u8) -> Self {
        Self { mantissa, scale }
    }

    /// Returns true if the decimal value is strictly negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.mantissa < 0
    }

    /// Normalizes trailing fractional zeros down to minimal scale (`scale >= 1` for canonical display).
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

    /// Checked addition returning a canonical decimal on success, or `None` on overflow.
    #[must_use]
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let (m1, s1) = self.minimal_form();
        let (m2, s2) = other.minimal_form();
        let target_scale = s1.max(s2);
        let a = scale_up_i128(m1, target_scale - s1)?;
        let b = scale_up_i128(m2, target_scale - s2)?;
        let sum = a.checked_add(b)?;
        Some(
            Self {
                mantissa: sum,
                scale: target_scale,
            }
            .canonical(),
        )
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
        let mut acc: u128 = 0;
        for b in int_digits.bytes().chain(frac_part.bytes()) {
            acc = acc
                .checked_mul(10)
                .and_then(|v| v.checked_add(u128::from(b - b'0')))
                .ok_or_else(|| AstError::InvalidDecimal("decimal overflow".into()))?;
        }
        let mantissa = if neg {
            if acc == 0 {
                0
            } else if acc == (i128::MAX as u128) + 1 {
                i128::MIN
            } else if acc <= i128::MAX as u128 {
                -(acc as i128)
            } else {
                return Err(AstError::InvalidDecimal("decimal underflow".into()));
            }
        } else {
            i128::try_from(acc).map_err(|_| AstError::InvalidDecimal("decimal overflow".into()))?
        };
        let scale = u8::try_from(frac_part.len())
            .map_err(|_| AstError::InvalidDecimal("decimal scale overflow".into()))?;
        Ok(Self { mantissa, scale })
    }
}

fn scale_up_i128(mut value: i128, steps: u8) -> Option<i128> {
    for _ in 0..steps {
        value = value.checked_mul(10)?;
    }
    Some(value)
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

/// Typed caveat predicate over a dot-separated `field_path`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Predicate {
    pub field_path: String,
    pub op: PredicateOp,
}

impl Predicate {
    /// Constructs an equality predicate (`field == value`).
    #[must_use]
    pub fn eq(field_path: impl Into<String>, value: Scalar) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Eq(value),
        }
    }

    /// Constructs a `>=` predicate.
    #[must_use]
    pub fn gte(field_path: impl Into<String>, value: Scalar) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Gte(value),
        }
    }

    /// Constructs a `>` predicate.
    #[must_use]
    pub fn gt(field_path: impl Into<String>, value: Scalar) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Gt(value),
        }
    }

    /// Constructs a `<=` predicate.
    #[must_use]
    pub fn lte(field_path: impl Into<String>, value: Scalar) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Lte(value),
        }
    }

    /// Constructs a `<` predicate.
    #[must_use]
    pub fn lt(field_path: impl Into<String>, value: Scalar) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Lt(value),
        }
    }

    /// Constructs a set membership predicate (`field IN { ... }`).
    #[must_use]
    pub fn in_set(field_path: impl Into<String>, values: BTreeSet<Scalar>) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::In(values),
        }
    }

    /// Constructs a string prefix predicate (`field PREFIX "..."`).
    #[must_use]
    pub fn prefix(field_path: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            field_path: field_path.into(),
            op: PredicateOp::Prefix(prefix.into()),
        }
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
    fn canonicalize(&mut self) {
        if let Self::Sum { max, .. } = self {
            *max = max.canonical();
        }
    }
}

/// Complete typed `HANDFEST v1` mandate AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandfestAst {
    pub parent: Option<MandateId>,
    pub from: ActorDecl,
    pub to: ActorDecl,
    pub max_hops: u32,
    pub allow: Vec<ActionPat>,
    pub on: Vec<ResourceSel>,
    pub where_clauses: Vec<Predicate>,
    pub limits: Vec<Quota>,
}

impl HandfestAst {
    /// Sorts and deduplicates `allow`, `on`, `where_clauses`, `limits`, and `In` sets deterministically,
    /// and normalizes all `Decimal` values to canonical form.
    pub fn canonicalize(&mut self) {
        for v in self.from.attrs.values_mut() {
            if let Scalar::Decimal(d) = v {
                *d = d.canonical();
            }
        }
        for v in self.to.attrs.values_mut() {
            if let Scalar::Decimal(d) = v {
                *d = d.canonical();
            }
        }
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
