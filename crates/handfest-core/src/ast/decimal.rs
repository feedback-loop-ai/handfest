//! Exact base-10 arbitrary-precision `Decimal` value type (`i128` mantissa, scale `0..=28`).

use alloc::format;
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use super::AstError;

/// Maximum fractional scale accepted for a `Decimal` value.
pub const MAX_DECIMAL_SCALE: u8 = 28;

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

    pub(crate) const fn from_valid_parts(mantissa: i128, scale: u8) -> Self {
        debug_assert!(scale <= MAX_DECIMAL_SCALE);
        Self { mantissa, scale }
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

    /// Maps a validated `Decimal` to its unique contiguous scale-band ordinal (`0..=56`) and
    /// integer coordinate within that band, in strictly increasing numeric order.
    fn band_coord(&self) -> (u8, i128) {
        let (m0, s0) = self.minimal_form();
        let max_pow = 10_i128.pow(u32::from(MAX_DECIMAL_SCALE - s0));
        if let Some(m) = m0.checked_mul(max_pow) {
            return (MAX_DECIMAL_SCALE, m);
        }
        for s in (s0..MAX_DECIMAL_SCALE).rev() {
            let pow = 10_i128.pow(u32::from(s - s0));
            if let Some(m) = m0.checked_mul(pow) {
                return if m < 0 {
                    (s, m)
                } else {
                    (2 * MAX_DECIMAL_SCALE - s, m)
                };
            }
        }
        // Unreachable because s == s0 has pow == 1 and m0.checked_mul(1) == Some(m0).
        if m0 < 0 {
            (s0, m0)
        } else {
            (2 * MAX_DECIMAL_SCALE - s0, m0)
        }
    }

    const fn band_bounds(band: u8) -> (i128, i128) {
        if band < MAX_DECIMAL_SCALE {
            (i128::MIN, i128::MIN / 10 - 1)
        } else if band == MAX_DECIMAL_SCALE {
            (i128::MIN, i128::MAX)
        } else {
            (i128::MAX / 10 + 1, i128::MAX)
        }
    }

    /// Returns the exact number of representable `Decimal` inhabitants in `self..=hi`,
    /// or `None` if either endpoint has an invalid scale or the count overflows `u128`.
    #[must_use]
    pub(crate) fn discrete_count_to(&self, hi: &Self) -> Option<u128> {
        if self.scale > MAX_DECIMAL_SCALE || hi.scale > MAX_DECIMAL_SCALE {
            return None;
        }
        if self > hi {
            return Some(0);
        }
        let (b_lo, m_lo) = self.band_coord();
        let (b_hi, m_hi) = hi.band_coord();
        if b_lo == b_hi {
            m_hi.abs_diff(m_lo).checked_add(1)
        } else if b_hi == b_lo + 1 {
            let (_, lo_band_max) = Self::band_bounds(b_lo);
            let (hi_band_min, _) = Self::band_bounds(b_hi);
            let left = lo_band_max.abs_diff(m_lo).checked_add(1)?;
            let right = m_hi.abs_diff(hi_band_min).checked_add(1)?;
            left.checked_add(right)
        } else {
            None
        }
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
