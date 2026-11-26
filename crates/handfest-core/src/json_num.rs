//! Pure `#![no_std]` canonical JSON integer and lossless base-10 decimal validation.
//!
//! Shared by `handfest-mcp` and `handfest-cli` so wire/CLI numeric parsing never drifts and never
//! routes decimal literals through IEEE-754 `f64`.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

use crate::ast::{AstError, Decimal, MAX_DECIMAL_SCALE};

/// Structured error returned by canonical JSON numeric parsing and decimal conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumberError {
    InvalidSyntax(String),
    NegativeZero,
    LeadingZero,
    ExponentOutOfRange(String),
    ExponentOverflow,
    ScaleOverflow { scale: u128, max: u8 },
    DecimalOverflow,
    InvalidDecimal(AstError),
}

impl fmt::Display for NumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSyntax(msg) => f.write_str(msg),
            Self::NegativeZero => f.write_str("negative zero is not permitted"),
            Self::LeadingZero => f.write_str("leading zeros are not permitted"),
            Self::ExponentOutOfRange(exp) => write!(f, "JSON number exponent '{exp}' out of range"),
            Self::ExponentOverflow => f.write_str("JSON number exponent overflow"),
            Self::ScaleOverflow { scale, max } => {
                write!(f, "scale {scale} exceeds maximum {max}")
            }
            Self::DecimalOverflow => f.write_str("decimal overflow"),
            Self::InvalidDecimal(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for NumberError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidDecimal(err) => Some(err),
            _ => None,
        }
    }
}

/// Exact canonical base-10 value of an RFC 8259 JSON numeric literal (`(-1)^neg * sig * 10^exp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonNumber {
    Zero,
    NonZero {
        neg: bool,
        sig_digits: String,
        exp: i128,
    },
}

/// Returns `true` when `raw` matches strict canonical base-10 integer grammar `^(0|-?[1-9][0-9]*)$`.
#[must_use]
pub fn is_canonical_json_int_syntax(raw: &str) -> bool {
    if raw == "0" {
        return true;
    }
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    matches!(digits.as_bytes(), [first @ b'1'..=b'9', rest @ ..] if rest.iter().all(u8::is_ascii_digit))
}

/// Parses a strict canonical base-10 JSON integer (`^(0|-?[1-9][0-9]*)$`) into `i64`.
///
/// Rejects `"-0"`, `"+1"`, leading zeros (`"00"`, `"-01"`), fractional parts, exponents, and
/// values outside `i64::MIN..=i64::MAX`.
#[must_use]
pub fn parse_canonical_json_int(raw: &str) -> Option<i64> {
    if !is_canonical_json_int_syntax(raw) {
        return None;
    }
    raw.parse::<i64>().ok()
}

/// Normalizes a valid RFC 8259 JSON number token for exact numeric equivalence (no `f64`).
///
/// Rejects leading zeros (`"010"`, `"-010"`) and negative zero (`"-0"`, `"-0.0"`, `"-0e5"`).
pub fn canonicalize_json_number(raw: &str) -> Result<CanonicalJsonNumber, NumberError> {
    let (mant_part, exp_str) = split_exponent(raw)?;
    let (neg, unsigned_mant) = match mant_part.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, mant_part),
    };
    let (int_digits, frac_digits) = split_int_frac(raw, unsigned_mant)?;

    let mut digits = String::with_capacity(int_digits.len() + frac_digits.len());
    digits.push_str(int_digits);
    digits.push_str(frac_digits);

    let trimmed_leading = digits.trim_start_matches('0');
    if trimmed_leading.is_empty() {
        if neg {
            return Err(NumberError::NegativeZero);
        }
        return Ok(CanonicalJsonNumber::Zero);
    }

    let exp: i128 = match exp_str {
        Some(s) => s
            .parse()
            .map_err(|_| NumberError::ExponentOutOfRange(s.to_string()))?,
        None => 0,
    };
    let frac_len = i128::try_from(frac_digits.len()).map_err(|_| NumberError::ExponentOverflow)?;
    let sig_digits = trimmed_leading.trim_end_matches('0');
    let trailing_zeros = i128::try_from(trimmed_leading.len() - sig_digits.len())
        .map_err(|_| NumberError::ExponentOverflow)?;
    // Combine `trailing_zeros - frac_len` before adding to `exp` so equivalent spellings such as
    // `1.0e<i128::MIN>` and `1e<i128::MIN>` never suffer spurious intermediate underflow/overflow.
    let exp_delta = trailing_zeros - frac_len;
    let net_exp = exp
        .checked_add(exp_delta)
        .ok_or(NumberError::ExponentOverflow)?;

    Ok(CanonicalJsonNumber::NonZero {
        neg,
        sig_digits: sig_digits.to_string(),
        exp: net_exp,
    })
}

/// Parses a strict canonical base-10 decimal string (`-?(0|[1-9][0-9]*)(\.[0-9]+)?`) without `f64`
/// rounding. Rejects exponents, leading zeros (`"010"`, `"-010"`), and negative zero (`"-0"`,
/// `"-0.0"`, `"-0.00"`).
pub fn parse_decimal_str(raw: &str) -> Result<Decimal, NumberError> {
    if raw.is_empty() {
        return Err(NumberError::InvalidSyntax(
            "empty decimal string".to_string(),
        ));
    }
    if raw.contains(['e', 'E']) {
        return Err(NumberError::InvalidSyntax(format!(
            "exponent not permitted in decimal string '{raw}'"
        )));
    }
    parse_json_decimal(raw)
}

/// Parses a canonical JSON numeric literal (plain or scientific notation) into an exact `Decimal`.
///
/// Rejects leading zeros and negative zero (`-0`, `-0.0`, `-0e5`).
pub fn parse_json_decimal(raw: &str) -> Result<Decimal, NumberError> {
    match canonicalize_json_number(raw)? {
        CanonicalJsonNumber::Zero => Ok(Decimal::ZERO),
        CanonicalJsonNumber::NonZero {
            neg,
            sig_digits,
            exp,
        } => build_decimal(neg, &sig_digits, exp),
    }
}

fn split_exponent(raw: &str) -> Result<(&str, Option<&str>), NumberError> {
    let Some(exp_pos) = raw.find(['e', 'E']) else {
        return Ok((raw, None));
    };
    let (mant, exp_part) = raw.split_at(exp_pos);
    let exp_str = &exp_part[1..];
    let exp_digits = exp_str.strip_prefix(['+', '-']).unwrap_or(exp_str);
    if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NumberError::InvalidSyntax(format!(
            "invalid exponent '{exp_str}'"
        )));
    }
    Ok((mant, Some(exp_str)))
}

fn split_int_frac<'a>(
    raw: &str,
    unsigned_mant: &'a str,
) -> Result<(&'a str, &'a str), NumberError> {
    let (int_digits, frac_digits) = match unsigned_mant.split_once('.') {
        Some((i, f)) => {
            if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(NumberError::InvalidSyntax(format!(
                    "invalid fractional digits in '{raw}'"
                )));
            }
            (i, f)
        }
        None => (unsigned_mant, ""),
    };
    if int_digits.is_empty() || !int_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NumberError::InvalidSyntax(format!(
            "invalid integer digits in '{raw}'"
        )));
    }
    if int_digits.len() > 1 && int_digits.starts_with('0') {
        return Err(NumberError::LeadingZero);
    }
    Ok((int_digits, frac_digits))
}

fn build_decimal(neg: bool, trimmed_digits: &str, net_exp: i128) -> Result<Decimal, NumberError> {
    let mut acc: u128 = 0;
    for b in trimmed_digits.bytes() {
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(u128::from(b - b'0')))
            .ok_or(NumberError::DecimalOverflow)?;
    }

    let scale = if net_exp >= 0 {
        if net_exp > 39 {
            return Err(NumberError::DecimalOverflow);
        }
        for _ in 0..net_exp {
            acc = acc.checked_mul(10).ok_or(NumberError::DecimalOverflow)?;
        }
        0u8
    } else {
        let abs_exp = net_exp.unsigned_abs();
        if abs_exp > u128::from(MAX_DECIMAL_SCALE) {
            return Err(NumberError::ScaleOverflow {
                scale: abs_exp,
                max: MAX_DECIMAL_SCALE,
            });
        }
        u8::try_from(abs_exp).map_err(|_| NumberError::ScaleOverflow {
            scale: abs_exp,
            max: MAX_DECIMAL_SCALE,
        })?
    };

    let mantissa = signed_from_u128(neg, acc).ok_or(NumberError::DecimalOverflow)?;
    Decimal::new(mantissa, scale)
        .map(|d| d.canonical())
        .map_err(NumberError::InvalidDecimal)
}

fn signed_from_u128(neg: bool, abs: u128) -> Option<i128> {
    if !neg {
        i128::try_from(abs).ok()
    } else if abs == (i128::MAX as u128) + 1 {
        Some(i128::MIN)
    } else {
        i128::try_from(abs).ok().map(|v| -v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_int_and_decimal_helpers_reject_negative_zero_and_leading_zeros() {
        assert_eq!(parse_canonical_json_int("0"), Some(0));
        assert_eq!(parse_canonical_json_int("-1"), Some(-1));
        assert_eq!(parse_canonical_json_int("-0"), None);
        assert_eq!(parse_canonical_json_int("01"), None);

        for neg_zero in ["-0", "-0.0", "-0.00", "-0e5", "-0.0e99"] {
            assert_eq!(
                canonicalize_json_number(neg_zero),
                Err(NumberError::NegativeZero),
                "expected NegativeZero for {neg_zero}"
            );
            assert_eq!(
                parse_json_decimal(neg_zero),
                Err(NumberError::NegativeZero),
                "expected NegativeZero decimal for {neg_zero}"
            );
        }
        for neg_zero_str in ["-0", "-0.0", "-0.00"] {
            assert_eq!(
                parse_decimal_str(neg_zero_str),
                Err(NumberError::NegativeZero),
                "expected NegativeZero decimal string for {neg_zero_str}"
            );
        }
        for leading in ["00", "010", "0100", "-010", "00.5", "-00.5"] {
            assert_eq!(
                parse_decimal_str(leading),
                Err(NumberError::LeadingZero),
                "expected LeadingZero for {leading}"
            );
            assert_eq!(
                parse_json_decimal(leading),
                Err(NumberError::LeadingZero),
                "expected LeadingZero json decimal for {leading}"
            );
        }
        assert_eq!(parse_decimal_str("0"), Ok(Decimal::ZERO));
        assert_eq!(parse_decimal_str("0.00"), Ok(Decimal::ZERO));
        assert_eq!(
            parse_decimal_str("10.5"),
            Ok(Decimal::parse("10.5").unwrap())
        );
        assert_eq!(
            parse_decimal_str("-10.5"),
            Ok(Decimal::parse("-10.5").unwrap())
        );
        assert!(matches!(
            parse_decimal_str("1e5"),
            Err(NumberError::InvalidSyntax(_))
        ));
        assert!(matches!(
            parse_decimal_str(""),
            Err(NumberError::InvalidSyntax(_))
        ));
    }
}
