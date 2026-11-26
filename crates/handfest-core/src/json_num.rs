//! Pure `#![no_std]` canonical JSON integer and lossless base-10 decimal validation.
//!
//! Shared by `handfest-mcp` and `handfest-cli` so wire/CLI numeric parsing never drifts and never
//! routes decimal literals through IEEE-754 `f64`.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;

use crate::ast::{Decimal, MAX_DECIMAL_SCALE};

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
        }
    }
}

impl core::error::Error for NumberError {}

/// Scans one RFC 8259 JSON number token starting at `start` within `bytes`, returning the end byte
/// offset of the scanned token on success.
///
/// Enforces RFC 8259 leading-zero, fractional-digit, and exponent-digit syntax rules.
pub(crate) fn scan_json_number_token(bytes: &[u8], start: usize) -> Result<usize, NumberError> {
    let mut pos = start;
    if bytes.get(pos) == Some(&b'-') {
        pos += 1;
    }
    match bytes.get(pos) {
        Some(&b'0') => {
            pos += 1;
            if matches!(bytes.get(pos), Some(b'0'..=b'9')) {
                return Err(NumberError::LeadingZero);
            }
        }
        Some(b'1'..=b'9') => {
            pos += 1;
            consume_ascii_digits(bytes, &mut pos);
        }
        _ => {
            return Err(NumberError::InvalidSyntax(format!(
                "invalid JSON number at offset {start}"
            )));
        }
    }

    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        if !consume_ascii_digits(bytes, &mut pos) {
            return Err(NumberError::InvalidSyntax(format!(
                "expected fractional digit at offset {pos}"
            )));
        }
    }

    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        if !consume_ascii_digits(bytes, &mut pos) {
            return Err(NumberError::InvalidSyntax(format!(
                "expected exponent digit at offset {pos}"
            )));
        }
    }

    Ok(pos)
}

fn consume_ascii_digits(bytes: &[u8], pos: &mut usize) -> bool {
    let start = *pos;
    while matches!(bytes.get(*pos), Some(b'0'..=b'9')) {
        *pos += 1;
    }
    *pos > start
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
        // Guaranteed `abs_exp <= MAX_DECIMAL_SCALE (28) <= u8::MAX`.
        abs_exp as u8
    };

    let mantissa = signed_from_u128(neg, acc).ok_or(NumberError::DecimalOverflow)?;
    Ok(Decimal::from_valid_parts(mantissa, scale).canonical())
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

    #[test]
    fn decimal_min_max_and_overflow_boundaries_are_exact() {
        let min_int = parse_decimal_str("-170141183460469231731687303715884105728").unwrap();
        assert_eq!(min_int, Decimal::new(i128::MIN, 0).unwrap());
        assert_eq!(min_int.mantissa(), i128::MIN);
        assert_eq!(min_int.scale(), 0);

        let min_scaled = parse_decimal_str("-1701411834604692317316873037158841057.28").unwrap();
        assert_eq!(min_scaled, Decimal::new(i128::MIN, 2).unwrap());
        assert_eq!(min_scaled.mantissa(), i128::MIN);
        assert_eq!(min_scaled.scale(), 2);

        let max_int = parse_decimal_str("170141183460469231731687303715884105727").unwrap();
        assert_eq!(max_int, Decimal::new(i128::MAX, 0).unwrap());

        for overflow in [
            "170141183460469231731687303715884105728",
            "-170141183460469231731687303715884105729",
            "340282366920938463463374607431768211456",
            "1e39",
            "1e40",
        ] {
            assert_eq!(
                parse_json_decimal(overflow),
                Err(NumberError::DecimalOverflow),
                "expected DecimalOverflow for {overflow}"
            );
        }

        assert_eq!(
            parse_json_decimal("1e-29"),
            Err(NumberError::ScaleOverflow {
                scale: 29,
                max: MAX_DECIMAL_SCALE,
            })
        );
    }

    #[test]
    fn malformed_integer_fraction_exponent_and_scanner_branches_fail_closed() {
        for bad_exp in ["1e", "1E", "1e+", "1e-", "1e1a", "1E+1.2", "1e2e3"] {
            assert!(
                matches!(
                    canonicalize_json_number(bad_exp),
                    Err(NumberError::InvalidSyntax(ref msg)) if msg.contains("invalid exponent")
                ),
                "expected invalid exponent syntax error for {bad_exp}"
            );
        }

        for bad_frac in ["1.", "0.", "1.a", "1.2.3", "-1."] {
            assert!(
                matches!(
                    canonicalize_json_number(bad_frac),
                    Err(NumberError::InvalidSyntax(ref msg))
                        if msg.contains("invalid fractional digits")
                ),
                "expected invalid fractional digits error for {bad_frac}"
            );
        }

        for bad_int in ["", "-", ".5", "-.5", "+1", "1a", " 1"] {
            assert!(
                matches!(
                    canonicalize_json_number(bad_int),
                    Err(NumberError::InvalidSyntax(ref msg))
                        if msg.contains("invalid integer digits")
                ),
                "expected invalid integer digits error for {bad_int}"
            );
        }

        // Shared scanner token boundaries
        assert_eq!(scan_json_number_token(b"0,", 0), Ok(1));
        assert_eq!(scan_json_number_token(b"-123.45e+6}", 0), Ok(10));
        assert_eq!(
            scan_json_number_token(b"01", 0),
            Err(NumberError::LeadingZero)
        );
        assert_eq!(
            scan_json_number_token(b"-01", 0),
            Err(NumberError::LeadingZero)
        );
        assert!(matches!(
            scan_json_number_token(b"-", 0),
            Err(NumberError::InvalidSyntax(ref msg)) if msg.contains("invalid JSON number")
        ));
        assert!(matches!(
            scan_json_number_token(b"1.", 0),
            Err(NumberError::InvalidSyntax(ref msg)) if msg.contains("expected fractional digit")
        ));
        assert!(matches!(
            scan_json_number_token(b"1e+", 0),
            Err(NumberError::InvalidSyntax(ref msg)) if msg.contains("expected exponent digit")
        ));
    }
}
