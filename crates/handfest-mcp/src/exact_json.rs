//! Re-exports of `handfest_core`'s lossless RFC 8259 JSON parser and exact base-10 numeric
//! helpers for `handfest-mcp`.

pub(crate) use handfest_core::exact_json::{write_json_string, ExactJson, JsonNumber};
pub(crate) use handfest_core::json_num::{
    canonicalize_json_number, is_canonical_json_int_syntax, parse_canonical_json_int,
    CanonicalJsonNumber, NumberError,
};
#[cfg(test)]
use handfest_core::json_num::{parse_decimal_str, parse_json_decimal};

/// Returns `true` when `raw` is a canonical JSON integer literal representable as a signed 64-bit integer.
pub(crate) fn is_valid_json_int(raw: &str) -> bool {
    parse_canonical_json_int(raw).is_some()
}

pub(crate) fn parse_exact_json(src: &str) -> Result<ExactJson, String> {
    handfest_core::exact_json::parse_exact_json(src).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use handfest_core::ast::Decimal;

    #[test]
    fn canonical_json_number_compares_losslessly() {
        assert_eq!(
            canonicalize_json_number("1.50").unwrap(),
            canonicalize_json_number("1.5").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("1.50").unwrap(),
            canonicalize_json_number("15e-1").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("0").unwrap(),
            canonicalize_json_number("0.0e99").unwrap()
        );
        for neg_zero in ["-0", "-0.0", "-0.00", "-0e5", "-0.0e99"] {
            assert_eq!(
                canonicalize_json_number(neg_zero),
                Err(NumberError::NegativeZero)
            );
            assert_eq!(parse_json_decimal(neg_zero), Err(NumberError::NegativeZero));
        }
        for bad_str in ["-0", "-0.0", "-0.00"] {
            assert_eq!(parse_decimal_str(bad_str), Err(NumberError::NegativeZero));
        }
        for leading in ["010", "0100", "-010", "00", "00.5"] {
            assert_eq!(parse_decimal_str(leading), Err(NumberError::LeadingZero));
            assert_eq!(parse_json_decimal(leading), Err(NumberError::LeadingZero));
        }
        assert_eq!(
            canonicalize_json_number("18446744073709551617").unwrap(),
            canonicalize_json_number("1.8446744073709551617e19").unwrap()
        );
        assert_ne!(
            canonicalize_json_number("18446744073709551616").unwrap(),
            canonicalize_json_number("18446744073709551617").unwrap()
        );
        assert_ne!(
            canonicalize_json_number("9007199254740992").unwrap(),
            canonicalize_json_number("9007199254740993").unwrap()
        );
        assert_eq!(
            canonicalize_json_number("1e9999999999999999999999999999999999999999"),
            Err(NumberError::ExponentOutOfRange(
                "9999999999999999999999999999999999999999".to_string()
            ))
        );

        let min_exp_one = format!("1e{}", i128::MIN);
        let min_exp_one_dot_zero = format!("1.0e{}", i128::MIN);
        assert_eq!(
            canonicalize_json_number(&min_exp_one_dot_zero),
            canonicalize_json_number(&min_exp_one)
        );
        assert_eq!(
            canonicalize_json_number(&min_exp_one_dot_zero),
            Ok(CanonicalJsonNumber::NonZero {
                neg: false,
                sig_digits: "1".to_string(),
                exp: i128::MIN,
            })
        );

        let max_exp_tenth = format!("0.1e{}", i128::MAX);
        let max_exp_minus_one = format!("1e{}", i128::MAX - 1);
        assert_eq!(
            canonicalize_json_number(&max_exp_tenth),
            canonicalize_json_number(&max_exp_minus_one)
        );

        assert_eq!(
            canonicalize_json_number(&format!("10e{}", i128::MAX)),
            Err(NumberError::ExponentOverflow)
        );
        assert_eq!(
            canonicalize_json_number(&format!("0.1e{}", i128::MIN)),
            Err(NumberError::ExponentOverflow)
        );
        assert_eq!(
            parse_json_decimal("1.500e+2"),
            Ok(Decimal::parse("150.0").unwrap())
        );
        assert_eq!(
            parse_json_decimal(&min_exp_one_dot_zero),
            Err(NumberError::ScaleOverflow {
                scale: i128::MIN.unsigned_abs(),
                max: handfest_core::ast::MAX_DECIMAL_SCALE,
            })
        );
    }

    #[test]
    fn serializer_preserves_numbers_escapes_control_chars_and_supports_deep_nesting() {
        let raw = r#"{"a":100.000000000000001,"b":18446744073709551617,"c":"line\r\n\t\b\f\u0001\"\\","d":[true,false,null]}"#;
        let parsed = parse_exact_json(raw).unwrap();
        let encoded = parsed.to_json_string();
        assert_eq!(encoded, raw);
        assert!(!encoded.contains('\r'));
        assert!(!encoded.contains('\n'));

        let depth_64 = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_exact_json(&depth_64).is_ok());

        let depth_129 = format!("{}1{}", "[".repeat(129), "]".repeat(129));
        assert_eq!(
            parse_exact_json(&depth_129).unwrap_err(),
            "JSON nesting depth exceeded"
        );
    }

    #[test]
    fn parse_canonical_json_int_enforces_strict_grammar_and_rejects_negative_zero() {
        assert_eq!(parse_canonical_json_int("0"), Some(0));
        assert_eq!(parse_canonical_json_int("1"), Some(1));
        assert_eq!(parse_canonical_json_int("-1"), Some(-1));
        assert_eq!(
            parse_canonical_json_int("9223372036854775807"),
            Some(i64::MAX)
        );
        assert_eq!(
            parse_canonical_json_int("-9223372036854775808"),
            Some(i64::MIN)
        );
        assert!(is_valid_json_int("0"));
        assert!(is_valid_json_int("-32601"));

        for invalid in [
            "-0",
            "+0",
            "+1",
            "00",
            "01",
            "-00",
            "-01",
            "1.0",
            "-0.0",
            "1e0",
            "1E0",
            "",
            "-",
            " 1",
            "1 ",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert_eq!(
                parse_canonical_json_int(invalid),
                None,
                "invalid canonical integer '{invalid}' must be rejected"
            );
            assert!(
                !is_valid_json_int(invalid),
                "is_valid_json_int must reject '{invalid}'"
            );
        }
    }
}
