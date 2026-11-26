use alloc::string::ToString;
use alloc::vec;
use core::error::Error as _;

use crate::json_num::NumberError;

use super::*;

#[test]
fn parses_and_serializes_full_rfc8259_values_and_escapes() {
    let raw = r#"{"a":100.000000000000001,"b":18446744073709551617,"c":"line\r\n\t\b\f\u0001\"\\\/","d":[true,false,null],"e":"caf\u00e9 \uD83D\uDE00 日本語"}"#;
    let parsed = parse_exact_json(raw).unwrap();
    let obj = parsed.as_object().unwrap();
    assert_eq!(
        obj.get("a"),
        Some(&ExactJson::Number(
            JsonNumber::parse("100.000000000000001").unwrap()
        ))
    );
    assert_eq!(
        obj.get("c").and_then(ExactJson::as_str),
        Some("line\r\n\t\u{08}\u{0C}\u{01}\"\\/")
    );
    assert_eq!(
        obj.get("e").and_then(ExactJson::as_str),
        Some("café 😀 日本語")
    );

    let roundtrip = parse_exact_json(&parsed.to_json_string()).unwrap();
    assert_eq!(roundtrip, parsed);

    let mut mutable = parse_exact_json(r#"{"arr":[1,2]}"#).unwrap();
    mutable
        .as_object_mut()
        .unwrap()
        .get_mut("arr")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(ExactJson::Number(JsonNumber::parse("3").unwrap()));
    assert_eq!(
        mutable.as_object().unwrap().get("arr"),
        Some(&ExactJson::Array(vec![
            ExactJson::Number(JsonNumber::parse("1").unwrap()),
            ExactJson::Number(JsonNumber::parse("2").unwrap()),
            ExactJson::Number(JsonNumber::parse("3").unwrap()),
        ]))
    );
    assert!(ExactJson::Null.as_object().is_none());
    assert!(ExactJson::Null.as_object_mut().is_none());
    assert!(ExactJson::Null.as_array_mut().is_none());
    assert!(ExactJson::Null.as_str().is_none());
}

#[test]
fn rejects_duplicate_keys_at_all_nesting_levels_including_arrays() {
    for raw in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"k":1,"k":2}}"#,
        r#"{"arr":[{"k":1,"k":2}]}"#,
        r#"[{"x":true,"x":false}]"#,
    ] {
        let err = parse_exact_json(raw).unwrap_err();
        assert!(
            matches!(err, JsonError::DuplicateKey(_)),
            "expected DuplicateKey for {raw}, got {err:?}"
        );
        assert!(err.to_string().contains("duplicate JSON object key"));
    }
}

#[test]
fn rejects_syntax_and_depth_errors() {
    assert_eq!(
        parse_exact_json_with_max_depth("[[1]]", 1),
        Err(JsonError::MaxDepthExceeded)
    );
    assert_eq!(
        parse_exact_json("1 2"),
        Err(JsonError::TrailingCharacters { offset: 2 })
    );
    assert_eq!(
        parse_exact_json("@"),
        Err(JsonError::UnexpectedByte {
            byte: b'@',
            offset: 0
        })
    );
    assert_eq!(parse_exact_json("   "), Err(JsonError::UnexpectedEof));
    assert_eq!(
        parse_exact_json("tru"),
        Err(JsonError::InvalidLiteral { offset: 0 })
    );
    assert_eq!(
        parse_exact_json("{1:2}"),
        Err(JsonError::Expected {
            expected: "string key",
            offset: 1
        })
    );
    assert_eq!(
        parse_exact_json(r#"{"a" 1}"#),
        Err(JsonError::Expected {
            expected: "':'",
            offset: 5
        })
    );
    assert_eq!(
        parse_exact_json(r#"{"a":1 "b":2}"#),
        Err(JsonError::Expected {
            expected: "',' or '}'",
            offset: 7
        })
    );
    assert_eq!(
        parse_exact_json("[1 2]"),
        Err(JsonError::Expected {
            expected: "',' or ']'",
            offset: 3
        })
    );
}

#[test]
fn rejects_string_escape_and_surrogate_errors() {
    assert_eq!(
        parse_exact_json(r#""abc\"#),
        Err(JsonError::UnterminatedEscape)
    );
    assert_eq!(
        parse_exact_json(r#""\u12""#),
        Err(JsonError::UnterminatedEscape)
    );
    assert_eq!(
        parse_exact_json(r#""abc"#),
        Err(JsonError::UnterminatedString)
    );
    assert!(matches!(
        parse_exact_json("\"bad\nnewline\""),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("unescaped control character")
    ));
    assert!(matches!(
        parse_exact_json(r#""\q""#),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("invalid escape")
    ));
    assert!(matches!(
        parse_exact_json(r#""\u123g""#),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("non-hex digit")
    ));
    assert!(matches!(
        parse_exact_json(r#""\uD83D""#),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("lone high surrogate")
    ));
    assert!(matches!(
        parse_exact_json(r#""\uD83D\u0041""#),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("invalid low surrogate")
    ));
    assert!(matches!(
        parse_exact_json(r#""\uDC00""#),
        Err(JsonError::InvalidString(ref msg)) if msg.contains("lone low surrogate")
    ));

    let num_err = parse_exact_json("01").unwrap_err();
    assert_eq!(num_err, JsonError::InvalidNumber(NumberError::LeadingZero));
    assert!(num_err.source().is_some());
    assert!(JsonError::UnexpectedEof.source().is_none());
    for err in [
        JsonError::MaxDepthExceeded,
        JsonError::TrailingCharacters { offset: 1 },
        JsonError::UnexpectedByte {
            byte: b'!',
            offset: 0,
        },
        JsonError::UnexpectedEof,
        JsonError::InvalidLiteral { offset: 0 },
        JsonError::Expected {
            expected: "':'",
            offset: 2,
        },
        JsonError::DuplicateKey("k".to_string()),
        JsonError::UnterminatedEscape,
        JsonError::UnterminatedString,
        JsonError::InvalidString("bad".to_string()),
        JsonError::InvalidNumber(NumberError::LeadingZero),
    ] {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn json_number_validates_tokens_and_serializes_single_line() {
    let valid = JsonNumber::parse("-123.45e+6").unwrap();
    assert_eq!(valid.as_str(), "-123.45e+6");
    assert_eq!(valid.to_string(), "-123.45e+6");
    assert_eq!(ExactJson::Number(valid).to_json_string(), "-123.45e+6");

    let from_i32 = JsonNumber::from(-32603);
    assert_eq!(from_i32.as_str(), "-32603");
    assert_eq!(ExactJson::Number(from_i32).to_json_string(), "-32603");

    for invalid in [
        "",
        " 1",
        "1 ",
        "1\n2",
        "1\r2",
        "1,{\"injected\":true}",
        "01",
        "-",
        "1.",
        "1e+",
        "abc",
    ] {
        let err = JsonNumber::parse(invalid).unwrap_err();
        assert!(
            matches!(
                err,
                NumberError::InvalidSyntax(_) | NumberError::LeadingZero
            ),
            "expected syntax/leading-zero error for {invalid:?}, got {err:?}"
        );
    }
}

#[test]
fn enforces_max_depth_on_empty_containers_at_entry() {
    assert_eq!(
        parse_exact_json_with_max_depth("1", 0),
        Ok(ExactJson::Number(JsonNumber::parse("1").unwrap()))
    );
    assert_eq!(
        parse_exact_json_with_max_depth("[]", 0),
        Err(JsonError::MaxDepthExceeded)
    );
    assert_eq!(
        parse_exact_json_with_max_depth("{}", 0),
        Err(JsonError::MaxDepthExceeded)
    );

    assert!(parse_exact_json_with_max_depth("[]", 1).is_ok());
    assert!(parse_exact_json_with_max_depth("{}", 1).is_ok());
    assert!(parse_exact_json_with_max_depth("[1]", 1).is_ok());
    assert!(parse_exact_json_with_max_depth(r#"{"a":1}"#, 1).is_ok());

    for too_deep in ["[[]]", "[{}]", r#"{"a":[]}"#, r#"{"a":{}}"#, "[[1]]"] {
        assert_eq!(
            parse_exact_json_with_max_depth(too_deep, 1),
            Err(JsonError::MaxDepthExceeded),
            "expected MaxDepthExceeded for {too_deep} with max_depth=1"
        );
    }
}

#[test]
fn reject_unknown_keys_returns_typed_unknown_key_error() {
    fn assert_core_error<E: core::error::Error>(_: &E) {}

    let parsed = parse_exact_json(r#"{"allowed":1,"extra":2}"#).unwrap();
    let obj = parsed.as_object().unwrap();

    assert_eq!(
        reject_unknown_keys(obj, &["allowed", "extra"], "envelope"),
        Ok(())
    );

    let err = reject_unknown_keys(obj, &["allowed"], "envelope").unwrap_err();
    assert_eq!(
        err,
        UnknownKeyError {
            context: "envelope".to_string(),
            key: "extra".to_string(),
        }
    );
    assert_eq!(err.to_string(), "unexpected envelope key 'extra'");
    assert_core_error(&err);
}
