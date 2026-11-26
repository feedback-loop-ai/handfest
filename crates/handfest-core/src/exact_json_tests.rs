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
        Some(&ExactJson::Number("100.000000000000001".to_string()))
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
        .push(ExactJson::Number("3".to_string()));
    assert_eq!(
        mutable.as_object().unwrap().get("arr"),
        Some(&ExactJson::Array(vec![
            ExactJson::Number("1".to_string()),
            ExactJson::Number("2".to_string()),
            ExactJson::Number("3".to_string()),
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
