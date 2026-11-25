//! Internal encoding/decoding helpers for SQLite receipt rows and `TrackRecord` serde.

use handfest_core::ast::MandateId;
use handfest_core::Verdict;

use crate::LedgerError;

pub(crate) mod key_id_serde {
    use handfest_core::ast::KeyId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(key: &KeyId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&key.to_string())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<KeyId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        KeyId::parse(&raw).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn parse_optional_mandate_id(
    seq: i64,
    column: &str,
    raw: Option<String>,
) -> Result<Option<MandateId>, LedgerError> {
    match raw {
        None => Ok(None),
        Some(s) => MandateId::parse(&s)
            .map(Some)
            .map_err(|err| LedgerError::Integrity(format!("seq {seq}: invalid {column}: {err}"))),
    }
}

pub(crate) fn parse_chain_ids_json(seq: i64, raw: &str) -> Result<Vec<MandateId>, LedgerError> {
    let items: Vec<String> = serde_json::from_str(raw).map_err(|err| {
        LedgerError::Integrity(format!("seq {seq}: invalid chain_ids_json: {err}"))
    })?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mid = MandateId::parse(&item).map_err(|err| {
            LedgerError::Integrity(format!(
                "seq {seq}: invalid mandate id in chain_ids_json: {err}"
            ))
        })?;
        out.push(mid);
    }
    Ok(out)
}

pub(crate) fn parse_verdict(
    seq: i64,
    verdict_raw: &str,
    deny_reason: Option<String>,
) -> Result<Verdict, LedgerError> {
    match (verdict_raw, deny_reason) {
        ("permit", None) => Ok(Verdict::Permit),
        ("deny", Some(reason)) => Ok(Verdict::Deny { reason }),
        ("permit", Some(_)) => Err(LedgerError::Integrity(format!(
            "seq {seq}: permit receipt unexpectedly contains deny_reason"
        ))),
        ("deny", None) => Err(LedgerError::Integrity(format!(
            "seq {seq}: deny receipt missing deny_reason"
        ))),
        (other, _) => Err(LedgerError::Integrity(format!(
            "seq {seq}: unknown verdict '{other}'"
        ))),
    }
}

/// Reconstructs the exact `DecisionReceipt::resource` encoding used by `handfest_core::gate`.
pub(crate) fn format_resource(kind: &str, id: &str) -> String {
    let mut out = String::with_capacity(kind.len() + id.len() + 3);
    write_escaped_receipt_token(&mut out, kind);
    out.push(' ');
    write_escaped_receipt_quoted(&mut out, id);
    out
}

fn write_escaped_receipt_token(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                for esc in c.escape_default() {
                    out.push(esc);
                }
            }
            c => out.push(c),
        }
    }
}

fn write_escaped_receipt_quoted(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                for esc in c.escape_default() {
                    out.push(esc);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_optional_mandate_id_handles_none_valid_and_invalid() {
        assert_eq!(parse_optional_mandate_id(1, "prev", None).unwrap(), None);
        let valid = MandateId::sha256(b"test");
        assert_eq!(
            parse_optional_mandate_id(1, "prev", Some(valid.to_string())).unwrap(),
            Some(valid)
        );
        assert!(matches!(
            parse_optional_mandate_id(1, "prev", Some("bad".to_string())),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn parse_chain_ids_json_rejects_malformed_json_and_bad_mandate_id() {
        assert!(matches!(
            parse_chain_ids_json(1, "not-json"),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            parse_chain_ids_json(1, r#"["not-a-mandate"]"#),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn parse_verdict_rejects_inconsistent_and_unknown_values() {
        assert_eq!(parse_verdict(1, "permit", None).unwrap(), Verdict::Permit);
        assert_eq!(
            parse_verdict(1, "deny", Some("no".to_string())).unwrap(),
            Verdict::Deny {
                reason: "no".to_string()
            }
        );
        assert!(matches!(
            parse_verdict(1, "permit", Some("extra".to_string())),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            parse_verdict(1, "deny", None),
            Err(LedgerError::Integrity(_))
        ));
        assert!(matches!(
            parse_verdict(1, "maybe", None),
            Err(LedgerError::Integrity(_))
        ));
    }

    #[test]
    fn format_resource_escapes_backslashes_quotes_and_control_chars() {
        let formatted = format_resource("repo\\k\n\x07", "a\\b\"c\t");
        assert_eq!(formatted, "repo\\\\k\\n\\u{7} \"a\\\\b\\\"c\\t\"");
    }
}
