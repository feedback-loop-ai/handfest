//! Canonical receipt escaping and formatting helpers for `handfest-core::gate`.

use alloc::format;
use alloc::string::{String, ToString};

use sha2::Sha256;

use crate::ast::{try_format_rfc3339_utc, Scalar};

pub(crate) fn hash_str(hasher: &mut Sha256, s: &str) {
    use sha2::Digest as _;
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

pub(crate) fn write_escaped_receipt_token(out: &mut String, value: &str) {
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

pub(crate) fn write_escaped_receipt_quoted(out: &mut String, value: &str) {
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

pub(crate) fn format_action(action: &str) -> String {
    let mut out = String::with_capacity(action.len());
    write_escaped_receipt_token(&mut out, action);
    out
}

pub(crate) fn format_resource(kind: &str, id: &str) -> String {
    let mut out = String::with_capacity(kind.len() + id.len() + 3);
    write_escaped_receipt_token(&mut out, kind);
    out.push(' ');
    write_escaped_receipt_quoted(&mut out, id);
    out
}

pub(crate) fn format_fact_scalar(val: &Scalar) -> String {
    match val {
        Scalar::Str(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            write_escaped_receipt_quoted(&mut out, s);
            out
        }
        Scalar::Timestamp(ts) => {
            try_format_rfc3339_utc(*ts).unwrap_or_else(|_| format!("Timestamp({ts})"))
        }
        Scalar::Decimal(d) => format!("{d}"),
        Scalar::Int(n) => format!("{n}"),
        Scalar::Bool(b) => (if *b { "true" } else { "false" }).to_string(),
    }
}
