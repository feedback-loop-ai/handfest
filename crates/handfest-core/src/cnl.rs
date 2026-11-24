//! Deterministic Controlled-English (`HANDFEST v1`) parser and canonical WYSIWYS renderer.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::ast::{
    format_rfc3339_utc, is_valid_field_path, is_valid_ident, parse_rfc3339_utc, ActionPat,
    ActorDecl, AstError, Decimal, HandfestAst, HandfestAstBuilder, KeyId, MandateId, Predicate,
    PredicateOp, Quota, ResourceSel, Scalar,
};
use crate::{ActorKind, MANDATE_VERSION};

/// Error returned when parsing or canonical-validating a `HANDFEST v1` mandate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Syntax { line: usize, message: String },
    Ast { line: usize, error: AstError },
    NonCanonical { expected: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { line, message } => write!(f, "line {line}: {message}"),
            Self::Ast { line, error } => write!(f, "line {line}: {error}"),
            Self::NonCanonical { .. } => {
                f.write_str("mandate text is not in canonical HANDFEST v1 form")
            }
        }
    }
}

impl core::error::Error for ParseError {}

/// Parses a `HANDFEST v1` Controlled-English mandate into a typed `HandfestAst`.
pub fn parse_mandate(input: &str) -> Result<HandfestAst, ParseError> {
    let lines = split_lines(input)?;
    let mut idx = 0usize;

    expect_exact_line(&lines, &mut idx, MANDATE_VERSION)?;

    let parent = parse_optional_parent(&lines, &mut idx)?;
    let from = parse_actor_line(&lines, &mut idx, "FROM")?;
    let to = parse_actor_line(&lines, &mut idx, "TO")?;
    let max_hops = parse_delegation_line(&lines, &mut idx)?;
    let allow = parse_allow_line(&lines, &mut idx)?;
    let on = parse_on_line(&lines, &mut idx)?;
    let where_clauses = parse_optional_where(&lines, &mut idx)?;
    let limits = parse_optional_limits(&lines, &mut idx)?;

    if idx < lines.len() {
        return Err(ParseError::Syntax {
            line: idx + 1,
            message: format!("unexpected trailing content: '{}'", lines[idx]),
        });
    }

    HandfestAstBuilder {
        parent,
        from,
        to,
        max_hops,
        allow,
        on,
        where_clauses,
        limits,
    }
    .build()
    .map_err(|error| ParseError::Ast {
        line: lines.len().max(1),
        error,
    })
}

/// Validates `ast` and renders it into its unique canonical `HANDFEST v1` Controlled-English string.
pub fn try_render_canonical(ast: &HandfestAst) -> Result<String, AstError> {
    ast.validate()?;
    Ok(render_canonical(ast))
}

/// Renders a validated `HandfestAst` into its unique canonical `HANDFEST v1` Controlled-English string.
#[must_use]
pub fn render_canonical(ast: &HandfestAst) -> String {
    let mut canon = ast.clone();
    canon.canonicalize();

    let mut out = String::new();
    let _ = writeln!(out, "{MANDATE_VERSION}");
    if let Some(parent) = canon.parent() {
        let _ = writeln!(out, "PARENT {parent}");
    }
    out.push_str("FROM ");
    write_actor(&mut out, canon.from());
    out.push('\n');

    out.push_str("TO ");
    write_actor(&mut out, canon.to());
    out.push('\n');

    let hop_word = if canon.max_hops() == 1 { "hop" } else { "hops" };
    let _ = writeln!(out, "DELEGATION max {} {hop_word}", canon.max_hops());

    out.push_str("ALLOW ");
    for (i, pat) in canon.allow().iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{pat}");
    }
    out.push('\n');

    out.push_str("ON ");
    for (i, sel) in canon.on().iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(sel.kind());
        out.push(' ');
        write_quoted(&mut out, sel.pattern());
    }
    out.push('\n');

    for (i, pred) in canon.where_clauses().iter().enumerate() {
        out.push_str(if i == 0 { "WHERE " } else { "  AND " });
        write_predicate(&mut out, pred);
        out.push('\n');
    }

    for (i, quota) in canon.limits().iter().enumerate() {
        out.push_str(if i == 0 { "LIMIT " } else { "  AND " });
        write_quota(&mut out, quota);
        out.push('\n');
    }

    out
}

/// Parses a `HANDFEST v1` mandate and rejects any input that is not byte-for-byte canonical.
pub fn parse_canonical(input: &str) -> Result<HandfestAst, ParseError> {
    let mut ast = parse_mandate(input)?;
    ast.canonicalize();
    let expected = render_canonical(&ast);
    if expected != input {
        return Err(ParseError::NonCanonical { expected });
    }
    Ok(ast)
}

/// Writes an escaped double-quoted string literal.
pub(crate) fn write_quoted(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_actor(out: &mut String, actor: &ActorDecl) {
    out.push_str(actor_kind_str(actor.kind()));
    out.push(' ');
    write_quoted(out, actor.name());
    let _ = write!(out, " (key: {}", actor.key());
    for (k, v) in actor.attrs() {
        out.push_str(", ");
        out.push_str(k);
        out.push_str(": ");
        write_scalar(out, v);
    }
    out.push(')');
}

fn actor_kind_str(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Org => "org",
        ActorKind::Agent => "agent",
        ActorKind::Service => "service",
    }
}

fn write_scalar(out: &mut String, scalar: &Scalar) {
    match scalar {
        Scalar::Str(s) => write_quoted(out, s),
        Scalar::Timestamp(ts) => out.push_str(&format_rfc3339_utc(*ts)),
        Scalar::Decimal(d) => {
            let _ = write!(out, "{d}");
        }
        Scalar::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Scalar::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
    }
}

fn write_predicate(out: &mut String, pred: &Predicate) {
    out.push_str(pred.field_path());
    match pred.op() {
        PredicateOp::Eq(v) => {
            out.push_str(" == ");
            write_scalar(out, v);
        }
        PredicateOp::Gte(v) => {
            out.push_str(" >= ");
            write_scalar(out, v);
        }
        PredicateOp::Gt(v) => {
            out.push_str(" > ");
            write_scalar(out, v);
        }
        PredicateOp::Lte(v) => {
            out.push_str(" <= ");
            write_scalar(out, v);
        }
        PredicateOp::Lt(v) => {
            out.push_str(" < ");
            write_scalar(out, v);
        }
        PredicateOp::In(set) => {
            out.push_str(" IN {");
            for (i, item) in set.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_scalar(out, item);
            }
            out.push('}');
        }
        PredicateOp::Prefix(pfx) => {
            out.push_str(" PREFIX ");
            write_quoted(out, pfx);
        }
    }
}

fn write_quota(out: &mut String, quota: &Quota) {
    match quota {
        Quota::Calls(n) => {
            let word = if *n == 1 { "call" } else { "calls" };
            let _ = write!(out, "{n} {word}");
        }
        Quota::Sum { max, unit, field } => {
            let _ = write!(out, "{max} {unit} sum({field})");
        }
    }
}

fn split_lines(input: &str) -> Result<Vec<&str>, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Syntax {
            line: 1,
            message: format!("expected '{MANDATE_VERSION}', found end of input"),
        });
    }
    let Some(trimmed) = input.strip_suffix('\n') else {
        let line = input.bytes().filter(|&b| b == b'\n').count() + 1;
        return Err(ParseError::Syntax {
            line,
            message: "mandate must end with a trailing newline ('\\n')".into(),
        });
    };
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    Ok(trimmed
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect())
}

fn expect_exact_line(lines: &[&str], idx: &mut usize, expected: &str) -> Result<(), ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: format!("expected '{expected}', found end of input"),
        });
    };
    if line.trim_end_matches(' ') != expected {
        return Err(ParseError::Syntax {
            line: line_no,
            message: format!("expected '{expected}', found '{line}'"),
        });
    }
    *idx += 1;
    Ok(())
}

fn parse_optional_parent(lines: &[&str], idx: &mut usize) -> Result<Option<MandateId>, ParseError> {
    let Some(&line) = lines.get(*idx) else {
        return Ok(None);
    };
    let Some(rest) = line.strip_prefix("PARENT ") else {
        return Ok(None);
    };
    let line_no = *idx + 1;
    let digest = MandateId::parse(rest.trim()).map_err(|error| ParseError::Ast {
        line: line_no,
        error,
    })?;
    *idx += 1;
    Ok(Some(digest))
}

fn parse_actor_line(
    lines: &[&str],
    idx: &mut usize,
    keyword: &str,
) -> Result<ActorDecl, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: format!("expected '{keyword}' clause, found end of input"),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str(keyword)?;
    cur.expect_spaces()?;
    let actor = parse_actor_decl(&mut cur)?;
    cur.expect_eol()?;
    *idx += 1;
    Ok(actor)
}

fn parse_actor_decl(cur: &mut Cursor<'_>) -> Result<ActorDecl, ParseError> {
    let kind_tok = cur.take_ident()?;
    let kind = match kind_tok {
        "human" => ActorKind::Human,
        "org" => ActorKind::Org,
        "agent" => ActorKind::Agent,
        "service" => ActorKind::Service,
        other => {
            return Err(cur.syntax(format!("unknown actor kind '{other}'")));
        }
    };
    cur.expect_spaces()?;
    let name = cur.take_quoted()?;
    cur.expect_spaces()?;
    cur.expect_char('(')?;
    cur.skip_spaces();
    cur.expect_str("key:")?;
    cur.expect_spaces()?;
    let key_str = cur.take_while(|b| !b.is_ascii_whitespace() && b != b',' && b != b')');
    let key = KeyId::parse(key_str).map_err(|error| cur.ast(error))?;

    let mut attrs = BTreeMap::new();
    loop {
        cur.skip_spaces();
        if cur.peek() == Some(b')') {
            cur.advance(1);
            break;
        }
        cur.expect_char(',')?;
        cur.skip_spaces();
        let attr_key = cur.take_ident()?;
        if attr_key == "key" {
            return Err(cur.syntax("duplicate reserved attribute 'key'".into()));
        }
        cur.expect_char(':')?;
        cur.expect_spaces()?;
        let val = parse_scalar(cur)?;
        if attrs.insert(attr_key.to_string(), val).is_some() {
            return Err(cur.syntax(format!("duplicate actor attribute '{attr_key}'")));
        }
    }

    ActorDecl::new(kind, name, key, attrs).map_err(|error| cur.ast(error))
}

fn parse_delegation_line(lines: &[&str], idx: &mut usize) -> Result<u32, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: "expected 'DELEGATION max ...' clause".into(),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("DELEGATION")?;
    cur.expect_spaces()?;
    cur.expect_str("max")?;
    cur.expect_spaces()?;
    let hops = cur.take_u32()?;
    cur.expect_spaces()?;
    let unit = cur.take_ident()?;
    if unit != "hop" && unit != "hops" {
        return Err(cur.syntax(format!("expected 'hop' or 'hops', found '{unit}'")));
    }
    cur.expect_eol()?;
    *idx += 1;
    Ok(hops)
}

fn parse_allow_line(lines: &[&str], idx: &mut usize) -> Result<Vec<ActionPat>, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: "expected 'ALLOW' clause".into(),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("ALLOW")?;
    cur.expect_spaces()?;

    let mut actions = Vec::new();
    loop {
        let raw = cur.take_while(|b| !b.is_ascii_whitespace() && b != b',');
        let pat = ActionPat::parse(raw).map_err(|error| cur.ast(error))?;
        actions.push(pat);
        cur.skip_spaces();
        if cur.peek() == Some(b',') {
            cur.advance(1);
            cur.skip_spaces();
            continue;
        }
        break;
    }
    cur.expect_eol()?;
    *idx += 1;
    Ok(actions)
}

fn parse_on_line(lines: &[&str], idx: &mut usize) -> Result<Vec<ResourceSel>, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: "expected 'ON' clause".into(),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("ON")?;
    cur.expect_spaces()?;

    let mut resources = Vec::new();
    loop {
        let kind = cur.take_ident()?;
        cur.expect_spaces()?;
        let pattern = cur.take_quoted()?;
        let sel = ResourceSel::new(kind, pattern).map_err(|error| cur.ast(error))?;
        resources.push(sel);
        cur.skip_spaces();
        if cur.peek() == Some(b',') {
            cur.advance(1);
            cur.skip_spaces();
            continue;
        }
        break;
    }
    cur.expect_eol()?;
    *idx += 1;
    Ok(resources)
}

fn parse_optional_where(lines: &[&str], idx: &mut usize) -> Result<Vec<Predicate>, ParseError> {
    let Some(&first) = lines.get(*idx) else {
        return Ok(Vec::new());
    };
    if !first.starts_with("WHERE ") {
        return Ok(Vec::new());
    }
    let mut preds = Vec::new();
    preds.push(parse_predicate_line(first, *idx + 1, "WHERE")?);
    *idx += 1;

    while let Some(&line) = lines.get(*idx) {
        if !line.trim_start_matches(' ').starts_with("AND ") {
            break;
        }
        preds.push(parse_predicate_line(line, *idx + 1, "AND")?);
        *idx += 1;
    }
    Ok(preds)
}

fn parse_predicate_line(
    line: &str,
    line_no: usize,
    keyword: &str,
) -> Result<Predicate, ParseError> {
    let mut cur = Cursor::new(line, line_no);
    if keyword == "AND" {
        cur.skip_spaces();
    }
    cur.expect_str(keyword)?;
    cur.expect_spaces()?;

    let field_path = cur.take_field_path()?;
    cur.expect_spaces()?;

    let op = if cur.consume_str("==") {
        cur.expect_spaces()?;
        PredicateOp::Eq(parse_scalar(&mut cur)?)
    } else if cur.consume_str(">=") {
        cur.expect_spaces()?;
        PredicateOp::Gte(parse_scalar(&mut cur)?)
    } else if cur.consume_str("<=") {
        cur.expect_spaces()?;
        PredicateOp::Lte(parse_scalar(&mut cur)?)
    } else if cur.consume_str(">") {
        cur.expect_spaces()?;
        PredicateOp::Gt(parse_scalar(&mut cur)?)
    } else if cur.consume_str("<") {
        cur.expect_spaces()?;
        PredicateOp::Lt(parse_scalar(&mut cur)?)
    } else if cur.consume_keyword("IN") {
        cur.expect_spaces()?;
        PredicateOp::In(parse_scalar_set(&mut cur)?)
    } else if cur.consume_keyword("PREFIX") {
        cur.expect_spaces()?;
        PredicateOp::Prefix(cur.take_quoted()?)
    } else {
        return Err(cur.syntax(format!("expected predicate operator after '{field_path}'")));
    };

    cur.expect_eol()?;
    Predicate::new(field_path, op).map_err(|error| cur.ast(error))
}

fn parse_scalar_set(cur: &mut Cursor<'_>) -> Result<BTreeSet<Scalar>, ParseError> {
    cur.expect_char('{')?;
    cur.skip_spaces();
    if cur.peek() == Some(b'}') {
        return Err(cur.syntax("IN set cannot be empty".into()));
    }
    let mut set = BTreeSet::new();
    loop {
        let scalar = parse_scalar(cur)?;
        set.insert(scalar);
        cur.skip_spaces();
        if cur.peek() == Some(b',') {
            cur.advance(1);
            cur.skip_spaces();
            continue;
        }
        cur.expect_char('}')?;
        break;
    }
    Ok(set)
}

fn parse_optional_limits(lines: &[&str], idx: &mut usize) -> Result<Vec<Quota>, ParseError> {
    let Some(&first) = lines.get(*idx) else {
        return Ok(Vec::new());
    };
    if !first.starts_with("LIMIT ") {
        return Ok(Vec::new());
    }
    let mut quotas = Vec::new();
    quotas.push(parse_quota_line(first, *idx + 1, "LIMIT")?);
    *idx += 1;

    while let Some(&line) = lines.get(*idx) {
        if !line.trim_start_matches(' ').starts_with("AND ") {
            break;
        }
        quotas.push(parse_quota_line(line, *idx + 1, "AND")?);
        *idx += 1;
    }
    Ok(quotas)
}

fn parse_quota_line(line: &str, line_no: usize, keyword: &str) -> Result<Quota, ParseError> {
    let mut cur = Cursor::new(line, line_no);
    if keyword == "AND" {
        cur.skip_spaces();
    }
    cur.expect_str(keyword)?;
    cur.expect_spaces()?;

    let num_tok = cur.take_while(|b| b.is_ascii_digit() || b == b'.' || b == b'-');
    if num_tok.is_empty() {
        return Err(cur.syntax("expected numeric quota bound".into()));
    }
    cur.expect_spaces()?;

    let quota = if num_tok.contains('.') {
        let max = Decimal::parse(num_tok).map_err(|error| cur.ast(error))?;
        if max.is_negative() {
            return Err(cur.syntax("sum quota bound must be non-negative".into()));
        }
        let unit = cur.take_ident()?.to_string();
        cur.expect_spaces()?;
        cur.expect_str("sum(")?;
        let field = cur.take_field_path()?.to_string();
        cur.expect_char(')')?;
        Quota::sum(max, unit, field).map_err(|error| cur.ast(error))?
    } else {
        if num_tok.starts_with('-') {
            return Err(cur.syntax("call quota bound must be non-negative".into()));
        }
        let count = num_tok
            .parse::<u64>()
            .map_err(|_| cur.syntax(format!("invalid call quota '{num_tok}'")))?;
        let unit = cur.take_ident()?;
        if unit != "call" && unit != "calls" {
            return Err(cur.syntax(format!("expected 'call' or 'calls', found '{unit}'")));
        }
        Quota::Calls(count)
    };

    cur.expect_eol()?;
    Ok(quota)
}

fn parse_scalar(cur: &mut Cursor<'_>) -> Result<Scalar, ParseError> {
    let Some(first) = cur.peek() else {
        return Err(cur.syntax("expected scalar literal".into()));
    };
    if first == b'"' {
        return Ok(Scalar::Str(cur.take_quoted()?));
    }
    if cur.consume_keyword("true") {
        return Ok(Scalar::Bool(true));
    }
    if cur.consume_keyword("false") {
        return Ok(Scalar::Bool(false));
    }
    let tok = cur.take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b',' | b')' | b'}'));
    if tok.is_empty() {
        return Err(cur.syntax("expected scalar literal".into()));
    }
    if looks_like_timestamp(tok) {
        let ts = parse_rfc3339_utc(tok).map_err(|error| cur.ast(error))?;
        return Ok(Scalar::Timestamp(ts));
    }
    if tok.contains('.') {
        let dec = Decimal::parse(tok).map_err(|error| cur.ast(error))?;
        return Ok(Scalar::Decimal(dec));
    }
    if tok.starts_with('+') {
        return Err(cur.syntax(format!("leading '+' is not allowed in integer '{tok}'")));
    }
    let n = tok
        .parse::<i64>()
        .map_err(|_| cur.syntax(format!("invalid scalar literal '{tok}'")))?;
    Ok(Scalar::Int(n))
}

fn looks_like_timestamp(tok: &str) -> bool {
    let b = tok.as_bytes();
    b.len() >= 5 && b[0..4].iter().all(u8::is_ascii_digit) && b[4] == b'-'
}

struct Cursor<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a str, line: usize) -> Self {
        Self {
            input,
            pos: 0,
            line,
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn syntax(&self, message: String) -> ParseError {
        ParseError::Syntax {
            line: self.line,
            message,
        }
    }

    const fn ast(&self, error: AstError) -> ParseError {
        ParseError::Ast {
            line: self.line,
            error,
        }
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(b' ') {
            self.pos += 1;
        }
    }

    fn expect_spaces(&mut self) -> Result<(), ParseError> {
        let start = self.pos;
        self.skip_spaces();
        if self.pos == start {
            return Err(self.syntax("expected space".into()));
        }
        Ok(())
    }

    fn expect_char(&mut self, expected: char) -> Result<(), ParseError> {
        if self.rest().starts_with(expected) {
            self.pos += expected.len_utf8();
            Ok(())
        } else {
            Err(self.syntax(format!("expected '{expected}'")))
        }
    }

    fn expect_str(&mut self, expected: &str) -> Result<(), ParseError> {
        if self.rest().starts_with(expected) {
            self.pos += expected.len();
            Ok(())
        } else {
            Err(self.syntax(format!("expected '{expected}'")))
        }
    }

    fn consume_str(&mut self, s: &str) -> bool {
        if self.rest().starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    fn consume_keyword(&mut self, kw: &str) -> bool {
        if !self.rest().starts_with(kw) {
            return false;
        }
        let next = self.input.as_bytes().get(self.pos + kw.len()).copied();
        if next.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return false;
        }
        self.pos += kw.len();
        true
    }

    fn take_while(&mut self, pred: impl Fn(u8) -> bool) -> &'a str {
        let start = self.pos;
        let bytes = self.input.as_bytes();
        while self.pos < bytes.len() && pred(bytes[self.pos]) {
            self.pos += 1;
        }
        &self.input[start..self.pos]
    }

    fn take_ident(&mut self) -> Result<&'a str, ParseError> {
        let tok = self.take_while(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !is_valid_ident(tok) {
            return Err(self.ast(AstError::InvalidIdent(tok.to_string())));
        }
        Ok(tok)
    }

    fn take_field_path(&mut self) -> Result<&'a str, ParseError> {
        let tok =
            self.take_while(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
        if !is_valid_field_path(tok) {
            return Err(self.ast(AstError::InvalidFieldPath(tok.to_string())));
        }
        Ok(tok)
    }

    fn take_u32(&mut self) -> Result<u32, ParseError> {
        let tok = self.take_while(|b| b.is_ascii_digit());
        if tok.is_empty() {
            return Err(self.syntax("expected unsigned integer".into()));
        }
        tok.parse::<u32>()
            .map_err(|_| self.syntax(format!("invalid unsigned integer '{tok}'")))
    }

    fn take_quoted(&mut self) -> Result<String, ParseError> {
        self.expect_char('"')?;
        let mut out = String::new();
        let mut chars = self.rest().char_indices();
        while let Some((offset, ch)) = chars.next() {
            match ch {
                '"' => {
                    self.pos += offset + 1;
                    return Ok(out);
                }
                '\\' => {
                    let Some((_, esc)) = chars.next() else {
                        return Err(self.syntax("unterminated escape sequence in string".into()));
                    };
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        other => {
                            return Err(self
                                .syntax(format!("invalid escape sequence '\\{other}' in string")));
                        }
                    }
                }
                c if c.is_control() => {
                    return Err(self.syntax("unescaped control character in string".into()));
                }
                c => out.push(c),
            }
        }
        Err(self.syntax("unterminated quoted string".into()))
    }

    fn expect_eol(&mut self) -> Result<(), ParseError> {
        self.skip_spaces();
        if self.pos < self.input.len() {
            return Err(self.syntax(format!("unexpected trailing text '{}'", self.rest())));
        }
        Ok(())
    }
}
