//! Canonical WYSIWYS `HANDFEST REVOKE v1` AST, parser/renderer, and pure chain revocation evaluator.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt::{self, Write};
use core::str::FromStr;

use crate::ast::{
    fmt_sha256_digest, format_rfc3339_utc, is_valid_timestamp, parse_rfc3339_utc,
    parse_sha256_digest, sha256_bytes, validate_quoted_str, ActorDecl, AstError, KeyId, MandateId,
};
use crate::cnl::{
    expect_exact_line, parse_actor_line, split_lines_with_header, write_actor, write_quoted,
    Cursor, ParseError,
};
use crate::gate::{validate_proof_shape, ProofShapeError, VerifiedAnchorProof, VerifiedMandate};
use crate::{ActorKind, REVOCATION_VERSION};

/// Content-addressed SHA-256 digest of canonical `HANDFEST REVOKE v1` text (`sha256:<64-lowercase-hex>`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevocationId(pub [u8; 32]);

impl RevocationId {
    /// Computes the SHA-256 digest of arbitrary bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(sha256_bytes(bytes))
    }

    /// Returns the raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses a strict `sha256:<64-lowercase-hex>` digest string.
    pub fn parse(input: &str) -> Result<Self, AstError> {
        parse_sha256_digest(input)
            .map(Self)
            .map_err(AstError::InvalidRevocationId)
    }
}

impl fmt::Display for RevocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_sha256_digest(&self.0, f)
    }
}

impl fmt::Debug for RevocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RevocationId(\"{self}\")")
    }
}

impl FromStr for RevocationId {
    type Err = AstError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Target of a `HANDFEST REVOKE v1` statement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RevocationTarget {
    /// Revokes a specific mandate (and transitively all sub-mandates attenuated from it).
    Mandate(MandateId),
    /// Emergency kill-switch revoking a compromised actor key across any chain containing it.
    Key(KeyId),
}

impl RevocationTarget {
    /// Validates lexical invariants of this revocation target.
    pub fn validate(&self) -> Result<(), AstError> {
        match self {
            Self::Mandate(_) => Ok(()),
            Self::Key(key) => key.validate(),
        }
    }
}

impl fmt::Display for RevocationTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mandate(id) => write!(f, "mandate {id}"),
            Self::Key(key) => write!(f, "key {key}"),
        }
    }
}

/// Complete typed, validated `HANDFEST REVOKE v1` revocation AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationAst {
    by: ActorDecl,
    target: RevocationTarget,
    effective_at: i64,
    reason: Option<String>,
}

impl RevocationAst {
    /// Validates all invariants, canonicalizes actor attributes, and constructs a [`RevocationAst`].
    pub fn new(
        mut by: ActorDecl,
        target: RevocationTarget,
        effective_at: i64,
        reason: Option<String>,
    ) -> Result<Self, AstError> {
        by.canonicalize();
        let ast = Self {
            by,
            target,
            effective_at,
            reason,
        };
        ast.validate()?;
        Ok(ast)
    }

    /// Validates every lexical, structural, and timestamp invariant required for canonical bijection.
    pub fn validate(&self) -> Result<(), AstError> {
        self.by.validate()?;
        self.target.validate()?;
        if !is_valid_timestamp(self.effective_at) {
            return Err(AstError::InvalidTimestamp(format!(
                "timestamp {} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z",
                self.effective_at
            )));
        }
        if let Some(reason) = &self.reason {
            if reason.is_empty() {
                return Err(AstError::InvalidString(
                    "revocation reason must not be empty".to_string(),
                ));
            }
            validate_quoted_str(reason, "revocation reason")?;
        }
        Ok(())
    }

    /// Returns the revoking principal (`BY` clause).
    #[must_use]
    pub const fn by(&self) -> &ActorDecl {
        &self.by
    }

    /// Returns the revocation target (`TARGET` clause).
    #[must_use]
    pub const fn target(&self) -> &RevocationTarget {
        &self.target
    }

    /// Returns the effective UTC Unix timestamp (`EFFECTIVE` clause).
    #[must_use]
    pub const fn effective_at(&self) -> i64 {
        self.effective_at
    }

    /// Returns the optional human-readable reason (`REASON` clause).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Validates the AST and computes its content-addressed [`RevocationId`].
    pub fn try_revocation_id(&self) -> Result<RevocationId, AstError> {
        let canonical = try_render_canonical_revocation(self)?;
        Ok(RevocationId::sha256(canonical.as_bytes()))
    }

    /// Computes the content-addressed [`RevocationId`] (`sha256` of `render_canonical_revocation(self)`).
    #[must_use]
    pub fn revocation_id(&self) -> RevocationId {
        let canonical = render_canonical_revocation(self);
        RevocationId::sha256(canonical.as_bytes())
    }
}

/// Parses a `HANDFEST REVOKE v1` Controlled-English revocation into a typed [`RevocationAst`].
pub fn parse_revocation(input: &str) -> Result<RevocationAst, ParseError> {
    let lines = split_lines_with_header(input, REVOCATION_VERSION, "revocation")?;
    let mut idx = 0usize;

    expect_exact_line(&lines, &mut idx, REVOCATION_VERSION)?;
    let by = parse_actor_line(&lines, &mut idx, "BY")?;
    let target = parse_target_line(&lines, &mut idx)?;
    let effective_at = parse_effective_line(&lines, &mut idx)?;
    let reason = parse_optional_reason_line(&lines, &mut idx)?;

    if idx < lines.len() {
        return Err(ParseError::Syntax {
            line: idx + 1,
            message: format!("unexpected trailing content: '{}'", lines[idx]),
        });
    }

    RevocationAst::new(by, target, effective_at, reason).map_err(|error| ParseError::Ast {
        line: lines.len().max(1),
        error,
    })
}

/// Validates `ast` and renders it into its unique canonical `HANDFEST REVOKE v1` string.
pub fn try_render_canonical_revocation(ast: &RevocationAst) -> Result<String, AstError> {
    ast.validate()?;
    Ok(render_canonical_revocation(ast))
}

/// Renders a validated [`RevocationAst`] into its unique canonical `HANDFEST REVOKE v1` string.
#[must_use]
pub fn render_canonical_revocation(ast: &RevocationAst) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{REVOCATION_VERSION}");
    out.push_str("BY ");
    write_actor(&mut out, ast.by());
    out.push('\n');

    let _ = writeln!(out, "TARGET {}", ast.target());
    let _ = writeln!(out, "EFFECTIVE {}", format_rfc3339_utc(ast.effective_at()));

    if let Some(reason) = ast.reason() {
        out.push_str("REASON ");
        write_quoted(&mut out, reason);
        out.push('\n');
    }
    out
}

/// Parses a `HANDFEST REVOKE v1` revocation and rejects any input that is not byte-for-byte canonical.
pub fn parse_canonical_revocation(input: &str) -> Result<RevocationAst, ParseError> {
    let ast = parse_revocation(input)?;
    let expected = render_canonical_revocation(&ast);
    if expected != input {
        return Err(ParseError::NonCanonical { expected });
    }
    Ok(ast)
}

fn parse_target_line(lines: &[&str], idx: &mut usize) -> Result<RevocationTarget, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: "expected 'TARGET' clause, found end of input".into(),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("TARGET")?;
    cur.expect_spaces()?;
    let kind = cur.take_ident()?;
    cur.expect_spaces()?;
    let raw_target = cur.take_while(|b| !b.is_ascii_whitespace());
    let target = match kind {
        "mandate" => {
            let mid = MandateId::parse(raw_target).map_err(|error| cur.ast(error))?;
            RevocationTarget::Mandate(mid)
        }
        "key" => {
            let key = KeyId::parse(raw_target).map_err(|error| cur.ast(error))?;
            RevocationTarget::Key(key)
        }
        other => {
            return Err(cur.syntax(format!(
                "unknown revocation target kind '{other}' (expected 'mandate' or 'key')"
            )));
        }
    };
    cur.expect_eol()?;
    *idx += 1;
    Ok(target)
}

fn parse_effective_line(lines: &[&str], idx: &mut usize) -> Result<i64, ParseError> {
    let line_no = *idx + 1;
    let Some(&line) = lines.get(*idx) else {
        return Err(ParseError::Syntax {
            line: line_no,
            message: "expected 'EFFECTIVE' clause, found end of input".into(),
        });
    };
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("EFFECTIVE")?;
    cur.expect_spaces()?;
    let ts_raw = cur.take_while(|b| !b.is_ascii_whitespace());
    let ts = parse_rfc3339_utc(ts_raw).map_err(|error| cur.ast(error))?;
    cur.expect_eol()?;
    *idx += 1;
    Ok(ts)
}

fn parse_optional_reason_line(
    lines: &[&str],
    idx: &mut usize,
) -> Result<Option<String>, ParseError> {
    let Some(&line) = lines.get(*idx) else {
        return Ok(None);
    };
    if !line.starts_with("REASON") {
        return Ok(None);
    }
    let line_no = *idx + 1;
    let mut cur = Cursor::new(line, line_no);
    cur.expect_str("REASON")?;
    cur.expect_spaces()?;
    let reason = cur.take_quoted()?;
    cur.expect_eol()?;
    *idx += 1;
    Ok(Some(reason))
}

/// A revocation statement paired with its verified trust-anchor signature proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRevocation {
    pub ast: RevocationAst,
    pub proof: VerifiedAnchorProof,
}

/// Structured error returned when a [`VerifiedRevocation`] violates AST or proof binding invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationProofError {
    InvalidAst(AstError),
    ProofShape(ProofShapeError),
    SignerMismatch {
        proof_key: KeyId,
        by_key: KeyId,
    },
    ActorKindMismatch {
        proof_kind: ActorKind,
        by_kind: ActorKind,
    },
}

impl fmt::Display for RevocationProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAst(err) => write!(f, "invalid revocation AST: {err}"),
            Self::ProofShape(err) => write!(f, "invalid revocation proof shape: {err}"),
            Self::SignerMismatch { proof_key, by_key } => write!(
                f,
                "revocation proof signer key {proof_key} does not match BY key {by_key}"
            ),
            Self::ActorKindMismatch {
                proof_kind,
                by_kind,
            } => write!(
                f,
                "revocation proof actor kind {proof_kind:?} does not match BY kind {by_kind:?}"
            ),
        }
    }
}

impl core::error::Error for RevocationProofError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidAst(err) => Some(err),
            Self::ProofShape(err) => Some(err),
            Self::SignerMismatch { .. } | Self::ActorKindMismatch { .. } => None,
        }
    }
}

/// Validates a [`VerifiedRevocation`]'s AST, proof shape, signer key, and actor kind bindings,
/// returning its content-addressed [`RevocationId`].
pub fn validate_verified_revocation(
    revocation: &VerifiedRevocation,
) -> Result<RevocationId, RevocationProofError> {
    let revocation_id = revocation
        .ast
        .try_revocation_id()
        .map_err(RevocationProofError::InvalidAst)?;
    validate_proof_shape(
        &revocation.proof.anchor_id,
        revocation.proof.valid_from,
        revocation.proof.valid_until,
    )
    .map_err(RevocationProofError::ProofShape)?;
    if revocation.proof.valid_from >= revocation.proof.valid_until {
        return Err(RevocationProofError::ProofShape(
            ProofShapeError::InvertedValidityWindow {
                valid_from: revocation.proof.valid_from,
                valid_until: revocation.proof.valid_until,
            },
        ));
    }
    if &revocation.proof.signer_key != revocation.ast.by().key() {
        return Err(RevocationProofError::SignerMismatch {
            proof_key: revocation.proof.signer_key.clone(),
            by_key: revocation.ast.by().key().clone(),
        });
    }
    if revocation.proof.actor_kind != revocation.ast.by().kind() {
        return Err(RevocationProofError::ActorKindMismatch {
            proof_kind: revocation.proof.actor_kind,
            by_kind: revocation.ast.by().kind(),
        });
    }
    Ok(revocation_id)
}

/// Pure snapshot of validated [`VerifiedRevocation`] statements indexed deterministically by [`RevocationId`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationSnapshot {
    entries: BTreeMap<RevocationId, VerifiedRevocation>,
}

impl RevocationSnapshot {
    /// Creates an empty revocation snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Validates and inserts a [`VerifiedRevocation`] into this snapshot, returning its [`RevocationId`].
    pub fn insert(
        &mut self,
        revocation: VerifiedRevocation,
    ) -> Result<RevocationId, RevocationProofError> {
        let revocation_id = validate_verified_revocation(&revocation)?;
        self.entries.insert(revocation_id, revocation);
        Ok(revocation_id)
    }

    /// Merges all already-validated revocations from `other` into `self`.
    pub fn extend_from(&mut self, other: &Self) {
        for (id, rev) in &other.entries {
            self.entries.insert(*id, rev.clone());
        }
    }

    /// Returns `true` if no revocations are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of distinct revocations in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterates over revocations in deterministic ascending [`RevocationId`] order.
    pub fn iter(&self) -> impl Iterator<Item = (&RevocationId, &VerifiedRevocation)> {
        self.entries.iter()
    }
}

/// Deterministic typed denial reason when a mandate chain is denied by cryptographic revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    InvalidTimestamp(i64),
    MandateRevoked {
        hop: usize,
        mandate_id: MandateId,
        revocation_id: RevocationId,
    },
    KeyRevoked {
        hop: usize,
        key_id: KeyId,
        revocation_id: RevocationId,
    },
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimestamp(ts) => write!(
                f,
                "evaluation timestamp {ts} outside supported RFC 3339 range"
            ),
            Self::MandateRevoked {
                hop,
                mandate_id,
                revocation_id,
            } => write!(
                f,
                "hop {hop}: mandate {mandate_id} revoked by {revocation_id}"
            ),
            Self::KeyRevoked {
                hop,
                key_id,
                revocation_id,
            } => write!(f, "hop {hop}: key {key_id} revoked by {revocation_id}"),
        }
    }
}

impl core::error::Error for DenyReason {}

/// Deterministically evaluates a mandate chain against `revocations` at UTC timestamp `now`.
///
/// Enforces:
/// - **Mandate revocation authority:** revoking hop `m_i` is authoritative iff `rev.by.key`
///   equals `m_j.from.key` for some `j <= i` (issuer or upstream ancestor) OR `m_i.to.key`
///   (self-renunciation by the grantee).
/// - **Key revocation authority:** revoking `target_key` (first appearing at hop `i`) is
///   authoritative iff `rev.by.key == target_key` (self-revocation) OR `rev.by.key == m_j.from.key`
///   for some `j <= i` (upstream principal in the delegation chain).
/// - **Effective timestamp:** a revocation applies iff `now >= rev.ast.effective_at()`.
/// - **Cascade:** revoking any hop `m_i` denies the entire chain `[m_0, ..., m_k]`.
/// - **Unauthorized third-party revocations** are ignored (cannot DoS unrelated mandates).
pub fn check_chain_revocations(
    chain: &[VerifiedMandate],
    revocations: &RevocationSnapshot,
    now: i64,
) -> Result<(), DenyReason> {
    if !is_valid_timestamp(now) {
        return Err(DenyReason::InvalidTimestamp(now));
    }
    if revocations.is_empty() {
        return Ok(());
    }
    let chain_ids: alloc::vec::Vec<MandateId> =
        chain.iter().map(|vm| vm.ast.mandate_id()).collect();
    check_chain_revocations_with_ids(chain, &chain_ids, revocations, now)
}

pub(crate) fn check_chain_revocations_with_ids(
    chain: &[VerifiedMandate],
    chain_ids: &[MandateId],
    revocations: &RevocationSnapshot,
    now: i64,
) -> Result<(), DenyReason> {
    if !is_valid_timestamp(now) {
        return Err(DenyReason::InvalidTimestamp(now));
    }
    if revocations.is_empty() {
        return Ok(());
    }
    debug_assert_eq!(chain.len(), chain_ids.len());
    for (hop, (vm, mid)) in chain.iter().zip(chain_ids.iter()).enumerate() {
        check_hop_mandate_revocations(chain, hop, *mid, revocations, now)?;
        check_hop_key_revocations(chain, hop, vm.ast.from().key(), revocations, now)?;
        check_hop_key_revocations(chain, hop, vm.ast.to().key(), revocations, now)?;
    }
    Ok(())
}

fn check_hop_mandate_revocations(
    chain: &[VerifiedMandate],
    hop: usize,
    mandate_id: MandateId,
    revocations: &RevocationSnapshot,
    now: i64,
) -> Result<(), DenyReason> {
    for (&revocation_id, rev) in revocations.iter() {
        if now < rev.ast.effective_at() || now < rev.proof.valid_from {
            continue;
        }
        let RevocationTarget::Mandate(target_id) = rev.ast.target() else {
            continue;
        };
        if *target_id != mandate_id {
            continue;
        }
        let revoker = rev.ast.by().key();
        let authorized = revoker == chain[hop].ast.to().key()
            || chain[..=hop]
                .iter()
                .any(|upstream| upstream.ast.from().key() == revoker);
        if authorized {
            return Err(DenyReason::MandateRevoked {
                hop,
                mandate_id,
                revocation_id,
            });
        }
    }
    Ok(())
}

fn check_hop_key_revocations(
    chain: &[VerifiedMandate],
    hop: usize,
    candidate_key: &KeyId,
    revocations: &RevocationSnapshot,
    now: i64,
) -> Result<(), DenyReason> {
    for (&revocation_id, rev) in revocations.iter() {
        if now < rev.ast.effective_at() || now < rev.proof.valid_from {
            continue;
        }
        let RevocationTarget::Key(target_key) = rev.ast.target() else {
            continue;
        };
        if target_key != candidate_key {
            continue;
        }
        let revoker = rev.ast.by().key();
        let authorized = revoker == target_key
            || chain[..=hop]
                .iter()
                .any(|upstream| upstream.ast.from().key() == revoker);
        if authorized {
            return Err(DenyReason::KeyRevoked {
                hop,
                key_id: target_key.clone(),
                revocation_id,
            });
        }
    }
    Ok(())
}
