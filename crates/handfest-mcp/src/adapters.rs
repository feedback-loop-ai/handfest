//! Pluggable runtime abstractions (clock, ledger, anchor chain verification) and proxy errors.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use handfest_anchors::{AnchorError, AnchorVerifier, Ed25519Verifier, SignedMandate};
use handfest_core::gate::{ActionRequest, DecisionReceipt, VerifiedFacts, VerifiedMandate};
use handfest_core::lattice::subsumes;
use handfest_core::Verdict;
use handfest_ledger::{LedgerError, SqliteLedger};

use crate::mapping::MappingError;

/// Wall-clock abstraction supplying UTC Unix seconds for authorization evaluation.
pub trait Clock {
    /// Returns the current UTC timestamp in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// Production wall-clock backed by [`SystemTime::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        i64::try_from(dur.as_secs()).unwrap_or(i64::MAX)
    }
}

/// Deterministic fixed-timestamp clock for tests and replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    now_unix: i64,
}

impl FixedClock {
    /// Creates a clock that always returns `now_unix` (UTC Unix seconds).
    #[must_use]
    pub const fn new(now_unix: i64) -> Self {
        Self { now_unix }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.now_unix
    }
}

/// Pluggable receipt and quota persistence abstraction consumed by [`crate::McpProxy`].
pub trait ReceiptLedger {
    /// Backend-specific persistence or integrity error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Atomically evaluates `chain` against `request` and `facts` at UTC timestamp `now`,
    /// persists the hash-chained `DecisionReceipt`, and updates quotas on `Permit`.
    fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), Self::Error>;
}

impl ReceiptLedger for SqliteLedger {
    type Error = LedgerError;

    fn evaluate_and_record(
        &mut self,
        chain: &[VerifiedMandate],
        request: &ActionRequest,
        facts: &VerifiedFacts,
        now: i64,
    ) -> Result<(Verdict, DecisionReceipt), Self::Error> {
        Self::evaluate_and_record(self, chain, request, facts, now)
    }
}

/// Errors returned while validating chains, constructing [`crate::McpProxy`], or running the loop.
#[derive(Debug)]
pub enum ProxyError {
    Anchor(AnchorError),
    InvalidChain(String),
    Mapping(MappingError),
    Ledger(Box<dyn std::error::Error + Send + Sync>),
    Io(std::io::Error),
    FrameTooLarge { max_bytes: usize },
    UpstreamFrameTooLarge { max_bytes: usize },
    UpstreamEof,
    UpstreamProtocol(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(err) => write!(f, "mandate signature verification failed: {err}"),
            Self::InvalidChain(msg) => write!(f, "invalid mandate chain: {msg}"),
            Self::Mapping(err) => write!(f, "policy mapping error: {err}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::FrameTooLarge { max_bytes } => {
                write!(
                    f,
                    "client JSON-RPC frame exceeded limit of {max_bytes} bytes"
                )
            }
            Self::UpstreamFrameTooLarge { max_bytes } => {
                write!(
                    f,
                    "upstream JSON-RPC frame exceeded limit of {max_bytes} bytes"
                )
            }
            Self::UpstreamEof => f.write_str("upstream MCP server closed stdout unexpectedly"),
            Self::UpstreamProtocol(msg) => write!(f, "upstream MCP protocol error: {msg}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Anchor(err) => Some(err),
            Self::Mapping(err) => Some(err),
            Self::Ledger(err) => Some(err.as_ref()),
            Self::Io(err) => Some(err),
            Self::InvalidChain(_)
            | Self::FrameTooLarge { .. }
            | Self::UpstreamFrameTooLarge { .. }
            | Self::UpstreamEof
            | Self::UpstreamProtocol(_) => None,
        }
    }
}

impl From<AnchorError> for ProxyError {
    fn from(err: AnchorError) -> Self {
        Self::Anchor(err)
    }
}

impl From<MappingError> for ProxyError {
    fn from(err: MappingError) -> Self {
        Self::Mapping(err)
    }
}

impl From<LedgerError> for ProxyError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(Box::new(err))
    }
}

impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Verifies every mandate in `signed` using a pluggable [`AnchorVerifier`] AND checks root parent
/// absence plus monotonic lattice narrowing (`subsumes`) across every hop.
pub fn verify_mandate_chain_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    signed: &[SignedMandate],
) -> Result<Vec<VerifiedMandate>, ProxyError> {
    if signed.is_empty() {
        return Err(ProxyError::Anchor(AnchorError::EmptyChain));
    }
    let mut verified = Vec::with_capacity(signed.len());
    for (hop, item) in signed.iter().enumerate() {
        let vm = verifier.verify(item).map_err(|source| {
            ProxyError::Anchor(AnchorError::ChainHop {
                hop,
                source: Box::new(source),
            })
        })?;
        verified.push(vm);
    }
    validate_verified_chain(&verified)?;
    Ok(verified)
}

/// Convenience wrapper verifying an Ed25519-signed mandate chain via [`Ed25519Verifier`].
pub fn verify_mandate_chain(signed: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, ProxyError> {
    verify_mandate_chain_with(&Ed25519Verifier, signed)
}

pub(crate) fn validate_verified_chain(verified: &[VerifiedMandate]) -> Result<(), ProxyError> {
    if verified.is_empty() {
        return Err(ProxyError::InvalidChain(
            "mandate chain must contain at least one mandate".to_string(),
        ));
    }
    if verified[0].ast.parent().is_some() {
        return Err(ProxyError::InvalidChain(
            "root mandate must not declare a PARENT digest".to_string(),
        ));
    }
    for (hop, vm) in verified.iter().enumerate() {
        vm.ast.try_mandate_id().map_err(|err| {
            ProxyError::InvalidChain(format!("hop {hop}: invalid mandate AST: {err}"))
        })?;
    }
    for (hop, pair) in verified.windows(2).enumerate() {
        subsumes(&pair[0].ast, &pair[1].ast).map_err(|err| {
            ProxyError::InvalidChain(format!(
                "attenuation check failed at hop {hop} -> {}: {err}",
                hop + 1
            ))
        })?;
    }
    Ok(())
}
