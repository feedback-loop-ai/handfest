//! Pluggable runtime abstractions (clock, anchor chain verification) and proxy errors.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use handfest_anchors::{
    verify_verifier_postconditions, AnchorError, AnchorRegistry, AnchorVerifier, SignedMandate,
};
use handfest_core::ast::MandateId;
use handfest_core::gate::{verify_chain_structure, ChainStructureError, VerifiedMandate};
use handfest_ledger::LedgerError;

use crate::mapping::MappingError;

/// Wall-clock abstraction supplying UTC Unix seconds for authorization evaluation.
pub trait Clock {
    /// Returns the current UTC timestamp in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// Converts a [`SystemTime`] into floored UTC Unix seconds, preserving pre-1970 negative
/// timestamps (with sub-second floor toward `-infinity`) and saturating to `i64::MIN`/`i64::MAX`.
#[must_use]
pub(crate) fn unix_seconds_from_system_time(t: SystemTime) -> i64 {
    unix_seconds_from_epoch_offset(t.duration_since(UNIX_EPOCH).map_err(|err| err.duration()))
}

fn unix_seconds_from_epoch_offset(offset: Result<Duration, Duration>) -> i64 {
    match offset {
        Ok(dur) => i64::try_from(dur.as_secs()).unwrap_or(i64::MAX),
        Err(dur) => {
            let abs_secs = dur
                .as_secs()
                .saturating_add(u64::from(dur.subsec_nanos() > 0));
            i64::try_from(abs_secs).map_or(i64::MIN, |secs| -secs)
        }
    }
}

/// Production wall-clock backed by [`SystemTime::now`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        unix_seconds_from_system_time(SystemTime::now())
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

/// Errors returned while validating chains, constructing [`crate::McpProxy`], or running the loop.
#[derive(Debug)]
pub enum ProxyError {
    Anchor(AnchorError),
    ChainStructure(ChainStructureError),
    InvalidChain(String),
    Mapping(MappingError),
    Ledger(LedgerError),
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
            Self::ChainStructure(err) => write!(f, "invalid mandate chain: {err}"),
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
            Self::ChainStructure(err) => Some(err),
            Self::Mapping(err) => Some(err),
            Self::Ledger(err) => Some(err),
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

impl From<ChainStructureError> for ProxyError {
    fn from(err: ChainStructureError) -> Self {
        Self::ChainStructure(err)
    }
}

impl From<MappingError> for ProxyError {
    fn from(err: MappingError) -> Self {
        Self::Mapping(err)
    }
}

impl From<LedgerError> for ProxyError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
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
        let vm = verifier
            .verify(item)
            .and_then(|vm| {
                verify_verifier_postconditions(item, &vm)?;
                Ok(vm)
            })
            .map_err(|source| {
                ProxyError::Anchor(AnchorError::ChainHop {
                    hop,
                    source: Box::new(source),
                })
            })?;
        verified.push(vm);
    }
    let _ = validate_verified_chain(&verified)?;
    Ok(verified)
}

/// Convenience wrapper verifying a mandate chain via [`AnchorRegistry::default_registry`].
pub fn verify_mandate_chain(signed: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, ProxyError> {
    verify_mandate_chain_with(&AnchorRegistry::default_registry(), signed)
}

pub(crate) fn validate_verified_chain(
    verified: &[VerifiedMandate],
) -> Result<Vec<MandateId>, ProxyError> {
    verify_chain_structure(verified).map_err(ProxyError::ChainStructure)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use handfest_core::ast::{is_valid_timestamp, MIN_RFC3339_TIMESTAMP};

    use super::*;

    #[test]
    fn unix_seconds_preserves_post_and_pre_1970_subsecond_and_saturation_bounds() {
        // Post-1970 (and exact epoch)
        assert_eq!(unix_seconds_from_system_time(UNIX_EPOCH), 0);
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH + Duration::new(1_700_000_000, 999_999_999)),
            1_700_000_000
        );

        // Pre-1970 whole seconds: must never clamp to 0
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::from_secs(3600)),
            -3600
        );

        // Sub-second pre-1970 floors toward -infinity
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::from_nanos(1)),
            -1
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::new(3600, 1)),
            -3601
        );
        assert_eq!(
            unix_seconds_from_system_time(UNIX_EPOCH - Duration::new(3600, 999_999_999)),
            -3601
        );

        // Pre-0000 underflow stays below MIN_RFC3339_TIMESTAMP (never clamped to 0)
        let before_year_zero_secs = MIN_RFC3339_TIMESTAMP.unsigned_abs() + 1;
        if let Some(pre_0000) = UNIX_EPOCH.checked_sub(Duration::from_secs(before_year_zero_secs)) {
            let ts = unix_seconds_from_system_time(pre_0000);
            assert_eq!(ts, MIN_RFC3339_TIMESTAMP - 1);
            assert!(!is_valid_timestamp(ts));
        }

        // Direct offset saturation checks for i64::MAX and i64::MIN boundaries
        assert_eq!(
            unix_seconds_from_epoch_offset(Ok(Duration::from_secs(u64::MAX))),
            i64::MAX
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Ok(Duration::from_secs(i64::MAX as u64))),
            i64::MAX
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::from_secs(u64::MAX))),
            i64::MIN
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::new(i64::MAX as u64, 1))),
            i64::MIN
        );
        assert_eq!(
            unix_seconds_from_epoch_offset(Err(Duration::new(i64::MAX as u64, 0))),
            i64::MIN + 1
        );
        assert_eq!(unix_seconds_from_epoch_offset(Err(Duration::ZERO)), 0);
    }

    #[test]
    fn proxy_error_preserves_typed_chain_structure_error() {
        let err = validate_verified_chain(&[]).unwrap_err();
        assert!(matches!(
            err,
            ProxyError::ChainStructure(ChainStructureError::EmptyChain)
        ));
        assert_eq!(
            err.to_string(),
            "invalid mandate chain: empty mandate chain"
        );
        assert!(err.source().is_some());
    }
}
