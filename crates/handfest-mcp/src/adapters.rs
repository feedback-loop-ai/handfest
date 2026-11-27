//! Pluggable runtime abstractions (clock, anchor chain verification) and proxy errors.
//!
//! Clock and chain-verification primitives are implemented in [`handfest_pep`] and re-exported
//! here for full backwards compatibility.

use std::fmt;

use handfest_anchors::{AnchorError, AnchorVerifier, SignedMandate, SignedRevocation};
#[cfg(test)]
use handfest_core::ast::MandateId;
use handfest_core::gate::{ChainStructureError, RevocationSnapshot, VerifiedMandate};
use handfest_ledger::LedgerError;
use handfest_pep::PepError;

pub use handfest_pep::{Clock, FixedClock, SystemClock};

use crate::mapping::MappingError;

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

impl From<PepError> for ProxyError {
    fn from(err: PepError) -> Self {
        match err {
            PepError::Anchor(e) => Self::Anchor(e),
            PepError::ChainStructure(e) => Self::ChainStructure(e),
            PepError::InvalidChain(msg) => Self::InvalidChain(msg),
            PepError::Ledger(e) => Self::Ledger(e),
            PepError::Secret(e) => Self::InvalidChain(e.to_string()),
            PepError::Io(e) => Self::Io(e),
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
    handfest_pep::verify_mandate_chain_with(verifier, signed).map_err(ProxyError::from)
}

/// Convenience wrapper verifying a mandate chain via `AnchorRegistry::default_registry`.
pub fn verify_mandate_chain(signed: &[SignedMandate]) -> Result<Vec<VerifiedMandate>, ProxyError> {
    handfest_pep::verify_mandate_chain(signed).map_err(ProxyError::from)
}

/// Verifies a slice of [`SignedRevocation`] envelopes using a pluggable [`AnchorVerifier`] into a
/// [`RevocationSnapshot`].
pub fn verify_revocations_with<V: AnchorVerifier + ?Sized>(
    verifier: &V,
    signed: &[SignedRevocation],
) -> Result<RevocationSnapshot, ProxyError> {
    handfest_pep::verify_revocations_with(verifier, signed).map_err(ProxyError::from)
}

/// Convenience wrapper verifying [`SignedRevocation`] envelopes via
/// `AnchorRegistry::default_registry`.
pub fn verify_revocations(signed: &[SignedRevocation]) -> Result<RevocationSnapshot, ProxyError> {
    handfest_pep::verify_revocations(signed).map_err(ProxyError::from)
}

#[cfg(test)]
pub(crate) fn validate_verified_chain(
    verified: &[VerifiedMandate],
) -> Result<Vec<MandateId>, ProxyError> {
    handfest_pep::validate_verified_chain(verified).map_err(ProxyError::from)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use handfest_anchors::AnchorRegistry;

    use super::*;

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

    #[test]
    fn verify_mandate_chain_rejects_empty_signed_chain() {
        assert!(matches!(
            verify_mandate_chain(&[]),
            Err(ProxyError::Anchor(AnchorError::EmptyChain))
        ));
        assert!(matches!(
            verify_mandate_chain_with(&AnchorRegistry::default_registry(), &[]),
            Err(ProxyError::Anchor(AnchorError::EmptyChain))
        ));
    }
}
