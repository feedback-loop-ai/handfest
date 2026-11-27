//! Typed errors returned by the shared PEP runtime.

use std::fmt;

use handfest_anchors::AnchorError;
use handfest_core::gate::ChainStructureError;
use handfest_ledger::LedgerError;

use crate::secret::SecretError;

/// Errors returned while verifying chains, constructing [`crate::GateEngine`], evaluating
/// mandates, or loading broker credentials.
#[derive(Debug)]
pub enum PepError {
    Anchor(AnchorError),
    ChainStructure(ChainStructureError),
    InvalidChain(String),
    Ledger(LedgerError),
    Secret(SecretError),
    Io(std::io::Error),
}

impl fmt::Display for PepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor(err) => write!(f, "mandate signature verification failed: {err}"),
            Self::ChainStructure(err) => write!(f, "invalid mandate chain: {err}"),
            Self::InvalidChain(msg) => write!(f, "invalid mandate chain: {msg}"),
            Self::Ledger(err) => write!(f, "ledger error: {err}"),
            Self::Secret(err) => write!(f, "credential error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for PepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Anchor(err) => Some(err),
            Self::ChainStructure(err) => Some(err),
            Self::Ledger(err) => Some(err),
            Self::Secret(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::InvalidChain(_) => None,
        }
    }
}

impl From<AnchorError> for PepError {
    fn from(err: AnchorError) -> Self {
        Self::Anchor(err)
    }
}

impl From<ChainStructureError> for PepError {
    fn from(err: ChainStructureError) -> Self {
        Self::ChainStructure(err)
    }
}

impl From<LedgerError> for PepError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
    }
}

impl From<SecretError> for PepError {
    fn from(err: SecretError) -> Self {
        Self::Secret(err)
    }
}

impl From<std::io::Error> for PepError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
