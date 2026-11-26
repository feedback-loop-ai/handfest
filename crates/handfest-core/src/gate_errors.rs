//! Structured static and runtime error types for mandate chain validation.

use alloc::boxed::Box;
use core::fmt;

use crate::ast::{AstError, KeyId};
use crate::lattice::NarrowError;
use crate::ActorKind;

/// Structured error returned when a mandate chain violates static structural invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStructureError {
    EmptyChain,
    RootHasParent,
    InvalidMandateAst {
        hop: usize,
        source: AstError,
    },
    MaxHopsExceeded {
        hop: usize,
        parent_max_hops: u32,
        child_max_hops: u32,
    },
    AttenuationFailed {
        hop: usize,
        source: Box<NarrowError>,
    },
}

impl fmt::Display for ChainStructureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => f.write_str("empty mandate chain"),
            Self::RootHasParent => f.write_str("root mandate must not declare a PARENT digest"),
            Self::InvalidMandateAst { hop, source } => {
                write!(f, "hop {hop}: invalid mandate AST: {source}")
            }
            Self::MaxHopsExceeded {
                hop,
                parent_max_hops,
                child_max_hops,
            } => write!(
                f,
                "hop {hop} -> {}: attenuation check failed: delegation hop overflow: parent allows max {parent_max_hops}, child claims {child_max_hops}",
                hop + 1
            ),
            Self::AttenuationFailed { hop, source } => {
                write!(
                    f,
                    "hop {hop} -> {}: attenuation check failed: {source}",
                    hop + 1
                )
            }
        }
    }
}

impl core::error::Error for ChainStructureError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidMandateAst { source, .. } => Some(source),
            Self::AttenuationFailed { source, .. } => Some(source.as_ref()),
            Self::EmptyChain | Self::RootHasParent | Self::MaxHopsExceeded { .. } => None,
        }
    }
}

/// Structured error returned when a mandate chain fails runtime validation at an evaluation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeChainError {
    Structure(ChainStructureError),
    InvalidTimestamp {
        timestamp: i64,
    },
    InvalidAnchorId {
        hop: usize,
    },
    ProofSignerMismatch {
        hop: usize,
        proof_key: KeyId,
        mandate_key: KeyId,
    },
    ProofActorKindMismatch {
        hop: usize,
        proof_kind: ActorKind,
        mandate_kind: ActorKind,
    },
    ProofTimestampOutOfRange {
        hop: usize,
        valid_from: i64,
        valid_until: i64,
    },
    InvalidProofValidityWindow {
        hop: usize,
        valid_from: i64,
        valid_until: i64,
    },
    OutsideProofValidityWindow {
        hop: usize,
        now: i64,
        valid_from: i64,
        valid_until: i64,
    },
    ActorKeyMismatch {
        expected: KeyId,
        actual: KeyId,
    },
}

impl fmt::Display for RuntimeChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structure(err) => write!(f, "{err}"),
            Self::InvalidTimestamp { timestamp } => write!(
                f,
                "timestamp {timestamp} outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
            ),
            Self::InvalidAnchorId { hop } => write!(
                f,
                "hop {hop}: invalid anchor proof anchor_id (must be non-empty without control characters)"
            ),
            Self::ProofSignerMismatch {
                hop,
                proof_key,
                mandate_key,
            } => write!(
                f,
                "hop {hop}: proof signer key {proof_key} does not match mandate FROM key {mandate_key}"
            ),
            Self::ProofActorKindMismatch {
                hop,
                proof_kind,
                mandate_kind,
            } => write!(
                f,
                "hop {hop}: proof actor kind {proof_kind:?} does not match mandate FROM kind {mandate_kind:?}"
            ),
            Self::ProofTimestampOutOfRange {
                hop,
                valid_from,
                valid_until,
            } => write!(
                f,
                "hop {hop}: anchor proof validity window [{valid_from}..{valid_until}) outside 0000-01-01T00:00:00Z..=9999-12-31T23:59:59Z"
            ),
            Self::InvalidProofValidityWindow {
                hop,
                valid_from,
                valid_until,
            } => write!(
                f,
                "hop {hop}: invalid anchor proof validity window [{valid_from}..{valid_until})"
            ),
            Self::OutsideProofValidityWindow {
                hop,
                now,
                valid_from,
                valid_until,
            } => write!(
                f,
                "hop {hop}: timestamp {now} outside anchor proof validity window [{valid_from}..{valid_until})"
            ),
            Self::ActorKeyMismatch { expected, actual } => write!(
                f,
                "request actor key {actual} does not match leaf mandate TO key {expected}"
            ),
        }
    }
}

impl core::error::Error for RuntimeChainError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Structure(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ChainStructureError> for RuntimeChainError {
    fn from(err: ChainStructureError) -> Self {
        Self::Structure(err)
    }
}
