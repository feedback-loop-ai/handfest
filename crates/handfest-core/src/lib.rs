#![no_std]
//! Pure, deterministic core for Executable Ricardian Mandates (`HANDFEST v1`).
//!
//! `handfest-core` performs no I/O, no clock reads, and no randomness.

extern crate alloc;

pub mod ast;
pub mod cnl;
pub mod gate;
mod gate_errors;
pub mod json_num;
pub mod lattice;

use alloc::string::String;

/// Current canonical wire and Controlled-English version header.
pub const MANDATE_VERSION: &str = "HANDFEST v1";

/// Actor class participating in a mandate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActorKind {
    Human,
    Org,
    Agent,
    Service,
}

/// Normalized assurance tier reported by a verified trust anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssuranceLevel {
    LocalKey,
    CryptoWallet,
    Passkey,
    SubstantialEidas,
    QualifiedQes,
}

/// Deterministic gate decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Deny { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_levels_order_monotonically() {
        assert!(AssuranceLevel::LocalKey < AssuranceLevel::QualifiedQes);
        assert_eq!(MANDATE_VERSION, "HANDFEST v1");
    }
}
