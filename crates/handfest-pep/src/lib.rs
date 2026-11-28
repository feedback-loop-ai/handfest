//! Transport-agnostic Policy Enforcement Point (PEP) runtime for `HANDFEST v1`.
//!
//! Provides a single audited enforcement kernel shared by MCP (`handfest-mcp`), CLI
//! (`handfest-exec`), and HTTP/REST (`handfest-http`) adapters:
//! - [`Clock`], [`SystemClock`], and [`FixedClock`] for deterministic UTC timestamps
//! - [`verify_mandate_chain`], [`verify_mandate_chain_with`], [`verify_revocations`], and
//!   [`verify_revocations_with`]
//! - [`GateEngine`] for atomic chain/revocation evaluation, quota accounting, and pre-gate denial
//!   receipts
//! - [`CredentialSource`] and [`SecretString`] for fail-closed, redacted secret loading outside
//!   agent-writable workspaces

mod chain;
mod clock;
mod engine;
mod error;
mod secret;

pub use chain::{
    load_signed_mandates_files, load_signed_revocations_files, parse_signed_mandate_json,
    validate_verified_chain, verify_mandate_chain, verify_mandate_chain_with, verify_revocations,
    verify_revocations_with,
};
pub use clock::{Clock, FixedClock, RuntimeClock, SystemClock};
pub use engine::{GateDecision, GateEngine, PreGateDenial};
pub use error::PepError;
pub use handfest_core::Verdict;
pub use handfest_ledger::ReceiptLedger;
#[cfg(unix)]
pub use secret::UNIX_O_NONBLOCK;
pub use secret::{
    decode_credential_source, is_valid_env_var_name, validate_absolute_clean_path,
    CredentialSource, SecretError, SecretString,
};
