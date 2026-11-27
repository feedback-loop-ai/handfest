//! Fail-closed CLI Policy Enforcement Point (`HANDFEST v1`) wrapping arbitrary executables
//! directly without a shell.
//!
//! Enforces verified `HANDFEST v1` mandate chains via [`handfest_pep::GateEngine`], maps
//! allowlisted `--flag` arguments into typed [`handfest_core::gate::ActionRequest`] and
//! [`handfest_core::gate::VerifiedFacts`], injects operator-held credentials strictly on
//! `Permit`, and records tamper-evident receipts (including pre-gate mapping denials).

pub mod argv;
pub mod executor;
pub mod policy;
mod policy_decode;

pub use argv::{denial_resource_id, parse_and_map_argv, ArgvError, MappedCommand};
pub use executor::{
    CommandExecutor, ExecError, ExecOutcome, ExecOutput, ExecProxy, ExecSpec, OsCommandExecutor,
    ProxyError,
};
pub use handfest_core::policy::{FactType, TypedScalar};
pub use handfest_core::Verdict;
pub use handfest_ledger::ReceiptLedger;
pub use handfest_pep::{
    verify_mandate_chain, verify_mandate_chain_with, verify_revocations, verify_revocations_with,
    Clock, CredentialSource, FixedClock, GateDecision, GateEngine, PepError, PreGateDenial,
    SecretError, SecretString, SystemClock,
};
pub use policy::{
    load_cli_policy_map_file, CliPolicyMap, CommandPolicy, CompiledCliPolicyMap, FlagKind,
    FlagSpec, PolicyError,
};
