//! Drop-in MCP stdio JSON-RPC proxy enforcing `HANDFEST v1` mandate chains.

mod adapters;
mod exact_json;
mod framing;
pub mod mapping;
pub mod proxy;
mod session;
mod transport;

pub use handfest_core::Verdict;
pub use handfest_ledger::ReceiptLedger;
pub use mapping::{
    CompiledPolicyMap, FactSpec, FactType, MappingError, StaticFactValue, ToolPolicy,
    ToolPolicyMap, TypedScalar,
};
pub use proxy::{
    verify_mandate_chain, verify_mandate_chain_with, verify_revocations, verify_revocations_with,
    Clock, FixedClock, McpProxy, ProxyError, SystemClock, DEFAULT_MAX_LINE_BYTES,
    DEFAULT_SHUTDOWN_TIMEOUT, HANDFEST_DENIED_ERROR_CODE,
};
