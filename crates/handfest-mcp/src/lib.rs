//! Drop-in MCP stdio JSON-RPC proxy enforcing `HANDFEST v1` mandate chains.

mod exact_json;
mod framing;
pub mod mapping;
pub mod proxy;

pub use handfest_core::Verdict;
pub use mapping::{FactSpec, FactType, MappingError, ToolPolicy, ToolPolicyMap, TypedScalar};
pub use proxy::{
    verify_mandate_chain, Clock, FixedClock, McpProxy, ProxyError, SystemClock,
    DEFAULT_MAX_LINE_BYTES, HANDFEST_DENIED_ERROR_CODE,
};
