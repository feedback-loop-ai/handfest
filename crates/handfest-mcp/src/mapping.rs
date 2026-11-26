//! Fail-closed mapping from MCP `tools/call` payloads to `HANDFEST v1` requests and facts.
//!
//! All transport-independent policy schema types, single-pass `ExactJson` decoding, and
//! lossless tool-call mapping live in [`handfest_core::policy`] and are re-exported here for
//! full public API compatibility.

pub use handfest_core::policy::{
    denial_resource_id, CompiledPolicyMap, FactSpec, FactType, MappingError, ToolPolicy,
    ToolPolicyMap, TypedScalar,
};
