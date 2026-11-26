//! Fail-closed mapping from MCP `tools/call` payloads to `HANDFEST v1` requests and facts.
//!
//! All transport-independent policy schema types, single-pass `ExactJson` decoding, and
//! lossless tool-call mapping live in [`handfest_core::policy`] and are re-exported here for
//! full public API compatibility.

use std::fs;
use std::path::Path;

pub use handfest_core::policy::{
    denial_resource_id, CompiledPolicyMap, FactSpec, FactType, MappingError, ToolPolicy,
    ToolPolicyMap, TypedScalar,
};

/// Loads and validates a [`ToolPolicyMap`] from a JSON file on disk.
pub fn load_policy_map_file(path: impl AsRef<Path>) -> Result<ToolPolicyMap, MappingError> {
    let path_ref = path.as_ref();
    let raw = fs::read_to_string(path_ref).map_err(|err| {
        MappingError::Io(format!("failed to read '{}': {err}", path_ref.display()))
    })?;
    ToolPolicyMap::from_json_str(&raw)
}
