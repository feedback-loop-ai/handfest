//! Fail-closed mapping from MCP `tools/call` payloads to `HANDFEST v1` requests and facts.
//!
//! All transport-independent policy schema types, single-pass `ExactJson` decoding, and
//! lossless tool-call mapping live in [`handfest_core::policy`]. [`ToolPolicyMap`] wraps that core
//! map at the MCP boundary so `handfest-core` remains strictly `#![no_std]` with zero I/O while
//! preserving `handfest_mcp::ToolPolicyMap::from_file`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use handfest_core::ast::KeyId;
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::policy::ToolPolicyMap as CoreToolPolicyMap;
use serde::{Deserialize, Serialize};

pub use handfest_core::policy::{
    denial_resource_id, CompiledPolicyMap, FactSpec, FactType, MappingError, ToolPolicy,
    TypedScalar,
};

/// JSON-deserializable mapping from admitted upstream MCP tool names to [`ToolPolicy`] rules.
///
/// Mirrors [`handfest_core::policy::ToolPolicyMap`] at the MCP boundary and adds
/// [`ToolPolicyMap::from_file`] without introducing file I/O into `handfest-core`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "CoreToolPolicyMap", into = "CoreToolPolicyMap")]
pub struct ToolPolicyMap {
    pub tools: BTreeMap<String, ToolPolicy>,
}

impl From<CoreToolPolicyMap> for ToolPolicyMap {
    fn from(core: CoreToolPolicyMap) -> Self {
        Self { tools: core.tools }
    }
}

impl From<ToolPolicyMap> for CoreToolPolicyMap {
    fn from(map: ToolPolicyMap) -> Self {
        Self { tools: map.tools }
    }
}

impl ToolPolicyMap {
    /// Parses and validates a [`ToolPolicyMap`] in a single pass via `ExactJson`, rejecting
    /// duplicate keys without double-parsing.
    pub fn from_json_str(raw: &str) -> Result<Self, MappingError> {
        CoreToolPolicyMap::from_json_str(raw).map(Self::from)
    }

    /// Loads and validates a [`ToolPolicyMap`] from a JSON file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, MappingError> {
        let path_ref = path.as_ref();
        let raw = fs::read_to_string(path_ref).map_err(|err| {
            MappingError::Io(format!("failed to read '{}': {err}", path_ref.display()))
        })?;
        Self::from_json_str(&raw)
    }

    /// Validates every tool policy and seals pre-compiled static [`VerifiedFacts`] into a
    /// [`CompiledPolicyMap`].
    pub fn compile(self) -> Result<CompiledPolicyMap, MappingError> {
        CoreToolPolicyMap::from(self).compile()
    }

    /// Validates every tool policy entry in this map.
    pub fn validate(&self) -> Result<(), MappingError> {
        CoreToolPolicyMap::from(self.clone()).validate()
    }

    /// Returns the policy configured for `tool_name`, if admitted.
    #[must_use]
    pub fn get(&self, tool_name: &str) -> Option<&ToolPolicy> {
        self.tools.get(tool_name)
    }

    /// Maps an MCP `tools/call` invocation with raw JSON `arguments` into an [`ActionRequest`]
    /// and [`VerifiedFacts`] losslessly (never routing decimals through `f64`).
    pub fn map_call_json(
        &self,
        actor_key: &KeyId,
        tool_name: &str,
        arguments_json: Option<&str>,
    ) -> Result<(ActionRequest, VerifiedFacts), MappingError> {
        CoreToolPolicyMap::from(self.clone()).map_call_json(actor_key, tool_name, arguments_json)
    }
}
