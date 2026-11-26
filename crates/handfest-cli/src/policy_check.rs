//! Policy-map backed `handfest check` request resolution, reusing `handfest-core`'s single
//! transport-independent `ToolPolicyMap` and exact-JSON/decimal codec.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use handfest_core::ast::KeyId;
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::policy::{MappingError, ToolPolicyMap};
use serde_json::json;

/// Structured policy-mapping error emitted on `stderr` so hooks and agents parse failure codes
/// deterministically without scraping prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyCheckError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl PolicyCheckError {
    pub(crate) fn emit_stderr(&self) {
        let payload = json!({
            "error": "policy_mapping_failed",
            "code": self.code,
            "message": self.message,
        });
        eprintln!("{payload}");
    }
}

pub(crate) fn classify_policy_load_error(err: &MappingError) -> &'static str {
    match err {
        MappingError::Io(_) | MappingError::InvalidJson(_) | MappingError::InvalidPolicy(_) => {
            "invalid_policy_map"
        }
        MappingError::UnmappedTool(_) => "unmapped_tool",
        MappingError::NonObjectArguments { .. }
        | MappingError::CaseCollidingArgumentKey { .. }
        | MappingError::NonAsciiArgumentKey { .. } => "invalid_input",
        MappingError::MissingResourceId { .. }
        | MappingError::InvalidResourceId { .. }
        | MappingError::MissingArgumentFact { .. }
        | MappingError::InvalidArgumentFact { .. } => "invalid_argument",
    }
}

pub(crate) fn classify_tool_call_error(err: &MappingError) -> &'static str {
    match err {
        MappingError::Io(_) | MappingError::InvalidPolicy(_) => "invalid_policy_map",
        MappingError::UnmappedTool(_) => "unmapped_tool",
        MappingError::InvalidJson(_)
        | MappingError::NonObjectArguments { .. }
        | MappingError::CaseCollidingArgumentKey { .. }
        | MappingError::NonAsciiArgumentKey { .. } => "invalid_input",
        MappingError::MissingResourceId { .. }
        | MappingError::InvalidResourceId { .. }
        | MappingError::MissingArgumentFact { .. }
        | MappingError::InvalidArgumentFact { .. } => "invalid_argument",
    }
}

pub(crate) fn resolve_policy_map_request(
    policy_map_path: &Path,
    actor_key: &KeyId,
    tool_name: &str,
    tool_input_arg: &str,
) -> Result<(ActionRequest, VerifiedFacts), PolicyCheckError> {
    let raw_policy = fs::read_to_string(policy_map_path).map_err(|err| {
        let map_err = MappingError::Io(format!(
            "failed to read '{}': {err}",
            policy_map_path.display()
        ));
        PolicyCheckError {
            code: classify_policy_load_error(&map_err),
            message: map_err.to_string(),
        }
    })?;
    let policy_map = ToolPolicyMap::from_json_str(&raw_policy).map_err(|err| PolicyCheckError {
        code: classify_policy_load_error(&err),
        message: err.to_string(),
    })?;
    let raw_input = read_tool_input(tool_input_arg)?;
    policy_map
        .map_call_json(actor_key, tool_name, Some(&raw_input))
        .map_err(|err| PolicyCheckError {
            code: classify_tool_call_error(&err),
            message: err.to_string(),
        })
}

fn read_tool_input(arg: &str) -> Result<String, PolicyCheckError> {
    if arg != "-" {
        return Ok(arg.to_string());
    }
    let mut raw = Vec::new();
    io::stdin()
        .read_to_end(&mut raw)
        .map_err(|err| PolicyCheckError {
            code: "invalid_input",
            message: format!("failed to read --tool-input from stdin: {err}"),
        })?;
    String::from_utf8(raw).map_err(|err| PolicyCheckError {
        code: "invalid_input",
        message: format!("--tool-input stdin is not valid UTF-8: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_errors_maps_every_mapping_error_variant() {
        let cases = [
            (
                MappingError::Io("io".into()),
                "invalid_policy_map",
                "invalid_policy_map",
            ),
            (
                MappingError::InvalidJson("bad json".into()),
                "invalid_policy_map",
                "invalid_input",
            ),
            (
                MappingError::InvalidPolicy("bad pol".into()),
                "invalid_policy_map",
                "invalid_policy_map",
            ),
            (
                MappingError::UnmappedTool("bash".into()),
                "unmapped_tool",
                "unmapped_tool",
            ),
            (
                MappingError::NonObjectArguments { tool: "t".into() },
                "invalid_input",
                "invalid_input",
            ),
            (
                MappingError::CaseCollidingArgumentKey {
                    tool: "t".into(),
                    key: "A".into(),
                    collides_with: "a".into(),
                },
                "invalid_input",
                "invalid_input",
            ),
            (
                MappingError::NonAsciiArgumentKey {
                    tool: "t".into(),
                    key: "café".into(),
                },
                "invalid_input",
                "invalid_input",
            ),
            (
                MappingError::MissingResourceId {
                    tool: "t".into(),
                    arg: "repo".into(),
                },
                "invalid_argument",
                "invalid_argument",
            ),
            (
                MappingError::InvalidResourceId {
                    tool: "t".into(),
                    arg: "repo".into(),
                    detail: "ctrl".into(),
                },
                "invalid_argument",
                "invalid_argument",
            ),
            (
                MappingError::MissingArgumentFact {
                    tool: "t".into(),
                    arg: "pr".into(),
                },
                "invalid_argument",
                "invalid_argument",
            ),
            (
                MappingError::InvalidArgumentFact {
                    tool: "t".into(),
                    arg: "amount".into(),
                    detail: "scale".into(),
                },
                "invalid_argument",
                "invalid_argument",
            ),
        ];
        for (err, load_code, call_code) in cases {
            assert_eq!(classify_policy_load_error(&err), load_code);
            assert_eq!(classify_tool_call_error(&err), call_code);
        }
    }
}
