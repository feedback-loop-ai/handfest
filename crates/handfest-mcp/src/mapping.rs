//! Fail-closed mapping from MCP `tools/call` payloads to `HANDFEST v1` requests and facts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use handfest_core::ast::{
    is_valid_field_path, is_valid_ident, is_valid_quoted_str, parse_rfc3339_utc, ActionPat, KeyId,
    Scalar,
};
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use serde::{Deserialize, Serialize};

use crate::exact_json::{parse_decimal_str, parse_exact_json, parse_json_decimal, ExactJson};

/// Expected scalar type for an argument-derived fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    #[serde(alias = "Str")]
    Str,
    #[serde(alias = "Int")]
    Int,
    #[serde(alias = "Decimal")]
    Decimal,
    #[serde(alias = "Bool")]
    Bool,
    #[serde(alias = "Timestamp")]
    Timestamp,
}

/// Specification mapping one MCP tool argument key to a typed `VerifiedFacts` field path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactSpec {
    pub field: String,
    #[serde(rename = "type")]
    pub fact_type: FactType,
}

/// Operator/broker-supplied static scalar fact with explicit type tagging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedScalar {
    #[serde(alias = "Str")]
    Str(String),
    #[serde(alias = "Int")]
    Int(i64),
    #[serde(alias = "Decimal")]
    Decimal(String),
    #[serde(alias = "Bool")]
    Bool(bool),
    #[serde(alias = "Timestamp")]
    Timestamp(String),
}

impl TypedScalar {
    /// Converts and validates this typed scalar into a canonical `handfest_core::ast::Scalar`.
    pub fn to_scalar(&self) -> Result<Scalar, MappingError> {
        let scalar = match self {
            Self::Str(s) => {
                if !is_valid_quoted_str(s) {
                    return Err(MappingError::InvalidPolicy(
                        "static string fact must not contain control characters".to_string(),
                    ));
                }
                Scalar::Str(s.clone())
            }
            Self::Int(n) => Scalar::Int(*n),
            Self::Decimal(raw) => {
                let dec = parse_decimal_str(raw).map_err(|err| {
                    MappingError::InvalidPolicy(format!("invalid static decimal '{raw}': {err}"))
                })?;
                Scalar::Decimal(dec)
            }
            Self::Bool(b) => Scalar::Bool(*b),
            Self::Timestamp(raw) => {
                let ts = parse_rfc3339_utc(raw).map_err(|err| {
                    MappingError::InvalidPolicy(format!("invalid static timestamp '{raw}': {err}"))
                })?;
                Scalar::Timestamp(ts)
            }
        };
        scalar
            .validate()
            .map_err(|err| MappingError::InvalidPolicy(format!("invalid static scalar: {err}")))?;
        Ok(scalar)
    }
}

/// Authorization mapping for a single admitted upstream MCP tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    pub action: String,
    pub resource_kind: String,
    #[serde(default)]
    pub resource_id_arg: Option<String>,
    #[serde(default)]
    pub static_resource_id: Option<String>,
    #[serde(default)]
    pub arg_facts: BTreeMap<String, FactSpec>,
    #[serde(default)]
    pub static_facts: BTreeMap<String, TypedScalar>,
}

impl ToolPolicy {
    /// Validates static configuration invariants for this tool mapping.
    pub fn validate(&self, tool_name: &str) -> Result<(), MappingError> {
        if tool_name.is_empty() {
            return Err(MappingError::InvalidPolicy(
                "tool name must not be empty".to_string(),
            ));
        }
        if !is_valid_concrete_action(&self.action) {
            return Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': invalid concrete action '{}'",
                self.action
            )));
        }
        if !is_valid_ident(&self.resource_kind) {
            return Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': invalid resource_kind '{}'",
                self.resource_kind
            )));
        }
        self.validate_resource_id_source(tool_name)?;
        self.validate_facts(tool_name)
    }

    fn validate_resource_id_source(&self, tool_name: &str) -> Result<(), MappingError> {
        match (&self.resource_id_arg, &self.static_resource_id) {
            (Some(arg), None) if arg.is_empty() => Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': resource_id_arg must not be empty"
            ))),
            (Some(_), None) => Ok(()),
            (None, Some(static_id)) if !is_valid_quoted_str(static_id) => {
                Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': static_resource_id must not contain control characters"
                )))
            }
            (None, Some(_)) => Ok(()),
            (None, None) => Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': must declare either resource_id_arg or static_resource_id"
            ))),
            (Some(_), Some(_)) => Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': cannot declare both resource_id_arg and static_resource_id"
            ))),
        }
    }

    fn validate_facts(&self, tool_name: &str) -> Result<(), MappingError> {
        let mut target_fields = BTreeSet::new();
        for (arg_key, spec) in &self.arg_facts {
            if arg_key.is_empty() {
                return Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': arg_facts key must not be empty"
                )));
            }
            if !is_valid_field_path(&spec.field) {
                return Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': invalid arg_facts field path '{}'",
                    spec.field
                )));
            }
            if !target_fields.insert(spec.field.clone()) {
                return Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': duplicate arg_facts target field '{}'",
                    spec.field
                )));
            }
        }

        for (field, value) in &self.static_facts {
            if !is_valid_field_path(field) {
                return Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': invalid static_facts field path '{field}'"
                )));
            }
            let _ = value.to_scalar().map_err(|err| {
                MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': static fact '{field}': {err}"
                ))
            })?;
        }
        Ok(())
    }
}

/// JSON-deserializable mapping from admitted upstream MCP tool names to [`ToolPolicy`] rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicyMap {
    pub tools: BTreeMap<String, ToolPolicy>,
}

/// Errors produced when loading, validating, or applying a [`ToolPolicyMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    Io(String),
    InvalidJson(String),
    InvalidPolicy(String),
    UnmappedTool(String),
    NonObjectArguments {
        tool: String,
    },
    MissingResourceId {
        tool: String,
        arg: String,
    },
    InvalidResourceId {
        tool: String,
        arg: String,
        detail: String,
    },
    MissingArgumentFact {
        tool: String,
        arg: String,
    },
    InvalidArgumentFact {
        tool: String,
        arg: String,
        detail: String,
    },
    CaseCollidingArgumentKey {
        tool: String,
        key: String,
        collides_with: String,
    },
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "policy map I/O error: {msg}"),
            Self::InvalidJson(msg) => write!(f, "invalid policy map JSON: {msg}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid policy map: {msg}"),
            Self::UnmappedTool(tool) => write!(f, "unmapped MCP tool '{tool}'"),
            Self::NonObjectArguments { tool } => {
                write!(f, "tool '{tool}': arguments must be a JSON object")
            }
            Self::MissingResourceId { tool, arg } => {
                write!(
                    f,
                    "tool '{tool}': missing required resource_id argument '{arg}'"
                )
            }
            Self::InvalidResourceId { tool, arg, detail } => {
                write!(
                    f,
                    "tool '{tool}': invalid resource_id argument '{arg}': {detail}"
                )
            }
            Self::MissingArgumentFact { tool, arg } => {
                write!(f, "tool '{tool}': missing required argument fact '{arg}'")
            }
            Self::InvalidArgumentFact { tool, arg, detail } => {
                write!(f, "tool '{tool}': invalid argument fact '{arg}': {detail}")
            }
            Self::CaseCollidingArgumentKey {
                tool,
                key,
                collides_with,
            } => write!(
                f,
                "tool '{tool}': argument key '{key}' collides case-insensitively with '{collides_with}'"
            ),
        }
    }
}

impl std::error::Error for MappingError {}

impl ToolPolicyMap {
    /// Parses and validates a [`ToolPolicyMap`] from a JSON string, rejecting duplicate keys.
    pub fn from_json_str(raw: &str) -> Result<Self, MappingError> {
        let _ = parse_exact_json(raw).map_err(MappingError::InvalidJson)?;
        let map: Self =
            serde_json::from_str(raw).map_err(|err| MappingError::InvalidJson(err.to_string()))?;
        map.validate()?;
        Ok(map)
    }

    /// Loads and validates a [`ToolPolicyMap`] from a JSON file on disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, MappingError> {
        let path_ref = path.as_ref();
        let raw = fs::read_to_string(path_ref).map_err(|err| {
            MappingError::Io(format!("failed to read '{}': {err}", path_ref.display()))
        })?;
        Self::from_json_str(&raw)
    }

    /// Validates every tool policy entry in this map.
    pub fn validate(&self) -> Result<(), MappingError> {
        for (tool_name, policy) in &self.tools {
            policy.validate(tool_name)?;
        }
        Ok(())
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
        let parsed = match arguments_json {
            Some(raw) => Some(parse_exact_json(raw).map_err(MappingError::InvalidJson)?),
            None => None,
        };
        self.map_call_exact(actor_key, tool_name, parsed.as_ref())
    }

    pub(crate) fn map_call_exact(
        &self,
        actor_key: &KeyId,
        tool_name: &str,
        arguments: Option<&ExactJson>,
    ) -> Result<(ActionRequest, VerifiedFacts), MappingError> {
        let policy = self
            .tools
            .get(tool_name)
            .ok_or_else(|| MappingError::UnmappedTool(tool_name.to_string()))?;
        policy.validate(tool_name)?;

        let empty_args = BTreeMap::new();
        let args_map = match arguments {
            None => &empty_args,
            Some(ExactJson::Object(map)) => map,
            Some(_) => {
                return Err(MappingError::NonObjectArguments {
                    tool: tool_name.to_string(),
                });
            }
        };

        if let Some(args_val) = arguments {
            check_argument_case_collisions(tool_name, policy, args_val, args_map)?;
        }

        let resource_id = resolve_resource_id(tool_name, policy, args_map)?;
        let facts = build_verified_facts(tool_name, policy, args_map)?;

        Ok((
            ActionRequest {
                actor_key: actor_key.clone(),
                action: policy.action.clone(),
                resource_kind: policy.resource_kind.clone(),
                resource_id,
            },
            facts,
        ))
    }
}

pub(crate) enum ResourceIdResolution<'a> {
    Resolved(&'a str),
    ControlChars { arg: &'a str, raw: &'a str },
    NotAString { arg: &'a str },
    Missing { arg: &'a str },
    Unconfigured,
}

pub(crate) fn inspect_resource_id<'a>(
    policy: &'a ToolPolicy,
    args_map: Option<&'a BTreeMap<String, ExactJson>>,
) -> ResourceIdResolution<'a> {
    if let Some(static_id) = &policy.static_resource_id {
        return ResourceIdResolution::Resolved(static_id.as_str());
    }
    let Some(arg_key) = policy.resource_id_arg.as_deref() else {
        return ResourceIdResolution::Unconfigured;
    };
    let Some(val) = args_map.and_then(|map| map.get(arg_key)) else {
        return ResourceIdResolution::Missing { arg: arg_key };
    };
    let Some(s) = val.as_str() else {
        return ResourceIdResolution::NotAString { arg: arg_key };
    };
    if !is_valid_quoted_str(s) {
        return ResourceIdResolution::ControlChars {
            arg: arg_key,
            raw: s,
        };
    }
    ResourceIdResolution::Resolved(s)
}

/// Resolves the honest `resource_id` for a pre-gate denial receipt on a mapped tool.
///
/// Static IDs and supplied string arguments (including strings containing control characters,
/// which `build_denial_receipt` safely escapes) are preserved verbatim. Missing or non-string
/// `resource_id_arg` values record `""` rather than fabricating the tool name.
pub(crate) fn denial_resource_id(policy: &ToolPolicy, arguments: Option<&ExactJson>) -> String {
    match inspect_resource_id(policy, arguments.and_then(ExactJson::as_object)) {
        ResourceIdResolution::Resolved(id) | ResourceIdResolution::ControlChars { raw: id, .. } => {
            id.to_string()
        }
        ResourceIdResolution::NotAString { .. }
        | ResourceIdResolution::Missing { .. }
        | ResourceIdResolution::Unconfigured => String::new(),
    }
}

fn resolve_resource_id(
    tool_name: &str,
    policy: &ToolPolicy,
    args_map: &BTreeMap<String, ExactJson>,
) -> Result<String, MappingError> {
    match inspect_resource_id(policy, Some(args_map)) {
        ResourceIdResolution::Resolved(id) => Ok(id.to_string()),
        ResourceIdResolution::ControlChars { arg, .. } => Err(MappingError::InvalidResourceId {
            tool: tool_name.to_string(),
            arg: arg.to_string(),
            detail: "must not contain control characters".to_string(),
        }),
        ResourceIdResolution::NotAString { arg } => Err(MappingError::InvalidResourceId {
            tool: tool_name.to_string(),
            arg: arg.to_string(),
            detail: "expected JSON string".to_string(),
        }),
        ResourceIdResolution::Missing { arg } => Err(MappingError::MissingResourceId {
            tool: tool_name.to_string(),
            arg: arg.to_string(),
        }),
        ResourceIdResolution::Unconfigured => Err(MappingError::InvalidPolicy(format!(
            "tool '{tool_name}': missing resource_id configuration"
        ))),
    }
}

fn build_verified_facts(
    tool_name: &str,
    policy: &ToolPolicy,
    args_map: &BTreeMap<String, ExactJson>,
) -> Result<VerifiedFacts, MappingError> {
    let mut facts = VerifiedFacts::new();

    for (arg_key, spec) in &policy.arg_facts {
        let Some(raw_val) = args_map.get(arg_key) else {
            return Err(MappingError::MissingArgumentFact {
                tool: tool_name.to_string(),
                arg: arg_key.clone(),
            });
        };
        let scalar = parse_arg_scalar(tool_name, arg_key, spec.fact_type, raw_val)?;
        if spec.field != "context.time" {
            facts.insert(spec.field.clone(), scalar);
        }
    }

    // Operator/broker-supplied static facts ALWAYS override argument-derived facts.
    // `context.time` is exclusively sourced from `Clock`, never from static or argument facts.
    for (field, typed) in &policy.static_facts {
        let scalar = typed.to_scalar()?;
        if field != "context.time" {
            facts.insert(field.clone(), scalar);
        }
    }

    Ok(facts)
}

fn parse_arg_scalar(
    tool_name: &str,
    arg_key: &str,
    expected: FactType,
    value: &ExactJson,
) -> Result<Scalar, MappingError> {
    let scalar = match (expected, value) {
        (FactType::Str, ExactJson::Str(s)) => {
            if !is_valid_quoted_str(s) {
                return Err(invalid_arg(
                    tool_name,
                    arg_key,
                    "string must not contain control characters",
                ));
            }
            Scalar::Str(s.clone())
        }
        (FactType::Bool, ExactJson::Bool(b)) => Scalar::Bool(*b),
        (FactType::Int, ExactJson::Number(raw)) => {
            if raw.contains(['.', 'e', 'E']) {
                return Err(invalid_arg(
                    tool_name,
                    arg_key,
                    "expected 64-bit signed integer",
                ));
            }
            let parsed = raw
                .parse::<i64>()
                .map_err(|_| invalid_arg(tool_name, arg_key, "integer outside 64-bit range"))?;
            Scalar::Int(parsed)
        }
        (FactType::Decimal, ExactJson::Number(raw)) => {
            let dec = parse_json_decimal(raw).map_err(|err| {
                invalid_arg(tool_name, arg_key, &format!("invalid decimal: {err}"))
            })?;
            Scalar::Decimal(dec)
        }
        (FactType::Decimal, ExactJson::Str(raw)) => {
            let dec = parse_decimal_str(raw).map_err(|err| {
                invalid_arg(tool_name, arg_key, &format!("invalid decimal: {err}"))
            })?;
            Scalar::Decimal(dec)
        }
        (FactType::Timestamp, ExactJson::Str(raw)) => {
            let ts = parse_rfc3339_utc(raw).map_err(|err| {
                invalid_arg(
                    tool_name,
                    arg_key,
                    &format!("invalid RFC 3339 UTC timestamp: {err}"),
                )
            })?;
            Scalar::Timestamp(ts)
        }
        _ => {
            return Err(invalid_arg(
                tool_name,
                arg_key,
                &format!("expected {expected:?}"),
            ));
        }
    };

    scalar
        .validate()
        .map_err(|err| invalid_arg(tool_name, arg_key, &err.to_string()))?;
    Ok(scalar)
}

fn invalid_arg(tool_name: &str, arg_key: &str, detail: &str) -> MappingError {
    MappingError::InvalidArgumentFact {
        tool: tool_name.to_string(),
        arg: arg_key.to_string(),
        detail: detail.to_string(),
    }
}

fn check_argument_case_collisions(
    tool_name: &str,
    policy: &ToolPolicy,
    args_val: &ExactJson,
    args_map: &BTreeMap<String, ExactJson>,
) -> Result<(), MappingError> {
    check_json_case_collisions(tool_name, args_val)?;
    if let Some(configured) = policy.resource_id_arg.as_deref() {
        reject_configured_case_collision(tool_name, args_map, configured)?;
    }
    for configured in policy.arg_facts.keys() {
        reject_configured_case_collision(tool_name, args_map, configured)?;
    }
    Ok(())
}

fn reject_configured_case_collision(
    tool_name: &str,
    args_map: &BTreeMap<String, ExactJson>,
    configured: &str,
) -> Result<(), MappingError> {
    if let Some(key) = args_map
        .keys()
        .find(|k| k.as_str() != configured && k.eq_ignore_ascii_case(configured))
    {
        return Err(MappingError::CaseCollidingArgumentKey {
            tool: tool_name.to_string(),
            key: key.clone(),
            collides_with: configured.to_string(),
        });
    }
    Ok(())
}

fn check_json_case_collisions(tool_name: &str, val: &ExactJson) -> Result<(), MappingError> {
    match val {
        ExactJson::Object(map) => {
            if let Some((a, b)) = find_case_colliding_keys(map) {
                return Err(MappingError::CaseCollidingArgumentKey {
                    tool: tool_name.to_string(),
                    key: b.to_string(),
                    collides_with: a.to_string(),
                });
            }
            for child in map.values() {
                check_json_case_collisions(tool_name, child)?;
            }
            Ok(())
        }
        ExactJson::Array(items) => {
            for item in items {
                check_json_case_collisions(tool_name, item)?;
            }
            Ok(())
        }
        ExactJson::Null | ExactJson::Bool(_) | ExactJson::Number(_) | ExactJson::Str(_) => Ok(()),
    }
}

fn find_case_colliding_keys(map: &BTreeMap<String, ExactJson>) -> Option<(&str, &str)> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for key in map.keys() {
        let folded = key.to_ascii_lowercase();
        if let Some(&prev) = seen.get(&folded) {
            return Some((prev, key.as_str()));
        }
        seen.insert(folded, key.as_str());
    }
    None
}

fn is_valid_concrete_action(action: &str) -> bool {
    ActionPat::parse(action).is_ok_and(|pat| !pat.is_wildcard())
}

#[cfg(test)]
mod tests {
    use handfest_core::ast::Decimal;

    use super::*;

    fn test_actor() -> KeyId {
        KeyId::parse("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap()
    }

    #[test]
    fn maps_all_five_fact_types_losslessly_with_static_resource_and_override() {
        let json = r#"{
            "tools": {
                "submit": {
                    "action": "finance.invoice.submit",
                    "resource_kind": "ledger",
                    "static_resource_id": "prod-main",
                    "arg_facts": {
                        "tag": { "field": "resource.tag", "type": "str" },
                        "count": { "field": "resource.count", "type": "int" },
                        "amount": { "field": "resource.amount", "type": "decimal" },
                        "urgent": { "field": "resource.urgent", "type": "bool" },
                        "due": { "field": "resource.due", "type": "timestamp" }
                    },
                    "static_facts": {
                        "resource.tag": { "str": "broker-enforced" }
                    }
                }
            }
        }"#;
        let map = ToolPolicyMap::from_json_str(json).unwrap();
        let args = r#"{
            "tag": "spoofed",
            "count": 7,
            "amount": 100.000000000000001,
            "urgent": true,
            "due": "2026-06-01T12:00:00Z"
        }"#;
        let (req, facts) = map
            .map_call_json(&test_actor(), "submit", Some(args))
            .unwrap();
        assert_eq!(req.action, "finance.invoice.submit");
        assert_eq!(req.resource_kind, "ledger");
        assert_eq!(req.resource_id, "prod-main");
        assert_eq!(
            facts.get("resource.tag"),
            Some(&Scalar::Str("broker-enforced".to_string()))
        );
        assert_eq!(facts.get("resource.count"), Some(&Scalar::Int(7)));
        assert_eq!(
            facts.get("resource.amount"),
            Some(&Scalar::Decimal(
                Decimal::parse("100.000000000000001").unwrap()
            ))
        );
        assert_eq!(facts.get("resource.urgent"), Some(&Scalar::Bool(true)));
        assert_eq!(
            facts.get("resource.due"),
            Some(&Scalar::Timestamp(
                parse_rfc3339_utc("2026-06-01T12:00:00Z").unwrap()
            ))
        );
    }

    #[test]
    fn rejects_wrong_types_missing_facts_and_invalid_policy_configs() {
        let json = r#"{
            "tools": {
                "pay": {
                    "action": "finance.pay",
                    "resource_kind": "account",
                    "resource_id_arg": "acct",
                    "arg_facts": {
                        "count": { "field": "resource.count", "type": "int" }
                    }
                }
            }
        }"#;
        let map = ToolPolicyMap::from_json_str(json).unwrap();

        // Wrong type: float given for int
        assert!(matches!(
            map.map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1","count":1.5}"#)),
            Err(MappingError::InvalidArgumentFact { .. })
        ));
        // Missing arg fact
        assert!(matches!(
            map.map_call_json(&test_actor(), "pay", Some(r#"{"acct":"a1"}"#)),
            Err(MappingError::MissingArgumentFact { .. })
        ));
        // Unmapped tool
        assert!(matches!(
            map.map_call_json(&test_actor(), "unknown", Some("{}")),
            Err(MappingError::UnmappedTool(_))
        ));
        // Duplicate JSON keys rejected
        assert!(matches!(
            ToolPolicyMap::from_json_str(
                r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","static_resource_id":"1"},"a":{"action":"x.z","resource_kind":"r","static_resource_id":"2"}}}"#
            ),
            Err(MappingError::InvalidJson(msg)) if msg.contains("duplicate JSON object key")
        ));
        // Both resource_id_arg and static_resource_id rejected
        assert!(matches!(
            ToolPolicyMap::from_json_str(
                r#"{"tools":{"a":{"action":"x.y","resource_kind":"r","resource_id_arg":"id","static_resource_id":"1"}}}"#
            ),
            Err(MappingError::InvalidPolicy(msg)) if msg.contains("cannot declare both")
        ));
        // Wildcard action rejected via handfest_core::ast::ActionPat delegation
        assert!(matches!(
            ToolPolicyMap::from_json_str(
                r#"{"tools":{"a":{"action":"x.*","resource_kind":"r","static_resource_id":"1"}}}"#
            ),
            Err(MappingError::InvalidPolicy(msg)) if msg.contains("invalid concrete action")
        ));
    }

    #[test]
    fn denial_resource_id_preserves_supplied_strings_and_uses_empty_when_missing() {
        let arg_policy = ToolPolicy {
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: Some("repo".to_string()),
            static_resource_id: None,
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        };
        assert_eq!(denial_resource_id(&arg_policy, None), "");
        let missing = parse_exact_json(r#"{}"#).unwrap();
        assert_eq!(denial_resource_id(&arg_policy, Some(&missing)), "");
        let non_str = parse_exact_json(r#"{"repo":42}"#).unwrap();
        assert_eq!(denial_resource_id(&arg_policy, Some(&non_str)), "");
        let valid = parse_exact_json(r#"{"repo":"acme/app"}"#).unwrap();
        assert_eq!(denial_resource_id(&arg_policy, Some(&valid)), "acme/app");
        let ctrl = parse_exact_json(r#"{"repo":"acme/app\ninjected"}"#).unwrap();
        assert_eq!(
            denial_resource_id(&arg_policy, Some(&ctrl)),
            "acme/app\ninjected"
        );

        let static_policy = ToolPolicy {
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: None,
            static_resource_id: Some("prod-main".to_string()),
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        };
        assert_eq!(denial_resource_id(&static_policy, None), "prod-main");

        let unconfigured = ToolPolicy {
            action: "git.pr.merge".to_string(),
            resource_kind: "repo".to_string(),
            resource_id_arg: None,
            static_resource_id: None,
            arg_facts: BTreeMap::new(),
            static_facts: BTreeMap::new(),
        };
        assert_eq!(denial_resource_id(&unconfigured, None), "");
        assert!(matches!(
            resolve_resource_id("merge_pr", &unconfigured, &BTreeMap::new()),
            Err(MappingError::InvalidPolicy(msg)) if msg.contains("missing resource_id configuration")
        ));
    }
}
