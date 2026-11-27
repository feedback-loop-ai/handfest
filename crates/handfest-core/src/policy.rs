//! Pure, transport-independent, fail-closed mapping from tool calls to `HANDFEST v1` requests
//! and [`VerifiedFacts`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::ast::{
    format_rfc3339_utc, is_valid_field_path, is_valid_ident, is_valid_quoted_str,
    is_valid_timestamp, parse_rfc3339_utc, ActionPat, Decimal, KeyId, Scalar,
};
use crate::exact_json::{parse_exact_json, validate_json_keys_recursive, ExactJson, JsonKeyError};
use crate::gate::{ActionRequest, VerifiedFacts};
use crate::json_num::{
    is_canonical_json_int_syntax, parse_canonical_json_int, parse_decimal_str, parse_json_decimal,
};

#[path = "policy_decode.rs"]
mod policy_decode;

pub use policy_decode::{
    decode_fact_type, decode_static_facts, decode_typed_scalar, parse_text_scalar,
};

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

mod serde_static_decimal {
    use alloc::format;
    use alloc::string::{String, ToString};
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{parse_decimal_str, Decimal};

    pub(super) fn serialize<S: Serializer>(val: &Decimal, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&val.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Decimal, D::Error> {
        let raw = String::deserialize(de)?;
        parse_decimal_str(&raw).map_err(|err| {
            serde::de::Error::custom(format!("invalid static decimal '{raw}': {err}"))
        })
    }
}

mod serde_static_timestamp {
    use alloc::format;
    use alloc::string::String;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{format_rfc3339_utc, is_valid_timestamp, parse_rfc3339_utc};

    pub(super) fn serialize<S: Serializer>(ts: &i64, ser: S) -> Result<S::Ok, S::Error> {
        if !is_valid_timestamp(*ts) {
            return Err(serde::ser::Error::custom(format!(
                "static timestamp {ts} outside valid RFC 3339 UTC range"
            )));
        }
        ser.serialize_str(&format_rfc3339_utc(*ts))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<i64, D::Error> {
        let raw = String::deserialize(de)?;
        parse_rfc3339_utc(&raw).map_err(|err| {
            serde::de::Error::custom(format!("invalid static timestamp '{raw}': {err}"))
        })
    }
}

/// Operator/broker-supplied static scalar fact with explicit type tagging.
///
/// Decimals and RFC 3339 UTC timestamps are parsed once at configuration deserialization so
/// runtime discovery and `tools/call` mapping never reparse string literals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedScalar {
    #[serde(alias = "Str")]
    Str(String),
    #[serde(alias = "Int")]
    Int(i64),
    #[serde(alias = "Decimal", with = "serde_static_decimal")]
    Decimal(Decimal),
    #[serde(alias = "Bool")]
    Bool(bool),
    #[serde(alias = "Timestamp", with = "serde_static_timestamp")]
    Timestamp(i64),
}

/// Public alias for [`TypedScalar`] matching the static-fact configuration terminology.
pub type StaticFactValue = TypedScalar;

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
            Self::Decimal(dec) => Scalar::Decimal(*dec),
            Self::Bool(b) => Scalar::Bool(*b),
            Self::Timestamp(ts) => Scalar::Timestamp(*ts),
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
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub arg_facts: BTreeMap<String, FactSpec>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
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
            (Some(arg), None) if !arg.is_ascii() => Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': resource_id_arg '{arg}' must be ASCII"
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
        let mut folded_arg_keys: BTreeMap<String, &str> = BTreeMap::new();
        for (arg_key, spec) in &self.arg_facts {
            self.validate_arg_fact_key(tool_name, arg_key, &mut folded_arg_keys)?;
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

    fn validate_arg_fact_key<'a>(
        &self,
        tool_name: &str,
        arg_key: &'a str,
        folded_arg_keys: &mut BTreeMap<String, &'a str>,
    ) -> Result<(), MappingError> {
        if arg_key.is_empty() {
            return Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': arg_facts key must not be empty"
            )));
        }
        if !arg_key.is_ascii() {
            return Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': arg_facts key '{arg_key}' must be ASCII"
            )));
        }
        if let Some(res_arg) = self.resource_id_arg.as_deref() {
            if arg_key != res_arg && arg_key.eq_ignore_ascii_case(res_arg) {
                return Err(MappingError::InvalidPolicy(format!(
                    "tool '{tool_name}': arg_facts key '{arg_key}' collides case-insensitively with resource_id_arg '{res_arg}'"
                )));
            }
        }
        if let Some(prev) = folded_arg_keys.insert(arg_key.to_ascii_lowercase(), arg_key) {
            return Err(MappingError::InvalidPolicy(format!(
                "tool '{tool_name}': arg_facts key '{arg_key}' collides case-insensitively with '{prev}'"
            )));
        }
        Ok(())
    }

    /// Builds [`VerifiedFacts`] from this policy's static facts (excluding `context.time`, which
    /// is exclusively sourced from the runtime `Clock`).
    fn static_verified_facts(&self) -> Result<VerifiedFacts, MappingError> {
        let mut facts = VerifiedFacts::new();
        for (field, typed) in &self.static_facts {
            let scalar = typed.to_scalar()?;
            if field != "context.time" {
                facts.insert(field.clone(), scalar);
            }
        }
        Ok(facts)
    }
}

/// Deserializes a JSON object into a [`BTreeMap`] while rejecting duplicate keys.
pub fn deserialize_unique_btreemap<'de, D, V>(de: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct UniqueMapVisitor<V>(PhantomData<V>);

    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for UniqueMapVisitor<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<String, V>()? {
                if map.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!("duplicate key '{key}'")));
                }
                map.insert(key, value);
            }
            Ok(map)
        }
    }

    de.deserialize_map(UniqueMapVisitor(PhantomData))
}

/// JSON-deserializable mapping from admitted upstream MCP tool names to [`ToolPolicy`] rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicyMap {
    #[serde(deserialize_with = "deserialize_unique_btreemap")]
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
    NonAsciiArgumentKey {
        tool: String,
        key: String,
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
            Self::NonAsciiArgumentKey { tool, key } => {
                write!(f, "tool '{tool}': argument key '{key}' must be ASCII")
            }
        }
    }
}

impl core::error::Error for MappingError {}

/// Validated [`ToolPolicyMap`] paired with pre-compiled static [`VerifiedFacts`] per tool.
///
/// Can only be constructed via [`ToolPolicyMap::compile`], guaranteeing that every tool policy
/// passed [`ToolPolicyMap::validate`] and preventing callers from injecting forged static facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicyMap {
    policy_map: ToolPolicyMap,
    static_facts: BTreeMap<String, VerifiedFacts>,
}

impl CompiledPolicyMap {
    /// Borrows the validated underlying [`ToolPolicyMap`].
    #[must_use]
    pub const fn policy_map(&self) -> &ToolPolicyMap {
        &self.policy_map
    }

    /// Returns the pre-compiled static [`VerifiedFacts`] for `tool_name`, if admitted.
    #[must_use]
    pub fn static_facts_for(&self, tool_name: &str) -> Option<&VerifiedFacts> {
        self.static_facts.get(tool_name)
    }

    /// Maps an MCP `tools/call` invocation using pre-validated policies and pre-compiled static
    /// facts.
    pub fn map_call_exact(
        &self,
        actor_key: &KeyId,
        tool_name: &str,
        arguments: Option<&ExactJson>,
    ) -> Result<(ActionRequest, VerifiedFacts), MappingError> {
        let (Some(policy), Some(static_facts)) = (
            self.policy_map.tools.get(tool_name),
            self.static_facts.get(tool_name),
        ) else {
            return Err(MappingError::UnmappedTool(tool_name.to_string()));
        };
        map_policy_call(actor_key, tool_name, policy, arguments, static_facts)
    }
}

impl ToolPolicyMap {
    /// Parses and validates a [`ToolPolicyMap`] in a single pass via `ExactJson`, rejecting
    /// duplicate keys without double-parsing.
    pub fn from_json_str(raw: &str) -> Result<Self, MappingError> {
        let parsed =
            parse_exact_json(raw).map_err(|err| MappingError::InvalidJson(err.to_string()))?;
        let map = policy_decode::decode_tool_policy_map(&parsed)?;
        map.validate()?;
        Ok(map)
    }

    /// Validates every tool policy and seals pre-compiled static [`VerifiedFacts`] into a
    /// [`CompiledPolicyMap`].
    pub fn compile(self) -> Result<CompiledPolicyMap, MappingError> {
        self.validate()?;
        let mut static_facts = BTreeMap::new();
        for (tool_name, policy) in &self.tools {
            static_facts.insert(tool_name.clone(), policy.static_verified_facts()?);
        }
        Ok(CompiledPolicyMap {
            policy_map: self,
            static_facts,
        })
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
            Some(raw) => Some(
                parse_exact_json(raw).map_err(|err| MappingError::InvalidJson(err.to_string()))?,
            ),
            None => None,
        };
        self.map_call_exact(actor_key, tool_name, parsed.as_ref())
    }

    pub fn map_call_exact(
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
        let static_facts = policy.static_verified_facts()?;
        map_policy_call(actor_key, tool_name, policy, arguments, &static_facts)
    }
}

enum ResourceIdResolution<'a> {
    Resolved(&'a str),
    ControlChars { arg: &'a str, raw: &'a str },
    NotAString { arg: &'a str },
    Missing { arg: &'a str },
    Unconfigured,
}

fn inspect_resource_id<'a>(
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
pub fn denial_resource_id(policy: &ToolPolicy, arguments: Option<&ExactJson>) -> String {
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

fn map_policy_call(
    actor_key: &KeyId,
    tool_name: &str,
    policy: &ToolPolicy,
    arguments: Option<&ExactJson>,
    static_facts: &VerifiedFacts,
) -> Result<(ActionRequest, VerifiedFacts), MappingError> {
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
    let facts = build_verified_facts(tool_name, policy, args_map, static_facts)?;

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

fn build_verified_facts(
    tool_name: &str,
    policy: &ToolPolicy,
    args_map: &BTreeMap<String, ExactJson>,
    static_facts: &VerifiedFacts,
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
    for (field, scalar) in &static_facts.0 {
        facts.insert(field.clone(), scalar.clone());
    }

    Ok(facts)
}

/// Parses and validates a lossless [`ExactJson`] scalar against `expected`.
pub fn parse_json_fact_scalar(
    expected: FactType,
    value: &ExactJson,
) -> Result<Scalar, MappingError> {
    parse_json_fact_scalar_detail(expected, value).map_err(MappingError::InvalidJson)
}

fn parse_arg_scalar(
    tool_name: &str,
    arg_key: &str,
    expected: FactType,
    value: &ExactJson,
) -> Result<Scalar, MappingError> {
    parse_json_fact_scalar_detail(expected, value)
        .map_err(|detail| invalid_arg(tool_name, arg_key, &detail))
}

fn parse_json_fact_scalar_detail(expected: FactType, value: &ExactJson) -> Result<Scalar, String> {
    let scalar = match (expected, value) {
        (FactType::Str, ExactJson::Str(s)) => {
            if !is_valid_quoted_str(s) {
                return Err("string must not contain control characters".to_string());
            }
            Scalar::Str(s.clone())
        }
        (FactType::Bool, ExactJson::Bool(b)) => Scalar::Bool(*b),
        (FactType::Int, ExactJson::Number(raw)) => {
            let parsed = parse_canonical_json_int(raw.as_str()).ok_or_else(|| {
                if is_canonical_json_int_syntax(raw.as_str()) {
                    "integer outside 64-bit range".to_string()
                } else {
                    "expected 64-bit signed integer".to_string()
                }
            })?;
            Scalar::Int(parsed)
        }
        (FactType::Decimal, ExactJson::Number(raw)) => {
            let dec = parse_json_decimal(raw.as_str())
                .map_err(|err| format!("invalid decimal: {err}"))?;
            Scalar::Decimal(dec)
        }
        (FactType::Decimal, ExactJson::Str(raw)) => {
            let dec = parse_decimal_str(raw).map_err(|err| format!("invalid decimal: {err}"))?;
            Scalar::Decimal(dec)
        }
        (FactType::Timestamp, ExactJson::Str(raw)) => {
            let ts = parse_rfc3339_utc(raw)
                .map_err(|err| format!("invalid RFC 3339 UTC timestamp: {err}"))?;
            Scalar::Timestamp(ts)
        }
        _ => {
            return Err(format!("expected {expected:?}"));
        }
    };

    scalar.validate().map_err(|err| err.to_string())?;
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
    validate_json_keys_recursive(args_val).map_err(|err| match err {
        JsonKeyError::NonAscii(key) => MappingError::NonAsciiArgumentKey {
            tool: tool_name.to_string(),
            key: key.to_string(),
        },
        JsonKeyError::CaseCollision {
            existing,
            colliding,
        } => MappingError::CaseCollidingArgumentKey {
            tool: tool_name.to_string(),
            key: colliding.to_string(),
            collides_with: existing.to_string(),
        },
    })?;
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

fn is_valid_concrete_action(action: &str) -> bool {
    ActionPat::parse(action).is_ok_and(|pat| !pat.is_wildcard())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
