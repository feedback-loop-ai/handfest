//! Direct single-pass decoding of [`ToolPolicyMap`] from a duplicate-checked [`ExactJson`] AST.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use crate::ast::parse_rfc3339_utc;
use crate::exact_json::{reject_unknown_keys, ExactJson};
use crate::json_num::{parse_canonical_json_int, parse_decimal_str};
use crate::policy::{FactSpec, FactType, MappingError, ToolPolicy, ToolPolicyMap, TypedScalar};

/// Decodes a [`ToolPolicyMap`] directly from a pre-parsed, duplicate-checked [`ExactJson`] tree.
pub(super) fn decode_tool_policy_map(root: &ExactJson) -> Result<ToolPolicyMap, MappingError> {
    let obj = expect_object(root, "policy map root")?;
    reject_unknown_keys(obj, &["tools"], "policy map root").map_err(MappingError::InvalidJson)?;
    let tools_val = obj
        .get("tools")
        .ok_or_else(|| MappingError::InvalidJson("missing required field 'tools'".to_string()))?;
    let tools_obj = expect_object(tools_val, "field 'tools'")?;
    let mut tools = BTreeMap::new();
    for (tool_name, policy_val) in tools_obj {
        tools.insert(
            tool_name.clone(),
            decode_tool_policy(tool_name, policy_val)?,
        );
    }
    Ok(ToolPolicyMap { tools })
}

fn decode_tool_policy(tool_name: &str, value: &ExactJson) -> Result<ToolPolicy, MappingError> {
    let ctx = format!("tool '{tool_name}'");
    let obj = expect_object(value, &ctx)?;
    reject_unknown_keys(
        obj,
        &[
            "action",
            "resource_kind",
            "resource_id_arg",
            "static_resource_id",
            "arg_facts",
            "static_facts",
        ],
        &ctx,
    )
    .map_err(MappingError::InvalidJson)?;

    let action = expect_required_str(obj, "action", &ctx)?;
    let resource_kind = expect_required_str(obj, "resource_kind", &ctx)?;
    let resource_id_arg = expect_optional_str(obj, "resource_id_arg", &ctx)?;
    let static_resource_id = expect_optional_str(obj, "static_resource_id", &ctx)?;

    let arg_facts = match obj.get("arg_facts") {
        None => BTreeMap::new(),
        Some(val) => decode_arg_facts(tool_name, val)?,
    };
    let static_facts = match obj.get("static_facts") {
        None => BTreeMap::new(),
        Some(val) => decode_static_facts(tool_name, val)?,
    };

    Ok(ToolPolicy {
        action,
        resource_kind,
        resource_id_arg,
        static_resource_id,
        arg_facts,
        static_facts,
    })
}

fn decode_arg_facts(
    tool_name: &str,
    value: &ExactJson,
) -> Result<BTreeMap<String, FactSpec>, MappingError> {
    let obj = expect_object(value, &format!("tool '{tool_name}'.arg_facts"))?;
    let mut out = BTreeMap::new();
    for (arg_key, spec_val) in obj {
        let ctx = format!("tool '{tool_name}'.arg_facts['{arg_key}']");
        let spec_obj = expect_object(spec_val, &ctx)?;
        reject_unknown_keys(spec_obj, &["field", "type"], &ctx)
            .map_err(MappingError::InvalidJson)?;
        let field = expect_required_str(spec_obj, "field", &ctx)?;
        let raw_type = expect_required_str(spec_obj, "type", &ctx)?;
        let fact_type = decode_fact_type(&raw_type, &ctx)?;
        out.insert(arg_key.clone(), FactSpec { field, fact_type });
    }
    Ok(out)
}

fn decode_fact_type(raw: &str, ctx: &str) -> Result<FactType, MappingError> {
    match raw {
        "str" | "Str" => Ok(FactType::Str),
        "int" | "Int" => Ok(FactType::Int),
        "decimal" | "Decimal" => Ok(FactType::Decimal),
        "bool" | "Bool" => Ok(FactType::Bool),
        "timestamp" | "Timestamp" => Ok(FactType::Timestamp),
        other => Err(MappingError::InvalidJson(format!(
            "{ctx}: unknown fact type '{other}'"
        ))),
    }
}

fn decode_static_facts(
    tool_name: &str,
    value: &ExactJson,
) -> Result<BTreeMap<String, TypedScalar>, MappingError> {
    let obj = expect_object(value, &format!("tool '{tool_name}'.static_facts"))?;
    let mut out = BTreeMap::new();
    for (field, scalar_val) in obj {
        let ctx = format!("tool '{tool_name}'.static_facts['{field}']");
        out.insert(field.clone(), decode_typed_scalar(scalar_val, &ctx)?);
    }
    Ok(out)
}

fn decode_typed_scalar(value: &ExactJson, ctx: &str) -> Result<TypedScalar, MappingError> {
    let obj = expect_object(value, ctx)?;
    let mut entries = obj.iter();
    let (Some((tag, inner)), None) = (entries.next(), entries.next()) else {
        return Err(MappingError::InvalidJson(format!(
            "{ctx}: typed scalar must be a single-key JSON object"
        )));
    };
    match tag.as_str() {
        "str" | "Str" => decode_str_scalar(tag, inner, ctx),
        "int" | "Int" => decode_int_scalar(tag, inner, ctx),
        "decimal" | "Decimal" => decode_decimal_scalar(tag, inner, ctx),
        "bool" | "Bool" => decode_bool_scalar(tag, inner, ctx),
        "timestamp" | "Timestamp" => decode_timestamp_scalar(tag, inner, ctx),
        other => Err(MappingError::InvalidJson(format!(
            "{ctx}: unknown static scalar tag '{other}'"
        ))),
    }
}

fn decode_str_scalar(tag: &str, inner: &ExactJson, ctx: &str) -> Result<TypedScalar, MappingError> {
    inner
        .as_str()
        .map(|s| TypedScalar::Str(s.to_string()))
        .ok_or_else(|| MappingError::InvalidJson(format!("{ctx}: '{tag}' expects a JSON string")))
}

fn decode_int_scalar(tag: &str, inner: &ExactJson, ctx: &str) -> Result<TypedScalar, MappingError> {
    let ExactJson::Number(num) = inner else {
        return Err(MappingError::InvalidJson(format!(
            "{ctx}: '{tag}' expects a JSON integer"
        )));
    };
    parse_canonical_json_int(num.as_str())
        .map(TypedScalar::Int)
        .ok_or_else(|| {
            MappingError::InvalidJson(format!("{ctx}: invalid static int '{}'", num.as_str()))
        })
}

fn decode_decimal_scalar(
    tag: &str,
    inner: &ExactJson,
    ctx: &str,
) -> Result<TypedScalar, MappingError> {
    let Some(raw) = inner.as_str() else {
        return Err(MappingError::InvalidJson(format!(
            "{ctx}: '{tag}' expects a JSON string"
        )));
    };
    parse_decimal_str(raw)
        .map(TypedScalar::Decimal)
        .map_err(|err| {
            MappingError::InvalidJson(format!("{ctx}: invalid static decimal '{raw}': {err}"))
        })
}

fn decode_bool_scalar(
    tag: &str,
    inner: &ExactJson,
    ctx: &str,
) -> Result<TypedScalar, MappingError> {
    let ExactJson::Bool(b) = inner else {
        return Err(MappingError::InvalidJson(format!(
            "{ctx}: '{tag}' expects a JSON boolean"
        )));
    };
    Ok(TypedScalar::Bool(*b))
}

fn decode_timestamp_scalar(
    tag: &str,
    inner: &ExactJson,
    ctx: &str,
) -> Result<TypedScalar, MappingError> {
    let Some(raw) = inner.as_str() else {
        return Err(MappingError::InvalidJson(format!(
            "{ctx}: '{tag}' expects a JSON string"
        )));
    };
    parse_rfc3339_utc(raw)
        .map(TypedScalar::Timestamp)
        .map_err(|err| {
            MappingError::InvalidJson(format!("{ctx}: invalid static timestamp '{raw}': {err}"))
        })
}

fn expect_object<'a>(
    value: &'a ExactJson,
    ctx: &str,
) -> Result<&'a BTreeMap<String, ExactJson>, MappingError> {
    value
        .as_object()
        .ok_or_else(|| MappingError::InvalidJson(format!("{ctx}: expected a JSON object")))
}

fn expect_required_str(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<String, MappingError> {
    let val = obj.get(field).ok_or_else(|| {
        MappingError::InvalidJson(format!("{ctx}: missing required field '{field}'"))
    })?;
    val.as_str().map(str::to_string).ok_or_else(|| {
        MappingError::InvalidJson(format!("{ctx}: field '{field}' must be a JSON string"))
    })
}

fn expect_optional_str(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<Option<String>, MappingError> {
    match obj.get(field) {
        None | Some(ExactJson::Null) => Ok(None),
        Some(ExactJson::Str(s)) => Ok(Some(s.clone())),
        Some(_) => Err(MappingError::InvalidJson(format!(
            "{ctx}: field '{field}' must be a JSON string or null"
        ))),
    }
}
