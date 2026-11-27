//! Single-pass decoding of [`CliPolicyMap`] from a duplicate-checked [`ExactJson`] AST.

use std::collections::BTreeMap;
use std::path::PathBuf;

use handfest_core::exact_json::{reject_unknown_keys, ExactJson};
use handfest_core::policy::{decode_fact_type, decode_static_facts};
use handfest_pep::{decode_credential_source, CredentialSource};

use crate::policy::{CliPolicyMap, CommandPolicy, FlagKind, FlagSpec, PolicyError};

/// Decodes a [`CliPolicyMap`] directly from a pre-parsed, duplicate-checked [`ExactJson`] tree.
pub(crate) fn decode_cli_policy_map(root: &ExactJson) -> Result<CliPolicyMap, PolicyError> {
    let obj = expect_object(root, "CLI policy map root")?;
    reject_unknown_keys(obj, &["commands"], "CLI policy map root")
        .map_err(|err| PolicyError::InvalidJson(err.to_string()))?;
    let cmds_val = obj
        .get("commands")
        .ok_or_else(|| PolicyError::InvalidJson("missing required field 'commands'".to_string()))?;
    let cmds_obj = expect_object(cmds_val, "field 'commands'")?;
    let mut commands = BTreeMap::new();
    for (cmd_name, policy_val) in cmds_obj {
        commands.insert(
            cmd_name.clone(),
            decode_command_policy(cmd_name, policy_val)?,
        );
    }
    Ok(CliPolicyMap { commands })
}

fn decode_command_policy(cmd_name: &str, value: &ExactJson) -> Result<CommandPolicy, PolicyError> {
    let ctx = format!("command '{cmd_name}'");
    let obj = expect_object(value, &ctx)?;
    reject_unknown_keys(
        obj,
        &[
            "executable",
            "fixed_args",
            "action",
            "resource_kind",
            "resource_id_flag",
            "static_resource_id",
            "allowed_flags",
            "static_facts",
            "pass_env",
            "env_secrets",
        ],
        &ctx,
    )
    .map_err(|err| PolicyError::InvalidJson(err.to_string()))?;

    let executable = PathBuf::from(expect_required_str(obj, "executable", &ctx)?);
    let fixed_args = decode_optional_str_array(obj, "fixed_args", &ctx)?;
    let action = expect_required_str(obj, "action", &ctx)?;
    let resource_kind = expect_required_str(obj, "resource_kind", &ctx)?;
    let resource_id_flag = expect_optional_str(obj, "resource_id_flag", &ctx)?;
    let static_resource_id = expect_optional_str(obj, "static_resource_id", &ctx)?;
    let allowed_flags = match obj.get("allowed_flags") {
        None => BTreeMap::new(),
        Some(val) => decode_allowed_flags(cmd_name, val)?,
    };
    let static_facts = match obj.get("static_facts") {
        None => BTreeMap::new(),
        Some(val) => decode_static_facts(val, &format!("command '{cmd_name}'.static_facts"))
            .map_err(|err| PolicyError::InvalidJson(err.to_string()))?,
    };
    let pass_env = decode_optional_str_array(obj, "pass_env", &ctx)?;
    let env_secrets = match obj.get("env_secrets") {
        None => BTreeMap::new(),
        Some(val) => decode_env_secrets(cmd_name, val)?,
    };

    Ok(CommandPolicy {
        executable,
        fixed_args,
        action,
        resource_kind,
        resource_id_flag,
        static_resource_id,
        allowed_flags,
        static_facts,
        pass_env,
        env_secrets,
    })
}

fn decode_allowed_flags(
    cmd_name: &str,
    value: &ExactJson,
) -> Result<BTreeMap<String, FlagSpec>, PolicyError> {
    let obj = expect_object(value, &format!("command '{cmd_name}'.allowed_flags"))?;
    let mut out = BTreeMap::new();
    for (flag_name, spec_val) in obj {
        let ctx = format!("command '{cmd_name}'.allowed_flags['{flag_name}']");
        let spec_obj = expect_object(spec_val, &ctx)?;
        reject_unknown_keys(spec_obj, &["kind", "fact_field", "required"], &ctx)
            .map_err(|err| PolicyError::InvalidJson(err.to_string()))?;
        let kind_val = spec_obj.get("kind").ok_or_else(|| {
            PolicyError::InvalidJson(format!("{ctx}: missing required field 'kind'"))
        })?;
        let kind = decode_flag_kind(kind_val, &ctx)?;
        let fact_field = expect_optional_str(spec_obj, "fact_field", &ctx)?;
        let required = expect_optional_bool(spec_obj, "required", &ctx)?;
        out.insert(
            flag_name.clone(),
            FlagSpec {
                kind,
                fact_field,
                required,
            },
        );
    }
    Ok(out)
}

fn decode_flag_kind(value: &ExactJson, ctx: &str) -> Result<FlagKind, PolicyError> {
    match value {
        ExactJson::Str(s) if s == "bool_switch" => Ok(FlagKind::BoolSwitch),
        ExactJson::Object(obj) => {
            let mut entries = obj.iter();
            let (Some((tag, inner)), None) = (entries.next(), entries.next()) else {
                return Err(PolicyError::InvalidJson(format!(
                    "{ctx}.kind: expected 'bool_switch' or {{\"value\": \"<type>\"}}"
                )));
            };
            if tag != "value" {
                return Err(PolicyError::InvalidJson(format!(
                    "{ctx}.kind: unknown flag kind tag '{tag}'"
                )));
            }
            let Some(raw_type) = inner.as_str() else {
                return Err(PolicyError::InvalidJson(format!(
                    "{ctx}.kind: 'value' expects a fact type string"
                )));
            };
            Ok(FlagKind::Value(decode_fact_type(raw_type, ctx).map_err(
                |err| PolicyError::InvalidJson(err.to_string()),
            )?))
        }
        _ => Err(PolicyError::InvalidJson(format!(
            "{ctx}.kind: expected 'bool_switch' or {{\"value\": \"<type>\"}}"
        ))),
    }
}

fn decode_env_secrets(
    cmd_name: &str,
    value: &ExactJson,
) -> Result<BTreeMap<String, CredentialSource>, PolicyError> {
    let obj = expect_object(value, &format!("command '{cmd_name}'.env_secrets"))?;
    let mut out = BTreeMap::new();
    for (env_var, src_val) in obj {
        let ctx = format!("command '{cmd_name}'.env_secrets['{env_var}']");
        let src = decode_credential_source(src_val, &ctx).map_err(PolicyError::InvalidJson)?;
        out.insert(env_var.clone(), src);
    }
    Ok(out)
}

fn expect_object<'a>(
    value: &'a ExactJson,
    ctx: &str,
) -> Result<&'a BTreeMap<String, ExactJson>, PolicyError> {
    value
        .as_object()
        .ok_or_else(|| PolicyError::InvalidJson(format!("{ctx}: expected a JSON object")))
}

fn expect_required_str(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<String, PolicyError> {
    let val = obj.get(field).ok_or_else(|| {
        PolicyError::InvalidJson(format!("{ctx}: missing required field '{field}'"))
    })?;
    val.as_str().map(str::to_string).ok_or_else(|| {
        PolicyError::InvalidJson(format!("{ctx}: field '{field}' must be a JSON string"))
    })
}

fn expect_optional_str(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<Option<String>, PolicyError> {
    match obj.get(field) {
        None | Some(ExactJson::Null) => Ok(None),
        Some(ExactJson::Str(s)) => Ok(Some(s.clone())),
        Some(_) => Err(PolicyError::InvalidJson(format!(
            "{ctx}: field '{field}' must be a JSON string or null"
        ))),
    }
}

fn expect_optional_bool(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<bool, PolicyError> {
    match obj.get(field) {
        None => Ok(false),
        Some(ExactJson::Bool(b)) => Ok(*b),
        Some(_) => Err(PolicyError::InvalidJson(format!(
            "{ctx}: field '{field}' must be a JSON boolean"
        ))),
    }
}

fn decode_optional_str_array(
    obj: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<Vec<String>, PolicyError> {
    let Some(val) = obj.get(field) else {
        return Ok(Vec::new());
    };
    let ExactJson::Array(items) = val else {
        return Err(PolicyError::InvalidJson(format!(
            "{ctx}: field '{field}' must be a JSON array of strings"
        )));
    };
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let Some(s) = item.as_str() else {
            return Err(PolicyError::InvalidJson(format!(
                "{ctx}: field '{field}[{idx}]' must be a JSON string"
            )));
        };
        out.push(s.to_string());
    }
    Ok(out)
}
