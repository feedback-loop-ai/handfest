//! Declarative, fail-closed `CliPolicyMap` schema, validation, and compilation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use handfest_core::ast::{is_valid_field_path, is_valid_ident, is_valid_quoted_str, ActionPat};
use handfest_core::exact_json::parse_exact_json;
use handfest_core::gate::VerifiedFacts;
use handfest_core::policy::{deserialize_unique_btreemap, FactType, TypedScalar};
use handfest_pep::{is_valid_env_var_name, validate_absolute_clean_path, CredentialSource};
use serde::{Deserialize, Serialize};

use crate::policy_decode::decode_cli_policy_map;

/// Expected CLI flag kind in [`CommandPolicy::allowed_flags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    /// Flag accepting a typed scalar value (`--flag=value` or `--flag value`).
    Value(FactType),
    /// Bare boolean switch (`--flag`, taking no value).
    BoolSwitch,
}

/// Allowlist entry describing one permitted `--flag` for a wrapped CLI command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagSpec {
    pub kind: FlagKind,
    #[serde(default)]
    pub fact_field: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Declarative execution and authorization policy for one logical CLI command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPolicy {
    pub executable: PathBuf,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    pub action: String,
    pub resource_kind: String,
    #[serde(default)]
    pub resource_id_flag: Option<String>,
    #[serde(default)]
    pub static_resource_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub allowed_flags: BTreeMap<String, FlagSpec>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub static_facts: BTreeMap<String, TypedScalar>,
    #[serde(default)]
    pub pass_env: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub env_secrets: BTreeMap<String, CredentialSource>,
}

/// Root JSON configuration mapping logical command names to [`CommandPolicy`] definitions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliPolicyMap {
    #[serde(deserialize_with = "deserialize_unique_btreemap")]
    pub commands: BTreeMap<String, CommandPolicy>,
}

/// Errors produced when loading, decoding, validating, or compiling a [`CliPolicyMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Io(String),
    InvalidJson(String),
    InvalidPolicy(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "CLI policy map I/O error: {msg}"),
            Self::InvalidJson(msg) => write!(f, "invalid CLI policy map JSON: {msg}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid CLI policy map: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Validated [`CliPolicyMap`] paired with pre-compiled static [`VerifiedFacts`] per command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCliPolicyMap {
    policy_map: CliPolicyMap,
    static_facts: BTreeMap<String, VerifiedFacts>,
}

impl CompiledCliPolicyMap {
    /// Borrows the validated underlying [`CliPolicyMap`].
    #[must_use]
    pub const fn policy_map(&self) -> &CliPolicyMap {
        &self.policy_map
    }

    /// Returns the validated [`CommandPolicy`] for `command_name`, if admitted.
    #[must_use]
    pub fn get(&self, command_name: &str) -> Option<&CommandPolicy> {
        self.policy_map.commands.get(command_name)
    }

    /// Returns pre-compiled static [`VerifiedFacts`] for `command_name`, if admitted.
    #[must_use]
    pub fn static_facts_for(&self, command_name: &str) -> Option<&VerifiedFacts> {
        self.static_facts.get(command_name)
    }
}

/// Loads, decodes (via single-pass `ExactJson`), and validates a [`CliPolicyMap`] from disk.
pub fn load_cli_policy_map_file(path: impl AsRef<Path>) -> Result<CliPolicyMap, PolicyError> {
    let path_ref = path.as_ref();
    let raw = fs::read_to_string(path_ref).map_err(|err| {
        PolicyError::Io(format!("failed to read '{}': {err}", path_ref.display()))
    })?;
    CliPolicyMap::from_json_str(&raw)
}

impl CliPolicyMap {
    /// Parses and validates a [`CliPolicyMap`] in a single pass via `ExactJson`, rejecting
    /// duplicate keys, unknown fields, and control characters.
    pub fn from_json_str(raw: &str) -> Result<Self, PolicyError> {
        let parsed =
            parse_exact_json(raw).map_err(|err| PolicyError::InvalidJson(err.to_string()))?;
        let map = decode_cli_policy_map(&parsed)?;
        map.validate()?;
        Ok(map)
    }

    /// Validates every command policy in this map.
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (command_name, policy) in &self.commands {
            policy.validate(command_name)?;
        }
        Ok(())
    }

    /// Validates every command policy and seals pre-compiled static [`VerifiedFacts`] into a
    /// [`CompiledCliPolicyMap`].
    pub fn compile(self) -> Result<CompiledCliPolicyMap, PolicyError> {
        self.validate()?;
        let mut static_facts = BTreeMap::new();
        for (command_name, policy) in &self.commands {
            static_facts.insert(command_name.clone(), policy.static_verified_facts()?);
        }
        Ok(CompiledCliPolicyMap {
            policy_map: self,
            static_facts,
        })
    }

    /// Returns the policy configured for `command_name`, if admitted.
    #[must_use]
    pub fn get(&self, command_name: &str) -> Option<&CommandPolicy> {
        self.commands.get(command_name)
    }
}

impl CommandPolicy {
    /// Validates all static security invariants for this command policy.
    pub fn validate(&self, command_name: &str) -> Result<(), PolicyError> {
        validate_command_name(command_name)?;
        self.validate_executable(command_name)?;
        self.validate_fixed_args(command_name)?;
        self.validate_action_and_kind(command_name)?;
        self.validate_allowed_flags(command_name)?;
        self.validate_resource_id_source(command_name)?;
        self.validate_static_facts(command_name)?;
        self.validate_env_and_secrets(command_name)
    }

    fn validate_executable(&self, command_name: &str) -> Result<(), PolicyError> {
        validate_absolute_clean_path(
            &self.executable,
            &format!("command '{command_name}': executable"),
        )
        .map_err(PolicyError::InvalidPolicy)
    }

    fn validate_fixed_args(&self, command_name: &str) -> Result<(), PolicyError> {
        for (idx, arg) in self.fixed_args.iter().enumerate() {
            if !is_valid_quoted_str(arg) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': fixed_args[{idx}] must not contain control characters"
                )));
            }
            if arg == "--" {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': fixed_args[{idx}] must not be '--'"
                )));
            }
            if arg.starts_with("--") {
                let flag_name = arg.split_once('=').map_or(arg.as_str(), |(k, _)| k);
                if self
                    .allowed_flags
                    .keys()
                    .any(|allowed| allowed.eq_ignore_ascii_case(flag_name))
                {
                    return Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': fixed_args[{idx}] flag '{flag_name}' cannot also be in allowed_flags"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_action_and_kind(&self, command_name: &str) -> Result<(), PolicyError> {
        if !is_valid_concrete_action(&self.action) {
            return Err(PolicyError::InvalidPolicy(format!(
                "command '{command_name}': invalid concrete action '{}'",
                self.action
            )));
        }
        if !is_valid_ident(&self.resource_kind) {
            return Err(PolicyError::InvalidPolicy(format!(
                "command '{command_name}': invalid resource_kind '{}'",
                self.resource_kind
            )));
        }
        Ok(())
    }

    fn validate_allowed_flags(&self, command_name: &str) -> Result<(), PolicyError> {
        let mut folded_flags: BTreeMap<String, &str> = BTreeMap::new();
        let mut target_fields: BTreeSet<&str> = BTreeSet::new();

        for (flag, spec) in &self.allowed_flags {
            if !is_valid_flag_name(flag) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': invalid allowed_flags key '{flag}'"
                )));
            }
            if let Some(prev) = folded_flags.insert(flag.to_ascii_lowercase(), flag.as_str()) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': flag '{flag}' collides case-insensitively with '{prev}'"
                )));
            }
            if let Some(field) = spec.fact_field.as_deref() {
                if !is_valid_field_path(field) {
                    return Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': flag '{flag}' has invalid fact_field '{field}'"
                    )));
                }
                if !target_fields.insert(field) {
                    return Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': duplicate flag target fact_field '{field}'"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_resource_id_source(&self, command_name: &str) -> Result<(), PolicyError> {
        match (&self.resource_id_flag, &self.static_resource_id) {
            (Some(flag), None) => {
                if !is_valid_flag_name(flag) {
                    return Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': invalid resource_id_flag '{flag}'"
                    )));
                }
                match self.allowed_flags.get(flag) {
                    Some(FlagSpec {
                        kind: FlagKind::Value(_),
                        ..
                    }) => Ok(()),
                    Some(FlagSpec {
                        kind: FlagKind::BoolSwitch,
                        ..
                    }) => Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': resource_id_flag '{flag}' cannot be a bool_switch"
                    ))),
                    None => Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': resource_id_flag '{flag}' must be declared in allowed_flags"
                    ))),
                }
            }
            (None, Some(static_id)) => {
                if !is_valid_quoted_str(static_id) {
                    return Err(PolicyError::InvalidPolicy(format!(
                        "command '{command_name}': static_resource_id must not contain control characters"
                    )));
                }
                Ok(())
            }
            (None, None) => Err(PolicyError::InvalidPolicy(format!(
                "command '{command_name}': must declare either resource_id_flag or static_resource_id"
            ))),
            (Some(_), Some(_)) => Err(PolicyError::InvalidPolicy(format!(
                "command '{command_name}': cannot declare both resource_id_flag and static_resource_id"
            ))),
        }
    }

    fn validate_static_facts(&self, command_name: &str) -> Result<(), PolicyError> {
        for (field, value) in &self.static_facts {
            if !is_valid_field_path(field) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': invalid static_facts field path '{field}'"
                )));
            }
            let _ = value.to_scalar().map_err(|err| {
                PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': static fact '{field}': {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn validate_env_and_secrets(&self, command_name: &str) -> Result<(), PolicyError> {
        let mut seen_pass_env: BTreeSet<&str> = BTreeSet::new();
        for var in &self.pass_env {
            if !is_valid_env_var_name(var) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': invalid pass_env variable name '{var}'"
                )));
            }
            if !seen_pass_env.insert(var.as_str()) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': duplicate pass_env variable '{var}'"
                )));
            }
        }

        for (var, source) in &self.env_secrets {
            if !is_valid_env_var_name(var) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': invalid env_secrets variable name '{var}'"
                )));
            }
            if seen_pass_env.contains(var.as_str()) {
                return Err(PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': variable '{var}' cannot appear in both pass_env and env_secrets"
                )));
            }
            source.validate().map_err(|err| {
                PolicyError::InvalidPolicy(format!(
                    "command '{command_name}': env_secrets['{var}']: {err}"
                ))
            })?;
        }
        Ok(())
    }

    /// Builds [`VerifiedFacts`] from this policy's static facts (excluding `context.time`, which
    /// is always sourced from the runtime `Clock`).
    pub(crate) fn static_verified_facts(&self) -> Result<VerifiedFacts, PolicyError> {
        let mut facts = VerifiedFacts::new();
        for (field, typed) in &self.static_facts {
            let scalar = typed.to_scalar().map_err(|err| {
                PolicyError::InvalidPolicy(format!("static fact '{field}': {err}"))
            })?;
            if field != "context.time" {
                facts.insert(field.clone(), scalar);
            }
        }
        Ok(facts)
    }
}

fn validate_command_name(command_name: &str) -> Result<(), PolicyError> {
    if command_name.is_empty() {
        return Err(PolicyError::InvalidPolicy(
            "command name must not be empty".to_string(),
        ));
    }
    if !is_valid_quoted_str(command_name) {
        return Err(PolicyError::InvalidPolicy(
            "command name must not contain control characters".to_string(),
        ));
    }
    Ok(())
}

fn is_valid_concrete_action(action: &str) -> bool {
    ActionPat::parse(action).is_ok_and(|pat| !pat.is_wildcard())
}

pub(crate) fn is_valid_flag_name(flag: &str) -> bool {
    let Some(rest) = flag.strip_prefix("--") else {
        return false;
    };
    let mut bytes = rest.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
