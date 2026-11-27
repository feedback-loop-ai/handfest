//! Strict fail-closed CLI argv parser and mapper to `HANDFEST v1` requests and facts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use handfest_core::ast::{is_valid_quoted_str, KeyId, Scalar};
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::policy::{parse_text_scalar, FactType};

use crate::policy::{CommandPolicy, CompiledCliPolicyMap, FlagKind, FlagSpec};

/// Validated, mapped CLI invocation ready for authorization and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedCommand {
    pub request: ActionRequest,
    pub facts: VerifiedFacts,
    /// Validated caller argv tokens to append strictly after `CommandPolicy::fixed_args`.
    pub validated_argv: Vec<String>,
}

/// Typed, fail-closed errors returned when mapping a command invocation's argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgvError {
    UnmappedCommand(String),
    ControlCharacter {
        command: String,
        arg_index: usize,
    },
    SeparatorSmuggling {
        command: String,
    },
    PositionalOrUnsupportedArg {
        command: String,
        arg: String,
    },
    NonAsciiFlag {
        command: String,
        flag: String,
    },
    CaseCollidingFlag {
        command: String,
        flag: String,
        collides_with: String,
    },
    UnknownFlag {
        command: String,
        flag: String,
    },
    DuplicateFlag {
        command: String,
        flag: String,
    },
    UnexpectedFlagValue {
        command: String,
        flag: String,
    },
    MissingFlagValue {
        command: String,
        flag: String,
    },
    InvalidFlagValue {
        command: String,
        flag: String,
        detail: String,
    },
    MissingRequiredFlag {
        command: String,
        flag: String,
    },
    MissingResourceId {
        command: String,
        flag: String,
    },
}

impl fmt::Display for ArgvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmappedCommand(cmd) => write!(f, "unmapped CLI command '{cmd}'"),
            Self::ControlCharacter { command, arg_index } => write!(
                f,
                "command '{command}': argument at index {arg_index} contains control characters"
            ),
            Self::SeparatorSmuggling { command } => {
                write!(f, "command '{command}': '--' separator smuggling is forbidden")
            }
            Self::PositionalOrUnsupportedArg { command, arg } => write!(
                f,
                "command '{command}': positional or non-'--' argument '{arg}' is forbidden"
            ),
            Self::NonAsciiFlag { command, flag } => {
                write!(f, "command '{command}': flag '{flag}' must be ASCII")
            }
            Self::CaseCollidingFlag {
                command,
                flag,
                collides_with,
            } => write!(
                f,
                "command '{command}': flag '{flag}' collides case-insensitively with '{collides_with}'"
            ),
            Self::UnknownFlag { command, flag } => {
                write!(f, "command '{command}': unknown flag '{flag}'")
            }
            Self::DuplicateFlag { command, flag } => {
                write!(f, "command '{command}': duplicate flag '{flag}'")
            }
            Self::UnexpectedFlagValue { command, flag } => write!(
                f,
                "command '{command}': bool_switch flag '{flag}' does not accept a value"
            ),
            Self::MissingFlagValue { command, flag } => {
                write!(f, "command '{command}': flag '{flag}' requires a value")
            }
            Self::InvalidFlagValue {
                command,
                flag,
                detail,
            } => write!(
                f,
                "command '{command}': invalid value for flag '{flag}': {detail}"
            ),
            Self::MissingRequiredFlag { command, flag } => {
                write!(f, "command '{command}': missing required flag '{flag}'")
            }
            Self::MissingResourceId { command, flag } => write!(
                f,
                "command '{command}': missing required resource_id flag '{flag}'"
            ),
        }
    }
}

impl std::error::Error for ArgvError {}

/// Parses and validates `raw_args` for `command_name` against `policy_map`, producing an
/// [`ActionRequest`], [`VerifiedFacts`], and validated argv tokens to append after `fixed_args`.
pub fn parse_and_map_argv(
    policy_map: &CompiledCliPolicyMap,
    actor_key: &KeyId,
    command_name: &str,
    raw_args: &[String],
) -> Result<MappedCommand, ArgvError> {
    let (Some(policy), Some(static_facts)) = (
        policy_map.get(command_name),
        policy_map.static_facts_for(command_name),
    ) else {
        return Err(ArgvError::UnmappedCommand(command_name.to_string()));
    };

    let parsed = parse_flags(command_name, policy, raw_args)?;
    let resource_id = resolve_resource_id(command_name, policy, &parsed.flag_values)?;
    check_required_flags(command_name, policy, &parsed.seen_flags)?;
    let facts = build_verified_facts(policy, &parsed, static_facts);

    Ok(MappedCommand {
        request: ActionRequest {
            actor_key: actor_key.clone(),
            action: policy.action.clone(),
            resource_kind: policy.resource_kind.clone(),
            resource_id,
        },
        facts,
        validated_argv: parsed.validated_argv,
    })
}

/// Resolves an honest `resource_id` for a pre-gate denial receipt on a mapped command.
///
/// Static IDs and unambiguously parsed caller-supplied `resource_id_flag` values are preserved
/// verbatim; any malformed, unknown, case-colliding, or duplicated flag or invalid value token
/// yields `""` rather than risking spoofed audit attribution.
#[must_use]
pub fn denial_resource_id(policy: &CommandPolicy, raw_args: &[String]) -> String {
    if let Some(static_id) = &policy.static_resource_id {
        return static_id.clone();
    }
    let Some(target_flag) = policy.resource_id_flag.as_deref() else {
        return String::new();
    };
    let Ok(parsed) = parse_flags("", policy, raw_args) else {
        return String::new();
    };
    parsed
        .flag_values
        .get(target_flag)
        .cloned()
        .unwrap_or_default()
}

fn is_negative_number_token(token: &str) -> bool {
    token
        .strip_prefix('-')
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
}

fn is_allowed_flag_value_token(token: &str, fact_type: FactType) -> bool {
    let allow_negative_num =
        matches!(fact_type, FactType::Int | FactType::Decimal) && is_negative_number_token(token);
    !token.starts_with('-') || allow_negative_num
}

struct ParsedFlags {
    seen_flags: BTreeSet<String>,
    flag_values: BTreeMap<String, String>,
    parsed_scalars: BTreeMap<String, Scalar>,
    validated_argv: Vec<String>,
}

fn parse_flags(
    command_name: &str,
    policy: &CommandPolicy,
    raw_args: &[String],
) -> Result<ParsedFlags, ArgvError> {
    let mut state = ParsedFlags {
        seen_flags: BTreeSet::new(),
        flag_values: BTreeMap::new(),
        parsed_scalars: BTreeMap::new(),
        validated_argv: Vec::with_capacity(raw_args.len()),
    };

    let mut idx = 0;
    while idx < raw_args.len() {
        let token = &raw_args[idx];
        if !is_valid_quoted_str(token) {
            return Err(ArgvError::ControlCharacter {
                command: command_name.to_string(),
                arg_index: idx,
            });
        }
        if token == "--" {
            return Err(ArgvError::SeparatorSmuggling {
                command: command_name.to_string(),
            });
        }
        if !token.starts_with("--") {
            return Err(ArgvError::PositionalOrUnsupportedArg {
                command: command_name.to_string(),
                arg: token.clone(),
            });
        }

        let (flag_name, inline_val) = match token.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (token.as_str(), None),
        };
        let spec = lookup_allowed_flag(command_name, policy, flag_name)?;
        if !state.seen_flags.insert(flag_name.to_string()) {
            return Err(ArgvError::DuplicateFlag {
                command: command_name.to_string(),
                flag: flag_name.to_string(),
            });
        }

        idx = consume_flag_value(
            command_name,
            flag_name,
            spec,
            inline_val,
            raw_args,
            idx,
            &mut state,
        )?;
    }

    Ok(state)
}

fn lookup_allowed_flag<'a>(
    command_name: &str,
    policy: &'a CommandPolicy,
    flag_name: &str,
) -> Result<&'a FlagSpec, ArgvError> {
    if !flag_name.is_ascii() {
        return Err(ArgvError::NonAsciiFlag {
            command: command_name.to_string(),
            flag: flag_name.to_string(),
        });
    }
    if let Some(spec) = policy.allowed_flags.get(flag_name) {
        return Ok(spec);
    }
    if let Some(colliding) = policy
        .allowed_flags
        .keys()
        .find(|allowed| allowed.eq_ignore_ascii_case(flag_name))
    {
        return Err(ArgvError::CaseCollidingFlag {
            command: command_name.to_string(),
            flag: flag_name.to_string(),
            collides_with: colliding.clone(),
        });
    }
    Err(ArgvError::UnknownFlag {
        command: command_name.to_string(),
        flag: flag_name.to_string(),
    })
}

fn consume_flag_value(
    command_name: &str,
    flag_name: &str,
    spec: &FlagSpec,
    inline_val: Option<&str>,
    raw_args: &[String],
    idx: usize,
    state: &mut ParsedFlags,
) -> Result<usize, ArgvError> {
    match spec.kind {
        FlagKind::BoolSwitch => {
            if inline_val.is_some() {
                return Err(ArgvError::UnexpectedFlagValue {
                    command: command_name.to_string(),
                    flag: flag_name.to_string(),
                });
            }
            state.validated_argv.push(flag_name.to_string());
            state
                .parsed_scalars
                .insert(flag_name.to_string(), Scalar::Bool(true));
            Ok(idx + 1)
        }
        FlagKind::Value(fact_type) => {
            let (raw_val, next_idx) = match inline_val {
                Some(v) => (v, idx + 1),
                None => {
                    let next =
                        raw_args
                            .get(idx + 1)
                            .ok_or_else(|| ArgvError::MissingFlagValue {
                                command: command_name.to_string(),
                                flag: flag_name.to_string(),
                            })?;
                    if !is_valid_quoted_str(next) {
                        return Err(ArgvError::ControlCharacter {
                            command: command_name.to_string(),
                            arg_index: idx + 1,
                        });
                    }
                    if next == "--" {
                        return Err(ArgvError::SeparatorSmuggling {
                            command: command_name.to_string(),
                        });
                    }
                    if !is_allowed_flag_value_token(next, fact_type) {
                        return Err(ArgvError::MissingFlagValue {
                            command: command_name.to_string(),
                            flag: flag_name.to_string(),
                        });
                    }
                    (next.as_str(), idx + 2)
                }
            };

            let scalar = parse_flag_scalar(command_name, flag_name, fact_type, raw_val)?;
            state
                .flag_values
                .insert(flag_name.to_string(), raw_val.to_string());
            state.parsed_scalars.insert(flag_name.to_string(), scalar);
            // Always emit canonical `--flag=value` so the child CLI cannot misinterpret
            // space-separated values as short flags or positional arguments.
            state.validated_argv.push(format!("{flag_name}={raw_val}"));
            Ok(next_idx)
        }
    }
}

fn parse_flag_scalar(
    command_name: &str,
    flag_name: &str,
    fact_type: FactType,
    raw: &str,
) -> Result<Scalar, ArgvError> {
    parse_text_scalar(fact_type, raw)
        .map_err(|detail| invalid_value(command_name, flag_name, &detail))
}

fn invalid_value(command: &str, flag: &str, detail: &str) -> ArgvError {
    ArgvError::InvalidFlagValue {
        command: command.to_string(),
        flag: flag.to_string(),
        detail: detail.to_string(),
    }
}

fn check_required_flags(
    command_name: &str,
    policy: &CommandPolicy,
    seen_flags: &BTreeSet<String>,
) -> Result<(), ArgvError> {
    for (flag, spec) in &policy.allowed_flags {
        if spec.required && !seen_flags.contains(flag) {
            return Err(ArgvError::MissingRequiredFlag {
                command: command_name.to_string(),
                flag: flag.clone(),
            });
        }
    }
    Ok(())
}

fn resolve_resource_id(
    command_name: &str,
    policy: &CommandPolicy,
    flag_values: &BTreeMap<String, String>,
) -> Result<String, ArgvError> {
    if let Some(flag) = policy.resource_id_flag.as_deref() {
        return flag_values
            .get(flag)
            .cloned()
            .ok_or_else(|| ArgvError::MissingResourceId {
                command: command_name.to_string(),
                flag: flag.to_string(),
            });
    }
    policy
        .static_resource_id
        .clone()
        .ok_or_else(|| ArgvError::MissingResourceId {
            command: command_name.to_string(),
            flag: "<unconfigured>".to_string(),
        })
}

fn build_verified_facts(
    policy: &CommandPolicy,
    parsed: &ParsedFlags,
    static_facts: &VerifiedFacts,
) -> VerifiedFacts {
    let mut facts = VerifiedFacts::new();

    for (flag, spec) in &policy.allowed_flags {
        let Some(field) = spec.fact_field.as_deref() else {
            continue;
        };
        if field == "context.time" {
            continue;
        }
        if let Some(scalar) = parsed.parsed_scalars.get(flag) {
            facts.insert(field.to_string(), scalar.clone());
        }
    }

    // Operator-pinned static facts ALWAYS override flag-derived facts.
    // `context.time` is excluded during compilation and always sourced from `Clock`.
    for (field, scalar) in &static_facts.0 {
        facts.insert(field.clone(), scalar.clone());
    }

    facts
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn resolve_resource_id_rejects_unconfigured_policy_instead_of_fabricating_empty() {
        let policy = CommandPolicy {
            executable: PathBuf::from("/usr/bin/true"),
            fixed_args: Vec::new(),
            action: "ops.ping".to_string(),
            resource_kind: "service".to_string(),
            resource_id_flag: None,
            static_resource_id: None,
            allowed_flags: BTreeMap::new(),
            static_facts: BTreeMap::new(),
            pass_env: Vec::new(),
            env_secrets: BTreeMap::new(),
        };
        let err = resolve_resource_id("ping", &policy, &BTreeMap::new())
            .expect_err("unconfigured resource_id must fail closed");
        assert_eq!(
            err,
            ArgvError::MissingResourceId {
                command: "ping".to_string(),
                flag: "<unconfigured>".to_string(),
            }
        );
    }
}
