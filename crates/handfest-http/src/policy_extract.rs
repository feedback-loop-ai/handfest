//! Lossless request-to-`(ActionRequest, VerifiedFacts)` extraction for compiled HTTP routes.

use std::collections::{BTreeMap, BTreeSet};

use handfest_core::ast::{is_valid_quoted_str, KeyId, Scalar};
use handfest_core::exact_json::{
    parse_exact_json, validate_json_keys_recursive, ExactJson, JsonKeyError,
};
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::policy::{parse_json_fact_scalar, parse_text_scalar, FactType};

use crate::policy::{CompiledRoute, HttpPolicyError, ResourceIdSource, RoutePolicy};

pub(crate) fn extract_route_request(
    actor_key: &KeyId,
    route: &CompiledRoute,
    path_params: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<(ActionRequest, VerifiedFacts), HttpPolicyError> {
    let policy = route.policy();
    let route_label = format!("{} {}", policy.method, policy.path_template);
    let max_bytes = policy.effective_max_body_bytes();
    if body.len() > max_bytes {
        return Err(HttpPolicyError::BodyTooLarge {
            route: route_label,
            actual: body.len(),
            max: max_bytes,
        });
    }

    check_query_configured_collisions(&route_label, policy, query)?;

    let parsed_body = if policy.requires_json_body() {
        Some(parse_and_validate_json_body(&route_label, policy, body)?)
    } else {
        None
    };
    let body_map = parsed_body.as_ref().and_then(ExactJson::as_object);

    let resource_id = resolve_resource_id(
        &route_label,
        &policy.resource_id,
        path_params,
        query,
        body_map,
    )?;

    let facts = build_verified_facts(&route_label, route, path_params, query, body_map)?;

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

pub(crate) fn resolve_denial_resource_id(
    route: &CompiledRoute,
    path_params: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    body: &[u8],
) -> String {
    match &route.policy().resource_id {
        ResourceIdSource::Static(val) => val.clone(),
        ResourceIdSource::PathParam(k) => path_params.get(k).cloned().unwrap_or_default(),
        ResourceIdSource::QueryParam(k) => {
            if has_ambiguous_query_keys(query) {
                return String::new();
            }
            query.get(k).cloned().unwrap_or_default()
        }
        ResourceIdSource::BodyField(k) => {
            if body.len() > route.policy().effective_max_body_bytes() {
                return String::new();
            }
            let Ok(raw) = std::str::from_utf8(body) else {
                return String::new();
            };
            let Ok(parsed) = parse_exact_json(raw) else {
                return String::new();
            };
            let Some(map) = parsed.as_object() else {
                return String::new();
            };
            if validate_json_keys_recursive(&parsed).is_err() {
                return String::new();
            }
            map.get(k)
                .and_then(ExactJson::as_str)
                .map(str::to_string)
                .unwrap_or_default()
        }
    }
}

fn has_ambiguous_query_keys(query: &BTreeMap<String, String>) -> bool {
    let mut seen_lower = BTreeSet::new();
    for key in query.keys() {
        if !key.is_ascii() || !seen_lower.insert(key.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

fn check_query_configured_collisions(
    route_label: &str,
    policy: &RoutePolicy,
    query: &BTreeMap<String, String>,
) -> Result<(), HttpPolicyError> {
    if let ResourceIdSource::QueryParam(configured) = &policy.resource_id {
        reject_case_collision_in_map(route_label, query.keys(), configured)?;
    }
    for configured in policy.query_facts.keys() {
        reject_case_collision_in_map(route_label, query.keys(), configured)?;
    }
    Ok(())
}

fn parse_and_validate_json_body(
    route_label: &str,
    policy: &RoutePolicy,
    body: &[u8],
) -> Result<ExactJson, HttpPolicyError> {
    let raw = std::str::from_utf8(body).map_err(|_| HttpPolicyError::InvalidJsonBody {
        route: route_label.to_string(),
        detail: "request body is not valid UTF-8".to_string(),
    })?;
    let parsed = parse_exact_json(raw).map_err(|err| HttpPolicyError::InvalidJsonBody {
        route: route_label.to_string(),
        detail: err.to_string(),
    })?;
    let Some(map) = parsed.as_object() else {
        return Err(HttpPolicyError::NonObjectJsonBody {
            route: route_label.to_string(),
        });
    };
    validate_json_keys_recursive(&parsed).map_err(|err| match err {
        JsonKeyError::NonAscii(key) => HttpPolicyError::NonAsciiKey {
            route: route_label.to_string(),
            key: key.to_string(),
        },
        JsonKeyError::CaseCollision {
            existing,
            colliding,
        } => HttpPolicyError::CaseCollidingKey {
            route: route_label.to_string(),
            key: colliding.to_string(),
            collides_with: existing.to_string(),
        },
    })?;
    if let ResourceIdSource::BodyField(configured) = &policy.resource_id {
        reject_case_collision_in_map(route_label, map.keys(), configured)?;
    }
    for configured in policy.body_facts.keys() {
        reject_case_collision_in_map(route_label, map.keys(), configured)?;
    }
    Ok(parsed)
}

fn reject_case_collision_in_map<'a, I>(
    route_label: &str,
    keys: I,
    configured: &str,
) -> Result<(), HttpPolicyError>
where
    I: IntoIterator<Item = &'a String>,
{
    if let Some(key) = keys
        .into_iter()
        .find(|k| k.as_str() != configured && k.eq_ignore_ascii_case(configured))
    {
        return Err(HttpPolicyError::CaseCollidingKey {
            route: route_label.to_string(),
            key: key.clone(),
            collides_with: configured.to_string(),
        });
    }
    Ok(())
}

fn resolve_resource_id(
    route_label: &str,
    source: &ResourceIdSource,
    path_params: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    body_map: Option<&BTreeMap<String, ExactJson>>,
) -> Result<String, HttpPolicyError> {
    match source {
        ResourceIdSource::Static(val) => Ok(val.clone()),
        ResourceIdSource::PathParam(name) => {
            let val = path_params
                .get(name)
                .ok_or_else(|| HttpPolicyError::MissingResourceId {
                    route: route_label.to_string(),
                    source: format!("path.{name}"),
                })?;
            validate_resource_id_str(route_label, &format!("path.{name}"), val)
        }
        ResourceIdSource::QueryParam(name) => {
            let val = query
                .get(name)
                .ok_or_else(|| HttpPolicyError::MissingResourceId {
                    route: route_label.to_string(),
                    source: format!("query.{name}"),
                })?;
            validate_resource_id_str(route_label, &format!("query.{name}"), val)
        }
        ResourceIdSource::BodyField(name) => {
            let val = body_map.and_then(|m| m.get(name)).ok_or_else(|| {
                HttpPolicyError::MissingResourceId {
                    route: route_label.to_string(),
                    source: format!("body.{name}"),
                }
            })?;
            let Some(s) = val.as_str() else {
                return Err(HttpPolicyError::InvalidResourceId {
                    route: route_label.to_string(),
                    source: format!("body.{name}"),
                    detail: "expected JSON string".to_string(),
                });
            };
            validate_resource_id_str(route_label, &format!("body.{name}"), s)
        }
    }
}

fn validate_resource_id_str(
    route_label: &str,
    source_label: &str,
    val: &str,
) -> Result<String, HttpPolicyError> {
    if !is_valid_quoted_str(val) {
        return Err(HttpPolicyError::InvalidResourceId {
            route: route_label.to_string(),
            source: source_label.to_string(),
            detail: "must not contain control characters".to_string(),
        });
    }
    Ok(val.to_string())
}

fn build_verified_facts(
    route_label: &str,
    route: &CompiledRoute,
    path_params: &BTreeMap<String, String>,
    query: &BTreeMap<String, String>,
    body_map: Option<&BTreeMap<String, ExactJson>>,
) -> Result<VerifiedFacts, HttpPolicyError> {
    let policy = route.policy();
    let mut facts = VerifiedFacts::new();

    for (key, spec) in &policy.path_facts {
        let raw = path_params
            .get(key)
            .ok_or_else(|| HttpPolicyError::MissingFact {
                route: route_label.to_string(),
                source: format!("path.{key}"),
            })?;
        let scalar = parse_str_fact(route_label, &format!("path.{key}"), spec.fact_type, raw)?;
        insert_non_time_fact(&mut facts, &spec.field, scalar);
    }

    for (key, spec) in &policy.query_facts {
        let raw = query.get(key).ok_or_else(|| HttpPolicyError::MissingFact {
            route: route_label.to_string(),
            source: format!("query.{key}"),
        })?;
        let scalar = parse_str_fact(route_label, &format!("query.{key}"), spec.fact_type, raw)?;
        insert_non_time_fact(&mut facts, &spec.field, scalar);
    }

    for (key, spec) in &policy.body_facts {
        let raw =
            body_map
                .and_then(|m| m.get(key))
                .ok_or_else(|| HttpPolicyError::MissingFact {
                    route: route_label.to_string(),
                    source: format!("body.{key}"),
                })?;
        let scalar = parse_json_fact(route_label, &format!("body.{key}"), spec.fact_type, raw)?;
        insert_non_time_fact(&mut facts, &spec.field, scalar);
    }

    // Operator-pinned static facts ALWAYS override request-derived facts.
    // `context.time` is exclusively sourced from `Clock`.
    for (field, scalar) in &route.static_facts().0 {
        insert_non_time_fact(&mut facts, field, scalar.clone());
    }

    Ok(facts)
}

fn insert_non_time_fact(facts: &mut VerifiedFacts, field: &str, scalar: Scalar) {
    if field != "context.time" {
        facts.insert(field.to_string(), scalar);
    }
}

fn parse_str_fact(
    route_label: &str,
    source_label: &str,
    expected: FactType,
    raw: &str,
) -> Result<Scalar, HttpPolicyError> {
    parse_text_scalar(expected, raw)
        .map_err(|detail| invalid_fact(route_label, source_label, &detail))
}

fn parse_json_fact(
    route_label: &str,
    source_label: &str,
    expected: FactType,
    value: &ExactJson,
) -> Result<Scalar, HttpPolicyError> {
    parse_json_fact_scalar(expected, value)
        .map_err(|err| invalid_fact(route_label, source_label, &err.to_string()))
}

fn invalid_fact(route_label: &str, source_label: &str, detail: &str) -> HttpPolicyError {
    HttpPolicyError::InvalidFact {
        route: route_label.to_string(),
        source: source_label.to_string(),
        detail: detail.to_string(),
    }
}
