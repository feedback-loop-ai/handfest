//! Single-pass decoding of [`HttpPolicyMap`] from a duplicate-checked [`ExactJson`] AST.

use std::collections::BTreeMap;

use handfest_core::exact_json::{reject_unknown_keys, ExactJson};
use handfest_core::json_num::parse_canonical_json_int;
use handfest_core::policy::{decode_fact_type, decode_static_facts, FactSpec};
use handfest_pep::decode_credential_source;

use crate::http1::HttpMethod;
use crate::policy::{HttpPolicyError, HttpPolicyMap, ResourceIdSource, RoutePolicy, UpstreamAuth};

/// Decodes an [`HttpPolicyMap`] directly from a pre-parsed, duplicate-checked [`ExactJson`] tree.
pub(crate) fn decode_http_policy_map(root: &ExactJson) -> Result<HttpPolicyMap, HttpPolicyError> {
    let obj = expect_object(root, "HTTP policy map root")?;
    reject_unknown_keys(
        obj,
        &["upstream_base_url", "upstream_auth", "routes"],
        "HTTP policy map root",
    )
    .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;

    let upstream_base_url = expect_required_str(obj, "upstream_base_url", "HTTP policy map root")?;
    let upstream_auth = match obj.get("upstream_auth") {
        None | Some(ExactJson::Null) => None,
        Some(val) => Some(decode_upstream_auth(val)?),
    };
    let routes_val = obj
        .get("routes")
        .ok_or_else(|| HttpPolicyError::InvalidJson("missing required field 'routes'".into()))?;
    let ExactJson::Array(route_items) = routes_val else {
        return Err(HttpPolicyError::InvalidJson(
            "field 'routes' must be a JSON array".into(),
        ));
    };

    let mut routes = Vec::with_capacity(route_items.len());
    for (idx, item) in route_items.iter().enumerate() {
        routes.push(decode_route_policy(idx, item)?);
    }

    Ok(HttpPolicyMap {
        upstream_base_url,
        upstream_auth,
        routes,
    })
}

fn decode_upstream_auth(value: &ExactJson) -> Result<UpstreamAuth, HttpPolicyError> {
    let ctx = "upstream_auth";
    let obj = expect_object(value, ctx)?;
    let (tag, inner) = expect_single_key(obj, ctx)?;
    match tag {
        "bearer" => {
            let inner_obj = expect_object(inner, "upstream_auth.bearer")?;
            reject_unknown_keys(inner_obj, &["source"], "upstream_auth.bearer")
                .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;
            let src_val = inner_obj.get("source").ok_or_else(|| {
                HttpPolicyError::InvalidJson("upstream_auth.bearer missing 'source'".into())
            })?;
            let source = decode_credential_source(src_val, "upstream_auth.bearer.source")
                .map_err(HttpPolicyError::InvalidJson)?;
            Ok(UpstreamAuth::Bearer { source })
        }
        "header" => {
            let inner_obj = expect_object(inner, "upstream_auth.header")?;
            reject_unknown_keys(inner_obj, &["name", "source"], "upstream_auth.header")
                .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;
            let name = expect_required_str(inner_obj, "name", "upstream_auth.header")?;
            let src_val = inner_obj.get("source").ok_or_else(|| {
                HttpPolicyError::InvalidJson("upstream_auth.header missing 'source'".into())
            })?;
            let source = decode_credential_source(src_val, "upstream_auth.header.source")
                .map_err(HttpPolicyError::InvalidJson)?;
            Ok(UpstreamAuth::Header { name, source })
        }
        other => Err(HttpPolicyError::InvalidJson(format!(
            "{ctx}: unknown variant '{other}'"
        ))),
    }
}

fn decode_route_policy(idx: usize, value: &ExactJson) -> Result<RoutePolicy, HttpPolicyError> {
    let ctx = format!("routes[{idx}]");
    let obj = expect_object(value, &ctx)?;
    reject_unknown_keys(
        obj,
        &[
            "method",
            "path_template",
            "action",
            "resource_kind",
            "resource_id",
            "path_facts",
            "query_facts",
            "body_facts",
            "static_facts",
            "max_body_bytes",
        ],
        &ctx,
    )
    .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;

    let raw_method = expect_required_str(obj, "method", &ctx)?;
    let method = HttpMethod::parse(&raw_method)
        .map_err(|err| HttpPolicyError::InvalidJson(format!("{ctx}.method: {err}")))?;
    let path_template = expect_required_str(obj, "path_template", &ctx)?;
    let action = expect_required_str(obj, "action", &ctx)?;
    let resource_kind = expect_required_str(obj, "resource_kind", &ctx)?;

    let res_val = obj.get("resource_id").ok_or_else(|| {
        HttpPolicyError::InvalidJson(format!("{ctx}: missing required field 'resource_id'"))
    })?;
    let resource_id = decode_resource_id_source(res_val, &format!("{ctx}.resource_id"))?;

    let path_facts = decode_optional_fact_map(obj, "path_facts", &ctx)?;
    let query_facts = decode_optional_fact_map(obj, "query_facts", &ctx)?;
    let body_facts = decode_optional_fact_map(obj, "body_facts", &ctx)?;
    let static_facts = match obj.get("static_facts") {
        None => BTreeMap::new(),
        Some(val) => decode_static_facts(val, &format!("{ctx}.static_facts"))
            .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?,
    };
    let max_body_bytes = decode_optional_usize(obj, "max_body_bytes", &ctx)?;

    Ok(RoutePolicy {
        method,
        path_template,
        action,
        resource_kind,
        resource_id,
        path_facts,
        query_facts,
        body_facts,
        static_facts,
        max_body_bytes,
    })
}

fn decode_resource_id_source(
    value: &ExactJson,
    ctx: &str,
) -> Result<ResourceIdSource, HttpPolicyError> {
    let obj = expect_object(value, ctx)?;
    let (tag, inner) = expect_single_key(obj, ctx)?;
    let raw = inner.as_str().ok_or_else(|| {
        HttpPolicyError::InvalidJson(format!("{ctx}.{tag}: expected JSON string"))
    })?;
    match tag {
        "path_param" => Ok(ResourceIdSource::PathParam(raw.to_string())),
        "query_param" => Ok(ResourceIdSource::QueryParam(raw.to_string())),
        "body_field" => Ok(ResourceIdSource::BodyField(raw.to_string())),
        "static" => Ok(ResourceIdSource::Static(raw.to_string())),
        other => Err(HttpPolicyError::InvalidJson(format!(
            "{ctx}: unknown resource_id source '{other}'"
        ))),
    }
}

fn decode_optional_fact_map(
    parent: &BTreeMap<String, ExactJson>,
    field: &str,
    ctx: &str,
) -> Result<BTreeMap<String, FactSpec>, HttpPolicyError> {
    let Some(value) = parent.get(field) else {
        return Ok(BTreeMap::new());
    };
    let map_ctx = format!("{ctx}.{field}");
    let obj = expect_object(value, &map_ctx)?;
    let mut out = BTreeMap::new();
    for (src_key, spec_val) in obj {
        let entry_ctx = format!("{map_ctx}['{src_key}']");
        let spec_obj = expect_object(spec_val, &entry_ctx)?;
        reject_unknown_keys(spec_obj, &["field", "type"], &entry_ctx)
            .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;
        let fact_field = expect_required_str(spec_obj, "field", &entry_ctx)?;
        let raw_type = expect_required_str(spec_obj, "type", &entry_ctx)?;
        let fact_type = decode_fact_type(&raw_type, &entry_ctx)
            .map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;
        out.insert(
            src_key.clone(),
            FactSpec {
                field: fact_field,
                fact_type,
            },
        );
    }
    Ok(out)
}

fn decode_optional_usize(
    obj: &BTreeMap<String, ExactJson>,
    key: &str,
    ctx: &str,
) -> Result<Option<usize>, HttpPolicyError> {
    match obj.get(key) {
        None | Some(ExactJson::Null) => Ok(None),
        Some(ExactJson::Number(num)) => {
            let parsed = parse_canonical_json_int(num.as_str()).ok_or_else(|| {
                HttpPolicyError::InvalidJson(format!(
                    "{ctx}.{key}: expected non-negative integer, got '{}'",
                    num.as_str()
                ))
            })?;
            usize::try_from(parsed).map(Some).map_err(|_| {
                HttpPolicyError::InvalidJson(format!(
                    "{ctx}.{key}: must be non-negative and fit usize"
                ))
            })
        }
        Some(_) => Err(HttpPolicyError::InvalidJson(format!(
            "{ctx}.{key}: expected integer"
        ))),
    }
}

fn expect_object<'a>(
    val: &'a ExactJson,
    ctx: &str,
) -> Result<&'a BTreeMap<String, ExactJson>, HttpPolicyError> {
    val.as_object()
        .ok_or_else(|| HttpPolicyError::InvalidJson(format!("{ctx}: expected JSON object")))
}

fn expect_single_key<'a>(
    obj: &'a BTreeMap<String, ExactJson>,
    ctx: &str,
) -> Result<(&'a str, &'a ExactJson), HttpPolicyError> {
    let mut iter = obj.iter();
    let (Some((tag, inner)), None) = (iter.next(), iter.next()) else {
        return Err(HttpPolicyError::InvalidJson(format!(
            "{ctx}: expected single-key JSON object"
        )));
    };
    Ok((tag.as_str(), inner))
}

fn expect_required_str(
    obj: &BTreeMap<String, ExactJson>,
    key: &str,
    ctx: &str,
) -> Result<String, HttpPolicyError> {
    let val = obj
        .get(key)
        .ok_or_else(|| HttpPolicyError::InvalidJson(format!("{ctx}: missing required '{key}'")))?;
    let s = val.as_str().ok_or_else(|| {
        HttpPolicyError::InvalidJson(format!("{ctx}.{key}: expected JSON string"))
    })?;
    if s.chars().any(char::is_control) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}.{key}: must not contain control characters"
        )));
    }
    Ok(s.to_string())
}
