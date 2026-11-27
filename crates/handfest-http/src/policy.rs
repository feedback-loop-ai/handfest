//! Fail-closed HTTP/REST route policy schema, single-pass `ExactJson` parser, route compiler, and
//! lossless `(ActionRequest, VerifiedFacts)` extractor.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use handfest_core::ast::{
    is_valid_field_path, is_valid_ident, is_valid_quoted_str, ActionPat, KeyId,
};
use handfest_core::exact_json::parse_exact_json;
use handfest_core::gate::{ActionRequest, VerifiedFacts};
use handfest_core::policy::{deserialize_unique_btreemap, FactSpec, TypedScalar};
use serde::{Deserialize, Serialize};

use crate::http1::{HttpMethod, DEFAULT_MAX_BODY_BYTES};
use crate::policy_decode::decode_http_policy_map;
pub use crate::policy_upstream::{ParsedBaseUrl, UpstreamAuth, UpstreamScheme};

/// Source for the `HANDFEST v1` `resource_id` bound to a matched HTTP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceIdSource {
    PathParam(String),
    QueryParam(String),
    BodyField(String),
    Static(String),
}

/// Authorization policy for a single admitted HTTP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicy {
    pub method: HttpMethod,
    pub path_template: String,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: ResourceIdSource,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub path_facts: BTreeMap<String, FactSpec>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub query_facts: BTreeMap<String, FactSpec>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub body_facts: BTreeMap<String, FactSpec>,
    #[serde(default, deserialize_with = "deserialize_unique_btreemap")]
    pub static_facts: BTreeMap<String, TypedScalar>,
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
}

impl RoutePolicy {
    /// Returns the effective maximum body size in bytes for this route (defaults to 1 MiB).
    #[must_use]
    pub fn effective_max_body_bytes(&self) -> usize {
        self.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES)
    }

    /// Returns `true` if this route extracts `resource_id` or facts from a JSON request body.
    #[must_use]
    pub fn requires_json_body(&self) -> bool {
        matches!(self.resource_id, ResourceIdSource::BodyField(_)) || !self.body_facts.is_empty()
    }
}

/// Top-level JSON-deserializable HTTP/REST policy map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicyMap {
    pub upstream_base_url: String,
    #[serde(default)]
    pub upstream_auth: Option<UpstreamAuth>,
    pub routes: Vec<RoutePolicy>,
}

/// One parsed segment of a validated route `path_template`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TemplateSegment {
    Literal(String),
    Param(String),
}

/// Pre-validated and compiled route policy with parsed template segments and static facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRoute {
    policy: RoutePolicy,
    segments: Vec<TemplateSegment>,
    static_facts: VerifiedFacts,
}

impl CompiledRoute {
    /// Borrows the underlying [`RoutePolicy`].
    #[must_use]
    pub const fn policy(&self) -> &RoutePolicy {
        &self.policy
    }

    pub(crate) const fn static_facts(&self) -> &VerifiedFacts {
        &self.static_facts
    }

    #[must_use]
    fn literal_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| matches!(s, TemplateSegment::Literal(_)))
            .count()
    }

    fn match_segments(&self, path_segments: &[String]) -> Option<BTreeMap<String, String>> {
        if self.segments.len() != path_segments.len() {
            return None;
        }
        let mut captures = BTreeMap::new();
        for (tmpl, actual) in self.segments.iter().zip(path_segments.iter()) {
            match tmpl {
                TemplateSegment::Literal(lit) => {
                    if lit != actual {
                        return None;
                    }
                }
                TemplateSegment::Param(name) => {
                    captures.insert(name.clone(), actual.clone());
                }
            }
        }
        Some(captures)
    }
}

/// Validated, pre-compiled [`HttpPolicyMap`] ready for deterministic route matching and lossless
/// fact extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledHttpPolicyMap {
    policy_map: HttpPolicyMap,
    base_url: ParsedBaseUrl,
    routes: Vec<CompiledRoute>,
}

/// Structured errors returned when loading, validating, or applying an [`HttpPolicyMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpPolicyError {
    Io(String),
    InvalidJson(String),
    InvalidPolicy(String),
    UnmappedRoute {
        method: HttpMethod,
        path: String,
    },
    BodyTooLarge {
        route: String,
        actual: usize,
        max: usize,
    },
    InvalidJsonBody {
        route: String,
        detail: String,
    },
    NonObjectJsonBody {
        route: String,
    },
    MissingResourceId {
        route: String,
        source: String,
    },
    InvalidResourceId {
        route: String,
        source: String,
        detail: String,
    },
    MissingFact {
        route: String,
        source: String,
    },
    InvalidFact {
        route: String,
        source: String,
        detail: String,
    },
    CaseCollidingKey {
        route: String,
        key: String,
        collides_with: String,
    },
    NonAsciiKey {
        route: String,
        key: String,
    },
}

impl fmt::Display for HttpPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "HTTP policy map I/O error: {msg}"),
            Self::InvalidJson(msg) => write!(f, "invalid HTTP policy map JSON: {msg}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid HTTP policy map: {msg}"),
            Self::UnmappedRoute { method, path } => {
                write!(f, "unmapped HTTP route '{method} {path}'")
            }
            Self::BodyTooLarge { route, actual, max } => {
                write!(
                    f,
                    "route '{route}': request body of {actual} bytes exceeds limit {max}"
                )
            }
            Self::InvalidJsonBody { route, detail } => {
                write!(f, "route '{route}': invalid JSON request body: {detail}")
            }
            Self::NonObjectJsonBody { route } => {
                write!(f, "route '{route}': JSON request body must be an object")
            }
            Self::MissingResourceId { route, source } => {
                write!(
                    f,
                    "route '{route}': missing required resource_id '{source}'"
                )
            }
            Self::InvalidResourceId {
                route,
                source,
                detail,
            } => write!(
                f,
                "route '{route}': invalid resource_id '{source}': {detail}"
            ),
            Self::MissingFact { route, source } => {
                write!(f, "route '{route}': missing required fact '{source}'")
            }
            Self::InvalidFact {
                route,
                source,
                detail,
            } => write!(f, "route '{route}': invalid fact '{source}': {detail}"),
            Self::CaseCollidingKey {
                route,
                key,
                collides_with,
            } => write!(
                f,
                "route '{route}': key '{key}' collides case-insensitively with '{collides_with}'"
            ),
            Self::NonAsciiKey { route, key } => {
                write!(f, "route '{route}': key '{key}' must be ASCII")
            }
        }
    }
}

impl std::error::Error for HttpPolicyError {}

/// Loads, parses (single-pass via `ExactJson`), and validates an [`HttpPolicyMap`] from disk.
pub fn load_http_policy_map_file(path: &Path) -> Result<HttpPolicyMap, HttpPolicyError> {
    let raw = fs::read_to_string(path)
        .map_err(|err| HttpPolicyError::Io(format!("'{}': {err}", path.display())))?;
    HttpPolicyMap::from_json_str(&raw)
}

impl HttpPolicyMap {
    /// Parses and validates an [`HttpPolicyMap`] in a single pass via `ExactJson`, rejecting
    /// duplicate keys, unknown fields, and control characters.
    pub fn from_json_str(raw: &str) -> Result<Self, HttpPolicyError> {
        let parsed =
            parse_exact_json(raw).map_err(|err| HttpPolicyError::InvalidJson(err.to_string()))?;
        let map = decode_http_policy_map(&parsed)?;
        map.validate()?;
        Ok(map)
    }

    /// Validates `upstream_base_url`, `upstream_auth`, all routes, and route uniqueness/ambiguity.
    pub fn validate(&self) -> Result<(), HttpPolicyError> {
        let _ = compile_routes_and_url(self)?;
        Ok(())
    }

    /// Validates and seals this [`HttpPolicyMap`] into a [`CompiledHttpPolicyMap`].
    pub fn compile(self) -> Result<CompiledHttpPolicyMap, HttpPolicyError> {
        let (base_url, routes) = compile_routes_and_url(&self)?;
        Ok(CompiledHttpPolicyMap {
            policy_map: self,
            base_url,
            routes,
        })
    }
}

impl CompiledHttpPolicyMap {
    /// Borrows the underlying [`HttpPolicyMap`].
    #[must_use]
    pub const fn policy_map(&self) -> &HttpPolicyMap {
        &self.policy_map
    }

    /// Borrows the validated [`ParsedBaseUrl`].
    #[must_use]
    pub const fn base_url(&self) -> &ParsedBaseUrl {
        &self.base_url
    }

    /// Borrows the optional [`UpstreamAuth`] configuration.
    #[must_use]
    pub const fn upstream_auth(&self) -> Option<&UpstreamAuth> {
        self.policy_map.upstream_auth.as_ref()
    }

    /// Borrows all compiled routes.
    #[must_use]
    pub fn routes(&self) -> &[CompiledRoute] {
        &self.routes
    }

    /// Returns the maximum `effective_max_body_bytes` across all configured routes (or the default
    /// 1 MiB when no routes are configured).
    #[must_use]
    pub fn max_route_body_bytes(&self) -> usize {
        self.routes
            .iter()
            .map(|r| r.policy.effective_max_body_bytes())
            .max()
            .unwrap_or(DEFAULT_MAX_BODY_BYTES)
    }

    /// Deterministically matches `(method, segments)` against compiled routes, preferring the
    /// unique most-specific route (highest literal segment count) independent of config order.
    #[must_use]
    pub fn match_route(
        &self,
        method: HttpMethod,
        segments: &[String],
    ) -> Option<(&CompiledRoute, BTreeMap<String, String>)> {
        let mut best: Option<(&CompiledRoute, BTreeMap<String, String>)> = None;
        for route in &self.routes {
            if route.policy.method != method {
                continue;
            }
            let Some(captures) = route.match_segments(segments) else {
                continue;
            };
            let is_better = match &best {
                None => true,
                Some((prev, _)) => route.literal_count() > prev.literal_count(),
            };
            if is_better {
                best = Some((route, captures));
            }
        }
        best
    }

    /// Losslessly extracts `(ActionRequest, VerifiedFacts)` for a matched route.
    pub fn extract_request(
        &self,
        actor_key: &KeyId,
        route: &CompiledRoute,
        path_params: &BTreeMap<String, String>,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<(ActionRequest, VerifiedFacts), HttpPolicyError> {
        crate::policy_extract::extract_route_request(actor_key, route, path_params, query, body)
    }

    /// Resolves an honest `resource_id` for a pre-gate denial receipt on a matched route without
    /// fabricating synthetic identifiers.
    #[must_use]
    pub fn denial_resource_id(
        &self,
        route: &CompiledRoute,
        path_params: &BTreeMap<String, String>,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> String {
        crate::policy_extract::resolve_denial_resource_id(route, path_params, query, body)
    }
}

fn compile_routes_and_url(
    map: &HttpPolicyMap,
) -> Result<(ParsedBaseUrl, Vec<CompiledRoute>), HttpPolicyError> {
    let base_url = ParsedBaseUrl::parse(&map.upstream_base_url)?;
    if let Some(auth) = &map.upstream_auth {
        auth.validate()?;
    }

    let mut compiled = Vec::with_capacity(map.routes.len());

    for (idx, route) in map.routes.iter().enumerate() {
        let cr = compile_route(idx, route)?;
        for existing in &compiled {
            if routes_incomparably_overlap(existing, &cr) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "duplicate or ambiguous overlapping routes '{} {}' and '{} {}'",
                    existing.policy.method,
                    existing.policy.path_template,
                    cr.policy.method,
                    cr.policy.path_template
                )));
            }
        }
        compiled.push(cr);
    }

    Ok((base_url, compiled))
}

fn routes_incomparably_overlap(a: &CompiledRoute, b: &CompiledRoute) -> bool {
    if a.policy.method != b.policy.method || a.segments.len() != b.segments.len() {
        return false;
    }
    let mut a_more_specific = false;
    let mut b_more_specific = false;
    for (sa, sb) in a.segments.iter().zip(b.segments.iter()) {
        match (sa, sb) {
            (TemplateSegment::Literal(la), TemplateSegment::Literal(lb)) if la != lb => {
                return false;
            }
            (TemplateSegment::Literal(_), TemplateSegment::Param(_)) => {
                a_more_specific = true;
            }
            (TemplateSegment::Param(_), TemplateSegment::Literal(_)) => {
                b_more_specific = true;
            }
            _ => {}
        }
    }
    a_more_specific == b_more_specific
}

fn compile_route(idx: usize, route: &RoutePolicy) -> Result<CompiledRoute, HttpPolicyError> {
    let ctx = format!("routes[{idx}] ('{} {}')", route.method, route.path_template);
    let (segments, param_names) = parse_path_template(&route.path_template, &ctx)?;

    if !is_valid_concrete_action(&route.action) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: invalid concrete action '{}'",
            route.action
        )));
    }
    if !is_valid_ident(&route.resource_kind) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: invalid resource_kind '{}'",
            route.resource_kind
        )));
    }

    validate_route_resource_id(route, &param_names, &ctx)?;
    let static_facts = validate_route_facts(route, &param_names, &ctx)?;

    Ok(CompiledRoute {
        policy: route.clone(),
        segments,
        static_facts,
    })
}

fn parse_path_template(
    template: &str,
    ctx: &str,
) -> Result<(Vec<TemplateSegment>, BTreeSet<String>), HttpPolicyError> {
    if !template.starts_with('/') {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: path_template must start with '/'"
        )));
    }
    if template.bytes().any(|b| b <= 0x20 || b >= 0x7F)
        || template.contains('?')
        || template.contains('#')
        || template.contains('%')
        || template.contains('\\')
    {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: path_template contains forbidden characters"
        )));
    }
    if template == "/" {
        return Ok((Vec::new(), BTreeSet::new()));
    }
    if template.ends_with('/') || template.contains("//") {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: path_template must not contain empty segments"
        )));
    }

    let mut segments = Vec::new();
    let mut param_names = BTreeSet::new();
    let mut folded_params: BTreeMap<String, String> = BTreeMap::new();

    for seg in template[1..].split('/') {
        if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            if !is_valid_ident(inner) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: invalid path parameter name '{{{inner}}}'"
                )));
            }
            if !param_names.insert(inner.to_string()) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: duplicate path parameter '{inner}'"
                )));
            }
            let folded = inner.to_ascii_lowercase();
            if let Some(prev) = folded_params.insert(folded, inner.to_string()) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: path parameter '{inner}' collides case-insensitively with '{prev}'"
                )));
            }
            segments.push(TemplateSegment::Param(inner.to_string()));
        } else {
            if seg == "." || seg == ".." || seg.contains('{') || seg.contains('}') {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: invalid literal segment '{seg}'"
                )));
            }
            segments.push(TemplateSegment::Literal(seg.to_string()));
        }
    }

    Ok((segments, param_names))
}

fn validate_route_resource_id(
    route: &RoutePolicy,
    param_names: &BTreeSet<String>,
    ctx: &str,
) -> Result<(), HttpPolicyError> {
    match &route.resource_id {
        ResourceIdSource::PathParam(name) => {
            if !param_names.contains(name) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: resource_id path_param '{name}' not declared in path_template"
                )));
            }
        }
        ResourceIdSource::QueryParam(name) => {
            validate_ascii_key(name, "resource_id query_param", ctx)?
        }
        ResourceIdSource::BodyField(name) => {
            validate_ascii_key(name, "resource_id body_field", ctx)?
        }
        ResourceIdSource::Static(val) => {
            if !is_valid_quoted_str(val) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: static resource_id must not contain control characters"
                )));
            }
        }
    }
    Ok(())
}

fn validate_route_facts(
    route: &RoutePolicy,
    param_names: &BTreeSet<String>,
    ctx: &str,
) -> Result<VerifiedFacts, HttpPolicyError> {
    let mut target_fields = BTreeSet::new();

    for (key, spec) in &route.path_facts {
        if !param_names.contains(key) {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "{ctx}: path_facts key '{key}' not declared in path_template"
            )));
        }
        register_target_field(&mut target_fields, &spec.field, "path_facts", ctx)?;
    }

    let query_res_key = match &route.resource_id {
        ResourceIdSource::QueryParam(k) => Some(k.as_str()),
        _ => None,
    };
    validate_keyed_fact_map(
        &route.query_facts,
        query_res_key,
        &mut target_fields,
        "query_facts",
        ctx,
    )?;

    let body_res_key = match &route.resource_id {
        ResourceIdSource::BodyField(k) => Some(k.as_str()),
        _ => None,
    };
    validate_keyed_fact_map(
        &route.body_facts,
        body_res_key,
        &mut target_fields,
        "body_facts",
        ctx,
    )?;

    let mut static_facts = VerifiedFacts::new();
    for (field, typed) in &route.static_facts {
        if !is_valid_field_path(field) {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "{ctx}: invalid static_facts field path '{field}'"
            )));
        }
        let scalar = typed.to_scalar().map_err(|err| {
            HttpPolicyError::InvalidPolicy(format!("{ctx}: static fact '{field}': {err}"))
        })?;
        if field != "context.time" {
            static_facts.insert(field.clone(), scalar);
        }
    }

    Ok(static_facts)
}

fn validate_keyed_fact_map(
    facts: &BTreeMap<String, FactSpec>,
    resource_id_key: Option<&str>,
    target_fields: &mut BTreeSet<String>,
    label: &str,
    ctx: &str,
) -> Result<(), HttpPolicyError> {
    let mut folded: BTreeMap<String, &str> = BTreeMap::new();
    for (key, spec) in facts {
        validate_ascii_key(key, label, ctx)?;
        if let Some(res_key) = resource_id_key {
            if key != res_key && key.eq_ignore_ascii_case(res_key) {
                return Err(HttpPolicyError::InvalidPolicy(format!(
                    "{ctx}: {label} key '{key}' collides case-insensitively with resource_id '{res_key}'"
                )));
            }
        }
        if let Some(prev) = folded.insert(key.to_ascii_lowercase(), key.as_str()) {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "{ctx}: {label} key '{key}' collides case-insensitively with '{prev}'"
            )));
        }
        register_target_field(target_fields, &spec.field, label, ctx)?;
    }
    Ok(())
}

fn validate_ascii_key(key: &str, label: &str, ctx: &str) -> Result<(), HttpPolicyError> {
    if key.is_empty() || !key.is_ascii() || key.chars().any(char::is_control) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: {label} key '{key}' must be non-empty ASCII without control characters"
        )));
    }
    Ok(())
}

fn register_target_field(
    target_fields: &mut BTreeSet<String>,
    field: &str,
    label: &str,
    ctx: &str,
) -> Result<(), HttpPolicyError> {
    if !is_valid_field_path(field) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: invalid {label} target field path '{field}'"
        )));
    }
    if !target_fields.insert(field.to_string()) {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "{ctx}: duplicate target fact field '{field}'"
        )));
    }
    Ok(())
}

fn is_valid_concrete_action(action: &str) -> bool {
    ActionPat::parse(action).is_ok_and(|pat| !pat.is_wildcard())
}
