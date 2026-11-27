use std::collections::BTreeMap;
use std::io::Cursor;

use handfest_core::ast::{Decimal, KeyId, Scalar};
use handfest_http::{
    parse_query_string, parse_request_target, read_http_request, read_http_response,
    sanitize_request_headers, write_http_request_wire, write_http_response_wire, Http1Error,
    HttpMethod, HttpPolicyError, HttpPolicyMap, HttpResponse, ParsedBaseUrl, UpstreamScheme,
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADER_BYTES,
};

fn actor_key() -> KeyId {
    KeyId::parse("ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .unwrap()
}

#[test]
fn policy_map_parses_single_pass_roundtrips_and_extracts_lossless_facts() {
    let raw = r#"{
        "upstream_base_url": "https://api.example.com:8443",
        "upstream_auth": {
            "bearer": {
                "source": { "env": { "var": "UPSTREAM_API_TOKEN" } }
            }
        },
        "routes": [
            {
                "method": "POST",
                "path_template": "/v1/accounts/{account_id}/transfers",
                "action": "payments.transfer",
                "resource_kind": "account",
                "resource_id": { "path_param": "account_id" },
                "path_facts": {
                    "account_id": { "field": "transfer.account", "type": "str" }
                },
                "query_facts": {
                    "dry_run": { "field": "transfer.dry_run", "type": "bool" },
                    "retries": { "field": "transfer.retries", "type": "int" }
                },
                "body_facts": {
                    "amount": { "field": "transfer.amount", "type": "decimal" },
                    "scheduled_at": { "field": "transfer.scheduled_at", "type": "timestamp" },
                    "env": { "field": "context.env", "type": "str" },
                    "spoof_time": { "field": "context.time", "type": "timestamp" }
                },
                "static_facts": {
                    "context.env": { "str": "prod-pinned" },
                    "context.time": { "timestamp": "2030-01-01T00:00:00Z" }
                },
                "max_body_bytes": 4096
            }
        ]
    }"#;

    let map = HttpPolicyMap::from_json_str(raw).expect("valid policy map");
    let roundtrip_json = serde_json::to_string(&map).expect("serde serialize");
    let reparsed = HttpPolicyMap::from_json_str(&roundtrip_json).expect("single-pass reparse");
    assert_eq!(map, reparsed);

    let compiled = map.compile().expect("compile policy map");
    assert_eq!(compiled.base_url().scheme, UpstreamScheme::Https);
    assert_eq!(compiled.base_url().port, 8443);
    assert_eq!(compiled.base_url().host_header, "api.example.com:8443");

    let target =
        parse_request_target("/v1/accounts/acct-42/transfers?dry_run=false&retries=3").unwrap();
    let (route, path_params) = compiled
        .match_route(HttpMethod::Post, &target.segments)
        .expect("route matched");

    // Exact decimal 12345678901234567890.123456789 loses precision in IEEE-754 f64.
    let body = br#"{"amount":12345678901234567890.123456789,"scheduled_at":"2026-06-01T12:00:00Z","env":"attacker-staging","spoof_time":"2020-01-01T00:00:00Z"}"#;
    let (action_req, facts) = compiled
        .extract_request(&actor_key(), route, &path_params, &target.query, body)
        .expect("lossless extraction succeeds");

    assert_eq!(action_req.action, "payments.transfer");
    assert_eq!(action_req.resource_kind, "account");
    assert_eq!(action_req.resource_id, "acct-42");
    assert_eq!(
        facts.get("transfer.account"),
        Some(&Scalar::Str("acct-42".into()))
    );
    assert_eq!(facts.get("transfer.dry_run"), Some(&Scalar::Bool(false)));
    assert_eq!(facts.get("transfer.retries"), Some(&Scalar::Int(3)));
    assert_eq!(
        facts.get("transfer.amount"),
        Some(&Scalar::Decimal(
            Decimal::new(12_345_678_901_234_567_890_123_456_789_i128, 9).unwrap()
        ))
    );
    // Static facts ALWAYS override request-derived facts.
    assert_eq!(
        facts.get("context.env"),
        Some(&Scalar::Str("prod-pinned".into()))
    );
    // `context.time` is NEVER populated from request or static facts.
    assert_eq!(facts.get("context.time"), None);
}

#[test]
fn policy_map_rejects_duplicate_json_keys_unknown_fields_bad_urls_and_ambiguous_routes() {
    let dup_json = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "upstream_base_url": "http://127.0.0.1:9090",
        "routes": []
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(dup_json),
        Err(HttpPolicyError::InvalidJson(_))
    ));

    let unknown_field = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "extra": true,
        "routes": []
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(unknown_field),
        Err(HttpPolicyError::InvalidJson(_))
    ));

    for bad_url in [
        "ftp://example.com",
        "http://user:pass@example.com",
        "http://example.com/path",
        "https://example.com?q=1",
        "https://example.com#frag",
        "http://example.com:0",
        "http://example.com:080",
        "http://example.com:99999",
        "http://bad host",
        "http://[::1",
        "http://example.com\r\n",
    ] {
        assert!(
            matches!(
                ParsedBaseUrl::parse(bad_url),
                Err(HttpPolicyError::InvalidPolicy(_))
            ),
            "expected InvalidPolicy for '{bad_url}'"
        );
    }
    assert_eq!(
        ParsedBaseUrl::parse("http://[::1]:8080")
            .unwrap()
            .socket_addr_string(),
        "[::1]:8080"
    );

    let bad_auth = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "upstream_auth": { "header": { "name": "Host", "source": { "env": { "var": "TOK" } } } },
        "routes": []
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(bad_auth),
        Err(HttpPolicyError::InvalidPolicy(_))
    ));
}

#[test]
fn policy_map_rejects_ambiguous_overlapping_and_malformed_routes() {
    let ambig_routes = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "routes": [
            {
                "method": "GET",
                "path_template": "/v1/orders/{id}",
                "action": "orders.read",
                "resource_kind": "order",
                "resource_id": { "path_param": "id" }
            },
            {
                "method": "GET",
                "path_template": "/v1/orders/{order_id}",
                "action": "orders.read",
                "resource_kind": "order",
                "resource_id": { "path_param": "order_id" }
            }
        ]
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(ambig_routes),
        Err(HttpPolicyError::InvalidPolicy(_))
    ));

    let overlap_routes = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "routes": [
            {
                "method": "GET",
                "path_template": "/v1/{tenant}/items",
                "action": "items.read",
                "resource_kind": "tenant",
                "resource_id": { "path_param": "tenant" }
            },
            {
                "method": "GET",
                "path_template": "/v1/users/{id}",
                "action": "users.read",
                "resource_kind": "user",
                "resource_id": { "path_param": "id" }
            }
        ]
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(overlap_routes),
        Err(HttpPolicyError::InvalidPolicy(_))
    ));

    for bad_tmpl in [
        "v1/orders",
        "/v1/../secret",
        "/v1/./x",
        "/v1//orders",
        "/v1/{id}/{id}",
    ] {
        let json = format!(
            r#"{{
                "upstream_base_url": "http://127.0.0.1:8080",
                "routes": [{{
                    "method": "GET",
                    "path_template": "{bad_tmpl}",
                    "action": "orders.read",
                    "resource_kind": "order",
                    "resource_id": {{ "static": "x" }}
                }}]
            }}"#
        );
        assert!(
            matches!(
                HttpPolicyMap::from_json_str(&json),
                Err(HttpPolicyError::InvalidPolicy(_))
            ),
            "expected InvalidPolicy for template '{bad_tmpl}'"
        );
    }

    let wildcard_action = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "routes": [{
            "method": "GET",
            "path_template": "/v1/orders",
            "action": "orders.*",
            "resource_kind": "order",
            "resource_id": { "static": "all" }
        }]
    }"#;
    assert!(matches!(
        HttpPolicyMap::from_json_str(wildcard_action),
        Err(HttpPolicyError::InvalidPolicy(_))
    ));
}

#[test]
fn route_specificity_is_order_independent_and_body_rejects_dup_and_case_colliding_keys() {
    let raw = r#"{
        "upstream_base_url": "http://127.0.0.1:8080",
        "routes": [
            {
                "method": "POST",
                "path_template": "/v1/orders/{id}",
                "action": "orders.update",
                "resource_kind": "order",
                "resource_id": { "path_param": "id" },
                "body_facts": {
                    "amount": { "field": "order.amount", "type": "decimal" }
                },
                "max_body_bytes": 128
            },
            {
                "method": "POST",
                "path_template": "/v1/orders/special",
                "action": "orders.special",
                "resource_kind": "order",
                "resource_id": { "static": "special" }
            }
        ]
    }"#;
    let compiled = HttpPolicyMap::from_json_str(raw)
        .unwrap()
        .compile()
        .unwrap();

    // Exact literal wins over parameter even though parameter route was declared first.
    let special_target = parse_request_target("/v1/orders/special").unwrap();
    let (special_route, _) = compiled
        .match_route(HttpMethod::Post, &special_target.segments)
        .unwrap();
    assert_eq!(special_route.policy().action, "orders.special");

    let id_target = parse_request_target("/v1/orders/ord-9").unwrap();
    let (id_route, params) = compiled
        .match_route(HttpMethod::Post, &id_target.segments)
        .unwrap();
    assert_eq!(id_route.policy().action, "orders.update");

    // Duplicate JSON body key rejected.
    let dup_body = br#"{"amount":10,"amount":9999}"#;
    assert!(matches!(
        compiled.extract_request(&actor_key(), id_route, &params, &BTreeMap::new(), dup_body),
        Err(HttpPolicyError::InvalidJsonBody { .. })
    ));

    // Case-colliding JSON body keys rejected.
    let case_body = br#"{"amount":10,"Amount":9999}"#;
    assert!(matches!(
        compiled.extract_request(&actor_key(), id_route, &params, &BTreeMap::new(), case_body),
        Err(HttpPolicyError::CaseCollidingKey { .. })
    ));

    // Oversized route body rejected.
    let huge = vec![b' '; 129];
    assert!(matches!(
        compiled.extract_request(&actor_key(), id_route, &params, &BTreeMap::new(), &huge),
        Err(HttpPolicyError::BodyTooLarge { max: 128, .. })
    ));
}

#[test]
fn path_normalization_and_query_parser_reject_traversal_and_collisions() {
    for bad_path in [
        "/v1/../secret",
        "/v1/./secret",
        "/v1/%2e%2e/secret",
        "/v1/%2E/secret",
        "/v1/a%2fb",
        "/v1/a%2Fb",
        "/v1/a%5cb",
        "/v1/a%5Cb",
        "/v1//orders",
        "/v1/orders/",
        "/v1/a\\b",
        "/v1/a%00b",
        "/v1/a%0ab",
        "/v1/a%2",
        "/v1/a%ZZ",
        "/v1/orders#frag",
        "v1/orders",
    ] {
        assert!(
            parse_request_target(bad_path).is_err(),
            "expected error for malicious target '{bad_path}'"
        );
    }

    let parsed = parse_request_target("/v1/files/report.pdf?tag=caf%C3%A9&page=2").unwrap();
    assert_eq!(parsed.segments, vec!["v1", "files", "report.pdf"]);
    assert_eq!(parsed.query.get("tag").map(String::as_str), Some("café"));
    assert_eq!(parsed.query.get("page").map(String::as_str), Some("2"));

    assert_eq!(
        parse_query_string("a=1&a=2"),
        Err(Http1Error::DuplicateQueryKey("a".into()))
    );
    assert_eq!(
        parse_query_string("amount=10&Amount=999"),
        Err(Http1Error::CaseCollidingQueryKey {
            existing: "amount".into(),
            colliding: "Amount".into(),
        })
    );
    assert!(matches!(
        parse_query_string(""),
        Err(Http1Error::InvalidQuery(_))
    ));
    assert!(matches!(
        parse_query_string("a=1&&b=2"),
        Err(Http1Error::InvalidQuery(_))
    ));
    assert!(matches!(
        parse_query_string("bare_key"),
        Err(Http1Error::InvalidQuery(_))
    ));
}

#[test]
fn http1_wire_parser_rejects_smuggling_and_enforces_limits() {
    let smuggle_te_cl = b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
    assert_eq!(
        read_http_request(
            &mut Cursor::new(smuggle_te_cl),
            DEFAULT_MAX_HEADER_BYTES,
            DEFAULT_MAX_BODY_BYTES
        ),
        Err(Http1Error::TransferEncodingWithContentLength)
    );

    let dup_cl = b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}";
    assert_eq!(
        read_http_request(
            &mut Cursor::new(dup_cl),
            DEFAULT_MAX_HEADER_BYTES,
            DEFAULT_MAX_BODY_BYTES
        ),
        Err(Http1Error::DuplicateContentLength)
    );

    let bad_te = b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n";
    assert_eq!(
        read_http_request(
            &mut Cursor::new(bad_te),
            DEFAULT_MAX_HEADER_BYTES,
            DEFAULT_MAX_BODY_BYTES
        ),
        Err(Http1Error::UnsupportedTransferEncoding("gzip".into()))
    );

    assert_eq!(
        read_http_request(&mut Cursor::new(b"GET / HTTP/1.1\nHost: x\n\n"), 4096, 1024),
        Err(Http1Error::BareLf)
    );
    assert_eq!(
        read_http_request(
            &mut Cursor::new(b"GET / HTTP/1.1\rHost: x\r\n\r\n"),
            4096,
            1024
        ),
        Err(Http1Error::BareCr)
    );
    assert_eq!(
        read_http_request(
            &mut Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n folded: 1\r\n\r\n"),
            4096,
            1024
        ),
        Err(Http1Error::ObsoleteLineFolding)
    );
    assert_eq!(
        read_http_request(
            &mut Cursor::new(b"GET / HTTP/1.1\r\nX-A: 1\r\n\r\n"),
            4096,
            1024
        ),
        Err(Http1Error::MissingHostHeader)
    );
    assert_eq!(
        read_http_request(
            &mut Cursor::new(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
            4096,
            1024
        ),
        Err(Http1Error::DuplicateHostHeader)
    );

    let req_wire =
        b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n0123456789";
    assert_eq!(
        read_http_request(&mut Cursor::new(req_wire), 20, 1024),
        Err(Http1Error::HeadersTooLarge { max_bytes: 20 })
    );
    assert_eq!(
        read_http_request(&mut Cursor::new(req_wire), 4096, 5),
        Err(Http1Error::BodyTooLarge { max_bytes: 5 })
    );
}

#[test]
fn http1_wire_chunked_sanitization_and_roundtrip_work() {
    let chunked_ok = b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
    let parsed_chunked = read_http_request(&mut Cursor::new(chunked_ok), 4096, 1024).unwrap();
    assert_eq!(parsed_chunked.body, br#"{"a":1}"#);

    let chunked_trailer = b"POST /v1/pay HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: sneak\r\n\r\n";
    assert!(matches!(
        read_http_request(&mut Cursor::new(chunked_trailer), 4096, 1024),
        Err(Http1Error::InvalidChunkedEncoding(_))
    ));

    let headers = vec![
        ("Host".into(), "evil.local".into()),
        ("Authorization".into(), "Bearer attacker".into()),
        ("X-Api-Key".into(), "forged-key".into()),
        ("Connection".into(), "keep-alive, X-Custom-Hop".into()),
        ("X-Custom-Hop".into(), "drop-me".into()),
        ("Keep-Alive".into(), "timeout=5".into()),
        ("Transfer-Encoding".into(), "chunked".into()),
        ("Content-Type".into(), "application/json".into()),
    ];
    let sanitized = sanitize_request_headers(&headers, Some("x-api-key"));
    assert_eq!(
        sanitized,
        vec![("Content-Type".to_string(), "application/json".to_string())]
    );

    let out_req = write_http_request_wire(
        HttpMethod::Post,
        "/v1/pay",
        "127.0.0.1:8080",
        &sanitized,
        br#"{"ok":1}"#,
    )
    .unwrap();
    let reparsed_req = read_http_request(&mut Cursor::new(&out_req), 4096, 1024).unwrap();
    assert_eq!(reparsed_req.method, HttpMethod::Post);
    assert_eq!(reparsed_req.target, "/v1/pay");
    assert_eq!(reparsed_req.body, br#"{"ok":1}"#);

    let resp_wire = write_http_response_wire(&HttpResponse::json(200, br#"{"ok":true}"#));
    let reparsed_resp = read_http_response(&mut Cursor::new(&resp_wire), 4096, 1024).unwrap();
    assert_eq!(reparsed_resp.status, 200);
    assert_eq!(reparsed_resp.body, br#"{"ok":true}"#);
}

#[test]
fn single_case_mismatched_query_and_body_keys_trigger_configured_collision_guards() {
    let policy_json = r#"{
        "upstream_base_url": "https://api.example.com",
        "routes": [
            {
                "method": "POST",
                "path_template": "/v1/transfers",
                "action": "finance.transfer",
                "resource_kind": "account",
                "resource_id": { "query_param": "acct" },
                "query_facts": {
                    "currency": { "field": "payment.currency", "type": "str" }
                },
                "body_facts": {
                    "amount": { "field": "payment.amount", "type": "decimal" }
                }
            },
            {
                "method": "POST",
                "path_template": "/v1/body-res",
                "action": "finance.transfer",
                "resource_kind": "account",
                "resource_id": { "body_field": "accountId" }
            }
        ]
    }"#;
    let compiled = HttpPolicyMap::from_json_str(policy_json)
        .unwrap()
        .compile()
        .unwrap();

    // 1. Single case-mismatched query fact key (`?acct=a1&Currency=EUR` without `currency`).
    let target1 = parse_request_target("/v1/transfers?acct=a1&Currency=EUR").unwrap();
    let (route1, params1) = compiled
        .match_route(HttpMethod::Post, &target1.segments)
        .unwrap();
    assert_eq!(
        compiled.extract_request(
            &actor_key(),
            route1,
            &params1,
            &target1.query,
            br#"{"amount":10.00}"#,
        ),
        Err(HttpPolicyError::CaseCollidingKey {
            route: "POST /v1/transfers".to_string(),
            key: "Currency".to_string(),
            collides_with: "currency".to_string(),
        })
    );

    // 2. Single case-mismatched query resource_id key (`?Acct=a1&currency=EUR` without `acct`).
    let target2 = parse_request_target("/v1/transfers?Acct=a1&currency=EUR").unwrap();
    assert_eq!(
        compiled.extract_request(
            &actor_key(),
            route1,
            &params1,
            &target2.query,
            br#"{"amount":10.00}"#,
        ),
        Err(HttpPolicyError::CaseCollidingKey {
            route: "POST /v1/transfers".to_string(),
            key: "Acct".to_string(),
            collides_with: "acct".to_string(),
        })
    );

    // 3. Single case-mismatched JSON body fact key (`{"Amount":9999}` without `amount`).
    let target3 = parse_request_target("/v1/transfers?acct=a1&currency=USD").unwrap();
    assert_eq!(
        compiled.extract_request(
            &actor_key(),
            route1,
            &params1,
            &target3.query,
            br#"{"Amount":9999}"#,
        ),
        Err(HttpPolicyError::CaseCollidingKey {
            route: "POST /v1/transfers".to_string(),
            key: "Amount".to_string(),
            collides_with: "amount".to_string(),
        })
    );

    // 4. Single case-mismatched JSON body resource_id key (`{"AccountId":"a1"}` without `accountId`).
    let target4 = parse_request_target("/v1/body-res").unwrap();
    let (route2, params2) = compiled
        .match_route(HttpMethod::Post, &target4.segments)
        .unwrap();
    assert_eq!(
        compiled.extract_request(
            &actor_key(),
            route2,
            &params2,
            &target4.query,
            br#"{"AccountId":"a1"}"#,
        ),
        Err(HttpPolicyError::CaseCollidingKey {
            route: "POST /v1/body-res".to_string(),
            key: "AccountId".to_string(),
            collides_with: "accountId".to_string(),
        })
    );
}

#[test]
fn resource_id_and_denial_resource_id_cover_static_and_query_sources() {
    let policy_json = r#"{
        "upstream_base_url": "https://api.example.com",
        "routes": [
            {
                "method": "GET",
                "path_template": "/v1/static",
                "action": "sys.read",
                "resource_kind": "system",
                "resource_id": { "static": "global-singleton" }
            },
            {
                "method": "GET",
                "path_template": "/v1/query",
                "action": "acct.read",
                "resource_kind": "account",
                "resource_id": { "query_param": "id" }
            },
            {
                "method": "POST",
                "path_template": "/v1/body",
                "action": "acct.update",
                "resource_kind": "account",
                "resource_id": { "body_field": "id" },
                "max_body_bytes": 24
            }
        ]
    }"#;
    let compiled = HttpPolicyMap::from_json_str(policy_json)
        .unwrap()
        .compile()
        .unwrap();
    let empty = BTreeMap::new();

    // Static resource_id
    let (r_static, _) = compiled
        .match_route(HttpMethod::Get, &["v1".into(), "static".into()])
        .unwrap();
    let (req_static, _) = compiled
        .extract_request(&actor_key(), r_static, &empty, &empty, b"")
        .unwrap();
    assert_eq!(req_static.resource_id, "global-singleton");
    assert_eq!(
        compiled.denial_resource_id(r_static, &empty, &empty, b""),
        "global-singleton"
    );

    // QueryParam resource_id: valid, missing, and control char
    let (r_query, _) = compiled
        .match_route(HttpMethod::Get, &["v1".into(), "query".into()])
        .unwrap();
    let q_ok = BTreeMap::from([("id".to_string(), "acct-q1".to_string())]);
    let (req_q, _) = compiled
        .extract_request(&actor_key(), r_query, &empty, &q_ok, b"")
        .unwrap();
    assert_eq!(req_q.resource_id, "acct-q1");
    assert_eq!(
        compiled.denial_resource_id(r_query, &empty, &q_ok, b""),
        "acct-q1"
    );
    assert_eq!(
        compiled.denial_resource_id(r_query, &empty, &empty, b""),
        ""
    );
    assert!(matches!(
        compiled.extract_request(&actor_key(), r_query, &empty, &empty, b""),
        Err(HttpPolicyError::MissingResourceId { ref source, .. }) if source == "query.id"
    ));
    let q_ctrl = BTreeMap::from([("id".to_string(), "bad\nid".to_string())]);
    assert!(matches!(
        compiled.extract_request(&actor_key(), r_query, &empty, &q_ctrl, b""),
        Err(HttpPolicyError::InvalidResourceId { ref source, .. }) if source == "query.id"
    ));
}

#[test]
fn resource_id_and_denial_resource_id_cover_body_field_and_oversized_body() {
    let policy_json = r#"{
        "upstream_base_url": "https://api.example.com",
        "routes": [
            {
                "method": "POST",
                "path_template": "/v1/body",
                "action": "acct.update",
                "resource_kind": "account",
                "resource_id": { "body_field": "id" },
                "max_body_bytes": 24
            }
        ]
    }"#;
    let compiled = HttpPolicyMap::from_json_str(policy_json)
        .unwrap()
        .compile()
        .unwrap();
    let empty = BTreeMap::new();

    // BodyField resource_id: valid, missing, non-string, oversized body skipping JSON parse
    let (r_body, _) = compiled
        .match_route(HttpMethod::Post, &["v1".into(), "body".into()])
        .unwrap();
    let (req_b, _) = compiled
        .extract_request(&actor_key(), r_body, &empty, &empty, br#"{"id":"b1"}"#)
        .unwrap();
    assert_eq!(req_b.resource_id, "b1");
    assert_eq!(
        compiled.denial_resource_id(r_body, &empty, &empty, br#"{"id":"b1"}"#),
        "b1"
    );
    assert!(matches!(
        compiled.extract_request(&actor_key(), r_body, &empty, &empty, br#"{}"#),
        Err(HttpPolicyError::MissingResourceId { ref source, .. }) if source == "body.id"
    ));
    assert!(matches!(
        compiled.extract_request(&actor_key(), r_body, &empty, &empty, br#"{"id":123}"#),
        Err(HttpPolicyError::InvalidResourceId { ref source, .. }) if source == "body.id"
    ));
    assert_eq!(
        compiled.denial_resource_id(r_body, &empty, &empty, br#"{"id":123}"#),
        ""
    );
    assert_eq!(
        compiled.denial_resource_id(r_body, &empty, &empty, b"\xff\xfe"),
        ""
    );
    let oversized = br#"{"id":"valid-json-but-exceeds-24-bytes"}"#;
    assert!(oversized.len() > 24);
    assert!(matches!(
        compiled.extract_request(&actor_key(), r_body, &empty, &empty, oversized),
        Err(HttpPolicyError::BodyTooLarge { max: 24, .. })
    ));
    assert_eq!(
        compiled.denial_resource_id(r_body, &empty, &empty, oversized),
        ""
    );
}

#[test]
fn round3_body_denial_resource_id_case_collision_and_json_body_refusals() {
    let empty = BTreeMap::new();
    // Case-colliding body keys yield "" for denial_resource_id.
    let big_policy = HttpPolicyMap::from_json_str(
        r#"{
            "upstream_base_url": "https://api.example.com",
            "routes": [{
                "method": "POST",
                "path_template": "/v1/body",
                "action": "acct.update",
                "resource_kind": "account",
                "resource_id": { "body_field": "id" },
                "body_facts": { "amount": { "field": "action.amount", "type": "int" } }
            }]
        }"#,
    )
    .unwrap()
    .compile()
    .unwrap();
    let (r_big, _) = big_policy
        .match_route(HttpMethod::Post, &["v1".into(), "body".into()])
        .unwrap();
    assert_eq!(
        big_policy.denial_resource_id(
            r_big,
            &empty,
            &empty,
            br#"{"id":"acct-benign","ID":"acct-victim"}"#
        ),
        ""
    );
    // Direct JSON body refusal coverage: invalid UTF-8, non-object array, and non-ASCII key.
    assert!(matches!(
        big_policy.extract_request(&actor_key(), r_big, &empty, &empty, b"\xff\xfe"),
        Err(HttpPolicyError::InvalidJsonBody { ref detail, .. }) if detail.contains("UTF-8")
    ));
    assert!(matches!(
        big_policy.extract_request(&actor_key(), r_big, &empty, &empty, b"[]"),
        Err(HttpPolicyError::NonObjectJsonBody { .. })
    ));
    assert!(matches!(
        big_policy.extract_request(
            &actor_key(),
            r_big,
            &empty,
            &empty,
            "{\"id\":\"b1\",\"amount\":5,\"é\":0}".as_bytes()
        ),
        Err(HttpPolicyError::NonAsciiKey { ref key, .. }) if key == "é"
    ));
}

#[test]
fn read_http_response_reads_eof_delimited_body_and_enforces_max_size() {
    use std::io::Cursor;

    let raw_eof = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello-until-eof";
    let resp = read_http_response(&mut Cursor::new(&raw_eof[..]), 4096, 64).expect("eof response");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello-until-eof");

    let too_big = read_http_response(&mut Cursor::new(&raw_eof[..]), 4096, 5)
        .expect_err("oversized eof body must fail");
    assert_eq!(too_big, Http1Error::BodyTooLarge { max_bytes: 5 });
}

#[test]
fn upstream_auth_file_source_rejects_relative_and_parent_traversal_paths() {
    for bad_path in ["relative/token.txt", "/run/secrets/../other.txt", ""] {
        let json = format!(
            r#"{{
                "upstream_base_url": "https://api.example.com",
                "upstream_auth": {{ "bearer": {{ "source": {{ "file": {{ "path": "{bad_path}" }} }} }} }},
                "routes": [
                    {{
                        "method": "GET",
                        "path_template": "/v1/ping",
                        "action": "api.ping",
                        "resource_kind": "service",
                        "resource_id": {{ "static": "ping" }}
                    }}
                ]
            }}"#
        );
        let err = HttpPolicyMap::from_json_str(&json)
            .expect_err("invalid credential path must fail validation");
        assert!(
            matches!(err, HttpPolicyError::InvalidPolicy(_)),
            "expected InvalidPolicy for '{bad_path}', got {err:?}"
        );
    }
}

#[test]
fn round2_http1_rejects_101_suppresses_bodyless_payloads_and_blocks_outbound_smuggling() {
    use std::io::Cursor;

    use handfest_http::http1::is_valid_header_value;
    use handfest_http::{write_http_request_wire, write_http_response_wire};

    // 101 Switching Protocols must be rejected fail-closed in read_http_response.
    let raw_101 = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
    let err_101 = read_http_response(&mut Cursor::new(&raw_101[..]), 4096, 1024)
        .expect_err("unsolicited 101 must fail");
    assert!(matches!(err_101, Http1Error::InvalidStatusLine(ref msg) if msg.contains("101")));

    // write_http_response_wire must NEVER emit body bytes or Content-Length for 204/304/1xx.
    for status in [100u16, 204, 304] {
        let resp = handfest_http::HttpResponse {
            status,
            reason: "No Content".to_string(),
            headers: vec![("X-Test".to_string(), "1".to_string())],
            body: b"HTTP/1.1 200 OK\r\n\r\nsmuggled".to_vec(),
        };
        let wire = write_http_response_wire(&resp);
        let wire_str = std::str::from_utf8(&wire).expect("ascii wire");
        assert!(
            wire_str.ends_with("\r\n\r\n"),
            "status {status} wire must end at CRLFCRLF with zero body bytes: {wire_str:?}"
        );
        assert!(
            !wire_str.contains("Content-Length"),
            "status {status} must not emit Content-Length"
        );
        assert!(!wire_str.contains("smuggled"));
    }

    // write_http_request_wire rejects forbidden framing/authority headers, #fragment, and HTAB.
    for forbidden in [
        "Host",
        "Transfer-Encoding",
        "Content-Length",
        "Connection",
        "host",
    ] {
        let err = write_http_request_wire(
            HttpMethod::Get,
            "/v1/items",
            "api.example.com",
            &[(forbidden.to_string(), "evil".to_string())],
            b"",
        )
        .expect_err("forbidden outbound header must fail");
        assert!(matches!(err, Http1Error::InvalidHeaderName(_)));
    }
    let frag_err = write_http_request_wire(
        HttpMethod::Get,
        "/v1/items#fragment",
        "api.example.com",
        &[],
        b"",
    )
    .expect_err("#fragment must fail");
    assert!(matches!(frag_err, Http1Error::InvalidTarget(_)));

    assert!(!is_valid_header_value("val\twith-tab"));
    let tab_err = write_http_request_wire(
        HttpMethod::Get,
        "/v1/items",
        "api.example.com",
        &[("X-Custom".to_string(), "a\tb".to_string())],
        b"",
    )
    .expect_err("HTAB in header value must fail");
    assert!(matches!(tab_err, Http1Error::InvalidHeaderValue { .. }));
}

#[test]
fn read_bounded_to_eof_propagates_connection_reset_as_io_error() {
    use std::io::{BufRead, Read};

    struct ResetAfterHead {
        buf: &'static [u8],
        pos: usize,
    }
    impl Read for ResetAfterHead {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "peer reset during body",
                ))
            }
        }
    }
    impl BufRead for ResetAfterHead {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.pos < self.buf.len() {
                Ok(&self.buf[self.pos..])
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "peer reset during body",
                ))
            }
        }
        fn consume(&mut self, amt: usize) {
            self.pos += amt;
        }
    }
    let mut failing = ResetAfterHead {
        buf: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial",
        pos: 0,
    };
    let io_err =
        read_http_response(&mut failing, 4096, 1024).expect_err("ConnectionReset must fail");
    assert!(matches!(io_err, Http1Error::Io(ref msg) if msg.contains("peer reset")));
}

#[test]
fn percent_decode_path_segment_handles_utf8_invalid_utf8_c1_controls_and_policy_ctrl_is_invalid_policy(
) {
    // Valid multi-byte UTF-8 percent-encoded path segment.
    let ok = parse_request_target("/v1/items/caf%C3%A9").expect("valid utf-8 segment");
    assert_eq!(ok.segments, vec!["v1", "items", "café"]);

    // Invalid UTF-8 bytes in percent-encoded path segment.
    let bad_utf8 = parse_request_target("/v1/items/%FF%FE").expect_err("invalid utf-8 must fail");
    assert!(
        matches!(bad_utf8, Http1Error::InvalidPercentEncoding(ref msg) if msg.contains("UTF-8"))
    );

    // C1 control character (U+0085 = %C2%85) rejected by is_valid_quoted_str.
    let c1_err = parse_request_target("/v1/items/a%C2%85b").expect_err("C1 control must fail");
    assert!(matches!(c1_err, Http1Error::InvalidTarget(ref msg) if msg.contains("control")));

    // Control characters in HTTP policy strings return InvalidPolicy (aligned with core & exec).
    let ctrl_policy = r#"{
        "upstream_base_url": "https://api.example.com",
        "routes": [{
            "method": "GET",
            "path_template": "/v1/ping",
            "action": "api.ping\u0007",
            "resource_kind": "service",
            "resource_id": { "static": "ping" }
        }]
    }"#;
    let err =
        HttpPolicyMap::from_json_str(ctrl_policy).expect_err("control char in action must fail");
    assert!(
        matches!(err, HttpPolicyError::InvalidPolicy(ref msg) if msg.contains("control characters")),
        "expected InvalidPolicy, got {err:?}"
    );
}

#[test]
fn round3_http1_wire_rejects_bodyless_framing_and_reads_sequential_bodyless_responses() {
    use std::io::Cursor;

    let cl_cases = [
        b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\nok".as_slice(),
        b"HTTP/1.1 103 Early Hints\r\nContent-Length: 5\r\n\r\nHTTP/1.1 200 OK\r\n\r\nok"
            .as_slice(),
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
    ];
    for raw in cl_cases {
        let err = read_http_response(&mut Cursor::new(raw), 4096, 1024)
            .expect_err("Content-Length on 1xx/204 must fail");
        assert!(
            matches!(err, Http1Error::InvalidContentLength(ref msg) if msg.contains("forbidden on HTTP")),
            "unexpected error: {err:?}"
        );
    }

    let te_cases = [
        b"HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\n\r\nok"
            .as_slice(),
        b"HTTP/1.1 103 Early Hints\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\n\r\nok"
            .as_slice(),
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
    ];
    for raw in te_cases {
        let err = read_http_response(&mut Cursor::new(raw), 4096, 1024)
            .expect_err("Transfer-Encoding on 1xx/204/304 must fail");
        assert!(
            matches!(err, Http1Error::UnsupportedTransferEncoding(ref msg) if msg.contains("forbidden on HTTP")),
            "unexpected error: {err:?}"
        );
    }

    let pipelined_304 = concat!(
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    let mut cursor = Cursor::new(pipelined_304.as_bytes());
    let first = read_http_response(&mut cursor, 4096, 1024).expect("304 must return immediately");
    assert_eq!(first.status, 304);
    assert!(first.body.is_empty());
    let second = read_http_response(&mut cursor, 4096, 1024).expect("following 200 must read");
    assert_eq!(second.status, 200);
    assert_eq!(second.body, b"ok");

    let pipelined_204 = concat!(
        "HTTP/1.1 204 No Content\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    let mut cursor2 = Cursor::new(pipelined_204.as_bytes());
    let r204 = read_http_response(&mut cursor2, 4096, 1024).expect("204 must return immediately");
    assert_eq!(r204.status, 204);
    assert!(r204.body.is_empty());
    let r200 = read_http_response(&mut cursor2, 4096, 1024).expect("following 200 must read");
    assert_eq!(r200.status, 200);
    assert_eq!(r200.body, b"ok");
}

#[test]
fn round3_http1_wire_enforces_cumulative_1xx_caps_and_outbound_header_validation() {
    use std::io::Cursor;

    use handfest_http::write_http_request_wire;

    let multi_100 = concat!(
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\n",
        "ok"
    );
    let cum_err = read_http_response(&mut Cursor::new(multi_100.as_bytes()), 60, 1024)
        .expect_err("cumulative 1xx + final headers exceeding max_header_bytes must fail");
    assert_eq!(cum_err, Http1Error::HeadersTooLarge { max_bytes: 60 });

    let five_100 = "HTTP/1.1 100 Continue\r\n\r\n".repeat(5) + "HTTP/1.1 200 OK\r\n\r\nok";
    let cap_err = read_http_response(&mut Cursor::new(five_100.as_bytes()), 4096, 1024)
        .expect_err(">4 interim 1xx blocks must fail");
    assert!(
        matches!(cap_err, Http1Error::InvalidStatusLine(ref msg) if msg.contains("too many interim 1xx")),
        "unexpected error: {cap_err:?}"
    );

    let bad_name_err = write_http_request_wire(
        HttpMethod::Get,
        "/v1/items",
        "api.example.com",
        &[("Bad Name".to_string(), "val".to_string())],
        b"",
    )
    .expect_err("invalid header name must fail");
    assert_eq!(
        bad_name_err,
        Http1Error::InvalidHeaderName("Bad Name".to_string())
    );

    let empty_host_err = write_http_request_wire(HttpMethod::Get, "/v1/items", "", &[], b"")
        .expect_err("empty host_header must fail");
    assert_eq!(
        empty_host_err,
        Http1Error::InvalidHeaderValue {
            name: "Host".to_string(),
        }
    );
}

#[test]
fn round4_forbids_content_type_and_encoding_auth_headers_and_hardens_query_denial_id() {
    for forbidden in [
        "Content-Encoding",
        "content-encoding",
        "Content-Type",
        "content-type",
    ] {
        let policy_json = format!(
            r#"{{
                "upstream_base_url": "https://api.example.com",
                "upstream_auth": {{
                    "header": {{
                        "name": "{forbidden}",
                        "source": {{ "env": {{ "var": "API_TOKEN" }} }}
                    }}
                }},
                "routes": [{{
                    "method": "GET",
                    "path_template": "/v1/ping",
                    "action": "api.ping",
                    "resource_kind": "service",
                    "resource_id": {{ "static": "ping" }}
                }}]
            }}"#
        );
        let err = HttpPolicyMap::from_json_str(&policy_json)
            .expect_err(&format!("upstream_auth header '{forbidden}' must fail"));
        assert!(
            matches!(err, HttpPolicyError::InvalidPolicy(ref msg) if msg.contains("forbidden")),
            "expected InvalidPolicy for '{forbidden}', got {err:?}"
        );
    }

    let query_policy = HttpPolicyMap::from_json_str(
        r#"{
            "upstream_base_url": "https://api.example.com",
            "routes": [{
                "method": "GET",
                "path_template": "/v1/items",
                "action": "item.read",
                "resource_kind": "account",
                "resource_id": { "query_param": "id" }
            }]
        }"#,
    )
    .unwrap()
    .compile()
    .unwrap();
    let (route, _) = query_policy
        .match_route(HttpMethod::Get, &["v1".into(), "items".into()])
        .unwrap();
    let empty = BTreeMap::new();

    let colliding_target = BTreeMap::from([
        ("id".to_string(), "acct-benign".to_string()),
        ("ID".to_string(), "acct-victim".to_string()),
    ]);
    assert_eq!(
        query_policy.denial_resource_id(route, &empty, &colliding_target, b""),
        ""
    );

    let colliding_other = BTreeMap::from([
        ("id".to_string(), "acct-benign".to_string()),
        ("foo".to_string(), "1".to_string()),
        ("FOO".to_string(), "2".to_string()),
    ]);
    assert_eq!(
        query_policy.denial_resource_id(route, &empty, &colliding_other, b""),
        ""
    );

    let non_ascii = BTreeMap::from([
        ("id".to_string(), "acct-benign".to_string()),
        ("café".to_string(), "1".to_string()),
    ]);
    assert_eq!(
        query_policy.denial_resource_id(route, &empty, &non_ascii, b""),
        ""
    );

    let clean = BTreeMap::from([
        ("id".to_string(), "acct-benign".to_string()),
        ("currency".to_string(), "USD".to_string()),
    ]);
    assert_eq!(
        query_policy.denial_resource_id(route, &empty, &clean, b""),
        "acct-benign"
    );
}
