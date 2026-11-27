//! Zero-dependency HTTP/REST Policy Enforcement Point (PEP) enforcing `HANDFEST v1` mandate
//! chains, lossless typed facts, tamper-evident receipts, and fail-closed credential injection.

pub mod http1;
mod http1_target;
mod http1_wire;
pub mod policy;
mod policy_decode;
mod policy_extract;
mod policy_upstream;
pub mod proxy;
pub mod transport;

pub use handfest_pep::{
    validate_verified_chain, verify_mandate_chain, verify_mandate_chain_with, verify_revocations,
    verify_revocations_with, Clock, CredentialSource, FixedClock, GateDecision, GateEngine,
    PepError, PreGateDenial, ReceiptLedger, SecretError, SecretString, SystemClock,
};
pub use http1::{
    parse_query_string, parse_request_target, read_http_request, read_http_response,
    sanitize_request_headers, sanitize_response_headers, write_http_request_wire,
    write_http_response_wire, Http1Error, HttpMethod, HttpRequest, HttpResponse, ParsedTarget,
    DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_HEADER_BYTES, DEFAULT_MAX_HEADER_COUNT,
    DEFAULT_MAX_RESPONSE_BYTES,
};
pub use policy::{
    load_http_policy_map_file, CompiledHttpPolicyMap, CompiledRoute, HttpPolicyError,
    HttpPolicyMap, ParsedBaseUrl, ResourceIdSource, RoutePolicy, UpstreamAuth, UpstreamScheme,
};
pub use proxy::{HttpProxy, HttpProxyError};
pub use transport::{
    AutoUpstreamTransport, CurlTlsTransport, Http1TcpTransport, TransportError, UpstreamRequest,
    UpstreamResponse, UpstreamTransport, DEFAULT_TIMEOUT_SECS,
};
