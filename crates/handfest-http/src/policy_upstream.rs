//! Validated upstream origin URL (`http://` / `https://`) and operator credential injection
//! configuration (`Bearer` / custom `Header`).

use std::net::Ipv6Addr;

use handfest_pep::{CredentialSource, SecretError, SecretString};
use serde::{Deserialize, Serialize};

use crate::http1::{is_forbidden_auth_header_name, is_valid_header_name};
use crate::policy::HttpPolicyError;

/// Validated upstream URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

impl UpstreamScheme {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// Validated upstream origin (`http://host[:port]` or `https://host[:port]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBaseUrl {
    pub scheme: UpstreamScheme,
    pub host: String,
    pub port: u16,
    pub host_header: String,
    pub origin: String,
}

impl ParsedBaseUrl {
    /// Parses and validates an upstream base URL (`http://host[:port]` or `https://host[:port]`).
    ///
    /// Rejects userinfo (`@`), path segments (`/`), query (`?`), fragment (`#`), whitespace,
    /// control characters, non-ASCII bytes, and invalid hosts/ports.
    pub fn parse(raw: &str) -> Result<Self, HttpPolicyError> {
        if raw.is_empty() || raw.bytes().any(|b| b <= 0x20 || b >= 0x7F) {
            return Err(HttpPolicyError::InvalidPolicy(
                "upstream_base_url must be non-empty printable ASCII without whitespace".into(),
            ));
        }
        let (scheme, authority) = if let Some(rest) = raw.strip_prefix("http://") {
            (UpstreamScheme::Http, rest)
        } else if let Some(rest) = raw.strip_prefix("https://") {
            (UpstreamScheme::Https, rest)
        } else {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "upstream_base_url '{raw}' must start with 'http://' or 'https://'"
            )));
        };

        if authority.is_empty()
            || authority.contains('@')
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('\\')
        {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "upstream_base_url '{raw}' must be strictly scheme://host[:port] without userinfo, path, query, or fragment"
            )));
        }

        let (host, explicit_port) = parse_authority(authority, raw)?;
        let port = explicit_port.unwrap_or_else(|| scheme.default_port());
        let host_header = match explicit_port {
            Some(p) if p != scheme.default_port() => format!("{host}:{p}"),
            _ => host.clone(),
        };
        let origin = match explicit_port {
            Some(p) => format!("{}://{host}:{p}", scheme.as_str()),
            None => format!("{}://{host}", scheme.as_str()),
        };

        Ok(Self {
            scheme,
            host,
            port,
            host_header,
            origin,
        })
    }

    /// Returns the `host:port` TCP address string for `ToSocketAddrs`.
    #[must_use]
    pub fn socket_addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn parse_authority(authority: &str, full: &str) -> Result<(String, Option<u16>), HttpPolicyError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((ipv6_str, tail)) = rest.split_once(']') else {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "upstream_base_url '{full}': unterminated IPv6 bracket"
            )));
        };
        if ipv6_str.parse::<Ipv6Addr>().is_err() {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "upstream_base_url '{full}': invalid IPv6 host '[{ipv6_str}]'"
            )));
        }
        let port = if tail.is_empty() {
            None
        } else if let Some(port_str) = tail.strip_prefix(':') {
            Some(parse_strict_port(port_str, full)?)
        } else {
            return Err(HttpPolicyError::InvalidPolicy(format!(
                "upstream_base_url '{full}': invalid trailing authority '{tail}'"
            )));
        };
        return Ok((format!("[{ipv6_str}]"), port));
    }

    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(parse_strict_port(p, full)?)),
        None => (authority, None),
    };
    validate_hostname(host, full)?;
    Ok((host.to_string(), port))
}

fn parse_strict_port(port_str: &str, full: &str) -> Result<u16, HttpPolicyError> {
    if port_str.is_empty()
        || !port_str.bytes().all(|b| b.is_ascii_digit())
        || (port_str.len() > 1 && port_str.starts_with('0'))
    {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "upstream_base_url '{full}': invalid port '{port_str}'"
        )));
    }
    let port: u16 = port_str.parse().map_err(|_| {
        HttpPolicyError::InvalidPolicy(format!(
            "upstream_base_url '{full}': port '{port_str}' out of range"
        ))
    })?;
    if port == 0 {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "upstream_base_url '{full}': port must be >= 1"
        )));
    }
    Ok(port)
}

fn validate_hostname(host: &str, full: &str) -> Result<(), HttpPolicyError> {
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(HttpPolicyError::InvalidPolicy(format!(
            "upstream_base_url '{full}': invalid host '{host}'"
        )));
    }
    Ok(())
}

/// Operator-configured credential injected into permitted upstream HTTP requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamAuth {
    /// Injects `Authorization: Bearer <secret>`.
    Bearer { source: CredentialSource },
    /// Injects `<name>: <secret>`.
    Header {
        name: String,
        source: CredentialSource,
    },
}

impl UpstreamAuth {
    /// Returns the HTTP header name that this auth config injects (and strips from client input).
    #[must_use]
    pub fn header_name(&self) -> &str {
        match self {
            Self::Bearer { .. } => "Authorization",
            Self::Header { name, .. } => name.as_str(),
        }
    }

    /// Validates static configuration invariants (valid HTTP header token, no CRLF, valid source).
    pub fn validate(&self) -> Result<(), HttpPolicyError> {
        match self {
            Self::Bearer { source } => validate_credential_source(source, "upstream_auth.bearer"),
            Self::Header { name, source } => {
                if !is_valid_header_name(name) {
                    return Err(HttpPolicyError::InvalidPolicy(format!(
                        "upstream_auth.header: invalid HTTP header name '{name}'"
                    )));
                }
                if is_forbidden_auth_header_name(name) {
                    return Err(HttpPolicyError::InvalidPolicy(format!(
                        "upstream_auth.header: forbidden framing/hop-by-hop header '{name}'"
                    )));
                }
                validate_credential_source(source, "upstream_auth.header")
            }
        }
    }

    /// Loads the credential fail-closed and returns `(header_name, redacted_secret)`.
    pub fn load_header(&self) -> Result<(String, SecretString), SecretError> {
        match self {
            Self::Bearer { source } => {
                let secret = source.load()?;
                Ok(("Authorization".to_string(), secret))
            }
            Self::Header { name, source } => {
                let secret = source.load()?;
                Ok((name.clone(), secret))
            }
        }
    }

    /// Formats the loaded secret into the wire header value (adding `Bearer ` prefix when needed).
    #[must_use]
    pub fn format_header_value(&self, secret: &SecretString) -> String {
        match self {
            Self::Bearer { .. } => format!("Bearer {}", secret.as_str()),
            Self::Header { .. } => secret.as_str().to_string(),
        }
    }
}

fn validate_credential_source(source: &CredentialSource, ctx: &str) -> Result<(), HttpPolicyError> {
    source
        .validate()
        .map_err(|err| HttpPolicyError::InvalidPolicy(format!("{ctx}: {err}")))
}
