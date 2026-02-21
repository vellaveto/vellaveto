//! Gateway types for multi-backend MCP routing (Phase 20).
//!
//! These types define the building blocks for Vellaveto's gateway mode,
//! where tool calls are routed to different upstream MCP servers based
//! on tool name prefix matching.

use serde::{Deserialize, Serialize};

/// Health status of an upstream backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendHealth {
    /// Backend is responding normally.
    #[default]
    Healthy,
    /// Backend has experienced failures but is recovering.
    Degraded,
    /// Backend has exceeded the failure threshold and is excluded from routing.
    Unhealthy,
}

fn default_weight() -> u8 {
    100
}

/// An upstream MCP server backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamBackend {
    /// Unique identifier for this backend.
    pub id: String,
    /// URL of the upstream MCP server.
    pub url: String,
    /// Tool name prefixes this backend handles. Empty = catch-all default.
    pub tool_prefixes: Vec<String>,
    /// Routing weight (1-100). Higher weight = preferred when multiple
    /// backends match. Default: 100.
    #[serde(default = "default_weight")]
    pub weight: u8,
    /// Current health status. Skipped during serialization.
    #[serde(skip, default)]
    pub health: BackendHealth,
}

impl UpstreamBackend {
    /// Validate structural invariants of an `UpstreamBackend`.
    ///
    /// Checks:
    /// - `id` is not empty
    /// - `url` is not empty
    /// - `url` starts with `http://` or `https://`
    /// - `url` host is not a loopback, link-local, or private IP (SSRF)
    ///
    /// SECURITY (FIND-P2-009): Backends with empty URLs could cause panics
    /// or undefined behavior in HTTP clients. Restricting schemes to HTTP(S)
    /// prevents SSRF via `file://`, `gopher://`, etc.
    ///
    /// SECURITY (FIND-R51-011): After scheme validation, parse the URL host
    /// and reject localhost, loopback, link-local, and private IP ranges to
    /// prevent SSRF attacks routing traffic to internal services.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("UpstreamBackend id must not be empty".to_string());
        }
        if self.url.is_empty() {
            return Err(format!(
                "UpstreamBackend '{}' url must not be empty",
                self.id
            ));
        }
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(format!(
                "UpstreamBackend '{}' url must start with http:// or https://, got: {}",
                self.id,
                self.url.chars().take(40).collect::<String>()
            ));
        }
        // SECURITY (FIND-R51-011): Reject SSRF vectors in URL host.
        Self::validate_url_ssrf(&self.url)
            .map_err(|e| format!("UpstreamBackend '{}' url {}", self.id, e))?;
        Ok(())
    }

    /// SECURITY (FIND-R51-011): Validate a backend URL against SSRF vectors.
    ///
    /// Rejects localhost, loopback, link-local, and private IP ranges in the
    /// host portion of the URL. Follows the same pattern as
    /// `FederationTrustAnchor::validate_jwks_uri_ssrf` in abac.rs.
    fn validate_url_ssrf(url: &str) -> Result<(), String> {
        // Extract the scheme-relative portion
        let after_scheme = if let Some(rest) = url.strip_prefix("https://") {
            rest
        } else if let Some(rest) = url.strip_prefix("http://") {
            rest
        } else {
            return Err("must use http(s) scheme".to_string());
        };

        // Extract authority (before first '/')
        let authority = after_scheme
            .find('/')
            .map_or(after_scheme, |i| &after_scheme[..i]);

        // Strip userinfo before '@'
        let host_portion = match authority.rfind('@') {
            Some(at) => &authority[at + 1..],
            None => authority,
        };

        // Extract host (handle IPv6 brackets and port)
        let host = if host_portion.starts_with('[') {
            if let Some(bracket_end) = host_portion.find(']') {
                host_portion[1..bracket_end].to_lowercase()
            } else {
                return Err("malformed IPv6 address (missing ']')".to_string());
            }
        } else {
            let host_end = host_portion
                .find([':', '/', '?', '#'])
                .unwrap_or(host_portion.len());
            host_portion[..host_end].to_lowercase()
        };

        if host.is_empty() {
            return Err("has no host".to_string());
        }

        // Reject localhost/loopback hostnames
        let loopbacks = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
        if loopbacks.iter().any(|lb| host == *lb) {
            return Err(format!(
                "must not target localhost/loopback, got '{}'",
                host
            ));
        }

        // Reject private IPv4 ranges
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            let is_private = ip.is_loopback()
                || ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xf0) == 16)
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
                || ip.octets()[0] == 0;
            if is_private {
                return Err(format!(
                    "must not target private/internal IPs, got '{}'",
                    host
                ));
            }
        }

        // Reject private IPv6 ranges
        if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
            let segs = ip6.segments();
            let is_private = ip6.is_loopback()
                || ip6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80;
            if is_private {
                return Err(format!(
                    "must not target private/internal IPv6 ranges, got '{}'",
                    host
                ));
            }
        }

        Ok(())
    }
}

/// Result of a routing decision.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// ID of the selected backend.
    pub backend_id: String,
    /// URL to forward the request to.
    pub upstream_url: String,
}

/// A tool name conflict detected across multiple backends.
#[derive(Debug, Clone)]
pub struct ToolConflict {
    /// The conflicting tool name.
    pub tool_name: String,
    /// Backend IDs that advertise this tool.
    pub backends: Vec<String>,
}
