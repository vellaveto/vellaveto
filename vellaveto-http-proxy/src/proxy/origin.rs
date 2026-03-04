// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! CSRF and DNS rebinding origin validation.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::net::SocketAddr;

/// Returns `true` if the socket address is bound to a loopback interface
/// (IPv4 `127.0.0.0/8` or IPv6 `::1`).  Used to determine whether
/// automatic localhost-only origin validation should be applied when
/// `allowed_origins` is empty.
pub fn is_loopback_addr(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

/// Loopback host names used to build the automatic localhost origin allowlist.
const LOOPBACK_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// Build the set of allowed origins for a loopback bind address.
///
/// Given a port, returns origins like `http://localhost:<port>`,
/// `http://127.0.0.1:<port>`, `http://[::1]:<port>` (and their `https://`
/// equivalents).
pub fn build_loopback_origins(port: u16) -> Vec<String> {
    let mut origins = Vec::with_capacity(LOOPBACK_HOSTS.len() * 2);
    for host in LOOPBACK_HOSTS {
        origins.push(format!("http://{}:{}", host, port));
        origins.push(format!("https://{}:{}", host, port));
    }
    origins
}

/// Validate the Origin header for CSRF and DNS rebinding protection.
///
/// DNS rebinding defense (CVE-2025-66414/CVE-2025-66416): When the proxy is
/// bound to a loopback address (`127.0.0.1`, `[::1]`) and no explicit
/// `allowed_origins` are configured, only localhost origins are accepted.
/// This prevents a malicious webpage from rebinding its domain to 127.0.0.1
/// and making cross-origin requests that bypass browser same-origin policy.
///
/// Returns `Ok(())` if:
/// - No `Origin` header is present (non-browser client — API clients don't send Origin)
/// - `allowed_origins` is non-empty and contains the Origin value (or `"*"`)
/// - `allowed_origins` is empty, bind address is loopback, and Origin is a localhost variant
/// - `allowed_origins` is empty, bind address is non-loopback, and Origin host matches Host header
///
/// Returns `Err(response)` with HTTP 403 and a JSON-RPC error if the origin is not allowed.
///
/// SECURITY: Logs rejected origins at warn level. Does NOT log Cookie or
/// Authorization headers to avoid credential leaks in logs.
#[allow(clippy::result_large_err)]
pub fn validate_origin(
    headers: &HeaderMap,
    bind_addr: &SocketAddr,
    allowed_origins: &[String],
) -> Result<(), Response> {
    // If no Origin header present, allow (non-browser client)
    let origin = match headers.get("origin").and_then(|o| o.to_str().ok()) {
        Some(o) => o,
        None => return Ok(()),
    };

    // If explicit allowlist is configured, use it
    if !allowed_origins.is_empty() {
        if allowed_origins.iter().any(|a| a == origin || a == "*") {
            // SECURITY (FIND-R51-011): Warn when wildcard "*" disables origin protection.
            if allowed_origins.iter().any(|o| o == "*") {
                tracing::warn!(
                    target: "vellaveto::security",
                    "SECURITY: allowed_origins contains '*' — CSRF and DNS rebinding protection is DISABLED"
                );
            }
            return Ok(());
        }
        tracing::warn!(
            origin = %origin,
            "DNS rebinding defense: rejected request with Origin not in allowed_origins"
        );
        return Err(make_origin_rejection_response());
    }

    // No explicit allowlist — use automatic detection based on bind address
    if is_loopback_addr(bind_addr) {
        // SECURITY (TASK-015): DNS rebinding defense for localhost-bound proxies.
        // Only accept origins that resolve to loopback addresses.
        // A DNS rebinding attack would present an Origin like "http://evil.com"
        // even though the request reaches 127.0.0.1 — we must reject it.
        let loopback_origins = build_loopback_origins(bind_addr.port());
        if loopback_origins.iter().any(|lo| lo == origin) {
            return Ok(());
        }
        tracing::warn!(
            origin = %origin,
            bind_addr = %bind_addr,
            "DNS rebinding defense: rejected non-localhost Origin on loopback-bound proxy"
        );
        return Err(make_origin_rejection_response());
    }

    // Non-loopback bind: fall back to same-origin check (Origin host must match Host header)
    // SECURITY (R23-PROXY-3): Lowercase the Host header for case-insensitive
    // comparison — DNS names are case-insensitive per RFC 4343, and
    // extract_authority_from_origin already lowercases the Origin authority.
    let host_raw = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let host = host_raw.to_lowercase();
    let host = host.as_str();

    // Extract host:port from origin URL (e.g., "http://localhost:3001" -> "localhost:3001")
    if let Some(origin_authority) = extract_authority_from_origin(origin) {
        if origin_authority == host {
            return Ok(());
        }
        // Also match if host lacks a port (e.g., origin "http://localhost:3001" vs host "localhost")
        if let Some(colon_pos) = origin_authority.rfind(':') {
            if &origin_authority[..colon_pos] == host {
                return Ok(());
            }
        }
    }

    tracing::warn!(
        origin = %origin,
        host = %host_raw,
        "CSRF protection: rejected request with mismatched Origin and Host"
    );
    Err(make_origin_rejection_response())
}

/// Build a 403 Forbidden response with a JSON-RPC error body for origin rejection.
///
/// Returns a JSON-RPC 2.0 error response instead of a plain REST error because
/// the HTTP proxy speaks the MCP JSON-RPC protocol. Clients expect errors in
/// the format `{ "jsonrpc": "2.0", "error": { "code": <int>, "message": <string> } }`.
/// Code `-32001` is a server-defined error in the JSON-RPC reserved range
/// (`-32000` to `-32099`), used here for origin/CSRF rejections.
///
/// FIND-R56-HTTP-004: Removed unused `origin` parameter — the origin value is
/// intentionally NOT included in the response body to prevent information leakage.
pub fn make_origin_rejection_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32001,
                "message": "Origin not allowed"
            }
        })),
    )
        .into_response()
}

/// Extract the authority (host:port) from an origin URL string.
///
/// E.g., `"http://localhost:3001"` -> `Some("localhost:3001")`
/// E.g., `"https://example.com"` -> `Some("example.com")`
///
/// Returns `None` if the URL cannot be parsed.
pub fn extract_authority_from_origin(origin: &str) -> Option<String> {
    // Origin format per RFC 6454: "scheme://host[:port]"
    // Defence-in-depth: strip path, query, fragment, and userinfo even though
    // a valid Origin header should never contain them.
    let authority_start = origin.find("://").map(|i| i + 3)?;
    let authority = &origin[authority_start..];
    // Strip path, query, and fragment
    let authority = authority.split('/').next().unwrap_or(authority);
    let authority = authority.split('?').next().unwrap_or(authority);
    let authority = authority.split('#').next().unwrap_or(authority);
    // Strip userinfo (RFC 3986 §3.2.1: userinfo@host)
    let authority = if let Some(at_pos) = authority.rfind('@') {
        &authority[at_pos + 1..]
    } else {
        authority
    };
    // Validate: authority must only contain alphanumeric, '.', '-', ':', '[', ']'
    // (brackets for IPv6 like [::1]:3001)
    if authority.is_empty()
        || !authority
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return None;
    }
    Some(authority.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    // =========================================================================
    // is_loopback_addr tests
    // =========================================================================

    #[test]
    fn test_is_loopback_addr_ipv4_localhost() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        assert!(is_loopback_addr(&addr));
    }

    #[test]
    fn test_is_loopback_addr_ipv4_127_range() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 42), 3000));
        assert!(is_loopback_addr(&addr));
    }

    #[test]
    fn test_is_loopback_addr_ipv6_localhost() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3000, 0, 0));
        assert!(is_loopback_addr(&addr));
    }

    #[test]
    fn test_is_loopback_addr_non_loopback_ipv4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 3000));
        assert!(!is_loopback_addr(&addr));
    }

    #[test]
    fn test_is_loopback_addr_non_loopback_ipv6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3000, 0, 0));
        assert!(!is_loopback_addr(&addr));
    }

    // =========================================================================
    // build_loopback_origins tests
    // =========================================================================

    #[test]
    fn test_build_loopback_origins_includes_all_variants() {
        let origins = build_loopback_origins(3000);
        assert_eq!(origins.len(), 6);
        assert!(origins.contains(&"http://localhost:3000".to_string()));
        assert!(origins.contains(&"https://localhost:3000".to_string()));
        assert!(origins.contains(&"http://127.0.0.1:3000".to_string()));
        assert!(origins.contains(&"https://127.0.0.1:3000".to_string()));
        assert!(origins.contains(&"http://[::1]:3000".to_string()));
        assert!(origins.contains(&"https://[::1]:3000".to_string()));
    }

    #[test]
    fn test_build_loopback_origins_different_port() {
        let origins = build_loopback_origins(8443);
        assert!(origins.contains(&"http://localhost:8443".to_string()));
        assert!(origins.contains(&"https://[::1]:8443".to_string()));
    }

    // =========================================================================
    // extract_authority_from_origin tests
    // =========================================================================

    #[test]
    fn test_extract_authority_http_localhost_port() {
        assert_eq!(
            extract_authority_from_origin("http://localhost:3001"),
            Some("localhost:3001".to_string())
        );
    }

    #[test]
    fn test_extract_authority_https_domain() {
        assert_eq!(
            extract_authority_from_origin("https://example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_authority_strips_path() {
        assert_eq!(
            extract_authority_from_origin("http://example.com:8080/path/to/page"),
            Some("example.com:8080".to_string())
        );
    }

    #[test]
    fn test_extract_authority_strips_query() {
        assert_eq!(
            extract_authority_from_origin("http://example.com?query=val"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_authority_strips_fragment() {
        assert_eq!(
            extract_authority_from_origin("http://example.com#section"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_authority_strips_userinfo() {
        assert_eq!(
            extract_authority_from_origin("http://user:pass@example.com:8080"),
            Some("example.com:8080".to_string())
        );
    }

    #[test]
    fn test_extract_authority_lowercases() {
        assert_eq!(
            extract_authority_from_origin("http://EXAMPLE.COM"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_authority_ipv6() {
        assert_eq!(
            extract_authority_from_origin("http://[::1]:3001"),
            Some("[::1]:3001".to_string())
        );
    }

    #[test]
    fn test_extract_authority_no_scheme_returns_none() {
        assert_eq!(extract_authority_from_origin("example.com"), None);
    }

    #[test]
    fn test_extract_authority_empty_authority_returns_none() {
        assert_eq!(extract_authority_from_origin("http:///path"), None);
    }

    #[test]
    fn test_extract_authority_invalid_chars_returns_none() {
        assert_eq!(
            extract_authority_from_origin("http://example.com<script>"),
            None
        );
    }

    // =========================================================================
    // validate_origin tests
    // =========================================================================

    #[test]
    fn test_validate_origin_no_header_allows() {
        let headers = HeaderMap::new();
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        assert!(validate_origin(&headers, &bind, &[]).is_ok());
    }

    #[test]
    fn test_validate_origin_allowlist_match() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://app.example.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let allowed = vec!["http://app.example.com".to_string()];
        assert!(validate_origin(&headers, &bind, &allowed).is_ok());
    }

    #[test]
    fn test_validate_origin_allowlist_wildcard() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://any-origin.example.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let allowed = vec!["*".to_string()];
        assert!(validate_origin(&headers, &bind, &allowed).is_ok());
    }

    #[test]
    fn test_validate_origin_allowlist_mismatch_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://evil.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
        let allowed = vec!["http://trusted.com".to_string()];
        assert!(validate_origin(&headers, &bind, &allowed).is_err());
    }

    #[test]
    fn test_validate_origin_loopback_localhost_allowed() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://localhost:3000".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        assert!(validate_origin(&headers, &bind, &[]).is_ok());
    }

    #[test]
    fn test_validate_origin_loopback_rejects_external() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://evil.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000));
        assert!(validate_origin(&headers, &bind, &[]).is_err());
    }

    #[test]
    fn test_validate_origin_non_loopback_same_origin_allowed() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://myserver.com:8080".parse().unwrap());
        headers.insert("host", "myserver.com:8080".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        assert!(validate_origin(&headers, &bind, &[]).is_ok());
    }

    #[test]
    fn test_validate_origin_non_loopback_mismatch_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://evil.com:8080".parse().unwrap());
        headers.insert("host", "myserver.com:8080".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        assert!(validate_origin(&headers, &bind, &[]).is_err());
    }

    #[test]
    fn test_validate_origin_host_without_port_matches_origin_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://myserver.com:8080".parse().unwrap());
        headers.insert("host", "myserver.com".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        assert!(validate_origin(&headers, &bind, &[]).is_ok());
    }

    #[test]
    fn test_validate_origin_case_insensitive_host() {
        let mut headers = HeaderMap::new();
        headers.insert("origin", "http://MyServer.COM:8080".parse().unwrap());
        headers.insert("host", "MYSERVER.com:8080".parse().unwrap());
        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        assert!(validate_origin(&headers, &bind, &[]).is_ok());
    }
}
