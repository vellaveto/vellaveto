//! Transport discovery and negotiation endpoint.
//!
//! Implements `GET /.well-known/mcp-transport` (RFC 8615) for MCP June 2026
//! spec compliance. Advertises available transports, SDK tier, and supported
//! protocol versions.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use vellaveto_config::TransportConfig;
use vellaveto_types::{SdkCapabilities, SdkTier, TransportEndpoint, TransportProtocol};

use super::{ProxyState, SUPPORTED_PROTOCOL_VERSIONS};

/// Vellaveto's declared SDK tier.
///
/// Vellaveto provides multi-transport support, advanced threat detection,
/// compliance evidence, and protocol extensions — qualifying as Extended.
pub const VELLAVETO_SDK_TIER: SdkTier = SdkTier::Extended;

/// Build SDK capabilities for the current Vellaveto instance.
pub fn build_sdk_capabilities() -> SdkCapabilities {
    SdkCapabilities {
        tier: VELLAVETO_SDK_TIER,
        capabilities: vec![
            "policy-evaluation".to_string(),
            "audit-logging".to_string(),
            "dlp-scanning".to_string(),
            "injection-detection".to_string(),
            "multi-transport".to_string(),
            "threat-detection".to_string(),
            "compliance-evidence".to_string(),
            "protocol-extensions".to_string(),
            "human-approval".to_string(),
            "oauth-validation".to_string(),
            "transport-negotiation".to_string(),
            "backward-compatibility".to_string(),
        ],
        supported_versions: SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

/// Build the list of available transport endpoints for the discovery response.
pub fn build_transport_endpoints(state: &ProxyState) -> Vec<TransportEndpoint> {
    let restricted = &state.transport_config.restricted_transports;
    let versions: Vec<String> = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut endpoints = Vec::new();

    // HTTP is always available (primary transport).
    if !restricted.contains(&TransportProtocol::Http) {
        let base = format!("http://{}/mcp", state.bind_addr);
        endpoints.push(TransportEndpoint {
            protocol: TransportProtocol::Http,
            url: base,
            available: true,
            protocol_versions: versions.clone(),
        });
    }

    // WebSocket is always available alongside HTTP.
    if !restricted.contains(&TransportProtocol::WebSocket) {
        let ws_url = format!("ws://{}/mcp/ws", state.bind_addr);
        endpoints.push(TransportEndpoint {
            protocol: TransportProtocol::WebSocket,
            url: ws_url,
            available: true,
            protocol_versions: versions.clone(),
        });
    }

    // gRPC is available only when a gRPC port is configured.
    if !restricted.contains(&TransportProtocol::Grpc) {
        if let Some(grpc_port) = state.grpc_port {
            let grpc_url = format!("http://{}:{}", state.bind_addr.ip(), grpc_port);
            endpoints.push(TransportEndpoint {
                protocol: TransportProtocol::Grpc,
                url: grpc_url,
                available: true,
                protocol_versions: versions,
            });
        }
    }

    endpoints
}

/// Discovery response returned by `GET /.well-known/mcp-transport`.
#[derive(Debug, Serialize)]
pub struct TransportDiscoveryResponse {
    /// Available transport endpoints.
    pub transports: Vec<TransportEndpoint>,
    /// SDK capabilities and tier.
    pub sdk: SdkCapabilities,
    /// Supported protocol versions (highest first).
    pub protocol_versions: Vec<String>,
}

/// Handler for `GET /.well-known/mcp-transport`.
///
/// Returns a JSON discovery document describing available transports,
/// SDK tier, and supported protocol versions. Returns 404 when
/// `transport.discovery_enabled` is false.
pub async fn handle_transport_discovery(State(state): State<ProxyState>) -> Response {
    if !state.transport_config.discovery_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let transports = build_transport_endpoints(&state);
    let sdk = if state.transport_config.advertise_capabilities {
        build_sdk_capabilities()
    } else {
        SdkCapabilities {
            tier: VELLAVETO_SDK_TIER,
            capabilities: Vec::new(),
            supported_versions: Vec::new(),
        }
    };

    let response = TransportDiscoveryResponse {
        transports,
        sdk,
        protocol_versions: SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };

    Json(response).into_response()
}

/// Parse the `mcp-transport-preference` header value into an ordered list
/// of `TransportProtocol` values. Unknown values are silently ignored.
pub fn parse_transport_preference(header: &str) -> Vec<TransportProtocol> {
    header
        .split(',')
        .filter_map(|s| match s.trim().to_lowercase().as_str() {
            "grpc" => Some(TransportProtocol::Grpc),
            "websocket" | "ws" => Some(TransportProtocol::WebSocket),
            "http" | "sse" => Some(TransportProtocol::Http),
            "stdio" => Some(TransportProtocol::Stdio),
            _ => None,
        })
        .collect()
}

/// Negotiate the best available transport given client preferences,
/// available endpoints, and restricted transports.
///
/// Pure logic — no I/O, no async. Returns the first preferred endpoint
/// that is both available and not restricted.
pub fn negotiate_transport(
    preferences: &[TransportProtocol],
    available: &[TransportEndpoint],
    restricted: &[TransportProtocol],
) -> Option<TransportEndpoint> {
    for pref in preferences {
        if restricted.contains(pref) {
            continue;
        }
        if let Some(endpoint) = available
            .iter()
            .find(|e| e.protocol == *pref && e.available)
        {
            return Some(endpoint.clone());
        }
    }
    None
}

/// Resolve transport priority order for a given tool name (Phase 29).
///
/// Resolution order (first match wins):
/// 1. Per-tool override from `config.transport_overrides` (glob match)
/// 2. Client preference from `mcp-transport-preference` header
/// 3. `config.upstream_priorities`
/// 4. Default: `[Grpc, WebSocket, Http]` (Stdio only if `stdio_fallback_enabled`)
///
/// Restricted transports are filtered out in all cases.
pub fn resolve_transport_priority(
    tool_name: &str,
    client_preference: Option<&[TransportProtocol]>,
    config: &TransportConfig,
) -> Vec<TransportProtocol> {
    let restricted = &config.restricted_transports;

    // 1. Per-tool override (glob match).
    for (glob_pattern, protos) in &config.transport_overrides {
        if glob_matches(glob_pattern, tool_name) {
            return filter_restricted(protos, restricted, config.stdio_fallback_enabled);
        }
    }

    // 2. Client preference.
    if let Some(prefs) = client_preference {
        if !prefs.is_empty() {
            return filter_restricted(prefs, restricted, config.stdio_fallback_enabled);
        }
    }

    // 3. Config upstream_priorities.
    if !config.upstream_priorities.is_empty() {
        return filter_restricted(
            &config.upstream_priorities,
            restricted,
            config.stdio_fallback_enabled,
        );
    }

    // 4. Default order.
    let mut defaults = vec![
        TransportProtocol::Grpc,
        TransportProtocol::WebSocket,
        TransportProtocol::Http,
    ];
    if config.stdio_fallback_enabled {
        defaults.push(TransportProtocol::Stdio);
    }
    filter_restricted(&defaults, restricted, config.stdio_fallback_enabled)
}

/// Filter out restricted transports and stdio (unless enabled).
fn filter_restricted(
    protos: &[TransportProtocol],
    restricted: &[TransportProtocol],
    stdio_enabled: bool,
) -> Vec<TransportProtocol> {
    protos
        .iter()
        .copied()
        .filter(|p| !restricted.contains(p))
        .filter(|p| *p != TransportProtocol::Stdio || stdio_enabled)
        .collect()
}

/// Simple glob matching for tool name patterns.
///
/// Supports `*` (match any characters) and `?` (match single character).
/// Used for `transport_overrides` keys.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    glob_matches_recursive(&pattern_chars, &text_chars, 0, 0)
}

fn glob_matches_recursive(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() {
        return ti == text.len();
    }

    match pattern[pi] {
        '*' => {
            // Try matching zero or more characters.
            for i in ti..=text.len() {
                if glob_matches_recursive(pattern, text, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < text.len() {
                glob_matches_recursive(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
        c => {
            if ti < text.len() && text[ti] == c {
                glob_matches_recursive(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::collections::HashMap;

    fn default_config() -> TransportConfig {
        TransportConfig::default()
    }

    #[test]
    fn test_resolve_transport_priority_default_order() {
        let config = default_config();
        let result = resolve_transport_priority("any_tool", None, &config);
        assert_eq!(
            result,
            vec![
                TransportProtocol::Grpc,
                TransportProtocol::WebSocket,
                TransportProtocol::Http,
            ]
        );
    }

    #[test]
    fn test_resolve_transport_priority_config_priorities() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http, TransportProtocol::Grpc],
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert_eq!(
            result,
            vec![TransportProtocol::Http, TransportProtocol::Grpc]
        );
    }

    #[test]
    fn test_resolve_transport_priority_client_preference() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http],
            ..default_config()
        };
        let prefs = vec![TransportProtocol::WebSocket, TransportProtocol::Http];
        let result = resolve_transport_priority("any_tool", Some(&prefs), &config);
        // Client preference takes precedence over config.
        assert_eq!(
            result,
            vec![TransportProtocol::WebSocket, TransportProtocol::Http]
        );
    }

    #[test]
    fn test_resolve_transport_priority_per_tool_override() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "fs_*".to_string(),
            vec![TransportProtocol::Http, TransportProtocol::WebSocket],
        );
        let config = TransportConfig {
            transport_overrides: overrides,
            upstream_priorities: vec![TransportProtocol::Grpc],
            ..default_config()
        };
        let prefs = vec![TransportProtocol::Grpc];
        // Per-tool override takes highest precedence.
        let result = resolve_transport_priority("fs_read", Some(&prefs), &config);
        assert_eq!(
            result,
            vec![TransportProtocol::Http, TransportProtocol::WebSocket]
        );
    }

    #[test]
    fn test_resolve_transport_priority_per_tool_no_match() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "fs_*".to_string(),
            vec![TransportProtocol::Http],
        );
        let config = TransportConfig {
            transport_overrides: overrides,
            ..default_config()
        };
        // Tool doesn't match the glob, so falls through to default.
        let result = resolve_transport_priority("db_query", None, &config);
        assert_eq!(
            result,
            vec![
                TransportProtocol::Grpc,
                TransportProtocol::WebSocket,
                TransportProtocol::Http,
            ]
        );
    }

    #[test]
    fn test_resolve_transport_priority_restricted_filtered() {
        let config = TransportConfig {
            restricted_transports: vec![TransportProtocol::Grpc],
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert!(!result.contains(&TransportProtocol::Grpc));
        assert_eq!(
            result,
            vec![TransportProtocol::WebSocket, TransportProtocol::Http]
        );
    }

    #[test]
    fn test_resolve_transport_priority_stdio_only_when_enabled() {
        let config = TransportConfig {
            stdio_fallback_enabled: true,
            stdio_command: Some("/usr/bin/mcp".to_string()),
            ..default_config()
        };
        let result = resolve_transport_priority("any_tool", None, &config);
        assert!(result.contains(&TransportProtocol::Stdio));

        // Without stdio enabled, Stdio should not appear.
        let config2 = default_config();
        let result2 = resolve_transport_priority("any_tool", None, &config2);
        assert!(!result2.contains(&TransportProtocol::Stdio));
    }

    #[test]
    fn test_resolve_transport_priority_empty_client_preference() {
        let config = TransportConfig {
            upstream_priorities: vec![TransportProtocol::Http],
            ..default_config()
        };
        // Empty preference should fall through to config.upstream_priorities.
        let result = resolve_transport_priority("any_tool", Some(&[]), &config);
        assert_eq!(result, vec![TransportProtocol::Http]);
    }

    #[test]
    fn test_glob_matches_basic() {
        assert!(glob_matches("fs_*", "fs_read"));
        assert!(glob_matches("fs_*", "fs_"));
        assert!(!glob_matches("fs_*", "db_read"));
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("?s_read", "fs_read"));
        assert!(!glob_matches("?s_read", "ffs_read"));
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "exactx"));
    }
}
