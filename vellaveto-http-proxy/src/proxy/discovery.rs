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
