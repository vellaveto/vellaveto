//! Integration tests for Phase 18: Transport negotiation and backward compatibility.
//!
//! Verifies that the transport discovery, negotiation, and protocol version
//! handling works correctly across supported MCP spec versions.

use vellaveto_types::{TransportEndpoint, TransportProtocol};

#[test]
fn test_backward_compat_no_transport_header() {
    // Clients that don't send the mcp-transport-preference header should
    // still work — HTTP is the implicit default.
    let prefs: Vec<TransportProtocol> =
        vellaveto_http_proxy::proxy::discovery::parse_transport_preference("");
    assert!(
        prefs.is_empty(),
        "Empty preference should result in empty list (HTTP implicit default)"
    );
}

#[test]
fn test_backward_compat_2025_03_26_version() {
    // Oldest supported version must still be in the supported list.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    assert!(
        caps.supported_versions.contains(&"2025-03-26".to_string()),
        "Oldest supported version (2025-03-26) must remain in supported_versions"
    );
}

#[test]
fn test_highest_supported_version_is_2025_11_25() {
    // The highest supported version must be 2025-11-25.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    assert!(
        caps.supported_versions.contains(&"2025-11-25".to_string()),
        "2025-11-25 must be in supported_versions"
    );
    // It should be the first (highest priority) entry.
    assert_eq!(
        caps.supported_versions[0], "2025-11-25",
        "2025-11-25 should be the first supported version"
    );
}

#[test]
fn test_transport_protocol_preference_order() {
    // Verify the natural ordering: Grpc < WebSocket < Http < Stdio
    assert!(TransportProtocol::Grpc < TransportProtocol::WebSocket);
    assert!(TransportProtocol::WebSocket < TransportProtocol::Http);
    assert!(TransportProtocol::Http < TransportProtocol::Stdio);
}

#[test]
fn test_discovery_response_structure() {
    // Verify SDK capabilities serialize to the expected shape.
    let caps = vellaveto_http_proxy::proxy::discovery::build_sdk_capabilities();
    let json = serde_json::to_value(&caps).unwrap();
    assert!(json.get("tier").is_some(), "Must have tier field");
    assert!(
        json.get("capabilities").is_some(),
        "Must have capabilities field"
    );
    assert!(
        json.get("supported_versions").is_some(),
        "Must have supported_versions field"
    );

    // Verify TransportEndpoint serializes correctly.
    let endpoint = TransportEndpoint {
        protocol: TransportProtocol::Http,
        url: "http://localhost:3001/mcp".to_string(),
        available: true,
        protocol_versions: vec!["2026-06".to_string()],
    };
    let endpoint_json = serde_json::to_value(&endpoint).unwrap();
    assert_eq!(endpoint_json["protocol"], "http");
    assert_eq!(endpoint_json["available"], true);
}
