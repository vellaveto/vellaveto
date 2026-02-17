//! Phase 29: Cross-Transport Smart Fallback integration tests.
//!
//! Tests the transport health tracker, priority resolution, configuration
//! validation, and backward compatibility when `cross_transport_fallback`
//! is disabled (default).
//!
//! NOTE: Async smart fallback chain tests that require `reqwest::Client` are
//! in `vellaveto-http-proxy/src/proxy/smart_fallback.rs` (unit tests) because
//! the integration test crate does not depend on `reqwest` directly.

use std::collections::HashMap;
use vellaveto_config::TransportConfig;
use vellaveto_http_proxy::proxy::discovery::resolve_transport_priority;
use vellaveto_http_proxy::proxy::transport_health::{
    TransportCircuitState, TransportHealthTracker,
};
use vellaveto_types::{FallbackNegotiationHistory, TransportAttempt, TransportProtocol};

// ═══════════════════════════════════════════════════
// TEST 1: Circuit breaker prevents retry to open transport
// ═══════════════════════════════════════════════════

#[test]
fn test_circuit_breaker_prevents_use_after_threshold() {
    let tracker = TransportHealthTracker::new(2, 1, 300);
    let proto = TransportProtocol::WebSocket;

    // First failure: still closed.
    assert_eq!(
        tracker.record_failure("up", proto),
        TransportCircuitState::Closed
    );
    assert!(tracker.can_use("up", proto).is_ok());

    // Second failure: opens circuit.
    assert_eq!(
        tracker.record_failure("up", proto),
        TransportCircuitState::Open
    );
    assert!(tracker.can_use("up", proto).is_err());

    // Different upstream is not affected.
    assert!(tracker.can_use("other-up", proto).is_ok());
}

// ═══════════════════════════════════════════════════
// TEST 2: Per-tool transport override applied correctly
// ═══════════════════════════════════════════════════

#[test]
fn test_per_tool_override_takes_precedence() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "db_*".to_string(),
        vec![TransportProtocol::Http, TransportProtocol::WebSocket],
    );

    let config = TransportConfig {
        cross_transport_fallback: true,
        transport_overrides: overrides,
        upstream_priorities: vec![TransportProtocol::Grpc],
        ..Default::default()
    };

    // db_ tools get the override.
    let result = resolve_transport_priority("db_query", None, &config);
    assert_eq!(
        result,
        vec![TransportProtocol::Http, TransportProtocol::WebSocket]
    );

    // Non-matching tools get upstream_priorities.
    let result = resolve_transport_priority("fs_read", None, &config);
    assert_eq!(result, vec![TransportProtocol::Grpc]);
}

// ═══════════════════════════════════════════════════
// TEST 3: Available transports filters out open circuits
// ═══════════════════════════════════════════════════

#[test]
fn test_available_transports_filters_open_circuits() {
    let tracker = TransportHealthTracker::new(1, 1, 300);

    // Open gRPC and WebSocket circuits for a specific upstream.
    tracker.record_failure("backend-1", TransportProtocol::Grpc);
    tracker.record_failure("backend-1", TransportProtocol::WebSocket);

    let priorities = vec![
        TransportProtocol::Grpc,
        TransportProtocol::WebSocket,
        TransportProtocol::Http,
    ];

    let available = tracker.available_transports("backend-1", &priorities);
    assert_eq!(available, vec![TransportProtocol::Http]);

    // Different upstream is unaffected.
    let available2 = tracker.available_transports("backend-2", &priorities);
    assert_eq!(available2, priorities);
}

// ═══════════════════════════════════════════════════
// TEST 4: Audit trail negotiation history serde
// ═══════════════════════════════════════════════════

#[test]
fn test_negotiation_history_serde_for_audit() {
    let history = FallbackNegotiationHistory {
        attempts: vec![
            TransportAttempt {
                protocol: TransportProtocol::Grpc,
                endpoint_url: "http://localhost:50051".to_string(),
                succeeded: false,
                duration_ms: 0,
                error: Some("circuit open".to_string()),
            },
            TransportAttempt {
                protocol: TransportProtocol::Http,
                endpoint_url: "http://localhost:3001/mcp".to_string(),
                succeeded: true,
                duration_ms: 15,
                error: None,
            },
        ],
        successful_transport: Some(TransportProtocol::Http),
        total_duration_ms: 15,
    };

    // Should serialize/deserialize cleanly for audit storage.
    let json = serde_json::to_value(&history).unwrap();
    assert_eq!(json["attempts"].as_array().unwrap().len(), 2);
    assert_eq!(json["successful_transport"], "http");
    assert_eq!(json["total_duration_ms"], 15);

    let roundtrip: FallbackNegotiationHistory = serde_json::from_value(json).unwrap();
    assert_eq!(roundtrip, history);
}

// ═══════════════════════════════════════════════════
// TEST 5: Backward compat — cross_transport_fallback: false
// ═══════════════════════════════════════════════════

#[test]
fn test_backward_compat_default_config_no_fallback() {
    let config = TransportConfig::default();
    assert!(!config.cross_transport_fallback);
    assert!(config.transport_overrides.is_empty());
    assert!(!config.stdio_fallback_enabled);
    assert!(config.stdio_command.is_none());
    assert!(config.validate().is_ok());

    // Resolve still works and returns default order.
    let priorities = resolve_transport_priority("any_tool", None, &config);
    assert_eq!(
        priorities,
        vec![
            TransportProtocol::Grpc,
            TransportProtocol::WebSocket,
            TransportProtocol::Http,
        ]
    );
}

// ═══════════════════════════════════════════════════
// TEST 6: Health tracker summary reflects actual state
// ═══════════════════════════════════════════════════

#[test]
fn test_health_tracker_summary_accuracy() {
    let tracker = TransportHealthTracker::new(1, 2, 300);

    // Record various states.
    tracker.record_success("up-a", TransportProtocol::Http); // Closed
    tracker.record_failure("up-b", TransportProtocol::Grpc); // Open
    tracker.record_success("up-c", TransportProtocol::WebSocket); // Closed

    let summary = tracker.summary();
    assert_eq!(summary.total, 3);
    assert_eq!(summary.closed, 2);
    assert_eq!(summary.open, 1);
    assert_eq!(summary.half_open, 0);

    // After reset, the entry is removed.
    tracker.reset("up-b", TransportProtocol::Grpc);
    let summary = tracker.summary();
    assert_eq!(summary.total, 2);
    assert_eq!(summary.open, 0);
}

// ═══════════════════════════════════════════════════
// TEST 7: Config validation cross-transport fields
// ═══════════════════════════════════════════════════

#[test]
fn test_config_validation_cross_transport_fields() {
    // Valid full configuration.
    let mut overrides = HashMap::new();
    overrides.insert(
        "fs_*".to_string(),
        vec![TransportProtocol::Http, TransportProtocol::WebSocket],
    );

    let config = TransportConfig {
        cross_transport_fallback: true,
        transport_overrides: overrides,
        transport_circuit_breaker_failure_threshold: 5,
        transport_circuit_breaker_open_duration_secs: 60,
        stdio_fallback_enabled: true,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    // Invalid: stdio enabled without command.
    let invalid = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: None,
        ..Default::default()
    };
    assert!(invalid.validate().is_err());

    // Invalid: circuit breaker threshold out of range.
    let invalid = TransportConfig {
        transport_circuit_breaker_failure_threshold: 0,
        ..Default::default()
    };
    assert!(invalid.validate().is_err());

    let invalid = TransportConfig {
        transport_circuit_breaker_failure_threshold: 51,
        ..Default::default()
    };
    assert!(invalid.validate().is_err());
}

// ═══════════════════════════════════════════════════
// TEST 8: Restricted transports filtered in resolution
// ═══════════════════════════════════════════════════

#[test]
fn test_restricted_transports_filtered_in_all_paths() {
    let config = TransportConfig {
        restricted_transports: vec![TransportProtocol::Grpc],
        ..Default::default()
    };

    // Default resolution filters gRPC.
    let result = resolve_transport_priority("any_tool", None, &config);
    assert!(!result.contains(&TransportProtocol::Grpc));
    assert_eq!(
        result,
        vec![TransportProtocol::WebSocket, TransportProtocol::Http]
    );

    // Client preference also filtered.
    let prefs = vec![TransportProtocol::Grpc, TransportProtocol::Http];
    let result = resolve_transport_priority("any_tool", Some(&prefs), &config);
    assert_eq!(result, vec![TransportProtocol::Http]);
}
