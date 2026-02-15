//! Unit tests for WebSocket transport (Phase 17.1 — SEP-1288).

use super::*;
use serde_json::json;
use vellaveto_mcp::extractor::{self, MessageType};

// ==========================================================================
// URL conversion tests
// ==========================================================================

#[test]
fn test_ws_url_scheme_conversion_http_to_ws() {
    assert_eq!(
        convert_to_ws_url("http://localhost:8000/mcp"),
        "ws://localhost:8000/mcp"
    );
}

#[test]
fn test_ws_url_scheme_conversion_https_to_wss() {
    assert_eq!(
        convert_to_ws_url("https://mcp.example.com/mcp"),
        "wss://mcp.example.com/mcp"
    );
}

#[test]
fn test_ws_url_scheme_passthrough_ws() {
    assert_eq!(
        convert_to_ws_url("ws://localhost:8000/mcp"),
        "ws://localhost:8000/mcp"
    );
}

#[test]
fn test_ws_url_scheme_passthrough_wss() {
    assert_eq!(
        convert_to_ws_url("wss://mcp.example.com/mcp"),
        "wss://mcp.example.com/mcp"
    );
}

#[test]
fn test_ws_url_scheme_unknown_passthrough() {
    assert_eq!(
        convert_to_ws_url("ftp://files.example.com"),
        "ftp://files.example.com"
    );
}

// ==========================================================================
// Rate limiting tests
// ==========================================================================

#[test]
fn test_ws_rate_limit_allows_within_limit() {
    let counter = AtomicU64::new(0);
    let window = std::sync::Mutex::new(std::time::Instant::now());

    // 10 messages at limit of 100/s should all pass
    for _ in 0..10 {
        assert!(check_rate_limit(&counter, &window, 100));
    }
}

#[test]
fn test_ws_rate_limit_blocks_over_limit() {
    let counter = AtomicU64::new(0);
    let window = std::sync::Mutex::new(std::time::Instant::now());

    // Fill up the limit
    for _ in 0..5 {
        assert!(check_rate_limit(&counter, &window, 5));
    }

    // 6th message should be rejected
    assert!(!check_rate_limit(&counter, &window, 5));
}

#[test]
fn test_ws_rate_limit_zero_means_unlimited() {
    let counter = AtomicU64::new(0);
    let window = std::sync::Mutex::new(std::time::Instant::now());

    // With limit=0, all messages should pass
    for _ in 0..1000 {
        assert!(check_rate_limit(&counter, &window, 0));
    }
}

#[test]
fn test_ws_rate_limit_resets_after_window() {
    let counter = AtomicU64::new(0);
    // Start window 2 seconds in the past to simulate window expiry
    let window =
        std::sync::Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(2));

    // Fill and exceed
    for _ in 0..5 {
        check_rate_limit(&counter, &window, 5);
    }

    // After window reset (the next call detects elapsed > 1s), should allow
    // Force a new window by setting start far in the past
    *window.lock().unwrap() = std::time::Instant::now() - std::time::Duration::from_secs(2);
    counter.store(0, Ordering::Relaxed);

    assert!(check_rate_limit(&counter, &window, 5));
}

// ==========================================================================
// Text frame classification tests
// ==========================================================================

#[test]
fn test_ws_text_frame_tool_call_classified() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/test"}
        }
    });

    match extractor::classify_message(&msg) {
        MessageType::ToolCall {
            id,
            tool_name,
            arguments,
        } => {
            assert_eq!(id, 1);
            assert_eq!(tool_name, "read_file");
            assert_eq!(arguments["path"], "/tmp/test");
        }
        other => panic!("Expected ToolCall, got {:?}", other),
    }
}

#[test]
fn test_ws_text_frame_passthrough_response() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": []}
    });

    assert!(matches!(
        extractor::classify_message(&msg),
        MessageType::PassThrough
    ));
}

#[test]
fn test_ws_text_frame_batch_rejected() {
    let msg = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "a", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "b", "arguments": {}}}
    ]);

    assert!(matches!(
        extractor::classify_message(&msg),
        MessageType::Batch
    ));
}

#[test]
fn test_ws_text_frame_invalid_no_method() {
    let msg = json!({"jsonrpc": "2.0", "id": 42});
    assert!(matches!(
        extractor::classify_message(&msg),
        MessageType::Invalid { .. }
    ));
}

// ==========================================================================
// make_ws_error_response tests
// ==========================================================================

#[test]
fn test_ws_error_response_with_id() {
    let id = json!(42);
    let response = make_ws_error_response(Some(&id), -32600, "Bad request");
    let parsed: Value = serde_json::from_str(&response).expect("valid JSON");

    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["error"]["code"], -32600);
    assert_eq!(parsed["error"]["message"], "Bad request");
}

#[test]
fn test_ws_error_response_null_id() {
    let response = make_ws_error_response(None, -32001, "Denied");
    let parsed: Value = serde_json::from_str(&response).expect("valid JSON");

    assert_eq!(parsed["id"], Value::Null);
    assert_eq!(parsed["error"]["code"], -32001);
}

#[test]
fn test_ws_error_response_string_id() {
    let id = json!("req-abc");
    let response = make_ws_error_response(Some(&id), -32001, "Denied by policy");
    let parsed: Value = serde_json::from_str(&response).expect("valid JSON");

    assert_eq!(parsed["id"], "req-abc");
}

// ==========================================================================
// extract_scannable_text tests
// ==========================================================================

#[test]
fn test_ws_scannable_text_from_result_content() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {"type": "text", "text": "Hello world"},
                {"type": "text", "text": "Second line"}
            ]
        }
    });

    let text = extract_scannable_text(&response);
    assert!(text.contains("Hello world"));
    assert!(text.contains("Second line"));
}

#[test]
fn test_ws_scannable_text_from_error() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "Something went wrong",
            "data": "extra error detail"
        }
    });

    let text = extract_scannable_text(&response);
    assert!(text.contains("Something went wrong"));
    assert!(text.contains("extra error detail"));
}

#[test]
fn test_ws_scannable_text_from_instructions() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "instructionsForUser": "Please click yes",
            "content": []
        }
    });

    let text = extract_scannable_text(&response);
    assert!(text.contains("Please click yes"));
}

#[test]
fn test_ws_scannable_text_empty_for_non_result() {
    let response = json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {"progress": 50}
    });

    let text = extract_scannable_text(&response);
    assert!(text.is_empty());
}

#[test]
fn test_ws_scannable_text_structured_content() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "structuredContent": {"key": "value", "nested": {"a": "b"}},
            "content": []
        }
    });

    let text = extract_scannable_text(&response);
    assert!(text.contains("key"));
    assert!(text.contains("value"));
}

// ==========================================================================
// WebSocketConfig tests
// ==========================================================================

#[test]
fn test_ws_config_defaults() {
    let config = WebSocketConfig::default();
    assert_eq!(config.max_message_size, 1_048_576);
    assert_eq!(config.idle_timeout_secs, 300);
    assert_eq!(config.message_rate_limit, 100);
}

#[test]
fn test_ws_config_custom_values() {
    let config = WebSocketConfig {
        max_message_size: 512_000,
        idle_timeout_secs: 60,
        message_rate_limit: 50,
    };
    assert_eq!(config.max_message_size, 512_000);
    assert_eq!(config.idle_timeout_secs, 60);
    assert_eq!(config.message_rate_limit, 50);
}

// ==========================================================================
// Close code constants tests
// ==========================================================================

#[test]
fn test_ws_close_codes() {
    assert_eq!(CLOSE_POLICY_VIOLATION, 1008);
    assert_eq!(CLOSE_UNSUPPORTED_DATA, 1003);
    assert_eq!(CLOSE_MESSAGE_TOO_BIG, 1009);
    assert_eq!(CLOSE_NORMAL, 1000);
}

// ==========================================================================
// Metrics counter tests
// ==========================================================================

#[test]
fn test_ws_connections_counter_increments() {
    let before = ws_connections_count();
    record_ws_connection();
    let after = ws_connections_count();
    assert!(after > before);
}

#[test]
fn test_ws_messages_counter_increments() {
    let before = ws_messages_count();
    record_ws_message("test");
    let after = ws_messages_count();
    assert!(after > before);
}

// ==========================================================================
// build_ws_evaluation_context tests
// ==========================================================================

#[test]
fn test_ws_evaluation_context_default_without_session() {
    let state = make_test_state();
    let ctx = build_ws_evaluation_context(&state, "nonexistent-session");
    assert!(ctx.agent_id.is_none());
    assert!(ctx.call_counts.is_empty());
    assert!(ctx.previous_actions.is_empty());
}

#[test]
fn test_ws_evaluation_context_with_session() {
    let state = make_test_state();

    // Create a session
    let session_id = state.sessions.get_or_create(None);

    // Add session state
    {
        let mut session = state.sessions.get_mut(&session_id).unwrap();
        session.oauth_subject = Some("agent-42".to_string());
        session.call_counts.insert("read_file".to_string(), 3);
        session.action_history.push_back("read_file".to_string());
        session.action_history.push_back("write_file".to_string());
    }

    let ctx = build_ws_evaluation_context(&state, &session_id);
    assert_eq!(ctx.agent_id.as_deref(), Some("agent-42"));
    assert_eq!(ctx.call_counts.get("read_file"), Some(&3));
    assert_eq!(ctx.previous_actions.len(), 2);
    assert_eq!(ctx.previous_actions[0], "read_file");
    assert_eq!(ctx.previous_actions[1], "write_file");
}

// ==========================================================================
// WsQueryParams tests
// ==========================================================================

#[test]
fn test_ws_query_params_default() {
    let params = WsQueryParams::default();
    assert!(params.session_id.is_none());
}

// ==========================================================================
// Test helper: build a minimal ProxyState for unit tests
// ==========================================================================

// ==========================================================================
// TaskRequest policy enforcement tests
// ==========================================================================

#[test]
fn test_task_request_policy_deny_ws() {
    // With no policies, task requests should be denied (fail-closed)
    let state = make_test_state();
    let session_id = state.sessions.get_or_create(None);

    let action = extractor::extract_task_action("tasks/get", Some("task-123"));
    let ctx = build_ws_evaluation_context(&state, &session_id);

    let verdict = state
        .engine
        .evaluate_action_with_context(&action, &state.policies, Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}

#[test]
fn test_task_request_policy_allow_ws() {
    // With a wildcard allow policy, task requests should be allowed
    let state = make_test_state_with_allow_all();
    let session_id = state.sessions.get_or_create(None);

    let action = extractor::extract_task_action("tasks/get", Some("task-123"));
    let ctx = build_ws_evaluation_context(&state, &session_id);

    let verdict = state
        .engine
        .evaluate_action_with_context(&action, &state.policies, Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Allow),
        "Expected Allow with wildcard policy, got: {:?}",
        verdict
    );
}

#[test]
fn test_extension_method_policy_deny_ws() {
    // With no policies, extension method calls should be denied (fail-closed)
    let state = make_test_state();
    let session_id = state.sessions.get_or_create(None);

    let action = extractor::extract_extension_action(
        "x-vellaveto-audit",
        "x-vellaveto-audit/stats",
        &json!({}),
    );
    let ctx = build_ws_evaluation_context(&state, &session_id);

    let verdict = state
        .engine
        .evaluate_action_with_context(&action, &state.policies, Some(&ctx))
        .unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Expected Deny with no policies, got: {:?}",
        verdict
    );
}

// ==========================================================================
// Test helpers
// ==========================================================================

fn make_test_state_with_allow_all() -> ProxyState {
    use vellaveto_engine::PolicyEngine;
    use vellaveto_types::{Policy, PolicyType};

    let policies = vec![Policy {
        id: "*:*".to_string(),
        name: "Allow all".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: None,
    }];

    let engine =
        PolicyEngine::with_policies(false, &policies).expect("Failed to compile test policies");

    let mut state = make_test_state();
    state.engine = Arc::new(engine);
    state.policies = Arc::new(policies);
    state
}

fn make_test_state() -> ProxyState {
    use std::sync::Arc;
    use std::time::Duration;
    use vellaveto_audit::AuditLogger;
    use vellaveto_engine::PolicyEngine;
    use vellaveto_mcp::output_validation::OutputSchemaRegistry;

    let engine = PolicyEngine::new(false);
    let audit = AuditLogger::new(std::path::PathBuf::from("/dev/null"));
    let sessions = crate::session::SessionStore::new(Duration::from_secs(300), 100);

    ProxyState {
        engine: Arc::new(engine),
        policies: Arc::new(vec![]),
        audit: Arc::new(audit),
        sessions: Arc::new(sessions),
        upstream_url: "http://localhost:8000/mcp".to_string(),
        http_client: reqwest::Client::new(),
        oauth: None,
        injection_scanner: None,
        injection_disabled: false,
        injection_blocking: false,
        api_key: None,
        approval_store: None,
        manifest_config: None,
        allowed_origins: vec![],
        bind_addr: "127.0.0.1:3001".parse().unwrap(),
        canonicalize: true,
        output_schema_registry: Arc::new(OutputSchemaRegistry::new()),
        response_dlp_enabled: true,
        response_dlp_blocking: false,
        known_tools: std::collections::HashSet::new(),
        elicitation_config: vellaveto_config::ElicitationConfig::default(),
        sampling_config: vellaveto_config::SamplingConfig::default(),
        tool_registry: None,
        call_chain_hmac_key: None,
        trace_enabled: false,
        circuit_breaker: None,
        shadow_agent: None,
        deputy: None,
        schema_lineage: None,
        auth_level: None,
        sampling_detector: None,
        limits: vellaveto_config::LimitsConfig::default(),
        ws_config: Some(WebSocketConfig::default()),
        extension_registry: None,
        transport_config: vellaveto_config::TransportConfig::default(),
        grpc_port: None,
        gateway: None,
        abac_engine: None,
        least_agency: None,
        continuous_auth_config: None,
    }
}
