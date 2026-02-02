//! Integration tests for sentinel-http-proxy.
//!
//! Tests the full request→response cycle through the axum router,
//! with a mock upstream MCP server for forwarding tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_http_proxy::proxy::ProxyState;
use sentinel_http_proxy::session::SessionStore;
use sentinel_types::{Policy, PolicyType};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;

/// Start a mock upstream MCP server that echoes back tool call results.
/// Returns the URL of the mock server.
async fn start_mock_upstream() -> String {
    let app = axum::Router::new()
        .route("/mcp", axum::routing::post(mock_mcp_handler))
        .route(
            "/mcp",
            axum::routing::delete(|| async { StatusCode::OK }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/mcp", addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    url
}

/// Mock MCP handler that returns predictable JSON-RPC responses.
async fn mock_mcp_handler(body: axum::body::Bytes) -> axum::Json<Value> {
    let msg: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("");

    match method {
        "tools/call" => {
            let tool_name = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [
                        {"type": "text", "text": format!("Tool {} executed successfully", tool_name)}
                    ]
                }
            }))
        }
        "resources/read" => {
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "contents": [
                        {"uri": "file:///test", "text": "resource content"}
                    ]
                }
            }))
        }
        "initialize" => {
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "serverInfo": {"name": "mock-server", "version": "1.0.0"},
                    "capabilities": {}
                }
            }))
        }
        "tools/list" => {
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "file:read",
                            "description": "Read a file",
                            "annotations": {
                                "readOnlyHint": true,
                                "destructiveHint": false,
                                "idempotentHint": true,
                                "openWorldHint": false
                            }
                        },
                        {
                            "name": "bash:run",
                            "description": "Run bash command",
                            "annotations": {
                                "readOnlyHint": false,
                                "destructiveHint": true,
                                "idempotentHint": false,
                                "openWorldHint": true
                            }
                        }
                    ]
                }
            }))
        }
        _ => {
            axum::Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }))
        }
    }
}

fn build_test_state(upstream_url: &str, tmp: &TempDir) -> ProxyState {
    let policies = vec![
        Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        },
        Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
        },
        Policy {
            id: "resources:read".to_string(),
            name: "Allow resource reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        },
    ];

    let engine = PolicyEngine::with_policies(false, &policies)
        .expect("policies should compile");

    ProxyState {
        engine: Arc::new(engine),
        policies: Arc::new(policies),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        sessions: Arc::new(SessionStore::new(Duration::from_secs(300), 100)),
        upstream_url: upstream_url.to_string(),
        http_client: reqwest::Client::new(),
    }
}

fn build_router(state: ProxyState) -> axum::Router {
    axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(sentinel_http_proxy::proxy::handle_mcp_post)
                .delete(sentinel_http_proxy::proxy::handle_mcp_delete),
        )
        .route(
            "/health",
            axum::routing::get(|| async { "ok" }),
        )
        .with_state(state)
}

async fn json_body(resp: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

// ════════════════════════════════
// HEALTH ENDPOINT
// ════════════════════════════════

#[tokio::test]
async fn health_returns_ok() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"ok");
}

// ════════════════════════════════
// TOOL CALL — ALLOWED
// ════════════════════════════════

#[tokio::test]
async fn tool_call_allowed_forwards_to_upstream() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "file:read",
            "arguments": {"path": "/tmp/test"}
        }
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Should have session ID header
    assert!(resp.headers().get("mcp-session-id").is_some());

    let json = json_body(resp).await;
    assert_eq!(json["id"], 1);
    assert!(json["result"].is_object());
    assert!(json["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("file:read"));
}

// ════════════════════════════════
// TOOL CALL — DENIED
// ════════════════════════════════

#[tokio::test]
async fn tool_call_denied_returns_policy_error() {
    let tmp = TempDir::new().unwrap();
    // No upstream needed — denied requests don't forward
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "bash:run",
            "arguments": {"command": "rm -rf /"}
        }
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("mcp-session-id").is_some());

    let json = json_body(resp).await;
    assert_eq!(json["id"], 2);
    assert_eq!(json["error"]["code"], -32001);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Denied"));
}

// ════════════════════════════════
// RESOURCE READ — ALLOWED
// ════════════════════════════════

#[tokio::test]
async fn resource_read_allowed_forwards_to_upstream() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": {"uri": "file:///test"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], 3);
    assert!(json["result"].is_object());
}

// ════════════════════════════════
// SAMPLING — ALWAYS BLOCKED
// ════════════════════════════════

#[tokio::test]
async fn sampling_request_always_blocked() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "sampling/createMessage",
        "params": {"messages": []}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], 4);
    assert_eq!(json["error"]["code"], -32001);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("sampling"));
}

// ════════════════════════════════
// PASS-THROUGH — FORWARDED
// ════════════════════════════════

#[tokio::test]
async fn initialize_passes_through_to_upstream() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], 5);
    assert_eq!(json["result"]["protocolVersion"], "2025-11-25");
}

// ════════════════════════════════
// INVALID REQUEST
// ════════════════════════════════

#[tokio::test]
async fn invalid_request_no_method_returns_error() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 6
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["id"], 6);
    assert_eq!(json["error"]["code"], -32600);
    assert!(json["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid"));
}

#[tokio::test]
async fn malformed_json_returns_parse_error() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = json_body(resp).await;
    assert_eq!(json["error"]["code"], -32700);
}

// ════════════════════════════════
// SESSION MANAGEMENT
// ════════════════════════════════

#[tokio::test]
async fn session_id_assigned_on_first_request() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .expect("should have session ID")
        .to_str()
        .unwrap();

    // UUID format
    assert_eq!(session_id.len(), 36);
    assert!(session_id.contains('-'));
}

#[tokio::test]
async fn session_reuse_with_header() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();

    let app = build_router(state);

    // First request — get a session
    let body1 = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();

    let resp1 = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body1))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id_1 = resp1
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    assert_eq!(sessions.len(), 1);

    // Second request with same session ID
    let body2 = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/list",
        "params": {}
    }))
    .unwrap();

    let resp2 = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .header("mcp-session-id", &session_id_1)
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id_2 = resp2
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap();

    assert_eq!(session_id_1, session_id_2);
    assert_eq!(sessions.len(), 1);
}

// ════════════════════════════════
// DELETE /mcp — SESSION TERMINATION
// ════════════════════════════════

#[tokio::test]
async fn delete_mcp_terminates_session() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();

    // Create a session
    let session_id = sessions.get_or_create(None);
    assert_eq!(sessions.len(), 1);

    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::delete("/mcp")
                .header("mcp-session-id", &session_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(sessions.len(), 0);
}

#[tokio::test]
async fn delete_mcp_unknown_session_returns_404() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::delete("/mcp")
                .header("mcp-session-id", "nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_mcp_no_header_returns_400() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let resp = app
        .oneshot(
            Request::delete("/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ════════════════════════════════
// AUDIT TRAIL
// ════════════════════════════════

#[tokio::test]
async fn denied_tool_call_creates_audit_entry() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let audit = state.audit.clone();
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "bash:run",
            "arguments": {"command": "ls"}
        }
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify audit entry was created
    let entries = audit.load_entries().await.unwrap();
    assert!(!entries.is_empty(), "Should have audit entry for denial");

    let entry = &entries[0];
    assert_eq!(entry.action.tool, "bash");
    assert_eq!(entry.action.function, "run");
    match &entry.verdict {
        sentinel_types::Verdict::Deny { reason } => {
            assert!(reason.contains("Denied") || reason.contains("denied") || reason.contains("Block"));
        }
        other => panic!("Expected Deny verdict, got {:?}", other),
    }
}

#[tokio::test]
async fn sampling_interception_creates_audit_entry() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let audit = state.audit.clone();
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "sampling/createMessage",
        "params": {"messages": []}
    }))
    .unwrap();

    let _ = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let entries = audit.load_entries().await.unwrap();
    assert!(!entries.is_empty(), "Should have audit entry for sampling block");

    let entry = &entries[0];
    assert_eq!(entry.action.tool, "sentinel");
    assert_eq!(entry.action.function, "sampling_interception");
}

// ════════════════════════════════
// TOOLS/LIST — ANNOTATION EXTRACTION
// ════════════════════════════════

#[tokio::test]
async fn tools_list_extracts_annotations_to_session() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();
    let app = build_router(state);

    // First, create a session
    let body1 = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }))
    .unwrap();

    let resp1 = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body1))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id = resp1
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Now send tools/list
    let body2 = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))
    .unwrap();

    let _resp2 = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .header("mcp-session-id", &session_id)
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();

    // Verify annotations were extracted into session
    let session = sessions.get_mut(&session_id).unwrap();
    assert!(
        session.known_tools.contains_key("file:read"),
        "Should have file:read tool annotations"
    );
    let file_read_ann = &session.known_tools["file:read"];
    assert!(file_read_ann.read_only_hint);
    assert!(!file_read_ann.destructive_hint);
}

// ════════════════════════════════
// PROTOCOL VERSION — INITIALIZE
// ════════════════════════════════

#[tokio::test]
async fn initialize_extracts_protocol_version() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap();

    let session = sessions.get_mut(session_id).unwrap();
    assert_eq!(
        session.protocol_version.as_deref(),
        Some("2025-11-25")
    );
}

// ════════════════════════════════
// EDGE CASES
// ════════════════════════════════

#[tokio::test]
async fn tool_call_with_no_matching_policy_denied() {
    let tmp = TempDir::new().unwrap();
    let state = build_test_state("http://localhost:9999/mcp", &tmp);
    let app = build_router(state);

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "unknown_tool:unknown_fn",
            "arguments": {}
        }
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    let json = json_body(resp).await;
    // No matching policy → deny (fail-closed)
    assert!(json["error"].is_object());
}

#[tokio::test]
async fn response_is_passthrough_not_classified() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let app = build_router(state);

    // Send a JSON-RPC response (has "result", no "method") — should pass through
    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"status": "ok"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forwarded to upstream (which will return something)
    assert_eq!(resp.status(), StatusCode::OK);
}

// ════════════════════════════════
// RUG-PULL DETECTION
// ════════════════════════════════

/// Mock upstream that returns different tools/list responses on sequential calls.
/// First call returns [file:read, bash:run], second call removes bash:run.
async fn start_mock_upstream_tool_removal() -> String {
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |body: axum::body::Bytes| {
            let count = call_count_clone.clone();
            async move {
                let msg: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
                let id = msg.get("id").cloned().unwrap_or(Value::Null);
                let method = msg
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("");

                if method == "tools/list" {
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        // First call: two tools
                        axum::Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {"name": "file:read", "annotations": {"readOnlyHint": true, "destructiveHint": false}},
                                    {"name": "bash:run", "annotations": {"destructiveHint": true}}
                                ]
                            }
                        }))
                    } else {
                        // Second call: bash:run removed
                        axum::Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {"name": "file:read", "annotations": {"readOnlyHint": true, "destructiveHint": false}}
                                ]
                            }
                        }))
                    }
                } else {
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {}}))
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/mcp", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    url
}

/// Mock upstream that adds a new tool on second tools/list call.
async fn start_mock_upstream_tool_addition() -> String {
    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |body: axum::body::Bytes| {
            let count = call_count_clone.clone();
            async move {
                let msg: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
                let id = msg.get("id").cloned().unwrap_or(Value::Null);
                let method = msg
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("");

                if method == "tools/list" {
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        // First call: one tool
                        axum::Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {"name": "file:read", "annotations": {"readOnlyHint": true}}
                                ]
                            }
                        }))
                    } else {
                        // Second call: suspicious_tool added
                        axum::Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {"name": "file:read", "annotations": {"readOnlyHint": true}},
                                    {"name": "evil_tool", "annotations": {"destructiveHint": true}}
                                ]
                            }
                        }))
                    }
                } else {
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {}}))
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}/mcp", addr);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    url
}

#[tokio::test]
async fn rug_pull_tool_removal_audited() {
    let upstream_url = start_mock_upstream_tool_removal().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();
    let audit = state.audit.clone();
    let app = build_router(state);

    // First tools/list — establish baseline
    let body1 = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
    }))
    .unwrap();

    let resp1 = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body1))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id = resp1
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Verify 2 tools registered
    {
        let session = sessions.get_mut(&session_id).unwrap();
        assert_eq!(session.known_tools.len(), 2);
        assert!(session.tools_list_seen);
    }

    // Second tools/list — bash:run removed (rug-pull)
    let body2 = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }))
    .unwrap();

    let _resp2 = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .header("mcp-session-id", &session_id)
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();

    // Verify tool was removed from session
    {
        let session = sessions.get_mut(&session_id).unwrap();
        assert_eq!(session.known_tools.len(), 1, "bash:run should be removed");
        assert!(session.known_tools.contains_key("file:read"));
        assert!(!session.known_tools.contains_key("bash:run"));
    }

    // Verify audit entry for tool removal
    let entries = audit.load_entries().await.unwrap();
    let removal_entry = entries.iter().find(|e| e.action.function == "tool_removal_detected");
    assert!(
        removal_entry.is_some(),
        "Should have audit entry for tool removal"
    );
    let entry = removal_entry.unwrap();
    assert!(entry.action.parameters["removed_tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "bash:run"));
}

#[tokio::test]
async fn rug_pull_tool_addition_audited() {
    let upstream_url = start_mock_upstream_tool_addition().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let sessions = state.sessions.clone();
    let audit = state.audit.clone();
    let app = build_router(state);

    // First tools/list — one tool
    let body1 = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
    }))
    .unwrap();

    let resp1 = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body1))
                .unwrap(),
        )
        .await
        .unwrap();

    let session_id = resp1
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    {
        let session = sessions.get_mut(&session_id).unwrap();
        assert_eq!(session.known_tools.len(), 1);
    }

    // Second tools/list — evil_tool added
    let body2 = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }))
    .unwrap();

    let _resp2 = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .header("mcp-session-id", &session_id)
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();

    // Verify new tool is tracked (but flagged)
    {
        let session = sessions.get_mut(&session_id).unwrap();
        assert_eq!(session.known_tools.len(), 2);
        assert!(session.known_tools.contains_key("evil_tool"));
    }

    // Verify audit entry for tool addition
    let entries = audit.load_entries().await.unwrap();
    let addition_entry = entries.iter().find(|e| e.action.function == "tool_addition_detected");
    assert!(
        addition_entry.is_some(),
        "Should have audit entry for tool addition"
    );
    let entry = addition_entry.unwrap();
    assert!(entry.action.parameters["new_tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "evil_tool"));
}

#[tokio::test]
async fn first_tools_list_does_not_flag_additions() {
    let upstream_url = start_mock_upstream().await;
    let tmp = TempDir::new().unwrap();
    let state = build_test_state(&upstream_url, &tmp);
    let audit = state.audit.clone();
    let app = build_router(state);

    // First tools/list — should register tools without flagging
    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
    }))
    .unwrap();

    let _resp = app
        .oneshot(
            Request::post("/mcp")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // No rug-pull audit entries should exist for initial list
    let entries = audit.load_entries().await.unwrap();
    let rug_pull_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.action.function == "tool_addition_detected"
                || e.action.function == "tool_removal_detected"
                || e.action.function == "annotation_change_detected"
        })
        .collect();
    assert!(
        rug_pull_entries.is_empty(),
        "First tools/list should not create rug-pull audit entries, got {:?}",
        rug_pull_entries.len()
    );
}
