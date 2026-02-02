//! HTTP route unit tests using axum test utilities.
//! Tests the full request→response cycle without spawning a real server.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState, Metrics, RateLimits};
use sentinel_types::{Policy, PolicyType};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

fn make_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(ArcSwap::from_pointee(vec![
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
        ])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };
    (state, tmp)
}

fn make_empty_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(ArcSwap::from_pointee(vec![])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };
    (state, tmp)
}

// ═══════════════════════════════════
// HEALTH ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn health_returns_200() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_response_contains_status_ok() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_reports_correct_policy_count() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["policies_loaded"], 2);
}

// ═══════════════════════════════════
// EVALUATE ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn evaluate_allowed_action_returns_allow() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "tool": "file",
                "function": "read",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Allow"),
        "file:read should be allowed: {:?}",
        json
    );
}

#[tokio::test]
async fn evaluate_denied_action_returns_deny() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "tool": "bash",
                "function": "execute",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Deny"),
        "bash:execute should be denied: {:?}",
        json
    );
}

#[tokio::test]
async fn evaluate_logs_to_audit() {
    let (state, _tmp) = make_state();
    let audit = state.audit.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "tool": "file",
                "function": "read",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    app.oneshot(req).await.unwrap();

    // Give async audit write time to complete
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entries = audit.load_entries().await.unwrap();
    assert!(!entries.is_empty(), "Evaluate endpoint should log to audit");
    assert_eq!(entries[0].action.tool, "file");
}

#[tokio::test]
async fn evaluate_with_empty_policies_returns_deny() {
    let (state, _tmp) = make_empty_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "tool": "anything",
                "function": "whatever",
                "parameters": {}
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.to_string().contains("Deny"),
        "Empty policies should produce Deny (fail-closed): {:?}",
        json
    );
}

#[tokio::test]
async fn evaluate_invalid_json_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from("not json"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should be 400 or 422 — NOT 200
    assert!(
        resp.status().is_client_error(),
        "Invalid JSON should return client error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn evaluate_missing_fields_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(json!({"tool": "bash"}).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "Missing required fields should return client error, got {}",
        resp.status()
    );
}

// ═══════════════════════════════════
// POLICIES CRUD ENDPOINTS
// ═══════════════════════════════════

#[tokio::test]
async fn list_policies_returns_array() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/policies").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "Policies should be an array: {:?}", json);
    assert_eq!(json.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn add_policy_increases_count() {
    let (state, _tmp) = make_state();
    let policies = state.policies.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/policies")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "id": "net:*",
                "name": "Block network",
                "policy_type": "Deny",
                "priority": 200
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Add policy should succeed, got {}",
        resp.status()
    );

    let count = policies.load().len();
    assert_eq!(count, 3, "Should have 3 policies after adding one");
}

#[tokio::test]
async fn add_policy_with_invalid_json_fails() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::post("/api/policies")
        .header("content-type", "application/json")
        .body(Body::from("not a policy"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn remove_policy_by_simple_id() {
    let (state, _tmp) = make_state();
    let policies = state.policies.clone();
    let app = routes::build_router(state);

    // Remove "file:read" — but note the colon in the URL path
    // This tests whether path params handle colons correctly
    let req = Request::delete("/api/policies/file:read")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Remove policy should succeed, got {}",
        resp.status()
    );

    let count = policies.load().len();
    assert_eq!(count, 1, "Should have 1 policy after removing one");
}

#[test]
fn remove_policy_nonexistent_id_is_not_error() {
    // Removing a non-existent policy should succeed (idempotent) or return 404
    // Either behavior is acceptable — the test documents which one was chosen
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (state, _tmp) = make_state();
        let app = routes::build_router(state);
        let req = Request::delete("/api/policies/nonexistent_policy_id")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should not be a 500
        assert_ne!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Removing non-existent policy should not be a server error"
        );
    });
}

// ═══════════════════════════════════
// AUDIT ENDPOINTS
// ═══════════════════════════════════

#[tokio::test]
async fn audit_entries_empty_returns_empty_array() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/audit/entries")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Route returns {"count": N, "entries": [...]}
    assert!(json.is_object());
    assert_eq!(json["count"], 0);
    assert!(
        json["entries"].as_array().unwrap().is_empty(),
        "Fresh audit should have no entries"
    );
}

#[tokio::test]
async fn audit_report_empty_returns_zero_counts() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/audit/report")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_entries"], 0);
    assert_eq!(json["allow_count"], 0);
    assert_eq!(json["deny_count"], 0);
}

// ═══════════════════════════════════
// RELOAD ENDPOINT
// ═══════════════════════════════════

#[tokio::test]
async fn reload_with_nonexistent_config_returns_error() {
    let (state, _tmp) = make_state();
    // config_path points to "nonexistent.toml" by default in test
    let app = routes::build_router(state);
    let req = Request::post("/api/policies/reload")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Should be a 500 or 400 — config file doesn't exist
    assert!(
        resp.status().is_server_error() || resp.status().is_client_error(),
        "Reload with nonexistent config should fail, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn reload_with_valid_config_succeeds() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("reload.toml");
    std::fs::write(
        &config_path,
        r#"
[[policies]]
name = "Reloaded"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
priority = 1
"#,
    )
    .unwrap();

    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(ArcSwap::from_pointee(vec![])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new(config_path.to_str().unwrap().to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };
    let policies = state.policies.clone();
    let app = routes::build_router(state);

    let req = Request::post("/api/policies/reload")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Reload with valid config should succeed, got {}",
        resp.status()
    );

    let count = policies.load().len();
    assert_eq!(count, 1, "Should have 1 policy after reload");
    assert_eq!(policies.load()[0].name, "Reloaded");
}

// ═══════════════════════════════════
// 404 FOR UNKNOWN ROUTES
// ════════════════════════════════════

#[tokio::test]
async fn unknown_route_returns_404() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/nonexistent")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_on_evaluate_endpoint_returns_405() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let req = Request::get("/api/evaluate").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // GET on a POST-only route should be 405 Method Not Allowed
    assert!(
        resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND,
        "Wrong method should not be 200, got {}",
        resp.status()
    );
}
