//! HTTP route tests using axum's tower test utilities.
//! Tests the full request→response cycle without spawning a real server.
//! Requires sentinel-server to export AppState and routes via lib.rs.

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

// ════════════════════════════════
// HEALTH ENDPOINT
// ════════════════════════════════

#[tokio::test]
async fn health_returns_200_with_ok_status() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.get("status").unwrap(), "ok");
    assert_eq!(json.get("policies_loaded").unwrap(), 2);
}

#[tokio::test]
async fn health_with_no_policies_shows_zero() {
    let (state, _tmp) = make_empty_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.get("policies_loaded").unwrap(), 0);
}

// ════════════════════════════════
// EVALUATE ENDPOINT
// ════════════════════════════════

#[tokio::test]
async fn evaluate_allowed_action_returns_allow() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {"path": "/tmp/test"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let verdict = json.get("verdict").unwrap();
    assert_eq!(verdict, "Allow");
}

#[tokio::test]
async fn evaluate_denied_action_returns_deny() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "bash",
        "function": "execute",
        "parameters": {}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let verdict = json.get("verdict").unwrap();
    assert!(
        verdict.get("Deny").is_some(),
        "bash should be denied, got: {}",
        verdict
    );
}

#[tokio::test]
async fn evaluate_with_empty_policies_returns_deny() {
    let (state, _tmp) = make_empty_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "any",
        "function": "thing",
        "parameters": {}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let verdict = json.get("verdict").unwrap();
    assert!(
        verdict.get("Deny").is_some(),
        "Empty policies should fail-closed with deny, got: {}",
        verdict
    );
}

#[tokio::test]
async fn evaluate_invalid_json_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be 4xx, not 5xx
    assert!(
        resp.status().is_client_error(),
        "Invalid JSON should return client error, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn evaluate_missing_required_fields_returns_error() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file"
        // missing function and parameters
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn evaluate_logs_to_audit() {
    let (state, tmp) = make_state();
    let audit_path = tmp.path().join("audit.log");
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify audit log was written
    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    assert!(
        !content.trim().is_empty(),
        "audit log should have at least one entry"
    );

    // Each line should be valid JSON
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: serde_json::Value =
            serde_json::from_str(line).expect("each audit line should be valid JSON");
        assert!(entry.get("action").is_some());
        assert!(entry.get("verdict").is_some());
    }
}

// ════════════════════════════════
// POLICIES CRUD ENDPOINTS
// ════════════════════════════════

#[tokio::test]
async fn list_policies_returns_loaded_policies() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/api/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let policies = json.as_array().expect("policies should be an array");
    assert_eq!(policies.len(), 2);
}

#[tokio::test]
async fn add_policy_increases_policy_count() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    let new_policy = serde_json::to_string(&json!({
        "id": "network:*",
        "name": "Block network",
        "policy_type": "Deny",
        "priority": 50
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(new_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "Add policy should succeed, got {}",
        resp.status()
    );

    // Verify count increased
    let count = state.policies.load().len();
    assert_eq!(count, 3, "Should have 3 policies after adding one");
}

#[tokio::test]
async fn delete_policy_removes_it() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    // Delete the "file:read" policy
    let resp = app
        .oneshot(
            Request::delete("/api/policies/file:read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let count = state.policies.load().len();
    assert_eq!(count, 1, "Should have 1 policy after deleting one");
}

#[tokio::test]
async fn delete_nonexistent_policy_returns_ok_but_no_change() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    let resp = app
        .oneshot(
            Request::delete("/api/policies/nonexistent-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not 500 — either 200 (idempotent) or 404 (not found) is acceptable
    assert_ne!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Deleting nonexistent policy should not be a server error"
    );
    let count = state.policies.load().len();
    assert_eq!(count, 2, "Count unchanged when deleting nonexistent policy");
}

// ════════════════════════════════
// AUDIT ENDPOINTS
// ═══════════════════════════════

#[tokio::test]
async fn audit_entries_returns_empty_initially() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit/entries")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Route returns {"count": N, "entries": [...]}
    assert!(
        json.is_object(),
        "audit entries should be an object: {:?}",
        json
    );
    assert_eq!(json["count"], 0);
    assert!(json["entries"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn audit_report_on_empty_log() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit/report")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json.get("total_entries").unwrap(), 0);
    assert_eq!(json.get("allow_count").unwrap(), 0);
    assert_eq!(json.get("deny_count").unwrap(), 0);
    assert_eq!(json.get("require_approval_count").unwrap(), 0);
}

// ════════════════════════════════
// RELOAD ENDPOINT
// ═══════════════════════════════

#[tokio::test]
async fn reload_with_nonexistent_config_returns_500() {
    let (state, _tmp) = make_state();
    // config_path is "nonexistent.toml" — reload should fail
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::post("/api/policies/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Reload with missing config file should return 500"
    );
}

#[tokio::test]
async fn reload_with_valid_config_updates_policies() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("reload.toml");
    std::fs::write(
        &config_path,
        r#"
[[policies]]
name = "Reloaded allow"
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
    let app = routes::build_router(state.clone());

    let resp = app
        .oneshot(
            Request::post("/api/policies/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let count = state.policies.load().len();
    assert_eq!(count, 1, "After reload, should have 1 policy from config");
}

// ════════════════════════════════
// ADVERSARIAL: URL-ENCODED POLICY IDS
// ═══════════════════════════════

#[tokio::test]
async fn delete_policy_with_url_encoded_colon() {
    // Policy ID "bash:*" contains a colon. axum should handle this
    // via path parameter extraction, but let's verify.
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    // Try deleting "bash:*" — the colon is in the path
    let resp = app
        .oneshot(
            Request::delete("/api/policies/bash:*")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let remaining = state.policies.load();
    // "bash:*" should have been removed, leaving only "file:read"
    assert_eq!(remaining.len(), 1, "bash:* should be removed");
    assert_eq!(remaining[0].id, "file:read");
}

// ════════════════════════════════
// SECURITY HEADERS
// ════════════════════════════════

#[tokio::test]
async fn security_headers_present_on_get() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .map(|v| v.as_bytes()),
        Some(b"nosniff".as_slice()),
        "X-Content-Type-Options header should be 'nosniff'"
    );
    assert_eq!(
        resp.headers().get("x-frame-options").map(|v| v.as_bytes()),
        Some(b"DENY".as_slice()),
        "X-Frame-Options header should be 'DENY'"
    );
    assert_eq!(
        resp.headers()
            .get("content-security-policy")
            .map(|v| v.as_bytes()),
        Some(b"default-src 'none'".as_slice()),
        "Content-Security-Policy header should be set"
    );
    assert_eq!(
        resp.headers().get("cache-control").map(|v| v.as_bytes()),
        Some(b"no-store".as_slice()),
        "Cache-Control header should be 'no-store'"
    );
}

#[tokio::test]
async fn security_headers_present_on_post() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {"path": "/tmp/test"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .map(|v| v.as_bytes()),
        Some(b"nosniff".as_slice()),
        "Security headers must be present on POST responses too"
    );
    assert_eq!(
        resp.headers().get("cache-control").map(|v| v.as_bytes()),
        Some(b"no-store".as_slice()),
    );
}
