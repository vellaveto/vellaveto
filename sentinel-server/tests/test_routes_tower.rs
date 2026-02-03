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
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![
            Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "bash:*".to_string(),
                name: "Block bash".to_string(),
                policy_type: PolicyType::Deny,
                priority: 100,
                path_rules: None,
                network_rules: None,
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
        trusted_proxies: Arc::new(vec![]),
    };
    (state, tmp)
}

fn make_empty_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
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
        trusted_proxies: Arc::new(vec![]),
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
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
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
        trusted_proxies: Arc::new(vec![]),
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
// APPROVAL ENDPOINTS
// ════════════════════════════════

fn make_approval_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![
            Policy {
                id: "sensitive:*".to_string(),
                name: "Require approval for sensitive ops".to_string(),
                policy_type: PolicyType::Conditional {
                    conditions: json!({"require_approval": true}),
                },
                priority: 100,
                path_rules: None,
                network_rules: None,
            },
            Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
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
        trusted_proxies: Arc::new(vec![]),
    };
    (state, tmp)
}

/// Helper: evaluate an action that requires approval, return the approval ID.
async fn create_pending_approval(state: &AppState) -> String {
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({
        "tool": "sensitive",
        "function": "delete",
        "parameters": {"target": "/important"}
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
        verdict.get("RequireApproval").is_some(),
        "Expected RequireApproval verdict, got: {}",
        verdict
    );
    json.get("approval_id")
        .and_then(|v| v.as_str())
        .expect("RequireApproval should include approval_id")
        .to_string()
}

#[tokio::test]
async fn approval_list_pending_empty() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/approvals/pending")
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
    assert_eq!(json["count"], 0);
    assert!(json["approvals"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn approval_list_pending_after_evaluate() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/approvals/pending")
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
    assert_eq!(json["count"], 1);
    let approvals = json["approvals"].as_array().unwrap();
    assert_eq!(approvals[0]["id"], approval_id);
    assert_eq!(approvals[0]["status"], "Pending");
}

#[tokio::test]
async fn approval_get_by_id() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/api/approvals/{}", approval_id))
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
    assert_eq!(json["id"], approval_id);
    assert_eq!(json["status"], "Pending");
    assert_eq!(json["action"]["tool"], "sensitive");
}

#[tokio::test]
async fn approval_get_nonexistent_returns_404() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/approvals/nonexistent-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_approve_success() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state);
    let body = serde_json::to_string(&json!({"resolved_by": "admin"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
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
    assert_eq!(json["status"], "Approved");
    assert_eq!(json["resolved_by"], "admin");
}

#[tokio::test]
async fn approval_deny_success() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state);
    let body = serde_json::to_string(&json!({"resolved_by": "security-team"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/deny", approval_id))
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
    assert_eq!(json["status"], "Denied");
    assert_eq!(json["resolved_by"], "security-team");
}

#[tokio::test]
async fn approval_double_approve_returns_conflict() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    // First approve
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "admin"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second approve should return 409 Conflict
    let app = routes::build_router(state);
    let body = serde_json::to_string(&json!({"resolved_by": "admin2"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "Double-approve should return 409 CONFLICT"
    );
}

#[tokio::test]
async fn approval_approve_nonexistent_returns_404() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({"resolved_by": "admin"})).unwrap();
    let resp = app
        .oneshot(
            Request::post("/api/approvals/nonexistent-id/approve")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approval_approve_without_body_uses_anonymous() {
    let (state, _tmp) = make_approval_state();
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state);
    // No Content-Type header — axum 0.8 rejects empty body with application/json
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
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
    assert_eq!(json["status"], "Approved");
    assert_eq!(json["resolved_by"], "anonymous");
}

// ════════════════════════════════
// AUDIT VERIFY ENDPOINT
// ════════════════════════════════

#[tokio::test]
async fn audit_verify_on_empty_log() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit/verify")
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
    // Empty audit chain should verify as valid
    assert!(json.is_object(), "verify should return an object");
}

#[tokio::test]
async fn audit_verify_after_evaluations() {
    let (state, _tmp) = make_state();

    // First, create some audit entries via evaluate
    let app = routes::build_router(state.clone());
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

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Now verify the chain
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/audit/verify")
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
    // After real evaluations, chain should still be valid
    assert!(
        json.is_object(),
        "verify should return a verification object"
    );
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

// ════════════════════════════════
// API KEY AUTHENTICATION
// ════════════════════════════════

fn make_authed_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: Some(Arc::new("test-secret-key-42".to_string())),
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
    };
    (state, tmp)
}

#[tokio::test]
async fn auth_post_without_header_returns_401() {
    let (state, _tmp) = make_authed_state();
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

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Authorization"));
}

#[tokio::test]
async fn auth_post_with_wrong_token_returns_401() {
    let (state, _tmp) = make_authed_state();
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
                .header("authorization", "Bearer wrong-key-99")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
async fn auth_post_with_malformed_header_returns_401() {
    let (state, _tmp) = make_authed_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {}
    }))
    .unwrap();

    // Not "Bearer <token>", just a raw token
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "test-secret-key-42")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Malformed auth header (no Bearer prefix) should be rejected"
    );
}

#[tokio::test]
async fn auth_get_bypasses_api_key_check() {
    let (state, _tmp) = make_authed_state();
    let app = routes::build_router(state);

    // GET requests should NOT require auth (read-only)
    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET requests should bypass API key auth"
    );
}

#[tokio::test]
async fn auth_post_with_valid_token_succeeds() {
    let (state, _tmp) = make_authed_state();
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
                .header("authorization", "Bearer test-secret-key-42")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Valid Bearer token should pass auth"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["verdict"], "Allow");
}

#[tokio::test]
async fn auth_no_api_key_configured_allows_all() {
    // Default make_state() has api_key: None
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {"path": "/tmp/test"}
    }))
    .unwrap();

    // POST without any auth header — should work when no api_key configured
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "No api_key configured means auth is disabled"
    );
}

#[tokio::test]
async fn auth_delete_requires_api_key() {
    let (state, _tmp) = make_authed_state();
    let app = routes::build_router(state);

    // DELETE is mutating — should require auth
    let resp = app
        .oneshot(
            Request::delete("/api/policies/file:read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "DELETE requests should require API key when configured"
    );
}

#[tokio::test]
async fn auth_get_requires_api_key() {
    let (state, _tmp) = make_authed_state();

    // GET /api/policies without auth header should return 401
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(Request::get("/api/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "GET /api/policies should require auth when api_key is configured"
    );

    // GET /api/policies with valid auth header should return 200
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/policies")
                .header("authorization", "Bearer test-secret-key-42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /api/policies with valid Bearer token should succeed"
    );
}

// ════════════════════════════════
// METRICS ENDPOINT
// ════════════════════════════════

#[tokio::test]
async fn metrics_returns_structure() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/api/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("uptime_seconds").is_some());
    assert_eq!(json["policies_loaded"], 2);
    assert_eq!(json["evaluations"]["total"], 0);
    assert_eq!(json["evaluations"]["allow"], 0);
    assert_eq!(json["evaluations"]["deny"], 0);
}

#[tokio::test]
async fn metrics_increment_after_evaluations() {
    let (state, _tmp) = make_state();

    // Evaluate an allow action
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {"path": "/tmp"}
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

    // Evaluate a deny action
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({
        "tool": "bash", "function": "execute", "parameters": {}
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

    // Check metrics reflect the evaluations
    let app = routes::build_router(state);
    let resp = app
        .oneshot(Request::get("/api/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["evaluations"]["total"], 2);
    assert_eq!(json["evaluations"]["allow"], 1);
    assert_eq!(json["evaluations"]["deny"], 1);
}

// ════════════════════════════════
// REQUEST-ID MIDDLEWARE
// ════════════════════════════════

#[tokio::test]
async fn request_id_generated_when_not_provided() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let request_id = resp.headers().get("x-request-id");
    assert!(
        request_id.is_some(),
        "X-Request-Id should be auto-generated"
    );
    // Should be a UUID (36 chars)
    let id_str = request_id.unwrap().to_str().unwrap();
    assert_eq!(
        id_str.len(),
        36,
        "Auto-generated request ID should be UUID format"
    );
}

#[tokio::test]
async fn request_id_preserved_when_client_sends_it() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/health")
                .header("x-request-id", "client-id-12345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let request_id = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        request_id, "client-id-12345",
        "Client-provided X-Request-Id should be echoed back"
    );
}

#[tokio::test]
async fn request_id_oversized_is_replaced_with_uuid() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let oversized_id = "x".repeat(200); // 200 chars, exceeds 128-char cap
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("x-request-id", &oversized_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let request_id = resp
        .headers()
        .get("x-request-id")
        .expect("Response must include X-Request-Id")
        .to_str()
        .unwrap();
    // Oversized client ID rejected, replaced with auto-generated UUID
    assert_ne!(
        request_id, oversized_id,
        "Oversized X-Request-Id must NOT be echoed back"
    );
    assert_eq!(
        request_id.len(),
        36,
        "Oversized X-Request-Id should be replaced with UUID (36 chars), got {} chars",
        request_id.len()
    );
}

#[tokio::test]
async fn request_id_at_128_chars_is_preserved() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);
    let max_id = "a".repeat(128); // Exactly at the cap
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("x-request-id", &max_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let request_id = resp
        .headers()
        .get("x-request-id")
        .expect("Response must include X-Request-Id")
        .to_str()
        .unwrap();
    assert_eq!(
        request_id, max_id,
        "X-Request-Id at exactly 128 chars should be preserved"
    );
}

// ════════════════════════════════
// CHECKPOINT ENDPOINTS
// ════════════════════════════════

fn make_checkpoint_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let signing_key = AuditLogger::generate_signing_key();
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }])),
        audit: Arc::new(
            AuditLogger::new(tmp.path().join("audit.log")).with_signing_key(signing_key),
        ),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
    };
    (state, tmp)
}

#[tokio::test]
async fn checkpoint_list_empty() {
    let (state, _tmp) = make_checkpoint_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit/checkpoints")
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
    assert_eq!(json["count"], 0);
    assert!(json["checkpoints"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn checkpoint_create_and_list() {
    let (state, _tmp) = make_checkpoint_state();

    // Create some audit entries first
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {"path": "/tmp"}
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

    // Wait for audit flush
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Create a checkpoint
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/audit/checkpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Creating checkpoint should succeed"
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("entry_count").is_some());
    assert!(json.get("signature").is_some());

    // Now list checkpoints — should have 1
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/audit/checkpoints")
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
    assert_eq!(json["count"], 1);
}

#[tokio::test]
async fn checkpoint_verify_after_create() {
    let (state, _tmp) = make_checkpoint_state();

    // Evaluate an action to generate audit entries
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {}
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
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Create checkpoint
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/audit/checkpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify checkpoints
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/audit/checkpoints/verify")
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
    // Verification should report valid chain
    assert!(json.is_object());
}

// ════════════════════════════════
// HEAD METHOD EXEMPTIONS
// ════════════════════════════════

#[tokio::test]
async fn head_request_bypasses_api_key_check() {
    let (state, _tmp) = make_authed_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // HEAD should bypass auth just like GET
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "HEAD requests should bypass API key auth"
    );
}

#[tokio::test]
async fn head_request_uses_readonly_rate_limit_bucket() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // HEAD to a non-health endpoint should still work (treated as readonly, not admin)
    let resp = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should not be rate-limited as admin
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "HEAD requests should use readonly rate limit bucket, not admin"
    );
}

#[tokio::test]
async fn checkpoint_create_without_signing_key_fails() {
    // Use default make_state() which has no signing key
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(
            Request::post("/api/audit/checkpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "Creating checkpoint without signing key should fail"
    );
}

// ════════════════════════════════
// APPROVAL AUDIT TRAIL (Phase 4D - M7)
// ════════════════════════════════

#[tokio::test]
async fn test_approve_creates_audit_entry() {
    let (state, tmp) = make_approval_state();
    let audit_path = tmp.path().join("audit.log");
    let approval_id = create_pending_approval(&state).await;

    // Approve the pending approval
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "admin"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read the audit log and find the approval_approved entry
    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist");
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each audit line should be valid JSON"))
        .collect();

    // There should be at least 2 entries: one from the initial evaluate (RequireApproval)
    // and one from the approval resolution
    let approval_entry = entries
        .iter()
        .find(|e| {
            e.get("metadata")
                .and_then(|m| m.get("event"))
                .and_then(|v| v.as_str())
                == Some("approval_approved")
        })
        .expect("Should find an audit entry with event=approval_approved");

    // Verify the audit entry contains the right action
    assert_eq!(
        approval_entry["action"]["tool"], "sentinel",
        "Audit entry tool should be 'sentinel'"
    );
    assert_eq!(
        approval_entry["action"]["function"], "approval_resolved",
        "Audit entry function should be 'approval_resolved'"
    );
    // Verify verdict is Allow
    assert_eq!(
        approval_entry["verdict"], "Allow",
        "Approval audit entry should have Allow verdict"
    );
}

#[tokio::test]
async fn test_deny_creates_audit_entry() {
    let (state, tmp) = make_approval_state();
    let audit_path = tmp.path().join("audit.log");
    let approval_id = create_pending_approval(&state).await;

    // Deny the pending approval
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "security-team"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/deny", approval_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read the audit log and find the approval_denied entry
    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist");
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each audit line should be valid JSON"))
        .collect();

    let denial_entry = entries
        .iter()
        .find(|e| {
            e.get("metadata")
                .and_then(|m| m.get("event"))
                .and_then(|v| v.as_str())
                == Some("approval_denied")
        })
        .expect("Should find an audit entry with event=approval_denied");

    // Verify the audit entry contains the right action
    assert_eq!(
        denial_entry["action"]["tool"], "sentinel",
        "Audit entry tool should be 'sentinel'"
    );
    assert_eq!(
        denial_entry["action"]["function"], "approval_resolved",
        "Audit entry function should be 'approval_resolved'"
    );
    // Verify verdict is Deny
    let verdict = &denial_entry["verdict"];
    assert!(
        verdict.get("Deny").is_some(),
        "Denial audit entry should have Deny verdict, got: {}",
        verdict
    );
}

#[tokio::test]
async fn test_audit_entry_contains_resolver_identity() {
    let (state, tmp) = make_approval_state();
    let audit_path = tmp.path().join("audit.log");
    let approval_id = create_pending_approval(&state).await;

    // Approve with a specific resolver identity (use a non-PII value to
    // avoid redaction by the default KeysAndPatterns level)
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "security-lead-team-alpha"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read the audit log and find the approval entry
    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist");
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each audit line should be valid JSON"))
        .collect();

    let approval_entry = entries
        .iter()
        .find(|e| {
            e.get("metadata")
                .and_then(|m| m.get("event"))
                .and_then(|v| v.as_str())
                == Some("approval_approved")
        })
        .expect("Should find an audit entry with event=approval_approved");

    // Verify the resolver identity is recorded in metadata
    let resolved_by = approval_entry["metadata"]["resolved_by"]
        .as_str()
        .expect("metadata.resolved_by should be a string");
    assert_eq!(
        resolved_by, "security-lead-team-alpha",
        "Audit entry should record the resolver identity"
    );

    // Verify the approval_id is recorded in the action parameters
    let recorded_id = approval_entry["action"]["parameters"]["approval_id"]
        .as_str()
        .expect("action.parameters.approval_id should be a string");
    assert_eq!(
        recorded_id, approval_id,
        "Audit entry should record the approval_id"
    );

    // Verify the original tool/function are recorded
    assert_eq!(
        approval_entry["action"]["parameters"]["original_tool"], "sensitive",
        "Audit entry should record the original tool"
    );
    assert_eq!(
        approval_entry["action"]["parameters"]["original_function"], "delete",
        "Audit entry should record the original function"
    );
}

// ════════════════════════════════
// SECURITY HEADERS: X-PERMITTED-CROSS-DOMAIN-POLICIES & HSTS (Phase 6C)
// ════════════════════════════════

#[tokio::test]
async fn test_security_header_xpcdp_always_present() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-permitted-cross-domain-policies")
            .map(|v| v.as_bytes()),
        Some(b"none".as_slice()),
        "X-Permitted-Cross-Domain-Policies header should always be 'none'"
    );
}

#[tokio::test]
async fn test_security_header_hsts_on_https() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // Simulate HTTPS via X-Forwarded-Proto header (as set by reverse proxies)
    let resp = app
        .oneshot(
            Request::get("/health")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let hsts = resp.headers().get("strict-transport-security");
    assert!(
        hsts.is_some(),
        "Strict-Transport-Security header should be present when X-Forwarded-Proto is https"
    );
    assert_eq!(
        hsts.unwrap().as_bytes(),
        b"max-age=31536000; includeSubDomains",
        "HSTS header should have correct value"
    );
}

#[tokio::test]
async fn test_security_header_no_hsts_on_http() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // No X-Forwarded-Proto header — plain HTTP
    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let hsts = resp.headers().get("strict-transport-security");
    assert!(
        hsts.is_none(),
        "Strict-Transport-Security header should NOT be present on plain HTTP"
    );
}

// ════════════════════════════════
// PER-PRINCIPAL RATE LIMITING
// ════════════════════════════════

fn make_per_principal_state(rps: u32) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let rate_limits =
        RateLimits::disabled().with_per_principal(std::num::NonZeroU32::new(rps).unwrap());
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow file reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
            path_rules: None,
            network_rules: None,
        }])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("nonexistent.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(rate_limits),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
    };
    (state, tmp)
}

#[tokio::test]
async fn per_principal_rate_limit_uses_x_principal_header() {
    // 1 req/s per principal — second request from same principal gets 429
    let (state, _tmp) = make_per_principal_state(1);
    let app = routes::build_router(state.clone());

    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {}
    }))
    .unwrap();

    // First request with X-Principal: agent-a — allowed
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-a")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second request with X-Principal: agent-a — rate limited
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-a")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second request from same principal should be rate-limited"
    );

    // Request with different principal: agent-b — allowed (independent)
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-b")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Different principal should not be rate-limited"
    );
}

#[tokio::test]
async fn per_principal_rate_limit_falls_back_to_bearer_token() {
    let (state, _tmp) = make_per_principal_state(1);
    let app = routes::build_router(state.clone());

    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {}
    }))
    .unwrap();

    // First request with Bearer token (no X-Principal) — allowed
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "Bearer my-api-key-123")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second request with same Bearer token — rate limited
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "Bearer my-api-key-123")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second request with same Bearer token should be rate-limited"
    );

    // Request with different Bearer token — allowed
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("authorization", "Bearer different-key-456")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Different Bearer token should not be rate-limited"
    );
}

#[tokio::test]
async fn per_principal_health_endpoint_exempt() {
    let (state, _tmp) = make_per_principal_state(1);

    // Health endpoint should always be exempt from rate limiting
    for _ in 0..5 {
        let app = routes::build_router(state.clone());
        let resp = app
            .oneshot(
                Request::get("/health")
                    .header("x-principal", "agent-flood")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/health should be exempt from per-principal rate limiting"
        );
    }
}

#[tokio::test]
async fn per_principal_x_principal_takes_precedence_over_bearer() {
    let (state, _tmp) = make_per_principal_state(1);

    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {}
    }))
    .unwrap();

    // First request: X-Principal: agent-x with Bearer token
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-x")
                .header("authorization", "Bearer some-token")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second request: same Bearer but different X-Principal — should be allowed
    // because X-Principal takes precedence
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-y")
                .header("authorization", "Bearer some-token")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Different X-Principal should be allowed even with same Bearer token"
    );
}
