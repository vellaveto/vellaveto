//! Unit tests for HTTP routes using axum test utilities.

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

fn test_state() -> (AppState, TempDir) {
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
        config_path: Arc::new("test-config.toml".to_string()),
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

#[tokio::test]
async fn health_returns_ok() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["policies_loaded"], 2);
}

#[tokio::test]
async fn evaluate_allowed_action() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "tool": "file",
                        "function": "read",
                        "parameters": {"path": "/tmp/test"}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["verdict"], "Allow");
}

#[tokio::test]
async fn evaluate_denied_action() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "tool": "bash",
                        "function": "execute",
                        "parameters": {}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["verdict"].is_object());
    assert!(json["verdict"]["Deny"].is_object());
}

#[tokio::test]
async fn list_policies_returns_array() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn add_policy_increases_count() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state.clone());

    // Add a policy
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "id": "net:*",
                        "name": "Block network",
                        "policy_type": "Deny",
                        "priority": 50
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status().is_success(),
        "Add policy should succeed, got {}",
        response.status()
    );

    // Verify count increased
    let policies = state.policies.load();
    assert_eq!(policies.len(), 3);
}

#[tokio::test]
async fn delete_nonexistent_policy_returns_not_found() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/policies/nonexistent_id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The current implementation returns 404 when no policy matched
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
