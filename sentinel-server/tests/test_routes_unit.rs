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

#[tokio::test]
async fn metrics_returns_counters() {
    let (state, _tmp) = test_state();

    // Evaluate one allowed and one denied action first
    let app = routes::build_router(state.clone());
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::build_router(state.clone());
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"bash","function":"exec","parameters":{}}"#,
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Check metrics
    let app = routes::build_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/metrics")
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
    assert_eq!(json["evaluations"]["total"], 2);
    assert_eq!(json["evaluations"]["allow"], 1);
    assert_eq!(json["evaluations"]["deny"], 1);
    assert!(json["uptime_seconds"].is_number());
    assert_eq!(json["policies_loaded"], 2);
}

#[tokio::test]
async fn responses_include_request_id_header() {
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
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("Response must include X-Request-Id header");
    let id_str = request_id.to_str().unwrap();
    // UUID v4 format: 8-4-4-4-12 hex digits
    assert_eq!(id_str.len(), 36, "X-Request-Id should be UUID format");
    assert_eq!(id_str.chars().filter(|c| *c == '-').count(), 4);
}

#[tokio::test]
async fn request_id_preserved_when_client_sends_one() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("x-request-id", "my-custom-id-12345")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("Response must include X-Request-Id header");
    assert_eq!(
        request_id.to_str().unwrap(),
        "my-custom-id-12345",
        "Client-provided X-Request-Id must be preserved"
    );
}

#[tokio::test]
async fn responses_include_security_headers() {
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
    let headers = response.headers();
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "Must have X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY",
        "Must have X-Frame-Options: DENY"
    );
    assert_eq!(
        headers.get("content-security-policy").unwrap(),
        "default-src 'none'",
        "Must have Content-Security-Policy"
    );
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "no-store",
        "Must have Cache-Control: no-store"
    );
}

#[tokio::test]
async fn health_not_rate_limited() {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(ArcSwap::from_pointee(vec![])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        // Set extremely low rate limit: 1 req/s for all categories
        rate_limits: Arc::new(RateLimits::new(Some(1), Some(1), Some(1))),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };

    // Rapid /health requests must all succeed despite strict rate limit
    for i in 0..5 {
        let app = routes::build_router(state.clone());
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "/health request {i} must not be rate-limited, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn rate_limit_429_includes_retry_after() {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(PolicyEngine::new(false)),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        }])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::new(Some(1), None, None)),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request consumes the token
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First request must succeed");

    // Second rapid request must be 429 with Retry-After header
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second rapid request must be 429"
    );
    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("429 response must include Retry-After header");
    let seconds: u64 = retry_after.to_str().unwrap().parse().unwrap();
    assert!(
        seconds >= 1,
        "Retry-After must be at least 1 second, got {seconds}"
    );
}

#[tokio::test]
async fn add_policy_creates_audit_entry() {
    let (state, _tmp) = test_state();
    let app = routes::build_router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&json!({
                        "id": "audit_test:*",
                        "name": "Audit test policy",
                        "policy_type": "Allow",
                        "priority": 1
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status().is_success());

    // Verify audit trail contains the add_policy event
    let entries = state.audit.load_entries().await.unwrap();
    let add_entry = entries
        .iter()
        .find(|e| e.action.function == "add_policy")
        .expect("Audit trail must contain add_policy event");
    assert_eq!(add_entry.action.tool, "sentinel");
    assert_eq!(add_entry.action.parameters["policy_id"], "audit_test:*");
}

#[tokio::test]
async fn remove_policy_creates_audit_entry() {
    let (state, _tmp) = test_state();

    // First add, then remove
    let app = routes::build_router(state.clone());
    app.oneshot(
        Request::builder()
            .method("DELETE")
            .uri("/api/policies/file:read")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    // Verify audit trail contains the remove_policy event
    let entries = state.audit.load_entries().await.unwrap();
    let remove_entry = entries
        .iter()
        .find(|e| e.action.function == "remove_policy")
        .expect("Audit trail must contain remove_policy event");
    assert_eq!(remove_entry.action.tool, "sentinel");
    assert_eq!(remove_entry.action.parameters["policy_id"], "file:read");
}
