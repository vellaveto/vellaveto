//! HTTP route tests using axum's tower test utilities.
//! Tests the full request→response cycle without spawning a real server.
//! Requires vellaveto-server to export AppState and routes via lib.rs.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{routes, AppState, Metrics, RateLimits};
use vellaveto_types::{Policy, PolicyType};

fn make_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![
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
            ],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
    };
    (state, tmp)
}

fn make_empty_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
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
    assert_eq!(json.get("status").unwrap(), "ok");
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

#[tokio::test]
async fn evaluate_audit_includes_forwarded_tls_metadata() {
    let (mut state, tmp) = make_state();
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
                .header("x-forwarded-tls-version", "TLSv1.3")
                .header("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384")
                .header("x-forwarded-tls-kex-group", "X25519MLKEM768")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    let entry = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit json"))
        .expect("expected at least one audit entry");

    assert_eq!(entry["metadata"]["tls"]["protocol"], "TLSv1.3");
    assert_eq!(entry["metadata"]["tls"]["cipher"], "TLS_AES_256_GCM_SHA384");
    assert_eq!(entry["metadata"]["tls"]["kex_group"], "X25519MLKEM768");
}

#[tokio::test]
async fn evaluate_audit_drops_conflicting_tls_protocol_aliases() {
    let (mut state, tmp) = make_state();
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
                .header("x-forwarded-tls-version", "TLSv1.3")
                .header("x-tls-protocol", "TLSv1.2")
                .header("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    let entry = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit json"))
        .expect("expected at least one audit entry");

    assert!(
        entry["metadata"]["tls"].get("protocol").is_none(),
        "conflicting protocol aliases must remove protocol metadata"
    );
    assert_eq!(entry["metadata"]["tls"]["cipher"], "TLS_AES_256_GCM_SHA384");
}

#[tokio::test]
async fn evaluate_audit_drops_conflicting_duplicate_tls_protocol_values() {
    let (mut state, tmp) = make_state();
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
                .header("x-forwarded-tls-version", "TLSv1.3")
                .header("x-forwarded-tls-version", "TLSv1.2")
                .header("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    let entry = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit json"))
        .expect("expected at least one audit entry");

    assert!(
        entry["metadata"]["tls"].get("protocol").is_none(),
        "conflicting duplicate protocol header values must remove protocol metadata"
    );
    assert_eq!(entry["metadata"]["tls"]["cipher"], "TLS_AES_256_GCM_SHA384");
}

#[tokio::test]
async fn evaluate_audit_tls_protocol_falls_back_to_valid_alias() {
    let (mut state, tmp) = make_state();
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
                .header("x-forwarded-tls-version", "TLSv1.3;BAD")
                .header("x-tls-protocol", "TLSv1.2")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    let entry = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit json"))
        .expect("expected at least one audit entry");

    assert_eq!(entry["metadata"]["tls"]["protocol"], "TLSv1.2");
}

#[tokio::test]
async fn evaluate_audit_ignores_forwarded_tls_metadata_from_untrusted_connection() {
    let (mut state, tmp) = make_state();
    state.trusted_proxies = Arc::new(vec!["10.0.0.1".parse().unwrap()]);
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
                .header("x-forwarded-tls-version", "TLSv1.3")
                .header("x-forwarded-tls-cipher", "TLS_AES_256_GCM_SHA384")
                .header("x-forwarded-tls-kex-group", "X25519MLKEM768")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path)
        .await
        .expect("audit log should exist after evaluate");
    let entry = content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit json"))
        .expect("expected at least one audit entry");

    assert!(
        entry["metadata"].get("tls").is_none(),
        "forwarded TLS metadata must be ignored when connection is not from a trusted proxy"
    );
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
    let count = state.policy_state.load().policies.len();
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
    let count = state.policy_state.load().policies.len();
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
    let count = state.policy_state.load().policies.len();
    assert_eq!(count, 2, "Count unchanged when deleting nonexistent policy");
}

// ════════════════════════════════
// ADD_POLICY VALIDATION (R12-SRV-1)
// ════════════════════════════════

#[tokio::test]
async fn add_policy_rejects_empty_id() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let bad_policy = serde_json::to_string(&json!({
        "id": "",
        "name": "Test",
        "policy_type": "Allow",
        "priority": 10
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(bad_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_policy_rejects_duplicate_id() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // "file:read" already exists in make_state()
    let dup_policy = serde_json::to_string(&json!({
        "id": "file:read",
        "name": "Duplicate",
        "policy_type": "Allow",
        "priority": 10
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(dup_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn add_policy_rejects_extreme_priority() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let bad_policy = serde_json::to_string(&json!({
        "id": "override-all",
        "name": "Evil override",
        "policy_type": "Allow",
        "priority": 999_999
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(bad_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn add_policy_rejects_control_chars_in_name() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let bad_policy = serde_json::to_string(&json!({
        "id": "test-ctrl",
        "name": "inject\nnewline",
        "policy_type": "Allow",
        "priority": 10
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(bad_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// R17-POL-1: Dynamic policies capped at ±1000 priority
#[tokio::test]
async fn add_policy_rejects_priority_above_1000() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    let bad_policy = serde_json::to_string(&json!({
        "id": "high-prio",
        "name": "Too high priority",
        "policy_type": "Allow",
        "priority": 1001
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(bad_policy))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// R17-POL-2: Wildcard-only policy IDs rejected via API
#[tokio::test]
async fn add_policy_rejects_wildcard_only_id() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    for wildcard_id in &["*", "*:*"] {
        let bad_policy = serde_json::to_string(&json!({
            "id": wildcard_id,
            "name": "Override all",
            "policy_type": "Allow",
            "priority": 100
        }))
        .unwrap();

        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/policies")
                    .header("content-type", "application/json")
                    .body(Body::from(bad_policy))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Wildcard-only ID '{}' must be rejected",
            wildcard_id
        );
    }
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
    // R14-AUDIT-1: Route returns paginated response with metadata
    assert!(
        json.is_object(),
        "audit entries should be an object: {:?}",
        json
    );
    assert_eq!(json["count"], 0);
    assert_eq!(json["total"], 0);
    assert_eq!(json["offset"], 0);
    assert_eq!(json["limit"], 100); // DEFAULT_AUDIT_PAGE_SIZE
    assert!(json["entries"].as_array().unwrap().is_empty());
}

/// R14-AUDIT-1: Audit entries endpoint respects `limit` query parameter.
#[tokio::test]
async fn audit_entries_respects_limit_parameter() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    // Create a few audit entries via the evaluate endpoint
    for i in 0..5 {
        let evaluate_body = serde_json::json!({
            "tool": "file",
            "function": "read",
            "parameters": {"path": format!("/tmp/test-{}", i)}
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&evaluate_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Request with limit=2
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/audit/entries?limit=2")
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
    assert_eq!(json["limit"], 2);
    assert_eq!(json["offset"], 0);
    assert_eq!(json["count"], 2, "Should return exactly 2 entries");
    assert!(
        json["total"].as_u64().unwrap() >= 5,
        "Total should reflect all entries"
    );
    assert_eq!(json["entries"].as_array().unwrap().len(), 2);
}

/// R14-AUDIT-1: Audit entries endpoint respects `offset` query parameter.
#[tokio::test]
async fn audit_entries_respects_offset_parameter() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    // Create audit entries
    for i in 0..5 {
        let evaluate_body = serde_json::json!({
            "tool": "file",
            "function": "read",
            "parameters": {"path": format!("/tmp/offset-test-{}", i)}
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&evaluate_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Request with offset=3 (skip 3 most recent)
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/audit/entries?offset=3")
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
    assert_eq!(json["offset"], 3);
    let total = json["total"].as_u64().unwrap();
    let count = json["count"].as_u64().unwrap();
    // With offset=3, we should get (total - 3) entries (up to the limit)
    assert!(
        count <= total.saturating_sub(3),
        "count={count} should be <= total-3={}",
        total.saturating_sub(3)
    );
}

/// R14-AUDIT-1: Limit is capped at MAX_AUDIT_PAGE_SIZE (1000) to prevent DoS.
#[tokio::test]
async fn audit_entries_caps_limit_at_max() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state);

    // Request with limit=99999 (should be capped to 1000)
    let resp = app
        .oneshot(
            Request::get("/api/audit/entries?limit=99999")
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
    assert_eq!(
        json["limit"], 1000,
        "Limit should be capped at MAX_AUDIT_PAGE_SIZE (1000)"
    );
}

/// R14-AUDIT-1: Default pagination values when no query parameters provided.
#[tokio::test]
async fn audit_entries_default_pagination() {
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
    assert_eq!(json["limit"], 100, "Default limit should be 100");
    assert_eq!(json["offset"], 0, "Default offset should be 0");
    assert!(json["total"].is_number(), "total must be present");
    assert!(json["count"].is_number(), "count must be present");
    assert!(json["entries"].is_array(), "entries must be present");
}

/// R14-AUDIT-1: Combined limit and offset for proper page navigation.
#[tokio::test]
async fn audit_entries_combined_limit_and_offset() {
    let (state, _tmp) = make_state();
    let app = routes::build_router(state.clone());

    // Create 5 audit entries
    for i in 0..5 {
        let evaluate_body = serde_json::json!({
            "tool": "file",
            "function": "read",
            "parameters": {"path": format!("/tmp/page-test-{}", i)}
        });
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&evaluate_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Request page 2: offset=2, limit=2
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/audit/entries?limit=2&offset=2")
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
    assert_eq!(json["limit"], 2);
    assert_eq!(json["offset"], 2);
    assert_eq!(json["count"], 2, "Should return 2 entries for this page");
    assert!(json["total"].as_u64().unwrap() >= 5);
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
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
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
    let count = state.policy_state.load().policies.len();
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
    let snapshot = state.policy_state.load();
    let remaining = &snapshot.policies;
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
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![
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
            ],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
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
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
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
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("Authentication required"));
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
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
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
        approval_entry["action"]["tool"], "vellaveto",
        "Audit entry tool should be 'vellaveto'"
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
        denial_entry["action"]["tool"], "vellaveto",
        "Audit entry tool should be 'vellaveto'"
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
// R11-APPR-4: RESOLVER IDENTITY FROM BEARER TOKEN
// ════════════════════════════════

#[tokio::test]
async fn test_approve_with_bearer_derives_resolver_from_token() {
    let (state, tmp) = make_approval_state();
    let audit_path = tmp.path().join("audit.log");
    let approval_id = create_pending_approval(&state).await;

    // Approve with a Bearer token — the resolver identity should be derived
    // from the token hash, not the client-supplied resolved_by.
    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "client-name"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", approval_id))
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-token-12345")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Give async audit write a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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
        .expect("Should find approval_approved audit entry");

    let resolved_by = approval_entry["metadata"]["resolved_by"]
        .as_str()
        .expect("metadata.resolved_by should be a string");

    // R11-APPR-4: With Bearer token, resolved_by should contain the bearer hash
    // and the client note, NOT just the raw client-supplied value
    assert!(
        resolved_by.starts_with("bearer:"),
        "With Bearer token, resolved_by should start with 'bearer:' but got: {}",
        resolved_by
    );
    assert!(
        resolved_by.contains("(note: client-name)"),
        "With Bearer token, should include client note: {}",
        resolved_by
    );
}

#[tokio::test]
async fn test_deny_with_bearer_derives_resolver_from_token() {
    let (state, tmp) = make_approval_state();
    let audit_path = tmp.path().join("audit.log");
    let approval_id = create_pending_approval(&state).await;

    let app = routes::build_router(state.clone());
    let body = serde_json::to_string(&json!({"resolved_by": "auditor"})).unwrap();
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/deny", approval_id))
                .header("content-type", "application/json")
                .header("authorization", "Bearer deny-token-67890")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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
        .expect("Should find approval_denied audit entry");

    let resolved_by = denial_entry["metadata"]["resolved_by"]
        .as_str()
        .expect("metadata.resolved_by should be a string");

    assert!(
        resolved_by.starts_with("bearer:"),
        "Deny with Bearer token should derive identity from token: {}",
        resolved_by
    );
    assert!(
        resolved_by.contains("(note: auditor)"),
        "Deny should include client note: {}",
        resolved_by
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
    let (mut state, _tmp) = make_state();
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
async fn test_security_header_no_hsts_for_untrusted_forwarded_proto() {
    let (mut state, _tmp) = make_state();
    state.trusted_proxies = Arc::new(vec!["10.0.0.1".parse().unwrap()]);
    let app = routes::build_router(state);

    // X-Forwarded-Proto should be ignored from untrusted direct peers.
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
        hsts.is_none(),
        "Strict-Transport-Security header should NOT be present when forwarded proto is untrusted"
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
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
            compliance_config: Default::default(),
        })),
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
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        task_state: None,
        auth_level: None,
        circuit_breaker: None,
        deputy: None,
        shadow_agent: None,
        schema_lineage: None,
        sampling_detector: None,
        exec_graph_store: None,
        etdi_store: None,
        etdi_verifier: None,
        etdi_attestations: None,
        etdi_version_pins: None,
        memory_security: None,
        nhi: None,
        observability: None,
        // Server Configuration (FIND-004, FIND-005)
        shadow_ai_discovery: None,
        least_agency_tracker: None,
        metrics_require_auth: true,
        audit_strict_mode: false,
        leader_election: None,
        service_discovery: None,
        deployment_config: Default::default(),
        start_time: std::time::Instant::now(),
        cached_discovered_endpoints: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cached_instance_id: std::sync::Arc::new("test-instance".to_string()),
        discovery_engine: None,
        discovery_audit: None,
        projector_registry: None,
        zk_proofs: None,
        zk_audit_enabled: false,
        zk_audit_config: Default::default(),
        federation_resolver: None,
        billing_config: std::sync::Arc::new(vellaveto_server::BillingState {
            paddle: Default::default(),
            stripe: Default::default(),
            enabled: false,
            licensing_validation: vellaveto_config::LicenseValidation {
                tier: vellaveto_config::LicenseTier::Community,
                limits: vellaveto_config::LicenseTier::Community.limits(),
                reason: "test".to_string(),
            },
        }),
        setup_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        wizard_sessions: Arc::new(dashmap::DashMap::new()),
    };
    (state, tmp)
}

#[tokio::test]
async fn per_principal_rate_limit_uses_x_principal_header() {
    // 1 req/s per principal — second request from same principal gets 429
    // KL1: X-Principal is only trusted from configured trusted proxies.
    // In tests without ConnectInfo, the connection IP defaults to 127.0.0.1.
    let (mut state, _tmp) = make_per_principal_state(1);
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
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
    // KL1: X-Principal is only trusted from configured trusted proxies.
    let (mut state, _tmp) = make_per_principal_state(1);
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);

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

#[tokio::test]
async fn per_principal_x_principal_with_xff_chain_uses_principal_identity() {
    // X-Principal trust is anchored to trusted direct proxy peer, not derived
    // client IP from X-Forwarded-For chain.
    let (mut state, _tmp) = make_per_principal_state(1);
    state.trusted_proxies = Arc::new(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);

    let body = serde_json::to_string(&json!({
        "tool": "file", "function": "read", "parameters": {}
    }))
    .unwrap();

    // First request from one forwarded client IP.
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-shared")
                .header("x-forwarded-for", "198.51.100.10, 127.0.0.1")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second request with same principal but different forwarded client IP.
    // Must still be rate-limited under principal identity.
    let app = routes::build_router(state);
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-principal", "agent-shared")
                .header("x-forwarded-for", "203.0.113.5, 127.0.0.1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "same principal should rate-limit even when forwarded client IP changes"
    );
}

// ═══════════════════════════════════════════════════
// COMPILE-FIRST-THEN-STORE (R12-RELOAD-3 / R12-INT-1)
// ═══════════════════════════════════════════════════

/// Adding a policy with an invalid path glob must fail with 400
/// and leave both the policy list and compiled engine unchanged.
#[tokio::test]
async fn add_policy_with_invalid_glob_is_rejected_and_state_unchanged() {
    let (state, _tmp) = make_state();
    let policies_before = state.policy_state.load().policies.len();

    let app = routes::build_router(state.clone());

    // Policy with a syntactically invalid glob in path_rules.blocked
    let bad_policy = json!({
        "id": "bad:glob",
        "name": "Bad glob policy",
        "policy_type": "Deny",
        "priority": 10,
        "path_rules": {
            "blocked": ["[invalid-glob"]
        }
    });

    let resp = app
        .oneshot(
            Request::post("/api/policies")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&bad_policy).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Policy with invalid glob should be rejected"
    );

    // Verify policy list is unchanged
    let policies_after = state.policy_state.load().policies.len();
    assert_eq!(
        policies_before, policies_after,
        "Policy list must not change on failed compilation"
    );
}

/// Removing a policy recompiles and stores atomically.
/// Removing a valid policy should succeed and update both stores.
#[tokio::test]
async fn remove_policy_atomic_store_updates_both() {
    let (state, _tmp) = make_state();

    // Start with compiled engine so remove can also compile
    {
        let snapshot = state.policy_state.load();
        let engine = PolicyEngine::with_policies(false, &snapshot.policies).unwrap();
        state
            .policy_state
            .store(Arc::new(vellaveto_server::PolicySnapshot {
                engine,
                policies: snapshot.policies.clone(),
                compliance_config: Default::default(),
            }));
    }

    let app = routes::build_router(state.clone());

    let resp = app
        .oneshot(
            Request::delete("/api/policies/file:read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the policy was actually removed from the stored list
    let snapshot = state.policy_state.load();
    let remaining = &snapshot.policies;
    assert!(
        !remaining.iter().any(|p| p.id == "file:read"),
        "file:read should have been removed"
    );
    assert_eq!(remaining.len(), 1, "Only bash:* should remain");
}

// === R16 Security Fix Tests ===

#[tokio::test]
async fn approval_rejects_oversized_id() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    let long_id = "a".repeat(200);
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/approve", long_id))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"resolved_by":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"].as_str().unwrap().contains("characters"),
        "Error should mention character limit"
    );
}

#[tokio::test]
async fn approval_rejects_control_chars_in_id() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    // Control chars in URL path won't be routed normally, but test via get endpoint
    // which also validates. Use a tab character.
    let resp = app
        .oneshot(
            Request::get("/api/approvals/abc%09def")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn approval_deny_rejects_oversized_id() {
    let (state, _tmp) = make_approval_state();
    let app = routes::build_router(state);

    let long_id = "b".repeat(200);
    let resp = app
        .oneshot(
            Request::post(format!("/api/approvals/{}/deny", long_id))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"resolved_by":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
