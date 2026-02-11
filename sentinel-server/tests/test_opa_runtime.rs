//! OPA runtime tests isolated from general route unit tests.
//!
//! These tests mutate global OPA runtime configuration, so they run in a
//! dedicated test target to avoid cross-test interference.

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_config::OpaConfig;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use sentinel_types::{Policy, PolicyType};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

static OPA_RUNTIME_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

struct OpaRuntimeResetGuard;

impl Drop for OpaRuntimeResetGuard {
    fn drop(&mut self) {
        let _ = sentinel_server::opa::configure_runtime_client(&OpaConfig::default());
    }
}

fn test_state() -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
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
        })),
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
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: sentinel_server::rbac::RbacConfig::default(),
        tenant_config: sentinel_server::tenant::TenantConfig::default(),
        tenant_store: None,
        idempotency: sentinel_server::idempotency::IdempotencyStore::new(
            sentinel_server::idempotency::IdempotencyConfig::default(),
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
        metrics_require_auth: true,
        audit_strict_mode: false,
    };
    (state, tmp)
}

async fn evaluate_file_read() -> (serde_json::Value, Arc<AuditLogger>, TempDir) {
    let (state, tmp) = test_state();
    let audit = state.audit.clone();
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
    (json, audit, tmp)
}

#[tokio::test]
async fn evaluate_opa_fail_closed_denies_on_unreachable_server() {
    let _lock = OPA_RUNTIME_TEST_LOCK.lock().await;
    let _reset = OpaRuntimeResetGuard;

    let cfg = OpaConfig {
        enabled: true,
        endpoint: Some("http://127.0.0.1:9".to_string()),
        decision_path: "sentinel/allow".to_string(),
        cache_ttl_secs: 0,
        timeout_ms: 50,
        fail_open: false,
        max_retries: 0,
        retry_backoff_ms: 10,
        headers: Default::default(),
        bundle_path: None,
        audit_decisions: false,
        cache_size: 1000,
    };
    sentinel_server::opa::configure_runtime_client(&cfg).unwrap();

    let (json, audit, _tmp) = evaluate_file_read().await;
    assert_eq!(
        json["verdict"]["Deny"]["reason"],
        "OPA evaluation failed (fail-closed)"
    );

    let entries = audit.load_entries().await.unwrap();
    let entry = entries.last().expect("expected audit entry");
    assert_eq!(entry.metadata["opa"]["result"], "error");
    assert_eq!(entry.metadata["opa"]["fail_open"], false);
}

#[tokio::test]
async fn evaluate_opa_fail_open_allows_on_unreachable_server() {
    let _lock = OPA_RUNTIME_TEST_LOCK.lock().await;
    let _reset = OpaRuntimeResetGuard;

    let cfg = OpaConfig {
        enabled: true,
        endpoint: Some("http://127.0.0.1:9".to_string()),
        decision_path: "sentinel/allow".to_string(),
        cache_ttl_secs: 0,
        timeout_ms: 50,
        fail_open: true,
        max_retries: 0,
        retry_backoff_ms: 10,
        headers: Default::default(),
        bundle_path: None,
        audit_decisions: false,
        cache_size: 1000,
    };
    sentinel_server::opa::configure_runtime_client(&cfg).unwrap();

    let (json, audit, _tmp) = evaluate_file_read().await;
    assert_eq!(json["verdict"], "Allow");

    let entries = audit.load_entries().await.unwrap();
    let entry = entries.last().expect("expected audit entry");
    assert_eq!(entry.metadata["opa"]["result"], "error");
    assert_eq!(entry.metadata["opa"]["fail_open"], true);
}
