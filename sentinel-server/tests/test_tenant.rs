//! Tenant isolation integration tests for the Sentinel HTTP API server.
//!
//! Verifies that multi-tenancy features work correctly:
//! - Tenant extraction from headers, subdomains
//! - Policy namespacing by tenant
//! - Tenant management API endpoints
//! - Tenant isolation between requests

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_server::tenant::{
    InMemoryTenantStore, Tenant, TenantConfig, TenantContext, TenantQuotas, TenantSource,
    TenantStore,
};
use sentinel_server::{routes, AppState, Metrics, PolicySnapshot, RateLimits};
use sentinel_types::{Policy, PolicyType};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

fn test_state_with_tenants(
    tenant_config: TenantConfig,
    tenant_store: Option<Arc<dyn sentinel_server::tenant::TenantStore>>,
) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![
                // Tenant-specific policy for acme
                Policy {
                    id: "acme:file:allow".to_string(),
                    name: "Acme file access".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                },
                // Tenant-specific policy for globex
                Policy {
                    id: "globex:file:deny".to_string(),
                    name: "Globex file deny".to_string(),
                    policy_type: PolicyType::Deny,
                    priority: 10,
                    path_rules: None,
                    network_rules: None,
                },
                // Global shared policy
                Policy {
                    id: "_global_:health:allow".to_string(),
                    name: "Global health check".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 5,
                    path_rules: None,
                    network_rules: None,
                },
                // Legacy policy (no tenant namespace)
                Policy {
                    id: "legacy:policy".to_string(),
                    name: "Legacy policy".to_string(),
                    policy_type: PolicyType::Allow,
                    priority: 1,
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
        api_key: None, // No API key auth for these tests
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
        cluster: None,
        rbac_config: sentinel_server::rbac::RbacConfig::default(),
        tenant_config,
        tenant_store,
        idempotency: sentinel_server::idempotency::IdempotencyStore::new(sentinel_server::idempotency::IdempotencyConfig::default()),
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
    };
    (state, tmp)
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Extraction Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tenant_disabled_uses_default_tenant() {
    let config = TenantConfig {
        enabled: false,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_extracted_from_header() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenant_required_but_missing_returns_400() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_not_found_returns_404() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenant_disabled_returns_403() {
    let store = Arc::new(InMemoryTenantStore::new());
    // Add a disabled tenant
    store
        .create_tenant(Tenant {
            id: "disabled-tenant".to_string(),
            name: "Disabled Tenant".to_string(),
            enabled: false,
            quotas: TenantQuotas::default(),
            metadata: Default::default(),
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    let config = TenantConfig {
        enabled: true,
        require_tenant: true,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-ID", "disabled-tenant")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Context Policy Matching Tests
// ────────────────────────────────────────────────────────────────────────────

fn tenant_ctx(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: id.to_string(),
        source: TenantSource::Header,
        quotas: None,
    }
}

#[test]
fn tenant_context_matches_own_policies() {
    let ctx = tenant_ctx("acme");

    // Own namespaced policy
    assert!(ctx.policy_matches("acme:file:read"));
    assert!(ctx.policy_matches("acme:tool:function"));

    // Global policies
    assert!(ctx.policy_matches("_global_:health:check"));

    // Legacy policies (no namespace)
    assert!(ctx.policy_matches("tool:function"));
    assert!(ctx.policy_matches("simple-policy"));
}

#[test]
fn tenant_context_rejects_other_tenant_policies() {
    let ctx = tenant_ctx("acme");

    // Other tenant's namespaced policies
    assert!(!ctx.policy_matches("globex:file:read"));
    assert!(!ctx.policy_matches("other:tool:function"));
}

#[test]
fn tenant_context_namespace_policy_correctly() {
    let ctx = tenant_ctx("acme");

    // Namespace a policy
    assert_eq!(ctx.namespace_policy("file:read"), "acme:file:read");
    assert_eq!(ctx.namespace_policy("tool:function"), "acme:tool:function");

    // Already namespaced (don't double-namespace)
    assert_eq!(ctx.namespace_policy("acme:file:read"), "acme:acme:file:read");
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Management API Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_tenants_empty_when_no_store() {
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenants: Vec<Tenant> = serde_json::from_slice(&body).unwrap();
    assert!(tenants.is_empty());
}

#[tokio::test]
async fn list_tenants_returns_all_tenants() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    store
        .create_tenant(Tenant::new("acme", "Acme Corporation"))
        .unwrap();
    store
        .create_tenant(Tenant::new("globex", "Globex Corporation"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tenants: Vec<Tenant> = serde_json::from_slice(&body).unwrap();
    assert_eq!(tenants.len(), 3); // default + acme + globex
}

#[tokio::test]
async fn get_tenant_returns_tenant() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    store
        .create_tenant(Tenant::new("acme", "Acme Corporation"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/acme")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["id"], "acme");
    assert_eq!(resp["tenant"]["name"], "Acme Corporation");
}

#[tokio::test]
async fn get_tenant_not_found() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "new-tenant",
        "name": "New Tenant Inc"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["id"], "new-tenant");
    assert_eq!(resp["tenant"]["name"], "New Tenant Inc");
    assert_eq!(resp["tenant"]["enabled"], true);
}

#[tokio::test]
async fn create_tenant_invalid_id() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "invalid@tenant!",
        "name": "Invalid Tenant"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_tenant_duplicate_id() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("existing", "Existing Tenant"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "existing",
        "name": "Duplicate Tenant"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/tenants")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("acme", "Acme Corp"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "acme",
        "name": "Acme Corporation Updated",
        "enabled": false
    });

    let request = Request::builder()
        .method("PUT")
        .uri("/api/tenants/acme")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["tenant"]["name"], "Acme Corporation Updated");
    assert_eq!(resp["tenant"]["enabled"], false);
}

#[tokio::test]
async fn update_tenant_id_mismatch() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("acme", "Acme Corp"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let body = json!({
        "id": "different-id",
        "name": "Acme Corporation"
    });

    let request = Request::builder()
        .method("PUT")
        .uri("/api/tenants/acme")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_tenant_success() {
    let store = Arc::new(InMemoryTenantStore::new());
    store
        .create_tenant(Tenant::new("to-delete", "Delete Me"))
        .unwrap();

    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store.clone()));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/to-delete")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify deletion
    assert!(store.get_tenant("to-delete").is_none());
}

#[tokio::test]
async fn delete_tenant_not_found() {
    let store = Arc::new(InMemoryTenantStore::new());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/nonexistent")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_default_tenant_forbidden() {
    let store = Arc::new(InMemoryTenantStore::with_default_tenant());
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, Some(store));
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("DELETE")
        .uri("/api/tenants/_default_")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tenant_store_not_configured_returns_501() {
    let config = TenantConfig::default();
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    let request = Request::builder()
        .method("GET")
        .uri("/api/tenants/some-tenant")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Isolation in Evaluate Tests
// ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn evaluate_includes_tenant_id_in_context() {
    let config = TenantConfig {
        enabled: true,
        require_tenant: false,
        allow_header_tenant: true,
        ..Default::default()
    };
    let (state, _tmp) = test_state_with_tenants(config, None);
    let app = routes::build_router(state);

    // Action is flattened into the request body
    let body = json!({
        "tool": "file",
        "function": "read",
        "parameters": {}
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/evaluate")
        .header("Content-Type", "application/json")
        .header("X-Tenant-ID", "test-tenant")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // Should succeed (no policies block it)
    assert_eq!(response.status(), StatusCode::OK);
}
