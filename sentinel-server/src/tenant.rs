//! Multi-tenancy support for Sentinel.
//!
//! Provides tenant isolation for SaaS deployments, including:
//! - Tenant data model with quotas
//! - Tenant extraction from JWT, headers, or subdomain
//! - Policy namespacing by tenant
//! - Tenant-scoped rate limiting
//!
//! ## Tenant Extraction Priority
//!
//! 1. JWT claim: `tenant_id` or `org_id`
//! 2. Header: `X-Tenant-ID`
//! 3. Subdomain: `{tenant}.sentinel.example.com`
//! 4. Default tenant (for single-tenant mode)
//!
//! ## Policy Namespacing
//!
//! Policies are namespaced by tenant ID:
//! - Tenant-specific: `{tenant_id}:policy_name`
//! - Global (shared): `_global_:policy_name`

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// Global policy prefix for policies shared across all tenants.
pub const GLOBAL_TENANT_PREFIX: &str = "_global_";

/// Default tenant ID when multi-tenancy is disabled or no tenant is specified.
pub const DEFAULT_TENANT_ID: &str = "_default_";

/// Tenant data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique tenant identifier (e.g., UUID or slug).
    pub id: String,

    /// Human-readable tenant name.
    pub name: String,

    /// Whether the tenant is active (disabled tenants are rejected).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Tenant-specific quota overrides.
    #[serde(default)]
    pub quotas: TenantQuotas,

    /// Tenant metadata (custom key-value pairs).
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// Creation timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// Last update timestamp (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Tenant {
    /// Create a new tenant with default quotas.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            enabled: true,
            quotas: TenantQuotas::default(),
            metadata: HashMap::new(),
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            updated_at: None,
        }
    }

    /// Create the default tenant (for single-tenant mode).
    pub fn default_tenant() -> Self {
        Self {
            id: DEFAULT_TENANT_ID.to_string(),
            name: "Default Tenant".to_string(),
            enabled: true,
            quotas: TenantQuotas::unlimited(),
            metadata: HashMap::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

/// Tenant quota limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuotas {
    /// Maximum number of policies this tenant can create.
    #[serde(default = "default_max_policies")]
    pub max_policies: u64,

    /// Maximum policy evaluations per minute.
    #[serde(default = "default_max_evaluations_per_minute")]
    pub max_evaluations_per_minute: u64,

    /// Maximum pending approvals at any time.
    #[serde(default = "default_max_pending_approvals")]
    pub max_pending_approvals: u64,

    /// Maximum audit log retention in days.
    #[serde(default = "default_max_audit_retention_days")]
    pub max_audit_retention_days: u64,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,
}

fn default_max_policies() -> u64 {
    1000
}

fn default_max_evaluations_per_minute() -> u64 {
    10000
}

fn default_max_pending_approvals() -> u64 {
    100
}

fn default_max_audit_retention_days() -> u64 {
    90
}

fn default_max_request_body_bytes() -> u64 {
    1024 * 1024 // 1 MB
}

impl Default for TenantQuotas {
    fn default() -> Self {
        Self {
            max_policies: default_max_policies(),
            max_evaluations_per_minute: default_max_evaluations_per_minute(),
            max_pending_approvals: default_max_pending_approvals(),
            max_audit_retention_days: default_max_audit_retention_days(),
            max_request_body_bytes: default_max_request_body_bytes(),
        }
    }
}

impl TenantQuotas {
    /// Create unlimited quotas (for default tenant or super-admin).
    pub fn unlimited() -> Self {
        Self {
            max_policies: u64::MAX,
            max_evaluations_per_minute: u64::MAX,
            max_pending_approvals: u64::MAX,
            max_audit_retention_days: u64::MAX,
            max_request_body_bytes: u64::MAX,
        }
    }
}

/// Multi-tenancy configuration.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Whether multi-tenancy is enabled.
    pub enabled: bool,

    /// Whether to allow tenant extraction from headers (X-Tenant-ID).
    /// Should be disabled in production unless behind a trusted proxy.
    pub allow_header_tenant: bool,

    /// Whether to extract tenant from subdomain.
    pub allow_subdomain_tenant: bool,

    /// Base domain for subdomain extraction (e.g., "sentinel.example.com").
    pub base_domain: Option<String>,

    /// Default tenant ID when no tenant is specified.
    pub default_tenant_id: String,

    /// Whether to require a valid tenant (reject requests without tenant).
    pub require_tenant: bool,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_header_tenant: false,
            allow_subdomain_tenant: false,
            base_domain: None,
            default_tenant_id: DEFAULT_TENANT_ID.to_string(),
            require_tenant: false,
        }
    }
}

/// Extracted tenant context stored in request extensions.
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant identifier.
    pub tenant_id: String,

    /// How the tenant was extracted.
    pub source: TenantSource,

    /// Tenant quotas (if available).
    pub quotas: Option<TenantQuotas>,
}

impl TenantContext {
    /// Create a context for the default tenant.
    pub fn default_tenant() -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID.to_string(),
            source: TenantSource::Default,
            quotas: Some(TenantQuotas::unlimited()),
        }
    }

    /// Check if this is the default tenant.
    pub fn is_default(&self) -> bool {
        self.tenant_id == DEFAULT_TENANT_ID
    }

    /// Check if this is a global policy prefix.
    pub fn is_global(policy_id: &str) -> bool {
        policy_id.starts_with(GLOBAL_TENANT_PREFIX)
    }

    /// Namespace a policy ID for this tenant.
    pub fn namespace_policy(&self, policy_id: &str) -> String {
        if Self::is_global(policy_id) {
            policy_id.to_string()
        } else {
            format!("{}:{}", self.tenant_id, policy_id)
        }
    }

    /// Extract the tenant ID from a namespaced policy ID.
    pub fn extract_tenant_from_policy(policy_id: &str) -> Option<&str> {
        policy_id.split_once(':').map(|(tenant, _)| tenant)
    }

    /// Check if a policy belongs to this tenant (or is global/legacy).
    ///
    /// Policy matching rules:
    /// - `_global_:{policy}` - matches all tenants (global shared policy)
    /// - `{tenant_id}:{tool}:{rest}` - matches only that tenant (has 2+ colons)
    /// - `{tool}:{function}` - legacy format, matches all tenants (has 1 colon)
    /// - `{policy_name}` - legacy format, matches all tenants (no colon)
    ///
    /// The distinguishing factor is the number of colons: namespaced policies
    /// have at least 2 colons (tenant:tool:function), while legacy policies
    /// have at most 1 colon (tool:function or just policy_name).
    pub fn policy_matches(&self, policy_id: &str) -> bool {
        // Global policies match all tenants
        if Self::is_global(policy_id) {
            return true;
        }

        // Count colons to distinguish namespaced from legacy
        let colon_count = policy_id.chars().filter(|&c| c == ':').count();

        if colon_count >= 2 {
            // Namespaced format: {tenant_id}:{tool}:{rest}
            if let Some((tenant_prefix, _rest)) = policy_id.split_once(':') {
                // Must be this tenant's policy
                return tenant_prefix == self.tenant_id;
            }
        }

        // Legacy policy (0-1 colons) - matches all tenants for backwards compatibility
        true
    }
}

/// How the tenant was extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSource {
    /// From JWT claims (tenant_id or org_id).
    Jwt,
    /// From X-Tenant-ID header.
    Header,
    /// From subdomain.
    Subdomain,
    /// Default tenant (no explicit tenant specified).
    Default,
}

/// JWT claims for tenant extraction.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantClaims {
    /// Tenant ID claim (primary).
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// Organization ID claim (alternative).
    #[serde(default)]
    pub org_id: Option<String>,

    /// Organization claim (another alternative).
    #[serde(default)]
    pub organization: Option<String>,
}

impl TenantClaims {
    /// Extract the effective tenant ID from claims.
    pub fn effective_tenant_id(&self) -> Option<&str> {
        self.tenant_id
            .as_deref()
            .or(self.org_id.as_deref())
            .or(self.organization.as_deref())
    }
}

/// Tenant extraction errors.
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    #[error("tenant required but not specified")]
    TenantRequired,

    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    #[error("tenant disabled: {0}")]
    TenantDisabled(String),

    #[error("invalid tenant ID: {0}")]
    InvalidTenantId(String),

    /// SECURITY (FIND-025): Internal error for lock poisoning.
    /// Fail-closed: lock poisoning prevents tenant operations rather than panicking.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Extract tenant ID from request headers.
pub fn extract_tenant_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Extract tenant ID from subdomain.
pub fn extract_tenant_from_subdomain(host: &str, base_domain: &str) -> Option<String> {
    // Remove port if present
    let host = host.split(':').next().unwrap_or(host);
    let base = base_domain.trim_start_matches('.');

    // Check if host ends with base domain
    if !host.ends_with(base) {
        return None;
    }

    // Extract subdomain
    let prefix = host.strip_suffix(base)?.trim_end_matches('.');
    if prefix.is_empty() {
        return None;
    }

    // Only use first subdomain segment
    let tenant = prefix.rsplit('.').next()?;
    if tenant.is_empty() {
        return None;
    }

    Some(tenant.to_string())
}

/// Validate a tenant ID format.
pub fn validate_tenant_id(id: &str) -> Result<(), TenantError> {
    if id.is_empty() {
        return Err(TenantError::InvalidTenantId(
            "tenant ID cannot be empty".to_string(),
        ));
    }

    if id.len() > 64 {
        return Err(TenantError::InvalidTenantId(
            "tenant ID too long (max 64 chars)".to_string(),
        ));
    }

    // Allow alphanumeric, hyphens, underscores
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(TenantError::InvalidTenantId(
            "tenant ID contains invalid characters".to_string(),
        ));
    }

    // Reserved prefixes
    if id.starts_with('_') && id != DEFAULT_TENANT_ID {
        return Err(TenantError::InvalidTenantId(
            "tenant ID cannot start with underscore (reserved)".to_string(),
        ));
    }

    Ok(())
}

/// Middleware state for tenant extraction.
#[derive(Clone)]
pub struct TenantState {
    pub config: TenantConfig,
    /// Tenant store for looking up tenant details and quotas.
    pub store: Option<Arc<dyn TenantStore>>,
}

/// Trait for tenant storage backends.
pub trait TenantStore: Send + Sync {
    /// Look up a tenant by ID.
    fn get_tenant(&self, id: &str) -> Option<Tenant>;

    /// List all tenants.
    fn list_tenants(&self) -> Vec<Tenant>;

    /// Create a new tenant.
    fn create_tenant(&self, tenant: Tenant) -> Result<(), TenantError>;

    /// Update an existing tenant.
    fn update_tenant(&self, tenant: Tenant) -> Result<(), TenantError>;

    /// Delete a tenant.
    fn delete_tenant(&self, id: &str) -> Result<(), TenantError>;
}

/// In-memory tenant store for testing and single-instance deployments.
#[derive(Debug, Default)]
pub struct InMemoryTenantStore {
    tenants: std::sync::RwLock<HashMap<String, Tenant>>,
}

impl InMemoryTenantStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_tenant() -> Self {
        let store = Self::new();
        // SECURITY (FIND-025): Use ok() to avoid panic on lock poisoning.
        // If poisoned at construction time, the store is empty but usable.
        if let Ok(mut tenants) = store.tenants.write() {
            tenants.insert(DEFAULT_TENANT_ID.to_string(), Tenant::default_tenant());
        }
        store
    }
}

impl TenantStore for InMemoryTenantStore {
    fn get_tenant(&self, id: &str) -> Option<Tenant> {
        // SECURITY (FIND-025): Fail-closed on lock poisoning — return None (tenant not found).
        // This denies access rather than panicking.
        self.tenants
            .read()
            .ok()
            .and_then(|guard| guard.get(id).cloned())
    }

    fn list_tenants(&self) -> Vec<Tenant> {
        // SECURITY (FIND-025): Fail-closed on lock poisoning — return empty list.
        self.tenants
            .read()
            .ok()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default()
    }

    fn create_tenant(&self, tenant: Tenant) -> Result<(), TenantError> {
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if tenants.contains_key(&tenant.id) {
            return Err(TenantError::InvalidTenantId(format!(
                "tenant already exists: {}",
                tenant.id
            )));
        }
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }

    fn update_tenant(&self, tenant: Tenant) -> Result<(), TenantError> {
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if !tenants.contains_key(&tenant.id) {
            return Err(TenantError::TenantNotFound(tenant.id.clone()));
        }
        tenants.insert(tenant.id.clone(), tenant);
        Ok(())
    }

    fn delete_tenant(&self, id: &str) -> Result<(), TenantError> {
        // SECURITY (FIND-025): Return error on lock poisoning instead of panicking.
        let mut tenants = self
            .tenants
            .write()
            .map_err(|_| TenantError::Internal("lock poisoned".into()))?;
        if tenants.remove(id).is_none() {
            return Err(TenantError::TenantNotFound(id.to_string()));
        }
        Ok(())
    }
}

/// Extract tenant context from a request.
pub fn extract_tenant_from_request(
    headers: &axum::http::HeaderMap,
    host: Option<&str>,
    config: &TenantConfig,
    store: Option<&dyn TenantStore>,
) -> Result<TenantContext, TenantError> {
    // Skip extraction if multi-tenancy is disabled
    if !config.enabled {
        return Ok(TenantContext::default_tenant());
    }

    // Try extraction in priority order
    let (tenant_id, source) = {
        // 1. Header (if allowed)
        if config.allow_header_tenant {
            if let Some(id) = extract_tenant_from_header(headers) {
                (Some(id), TenantSource::Header)
            } else {
                (None, TenantSource::Default)
            }
        }
        // 2. Subdomain (if allowed)
        else if config.allow_subdomain_tenant {
            if let (Some(host), Some(base)) = (host, &config.base_domain) {
                if let Some(id) = extract_tenant_from_subdomain(host, base) {
                    (Some(id), TenantSource::Subdomain)
                } else {
                    (None, TenantSource::Default)
                }
            } else {
                (None, TenantSource::Default)
            }
        } else {
            (None, TenantSource::Default)
        }
    };

    // Use default tenant if none extracted
    let (tenant_id, source) = match tenant_id {
        Some(id) => (id, source),
        None => {
            if config.require_tenant {
                return Err(TenantError::TenantRequired);
            }
            (config.default_tenant_id.clone(), TenantSource::Default)
        }
    };

    // Validate tenant ID format
    validate_tenant_id(&tenant_id)?;

    // Look up tenant in store (if available) to get quotas and check enabled status
    let quotas = if let Some(store) = store {
        match store.get_tenant(&tenant_id) {
            Some(tenant) => {
                if !tenant.enabled {
                    return Err(TenantError::TenantDisabled(tenant_id));
                }
                Some(tenant.quotas)
            }
            None => {
                // Tenant not found in store - use default quotas
                // (or reject if require_tenant is true)
                if config.require_tenant && source != TenantSource::Default {
                    return Err(TenantError::TenantNotFound(tenant_id));
                }
                None
            }
        }
    } else {
        None
    };

    Ok(TenantContext {
        tenant_id,
        source,
        quotas,
    })
}

/// Tenant extraction middleware.
///
/// Extracts tenant from JWT, header, or subdomain and stores in request extensions.
pub async fn tenant_middleware(
    State(tenant_state): State<TenantState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Skip if multi-tenancy is disabled
    if !tenant_state.config.enabled {
        request
            .extensions_mut()
            .insert(TenantContext::default_tenant());
        return next.run(request).await;
    }

    // Extract host from headers
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract tenant
    let store = tenant_state.store.as_deref();
    match extract_tenant_from_request(
        request.headers(),
        host.as_deref(),
        &tenant_state.config,
        store,
    ) {
        Ok(context) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(e) => {
            let status = match &e {
                TenantError::TenantRequired => StatusCode::BAD_REQUEST,
                TenantError::TenantNotFound(_) => StatusCode::NOT_FOUND,
                TenantError::TenantDisabled(_) => StatusCode::FORBIDDEN,
                TenantError::InvalidTenantId(_) => StatusCode::BAD_REQUEST,
                TenantError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(json!({ "error": e.to_string() }))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_new() {
        let tenant = Tenant::new("test-tenant", "Test Tenant");
        assert_eq!(tenant.id, "test-tenant");
        assert_eq!(tenant.name, "Test Tenant");
        assert!(tenant.enabled);
        assert!(tenant.created_at.is_some());
    }

    #[test]
    fn test_tenant_quotas_default() {
        let quotas = TenantQuotas::default();
        assert_eq!(quotas.max_policies, 1000);
        assert_eq!(quotas.max_evaluations_per_minute, 10000);
        assert_eq!(quotas.max_pending_approvals, 100);
        assert_eq!(quotas.max_audit_retention_days, 90);
    }

    #[test]
    fn test_tenant_quotas_unlimited() {
        let quotas = TenantQuotas::unlimited();
        assert_eq!(quotas.max_policies, u64::MAX);
        assert_eq!(quotas.max_evaluations_per_minute, u64::MAX);
    }

    #[test]
    fn test_tenant_context_namespace_policy() {
        let context = TenantContext {
            tenant_id: "acme".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };

        // Regular policy gets namespaced (adds tenant: prefix)
        assert_eq!(context.namespace_policy("file:read"), "acme:file:read");
        assert_eq!(
            context.namespace_policy("file_system:read_file"),
            "acme:file_system:read_file"
        );

        // Policy without colons gets namespaced
        assert_eq!(context.namespace_policy("dangerous_block"), "acme:dangerous_block");

        // Global policy stays as-is
        assert_eq!(
            context.namespace_policy("_global_:dangerous_block"),
            "_global_:dangerous_block"
        );
    }

    #[test]
    fn test_tenant_context_policy_matches() {
        let context = TenantContext {
            tenant_id: "acme".to_string(),
            source: TenantSource::Header,
            quotas: None,
        };

        // Matches own policies (namespaced: tenant:tool:function with 2+ colons)
        assert!(context.policy_matches("acme:file:read"));
        assert!(context.policy_matches("acme:file_system:read_file"));

        // Matches global policies
        assert!(context.policy_matches("_global_:block_dangerous"));

        // Doesn't match other tenant's policies
        assert!(!context.policy_matches("other:file:read"));
        assert!(!context.policy_matches("competitor:file_system:write"));

        // Matches legacy policies (0-1 colons for backwards compatibility)
        assert!(context.policy_matches("file:read"));  // 1 colon - legacy
        assert!(context.policy_matches("dangerous_block"));  // 0 colons - legacy
    }

    #[test]
    fn test_extract_tenant_from_subdomain() {
        // Basic extraction
        assert_eq!(
            extract_tenant_from_subdomain("acme.sentinel.example.com", "sentinel.example.com"),
            Some("acme".to_string())
        );

        // With port
        assert_eq!(
            extract_tenant_from_subdomain("acme.sentinel.example.com:8080", "sentinel.example.com"),
            Some("acme".to_string())
        );

        // Multi-level subdomain (only first level)
        assert_eq!(
            extract_tenant_from_subdomain("dev.acme.sentinel.example.com", "sentinel.example.com"),
            Some("acme".to_string())
        );

        // No subdomain
        assert_eq!(
            extract_tenant_from_subdomain("sentinel.example.com", "sentinel.example.com"),
            None
        );

        // Different domain
        assert_eq!(
            extract_tenant_from_subdomain("acme.other.com", "sentinel.example.com"),
            None
        );
    }

    #[test]
    fn test_validate_tenant_id() {
        // Valid
        assert!(validate_tenant_id("acme").is_ok());
        assert!(validate_tenant_id("acme-corp").is_ok());
        assert!(validate_tenant_id("tenant_123").is_ok());
        assert!(validate_tenant_id("ACME").is_ok());

        // Invalid: empty
        assert!(validate_tenant_id("").is_err());

        // Invalid: too long
        let long_id = "a".repeat(65);
        assert!(validate_tenant_id(&long_id).is_err());

        // Invalid: special characters
        assert!(validate_tenant_id("acme.corp").is_err());
        assert!(validate_tenant_id("acme/corp").is_err());
        assert!(validate_tenant_id("acme:corp").is_err());

        // Invalid: underscore prefix (reserved)
        assert!(validate_tenant_id("_custom").is_err());

        // Valid: _default_ is allowed
        assert!(validate_tenant_id("_default_").is_ok());
    }

    #[test]
    fn test_in_memory_tenant_store() {
        let store = InMemoryTenantStore::new();

        // Create
        let tenant = Tenant::new("acme", "Acme Corp");
        store.create_tenant(tenant.clone()).unwrap();

        // Get
        let fetched = store.get_tenant("acme").unwrap();
        assert_eq!(fetched.name, "Acme Corp");

        // List
        let tenants = store.list_tenants();
        assert_eq!(tenants.len(), 1);

        // Update
        let mut updated = tenant.clone();
        updated.name = "Acme Corporation".to_string();
        store.update_tenant(updated).unwrap();
        let fetched = store.get_tenant("acme").unwrap();
        assert_eq!(fetched.name, "Acme Corporation");

        // Delete
        store.delete_tenant("acme").unwrap();
        assert!(store.get_tenant("acme").is_none());

        // Delete non-existent
        assert!(store.delete_tenant("nonexistent").is_err());
    }

    #[test]
    fn test_extract_tenant_from_request_disabled() {
        let config = TenantConfig {
            enabled: false,
            ..Default::default()
        };

        let headers = axum::http::HeaderMap::new();
        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.tenant_id, DEFAULT_TENANT_ID);
        assert!(context.is_default());
    }

    #[test]
    fn test_extract_tenant_from_request_header() {
        let config = TenantConfig {
            enabled: true,
            allow_header_tenant: true,
            ..Default::default()
        };

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static("x-tenant-id"),
            axum::http::HeaderValue::from_static("acme"),
        );

        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.tenant_id, "acme");
        assert_eq!(context.source, TenantSource::Header);
    }

    #[test]
    fn test_extract_tenant_required() {
        let config = TenantConfig {
            enabled: true,
            allow_header_tenant: true,
            require_tenant: true,
            ..Default::default()
        };

        let headers = axum::http::HeaderMap::new();
        let result = extract_tenant_from_request(&headers, None, &config, None);
        assert!(matches!(result, Err(TenantError::TenantRequired)));
    }

    #[test]
    fn test_tenant_context_is_global() {
        assert!(TenantContext::is_global("_global_:dangerous_block"));
        assert!(!TenantContext::is_global("acme:file:read"));
        assert!(!TenantContext::is_global("file:read"));
    }
}
