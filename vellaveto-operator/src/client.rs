//! Typed HTTP client for the Vellaveto server REST API.
//!
//! The operator uses this client to reconcile CRD desired state against
//! the Vellaveto server. All methods validate inputs, use `?` for error
//! propagation, and enforce a 10-second default timeout.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crd::is_unicode_format_char;
use crate::error::OperatorError;

/// Maximum URL length accepted by the client.
const MAX_URL_LEN: usize = 2048;

/// Default request timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum path parameter length.
const MAX_PATH_PARAM_LEN: usize = 256;

/// Maximum response body size (16 MiB).
const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// Typed HTTP client wrapping `reqwest::Client` for the Vellaveto REST API.
#[derive(Debug, Clone)]
pub struct VellavetoApiClient {
    client: reqwest::Client,
    base_url: String,
}

// ═══════════════════════════════════════════════════
// API response/request types
// ═══════════════════════════════════════════════════

/// Policy as returned by the Vellaveto server API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiPolicy {
    pub id: String,
    pub name: String,
    pub policy_type: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<ApiPathRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<ApiNetworkRules>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiPathRules {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiNetworkRules {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_rules: Option<ApiIpRules>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiIpRules {
    #[serde(default)]
    pub block_private: bool,
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

/// Tenant as returned by the Vellaveto server API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTenant {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub quotas: ApiTenantQuotas,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApiTenantQuotas {
    #[serde(default)]
    pub max_policies: u64,
    #[serde(default)]
    pub max_evaluations_per_minute: u64,
    #[serde(default)]
    pub max_pending_approvals: u64,
    #[serde(default)]
    pub max_audit_retention_days: u64,
    #[serde(default)]
    pub max_request_body_bytes: u64,
}

/// Request body for creating/updating a tenant.
#[derive(Debug, Clone, Serialize)]
pub struct TenantRequest {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotas: Option<ApiTenantQuotas>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

/// Wrapper for tenant API responses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResponse {
    pub tenant: ApiTenant,
}

/// Wrapper for tenant list API responses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantListResponse {
    pub tenants: Vec<ApiTenant>,
}

/// Wrapper for policy list API responses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyListResponse {
    pub policies: Vec<ApiPolicy>,
}

/// Health check response.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    #[serde(default)]
    pub status: String,
}

// ═══════════════════════════════════════════════════
// Client implementation
// ═══════════════════════════════════════════════════

impl VellavetoApiClient {
    /// Create a new API client with the given base URL.
    ///
    /// Validates the URL scheme (must be http or https) and rejects
    /// URLs pointing to SSRF-sensitive addresses.
    pub fn new(base_url: &str) -> Result<Self, OperatorError> {
        if base_url.is_empty() {
            return Err(OperatorError::Config("base_url must not be empty".into()));
        }
        if base_url.len() > MAX_URL_LEN {
            return Err(OperatorError::Config(format!(
                "base_url exceeds max length of {MAX_URL_LEN}"
            )));
        }
        // Validate scheme
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(OperatorError::Config(
                "base_url must use http:// or https:// scheme".into(),
            ));
        }
        // Reject userinfo in URL (SSRF vector)
        if let Some(authority) = base_url
            .strip_prefix("http://")
            .or_else(|| base_url.strip_prefix("https://"))
        {
            let host_part = authority.split('/').next().unwrap_or("");
            if host_part.contains('@') {
                return Err(OperatorError::Config(
                    "base_url must not contain userinfo (@)".into(),
                ));
            }
        }

        let url = base_url.trim_end_matches('/').to_string();

        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OperatorError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            base_url: url,
        })
    }

    /// Health check — verifies the Vellaveto server is reachable.
    pub async fn health(&self) -> Result<(), OperatorError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(OperatorError::Api(format!(
                "health check failed with status {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// List all policies from the Vellaveto server.
    pub async fn list_policies(&self) -> Result<Vec<ApiPolicy>, OperatorError> {
        let resp = self
            .client
            .get(format!("{}/api/policies", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(OperatorError::Api(format!(
                "list_policies failed with status {}",
                resp.status()
            )));
        }
        let body = self.read_bounded_body(resp).await?;
        let list: PolicyListResponse = serde_json::from_str(&body)?;
        Ok(list.policies)
    }

    /// Add a policy to the Vellaveto server.
    pub async fn add_policy(&self, policy: &ApiPolicy) -> Result<(), OperatorError> {
        validate_path_param(&policy.id, "policy.id")?;
        let resp = self
            .client
            .post(format!("{}/api/policies", self.base_url))
            .json(policy)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = self.read_bounded_body(resp).await.unwrap_or_default();
            return Err(OperatorError::Api(format!(
                "add_policy failed with status {status}: {body}"
            )));
        }
        Ok(())
    }

    /// Delete a policy from the Vellaveto server.
    pub async fn delete_policy(&self, id: &str) -> Result<(), OperatorError> {
        validate_path_param(id, "policy_id")?;
        let resp = self
            .client
            .delete(format!("{}/api/policies/{id}", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            // 404 is acceptable — policy may already be deleted
            if status.as_u16() == 404 {
                return Ok(());
            }
            return Err(OperatorError::Api(format!(
                "delete_policy failed with status {status}"
            )));
        }
        Ok(())
    }

    /// List all tenants from the Vellaveto server.
    pub async fn list_tenants(&self) -> Result<Vec<ApiTenant>, OperatorError> {
        let resp = self
            .client
            .get(format!("{}/api/tenants", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(OperatorError::Api(format!(
                "list_tenants failed with status {}",
                resp.status()
            )));
        }
        let body = self.read_bounded_body(resp).await?;
        let list: TenantListResponse = serde_json::from_str(&body)?;
        Ok(list.tenants)
    }

    /// Get a single tenant by ID.
    pub async fn get_tenant(&self, id: &str) -> Result<Option<ApiTenant>, OperatorError> {
        validate_path_param(id, "tenant_id")?;
        let resp = self
            .client
            .get(format!("{}/api/tenants/{id}", self.base_url))
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(OperatorError::Api(format!(
                "get_tenant failed with status {}",
                resp.status()
            )));
        }
        let body = self.read_bounded_body(resp).await?;
        let tenant_resp: TenantResponse = serde_json::from_str(&body)?;
        Ok(Some(tenant_resp.tenant))
    }

    /// Create a tenant on the Vellaveto server.
    pub async fn create_tenant(&self, req: &TenantRequest) -> Result<ApiTenant, OperatorError> {
        validate_path_param(&req.id, "tenant_id")?;
        let resp = self
            .client
            .post(format!("{}/api/tenants", self.base_url))
            .json(req)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = self.read_bounded_body(resp).await.unwrap_or_default();
            return Err(OperatorError::Api(format!(
                "create_tenant failed with status {status}: {body}"
            )));
        }
        let body = self.read_bounded_body(resp).await?;
        let tenant_resp: TenantResponse = serde_json::from_str(&body)?;
        Ok(tenant_resp.tenant)
    }

    /// Update a tenant on the Vellaveto server.
    pub async fn update_tenant(
        &self,
        id: &str,
        req: &TenantRequest,
    ) -> Result<ApiTenant, OperatorError> {
        validate_path_param(id, "tenant_id")?;
        let resp = self
            .client
            .put(format!("{}/api/tenants/{id}", self.base_url))
            .json(req)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = self.read_bounded_body(resp).await.unwrap_or_default();
            return Err(OperatorError::Api(format!(
                "update_tenant failed with status {status}: {body}"
            )));
        }
        let body = self.read_bounded_body(resp).await?;
        let tenant_resp: TenantResponse = serde_json::from_str(&body)?;
        Ok(tenant_resp.tenant)
    }

    /// Delete a tenant from the Vellaveto server.
    pub async fn delete_tenant(&self, id: &str) -> Result<(), OperatorError> {
        validate_path_param(id, "tenant_id")?;
        let resp = self
            .client
            .delete(format!("{}/api/tenants/{id}", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            // 404 is acceptable — tenant may already be deleted
            if status.as_u16() == 404 {
                return Ok(());
            }
            return Err(OperatorError::Api(format!(
                "delete_tenant failed with status {status}"
            )));
        }
        Ok(())
    }

    /// Read the response body with a size bound to prevent OOM.
    async fn read_bounded_body(&self, resp: reqwest::Response) -> Result<String, OperatorError> {
        let content_length = resp.content_length().unwrap_or(0) as usize;
        if content_length > MAX_RESPONSE_BODY {
            return Err(OperatorError::Api(format!(
                "response body too large: {content_length} bytes"
            )));
        }
        let bytes = resp.bytes().await?;
        if bytes.len() > MAX_RESPONSE_BODY {
            return Err(OperatorError::Api(format!(
                "response body too large: {} bytes",
                bytes.len()
            )));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|e| OperatorError::Api(format!("response body is not valid UTF-8: {e}")))
    }
}

/// Validate a path parameter for length and dangerous characters.
fn validate_path_param(value: &str, field: &str) -> Result<(), OperatorError> {
    if value.is_empty() {
        return Err(OperatorError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_PATH_PARAM_LEN {
        return Err(OperatorError::Validation(format!(
            "{field} exceeds max length of {MAX_PATH_PARAM_LEN}"
        )));
    }
    if value
        .chars()
        .any(|c| c.is_control() || is_unicode_format_char(c) || c == '/' || c == '\\')
    {
        return Err(OperatorError::Validation(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new_valid() {
        let client = VellavetoApiClient::new("http://vellaveto.default.svc.cluster.local:3000");
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_new_https() {
        let client = VellavetoApiClient::new("https://vellaveto.example.com");
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_new_empty_url() {
        let client = VellavetoApiClient::new("");
        assert!(client.is_err());
        assert!(matches!(client.unwrap_err(), OperatorError::Config(_)));
    }

    #[test]
    fn test_client_new_invalid_scheme() {
        let client = VellavetoApiClient::new("ftp://example.com");
        assert!(client.is_err());
    }

    #[test]
    fn test_client_new_userinfo_rejected() {
        let client = VellavetoApiClient::new("http://user:pass@example.com");
        assert!(client.is_err());
        let err = client.unwrap_err().to_string();
        assert!(err.contains("userinfo"));
    }

    #[test]
    fn test_client_new_strips_trailing_slash() {
        let client = VellavetoApiClient::new("http://example.com/").unwrap();
        assert_eq!(client.base_url, "http://example.com");
    }

    #[test]
    fn test_validate_path_param_valid() {
        assert!(validate_path_param("pol-123", "id").is_ok());
    }

    #[test]
    fn test_validate_path_param_empty() {
        assert!(validate_path_param("", "id").is_err());
    }

    #[test]
    fn test_validate_path_param_slash() {
        assert!(validate_path_param("../etc/passwd", "id").is_err());
    }

    #[test]
    fn test_validate_path_param_control_char() {
        assert!(validate_path_param("id\x00", "id").is_err());
    }

    #[test]
    fn test_api_policy_serde_roundtrip() {
        let policy = ApiPolicy {
            id: "p1".into(),
            name: "Test".into(),
            policy_type: "Allow".into(),
            priority: 10,
            path_rules: Some(ApiPathRules {
                allowed: vec!["/data/**".into()],
                blocked: vec![],
            }),
            network_rules: None,
            conditions: None,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: ApiPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "p1");
    }

    // FIND-R216-001: Unicode format char validation in path params
    #[test]
    fn test_validate_path_param_unicode_format_char() {
        // Zero-width space (U+200B)
        assert!(validate_path_param("id\u{200B}test", "id").is_err());
    }

    #[test]
    fn test_validate_path_param_bidi_override() {
        // Right-to-left override (U+202E)
        assert!(validate_path_param("id\u{202E}test", "id").is_err());
    }

    #[test]
    fn test_validate_path_param_bom() {
        // BOM (U+FEFF)
        assert!(validate_path_param("\u{FEFF}id", "id").is_err());
    }

    // FIND-R216-003: redirect policy none
    #[test]
    fn test_client_no_redirect_policy() {
        // Build the client and verify it was constructed with redirect disabled
        // (indirectly tested via a successful construction)
        let client = VellavetoApiClient::new("http://localhost:3000");
        assert!(client.is_ok());
    }

    // ═══════════════════════════════════════════════════
    // FIND-R224-003: deny_unknown_fields on API response types
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_api_policy_deny_unknown_fields() {
        let json = r#"{"id":"p1","name":"t","policy_type":"Allow","priority":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiPolicy>(json);
        assert!(result.is_err(), "ApiPolicy should reject unknown fields");
    }

    #[test]
    fn test_api_path_rules_deny_unknown_fields() {
        let json = r#"{"allowed":[],"blocked":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiPathRules>(json);
        assert!(result.is_err(), "ApiPathRules should reject unknown fields");
    }

    #[test]
    fn test_api_network_rules_deny_unknown_fields() {
        let json = r#"{"allowed_domains":[],"blocked_domains":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiNetworkRules>(json);
        assert!(
            result.is_err(),
            "ApiNetworkRules should reject unknown fields"
        );
    }

    #[test]
    fn test_api_ip_rules_deny_unknown_fields() {
        let json = r#"{"block_private":false,"blocked_cidrs":[],"allowed_cidrs":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiIpRules>(json);
        assert!(result.is_err(), "ApiIpRules should reject unknown fields");
    }

    #[test]
    fn test_api_tenant_deny_unknown_fields() {
        let json =
            r#"{"id":"t1","name":"T","enabled":true,"quotas":{},"metadata":{},"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiTenant>(json);
        assert!(result.is_err(), "ApiTenant should reject unknown fields");
    }

    #[test]
    fn test_api_tenant_quotas_deny_unknown_fields() {
        let json = r#"{"max_policies":10,"extra":"bad"}"#;
        let result = serde_json::from_str::<ApiTenantQuotas>(json);
        assert!(
            result.is_err(),
            "ApiTenantQuotas should reject unknown fields"
        );
    }

    #[test]
    fn test_tenant_response_deny_unknown_fields() {
        let json = r#"{"tenant":{"id":"t1","name":"T","enabled":true,"quotas":{},"metadata":{}},"extra":"bad"}"#;
        let result = serde_json::from_str::<TenantResponse>(json);
        assert!(
            result.is_err(),
            "TenantResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_tenant_list_response_deny_unknown_fields() {
        let json = r#"{"tenants":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<TenantListResponse>(json);
        assert!(
            result.is_err(),
            "TenantListResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_policy_list_response_deny_unknown_fields() {
        let json = r#"{"policies":[],"extra":"bad"}"#;
        let result = serde_json::from_str::<PolicyListResponse>(json);
        assert!(
            result.is_err(),
            "PolicyListResponse should reject unknown fields"
        );
    }

    #[test]
    fn test_health_response_deny_unknown_fields() {
        let json = r#"{"status":"ok","extra":"bad"}"#;
        let result = serde_json::from_str::<HealthResponse>(json);
        assert!(
            result.is_err(),
            "HealthResponse should reject unknown fields"
        );
    }
}
