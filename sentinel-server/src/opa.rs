//! Open Policy Agent (OPA) integration for external policy evaluation.
//!
//! Provides async client for querying OPA for policy decisions,
//! with caching and fail-open/fail-closed modes.
//!
//! ## Security Warning
//!
//! The `fail_open` configuration option should be used with extreme caution.
//! When enabled, OPA unavailability results in ALLOW decisions, violating
//! the fail-closed security principle. See [`OpaClient::log_security_warnings`].

use lru::LruCache;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use sentinel_config::OpaConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Fallback cache size for OPA decisions if configured size is zero.
const FALLBACK_CACHE_SIZE: usize = 1000;

/// Errors that can occur during OPA evaluation.
#[derive(Debug, Error)]
pub enum OpaError {
    #[error("OPA request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("OPA returned invalid response: {0}")]
    InvalidResponse(String),

    #[error("OPA endpoint not configured")]
    NotConfigured,

    #[error("OPA evaluation timed out after {0}ms")]
    Timeout(u64),

    #[error("OPA decision path not found: {0}")]
    DecisionNotFound(String),
}

/// Cached OPA decision with TTL.
#[derive(Debug, Clone)]
struct CachedDecision {
    decision: OpaDecision,
    expires_at: Instant,
}

/// OPA policy decision result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaDecision {
    /// Whether the action is allowed.
    pub allow: bool,
    /// Optional reason for denial.
    #[serde(default)]
    pub reason: Option<String>,
    /// Additional metadata from OPA.
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Input sent to OPA for evaluation.
#[derive(Debug, Serialize)]
pub struct OpaInput {
    /// The tool being called.
    pub tool: String,
    /// The function/action being performed.
    pub function: String,
    /// Parameters of the action.
    pub parameters: serde_json::Value,
    /// Principal (user/agent) making the request.
    pub principal: Option<String>,
    /// Session ID.
    pub session_id: Option<String>,
    /// Additional context.
    #[serde(flatten)]
    pub context: serde_json::Value,
}

/// OPA response wrapper.
#[derive(Debug, Deserialize)]
struct OpaResponse {
    result: serde_json::Value,
}

/// OPA client for policy evaluation.
pub struct OpaClient {
    config: OpaConfig,
    client: Client,
    cache: Arc<RwLock<LruCache<String, CachedDecision>>>,
}

impl OpaClient {
    /// Create a new OPA client from configuration.
    pub fn new(config: &OpaConfig) -> Result<Option<Self>, OpaError> {
        if !config.enabled {
            return Ok(None);
        }

        if config.endpoint.is_none() {
            return Err(OpaError::NotConfigured);
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;

        // IMP-008: Use configurable cache size with fallback
        let configured_size = if config.cache_size > 0 {
            config.cache_size
        } else {
            FALLBACK_CACHE_SIZE
        };
        let cache_size = NonZeroUsize::new(configured_size).unwrap_or(NonZeroUsize::MIN);
        let cache = Arc::new(RwLock::new(LruCache::new(cache_size)));

        let opa_client = OpaClient {
            config: config.clone(),
            client,
            cache,
        };

        // SEC-001: Log security warnings for dangerous configurations
        opa_client.log_security_warnings();

        Ok(Some(opa_client))
    }

    /// Log security warnings for potentially dangerous configurations.
    ///
    /// # Security Warning (SEC-001)
    ///
    /// When `fail_open = true`, OPA unavailability causes policy decisions to
    /// default to ALLOW. This violates the fail-closed security principle and
    /// can be exploited by attackers who cause OPA service disruption.
    ///
    /// This method logs a warning at startup so operators are aware of the risk.
    pub fn log_security_warnings(&self) {
        if self.config.fail_open {
            tracing::warn!(
                target: "sentinel::security",
                "SECURITY WARNING: OPA fail_open=true is configured. \
                 Policy decisions will default to ALLOW when OPA is unreachable. \
                 This violates fail-closed security principles and may allow \
                 unauthorized actions during OPA outages. Consider using \
                 fail_open=false (the default) for production environments."
            );
        }
    }

    /// Evaluate a policy decision via OPA.
    pub async fn evaluate(&self, input: &OpaInput) -> Result<OpaDecision, OpaError> {
        let cache_key = self.cache_key(input);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.decision.clone());
                }
            }
        }

        // Query OPA
        let decision = self.query_opa(input).await?;

        // Update cache
        if self.config.cache_ttl_secs > 0 {
            let mut cache = self.cache.write().await;
            cache.put(
                cache_key,
                CachedDecision {
                    decision: decision.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                },
            );
        }

        Ok(decision)
    }

    /// Query OPA endpoint directly with retry logic (GAP-002).
    ///
    /// Implements exponential backoff for transient failures (connection errors,
    /// timeouts, 5xx responses). Retries are configurable via `max_retries` and
    /// `retry_backoff_ms` in OpaConfig.
    async fn query_opa(&self, input: &OpaInput) -> Result<OpaDecision, OpaError> {
        let endpoint = self
            .config
            .endpoint
            .as_ref()
            .ok_or(OpaError::NotConfigured)?;

        let url = self.build_query_url(endpoint);
        let body = serde_json::json!({ "input": input });
        let headers = self.build_request_headers();

        let mut last_error: Option<OpaError> = None;
        let mut backoff_ms = self.config.retry_backoff_ms;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tracing::debug!(
                    target: "sentinel::opa",
                    attempt = attempt,
                    backoff_ms = backoff_ms,
                    "Retrying OPA request after backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2); // Exponential backoff
            }

            let result = self
                .client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    // 5xx errors are retryable
                    if status.is_server_error() {
                        last_error = Some(OpaError::InvalidResponse(format!(
                            "OPA returned status {}",
                            status
                        )));
                        continue;
                    }

                    // 4xx errors are not retryable
                    if !status.is_success() {
                        return Err(OpaError::InvalidResponse(format!(
                            "OPA returned status {}",
                            status
                        )));
                    }

                    // Success - parse response
                    let opa_response: OpaResponse = response.json().await?;
                    return self.parse_decision(opa_response.result);
                }
                Err(e) => {
                    // Timeouts and connection errors are retryable
                    let error = if e.is_timeout() {
                        OpaError::Timeout(self.config.timeout_ms)
                    } else if e.is_connect() {
                        OpaError::Request(e)
                    } else {
                        // Other errors (e.g., invalid URL) are not retryable
                        return Err(OpaError::Request(e));
                    };
                    last_error = Some(error);
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or(OpaError::NotConfigured))
    }

    /// Build the OPA query URL from endpoint config.
    ///
    /// Supports both:
    /// - base endpoint (e.g. `http://opa:8181`) + decision path
    /// - full data endpoint (e.g. `http://opa:8181/v1/data/sentinel/allow`)
    fn build_query_url(&self, endpoint: &str) -> String {
        let endpoint = endpoint.trim_end_matches('/');
        if endpoint.contains("/v1/data/") || endpoint.ends_with("/v1/data") {
            endpoint.to_string()
        } else {
            let decision_path = self.config.decision_path.trim_start_matches('/');
            format!("{}/v1/data/{}", endpoint, decision_path)
        }
    }

    /// Build HTTP headers for OPA requests from config.
    ///
    /// Invalid header names/values are skipped with a warning.
    fn build_request_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in &self.config.headers {
            let parsed_name = match HeaderName::from_bytes(name.as_bytes()) {
                Ok(n) => n,
                Err(_) => {
                    tracing::warn!("Skipping invalid OPA header name: '{}'", name);
                    continue;
                }
            };
            let parsed_value = match HeaderValue::from_str(value) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("Skipping invalid OPA header value for '{}'", name);
                    continue;
                }
            };
            headers.insert(parsed_name, parsed_value);
        }
        headers
    }

    /// Parse OPA result into a decision.
    fn parse_decision(&self, result: serde_json::Value) -> Result<OpaDecision, OpaError> {
        // Handle both boolean results and structured results
        match result {
            serde_json::Value::Bool(allow) => Ok(OpaDecision {
                allow,
                reason: None,
                metadata: serde_json::Value::Null,
            }),
            serde_json::Value::Object(obj) => {
                let allow = obj.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
                let reason = obj.get("reason").and_then(|v| v.as_str()).map(String::from);
                Ok(OpaDecision {
                    allow,
                    reason,
                    metadata: serde_json::Value::Object(obj),
                })
            }
            serde_json::Value::Null => {
                // Decision path not found
                Err(OpaError::DecisionNotFound(
                    self.config.decision_path.clone(),
                ))
            }
            _ => Err(OpaError::InvalidResponse(
                "Unexpected result type from OPA".to_string(),
            )),
        }
    }

    /// Generate cache key for an input.
    ///
    /// Includes request parameters and context to prevent cross-request cache
    /// reuse where one allowed decision could be replayed for different inputs.
    fn cache_key(&self, input: &OpaInput) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.tool.as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.function.as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.principal.as_deref().unwrap_or("").as_bytes());
        hasher.update([0x1f]);
        hasher.update(input.session_id.as_deref().unwrap_or("").as_bytes());
        hasher.update([0x1f]);

        match serde_json::to_vec(&input.parameters) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b"<serde-json-error:parameters>"),
        }
        hasher.update([0x1f]);

        match serde_json::to_vec(&input.context) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b"<serde-json-error:context>"),
        }

        format!("{:x}", hasher.finalize())
    }

    /// Check if fail-open mode is enabled.
    pub fn fail_open(&self) -> bool {
        self.config.fail_open
    }

    /// Clear the decision cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opa_client_disabled() {
        let config = OpaConfig {
            enabled: false,
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap();
        assert!(client.is_none());
    }

    #[test]
    fn test_opa_client_no_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: None,
            ..Default::default()
        };
        let result = OpaClient::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_decision_bool() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let decision = client
            .parse_decision(serde_json::Value::Bool(true))
            .unwrap();
        assert!(decision.allow);
        assert!(decision.reason.is_none());
    }

    #[test]
    fn test_parse_decision_object() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let result = serde_json::json!({
            "allow": false,
            "reason": "Policy violation"
        });
        let decision = client.parse_decision(result).unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason, Some("Policy violation".to_string()));
    }

    #[test]
    fn test_parse_decision_null() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let result = client.parse_decision(serde_json::Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_key_is_stable_and_input_sensitive() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let input = OpaInput {
            tool: "filesystem".to_string(),
            function: "read".to_string(),
            parameters: serde_json::json!({"path": "/tmp/file.txt"}),
            principal: Some("user1".to_string()),
            session_id: Some("sess123".to_string()),
            context: serde_json::json!({"tenant": "acme"}),
        };
        let key1 = client.cache_key(&input);
        let key2 = client.cache_key(&input);
        assert_eq!(key1, key2, "cache key must be deterministic");

        let changed_params = OpaInput {
            parameters: serde_json::json!({"path": "/etc/shadow"}),
            ..input
        };
        let key3 = client.cache_key(&changed_params);
        assert_ne!(key1, key3, "cache key must change when parameters change");
    }

    #[test]
    fn test_build_request_headers_filters_invalid_entries() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-api-key".to_string(), "secret".to_string());
        headers.insert("bad header".to_string(), "value".to_string());
        headers.insert("x-bad-value".to_string(), "line\nbreak".to_string());

        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            headers,
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();

        let request_headers = client.build_request_headers();
        assert_eq!(
            request_headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok()),
            Some("secret")
        );
        assert!(request_headers.get("bad header").is_none());
        assert!(request_headers.get("x-bad-value").is_none());
    }

    #[test]
    fn test_build_query_url_with_base_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();
        assert_eq!(
            client.build_query_url("http://localhost:8181"),
            "http://localhost:8181/v1/data/sentinel/allow"
        );
    }

    #[test]
    fn test_build_query_url_with_full_data_endpoint() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://opa:8181/v1/data/sentinel/allow".to_string()),
            decision_path: "result.allow".to_string(),
            ..Default::default()
        };
        let client = OpaClient::new(&config).unwrap().unwrap();
        assert_eq!(
            client.build_query_url("http://opa:8181/v1/data/sentinel/allow"),
            "http://opa:8181/v1/data/sentinel/allow"
        );
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            ..Default::default()
        };

        // Verify default retry settings
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_backoff_ms, 50);
    }

    #[test]
    fn test_retry_config_custom() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            max_retries: 5,
            retry_backoff_ms: 100,
            ..Default::default()
        };

        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_backoff_ms, 100);
    }

    #[test]
    fn test_retry_disabled() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            max_retries: 0,
            ..Default::default()
        };

        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_cache_size_default() {
        let config = OpaConfig::default();
        assert_eq!(config.cache_size, 1000);
    }

    #[test]
    fn test_cache_size_custom() {
        let config = OpaConfig {
            enabled: true,
            endpoint: Some("http://localhost:8181".to_string()),
            decision_path: "sentinel/allow".to_string(),
            cache_size: 5000,
            ..Default::default()
        };

        assert_eq!(config.cache_size, 5000);
    }
}
