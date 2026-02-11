//! Threat Intelligence integration for Sentinel.
//!
//! Supports multiple threat intel providers:
//! - TAXII 2.x feeds (STIX format)
//! - MISP (Malware Information Sharing Platform)
//! - Custom REST API endpoints

use lru::LruCache;
use reqwest::Client;
use sentinel_config::{ThreatIntelConfig, ThreatIntelProvider};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors that can occur during threat intel operations.
#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("Threat intel request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Invalid threat intel response: {0}")]
    InvalidResponse(String),

    #[error("Threat intel not configured")]
    NotConfigured,

    #[error("Provider not supported: {0}")]
    UnsupportedProvider(String),
}

/// A threat indicator from intelligence feeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// Indicator type (domain, ip, url, hash, etc.)
    pub indicator_type: IndicatorType,
    /// The indicator value.
    pub value: String,
    /// Confidence score (0-100).
    pub confidence: u8,
    /// Severity level.
    pub severity: Severity,
    /// Source of the indicator.
    pub source: String,
    /// Description or context.
    pub description: Option<String>,
    /// Associated tags/labels.
    #[serde(default)]
    pub tags: Vec<String>,
    /// When the indicator was first seen.
    pub first_seen: Option<String>,
    /// When the indicator was last seen.
    pub last_seen: Option<String>,
}

/// Types of threat indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Domain,
    Ip,
    Url,
    FileHash,
    Email,
    ToolName,
    Unknown,
}

/// Severity levels for indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Result of checking against threat intelligence.
#[derive(Debug, Clone)]
pub struct ThreatCheckResult {
    /// Whether a match was found.
    pub matched: bool,
    /// Matching indicators (if any).
    pub indicators: Vec<ThreatIndicator>,
    /// Recommended action based on config.
    pub action: ThreatAction,
}

/// Action to take on threat match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatAction {
    /// Allow the request.
    Allow,
    /// Deny the request.
    Deny,
    /// Alert but allow.
    Alert,
    /// Require approval.
    RequireApproval,
}

/// Cached indicator set with TTL.
struct CachedIndicators {
    indicators: HashSet<String>,
    expires_at: Instant,
}

/// Threat intelligence client.
pub struct ThreatIntelClient {
    config: ThreatIntelConfig,
    client: Client,
    /// Cached indicators by type.
    cache: Arc<RwLock<LruCache<IndicatorType, CachedIndicators>>>,
    /// Full indicator details cache.
    details_cache: Arc<RwLock<LruCache<String, ThreatIndicator>>>,
}

impl ThreatIntelClient {
    /// Create a new threat intel client from configuration.
    pub fn new(config: &ThreatIntelConfig) -> Result<Option<Self>, ThreatIntelError> {
        if !config.enabled {
            return Ok(None);
        }

        if config.endpoint.is_none() {
            return Err(ThreatIntelError::NotConfigured);
        }

        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

        // Constants are guaranteed non-zero; keep this panic-free for strict runtimes.
        let cache_size = NonZeroUsize::new(100).unwrap_or(NonZeroUsize::MIN);
        let details_size = NonZeroUsize::new(10_000).unwrap_or(NonZeroUsize::MIN);

        Ok(Some(ThreatIntelClient {
            config: config.clone(),
            client,
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            details_cache: Arc::new(RwLock::new(LruCache::new(details_size))),
        }))
    }

    /// Check a domain against threat intelligence.
    pub async fn check_domain(&self, domain: &str) -> Result<ThreatCheckResult, ThreatIntelError> {
        self.check_indicator(IndicatorType::Domain, domain).await
    }

    /// Check an IP address against threat intelligence.
    pub async fn check_ip(&self, ip: &str) -> Result<ThreatCheckResult, ThreatIntelError> {
        self.check_indicator(IndicatorType::Ip, ip).await
    }

    /// Check a URL against threat intelligence.
    pub async fn check_url(&self, url: &str) -> Result<ThreatCheckResult, ThreatIntelError> {
        self.check_indicator(IndicatorType::Url, url).await
    }

    /// Check a tool name against threat intelligence.
    pub async fn check_tool(&self, tool: &str) -> Result<ThreatCheckResult, ThreatIntelError> {
        self.check_indicator(IndicatorType::ToolName, tool).await
    }

    /// Check an indicator against threat intelligence.
    async fn check_indicator(
        &self,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<ThreatCheckResult, ThreatIntelError> {
        let normalized = value.to_lowercase();

        // Check local cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.peek(&indicator_type) {
                if cached.expires_at > Instant::now() && cached.indicators.contains(&normalized) {
                    // Found in cache - get details
                    let details = self.details_cache.read().await;
                    let indicators: Vec<_> = details
                        .peek(&normalized)
                        .into_iter()
                        .filter(|i| i.confidence >= self.config.min_confidence)
                        .cloned()
                        .collect();

                    return Ok(ThreatCheckResult {
                        matched: !indicators.is_empty(),
                        indicators,
                        action: self.determine_action(),
                    });
                }
            }
        }

        // Query the provider
        let indicators = self.query_provider(indicator_type, &normalized).await?;

        // Filter by confidence
        let filtered: Vec<_> = indicators
            .into_iter()
            .filter(|i| i.confidence >= self.config.min_confidence)
            .collect();

        let matched = !filtered.is_empty();

        Ok(ThreatCheckResult {
            matched,
            indicators: filtered,
            action: if matched {
                self.determine_action()
            } else {
                ThreatAction::Allow
            },
        })
    }

    /// Query the configured threat intel provider.
    async fn query_provider(
        &self,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let endpoint = self
            .config
            .endpoint
            .as_ref()
            .ok_or(ThreatIntelError::NotConfigured)?;

        match self.config.provider {
            Some(ThreatIntelProvider::Taxii) => {
                self.query_taxii(endpoint, indicator_type, value).await
            }
            Some(ThreatIntelProvider::Misp) => {
                self.query_misp(endpoint, indicator_type, value).await
            }
            Some(ThreatIntelProvider::Custom) | None => {
                self.query_custom(endpoint, indicator_type, value).await
            }
        }
    }

    /// Query TAXII 2.x feed.
    async fn query_taxii(
        &self,
        endpoint: &str,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        // TAXII query format
        let url = format!("{}/objects", endpoint);

        let response = self
            .client
            .get(&url)
            .query(&[
                ("match[pattern]", value),
                ("match[type]", indicator_type_to_stix(indicator_type)),
            ])
            .header("Accept", "application/taxii+json;version=2.1")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "TAXII provider returned HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await?;
        self.parse_stix_objects(&body)
    }

    /// Query MISP instance.
    async fn query_misp(
        &self,
        endpoint: &str,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let url = format!("{}/attributes/restSearch", endpoint);

        let body = serde_json::json!({
            "returnFormat": "json",
            "value": value,
            "type": indicator_type_to_misp(indicator_type),
        });

        let response = self.client.post(&url).json(&body).send().await?;

        if !response.status().is_success() {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "MISP provider returned HTTP {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await?;
        self.parse_misp_response(&body)
    }

    /// Query custom REST endpoint.
    async fn query_custom(
        &self,
        endpoint: &str,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let url = build_custom_indicator_url(endpoint, indicator_type, value)?;

        let response = self.client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "custom provider returned HTTP {}",
                response.status()
            )));
        }

        let indicators: Vec<ThreatIndicator> = response.json().await.map_err(|e| {
            ThreatIntelError::InvalidResponse(format!("custom provider JSON decode failed: {}", e))
        })?;
        Ok(indicators)
    }

    /// Parse STIX objects into ThreatIndicators.
    fn parse_stix_objects(
        &self,
        body: &serde_json::Value,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let objects = body
            .get("objects")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ThreatIntelError::InvalidResponse(
                    "TAXII response missing required 'objects' array".to_string(),
                )
            })?;

        let mut indicators = Vec::new();
        let mut saw_invalid_indicator = false;

        for obj in objects {
            if obj.get("type").and_then(|v| v.as_str()) == Some("indicator") {
                let Some(pattern) = obj
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                else {
                    saw_invalid_indicator = true;
                    continue;
                };

                let confidence = obj
                    .get("confidence")
                    .and_then(|v| v.as_u64())
                    .map(|v| v.min(100) as u8)
                    .unwrap_or(50);

                indicators.push(ThreatIndicator {
                    indicator_type: IndicatorType::Unknown,
                    value: pattern.to_string(),
                    confidence,
                    severity: Severity::Medium,
                    source: "TAXII".to_string(),
                    description: obj
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    tags: Vec::new(),
                    first_seen: obj
                        .get("valid_from")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    last_seen: obj
                        .get("valid_until")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                });
            }
        }

        if indicators.is_empty() && saw_invalid_indicator {
            return Err(ThreatIntelError::InvalidResponse(
                "TAXII response contained indicator objects without valid 'pattern'".to_string(),
            ));
        }

        Ok(indicators)
    }

    /// Parse MISP response into ThreatIndicators.
    fn parse_misp_response(
        &self,
        body: &serde_json::Value,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let attributes = body
            .get("response")
            .and_then(|v| v.get("Attribute"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ThreatIntelError::InvalidResponse(
                    "MISP response missing required 'response.Attribute' array".to_string(),
                )
            })?;

        let mut indicators = Vec::new();
        let mut saw_invalid_attribute = false;

        for attr in attributes {
            let Some(value) = attr
                .get("value")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            else {
                saw_invalid_attribute = true;
                continue;
            };

            indicators.push(ThreatIndicator {
                indicator_type: IndicatorType::Unknown,
                value: value.to_string(),
                confidence: 70,
                severity: Severity::Medium,
                source: "MISP".to_string(),
                description: attr
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                tags: Vec::new(),
                first_seen: attr
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                last_seen: None,
            });
        }

        if indicators.is_empty() && saw_invalid_attribute && !attributes.is_empty() {
            return Err(ThreatIntelError::InvalidResponse(
                "MISP response contained attributes without valid 'value'".to_string(),
            ));
        }

        Ok(indicators)
    }

    /// Determine action based on configuration.
    fn determine_action(&self) -> ThreatAction {
        match self.config.on_match.as_str() {
            "deny" => ThreatAction::Deny,
            "alert" => ThreatAction::Alert,
            "require_approval" => ThreatAction::RequireApproval,
            _ => ThreatAction::Deny,
        }
    }

    /// Clear all caches.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        let mut details = self.details_cache.write().await;
        details.clear();
    }
}

fn indicator_type_to_stix(t: IndicatorType) -> &'static str {
    match t {
        IndicatorType::Domain => "domain-name",
        IndicatorType::Ip => "ipv4-addr",
        IndicatorType::Url => "url",
        IndicatorType::FileHash => "file",
        IndicatorType::Email => "email-addr",
        IndicatorType::ToolName => "tool",
        IndicatorType::Unknown => "indicator",
    }
}

fn indicator_type_to_misp(t: IndicatorType) -> &'static str {
    match t {
        IndicatorType::Domain => "domain",
        IndicatorType::Ip => "ip-dst",
        IndicatorType::Url => "url",
        IndicatorType::FileHash => "md5",
        IndicatorType::Email => "email-src",
        IndicatorType::ToolName => "text",
        IndicatorType::Unknown => "text",
    }
}

fn indicator_type_to_string(t: IndicatorType) -> &'static str {
    match t {
        IndicatorType::Domain => "domain",
        IndicatorType::Ip => "ip",
        IndicatorType::Url => "url",
        IndicatorType::FileHash => "hash",
        IndicatorType::Email => "email",
        IndicatorType::ToolName => "tool",
        IndicatorType::Unknown => "unknown",
    }
}

fn build_custom_indicator_url(
    endpoint: &str,
    indicator_type: IndicatorType,
    value: &str,
) -> Result<reqwest::Url, ThreatIntelError> {
    let mut url = reqwest::Url::parse(endpoint).map_err(|e| {
        ThreatIntelError::InvalidResponse(format!("invalid custom provider endpoint: {}", e))
    })?;

    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            ThreatIntelError::InvalidResponse(
                "custom provider endpoint cannot be used as a base URL".to_string(),
            )
        })?;
        segments.push("indicators");
        segments.push(indicator_type_to_string(indicator_type));
        segments.push(value);
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_client() -> ThreatIntelClient {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: Some("http://localhost".to_string()),
            ..Default::default()
        };
        ThreatIntelClient::new(&config)
            .expect("threat intel client should construct")
            .expect("threat intel must be enabled for tests")
    }

    #[test]
    fn test_threat_intel_disabled() {
        let config = ThreatIntelConfig {
            enabled: false,
            ..Default::default()
        };
        let client = ThreatIntelClient::new(&config).unwrap();
        assert!(client.is_none());
    }

    #[test]
    fn test_threat_intel_no_endpoint() {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: None,
            ..Default::default()
        };
        let result = ThreatIntelClient::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_action_deny() {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: Some("http://localhost".to_string()),
            on_match: "deny".to_string(),
            ..Default::default()
        };
        let client = ThreatIntelClient::new(&config).unwrap().unwrap();
        assert_eq!(client.determine_action(), ThreatAction::Deny);
    }

    #[test]
    fn test_determine_action_alert() {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: Some("http://localhost".to_string()),
            on_match: "alert".to_string(),
            ..Default::default()
        };
        let client = ThreatIntelClient::new(&config).unwrap().unwrap();
        assert_eq!(client.determine_action(), ThreatAction::Alert);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_indicator_type_conversion() {
        assert_eq!(indicator_type_to_stix(IndicatorType::Domain), "domain-name");
        assert_eq!(indicator_type_to_misp(IndicatorType::Domain), "domain");
        assert_eq!(indicator_type_to_string(IndicatorType::Domain), "domain");
    }

    #[test]
    fn test_parse_stix_objects_missing_objects_array_errors() {
        let client = test_client();
        let result = client.parse_stix_objects(&json!({"foo": "bar"}));
        assert!(matches!(result, Err(ThreatIntelError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_stix_objects_invalid_indicator_pattern_errors() {
        let client = test_client();
        let result = client.parse_stix_objects(&json!({
            "objects": [
                {"type": "indicator", "pattern": ""}
            ]
        }));
        assert!(matches!(result, Err(ThreatIntelError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_stix_objects_confidence_is_clamped() {
        let client = test_client();
        let indicators = client
            .parse_stix_objects(&json!({
                "objects": [
                    {"type": "indicator", "pattern": "[domain-name:value = 'evil.test']", "confidence": 255}
                ]
            }))
            .expect("valid STIX response should parse");
        assert_eq!(indicators.len(), 1);
        assert_eq!(indicators[0].confidence, 100);
    }

    #[test]
    fn test_parse_misp_response_missing_attribute_array_errors() {
        let client = test_client();
        let result = client.parse_misp_response(&json!({"response": {}}));
        assert!(matches!(result, Err(ThreatIntelError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_misp_response_invalid_attributes_error_when_non_empty() {
        let client = test_client();
        let result = client.parse_misp_response(&json!({
            "response": {
                "Attribute": [
                    {"value": ""},
                    {"comment": "missing value"}
                ]
            }
        }));
        assert!(matches!(result, Err(ThreatIntelError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_misp_response_empty_attribute_array_is_ok() {
        let client = test_client();
        let indicators = client
            .parse_misp_response(&json!({"response": {"Attribute": []}}))
            .expect("empty result should be valid");
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_build_custom_indicator_url_encodes_value_as_path_segment() {
        let url = build_custom_indicator_url(
            "https://intel.example.com/api",
            IndicatorType::Domain,
            "evil.test/a b",
        )
        .expect("valid endpoint should produce a URL");

        assert_eq!(
            url.as_str(),
            "https://intel.example.com/api/indicators/domain/evil.test%2Fa%20b"
        );
    }

    #[test]
    fn test_build_custom_indicator_url_rejects_invalid_endpoint() {
        let result = build_custom_indicator_url("not a url", IndicatorType::Ip, "1.2.3.4");
        assert!(matches!(result, Err(ThreatIntelError::InvalidResponse(_))));
    }
}
