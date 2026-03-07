// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Threat Intelligence integration for Vellaveto.
//!
//! Supports multiple threat intel providers:
//! - TAXII 2.x feeds (STIX format)
//! - MISP (Malware Information Sharing Platform)
//! - Custom REST API endpoints

use lru::LruCache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use vellaveto_config::{ThreatIntelConfig, ThreatIntelProvider};

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

/// Maximum response body size from threat intel providers (16 MB).
/// Prevents OOM from malicious or misconfigured provider responses.
const MAX_THREAT_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of STIX objects in a single TAXII response.
const MAX_STIX_OBJECTS: usize = 10_000;

/// Maximum length for an indicator value string.
const MAX_INDICATOR_VALUE_LEN: usize = 4_096;

/// Maximum number of MISP attributes in a single response.
const MAX_MISP_ATTRIBUTES: usize = 10_000;

/// Maximum tags per indicator (FIND-R58-SRV-008).
const MAX_INDICATOR_TAGS: usize = 50;

/// Maximum length per tag string.
const MAX_TAG_LEN: usize = 256;

/// Maximum length for source field.
const MAX_SOURCE_LEN: usize = 512;

/// Maximum length for description field.
const MAX_DESCRIPTION_LEN: usize = 4_096;

/// Maximum length for first_seen / last_seen timestamp fields.
const MAX_TIMESTAMP_LEN: usize = 64;

/// A threat indicator from intelligence feeds.
// SECURITY (R234-SRV-4): Reject unknown fields from external threat feeds
// to prevent attacker-injected fields from surviving deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl ThreatIndicator {
    /// Validate indicator bounds and content (FIND-R58-SRV-008, R242-SRV-2).
    pub fn validate(&self) -> Result<(), ThreatIntelError> {
        // SECURITY (R242-SRV-2): Validate value — flows into cache keys and log output.
        if self.value.len() > MAX_INDICATOR_VALUE_LEN {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "value too long ({} > {MAX_INDICATOR_VALUE_LEN} bytes)",
                self.value.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.value) {
            return Err(ThreatIntelError::InvalidResponse(
                "value contains control or format characters".to_string(),
            ));
        }
        // SECURITY (R242-SRV-2): Validate source — appears in audit logs.
        if self.source.len() > MAX_SOURCE_LEN {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "source too long ({} > {MAX_SOURCE_LEN} bytes)",
                self.source.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.source) {
            return Err(ThreatIntelError::InvalidResponse(
                "source contains control or format characters".to_string(),
            ));
        }
        // SECURITY (R242-SRV-2): Validate description — appears in threat reports.
        if let Some(ref desc) = self.description {
            if desc.len() > MAX_DESCRIPTION_LEN {
                return Err(ThreatIntelError::InvalidResponse(format!(
                    "description too long ({} > {MAX_DESCRIPTION_LEN} bytes)",
                    desc.len()
                )));
            }
            if vellaveto_types::has_dangerous_chars(desc) {
                return Err(ThreatIntelError::InvalidResponse(
                    "description contains control or format characters".to_string(),
                ));
            }
        }
        // Validate tags (count + length + content).
        if self.tags.len() > MAX_INDICATOR_TAGS {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "indicator has {} tags, max {}",
                self.tags.len(),
                MAX_INDICATOR_TAGS
            )));
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LEN {
                return Err(ThreatIntelError::InvalidResponse(format!(
                    "tag too long ({} > {} bytes)",
                    tag.len(),
                    MAX_TAG_LEN
                )));
            }
            // SECURITY (R242-SRV-2): Tags flow into audit metadata.
            if vellaveto_types::has_dangerous_chars(tag) {
                return Err(ThreatIntelError::InvalidResponse(
                    "tag contains control or format characters".to_string(),
                ));
            }
        }
        // SECURITY (R242-SRV-2): Validate timestamp fields — parsed and logged.
        for (name, ts_opt) in [
            ("first_seen", &self.first_seen),
            ("last_seen", &self.last_seen),
        ] {
            if let Some(ref ts) = ts_opt {
                if ts.len() > MAX_TIMESTAMP_LEN {
                    return Err(ThreatIntelError::InvalidResponse(format!(
                        "{name} too long ({} > {MAX_TIMESTAMP_LEN} bytes)",
                        ts.len()
                    )));
                }
                if vellaveto_types::has_dangerous_chars(ts) {
                    return Err(ThreatIntelError::InvalidResponse(format!(
                        "{name} contains control or format characters"
                    )));
                }
            }
        }
        Ok(())
    }
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

        // SECURITY (R234-SRV-3): Disable automatic redirect following to prevent
        // SSRF via redirect to internal/metadata endpoints (e.g., 169.254.169.254).
        // Callers should treat non-2xx status (including 3xx) as an error.
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

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
        // SECURITY (R235-SRV-4): Validate indicator value before processing.
        if value.len() > MAX_INDICATOR_VALUE_LEN {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "indicator value too long ({} > {MAX_INDICATOR_VALUE_LEN})",
                value.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(value) {
            return Err(ThreatIntelError::InvalidResponse(
                "indicator value contains control or format characters".to_string(),
            ));
        }
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

    /// Read response body with size bound, returning bytes.
    ///
    /// SECURITY (FIND-R58-SRV-THREAT-001): Checks Content-Length header first
    /// for early rejection, then enforces size on the actual body bytes.
    async fn read_bounded_response(
        response: reqwest::Response,
        provider_name: &str,
    ) -> Result<Vec<u8>, ThreatIntelError> {
        // Early rejection via Content-Length header
        if let Some(content_length) = response.content_length() {
            if content_length > MAX_THREAT_RESPONSE_BYTES as u64 {
                return Err(ThreatIntelError::InvalidResponse(format!(
                    "{provider_name} response Content-Length {content_length} exceeds limit {MAX_THREAT_RESPONSE_BYTES}"
                )));
            }
        }

        let body_bytes = response.bytes().await?;
        if body_bytes.len() > MAX_THREAT_RESPONSE_BYTES {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "{} response body {} bytes exceeds limit {}",
                provider_name,
                body_bytes.len(),
                MAX_THREAT_RESPONSE_BYTES
            )));
        }

        Ok(body_bytes.to_vec())
    }

    /// Query TAXII 2.x feed.
    async fn query_taxii(
        &self,
        endpoint: &str,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        // TAXII query format
        let url = format!("{endpoint}/objects");

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

        let body_bytes = Self::read_bounded_response(response, "TAXII").await?;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            ThreatIntelError::InvalidResponse(format!("TAXII response JSON decode failed: {e}"))
        })?;
        self.parse_stix_objects(&body)
    }

    /// Query MISP instance.
    async fn query_misp(
        &self,
        endpoint: &str,
        indicator_type: IndicatorType,
        value: &str,
    ) -> Result<Vec<ThreatIndicator>, ThreatIntelError> {
        let url = format!("{endpoint}/attributes/restSearch");

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

        let body_bytes = Self::read_bounded_response(response, "MISP").await?;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            ThreatIntelError::InvalidResponse(format!("MISP response JSON decode failed: {e}"))
        })?;
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

        let body_bytes = Self::read_bounded_response(response, "custom").await?;
        let indicators: Vec<ThreatIndicator> =
            serde_json::from_slice(&body_bytes).map_err(|e| {
                ThreatIntelError::InvalidResponse(format!(
                    "custom provider JSON decode failed: {e}"
                ))
            })?;
        // SECURITY (R235-SRV-5): Validate deserialized indicators to enforce
        // bounds on tags and detect malicious payloads from external feeds.
        for indicator in &indicators {
            indicator.validate()?;
        }
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

        if objects.len() > MAX_STIX_OBJECTS {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "TAXII response contains {} objects, max {}",
                objects.len(),
                MAX_STIX_OBJECTS
            )));
        }

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

        if attributes.len() > MAX_MISP_ATTRIBUTES {
            return Err(ThreatIntelError::InvalidResponse(format!(
                "MISP response contains {} attributes, max {}",
                attributes.len(),
                MAX_MISP_ATTRIBUTES
            )));
        }

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
        ThreatIntelError::InvalidResponse(format!("invalid custom provider endpoint: {e}"))
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
    fn test_parse_stix_objects_exceeds_max_objects() {
        let client = test_client();
        let objects: Vec<serde_json::Value> = (0..MAX_STIX_OBJECTS + 1)
            .map(|i| json!({"type": "indicator", "pattern": format!("pattern-{}", i)}))
            .collect();
        let result = client.parse_stix_objects(&json!({"objects": objects}));
        assert!(
            matches!(result, Err(ThreatIntelError::InvalidResponse(ref msg)) if msg.contains("max"))
        );
    }

    #[test]
    fn test_parse_misp_response_exceeds_max_attributes() {
        let client = test_client();
        let attributes: Vec<serde_json::Value> = (0..MAX_MISP_ATTRIBUTES + 1)
            .map(|i| json!({"value": format!("attr-{}", i)}))
            .collect();
        let result = client.parse_misp_response(&json!({
            "response": { "Attribute": attributes }
        }));
        assert!(
            matches!(result, Err(ThreatIntelError::InvalidResponse(ref msg)) if msg.contains("max"))
        );
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

    // ── indicator_type conversions ────────────────────────────────────

    #[test]
    fn test_indicator_type_to_stix_all_variants() {
        assert_eq!(indicator_type_to_stix(IndicatorType::Ip), "ipv4-addr");
        assert_eq!(indicator_type_to_stix(IndicatorType::Url), "url");
        assert_eq!(indicator_type_to_stix(IndicatorType::FileHash), "file");
        assert_eq!(indicator_type_to_stix(IndicatorType::Email), "email-addr");
        assert_eq!(indicator_type_to_stix(IndicatorType::ToolName), "tool");
        assert_eq!(indicator_type_to_stix(IndicatorType::Unknown), "indicator");
    }

    #[test]
    fn test_indicator_type_to_misp_all_variants() {
        assert_eq!(indicator_type_to_misp(IndicatorType::Ip), "ip-dst");
        assert_eq!(indicator_type_to_misp(IndicatorType::Url), "url");
        assert_eq!(indicator_type_to_misp(IndicatorType::FileHash), "md5");
        assert_eq!(indicator_type_to_misp(IndicatorType::Email), "email-src");
        assert_eq!(indicator_type_to_misp(IndicatorType::ToolName), "text");
        assert_eq!(indicator_type_to_misp(IndicatorType::Unknown), "text");
    }

    #[test]
    fn test_indicator_type_to_string_all_variants() {
        assert_eq!(indicator_type_to_string(IndicatorType::Ip), "ip");
        assert_eq!(indicator_type_to_string(IndicatorType::Url), "url");
        assert_eq!(indicator_type_to_string(IndicatorType::FileHash), "hash");
        assert_eq!(indicator_type_to_string(IndicatorType::Email), "email");
        assert_eq!(indicator_type_to_string(IndicatorType::ToolName), "tool");
        assert_eq!(indicator_type_to_string(IndicatorType::Unknown), "unknown");
    }

    // ── ThreatIndicator validation ────────────────────────────────────

    #[test]
    fn test_indicator_validate_valid_no_tags() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Domain,
            value: "evil.com".to_string(),
            confidence: 90,
            severity: Severity::High,
            source: "test".to_string(),
            description: None,
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_ok());
    }

    #[test]
    fn test_indicator_validate_max_tags_ok() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Ip,
            value: "1.2.3.4".to_string(),
            confidence: 50,
            severity: Severity::Medium,
            source: "test".to_string(),
            description: None,
            tags: (0..MAX_INDICATOR_TAGS)
                .map(|i| format!("tag-{i}"))
                .collect(),
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_ok());
    }

    #[test]
    fn test_indicator_validate_too_many_tags_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Ip,
            value: "1.2.3.4".to_string(),
            confidence: 50,
            severity: Severity::Medium,
            source: "test".to_string(),
            description: None,
            tags: (0..=MAX_INDICATOR_TAGS)
                .map(|i| format!("tag-{i}"))
                .collect(),
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_tag_too_long_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Url,
            value: "https://evil.com".to_string(),
            confidence: 80,
            severity: Severity::Critical,
            source: "test".to_string(),
            description: None,
            tags: vec!["x".repeat(MAX_TAG_LEN + 1)],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_tag_at_max_length_ok() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Url,
            value: "https://evil.com".to_string(),
            confidence: 80,
            severity: Severity::Critical,
            source: "test".to_string(),
            description: None,
            tags: vec!["x".repeat(MAX_TAG_LEN)],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_ok());
    }

    // ── R242-SRV-2: dangerous char validation on all string fields ───

    #[test]
    fn test_indicator_validate_value_dangerous_chars_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Domain,
            value: "evil\u{200B}.com".to_string(),
            confidence: 90,
            severity: Severity::High,
            source: "test".to_string(),
            description: None,
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_source_dangerous_chars_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Domain,
            value: "evil.com".to_string(),
            confidence: 90,
            severity: Severity::High,
            source: "feed\x00injected".to_string(),
            description: None,
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_description_dangerous_chars_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Ip,
            value: "1.2.3.4".to_string(),
            confidence: 50,
            severity: Severity::Medium,
            source: "test".to_string(),
            description: Some("malware\u{200B}description".to_string()),
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_tag_dangerous_chars_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Ip,
            value: "1.2.3.4".to_string(),
            confidence: 50,
            severity: Severity::Medium,
            source: "test".to_string(),
            description: None,
            tags: vec!["apt\x1bgroup".to_string()],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_first_seen_dangerous_chars_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Domain,
            value: "evil.com".to_string(),
            confidence: 80,
            severity: Severity::High,
            source: "test".to_string(),
            description: None,
            tags: vec![],
            first_seen: Some("2026-01-01\x00T00:00:00Z".to_string()),
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_source_too_long_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Domain,
            value: "evil.com".to_string(),
            confidence: 90,
            severity: Severity::High,
            source: "x".repeat(MAX_SOURCE_LEN + 1),
            description: None,
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    #[test]
    fn test_indicator_validate_description_too_long_rejected() {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::Ip,
            value: "1.2.3.4".to_string(),
            confidence: 50,
            severity: Severity::Medium,
            source: "test".to_string(),
            description: Some("d".repeat(MAX_DESCRIPTION_LEN + 1)),
            tags: vec![],
            first_seen: None,
            last_seen: None,
        };
        assert!(indicator.validate().is_err());
    }

    // ── Severity ordering ─────────────────────────────────────────────

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::High, Severity::High);
        assert_ne!(Severity::High, Severity::Low);
    }

    // ── ThreatAction ──────────────────────────────────────────────────

    #[test]
    fn test_threat_action_equality() {
        assert_eq!(ThreatAction::Deny, ThreatAction::Deny);
        assert_ne!(ThreatAction::Deny, ThreatAction::Allow);
        assert_ne!(ThreatAction::Alert, ThreatAction::RequireApproval);
    }

    // ── determine_action edge cases ───────────────────────────────────

    #[test]
    fn test_determine_action_require_approval() {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: Some("http://localhost".to_string()),
            on_match: "require_approval".to_string(),
            ..Default::default()
        };
        let client = ThreatIntelClient::new(&config).unwrap().unwrap();
        assert_eq!(client.determine_action(), ThreatAction::RequireApproval);
    }

    #[test]
    fn test_determine_action_unknown_defaults_to_deny() {
        let config = ThreatIntelConfig {
            enabled: true,
            endpoint: Some("http://localhost".to_string()),
            on_match: "unknown_action".to_string(),
            ..Default::default()
        };
        let client = ThreatIntelClient::new(&config).unwrap().unwrap();
        assert_eq!(client.determine_action(), ThreatAction::Deny);
    }

    // ── STIX parsing edge cases ───────────────────────────────────────

    #[test]
    fn test_parse_stix_objects_non_indicator_objects_skipped() {
        let client = test_client();
        let result = client
            .parse_stix_objects(&json!({
                "objects": [
                    {"type": "relationship", "id": "relationship--1"},
                    {"type": "indicator", "pattern": "[domain:value='evil.com']"}
                ]
            }))
            .expect("should parse valid indicators");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, "TAXII");
    }

    #[test]
    fn test_parse_stix_objects_default_confidence() {
        let client = test_client();
        let result = client
            .parse_stix_objects(&json!({
                "objects": [
                    {"type": "indicator", "pattern": "[ip:value='1.2.3.4']"}
                ]
            }))
            .expect("should parse");
        assert_eq!(result[0].confidence, 50); // default
    }

    #[test]
    fn test_parse_stix_objects_empty_objects_array() {
        let client = test_client();
        let result = client
            .parse_stix_objects(&json!({"objects": []}))
            .expect("empty array should be valid");
        assert!(result.is_empty());
    }

    // ── MISP parsing edge cases ───────────────────────────────────────

    #[test]
    fn test_parse_misp_response_valid_attributes() {
        let client = test_client();
        let result = client
            .parse_misp_response(&json!({
                "response": {
                    "Attribute": [
                        {"value": "evil.com", "comment": "malware domain"},
                        {"value": "1.2.3.4"}
                    ]
                }
            }))
            .expect("should parse valid attributes");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].value, "evil.com");
        assert_eq!(result[0].source, "MISP");
        assert_eq!(result[0].description, Some("malware domain".to_string()));
    }

    // ── build_custom_indicator_url path variants ──────────────────────

    #[test]
    fn test_build_custom_indicator_url_ip_type() {
        let url =
            build_custom_indicator_url("https://intel.example.com", IndicatorType::Ip, "10.0.0.1")
                .expect("valid URL");
        assert!(url.as_str().contains("/indicators/ip/10.0.0.1"));
    }

    #[test]
    fn test_build_custom_indicator_url_url_type() {
        let url = build_custom_indicator_url(
            "https://intel.example.com",
            IndicatorType::Url,
            "https://evil.com",
        )
        .expect("valid URL");
        assert!(url.as_str().contains("/indicators/url/"));
    }

    // ── ThreatIntelError display ──────────────────────────────────────

    #[test]
    fn test_threat_intel_error_display() {
        let err = ThreatIntelError::NotConfigured;
        assert!(err.to_string().contains("not configured"));

        let err = ThreatIntelError::UnsupportedProvider("custom-v2".to_string());
        assert!(err.to_string().contains("custom-v2"));

        let err = ThreatIntelError::InvalidResponse("bad json".to_string());
        assert!(err.to_string().contains("bad json"));
    }
}
