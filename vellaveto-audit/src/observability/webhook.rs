//! Generic webhook exporter for AI observability.
//!
//! Sends security spans as JSON to any HTTP endpoint. Supports
//! optional gzip compression and custom headers.
//!
//! ## Feature Gate
//!
//! Requires `observability-exporters` feature.

use super::{ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan};
use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Webhook exporter configuration.
///
/// SECURITY (FIND-R157-005): Custom Debug redacts `auth_header` to prevent
/// credentials leaking into logs.
#[derive(Clone)]
pub struct WebhookExporterConfig {
    /// Webhook endpoint URL.
    pub endpoint: String,
    /// Optional authorization header value.
    pub auth_header: Option<String>,
    /// Custom HTTP headers.
    pub headers: HashMap<String, String>,
    /// Enable gzip compression.
    pub compress: bool,
    /// Common exporter config.
    pub common: ObservabilityExporterConfig,
}

impl std::fmt::Debug for WebhookExporterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookExporterConfig")
            .field("endpoint", &self.endpoint)
            .field("auth_header", &"[REDACTED]")
            .field("headers", &self.headers)
            .field("compress", &self.compress)
            .field("common", &self.common)
            .finish()
    }
}

impl WebhookExporterConfig {
    /// Create a new webhook exporter configuration.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_header: None,
            headers: HashMap::new(),
            compress: true,
            common: ObservabilityExporterConfig::default(),
        }
    }

    /// Load auth header from environment variable.
    pub fn from_env(
        endpoint: impl Into<String>,
        auth_env: &str,
    ) -> Result<Self, ObservabilityError> {
        let auth_header = std::env::var(auth_env).ok();
        let mut config = Self::new(endpoint);
        config.auth_header = auth_header;
        Ok(config)
    }

    /// Set the authorization header.
    pub fn with_auth(mut self, auth: impl Into<String>) -> Self {
        self.auth_header = Some(auth.into());
        self
    }

    /// Add a custom header.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Enable or disable compression.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compress = enabled;
        self
    }
}

/// Generic webhook observability exporter.
pub struct WebhookExporter {
    config: WebhookExporterConfig,
    client: reqwest::Client,
}

impl std::fmt::Debug for WebhookExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookExporter")
            .field("endpoint", &self.config.endpoint)
            .finish_non_exhaustive()
    }
}

impl WebhookExporter {
    /// Create a new webhook exporter.
    ///
    /// SECURITY (GAP-S04): Validates that the endpoint URL uses http:// or https://
    /// scheme to prevent SSRF via exotic URL schemes (file://, ftp://, etc.).
    pub fn new(config: WebhookExporterConfig) -> Result<Self, ObservabilityError> {
        // SECURITY (GAP-S04): Validate URL scheme before creating the client.
        if !config.endpoint.starts_with("http://") && !config.endpoint.starts_with("https://") {
            return Err(ObservabilityError::Configuration(format!(
                "Webhook endpoint URL must use http:// or https:// scheme, got: {}",
                config.endpoint.split(':').next().unwrap_or("(empty)")
            )));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ObservabilityError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self { config, client })
    }

    /// Send a batch of spans to the webhook endpoint.
    async fn send_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        let request = WebhookRequest {
            spans: spans.to_vec(),
            metadata: WebhookMetadata {
                service: "vellaveto".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                batch_size: spans.len(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        };

        // Serialize to JSON
        let json = serde_json::to_vec(&request)
            .map_err(|e| ObservabilityError::Serialization(e.to_string()))?;

        // Optionally compress
        let (body, content_encoding) = if self.config.compress {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&json).map_err(|e| {
                ObservabilityError::Serialization(format!("Compression failed: {}", e))
            })?;
            let compressed = encoder.finish().map_err(|e| {
                ObservabilityError::Serialization(format!("Compression failed: {}", e))
            })?;
            (compressed, Some("gzip"))
        } else {
            (json, None)
        };

        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json");

        // Add authorization header if configured
        if let Some(auth) = &self.config.auth_header {
            builder = builder.header("Authorization", auth);
        }

        // Add content encoding header if compressed
        if let Some(encoding) = content_encoding {
            builder = builder.header("Content-Encoding", encoding);
        }

        // Add custom headers
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            debug!("Webhook batch sent successfully");
            Ok(())
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ObservabilityError::AuthError(format!(
                "Authentication failed: {}",
                status
            )))
        } else if status.as_u16() == 429 {
            // SECURITY (FIND-R46-004): Cap Retry-After at 300 seconds to prevent
            // an adversarial server from stalling the exporter indefinitely.
            const MAX_RETRY_AFTER_SECS: u64 = 300;
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60)
                .min(MAX_RETRY_AFTER_SECS);
            Err(ObservabilityError::RateLimited {
                retry_after_secs: retry_after,
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(ObservabilityError::ServerError {
                status: status.as_u16(),
                message: body,
            })
        }
    }
}

#[async_trait]
impl ObservabilityExporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn export_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        if spans.is_empty() {
            return Ok(());
        }

        let batch_size = self.config.common.batch_size;
        for chunk in spans.chunks(batch_size) {
            let mut retries = 0;
            let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);

            loop {
                match self.send_batch(chunk).await {
                    Ok(()) => break,
                    Err(ObservabilityError::RateLimited { retry_after_secs }) => {
                        if retries >= self.config.common.max_retries {
                            return Err(ObservabilityError::RateLimited { retry_after_secs });
                        }
                        warn!(
                            "Webhook rate limited, retrying in {} seconds (attempt {}/{})",
                            retry_after_secs,
                            retries + 1,
                            self.config.common.max_retries
                        );
                        tokio::time::sleep(Duration::from_secs(retry_after_secs)).await;
                        retries += 1;
                    }
                    Err(ObservabilityError::ServerError { status, message }) if status >= 500 => {
                        if retries >= self.config.common.max_retries {
                            return Err(ObservabilityError::ServerError { status, message });
                        }
                        warn!(
                            "Webhook server error ({}), retrying in {:?} (attempt {}/{})",
                            status,
                            backoff,
                            retries + 1,
                            self.config.common.max_retries
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        retries += 1;
                    }
                    Err(e) => {
                        error!("Webhook export failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<(), ObservabilityError> {
        // Send an empty request to verify connectivity
        let request = WebhookRequest {
            spans: vec![],
            metadata: WebhookMetadata {
                service: "vellaveto".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                batch_size: 0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        };

        let json = serde_json::to_vec(&request)
            .map_err(|e| ObservabilityError::Serialization(e.to_string()))?;

        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json");

        if let Some(auth) = &self.config.auth_header {
            builder = builder.header("Authorization", auth);
        }

        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        let response = builder
            .body(json)
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 400 {
            Ok(())
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ObservabilityError::AuthError(
                "Invalid credentials".to_string(),
            ))
        } else {
            Err(ObservabilityError::ServerError {
                status: status.as_u16(),
                message: response.text().await.unwrap_or_default(),
            })
        }
    }

    fn config(&self) -> &ObservabilityExporterConfig {
        &self.config.common
    }
}

// ============================================================================
// Webhook API Types
// ============================================================================

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct WebhookRequest {
    spans: Vec<SecuritySpan>,
    metadata: WebhookMetadata,
}

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize))]
struct WebhookMetadata {
    service: String,
    version: String,
    batch_size: usize,
    timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{
        ActionSummary, DetectionType, SecurityDetection, SpanKind, VerdictSummary,
    };

    fn test_config() -> WebhookExporterConfig {
        WebhookExporterConfig::new("https://example.com/webhook")
    }

    #[test]
    fn test_config_creation() {
        let config = test_config();
        assert_eq!(config.endpoint, "https://example.com/webhook");
        assert!(config.compress);
    }

    #[test]
    fn test_config_with_auth() {
        let config = test_config().with_auth("Bearer test-token");
        assert_eq!(config.auth_header, Some("Bearer test-token".to_string()));
    }

    #[test]
    fn test_config_with_header() {
        let config = test_config().with_header("X-Custom-Header", "custom-value");
        assert_eq!(
            config.headers.get("X-Custom-Header"),
            Some(&"custom-value".to_string())
        );
    }

    #[test]
    fn test_config_without_compression() {
        let config = test_config().with_compression(false);
        assert!(!config.compress);
    }

    #[test]
    fn test_exporter_creation() {
        let config = test_config();
        let exporter = WebhookExporter::new(config).unwrap();
        assert_eq!(exporter.name(), "webhook");
    }

    /// GAP-S04: Webhook exporter rejects non-HTTP URL schemes.
    #[test]
    fn test_gap_s04_rejects_non_http_scheme() {
        let config = WebhookExporterConfig::new("ftp://example.com/webhook");
        let result = WebhookExporter::new(config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("http://") || err.contains("https://"));
    }

    /// GAP-S04: Webhook exporter accepts http:// scheme.
    #[test]
    fn test_gap_s04_accepts_http_scheme() {
        let config = WebhookExporterConfig::new("http://example.com/webhook");
        assert!(WebhookExporter::new(config).is_ok());
    }

    #[test]
    fn test_compression() {
        // Verify that compression actually reduces size for repeated data
        let span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Tool,
            name: "test_span".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("test_tool", "test_function"),
            verdict: VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            },
            matched_policy: Some("test-policy".to_string()),
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        // Create multiple copies to make compression worthwhile
        let spans: Vec<SecuritySpan> = (0..10)
            .map(|i| {
                let mut s = span.clone();
                s.span_id = format!("span-{}", i);
                s
            })
            .collect();

        let request = WebhookRequest {
            spans,
            metadata: WebhookMetadata {
                service: "vellaveto".to_string(),
                version: "test".to_string(),
                batch_size: 10,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
        };

        let json = serde_json::to_vec(&request).unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&json).unwrap();
        let compressed = encoder.finish().unwrap();

        // Compressed should be smaller
        assert!(compressed.len() < json.len());
    }

    /// GAP-014: Comprehensive compression round-trip test
    /// Verifies that data survives compress → decompress cycle unchanged.
    #[test]
    fn test_compression_round_trip() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        // Create a complex span with various data types
        let mut attributes = HashMap::new();
        attributes.insert("user_id".to_string(), serde_json::json!("user-123"));
        attributes.insert("action_count".to_string(), serde_json::json!(42));
        attributes.insert(
            "nested".to_string(),
            serde_json::json!({
                "deep": {
                    "value": "test data with unicode: 日本語 emoji: 🔐"
                }
            }),
        );

        let span = SecuritySpan {
            span_id: "span-roundtrip".to_string(),
            parent_span_id: Some("parent-span".to_string()),
            trace_id: "trace-roundtrip".to_string(),
            span_kind: SpanKind::Chain,
            name: "roundtrip_test_span".to_string(),
            start_time: "2024-06-15T10:30:00Z".to_string(),
            end_time: "2024-06-15T10:30:05Z".to_string(),
            duration_ms: 5000,
            action: ActionSummary::new("security_tool", "validate"),
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("Policy violation detected".to_string()),
            },
            matched_policy: Some("critical-policy-001".to_string()),
            detections: vec![SecurityDetection {
                detection_type: DetectionType::Dlp,
                severity: 8,
                description: "Credit card pattern detected".to_string(),
                pattern: Some("credit_card".to_string()),
                metadata: HashMap::new(),
            }],
            request_body: Some(serde_json::json!({
                "payment_info": "4111-1111-1111-1111"
            })),
            response_body: None,
            attributes,
        };

        let request = WebhookRequest {
            spans: vec![span],
            metadata: WebhookMetadata {
                service: "vellaveto-test".to_string(),
                version: "2.0.0".to_string(),
                batch_size: 1,
                timestamp: "2024-06-15T10:30:05Z".to_string(),
            },
        };

        // Serialize to JSON
        let original_json = serde_json::to_vec(&request).unwrap();

        // Compress
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_json).unwrap();
        let compressed = encoder.finish().unwrap();

        // Decompress
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        // Verify round-trip integrity
        assert_eq!(
            original_json, decompressed,
            "Decompressed data should match original"
        );

        // Parse the decompressed JSON and verify structure
        let parsed: WebhookRequest = serde_json::from_slice(&decompressed).unwrap();
        assert_eq!(parsed.spans.len(), 1);
        assert_eq!(parsed.spans[0].span_id, "span-roundtrip");
        assert_eq!(parsed.spans[0].verdict.outcome, "deny");
        assert_eq!(parsed.spans[0].detections.len(), 1);
        assert_eq!(parsed.spans[0].detections[0].severity, 8);
        assert_eq!(
            parsed.spans[0].detections[0].detection_type,
            DetectionType::Dlp
        );
        assert_eq!(parsed.metadata.version, "2.0.0");
    }

    /// GAP-014: Test compression of empty batch (edge case)
    #[test]
    fn test_compression_empty_batch() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let request = WebhookRequest {
            spans: vec![],
            metadata: WebhookMetadata {
                service: "vellaveto".to_string(),
                version: "test".to_string(),
                batch_size: 0,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
        };

        let original_json = serde_json::to_vec(&request).unwrap();

        // Compress empty batch
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_json).unwrap();
        let compressed = encoder.finish().unwrap();

        // Decompress
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        // Verify round-trip
        assert_eq!(original_json, decompressed);

        let parsed: WebhookRequest = serde_json::from_slice(&decompressed).unwrap();
        assert!(parsed.spans.is_empty());
        assert_eq!(parsed.metadata.batch_size, 0);
    }

    /// GAP-014: Test compression with large payloads
    #[test]
    fn test_compression_large_payload() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        // Generate a large number of spans
        let spans: Vec<SecuritySpan> = (0..100)
            .map(|i| SecuritySpan {
                span_id: format!("span-{}", i),
                parent_span_id: if i > 0 {
                    Some(format!("span-{}", i - 1))
                } else {
                    None
                },
                trace_id: "trace-large".to_string(),
                span_kind: SpanKind::Tool,
                name: format!("operation_{}", i),
                start_time: "2024-01-01T00:00:00Z".to_string(),
                end_time: "2024-01-01T00:00:01Z".to_string(),
                duration_ms: 100 + i as u64,
                action: ActionSummary::new(format!("tool_{}", i % 10), format!("func_{}", i % 5)),
                verdict: VerdictSummary {
                    outcome: if i % 3 == 0 { "deny" } else { "allow" }.to_string(),
                    reason: if i % 3 == 0 {
                        Some(format!("Reason for span {}", i))
                    } else {
                        None
                    },
                },
                matched_policy: Some(format!("policy-{}", i % 5)),
                detections: vec![],
                request_body: Some(serde_json::json!({
                    "iteration": i,
                    "data": "x".repeat(100)  // Some repeated data for compression
                })),
                response_body: None,
                attributes: HashMap::new(),
            })
            .collect();

        let request = WebhookRequest {
            spans,
            metadata: WebhookMetadata {
                service: "vellaveto".to_string(),
                version: "test".to_string(),
                batch_size: 100,
                timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
        };

        let original_json = serde_json::to_vec(&request).unwrap();

        // Compress
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_json).unwrap();
        let compressed = encoder.finish().unwrap();

        // Compression should be effective for this repetitive data
        let compression_ratio = compressed.len() as f64 / original_json.len() as f64;
        assert!(
            compression_ratio < 0.5,
            "Compression ratio should be < 50% for repetitive data, got {:.1}%",
            compression_ratio * 100.0
        );

        // Decompress and verify
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        let parsed: WebhookRequest = serde_json::from_slice(&decompressed).unwrap();
        assert_eq!(parsed.spans.len(), 100);
        assert_eq!(parsed.spans[0].span_id, "span-0");
        assert_eq!(parsed.spans[99].span_id, "span-99");
    }
}
