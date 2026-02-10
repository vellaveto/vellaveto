//! Generic webhook exporter for AI observability.
//!
//! Sends security spans as JSON to any HTTP endpoint. Supports
//! optional gzip compression and custom headers.
//!
//! ## Feature Gate
//!
//! Requires `observability-exporters` feature.

use super::{
    ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan,
};
use async_trait::async_trait;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Webhook exporter configuration.
#[derive(Debug, Clone)]
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
    pub fn from_env(endpoint: impl Into<String>, auth_env: &str) -> Result<Self, ObservabilityError> {
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

impl WebhookExporter {
    /// Create a new webhook exporter.
    pub fn new(config: WebhookExporterConfig) -> Result<Self, ObservabilityError> {
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
                service: "sentinel".to_string(),
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
            encoder
                .write_all(&json)
                .map_err(|e| ObservabilityError::Serialization(format!("Compression failed: {}", e)))?;
            let compressed = encoder
                .finish()
                .map_err(|e| ObservabilityError::Serialization(format!("Compression failed: {}", e)))?;
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
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(60);
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
                service: "sentinel".to_string(),
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
struct WebhookRequest {
    spans: Vec<SecuritySpan>,
    metadata: WebhookMetadata,
}

#[derive(Debug, Serialize)]
struct WebhookMetadata {
    service: String,
    version: String,
    batch_size: usize,
    timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{ActionSummary, SpanKind, VerdictSummary};

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
                service: "sentinel".to_string(),
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
}
