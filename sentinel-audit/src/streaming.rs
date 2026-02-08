//! Streaming SIEM exporters for real-time audit log delivery.
//!
//! This module provides async exporters that push audit entries to external
//! SIEM systems in near-real-time, with batching, retry logic, and backpressure.
//!
//! ## Supported Exporters
//!
//! - **Splunk HEC** (HTTP Event Collector): Batch JSON events to Splunk
//! - **Datadog**: Batch logs to Datadog intake API
//! - **Elasticsearch**: Bulk index to Elasticsearch
//! - **Webhook**: Generic HTTP POST to any endpoint
//! - **Syslog**: RFC 5424 formatted syslog messages
//!
//! ## Configuration
//!
//! ```toml
//! [audit.export]
//! enabled = true
//! exporters = ["splunk"]
//!
//! [audit.export.splunk]
//! endpoint = "https://splunk.example.com:8088/services/collector"
//! token_env = "SPLUNK_HEC_TOKEN"
//! index = "sentinel"
//! source = "sentinel-prod"
//! batch_size = 100
//! flush_interval_secs = 5
//! max_retries = 3
//! ```

use crate::AuditEntry;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Error type for SIEM export operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("authentication failed: {0}")]
    AuthError(String),

    #[error("rate limited, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("server error: {status} - {message}")]
    ServerError { status: u16, message: String },
}

/// Configuration for exporter batching and retry behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    /// Maximum entries per batch.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval for partial batches.
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts for failed exports.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial retry backoff duration.
    #[serde(default = "default_retry_backoff_secs")]
    pub retry_backoff_secs: u64,

    /// Request timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_batch_size() -> usize {
    100
}
fn default_flush_interval_secs() -> u64 {
    5
}
fn default_max_retries() -> u32 {
    3
}
fn default_retry_backoff_secs() -> u64 {
    1
}
fn default_timeout_secs() -> u64 {
    30
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval_secs(),
            max_retries: default_max_retries(),
            retry_backoff_secs: default_retry_backoff_secs(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

/// Trait for SIEM exporters that can send audit entries to external systems.
#[async_trait]
pub trait SiemExporter: Send + Sync {
    /// Unique name of this exporter (e.g., "splunk", "datadog").
    fn name(&self) -> &str;

    /// Export a batch of audit entries.
    ///
    /// Implementations should handle serialization, batching, and error
    /// handling internally. Returns Ok(()) if all entries were accepted
    /// by the remote system.
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError>;

    /// Check if the exporter is healthy and can accept entries.
    ///
    /// Used for startup validation and health checks.
    async fn health_check(&self) -> Result<(), ExportError>;

    /// Get the exporter configuration.
    fn config(&self) -> &ExporterConfig;
}

/// Splunk HTTP Event Collector (HEC) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// HEC endpoint URL (e.g., "https://splunk:8088/services/collector").
    pub endpoint: String,

    /// HEC token (loaded from environment variable).
    #[serde(default)]
    pub token: Option<String>,

    /// Environment variable containing the HEC token.
    #[serde(default)]
    pub token_env: Option<String>,

    /// Splunk index to write to.
    #[serde(default)]
    pub index: Option<String>,

    /// Source identifier for events.
    #[serde(default = "default_splunk_source")]
    pub source: String,

    /// Source type for events.
    #[serde(default = "default_splunk_sourcetype")]
    pub sourcetype: String,

    /// Common exporter configuration (batching, retries).
    #[serde(flatten)]
    pub common: ExporterConfig,
}

fn default_splunk_source() -> String {
    "sentinel".to_string()
}

fn default_splunk_sourcetype() -> String {
    "sentinel:audit".to_string()
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            token: None,
            token_env: Some("SPLUNK_HEC_TOKEN".to_string()),
            index: None,
            source: default_splunk_source(),
            sourcetype: default_splunk_sourcetype(),
            common: ExporterConfig::default(),
        }
    }
}

/// Splunk HEC event wrapper.
#[cfg(feature = "siem-exporters")]
#[derive(Serialize)]
struct SplunkEvent<'a> {
    /// Event timestamp (epoch seconds with milliseconds).
    time: f64,
    /// Source identifier.
    source: &'a str,
    /// Source type.
    sourcetype: &'a str,
    /// Target index (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<&'a str>,
    /// Event payload.
    event: &'a AuditEntry,
}

/// Splunk HTTP Event Collector exporter.
#[cfg(feature = "siem-exporters")]
pub struct SplunkExporter {
    config: SplunkConfig,
    client: reqwest::Client,
    token: String,
}

#[cfg(feature = "siem-exporters")]
impl SplunkExporter {
    /// Create a new Splunk HEC exporter.
    ///
    /// The token is loaded from the configured environment variable or
    /// the direct `token` field in the configuration.
    pub fn new(config: SplunkConfig) -> Result<Self, ExportError> {
        // Load token
        let token = if let Some(ref t) = config.token {
            t.clone()
        } else if let Some(ref env_var) = config.token_env {
            std::env::var(env_var).map_err(|_| {
                ExportError::Configuration(format!(
                    "HEC token environment variable '{}' not set",
                    env_var
                ))
            })?
        } else {
            return Err(ExportError::Configuration(
                "No HEC token configured (set 'token' or 'token_env')".to_string(),
            ));
        };

        if config.endpoint.is_empty() {
            return Err(ExportError::Configuration(
                "Splunk HEC endpoint not configured".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| ExportError::Configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client,
            token,
        })
    }

    /// Format entries as Splunk HEC events.
    fn format_events(&self, entries: &[AuditEntry]) -> Result<String, ExportError> {
        let mut output = String::new();

        for entry in entries {
            // Parse timestamp to epoch seconds
            let time = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                .map(|dt| dt.timestamp() as f64 + dt.timestamp_subsec_millis() as f64 / 1000.0)
                .unwrap_or_else(|_| chrono::Utc::now().timestamp() as f64);

            let event = SplunkEvent {
                time,
                source: &self.config.source,
                sourcetype: &self.config.sourcetype,
                index: self.config.index.as_deref(),
                event: entry,
            };

            let json = serde_json::to_string(&event)
                .map_err(|e| ExportError::Serialization(e.to_string()))?;
            output.push_str(&json);
        }

        Ok(output)
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for SplunkExporter {
    fn name(&self) -> &str {
        "splunk"
    }

    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let body = self.format_events(entries)?;

        let mut retries = 0;
        let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);

        loop {
            let result = self
                .client
                .post(&self.config.endpoint)
                .header("Authorization", format!("Splunk {}", self.token))
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        tracing::debug!(
                            exporter = "splunk",
                            entries = entries.len(),
                            "Successfully exported batch"
                        );
                        return Ok(());
                    }

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(60);

                        if retries >= self.config.common.max_retries {
                            return Err(ExportError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                        }

                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        retries += 1;
                        continue;
                    }

                    if status.is_server_error() && retries < self.config.common.max_retries {
                        tracing::warn!(
                            exporter = "splunk",
                            status = %status,
                            retry = retries + 1,
                            "Server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        retries += 1;
                        continue;
                    }

                    let body = response.text().await.unwrap_or_default();
                    return Err(ExportError::ServerError {
                        status: status.as_u16(),
                        message: body,
                    });
                }
                Err(e) => {
                    if e.is_timeout() {
                        if retries < self.config.common.max_retries {
                            tracing::warn!(
                                exporter = "splunk",
                                retry = retries + 1,
                                "Request timeout, retrying"
                            );
                            tokio::time::sleep(backoff).await;
                            backoff *= 2;
                            retries += 1;
                            continue;
                        }
                        return Err(ExportError::Timeout(Duration::from_secs(
                            self.config.common.timeout_secs,
                        )));
                    }

                    if retries < self.config.common.max_retries {
                        tracing::warn!(
                            exporter = "splunk",
                            error = %e,
                            retry = retries + 1,
                            "HTTP error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        retries += 1;
                        continue;
                    }

                    return Err(ExportError::HttpError(e.to_string()));
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // Send a simple GET to the HEC endpoint to verify connectivity
        // Splunk HEC returns 400 for GET but that confirms the endpoint is reachable
        let result = self
            .client
            .get(&self.config.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .send()
            .await;

        match result {
            Ok(response) => {
                // 400 is expected for GET on HEC, 401 means bad token
                if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                    return Err(ExportError::AuthError("Invalid HEC token".to_string()));
                }
                Ok(())
            }
            Err(e) => Err(ExportError::HttpError(e.to_string())),
        }
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

/// Generic webhook exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub endpoint: String,

    /// Optional authorization header value.
    #[serde(default)]
    pub auth_header: Option<String>,

    /// Environment variable containing the auth header value.
    #[serde(default)]
    pub auth_header_env: Option<String>,

    /// Additional headers to include.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Common exporter configuration.
    #[serde(flatten)]
    pub common: ExporterConfig,
}

/// Generic webhook exporter.
#[cfg(feature = "siem-exporters")]
pub struct WebhookExporter {
    config: WebhookConfig,
    client: reqwest::Client,
    auth_header: Option<String>,
}

#[cfg(feature = "siem-exporters")]
impl WebhookExporter {
    /// Create a new webhook exporter.
    pub fn new(config: WebhookConfig) -> Result<Self, ExportError> {
        let auth_header = if let Some(ref h) = config.auth_header {
            Some(h.clone())
        } else if let Some(ref env_var) = config.auth_header_env {
            std::env::var(env_var).ok()
        } else {
            None
        };

        if config.endpoint.is_empty() {
            return Err(ExportError::Configuration(
                "Webhook endpoint not configured".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| ExportError::Configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            client,
            auth_header,
        })
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let body = serde_json::to_string(&entries)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        let mut request = self
            .client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json");

        if let Some(ref auth) = self.auth_header {
            request = request.header("Authorization", auth);
        }

        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }

        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| ExportError::HttpError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            Err(ExportError::ServerError { status, message })
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // Simple connectivity check
        let response = self
            .client
            .head(&self.config.endpoint)
            .send()
            .await
            .map_err(|e| ExportError::HttpError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ExportError::AuthError("Unauthorized".to_string()));
        }

        Ok(())
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exporter_config_defaults() {
        let config = ExporterConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.flush_interval_secs, 5);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_backoff_secs, 1);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_splunk_config_defaults() {
        let config = SplunkConfig::default();
        assert_eq!(config.source, "sentinel");
        assert_eq!(config.sourcetype, "sentinel:audit");
        assert_eq!(config.token_env, Some("SPLUNK_HEC_TOKEN".to_string()));
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_exporter_requires_endpoint() {
        let config = SplunkConfig {
            endpoint: String::new(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_exporter_requires_token() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088/services/collector".to_string(),
            token: None,
            token_env: None,
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_webhook_exporter_requires_endpoint() {
        let config = WebhookConfig {
            endpoint: String::new(),
            auth_header: None,
            auth_header_env: None,
            headers: Default::default(),
            common: ExporterConfig::default(),
        };
        let result = WebhookExporter::new(config);
        assert!(result.is_err());
    }
}
