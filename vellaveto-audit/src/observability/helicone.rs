// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Helicone AI observability platform exporter.
//!
//! Helicone (<https://helicone.ai>) provides LLM observability through
//! a simple logging API. This exporter sends security spans as log entries.
//!
//! ## Feature Gate
//!
//! Requires `observability-exporters` feature.

use super::{ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Helicone exporter configuration.
///
/// SECURITY (FIND-R157-005): Custom Debug redacts `api_key` to prevent
/// credentials leaking into logs.
#[derive(Clone)]
pub struct HeliconeExporterConfig {
    /// Helicone API endpoint.
    pub endpoint: String,
    /// Helicone API key.
    pub api_key: String,
    /// Custom properties to add to all logs.
    pub custom_properties: HashMap<String, String>,
    /// Common exporter config.
    pub common: ObservabilityExporterConfig,
}

impl std::fmt::Debug for HeliconeExporterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeliconeExporterConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("custom_properties", &self.custom_properties)
            .field("common", &self.common)
            .finish()
    }
}

impl HeliconeExporterConfig {
    /// Create a new Helicone exporter configuration.
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_key: api_key.into(),
            custom_properties: HashMap::new(),
            common: ObservabilityExporterConfig::default(),
        }
    }

    /// Load API key from environment variable.
    pub fn from_env(
        endpoint: impl Into<String>,
        api_key_env: &str,
    ) -> Result<Self, ObservabilityError> {
        let api_key = std::env::var(api_key_env).map_err(|_| {
            ObservabilityError::Configuration(format!(
                "Missing environment variable: {api_key_env}"
            ))
        })?;
        Ok(Self::new(endpoint, api_key))
    }

    /// Add a custom property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_properties.insert(key.into(), value.into());
        self
    }
}

/// Helicone observability exporter.
pub struct HeliconeExporter {
    config: HeliconeExporterConfig,
    client: reqwest::Client,
}

impl HeliconeExporter {
    /// Create a new Helicone exporter.
    pub fn new(config: HeliconeExporterConfig) -> Result<Self, ObservabilityError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ObservabilityError::Configuration(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { config, client })
    }

    /// Convert a SecuritySpan to a Helicone log entry.
    fn span_to_log(&self, span: &SecuritySpan) -> HeliconeLog {
        let mut properties = self.config.custom_properties.clone();

        // Add security-specific properties
        properties.insert("vellaveto_tool".to_string(), span.action.tool.clone());
        properties.insert(
            "vellaveto_function".to_string(),
            span.action.function.clone(),
        );
        properties.insert(
            "vellaveto_verdict".to_string(),
            span.verdict.outcome.clone(),
        );
        properties.insert(
            "vellaveto_span_kind".to_string(),
            span.span_kind.as_str().to_string(),
        );
        properties.insert(
            "vellaveto_duration_ms".to_string(),
            span.duration_ms.to_string(),
        );

        if let Some(reason) = &span.verdict.reason {
            properties.insert("vellaveto_verdict_reason".to_string(), reason.clone());
        }

        if let Some(policy) = &span.matched_policy {
            properties.insert("vellaveto_matched_policy".to_string(), policy.clone());
        }

        if !span.detections.is_empty() {
            properties.insert(
                "vellaveto_detection_count".to_string(),
                span.detections.len().to_string(),
            );
            properties.insert(
                "vellaveto_max_severity".to_string(),
                span.max_severity().to_string(),
            );
        }

        HeliconeLog {
            trace_id: span.trace_id.clone(),
            span_id: span.span_id.clone(),
            parent_span_id: span.parent_span_id.clone(),
            name: span.name.clone(),
            start_time: span.start_time.clone(),
            end_time: span.end_time.clone(),
            duration_ms: span.duration_ms,
            status: if span.is_denied() { "error" } else { "ok" }.to_string(),
            status_message: span.verdict.reason.clone(),
            input: span.request_body.clone(),
            output: span.response_body.clone(),
            properties,
        }
    }

    /// Send a batch of logs to Helicone.
    async fn send_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        let logs: Vec<HeliconeLog> = spans.iter().map(|s| self.span_to_log(s)).collect();

        let request = HeliconeRequest { logs };

        let response = self
            .client
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            debug!("Helicone batch sent successfully");
            Ok(())
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ObservabilityError::AuthError(format!(
                "Authentication failed: {status}"
            )))
        } else if status.as_u16() == 429 {
            // SECURITY (FIND-R71-P3-006): Cap Retry-After at 300 seconds to prevent
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
impl ObservabilityExporter for HeliconeExporter {
    fn name(&self) -> &str {
        "helicone"
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
                            "Helicone rate limited, retrying in {} seconds (attempt {}/{})",
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
                            "Helicone server error ({}), retrying in {:?} (attempt {}/{})",
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
                        error!("Helicone export failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<(), ObservabilityError> {
        // Send an empty request to verify credentials
        let request = HeliconeRequest { logs: vec![] };

        let response = self
            .client
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
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
// Helicone API Types
// ============================================================================

#[derive(Debug, Serialize)]
struct HeliconeRequest {
    logs: Vec<HeliconeLog>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HeliconeLog {
    trace_id: String,
    span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    name: String,
    start_time: String,
    end_time: String,
    duration_ms: u64,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    properties: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{ActionSummary, SpanKind, VerdictSummary};

    fn test_config() -> HeliconeExporterConfig {
        HeliconeExporterConfig::new("https://api.helicone.ai/v1/log", "test-key-123")
    }

    #[test]
    fn test_config_creation() {
        let config = test_config();
        assert_eq!(config.endpoint, "https://api.helicone.ai/v1/log");
        assert_eq!(config.api_key, "test-key-123");
    }

    #[test]
    fn test_config_with_property() {
        let config = test_config().with_property("env", "production");
        assert_eq!(
            config.custom_properties.get("env"),
            Some(&"production".to_string())
        );
    }

    #[test]
    fn test_exporter_creation() {
        let config = test_config();
        let exporter = HeliconeExporter::new(config).unwrap();
        assert_eq!(exporter.name(), "helicone");
    }

    #[test]
    fn test_span_to_log() {
        let config = test_config();
        let exporter = HeliconeExporter::new(config).unwrap();

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

        let log = exporter.span_to_log(&span);
        assert_eq!(log.trace_id, "trace-1");
        assert_eq!(log.span_id, "span-1");
        assert_eq!(log.name, "test_span");
        assert_eq!(log.status, "ok");
        assert!(log.properties.contains_key("vellaveto_tool"));
    }

    #[test]
    fn test_denied_span_status() {
        let config = test_config();
        let exporter = HeliconeExporter::new(config).unwrap();

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
                outcome: "deny".to_string(),
                reason: Some("blocked by policy".to_string()),
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let log = exporter.span_to_log(&span);
        assert_eq!(log.status, "error");
        assert_eq!(log.status_message, Some("blocked by policy".to_string()));
    }
}
