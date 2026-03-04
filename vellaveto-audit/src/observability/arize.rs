// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Arize AI observability platform exporter.
//!
//! Arize (<https://arize.com>) provides ML observability with a focus on
//! embeddings, model performance, and drift detection.
//!
//! ## API Integration
//!
//! This exporter uses Arize's OTLP-compatible HTTP endpoint with
//! OpenInference semantic conventions for LLM tracing.
//!
//! ## Feature Gate
//!
//! Requires `observability-exporters` feature.

use super::{
    ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan, SpanKind,
};
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Arize exporter configuration.
///
/// SECURITY (FIND-R157-005): Custom Debug redacts `api_key` and `space_key`
/// to prevent credentials leaking into logs.
#[derive(Clone)]
pub struct ArizeExporterConfig {
    /// Arize OTLP endpoint.
    pub endpoint: String,
    /// Arize space key.
    pub space_key: String,
    /// Arize API key.
    pub api_key: String,
    /// Model ID for tracking.
    pub model_id: String,
    /// Model version.
    pub model_version: Option<String>,
    /// Common exporter config.
    pub common: ObservabilityExporterConfig,
}

impl std::fmt::Debug for ArizeExporterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArizeExporterConfig")
            .field("endpoint", &self.endpoint)
            .field("space_key", &"[REDACTED]")
            .field("api_key", &"[REDACTED]")
            .field("model_id", &self.model_id)
            .field("model_version", &self.model_version)
            .field("common", &self.common)
            .finish()
    }
}

impl ArizeExporterConfig {
    /// Create a new Arize exporter configuration.
    pub fn new(
        endpoint: impl Into<String>,
        space_key: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            space_key: space_key.into(),
            api_key: api_key.into(),
            model_id: "vellaveto-mcp-firewall".to_string(),
            model_version: None,
            common: ObservabilityExporterConfig::default(),
        }
    }

    /// Load keys from environment variables.
    pub fn from_env(
        endpoint: impl Into<String>,
        space_key_env: &str,
        api_key_env: &str,
    ) -> Result<Self, ObservabilityError> {
        let space_key = std::env::var(space_key_env).map_err(|_| {
            ObservabilityError::Configuration(format!(
                "Missing environment variable: {space_key_env}"
            ))
        })?;
        let api_key = std::env::var(api_key_env).map_err(|_| {
            ObservabilityError::Configuration(format!(
                "Missing environment variable: {api_key_env}"
            ))
        })?;
        Ok(Self::new(endpoint, space_key, api_key))
    }

    /// Set the model ID.
    pub fn with_model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = model_id.into();
        self
    }

    /// Set the model version.
    pub fn with_model_version(mut self, version: impl Into<String>) -> Self {
        self.model_version = Some(version.into());
        self
    }
}

/// Arize observability exporter using OTLP format.
pub struct ArizeExporter {
    config: ArizeExporterConfig,
    client: reqwest::Client,
}

impl ArizeExporter {
    /// Create a new Arize exporter.
    pub fn new(config: ArizeExporterConfig) -> Result<Self, ObservabilityError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ObservabilityError::Configuration(format!("Failed to create HTTP client: {e}"))
            })?;

        Ok(Self { config, client })
    }

    /// Convert a SecuritySpan to OTLP span format with OpenInference attributes.
    fn span_to_otlp(&self, span: &SecuritySpan) -> OtlpSpan {
        let mut attributes = vec![
            // OpenInference semantic conventions
            OtlpAttribute {
                key: "openinference.span.kind".to_string(),
                value: OtlpValue::String(self.span_kind_to_openinference(&span.span_kind)),
            },
            // Vellaveto-specific attributes
            OtlpAttribute {
                key: "vellaveto.tool".to_string(),
                value: OtlpValue::String(span.action.tool.clone()),
            },
            OtlpAttribute {
                key: "vellaveto.function".to_string(),
                value: OtlpValue::String(span.action.function.clone()),
            },
            OtlpAttribute {
                key: "vellaveto.verdict".to_string(),
                value: OtlpValue::String(span.verdict.outcome.clone()),
            },
            OtlpAttribute {
                key: "vellaveto.duration_ms".to_string(),
                value: OtlpValue::Int(span.duration_ms as i64),
            },
        ];

        if let Some(reason) = &span.verdict.reason {
            attributes.push(OtlpAttribute {
                key: "vellaveto.verdict_reason".to_string(),
                value: OtlpValue::String(reason.clone()),
            });
        }

        if let Some(policy) = &span.matched_policy {
            attributes.push(OtlpAttribute {
                key: "vellaveto.matched_policy".to_string(),
                value: OtlpValue::String(policy.clone()),
            });
        }

        // Model information
        attributes.push(OtlpAttribute {
            key: "model_id".to_string(),
            value: OtlpValue::String(self.config.model_id.clone()),
        });

        if let Some(version) = &self.config.model_version {
            attributes.push(OtlpAttribute {
                key: "model_version".to_string(),
                value: OtlpValue::String(version.clone()),
            });
        }

        // Detection information
        if !span.detections.is_empty() {
            attributes.push(OtlpAttribute {
                key: "vellaveto.detection_count".to_string(),
                value: OtlpValue::Int(span.detections.len() as i64),
            });
            attributes.push(OtlpAttribute {
                key: "vellaveto.max_severity".to_string(),
                value: OtlpValue::Int(span.max_severity() as i64),
            });
        }

        // Target information
        if !span.action.target_paths.is_empty() {
            attributes.push(OtlpAttribute {
                key: "vellaveto.target_paths".to_string(),
                value: OtlpValue::String(span.action.target_paths.join(",")),
            });
        }
        if !span.action.target_domains.is_empty() {
            attributes.push(OtlpAttribute {
                key: "vellaveto.target_domains".to_string(),
                value: OtlpValue::String(span.action.target_domains.join(",")),
            });
        }

        // Request/response as input/output
        if let Some(req) = &span.request_body {
            attributes.push(OtlpAttribute {
                key: "input.value".to_string(),
                value: OtlpValue::String(req.to_string()),
            });
        }
        if let Some(resp) = &span.response_body {
            attributes.push(OtlpAttribute {
                key: "output.value".to_string(),
                value: OtlpValue::String(resp.to_string()),
            });
        }

        // Custom attributes
        for (key, value) in &span.attributes {
            attributes.push(OtlpAttribute {
                key: format!("vellaveto.attr.{key}"),
                value: OtlpValue::String(value.to_string()),
            });
        }

        // Convert timestamps to nanoseconds (ISO 8601 to Unix nanos)
        let start_time_nanos = parse_iso8601_to_nanos(&span.start_time).unwrap_or(0);
        let end_time_nanos = parse_iso8601_to_nanos(&span.end_time).unwrap_or(start_time_nanos);

        OtlpSpan {
            trace_id: hex_to_bytes(&span.trace_id),
            span_id: hex_to_bytes(&span.span_id),
            parent_span_id: span.parent_span_id.as_ref().map(|s| hex_to_bytes(s)),
            name: span.name.clone(),
            kind: self.span_kind_to_otlp(&span.span_kind),
            start_time_unix_nano: start_time_nanos,
            end_time_unix_nano: end_time_nanos,
            attributes,
            status: Some(OtlpStatus {
                code: if span.is_denied() { 2 } else { 1 }, // 1=OK, 2=ERROR
                message: span.verdict.reason.clone(),
            }),
        }
    }

    /// Map SpanKind to OpenInference span kind.
    fn span_kind_to_openinference(&self, kind: &SpanKind) -> String {
        match kind {
            SpanKind::Chain => "CHAIN".to_string(),
            SpanKind::Tool => "TOOL".to_string(),
            SpanKind::Guardrail => "GUARDRAIL".to_string(),
            SpanKind::Llm => "LLM".to_string(),
            SpanKind::Policy => "TOOL".to_string(), // Map to TOOL for OpenInference
            SpanKind::Approval => "TOOL".to_string(),
            SpanKind::Gateway => "CHAIN".to_string(), // Gateway is a routing chain
        }
    }

    /// Map SpanKind to OTLP span kind code.
    fn span_kind_to_otlp(&self, kind: &SpanKind) -> i32 {
        match kind {
            SpanKind::Chain => 1, // INTERNAL
            SpanKind::Tool => 3,  // CLIENT
            SpanKind::Guardrail => 1,
            SpanKind::Llm => 3,
            SpanKind::Policy => 1,
            SpanKind::Approval => 1,
            SpanKind::Gateway => 1, // INTERNAL
        }
    }

    /// Send a batch of spans to Arize.
    async fn send_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        let otlp_spans: Vec<OtlpSpan> = spans.iter().map(|s| self.span_to_otlp(s)).collect();

        let request = OtlpExportRequest {
            resource_spans: vec![OtlpResourceSpans {
                resource: OtlpResource {
                    attributes: vec![
                        OtlpAttribute {
                            key: "service.name".to_string(),
                            value: OtlpValue::String("vellaveto".to_string()),
                        },
                        OtlpAttribute {
                            key: "service.version".to_string(),
                            value: OtlpValue::String(env!("CARGO_PKG_VERSION").to_string()),
                        },
                    ],
                },
                scope_spans: vec![OtlpScopeSpans {
                    scope: OtlpScope {
                        name: "vellaveto-audit".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                    spans: otlp_spans,
                }],
            }],
        };

        let url = format!("{}/v1/traces", self.config.endpoint.trim_end_matches('/'));

        let response = self
            .client
            .post(&url)
            .header("space_key", &self.config.space_key)
            .header("api_key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            debug!("Arize batch sent successfully");
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
impl ObservabilityExporter for ArizeExporter {
    fn name(&self) -> &str {
        "arize"
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
                            "Arize rate limited, retrying in {} seconds (attempt {}/{})",
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
                            "Arize server error ({}), retrying in {:?} (attempt {}/{})",
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
                        error!("Arize export failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<(), ObservabilityError> {
        // Send an empty batch to verify credentials
        let request = OtlpExportRequest {
            resource_spans: vec![],
        };

        let url = format!("{}/v1/traces", self.config.endpoint.trim_end_matches('/'));

        let response = self
            .client
            .post(&url)
            .header("space_key", &self.config.space_key)
            .header("api_key", &self.config.api_key)
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
// OTLP Types (simplified for JSON serialization)
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpExportRequest {
    resource_spans: Vec<OtlpResourceSpans>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpResourceSpans {
    resource: OtlpResource,
    scope_spans: Vec<OtlpScopeSpans>,
}

#[derive(Debug, Serialize)]
struct OtlpResource {
    attributes: Vec<OtlpAttribute>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpScopeSpans {
    scope: OtlpScope,
    spans: Vec<OtlpSpan>,
}

#[derive(Debug, Serialize)]
struct OtlpScope {
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OtlpSpan {
    #[serde(with = "base64_bytes")]
    trace_id: Vec<u8>,
    #[serde(with = "base64_bytes")]
    span_id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", with = "base64_bytes_opt")]
    parent_span_id: Option<Vec<u8>>,
    name: String,
    kind: i32,
    #[serde(serialize_with = "serialize_nanos")]
    start_time_unix_nano: u64,
    #[serde(serialize_with = "serialize_nanos")]
    end_time_unix_nano: u64,
    attributes: Vec<OtlpAttribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<OtlpStatus>,
}

#[derive(Debug, Serialize)]
struct OtlpAttribute {
    key: String,
    value: OtlpValue,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Variants kept for OTLP completeness
enum OtlpValue {
    String(String),
    Int(i64),
    Bool(bool),
    Double(f64),
}

#[derive(Debug, Serialize)]
struct OtlpStatus {
    code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

// Serialization helpers
mod base64_bytes {
    use base64::Engine;
    use serde::{self, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }
}

mod base64_bytes_opt {
    use base64::Engine;
    use serde::{self, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(b);
                serializer.serialize_str(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }
}

fn serialize_nanos<S>(nanos: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // OTLP expects nanoseconds as a string
    serializer.serialize_str(&nanos.to_string())
}

/// Parse ISO 8601 (RFC 3339) timestamp to Unix nanoseconds.
///
/// # Returns
///
/// - `Some(nanos)` for valid RFC 3339 timestamps
/// - `None` for invalid timestamps (empty strings, malformed dates, etc.)
///
/// # Fallback Behavior
///
/// When used in `span_to_otlp`, a `None` result defaults to `0` nanoseconds.
/// This ensures graceful handling of malformed span timestamps without panicking.
///
/// # Examples
///
/// ```ignore
/// // Valid timestamps
/// assert!(parse_iso8601_to_nanos("2024-01-01T00:00:00Z").is_some());
/// assert!(parse_iso8601_to_nanos("1970-01-01T00:00:00Z") == Some(0));
///
/// // Invalid timestamps return None
/// assert!(parse_iso8601_to_nanos("invalid").is_none());
/// assert!(parse_iso8601_to_nanos("").is_none());
/// ```
fn parse_iso8601_to_nanos(timestamp: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0) as u64)
}

/// Convert hex string to bytes for OTLP trace/span IDs.
///
/// # Behavior
///
/// - **Valid hex:** Decoded directly to bytes (e.g., `"abcd1234"` → `[0xab, 0xcd, 0x12, 0x34]`)
/// - **Invalid hex:** Hashed via SHA-256 to produce consistent 16-byte output
///
/// # Fallback Rationale
///
/// When Vellaveto receives non-standard trace IDs (e.g., UUIDs with hyphens,
/// arbitrary strings), this function produces a deterministic byte representation
/// using SHA-256 truncated to 16 bytes. This ensures:
/// - Consistent output for the same input (idempotent)
/// - Valid OTLP span/trace IDs that won't cause protocol errors
/// - No panics on malformed input
///
/// # Examples
///
/// ```ignore
/// // Valid hex
/// let bytes = hex_to_bytes("abcd1234");
/// assert_eq!(bytes.len(), 4);
///
/// // Invalid hex produces consistent hash
/// let bytes1 = hex_to_bytes("not-valid-hex");
/// let bytes2 = hex_to_bytes("not-valid-hex");
/// assert_eq!(bytes1, bytes2);
/// assert_eq!(bytes1.len(), 16);
/// ```
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap_or_else(|_| {
        // If hex decode fails, hash the input to get consistent bytes
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(hex.as_bytes());
        hash[..16].to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{ActionSummary, VerdictSummary};
    use std::collections::HashMap;

    fn test_config() -> ArizeExporterConfig {
        ArizeExporterConfig::new("https://otlp.arize.com/v1", "space-123", "key-456")
    }

    #[test]
    fn test_config_creation() {
        let config = test_config();
        assert_eq!(config.endpoint, "https://otlp.arize.com/v1");
        assert_eq!(config.space_key, "space-123");
        assert_eq!(config.api_key, "key-456");
    }

    #[test]
    fn test_exporter_creation() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();
        assert_eq!(exporter.name(), "arize");
    }

    #[test]
    fn test_span_to_otlp() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "abcd1234".to_string(),
            parent_span_id: None,
            trace_id: "trace12345678".to_string(),
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

        let otlp = exporter.span_to_otlp(&span);
        assert_eq!(otlp.name, "test_span");
        assert!(!otlp.attributes.is_empty());
    }

    #[test]
    fn test_span_kind_mapping() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();

        assert_eq!(
            exporter.span_kind_to_openinference(&SpanKind::Chain),
            "CHAIN"
        );
        assert_eq!(exporter.span_kind_to_openinference(&SpanKind::Tool), "TOOL");
        assert_eq!(
            exporter.span_kind_to_openinference(&SpanKind::Guardrail),
            "GUARDRAIL"
        );
        assert_eq!(exporter.span_kind_to_openinference(&SpanKind::Llm), "LLM");
    }

    #[test]
    fn test_hex_to_bytes() {
        let bytes = hex_to_bytes("0af7651916cd43dd");
        assert_eq!(bytes.len(), 8);

        // Invalid hex should produce consistent hash-based bytes
        let bytes2 = hex_to_bytes("invalid-hex");
        assert_eq!(bytes2.len(), 16);
    }

    // ========================================
    // Task 9: ArizeExporter Edge Cases (GAP-007, GAP-012)
    // ========================================

    #[test]
    fn test_parse_iso8601_to_nanos_valid() {
        let nanos = parse_iso8601_to_nanos("2024-01-01T00:00:00Z");
        assert!(nanos.is_some());
        assert!(nanos.unwrap() > 0);
    }

    #[test]
    fn test_parse_iso8601_to_nanos_invalid() {
        // Invalid timestamp should return None
        assert!(parse_iso8601_to_nanos("not-a-timestamp").is_none());
        assert!(parse_iso8601_to_nanos("").is_none());
        assert!(parse_iso8601_to_nanos("2024-13-45").is_none()); // Invalid date
    }

    #[test]
    fn test_parse_iso8601_to_nanos_epoch() {
        // Unix epoch
        let nanos = parse_iso8601_to_nanos("1970-01-01T00:00:00Z");
        assert!(nanos.is_some());
        assert_eq!(nanos.unwrap(), 0);
    }

    #[test]
    fn test_parse_iso8601_to_nanos_year_2038() {
        // Year 2038 (32-bit overflow boundary)
        let nanos = parse_iso8601_to_nanos("2038-01-19T03:14:07Z");
        assert!(nanos.is_some());
        // Should be close to max i32 in seconds (2147483647)
        let secs = nanos.unwrap() / 1_000_000_000;
        assert!(secs > 2_000_000_000);
    }

    #[test]
    fn test_parse_iso8601_to_nanos_far_future() {
        // Far future date
        let nanos = parse_iso8601_to_nanos("2099-12-31T23:59:59Z");
        assert!(nanos.is_some());
        assert!(nanos.unwrap() > 0);
    }

    #[test]
    fn test_hex_to_bytes_valid() {
        // Valid 16-char hex (span ID)
        let bytes = hex_to_bytes("b7ad6b7169203331");
        assert_eq!(bytes.len(), 8);

        // Valid 32-char hex (trace ID)
        let bytes = hex_to_bytes("0af7651916cd43dd8448eb211c80319c");
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_hex_to_bytes_invalid_consistent() {
        // Invalid hex should hash to consistent bytes
        let bytes1 = hex_to_bytes("invalid-hex-string");
        let bytes2 = hex_to_bytes("invalid-hex-string");

        assert_eq!(bytes1.len(), 16); // SHA256 truncated to 16 bytes
        assert_eq!(bytes1, bytes2, "same input should produce same hash");
    }

    #[test]
    fn test_hex_to_bytes_very_long() {
        // Very long trace ID should still work
        let long_hex = "a".repeat(100);
        let bytes = hex_to_bytes(&long_hex);
        assert_eq!(bytes.len(), 50); // Each pair of hex chars = 1 byte
    }

    #[test]
    fn test_span_to_otlp_all_fields() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert("custom_key".to_string(), serde_json::json!("custom_value"));

        let span = SecuritySpan {
            span_id: "abcd1234".to_string(),
            parent_span_id: Some("parent123".to_string()),
            trace_id: "trace12345678901234567890123456".to_string(),
            span_kind: SpanKind::Guardrail,
            name: "full_span".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary {
                tool: "test_tool".to_string(),
                function: "test_function".to_string(),
                parameter_count: 5,
                target_paths: vec!["/path/a".to_string(), "/path/b".to_string()],
                target_domains: vec!["example.com".to_string()],
                agent_id: Some("agent-1".to_string()),
            },
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("blocked by policy".to_string()),
            },
            matched_policy: Some("block-sensitive".to_string()),
            detections: vec![],
            request_body: Some(serde_json::json!({"request": "data"})),
            response_body: Some(serde_json::json!({"response": "data"})),
            attributes,
        };

        let otlp = exporter.span_to_otlp(&span);

        // Verify all fields mapped
        assert_eq!(otlp.name, "full_span");
        assert!(!otlp.trace_id.is_empty());
        assert!(!otlp.span_id.is_empty());
        assert!(otlp.parent_span_id.is_some());

        // Verify attributes contain expected fields
        let attr_map: HashMap<String, &OtlpAttribute> = otlp
            .attributes
            .iter()
            .map(|kv| (kv.key.clone(), kv))
            .collect();

        assert!(attr_map.contains_key("vellaveto.tool"));
        assert!(attr_map.contains_key("vellaveto.function"));
        assert!(attr_map.contains_key("vellaveto.verdict"));
        assert!(attr_map.contains_key("vellaveto.matched_policy"));
    }

    #[test]
    fn test_span_to_otlp_large_attributes() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();

        // Create span with 100+ attributes
        let mut attributes = HashMap::new();
        for i in 0..150 {
            attributes.insert(
                format!("key_{i}"),
                serde_json::json!(format!("value_{}", i)),
            );
        }

        let span = SecuritySpan {
            span_id: "abcd1234".to_string(),
            parent_span_id: None,
            trace_id: "trace12345678".to_string(),
            span_kind: SpanKind::Tool,
            name: "large_attrs".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("test_tool", "test_function"),
            verdict: VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes,
        };

        let otlp = exporter.span_to_otlp(&span);

        // Should not panic and should include custom attributes
        // Total attributes = 150 custom + ~10 standard vellaveto attrs
        assert!(
            otlp.attributes.len() >= 150,
            "should have at least 150 custom attributes, got {}",
            otlp.attributes.len()
        );
    }

    #[test]
    fn test_span_to_otlp_empty_paths_domains() {
        let config = test_config();
        let exporter = ArizeExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "abcd1234".to_string(),
            parent_span_id: None,
            trace_id: "trace12345678".to_string(),
            span_kind: SpanKind::Tool,
            name: "empty_targets".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary {
                tool: "test_tool".to_string(),
                function: "test_function".to_string(),
                parameter_count: 0,
                target_paths: vec![],   // Empty
                target_domains: vec![], // Empty
                agent_id: None,
            },
            verdict: VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let otlp = exporter.span_to_otlp(&span);

        // Should handle empty arrays gracefully
        let attr_map: HashMap<String, &OtlpAttribute> = otlp
            .attributes
            .iter()
            .map(|kv| (kv.key.clone(), kv))
            .collect();

        // Target paths/domains should still be present (empty string or not present)
        assert!(
            !attr_map.contains_key("vellaveto.target_paths")
                || matches!(&attr_map.get("vellaveto.target_paths").unwrap().value,
                OtlpValue::String(s) if s.is_empty())
        );
    }
}
