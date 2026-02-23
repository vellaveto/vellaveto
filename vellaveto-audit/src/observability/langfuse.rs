//! Langfuse AI observability platform exporter.
//!
//! Langfuse (<https://langfuse.com>) provides tracing, evaluation, and
//! observability for LLM applications.
//!
//! ## API Integration
//!
//! This exporter uses Langfuse's public REST API:
//! - `POST /api/public/ingestion` - Batch ingestion endpoint
//!
//! Authentication uses HTTP Basic Auth with `public_key:secret_key`.
//!
//! ## Trace Hierarchy
//!
//! Vellaveto spans map to Langfuse concepts:
//! - Root `SecuritySpan` (SpanKind::Chain) → Langfuse Trace
//! - Child spans → Langfuse Observations with type "span"
//!
//! ## Feature Gate
//!
//! Requires `observability-exporters` feature.

use super::{
    ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan, SpanKind,
};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Langfuse exporter configuration.
///
/// SECURITY (FIND-R157-005): Custom Debug redacts `secret_key` and `public_key`
/// to prevent credentials leaking into logs.
#[derive(Clone)]
pub struct LangfuseExporterConfig {
    /// Langfuse API endpoint.
    pub endpoint: String,
    /// Langfuse public key.
    pub public_key: String,
    /// Langfuse secret key.
    pub secret_key: String,
    /// Optional release/version tag.
    pub release: Option<String>,
    /// Custom metadata to add to all traces.
    pub metadata: HashMap<String, serde_json::Value>,
    /// Common exporter config.
    pub common: ObservabilityExporterConfig,
}

impl std::fmt::Debug for LangfuseExporterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LangfuseExporterConfig")
            .field("endpoint", &self.endpoint)
            .field("public_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("release", &self.release)
            .field("metadata", &self.metadata)
            .field("common", &self.common)
            .finish()
    }
}

impl LangfuseExporterConfig {
    /// Create a new Langfuse exporter configuration.
    pub fn new(
        endpoint: impl Into<String>,
        public_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            public_key: public_key.into(),
            secret_key: secret_key.into(),
            release: None,
            metadata: HashMap::new(),
            common: ObservabilityExporterConfig::default(),
        }
    }

    /// Load keys from environment variables.
    pub fn from_env(
        endpoint: impl Into<String>,
        public_key_env: &str,
        secret_key_env: &str,
    ) -> Result<Self, ObservabilityError> {
        let public_key = std::env::var(public_key_env).map_err(|_| {
            ObservabilityError::Configuration(format!(
                "Missing environment variable: {}",
                public_key_env
            ))
        })?;
        let secret_key = std::env::var(secret_key_env).map_err(|_| {
            ObservabilityError::Configuration(format!(
                "Missing environment variable: {}",
                secret_key_env
            ))
        })?;
        Ok(Self::new(endpoint, public_key, secret_key))
    }

    /// Set the release tag.
    pub fn with_release(mut self, release: impl Into<String>) -> Self {
        self.release = Some(release.into());
        self
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Langfuse observability exporter.
pub struct LangfuseExporter {
    config: LangfuseExporterConfig,
    client: reqwest::Client,
    auth_header: String,
}

impl LangfuseExporter {
    /// Create a new Langfuse exporter.
    pub fn new(config: LangfuseExporterConfig) -> Result<Self, ObservabilityError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ObservabilityError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        // Pre-compute Basic auth header
        let credentials = format!("{}:{}", config.public_key, config.secret_key);
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {}", encoded);

        Ok(Self {
            config,
            client,
            auth_header,
        })
    }

    /// Convert a SecuritySpan to Langfuse ingestion events.
    fn span_to_events(&self, span: &SecuritySpan) -> Vec<LangfuseEvent> {
        let mut events = Vec::new();

        // Determine if this is a root span (trace) or child span (observation)
        let is_root = span.parent_span_id.is_none() || span.span_kind == SpanKind::Chain;

        if is_root {
            // Create a trace for root spans
            let trace = LangfuseTrace {
                id: span.trace_id.clone(),
                timestamp: span.start_time.clone(),
                name: Some(span.name.clone()),
                user_id: span.action.agent_id.clone(),
                metadata: self.build_metadata(span),
                release: self.config.release.clone(),
                version: None,
                session_id: None,
                public: Some(false),
                tags: self.build_tags(span),
            };
            events.push(LangfuseEvent::TraceCreate {
                event_type: "trace-create".to_string(),
                body: Box::new(trace),
            });
        }

        // Create an observation for all spans
        let observation = LangfuseObservation {
            id: span.span_id.clone(),
            trace_id: span.trace_id.clone(),
            r#type: "SPAN".to_string(),
            name: span.name.clone(),
            start_time: span.start_time.clone(),
            end_time: Some(span.end_time.clone()),
            completion_start_time: None,
            model: None,
            model_parameters: None,
            input: span.request_body.clone(),
            output: span.response_body.clone(),
            usage: None,
            metadata: self.build_observation_metadata(span),
            level: self.verdict_to_level(span),
            status_message: span.verdict.reason.clone(),
            parent_observation_id: span.parent_span_id.clone(),
            version: None,
        };
        events.push(LangfuseEvent::ObservationCreate {
            event_type: "observation-create".to_string(),
            body: Box::new(observation),
        });

        events
    }

    /// Build metadata for a trace.
    fn build_metadata(&self, span: &SecuritySpan) -> Option<serde_json::Value> {
        let mut metadata = serde_json::Map::new();

        // Add custom metadata from config
        for (k, v) in &self.config.metadata {
            metadata.insert(k.clone(), v.clone());
        }

        // Add span-specific metadata
        metadata.insert("tool".into(), serde_json::json!(span.action.tool));
        metadata.insert("function".into(), serde_json::json!(span.action.function));
        metadata.insert("verdict".into(), serde_json::json!(span.verdict.outcome));
        metadata.insert(
            "span_kind".into(),
            serde_json::json!(span.span_kind.as_str()),
        );

        if let Some(policy) = &span.matched_policy {
            metadata.insert("matched_policy".into(), serde_json::json!(policy));
        }

        if !span.detections.is_empty() {
            let detections: Vec<_> = span
                .detections
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "type": format!("{:?}", d.detection_type),
                        "severity": d.severity,
                        "description": d.description
                    })
                })
                .collect();
            metadata.insert("security_detections".into(), serde_json::json!(detections));
        }

        // Add any custom attributes
        for (k, v) in &span.attributes {
            metadata.insert(k.clone(), v.clone());
        }

        if metadata.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(metadata))
        }
    }

    /// Build metadata for an observation.
    fn build_observation_metadata(&self, span: &SecuritySpan) -> Option<serde_json::Value> {
        let mut metadata = serde_json::Map::new();

        metadata.insert("duration_ms".into(), serde_json::json!(span.duration_ms));
        metadata.insert("verdict".into(), serde_json::json!(span.verdict.outcome));

        if let Some(reason) = &span.verdict.reason {
            metadata.insert("verdict_reason".into(), serde_json::json!(reason));
        }

        if let Some(policy) = &span.matched_policy {
            metadata.insert("matched_policy".into(), serde_json::json!(policy));
        }

        if !span.detections.is_empty() {
            metadata.insert(
                "detection_count".into(),
                serde_json::json!(span.detections.len()),
            );
            metadata.insert(
                "max_severity".into(),
                serde_json::json!(span.max_severity()),
            );
        }

        if !span.action.target_paths.is_empty() {
            metadata.insert(
                "target_paths".into(),
                serde_json::json!(span.action.target_paths),
            );
        }

        if !span.action.target_domains.is_empty() {
            metadata.insert(
                "target_domains".into(),
                serde_json::json!(span.action.target_domains),
            );
        }

        if metadata.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(metadata))
        }
    }

    /// Build tags for a trace.
    fn build_tags(&self, span: &SecuritySpan) -> Option<Vec<String>> {
        let mut tags = Vec::new();

        // Tag by verdict
        tags.push(format!("verdict:{}", span.verdict.outcome));

        // Tag by span kind
        tags.push(format!("kind:{}", span.span_kind.as_str()));

        // Tag if there are detections
        if span.has_detections() {
            tags.push("has_detections".to_string());
            if span.max_severity() >= 7 {
                tags.push("high_severity".to_string());
            }
        }

        // Tag if denied
        if span.is_denied() {
            tags.push("denied".to_string());
        }

        if tags.is_empty() {
            None
        } else {
            Some(tags)
        }
    }

    /// Map verdict to Langfuse observation level.
    fn verdict_to_level(&self, span: &SecuritySpan) -> Option<String> {
        match span.verdict.outcome.as_str() {
            "deny" => Some("ERROR".to_string()),
            "require_approval" => Some("WARNING".to_string()),
            "allow" => {
                if span.has_detections() && span.max_severity() >= 5 {
                    Some("WARNING".to_string())
                } else {
                    Some("DEFAULT".to_string())
                }
            }
            _ => Some("DEFAULT".to_string()),
        }
    }

    /// Send a batch of events to Langfuse.
    async fn send_batch(&self, events: Vec<LangfuseEvent>) -> Result<(), ObservabilityError> {
        let batch = LangfuseBatch {
            batch: events,
            metadata: None,
        };

        let url = format!(
            "{}/api/public/ingestion",
            self.config.endpoint.trim_end_matches('/')
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .json(&batch)
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            debug!("Langfuse batch sent successfully");
            Ok(())
        } else if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(ObservabilityError::AuthError(format!(
                "Authentication failed: {}",
                status
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
impl ObservabilityExporter for LangfuseExporter {
    fn name(&self) -> &str {
        "langfuse"
    }

    async fn export_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        if spans.is_empty() {
            return Ok(());
        }

        // Convert all spans to Langfuse events
        let events: Vec<LangfuseEvent> = spans
            .iter()
            .flat_map(|span| self.span_to_events(span))
            .collect();

        // Send in batches if needed
        let batch_size = self.config.common.batch_size;
        for chunk in events.chunks(batch_size) {
            let mut retries = 0;
            let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);

            loop {
                match self.send_batch(chunk.to_vec()).await {
                    Ok(()) => break,
                    Err(ObservabilityError::RateLimited { retry_after_secs }) => {
                        if retries >= self.config.common.max_retries {
                            return Err(ObservabilityError::RateLimited { retry_after_secs });
                        }
                        warn!(
                            "Langfuse rate limited, retrying in {} seconds (attempt {}/{})",
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
                            "Langfuse server error ({}), retrying in {:?} (attempt {}/{})",
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
                        error!("Langfuse export failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<(), ObservabilityError> {
        // Langfuse doesn't have a dedicated health endpoint, so we try
        // to create an empty batch to verify credentials
        let url = format!(
            "{}/api/public/ingestion",
            self.config.endpoint.trim_end_matches('/')
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .json(&LangfuseBatch {
                batch: vec![],
                metadata: None,
            })
            .send()
            .await
            .map_err(|e| ObservabilityError::HttpError(e.to_string()))?;

        let status = response.status();
        if status.is_success() || status.as_u16() == 400 {
            // 400 is expected for empty batch but means auth worked
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
// Langfuse API Types
// ============================================================================

/// Langfuse batch ingestion request.
#[derive(Debug, Serialize)]
struct LangfuseBatch {
    batch: Vec<LangfuseEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Langfuse event types.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum LangfuseEvent {
    TraceCreate {
        #[serde(rename = "type")]
        event_type: String,
        body: Box<LangfuseTrace>,
    },
    ObservationCreate {
        #[serde(rename = "type")]
        event_type: String,
        body: Box<LangfuseObservation>,
    },
}

/// Langfuse trace object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LangfuseTrace {
    id: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// Langfuse observation object.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LangfuseObservation {
    id: String,
    trace_id: String,
    r#type: String,
    name: String,
    start_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<LangfuseUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_observation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

/// Langfuse usage metrics (for LLM observations).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LangfuseUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_tokens: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{ActionSummary, VerdictSummary};

    fn test_config() -> LangfuseExporterConfig {
        LangfuseExporterConfig::new("https://cloud.langfuse.com", "pk-test-123", "sk-test-456")
    }

    #[test]
    fn test_config_creation() {
        let config = test_config();
        assert_eq!(config.endpoint, "https://cloud.langfuse.com");
        assert_eq!(config.public_key, "pk-test-123");
        assert_eq!(config.secret_key, "sk-test-456");
    }

    #[test]
    fn test_config_with_release() {
        let config = test_config().with_release("v1.2.3");
        assert_eq!(config.release, Some("v1.2.3".to_string()));
    }

    #[test]
    fn test_exporter_creation() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();
        assert_eq!(exporter.name(), "langfuse");
    }

    #[test]
    fn test_span_to_events_root() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Chain,
            name: "test_request".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("test_tool", "test_function"),
            verdict: VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            },
            matched_policy: Some("allow-all".to_string()),
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let events = exporter.span_to_events(&span);
        // Root span should create both a trace and an observation
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_span_to_events_child() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-2".to_string(),
            parent_span_id: Some("span-1".to_string()),
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Guardrail,
            name: "dlp_scan".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:00.100Z".to_string(),
            duration_ms: 100,
            action: ActionSummary::new("test_tool", "test_function"),
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("API key detected".to_string()),
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let events = exporter.span_to_events(&span);
        // Child span should only create an observation
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_verdict_to_level() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let mut span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Tool,
            name: "test".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("t", "f"),
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("blocked".to_string()),
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        assert_eq!(exporter.verdict_to_level(&span), Some("ERROR".to_string()));

        span.verdict.outcome = "require_approval".to_string();
        assert_eq!(
            exporter.verdict_to_level(&span),
            Some("WARNING".to_string())
        );

        span.verdict.outcome = "allow".to_string();
        assert_eq!(
            exporter.verdict_to_level(&span),
            Some("DEFAULT".to_string())
        );
    }

    #[test]
    fn test_build_tags() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Tool,
            name: "test".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("t", "f"),
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("blocked".to_string()),
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let tags = exporter.build_tags(&span).unwrap();
        assert!(tags.contains(&"verdict:deny".to_string()));
        assert!(tags.contains(&"kind:tool".to_string()));
        assert!(tags.contains(&"denied".to_string()));
    }

    // ========================================
    // Task 10: LangfuseExporter Edge Cases (GAP-014)
    // ========================================

    #[test]
    fn test_span_to_events_chain_with_parent() {
        // Edge case: span has both parent_span_id AND span_kind == Chain
        // The is_root logic is: parent_span_id.is_none() || span_kind == Chain
        // So Chain kind ALWAYS creates trace + observation (2 events) due to OR logic
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-child".to_string(),
            parent_span_id: Some("span-parent".to_string()),
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Chain, // Chain kind with parent
            name: "nested_chain".to_string(),
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
            attributes: HashMap::new(),
        };

        let events = exporter.span_to_events(&span);
        // Chain always treated as root due to: is_root = parent.is_none() || kind == Chain
        assert_eq!(
            events.len(),
            2,
            "Chain kind always creates trace + observation due to OR logic"
        );
    }

    #[test]
    fn test_span_to_events_zero_detections_denied() {
        // Edge case: span with deny verdict but zero detections
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Guardrail,
            name: "policy_deny".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("test_tool", "test_function"),
            verdict: VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("blocked by policy".to_string()),
            },
            matched_policy: Some("block-all".to_string()),
            detections: vec![], // Zero detections
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        let events = exporter.span_to_events(&span);
        // Should create 2 events (trace + observation) for root span
        assert_eq!(events.len(), 2);

        // Tags should not include detection tags since there are none
        let tags = exporter.build_tags(&span).unwrap();
        assert!(
            !tags.iter().any(|t| t.starts_with("detection:")),
            "no detection tags should exist for zero detections"
        );
    }

    #[test]
    fn test_span_to_events_count_verification() {
        // Verify exact event counts for different scenarios
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        // Scenario 1: Root Chain span -> 2 events (trace + observation)
        let root_chain = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Chain,
            name: "root".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("t", "f"),
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
        assert_eq!(
            exporter.span_to_events(&root_chain).len(),
            2,
            "root Chain span should create exactly 2 events"
        );

        // Scenario 2: Root Tool span -> 2 events (trace + observation)
        let root_tool = SecuritySpan {
            span_kind: SpanKind::Tool,
            ..root_chain.clone()
        };
        assert_eq!(
            exporter.span_to_events(&root_tool).len(),
            2,
            "root Tool span should create exactly 2 events"
        );

        // Scenario 3: Non-Chain child span with parent -> 1 event (observation only)
        let child = SecuritySpan {
            parent_span_id: Some("parent".to_string()),
            span_kind: SpanKind::Guardrail, // Not Chain, so parent takes effect
            ..root_chain.clone()
        };
        assert_eq!(
            exporter.span_to_events(&child).len(),
            1,
            "non-Chain child span should create exactly 1 event"
        );
    }

    #[test]
    fn test_verdict_to_level_unknown() {
        let config = test_config();
        let exporter = LangfuseExporter::new(config).unwrap();

        let span = SecuritySpan {
            span_id: "span-1".to_string(),
            parent_span_id: None,
            trace_id: "trace-1".to_string(),
            span_kind: SpanKind::Tool,
            name: "test".to_string(),
            start_time: "2024-01-01T00:00:00Z".to_string(),
            end_time: "2024-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            action: ActionSummary::new("t", "f"),
            verdict: VerdictSummary {
                outcome: "unknown".to_string(), // Non-standard outcome
                reason: None,
            },
            matched_policy: None,
            detections: vec![],
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        };

        // Unknown verdict should map to DEFAULT level (catch-all case)
        assert_eq!(
            exporter.verdict_to_level(&span),
            Some("DEFAULT".to_string()),
            "unknown verdict should map to DEFAULT"
        );
    }
}
