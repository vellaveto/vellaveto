//! AI Observability Platform Integration.
//!
//! This module provides exporters for AI observability platforms like Langfuse, Arize,
//! and Helicone. Unlike SIEM exporters (which work with `AuditEntry` logs), observability
//! exporters work with `SecuritySpan` traces that capture hierarchical timing and
//! correlation data.
//!
//! ## Architecture
//!
//! - **Non-blocking:** Data capture in-line, export via async background tasks
//! - **Sampling:** Configurable rate with always-sample-denies option
//! - **Trace correlation:** W3C Trace Context propagation
//!
//! ## Sampling Behavior
//!
//! The [`SpanSampler`] uses deterministic sampling based on trace ID hashing:
//! - Same `trace_id` always produces the same sampling decision
//! - Uses `DefaultHasher` for consistent hash distribution
//! - Hash is compared against `sample_rate * u64::MAX` threshold
//! - At 50% sample rate, expect ~50% of distinct trace IDs to be sampled (±5%)
//!
//! ## Feature Gate
//!
//! Enable with `observability-exporters` feature:
//! ```toml
//! sentinel-audit = { version = "2.0", features = ["observability-exporters"] }
//! ```

#[cfg(feature = "observability-exporters")]
pub mod arize;
#[cfg(feature = "observability-exporters")]
pub mod helicone;
#[cfg(feature = "observability-exporters")]
pub mod langfuse;
#[cfg(feature = "observability-exporters")]
pub mod webhook;

use async_trait::async_trait;
use sentinel_types::Verdict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, trace};

/// Error type for observability export operations.
#[derive(Debug, Error)]
pub enum ObservabilityError {
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

    #[error("timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("server error: {status} - {message}")]
    ServerError { status: u16, message: String },
}

/// Kind of security span in the trace hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    /// Top-level request chain (MCP request → response).
    Chain,
    /// Individual tool call evaluation.
    Tool,
    /// Security guardrail check (DLP, injection, etc.).
    Guardrail,
    /// LLM interaction (sampling request, semantic evaluation).
    Llm,
    /// Policy evaluation span.
    Policy,
    /// Approval workflow span.
    Approval,
}

impl SpanKind {
    /// Return the string representation for observability platforms.
    pub fn as_str(&self) -> &'static str {
        match self {
            SpanKind::Chain => "chain",
            SpanKind::Tool => "tool",
            SpanKind::Guardrail => "guardrail",
            SpanKind::Llm => "llm",
            SpanKind::Policy => "policy",
            SpanKind::Approval => "approval",
        }
    }
}

/// Type of security detection that occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    /// Data Loss Prevention finding.
    Dlp,
    /// Prompt injection detection.
    Injection,
    /// Rug-pull attack detection.
    RugPull,
    /// Tool squatting detection.
    Squatting,
    /// Behavioral anomaly.
    Anomaly,
    /// Semantic policy violation.
    Semantic,
    /// Memory poisoning attempt.
    MemoryPoisoning,
    /// Cross-request data flow.
    DataFlow,
    /// Unknown detection type.
    Other,
}

/// A security detection that occurred during span execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDetection {
    /// Type of detection.
    pub detection_type: DetectionType,
    /// Severity level (1-10, with 10 being most severe).
    pub severity: u8,
    /// Human-readable description.
    pub description: String,
    /// Pattern or rule that matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Additional metadata.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl SecurityDetection {
    /// Create a new security detection.
    pub fn new(
        detection_type: DetectionType,
        severity: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            detection_type,
            severity: severity.min(10),
            description: description.into(),
            pattern: None,
            metadata: HashMap::new(),
        }
    }

    /// Add a pattern to the detection.
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    /// Add metadata to the detection.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Summary of an action for observability (avoids full Action serialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    /// Tool name.
    pub tool: String,
    /// Function name.
    pub function: String,
    /// Target paths (sanitized/redacted as configured).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    /// Target domains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
    /// Parameter count (not values, for privacy).
    pub parameter_count: usize,
    /// Agent ID if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl ActionSummary {
    /// Create an action summary from a tool and function.
    pub fn new(tool: impl Into<String>, function: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            function: function.into(),
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            parameter_count: 0,
            agent_id: None,
        }
    }
}

impl From<&sentinel_types::Action> for ActionSummary {
    fn from(action: &sentinel_types::Action) -> Self {
        Self {
            tool: action.tool.clone(),
            function: action.function.clone(),
            target_paths: action.target_paths.clone(),
            target_domains: action.target_domains.clone(),
            parameter_count: action.parameters.as_object().map(|o| o.len()).unwrap_or(0),
            // `Action` no longer carries agent identity directly.
            // Keep this optional field for compatibility with existing span schema.
            agent_id: None,
        }
    }
}

/// A security span representing a traced operation.
///
/// Security spans capture timing, verdicts, and detections for observability
/// platforms. They form a hierarchical trace with parent-child relationships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySpan {
    /// Unique span identifier.
    pub span_id: String,
    /// Parent span ID (None for root spans).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Trace ID (shared across all spans in a request).
    pub trace_id: String,
    /// Kind of span.
    pub span_kind: SpanKind,
    /// Human-readable span name.
    pub name: String,
    /// Start time (ISO 8601).
    pub start_time: String,
    /// End time (ISO 8601).
    pub end_time: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Action summary (tool, function, targets).
    pub action: ActionSummary,
    /// Security verdict.
    pub verdict: VerdictSummary,
    /// Policy that matched (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_policy: Option<String>,
    /// Security detections that occurred.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detections: Vec<SecurityDetection>,
    /// Request body (if capture enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<serde_json::Value>,
    /// Response body (if capture enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<serde_json::Value>,
    /// Additional attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, serde_json::Value>,
}

/// Simplified verdict for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictSummary {
    /// Verdict outcome: "allow", "deny", or "require_approval".
    pub outcome: String,
    /// Reason (for deny/require_approval).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&Verdict> for VerdictSummary {
    fn from(verdict: &Verdict) -> Self {
        match verdict {
            Verdict::Allow => VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            },
            Verdict::Deny { reason } => VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some(reason.clone()),
            },
            Verdict::RequireApproval { reason, .. } => VerdictSummary {
                outcome: "require_approval".to_string(),
                reason: Some(reason.clone()),
            },
            _ => VerdictSummary {
                outcome: "unknown".to_string(),
                reason: None,
            },
        }
    }
}

impl SecuritySpan {
    /// Create a new security span builder.
    pub fn builder(trace_id: impl Into<String>, span_kind: SpanKind) -> SecuritySpanBuilder {
        SecuritySpanBuilder::new(trace_id, span_kind)
    }

    /// Check if this span has any security detections.
    pub fn has_detections(&self) -> bool {
        !self.detections.is_empty()
    }

    /// Check if the verdict was a denial.
    pub fn is_denied(&self) -> bool {
        self.verdict.outcome == "deny"
    }

    /// Get the highest severity detection.
    pub fn max_severity(&self) -> u8 {
        self.detections
            .iter()
            .map(|d| d.severity)
            .max()
            .unwrap_or(0)
    }
}

/// Builder for constructing `SecuritySpan` instances.
pub struct SecuritySpanBuilder {
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    span_kind: SpanKind,
    name: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    duration_ms: Option<u64>,
    action: Option<ActionSummary>,
    verdict: Option<VerdictSummary>,
    matched_policy: Option<String>,
    detections: Vec<SecurityDetection>,
    request_body: Option<serde_json::Value>,
    response_body: Option<serde_json::Value>,
    attributes: HashMap<String, serde_json::Value>,
}

impl SecuritySpanBuilder {
    /// Create a new builder with required fields.
    pub fn new(trace_id: impl Into<String>, span_kind: SpanKind) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: None,
            span_kind,
            name: None,
            start_time: None,
            end_time: None,
            duration_ms: None,
            action: None,
            verdict: None,
            matched_policy: None,
            detections: Vec::new(),
            request_body: None,
            response_body: None,
            attributes: HashMap::new(),
        }
    }

    /// Set the span ID.
    pub fn span_id(mut self, id: impl Into<String>) -> Self {
        self.span_id = id.into();
        self
    }

    /// Set the parent span ID.
    pub fn parent_span_id(mut self, id: impl Into<String>) -> Self {
        self.parent_span_id = Some(id.into());
        self
    }

    /// Set the span name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the start time.
    pub fn start_time(mut self, time: impl Into<String>) -> Self {
        self.start_time = Some(time.into());
        self
    }

    /// Set the end time.
    pub fn end_time(mut self, time: impl Into<String>) -> Self {
        self.end_time = Some(time.into());
        self
    }

    /// Set the duration in milliseconds.
    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Set the action summary.
    pub fn action(mut self, action: ActionSummary) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the action from a sentinel Action.
    pub fn action_from(mut self, action: &sentinel_types::Action) -> Self {
        self.action = Some(ActionSummary::from(action));
        self
    }

    /// Set the verdict summary.
    pub fn verdict(mut self, verdict: VerdictSummary) -> Self {
        self.verdict = Some(verdict);
        self
    }

    /// Set the verdict from a sentinel Verdict.
    pub fn verdict_from(mut self, verdict: &Verdict) -> Self {
        self.verdict = Some(VerdictSummary::from(verdict));
        self
    }

    /// Set the matched policy name.
    pub fn matched_policy(mut self, policy: impl Into<String>) -> Self {
        self.matched_policy = Some(policy.into());
        self
    }

    /// Add a security detection.
    pub fn detection(mut self, detection: SecurityDetection) -> Self {
        self.detections.push(detection);
        self
    }

    /// Add multiple security detections.
    pub fn detections(mut self, detections: Vec<SecurityDetection>) -> Self {
        self.detections.extend(detections);
        self
    }

    /// Set the request body.
    pub fn request_body(mut self, body: serde_json::Value) -> Self {
        self.request_body = Some(body);
        self
    }

    /// Set the response body.
    pub fn response_body(mut self, body: serde_json::Value) -> Self {
        self.response_body = Some(body);
        self
    }

    /// Add an attribute.
    pub fn attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Build the security span.
    ///
    /// Returns `None` if required fields are missing.
    pub fn build(self) -> Option<SecuritySpan> {
        let now = chrono::Utc::now().to_rfc3339();
        Some(SecuritySpan {
            span_id: self.span_id,
            parent_span_id: self.parent_span_id,
            trace_id: self.trace_id,
            span_kind: self.span_kind,
            name: self
                .name
                .unwrap_or_else(|| self.span_kind.as_str().to_string()),
            start_time: self.start_time.unwrap_or_else(|| now.clone()),
            end_time: self.end_time.unwrap_or(now),
            duration_ms: self.duration_ms.unwrap_or(0),
            action: self
                .action
                .unwrap_or_else(|| ActionSummary::new("unknown", "unknown")),
            verdict: self.verdict.unwrap_or(VerdictSummary {
                outcome: "unknown".to_string(),
                reason: None,
            }),
            matched_policy: self.matched_policy,
            detections: self.detections,
            request_body: self.request_body,
            response_body: self.response_body,
            attributes: self.attributes,
        })
    }
}

/// Configuration for observability exporter batching and retry behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityExporterConfig {
    /// Maximum spans per batch.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval for partial batches in seconds.
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts for failed exports.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial retry backoff duration in seconds.
    #[serde(default = "default_retry_backoff_secs")]
    pub retry_backoff_secs: u64,

    /// Request timeout in seconds.
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

impl Default for ObservabilityExporterConfig {
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

/// Trait for observability platform exporters.
///
/// Unlike `SiemExporter` which works with `AuditEntry` logs, this trait
/// works with `SecuritySpan` traces for AI observability platforms.
#[async_trait]
pub trait ObservabilityExporter: Send + Sync {
    /// Unique name of this exporter (e.g., "langfuse", "arize").
    fn name(&self) -> &str;

    /// Export a batch of security spans.
    ///
    /// Implementations should handle serialization, batching, and error
    /// handling internally.
    async fn export_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError>;

    /// Check if the exporter is healthy and can accept spans.
    ///
    /// Used for startup validation and health checks.
    async fn health_check(&self) -> Result<(), ObservabilityError>;

    /// Get the exporter configuration.
    fn config(&self) -> &ObservabilityExporterConfig;
}

/// Sampling configuration for observability spans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sample rate (0.0 to 1.0). 1.0 = sample everything.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Always sample denied requests regardless of sample rate.
    #[serde(default = "default_true")]
    pub always_sample_denies: bool,

    /// Always sample requests with security detections.
    #[serde(default = "default_true")]
    pub always_sample_detections: bool,

    /// Minimum severity to force sampling.
    #[serde(default = "default_min_severity")]
    pub min_severity_to_sample: u8,
}

fn default_sample_rate() -> f64 {
    1.0
}
fn default_true() -> bool {
    true
}
fn default_min_severity() -> u8 {
    7
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            sample_rate: default_sample_rate(),
            always_sample_denies: true,
            always_sample_detections: true,
            min_severity_to_sample: default_min_severity(),
        }
    }
}

/// Sampler that decides whether to export a span based on configuration.
#[derive(Debug, Clone)]
pub struct SpanSampler {
    config: SamplingConfig,
}

impl SpanSampler {
    /// Create a new sampler with the given configuration.
    pub fn new(config: SamplingConfig) -> Self {
        Self { config }
    }

    /// Decide whether to sample a span.
    ///
    /// Returns `true` if the span should be exported.
    ///
    /// # Sampling Algorithm
    ///
    /// 1. Force-sample denied requests if `always_sample_denies` is enabled
    /// 2. Force-sample high-severity detections if `always_sample_detections` is enabled
    /// 3. Apply probabilistic sampling using trace_id hash for determinism
    ///
    /// The probabilistic sampling ensures all spans from the same trace are
    /// sampled together (or not), providing complete trace visibility.
    pub fn should_sample(&self, span: &SecuritySpan) -> bool {
        // Always sample denies if configured
        if self.config.always_sample_denies && span.is_denied() {
            debug!(
                trace_id = %span.trace_id,
                verdict = "deny",
                "force-sampling denied span"
            );
            return true;
        }

        // Always sample high-severity detections if configured
        if self.config.always_sample_detections
            && span.has_detections()
            && span.max_severity() >= self.config.min_severity_to_sample
        {
            debug!(
                trace_id = %span.trace_id,
                detection_count = span.detections.len(),
                max_severity = span.max_severity(),
                "force-sampling span with high-severity detections"
            );
            return true;
        }

        // Apply probabilistic sampling
        if self.config.sample_rate >= 1.0 {
            trace!(trace_id = %span.trace_id, "sample_rate=1.0, sampling all");
            return true;
        }
        if self.config.sample_rate <= 0.0 {
            trace!(trace_id = %span.trace_id, "sample_rate=0.0, sampling none");
            return false;
        }

        // Use trace_id for deterministic sampling across spans in same trace
        let hash = Self::hash_trace_id(&span.trace_id);
        let threshold = (self.config.sample_rate * u64::MAX as f64) as u64;
        let sampled = hash < threshold;

        trace!(
            trace_id = %span.trace_id,
            hash = hash,
            threshold = threshold,
            sample_rate = self.config.sample_rate,
            sampled = sampled,
            "probabilistic sampling decision"
        );

        sampled
    }

    /// Hash a trace ID for deterministic sampling.
    fn hash_trace_id(trace_id: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        trace_id.hash(&mut hasher);
        hasher.finish()
    }
}

/// W3C Trace Context header names.
pub mod trace_context {
    /// The traceparent header name.
    pub const TRACEPARENT: &str = "traceparent";
    /// The tracestate header name.
    pub const TRACESTATE: &str = "tracestate";
}

/// Parsed W3C Trace Context from incoming request headers.
#[derive(Debug, Clone, Default)]
pub struct TraceContext {
    /// Trace ID (32 hex chars).
    pub trace_id: Option<String>,
    /// Parent span ID (16 hex chars).
    pub parent_span_id: Option<String>,
    /// Trace flags (sampled, etc.).
    pub trace_flags: u8,
    /// Vendor-specific trace state.
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// Parse W3C traceparent header.
    ///
    /// Format: `version-trace_id-parent_id-flags`
    /// Example: `00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01`
    pub fn parse_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            // We only support version 00
            return None;
        }

        let trace_id = parts[1];
        if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let parent_span_id = parts[2];
        if parent_span_id.len() != 16 || !parent_span_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(TraceContext {
            trace_id: Some(trace_id.to_string()),
            parent_span_id: Some(parent_span_id.to_string()),
            trace_flags: flags,
            trace_state: None,
        })
    }

    /// Add tracestate to an existing context.
    pub fn with_tracestate(mut self, state: impl Into<String>) -> Self {
        self.trace_state = Some(state.into());
        self
    }

    /// Generate a new trace ID if none exists.
    pub fn ensure_trace_id(&mut self) -> &str {
        if self.trace_id.is_none() {
            // Generate a 32-char hex trace ID
            self.trace_id = Some(format!("{:032x}", uuid::Uuid::new_v4().as_u128()));
        }
        self.trace_id.as_deref().unwrap_or_default()
    }

    /// Generate a new span ID.
    pub fn new_span_id() -> String {
        // Generate a 16-char hex span ID
        format!("{:016x}", rand::random::<u64>())
    }

    /// Check if sampling is requested (trace flags bit 0).
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }

    /// Format as traceparent header value.
    pub fn to_traceparent(&self) -> Option<String> {
        let trace_id = self.trace_id.as_ref()?;
        let parent_id = self.parent_span_id.as_deref().unwrap_or("0000000000000000");
        Some(format!(
            "00-{}-{}-{:02x}",
            trace_id, parent_id, self.trace_flags
        ))
    }
}

/// Redaction configuration for request/response bodies.
///
/// # Redaction Behavior
///
/// - **Substring Matching:** Field names are matched using case-insensitive substring
///   matching. For example, `"password"` matches `"user_password"`, `"PASSWORD123"`, etc.
/// - **Enabled Flag:** When `enabled = false`, redaction is completely bypassed and the
///   original JSON is returned unchanged. All other configuration fields are ignored.
/// - **Recursion Depth:** Redaction recurses up to 50 levels deep to prevent stack
///   overflow on deeply nested JSON. Fields beyond depth 50 are returned unredacted.
///
/// # Performance
///
/// Redaction clones JSON values during traversal. For very large bodies (>100KB),
/// consider using `max_body_size` to truncate before redaction.
///
/// # Compliance Notes
///
/// The `redaction_text` field is configurable to support compliance requirements
/// that may specify particular replacement markers (e.g., `"***REDACTED***"`).
///
/// # Example
///
/// ```
/// use sentinel_audit::observability::RedactionConfig;
///
/// let config = RedactionConfig::default();
/// let input = serde_json::json!({
///     "username": "alice",
///     "password": "secret123",
///     "nested": { "api_key": "sk-1234" }
/// });
///
/// let redacted = config.redact(&input);
/// assert_eq!(redacted["password"], "[REDACTED]");
/// assert_eq!(redacted["nested"]["api_key"], "[REDACTED]");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    /// Enable body capture and redaction.
    ///
    /// When `false`, `redact()` returns the input unchanged without any processing.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum body size to capture (bytes).
    ///
    /// Bodies exceeding this size are truncated via `truncate_body()`.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Fields to always redact (case-insensitive substring match).
    ///
    /// Each entry is matched against JSON object keys. A match occurs if the
    /// key contains the redacted field as a case-insensitive substring.
    #[serde(default = "default_redacted_fields")]
    pub redacted_fields: Vec<String>,

    /// Replacement text for redacted values.
    ///
    /// Default: `"[REDACTED]"`. May be customized for compliance requirements.
    #[serde(default = "default_redaction_text")]
    pub redaction_text: String,
}

fn default_max_body_size() -> usize {
    10240 // 10KB
}

fn default_redacted_fields() -> Vec<String> {
    vec![
        "password".to_string(),
        "secret".to_string(),
        "token".to_string(),
        "api_key".to_string(),
        "apikey".to_string(),
        "authorization".to_string(),
        "bearer".to_string(),
        "credential".to_string(),
        "private_key".to_string(),
    ]
}

fn default_redaction_text() -> String {
    "[REDACTED]".to_string()
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_body_size: default_max_body_size(),
            redacted_fields: default_redacted_fields(),
            redaction_text: default_redaction_text(),
        }
    }
}

impl RedactionConfig {
    /// Redact sensitive fields from a JSON value.
    pub fn redact(&self, value: &serde_json::Value) -> serde_json::Value {
        if !self.enabled {
            return value.clone();
        }
        self.redact_recursive(value, 0)
    }

    fn redact_recursive(&self, value: &serde_json::Value, depth: usize) -> serde_json::Value {
        // Prevent stack overflow with deep recursion (limit: 50)
        if depth > 50 {
            trace!(depth = depth, "redaction depth limit exceeded, returning unredacted");
            return value.clone();
        }

        match value {
            serde_json::Value::Object(map) => {
                let mut redacted = serde_json::Map::new();
                for (key, val) in map {
                    let lower_key = key.to_lowercase();
                    let should_redact = self
                        .redacted_fields
                        .iter()
                        .any(|f| lower_key.contains(&f.to_lowercase()));

                    if should_redact {
                        trace!(
                            field = %key,
                            depth = depth,
                            "redacting sensitive field"
                        );
                        redacted.insert(
                            key.clone(),
                            serde_json::Value::String(self.redaction_text.clone()),
                        );
                    } else {
                        redacted.insert(key.clone(), self.redact_recursive(val, depth + 1));
                    }
                }
                serde_json::Value::Object(redacted)
            }
            serde_json::Value::Array(arr) => serde_json::Value::Array(
                arr.iter()
                    .map(|v| self.redact_recursive(v, depth + 1))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    /// Truncate a body if it exceeds max size.
    pub fn truncate_body(&self, body: &serde_json::Value) -> serde_json::Value {
        let serialized = match serde_json::to_string(body) {
            Ok(s) => s,
            Err(_) => return body.clone(),
        };

        if serialized.len() <= self.max_body_size {
            return body.clone();
        }

        // Truncate and add indicator
        let truncated = &serialized[..self.max_body_size.min(serialized.len())];
        serde_json::json!({
            "_truncated": true,
            "_original_size": serialized.len(),
            "_content_preview": truncated
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_kind_as_str() {
        assert_eq!(SpanKind::Chain.as_str(), "chain");
        assert_eq!(SpanKind::Tool.as_str(), "tool");
        assert_eq!(SpanKind::Guardrail.as_str(), "guardrail");
        assert_eq!(SpanKind::Llm.as_str(), "llm");
        assert_eq!(SpanKind::Policy.as_str(), "policy");
        assert_eq!(SpanKind::Approval.as_str(), "approval");
    }

    #[test]
    fn test_security_detection_builder() {
        let detection = SecurityDetection::new(DetectionType::Dlp, 8, "API key detected")
            .with_pattern("sk-[a-zA-Z0-9]+")
            .with_metadata("location", serde_json::json!("parameters.api_key"));

        assert_eq!(detection.detection_type, DetectionType::Dlp);
        assert_eq!(detection.severity, 8);
        assert_eq!(detection.description, "API key detected");
        assert_eq!(detection.pattern, Some("sk-[a-zA-Z0-9]+".to_string()));
        assert!(detection.metadata.contains_key("location"));
    }

    #[test]
    fn test_security_span_builder() {
        let span = SecuritySpan::builder("trace-123", SpanKind::Tool)
            .name("policy_evaluation")
            .duration_ms(5)
            .action(ActionSummary::new("fs", "read_file"))
            .verdict(VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("path blocked".to_string()),
            })
            .matched_policy("block-sensitive")
            .build()
            .expect("should build");

        assert_eq!(span.trace_id, "trace-123");
        assert_eq!(span.span_kind, SpanKind::Tool);
        assert_eq!(span.name, "policy_evaluation");
        assert_eq!(span.duration_ms, 5);
        assert!(span.is_denied());
    }

    #[test]
    fn test_verdict_summary_from_verdict() {
        let allow = VerdictSummary::from(&Verdict::Allow);
        assert_eq!(allow.outcome, "allow");
        assert!(allow.reason.is_none());

        let deny = VerdictSummary::from(&Verdict::Deny {
            reason: "blocked".to_string(),
        });
        assert_eq!(deny.outcome, "deny");
        assert_eq!(deny.reason, Some("blocked".to_string()));
    }

    #[test]
    fn test_sampler_always_sample_denies() {
        let config = SamplingConfig {
            sample_rate: 0.0, // Would normally sample nothing
            always_sample_denies: true,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        let denied_span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("test".to_string()),
            })
            .build()
            .unwrap();

        assert!(sampler.should_sample(&denied_span));
    }

    #[test]
    fn test_sampler_probabilistic() {
        let config = SamplingConfig {
            sample_rate: 0.5,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        // Deterministic based on trace_id
        let span1 = SecuritySpan::builder("trace-a", SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .build()
            .unwrap();
        let span2 = SecuritySpan::builder("trace-a", SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .build()
            .unwrap();

        // Same trace_id should give same result
        assert_eq!(sampler.should_sample(&span1), sampler.should_sample(&span2));
    }

    #[test]
    fn test_trace_context_parse() {
        let ctx = TraceContext::parse_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )
        .expect("should parse");

        assert_eq!(
            ctx.trace_id,
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
        assert_eq!(ctx.parent_span_id, Some("b7ad6b7169203331".to_string()));
        assert_eq!(ctx.trace_flags, 1);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_trace_context_invalid() {
        assert!(TraceContext::parse_traceparent("invalid").is_none());
        assert!(TraceContext::parse_traceparent("00-short-short-01").is_none());
        assert!(TraceContext::parse_traceparent(
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        )
        .is_none());
    }

    #[test]
    fn test_trace_context_to_traceparent() {
        let ctx = TraceContext {
            trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
            parent_span_id: Some("b7ad6b7169203331".to_string()),
            trace_flags: 1,
            trace_state: None,
        };

        assert_eq!(
            ctx.to_traceparent(),
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string())
        );
    }

    #[test]
    fn test_redaction_config() {
        let config = RedactionConfig::default();
        let value = serde_json::json!({
            "username": "alice",
            "password": "secret123",
            "api_key": "sk-12345",
            "nested": {
                "token": "bearer-abc"
            }
        });

        let redacted = config.redact(&value);
        assert_eq!(redacted["username"], "alice");
        assert_eq!(redacted["password"], "[REDACTED]");
        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["nested"]["token"], "[REDACTED]");
    }

    #[test]
    fn test_redaction_truncate() {
        let config = RedactionConfig {
            max_body_size: 50,
            ..Default::default()
        };
        let large_value = serde_json::json!({
            "data": "This is a very long string that should be truncated because it exceeds the limit"
        });

        let truncated = config.truncate_body(&large_value);
        assert!(truncated.get("_truncated").is_some());
    }

    #[test]
    fn test_action_summary_from_action() {
        let action = sentinel_types::Action {
            tool: "filesystem".to_string(),
            function: "read_file".to_string(),
            parameters: serde_json::json!({"path": "/etc/passwd"}),
            target_paths: vec!["/etc/passwd".to_string()],
            target_domains: vec![],
            resolved_ips: vec![],
        };

        let summary = ActionSummary::from(&action);
        assert_eq!(summary.tool, "filesystem");
        assert_eq!(summary.function, "read_file");
        assert_eq!(summary.parameter_count, 1);
        // agent_id is not part of Action, so it will be None
        assert_eq!(summary.agent_id, None);
    }

    // ========================================
    // Task 2: Redaction Boundary Testing (GAP-002)
    // ========================================

    #[test]
    fn test_redaction_depth_50_works() {
        // Build a 50-level deep nested object
        let config = RedactionConfig::default();
        let mut value = serde_json::json!({"password": "secret_at_depth_50"});
        for _ in 0..49 {
            value = serde_json::json!({"nested": value});
        }

        let redacted = config.redact(&value);
        // Navigate down 49 levels to get to depth 50
        let mut current = &redacted;
        for _ in 0..49 {
            current = &current["nested"];
        }
        // Password at depth 50 should be redacted
        assert_eq!(current["password"], "[REDACTED]");
    }

    #[test]
    fn test_redaction_depth_51_not_redacted() {
        // Build a 52-level deep nested object (depth 0-51)
        // The limit is `depth > 50`, so depth 51 will return early
        let config = RedactionConfig::default();
        let mut value = serde_json::json!({"password": "secret_at_depth_52"});
        for _ in 0..51 {
            value = serde_json::json!({"nested": value});
        }

        let redacted = config.redact(&value);
        // Navigate down 51 levels to get to depth 52
        let mut current = &redacted;
        for _ in 0..51 {
            current = &current["nested"];
        }
        // Password at depth 52 should NOT be redacted (past limit of 50)
        assert_eq!(current["password"], "secret_at_depth_52");
    }

    #[test]
    fn test_redaction_large_array_with_objects() {
        let config = RedactionConfig::default();
        let items: Vec<_> = (0..100)
            .map(|i| {
                serde_json::json!({
                    "id": i,
                    "password": format!("secret_{}", i),
                    "data": {"token": format!("token_{}", i)}
                })
            })
            .collect();
        let value = serde_json::json!({"items": items});

        let redacted = config.redact(&value);
        let redacted_items = redacted["items"].as_array().unwrap();

        assert_eq!(redacted_items.len(), 100);
        for item in redacted_items {
            assert_eq!(item["password"], "[REDACTED]");
            assert_eq!(item["data"]["token"], "[REDACTED]");
        }
    }

    #[test]
    fn test_redaction_mixed_array_object_nesting() {
        let config = RedactionConfig::default();
        let value = serde_json::json!({
            "level1": [
                {"level2": [{"level3": {"password": "secret"}}]},
                {"api_key": "key123"}
            ]
        });

        let redacted = config.redact(&value);
        assert_eq!(
            redacted["level1"][0]["level2"][0]["level3"]["password"],
            "[REDACTED]"
        );
        assert_eq!(redacted["level1"][1]["api_key"], "[REDACTED]");
    }

    // ========================================
    // Task 3: TraceContext W3C Compliance (GAP-005)
    // ========================================

    #[test]
    fn test_trace_context_uppercase_hex() {
        // W3C spec says implementations SHOULD accept uppercase
        let ctx = TraceContext::parse_traceparent(
            "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01",
        );
        assert!(ctx.is_some(), "uppercase hex should be accepted");
        let ctx = ctx.unwrap();
        assert_eq!(
            ctx.trace_id,
            Some("0AF7651916CD43DD8448EB211C80319C".to_string())
        );
    }

    #[test]
    fn test_trace_context_mixed_case_hex() {
        let ctx = TraceContext::parse_traceparent(
            "00-0Af7651916Cd43dD8448eB211C80319c-b7Ad6B7169203331-01",
        );
        assert!(ctx.is_some(), "mixed case hex should be accepted");
    }

    #[test]
    fn test_trace_context_all_zeros_trace_id() {
        // All-zeros trace ID is technically valid per W3C but may be treated specially
        let ctx = TraceContext::parse_traceparent(
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",
        );
        assert!(ctx.is_some(), "all-zeros trace_id should parse");
        assert_eq!(
            ctx.unwrap().trace_id,
            Some("00000000000000000000000000000000".to_string())
        );
    }

    #[test]
    fn test_trace_context_all_zeros_span_id() {
        let ctx = TraceContext::parse_traceparent(
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
        );
        assert!(ctx.is_some(), "all-zeros span_id should parse");
        assert_eq!(
            ctx.unwrap().parent_span_id,
            Some("0000000000000000".to_string())
        );
    }

    #[test]
    fn test_trace_context_leading_zeros_preserved() {
        let ctx = TraceContext::parse_traceparent(
            "00-00f7651916cd43dd8448eb211c80319c-00ad6b7169203331-00",
        )
        .unwrap();

        // Leading zeros must be preserved
        assert!(ctx.trace_id.as_ref().unwrap().starts_with("00"));
        assert!(ctx.parent_span_id.as_ref().unwrap().starts_with("00"));
        assert_eq!(ctx.trace_flags, 0);
    }

    #[test]
    fn test_trace_context_invalid_hex_chars() {
        // 'g' is not valid hex
        assert!(TraceContext::parse_traceparent(
            "00-0af7651916cd43dd8448eb211c80319g-b7ad6b7169203331-01"
        )
        .is_none());
    }

    // ========================================
    // Task 4: SpanSampler Determinism (GAP-011)
    // ========================================

    #[test]
    fn test_sampler_determinism_same_trace_id() {
        let config = SamplingConfig {
            sample_rate: 0.5,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        // Test 10 runs with same trace_id
        let results: Vec<bool> = (0..10)
            .map(|_| {
                let span = SecuritySpan::builder("determinism-test-trace", SpanKind::Tool)
                    .verdict(VerdictSummary {
                        outcome: "allow".to_string(),
                        reason: None,
                    })
                    .build()
                    .unwrap();
                sampler.should_sample(&span)
            })
            .collect();

        // All results should be identical
        let first = results[0];
        assert!(
            results.iter().all(|&r| r == first),
            "same trace_id must always give same sampling decision"
        );
    }

    #[test]
    fn test_sampler_distribution_uniformity() {
        let config = SamplingConfig {
            sample_rate: 0.5,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        // Sample 1000 different trace_ids
        let sampled_count = (0..1000)
            .filter(|i| {
                let span = SecuritySpan::builder(format!("trace-{}", i), SpanKind::Tool)
                    .verdict(VerdictSummary {
                        outcome: "allow".to_string(),
                        reason: None,
                    })
                    .build()
                    .unwrap();
                sampler.should_sample(&span)
            })
            .count();

        // With 50% sample rate, expect ~500 ±10% (450-550)
        assert!(
            (450..=550).contains(&sampled_count),
            "expected ~500 sampled at 50% rate, got {}",
            sampled_count
        );
    }

    #[test]
    fn test_sampler_rate_zero_never_samples() {
        let config = SamplingConfig {
            sample_rate: 0.0,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        let sampled = (0..100).any(|i| {
            let span = SecuritySpan::builder(format!("trace-{}", i), SpanKind::Tool)
                .verdict(VerdictSummary {
                    outcome: "allow".to_string(),
                    reason: None,
                })
                .build()
                .unwrap();
            sampler.should_sample(&span)
        });

        assert!(!sampled, "sample_rate=0.0 should never sample");
    }

    #[test]
    fn test_sampler_rate_one_always_samples() {
        let config = SamplingConfig {
            sample_rate: 1.0,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        let all_sampled = (0..100).all(|i| {
            let span = SecuritySpan::builder(format!("trace-{}", i), SpanKind::Tool)
                .verdict(VerdictSummary {
                    outcome: "allow".to_string(),
                    reason: None,
                })
                .build()
                .unwrap();
            sampler.should_sample(&span)
        });

        assert!(all_sampled, "sample_rate=1.0 should always sample");
    }

    #[test]
    fn test_sampler_edge_trace_ids() {
        let config = SamplingConfig {
            sample_rate: 0.5,
            always_sample_denies: false,
            always_sample_detections: false,
            ..Default::default()
        };
        let sampler = SpanSampler::new(config);

        // Empty trace_id should not panic
        let span_empty = SecuritySpan::builder("", SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .build()
            .unwrap();
        let _ = sampler.should_sample(&span_empty); // Just verify no panic

        // Very long trace_id should not panic
        let long_id = "a".repeat(1000);
        let span_long = SecuritySpan::builder(&long_id, SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .build()
            .unwrap();
        let _ = sampler.should_sample(&span_long); // Just verify no panic

        // Special characters should not panic
        let span_special = SecuritySpan::builder("trace-with-émoji-🎉-and-日本語", SpanKind::Tool)
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .build()
            .unwrap();
        let _ = sampler.should_sample(&span_special); // Just verify no panic
    }

    // ========================================
    // Task 5: Rate Limit Header Edge Cases
    // Note: These test the parse logic used by exporters
    // ========================================

    #[test]
    fn test_retry_after_parsing_valid() {
        // Simulating the parse logic used in exporters
        fn parse_retry_after(value: &str) -> u64 {
            value.parse().unwrap_or(60)
        }

        assert_eq!(parse_retry_after("120"), 120);
        assert_eq!(parse_retry_after("0"), 0);
        assert_eq!(parse_retry_after("3600"), 3600);
    }

    #[test]
    fn test_retry_after_parsing_invalid() {
        fn parse_retry_after(value: &str) -> u64 {
            value.parse().unwrap_or(60)
        }

        // Non-numeric defaults to 60
        assert_eq!(parse_retry_after("not-a-number"), 60);
        assert_eq!(parse_retry_after(""), 60);
        assert_eq!(parse_retry_after("abc123"), 60);
    }

    #[test]
    fn test_retry_after_parsing_negative() {
        fn parse_retry_after(value: &str) -> u64 {
            value.parse().unwrap_or(60)
        }

        // Negative values can't parse to u64, defaults to 60
        assert_eq!(parse_retry_after("-1"), 60);
        assert_eq!(parse_retry_after("-100"), 60);
    }

    #[test]
    fn test_retry_after_parsing_extremely_large() {
        fn parse_retry_after(value: &str) -> u64 {
            value.parse().unwrap_or(60)
        }

        // Very large but valid u64
        assert_eq!(parse_retry_after("86400"), 86400); // 1 day
        assert_eq!(parse_retry_after("604800"), 604800); // 1 week

        // Overflow defaults to 60
        assert_eq!(parse_retry_after("99999999999999999999999999"), 60);
    }

    // ========================================
    // Task 12: SecuritySpanBuilder Tests (GAP-016, GAP-018)
    // ========================================

    #[test]
    fn test_builder_consecutive_builds_unique_ids() {
        // Build two spans from same builder context
        let span1 = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .name("test")
            .build()
            .unwrap();

        let span2 = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .name("test")
            .build()
            .unwrap();

        // Span IDs should be different (generated fresh each time)
        assert_ne!(
            span1.span_id, span2.span_id,
            "consecutive builds should produce different span IDs"
        );
    }

    #[test]
    fn test_builder_timestamps_are_recent() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .name("test")
            .build()
            .unwrap();

        // Parse the timestamp and verify it's recent (within last 5 seconds)
        let now = chrono::Utc::now();
        let start = chrono::DateTime::parse_from_rfc3339(&span.start_time)
            .expect("start_time should be valid RFC3339");
        let end = chrono::DateTime::parse_from_rfc3339(&span.end_time)
            .expect("end_time should be valid RFC3339");

        let five_secs_ago = now - chrono::Duration::seconds(5);
        assert!(
            start.with_timezone(&chrono::Utc) >= five_secs_ago,
            "start_time should be within last 5 seconds"
        );
        assert!(
            end.with_timezone(&chrono::Utc) >= five_secs_ago,
            "end_time should be within last 5 seconds"
        );
    }

    #[test]
    fn test_builder_duration_defaults_to_zero() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .name("test")
            .build()
            .unwrap();

        assert_eq!(span.duration_ms, 0, "duration should default to 0");
    }

    #[test]
    fn test_builder_action_defaults() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .build()
            .unwrap();

        assert_eq!(span.action.tool, "unknown");
        assert_eq!(span.action.function, "unknown");
    }

    #[test]
    fn test_builder_verdict_defaults() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .build()
            .unwrap();

        assert_eq!(span.verdict.outcome, "unknown");
        assert!(span.verdict.reason.is_none());
    }

    #[test]
    fn test_new_span_id_length_and_hex() {
        // Generate 100 span IDs and verify properties
        for _ in 0..100 {
            let id = TraceContext::new_span_id();

            // Should be exactly 16 characters
            assert_eq!(id.len(), 16, "span ID should be 16 characters");

            // Should be valid hex
            assert!(
                id.chars().all(|c| c.is_ascii_hexdigit()),
                "span ID should be valid hex: {}",
                id
            );
        }
    }

    #[test]
    fn test_new_span_id_uniqueness() {
        use std::collections::HashSet;

        // Generate 1000 span IDs and verify uniqueness
        let mut ids: HashSet<String> = HashSet::new();
        for _ in 0..1000 {
            let id = TraceContext::new_span_id();
            ids.insert(id);
        }

        assert_eq!(
            ids.len(),
            1000,
            "all 1000 generated span IDs should be unique"
        );
    }

    #[test]
    fn test_ensure_trace_id_generates_when_none() {
        let mut ctx = TraceContext::default();
        assert!(ctx.trace_id.is_none());

        // First call generates the ID
        let trace_id = ctx.ensure_trace_id().to_string();
        assert_eq!(trace_id.len(), 32, "trace ID should be 32 characters");
        assert!(
            trace_id.chars().all(|c| c.is_ascii_hexdigit()),
            "trace ID should be valid hex"
        );

        // Should return same ID on subsequent calls
        let trace_id2 = ctx.ensure_trace_id().to_string();
        assert_eq!(trace_id, trace_id2);
    }
}
