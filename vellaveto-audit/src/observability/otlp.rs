//! OTLP (OpenTelemetry Protocol) Exporter.
//!
//! Maps Vellaveto `SecuritySpan` traces to OpenTelemetry spans with GenAI
//! semantic conventions and exports them via OTLP to any compatible collector
//! (Jaeger, Grafana Tempo, Datadog, etc.).
//!
//! # GenAI Semantic Conventions
//!
//! Uses the OpenTelemetry GenAI semantic conventions for AI-specific attributes:
//! - `gen_ai.system` → `"vellaveto"`
//! - `gen_ai.operation.name` → tool name
//! - Custom `vellaveto.*` attributes for security-specific data.
//!
//! # Feature Gate
//!
//! Requires the `otlp-exporter` feature flag:
//! ```toml
//! vellaveto-audit = { version = "2.2", features = ["otlp-exporter"] }
//! ```

use super::{
    ObservabilityError, ObservabilityExporter, ObservabilityExporterConfig, SecuritySpan, SpanKind,
};
use async_trait::async_trait;
use opentelemetry::trace::{SpanId, TraceId};
use opentelemetry::KeyValue;
use std::time::SystemTime;

/// OTLP exporter configuration (runtime, not the vellaveto-config type).
#[derive(Debug, Clone)]
pub struct OtlpExporterConfig {
    /// Base exporter config (batching, retry, timeout).
    pub base: ObservabilityExporterConfig,
    /// OTLP endpoint URL.
    pub endpoint: String,
    /// Service name for the OTel resource.
    pub service_name: String,
}

/// OTLP exporter for SecuritySpan traces.
///
/// Converts Vellaveto SecuritySpan instances to OpenTelemetry spans and
/// exports them to an OTLP-compatible collector. The exporter adds GenAI
/// semantic convention attributes for AI observability.
pub struct OtlpExporter {
    config: OtlpExporterConfig,
}

impl OtlpExporter {
    /// Create a new OTLP exporter with the given configuration.
    ///
    /// SECURITY (FIND-P1-3): Logs a warning at construction time because the
    /// OTLP exporter is not yet fully implemented. `export_batch` will return
    /// an error to ensure operators are aware that data is NOT being exported.
    pub fn new(config: OtlpExporterConfig) -> Self {
        tracing::warn!(
            endpoint = %config.endpoint,
            "OTLP exporter instantiated but NOT yet implemented — \
             audit spans will NOT be exported. Use webhook or streaming exporters instead."
        );
        Self { config }
    }
}

#[async_trait]
impl ObservabilityExporter for OtlpExporter {
    fn name(&self) -> &str {
        "otlp"
    }

    /// SECURITY (FIND-P1-3): This method returns an error to clearly signal
    /// that the OTLP exporter is a stub and no data is being exported. Empty
    /// batches are accepted silently (no-op). Non-empty batches fail with a
    /// descriptive error so operators are immediately aware of the gap.
    async fn export_batch(&self, spans: &[SecuritySpan]) -> Result<(), ObservabilityError> {
        if spans.is_empty() {
            return Ok(());
        }

        // Validate the conversion so we catch attribute-mapping regressions
        // even though we cannot actually send the data.
        for span in spans {
            let _attributes = span_to_otel_attributes(span);
            let _trace_id = parse_trace_id(&span.trace_id);
            let _span_id = parse_span_id(&span.span_id);
        }

        tracing::warn!(
            endpoint = %self.config.endpoint,
            count = spans.len(),
            "OTLP exporter is not yet implemented — {} spans will NOT be exported. \
             Use webhook or streaming exporters instead.",
            spans.len(),
        );

        Err(ObservabilityError::Configuration(
            "OTLP exporter is not yet implemented — data will not be exported. \
             Use webhook or streaming exporters instead."
                .to_string(),
        ))
    }

    async fn health_check(&self) -> Result<(), ObservabilityError> {
        // Validate endpoint is reachable (basic check)
        if self.config.endpoint.is_empty() {
            return Err(ObservabilityError::Configuration(
                "OTLP endpoint is empty".to_string(),
            ));
        }
        Ok(())
    }

    fn config(&self) -> &ObservabilityExporterConfig {
        &self.config.base
    }
}

// ── Attribute Mapping ────────────────────────────────────────────────────────

/// Convert a `SecuritySpan` to OpenTelemetry `KeyValue` attributes.
///
/// Maps vellaveto-specific fields to a combination of GenAI semantic
/// conventions and custom `vellaveto.*` attributes.
///
/// SECURITY (FIND-R46-008): PII/secret redaction is NOT applied in this function.
/// Redaction is applied at the `AuditLogger::log_entry()` level before data reaches
/// the observability pipeline. `SecuritySpan` instances are constructed from already-
/// redacted `AuditEntry` data. If `SecuritySpan` instances are constructed from
/// unredacted sources outside the audit pipeline, the caller is responsible for
/// applying redaction before export.
pub fn span_to_otel_attributes(span: &SecuritySpan) -> Vec<KeyValue> {
    let mut attrs = Vec::with_capacity(16);

    // GenAI semantic conventions
    attrs.push(KeyValue::new("gen_ai.system", "vellaveto"));
    attrs.push(KeyValue::new(
        "gen_ai.operation.name",
        span.action.tool.clone(),
    ));

    // Vellaveto-specific attributes
    attrs.push(KeyValue::new(
        "vellaveto.tool.name",
        span.action.tool.clone(),
    ));
    attrs.push(KeyValue::new(
        "vellaveto.tool.function",
        span.action.function.clone(),
    ));
    attrs.push(KeyValue::new(
        "vellaveto.verdict",
        span.verdict.outcome.clone(),
    ));

    if let Some(ref policy) = span.matched_policy {
        attrs.push(KeyValue::new("vellaveto.policy.id", policy.clone()));
    }

    if let Some(ref reason) = span.verdict.reason {
        attrs.push(KeyValue::new("vellaveto.verdict.reason", reason.clone()));
    }

    if let Some(ref agent_id) = span.action.agent_id {
        attrs.push(KeyValue::new("vellaveto.agent.id", agent_id.clone()));
    }

    // GenAI agent identity attributes (Phase 28)
    if let Some(agent_id) = span
        .attributes
        .get("gen_ai.agent.id")
        .and_then(|v| v.as_str())
    {
        attrs.push(KeyValue::new("gen_ai.agent.id", agent_id.to_string()));
    }
    if let Some(agent_name) = span
        .attributes
        .get("gen_ai.agent.name")
        .and_then(|v| v.as_str())
    {
        attrs.push(KeyValue::new("gen_ai.agent.name", agent_name.to_string()));
    }

    // Detection type (first detection, if any)
    if let Some(detection) = span.detections.first() {
        attrs.push(KeyValue::new(
            "vellaveto.detection.type",
            format!("{:?}", detection.detection_type),
        ));
        attrs.push(KeyValue::new(
            "vellaveto.detection.severity",
            i64::from(detection.severity),
        ));
    }

    // Span metadata
    attrs.push(KeyValue::new(
        "vellaveto.span_kind",
        span.span_kind.as_str().to_string(),
    ));
    attrs.push(KeyValue::new(
        "vellaveto.duration_ms",
        span.duration_ms as i64,
    ));

    // Custom attributes from the span
    for (key, value) in &span.attributes {
        let otel_key = format!("vellaveto.custom.{}", key);
        if let Some(s) = value.as_str() {
            attrs.push(KeyValue::new(otel_key, s.to_string()));
        } else if let Some(n) = value.as_i64() {
            attrs.push(KeyValue::new(otel_key, n));
        } else if let Some(b) = value.as_bool() {
            attrs.push(KeyValue::new(otel_key, b));
        }
    }

    attrs
}

/// Map a `SpanKind` to an OpenTelemetry `SpanKind`.
pub fn map_span_kind(kind: SpanKind) -> opentelemetry::trace::SpanKind {
    match kind {
        SpanKind::Chain => opentelemetry::trace::SpanKind::Server,
        SpanKind::Tool => opentelemetry::trace::SpanKind::Internal,
        SpanKind::Guardrail => opentelemetry::trace::SpanKind::Internal,
        SpanKind::Llm => opentelemetry::trace::SpanKind::Client,
        SpanKind::Policy => opentelemetry::trace::SpanKind::Internal,
        SpanKind::Approval => opentelemetry::trace::SpanKind::Internal,
        SpanKind::Gateway => opentelemetry::trace::SpanKind::Internal,
    }
}

/// Map a verdict outcome to an OpenTelemetry `Status`.
pub fn verdict_to_status(outcome: &str) -> opentelemetry::trace::Status {
    match outcome {
        "allow" => opentelemetry::trace::Status::Ok,
        "deny" => opentelemetry::trace::Status::error("denied by policy"),
        _ => opentelemetry::trace::Status::Unset,
    }
}

/// Parse a trace ID string to an OpenTelemetry `TraceId`.
///
/// Expects a hex string. Pads or truncates to 32 hex characters (16 bytes).
pub fn parse_trace_id(id: &str) -> TraceId {
    let hex = normalize_hex_id(id, 32);
    let bytes = hex_to_bytes_padded(&hex, 16);
    TraceId::from_bytes(bytes)
}

/// Parse a span ID string to an OpenTelemetry `SpanId`.
///
/// Expects a hex string or UUID. Truncates/pads to 16 hex characters (8 bytes).
pub fn parse_span_id(id: &str) -> SpanId {
    // Strip hyphens for UUID-format span IDs
    let cleaned: String = id.chars().filter(|c| *c != '-').collect();
    let hex = normalize_hex_id(&cleaned, 16);
    let bytes = hex_to_bytes_padded(&hex, 8);
    SpanId::from_bytes(bytes)
}

/// Parse an ISO 8601 timestamp string to `SystemTime`.
///
/// Returns `SystemTime::now()` if parsing fails.
pub fn parse_time(timestamp: &str) -> SystemTime {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| SystemTime::from(dt))
        .unwrap_or_else(|_| SystemTime::now())
}

/// Normalize a hex string to exactly `target_len` characters.
fn normalize_hex_id(id: &str, target_len: usize) -> String {
    // Take only hex chars
    let hex_chars: String = id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_chars.len() >= target_len {
        hex_chars[..target_len].to_string()
    } else {
        format!("{:0>width$}", hex_chars, width = target_len)
    }
}

/// Convert a hex string to a fixed-size byte array, zero-padding if needed.
fn hex_to_bytes_padded<const N: usize>(hex: &str, _len: usize) -> [u8; N] {
    let mut bytes = [0u8; N];
    let decoded = hex::decode(hex).unwrap_or_default();
    let copy_len = decoded.len().min(N);
    bytes[..copy_len].copy_from_slice(&decoded[..copy_len]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{
        ActionSummary, DetectionType, SecurityDetection, SecuritySpan, VerdictSummary,
    };

    fn make_test_span() -> SecuritySpan {
        SecuritySpan::builder("0af7651916cd43dd8448eb211c80319c", SpanKind::Tool)
            .span_id("b7ad6b7169203331")
            .name("read_file")
            .duration_ms(5)
            .action(ActionSummary::new("filesystem", "read_file"))
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .matched_policy("allow-fs")
            .build()
            .unwrap()
    }

    #[test]
    fn test_span_to_otel_attributes() {
        let span = make_test_span();
        let attrs = span_to_otel_attributes(&span);

        let find = |key: &str| attrs.iter().find(|kv| kv.key.as_str() == key);

        assert!(find("gen_ai.system").is_some());
        assert!(find("gen_ai.operation.name").is_some());
        assert!(find("vellaveto.tool.name").is_some());
        assert!(find("vellaveto.tool.function").is_some());
        assert!(find("vellaveto.verdict").is_some());
        assert!(find("vellaveto.policy.id").is_some());
    }

    #[test]
    fn test_genai_semantic_conventions() {
        let span = make_test_span();
        let attrs = span_to_otel_attributes(&span);

        let system = attrs
            .iter()
            .find(|kv| kv.key.as_str() == "gen_ai.system")
            .unwrap();
        assert_eq!(system.value.as_str(), "vellaveto");

        let op_name = attrs
            .iter()
            .find(|kv| kv.key.as_str() == "gen_ai.operation.name")
            .unwrap();
        assert_eq!(op_name.value.as_str(), "filesystem");
    }

    #[test]
    fn test_verdict_to_status() {
        assert!(matches!(
            verdict_to_status("allow"),
            opentelemetry::trace::Status::Ok
        ));
        assert!(matches!(
            verdict_to_status("deny"),
            opentelemetry::trace::Status::Error { .. }
        ));
        assert!(matches!(
            verdict_to_status("require_approval"),
            opentelemetry::trace::Status::Unset
        ));
    }

    #[test]
    fn test_span_kind_mapping() {
        use opentelemetry::trace::SpanKind as OtelKind;
        assert!(matches!(map_span_kind(SpanKind::Chain), OtelKind::Server));
        assert!(matches!(map_span_kind(SpanKind::Tool), OtelKind::Internal));
        assert!(matches!(map_span_kind(SpanKind::Llm), OtelKind::Client));
        assert!(matches!(
            map_span_kind(SpanKind::Policy),
            OtelKind::Internal
        ));
    }

    #[test]
    fn test_detection_to_event() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .detection(SecurityDetection::new(
                DetectionType::Dlp,
                8,
                "API key detected",
            ))
            .detection(SecurityDetection::new(
                DetectionType::Injection,
                5,
                "SQL injection",
            ))
            .verdict(VerdictSummary {
                outcome: "deny".to_string(),
                reason: Some("DLP finding".to_string()),
            })
            .build()
            .unwrap();

        let attrs = span_to_otel_attributes(&span);
        let detection_type = attrs
            .iter()
            .find(|kv| kv.key.as_str() == "vellaveto.detection.type")
            .unwrap();
        assert_eq!(detection_type.value.as_str(), "Dlp");
    }

    #[test]
    fn test_time_parsing() {
        let time = parse_time("2026-01-15T10:30:00Z");
        let now = SystemTime::now();
        // Should be in the past
        assert!(time < now);

        // Invalid timestamps return now
        let fallback = parse_time("not-a-timestamp");
        let diff = now
            .duration_since(fallback)
            .or_else(|e| Ok::<_, ()>(e.duration()))
            .unwrap();
        assert!(diff.as_secs() < 2, "fallback should be close to now");
    }

    #[test]
    fn test_span_id_conversion() {
        let span_id = parse_span_id("b7ad6b7169203331");
        assert_ne!(span_id, SpanId::INVALID);
    }

    #[test]
    fn test_trace_id_conversion() {
        let trace_id = parse_trace_id("0af7651916cd43dd8448eb211c80319c");
        assert_ne!(trace_id, TraceId::INVALID);
    }

    #[test]
    fn test_trace_id_short_padded() {
        // Short IDs should be zero-padded
        let trace_id = parse_trace_id("abc123");
        assert_ne!(trace_id, TraceId::INVALID);
    }

    #[test]
    fn test_span_id_uuid_format() {
        // UUID-format span IDs should work (hyphens stripped)
        let span_id = parse_span_id("550e8400-e29b-41d4-a716-446655440000");
        assert_ne!(span_id, SpanId::INVALID);
    }

    #[test]
    fn test_genai_agent_attributes_in_span() {
        let span = SecuritySpan::builder("trace-1", SpanKind::Tool)
            .span_id("abcdef0123456789")
            .verdict(VerdictSummary {
                outcome: "allow".to_string(),
                reason: None,
            })
            .attribute("gen_ai.agent.id", serde_json::json!("agent-007"))
            .attribute("gen_ai.agent.name", serde_json::json!("research-bot"))
            .build()
            .unwrap();

        let attrs = span_to_otel_attributes(&span);
        let find = |key: &str| attrs.iter().find(|kv| kv.key.as_str() == key);

        let agent_id = find("gen_ai.agent.id").expect("gen_ai.agent.id should be present");
        assert_eq!(agent_id.value.as_str(), "agent-007");

        let agent_name = find("gen_ai.agent.name").expect("gen_ai.agent.name should be present");
        assert_eq!(agent_name.value.as_str(), "research-bot");
    }

    #[test]
    fn test_gateway_span_kind_mapping() {
        use opentelemetry::trace::SpanKind as OtelKind;
        assert!(matches!(
            map_span_kind(SpanKind::Gateway),
            OtelKind::Internal
        ));
    }

    #[test]
    fn test_genai_agent_attributes_absent_when_not_set() {
        let span = make_test_span();
        let attrs = span_to_otel_attributes(&span);
        let find = |key: &str| attrs.iter().find(|kv| kv.key.as_str() == key);

        assert!(find("gen_ai.agent.id").is_none());
        assert!(find("gen_ai.agent.name").is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = OtlpExporterConfig {
            base: ObservabilityExporterConfig::default(),
            endpoint: "http://localhost:4317".to_string(),
            service_name: "vellaveto".to_string(),
        };
        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "vellaveto");
        assert_eq!(config.base.batch_size, 100);
    }
}
