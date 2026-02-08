//! OpenTelemetry instrumentation for Sentinel.
//!
//! Provides distributed tracing with OTLP export for observability.
//!
//! ## Span Hierarchy
//!
//! ```text
//! sentinel.http_request
//! ├── sentinel.auth_validation
//! ├── sentinel.policy_evaluation
//! │   ├── sentinel.path_matching
//! │   ├── sentinel.network_matching
//! │   └── sentinel.context_evaluation
//! ├── sentinel.dlp_scanning
//! ├── sentinel.audit_logging
//! └── sentinel.upstream_proxy (if proxying)
//! ```
//!
//! ## Configuration
//!
//! ```toml
//! [telemetry]
//! enabled = true
//! service_name = "sentinel"
//! exporter = "otlp"
//!
//! [telemetry.otlp]
//! endpoint = "http://otel-collector:4317"
//! protocol = "grpc"
//!
//! [telemetry.sampling]
//! strategy = "parent_based"
//! ratio = 0.1
//! ```

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{Config, RandomIdGenerator, Sampler, TracerProvider};
use opentelemetry_sdk::Resource;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Service name for traces.
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Service version (defaults to crate version).
    #[serde(default)]
    pub service_version: Option<String>,

    /// OTLP exporter configuration.
    #[serde(default)]
    pub otlp: OtlpConfig,

    /// Sampling configuration.
    #[serde(default)]
    pub sampling: SamplingConfig,
}

fn default_service_name() -> String {
    "sentinel".to_string()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: default_service_name(),
            service_version: None,
            otlp: OtlpConfig::default(),
            sampling: SamplingConfig::default(),
        }
    }
}

/// OTLP exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpConfig {
    /// OTLP endpoint (e.g., "http://otel-collector:4317").
    #[serde(default = "default_otlp_endpoint")]
    pub endpoint: String,

    /// Protocol: "grpc" or "http".
    #[serde(default = "default_otlp_protocol")]
    pub protocol: String,

    /// Timeout for export operations.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Headers to include with requests (e.g., for authentication).
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_otlp_protocol() -> String {
    "grpc".to_string()
}

fn default_timeout_secs() -> u64 {
    10
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: default_otlp_endpoint(),
            protocol: default_otlp_protocol(),
            timeout_secs: default_timeout_secs(),
            headers: Default::default(),
        }
    }
}

/// Sampling configuration for traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling strategy: "always_on", "always_off", "parent_based", "ratio".
    #[serde(default = "default_sampling_strategy")]
    pub strategy: String,

    /// Sampling ratio (0.0 to 1.0) for "ratio" and "parent_based" strategies.
    #[serde(default = "default_sampling_ratio")]
    pub ratio: f64,
}

fn default_sampling_strategy() -> String {
    "parent_based".to_string()
}

fn default_sampling_ratio() -> f64 {
    1.0 // Sample everything by default (can be reduced in production)
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            strategy: default_sampling_strategy(),
            ratio: default_sampling_ratio(),
        }
    }
}

/// Error type for telemetry initialization.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("failed to initialize OTLP exporter: {0}")]
    ExporterInit(String),

    #[error("failed to initialize tracer provider: {0}")]
    TracerInit(String),

    #[error("invalid sampling configuration: {0}")]
    InvalidSampling(String),

    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}

/// Initialize OpenTelemetry with the given configuration.
///
/// Returns a guard that should be kept alive for the lifetime of the application.
/// When dropped, it will flush and shut down the tracer provider.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    if !config.enabled {
        // Just initialize tracing without OpenTelemetry
        init_tracing_only();
        return Ok(TelemetryGuard { provider: None });
    }

    // Build resource with service info
    let resource = Resource::new(vec![
        KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_NAME,
            config.service_name.clone(),
        ),
        KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
            config
                .service_version
                .clone()
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
        ),
    ]);

    // Build sampler
    let sampler = build_sampler(&config.sampling)?;

    // Build OTLP exporter based on protocol
    let provider = match config.otlp.protocol.as_str() {
        "grpc" => build_grpc_provider(&config.otlp, resource, sampler)?,
        "http" => build_http_provider(&config.otlp, resource, sampler)?,
        proto => return Err(TelemetryError::UnsupportedProtocol(proto.to_string())),
    };

    // Get a tracer from the provider
    let tracer = provider.tracer("sentinel");

    // Create OpenTelemetry layer for tracing
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Initialize tracing with OpenTelemetry layer
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    tracing::info!(
        service_name = %config.service_name,
        endpoint = %config.otlp.endpoint,
        protocol = %config.otlp.protocol,
        sampling_strategy = %config.sampling.strategy,
        sampling_ratio = %config.sampling.ratio,
        "OpenTelemetry initialized"
    );

    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}

/// Initialize tracing without OpenTelemetry (for when telemetry is disabled).
fn init_tracing_only() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn build_sampler(config: &SamplingConfig) -> Result<Sampler, TelemetryError> {
    match config.strategy.as_str() {
        "always_on" => Ok(Sampler::AlwaysOn),
        "always_off" => Ok(Sampler::AlwaysOff),
        "ratio" => {
            if !(0.0..=1.0).contains(&config.ratio) {
                return Err(TelemetryError::InvalidSampling(format!(
                    "ratio must be between 0.0 and 1.0, got {}",
                    config.ratio
                )));
            }
            Ok(Sampler::TraceIdRatioBased(config.ratio))
        }
        "parent_based" => {
            if !(0.0..=1.0).contains(&config.ratio) {
                return Err(TelemetryError::InvalidSampling(format!(
                    "ratio must be between 0.0 and 1.0, got {}",
                    config.ratio
                )));
            }
            Ok(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                config.ratio,
            ))))
        }
        strategy => Err(TelemetryError::InvalidSampling(format!(
            "unknown sampling strategy: {}",
            strategy
        ))),
    }
}

fn build_grpc_provider(
    config: &OtlpConfig,
    resource: Resource,
    sampler: Sampler,
) -> Result<TracerProvider, TelemetryError> {
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_secs))
        .build_span_exporter()
        .map_err(|e| TelemetryError::ExporterInit(e.to_string()))?;

    let trace_config = Config::default()
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource);

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_config(trace_config)
        .build();

    Ok(provider)
}

fn build_http_provider(
    config: &OtlpConfig,
    resource: Resource,
    sampler: Sampler,
) -> Result<TracerProvider, TelemetryError> {
    let exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_secs))
        .build_span_exporter()
        .map_err(|e| TelemetryError::ExporterInit(e.to_string()))?;

    let trace_config = Config::default()
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource);

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_config(trace_config)
        .build();

    Ok(provider)
}

/// Guard that shuts down the tracer provider when dropped.
pub struct TelemetryGuard {
    provider: Option<TracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if self.provider.is_some() {
            // Force flush any pending spans
            // The TracerProvider will be dropped automatically which flushes spans
            opentelemetry::global::shutdown_tracer_provider();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.service_name, "sentinel");
        assert_eq!(config.otlp.endpoint, "http://localhost:4317");
        assert_eq!(config.otlp.protocol, "grpc");
        assert_eq!(config.sampling.strategy, "parent_based");
        assert_eq!(config.sampling.ratio, 1.0);
    }

    #[test]
    fn test_build_sampler_always_on() {
        let config = SamplingConfig {
            strategy: "always_on".to_string(),
            ratio: 0.5,
        };
        let sampler = build_sampler(&config).unwrap();
        // Just verify it doesn't error
        assert!(matches!(sampler, Sampler::AlwaysOn));
    }

    #[test]
    fn test_build_sampler_always_off() {
        let config = SamplingConfig {
            strategy: "always_off".to_string(),
            ratio: 0.5,
        };
        let sampler = build_sampler(&config).unwrap();
        assert!(matches!(sampler, Sampler::AlwaysOff));
    }

    #[test]
    fn test_build_sampler_ratio() {
        let config = SamplingConfig {
            strategy: "ratio".to_string(),
            ratio: 0.5,
        };
        let sampler = build_sampler(&config).unwrap();
        assert!(matches!(sampler, Sampler::TraceIdRatioBased(_)));
    }

    #[test]
    fn test_build_sampler_invalid_ratio() {
        let config = SamplingConfig {
            strategy: "ratio".to_string(),
            ratio: 1.5,
        };
        let result = build_sampler(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_sampler_unknown_strategy() {
        let config = SamplingConfig {
            strategy: "unknown".to_string(),
            ratio: 0.5,
        };
        let result = build_sampler(&config);
        assert!(result.is_err());
    }
}
