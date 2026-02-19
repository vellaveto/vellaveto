//! OpenTelemetry instrumentation for Vellaveto.
//!
//! Provides distributed tracing with OTLP export for observability.
//!
//! ## Span Hierarchy
//!
//! ```text
//! vellaveto.http_request
//! ├── vellaveto.auth_validation
//! ├── vellaveto.policy_evaluation
//! │   ├── vellaveto.path_matching
//! │   ├── vellaveto.network_matching
//! │   └── vellaveto.context_evaluation
//! ├── vellaveto.dlp_scanning
//! ├── vellaveto.audit_logging
//! └── vellaveto.upstream_proxy (if proxying)
//! ```
//!
//! ## Configuration
//!
//! ```toml
//! [telemetry]
//! enabled = true
//! service_name = "vellaveto"
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
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Maximum length for service name.
const MAX_SERVICE_NAME_LEN: usize = 256;

/// Maximum length for service version.
const MAX_SERVICE_VERSION_LEN: usize = 128;

/// Maximum length for OTLP endpoint URL.
const MAX_OTLP_ENDPOINT_LEN: usize = 1024;

/// Maximum length for OTLP protocol string.
const MAX_OTLP_PROTOCOL_LEN: usize = 64;

/// Maximum length for sampling strategy string.
const MAX_SAMPLING_STRATEGY_LEN: usize = 64;

/// Maximum number of OTLP headers.
const MAX_OTLP_HEADERS: usize = 32;

/// Maximum length for an OTLP header key or value.
const MAX_OTLP_HEADER_FIELD_LEN: usize = 512;

/// Returns `true` if `c` is a valid HTTP token character per RFC 7230 §3.2.6.
///
/// HTTP token = 1*tchar
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
///
/// SECURITY (P3): Header keys containing non-token characters may bypass
/// validation in downstream HTTP libraries or inject header delimiters.
fn is_http_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// SECURITY: Detect control characters AND Unicode format characters.
fn is_unsafe_char_telemetry(c: char) -> bool {
    let cp = c as u32;
    c.is_control()
        || (0x200B..=0x200F).contains(&cp)
        || (0x202A..=0x202E).contains(&cp)
        || (0x2060..=0x2064).contains(&cp)
        || (0x2066..=0x2069).contains(&cp)
        || cp == 0xFEFF
        || (0xFFF9..=0xFFFB).contains(&cp)
        || (0xE0001..=0xE007F).contains(&cp)
        || cp == 0x00AD
}

/// Telemetry configuration.
// SECURITY (FIND-R74-008): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    "vellaveto".to_string()
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

// SECURITY (FIND-R58-SRV-011): Validate telemetry config string fields.
impl TelemetryConfig {
    /// Validate all string fields for control characters and length bounds.
    pub fn validate(&self) -> Result<(), TelemetryError> {
        if self.service_name.len() > MAX_SERVICE_NAME_LEN {
            return Err(TelemetryError::InvalidConfig(
                "service_name too long".into(),
            ));
        }
        if self.service_name.chars().any(is_unsafe_char_telemetry) {
            return Err(TelemetryError::InvalidConfig(
                "service_name contains control/format characters".into(),
            ));
        }
        if let Some(ref v) = self.service_version {
            if v.len() > MAX_SERVICE_VERSION_LEN {
                return Err(TelemetryError::InvalidConfig(
                    "service_version too long".into(),
                ));
            }
            if v.chars().any(is_unsafe_char_telemetry) {
                return Err(TelemetryError::InvalidConfig(
                    "service_version contains control/format characters".into(),
                ));
            }
        }
        // Validate OTLP config
        if self.otlp.endpoint.len() > MAX_OTLP_ENDPOINT_LEN {
            return Err(TelemetryError::InvalidConfig(
                "otlp.endpoint too long".into(),
            ));
        }
        if self.otlp.endpoint.chars().any(is_unsafe_char_telemetry) {
            return Err(TelemetryError::InvalidConfig(
                "otlp.endpoint contains control/format characters".into(),
            ));
        }
        // Validate endpoint URL scheme
        if !self.otlp.endpoint.starts_with("http://") && !self.otlp.endpoint.starts_with("https://")
        {
            return Err(TelemetryError::InvalidConfig(
                "otlp.endpoint must use http:// or https:// scheme".into(),
            ));
        }
        // SECURITY (FIND-R74-007): Validate OTLP endpoint against private/loopback IPs
        // to prevent SSRF. Matches the pattern used for webhook_url in config_validate.rs.
        // Only enforced when telemetry is enabled — default config uses localhost:4317
        // which is correct for local OTLP collectors and should not block disabled configs.
        if self.enabled {
            let after_scheme = if self.otlp.endpoint.starts_with("https://") {
                &self.otlp.endpoint["https://".len()..]
            } else {
                &self.otlp.endpoint["http://".len()..]
            };
            // Strip userinfo (RFC 3986 §3.2.1)
            let authority = after_scheme
                .find('/')
                .map_or(after_scheme, |i| &after_scheme[..i]);
            let host_portion = match authority.rfind('@') {
                Some(at) => &after_scheme[at + 1..],
                None => after_scheme,
            };
            // Percent-decode brackets for IPv6 detection
            let host_portion_decoded = host_portion
                .replace("%5B", "[")
                .replace("%5b", "[")
                .replace("%5D", "]")
                .replace("%5d", "]");
            let host_portion = host_portion_decoded.as_str();
            let host = if host_portion.starts_with('[') {
                if let Some(bracket_end) = host_portion.find(']') {
                    host_portion[..bracket_end + 1].to_lowercase()
                } else {
                    return Err(TelemetryError::InvalidConfig(
                        "otlp.endpoint has malformed IPv6 address (missing ']')".into(),
                    ));
                }
            } else {
                let host_end = host_portion
                    .find(['/', ':', '?', '#'])
                    .unwrap_or(host_portion.len());
                host_portion[..host_end].to_lowercase()
            };
            if host.is_empty() {
                return Err(TelemetryError::InvalidConfig(
                    "otlp.endpoint has no host".into(),
                ));
            }
            // Percent-decode host before comparison
            let host_for_check = {
                let mut decoded = String::with_capacity(host.len());
                let bytes = host.as_bytes();
                let mut i = 0;
                while i < bytes.len() {
                    if bytes[i] == b'%' && i + 2 < bytes.len() {
                        if let (Some(hi), Some(lo)) = (
                            (bytes[i + 1] as char).to_digit(16),
                            (bytes[i + 2] as char).to_digit(16),
                        ) {
                            decoded.push((hi * 16 + lo) as u8 as char);
                            i += 3;
                            continue;
                        }
                    }
                    decoded.push(bytes[i] as char);
                    i += 1;
                }
                decoded.to_lowercase()
            };
            // Reject localhost/loopback
            let loopbacks = ["localhost", "127.0.0.1", "[::1]", "0.0.0.0"];
            if loopbacks.iter().any(|lb| host_for_check == *lb) {
                return Err(TelemetryError::InvalidConfig(format!(
                    "otlp.endpoint must not target localhost/loopback, got '{}'",
                    host
                )));
            }
            // Reject private IPv4 ranges
            if let Ok(ip) = host_for_check.parse::<std::net::Ipv4Addr>() {
                let is_private = ip.is_loopback()
                    || ip.octets()[0] == 10                          // 10.0.0.0/8
                    || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xf0) == 16) // 172.16.0.0/12
                    || (ip.octets()[0] == 192 && ip.octets()[1] == 168)         // 192.168.0.0/16
                    || (ip.octets()[0] == 169 && ip.octets()[1] == 254)         // 169.254.0.0/16 (link-local/metadata)
                    || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
                    || ip.octets()[0] == 0                           // 0.0.0.0/8
                    || ip.is_broadcast(); // 255.255.255.255
                if is_private {
                    return Err(TelemetryError::InvalidConfig(format!(
                        "otlp.endpoint must not target private/internal IP ranges, got '{}'",
                        host
                    )));
                }
            }
            // Reject private IPv6 ranges
            let ipv6_host = host_for_check.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip6) = ipv6_host.parse::<std::net::Ipv6Addr>() {
                // Check IPv4-mapped IPv6 (::ffff:x.x.x.x)
                let segs = ip6.segments();
                let is_ipv4_mapped = segs[0] == 0
                    && segs[1] == 0
                    && segs[2] == 0
                    && segs[3] == 0
                    && segs[4] == 0
                    && segs[5] == 0xffff;
                if is_ipv4_mapped {
                    let mapped_ip = std::net::Ipv4Addr::new(
                        (segs[6] >> 8) as u8,
                        segs[6] as u8,
                        (segs[7] >> 8) as u8,
                        segs[7] as u8,
                    );
                    let is_private_v4 = mapped_ip.is_loopback()
                        || mapped_ip.octets()[0] == 10
                        || (mapped_ip.octets()[0] == 172
                            && (mapped_ip.octets()[1] & 0xf0) == 16)
                        || (mapped_ip.octets()[0] == 192 && mapped_ip.octets()[1] == 168)
                        || (mapped_ip.octets()[0] == 169 && mapped_ip.octets()[1] == 254)
                        || (mapped_ip.octets()[0] == 100
                            && (mapped_ip.octets()[1] & 0xc0) == 64)
                        || mapped_ip.octets()[0] == 0
                        || mapped_ip.is_broadcast();
                    if is_private_v4 {
                        return Err(TelemetryError::InvalidConfig(format!(
                            "otlp.endpoint must not target private/internal IP ranges (IPv4-mapped IPv6), got '{}'",
                            host
                        )));
                    }
                }
                let is_private = ip6.is_loopback()
                    || ip6.is_unspecified()
                    || (segs[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                    || (segs[0] & 0xffc0) == 0xfe80; // fe80::/10 (link-local)
                if is_private {
                    return Err(TelemetryError::InvalidConfig(format!(
                        "otlp.endpoint must not target private/internal IPv6 ranges, got '{}'",
                        host
                    )));
                }
            }
        }
        if self.otlp.protocol.len() > MAX_OTLP_PROTOCOL_LEN {
            return Err(TelemetryError::InvalidConfig(
                "otlp.protocol too long".into(),
            ));
        }
        if self.otlp.headers.len() > MAX_OTLP_HEADERS {
            return Err(TelemetryError::InvalidConfig(
                "too many otlp.headers".into(),
            ));
        }
        for (k, v) in &self.otlp.headers {
            if k.len() > MAX_OTLP_HEADER_FIELD_LEN || v.len() > MAX_OTLP_HEADER_FIELD_LEN {
                return Err(TelemetryError::InvalidConfig(
                    "otlp header key or value too long".into(),
                ));
            }
            if k.chars().any(is_unsafe_char_telemetry) || v.chars().any(is_unsafe_char_telemetry) {
                return Err(TelemetryError::InvalidConfig(
                    "otlp header contains control/format characters".into(),
                ));
            }
            // SECURITY (P3): Validate header key against HTTP token charset (RFC 7230 §3.2.6).
            // Non-token characters in header names can bypass downstream validation or
            // inject header delimiters (e.g., ':', '\r', '\n').
            if k.is_empty() || !k.chars().all(is_http_token_char) {
                return Err(TelemetryError::InvalidConfig(
                    "otlp header key contains invalid characters (must be RFC 7230 token)".into(),
                ));
            }
        }
        // Validate sampling
        if self.sampling.strategy.len() > MAX_SAMPLING_STRATEGY_LEN {
            return Err(TelemetryError::InvalidConfig(
                "sampling.strategy too long".into(),
            ));
        }
        if !self.sampling.ratio.is_finite()
            || self.sampling.ratio < 0.0
            || self.sampling.ratio > 1.0
        {
            return Err(TelemetryError::InvalidConfig(
                "sampling.ratio must be finite and in [0.0, 1.0]".into(),
            ));
        }
        Ok(())
    }
}

/// OTLP exporter configuration.
// SECURITY (FIND-R74-008): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
// SECURITY (FIND-R74-008): deny_unknown_fields prevents attacker-injected
// fields from being silently accepted in security-critical configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Initialize OpenTelemetry with the given configuration.
///
/// Returns a guard that should be kept alive for the lifetime of the application.
/// When dropped, it will flush and shut down the tracer provider.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    // SECURITY: Validate config fields before using them (FIND-R59-SRV-001).
    config.validate()?;

    if !config.enabled {
        // Just initialize tracing without OpenTelemetry
        init_tracing_only();
        return Ok(TelemetryGuard { provider: None });
    }

    // Build resource with service info
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attribute(KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
            config
                .service_version
                .clone()
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
        ))
        .build();

    // Build sampler
    let sampler = build_sampler(&config.sampling)?;

    // Build OTLP exporter based on protocol
    let provider = match config.otlp.protocol.as_str() {
        "grpc" => build_grpc_provider(&config.otlp, resource, sampler)?,
        "http" => build_http_provider(&config.otlp, resource, sampler)?,
        proto => return Err(TelemetryError::UnsupportedProtocol(proto.to_string())),
    };

    // Get a tracer from the provider
    let tracer = provider.tracer("vellaveto");

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
) -> Result<SdkTracerProvider, TelemetryError> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| TelemetryError::ExporterInit(e.to_string()))?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    Ok(provider)
}

fn build_http_provider(
    config: &OtlpConfig,
    resource: Resource,
    sampler: Sampler,
) -> Result<SdkTracerProvider, TelemetryError> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.endpoint)
        .with_timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .map_err(|e| TelemetryError::ExporterInit(e.to_string()))?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    Ok(provider)
}

/// Guard that shuts down the tracer provider when dropped.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Force flush any pending spans and shutdown
            if let Err(e) = provider.shutdown() {
                // Log at debug level since this happens during shutdown
                // and higher levels might not be visible
                eprintln!("Warning: Telemetry provider shutdown error: {}", e);
            }
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
        assert_eq!(config.service_name, "vellaveto");
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
