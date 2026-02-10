//! AI Observability Platform Configuration.
//!
//! This module provides configuration types for AI observability platforms
//! like Langfuse, Arize, and Helicone.
//!
//! # Example Configuration
//!
//! ```toml
//! [observability]
//! enabled = true
//! sample_rate = 1.0
//! always_sample_denies = true
//! capture_request_body = true
//! capture_response_body = false
//! max_body_size = 10240
//!
//! [observability.langfuse]
//! enabled = true
//! endpoint = "https://cloud.langfuse.com"
//! public_key_env = "LANGFUSE_PUBLIC_KEY"
//! secret_key_env = "LANGFUSE_SECRET_KEY"
//!
//! [observability.arize]
//! enabled = false
//! endpoint = "https://otlp.arize.com/v1"
//! space_key_env = "ARIZE_SPACE_KEY"
//! api_key_env = "ARIZE_API_KEY"
//!
//! [observability.helicone]
//! enabled = false
//! api_key_env = "HELICONE_API_KEY"
//!
//! [observability.webhook]
//! enabled = false
//! endpoint = "https://custom.example.com/observability"
//! auth_header_env = "OBSERVABILITY_AUTH"
//! ```

use serde::{Deserialize, Serialize};

/// Master observability configuration.
///
/// Controls AI observability platform integrations (Langfuse, Arize, Helicone)
/// and enhanced tracing with request/response body capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservabilityConfig {
    /// Master toggle for observability. Default: false (opt-in).
    #[serde(default)]
    pub enabled: bool,

    /// Sample rate (0.0 to 1.0). 1.0 = sample all requests. Default: 1.0.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Always sample denied requests regardless of sample rate. Default: true.
    #[serde(default = "default_true")]
    pub always_sample_denies: bool,

    /// Always sample requests with security detections. Default: true.
    #[serde(default = "default_true")]
    pub always_sample_detections: bool,

    /// Minimum severity (1-10) to force sampling. Default: 7.
    #[serde(default = "default_min_severity")]
    pub min_severity_to_sample: u8,

    /// Enable request body capture. Default: true.
    #[serde(default = "default_true")]
    pub capture_request_body: bool,

    /// Enable response body capture. Default: false.
    #[serde(default)]
    pub capture_response_body: bool,

    /// Maximum body size to capture (bytes). Default: 10240 (10KB).
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Mask sensitive data in captured bodies. Default: true.
    #[serde(default = "default_true")]
    pub mask_sensitive_data: bool,

    /// Additional fields to redact (case-insensitive, partial match).
    #[serde(default)]
    pub redacted_fields: Vec<String>,

    /// Langfuse platform configuration.
    #[serde(default)]
    pub langfuse: LangfuseConfig,

    /// Arize platform configuration.
    #[serde(default)]
    pub arize: ArizeConfig,

    /// Helicone platform configuration.
    #[serde(default)]
    pub helicone: HeliconeConfig,

    /// Generic webhook exporter configuration.
    #[serde(default)]
    pub webhook: WebhookExporterConfig,
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

fn default_max_body_size() -> usize {
    10240 // 10KB
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate: default_sample_rate(),
            always_sample_denies: true,
            always_sample_detections: true,
            min_severity_to_sample: default_min_severity(),
            capture_request_body: true,
            capture_response_body: false,
            max_body_size: default_max_body_size(),
            mask_sensitive_data: true,
            redacted_fields: Vec::new(),
            langfuse: LangfuseConfig::default(),
            arize: ArizeConfig::default(),
            helicone: HeliconeConfig::default(),
            webhook: WebhookExporterConfig::default(),
        }
    }
}

/// Langfuse AI observability platform configuration.
///
/// Langfuse (https://langfuse.com) provides tracing, evaluation, and
/// observability for LLM applications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LangfuseConfig {
    /// Enable Langfuse exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Langfuse API endpoint. Default: "https://cloud.langfuse.com".
    #[serde(default = "default_langfuse_endpoint")]
    pub endpoint: String,

    /// Environment variable containing the Langfuse public key.
    #[serde(default = "default_langfuse_public_key_env")]
    pub public_key_env: String,

    /// Environment variable containing the Langfuse secret key.
    #[serde(default = "default_langfuse_secret_key_env")]
    pub secret_key_env: String,

    /// Maximum spans per batch. Default: 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds. Default: 5.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts. Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Request timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Custom release/version tag for traces.
    #[serde(default)]
    pub release: Option<String>,

    /// Custom metadata to add to all traces.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

fn default_langfuse_endpoint() -> String {
    "https://cloud.langfuse.com".to_string()
}

fn default_langfuse_public_key_env() -> String {
    "LANGFUSE_PUBLIC_KEY".to_string()
}

fn default_langfuse_secret_key_env() -> String {
    "LANGFUSE_SECRET_KEY".to_string()
}

fn default_batch_size() -> usize {
    100
}

fn default_flush_interval() -> u64 {
    5
}

fn default_max_retries() -> u32 {
    3
}

fn default_timeout() -> u64 {
    30
}

impl Default for LangfuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_langfuse_endpoint(),
            public_key_env: default_langfuse_public_key_env(),
            secret_key_env: default_langfuse_secret_key_env(),
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            max_retries: default_max_retries(),
            timeout_secs: default_timeout(),
            release: None,
            metadata: std::collections::HashMap::new(),
        }
    }
}

/// Arize AI observability platform configuration.
///
/// Arize (https://arize.com) provides ML observability with a focus on
/// embeddings, model performance, and drift detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArizeConfig {
    /// Enable Arize exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Arize OTLP endpoint. Default: "https://otlp.arize.com/v1".
    #[serde(default = "default_arize_endpoint")]
    pub endpoint: String,

    /// Environment variable containing the Arize space key.
    #[serde(default = "default_arize_space_key_env")]
    pub space_key_env: String,

    /// Environment variable containing the Arize API key.
    #[serde(default = "default_arize_api_key_env")]
    pub api_key_env: String,

    /// Model ID for Arize tracking.
    #[serde(default = "default_arize_model_id")]
    pub model_id: String,

    /// Model version for Arize tracking.
    #[serde(default)]
    pub model_version: Option<String>,

    /// Maximum spans per batch. Default: 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds. Default: 5.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts. Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Request timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_arize_endpoint() -> String {
    "https://otlp.arize.com/v1".to_string()
}

fn default_arize_space_key_env() -> String {
    "ARIZE_SPACE_KEY".to_string()
}

fn default_arize_api_key_env() -> String {
    "ARIZE_API_KEY".to_string()
}

fn default_arize_model_id() -> String {
    "sentinel-mcp-firewall".to_string()
}

impl Default for ArizeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_arize_endpoint(),
            space_key_env: default_arize_space_key_env(),
            api_key_env: default_arize_api_key_env(),
            model_id: default_arize_model_id(),
            model_version: None,
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            max_retries: default_max_retries(),
            timeout_secs: default_timeout(),
        }
    }
}

/// Helicone AI observability platform configuration.
///
/// Helicone (https://helicone.ai) provides LLM observability through
/// header-based integration with LLM API providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeliconeConfig {
    /// Enable Helicone exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Environment variable containing the Helicone API key.
    #[serde(default = "default_helicone_api_key_env")]
    pub api_key_env: String,

    /// Helicone log endpoint. Default: "https://api.helicone.ai/v1/log".
    #[serde(default = "default_helicone_endpoint")]
    pub endpoint: String,

    /// Custom properties to add to all logs.
    #[serde(default)]
    pub custom_properties: std::collections::HashMap<String, String>,

    /// Maximum logs per batch. Default: 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds. Default: 5.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts. Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Request timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_helicone_api_key_env() -> String {
    "HELICONE_API_KEY".to_string()
}

fn default_helicone_endpoint() -> String {
    "https://api.helicone.ai/v1/log".to_string()
}

impl Default for HeliconeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key_env: default_helicone_api_key_env(),
            endpoint: default_helicone_endpoint(),
            custom_properties: std::collections::HashMap::new(),
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            max_retries: default_max_retries(),
            timeout_secs: default_timeout(),
        }
    }
}

/// Generic webhook exporter configuration for observability.
///
/// Sends security spans to a custom HTTP endpoint as JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookExporterConfig {
    /// Enable webhook exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Webhook endpoint URL.
    #[serde(default)]
    pub endpoint: String,

    /// Environment variable containing the auth header value.
    /// The header will be sent as `Authorization: <value>`.
    #[serde(default)]
    pub auth_header_env: Option<String>,

    /// Custom HTTP headers to send with each request.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Maximum spans per batch. Default: 100.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval in seconds. Default: 5.
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts. Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Request timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Use gzip compression for payloads. Default: true.
    #[serde(default = "default_true")]
    pub compress: bool,
}

impl Default for WebhookExporterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            auth_header_env: None,
            headers: std::collections::HashMap::new(),
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            max_retries: default_max_retries(),
            timeout_secs: default_timeout(),
            compress: true,
        }
    }
}

impl ObservabilityConfig {
    /// Check if any exporter is enabled.
    pub fn has_enabled_exporters(&self) -> bool {
        self.enabled
            && (self.langfuse.enabled
                || self.arize.enabled
                || self.helicone.enabled
                || self.webhook.enabled)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Validate sample_rate
        if self.sample_rate < 0.0 || self.sample_rate > 1.0 {
            return Err(format!(
                "observability.sample_rate must be between 0.0 and 1.0, got {}",
                self.sample_rate
            ));
        }

        // Validate severity
        if self.min_severity_to_sample > 10 {
            return Err(format!(
                "observability.min_severity_to_sample must be <= 10, got {}",
                self.min_severity_to_sample
            ));
        }

        // Validate max_body_size (prevent excessive memory usage)
        const MAX_BODY_SIZE_LIMIT: usize = 1_048_576; // 1MB
        if self.max_body_size > MAX_BODY_SIZE_LIMIT {
            return Err(format!(
                "observability.max_body_size must be <= {} (1MB), got {}",
                MAX_BODY_SIZE_LIMIT, self.max_body_size
            ));
        }

        // Validate Langfuse config
        if self.langfuse.enabled {
            if self.langfuse.endpoint.is_empty() {
                return Err(
                    "observability.langfuse.endpoint must not be empty when enabled".to_string(),
                );
            }
            Self::validate_url(&self.langfuse.endpoint, "observability.langfuse.endpoint")?;

            if self.langfuse.batch_size == 0 || self.langfuse.batch_size > 10_000 {
                return Err(format!(
                    "observability.langfuse.batch_size must be 1-10000, got {}",
                    self.langfuse.batch_size
                ));
            }
            if self.langfuse.timeout_secs == 0 {
                return Err(
                    "observability.langfuse.timeout_secs must be > 0".to_string(),
                );
            }
            if self.langfuse.flush_interval_secs == 0 {
                return Err(
                    "observability.langfuse.flush_interval_secs must be > 0".to_string(),
                );
            }
        }

        // Validate Arize config
        if self.arize.enabled {
            if self.arize.endpoint.is_empty() {
                return Err(
                    "observability.arize.endpoint must not be empty when enabled".to_string(),
                );
            }
            Self::validate_url(&self.arize.endpoint, "observability.arize.endpoint")?;

            if self.arize.batch_size == 0 || self.arize.batch_size > 10_000 {
                return Err(format!(
                    "observability.arize.batch_size must be 1-10000, got {}",
                    self.arize.batch_size
                ));
            }
            if self.arize.timeout_secs == 0 {
                return Err(
                    "observability.arize.timeout_secs must be > 0".to_string(),
                );
            }
            if self.arize.flush_interval_secs == 0 {
                return Err(
                    "observability.arize.flush_interval_secs must be > 0".to_string(),
                );
            }
        }

        // Validate Helicone config
        if self.helicone.enabled {
            if self.helicone.endpoint.is_empty() {
                return Err(
                    "observability.helicone.endpoint must not be empty when enabled".to_string(),
                );
            }
            Self::validate_url(&self.helicone.endpoint, "observability.helicone.endpoint")?;

            if self.helicone.batch_size == 0 || self.helicone.batch_size > 10_000 {
                return Err(format!(
                    "observability.helicone.batch_size must be 1-10000, got {}",
                    self.helicone.batch_size
                ));
            }
            if self.helicone.timeout_secs == 0 {
                return Err(
                    "observability.helicone.timeout_secs must be > 0".to_string(),
                );
            }
            if self.helicone.flush_interval_secs == 0 {
                return Err(
                    "observability.helicone.flush_interval_secs must be > 0".to_string(),
                );
            }
        }

        // Validate webhook config
        if self.webhook.enabled {
            if self.webhook.endpoint.is_empty() {
                return Err(
                    "observability.webhook.endpoint must not be empty when enabled".to_string(),
                );
            }
            Self::validate_url(&self.webhook.endpoint, "observability.webhook.endpoint")?;

            // SECURITY: Reject private/loopback URLs (SSRF prevention)
            Self::validate_not_private(&self.webhook.endpoint, "observability.webhook.endpoint")?;

            if self.webhook.batch_size == 0 || self.webhook.batch_size > 10_000 {
                return Err(format!(
                    "observability.webhook.batch_size must be 1-10000, got {}",
                    self.webhook.batch_size
                ));
            }
            if self.webhook.timeout_secs == 0 {
                return Err(
                    "observability.webhook.timeout_secs must be > 0".to_string(),
                );
            }
            if self.webhook.flush_interval_secs == 0 {
                return Err(
                    "observability.webhook.flush_interval_secs must be > 0".to_string(),
                );
            }
        }

        Ok(())
    }

    /// Validate a URL is well-formed.
    fn validate_url(url: &str, field: &str) -> Result<(), String> {
        let parsed =
            url::Url::parse(url).map_err(|e| format!("{} is not a valid URL: {}", field, e))?;

        match parsed.scheme() {
            "http" | "https" => Ok(()),
            scheme => Err(format!(
                "{} must use http or https scheme, got '{}'",
                field, scheme
            )),
        }
    }

    /// Validate URL does not point to private/internal addresses.
    fn validate_not_private(url: &str, field: &str) -> Result<(), String> {
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return Ok(()), // Already validated in validate_url
        };

        let host = match parsed.host_str() {
            Some(h) => h,
            None => return Err(format!("{} must have a host", field)),
        };

        // Check for localhost
        let lower_host = host.to_lowercase();
        if lower_host == "localhost" || lower_host.starts_with("localhost.") {
            return Err(format!(
                "{} must not target localhost, got '{}'",
                field, host
            ));
        }

        // Check for private IP addresses
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            let is_private = ip.is_loopback()
                || ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xf0) == 16)
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
                || ip.octets()[0] == 0
                || ip.is_broadcast();
            if is_private {
                return Err(format!(
                    "{} must not target private/internal IP ranges, got '{}'",
                    field, host
                ));
            }
        }

        // Check IPv6
        let ipv6_host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip6) = ipv6_host.parse::<std::net::Ipv6Addr>() {
            let segs = ip6.segments();
            let is_private = ip6.is_loopback()
                || ip6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
                || (segs[0] & 0xffc0) == 0xfe80; // fe80::/10 (link-local)
            if is_private {
                return Err(format!(
                    "{} must not target private/internal IPv6 ranges, got '{}'",
                    field, host
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ObservabilityConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.sample_rate, 1.0);
        assert!(config.always_sample_denies);
        assert!(config.capture_request_body);
        assert!(!config.capture_response_body);
        assert!(!config.has_enabled_exporters());
    }

    #[test]
    fn test_has_enabled_exporters() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        assert!(!config.has_enabled_exporters());

        config.langfuse.enabled = true;
        assert!(config.has_enabled_exporters());
    }

    #[test]
    fn test_validate_sample_rate() {
        let mut config = ObservabilityConfig::default();
        config.sample_rate = 1.5;
        assert!(config.validate().is_err());

        config.sample_rate = -0.1;
        assert!(config.validate().is_err());

        config.sample_rate = 0.5;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_langfuse() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = true;
        config.langfuse.endpoint = String::new();
        assert!(config.validate().is_err());

        config.langfuse.endpoint = "https://cloud.langfuse.com".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_webhook_ssrf() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // Private IP should be rejected
        config.webhook.endpoint = "https://192.168.1.1/webhook".to_string();
        assert!(config.validate().is_err());

        // Localhost should be rejected
        config.webhook.endpoint = "https://localhost/webhook".to_string();
        assert!(config.validate().is_err());

        // Public IP should be accepted
        config.webhook.endpoint = "https://api.example.com/webhook".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_langfuse_default() {
        let config = LangfuseConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint, "https://cloud.langfuse.com");
        assert_eq!(config.public_key_env, "LANGFUSE_PUBLIC_KEY");
        assert_eq!(config.secret_key_env, "LANGFUSE_SECRET_KEY");
    }

    #[test]
    fn test_arize_default() {
        let config = ArizeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint, "https://otlp.arize.com/v1");
        assert_eq!(config.model_id, "sentinel-mcp-firewall");
    }

    #[test]
    fn test_helicone_default() {
        let config = HeliconeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.endpoint, "https://api.helicone.ai/v1/log");
    }

    #[test]
    fn test_webhook_default() {
        let config = WebhookExporterConfig::default();
        assert!(!config.enabled);
        assert!(config.endpoint.is_empty());
        assert!(config.compress);
    }

    // ========================================
    // Task 11: Private IP Validation Coverage (GAP-009)
    // ========================================

    #[test]
    fn test_validate_ipv4_10_0_0_0_8() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 10.0.0.0/8 range
        config.webhook.endpoint = "https://10.0.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "10.0.0.1 should be rejected");

        config.webhook.endpoint = "https://10.255.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "10.255.255.255 should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv4_172_16_0_0_12() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 172.16.0.0/12 range (172.16.0.0 - 172.31.255.255)
        config.webhook.endpoint = "https://172.16.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "172.16.0.1 should be rejected");

        config.webhook.endpoint = "https://172.31.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "172.31.255.255 should be rejected"
        );

        // 172.15.x.x should be allowed (outside the private range)
        config.webhook.endpoint = "https://172.15.0.1/webhook".to_string();
        assert!(config.validate().is_ok(), "172.15.0.1 should be allowed");
    }

    #[test]
    fn test_validate_ipv4_192_168_0_0_16() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 192.168.0.0/16 range
        config.webhook.endpoint = "https://192.168.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "192.168.0.1 should be rejected");

        config.webhook.endpoint = "https://192.168.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "192.168.255.255 should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv4_169_254_0_0_16() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 169.254.0.0/16 (link-local)
        config.webhook.endpoint = "https://169.254.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "169.254.0.1 should be rejected");

        config.webhook.endpoint = "https://169.254.169.254/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "169.254.169.254 (cloud metadata) should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv4_100_64_0_0_10() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 100.64.0.0/10 (CGNAT)
        config.webhook.endpoint = "https://100.64.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "100.64.0.1 should be rejected");

        config.webhook.endpoint = "https://100.127.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "100.127.255.255 should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv4_0_0_0_0_8() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 0.0.0.0/8 (this network)
        config.webhook.endpoint = "https://0.0.0.0/webhook".to_string();
        assert!(config.validate().is_err(), "0.0.0.0 should be rejected");

        config.webhook.endpoint = "https://0.255.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "0.255.255.255 should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv4_loopback() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // 127.0.0.0/8 (loopback)
        config.webhook.endpoint = "https://127.0.0.1/webhook".to_string();
        assert!(config.validate().is_err(), "127.0.0.1 should be rejected");

        config.webhook.endpoint = "https://127.255.255.255/webhook".to_string();
        assert!(
            config.validate().is_err(),
            "127.255.255.255 should be rejected"
        );
    }

    #[test]
    fn test_validate_ipv6_loopback() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // ::1 (IPv6 loopback)
        config.webhook.endpoint = "https://[::1]/webhook".to_string();
        assert!(config.validate().is_err(), "::1 should be rejected");
    }

    #[test]
    fn test_validate_ipv6_unspecified() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // :: (IPv6 unspecified)
        config.webhook.endpoint = "https://[::]/webhook".to_string();
        assert!(config.validate().is_err(), ":: should be rejected");
    }

    #[test]
    fn test_validate_ipv6_ula() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // fc00::/7 (ULA - Unique Local Address)
        config.webhook.endpoint = "https://[fc00::1]/webhook".to_string();
        assert!(config.validate().is_err(), "fc00::1 should be rejected");

        config.webhook.endpoint = "https://[fd00::1]/webhook".to_string();
        assert!(config.validate().is_err(), "fd00::1 should be rejected");
    }

    #[test]
    fn test_validate_ipv6_link_local() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // fe80::/10 (link-local)
        config.webhook.endpoint = "https://[fe80::1]/webhook".to_string();
        assert!(config.validate().is_err(), "fe80::1 should be rejected");

        config.webhook.endpoint = "https://[febf::1]/webhook".to_string();
        assert!(config.validate().is_err(), "febf::1 should be rejected");
    }

    #[test]
    fn test_validate_ipv6_public() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;

        // Public IPv6 should be allowed
        config.webhook.endpoint = "https://[2001:db8::1]/webhook".to_string();
        assert!(config.validate().is_ok(), "2001:db8::1 should be allowed");
    }

    // ========================================
    // Task 13: has_enabled_exporters Combinations (GAP-020)
    // ========================================

    #[test]
    fn test_has_enabled_exporters_master_false_all_exporters_true() {
        let mut config = ObservabilityConfig::default();
        config.enabled = false;
        config.langfuse.enabled = true;
        config.arize.enabled = true;
        config.helicone.enabled = true;
        config.webhook.enabled = true;

        assert!(
            !config.has_enabled_exporters(),
            "master=false should override all exporter settings"
        );
    }

    #[test]
    fn test_has_enabled_exporters_master_true_all_false() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = false;
        config.arize.enabled = false;
        config.helicone.enabled = false;
        config.webhook.enabled = false;

        assert!(
            !config.has_enabled_exporters(),
            "master=true with all exporters=false should return false"
        );
    }

    #[test]
    fn test_has_enabled_exporters_each_exporter_individually() {
        // Test each exporter individually
        let exporters = ["langfuse", "arize", "helicone", "webhook"];

        for exporter in &exporters {
            let mut config = ObservabilityConfig::default();
            config.enabled = true;

            match *exporter {
                "langfuse" => config.langfuse.enabled = true,
                "arize" => config.arize.enabled = true,
                "helicone" => config.helicone.enabled = true,
                "webhook" => config.webhook.enabled = true,
                _ => {}
            }

            assert!(
                config.has_enabled_exporters(),
                "master=true with {}=true should return true",
                exporter
            );
        }
    }

    #[test]
    fn test_has_enabled_exporters_multiple_exporters() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = true;
        config.webhook.enabled = true;

        assert!(
            config.has_enabled_exporters(),
            "master=true with multiple exporters should return true"
        );
    }

    // ========================================
    // Task 8: Enhanced Config Validation (GAP-006)
    // ========================================

    #[test]
    fn test_validate_langfuse_timeout_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = true;
        config.langfuse.timeout_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("timeout_secs must be > 0"),
            "expected timeout error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_langfuse_flush_interval_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = true;
        config.langfuse.flush_interval_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("flush_interval_secs must be > 0"),
            "expected flush_interval error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_arize_timeout_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.arize.enabled = true;
        config.arize.timeout_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("timeout_secs must be > 0"),
            "expected timeout error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_arize_flush_interval_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.arize.enabled = true;
        config.arize.flush_interval_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("flush_interval_secs must be > 0"),
            "expected flush_interval error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_helicone_timeout_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.helicone.enabled = true;
        config.helicone.timeout_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("timeout_secs must be > 0"),
            "expected timeout error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_helicone_flush_interval_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.helicone.enabled = true;
        config.helicone.flush_interval_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("flush_interval_secs must be > 0"),
            "expected flush_interval error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_webhook_timeout_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;
        config.webhook.endpoint = "https://api.example.com/webhook".to_string();
        config.webhook.timeout_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("timeout_secs must be > 0"),
            "expected timeout error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_webhook_flush_interval_zero() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.webhook.enabled = true;
        config.webhook.endpoint = "https://api.example.com/webhook".to_string();
        config.webhook.flush_interval_secs = 0;

        let err = config.validate().unwrap_err();
        assert!(
            err.contains("flush_interval_secs must be > 0"),
            "expected flush_interval error, got: {}",
            err
        );
    }

    #[test]
    fn test_validate_valid_nonzero_configs() {
        let mut config = ObservabilityConfig::default();
        config.enabled = true;
        config.langfuse.enabled = true;
        // Defaults should be valid (non-zero)
        assert!(config.validate().is_ok(), "defaults should be valid");

        // Explicit non-zero values should be valid
        config.langfuse.timeout_secs = 30;
        config.langfuse.flush_interval_secs = 5;
        assert!(config.validate().is_ok(), "explicit non-zero values should be valid");
    }
}
