//! Gateway configuration for multi-backend MCP routing (Phase 20).
//!
//! Defines the configuration schema for Vellaveto's gateway mode, where
//! tool calls are routed to different upstream MCP servers based on
//! tool name prefix matching with health-aware failover.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vellaveto_types::TransportProtocol;

/// Maximum number of upstream backends in gateway configuration.
pub const MAX_BACKENDS: usize = 64;

/// Maximum length for a backend ID (FIND-R43-004).
pub const MAX_BACKEND_ID_LEN: usize = 128;

/// Maximum length for a single tool_prefix entry (FIND-R43-005).
pub const MAX_TOOL_PREFIX_LEN: usize = 256;

fn default_health_check_interval_secs() -> u64 {
    15
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_weight() -> u8 {
    100
}

/// Gateway configuration for multi-backend MCP routing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Whether gateway mode is enabled. When false, Vellaveto uses the
    /// single upstream URL from `--upstream`.
    #[serde(default)]
    pub enabled: bool,

    /// List of upstream backend servers.
    #[serde(default)]
    pub backends: Vec<BackendConfig>,

    /// Health check interval in seconds (default: 15, range: 5-300).
    #[serde(default = "default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,

    /// Number of consecutive failures before marking a backend unhealthy
    /// (default: 3, range: 1-100).
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before restoring a backend to healthy
    /// (default: 2, range: 1-100).
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backends: Vec::new(),
            health_check_interval_secs: default_health_check_interval_secs(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
        }
    }
}

impl GatewayConfig {
    /// Validate the gateway configuration.
    ///
    /// Returns `Ok(())` immediately when disabled — validation of backend URLs,
    /// IDs, and thresholds is only meaningful when the gateway is active. This
    /// avoids noisy errors during development when the gateway block exists in
    /// config but is toggled off.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        if self.backends.is_empty() {
            return Err("gateway.backends must not be empty when gateway is enabled".to_string());
        }

        if self.backends.len() > MAX_BACKENDS {
            return Err(format!(
                "gateway.backends has {} entries, max is {}",
                self.backends.len(),
                MAX_BACKENDS
            ));
        }

        // Check for duplicate IDs
        let mut seen_ids = std::collections::HashSet::new();
        let mut seen_prefixes = std::collections::HashSet::new();
        let mut default_count = 0u32;
        for (i, backend) in self.backends.iter().enumerate() {
            if backend.id.is_empty() {
                return Err(format!("gateway.backends[{}].id must not be empty", i));
            }
            // SECURITY (FIND-R43-004): Validate backend ID length and characters.
            // Backend IDs are used as HashMap keys, metric labels, and log fields.
            // Unbounded or non-ASCII IDs can cause log injection or metric cardinality issues.
            if backend.id.len() > MAX_BACKEND_ID_LEN {
                return Err(format!(
                    "gateway.backends[{}].id exceeds max length of {} (got {})",
                    i,
                    MAX_BACKEND_ID_LEN,
                    backend.id.len()
                ));
            }
            if !backend
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(format!(
                    "gateway.backends[{}].id contains invalid characters — \
                     must be ASCII alphanumeric, '-', '_', or '.' (id: '{}')",
                    i, backend.id
                ));
            }
            if backend.url.is_empty() {
                return Err(format!(
                    "gateway.backends[{}].url must not be empty (id: '{}')",
                    i, backend.id
                ));
            }
            // SECURITY (FIND-R42-008): Validate backend.url has a safe scheme.
            // SECURITY (FIND-R44-006): Case-insensitive per RFC 3986 Section 3.1.
            let url_trimmed = backend.url.trim();
            let url_lower = url_trimmed.to_ascii_lowercase();
            if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
                return Err(format!(
                    "gateway.backends[{}].url must use http:// or https:// scheme (id: '{}', url: '{}')",
                    i, backend.id, url_trimmed
                ));
            }
            if backend.weight == 0 {
                return Err(format!(
                    "gateway.backends[{}].weight must be >= 1 (id: '{}')",
                    i, backend.id
                ));
            }
            if !seen_ids.insert(&backend.id) {
                return Err(format!(
                    "gateway.backends has duplicate id '{}'",
                    backend.id
                ));
            }
            // SECURITY (FIND-R152-002): Bound total tool_prefixes per backend to prevent
            // memory exhaustion and O(n) routing overhead from config bloat.
            const MAX_TOOL_PREFIXES_PER_BACKEND: usize = 1000;
            if backend.tool_prefixes.len() > MAX_TOOL_PREFIXES_PER_BACKEND {
                return Err(format!(
                    "gateway.backends[{}].tool_prefixes has {} entries, max is {} (id: '{}')",
                    i,
                    backend.tool_prefixes.len(),
                    MAX_TOOL_PREFIXES_PER_BACKEND,
                    backend.id
                ));
            }
            // SECURITY (FIND-R43-005): Validate tool_prefixes are bounded, non-empty strings,
            // and unique across all backends to prevent ambiguous routing.
            for (pi, prefix) in backend.tool_prefixes.iter().enumerate() {
                if prefix.is_empty() {
                    return Err(format!(
                        "gateway.backends[{}].tool_prefixes[{}] must not be empty (id: '{}')",
                        i, pi, backend.id
                    ));
                }
                if prefix.len() > MAX_TOOL_PREFIX_LEN {
                    return Err(format!(
                        "gateway.backends[{}].tool_prefixes[{}] exceeds max length of {} (id: '{}')",
                        i, pi, MAX_TOOL_PREFIX_LEN, backend.id
                    ));
                }
                if !seen_prefixes.insert(prefix.clone()) {
                    return Err(format!(
                        "gateway.backends has duplicate tool_prefix '{}' (id: '{}')",
                        prefix, backend.id
                    ));
                }
            }
            if backend.tool_prefixes.is_empty() {
                default_count += 1;
            }
            // SECURITY (FIND-R152-001): Bound transport_urls per backend. TransportProtocol
            // is an enum with ~4 variants, but without a bound a malicious config could
            // exploit HashMap capacity or future enum extensions.
            const MAX_TRANSPORT_URLS_PER_BACKEND: usize = 10;
            if backend.transport_urls.len() > MAX_TRANSPORT_URLS_PER_BACKEND {
                return Err(format!(
                    "gateway.backends[{}].transport_urls has {} entries, max is {} (id: '{}')",
                    i,
                    backend.transport_urls.len(),
                    MAX_TRANSPORT_URLS_PER_BACKEND,
                    backend.id
                ));
            }
            // Phase 29: Validate transport_urls values are non-empty and use safe schemes.
            // SECURITY (FIND-R41-008): Validate URL scheme matches expected protocol.
            for (proto, url) in &backend.transport_urls {
                let trimmed = url.trim();
                if trimmed.is_empty() {
                    return Err(format!(
                        "gateway.backends[{}].transport_urls[{:?}] must not be empty (id: '{}')",
                        i, proto, backend.id
                    ));
                }
                // SECURITY (FIND-R44-006): Case-insensitive scheme check.
                let trimmed_lower = trimmed.to_ascii_lowercase();
                let valid_scheme = match proto {
                    TransportProtocol::Http | TransportProtocol::Grpc => {
                        trimmed_lower.starts_with("http://")
                            || trimmed_lower.starts_with("https://")
                    }
                    TransportProtocol::WebSocket => {
                        trimmed_lower.starts_with("ws://") || trimmed_lower.starts_with("wss://")
                    }
                    TransportProtocol::Stdio => true, // no URL scheme constraint
                };
                if !valid_scheme {
                    return Err(format!(
                        "gateway.backends[{}].transport_urls[{:?}] has invalid URL scheme (id: '{}', url: '{}')",
                        i, proto, backend.id, trimmed
                    ));
                }
            }
        }

        if default_count > 1 {
            return Err(
                "gateway.backends has multiple default backends (empty tool_prefixes); at most one allowed".to_string(),
            );
        }

        // Validate thresholds
        if self.health_check_interval_secs < 5 || self.health_check_interval_secs > 300 {
            return Err(format!(
                "gateway.health_check_interval_secs must be in [5, 300], got {}",
                self.health_check_interval_secs
            ));
        }
        if self.unhealthy_threshold == 0 || self.unhealthy_threshold > 100 {
            return Err(format!(
                "gateway.unhealthy_threshold must be in [1, 100], got {}",
                self.unhealthy_threshold
            ));
        }
        if self.healthy_threshold == 0 || self.healthy_threshold > 100 {
            return Err(format!(
                "gateway.healthy_threshold must be in [1, 100], got {}",
                self.healthy_threshold
            ));
        }

        Ok(())
    }
}

/// Configuration for a single upstream backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    /// Unique identifier for this backend.
    pub id: String,
    /// URL of the upstream MCP server.
    pub url: String,
    /// Tool name prefixes this backend handles. Empty = catch-all default.
    #[serde(default)]
    pub tool_prefixes: Vec<String>,
    /// Routing weight (1-100). Higher weight = preferred. Default: 100.
    #[serde(default = "default_weight")]
    pub weight: u8,

    /// Per-transport endpoint URLs for multi-transport backends (Phase 29).
    /// Maps each `TransportProtocol` to its endpoint URL. Used when
    /// `cross_transport_fallback` is enabled to try alternative transports.
    #[serde(default)]
    pub transport_urls: HashMap<TransportProtocol, String>,
}
