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
        let mut default_count = 0u32;
        for (i, backend) in self.backends.iter().enumerate() {
            if backend.id.is_empty() {
                return Err(format!("gateway.backends[{}].id must not be empty", i));
            }
            if backend.url.is_empty() {
                return Err(format!(
                    "gateway.backends[{}].url must not be empty (id: '{}')",
                    i, backend.id
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
            if backend.tool_prefixes.is_empty() {
                default_count += 1;
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
                let valid_scheme = match proto {
                    TransportProtocol::Http | TransportProtocol::Grpc => {
                        trimmed.starts_with("http://") || trimmed.starts_with("https://")
                    }
                    TransportProtocol::WebSocket => {
                        trimmed.starts_with("ws://") || trimmed.starts_with("wss://")
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
