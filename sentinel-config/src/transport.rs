//! Transport discovery and negotiation configuration.
//!
//! Controls which transports are advertised via `/.well-known/mcp-transport`,
//! upstream fallback priorities, and transport restrictions.

use sentinel_types::TransportProtocol;
use serde::{Deserialize, Serialize};

/// Maximum fallback retries to prevent retry storms.
const MAX_FALLBACK_RETRIES: u32 = 10;

/// Minimum fallback timeout in seconds.
const MIN_FALLBACK_TIMEOUT_SECS: u64 = 1;

/// Maximum fallback timeout in seconds.
const MAX_FALLBACK_TIMEOUT_SECS: u64 = 120;

fn default_discovery_enabled() -> bool {
    true
}

fn default_advertise_capabilities() -> bool {
    true
}

fn default_max_fallback_retries() -> u32 {
    1
}

fn default_fallback_timeout_secs() -> u64 {
    10
}

/// Transport discovery and negotiation configuration.
///
/// Controls the `/.well-known/mcp-transport` discovery endpoint, upstream
/// transport priorities, and transport restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransportConfig {
    /// Enable the `/.well-known/mcp-transport` discovery endpoint.
    /// Default: true.
    #[serde(default = "default_discovery_enabled")]
    pub discovery_enabled: bool,

    /// Ordered list of upstream transport protocols to try.
    /// Empty means HTTP-only (implicit default).
    #[serde(default)]
    pub upstream_priorities: Vec<TransportProtocol>,

    /// Transports that must not be advertised or used.
    /// Useful for disabling gRPC or WebSocket in restricted environments.
    #[serde(default)]
    pub restricted_transports: Vec<TransportProtocol>,

    /// Whether to include SDK capabilities in discovery responses.
    /// Default: true.
    #[serde(default = "default_advertise_capabilities")]
    pub advertise_capabilities: bool,

    /// Maximum number of fallback attempts when the primary transport fails.
    /// Default: 1. Max: 10.
    #[serde(default = "default_max_fallback_retries")]
    pub max_fallback_retries: u32,

    /// Timeout per fallback attempt in seconds.
    /// Default: 10. Range: 1–120.
    #[serde(default = "default_fallback_timeout_secs")]
    pub fallback_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            discovery_enabled: default_discovery_enabled(),
            upstream_priorities: Vec::new(),
            restricted_transports: Vec::new(),
            advertise_capabilities: default_advertise_capabilities(),
            max_fallback_retries: default_max_fallback_retries(),
            fallback_timeout_secs: default_fallback_timeout_secs(),
        }
    }
}

impl TransportConfig {
    /// Validate transport configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_fallback_retries > MAX_FALLBACK_RETRIES {
            return Err(format!(
                "transport.max_fallback_retries must be <= {}, got {}",
                MAX_FALLBACK_RETRIES, self.max_fallback_retries
            ));
        }

        if self.fallback_timeout_secs < MIN_FALLBACK_TIMEOUT_SECS
            || self.fallback_timeout_secs > MAX_FALLBACK_TIMEOUT_SECS
        {
            return Err(format!(
                "transport.fallback_timeout_secs must be in [{}, {}], got {}",
                MIN_FALLBACK_TIMEOUT_SECS, MAX_FALLBACK_TIMEOUT_SECS, self.fallback_timeout_secs
            ));
        }

        // A transport cannot appear in both priorities and restricted lists.
        for proto in &self.upstream_priorities {
            if self.restricted_transports.contains(proto) {
                return Err(format!(
                    "transport {:?} appears in both upstream_priorities and restricted_transports",
                    proto
                ));
            }
        }

        Ok(())
    }
}
