//! A2A (Agent-to-Agent) protocol security configuration.

use crate::default_true;
use serde::{Deserialize, Serialize};

/// A2A (Agent-to-Agent) protocol security configuration.
///
/// Controls Sentinel's A2A proxy behavior including message interception,
/// policy evaluation, agent card verification, and security feature integration.
///
/// # TOML Example
///
/// ```toml
/// [a2a]
/// enabled = true
/// upstream_url = "https://agent.example.com"
/// listen_addr = "0.0.0.0:8082"
/// require_agent_card = true
/// agent_card_cache_secs = 3600
/// allowed_auth_methods = ["bearer", "oauth2"]
/// enable_circuit_breaker = true
/// enable_shadow_agent_detection = true
/// enable_dlp_scanning = true
/// enable_injection_detection = true
/// max_message_size = 10485760
/// request_timeout_ms = 30000
/// allowed_task_operations = []
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct A2aConfig {
    /// Enable A2A protocol support. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Upstream A2A server URL (when acting as proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,

    /// Listen address for A2A proxy (e.g., "0.0.0.0:8082").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,

    /// Require agent card verification before allowing requests. Default: false.
    #[serde(default)]
    pub require_agent_card: bool,

    /// Cache agent cards for this duration in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_a2a_card_cache_secs")]
    pub agent_card_cache_secs: u64,

    /// Allowed authentication methods. Default: ["apikey", "bearer"].
    /// Valid values: "apikey", "bearer", "oauth2", "mtls"
    #[serde(default = "default_a2a_auth_methods")]
    pub allowed_auth_methods: Vec<String>,

    /// Apply circuit breaker to upstream A2A servers. Default: true.
    #[serde(default = "default_true")]
    pub enable_circuit_breaker: bool,

    /// Enable shadow agent detection for A2A traffic. Default: true.
    #[serde(default = "default_true")]
    pub enable_shadow_agent_detection: bool,

    /// Enable DLP scanning on A2A message content. Default: true.
    #[serde(default = "default_true")]
    pub enable_dlp_scanning: bool,

    /// Enable injection detection on A2A text content. Default: true.
    #[serde(default = "default_true")]
    pub enable_injection_detection: bool,

    /// Maximum message size in bytes. Default: 10 MB.
    #[serde(default = "default_a2a_max_message_size")]
    pub max_message_size: usize,

    /// Request timeout in milliseconds. Default: 30000 (30 seconds).
    #[serde(default = "default_a2a_timeout")]
    pub request_timeout_ms: u64,

    /// Allowed task operations (empty = all allowed). Default: [].
    /// Valid values: "get", "cancel", "resubscribe"
    #[serde(default)]
    pub allowed_task_operations: Vec<String>,
}

fn default_a2a_card_cache_secs() -> u64 {
    3600 // 1 hour
}

fn default_a2a_auth_methods() -> Vec<String> {
    vec!["apikey".to_string(), "bearer".to_string()]
}

fn default_a2a_max_message_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_a2a_timeout() -> u64 {
    30000 // 30 seconds
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream_url: None,
            listen_addr: None,
            require_agent_card: false,
            agent_card_cache_secs: default_a2a_card_cache_secs(),
            allowed_auth_methods: default_a2a_auth_methods(),
            enable_circuit_breaker: true,
            enable_shadow_agent_detection: true,
            enable_dlp_scanning: true,
            enable_injection_detection: true,
            max_message_size: default_a2a_max_message_size(),
            request_timeout_ms: default_a2a_timeout(),
            allowed_task_operations: vec![],
        }
    }
}
