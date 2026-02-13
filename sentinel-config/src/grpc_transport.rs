//! gRPC transport configuration (Phase 17.2).
//!
//! Provides configuration types for the optional gRPC transport server.
//! Feature-gated behind `grpc` on `sentinel-http-proxy`.

use serde::{Deserialize, Serialize};

/// Configuration for gRPC transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcTransportConfig {
    /// Enable the gRPC transport server.
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for the gRPC server (default: "127.0.0.1:50051").
    #[serde(default = "default_listen_address")]
    pub listen_address: String,

    /// Maximum inbound/outbound message size in bytes (default: 4194304 = 4 MB).
    #[serde(default = "default_max_message_size")]
    pub max_message_size_bytes: usize,

    /// Optional upstream gRPC URL for native gRPC-to-gRPC forwarding.
    /// When absent, requests are converted to HTTP and forwarded to the
    /// main `upstream_url`.
    #[serde(default)]
    pub upstream_grpc_url: Option<String>,

    /// Enable gRPC health checking service (default: true).
    #[serde(default = "default_health_enabled")]
    pub health_enabled: bool,
}

fn default_listen_address() -> String {
    "127.0.0.1:50051".to_string()
}

fn default_max_message_size() -> usize {
    4 * 1024 * 1024 // 4 MB
}

fn default_health_enabled() -> bool {
    true
}

impl Default for GrpcTransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_listen_address(),
            max_message_size_bytes: default_max_message_size(),
            upstream_grpc_url: None,
            health_enabled: true,
        }
    }
}
