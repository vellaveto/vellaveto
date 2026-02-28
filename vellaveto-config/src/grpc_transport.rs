// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! gRPC transport configuration (Phase 17.2).
//!
//! Provides configuration types for the optional gRPC transport server.
//! Feature-gated behind `grpc` on `vellaveto-http-proxy`.

use serde::{Deserialize, Serialize};

/// Configuration for gRPC transport.
/// SECURITY (FIND-R55-GRPC-007): deny_unknown_fields prevents config injection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Maximum allowed gRPC message size (256 MB).
pub const MAX_GRPC_MESSAGE_SIZE: usize = 268_435_456;

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

impl GrpcTransportConfig {
    /// Validate gRPC transport configuration bounds.
    ///
    /// NOTE: This method is not called from `PolicyConfig::validate()` because
    /// gRPC transport config lives outside the main `PolicyConfig` struct.
    /// Callers (e.g., server startup) are responsible for invoking it explicitly.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_message_size_bytes == 0 || self.max_message_size_bytes > MAX_GRPC_MESSAGE_SIZE {
            return Err(format!(
                "grpc.max_message_size_bytes must be in [1, {}] (256 MB), got {}",
                MAX_GRPC_MESSAGE_SIZE, self.max_message_size_bytes
            ));
        }
        let addr = self.listen_address.trim();
        if addr.is_empty() {
            return Err("grpc.listen_address must not be empty".to_string());
        }
        // SECURITY: Reject control and format characters in listen_address.
        if vellaveto_types::has_dangerous_chars(addr) {
            return Err("grpc.listen_address contains control or format characters".to_string());
        }
        // SECURITY: Validate upstream_grpc_url for SSRF when present.
        if let Some(ref url) = self.upstream_grpc_url {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                return Err("grpc.upstream_grpc_url must not be empty when provided".to_string());
            }
            const MAX_UPSTREAM_GRPC_URL_LEN: usize = 2048;
            if trimmed.len() > MAX_UPSTREAM_GRPC_URL_LEN {
                return Err(format!(
                    "grpc.upstream_grpc_url exceeds max length ({} > {})",
                    trimmed.len(),
                    MAX_UPSTREAM_GRPC_URL_LEN,
                ));
            }
            if vellaveto_types::has_dangerous_chars(trimmed) {
                return Err(
                    "grpc.upstream_grpc_url contains control or format characters".to_string(),
                );
            }
            // SECURITY: Require http:// or https:// scheme.
            let lower = trimmed.to_lowercase();
            if !lower.starts_with("http://") && !lower.starts_with("https://") {
                return Err(
                    "grpc.upstream_grpc_url must use http:// or https:// scheme".to_string()
                );
            }
            // SECURITY: SSRF validation — reject private IPs, cloud metadata endpoints.
            // Allow localhost for development environments.
            if !crate::validation::is_http_localhost_url(trimmed) {
                if let Err(e) = vellaveto_types::validate_url_no_ssrf(trimmed) {
                    return Err(format!("grpc.upstream_grpc_url {}", e));
                }
            }
        }
        Ok(())
    }
}
