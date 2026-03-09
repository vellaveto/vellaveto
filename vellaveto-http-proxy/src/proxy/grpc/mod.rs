// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! gRPC transport for MCP JSON-RPC messages (Phase 17.2).
//!
//! Provides a tonic-based gRPC server that wraps JSON-RPC MCP messages in
//! Protocol Buffers and enforces the same policy evaluation, DLP scanning,
//! and injection detection as the HTTP and WebSocket transports.
//!
//! Security invariants:
//! - **Fail-closed**: Conversion errors, auth failures → gRPC error status.
//! - **Policy denials as JSON-RPC errors**: Policy denials return inside a
//!   successful gRPC response (matching HTTP/WS behavior).
//! - **Feature-gated**: All code behind `#[cfg(feature = "grpc")]`.

pub mod convert;
pub mod interceptors;
pub mod service;
#[cfg(test)]
pub mod tests;
pub mod upstream;

/// Generated protobuf types and service traits.
pub mod proto {
    tonic::include_proto!("mcp.v1");
}

use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use super::ProxyState;

/// Configuration for the gRPC transport server.
/// SECURITY (FIND-R55-GRPC-007): deny_unknown_fields prevents config injection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    /// Socket address to listen on (default: 127.0.0.1:50051).
    #[serde(default = "default_grpc_addr")]
    pub listen_addr: SocketAddr,

    /// Maximum inbound message size in bytes (default: 4 MB).
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Optional upstream gRPC URL for gRPC-to-gRPC forwarding.
    /// When `None`, falls back to HTTP forwarding via `ProxyState.upstream_url`.
    #[serde(default)]
    pub upstream_grpc_url: Option<String>,

    /// Enable gRPC health checking service (default: true).
    #[serde(default = "default_health_enabled")]
    pub health_enabled: bool,

    /// Maximum messages per second per stream connection (default: 100).
    /// SECURITY (FIND-R55-GRPC-010): Per-message rate limiting for streaming RPCs.
    /// Set to 0 for unlimited (not recommended in production).
    #[serde(default = "default_stream_message_rate_limit")]
    pub stream_message_rate_limit: u32,
}

/// FIND-R56-HTTP-005: Replaced runtime `.expect()` with a compile-time const
/// to eliminate panic potential in library code.
const DEFAULT_GRPC_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    50051,
);

fn default_grpc_addr() -> SocketAddr {
    DEFAULT_GRPC_ADDR
}

fn default_max_message_size() -> usize {
    4 * 1024 * 1024 // 4 MB
}

fn default_health_enabled() -> bool {
    true
}

fn default_stream_message_rate_limit() -> u32 {
    100
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_grpc_addr(),
            max_message_size: default_max_message_size(),
            upstream_grpc_url: None,
            health_enabled: true,
            stream_message_rate_limit: default_stream_message_rate_limit(),
        }
    }
}

/// Maximum allowed gRPC message size (256 MB).
const MAX_GRPC_MESSAGE_SIZE: usize = 256 * 1024 * 1024;

/// Maximum allowed stream message rate limit (10,000 msg/s).
const MAX_STREAM_MESSAGE_RATE_LIMIT: u32 = 10_000;

impl GrpcConfig {
    /// Validate the gRPC configuration for security constraints.
    ///
    /// SECURITY (R245-GRPC-1): Runtime GrpcConfig was constructed from CLI args
    /// without validation, bypassing config-level bounds. This method enforces:
    /// - max_message_size in [1, 256 MB]
    /// - upstream_grpc_url free of dangerous chars + SSRF-safe
    pub fn validate(&self) -> Result<(), String> {
        if self.max_message_size == 0 || self.max_message_size > MAX_GRPC_MESSAGE_SIZE {
            return Err(format!(
                "grpc max_message_size must be in [1, {}], got {}",
                MAX_GRPC_MESSAGE_SIZE, self.max_message_size
            ));
        }
        // SECURITY (R251-GRPC-1): Reject stream_message_rate_limit=0 (fail-closed).
        if self.stream_message_rate_limit == 0 {
            return Err("grpc stream_message_rate_limit must be > 0".to_string());
        }
        if self.stream_message_rate_limit > MAX_STREAM_MESSAGE_RATE_LIMIT {
            return Err(format!(
                "grpc stream_message_rate_limit must be <= {}, got {}",
                MAX_STREAM_MESSAGE_RATE_LIMIT, self.stream_message_rate_limit
            ));
        }
        if let Some(ref url) = self.upstream_grpc_url {
            if vellaveto_types::has_dangerous_chars(url) {
                return Err(
                    "grpc upstream_grpc_url contains control or format characters".to_string(),
                );
            }
            if !url.trim().is_empty() {
                vellaveto_types::validate_url_no_ssrf(url.trim())
                    .map_err(|e| format!("grpc upstream_grpc_url {e}"))?;
            }
        }
        Ok(())
    }
}

/// Start the gRPC server with the given proxy state and configuration.
///
/// The server runs until the `shutdown` token is cancelled. It shares
/// the same `ProxyState` as the HTTP/WebSocket server, so policy engine,
/// audit logger, session store, etc. are all the same instances.
pub async fn start_grpc_server(
    state: ProxyState,
    config: GrpcConfig,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use interceptors::{AuthInterceptor, CombinedInterceptor, RateLimitInterceptor};
    use proto::mcp_service_server::McpServiceServer;
    use service::McpGrpcService;

    // SECURITY (R245-GRPC-1): Validate config before use.
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            tracing::error!(error = %e, "gRPC config validation failed");
            e.into()
        })?;

    let state = Arc::new(state);
    let svc = McpGrpcService::new(state.clone(), config.stream_message_rate_limit);

    // SECURITY (FIND-R54-001): Wire auth + rate limit interceptors into gRPC server.
    // Previously McpServiceServer::new(svc) was used, making AuthInterceptor and
    // RateLimitInterceptor dead code — the entire gRPC transport was unauthenticated
    // and unrate-limited.
    let interceptor =
        CombinedInterceptor::new(AuthInterceptor::new(state), RateLimitInterceptor::new(None));

    let mut server_builder = tonic::transport::Server::builder();

    // Apply size limits first, then wrap with interceptor.
    let mcp_server = McpServiceServer::new(svc)
        .max_decoding_message_size(config.max_message_size)
        .max_encoding_message_size(config.max_message_size);
    let intercepted = tonic::service::interceptor::InterceptedService::new(mcp_server, interceptor);

    let router = if config.health_enabled {
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<McpServiceServer<McpGrpcService>>()
            .await;
        server_builder
            .add_service(health_service)
            .add_service(intercepted)
    } else {
        server_builder.add_service(intercepted)
    };

    tracing::info!(
        listen_addr = %config.listen_addr,
        max_message_size = config.max_message_size,
        health = config.health_enabled,
        "gRPC transport starting"
    );

    let shutdown_token = shutdown.clone();
    router
        .serve_with_shutdown(config.listen_addr, async move {
            shutdown_token.cancelled().await;
            tracing::info!("gRPC server shutting down");
        })
        .await?;

    Ok(())
}
