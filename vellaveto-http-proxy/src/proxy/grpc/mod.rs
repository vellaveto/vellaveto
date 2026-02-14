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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
}

fn default_grpc_addr() -> SocketAddr {
    "127.0.0.1:50051".parse().expect("valid default addr")
}

fn default_max_message_size() -> usize {
    4 * 1024 * 1024 // 4 MB
}

fn default_health_enabled() -> bool {
    true
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_grpc_addr(),
            max_message_size: default_max_message_size(),
            upstream_grpc_url: None,
            health_enabled: true,
        }
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
    use proto::mcp_service_server::McpServiceServer;
    use service::McpGrpcService;

    let svc = McpGrpcService::new(Arc::new(state));

    let mut server_builder = tonic::transport::Server::builder();

    let mcp_server = McpServiceServer::new(svc)
        .max_decoding_message_size(config.max_message_size)
        .max_encoding_message_size(config.max_message_size);

    let router = if config.health_enabled {
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<McpServiceServer<McpGrpcService>>()
            .await;
        server_builder
            .add_service(health_service)
            .add_service(mcp_server)
    } else {
        server_builder.add_service(mcp_server)
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
