//! Upstream forwarding for gRPC transport.
//!
//! Two modes:
//! - **gRPC-to-HTTP fallback**: Converts proto→JSON, sends via HTTP to the
//!   upstream URL, and converts the response back to proto. This lets gRPC
//!   clients work with existing HTTP MCP servers.
//! - **gRPC-to-gRPC**: When `upstream_grpc_url` is configured, forwards
//!   proto messages directly via a tonic client.

use std::sync::Arc;

use serde_json::Value;

use super::ProxyState;

/// Errors from upstream forwarding.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("HTTP upstream request failed: {0}")]
    HttpError(String),

    #[error("HTTP upstream response is not valid JSON: {0}")]
    JsonError(String),

    #[error("gRPC upstream error: {0}")]
    GrpcError(String),

    #[error("upstream URL not configured")]
    NoUpstream,
}

/// Forwards JSON-RPC requests to the upstream MCP server.
///
/// Supports HTTP fallback mode (convert JSON, POST to upstream_url) and
/// native gRPC forwarding when an upstream gRPC URL is configured.
#[derive(Clone)]
pub struct UpstreamForwarder {
    state: Arc<ProxyState>,
}

impl UpstreamForwarder {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }

    /// Forward a JSON-RPC request (as `serde_json::Value`) to the upstream server.
    ///
    /// Currently uses HTTP fallback mode: serializes the JSON, POSTs to the
    /// upstream URL, and parses the response. This allows gRPC clients to
    /// work with any existing HTTP MCP server without modification.
    pub async fn forward_json(&self, json_req: &Value) -> Result<Value, UpstreamError> {
        self.forward_via_http(json_req).await
    }

    /// Forward via HTTP (gRPC-to-HTTP fallback).
    async fn forward_via_http(&self, json_req: &Value) -> Result<Value, UpstreamError> {
        let body = serde_json::to_vec(json_req)
            .map_err(|e| UpstreamError::HttpError(format!("Failed to serialize request: {}", e)))?;

        // Phase 20: Use gateway default backend if configured
        let upstream_url = if let Some(ref gw) = self.state.gateway {
            gw.route("")
                .map(|d| d.upstream_url)
                .unwrap_or_else(|| self.state.upstream_url.clone())
        } else {
            self.state.upstream_url.clone()
        };

        let response = self
            .state
            .http_client
            .post(&upstream_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| UpstreamError::HttpError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| UpstreamError::HttpError(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            // Try to parse error body as JSON, fall back to status code
            if let Ok(json_val) = serde_json::from_slice::<Value>(&response_bytes) {
                return Ok(json_val);
            }
            return Err(UpstreamError::HttpError(format!(
                "Upstream returned HTTP {}",
                status
            )));
        }

        serde_json::from_slice(&response_bytes).map_err(|e| {
            UpstreamError::JsonError(format!("Failed to parse upstream response: {}", e))
        })
    }
}
