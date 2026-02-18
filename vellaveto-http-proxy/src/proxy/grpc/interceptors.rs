//! gRPC interceptors for authentication and rate limiting.
//!
//! These interceptors run before the `McpGrpcService` handler, providing
//! the same auth and rate-limiting guarantees as the HTTP/WS transports.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tonic::{service::Interceptor, Request, Status};

use super::super::ProxyState;

/// gRPC metadata key names (matching HTTP header semantics).
pub const METADATA_AUTHORIZATION: &str = "authorization";
pub const METADATA_MCP_SESSION_ID: &str = "mcp-session-id";
pub const METADATA_AGENT_IDENTITY: &str = "x-agent-identity";
pub const METADATA_UPSTREAM_AGENTS: &str = "x-upstream-agents";
pub const METADATA_REQUEST_ID: &str = "x-request-id";

/// Authentication interceptor for gRPC requests.
///
/// Extracts the `authorization` metadata key and validates against the
/// configured API key using constant-time SHA-256 comparison (matching
/// the pattern from `proxy/auth.rs`).
#[derive(Clone)]
pub struct AuthInterceptor {
    state: Arc<ProxyState>,
}

impl AuthInterceptor {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        // When OAuth is configured, it handles auth via JWTs — defer to service layer
        if self.state.oauth.is_some() {
            return Ok(request);
        }

        let api_key = match &self.state.api_key {
            Some(key) => key,
            None => return Ok(request), // No key configured (--allow-anonymous)
        };

        let auth_value = request
            .metadata()
            .get(METADATA_AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        match auth_value {
            Some(h) if h.len() > 7 && h[..7].eq_ignore_ascii_case("bearer ") => {
                let token = &h[7..];
                // SECURITY: Hash before comparing to prevent length oracle (FIND-008 pattern).
                use sha2::{Digest, Sha256};
                use subtle::ConstantTimeEq;
                let token_hash = Sha256::digest(token.as_bytes());
                let key_hash = Sha256::digest(api_key.as_bytes());
                if token_hash.ct_eq(&key_hash).into() {
                    Ok(request)
                } else {
                    Err(Status::unauthenticated("Invalid API key"))
                }
            }
            _ => Err(Status::unauthenticated("Authentication required")),
        }
    }
}

/// Extract the MCP session ID from gRPC metadata.
///
/// Returns `None` if the metadata key is not present or not valid UTF-8.
pub fn extract_session_id(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get(METADATA_MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .map(|s| s.to_string())
}

/// gRPC metadata key for W3C traceparent propagation (Phase 28).
pub const METADATA_TRACEPARENT: &str = "traceparent";
/// gRPC metadata key for W3C tracestate propagation (Phase 28).
pub const METADATA_TRACESTATE: &str = "tracestate";

/// Extract W3C Trace Context from gRPC metadata (Phase 28).
///
/// Parses `traceparent` and `tracestate` metadata keys. If `traceparent` is
/// missing or invalid, generates a new trace context (fail-open for observability).
pub fn extract_trace_context_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> vellaveto_audit::observability::TraceContext {
    let traceparent = metadata
        .get(METADATA_TRACEPARENT)
        .and_then(|v| v.to_str().ok());

    let mut ctx = match traceparent {
        Some(tp) => {
            vellaveto_audit::observability::TraceContext::parse_traceparent(tp).unwrap_or_default()
        }
        None => vellaveto_audit::observability::TraceContext::default(),
    };

    ctx.ensure_trace_id();

    // SECURITY (FIND-R44-009): Reject tracestate exceeding W3C 512-byte limit
    if let Some(ts) = metadata
        .get(METADATA_TRACESTATE)
        .and_then(|v| v.to_str().ok())
    {
        if !ts.is_empty() && ts.len() <= vellaveto_audit::observability::MAX_TRACESTATE_BYTES {
            ctx = ctx.with_parsed_tracestate(ts);
        }
    }

    ctx
}

/// Extract the request ID from gRPC metadata, or generate one.
pub fn extract_or_generate_request_id(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get(METADATA_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128 && !s.chars().any(|c| c.is_control()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Default gRPC rate limit: requests per second.
const DEFAULT_GRPC_RATE_LIMIT: u64 = 100;

/// Rate limiting interceptor for gRPC requests.
///
/// SECURITY (FIND-R53-GRPC-005): Provides per-service rate limiting for
/// gRPC calls, matching the WS transport's `message_rate_limit` (websocket/mod.rs:54).
/// Uses a simple counter-per-second window like the WS handler.
#[derive(Clone)]
pub struct RateLimitInterceptor {
    counter: Arc<AtomicU64>,
    window_start: Arc<Mutex<Instant>>,
    limit: u64,
}

impl RateLimitInterceptor {
    pub fn new(limit: Option<u64>) -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(0)),
            window_start: Arc::new(Mutex::new(Instant::now())),
            limit: limit.unwrap_or(DEFAULT_GRPC_RATE_LIMIT),
        }
    }
}

impl Interceptor for RateLimitInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        // Check/reset window — fail-closed on poisoned lock
        let should_reset = self
            .window_start
            .lock()
            .map(|start| start.elapsed().as_secs() >= 1)
            .unwrap_or(true);

        if should_reset {
            self.counter.store(0, Ordering::SeqCst);
            if let Ok(mut start) = self.window_start.lock() {
                *start = Instant::now();
            }
        }

        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        if count >= self.limit {
            tracing::warn!(
                "gRPC rate limit exceeded: {} requests in window (limit: {})",
                count,
                self.limit
            );
            return Err(Status::resource_exhausted("Rate limit exceeded"));
        }

        Ok(request)
    }
}
