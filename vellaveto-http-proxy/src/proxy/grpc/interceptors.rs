//! gRPC interceptors for authentication and rate limiting.
//!
//! These interceptors run before the `McpGrpcService` handler, providing
//! the same auth and rate-limiting guarantees as the HTTP/WS transports.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tonic::{service::Interceptor, Request, Status};

use super::super::ProxyState;

/// SECURITY (FIND-R54-009, FIND-R54-010): Check for Unicode format characters
/// that could bypass identity/session checks via invisible chars.
/// Mirrors `EvaluationContext::is_unicode_format_char()` from vellaveto-types.
pub(crate) fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}' |  // zero-width space, ZWNJ, ZWJ, LRM, RLM
        '\u{202A}'..='\u{202E}' |  // bidi overrides (LRE, RLE, PDF, LRO, RLO)
        '\u{2060}'..='\u{2069}' |  // word joiner, invisible separators, bidi isolates
        '\u{FEFF}'                  // BOM / zero-width no-break space
    )
}

/// Check if a string contains ASCII control characters (excluding JSON whitespace)
/// or Unicode format characters.
///
/// SECURITY: Rejects both ASCII controls (NUL, BEL, ESC, etc.) and Unicode
/// format chars (zero-width, bidi overrides, BOM) that could bypass security
/// checks via invisible character injection.
pub(crate) fn contains_dangerous_chars(s: &str) -> bool {
    s.chars().any(|c| {
        (c.is_control() && c != '\n' && c != '\r' && c != '\t') || is_unicode_format_char(c)
    })
}

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
/// Returns `None` if the metadata key is not present, not valid UTF-8,
/// or contains control/Unicode format characters (FIND-R54-009).
pub fn extract_session_id(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get(METADATA_MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 256 && !contains_dangerous_chars(s))
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
///
/// SECURITY (FIND-R54-010): Rejects IDs with control characters AND Unicode
/// format characters (zero-width, bidi overrides, BOM).
pub fn extract_or_generate_request_id(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get(METADATA_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128 && !contains_dangerous_chars(s))
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
        // SECURITY (FIND-R54-008): Hold mutex across window check + counter reset
        // to prevent TOCTOU race. Without this, two threads could both see
        // should_reset=true, both reset the counter, and lose requests between them.
        // Fail-closed on poisoned lock.
        let mut window = match self.window_start.lock() {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!("gRPC rate limiter mutex poisoned — fail-closed");
                return Err(Status::resource_exhausted("Rate limit exceeded"));
            }
        };

        if window.elapsed().as_secs() >= 1 {
            self.counter.store(0, Ordering::SeqCst);
            *window = Instant::now();
        }

        // Increment under lock to prevent TOCTOU between reset and count check.
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        drop(window);

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

/// Combined interceptor that runs authentication then rate limiting.
///
/// SECURITY (FIND-R54-001): Chains `AuthInterceptor` and `RateLimitInterceptor`
/// into a single interceptor for use with `McpServiceServer`. Auth runs first —
/// unauthenticated requests are rejected before consuming rate limit budget.
#[derive(Clone)]
pub struct CombinedInterceptor {
    auth: AuthInterceptor,
    rate_limit: RateLimitInterceptor,
}

impl CombinedInterceptor {
    pub fn new(auth: AuthInterceptor, rate_limit: RateLimitInterceptor) -> Self {
        Self { auth, rate_limit }
    }
}

impl Interceptor for CombinedInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let request = self.auth.call(request)?;
        self.rate_limit.call(request)
    }
}

/// Maximum size of x-upstream-agents metadata value in bytes.
const MAX_UPSTREAM_AGENTS_METADATA_BYTES: usize = 32768;

/// Extract the upstream call chain from gRPC metadata.
///
/// Parses the `x-upstream-agents` metadata key as a JSON array of
/// `CallChainEntry` objects, applying the same size and entry limits
/// as the HTTP header equivalent (call_chain.rs).
pub fn extract_call_chain_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
    limits: &vellaveto_config::LimitsConfig,
) -> Vec<vellaveto_types::CallChainEntry> {
    let raw = match metadata
        .get(METADATA_UPSTREAM_AGENTS)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s,
        None => return Vec::new(),
    };

    let max_bytes = limits
        .max_call_chain_header_bytes
        .min(MAX_UPSTREAM_AGENTS_METADATA_BYTES);
    if raw.len() > max_bytes {
        tracing::warn!(
            len = raw.len(),
            max = max_bytes,
            "gRPC x-upstream-agents metadata exceeds size limit"
        );
        return Vec::new();
    }

    match serde_json::from_str::<Vec<vellaveto_types::CallChainEntry>>(raw) {
        Ok(entries) if entries.len() <= limits.max_call_chain_length => entries,
        Ok(entries) => {
            tracing::warn!(
                count = entries.len(),
                max = limits.max_call_chain_length,
                "gRPC x-upstream-agents metadata exceeds entry limit"
            );
            Vec::new()
        }
        Err(e) => {
            tracing::warn!("gRPC x-upstream-agents metadata is not valid JSON: {}", e);
            Vec::new()
        }
    }
}

/// Extract the agent identity token from gRPC metadata.
///
/// Returns the raw JWT token string, or None if not present.
/// SECURITY (FIND-R54-GRPC-005): Rejects tokens with control/Unicode format chars.
pub fn extract_agent_identity_token(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get(METADATA_AGENT_IDENTITY)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 8192 && !contains_dangerous_chars(s))
        .map(|s| s.to_string())
}
