// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! gRPC interceptors for authentication and rate limiting.
//!
//! These interceptors run before the `McpGrpcService` handler, providing
//! the same auth and rate-limiting guarantees as the HTTP/WS transports.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tonic::{service::Interceptor, Request, Status};

use super::super::ProxyState;

/// Check if a string contains ASCII control characters or Unicode format characters.
///
/// SECURITY (FIND-R73-SRV-004, IMP-R126-002): Delegates to canonical
/// `has_dangerous_chars()` from vellaveto-types. Rejects ALL ASCII controls
/// (including \n, \r, \t) and Unicode format chars (zero-width, bidi overrides, BOM).
pub(crate) fn contains_dangerous_chars(s: &str) -> bool {
    vellaveto_types::has_dangerous_chars(s)
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

        // SECURITY (FIND-R155-GRPC-003): Use fetch_update with conditional increment
        // to prevent overflow wrap-to-zero resetting rate limit counter.
        // Parity with WS check_rate_limit (websocket/mod.rs:4236-4238).
        let limit = self.limit;
        let result = self
            .counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                if v >= limit {
                    None
                } else {
                    Some(v.saturating_add(1))
                }
            });
        drop(window);

        match result {
            Ok(_prev) => Ok(request),
            Err(_) => {
                tracing::warn!("gRPC rate limit exceeded (limit: {})", self.limit);
                Err(Status::resource_exhausted("Rate limit exceeded"))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // contains_dangerous_chars

    #[test]
    fn test_contains_dangerous_chars_clean_string() {
        assert!(!contains_dangerous_chars("hello-world_123"));
    }

    #[test]
    fn test_contains_dangerous_chars_null_byte() {
        assert!(contains_dangerous_chars("hello\x00world"));
    }

    #[test]
    fn test_contains_dangerous_chars_newline() {
        assert!(contains_dangerous_chars("hello\nworld"));
    }

    #[test]
    fn test_contains_dangerous_chars_tab() {
        assert!(contains_dangerous_chars("hello\tworld"));
    }

    #[test]
    fn test_contains_dangerous_chars_del() {
        assert!(contains_dangerous_chars("hello\x7Fworld"));
    }

    #[test]
    fn test_contains_dangerous_chars_zwsp() {
        assert!(contains_dangerous_chars("hello\u{200B}world"));
    }

    #[test]
    fn test_contains_dangerous_chars_bom() {
        assert!(contains_dangerous_chars("hello\u{FEFF}world"));
    }

    // extract_session_id

    #[test]
    fn test_extract_session_id_valid() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_MCP_SESSION_ID, "sess-abc".parse().unwrap());
        assert_eq!(extract_session_id(&m), Some("sess-abc".to_string()));
    }

    #[test]
    fn test_extract_session_id_missing() {
        assert_eq!(extract_session_id(&tonic::metadata::MetadataMap::new()), None);
    }

    #[test]
    fn test_extract_session_id_empty_rejected() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_MCP_SESSION_ID, "".parse().unwrap());
        assert_eq!(extract_session_id(&m), None);
    }

    #[test]
    fn test_extract_session_id_oversize_rejected() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_MCP_SESSION_ID, "s".repeat(257).parse().unwrap());
        assert_eq!(extract_session_id(&m), None);
    }

    #[test]
    fn test_extract_session_id_at_max_length_accepted() {
        let mut m = tonic::metadata::MetadataMap::new();
        let exact = "s".repeat(256);
        m.insert(METADATA_MCP_SESSION_ID, exact.parse().unwrap());
        assert_eq!(extract_session_id(&m), Some(exact));
    }

    // extract_or_generate_request_id

    #[test]
    fn test_extract_request_id_valid() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_REQUEST_ID, "req-456".parse().unwrap());
        assert_eq!(extract_or_generate_request_id(&m), "req-456");
    }

    #[test]
    fn test_extract_request_id_generates_uuid_when_missing() {
        let id = extract_or_generate_request_id(&tonic::metadata::MetadataMap::new());
        assert!(!id.is_empty());
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_extract_request_id_overlong_rejected_and_generated() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_REQUEST_ID, "r".repeat(129).parse().unwrap());
        let id = extract_or_generate_request_id(&m);
        assert_ne!(id.len(), 129);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_extract_request_id_at_max_length_accepted() {
        let mut m = tonic::metadata::MetadataMap::new();
        let exact = "r".repeat(128);
        m.insert(METADATA_REQUEST_ID, exact.parse().unwrap());
        assert_eq!(extract_or_generate_request_id(&m), exact);
    }

    // extract_agent_identity_token

    #[test]
    fn test_extract_agent_identity_token_valid() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_AGENT_IDENTITY, "eyJhbGci.payload.sig".parse().unwrap());
        assert_eq!(extract_agent_identity_token(&m), Some("eyJhbGci.payload.sig".to_string()));
    }

    #[test]
    fn test_extract_agent_identity_token_missing() {
        assert_eq!(extract_agent_identity_token(&tonic::metadata::MetadataMap::new()), None);
    }

    #[test]
    fn test_extract_agent_identity_token_empty_rejected() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_AGENT_IDENTITY, "".parse().unwrap());
        assert_eq!(extract_agent_identity_token(&m), None);
    }

    #[test]
    fn test_extract_agent_identity_token_overlong_rejected() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_AGENT_IDENTITY, "t".repeat(8193).parse().unwrap());
        assert_eq!(extract_agent_identity_token(&m), None);
    }

    #[test]
    fn test_extract_agent_identity_token_at_max_length_accepted() {
        let mut m = tonic::metadata::MetadataMap::new();
        let exact = "t".repeat(8192);
        m.insert(METADATA_AGENT_IDENTITY, exact.parse().unwrap());
        assert_eq!(extract_agent_identity_token(&m), Some(exact));
    }

    // RateLimitInterceptor

    #[test]
    fn test_rate_limit_interceptor_allows_under_limit() {
        let mut rl = RateLimitInterceptor::new(Some(10));
        for _ in 0..10 {
            assert!(rl.call(Request::new(())).is_ok());
        }
    }

    #[test]
    fn test_rate_limit_interceptor_rejects_at_limit() {
        let mut rl = RateLimitInterceptor::new(Some(5));
        for _ in 0..5 { assert!(rl.call(Request::new(())).is_ok()); }
        let r = rl.call(Request::new(()));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn test_rate_limit_interceptor_default_limit_is_100() {
        assert_eq!(RateLimitInterceptor::new(None).limit, 100);
    }

    #[test]
    fn test_rate_limit_interceptor_custom_limit() {
        assert_eq!(RateLimitInterceptor::new(Some(50)).limit, 50);
    }

    // extract_call_chain_from_metadata

    #[test]
    fn test_extract_call_chain_missing_metadata() {
        let limits = vellaveto_config::LimitsConfig::default();
        assert!(extract_call_chain_from_metadata(&tonic::metadata::MetadataMap::new(), &limits).is_empty());
    }

    #[test]
    fn test_extract_call_chain_valid_json() {
        let mut m = tonic::metadata::MetadataMap::new();
        let j = r#"[{"agent_id":"agent1","tool":"t","function":"f","timestamp":"2026-01-01T00:00:00Z"}]"#;
        m.insert(METADATA_UPSTREAM_AGENTS, j.parse().unwrap());
        let chain = extract_call_chain_from_metadata(&m, &vellaveto_config::LimitsConfig::default());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].agent_id, "agent1");
    }

    #[test]
    fn test_extract_call_chain_invalid_json_returns_empty() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_UPSTREAM_AGENTS, "not-json".parse().unwrap());
        assert!(extract_call_chain_from_metadata(&m, &vellaveto_config::LimitsConfig::default()).is_empty());
    }

    #[test]
    fn test_extract_call_chain_oversized_returns_empty() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert(METADATA_UPSTREAM_AGENTS, "x".repeat(9000).parse().unwrap());
        assert!(extract_call_chain_from_metadata(&m, &vellaveto_config::LimitsConfig::default()).is_empty());
    }

    #[test]
    fn test_extract_call_chain_exceeds_entry_limit_returns_empty() {
        let mut m = tonic::metadata::MetadataMap::new();
        let mut entries = Vec::new();
        for i in 0..21 {
            entries.push(format!(r#"{{"agent_id":"a{i}","tool":"t","function":"f","timestamp":"2026-01-01T00:00:00Z"}}"#));
        }
        m.insert(METADATA_UPSTREAM_AGENTS, format!("[{}]", entries.join(",")).parse().unwrap());
        assert!(extract_call_chain_from_metadata(&m, &vellaveto_config::LimitsConfig::default()).is_empty());
    }

    // Metadata constants

    #[test]
    fn test_metadata_constants_are_lowercase() {
        assert_eq!(METADATA_AUTHORIZATION, "authorization");
        assert_eq!(METADATA_MCP_SESSION_ID, "mcp-session-id");
        assert_eq!(METADATA_AGENT_IDENTITY, "x-agent-identity");
        assert_eq!(METADATA_UPSTREAM_AGENTS, "x-upstream-agents");
        assert_eq!(METADATA_REQUEST_ID, "x-request-id");
        assert_eq!(METADATA_TRACEPARENT, "traceparent");
        assert_eq!(METADATA_TRACESTATE, "tracestate");
    }

    // extract_trace_context_from_metadata

    #[test]
    fn test_extract_trace_context_valid_traceparent() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".parse().unwrap());
        let ctx = extract_trace_context_from_metadata(&m);
        assert_eq!(ctx.trace_id, Some("0af7651916cd43dd8448eb211c80319c".to_string()));
    }

    #[test]
    fn test_extract_trace_context_missing_generates_id() {
        let ctx = extract_trace_context_from_metadata(&tonic::metadata::MetadataMap::new());
        assert!(ctx.trace_id.is_some());
        assert_eq!(ctx.trace_id.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_extract_trace_context_invalid_traceparent_generates_fresh() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("traceparent", "garbage".parse().unwrap());
        assert!(extract_trace_context_from_metadata(&m).trace_id.is_some());
    }

    #[test]
    fn test_extract_trace_context_with_tracestate() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".parse().unwrap());
        m.insert("tracestate", "vendor1=value1,vendor2=value2".parse().unwrap());
        assert!(extract_trace_context_from_metadata(&m).trace_state.is_some());
    }

    #[test]
    fn test_extract_trace_context_overlong_tracestate_ignored() {
        let mut m = tonic::metadata::MetadataMap::new();
        m.insert("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".parse().unwrap());
        m.insert("tracestate", "x".repeat(1000).parse().unwrap());
        assert!(extract_trace_context_from_metadata(&m).trace_state.is_none());
    }
}
