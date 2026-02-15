//! Upstream transport fallback logic.
//!
//! Provides a structural foundation for cross-transport fallback. The current
//! implementation supports HTTP-only forwarding with timeout-based retry.
//! Cross-transport fallback (e.g., gRPC → HTTP) is deferred to Phase 20
//! (Gateway Mode) when multiple upstream URLs will be available.

use std::fmt;
use vellaveto_types::{FallbackNegotiationHistory, TransportProtocol};

/// Errors returned by fallback forwarding.
#[derive(Debug)]
pub enum FallbackError {
    /// All configured transports failed after retries.
    AllFailed { attempts: u32, last_error: String },
    /// No fallback transports are configured.
    NoFallback,
}

impl fmt::Display for FallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllFailed {
                attempts,
                last_error,
            } => write!(
                f,
                "all {} fallback attempt(s) failed: {}",
                attempts, last_error
            ),
            Self::NoFallback => write!(f, "no fallback transports configured"),
        }
    }
}

impl std::error::Error for FallbackError {}

/// Result of a successful fallback attempt.
#[derive(Debug)]
pub struct FallbackResult {
    /// The raw response bytes from the upstream.
    pub response: bytes::Bytes,
    /// The transport protocol that successfully handled the request.
    pub transport_used: TransportProtocol,
    /// Number of fallback attempts before success (0 = primary succeeded).
    pub fallback_attempts: u32,
    /// HTTP status code from the upstream response.
    pub status: u16,
    /// Cross-transport fallback negotiation history (Phase 29).
    /// `None` for simple HTTP-only forwarding (backward compatible).
    pub negotiation_history: Option<FallbackNegotiationHistory>,
}

/// Maximum response body size from upstream (16 MB). FIND-R42-020.
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// SECURITY (FIND-041-008): Allowlist of headers forwarded to upstream.
/// Only these headers are forwarded to prevent leaking internal/sensitive
/// headers (e.g., authorization, cookies) to upstream backends.
const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "user-agent",
    "traceparent",
    "tracestate",
    "x-request-id",
];

/// Forward a request to the upstream with timeout-based retry.
///
/// This is the foundational fallback function. Currently only supports HTTP
/// transport. Cross-transport fallback (trying gRPC, then WebSocket, then
/// HTTP) will be added in Phase 20 when `upstream_priorities` contains
/// multiple transport URLs.
pub async fn forward_with_fallback(
    client: &reqwest::Client,
    upstream_url: &str,
    body: bytes::Bytes,
    headers: &reqwest::header::HeaderMap,
    max_retries: u32,
    timeout: std::time::Duration,
) -> Result<FallbackResult, FallbackError> {
    let mut last_error = String::new();

    for attempt in 0..=max_retries {
        let mut request = client.post(upstream_url).timeout(timeout);

        // SECURITY (FIND-041-008): Only forward allowlisted headers to
        // prevent leaking internal/sensitive headers to upstream backends.
        for (key, value) in headers {
            let key_lower = key.as_str().to_lowercase();
            if FORWARDED_HEADERS.iter().any(|&allowed| allowed == key_lower) {
                request = request.header(key.clone(), value.clone());
            }
        }

        match request.body(body.clone()).send().await {
            Ok(mut resp) => {
                let status = resp.status().as_u16();

                // SECURITY (FIND-R42-020): Fast-reject if Content-Length exceeds limit.
                if let Some(len) = resp.content_length() {
                    if len as usize > MAX_RESPONSE_BODY_BYTES {
                        last_error = format!(
                            "response body too large: {} bytes (max {})",
                            len, MAX_RESPONSE_BODY_BYTES
                        );
                        continue;
                    }
                }

                // SECURITY (FIND-R42-020): Read body in chunks with bounded accumulation.
                // Prevents OOM from chunked-encoded responses that omit Content-Length.
                let capacity = std::cmp::min(
                    resp.content_length().unwrap_or(8192) as usize,
                    MAX_RESPONSE_BODY_BYTES,
                );
                let mut response_body = Vec::with_capacity(capacity);
                let mut body_too_large = false;
                loop {
                    match resp.chunk().await {
                        Ok(Some(chunk)) => {
                            if response_body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
                                last_error = format!(
                                    "response body too large: >{} bytes (max {})",
                                    MAX_RESPONSE_BODY_BYTES, MAX_RESPONSE_BODY_BYTES
                                );
                                body_too_large = true;
                                break;
                            }
                            response_body.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            last_error = format!("response body read error: {}", e);
                            body_too_large = true;
                            break;
                        }
                    }
                }
                if body_too_large {
                    continue;
                }

                return Ok(FallbackResult {
                    response: bytes::Bytes::from(response_body),
                    transport_used: TransportProtocol::Http,
                    fallback_attempts: attempt,
                    status,
                    negotiation_history: None,
                });
            }
            Err(e) => {
                last_error = format!("request error: {}", e);
            }
        }
    }

    Err(FallbackError::AllFailed {
        attempts: max_retries + 1,
        last_error,
    })
}
