// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

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
            } => write!(f, "all {attempts} fallback attempt(s) failed: {last_error}"),
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

use super::{FORWARDED_HEADERS, MAX_RESPONSE_BODY_BYTES};

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
    if upstream_url.trim().is_empty() {
        return Err(FallbackError::NoFallback);
    }

    // SECURITY (R239-PROXY-1, R240-IMP-008): Enforce HTTPS for upstream URLs.
    // Uses shared validation that also handles bracketed IPv6 like [::1]:8080.
    if let Err(reason) = super::validate_upstream_url_scheme(upstream_url) {
        tracing::warn!("Rejecting non-HTTPS upstream URL (only localhost HTTP is allowed)");
        return Err(FallbackError::AllFailed {
            attempts: 0,
            last_error: reason,
        });
    }

    // SECURITY (IMP-R118-009): Cap retries to prevent resource exhaustion.
    const MAX_FALLBACK_RETRIES: u32 = 10;
    let effective_retries = max_retries.min(MAX_FALLBACK_RETRIES);

    let mut last_error = String::new();

    for attempt in 0..=effective_retries {
        let mut request = client.post(upstream_url).timeout(timeout);

        // SECURITY (FIND-041-008): Only forward allowlisted headers to
        // prevent leaking internal/sensitive headers to upstream backends.
        for (key, value) in headers {
            let key_lower = key.as_str().to_lowercase();
            if FORWARDED_HEADERS
                .iter()
                .any(|&allowed| allowed == key_lower)
            {
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
                            "response body too large: {len} bytes (max {MAX_RESPONSE_BODY_BYTES})"
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
                            if response_body.len().saturating_add(chunk.len())
                                > MAX_RESPONSE_BODY_BYTES
                            {
                                last_error = format!(
                                    "response body too large: >{MAX_RESPONSE_BODY_BYTES} bytes (max {MAX_RESPONSE_BODY_BYTES})"
                                );
                                body_too_large = true;
                                break;
                            }
                            response_body.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            last_error = format!("response body read error: {e}");
                            body_too_large = true;
                            break;
                        }
                    }
                }
                // SECURITY (FIND-R44-003): Oversize responses are deterministic —
                // retrying yields the same result, wasting bandwidth (11×16MB).
                if body_too_large {
                    return Err(FallbackError::AllFailed {
                        attempts: attempt + 1,
                        last_error,
                    });
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
                last_error = format!("request error: {e}");
            }
        }
    }

    Err(FallbackError::AllFailed {
        // SECURITY (IMP-R118-015): Use saturating_add to prevent overflow.
        attempts: effective_retries.saturating_add(1),
        last_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // FallbackError Display tests
    // =========================================================================

    #[test]
    fn test_fallback_error_all_failed_display() {
        let err = FallbackError::AllFailed {
            attempts: 3,
            last_error: "connection refused".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("3 fallback attempt(s) failed"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_fallback_error_no_fallback_display() {
        let err = FallbackError::NoFallback;
        let display = format!("{err}");
        assert_eq!(display, "no fallback transports configured");
    }

    #[test]
    fn test_fallback_error_all_failed_single_attempt() {
        let err = FallbackError::AllFailed {
            attempts: 1,
            last_error: "timeout".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("1 fallback attempt(s) failed"));
    }

    #[test]
    fn test_fallback_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(FallbackError::NoFallback);
        assert!(err.to_string().contains("no fallback"));
    }

    // =========================================================================
    // FallbackResult struct tests
    // =========================================================================

    #[test]
    fn test_fallback_result_primary_success() {
        let result = FallbackResult {
            response: bytes::Bytes::from_static(b"ok"),
            transport_used: TransportProtocol::Http,
            fallback_attempts: 0,
            status: 200,
            negotiation_history: None,
        };
        assert_eq!(result.fallback_attempts, 0);
        assert_eq!(result.status, 200);
        assert!(result.negotiation_history.is_none());
    }

    #[test]
    fn test_fallback_result_after_retries() {
        let result = FallbackResult {
            response: bytes::Bytes::from_static(b"recovered"),
            transport_used: TransportProtocol::Http,
            fallback_attempts: 2,
            status: 200,
            negotiation_history: None,
        };
        assert_eq!(result.fallback_attempts, 2);
    }

    #[test]
    fn test_fallback_result_non_success_status() {
        let result = FallbackResult {
            response: bytes::Bytes::from_static(b"error"),
            transport_used: TransportProtocol::Http,
            fallback_attempts: 0,
            status: 500,
            negotiation_history: None,
        };
        assert_eq!(result.status, 500);
    }

    // =========================================================================
    // forward_with_fallback edge case tests (async)
    // =========================================================================

    #[tokio::test]
    async fn test_forward_with_fallback_empty_url_returns_no_fallback() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        let result = forward_with_fallback(
            &client,
            "",
            bytes::Bytes::new(),
            &headers,
            3,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(matches!(result, Err(FallbackError::NoFallback)));
    }

    #[tokio::test]
    async fn test_forward_with_fallback_whitespace_url_returns_no_fallback() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        let result = forward_with_fallback(
            &client,
            "   ",
            bytes::Bytes::new(),
            &headers,
            3,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(matches!(result, Err(FallbackError::NoFallback)));
    }

    #[tokio::test]
    async fn test_forward_with_fallback_retries_capped_at_max() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        // SECURITY (R239-PROXY-1): Use localhost HTTP (allowed by HTTPS enforcement)
        // with an unreachable port to test retry capping.
        let result = forward_with_fallback(
            &client,
            "http://127.0.0.1:1", // Unreachable port on localhost
            bytes::Bytes::from("{}"),
            &headers,
            100, // Request 100 retries
            std::time::Duration::from_millis(50),
        )
        .await;
        // Should be capped at MAX_FALLBACK_RETRIES (10) + 1 = 11
        if let Err(FallbackError::AllFailed { attempts, .. }) = result {
            assert!(
                attempts <= 11,
                "retries should be capped at MAX_FALLBACK_RETRIES + 1, got {attempts}"
            );
        } else {
            panic!("Expected AllFailed error");
        }
    }

    // =========================================================================
    // HTTPS enforcement tests (R239-PROXY-1)
    // =========================================================================

    #[tokio::test]
    async fn test_forward_rejects_non_local_http() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        let result = forward_with_fallback(
            &client,
            "http://example.com/api",
            bytes::Bytes::new(),
            &headers,
            0,
            std::time::Duration::from_secs(5),
        )
        .await;
        match result {
            Err(FallbackError::AllFailed { last_error, .. }) => {
                assert!(
                    last_error.contains("HTTPS required"),
                    "Expected HTTPS enforcement error, got: {last_error}"
                );
            }
            other => panic!("Expected AllFailed with HTTPS error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_forward_allows_localhost_http() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        // localhost HTTP should be allowed (will fail on connection, not scheme check)
        let result = forward_with_fallback(
            &client,
            "http://localhost:1",
            bytes::Bytes::new(),
            &headers,
            0,
            std::time::Duration::from_millis(50),
        )
        .await;
        // Should fail with connection error, NOT "HTTPS required"
        match result {
            Err(FallbackError::AllFailed { last_error, .. }) => {
                assert!(
                    !last_error.contains("HTTPS required"),
                    "localhost HTTP should be allowed, got: {last_error}"
                );
            }
            _ => {} // Connection might succeed on some systems — fine either way
        }
    }

    #[tokio::test]
    async fn test_forward_allows_https() {
        let client = reqwest::Client::new();
        let headers = reqwest::header::HeaderMap::new();
        // HTTPS should always be allowed (will fail on DNS/connection, not scheme check)
        let result = forward_with_fallback(
            &client,
            "https://192.0.2.1:1",
            bytes::Bytes::new(),
            &headers,
            0,
            std::time::Duration::from_millis(50),
        )
        .await;
        match result {
            Err(FallbackError::AllFailed { last_error, .. }) => {
                assert!(
                    !last_error.contains("HTTPS required"),
                    "HTTPS URLs should be allowed, got: {last_error}"
                );
            }
            _ => {}
        }
    }
}
