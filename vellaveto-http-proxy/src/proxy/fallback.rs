//! Upstream transport fallback logic.
//!
//! Provides a structural foundation for cross-transport fallback. The current
//! implementation supports HTTP-only forwarding with timeout-based retry.
//! Cross-transport fallback (e.g., gRPC → HTTP) is deferred to Phase 20
//! (Gateway Mode) when multiple upstream URLs will be available.

use std::fmt;
use vellaveto_types::TransportProtocol;

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
}

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

        // Forward relevant headers.
        for (key, value) in headers {
            request = request.header(key.clone(), value.clone());
        }

        match request.body(body.clone()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                match resp.bytes().await {
                    Ok(response_body) => {
                        return Ok(FallbackResult {
                            response: response_body,
                            transport_used: TransportProtocol::Http,
                            fallback_attempts: attempt,
                            status,
                        });
                    }
                    Err(e) => {
                        last_error = format!("response body read error: {}", e);
                    }
                }
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
