//! Shield HTTP proxy error types.

use thiserror::Error;

/// Errors from the shield HTTP proxy layer.
#[derive(Debug, Error)]
pub enum ShieldProxyError {
    /// Traffic padding configuration error.
    #[error("traffic padding error: {0}")]
    TrafficPadding(String),

    /// Request splitting error.
    #[error("request splitting error: {0}")]
    RequestSplitting(String),

    /// Proxy transport error.
    #[error("transport error: {0}")]
    Transport(String),
}
