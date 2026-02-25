//! Error types for the Vellaveto Kubernetes operator.

/// Unified error type for all operator operations.
#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    /// Kubernetes API error.
    #[error("Kubernetes API error: {0}")]
    Kube(#[source] kube::Error),

    /// Vellaveto server API error.
    #[error("Vellaveto API error: {0}")]
    Api(String),

    /// Configuration or environment error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// CRD spec validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// HTTP client error.
    #[error("HTTP client error: {0}")]
    Http(#[source] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[source] serde_json::Error),

    /// Target VellavetoCluster not found.
    #[error("Cluster not found: {0}")]
    ClusterNotFound(String),

    /// Finalizer management error.
    #[error("Finalizer error: {0}")]
    Finalizer(String),
}

impl From<kube::Error> for OperatorError {
    fn from(e: kube::Error) -> Self {
        OperatorError::Kube(e)
    }
}

impl From<reqwest::Error> for OperatorError {
    fn from(e: reqwest::Error) -> Self {
        OperatorError::Http(e)
    }
}

impl From<serde_json::Error> for OperatorError {
    fn from(e: serde_json::Error) -> Self {
        OperatorError::Serialization(e)
    }
}
