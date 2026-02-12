//! Distributed clustering configuration — Redis backend and local fallback.

use serde::{Deserialize, Serialize};

/// Distributed clustering configuration (P3.4).
///
/// When enabled, multiple Sentinel instances share approval and rate limit
/// state via Redis. When disabled (default), `LocalBackend` preserves
/// single-instance behavior exactly.
///
/// # TOML Example
///
/// ```toml
/// [cluster]
/// enabled = true
/// backend = "redis"
/// redis_url = "redis://sentinel-redis:6379"
/// redis_pool_size = 8
/// key_prefix = "sentinel:"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClusterConfig {
    /// Enable clustering. When false (default), local in-process state is used.
    #[serde(default)]
    pub enabled: bool,

    /// Backend type: "local" or "redis". Default: "local".
    #[serde(default = "default_cluster_backend")]
    pub backend: String,

    /// Redis connection URL. Only used when backend = "redis".
    /// Default: "redis://127.0.0.1:6379"
    #[serde(default = "default_cluster_redis_url")]
    pub redis_url: String,

    /// Redis connection pool size. Default: 8.
    #[serde(default = "default_cluster_pool_size")]
    pub redis_pool_size: usize,

    /// Key prefix for Redis keys. Default: "sentinel:".
    /// Allows multiple Sentinel deployments to share a Redis instance.
    #[serde(default = "default_cluster_key_prefix")]
    pub key_prefix: String,
}

fn default_cluster_backend() -> String {
    "local".to_string()
}

fn default_cluster_redis_url() -> String {
    "redis://127.0.0.1:6379".to_string()
}

fn default_cluster_pool_size() -> usize {
    8
}

fn default_cluster_key_prefix() -> String {
    "sentinel:".to_string()
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_cluster_backend(),
            redis_url: default_cluster_redis_url(),
            redis_pool_size: default_cluster_pool_size(),
            key_prefix: default_cluster_key_prefix(),
        }
    }
}
