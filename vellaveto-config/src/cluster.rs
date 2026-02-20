//! Distributed clustering configuration — Redis backend and local fallback.

use serde::{Deserialize, Serialize};

/// Distributed clustering configuration (P3.4).
///
/// When enabled, multiple Vellaveto instances share approval and rate limit
/// state via Redis. When disabled (default), `LocalBackend` preserves
/// single-instance behavior exactly.
///
/// # TOML Example
///
/// ```toml
/// [cluster]
/// enabled = true
/// backend = "redis"
/// redis_url = "redis://vellaveto-redis:6379"
/// redis_pool_size = 8
/// key_prefix = "vellaveto:"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

    /// Key prefix for Redis keys. Default: "vellaveto:".
    /// Allows multiple Vellaveto deployments to share a Redis instance.
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
    "vellaveto:".to_string()
}

/// Check if a string contains ASCII or C1 control characters.
fn cluster_contains_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || (0x7F..=0x9F).contains(&b))
}

/// Maximum URL length for Redis connection string.
const MAX_CLUSTER_URL_LENGTH: usize = 2048;

/// Maximum key prefix length.
const MAX_CLUSTER_PREFIX_LENGTH: usize = 64;

/// Maximum Redis connection pool size.
const MAX_CLUSTER_REDIS_POOL_SIZE: usize = 512;

/// Valid cluster backend values.
const VALID_CLUSTER_BACKENDS: &[&str] = &["local", "redis"];

impl ClusterConfig {
    /// Validate cluster configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        // Validate backend
        if !VALID_CLUSTER_BACKENDS.contains(&self.backend.as_str()) {
            return Err(format!(
                "cluster.backend must be one of {:?}, got '{}'",
                VALID_CLUSTER_BACKENDS, self.backend
            ));
        }
        if cluster_contains_control_chars(&self.backend) {
            return Err("cluster.backend contains control characters".to_string());
        }

        // Validate redis_url
        if self.redis_url.len() > MAX_CLUSTER_URL_LENGTH {
            return Err(format!(
                "cluster.redis_url length {} exceeds maximum {}",
                self.redis_url.len(),
                MAX_CLUSTER_URL_LENGTH
            ));
        }
        if cluster_contains_control_chars(&self.redis_url) {
            return Err("cluster.redis_url contains control characters".to_string());
        }
        // SECURITY (FIND-R110-CFG-002): Reject non-Redis URL schemes to prevent
        // SSRF via arbitrary protocol URLs (e.g., file://, http://).
        if !self.redis_url.is_empty()
            && !self.redis_url.starts_with("redis://")
            && !self.redis_url.starts_with("rediss://")
        {
            return Err(
                "cluster.redis_url must use redis:// or rediss:// scheme".to_string(),
            );
        }

        // Validate redis_pool_size
        if self.redis_pool_size == 0 {
            return Err("cluster.redis_pool_size must be >= 1".to_string());
        }
        if self.redis_pool_size > MAX_CLUSTER_REDIS_POOL_SIZE {
            return Err(format!(
                "cluster.redis_pool_size {} exceeds maximum {}",
                self.redis_pool_size, MAX_CLUSTER_REDIS_POOL_SIZE
            ));
        }

        // Validate key_prefix
        if self.key_prefix.len() > MAX_CLUSTER_PREFIX_LENGTH {
            return Err(format!(
                "cluster.key_prefix length {} exceeds maximum {}",
                self.key_prefix.len(),
                MAX_CLUSTER_PREFIX_LENGTH
            ));
        }
        if cluster_contains_control_chars(&self.key_prefix) {
            return Err("cluster.key_prefix contains control characters".to_string());
        }

        Ok(())
    }
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
