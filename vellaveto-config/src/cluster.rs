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
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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

/// SECURITY (FIND-R112-019): Custom Debug impl to redact redis_url which may
/// contain embedded credentials (e.g., redis://user:password@host:6379).
impl std::fmt::Debug for ClusterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterConfig")
            .field("enabled", &self.enabled)
            .field("backend", &self.backend)
            .field("redis_url", &"[REDACTED]")
            .field("redis_pool_size", &self.redis_pool_size)
            .field("key_prefix", &self.key_prefix)
            .finish()
    }
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
    ///
    /// SECURITY (FIND-R111-005): This method is the single authoritative validation
    /// path for `ClusterConfig`. All validation logic lives here; callers must not
    /// duplicate checks inline (to avoid constant/logic divergence).
    pub fn validate(&self) -> Result<(), String> {
        // Validate backend
        if !VALID_CLUSTER_BACKENDS.contains(&self.backend.as_str()) {
            return Err(format!(
                "cluster.backend must be one of {:?}, got '{}'",
                VALID_CLUSTER_BACKENDS, self.backend
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.backend) {
            return Err("cluster.backend contains control or format characters".to_string());
        }

        // Validate redis_url
        if self.redis_url.len() > MAX_CLUSTER_URL_LENGTH {
            return Err(format!(
                "cluster.redis_url length {} exceeds maximum {}",
                self.redis_url.len(),
                MAX_CLUSTER_URL_LENGTH
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.redis_url) {
            return Err("cluster.redis_url contains control or format characters".to_string());
        }
        // SECURITY (FIND-R111-005): When backend="redis", redis_url must be provided.
        // An empty redis_url with a redis backend would silently use no connection,
        // causing all cluster operations to fail at runtime instead of at startup.
        if self.backend == "redis" && self.redis_url.is_empty() {
            return Err("cluster.redis_url must not be empty when backend is 'redis'".to_string());
        }
        // SECURITY (FIND-R110-CFG-002): Reject non-Redis URL schemes to prevent
        // SSRF via arbitrary protocol URLs (e.g., file://, http://).
        if !self.redis_url.is_empty()
            && !self.redis_url.starts_with("redis://")
            && !self.redis_url.starts_with("rediss://")
        {
            return Err("cluster.redis_url must use redis:// or rediss:// scheme".to_string());
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
        if vellaveto_types::has_dangerous_chars(&self.key_prefix) {
            return Err("cluster.key_prefix contains control or format characters".to_string());
        }
        // SECURITY (FIND-R184-005): Reject Redis hash tag characters. A key_prefix
        // containing {..} forces all keys to hash to the same cluster slot, creating
        // a hot-key DoS condition in Redis Cluster deployments.
        if self.key_prefix.contains('{') || self.key_prefix.contains('}') {
            return Err(
                "cluster.key_prefix must not contain '{' or '}' (Redis hash tag characters)"
                    .to_string(),
            );
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
