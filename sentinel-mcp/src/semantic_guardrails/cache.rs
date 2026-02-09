//! LRU cache with TTL for semantic guardrails evaluations (Phase 12).
//!
//! Provides a thread-safe evaluation cache that follows the OPA client pattern
//! from `sentinel-server/src/opa.rs`. Cache entries expire after a configurable
//! TTL to ensure policy changes take effect.
//!
//! # Features
//!
//! - LRU eviction when at capacity
//! - TTL-based expiration
//! - Thread-safe via `RwLock`
//! - SHA-256 based cache keys for determinism
//! - Statistics tracking
//!
//! # Example
//!
//! ```rust
//! use sentinel_mcp::semantic_guardrails::cache::{EvaluationCache, CacheConfig};
//! use sentinel_mcp::semantic_guardrails::evaluator::LlmEvaluation;
//!
//! let config = CacheConfig::default();
//! let cache = EvaluationCache::new(config);
//!
//! // Store an evaluation
//! let key = cache.compute_key("fs", "read", &serde_json::json!({"path": "/tmp"}), &[]);
//! cache.put(&key, LlmEvaluation::allow());
//!
//! // Retrieve it
//! if let Some(cached) = cache.get(&key) {
//!     println!("Cache hit: {:?}", cached);
//! }
//! ```

use crate::semantic_guardrails::evaluator::LlmEvaluation;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for the evaluation cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache.
    /// Default: 10,000
    #[serde(default = "default_max_size")]
    pub max_size: usize,

    /// Time-to-live for cache entries in seconds.
    /// Default: 300 (5 minutes)
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,

    /// Whether caching is enabled.
    /// Default: true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_max_size() -> usize {
    10_000
}

fn default_ttl_secs() -> u64 {
    300
}

fn default_enabled() -> bool {
    true
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: default_max_size(),
            ttl_secs: default_ttl_secs(),
            enabled: default_enabled(),
        }
    }
}

impl CacheConfig {
    /// Creates a disabled cache configuration.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_size == 0 && self.enabled {
            return Err("max_size must be > 0 when cache is enabled".to_string());
        }
        if self.max_size > 1_000_000 {
            return Err("max_size cannot exceed 1,000,000".to_string());
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// CACHED ENTRY
// ═══════════════════════════════════════════════════

/// A cached evaluation entry with expiration time.
#[derive(Debug, Clone)]
struct CachedEntry {
    /// The cached evaluation result.
    evaluation: LlmEvaluation,
    /// When this entry expires.
    expires_at: Instant,
}

impl CachedEntry {
    /// Returns true if this entry has expired.
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

// ═══════════════════════════════════════════════════
// CACHE STATISTICS
// ═══════════════════════════════════════════════════

/// Statistics about cache usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of expired entries encountered.
    pub expirations: u64,
    /// Current number of entries in cache.
    pub size: usize,
    /// Maximum cache size.
    pub max_size: usize,
    /// Cache hit rate (0.0 to 1.0).
    pub hit_rate: f64,
}

// ═══════════════════════════════════════════════════
// EVALUATION CACHE
// ═══════════════════════════════════════════════════

/// Thread-safe LRU cache for LLM evaluations.
///
/// Uses `RwLock` to allow concurrent reads while serializing writes.
/// Entries expire after the configured TTL.
pub struct EvaluationCache {
    config: CacheConfig,
    cache: Arc<RwLock<LruCache<String, CachedEntry>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    expirations: AtomicU64,
}

impl EvaluationCache {
    /// Creates a new evaluation cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        let size = if config.enabled && config.max_size > 0 {
            NonZeroUsize::new(config.max_size).expect("max_size > 0")
        } else {
            NonZeroUsize::new(1).expect("1 is non-zero")
        };

        Self {
            config,
            cache: Arc::new(RwLock::new(LruCache::new(size))),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            expirations: AtomicU64::new(0),
        }
    }

    /// Creates a disabled cache (no-op operations).
    pub fn disabled() -> Self {
        Self::new(CacheConfig::disabled())
    }

    /// Computes a cache key from the input components.
    ///
    /// Uses SHA-256 to create a deterministic key from:
    /// - Tool name
    /// - Function name
    /// - Parameters (canonicalized JSON)
    /// - NL policies
    pub fn compute_key(
        &self,
        tool: &str,
        function: &str,
        parameters: &serde_json::Value,
        nl_policies: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(tool.as_bytes());
        hasher.update(b":");
        hasher.update(function.as_bytes());
        hasher.update(b":");

        // Canonicalize parameters for consistent hashing
        if let Ok(canonical) = serde_json_canonicalizer::to_string(parameters) {
            hasher.update(canonical.as_bytes());
        } else {
            hasher.update(parameters.to_string().as_bytes());
        }

        hasher.update(b":");
        for policy in nl_policies {
            hasher.update(policy.as_bytes());
            hasher.update(b"|");
        }

        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Retrieves a cached evaluation if present and not expired.
    ///
    /// Returns `None` if:
    /// - Caching is disabled
    /// - Key not found
    /// - Entry has expired
    pub fn get(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Use blocking read for sync compatibility
        let cache = self.cache.blocking_read();
        if let Some(entry) = cache.peek(key) {
            if entry.is_expired() {
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            let mut eval = entry.evaluation.clone();
            eval.from_cache = true;
            Some(eval)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Retrieves a cached evaluation asynchronously.
    pub async fn get_async(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let cache = self.cache.read().await;
        if let Some(entry) = cache.peek(key) {
            if entry.is_expired() {
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            self.hits.fetch_add(1, Ordering::Relaxed);
            let mut eval = entry.evaluation.clone();
            eval.from_cache = true;
            Some(eval)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Stores an evaluation in the cache.
    ///
    /// If caching is disabled or TTL is 0, this is a no-op.
    pub fn put(&self, key: &str, evaluation: LlmEvaluation) {
        if !self.config.enabled || self.config.ttl_secs == 0 {
            return;
        }

        let entry = CachedEntry {
            evaluation,
            expires_at: Instant::now() + Duration::from_secs(self.config.ttl_secs),
        };

        let mut cache = self.cache.blocking_write();
        cache.put(key.to_string(), entry);
    }

    /// Stores an evaluation asynchronously.
    pub async fn put_async(&self, key: &str, evaluation: LlmEvaluation) {
        if !self.config.enabled || self.config.ttl_secs == 0 {
            return;
        }

        let entry = CachedEntry {
            evaluation,
            expires_at: Instant::now() + Duration::from_secs(self.config.ttl_secs),
        };

        let mut cache = self.cache.write().await;
        cache.put(key.to_string(), entry);
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            return None;
        }

        let mut cache = self.cache.blocking_write();
        cache.pop(key).map(|e| e.evaluation)
    }

    /// Removes an entry asynchronously.
    pub async fn remove_async(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            return None;
        }

        let mut cache = self.cache.write().await;
        cache.pop(key).map(|e| e.evaluation)
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        let mut cache = self.cache.blocking_write();
        cache.clear();
    }

    /// Clears all entries asynchronously.
    pub async fn clear_async(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Returns the current number of entries in the cache.
    pub fn len(&self) -> usize {
        let cache = self.cache.blocking_read();
        cache.len()
    }

    /// Returns the current number of entries asynchronously.
    pub async fn len_async(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            expirations: self.expirations.load(Ordering::Relaxed),
            size: self.len(),
            max_size: self.config.max_size,
            hit_rate,
        }
    }

    /// Returns cache statistics asynchronously.
    pub async fn stats_async(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            expirations: self.expirations.load(Ordering::Relaxed),
            size: self.len_async().await,
            max_size: self.config.max_size,
            hit_rate,
        }
    }

    /// Resets cache statistics.
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.expirations.store(0, Ordering::Relaxed);
    }

    /// Returns the cache configuration.
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Removes expired entries from the cache.
    ///
    /// This is an O(n) operation and should be called periodically,
    /// not on every access.
    pub async fn evict_expired(&self) {
        if !self.config.enabled {
            return;
        }

        let mut cache = self.cache.write().await;
        let mut expired_keys = Vec::new();

        // Collect expired keys (can't modify during iteration)
        for (key, entry) in cache.iter() {
            if entry.is_expired() {
                expired_keys.push(key.clone());
            }
        }

        // Remove expired entries
        for key in expired_keys {
            cache.pop(&key);
            self.expirations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Clone for EvaluationCache {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cache: Arc::clone(&self.cache),
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
            misses: AtomicU64::new(self.misses.load(Ordering::Relaxed)),
            expirations: AtomicU64::new(self.expirations.load(Ordering::Relaxed)),
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cache() -> EvaluationCache {
        EvaluationCache::new(CacheConfig {
            max_size: 100,
            ttl_secs: 60,
            enabled: true,
        })
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.max_size, 10_000);
        assert_eq!(config.ttl_secs, 300);
        assert!(config.enabled);
    }

    #[test]
    fn test_cache_config_validation() {
        let config = CacheConfig {
            max_size: 0,
            enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = CacheConfig {
            max_size: 2_000_000,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = CacheConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_cache_put_and_get() {
        let cache = test_cache();
        let key = cache.compute_key("fs", "read", &serde_json::json!({}), &[]);

        assert!(cache.get(&key).is_none());

        cache.put(&key, LlmEvaluation::allow());

        let cached = cache.get(&key);
        assert!(cached.is_some());
        assert!(cached.unwrap().from_cache);
    }

    #[test]
    fn test_cache_key_determinism() {
        let cache = test_cache();
        let params = serde_json::json!({"path": "/tmp/foo", "mode": "r"});

        let key1 = cache.compute_key("fs", "read", &params, &["no deletion".to_string()]);
        let key2 = cache.compute_key("fs", "read", &params, &["no deletion".to_string()]);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_uniqueness() {
        let cache = test_cache();
        let params = serde_json::json!({"path": "/tmp"});

        let key1 = cache.compute_key("fs", "read", &params, &[]);
        let key2 = cache.compute_key("fs", "write", &params, &[]);
        let key3 = cache.compute_key("fs", "read", &params, &["policy".to_string()]);

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_cache_disabled() {
        let cache = EvaluationCache::disabled();
        let key = "test_key";

        cache.put(key, LlmEvaluation::allow());
        assert!(cache.get(key).is_none());
    }

    #[test]
    fn test_cache_remove() {
        let cache = test_cache();
        let key = "test_key";

        cache.put(key, LlmEvaluation::allow());
        assert!(cache.get(key).is_some());

        cache.remove(key);
        assert!(cache.get(key).is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = test_cache();

        cache.put("key1", LlmEvaluation::allow());
        cache.put("key2", LlmEvaluation::allow());
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats() {
        let cache = test_cache();
        let key = "test_key";

        // Miss
        cache.get(key);

        // Put and hit
        cache.put(key, LlmEvaluation::allow());
        cache.get(key);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_stats_reset() {
        let cache = test_cache();
        cache.put("key", LlmEvaluation::allow());
        cache.get("key");
        cache.get("nonexistent");

        cache.reset_stats();
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = EvaluationCache::new(CacheConfig {
            max_size: 2,
            ttl_secs: 60,
            enabled: true,
        });

        cache.put("key1", LlmEvaluation::allow());
        cache.put("key2", LlmEvaluation::allow());
        cache.put("key3", LlmEvaluation::allow()); // Should evict key1

        assert!(cache.get("key1").is_none());
        assert!(cache.get("key2").is_some());
        assert!(cache.get("key3").is_some());
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let cache = EvaluationCache::new(CacheConfig {
            max_size: 100,
            ttl_secs: 0, // Immediate expiration (actually disables caching)
            enabled: true,
        });

        cache.put("key", LlmEvaluation::allow());
        // With ttl_secs = 0, put is a no-op
        assert!(cache.get("key").is_none());
    }

    #[test]
    fn test_cache_clone() {
        let cache1 = test_cache();
        cache1.put("key", LlmEvaluation::allow());

        let cache2 = cache1.clone();
        assert!(cache2.get("key").is_some());
    }

    #[tokio::test]
    async fn test_cache_async_operations() {
        let cache = test_cache();
        let key = "async_key";

        cache.put_async(key, LlmEvaluation::allow()).await;
        let cached = cache.get_async(key).await;
        assert!(cached.is_some());

        let len = cache.len_async().await;
        assert_eq!(len, 1);

        cache.remove_async(key).await;
        assert!(cache.get_async(key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_evict_expired() {
        use std::time::Duration;

        let cache = EvaluationCache::new(CacheConfig {
            max_size: 100,
            ttl_secs: 1, // 1 second TTL
            enabled: true,
        });

        cache.put_async("key", LlmEvaluation::allow()).await;
        assert!(cache.get_async("key").await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Entry should be expired but still in cache until eviction
        cache.evict_expired().await;

        assert!(cache.len_async().await == 0);
    }
}
