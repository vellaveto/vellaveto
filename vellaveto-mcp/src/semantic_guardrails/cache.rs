//! LRU cache with TTL for semantic guardrails evaluations (Phase 12).
//!
//! Provides a thread-safe evaluation cache that follows the OPA client pattern
//! from `vellaveto-server/src/opa.rs`. Cache entries expire after a configurable
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
//! use vellaveto_mcp::semantic_guardrails::cache::{EvaluationCache, CacheConfig};
//! use vellaveto_mcp::semantic_guardrails::evaluator::LlmEvaluation;
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
#[serde(deny_unknown_fields)]
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

/// Fallback cache size when disabled or when max_size is 0.
const FALLBACK_CACHE_SIZE: NonZeroUsize = NonZeroUsize::MIN;

/// SECURITY (FIND-R69-001): Maximum TTL in seconds (7 days) to prevent
/// `Instant::now() + Duration` overflow panic on extreme config values.
const MAX_TTL_SECS: u64 = 7 * 24 * 3600;

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
        // SECURITY (FIND-R168-001): Reject TTL values exceeding MAX_TTL_SECS at
        // validation time rather than relying on runtime clamping. Fail-closed
        // principle: invalid config should be rejected, not silently adjusted.
        if self.ttl_secs > MAX_TTL_SECS {
            return Err(format!(
                "ttl_secs {} exceeds maximum of {} (7 days)",
                self.ttl_secs, MAX_TTL_SECS
            ));
        }
        // SECURITY (FIND-R168-002): ttl_secs=0 with enabled=true creates a
        // silent no-op cache where all put operations are skipped. Reject this
        // at validation time rather than logging a runtime warning.
        if self.ttl_secs == 0 && self.enabled {
            return Err("ttl_secs must be > 0 when cache is enabled".to_string());
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
#[serde(deny_unknown_fields)]
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
    ///
    /// Validates that the configuration is sensible (capacity > 0 when enabled,
    /// TTL > 0 when enabled). Invalid configurations are logged as warnings and
    /// the cache falls back to a safe default (disabled or capacity 1).
    pub fn new(config: CacheConfig) -> Self {
        // Validate configuration and warn on issues
        if config.enabled {
            if config.max_size == 0 {
                tracing::warn!(
                    "EvaluationCache: max_size is 0 with cache enabled — cache will use fallback capacity 1"
                );
            }
            if config.ttl_secs == 0 {
                tracing::warn!(
                    "EvaluationCache: ttl_secs is 0 with cache enabled — put operations will be no-ops"
                );
            }
        }

        // Use the configured max_size if valid, otherwise fall back to 1.
        // This avoids expect()/unwrap() per project no-panic policy.
        let size = if config.enabled && config.max_size > 0 {
            NonZeroUsize::new(config.max_size).unwrap_or(FALLBACK_CACHE_SIZE)
        } else {
            FALLBACK_CACHE_SIZE
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
    ///
    /// SECURITY (FIND-R213-001): Each field is length-prefixed with u64 LE bytes
    /// before the content to prevent delimiter-based collision attacks. Without
    /// length prefixing, tool="a:b" + function="c" would hash identically to
    /// tool="a" + function="b:c" because the concatenated byte stream is the same.
    pub fn compute_key(
        &self,
        tool: &str,
        function: &str,
        parameters: &serde_json::Value,
        nl_policies: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        Self::hash_field(&mut hasher, tool.as_bytes());
        Self::hash_field(&mut hasher, function.as_bytes());

        // Canonicalize parameters for consistent hashing
        if let Ok(canonical) = serde_json_canonicalizer::to_string(parameters) {
            Self::hash_field(&mut hasher, canonical.as_bytes());
        } else {
            Self::hash_field(&mut hasher, parameters.to_string().as_bytes());
        }

        // Length-prefix the policy count so [] and [""] produce different keys
        hasher.update((nl_policies.len() as u64).to_le_bytes());
        for policy in nl_policies {
            Self::hash_field(&mut hasher, policy.as_bytes());
        }

        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Write a length-prefixed field into the hasher.
    ///
    /// SECURITY (FIND-R213-001): Writes the field length as u64 LE bytes before
    /// the field content, preventing boundary-shift collisions. This matches the
    /// pattern used in `AuditLogger::hash_field()`.
    fn hash_field(hasher: &mut Sha256, data: &[u8]) {
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Retrieves a cached evaluation if present and not expired.
    ///
    /// Returns `None` if:
    /// - Caching is disabled
    /// - Key not found
    /// - Entry has expired
    ///
    /// SECURITY (FIND-028): Uses a write lock to atomically remove expired
    /// entries on access. Previously used a read lock which left expired
    /// entries lingering in the cache until periodic eviction, creating a
    /// window where stale verdicts could theoretically be observed under
    /// concurrent access patterns.
    pub fn get(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let mut cache = self.cache.blocking_write();
        // Check expiry first (peek does not update LRU order)
        let expired = cache.peek(key).map(|e| e.is_expired());
        match expired {
            Some(true) => {
                // Atomically remove the expired entry while holding the write lock
                cache.pop(key);
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Some(false) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                // Entry is known to exist and not expired; peek again to clone
                cache.peek(key).map(|e| {
                    let mut eval = e.evaluation.clone();
                    eval.from_cache = true;
                    eval
                })
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Retrieves a cached evaluation asynchronously.
    ///
    /// SECURITY (FIND-028): Uses a write lock to atomically remove expired
    /// entries on access, matching the sync `get()` behavior.
    pub async fn get_async(&self, key: &str) -> Option<LlmEvaluation> {
        if !self.config.enabled {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let mut cache = self.cache.write().await;
        let expired = cache.peek(key).map(|e| e.is_expired());
        match expired {
            Some(true) => {
                cache.pop(key);
                self.expirations.fetch_add(1, Ordering::Relaxed);
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Some(false) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                cache.peek(key).map(|e| {
                    let mut eval = e.evaluation.clone();
                    eval.from_cache = true;
                    eval
                })
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Stores an evaluation in the cache.
    ///
    /// If caching is disabled or TTL is 0, this is a no-op.
    pub fn put(&self, key: &str, evaluation: LlmEvaluation) {
        if !self.config.enabled || self.config.ttl_secs == 0 {
            return;
        }

        // SECURITY (FIND-R69-001): Use checked_add to prevent Instant overflow panic
        // on extreme ttl_secs values.
        let ttl = Duration::from_secs(self.config.ttl_secs.min(MAX_TTL_SECS));
        let expires_at = match Instant::now().checked_add(ttl) {
            Some(t) => t,
            None => {
                tracing::warn!("Cache TTL overflow, using fallback 1h expiry");
                Instant::now() + Duration::from_secs(3600)
            }
        };

        let entry = CachedEntry {
            evaluation,
            expires_at,
        };

        let mut cache = self.cache.blocking_write();
        cache.put(key.to_string(), entry);
    }

    /// Stores an evaluation asynchronously.
    pub async fn put_async(&self, key: &str, evaluation: LlmEvaluation) {
        if !self.config.enabled || self.config.ttl_secs == 0 {
            return;
        }

        // SECURITY (FIND-R69-001): Use checked_add to prevent Instant overflow panic.
        let ttl = Duration::from_secs(self.config.ttl_secs.min(MAX_TTL_SECS));
        let expires_at = match Instant::now().checked_add(ttl) {
            Some(t) => t,
            None => {
                tracing::warn!("Cache TTL overflow, using fallback 1h expiry");
                Instant::now() + Duration::from_secs(3600)
            }
        };

        let entry = CachedEntry {
            evaluation,
            expires_at,
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
        let total = hits.saturating_add(misses);
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
        let total = hits.saturating_add(misses);
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

    /// SECURITY (FIND-R168-001): TTL exceeding MAX_TTL_SECS is rejected.
    #[test]
    fn test_cache_config_validate_ttl_exceeds_max() {
        let config = CacheConfig {
            ttl_secs: 604_801, // 7 days + 1 second
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("ttl_secs"));
    }

    /// SECURITY (FIND-R168-002): ttl_secs=0 with enabled=true is rejected.
    #[test]
    fn test_cache_config_validate_zero_ttl_enabled() {
        let config = CacheConfig {
            ttl_secs: 0,
            enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    /// ttl_secs=0 with enabled=false is valid (disabled cache).
    #[test]
    fn test_cache_config_validate_zero_ttl_disabled_ok() {
        let config = CacheConfig {
            ttl_secs: 0,
            enabled: false,
            max_size: 0,
        };
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

    /// SECURITY (FIND-R213-001): Verify that delimiter-ambiguous field values
    /// produce different cache keys (length-prefixing prevents collisions).
    #[test]
    fn test_cache_key_no_delimiter_collision() {
        let cache = test_cache();
        let params = serde_json::json!({});

        // tool="a:b", function="c" vs tool="a", function="b:c"
        let key1 = cache.compute_key("a:b", "c", &params, &[]);
        let key2 = cache.compute_key("a", "b:c", &params, &[]);
        assert_ne!(
            key1, key2,
            "FIND-R213-001: delimiter in field values must not cause key collision"
        );

        // tool="a|b", function="c" vs tool="a", function="b|c"
        let key3 = cache.compute_key("a|b", "c", &params, &[]);
        let key4 = cache.compute_key("a", "b|c", &params, &[]);
        assert_ne!(
            key3, key4,
            "FIND-R213-001: pipe in field values must not cause key collision"
        );

        // nl_policies boundary: ["ab", "cd"] vs ["a", "bcd"]
        let key5 = cache.compute_key(
            "t",
            "f",
            &params,
            &["ab".to_string(), "cd".to_string()],
        );
        let key6 = cache.compute_key(
            "t",
            "f",
            &params,
            &["a".to_string(), "bcd".to_string()],
        );
        assert_ne!(
            key5, key6,
            "FIND-R213-001: policy boundary shift must produce different keys"
        );

        // nl_policies count: [] vs [""]
        let key7 = cache.compute_key("t", "f", &params, &[]);
        let key8 = cache.compute_key("t", "f", &params, &["".to_string()]);
        assert_ne!(
            key7, key8,
            "FIND-R213-001: empty vs one-empty-string policy list must differ"
        );
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

    // SECURITY (FIND-028): Verify that get() atomically removes expired entries
    // from the cache, rather than just returning None and leaving them lingering.
    #[tokio::test]
    async fn test_find_028_get_removes_expired_entry() {
        use std::time::Duration;

        let cache = EvaluationCache::new(CacheConfig {
            max_size: 100,
            ttl_secs: 1,
            enabled: true,
        });

        cache.put_async("key", LlmEvaluation::allow()).await;
        assert_eq!(cache.len_async().await, 1);

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // get_async should return None AND remove the entry from the cache
        assert!(cache.get_async("key").await.is_none());
        assert_eq!(
            cache.len_async().await,
            0,
            "FIND-028: expired entry must be removed from cache on access"
        );
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
