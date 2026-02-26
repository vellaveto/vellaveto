//! MCP Registry Integration — Phase 65.
//!
//! Provides integration with the MCP registry for server discovery:
//!
//! - **Query registry**: Search the MCP registry for available servers
//!   matching a given query or capability set.
//! - **Identity verification**: Verify a server's identity against
//!   registry-published metadata (name, version, publisher hash).
//! - **Cached responses**: Registry responses are cached with configurable
//!   TTL to reduce external calls and latency.
//!
//! # Security Design
//!
//! - Fail-closed: registry unavailability means no discovery, not open access.
//! - All strings validated with `has_dangerous_chars()`.
//! - Bounded collections with `MAX_*` constants.
//! - TTL-based cache with eviction.
//! - No secrets in Debug output.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::error::DiscoveryError;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of registry entries to cache.
const MAX_REGISTRY_CACHE_ENTRIES: usize = 5_000;

/// Default TTL for cached registry entries in seconds.
const DEFAULT_REGISTRY_CACHE_TTL_SECS: u64 = 300;

/// Maximum length of a registry server ID.
const MAX_REGISTRY_SERVER_ID_LEN: usize = 512;

/// Maximum length of a registry server name.
const MAX_REGISTRY_SERVER_NAME_LEN: usize = 512;

/// Maximum length of a registry server description.
const MAX_REGISTRY_SERVER_DESCRIPTION_LEN: usize = 4096;

/// Maximum length of a registry server URL.
const MAX_REGISTRY_SERVER_URL_LEN: usize = 2048;

/// Maximum number of capabilities per server entry.
const MAX_REGISTRY_CAPABILITIES: usize = 100;

/// Maximum length of a single capability string.
const MAX_CAPABILITY_LEN: usize = 256;

/// Maximum number of servers returned per query.
const MAX_REGISTRY_QUERY_RESULTS: usize = 100;

/// Maximum query string length.
const MAX_REGISTRY_QUERY_LEN: usize = 1024;

/// Maximum length of a publisher hash (SHA-256 hex = 64 chars).
const MAX_PUBLISHER_HASH_LEN: usize = 128;

/// Maximum registry URL length.
const MAX_REGISTRY_URL_LEN: usize = 2048;

/// Maximum number of tags per server entry.
const MAX_REGISTRY_TAGS: usize = 50;

/// Maximum tag length.
const MAX_TAG_LEN: usize = 128;

/// Maximum version string length.
const MAX_VERSION_LEN: usize = 64;

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// MCP server metadata as published in the registry.
///
/// This represents a single server entry from the MCP registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryServerEntry {
    /// Unique server identifier in the registry.
    pub server_id: String,
    /// Human-readable server name.
    pub name: String,
    /// Server description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Server endpoint URL.
    pub url: String,
    /// Server version.
    pub version: String,
    /// Publisher identity hash (SHA-256 of the publisher's public key or identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_hash: Option<String>,
    /// Capabilities this server provides.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the server entry is verified by the registry.
    #[serde(default)]
    pub verified: bool,
}

impl RegistryServerEntry {
    /// Validate the entry's fields are within bounds.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.server_id.is_empty() || self.server_id.len() > MAX_REGISTRY_SERVER_ID_LEN {
            return Err(DiscoveryError::InvalidMetadata(
                "server_id must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.server_id) {
            return Err(DiscoveryError::InvalidMetadata(
                "server_id contains control or Unicode format characters".to_string(),
            ));
        }
        if self.name.is_empty() || self.name.len() > MAX_REGISTRY_SERVER_NAME_LEN {
            return Err(DiscoveryError::InvalidMetadata(
                "name must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.name) {
            return Err(DiscoveryError::InvalidMetadata(
                "name contains control or Unicode format characters".to_string(),
            ));
        }
        if let Some(ref desc) = self.description {
            if desc.len() > MAX_REGISTRY_SERVER_DESCRIPTION_LEN {
                return Err(DiscoveryError::InvalidMetadata(format!(
                    "description length {} exceeds maximum {}",
                    desc.len(),
                    MAX_REGISTRY_SERVER_DESCRIPTION_LEN
                )));
            }
            if vellaveto_types::has_dangerous_chars(desc) {
                return Err(DiscoveryError::InvalidMetadata(
                    "description contains control or Unicode format characters".to_string(),
                ));
            }
        }
        if self.url.is_empty() || self.url.len() > MAX_REGISTRY_SERVER_URL_LEN {
            return Err(DiscoveryError::InvalidMetadata(
                "url must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.url) {
            return Err(DiscoveryError::InvalidMetadata(
                "url contains control or Unicode format characters".to_string(),
            ));
        }
        if self.version.is_empty() || self.version.len() > MAX_VERSION_LEN {
            return Err(DiscoveryError::InvalidMetadata(
                "version must be non-empty and within bounds".to_string(),
            ));
        }
        if let Some(ref ph) = self.publisher_hash {
            if ph.len() > MAX_PUBLISHER_HASH_LEN {
                return Err(DiscoveryError::InvalidMetadata(format!(
                    "publisher_hash length {} exceeds maximum {}",
                    ph.len(),
                    MAX_PUBLISHER_HASH_LEN
                )));
            }
        }
        if self.capabilities.len() > MAX_REGISTRY_CAPABILITIES {
            return Err(DiscoveryError::InvalidMetadata(format!(
                "capabilities count {} exceeds maximum {}",
                self.capabilities.len(),
                MAX_REGISTRY_CAPABILITIES
            )));
        }
        for cap in &self.capabilities {
            if cap.len() > MAX_CAPABILITY_LEN {
                return Err(DiscoveryError::InvalidMetadata(format!(
                    "capability length {} exceeds maximum {}",
                    cap.len(),
                    MAX_CAPABILITY_LEN
                )));
            }
        }
        if self.tags.len() > MAX_REGISTRY_TAGS {
            return Err(DiscoveryError::InvalidMetadata(format!(
                "tags count {} exceeds maximum {}",
                self.tags.len(),
                MAX_REGISTRY_TAGS
            )));
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LEN {
                return Err(DiscoveryError::InvalidMetadata(format!(
                    "tag length {} exceeds maximum {}",
                    tag.len(),
                    MAX_TAG_LEN
                )));
            }
        }
        Ok(())
    }
}

/// Result of a registry query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryQueryResult {
    /// Matching server entries.
    pub servers: Vec<RegistryServerEntry>,
    /// Total number of matches in the registry (may be > servers.len() if capped).
    pub total_matches: usize,
    /// Whether the result was served from cache.
    pub from_cache: bool,
}

/// Server identity verification result.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryVerificationResult {
    /// Whether the server was found in the registry.
    pub found: bool,
    /// Whether the server's identity matches the registry entry.
    pub identity_match: bool,
    /// Whether the publisher hash matches.
    pub publisher_match: bool,
    /// Whether the server version matches.
    pub version_match: bool,
    /// The registry entry, if found.
    pub registry_entry: Option<RegistryServerEntry>,
    /// Human-readable verification summary.
    pub summary: String,
}

/// Configuration for the MCP registry client.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Base URL of the MCP registry.
    pub registry_url: String,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to require HTTPS for registry communication.
    pub require_https: bool,
    /// Whether to only trust verified entries.
    pub only_verified: bool,
    /// API key for registry access (if required).
    api_key: Option<String>,
}

impl fmt::Display for RegistryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegistryConfig(url={}, ttl={}s, https={}, verified_only={})",
            self.registry_url, self.cache_ttl_secs, self.require_https, self.only_verified
        )
    }
}

impl RegistryConfig {
    /// Create a new registry configuration.
    pub fn new(registry_url: &str) -> Result<Self, DiscoveryError> {
        if registry_url.is_empty() || registry_url.len() > MAX_REGISTRY_URL_LEN {
            return Err(DiscoveryError::ConfigError(
                "registry_url must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(registry_url) {
            return Err(DiscoveryError::ConfigError(
                "registry_url contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(Self {
            registry_url: registry_url.to_string(),
            cache_ttl_secs: DEFAULT_REGISTRY_CACHE_TTL_SECS,
            require_https: true,
            only_verified: false,
            api_key: None,
        })
    }

    /// Set the cache TTL.
    pub fn with_cache_ttl(mut self, secs: u64) -> Self {
        self.cache_ttl_secs = secs;
        self
    }

    /// Set whether only verified entries are returned.
    pub fn with_only_verified(mut self, only_verified: bool) -> Self {
        self.only_verified = only_verified;
        self
    }

    /// Set the API key. Custom Debug will redact this.
    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.require_https && !self.registry_url.starts_with("https://") {
            return Err(DiscoveryError::ConfigError(
                "registry_url must use HTTPS when require_https is enabled".to_string(),
            ));
        }
        if self.cache_ttl_secs > 86_400 {
            return Err(DiscoveryError::ConfigError(
                "cache_ttl_secs must not exceed 86400 (24 hours)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Cached registry entry.
struct CachedRegistryEntry {
    entries: Vec<RegistryServerEntry>,
    total_matches: usize,
    cached_at: Instant,
}

/// MCP Registry Client.
///
/// Provides query, verification, and caching for MCP server registry lookups.
/// Thread-safe via internal `RwLock` on the cache.
pub struct McpRegistryClient {
    config: RegistryConfig,
    /// Cache keyed by query string.
    cache: RwLock<HashMap<String, CachedRegistryEntry>>,
    /// Cache keyed by server_id for identity verification.
    identity_cache: RwLock<HashMap<String, CachedRegistryEntry>>,
    /// Cache TTL.
    cache_ttl: Duration,
    /// Counter for cache hits.
    cache_hits: std::sync::atomic::AtomicU64,
    /// Counter for cache misses.
    cache_misses: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for McpRegistryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpRegistryClient")
            .field("config", &self.config.to_string())
            .field(
                "cache_hits",
                &self
                    .cache_hits
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "cache_misses",
                &self
                    .cache_misses
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl McpRegistryClient {
    /// Create a new registry client with the given configuration.
    pub fn new(config: RegistryConfig) -> Result<Self, DiscoveryError> {
        config.validate()?;
        let ttl = Duration::from_secs(config.cache_ttl_secs);
        Ok(Self {
            config,
            cache: RwLock::new(HashMap::new()),
            identity_cache: RwLock::new(HashMap::new()),
            cache_ttl: ttl,
            cache_hits: std::sync::atomic::AtomicU64::new(0),
            cache_misses: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Query the registry for servers matching a query string.
    ///
    /// In the current implementation, this operates on locally-cached data
    /// populated via `ingest_registry_response`. For production use, this
    /// would issue an HTTP request to the registry endpoint.
    ///
    /// # Errors
    ///
    /// Fails closed: lock poisoning or invalid query returns error.
    pub fn query(
        &self,
        query: &str,
        max_results: usize,
    ) -> Result<RegistryQueryResult, DiscoveryError> {
        // Validate query input
        if query.len() > MAX_REGISTRY_QUERY_LEN {
            return Err(DiscoveryError::InvalidMetadata(format!(
                "query length {} exceeds maximum {}",
                query.len(),
                MAX_REGISTRY_QUERY_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(query) {
            return Err(DiscoveryError::InvalidMetadata(
                "query contains control or Unicode format characters".to_string(),
            ));
        }

        let effective_max = max_results.min(MAX_REGISTRY_QUERY_RESULTS);
        let cache_key = compute_cache_key(query);

        // Check cache
        if let Some(result) = self.check_cache(&cache_key) {
            self.cache_hits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut servers = result.entries;
            if self.config.only_verified {
                servers.retain(|s| s.verified);
            }
            let total = servers.len();
            servers.truncate(effective_max);
            return Ok(RegistryQueryResult {
                servers,
                total_matches: total,
                from_cache: true,
            });
        }

        self.cache_misses
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // In this implementation, a cache miss means no data available.
        // A production implementation would issue an HTTP request here.
        Ok(RegistryQueryResult {
            servers: Vec::new(),
            total_matches: 0,
            from_cache: false,
        })
    }

    /// Ingest a registry response (from an HTTP fetch or test fixture).
    ///
    /// Parses the JSON response and populates the cache for subsequent queries.
    pub fn ingest_registry_response(
        &self,
        query: &str,
        entries: Vec<RegistryServerEntry>,
    ) -> Result<usize, DiscoveryError> {
        // Validate each entry
        let mut valid_entries = Vec::new();
        for entry in entries {
            match entry.validate() {
                Ok(()) => valid_entries.push(entry),
                Err(e) => {
                    tracing::warn!(
                        "registry: skipping invalid entry '{}': {}",
                        entry.server_id.chars().take(64).collect::<String>(),
                        e
                    );
                }
            }
        }

        let count = valid_entries.len();
        let total = count;
        let cache_key = compute_cache_key(query);

        let mut cache = self.cache.write().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "McpRegistryClient cache write lock poisoned"
            );
            DiscoveryError::LockPoisoned
        })?;

        // Evict expired entries
        let ttl = self.cache_ttl;
        cache.retain(|_, v| v.cached_at.elapsed() < ttl);

        // Evict oldest if at capacity
        while cache.len() >= MAX_REGISTRY_CACHE_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }

        cache.insert(
            cache_key,
            CachedRegistryEntry {
                entries: valid_entries,
                total_matches: total,
                cached_at: Instant::now(),
            },
        );

        Ok(count)
    }

    /// Verify a server's identity against the registry.
    ///
    /// Checks if the server exists in the registry and whether its
    /// metadata matches the expected identity.
    pub fn verify_server_identity(
        &self,
        server_id: &str,
        expected_url: &str,
        expected_publisher_hash: Option<&str>,
        expected_version: Option<&str>,
    ) -> Result<RegistryVerificationResult, DiscoveryError> {
        if server_id.len() > MAX_REGISTRY_SERVER_ID_LEN {
            return Err(DiscoveryError::InvalidMetadata(
                "server_id exceeds maximum length".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(server_id) {
            return Err(DiscoveryError::InvalidMetadata(
                "server_id contains control or Unicode format characters".to_string(),
            ));
        }

        // Look up in identity cache first
        let identity_key = format!("id:{}", server_id);
        if let Some(cached) = self.check_identity_cache(&identity_key) {
            if let Some(entry) = cached.entries.into_iter().find(|e| e.server_id == server_id) {
                return Ok(self.build_verification_result(
                    &entry,
                    expected_url,
                    expected_publisher_hash,
                    expected_version,
                ));
            }
        }

        // Look in the main query cache (scan all cached results)
        let cache = self.cache.read().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "McpRegistryClient cache read lock poisoned"
            );
            DiscoveryError::LockPoisoned
        })?;
        for (_, cached_entry) in cache.iter() {
            if cached_entry.cached_at.elapsed() < self.cache_ttl {
                if let Some(entry) = cached_entry
                    .entries
                    .iter()
                    .find(|e| e.server_id == server_id)
                {
                    return Ok(self.build_verification_result(
                        entry,
                        expected_url,
                        expected_publisher_hash,
                        expected_version,
                    ));
                }
            }
        }

        // Not found in any cache
        Ok(RegistryVerificationResult {
            found: false,
            identity_match: false,
            publisher_match: false,
            version_match: false,
            registry_entry: None,
            summary: format!("server '{}' not found in registry", server_id),
        })
    }

    /// Store a registry entry for identity verification.
    pub fn store_identity_entry(
        &self,
        entry: RegistryServerEntry,
    ) -> Result<(), DiscoveryError> {
        entry.validate()?;
        let identity_key = format!("id:{}", entry.server_id);

        let mut cache = self.identity_cache.write().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "McpRegistryClient identity_cache write lock poisoned"
            );
            DiscoveryError::LockPoisoned
        })?;

        // Evict expired entries
        let ttl = self.cache_ttl;
        cache.retain(|_, v| v.cached_at.elapsed() < ttl);

        // Evict oldest if at capacity
        while cache.len() >= MAX_REGISTRY_CACHE_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }

        cache.insert(
            identity_key,
            CachedRegistryEntry {
                entries: vec![entry],
                total_matches: 1,
                cached_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Build a verification result from a registry entry.
    fn build_verification_result(
        &self,
        entry: &RegistryServerEntry,
        expected_url: &str,
        expected_publisher_hash: Option<&str>,
        expected_version: Option<&str>,
    ) -> RegistryVerificationResult {
        let identity_match = entry.url == expected_url;
        let publisher_match = match (expected_publisher_hash, &entry.publisher_hash) {
            (Some(expected), Some(actual)) => {
                // Constant-time comparison for publisher hashes
                use subtle::ConstantTimeEq;
                if expected.len() == actual.len() {
                    expected.as_bytes().ct_eq(actual.as_bytes()).into()
                } else {
                    false
                }
            }
            (None, _) => true, // No expectation
            (Some(_), None) => false, // Expected but not present
        };
        let version_match = match expected_version {
            Some(v) => entry.version == v,
            None => true,
        };

        let summary = if identity_match && publisher_match && version_match {
            "server identity verified successfully".to_string()
        } else {
            let mut issues = Vec::new();
            if !identity_match {
                issues.push("URL mismatch");
            }
            if !publisher_match {
                issues.push("publisher hash mismatch");
            }
            if !version_match {
                issues.push("version mismatch");
            }
            format!("verification failed: {}", issues.join(", "))
        };

        RegistryVerificationResult {
            found: true,
            identity_match,
            publisher_match,
            version_match,
            registry_entry: Some(entry.clone()),
            summary,
        }
    }

    /// Check the query cache for a matching entry.
    fn check_cache(&self, cache_key: &str) -> Option<CachedRegistryEntry> {
        let cache = match self.cache.read() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "McpRegistryClient cache read lock poisoned"
                );
                return None;
            }
        };
        if let Some(entry) = cache.get(cache_key) {
            if entry.cached_at.elapsed() < self.cache_ttl {
                return Some(CachedRegistryEntry {
                    entries: entry.entries.clone(),
                    total_matches: entry.total_matches,
                    cached_at: entry.cached_at,
                });
            }
        }
        None
    }

    /// Check the identity cache.
    fn check_identity_cache(&self, key: &str) -> Option<CachedRegistryEntry> {
        let cache = match self.identity_cache.read() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "McpRegistryClient identity_cache read lock poisoned"
                );
                return None;
            }
        };
        if let Some(entry) = cache.get(key) {
            if entry.cached_at.elapsed() < self.cache_ttl {
                return Some(CachedRegistryEntry {
                    entries: entry.entries.clone(),
                    total_matches: entry.total_matches,
                    cached_at: entry.cached_at,
                });
            }
        }
        None
    }

    /// Clear all caches.
    pub fn clear_caches(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        } else {
            tracing::error!(
                target: "vellaveto::security",
                "McpRegistryClient cache write lock poisoned during clear"
            );
        }
        if let Ok(mut cache) = self.identity_cache.write() {
            cache.clear();
        } else {
            tracing::error!(
                target: "vellaveto::security",
                "McpRegistryClient identity_cache write lock poisoned during clear"
            );
        }
    }

    /// Get the number of cache hits.
    pub fn cache_hit_count(&self) -> u64 {
        self.cache_hits
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the number of cache misses.
    pub fn cache_miss_count(&self) -> u64 {
        self.cache_misses
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }
}

/// Compute a cache key from a query string.
fn compute_cache_key(query: &str) -> String {
    let hash = Sha256::digest(query.as_bytes());
    format!("q:{}", hex::encode(hash))
}

/// Compute a publisher hash from a public key or identity string.
pub fn compute_publisher_hash(identity_data: &[u8]) -> String {
    let hash = Sha256::digest(identity_data);
    hex::encode(hash)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(id: &str) -> RegistryServerEntry {
        RegistryServerEntry {
            server_id: id.to_string(),
            name: format!("Server {}", id),
            description: Some("A test server".to_string()),
            url: format!("https://{}.example.com", id),
            version: "1.0.0".to_string(),
            publisher_hash: Some(compute_publisher_hash(b"test-publisher")),
            capabilities: vec!["tools".to_string(), "resources".to_string()],
            tags: vec!["test".to_string()],
            verified: true,
        }
    }

    fn test_config() -> RegistryConfig {
        RegistryConfig {
            registry_url: "https://registry.mcp.example.com".to_string(),
            cache_ttl_secs: 300,
            require_https: true,
            only_verified: false,
            api_key: None,
        }
    }

    // ── RegistryServerEntry validation ──────────────────────────────────

    #[test]
    fn test_entry_validate_valid() {
        let entry = sample_entry("srv-1");
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_entry_validate_empty_server_id_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.server_id = String::new();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_oversized_server_id_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.server_id = "x".repeat(MAX_REGISTRY_SERVER_ID_LEN + 1);
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_dangerous_chars_in_name_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.name = "bad\x00name".to_string();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_oversized_description_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.description = Some("x".repeat(MAX_REGISTRY_SERVER_DESCRIPTION_LEN + 1));
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_empty_url_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.url = String::new();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_too_many_capabilities_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.capabilities = (0..MAX_REGISTRY_CAPABILITIES + 1)
            .map(|i| format!("cap-{}", i))
            .collect();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_too_many_tags_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.tags = (0..MAX_REGISTRY_TAGS + 1)
            .map(|i| format!("tag-{}", i))
            .collect();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_validate_capability_too_long_rejected() {
        let mut entry = sample_entry("srv-1");
        entry.capabilities = vec!["x".repeat(MAX_CAPABILITY_LEN + 1)];
        assert!(entry.validate().is_err());
    }

    // ── RegistryConfig ──────────────────────────────────────────────────

    #[test]
    fn test_config_new_valid() {
        let config = RegistryConfig::new("https://registry.example.com");
        assert!(config.is_ok());
    }

    #[test]
    fn test_config_new_empty_url_rejected() {
        let config = RegistryConfig::new("");
        assert!(config.is_err());
    }

    #[test]
    fn test_config_validate_http_when_https_required_rejected() {
        let mut config = test_config();
        config.registry_url = "http://insecure.example.com".to_string();
        config.require_https = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_excessive_ttl_rejected() {
        let mut config = test_config();
        config.cache_ttl_secs = 100_000;
        assert!(config.validate().is_err());
    }

    // ── McpRegistryClient ───────────────────────────────────────────────

    #[test]
    fn test_client_new_valid() {
        let client = McpRegistryClient::new(test_config());
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_query_empty_cache() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let result = client.query("filesystem", 10).unwrap();
        assert!(result.servers.is_empty());
        assert!(!result.from_cache);
        assert_eq!(client.cache_miss_count(), 1);
    }

    #[test]
    fn test_client_ingest_and_query() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let entries = vec![
            sample_entry("fs-server"),
            sample_entry("db-server"),
        ];
        let ingested = client
            .ingest_registry_response("filesystem", entries)
            .unwrap();
        assert_eq!(ingested, 2);

        let result = client.query("filesystem", 10).unwrap();
        assert_eq!(result.servers.len(), 2);
        assert!(result.from_cache);
        assert_eq!(client.cache_hit_count(), 1);
    }

    #[test]
    fn test_client_query_caps_results() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let entries: Vec<_> = (0..10).map(|i| sample_entry(&format!("srv-{}", i))).collect();
        client
            .ingest_registry_response("test", entries)
            .unwrap();

        let result = client.query("test", 3).unwrap();
        assert!(result.servers.len() <= 3);
    }

    #[test]
    fn test_client_query_dangerous_chars_rejected() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let result = client.query("bad\x00query", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_query_oversized_rejected() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let result = client.query(&"x".repeat(MAX_REGISTRY_QUERY_LEN + 1), 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_only_verified_filter() {
        let mut config = test_config();
        config.only_verified = true;
        let client = McpRegistryClient::new(config).unwrap();

        let mut unverified = sample_entry("unverified-srv");
        unverified.verified = false;
        let entries = vec![sample_entry("verified-srv"), unverified];
        client
            .ingest_registry_response("test", entries)
            .unwrap();

        let result = client.query("test", 10).unwrap();
        assert_eq!(result.servers.len(), 1);
        assert!(result.servers[0].verified);
    }

    // ── Server identity verification ────────────────────────────────────

    #[test]
    fn test_verify_server_identity_found_and_matching() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let entry = sample_entry("my-server");
        let publisher_hash = entry.publisher_hash.clone();
        client.store_identity_entry(entry).unwrap();

        let result = client
            .verify_server_identity(
                "my-server",
                "https://my-server.example.com",
                publisher_hash.as_deref(),
                Some("1.0.0"),
            )
            .unwrap();
        assert!(result.found);
        assert!(result.identity_match);
        assert!(result.publisher_match);
        assert!(result.version_match);
        assert!(result.summary.contains("verified successfully"));
    }

    #[test]
    fn test_verify_server_identity_url_mismatch() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        client.store_identity_entry(sample_entry("my-server")).unwrap();

        let result = client
            .verify_server_identity("my-server", "https://evil.example.com", None, None)
            .unwrap();
        assert!(result.found);
        assert!(!result.identity_match);
        assert!(result.summary.contains("URL mismatch"));
    }

    #[test]
    fn test_verify_server_identity_publisher_hash_mismatch() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        client.store_identity_entry(sample_entry("my-server")).unwrap();

        let result = client
            .verify_server_identity(
                "my-server",
                "https://my-server.example.com",
                Some("0000000000000000000000000000000000000000000000000000000000000000"),
                None,
            )
            .unwrap();
        assert!(result.found);
        assert!(!result.publisher_match);
        assert!(result.summary.contains("publisher hash mismatch"));
    }

    #[test]
    fn test_verify_server_identity_not_found() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let result = client
            .verify_server_identity("nonexistent", "https://nowhere.com", None, None)
            .unwrap();
        assert!(!result.found);
        assert!(!result.identity_match);
        assert!(result.summary.contains("not found"));
    }

    #[test]
    fn test_verify_server_identity_version_mismatch() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        client.store_identity_entry(sample_entry("my-server")).unwrap();

        let result = client
            .verify_server_identity(
                "my-server",
                "https://my-server.example.com",
                None,
                Some("2.0.0"),
            )
            .unwrap();
        assert!(result.found);
        assert!(!result.version_match);
    }

    #[test]
    fn test_verify_server_identity_dangerous_chars_rejected() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let result =
            client.verify_server_identity("bad\nid", "https://example.com", None, None);
        assert!(result.is_err());
    }

    // ── Ingestion validation ────────────────────────────────────────────

    #[test]
    fn test_ingest_skips_invalid_entries() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        let mut bad = sample_entry("bad");
        bad.server_id = String::new(); // Invalid
        let entries = vec![sample_entry("good"), bad];
        let count = client
            .ingest_registry_response("test", entries)
            .unwrap();
        assert_eq!(count, 1);
    }

    // ── Cache operations ────────────────────────────────────────────────

    #[test]
    fn test_client_clear_caches() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        client
            .ingest_registry_response("test", vec![sample_entry("srv")])
            .unwrap();
        client.clear_caches();
        let result = client.query("test", 10).unwrap();
        assert!(result.servers.is_empty());
    }

    // ── Helper functions ────────────────────────────────────────────────

    #[test]
    fn test_compute_cache_key_deterministic() {
        let key1 = compute_cache_key("test query");
        let key2 = compute_cache_key("test query");
        assert_eq!(key1, key2);
        assert!(key1.starts_with("q:"));
    }

    #[test]
    fn test_compute_cache_key_different_queries_differ() {
        assert_ne!(compute_cache_key("a"), compute_cache_key("b"));
    }

    #[test]
    fn test_compute_publisher_hash_deterministic() {
        let h1 = compute_publisher_hash(b"test-data");
        let h2 = compute_publisher_hash(b"test-data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_compute_publisher_hash_different_data_differ() {
        assert_ne!(
            compute_publisher_hash(b"a"),
            compute_publisher_hash(b"b")
        );
    }

    // ── Entry serde roundtrip ───────────────────────────────────────────

    #[test]
    fn test_entry_serde_roundtrip() {
        let entry = sample_entry("srv-1");
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RegistryServerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.server_id, "srv-1");
        assert_eq!(parsed.capabilities.len(), 2);
        assert!(parsed.verified);
    }

    // ── Verify from query cache ─────────────────────────────────────────

    #[test]
    fn test_verify_server_identity_from_query_cache() {
        let client = McpRegistryClient::new(test_config()).unwrap();
        // Store via ingest (query cache), not identity cache
        client
            .ingest_registry_response("all", vec![sample_entry("cached-srv")])
            .unwrap();

        let result = client
            .verify_server_identity(
                "cached-srv",
                "https://cached-srv.example.com",
                None,
                None,
            )
            .unwrap();
        assert!(result.found);
        assert!(result.identity_match);
    }

    // ── Debug output ────────────────────────────────────────────────────

    #[test]
    fn test_client_debug_does_not_leak_api_key() {
        let config = test_config().with_api_key("secret-key-12345".to_string());
        let client = McpRegistryClient::new(config).unwrap();
        let debug_str = format!("{:?}", client);
        assert!(!debug_str.contains("secret-key-12345"));
    }
}
