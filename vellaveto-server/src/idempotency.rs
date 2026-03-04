// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Idempotency key support for mutating endpoints.
//!
//! Provides at-most-once execution semantics for POST/PUT/DELETE requests
//! by caching responses keyed by a client-provided `X-Idempotency-Key` header.
//!
//! ## Usage
//!
//! Clients include an `X-Idempotency-Key` header with a unique identifier
//! (typically a UUID). The server:
//!
//! 1. Checks if the key exists in the store
//! 2. If found and not expired: returns the cached response
//! 3. If not found: executes the request, caches the response, returns it
//!
//! ## Configuration
//!
//! ```toml
//! [server.idempotency]
//! enabled = true
//! ttl_hours = 24      # Keys expire after 24 hours
//! max_keys = 100000   # Maximum keys to store (LRU eviction)
//! ```

use axum::{
    body::Body,
    http::{HeaderMap, Response, StatusCode},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Header name for idempotency keys.
pub const IDEMPOTENCY_KEY_HEADER: &str = "x-idempotency-key";

/// Maximum cached response body size (1 MB). Bodies exceeding this limit are
/// dropped with a warning to prevent memory exhaustion from large payloads.
const MAX_CACHED_BODY_BYTES: usize = 1_048_576;

/// Header indicating a cached response was returned.
pub const IDEMPOTENCY_REPLAYED_HEADER: &str = "x-idempotency-replayed";

/// Configuration for idempotency key handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyConfig {
    /// Whether idempotency key handling is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Time-to-live for idempotency keys in hours.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u64,

    /// Maximum number of keys to store. Older keys are evicted when exceeded.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,

    /// Maximum key length (to prevent memory exhaustion attacks).
    #[serde(default = "default_max_key_length")]
    pub max_key_length: usize,
}

fn default_ttl_hours() -> u64 {
    24
}

fn default_max_keys() -> usize {
    100_000
}

fn default_max_key_length() -> usize {
    256
}

impl IdempotencyConfig {
    /// Validate configuration bounds.
    ///
    /// Enforces minimum values to prevent misconfiguration:
    /// - `ttl_hours >= 1` (keys must live at least 1 hour)
    /// - `max_key_length >= 16` (keys must allow at least UUID-short format)
    /// - `max_keys >= 1` (must store at least one key)
    pub fn validate(&self) -> Result<(), String> {
        if self.ttl_hours < 1 {
            return Err("idempotency.ttl_hours must be >= 1".to_string());
        }
        if self.max_key_length < 16 {
            return Err("idempotency.max_key_length must be >= 16".to_string());
        }
        if self.max_keys < 1 {
            return Err("idempotency.max_keys must be >= 1".to_string());
        }
        Ok(())
    }
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_hours: default_ttl_hours(),
            max_keys: default_max_keys(),
            max_key_length: default_max_key_length(),
        }
    }
}

/// Cached response for idempotency replay.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response body (serialized as bytes).
    pub body: Vec<u8>,
    /// Content-Type header value.
    pub content_type: Option<String>,
    /// When this entry was created.
    pub created_at: Instant,
    /// When this entry expires.
    pub expires_at: Instant,
}

impl CachedResponse {
    /// Check if this cached response has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// State of an idempotency key.
#[derive(Debug, Clone)]
pub enum IdempotencyState {
    /// Request is currently being processed.
    InProgress {
        /// When processing started.
        started_at: Instant,
    },
    /// Request completed with this response.
    Completed(CachedResponse),
}

/// Store for idempotency keys and their associated responses.
#[derive(Debug, Clone)]
pub struct IdempotencyStore {
    /// Map of idempotency keys to their state.
    entries: Arc<DashMap<String, IdempotencyState>>,
    /// Configuration for this store.
    config: IdempotencyConfig,
}

impl IdempotencyStore {
    /// Create a new idempotency store with the given configuration.
    pub fn new(config: IdempotencyConfig) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Check if idempotency handling is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the TTL duration.
    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.config.ttl_hours * 3600)
    }

    /// Extract and validate an idempotency key from request headers.
    ///
    /// SECURITY (R234-SRV-6): When `tenant_id` is provided, the key is prefixed
    /// with `{tenant_id}:` to prevent cross-tenant response caching. Without this,
    /// two tenants submitting the same idempotency key would share cached responses.
    pub fn extract_key(
        &self,
        headers: &HeaderMap,
        tenant_id: Option<&str>,
    ) -> Result<Option<String>, IdempotencyError> {
        let key = match headers.get(IDEMPOTENCY_KEY_HEADER) {
            Some(value) => value,
            None => return Ok(None),
        };

        let key_str = key
            .to_str()
            .map_err(|_| IdempotencyError::InvalidKey("key contains invalid characters".into()))?;

        // Validate key length
        if key_str.len() > self.config.max_key_length {
            return Err(IdempotencyError::InvalidKey(format!(
                "key exceeds maximum length of {} characters",
                self.config.max_key_length
            )));
        }

        // Validate key format (alphanumeric, hyphens, underscores only)
        if !key_str
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(IdempotencyError::InvalidKey(
                "key must contain only alphanumeric characters, hyphens, and underscores".into(),
            ));
        }

        // SECURITY (R234-SRV-6): Tenant-scope the key to prevent cross-tenant leakage.
        let scoped_key = match tenant_id {
            Some(tid) => format!("{tid}:{key_str}"),
            None => key_str.to_string(),
        };

        Ok(Some(scoped_key))
    }

    /// Try to acquire a lock for processing a request with the given key.
    ///
    /// Returns:
    /// - `Ok(None)` if the key is new and we acquired the lock
    /// - `Ok(Some(response))` if the key exists and has a cached response
    /// - `Err(IdempotencyError::InProgress)` if another request is processing this key
    ///
    /// SECURITY (FIND-R72-SRV-002): Uses DashMap's `entry()` API for atomic
    /// check-and-insert, eliminating the TOCTOU race between the previous
    /// separate `get()` and `insert()` calls.
    pub fn try_acquire(&self, key: &str) -> Result<Option<CachedResponse>, IdempotencyError> {
        // First, check if we need to evict old entries
        self.maybe_evict();

        // Use entry() API for atomic check-and-insert
        let entry = self.entries.entry(key.to_string());
        match entry {
            dashmap::Entry::Occupied(mut occupied) => {
                match occupied.get() {
                    IdempotencyState::InProgress { started_at } => {
                        // Check if the in-progress request has timed out (5 minutes)
                        if started_at.elapsed() > Duration::from_secs(300) {
                            // Stale in-progress entry, replace with new in-progress marker
                            occupied.insert(IdempotencyState::InProgress {
                                started_at: Instant::now(),
                            });
                            Ok(None)
                        } else {
                            Err(IdempotencyError::InProgress)
                        }
                    }
                    IdempotencyState::Completed(response) => {
                        if response.is_expired() {
                            // Expired entry, replace with new in-progress marker
                            occupied.insert(IdempotencyState::InProgress {
                                started_at: Instant::now(),
                            });
                            Ok(None)
                        } else {
                            // Return cached response
                            Ok(Some(response.clone()))
                        }
                    }
                }
            }
            dashmap::Entry::Vacant(vacant) => {
                // New key — insert in-progress marker atomically
                vacant.insert(IdempotencyState::InProgress {
                    started_at: Instant::now(),
                });
                Ok(None)
            }
        }
    }

    /// Complete a request and cache the response.
    ///
    /// SECURITY (FIND-R58-SRV-IDEM-001): If the response body exceeds
    /// `MAX_CACHED_BODY_BYTES` (1 MB), the body is dropped and only the
    /// status code is cached. This prevents memory exhaustion from large payloads.
    pub fn complete(
        &self,
        key: &str,
        status: StatusCode,
        body: Vec<u8>,
        content_type: Option<String>,
    ) {
        let cached_body = if body.len() > MAX_CACHED_BODY_BYTES {
            tracing::warn!(
                key = key,
                body_len = body.len(),
                max = MAX_CACHED_BODY_BYTES,
                "idempotency cached body exceeds size limit; dropping body"
            );
            Vec::new()
        } else {
            body
        };

        let now = Instant::now();
        let response = CachedResponse {
            status,
            body: cached_body,
            content_type,
            created_at: now,
            expires_at: now + self.ttl(),
        };
        self.entries
            .insert(key.to_string(), IdempotencyState::Completed(response));
    }

    /// Release a lock without caching a response (for error cases).
    pub fn release(&self, key: &str) {
        self.entries.remove(key);
    }

    /// Evict expired entries if we're over capacity.
    fn maybe_evict(&self) {
        if self.entries.len() <= self.config.max_keys {
            return;
        }

        // Remove expired entries
        self.entries.retain(|_, state| match state {
            IdempotencyState::InProgress { started_at } => {
                // Keep in-progress entries unless they're stale (5 min timeout)
                started_at.elapsed() < Duration::from_secs(300)
            }
            IdempotencyState::Completed(response) => !response.is_expired(),
        });

        // If still over capacity, remove oldest entries
        // (This is a simple LRU approximation - we just remove any entries until under limit)
        while self.entries.len() > self.config.max_keys {
            if let Some(entry) = self.entries.iter().next() {
                let key = entry.key().clone();
                drop(entry);
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Get the current number of stored keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Errors that can occur during idempotency handling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum IdempotencyError {
    #[error("invalid idempotency key: {0}")]
    InvalidKey(String),

    #[error("request with this idempotency key is already in progress")]
    InProgress,
}

/// Build a response from a cached response.
pub fn build_cached_response(cached: &CachedResponse) -> Response<Body> {
    let mut response = Response::builder()
        .status(cached.status)
        .header(IDEMPOTENCY_REPLAYED_HEADER, "true");

    if let Some(ref ct) = cached.content_type {
        response = response.header("content-type", ct.as_str());
    }

    response
        .body(Body::from(cached.body.clone()))
        .unwrap_or_else(|_| {
            // Construct fallback without builder to avoid unwrap()
            let mut resp = Response::new(Body::from("failed to build cached response"));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn test_config() -> IdempotencyConfig {
        IdempotencyConfig {
            enabled: true,
            ttl_hours: 1,
            max_keys: 100,
            max_key_length: 64,
        }
    }

    #[test]
    fn test_extract_key_valid() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("abc-123_DEF"),
        );

        let key = store.extract_key(&headers, None).unwrap();
        assert_eq!(key, Some("abc-123_DEF".to_string()));
    }

    #[test]
    fn test_extract_key_missing() {
        let store = IdempotencyStore::new(test_config());
        let headers = HeaderMap::new();

        let key = store.extract_key(&headers, None).unwrap();
        assert_eq!(key, None);
    }

    #[test]
    fn test_extract_key_too_long() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        let long_key = "a".repeat(100);
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_str(&long_key).unwrap(),
        );

        let result = store.extract_key(&headers, None);
        assert!(matches!(result, Err(IdempotencyError::InvalidKey(_))));
    }

    #[test]
    fn test_extract_key_invalid_chars() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("key with spaces"),
        );

        let result = store.extract_key(&headers, None);
        assert!(matches!(result, Err(IdempotencyError::InvalidKey(_))));
    }

    #[test]
    fn test_try_acquire_new_key() {
        let store = IdempotencyStore::new(test_config());
        let result = store.try_acquire("new-key");
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn test_try_acquire_in_progress() {
        let store = IdempotencyStore::new(test_config());

        // First acquire succeeds
        let _ = store.try_acquire("key-1");

        // Second acquire fails (in progress)
        let result = store.try_acquire("key-1");
        assert!(matches!(result, Err(IdempotencyError::InProgress)));
    }

    #[test]
    fn test_complete_and_replay() {
        let store = IdempotencyStore::new(test_config());

        // Acquire and complete
        let _ = store.try_acquire("key-1");
        store.complete(
            "key-1",
            StatusCode::CREATED,
            b"response body".to_vec(),
            Some("application/json".to_string()),
        );

        // Second acquire returns cached response
        let result = store.try_acquire("key-1");
        assert!(matches!(result, Ok(Some(_))));

        if let Ok(Some(cached)) = result {
            assert_eq!(cached.status, StatusCode::CREATED);
            assert_eq!(cached.body, b"response body");
        }
    }

    #[test]
    fn test_release_allows_retry() {
        let store = IdempotencyStore::new(test_config());

        // Acquire
        let _ = store.try_acquire("key-1");

        // Release without completing
        store.release("key-1");

        // Can acquire again
        let result = store.try_acquire("key-1");
        assert!(matches!(result, Ok(None)));
    }

    // ── validate() tests ──

    #[test]
    fn test_validate_default_config_ok() {
        assert!(IdempotencyConfig::default().validate().is_ok());
    }

    #[test]
    fn test_validate_ttl_hours_zero_fails() {
        let mut cfg = test_config();
        cfg.ttl_hours = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("ttl_hours must be >= 1"));
    }

    #[test]
    fn test_validate_max_key_length_too_small_fails() {
        let mut cfg = test_config();
        cfg.max_key_length = 15;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_key_length must be >= 16"));
    }

    #[test]
    fn test_validate_max_keys_zero_fails() {
        let mut cfg = test_config();
        cfg.max_keys = 0;
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("max_keys must be >= 1"));
    }

    // ── body size limit tests ──

    #[test]
    fn test_complete_oversized_body_drops_body() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("big-key");

        let large_body = vec![0u8; MAX_CACHED_BODY_BYTES + 1];
        store.complete("big-key", StatusCode::OK, large_body, None);

        let result = store.try_acquire("big-key");
        if let Ok(Some(cached)) = result {
            assert!(cached.body.is_empty(), "oversized body should be dropped");
        } else {
            panic!("expected completed cached response");
        }
    }

    #[test]
    fn test_complete_body_within_limit_preserved() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("ok-key");

        let body = vec![1u8; 100];
        store.complete("ok-key", StatusCode::OK, body.clone(), None);

        let result = store.try_acquire("ok-key");
        if let Ok(Some(cached)) = result {
            assert_eq!(cached.body, body);
        } else {
            panic!("expected completed cached response");
        }
    }

    #[test]
    fn test_cached_response_not_expired() {
        let response = CachedResponse {
            status: StatusCode::OK,
            body: vec![],
            content_type: None,
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        assert!(!response.is_expired());
    }

    // ── Additional edge case tests ────────────────────────────────────

    #[test]
    fn test_extract_key_exact_max_length_ok() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        let key = "a".repeat(64); // max_key_length = 64 in test_config
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_str(&key).unwrap());
        let result = store.extract_key(&headers, None).unwrap();
        assert_eq!(result, Some(key));
    }

    #[test]
    fn test_extract_key_special_chars_rejected() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();

        // Dot
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("key.with.dots"),
        );
        assert!(matches!(
            store.extract_key(&headers, None),
            Err(IdempotencyError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_extract_key_slash_rejected() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("key/slash"),
        );
        assert!(matches!(
            store.extract_key(&headers, None),
            Err(IdempotencyError::InvalidKey(_))
        ));
    }

    #[test]
    fn test_store_is_empty_initially() {
        let store = IdempotencyStore::new(test_config());
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_store_len_after_acquire() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("key-1");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn test_store_is_enabled_flag() {
        let enabled_store = IdempotencyStore::new(test_config());
        assert!(enabled_store.is_enabled());

        let disabled_store = IdempotencyStore::new(IdempotencyConfig::default());
        assert!(!disabled_store.is_enabled());
    }

    #[test]
    fn test_store_ttl_calculation() {
        let store = IdempotencyStore::new(test_config());
        // test_config has ttl_hours = 1
        assert_eq!(store.ttl(), Duration::from_secs(3600));
    }

    #[test]
    fn test_complete_with_content_type() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("ct-key");
        store.complete(
            "ct-key",
            StatusCode::OK,
            b"body".to_vec(),
            Some("text/plain".to_string()),
        );

        if let Ok(Some(cached)) = store.try_acquire("ct-key") {
            assert_eq!(cached.content_type, Some("text/plain".to_string()));
        } else {
            panic!("expected cached response with content type");
        }
    }

    #[test]
    fn test_complete_without_content_type() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("no-ct-key");
        store.complete("no-ct-key", StatusCode::NO_CONTENT, vec![], None);

        if let Ok(Some(cached)) = store.try_acquire("no-ct-key") {
            assert!(cached.content_type.is_none());
            assert!(cached.body.is_empty());
            assert_eq!(cached.status, StatusCode::NO_CONTENT);
        } else {
            panic!("expected cached response");
        }
    }

    #[test]
    fn test_complete_body_exactly_at_limit() {
        let store = IdempotencyStore::new(test_config());
        let _ = store.try_acquire("exact-key");
        let body = vec![0u8; MAX_CACHED_BODY_BYTES];
        store.complete("exact-key", StatusCode::OK, body.clone(), None);

        if let Ok(Some(cached)) = store.try_acquire("exact-key") {
            assert_eq!(cached.body.len(), MAX_CACHED_BODY_BYTES);
        } else {
            panic!("expected cached response");
        }
    }

    #[test]
    fn test_validate_all_valid_boundary_values() {
        // Minimum valid values
        let cfg = IdempotencyConfig {
            enabled: true,
            ttl_hours: 1,
            max_keys: 1,
            max_key_length: 16,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_idempotency_error_display() {
        let err = IdempotencyError::InvalidKey("test reason".into());
        assert!(err.to_string().contains("test reason"));

        let err = IdempotencyError::InProgress;
        assert!(err.to_string().contains("already in progress"));
    }

    #[test]
    fn test_build_cached_response_with_content_type() {
        let cached = CachedResponse {
            status: StatusCode::CREATED,
            body: b"response".to_vec(),
            content_type: Some("application/json".to_string()),
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        let response = build_cached_response(&cached);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response
            .headers()
            .get(IDEMPOTENCY_REPLAYED_HEADER)
            .is_some());
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    // ── R234-SRV-6: Tenant-scoped idempotency keys ──

    #[test]
    fn test_extract_key_tenant_scoped() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("abc-123"));

        // With tenant_id, key is prefixed
        let key = store.extract_key(&headers, Some("tenant-A")).unwrap();
        assert_eq!(key, Some("tenant-A:abc-123".to_string()));
    }

    #[test]
    fn test_extract_key_without_tenant_no_prefix() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("abc-123"));

        // Without tenant_id, key is raw
        let key = store.extract_key(&headers, None).unwrap();
        assert_eq!(key, Some("abc-123".to_string()));
    }

    #[test]
    fn test_extract_key_different_tenants_different_keys() {
        let store = IdempotencyStore::new(test_config());
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, HeaderValue::from_static("same-key"));

        let key_a = store.extract_key(&headers, Some("tenant-A")).unwrap();
        let key_b = store.extract_key(&headers, Some("tenant-B")).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_build_cached_response_without_content_type() {
        let cached = CachedResponse {
            status: StatusCode::OK,
            body: vec![],
            content_type: None,
            created_at: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        let response = build_cached_response(&cached);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-type").is_none());
    }
}
