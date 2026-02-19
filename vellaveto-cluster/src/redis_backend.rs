//! Redis cluster backend for distributed Vellaveto state.
//!
//! Stores approvals and rate limit state in Redis, enabling multiple Vellaveto
//! instances to share state behind a load balancer.
//!
//! **Data model:**
//! - Approval objects: `{prefix}approval:{id}` → JSON string (Redis string)
//! - Dedup index: `{prefix}dedup:{hash}` → approval ID (Redis string with TTL)
//! - Pending set: `{prefix}pending` → sorted set scored by expiry timestamp
//! - Rate limits: `{prefix}rl:{category}:{key}` → sliding window counter (Lua script)
//!
//! **Fail-closed:** All operations return `ClusterError::Connection` on Redis
//! failures. The caller converts errors to `Deny` verdicts.

use async_trait::async_trait;
use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use vellaveto_approval::{ApprovalStatus, PendingApproval};
use vellaveto_types::Action;

use crate::{ClusterBackend, ClusterError};

/// Redis-backed cluster state.
pub struct RedisBackend {
    pool: Pool,
    key_prefix: String,
    default_ttl_secs: u64,
    max_pending: usize,
}

/// Default maximum pending approvals in Redis.
const DEFAULT_MAX_PENDING: usize = 10_000;

/// Default approval TTL in seconds (15 minutes).
const DEFAULT_TTL_SECS: u64 = 900;

impl RedisBackend {
    /// Create a new Redis backend.
    ///
    /// # Errors
    ///
    /// Returns `ClusterError::Connection` if the pool cannot be created.
    pub fn new(redis_url: &str, pool_size: usize, key_prefix: &str) -> Result<Self, ClusterError> {
        let cfg = PoolConfig::from_url(redis_url);
        let pool = cfg
            .builder()
            .map_err(|e| ClusterError::Connection(format!("Failed to create pool builder: {}", e)))?
            .max_size(pool_size)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| ClusterError::Connection(format!("Failed to build pool: {}", e)))?;

        Ok(Self {
            pool,
            key_prefix: key_prefix.to_string(),
            default_ttl_secs: DEFAULT_TTL_SECS,
            max_pending: DEFAULT_MAX_PENDING,
        })
    }

    /// Set the default TTL for approvals (useful for testing).
    pub fn with_ttl_secs(mut self, ttl: u64) -> Self {
        self.default_ttl_secs = ttl;
        self
    }

    /// Set the maximum number of pending approvals.
    pub fn with_max_pending(mut self, max: usize) -> Self {
        self.max_pending = max;
        self
    }

    fn key(&self, suffix: &str) -> String {
        format!("{}{}", self.key_prefix, suffix)
    }

    fn approval_key(&self, id: &str) -> String {
        self.key(&format!("approval:{}", id))
    }

    fn dedup_key(&self, hash: &str) -> String {
        self.key(&format!("dedup:{}", hash))
    }

    fn pending_set_key(&self) -> String {
        self.key("pending")
    }

    fn rate_limit_key(&self, category: &str, key: &str) -> String {
        self.key(&format!("rl:{}:{}", category, key))
    }

    async fn get_conn(&self) -> Result<deadpool_redis::Connection, ClusterError> {
        self.pool
            .get()
            .await
            .map_err(|e| ClusterError::Connection(format!("Failed to get Redis connection: {}", e)))
    }

    /// Compute a dedup key from action + reason + requested_by.
    /// Mirrors the logic in vellaveto-approval to ensure compatibility.
    fn compute_dedup_hash(
        action: &Action,
        reason: &str,
        requested_by: Option<&str>,
    ) -> Result<String, ClusterError> {
        use sha2::{Digest, Sha256};

        let mut sorted_ips = action.resolved_ips.clone();
        sorted_ips.sort();
        let mut sorted_paths = action.target_paths.clone();
        sorted_paths.sort();
        let mut sorted_domains = action.target_domains.clone();
        sorted_domains.sort();

        let canonical = serde_json::json!({
            "tool": action.tool,
            "function": action.function,
            "parameters": action.parameters,
            "target_paths": sorted_paths,
            "target_domains": sorted_domains,
            "resolved_ips": sorted_ips,
        });

        let canonical_str = serde_json::to_string(&canonical)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;
        let input = format!(
            "{}||{}||{}",
            canonical_str,
            reason,
            requested_by.unwrap_or(""),
        );
        let hash = Sha256::digest(input.as_bytes());
        Ok(format!("{:x}", hash))
    }
}

/// Lua script for atomic sliding window rate limiting.
///
/// Uses a sorted set where members are unique request IDs (timestamps + random)
/// and scores are timestamps. On each check:
/// 1. Remove entries older than the window
/// 2. Count remaining entries
/// 3. If under limit, add the new entry
/// 4. Set TTL on the key to auto-cleanup
///
/// Returns 1 if allowed, 0 if rate-limited.
const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local request_id = ARGV[4]

-- Remove entries outside the window
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- Count current entries
local count = redis.call('ZCARD', key)

if count < limit then
    -- Add the new request
    redis.call('ZADD', key, now, request_id)
    -- Set TTL to auto-cleanup abandoned keys
    redis.call('EXPIRE', key, window + 1)
    return 1
else
    return 0
end
"#;

#[async_trait]
impl ClusterBackend for RedisBackend {
    async fn approval_create(
        &self,
        action: Action,
        reason: String,
        requested_by: Option<String>,
    ) -> Result<String, ClusterError> {
        // Validate identity length (mirrors vellaveto-approval store-level check)
        if let Some(ref rb) = requested_by {
            if rb.len() > vellaveto_approval::MAX_IDENTITY_LEN {
                return Err(ClusterError::Validation(format!(
                    "requested_by exceeds maximum length of {} bytes",
                    vellaveto_approval::MAX_IDENTITY_LEN
                )));
            }
        }

        let dedup_hash = Self::compute_dedup_hash(&action, &reason, requested_by.as_deref())?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::seconds(self.default_ttl_secs as i64);
        let expires_at = now + ttl;

        let approval = PendingApproval {
            id: id.clone(),
            action,
            reason,
            created_at: now,
            expires_at,
            status: ApprovalStatus::Pending,
            resolved_by: None,
            resolved_at: None,
            requested_by,
        };

        let approval_json = serde_json::to_string(&approval)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;

        let mut conn = self.get_conn().await?;

        // First, check dedup without Lua for simplicity and correctness
        let dedup_redis_key = self.dedup_key(&dedup_hash);
        let existing_id: Option<String> = conn
            .get(&dedup_redis_key)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET dedup failed: {}", e)))?;

        if let Some(ref eid) = existing_id {
            // Verify the referenced approval is still pending
            let existing_json: Option<String> =
                conn.get(self.approval_key(eid)).await.map_err(|e| {
                    ClusterError::Connection(format!("Redis GET approval failed: {}", e))
                })?;
            if let Some(ref json_str) = existing_json {
                if let Ok(existing) = serde_json::from_str::<PendingApproval>(json_str) {
                    if existing.status == ApprovalStatus::Pending {
                        return Ok(eid.clone());
                    }
                }
            }
            // Stale dedup — remove it and continue to create new
            let _: () = conn
                .del(&dedup_redis_key)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis DEL dedup failed: {}", e)))?;
        }

        // Check capacity
        let pending_count: usize = conn
            .zcard(self.pending_set_key())
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZCARD failed: {}", e)))?;
        if pending_count >= self.max_pending {
            return Err(ClusterError::CapacityExceeded(self.max_pending));
        }

        // Store the approval
        let approval_redis_key = self.approval_key(&id);
        let _: () = conn
            .set(&approval_redis_key, &approval_json)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis SET approval failed: {}", e)))?;

        // Add to pending sorted set (scored by expiry timestamp)
        let expiry_ts = expires_at.timestamp() as f64;
        let _: () = conn
            .zadd(self.pending_set_key(), &id, expiry_ts)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZADD pending failed: {}", e)))?;

        // Set dedup key with TTL matching the approval TTL
        let _: () = conn
            .set_ex(&dedup_redis_key, &id, self.default_ttl_secs)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis SET dedup failed: {}", e)))?;

        Ok(id)
    }

    async fn approval_get(&self, id: &str) -> Result<PendingApproval, ClusterError> {
        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))
            }
            None => Err(ClusterError::NotFound(id.to_string())),
        }
    }

    async fn approval_approve(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError> {
        if by.len() > vellaveto_approval::MAX_IDENTITY_LEN {
            return Err(ClusterError::Validation(format!(
                "resolved_by exceeds maximum length of {} bytes",
                vellaveto_approval::MAX_IDENTITY_LEN
            )));
        }

        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        let mut approval: PendingApproval = match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))?
            }
            None => return Err(ClusterError::NotFound(id.to_string())),
        };

        if approval.status != ApprovalStatus::Pending {
            return Err(ClusterError::AlreadyResolved(id.to_string()));
        }

        // Check expiry
        let now = chrono::Utc::now();
        if now > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            self.persist_and_cleanup(&mut conn, &approval).await?;
            return Err(ClusterError::Expired(id.to_string()));
        }

        // Self-approval check: delegate to the same logic that vellaveto-approval uses.
        // We replicate the key checks here to avoid depending on internal approval methods.
        if let Some(ref requester) = approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let approver_base = by.split(" (note:").next().unwrap_or(by);

            if requester_base.contains('(') || approver_base.contains('(') {
                return Err(ClusterError::Validation(
                    "Self-approval denied: principal contains invalid characters".to_string(),
                ));
            }

            use unicode_normalization::UnicodeNormalization;
            use vellaveto_types::unicode::normalize_homoglyphs;
            let requester_normalized: String = requester_base.nfkc().collect();
            let approver_normalized: String = approver_base.nfkc().collect();
            let req_lower: String = requester_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let app_lower: String = approver_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            // SECURITY (FIND-R58-CFG-001): Apply homoglyph normalization
            // to match vellaveto-approval parity. Without this, Cyrillic
            // homoglyphs (e.g., U+0430 for 'a') bypass self-approval check.
            let req_final = normalize_homoglyphs(&req_lower);
            let app_final = normalize_homoglyphs(&app_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == app_final {
                return Err(ClusterError::Validation(format!(
                    "Self-approval denied: requester '{}' cannot approve their own request",
                    requester_base
                )));
            }
        }

        approval.status = ApprovalStatus::Approved;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(now);

        self.persist_and_cleanup(&mut conn, &approval).await?;
        Ok(approval)
    }

    async fn approval_deny(&self, id: &str, by: &str) -> Result<PendingApproval, ClusterError> {
        if by.len() > vellaveto_approval::MAX_IDENTITY_LEN {
            return Err(ClusterError::Validation(format!(
                "resolved_by exceeds maximum length of {} bytes",
                vellaveto_approval::MAX_IDENTITY_LEN
            )));
        }

        let mut conn = self.get_conn().await?;
        let json: Option<String> = conn
            .get(self.approval_key(id))
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;

        let mut approval: PendingApproval = match json {
            Some(j) => {
                serde_json::from_str(&j).map_err(|e| ClusterError::Serialization(e.to_string()))?
            }
            None => return Err(ClusterError::NotFound(id.to_string())),
        };

        if approval.status != ApprovalStatus::Pending {
            return Err(ClusterError::AlreadyResolved(id.to_string()));
        }

        let now = chrono::Utc::now();
        if now > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            self.persist_and_cleanup(&mut conn, &approval).await?;
            return Err(ClusterError::Expired(id.to_string()));
        }

        // SECURITY (FIND-R58-CFG-002): Self-denial prevention — mirrors
        // vellaveto-approval::ApprovalStore::deny() parity. A requester
        // must not be able to deny their own request, as this breaks
        // separation-of-privilege.
        if let Some(ref requester) = approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let denier_base = by.split(" (note:").next().unwrap_or(by);

            if requester_base.contains('(') || denier_base.contains('(') {
                return Err(ClusterError::Validation(
                    "Self-denial denied: principal contains invalid characters".to_string(),
                ));
            }

            use unicode_normalization::UnicodeNormalization;
            use vellaveto_types::unicode::normalize_homoglyphs;
            let requester_normalized: String = requester_base.nfkc().collect();
            let denier_normalized: String = denier_base.nfkc().collect();
            let req_lower: String = requester_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let den_lower: String = denier_normalized
                .chars()
                .flat_map(char::to_lowercase)
                .collect();
            let req_final = normalize_homoglyphs(&req_lower);
            let den_final = normalize_homoglyphs(&den_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == den_final {
                return Err(ClusterError::Validation(format!(
                    "Self-denial denied: requester '{}' cannot deny their own request",
                    requester_base
                )));
            }
        }

        approval.status = ApprovalStatus::Denied;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(now);

        self.persist_and_cleanup(&mut conn, &approval).await?;
        Ok(approval)
    }

    async fn approval_list_pending(&self) -> Result<Vec<PendingApproval>, ClusterError> {
        let mut conn = self.get_conn().await?;

        // Get all members of the pending set
        let ids: Vec<String> = conn
            .zrangebyscore(self.pending_set_key(), "-inf", "+inf")
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZRANGEBYSCORE failed: {}", e)))?;

        let mut approvals = Vec::with_capacity(ids.len());
        for id in &ids {
            let json: Option<String> = conn
                .get(self.approval_key(id))
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;
            if let Some(j) = json {
                if let Ok(approval) = serde_json::from_str::<PendingApproval>(&j) {
                    if approval.status == ApprovalStatus::Pending {
                        approvals.push(approval);
                    }
                }
            }
        }

        Ok(approvals)
    }

    async fn approval_pending_count(&self) -> Result<usize, ClusterError> {
        let mut conn = self.get_conn().await?;
        let count: usize = conn
            .zcard(self.pending_set_key())
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZCARD failed: {}", e)))?;
        Ok(count)
    }

    async fn approval_expire_stale(&self) -> Result<usize, ClusterError> {
        let mut conn = self.get_conn().await?;
        let now = chrono::Utc::now();
        let now_ts = now.timestamp() as f64;

        // Get expired members (score <= now timestamp)
        let expired_ids: Vec<String> = conn
            .zrangebyscore(self.pending_set_key(), "-inf", now_ts)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis ZRANGEBYSCORE failed: {}", e)))?;

        let mut expired_count = 0;
        for id in &expired_ids {
            let json: Option<String> = conn
                .get(self.approval_key(id))
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis GET failed: {}", e)))?;
            if let Some(j) = json {
                if let Ok(mut approval) = serde_json::from_str::<PendingApproval>(&j) {
                    if approval.status == ApprovalStatus::Pending {
                        approval.status = ApprovalStatus::Expired;
                        self.persist_and_cleanup(&mut conn, &approval).await?;
                        expired_count += 1;
                    } else {
                        // Already resolved — just remove from pending set
                        let _: () = conn.zrem(self.pending_set_key(), id).await.map_err(|e| {
                            ClusterError::Connection(format!("Redis ZREM failed: {}", e))
                        })?;
                    }
                }
            } else {
                // Orphan entry in pending set — remove it
                let _: () = conn
                    .zrem(self.pending_set_key(), id)
                    .await
                    .map_err(|e| ClusterError::Connection(format!("Redis ZREM failed: {}", e)))?;
            }
        }

        Ok(expired_count)
    }

    async fn rate_limit_check(
        &self,
        category: &str,
        key: &str,
        rps: u32,
        burst: u32,
    ) -> Result<bool, ClusterError> {
        let mut conn = self.get_conn().await?;
        let redis_key = self.rate_limit_key(category, key);

        // Sliding window: window = 1 second, limit = burst (or rps if burst is 0)
        let limit = if burst > 0 { burst } else { rps };
        let window_ms: u64 = 1000; // 1 second window
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ClusterError::Backend(format!("System time error: {}", e)))?
            .as_millis() as u64;

        let request_id = format!("{}:{}", now_ms, uuid::Uuid::new_v4());

        let result: i32 = deadpool_redis::redis::Script::new(RATE_LIMIT_SCRIPT)
            .key(&redis_key)
            .arg(now_ms)
            .arg(window_ms)
            .arg(limit)
            .arg(&request_id)
            .invoke_async(&mut *conn)
            .await
            .map_err(|e| {
                ClusterError::Connection(format!("Redis rate limit script failed: {}", e))
            })?;

        Ok(result == 1)
    }

    async fn health_check(&self) -> Result<(), ClusterError> {
        let mut conn = self.get_conn().await?;
        let pong: String = deadpool_redis::redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis PING failed: {}", e)))?;
        if pong != "PONG" {
            return Err(ClusterError::Connection(format!(
                "Unexpected PING response: {}",
                pong
            )));
        }
        Ok(())
    }
}

impl RedisBackend {
    /// Persist an updated approval and cleanup associated indices.
    async fn persist_and_cleanup(
        &self,
        conn: &mut deadpool_redis::Connection,
        approval: &PendingApproval,
    ) -> Result<(), ClusterError> {
        let json = serde_json::to_string(approval)
            .map_err(|e| ClusterError::Serialization(e.to_string()))?;

        // Update the approval object
        let _: () = conn
            .set(self.approval_key(&approval.id), &json)
            .await
            .map_err(|e| ClusterError::Connection(format!("Redis SET failed: {}", e)))?;

        // If no longer pending, remove from pending set and dedup index
        if approval.status != ApprovalStatus::Pending {
            let _: () = conn
                .zrem(self.pending_set_key(), &approval.id)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis ZREM failed: {}", e)))?;

            // Remove dedup key
            if let Ok(dedup_hash) = Self::compute_dedup_hash(
                &approval.action,
                &approval.reason,
                approval.requested_by.as_deref(),
            ) {
                let _: () = conn.del(self.dedup_key(&dedup_hash)).await.map_err(|e| {
                    ClusterError::Connection(format!("Redis DEL dedup failed: {}", e))
                })?;
            }

            // Set a TTL on the approval itself for eventual cleanup (1 hour)
            let _: () = conn
                .expire(self.approval_key(&approval.id), 3600)
                .await
                .map_err(|e| ClusterError::Connection(format!("Redis EXPIRE failed: {}", e)))?;
        }

        Ok(())
    }
}
