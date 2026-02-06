use chrono::{DateTime, Duration, Utc};
use sentinel_types::Action;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ApprovalError {
    #[error("Approval not found: {0}")]
    NotFound(String),
    #[error("Approval already resolved: {0}")]
    AlreadyResolved(String),
    #[error("Approval expired: {0}")]
    Expired(String),
    #[error("Approval store at capacity ({0} max pending)")]
    CapacityExceeded(usize),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub action: Action,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    /// SECURITY (R9-2): Identity of the agent/principal that requested this approval.
    /// Derived from the authenticated Bearer token hash at creation time.
    /// Used to prevent self-approval: the resolver must differ from the requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
}

/// Default maximum number of pending approvals before rejecting new ones.
pub const DEFAULT_MAX_PENDING: usize = 10_000;

/// Compute a deduplication key from an action and reason.
///
/// The key is a SHA-256 hash of the canonical JSON representation of the
/// action's tool, function, parameters, target_paths, and target_domains
/// fields combined with the reason string. This ensures that identical
/// requests map to the same key regardless of field ordering in the
/// parameters object.
///
/// SECURITY (R28-SUP-1): target_paths and target_domains are included to
/// prevent dedup collision between semantically different actions (e.g.,
/// same tool/function/params but different file paths).
///
/// SECURITY (R30-SUP-5): `requested_by` is included so that different
/// principals cannot piggyback on each other's pending approvals. Without
/// this, principal A could create an approval and principal B could resolve
/// it, effectively approving on behalf of A.
fn compute_dedup_key(action: &Action, reason: &str, requested_by: Option<&str>) -> String {
    let canonical = serde_json::json!({
        "tool": action.tool,
        "function": action.function,
        "parameters": action.parameters,
        "target_paths": action.target_paths,
        "target_domains": action.target_domains,
    });
    let input = format!(
        "{}||{}||{}",
        serde_json::to_string(&canonical).unwrap_or_default(),
        reason,
        requested_by.unwrap_or(""),
    );
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

/// In-memory approval store with file-based persistence.
pub struct ApprovalStore {
    pending: RwLock<HashMap<String, PendingApproval>>,
    /// Maps dedup_key (SHA-256 of action+reason) to approval_id for pending entries.
    dedup_index: RwLock<HashMap<String, String>>,
    log_path: PathBuf,
    default_ttl: std::time::Duration,
    max_pending: usize,
}

impl ApprovalStore {
    /// Create a new approval store.
    ///
    /// `default_ttl` is the time-to-live for new approvals (default: 15 minutes).
    pub fn new(log_path: PathBuf, default_ttl: std::time::Duration) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            dedup_index: RwLock::new(HashMap::new()),
            log_path,
            default_ttl,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }

    /// Create a new approval store with a custom maximum capacity.
    pub fn with_max_pending(
        log_path: PathBuf,
        default_ttl: std::time::Duration,
        max_pending: usize,
    ) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            dedup_index: RwLock::new(HashMap::new()),
            log_path,
            default_ttl,
            max_pending,
        }
    }

    /// Load approvals from the persistence file into memory.
    ///
    /// Reads the JSONL file and loads the latest state of each approval.
    /// Because the file is append-only (each state change appends a new line),
    /// later entries override earlier ones for the same ID.
    pub async fn load_from_file(&self) -> Result<usize, ApprovalError> {
        // SECURITY (R28-SUP-3): Bound file size before reading to prevent OOM
        // on startup from a corrupted or maliciously inflated approval file.
        const MAX_APPROVAL_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
        match tokio::fs::metadata(&self.log_path).await {
            Ok(meta) if meta.len() > MAX_APPROVAL_FILE_SIZE => {
                return Err(ApprovalError::Validation(format!(
                    "Approval file too large ({} bytes, max {} bytes)",
                    meta.len(),
                    MAX_APPROVAL_FILE_SIZE
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(ApprovalError::Io(e)),
            Ok(_) => {} // Size OK, proceed to read
        }

        let content = match tokio::fs::read_to_string(&self.log_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(ApprovalError::Io(e)),
        };

        let mut pending = self.pending.write().await;
        let mut count = 0;

        let mut skipped = 0usize;
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<PendingApproval>(line) {
                Ok(approval) => {
                    pending.insert(approval.id.clone(), approval);
                    count += 1;
                }
                Err(e) => {
                    // Fix #28: Log malformed lines instead of silently dropping them.
                    // This makes data corruption visible on restart.
                    tracing::warn!(
                        "Skipping malformed approval entry at line {}: {} (content: {})",
                        line_num + 1,
                        e,
                        &line[..line.len().min(200)]
                    );
                    skipped += 1;
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                "Loaded {} approval entries, skipped {} malformed lines from {:?}",
                count,
                skipped,
                self.log_path
            );
        }

        // Rebuild the dedup index for entries that are still pending
        let mut dedup = self.dedup_index.write().await;
        dedup.clear();
        for approval in pending.values() {
            if approval.status == ApprovalStatus::Pending {
                let key = compute_dedup_key(&approval.action, &approval.reason, approval.requested_by.as_deref());
                dedup.insert(key, approval.id.clone());
            }
        }

        Ok(count)
    }

    /// Create a new pending approval for an action.
    ///
    /// Returns the approval ID. Fails with `CapacityExceeded` when the store
    /// is at `max_pending` capacity (fail-closed: the caller should convert
    /// this to a Deny verdict).
    ///
    /// The write lock is acquired before persistence to prevent a visibility
    /// gap where the approval exists on disk but not in memory (Finding #27).
    pub async fn create(
        &self,
        action: Action,
        reason: String,
        requested_by: Option<String>,
    ) -> Result<String, ApprovalError> {
        let dedup_key = compute_dedup_key(&action, &reason, requested_by.as_deref());

        // Check dedup index: if an identical pending approval exists, return its ID
        {
            let dedup = self.dedup_index.read().await;
            if let Some(existing_id) = dedup.get(&dedup_key) {
                let pending = self.pending.read().await;
                if let Some(existing) = pending.get(existing_id) {
                    if existing.status == ApprovalStatus::Pending {
                        return Ok(existing_id.clone());
                    }
                }
                // If the existing approval is no longer pending (or was removed),
                // fall through to create a new one and update the dedup index.
            }
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let ttl = Duration::from_std(self.default_ttl).unwrap_or_else(|_| Duration::seconds(900));

        let approval = PendingApproval {
            id: id.clone(),
            action,
            reason,
            created_at: now,
            expires_at: now + ttl,
            status: ApprovalStatus::Pending,
            resolved_by: None,
            resolved_at: None,
            requested_by,
        };

        // Acquire lock FIRST, then persist (Finding #27: prevents visibility gap)
        let mut pending = self.pending.write().await;

        // Double-check dedup under write lock to handle races
        {
            let dedup = self.dedup_index.read().await;
            if let Some(existing_id) = dedup.get(&dedup_key) {
                if let Some(existing) = pending.get(existing_id) {
                    if existing.status == ApprovalStatus::Pending {
                        return Ok(existing_id.clone());
                    }
                }
            }
        }

        // Check capacity before inserting (Finding #26: prevents unbounded growth)
        if pending.len() >= self.max_pending {
            return Err(ApprovalError::CapacityExceeded(self.max_pending));
        }

        // Insert into memory first so concurrent readers see it immediately
        pending.insert(id.clone(), approval.clone());

        // Update dedup index
        {
            let mut dedup = self.dedup_index.write().await;
            dedup.insert(dedup_key.clone(), id.clone());
        }

        // Persist to disk; rollback on failure
        if let Err(e) = self.persist_approval(&approval).await {
            pending.remove(&id);
            let mut dedup = self.dedup_index.write().await;
            dedup.remove(&dedup_key);
            return Err(e);
        }

        Ok(id)
    }

    /// Approve a pending approval.
    ///
    /// SECURITY (R9-2): When `requested_by` is set on the approval, the
    /// resolver identity (`by`) must differ from the requester. This prevents
    /// an agent from approving its own tool calls — a separation-of-privilege
    /// requirement for meaningful human-in-the-loop approval flows.
    pub async fn approve(&self, id: &str, by: &str) -> Result<PendingApproval, ApprovalError> {
        let mut pending = self.pending.write().await;
        let approval = pending
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyResolved(id.to_string()));
        }

        // SECURITY (R9-2): Prevent self-approval. If the approval was
        // requested by a known principal, the approver must be different.
        // Compare the base principal (before any "(note: ...)" suffix).
        // SECURITY (R23-SUP-1): Also reject principals that contain the
        // `" (note:"` separator themselves — an attacker could inject a
        // crafted `requested_by` like `"victim (note:real_id"` so the
        // split produces a different base than their actual identity.
        if let Some(requester) = &approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let approver_base = by.split(" (note:").next().unwrap_or(by);

            // Reject if the base principal contains parentheses — indicates
            // an attempt to embed a fake note separator in the identity.
            if requester_base.contains('(') || approver_base.contains('(') {
                return Err(ApprovalError::Validation(
                    "Self-approval denied: principal contains invalid characters".to_string(),
                ));
            }

            // SECURITY (R28-SUP-10): Case-insensitive comparison to prevent
            // self-approval bypass via casing variations (e.g., "Admin@Corp.com"
            // vs "admin@corp.com").
            if !requester_base.is_empty()
                && !requester_base.eq_ignore_ascii_case("anonymous")
                && requester_base.eq_ignore_ascii_case(approver_base)
            {
                return Err(ApprovalError::Validation(format!(
                    "Self-approval denied: requester '{}' cannot approve their own request",
                    requester_base
                )));
            }
        }

        // Compute dedup key before mutating the approval
        let dedup_key = compute_dedup_key(&approval.action, &approval.reason, approval.requested_by.as_deref());

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            // Remove from dedup index since it's no longer pending
            let mut dedup = self.dedup_index.write().await;
            dedup.remove(&dedup_key);
            drop(dedup);
            self.persist_approval(&result).await?;
            return Err(ApprovalError::Expired(id.to_string()));
        }

        approval.status = ApprovalStatus::Approved;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(Utc::now());

        let result = approval.clone();
        // Remove from dedup index since it's no longer pending
        let mut dedup = self.dedup_index.write().await;
        dedup.remove(&dedup_key);
        drop(dedup);
        self.persist_approval(&result).await?;
        Ok(result)
    }

    /// Deny a pending approval.
    pub async fn deny(&self, id: &str, by: &str) -> Result<PendingApproval, ApprovalError> {
        let mut pending = self.pending.write().await;
        let approval = pending
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyResolved(id.to_string()));
        }

        // Compute dedup key before mutating the approval
        let dedup_key = compute_dedup_key(&approval.action, &approval.reason, approval.requested_by.as_deref());

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            // Remove from dedup index since it's no longer pending
            let mut dedup = self.dedup_index.write().await;
            dedup.remove(&dedup_key);
            drop(dedup);
            self.persist_approval(&result).await?;
            return Err(ApprovalError::Expired(id.to_string()));
        }

        approval.status = ApprovalStatus::Denied;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(Utc::now());

        let result = approval.clone();
        // Remove from dedup index since it's no longer pending
        let mut dedup = self.dedup_index.write().await;
        dedup.remove(&dedup_key);
        drop(dedup);
        self.persist_approval(&result).await?;
        Ok(result)
    }

    /// Get an approval by ID.
    pub async fn get(&self, id: &str) -> Result<PendingApproval, ApprovalError> {
        let pending = self.pending.read().await;
        pending
            .get(id)
            .cloned()
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))
    }

    /// List all pending (not yet resolved) approvals.
    pub async fn list_pending(&self) -> Vec<PendingApproval> {
        let pending = self.pending.read().await;
        pending
            .values()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .cloned()
            .collect()
    }

    /// Expire all stale approvals that have passed their TTL.
    ///
    /// Persists the expired status to the JSONL file so restarts don't
    /// resurrect expired approvals as pending. Also removes resolved
    /// (approved/denied/expired) entries older than 1 hour from memory
    /// to prevent unbounded growth.
    pub async fn expire_stale(&self) -> usize {
        let now = Utc::now();
        // SECURITY (R21-SUP-2): Acquire both locks atomically in consistent order
        // (pending -> dedup_index) to prevent a race window where a concurrent
        // create() inserts a dedup entry for an approval being expired.
        let mut pending = self.pending.write().await;
        let mut dedup = self.dedup_index.write().await;
        let mut expired_count = 0;
        let mut to_persist = Vec::new();

        for approval in pending.values_mut() {
            if approval.status == ApprovalStatus::Pending && now > approval.expires_at {
                // Remove dedup key atomically while both locks are held
                let dedup_key = compute_dedup_key(&approval.action, &approval.reason, approval.requested_by.as_deref());
                dedup.remove(&dedup_key);
                approval.status = ApprovalStatus::Expired;
                expired_count += 1;
                to_persist.push(approval.clone());
            }
        }

        // Remove resolved entries older than 1 hour to prevent memory leaks
        let retention_cutoff = now - Duration::hours(1);
        pending
            .retain(|_, a| a.status == ApprovalStatus::Pending || a.created_at > retention_cutoff);

        // Drop both locks before I/O operations
        drop(dedup);
        drop(pending);

        for approval in &to_persist {
            if let Err(e) = self.persist_approval(approval).await {
                tracing::warn!("Failed to persist expired approval {}: {}", approval.id, e);
            }
        }

        expired_count
    }

    /// Persist an approval event to the log file.
    async fn persist_approval(&self, approval: &PendingApproval) -> Result<(), ApprovalError> {
        let mut line = serde_json::to_string(approval)?;
        line.push('\n');

        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await
        {
            Ok(f) => f,
            Err(_) => {
                if let Some(parent) = self.log_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.log_path)
                    .await?
            }
        };

        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        // Fix #29: sync_data() forces the kernel to write to stable storage.
        // Without this, a power loss after flush() can lose approval state
        // changes (e.g., an approved action reverts to pending on restart).
        file.sync_data().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn test_action() -> Action {
        Action::new(
            "file_system".to_string(),
            "delete_file".to_string(),
            json!({"path": "/important/data"}),
        )
    }

    #[tokio::test]
    async fn test_create_approval() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();
        assert!(!id.is_empty());

        let approval = store.get(&id).await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
        assert_eq!(approval.reason, "needs review");
    }

    #[tokio::test]
    async fn test_approve() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        let approval = store.approve(&id, "admin").await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Approved);
        assert_eq!(approval.resolved_by.as_deref(), Some("admin"));
        assert!(approval.resolved_at.is_some());
    }

    #[tokio::test]
    async fn test_deny() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        let approval = store.deny(&id, "admin").await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn test_double_approve_fails() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        store.approve(&id, "admin").await.unwrap();
        let result = store.approve(&id, "admin").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_not_found() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let result = store.get("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_pending() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id1 = store
            .create(test_action(), "reason1".to_string(), None)
            .await
            .unwrap();
        store
            .create(test_action(), "reason2".to_string(), None)
            .await
            .unwrap();

        // Approve one
        store.approve(&id1, "admin").await.unwrap();

        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].reason, "reason2");
    }

    #[tokio::test]
    async fn test_expire_stale() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");
        // TTL of 0 seconds = immediately expires
        let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(0));

        let id = store
            .create(test_action(), "will expire".to_string(), None)
            .await
            .unwrap();

        // Small sleep to ensure we're past the TTL
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let expired = store.expire_stale().await;
        assert_eq!(expired, 1);

        let pending = store.list_pending().await;
        assert!(pending.is_empty());

        // Fix #21: Verify expired status was persisted to file
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Should have 2 lines: initial Pending + Expired update
        assert!(lines.len() >= 2, "Expired status must be persisted");
        let last: PendingApproval = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(last.id, id);
        assert_eq!(last.status, ApprovalStatus::Expired);
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");
        let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));

        store
            .create(test_action(), "persisted".to_string(), None)
            .await
            .unwrap();

        // Verify file was written
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty());
        let entry: PendingApproval = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.reason, "persisted");
    }

    #[tokio::test]
    async fn test_approve_expired_returns_expired_error() {
        let dir = TempDir::new().unwrap();
        // TTL of 0 = immediately expired
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(0),
        );

        let id = store
            .create(
                test_action(),
                "will expire before approve".to_string(),
                None,
            )
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Attempting to approve should return Expired error (not AlreadyResolved)
        let result = store.approve(&id, "admin").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired(_)),
            "Expected Expired error, got: {:?}",
            err
        );

        // The approval should now be marked Expired in the store
        let approval = store.get(&id).await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Expired);
    }

    #[tokio::test]
    async fn test_deny_expired_returns_expired_error() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(0),
        );

        let id = store
            .create(test_action(), "will expire before deny".to_string(), None)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let result = store.deny(&id, "admin").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApprovalError::Expired(_)));
    }

    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");

        // Create entries in first store instance
        let id1;
        let id2;
        {
            let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));
            id1 = store
                .create(test_action(), "first".to_string(), None)
                .await
                .unwrap();
            id2 = store
                .create(test_action(), "second".to_string(), None)
                .await
                .unwrap();
            store.approve(&id1, "admin").await.unwrap();
            // id2 remains pending
        }
        // First store dropped

        // Load into a new store instance from the same file
        let store2 = ApprovalStore::new(log_path, std::time::Duration::from_secs(900));
        let loaded = store2.load_from_file().await.unwrap();
        assert!(
            loaded >= 2,
            "Should load at least 2 entries, got {}",
            loaded
        );

        // Verify states survived the round-trip
        let a1 = store2.get(&id1).await.unwrap();
        assert_eq!(a1.status, ApprovalStatus::Approved);
        assert_eq!(a1.resolved_by.as_deref(), Some("admin"));

        let a2 = store2.get(&id2).await.unwrap();
        assert_eq!(a2.status, ApprovalStatus::Pending);
        assert_eq!(a2.reason, "second");
    }

    #[tokio::test]
    async fn test_expire_stale_idempotent() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(0),
        );

        store
            .create(test_action(), "expire me".to_string(), None)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // First expire should find 1
        let count1 = store.expire_stale().await;
        assert_eq!(count1, 1);

        // Second expire should find 0 (already expired)
        let count2 = store.expire_stale().await;
        assert_eq!(count2, 0);
    }

    // --- Deduplication tests (Phase 4A / M4) ---

    #[tokio::test]
    async fn test_dedup_same_action_returns_existing_id() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let action1 = test_action();
        let action2 = test_action();
        let reason = "needs review".to_string();

        let id1 = store.create(action1, reason.clone(), None).await.unwrap();
        let id2 = store.create(action2, reason, None).await.unwrap();

        // Same action + same reason should return the same pending approval ID
        assert_eq!(
            id1, id2,
            "Duplicate create should return existing pending ID"
        );

        // Only one pending approval should exist
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn test_dedup_different_actions_get_separate_ids() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let action1 = Action::new(
            "file_system".to_string(),
            "delete_file".to_string(),
            json!({"path": "/important/data"}),
        );
        let action2 = Action::new(
            "network".to_string(),
            "http_request".to_string(),
            json!({"url": "https://example.com"}),
        );

        let id1 = store
            .create(action1, "needs review".to_string(), None)
            .await
            .unwrap();
        let id2 = store
            .create(action2, "needs review".to_string(), None)
            .await
            .unwrap();

        // Different actions should get different IDs
        assert_ne!(id1, id2, "Different actions must get separate approval IDs");

        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_dedup_resolved_action_creates_fresh() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let reason = "needs review".to_string();

        // Create and approve the first one
        let id1 = store
            .create(test_action(), reason.clone(), None)
            .await
            .unwrap();
        store.approve(&id1, "admin").await.unwrap();

        // Creating the same action+reason after approval should produce a NEW id
        let id2 = store.create(test_action(), reason, None).await.unwrap();
        assert_ne!(
            id1, id2,
            "After resolving, a new create should produce a fresh ID"
        );

        // The new one should be pending
        let approval = store.get(&id2).await.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
    }

    #[tokio::test]
    async fn test_dedup_concurrent_safety() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        ));

        let action = test_action();
        let reason = "concurrent review".to_string();

        // Spawn two concurrent creates with identical action+reason
        let store1 = store.clone();
        let action1 = action.clone();
        let reason1 = reason.clone();
        let handle1 =
            tokio::spawn(async move { store1.create(action1, reason1, None).await.unwrap() });

        let store2 = store.clone();
        let action2 = action.clone();
        let reason2 = reason.clone();
        let handle2 =
            tokio::spawn(async move { store2.create(action2, reason2, None).await.unwrap() });

        let id1 = handle1.await.unwrap();
        let id2 = handle2.await.unwrap();

        // Both should resolve to the same approval ID
        assert_eq!(
            id1, id2,
            "Concurrent creates of the same action must return the same ID"
        );

        // Only one pending approval should exist
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
    }
}
