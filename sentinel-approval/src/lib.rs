use chrono::{DateTime, Duration, Utc};
use sentinel_types::Action;
use serde::{Deserialize, Serialize};
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
}

/// In-memory approval store with file-based persistence.
pub struct ApprovalStore {
    pending: RwLock<HashMap<String, PendingApproval>>,
    log_path: PathBuf,
    default_ttl: std::time::Duration,
}

impl ApprovalStore {
    /// Create a new approval store.
    ///
    /// `default_ttl` is the time-to-live for new approvals (default: 15 minutes).
    pub fn new(log_path: PathBuf, default_ttl: std::time::Duration) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            log_path,
            default_ttl,
        }
    }

    /// Create a new pending approval for an action.
    ///
    /// Returns the approval ID.
    pub async fn create(&self, action: Action, reason: String) -> Result<String, ApprovalError> {
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
        };

        self.persist_approval(&approval).await?;

        let mut pending = self.pending.write().await;
        pending.insert(id.clone(), approval);

        Ok(id)
    }

    /// Approve a pending approval.
    pub async fn approve(&self, id: &str, by: &str) -> Result<PendingApproval, ApprovalError> {
        let mut pending = self.pending.write().await;
        let approval = pending
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyResolved(id.to_string()));
        }

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            self.persist_approval(&result).await?;
            return Err(ApprovalError::Expired(id.to_string()));
        }

        approval.status = ApprovalStatus::Approved;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(Utc::now());

        let result = approval.clone();
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

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            self.persist_approval(&result).await?;
            return Err(ApprovalError::Expired(id.to_string()));
        }

        approval.status = ApprovalStatus::Denied;
        approval.resolved_by = Some(by.to_string());
        approval.resolved_at = Some(Utc::now());

        let result = approval.clone();
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
    pub async fn expire_stale(&self) -> usize {
        let now = Utc::now();
        let mut pending = self.pending.write().await;
        let mut expired_count = 0;

        for approval in pending.values_mut() {
            if approval.status == ApprovalStatus::Pending && now > approval.expires_at {
                approval.status = ApprovalStatus::Expired;
                expired_count += 1;
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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn test_action() -> Action {
        Action {
            tool: "file_system".to_string(),
            function: "delete_file".to_string(),
            parameters: json!({"path": "/important/data"}),
        }
    }

    #[tokio::test]
    async fn test_create_approval() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string())
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
            .create(test_action(), "needs review".to_string())
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
            .create(test_action(), "needs review".to_string())
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
            .create(test_action(), "needs review".to_string())
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
            .create(test_action(), "reason1".to_string())
            .await
            .unwrap();
        store
            .create(test_action(), "reason2".to_string())
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
        // TTL of 0 seconds = immediately expires
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(0),
        );

        store
            .create(test_action(), "will expire".to_string())
            .await
            .unwrap();

        // Small sleep to ensure we're past the TTL
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let expired = store.expire_stale().await;
        assert_eq!(expired, 1);

        let pending = store.list_pending().await;
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");
        let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));

        store
            .create(test_action(), "persisted".to_string())
            .await
            .unwrap();

        // Verify file was written
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty());
        let entry: PendingApproval = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(entry.reason, "persisted");
    }
}
