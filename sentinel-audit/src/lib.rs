use chrono::Utc;
use sentinel_types::{Action, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub action: Action,
    pub verdict: Verdict,
    pub timestamp: String,
    pub metadata: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub total_entries: usize,
    pub allow_count: usize,
    pub deny_count: usize,
    pub require_approval_count: usize,
    pub entries: Vec<AuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLogEntry {
    pub timestamp: String,
    pub error: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_broken_at: Option<usize>,
}

/// Append-only audit logger for policy evaluation decisions.
///
/// Records every [`Action`] + [`Verdict`] pair to a persistent log file
/// in JSONL format for compliance, debugging, and forensic analysis.
///
/// New entries include SHA-256 hash chains for tamper evidence.
pub struct AuditLogger {
    log_path: PathBuf,
    last_hash: Mutex<Option<String>>,
}

impl AuditLogger {
    /// Create a new audit logger writing to the specified path.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: Mutex::new(None),
        }
    }

    /// Initialize the hash chain by reading the last entry from the log.
    ///
    /// Call this once at startup to seed the chain head.
    pub async fn initialize_chain(&self) -> Result<(), AuditError> {
        let entries = self.load_entries().await?;
        let mut last_hash = self.last_hash.lock().await;
        if let Some(last_entry) = entries.last() {
            *last_hash = last_entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Compute the SHA-256 hash of an entry's content.
    ///
    /// Hash = SHA-256(id || action_json || verdict_json || timestamp || metadata_json || prev_hash)
    fn compute_entry_hash(entry: &AuditEntry) -> Result<String, AuditError> {
        let action_json = serde_json::to_string(&entry.action)?;
        let verdict_json = serde_json::to_string(&entry.verdict)?;
        let metadata_json = serde_json::to_string(&entry.metadata)?;
        let prev_hash = entry.prev_hash.as_deref().unwrap_or("");

        let mut hasher = Sha256::new();
        hasher.update(entry.id.as_bytes());
        hasher.update(action_json.as_bytes());
        hasher.update(verdict_json.as_bytes());
        hasher.update(entry.timestamp.as_bytes());
        hasher.update(metadata_json.as_bytes());
        hasher.update(prev_hash.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    /// Log an action-verdict pair to the audit file.
    ///
    /// Validates input before writing. Each entry is a single JSON line
    /// with a SHA-256 hash chain linking it to the previous entry.
    pub async fn log_entry(
        &self,
        action: &Action,
        verdict: &Verdict,
        metadata: serde_json::Value,
    ) -> Result<(), AuditError> {
        // Validate input
        self.validate_action(action)?;

        let mut last_hash_guard = self.last_hash.lock().await;

        let mut entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            action: action.clone(),
            verdict: verdict.clone(),
            timestamp: Utc::now().to_rfc3339(),
            metadata,
            entry_hash: None,
            prev_hash: last_hash_guard.clone(),
        };

        // Compute hash
        let hash = Self::compute_entry_hash(&entry)?;
        entry.entry_hash = Some(hash.clone());

        // Update chain head
        *last_hash_guard = Some(hash);

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        // Open file with append mode, creating parent dirs if needed
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

    /// Load all entries from the audit log.
    pub async fn load_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let content = match tokio::fs::read_to_string(&self.log_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut entries = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Verify the hash chain integrity of the audit log.
    ///
    /// Walks all entries and verifies that each hash links correctly
    /// to the previous entry's hash.
    pub async fn verify_chain(&self) -> Result<ChainVerification, AuditError> {
        let entries = self.load_entries().await?;

        if entries.is_empty() {
            return Ok(ChainVerification {
                valid: true,
                entries_checked: 0,
                first_broken_at: None,
            });
        }

        let mut prev_hash: Option<String> = None;

        for (i, entry) in entries.iter().enumerate() {
            // Skip verification for legacy entries without hashes
            if entry.entry_hash.is_none() {
                prev_hash = None;
                continue;
            }

            // Verify prev_hash links to the previous entry
            if entry.prev_hash != prev_hash {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }

            // Verify the entry's own hash
            let computed = Self::compute_entry_hash(entry)?;
            if entry.entry_hash.as_deref() != Some(&computed) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }

            prev_hash = entry.entry_hash.clone();
        }

        Ok(ChainVerification {
            valid: true,
            entries_checked: entries.len(),
            first_broken_at: None,
        })
    }

    /// Generate a summary report from the audit log.
    pub async fn generate_report(&self) -> Result<AuditReport, AuditError> {
        let entries = self.load_entries().await?;

        let mut allow_count = 0;
        let mut deny_count = 0;
        let mut require_approval_count = 0;

        for entry in &entries {
            match &entry.verdict {
                Verdict::Allow => allow_count += 1,
                Verdict::Deny { .. } => deny_count += 1,
                Verdict::RequireApproval { .. } => require_approval_count += 1,
            }
        }

        Ok(AuditReport {
            total_entries: entries.len(),
            allow_count,
            deny_count,
            require_approval_count,
            entries,
        })
    }

    /// Validate an action before logging.
    ///
    /// Rejects actions with newlines or null bytes in tool/function names,
    /// and limits JSON nesting depth in parameters.
    fn validate_action(&self, action: &Action) -> Result<(), AuditError> {
        // Check for newlines in tool/function names
        if action.tool.contains('\n') || action.tool.contains('\r') {
            return Err(AuditError::Validation(
                "Tool name contains newline characters".to_string(),
            ));
        }
        if action.function.contains('\n') || action.function.contains('\r') {
            return Err(AuditError::Validation(
                "Function name contains newline characters".to_string(),
            ));
        }

        // Check for null bytes
        if action.tool.contains('\0') {
            return Err(AuditError::Validation(
                "Tool name contains null bytes".to_string(),
            ));
        }
        if action.function.contains('\0') {
            return Err(AuditError::Validation(
                "Function name contains null bytes".to_string(),
            ));
        }

        // Check JSON nesting depth
        if Self::json_depth(&action.parameters) > 20 {
            return Err(AuditError::Validation(
                "Parameters exceed maximum nesting depth of 20".to_string(),
            ));
        }

        // Check serialized size
        let size = action.parameters.to_string().len();
        if size > 1_000_000 {
            return Err(AuditError::Validation(format!(
                "Parameters too large: {} bytes (max 1000000)",
                size
            )));
        }

        Ok(())
    }

    fn json_depth(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(arr) => {
                1 + arr.iter().map(Self::json_depth).max().unwrap_or(0)
            }
            serde_json::Value::Object(obj) => {
                1 + obj.values().map(Self::json_depth).max().unwrap_or(0)
            }
            _ => 0,
        }
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
            function: "read_file".to_string(),
            parameters: json!({"path": "/tmp/test.txt"}),
        }
    }

    #[tokio::test]
    async fn test_log_and_load() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        let verdict = Verdict::Allow;

        logger
            .log_entry(&action, &verdict, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.tool, "file_system");
        // New entries should have hashes
        assert!(entries[0].entry_hash.is_some());
        assert!(entries[0].prev_hash.is_none()); // First entry has no prev
    }

    #[tokio::test]
    async fn test_generate_report() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "blocked".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::RequireApproval {
                    reason: "needs review".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let report = logger.generate_report().await.unwrap();
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 1);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 1);
    }

    #[tokio::test]
    async fn test_validation_newline_in_tool() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = Action {
            tool: "bad\ntool".to_string(),
            function: "read".to_string(),
            parameters: json!({}),
        };

        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validation_null_byte() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = Action {
            tool: "bad\0tool".to_string(),
            function: "read".to_string(),
            parameters: json!({}),
        };

        let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_log_load() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("nonexistent.jsonl");
        let logger = AuditLogger::new(log_path);

        let entries = logger.load_entries().await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_entries_append() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test]
    async fn test_parent_dir_creation() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("sub").join("dir").join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_hash_chain_integrity() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        // First entry: no prev_hash
        assert!(entries[0].prev_hash.is_none());
        // Subsequent entries: prev_hash equals previous entry_hash
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
        assert_eq!(entries[2].prev_hash, entries[1].entry_hash);
    }

    #[tokio::test]
    async fn test_verify_chain_valid() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 5);
        assert!(verification.first_broken_at.is_none());
    }

    #[tokio::test]
    async fn test_verify_chain_empty() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("nonexistent.jsonl");
        let logger = AuditLogger::new(log_path);

        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 0);
    }

    #[tokio::test]
    async fn test_verify_chain_detects_tampering() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Tamper with the file: modify second entry's action
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut entry1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        entry1.action.tool = "tampered".to_string();
        let tampered_line = serde_json::to_string(&entry1).unwrap();

        let new_content = format!("{}\n{}\n{}\n", lines[0], tampered_line, lines[2]);
        tokio::fs::write(&log_path, new_content).await.unwrap();

        let verification = logger.verify_chain().await.unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_broken_at, Some(1));
    }

    #[tokio::test]
    async fn test_initialize_chain_resumes() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // Write entries with first logger instance
        let logger1 = AuditLogger::new(log_path.clone());
        let action = test_action();
        logger1
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger1
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Create new logger instance and initialize chain
        let logger2 = AuditLogger::new(log_path);
        logger2.initialize_chain().await.unwrap();
        logger2
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Chain should still be valid
        let verification = logger2.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 3);
    }

    #[tokio::test]
    async fn test_backward_compat_legacy_entries() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // Write a legacy entry (no hashes) directly to file
        let legacy = json!({
            "id": "legacy-1",
            "action": {"tool": "test", "function": "fn", "parameters": {}},
            "verdict": "Allow",
            "timestamp": "2026-01-01T00:00:00Z",
            "metadata": {}
        });
        let line = format!("{}\n", serde_json::to_string(&legacy).unwrap());
        tokio::fs::write(&log_path, &line).await.unwrap();

        let logger = AuditLogger::new(log_path);
        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].entry_hash.is_none());
        assert!(entries[0].prev_hash.is_none());

        // Verification should handle legacy entries gracefully
        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
    }
}
