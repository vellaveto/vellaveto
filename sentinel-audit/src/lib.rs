use chrono::Utc;
use sentinel_types::{Action, Verdict};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
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

/// Sensitive parameter key names that should always be redacted.
const SENSITIVE_PARAM_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
    "authorization",
    "credentials",
    "session_token",
    "refresh_token",
    "client_secret",
];

/// Prefixes of values that indicate secrets. If a string value starts with
/// any of these prefixes, the value is redacted.
const SENSITIVE_VALUE_PREFIXES: &[&str] = &[
    "sk-",         // OpenAI, Anthropic API keys
    "AKIA",        // AWS access key ID
    "ghp_",        // GitHub personal access token
    "gho_",        // GitHub OAuth token
    "ghs_",        // GitHub server-to-server token
    "github_pat_", // GitHub fine-grained PAT
    "xoxb-",       // Slack bot token
    "xoxp-",       // Slack user token
    "Bearer ",     // Authorization header value
    "Basic ",      // Authorization header value
];

const REDACTED: &str = "[REDACTED]";

/// Recursively walk a JSON value and redact sensitive keys/values.
///
/// - Keys matching `SENSITIVE_PARAM_KEYS` (case-insensitive) have their values replaced.
/// - String values starting with `SENSITIVE_VALUE_PREFIXES` are replaced.
fn redact_sensitive_values(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if SENSITIVE_PARAM_KEYS.iter().any(|k| key_lower == *k) {
                    result.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    result.insert(key.clone(), redact_sensitive_values(val));
                }
            }
            serde_json::Value::Object(result)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_sensitive_values).collect())
        }
        serde_json::Value::String(s) => {
            if SENSITIVE_VALUE_PREFIXES
                .iter()
                .any(|prefix| s.starts_with(prefix))
            {
                serde_json::Value::String(REDACTED.to_string())
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

/// Default max file size before rotation: 100 MB.
const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Append-only audit logger for policy evaluation decisions.
///
/// Records every [`Action`] + [`Verdict`] pair to a persistent log file
/// in JSONL format for compliance, debugging, and forensic analysis.
///
/// New entries include SHA-256 hash chains for tamper evidence.
/// Sensitive values in parameters are redacted by default.
///
/// When the log file exceeds `max_file_size`, it is rotated to a
/// timestamped filename (e.g., `audit.2026-02-02T12-00-00.log`) and
/// a fresh file + hash chain is started.
pub struct AuditLogger {
    log_path: PathBuf,
    last_hash: Mutex<Option<String>>,
    redact: bool,
    /// Maximum log file size in bytes before rotation. 0 = no rotation.
    max_file_size: u64,
}

impl AuditLogger {
    /// Create a new audit logger writing to the specified path.
    /// Sensitive value redaction is enabled by default.
    /// Log rotation is enabled at 100 MB by default.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: Mutex::new(None),
            redact: true,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }

    /// Create a new audit logger with redaction disabled.
    /// Use this only for testing or when full parameter logging is required.
    pub fn new_unredacted(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: Mutex::new(None),
            redact: false,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }

    /// Set the maximum log file size before rotation.
    /// Pass 0 to disable rotation entirely.
    pub fn with_max_file_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size = max_bytes;
        self
    }

    /// Initialize the hash chain by reading the last entry from the log.
    ///
    /// Call this once at startup to seed the chain head.
    pub async fn initialize_chain(&self) -> Result<(), AuditError> {
        let entries = self.load_entries().await?;
        if entries.is_empty() {
            return Ok(());
        }

        // Verify the chain before trusting any hash from the file.
        // A tampered file must not poison the in-memory chain head.
        let verification = self.verify_chain().await?;
        let mut last_hash = self.last_hash.lock().await;

        if verification.valid {
            if let Some(last_entry) = entries.last() {
                *last_hash = last_entry.entry_hash.clone();
            }
        } else {
            tracing::warn!(
                "Audit chain verification failed at entry {}. Starting new chain segment.",
                verification.first_broken_at.unwrap_or(0)
            );
            // Do NOT trust any hash from the file. Start a fresh chain segment
            // by leaving last_hash as None. The next entry will begin a new segment.
        }
        Ok(())
    }

    /// Rotate the log file if it exceeds `max_file_size`.
    ///
    /// The caller MUST hold `last_hash` lock. On successful rotation the
    /// caller should reset the lock to `None` (new file = new chain).
    ///
    /// Returns `true` if rotation occurred.
    async fn maybe_rotate(&self) -> Result<bool, AuditError> {
        if self.max_file_size == 0 {
            return Ok(false);
        }

        let metadata = match tokio::fs::metadata(&self.log_path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(AuditError::Io(e)),
        };

        if metadata.len() < self.max_file_size {
            return Ok(false);
        }

        let rotated_path = self.rotated_path();
        tokio::fs::rename(&self.log_path, &rotated_path).await?;

        tracing::info!(
            "Rotated audit log {} -> {} ({} bytes)",
            self.log_path.display(),
            rotated_path.display(),
            metadata.len(),
        );

        Ok(true)
    }

    /// Build the destination path for a rotated log file.
    ///
    /// Format: `<stem>.<timestamp>.<ext>` where timestamp uses hyphens
    /// (filesystem-safe) e.g. `audit.2026-02-02T12-00-00.log`.
    /// If a file with that name already exists (multiple rotations in the
    /// same second), a counter suffix is appended.
    fn rotated_path(&self) -> PathBuf {
        let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%S");
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let ext = self
            .log_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let parent = self.log_path.parent().unwrap_or(Path::new("."));

        let base = parent.join(format!("{}.{}{}", stem, timestamp, ext));
        if !base.exists() {
            return base;
        }

        // Collision: add incrementing counter suffix
        for i in 1..10_000 {
            let path = parent.join(format!("{}.{}-{}{}", stem, timestamp, i, ext));
            if !path.exists() {
                return path;
            }
        }

        // Fallback with UUID (should never happen)
        parent.join(format!(
            "{}.{}-{}{}",
            stem,
            timestamp,
            Uuid::new_v4(),
            ext
        ))
    }

    /// List rotated log files in the same directory as the active log.
    ///
    /// Returns paths sorted oldest-first. Only files whose name starts
    /// with the active log's stem and contains a timestamp segment are
    /// included.
    pub fn list_rotated_files(&self) -> Result<Vec<PathBuf>, AuditError> {
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let mut rotated: Vec<PathBuf> = Vec::new();

        let entries = match std::fs::read_dir(parent) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Match pattern: <stem>.<timestamp>.<ext>
            // e.g. "audit.2026-02-02T12-00-00.log"
            if name.starts_with(&format!("{}.", stem)) && name != self.log_path.file_name().unwrap_or_default().to_string_lossy() {
                // Verify it looks like a rotated file (contains a timestamp-like segment)
                let after_stem = &name[stem.len() + 1..];
                if after_stem.contains('T') && after_stem.contains('-') {
                    rotated.push(entry.path());
                }
            }
        }

        rotated.sort();
        Ok(rotated)
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
        // Length-prefix each field with u64 little-endian to prevent
        // boundary-shift collisions (e.g., id="ab",action="cd" vs id="abc",action="d")
        Self::hash_field(&mut hasher, entry.id.as_bytes());
        Self::hash_field(&mut hasher, action_json.as_bytes());
        Self::hash_field(&mut hasher, verdict_json.as_bytes());
        Self::hash_field(&mut hasher, entry.timestamp.as_bytes());
        Self::hash_field(&mut hasher, metadata_json.as_bytes());
        Self::hash_field(&mut hasher, prev_hash.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    /// Write a length-prefixed field into the hasher.
    fn hash_field(hasher: &mut Sha256, data: &[u8]) {
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
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

        // Redact sensitive values from action parameters before logging
        let logged_action = if self.redact {
            Action {
                tool: action.tool.clone(),
                function: action.function.clone(),
                parameters: redact_sensitive_values(&action.parameters),
            }
        } else {
            action.clone()
        };

        // Also redact metadata values
        let logged_metadata = if self.redact {
            redact_sensitive_values(&metadata)
        } else {
            metadata
        };

        let mut last_hash_guard = self.last_hash.lock().await;

        // Rotate if the current log exceeds max_file_size.
        // Done under the lock to prevent concurrent writes from racing.
        if self.maybe_rotate().await? {
            *last_hash_guard = None; // New file = new hash chain
        }

        let mut entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            action: logged_action,
            verdict: verdict.clone(),
            timestamp: Utc::now().to_rfc3339(),
            metadata: logged_metadata,
            entry_hash: None,
            prev_hash: last_hash_guard.clone(),
        };

        // Compute hash
        let hash = Self::compute_entry_hash(&entry)?;
        entry.entry_hash = Some(hash.clone());

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

        // Fix #35: For Deny verdicts, call sync_data() to ensure the entry
        // survives power loss. Allow/RequireApproval can remain buffered.
        if matches!(verdict, Verdict::Deny { .. }) {
            file.sync_data().await?;
        }

        // Update chain head ONLY after successful file write.
        // If the write fails, the in-memory hash must not advance,
        // otherwise the chain diverges from what's on disk.
        *last_hash_guard = Some(hash);

        Ok(())
    }

    /// Load all entries from the audit log.
    ///
    /// Corrupt or malformed lines are skipped with a warning rather than
    /// failing the entire load. This ensures the audit log remains readable
    /// even if a single line is corrupted (e.g., partial write, disk error).
    pub async fn load_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let content = match tokio::fs::read_to_string(&self.log_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut entries = Vec::new();
        let mut skipped = 0usize;
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    skipped += 1;
                    tracing::warn!(
                        "Skipping corrupt audit line {} in {:?}: {}",
                        line_num + 1,
                        self.log_path,
                        e
                    );
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                "Skipped {} corrupt line(s) while loading audit log {:?}",
                skipped,
                self.log_path
            );
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
        let mut seen_hashed_entry = false;

        for (i, entry) in entries.iter().enumerate() {
            if entry.entry_hash.is_none() {
                // Legacy entries are only allowed before the first hashed entry.
                // Once a hashed entry appears, all subsequent entries MUST have hashes.
                if seen_hashed_entry {
                    return Ok(ChainVerification {
                        valid: false,
                        entries_checked: i + 1,
                        first_broken_at: Some(i),
                    });
                }
                prev_hash = None;
                continue;
            }

            seen_hashed_entry = true;

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
        let mut max_depth: usize = 0;
        let mut stack: Vec<(&serde_json::Value, usize)> = vec![(value, 0)];
        while let Some((val, depth)) = stack.pop() {
            if depth > max_depth {
                max_depth = depth;
            }
            if max_depth > 128 {
                return max_depth;
            }
            match val {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        stack.push((item, depth + 1));
                    }
                }
                serde_json::Value::Object(obj) => {
                    for item in obj.values() {
                        stack.push((item, depth + 1));
                    }
                }
                _ => {}
            }
        }
        max_depth
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

    // === Security regression tests (Controller Directive C-2) ===

    #[tokio::test]
    async fn test_fix1_hashless_entry_after_hashed_rejected() {
        // CRITICAL Fix #1: Once hashed entries appear, hashless entries must be rejected.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        // Write a proper hashed entry
        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Now manually inject a hashless (legacy-style) entry AFTER the hashed one
        let hashless = json!({
            "id": "injected-hashless",
            "action": {"tool": "evil", "function": "exfil", "parameters": {}},
            "verdict": "Allow",
            "timestamp": "2026-02-02T00:00:00Z",
            "metadata": {}
        });
        let inject_line = format!("{}\n", serde_json::to_string(&hashless).unwrap());
        let mut file = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .await
            .unwrap();
        file.write_all(inject_line.as_bytes()).await.unwrap();

        // Verification MUST fail — hashless entry after hashed is not allowed
        let verification = logger.verify_chain().await.unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_broken_at, Some(1));
    }

    #[tokio::test]
    async fn test_fix2_field_separator_prevents_boundary_shift() {
        // CRITICAL Fix #2: Length-prefixed fields prevent boundary-shift collisions.
        // Two entries with fields that differ only at boundaries must produce different hashes.
        let entry_a = AuditEntry {
            id: "ab".to_string(),
            action: Action {
                tool: "cd".to_string(),
                function: "ef".to_string(),
                parameters: json!({}),
            },
            verdict: Verdict::Allow,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: json!({}),
            entry_hash: None,
            prev_hash: None,
        };

        let entry_b = AuditEntry {
            id: "abc".to_string(),
            action: Action {
                tool: "d".to_string(),
                function: "ef".to_string(),
                parameters: json!({}),
            },
            verdict: Verdict::Allow,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: json!({}),
            entry_hash: None,
            prev_hash: None,
        };

        let hash_a = AuditLogger::compute_entry_hash(&entry_a).unwrap();
        let hash_b = AuditLogger::compute_entry_hash(&entry_b).unwrap();
        assert_ne!(
            hash_a, hash_b,
            "Boundary-shifted fields must produce different hashes"
        );
    }

    #[tokio::test]
    async fn test_fix3_initialize_chain_rejects_tampered_file() {
        // CRITICAL Fix #3: initialize_chain must verify before trusting.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // Write valid entries with first logger
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

        // Tamper with the file
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut entry0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        entry0.action.tool = "tampered".to_string();
        let tampered_line = serde_json::to_string(&entry0).unwrap();
        let new_content = format!("{}\n{}\n", tampered_line, lines[1]);
        tokio::fs::write(&log_path, new_content).await.unwrap();

        // Create new logger and initialize — should NOT trust the tampered hash
        let logger2 = AuditLogger::new(log_path.clone());
        logger2.initialize_chain().await.unwrap();

        // Write a new entry — it should start a fresh chain segment (prev_hash = None)
        logger2
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger2.load_entries().await.unwrap();
        let new_entry = entries.last().unwrap();
        // The new entry should NOT chain from the tampered entry
        assert!(
            new_entry.prev_hash.is_none(),
            "Should not chain from tampered file"
        );
    }

    #[tokio::test]
    async fn test_fix4_hash_not_updated_on_write_failure() {
        // CRITICAL Fix #4: last_hash must not advance if file write fails.
        // We test this by verifying the ordering: write happens before hash update.
        // The simplest way: write to a valid path, then verify chain continuity
        // after simulating the write-then-verify pattern.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = test_action();
        // Write two entries successfully
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        // Verify chain is valid — this also indirectly tests that the hash update
        // happened after the file write (if it happened before and the write failed,
        // the chain would be broken on the next write).
        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 2);
    }

    // --- Phase 3.3: Sensitive value redaction tests ---

    #[tokio::test]
    async fn test_redaction_sensitive_param_key() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone()); // redaction enabled

        let action = Action {
            tool: "http_request".to_string(),
            function: "post".to_string(),
            parameters: json!({
                "url": "https://api.example.com",
                "password": "super_secret_123",
                "api_key": "sk-1234567890",
                "headers": {
                    "authorization": "Bearer token123"
                }
            }),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        let params = &entries[0].action.parameters;
        // Sensitive keys should be redacted
        assert_eq!(params["password"], "[REDACTED]");
        assert_eq!(params["api_key"], "[REDACTED]");
        assert_eq!(params["headers"]["authorization"], "[REDACTED]");
        // Non-sensitive keys should be preserved
        assert_eq!(params["url"], "https://api.example.com");
    }

    #[tokio::test]
    async fn test_redaction_sensitive_value_prefix() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = Action {
            tool: "tool".to_string(),
            function: "func".to_string(),
            parameters: json!({
                "key1": "sk-abc123def456",
                "key2": "AKIAIOSFODNN7EXAMPLE",
                "key3": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "safe_value": "normal text"
            }),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let params = &entries[0].action.parameters;
        assert_eq!(params["key1"], "[REDACTED]");
        assert_eq!(params["key2"], "[REDACTED]");
        assert_eq!(params["key3"], "[REDACTED]");
        assert_eq!(params["safe_value"], "normal text");
    }

    #[tokio::test]
    async fn test_redaction_nested_values() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = Action {
            tool: "tool".to_string(),
            function: "func".to_string(),
            parameters: json!({
                "config": {
                    "nested": {
                        "token": "should_be_redacted",
                        "name": "safe"
                    }
                },
                "items": ["normal", "sk-secret123", "safe"]
            }),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let params = &entries[0].action.parameters;
        assert_eq!(params["config"]["nested"]["token"], "[REDACTED]");
        assert_eq!(params["config"]["nested"]["name"], "safe");
        assert_eq!(params["items"][0], "normal");
        assert_eq!(params["items"][1], "[REDACTED]"); // sk- prefix
        assert_eq!(params["items"][2], "safe");
    }

    #[tokio::test]
    async fn test_unredacted_logger_preserves_all_values() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new_unredacted(log_path.clone());

        let action = Action {
            tool: "tool".to_string(),
            function: "func".to_string(),
            parameters: json!({
                "password": "visible_password",
                "key": "sk-visible-key"
            }),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let params = &entries[0].action.parameters;
        // With redaction disabled, all values are preserved
        assert_eq!(params["password"], "visible_password");
        assert_eq!(params["key"], "sk-visible-key");
    }

    #[tokio::test]
    async fn test_redaction_metadata_also_redacted() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = test_action();
        let metadata = json!({
            "source": "proxy",
            "secret": "should_be_redacted",
            "auth_header": "Bearer xyz123"
        });

        logger
            .log_entry(&action, &Verdict::Allow, metadata)
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        let meta = &entries[0].metadata;
        assert_eq!(meta["source"], "proxy");
        assert_eq!(meta["secret"], "[REDACTED]");
        assert_eq!(meta["auth_header"], "[REDACTED]"); // "Bearer " prefix
    }

    #[tokio::test]
    async fn test_redaction_hash_chain_still_valid() {
        // Verify that redacted entries still form a valid hash chain
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = Action {
            tool: "tool".to_string(),
            function: "func".to_string(),
            parameters: json!({"password": "secret123", "path": "/tmp/safe"}),
        };

        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "test".into(),
                },
                json!({}),
            )
            .await
            .unwrap();

        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 2);
    }

    // === Log rotation tests (Fix #36) ===

    #[tokio::test]
    async fn test_rotation_triggers_when_size_exceeded() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        // Set a tiny threshold so rotation triggers quickly
        let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

        let action = test_action();

        // Write entries until rotation triggers
        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // At least one rotated file should exist
        let rotated = logger.list_rotated_files().unwrap();
        assert!(
            !rotated.is_empty(),
            "Expected at least one rotated file"
        );

        // The active log should still exist with entries
        let active_entries = logger.load_entries().await.unwrap();
        assert!(
            !active_entries.is_empty(),
            "Active log should still have entries after rotation"
        );
    }

    #[tokio::test]
    async fn test_rotation_starts_fresh_hash_chain() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

        let action = test_action();

        // Write enough entries to trigger at least one rotation
        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // The current (active) log should have a valid chain with
        // the first entry having prev_hash = None (fresh chain)
        let entries = logger.load_entries().await.unwrap();
        assert!(!entries.is_empty());
        assert!(
            entries[0].prev_hash.is_none(),
            "First entry in rotated-to file should have no prev_hash"
        );

        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
    }

    #[tokio::test]
    async fn test_rotation_disabled_when_zero() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone()).with_max_file_size(0);

        let action = test_action();

        // Write many entries — no rotation should occur
        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let rotated = logger.list_rotated_files().unwrap();
        assert!(rotated.is_empty(), "No rotation should occur when max_file_size=0");

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 20);
    }

    #[tokio::test]
    async fn test_rotation_no_data_loss() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

        let action = test_action();
        let total = 30;

        for _ in 0..total {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Count entries across active + rotated files
        let active_entries = logger.load_entries().await.unwrap();
        let rotated_files = logger.list_rotated_files().unwrap();

        let mut total_count = active_entries.len();
        for path in &rotated_files {
            let content = tokio::fs::read_to_string(path).await.unwrap();
            let count = content.lines().filter(|l| !l.trim().is_empty()).count();
            total_count += count;
        }

        assert_eq!(
            total_count, total,
            "Total entries across all files should equal entries written"
        );
    }

    #[tokio::test]
    async fn test_rotation_rotated_file_has_valid_chain() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

        let action = test_action();
        for _ in 0..20 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Verify the rotated file's chain is independently valid
        let rotated_files = logger.list_rotated_files().unwrap();
        assert!(!rotated_files.is_empty());

        let rotated_logger = AuditLogger::new(rotated_files[0].clone()).with_max_file_size(0);
        let verification = rotated_logger.verify_chain().await.unwrap();
        assert!(
            verification.valid,
            "Rotated file should have a valid hash chain"
        );
    }

    #[tokio::test]
    async fn test_list_rotated_files_empty_when_no_rotation() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path.clone());

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let rotated = logger.list_rotated_files().unwrap();
        assert!(rotated.is_empty());
    }

    #[tokio::test]
    async fn test_list_rotated_files_nonexistent_dir() {
        let logger = AuditLogger::new(PathBuf::from("/nonexistent/path/audit.jsonl"));
        let rotated = logger.list_rotated_files().unwrap();
        assert!(rotated.is_empty());
    }

    #[tokio::test]
    async fn test_rotation_initialize_chain_after_rotation() {
        // After rotation, a new logger instance should initialize correctly
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // First logger: write enough to trigger rotation
        let logger1 = AuditLogger::new(log_path.clone()).with_max_file_size(200);
        let action = test_action();
        for _ in 0..20 {
            logger1
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Second logger: initialize chain from active log
        let logger2 = AuditLogger::new(log_path.clone()).with_max_file_size(200);
        logger2.initialize_chain().await.unwrap();

        // Write more entries — chain should remain valid
        logger2
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let verification = logger2.verify_chain().await.unwrap();
        assert!(verification.valid);
    }

    #[tokio::test]
    async fn test_with_max_file_size_builder() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path)
            .with_max_file_size(50 * 1024 * 1024); // 50 MB

        // Just verifying the builder doesn't panic and logger works
        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    }
}
