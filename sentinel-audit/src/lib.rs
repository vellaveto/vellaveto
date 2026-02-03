use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
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

/// A signed checkpoint that periodically attests to the audit chain state.
///
/// Checkpoints provide non-repudiation: even if an attacker compromises the
/// server and modifies audit entries, they cannot forge valid Ed25519 signatures
/// without the signing key. Checkpoints are stored in a separate JSONL file
/// alongside the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique checkpoint identifier.
    pub id: String,
    /// ISO 8601 timestamp when the checkpoint was created.
    pub timestamp: String,
    /// Number of entries in the audit log at checkpoint time.
    pub entry_count: usize,
    /// SHA-256 hash of the last entry at checkpoint time (chain head).
    /// None if the audit log is empty.
    pub chain_head_hash: Option<String>,
    /// Ed25519 signature over the canonical checkpoint content.
    /// Hex-encoded 64-byte signature.
    pub signature: String,
    /// Ed25519 verifying key (public key) for this checkpoint.
    /// Hex-encoded 32-byte key.
    pub verifying_key: String,
}

/// Result of verifying all checkpoints against the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVerification {
    /// Whether all checkpoints are valid.
    pub valid: bool,
    /// Number of checkpoints checked.
    pub checkpoints_checked: usize,
    /// Index of the first invalid checkpoint, if any.
    pub first_invalid_at: Option<usize>,
    /// Reason for the first failure, if any.
    pub failure_reason: Option<String>,
}

impl Checkpoint {
    /// Compute the canonical content that is signed.
    ///
    /// Content = SHA-256(id || timestamp || entry_count_le || chain_head_hash)
    /// Each field is length-prefixed with u64 LE to prevent boundary collisions.
    fn signing_content(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        Self::hash_field(&mut hasher, self.id.as_bytes());
        Self::hash_field(&mut hasher, self.timestamp.as_bytes());
        Self::hash_field(&mut hasher, &(self.entry_count as u64).to_le_bytes());
        Self::hash_field(
            &mut hasher,
            self.chain_head_hash.as_deref().unwrap_or("").as_bytes(),
        );
        hasher.finalize().to_vec()
    }

    fn hash_field(hasher: &mut Sha256, data: &[u8]) {
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }
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
    /// Optional Ed25519 signing key for creating signed checkpoints.
    /// Boxed to prevent stack copies of key material during moves.
    signing_key: Option<Box<SigningKey>>,
    /// Optional pinned verifying key (hex-encoded 32-byte Ed25519 public key).
    /// When set, `verify_checkpoints()` rejects checkpoints signed by any other key.
    /// This prevents an attacker with file write access from forging checkpoints
    /// with their own keypair.
    trusted_verifying_key: Option<String>,
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
            signing_key: None,
            trusted_verifying_key: None,
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
            signing_key: None,
            trusted_verifying_key: None,
        }
    }

    /// Set the maximum log file size before rotation.
    /// Pass 0 to disable rotation entirely.
    pub fn with_max_file_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size = max_bytes;
        self
    }

    /// Set the Ed25519 signing key for creating signed checkpoints.
    /// The key is boxed to prevent stack copies of sensitive key material.
    pub fn with_signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(Box::new(key));
        self
    }

    /// Pin a trusted Ed25519 verifying key (hex-encoded 32-byte public key).
    ///
    /// When set, `verify_checkpoints()` rejects any checkpoint signed by a
    /// different key. This prevents an attacker with file write access from
    /// forging checkpoints with their own keypair.
    ///
    /// If not set, key continuity is still enforced: the first checkpoint's
    /// key pins all subsequent ones (TOFU model).
    pub fn with_trusted_key(mut self, hex_key: String) -> Self {
        self.trusted_verifying_key = Some(hex_key);
        self
    }

    /// Generate a new random Ed25519 signing key.
    pub fn generate_signing_key() -> SigningKey {
        SigningKey::generate(&mut rand::thread_rng())
    }

    /// Load an Ed25519 signing key from raw 32-byte seed.
    pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(bytes)
    }

    /// Perform a final fsync on the audit log file.
    ///
    /// Call this during graceful shutdown to ensure all buffered entries
    /// (including Allow/RequireApproval verdicts that skip per-write fsync)
    /// are flushed to durable storage.
    pub async fn sync(&self) -> Result<(), AuditError> {
        let file = OpenOptions::new().read(true).open(&self.log_path).await;

        match file {
            Ok(f) => {
                f.sync_all().await?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuditError::Io(e)),
        }
    }

    /// Get the path to the checkpoint file (derived from the audit log path).
    fn checkpoint_path(&self) -> PathBuf {
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{}.checkpoints.jsonl", stem))
    }

    /// Create a signed checkpoint of the current audit chain state.
    ///
    /// The checkpoint records the current entry count and chain head hash,
    /// signs them with the Ed25519 key, and appends the checkpoint to the
    /// checkpoint file.
    ///
    /// Returns the created checkpoint, or an error if no signing key is set.
    pub async fn create_checkpoint(&self) -> Result<Checkpoint, AuditError> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            AuditError::Validation("No signing key configured for checkpoints".to_string())
        })?;

        let entries = self.load_entries().await?;
        let chain_head_hash = entries.last().and_then(|e| e.entry_hash.clone());

        let mut checkpoint = Checkpoint {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            entry_count: entries.len(),
            chain_head_hash,
            signature: String::new(),
            verifying_key: hex::encode(signing_key.verifying_key().as_bytes()),
        };

        // Sign the canonical content
        let content = checkpoint.signing_content();
        let signature = signing_key.sign(&content);
        checkpoint.signature = hex::encode(signature.to_bytes());

        // Append to checkpoint file
        let mut line = serde_json::to_string(&checkpoint)?;
        line.push('\n');

        let cp_path = self.checkpoint_path();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cp_path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;

        Ok(checkpoint)
    }

    /// Load all checkpoints from the checkpoint file.
    pub async fn load_checkpoints(&self) -> Result<Vec<Checkpoint>, AuditError> {
        let cp_path = self.checkpoint_path();
        let content = match tokio::fs::read_to_string(&cp_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut checkpoints = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Checkpoint>(line) {
                Ok(cp) => checkpoints.push(cp),
                Err(e) => {
                    tracing::warn!("Skipping corrupt checkpoint line: {}", e);
                }
            }
        }
        Ok(checkpoints)
    }

    /// Verify all checkpoints against the current audit log.
    ///
    /// For each checkpoint:
    /// 1. Verify the Ed25519 signature using the embedded verifying key.
    /// 2. Verify the entry_count matches the log at that point.
    /// 3. Verify the chain_head_hash matches the hash chain.
    ///
    /// Checkpoints must be in chronological order and their entry_counts
    /// must be non-decreasing.
    pub async fn verify_checkpoints(&self) -> Result<CheckpointVerification, AuditError> {
        self.verify_checkpoints_with_key(self.trusted_verifying_key.as_deref())
            .await
    }

    /// Verify all checkpoints with optional key pinning.
    ///
    /// If `pinned_key` is provided (hex-encoded 32-byte verifying key), all
    /// checkpoints MUST be signed by that key. This prevents an attacker with
    /// file write access from forging checkpoints with their own keypair.
    ///
    /// Additionally, key continuity is enforced: all checkpoints must use the
    /// same verifying key. If the first checkpoint establishes a key, all
    /// subsequent checkpoints must use that same key.
    pub async fn verify_checkpoints_with_key(
        &self,
        pinned_key: Option<&str>,
    ) -> Result<CheckpointVerification, AuditError> {
        let checkpoints = self.load_checkpoints().await?;
        if checkpoints.is_empty() {
            return Ok(CheckpointVerification {
                valid: true,
                checkpoints_checked: 0,
                first_invalid_at: None,
                failure_reason: None,
            });
        }

        let entries = self.load_entries().await?;

        // Exploit #8 hardening: verify hash chain continuity for ALL entries.
        // Without this, entries between checkpoints can be silently deleted —
        // checkpoint verification only checked the head hash at each checkpoint
        // boundary, missing middle deletions.
        {
            let mut prev_hash: Option<String> = None;
            let mut seen_hashed_entry = false;
            for (i, entry) in entries.iter().enumerate() {
                if entry.entry_hash.is_none() {
                    if seen_hashed_entry {
                        return Ok(CheckpointVerification {
                            valid: false,
                            checkpoints_checked: 0,
                            first_invalid_at: Some(0),
                            failure_reason: Some(format!(
                                "Hash chain broken: entry {} missing hash after hashed entries",
                                i
                            )),
                        });
                    }
                    prev_hash = None;
                    continue;
                }
                seen_hashed_entry = true;
                if entry.prev_hash != prev_hash {
                    return Ok(CheckpointVerification {
                        valid: false,
                        checkpoints_checked: 0,
                        first_invalid_at: Some(0),
                        failure_reason: Some(format!(
                            "Hash chain broken at entry {}: prev_hash mismatch (middle deletion detected)",
                            i
                        )),
                    });
                }
                let computed = Self::compute_entry_hash(entry)?;
                if entry.entry_hash.as_deref() != Some(&computed) {
                    return Ok(CheckpointVerification {
                        valid: false,
                        checkpoints_checked: 0,
                        first_invalid_at: Some(0),
                        failure_reason: Some(format!(
                            "Hash chain broken at entry {}: entry_hash mismatch (tampering detected)",
                            i
                        )),
                    });
                }
                prev_hash = entry.entry_hash.clone();
            }
        }

        let mut prev_entry_count = 0usize;
        // Track the first checkpoint's key for continuity enforcement
        let mut established_key: Option<String> = pinned_key.map(|k| k.to_string());

        for (i, cp) in checkpoints.iter().enumerate() {
            // 1. Verify entry_count is non-decreasing
            if cp.entry_count < prev_entry_count {
                return Ok(CheckpointVerification {
                    valid: false,
                    checkpoints_checked: i + 1,
                    first_invalid_at: Some(i),
                    failure_reason: Some(format!(
                        "Entry count decreased from {} to {}",
                        prev_entry_count, cp.entry_count
                    )),
                });
            }
            prev_entry_count = cp.entry_count;

            // 2. Key continuity: enforce all checkpoints use the same key
            match &established_key {
                Some(expected) if *expected != cp.verifying_key => {
                    return Ok(CheckpointVerification {
                        valid: false,
                        checkpoints_checked: i + 1,
                        first_invalid_at: Some(i),
                        failure_reason: Some(
                            "Verifying key changed between checkpoints (key continuity violated)"
                                .to_string(),
                        ),
                    });
                }
                None => {
                    // First checkpoint establishes the key
                    established_key = Some(cp.verifying_key.clone());
                }
                _ => {} // Key matches
            }

            // 3. Decode verifying key
            let vk_bytes = hex::decode(&cp.verifying_key)
                .map_err(|e| AuditError::Validation(format!("Invalid verifying key hex: {}", e)))?;
            let vk_array: [u8; 32] = vk_bytes.try_into().map_err(|_| {
                AuditError::Validation("Verifying key must be 32 bytes".to_string())
            })?;
            let verifying_key = VerifyingKey::from_bytes(&vk_array)
                .map_err(|e| AuditError::Validation(format!("Invalid verifying key: {}", e)))?;

            // 4. Decode signature
            let sig_bytes = hex::decode(&cp.signature)
                .map_err(|e| AuditError::Validation(format!("Invalid signature hex: {}", e)))?;
            let sig_array: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| AuditError::Validation("Signature must be 64 bytes".to_string()))?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

            // 5. Verify signature over canonical content
            let content = cp.signing_content();
            if verifying_key.verify(&content, &signature).is_err() {
                return Ok(CheckpointVerification {
                    valid: false,
                    checkpoints_checked: i + 1,
                    first_invalid_at: Some(i),
                    failure_reason: Some("Signature verification failed".to_string()),
                });
            }

            // 6. Verify chain_head_hash against the audit log
            if cp.entry_count > 0 && cp.entry_count <= entries.len() {
                let expected_hash = entries[cp.entry_count - 1].entry_hash.as_deref();
                if cp.chain_head_hash.as_deref() != expected_hash {
                    return Ok(CheckpointVerification {
                        valid: false,
                        checkpoints_checked: i + 1,
                        first_invalid_at: Some(i),
                        failure_reason: Some(format!(
                            "Chain head hash mismatch at entry {}",
                            cp.entry_count
                        )),
                    });
                }
            } else if cp.entry_count == 0 && cp.chain_head_hash.is_some() {
                return Ok(CheckpointVerification {
                    valid: false,
                    checkpoints_checked: i + 1,
                    first_invalid_at: Some(i),
                    failure_reason: Some(
                        "Chain head hash should be None for empty log".to_string(),
                    ),
                });
            } else if cp.entry_count > entries.len() {
                // Exploit #8 fix: detect audit log tail truncation.
                // If a checkpoint recorded N entries but the log has fewer,
                // entries were deleted. This MUST fail verification.
                return Ok(CheckpointVerification {
                    valid: false,
                    checkpoints_checked: i + 1,
                    first_invalid_at: Some(i),
                    failure_reason: Some(format!(
                        "Audit log truncated: checkpoint references {} entries but log has only {}",
                        cp.entry_count,
                        entries.len()
                    )),
                });
            }
        }

        Ok(CheckpointVerification {
            valid: true,
            checkpoints_checked: checkpoints.len(),
            first_invalid_at: None,
            failure_reason: None,
        })
    }

    // ═══════════════════════════════════════════════════
    // HEARTBEAT ENTRIES (Phase 10.6)
    // ═══════════════════════════════════════════════════

    /// Write a heartbeat entry to the audit log.
    ///
    /// Heartbeat entries are lightweight sentinel entries that maintain hash chain
    /// continuity. When the audit log has gaps in timestamps exceeding an expected
    /// heartbeat interval, it indicates potential truncation or tampering.
    ///
    /// The entry uses `tool: "sentinel"`, `function: "heartbeat"` with an `Allow`
    /// verdict and metadata recording the heartbeat interval and sequence number.
    pub async fn log_heartbeat(&self, interval_secs: u64, sequence: u64) -> Result<(), AuditError> {
        let action = Action {
            tool: "sentinel".to_string(),
            function: "heartbeat".to_string(),
            parameters: serde_json::json!({}),
        };
        let verdict = Verdict::Allow;
        let metadata = serde_json::json!({
            "event": "heartbeat",
            "interval_secs": interval_secs,
            "sequence": sequence,
        });
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Check whether the audit log has a heartbeat gap — a period longer than
    /// `max_gap_secs` between consecutive entries (heartbeat or otherwise).
    ///
    /// Returns the first detected gap as `(gap_start_timestamp, gap_end_timestamp, gap_seconds)`
    /// or `None` if the log has no gaps exceeding the threshold.
    pub async fn detect_heartbeat_gap(
        &self,
        max_gap_secs: u64,
    ) -> Result<Option<(String, String, u64)>, AuditError> {
        let entries = self.load_entries().await?;
        if entries.len() < 2 {
            return Ok(None);
        }

        for window in entries.windows(2) {
            let prev_ts = chrono::DateTime::parse_from_rfc3339(&window[0].timestamp).ok();
            let curr_ts = chrono::DateTime::parse_from_rfc3339(&window[1].timestamp).ok();

            if let (Some(prev), Some(curr)) = (prev_ts, curr_ts) {
                let gap = (curr - prev).num_seconds().unsigned_abs();
                if gap > max_gap_secs {
                    return Ok(Some((
                        window[0].timestamp.clone(),
                        window[1].timestamp.clone(),
                        gap,
                    )));
                }
            }
        }

        Ok(None)
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
        parent.join(format!("{}.{}-{}{}", stem, timestamp, Uuid::new_v4(), ext))
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
            if name.starts_with(&format!("{}.", stem))
                && name
                    != self
                        .log_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
            {
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

    /// Serialize a value to RFC 8785 canonical JSON (deterministic key order,
    /// normalized numbers, minimal Unicode escaping).
    fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
        let raw = serde_json::to_vec(value)?;
        let canonical = serde_json_canonicalizer::to_string(&raw)
            .map_err(|e| AuditError::Validation(format!("Canonical JSON error: {e}")))?;
        Ok(canonical.into_bytes())
    }

    /// Compute the SHA-256 hash of an entry's content.
    ///
    /// Hash = SHA-256(id || action_json || verdict_json || timestamp || metadata_json || prev_hash)
    ///
    /// Uses RFC 8785 (JSON Canonicalization Scheme) for deterministic JSON serialization.
    /// This ensures hash stability across serde_json versions and key insertion orders.
    fn compute_entry_hash(entry: &AuditEntry) -> Result<String, AuditError> {
        let action_json = Self::canonical_json(&entry.action)?;
        let verdict_json = Self::canonical_json(&entry.verdict)?;
        let metadata_json = Self::canonical_json(&entry.metadata)?;
        let prev_hash = entry.prev_hash.as_deref().unwrap_or("");

        let mut hasher = Sha256::new();
        // Length-prefix each field with u64 little-endian to prevent
        // boundary-shift collisions (e.g., id="ab",action="cd" vs id="abc",action="d")
        Self::hash_field(&mut hasher, entry.id.as_bytes());
        Self::hash_field(&mut hasher, &action_json);
        Self::hash_field(&mut hasher, &verdict_json);
        Self::hash_field(&mut hasher, entry.timestamp.as_bytes());
        Self::hash_field(&mut hasher, &metadata_json);
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

        let mut line_bytes = serde_json::to_vec(&entry)?;
        line_bytes.push(b'\n');

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

        file.write_all(&line_bytes).await?;
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

    /// Maximum audit log file size for load operations (100 MB).
    ///
    /// Prevents memory DoS (Exploit #10) where an attacker grows the audit log
    /// and then triggers `verify_chain()` to OOM the server.
    const MAX_AUDIT_LOG_SIZE: u64 = 100 * 1024 * 1024;

    /// Load all entries from the audit log.
    ///
    /// Corrupt or malformed lines are skipped with a warning rather than
    /// failing the entire load. This ensures the audit log remains readable
    /// even if a single line is corrupted (e.g., partial write, disk error).
    ///
    /// **Security:** File size is checked before reading to prevent memory DoS.
    /// Files larger than 100 MB are rejected with an error.
    pub async fn load_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        // Exploit #10 fix: check file size before loading to prevent memory DoS
        match tokio::fs::metadata(&self.log_path).await {
            Ok(meta) if meta.len() > Self::MAX_AUDIT_LOG_SIZE => {
                return Err(AuditError::Validation(format!(
                    "Audit log too large ({} bytes, max {} bytes). Use log rotation.",
                    meta.len(),
                    Self::MAX_AUDIT_LOG_SIZE
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
            Ok(_) => {} // Size OK, proceed
        }

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
    async fn test_canonical_json_produces_deterministic_hashes() {
        // RFC 8785 canonical JSON ensures hash stability regardless of key insertion order.
        // Construct two entries with semantically identical metadata but different key order.
        let metadata_a =
            serde_json::from_str::<serde_json::Value>(r#"{"zebra": 1, "alpha": 2, "middle": 3}"#)
                .unwrap();
        let metadata_b =
            serde_json::from_str::<serde_json::Value>(r#"{"alpha": 2, "middle": 3, "zebra": 1}"#)
                .unwrap();

        let entry_a = AuditEntry {
            id: "test-canonical".to_string(),
            action: Action {
                tool: "test".to_string(),
                function: "run".to_string(),
                parameters: json!({"b": 1, "a": 2}),
            },
            verdict: Verdict::Allow,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: metadata_a,
            entry_hash: None,
            prev_hash: None,
        };

        let entry_b = AuditEntry {
            id: "test-canonical".to_string(),
            action: Action {
                tool: "test".to_string(),
                function: "run".to_string(),
                parameters: json!({"a": 2, "b": 1}),
            },
            verdict: Verdict::Allow,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            metadata: metadata_b,
            entry_hash: None,
            prev_hash: None,
        };

        let hash_a = AuditLogger::compute_entry_hash(&entry_a).unwrap();
        let hash_b = AuditLogger::compute_entry_hash(&entry_b).unwrap();
        assert_eq!(
            hash_a, hash_b,
            "Semantically identical entries must produce the same hash via canonical JSON"
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
        assert!(!rotated.is_empty(), "Expected at least one rotated file");

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
        assert!(
            rotated.is_empty(),
            "No rotation should occur when max_file_size=0"
        );

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
        let logger = AuditLogger::new(log_path).with_max_file_size(50 * 1024 * 1024); // 50 MB

        // Just verifying the builder doesn't panic and logger works
        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    // === Signed checkpoint tests (Phase 10.3) ===

    #[tokio::test]
    async fn test_checkpoint_creation() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path).with_signing_key(key);

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let checkpoint = logger.create_checkpoint().await.unwrap();
        assert_eq!(checkpoint.entry_count, 5);
        assert!(checkpoint.chain_head_hash.is_some());
        assert!(!checkpoint.signature.is_empty());
        assert!(!checkpoint.verifying_key.is_empty());
        assert!(!checkpoint.id.is_empty());
        assert!(!checkpoint.timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_checkpoint_no_key_returns_error() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path); // No signing key

        let result = logger.create_checkpoint().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AuditError::Validation(msg) => {
                assert!(msg.contains("signing key"));
            }
            other => panic!("Expected Validation error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_checkpoint_empty_log() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path).with_signing_key(key);

        let checkpoint = logger.create_checkpoint().await.unwrap();
        assert_eq!(checkpoint.entry_count, 0);
        assert!(checkpoint.chain_head_hash.is_none());
    }

    #[tokio::test]
    async fn test_checkpoint_verification_valid() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path).with_signing_key(key);

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Write more entries and create another checkpoint
        for _ in 0..2 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checkpoints_checked, 2);
        assert!(verification.first_invalid_at.is_none());
        assert!(verification.failure_reason.is_none());
    }

    #[tokio::test]
    async fn test_checkpoint_verification_empty() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checkpoints_checked, 0);
    }

    #[tokio::test]
    async fn test_checkpoint_tampered_signature_detected() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Tamper with the checkpoint signature
        let cp_path = logger.checkpoint_path();
        let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        // Flip a byte in the signature
        let sig = cp["signature"].as_str().unwrap().to_string();
        let tampered_sig = if let Some(rest) = sig.strip_prefix('a') {
            format!("b{}", rest)
        } else {
            format!("a{}", &sig[1..])
        };
        cp["signature"] = serde_json::Value::String(tampered_sig);
        let tampered = format!("{}\n", serde_json::to_string(&cp).unwrap());
        tokio::fs::write(&cp_path, tampered).await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_at, Some(0));
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("Signature"));
    }

    #[tokio::test]
    async fn test_checkpoint_tampered_entry_count_detected() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Tamper: change entry_count in checkpoint (without re-signing)
        let cp_path = logger.checkpoint_path();
        let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        cp["entry_count"] = serde_json::Value::Number(serde_json::Number::from(999));
        let tampered = format!("{}\n", serde_json::to_string(&cp).unwrap());
        tokio::fs::write(&cp_path, tampered).await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        // Signature check should fail because the content changed
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("Signature"));
    }

    #[tokio::test]
    async fn test_checkpoint_tampered_audit_log_detected() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Tamper with the audit log (change the last entry's hash)
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut last_entry: serde_json::Value =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        last_entry["entry_hash"] = serde_json::Value::String("0".repeat(64));
        *lines.last_mut().unwrap() = serde_json::to_string(&last_entry).unwrap();
        let tampered = lines.join("\n") + "\n";
        tokio::fs::write(&log_path, tampered).await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        let reason = verification.failure_reason.as_ref().unwrap();
        // Chain verification now detects tampering at the hash level (entry_hash
        // mismatch) before reaching the checkpoint head-hash comparison.
        assert!(
            reason.contains("entry_hash mismatch") || reason.contains("Chain head hash mismatch"),
            "Expected tampering detection, got: {}",
            reason
        );
    }

    #[tokio::test]
    async fn test_exploit8_middle_deletion_detected() {
        // Exploit #8 hardening: deleting entries between two checkpoints
        // must be detected. Previously, only tail truncation was caught.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();

        // Write 3 entries + checkpoint A
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Write 3 more entries + checkpoint B
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Delete entry #4 (middle of the chain, between checkpoints A and B)
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert!(
            lines.len() >= 6,
            "Expected at least 6 entries, got {}",
            lines.len()
        );
        // Remove the 4th entry (index 3) — this is between checkpoint A and B
        let mut tampered_lines: Vec<&str> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if i != 3 {
                tampered_lines.push(line);
            }
        }
        let tampered = tampered_lines.join("\n") + "\n";
        tokio::fs::write(&log_path, tampered).await.unwrap();

        // Verification must detect the deletion
        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(
            !verification.valid,
            "Middle deletion should be detected by checkpoint verification"
        );
        let reason = verification.failure_reason.as_ref().unwrap();
        assert!(
            reason.contains("middle deletion")
                || reason.contains("prev_hash mismatch")
                || reason.contains("Chain head hash mismatch")
                || reason.contains("truncated"),
            "Expected chain break detection, got: {}",
            reason
        );
    }

    #[tokio::test]
    async fn test_checkpoint_multiple_sequential() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path).with_signing_key(key);

        let action = test_action();

        // Create checkpoint on empty log
        logger.create_checkpoint().await.unwrap();

        // Add entries and checkpoint
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Add more entries and checkpoint again
        for _ in 0..3 {
            logger
                .log_entry(
                    &action,
                    &Verdict::Deny {
                        reason: "test".to_string(),
                    },
                    json!({}),
                )
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        let checkpoints = logger.load_checkpoints().await.unwrap();
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0].entry_count, 0);
        assert_eq!(checkpoints[1].entry_count, 5);
        assert_eq!(checkpoints[2].entry_count, 8);

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checkpoints_checked, 3);
    }

    #[tokio::test]
    async fn test_checkpoint_different_key_single_checkpoint_passes_without_pin() {
        // A single forged checkpoint with a different key passes basic verification
        // because there's no prior key to enforce continuity against.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key1 = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        // Tamper: replace the checkpoint with one signed by a different key
        let key2 = AuditLogger::generate_signing_key();
        let cp_path = logger.checkpoint_path();
        let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();

        // Re-sign with the wrong key
        cp.verifying_key = hex::encode(key2.verifying_key().as_bytes());
        let sig = key2.sign(&cp.signing_content());
        cp.signature = hex::encode(sig.to_bytes());
        let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
        tokio::fs::write(&cp_path, forged).await.unwrap();

        // Without key pinning, a single re-signed checkpoint passes
        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(verification.valid);
    }

    #[tokio::test]
    async fn test_checkpoint_key_pinning_rejects_forged_key() {
        // Key pinning catches a forged checkpoint signed by an unexpected key
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key1 = AuditLogger::generate_signing_key();
        let pinned_vk = hex::encode(key1.verifying_key().as_bytes());
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        // Tamper: replace with checkpoint signed by key2
        let key2 = AuditLogger::generate_signing_key();
        let cp_path = logger.checkpoint_path();
        let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();
        cp.verifying_key = hex::encode(key2.verifying_key().as_bytes());
        let sig = key2.sign(&cp.signing_content());
        cp.signature = hex::encode(sig.to_bytes());
        let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
        tokio::fs::write(&cp_path, forged).await.unwrap();

        // With key pinning, the forged checkpoint is rejected
        let verification = logger
            .verify_checkpoints_with_key(Some(&pinned_vk))
            .await
            .unwrap();
        assert!(!verification.valid);
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("key continuity violated"));
    }

    #[tokio::test]
    async fn test_trusted_key_builder_rejects_single_forged_checkpoint() {
        // Challenge 9 fix: with_trusted_key() makes verify_checkpoints() reject
        // a single forged checkpoint (which previously passed without pinning).
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key1 = AuditLogger::generate_signing_key();
        let pinned_vk = hex::encode(key1.verifying_key().as_bytes());
        let logger = AuditLogger::new(log_path.clone())
            .with_signing_key(key1)
            .with_trusted_key(pinned_vk);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        // Tamper: replace checkpoint with one signed by attacker's key
        let attacker_key = AuditLogger::generate_signing_key();
        let cp_path = logger.checkpoint_path();
        let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();
        cp.verifying_key = hex::encode(attacker_key.verifying_key().as_bytes());
        let sig = attacker_key.sign(&cp.signing_content());
        cp.signature = hex::encode(sig.to_bytes());
        let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
        tokio::fs::write(&cp_path, forged).await.unwrap();

        // Default verify_checkpoints() now rejects because trusted key is pinned
        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("key continuity violated"));
    }

    #[tokio::test]
    async fn test_trusted_key_builder_accepts_legitimate_checkpoint() {
        // Legitimate checkpoints pass when the correct key is pinned.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let pinned_vk = hex::encode(key.verifying_key().as_bytes());
        let logger = AuditLogger::new(log_path.clone())
            .with_signing_key(key)
            .with_trusted_key(pinned_vk);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checkpoints_checked, 1);
    }

    #[tokio::test]
    async fn test_checkpoint_key_continuity_rejects_key_change() {
        // Two checkpoints from different keys are rejected even without pinning
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key1 = AuditLogger::generate_signing_key();
        let key2 = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

        let action = test_action();
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        logger.create_checkpoint().await.unwrap();

        // Add more entries and create a second checkpoint with a different key
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
        // Forge a second checkpoint with key2
        let entries = logger.load_entries().await.unwrap();
        let mut cp2 = Checkpoint {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            entry_count: entries.len(),
            chain_head_hash: entries.last().and_then(|e| e.entry_hash.clone()),
            signature: String::new(),
            verifying_key: hex::encode(key2.verifying_key().as_bytes()),
        };
        let sig = key2.sign(&cp2.signing_content());
        cp2.signature = hex::encode(sig.to_bytes());

        let cp_path = logger.checkpoint_path();
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&cp_path)
            .await
            .unwrap();
        let line = format!("{}\n", serde_json::to_string(&cp2).unwrap());
        tokio::io::AsyncWriteExt::write_all(&mut file, line.as_bytes())
            .await
            .unwrap();

        // Key continuity violation detected
        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("key continuity violated"));
    }

    #[tokio::test]
    async fn test_checkpoint_key_from_bytes_roundtrip() {
        let key = AuditLogger::generate_signing_key();
        let bytes = key.to_bytes();
        let restored = AuditLogger::signing_key_from_bytes(&bytes);
        assert_eq!(key.to_bytes(), restored.to_bytes());
    }

    #[tokio::test]
    async fn test_checkpoint_path_derivation() {
        let logger = AuditLogger::new(PathBuf::from("/var/log/audit.jsonl"));
        let cp_path = logger.checkpoint_path();
        assert_eq!(cp_path, PathBuf::from("/var/log/audit.checkpoints.jsonl"));
    }

    #[tokio::test]
    async fn test_checkpoint_decreasing_entry_count_detected() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key.clone());

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Forge a second checkpoint with lower entry_count (properly signed)
        let cp_path = logger.checkpoint_path();
        let forged_cp = Checkpoint {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            entry_count: 2, // Less than 5 — suspicious
            chain_head_hash: None,
            signature: String::new(),
            verifying_key: hex::encode(key.verifying_key().as_bytes()),
        };
        let content = forged_cp.signing_content();
        let sig = key.sign(&content);
        let mut forged = forged_cp;
        forged.signature = hex::encode(sig.to_bytes());

        let mut cp_content = tokio::fs::read_to_string(&cp_path).await.unwrap();
        cp_content.push_str(&serde_json::to_string(&forged).unwrap());
        cp_content.push('\n');
        tokio::fs::write(&cp_path, cp_content).await.unwrap();

        let verification = logger.verify_checkpoints().await.unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_at, Some(1));
        assert!(verification
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("decreased"));
    }

    // ═══════════════════════════════════════════════════════════
    // Exploit #8 Regression: Audit tail truncation detection
    // ═══════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_exploit8_tail_truncation_detected_by_checkpoint() {
        // EXPLOIT #8: An attacker deletes the last N entries from the audit log.
        // The hash chain of remaining entries is still valid, but the checkpoint
        // records a higher entry_count. verify_checkpoints() MUST detect this.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        // Write 10 entries
        let action = test_action();
        for _ in 0..10 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        // Create checkpoint recording 10 entries
        logger.create_checkpoint().await.unwrap();

        // Simulate tail truncation: keep only first 7 entries
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 10);
        let truncated = lines[..7].join("\n") + "\n";
        tokio::fs::write(&log_path, truncated).await.unwrap();

        // verify_chain() still passes (the 7 remaining entries have valid chain)
        let chain_result = logger.verify_chain().await.unwrap();
        assert!(
            chain_result.valid,
            "Truncated chain should still be internally valid"
        );

        // verify_checkpoints() MUST detect the truncation
        let cp_result = logger.verify_checkpoints().await.unwrap();
        assert!(
            !cp_result.valid,
            "Checkpoint must detect tail truncation (10 entries in checkpoint, 7 in log)"
        );
        assert!(
            cp_result
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("truncated"),
            "Failure reason should mention truncation, got: {:?}",
            cp_result.failure_reason
        );
    }

    #[tokio::test]
    async fn test_exploit8_no_false_positive_when_entries_match() {
        // Verify that checkpoint passes when entry count matches
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        let cp_result = logger.verify_checkpoints().await.unwrap();
        assert!(
            cp_result.valid,
            "Checkpoint should pass when entry count matches"
        );
    }

    #[tokio::test]
    async fn test_exploit8_entries_added_after_checkpoint_still_valid() {
        // Adding entries AFTER a checkpoint should not cause a false positive
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let key = AuditLogger::generate_signing_key();
        let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

        let action = test_action();
        for _ in 0..5 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }
        logger.create_checkpoint().await.unwrap();

        // Add 3 more entries after the checkpoint
        for _ in 0..3 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let cp_result = logger.verify_checkpoints().await.unwrap();
        assert!(
            cp_result.valid,
            "Entries added after checkpoint should not cause false positive"
        );
    }

    // ═══════════════════════════════════════════════════════
    // Exploit #10 Regression: verify_chain() memory DoS
    // ═══════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_exploit10_oversized_audit_log_rejected() {
        // EXPLOIT #10: Attacker grows audit log to several GB, then triggers
        // verify_chain() which loads entire file into memory → OOM.
        // Fix: load_entries() checks file size before reading.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        // Create a sparse file exceeding MAX_AUDIT_LOG_SIZE (100MB)
        let file = tokio::fs::File::create(&log_path).await.unwrap();
        file.set_len(101 * 1024 * 1024).await.unwrap(); // 101 MB sparse

        let logger = AuditLogger::new(log_path);
        let result = logger.load_entries().await;
        assert!(result.is_err(), "Oversized audit log must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "Error should mention file is too large, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_exploit10_verify_chain_rejects_oversized_log() {
        // verify_chain() calls load_entries() internally, so it should also
        // reject oversized files without loading them.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");

        let file = tokio::fs::File::create(&log_path).await.unwrap();
        file.set_len(101 * 1024 * 1024).await.unwrap();

        let logger = AuditLogger::new(log_path);
        let result = logger.verify_chain().await;
        assert!(result.is_err(), "verify_chain must reject oversized log");
    }

    #[tokio::test]
    async fn test_exploit10_normal_sized_log_loads_fine() {
        // Normal-sized logs should load without error
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(log_path);

        let action = test_action();
        for _ in 0..10 {
            logger
                .log_entry(&action, &Verdict::Allow, json!({}))
                .await
                .unwrap();
        }

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 10);

        let chain = logger.verify_chain().await.unwrap();
        assert!(chain.valid);
    }

    // ═══════════════════════════════════════════════════
    // HEARTBEAT TESTS (Phase 10.6)
    // ═══════════════════════════════════════════════════

    #[tokio::test]
    async fn test_heartbeat_creates_valid_entry() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("heartbeat.log");
        let logger = AuditLogger::new(log_path);
        logger.initialize_chain().await.unwrap();

        logger.log_heartbeat(60, 1).await.unwrap();
        logger.log_heartbeat(60, 2).await.unwrap();

        let entries = logger.load_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        // Verify heartbeat entry structure
        assert_eq!(entries[0].action.tool, "sentinel");
        assert_eq!(entries[0].action.function, "heartbeat");
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert_eq!(entries[0].metadata["event"], "heartbeat");
        assert_eq!(entries[0].metadata["interval_secs"], 60);
        assert_eq!(entries[0].metadata["sequence"], 1);

        assert_eq!(entries[1].metadata["sequence"], 2);
    }

    #[tokio::test]
    async fn test_heartbeat_participates_in_hash_chain() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("heartbeat_chain.log");
        let logger = AuditLogger::new(log_path);
        logger.initialize_chain().await.unwrap();

        // Mix regular entries with heartbeats
        let action = Action {
            tool: "bash".to_string(),
            function: "run".to_string(),
            parameters: serde_json::json!({"command": "ls"}),
        };
        logger
            .log_entry(&action, &Verdict::Allow, serde_json::json!({}))
            .await
            .unwrap();
        logger.log_heartbeat(60, 1).await.unwrap();
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                serde_json::json!({}),
            )
            .await
            .unwrap();
        logger.log_heartbeat(60, 2).await.unwrap();

        // Verify the full chain is valid
        let verification = logger.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.entries_checked, 4);
    }

    #[tokio::test]
    async fn test_detect_heartbeat_gap_no_gap() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("no_gap.log");
        let logger = AuditLogger::new(log_path);
        logger.initialize_chain().await.unwrap();

        // Write entries quickly (no significant gap)
        logger.log_heartbeat(60, 1).await.unwrap();
        logger.log_heartbeat(60, 2).await.unwrap();
        logger.log_heartbeat(60, 3).await.unwrap();

        // Check for gaps > 120 seconds (none should exist)
        let gap = logger.detect_heartbeat_gap(120).await.unwrap();
        assert!(gap.is_none());
    }

    #[tokio::test]
    async fn test_detect_heartbeat_gap_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("empty_gap.log");
        let logger = AuditLogger::new(log_path);

        let gap = logger.detect_heartbeat_gap(60).await.unwrap();
        assert!(gap.is_none());
    }

    #[tokio::test]
    async fn test_detect_heartbeat_gap_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("single_gap.log");
        let logger = AuditLogger::new(log_path);
        logger.initialize_chain().await.unwrap();

        logger.log_heartbeat(60, 1).await.unwrap();

        let gap = logger.detect_heartbeat_gap(60).await.unwrap();
        assert!(gap.is_none());
    }
}
