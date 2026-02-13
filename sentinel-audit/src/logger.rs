use crate::pii::PiiScanner;
use crate::redaction::{
    redact_keys_and_patterns, redact_keys_and_patterns_with_scanner, redact_keys_only, PII_REGEXES,
    REDACTED,
};
use crate::types::{AuditEntry, AuditError, RedactionLevel};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use sentinel_types::{Action, Verdict};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::pii::CustomPiiPattern;
use crate::rotation::DEFAULT_MAX_FILE_SIZE;

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
    pub(crate) log_path: PathBuf,
    pub(crate) last_hash: Mutex<Option<String>>,
    pub(crate) redaction_level: RedactionLevel,
    /// Maximum log file size in bytes before rotation. 0 = no rotation.
    pub(crate) max_file_size: u64,
    /// Optional Ed25519 signing key for creating signed checkpoints.
    /// Boxed to prevent stack copies of key material during moves.
    pub(crate) signing_key: Option<Box<SigningKey>>,
    /// Optional pinned verifying key (hex-encoded 32-byte Ed25519 public key).
    /// When set, `verify_checkpoints()` rejects checkpoints signed by any other key.
    /// This prevents an attacker with file write access from forging checkpoints
    /// with their own keypair.
    pub(crate) trusted_verifying_key: Option<String>,
    /// Optional PII scanner with custom patterns (replaces global PII_REGEXES).
    /// When present, uses substring redaction instead of whole-value replacement.
    pub(crate) pii_scanner: Option<PiiScanner>,
    /// In-memory entry count for the current log file.
    /// Incremented after each successful write. Reset to 0 on rotation.
    /// Used to avoid re-reading the file to count entries during rotation.
    pub(crate) entry_count: AtomicU64,
}

impl AuditLogger {
    /// Create a new audit logger writing to the specified path.
    /// Sensitive value redaction is enabled by default.
    /// Log rotation is enabled at 100 MB by default.
    ///
    /// SECURITY (R22-SUP-1): A default PiiScanner is always constructed so that
    /// credit card (with Luhn), JWT, IPv4, and AWS key patterns are applied even
    /// when no custom patterns are configured. The legacy PII_REGEXES fallback
    /// (email/SSN/phone only) is never used.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: Mutex::new(None),
            redaction_level: RedactionLevel::KeysAndPatterns,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            signing_key: None,
            trusted_verifying_key: None,
            pii_scanner: Some(PiiScanner::new(&[])),
            entry_count: AtomicU64::new(0),
        }
    }

    /// Create a new audit logger with redaction disabled.
    /// Use this only for testing or when full parameter logging is required.
    pub fn new_unredacted(log_path: PathBuf) -> Self {
        Self {
            log_path,
            last_hash: Mutex::new(None),
            redaction_level: RedactionLevel::Off,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            signing_key: None,
            trusted_verifying_key: None,
            pii_scanner: None,
            entry_count: AtomicU64::new(0),
        }
    }

    /// Set the redaction level for audit log entries.
    pub fn with_redaction_level(mut self, level: RedactionLevel) -> Self {
        self.redaction_level = level;
        self
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

    /// Set custom PII patterns for enhanced detection.
    ///
    /// When called, a `PiiScanner` is built with both default and custom patterns.
    /// The scanner uses **substring** replacement (e.g., `"Call 555-123-4567"` →
    /// `"Call [REDACTED]"`) instead of the legacy whole-value replacement.
    pub fn with_custom_pii_patterns(mut self, patterns: &[CustomPiiPattern]) -> Self {
        self.pii_scanner = Some(PiiScanner::new(patterns));
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

    /// Serialize a value to RFC 8785 canonical JSON (deterministic key order,
    /// normalized numbers, minimal Unicode escaping).
    pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
        let raw = serde_json::to_vec(value)?;
        let canonical = serde_json_canonicalizer::to_string(&raw)
            .map_err(|e| AuditError::Validation(format!("Canonical JSON error: {e}")))?;
        Ok(canonical.into_bytes())
    }

    /// Compute the SHA-256 hash of an entry's content.
    ///
    /// Hash = SHA-256(id || sequence || action_json || verdict_json || timestamp || metadata_json || prev_hash)
    ///
    /// Uses RFC 8785 (JSON Canonicalization Scheme) for deterministic JSON serialization.
    /// This ensures hash stability across serde_json versions and key insertion orders.
    ///
    /// SECURITY (R33-001): The sequence number is included in the hash to prevent
    /// collision attacks under high load where timestamps might be identical.
    pub(crate) fn compute_entry_hash(entry: &AuditEntry) -> Result<String, AuditError> {
        let action_json = Self::canonical_json(&entry.action)?;
        let verdict_json = Self::canonical_json(&entry.verdict)?;
        let metadata_json = Self::canonical_json(&entry.metadata)?;
        let prev_hash = entry.prev_hash.as_deref().unwrap_or("");

        let mut hasher = Sha256::new();
        // Length-prefix each field with u64 little-endian to prevent
        // boundary-shift collisions (e.g., id="ab",action="cd" vs id="abc",action="d")
        Self::hash_field(&mut hasher, entry.id.as_bytes());
        // SECURITY (R33-001): Include monotonic sequence number to ensure uniqueness
        // even if two entries have identical timestamps under high load.
        hasher.update(entry.sequence.to_le_bytes());
        Self::hash_field(&mut hasher, &action_json);
        Self::hash_field(&mut hasher, &verdict_json);
        Self::hash_field(&mut hasher, entry.timestamp.as_bytes());
        Self::hash_field(&mut hasher, &metadata_json);
        Self::hash_field(&mut hasher, prev_hash.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    /// Write a length-prefixed field into the hasher.
    pub(crate) fn hash_field(hasher: &mut Sha256, data: &[u8]) {
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

        // SECURITY (R9-4): Validate metadata size to prevent oversized entries
        // from exhausting disk space or pushing the log past the load limit.
        const MAX_METADATA_SIZE: usize = 65536; // 64 KB
        let metadata_size = serde_json::to_string(&metadata)
            .map(|s| s.len())
            .unwrap_or(0);
        if metadata_size > MAX_METADATA_SIZE {
            return Err(AuditError::Validation(format!(
                "Metadata too large: {} bytes (max {} bytes)",
                metadata_size, MAX_METADATA_SIZE
            )));
        }

        // SECURITY (R16-AUDIT-2): Validate metadata nesting depth to prevent
        // stack overflow in recursive redaction functions. Action parameters are
        // already depth-checked (max 20), but metadata was not.
        const MAX_METADATA_DEPTH: usize = 20;
        if Self::json_depth(&metadata) > MAX_METADATA_DEPTH {
            return Err(AuditError::Validation(format!(
                "Metadata exceeds maximum nesting depth of {}",
                MAX_METADATA_DEPTH
            )));
        }

        // Redact sensitive values based on configured redaction level
        let logged_action = match self.redaction_level {
            RedactionLevel::Off => action.clone(),
            RedactionLevel::KeysOnly => {
                let mut a = action.clone();
                a.parameters = redact_keys_only(&action.parameters);
                a
            }
            RedactionLevel::KeysAndPatterns => {
                let mut a = action.clone();
                a.parameters = if let Some(scanner) = &self.pii_scanner {
                    redact_keys_and_patterns_with_scanner(&action.parameters, scanner)
                } else {
                    redact_keys_and_patterns(&action.parameters)
                };
                // SECURITY (R33-SUP-2): Also scan target_paths, target_domains,
                // and resolved_ips for PII patterns. Paths like /home/john.doe/
                // or domains with personal subdomains could leak PII into audit logs.
                // SECURITY (R36-SUP-1): Use configured PiiScanner when available
                // instead of legacy PII_REGEXES (which only detects email/SSN/phone).
                // PiiScanner also detects credit cards, IPv4, JWT, and AWS keys.
                // SECURITY (R36-SUP-3): Also redact resolved_ips which may contain
                // internal network addresses or other PII-adjacent data.
                let pii_scanner_ref = &self.pii_scanner;
                let redact_strings = |strings: &[String]| -> Vec<String> {
                    strings
                        .iter()
                        .map(|s| {
                            if let Some(ref scanner) = pii_scanner_ref {
                                if scanner.has_pii(s) {
                                    REDACTED.to_string()
                                } else {
                                    s.clone()
                                }
                            } else if PII_REGEXES.iter().any(|re| re.is_match(s)) {
                                REDACTED.to_string()
                            } else {
                                s.clone()
                            }
                        })
                        .collect()
                };
                a.target_paths = redact_strings(&action.target_paths);
                a.target_domains = redact_strings(&action.target_domains);
                a.resolved_ips = redact_strings(&action.resolved_ips);
                a
            }
        };

        let logged_metadata = match self.redaction_level {
            RedactionLevel::Off => metadata,
            RedactionLevel::KeysOnly => redact_keys_only(&metadata),
            RedactionLevel::KeysAndPatterns => {
                if let Some(scanner) = &self.pii_scanner {
                    redact_keys_and_patterns_with_scanner(&metadata, scanner)
                } else {
                    redact_keys_and_patterns(&metadata)
                }
            }
        };

        // SECURITY (R37-SUP-1): Redact PII in verdict deny/approval reasons.
        // Deny reasons can contain user-controlled data (paths, domains, JWT claims)
        // that would be caught by PII scanning in action fields but were not being
        // redacted in the verdict. This closes that gap.
        let logged_verdict = match self.redaction_level {
            RedactionLevel::Off => verdict.clone(),
            RedactionLevel::KeysOnly => verdict.clone(),
            RedactionLevel::KeysAndPatterns => match verdict {
                Verdict::Deny { reason } => {
                    let redacted_reason = if let Some(ref scanner) = self.pii_scanner {
                        scanner.redact_string(reason)
                    } else {
                        let mut r = reason.clone();
                        for re in PII_REGEXES.iter() {
                            r = re.replace_all(&r, REDACTED).to_string();
                        }
                        r
                    };
                    Verdict::Deny {
                        reason: redacted_reason,
                    }
                }
                Verdict::RequireApproval { reason } => {
                    let redacted_reason = if let Some(ref scanner) = self.pii_scanner {
                        scanner.redact_string(reason)
                    } else {
                        let mut r = reason.clone();
                        for re in PII_REGEXES.iter() {
                            r = re.replace_all(&r, REDACTED).to_string();
                        }
                        r
                    };
                    Verdict::RequireApproval {
                        reason: redacted_reason,
                    }
                }
                other => other.clone(),
            },
        };

        let mut last_hash_guard = self.last_hash.lock().await;

        // Rotate if the current log exceeds max_file_size.
        // Done under the lock to prevent concurrent writes from racing.
        if self.maybe_rotate().await? {
            *last_hash_guard = None; // New file = new hash chain
            self.entry_count.store(0, Ordering::Relaxed); // Reset counter for new file
        }

        // SECURITY (R33-001): Assign monotonic sequence number BEFORE creating entry.
        // This ensures the sequence is included in the hash, preventing collision
        // attacks where two entries might have identical timestamps under high load.
        let sequence = self.entry_count.load(Ordering::Relaxed);

        let mut entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            action: logged_action,
            verdict: logged_verdict,
            timestamp: Utc::now().to_rfc3339(),
            metadata: logged_metadata,
            sequence,
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

        // SECURITY (R16-AUDIT-4): Restrict audit log file permissions on Unix (0o600).
        // Parity with checkpoint file permissions — prevents other users from
        // reading action parameters or modifying the hash chain.
        // SECURITY (FIND-065): Log warning on permission failure instead of silently ignoring.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) =
                tokio::fs::set_permissions(&self.log_path, std::fs::Permissions::from_mode(0o600))
                    .await
            {
                tracing::warn!(
                    path = %self.log_path.display(),
                    error = %e,
                    "Failed to set audit log file permissions to 0o600"
                );
            }
        }

        // Fix #35: For Deny verdicts, call sync_data() to ensure the entry
        // survives power loss. Allow/RequireApproval can remain buffered.
        if matches!(verdict, Verdict::Deny { .. }) {
            file.sync_data().await?;
        }

        // Update chain head ONLY after successful file write.
        // If the write fails, the in-memory hash must not advance,
        // otherwise the chain diverges from what's on disk.
        *last_hash_guard = Some(hash);

        // Increment in-memory entry count for rotation metadata
        self.entry_count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Validate an action before logging.
    ///
    /// Rejects actions with control characters in tool/function names,
    /// and limits JSON nesting depth in parameters.
    ///
    /// SECURITY (FIND-074): Expanded from newline/null checks to reject ALL
    /// control characters (U+0000–U+001F, U+007F, U+0080–U+009F). This
    /// prevents log injection via tabs, backspaces, escape sequences, etc.
    fn validate_action(&self, action: &Action) -> Result<(), AuditError> {
        // Check for control characters in tool/function names
        if action.tool.chars().any(|c| c.is_control()) {
            return Err(AuditError::Validation(
                "Tool name contains control characters".to_string(),
            ));
        }
        if action.function.chars().any(|c| c.is_control()) {
            return Err(AuditError::Validation(
                "Function name contains control characters".to_string(),
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

    pub(crate) fn json_depth(value: &serde_json::Value) -> usize {
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
