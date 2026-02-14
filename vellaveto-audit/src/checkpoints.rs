use crate::logger::AuditLogger;
use crate::types::{AuditError, Checkpoint, CheckpointVerification};
use chrono::Utc;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use std::path::Path;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

impl AuditLogger {
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
    pub(crate) fn checkpoint_path(&self) -> PathBuf {
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{stem}.checkpoints.jsonl"))
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

        // Read Merkle root if tree is enabled
        let merkle_root = if let Some(ref merkle) = self.merkle_tree {
            let tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {}", e)))?;
            tree.root_hex()
        } else {
            None
        };

        let mut checkpoint = Checkpoint {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            entry_count: entries.len(),
            chain_head_hash,
            signature: String::new(),
            verifying_key: hex::encode(signing_key.verifying_key().as_bytes()),
            merkle_root,
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
        // M1: Use sync_data() instead of flush() for durable writes
        file.sync_data().await?;

        // M1: Restrict checkpoint file permissions on Unix (0o600 = owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = tokio::fs::set_permissions(&cp_path, perms).await {
                tracing::warn!("Failed to set checkpoint permissions: {}", e);
            }
        }

        Ok(checkpoint)
    }

    /// Maximum checkpoint file size (10 MB). Prevents memory DoS from
    /// oversized checkpoint files.
    const MAX_CHECKPOINT_FILE_SIZE: u64 = 10 * 1024 * 1024;

    /// Maximum checkpoint line size (64 KB). Prevents memory exhaustion from
    /// maliciously crafted checkpoint files with extremely long lines.
    /// SECURITY (R33-002): A valid checkpoint line should be well under 4 KB,
    /// so 64 KB is generous while still preventing abuse.
    const MAX_CHECKPOINT_LINE_SIZE: usize = 64 * 1024;

    /// Load all checkpoints from the checkpoint file.
    pub async fn load_checkpoints(&self) -> Result<Vec<Checkpoint>, AuditError> {
        let cp_path = self.checkpoint_path();

        // SECURITY (R24-SRV-3): Check file size before reading to prevent
        // memory DoS from oversized checkpoint files.
        match tokio::fs::metadata(&cp_path).await {
            Ok(meta) if meta.len() > Self::MAX_CHECKPOINT_FILE_SIZE => {
                return Err(AuditError::Io(std::io::Error::other(format!(
                    "Checkpoint file too large ({} bytes, max {} bytes)",
                    meta.len(),
                    Self::MAX_CHECKPOINT_FILE_SIZE
                ))));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
            _ => {}
        }

        let content = match tokio::fs::read_to_string(&cp_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut checkpoints = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            // SECURITY (R33-002): Reject oversized lines to prevent memory exhaustion.
            // A valid checkpoint line should be well under 4 KB.
            if line.len() > Self::MAX_CHECKPOINT_LINE_SIZE {
                tracing::warn!(
                    line_num = line_num + 1,
                    line_len = line.len(),
                    max_len = Self::MAX_CHECKPOINT_LINE_SIZE,
                    "Skipping oversized checkpoint line"
                );
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
                                "Hash chain broken: entry {i} missing hash after hashed entries"
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
}
