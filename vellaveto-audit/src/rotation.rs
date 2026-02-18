use crate::logger::AuditLogger;
use crate::types::{AuditEntry, AuditError, RotationVerification};
use chrono::Utc;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Default max file size before rotation: 100 MB.
pub(crate) const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of rotated log files to retain.
/// Oldest files beyond this limit are deleted to prevent disk exhaustion.
const MAX_ROTATED_FILES: usize = 100;

impl AuditLogger {
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

        // Initialize entry count from loaded entries
        // SECURITY (FIND-R52-AUDIT-002): Use SeqCst for sequence counter to ensure
        // globally consistent ordering and prevent duplicate sequence numbers.
        self.entry_count
            .store(entries.len() as u64, Ordering::SeqCst);

        // Initialize Merkle tree from existing leaf file (if enabled)
        if let Some(ref merkle) = self.merkle_tree {
            let mut tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {}", e)))?;
            tree.initialize()?;
        }

        Ok(())
    }

    /// Get the path to the rotation manifest file.
    ///
    /// The manifest records each rotation event with the tail hash and
    /// entry count, enabling cross-rotation chain verification (H1).
    pub(crate) fn rotation_manifest_path(&self) -> PathBuf {
        // Safe: file_stem() returns None only for ".." or empty paths, which
        // are never valid audit log paths. unwrap_or_default yields "" as fallback.
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        // Safe: parent() returns None only for root path "/". Audit log paths
        // are always within a directory, so "." is a safe fallback.
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{}.rotation-manifest.jsonl", stem))
    }

    /// Rotate the log file if it exceeds `max_file_size`.
    ///
    /// The caller MUST hold `last_hash` lock. On successful rotation the
    /// caller should reset the lock to `None` (new file = new chain).
    ///
    /// H1: Before rotation, captures the tail hash of the current log.
    /// After rotation, appends a manifest entry recording the rotated file,
    /// its tail hash, and entry count for cross-rotation verification.
    ///
    /// Returns `true` if rotation occurred.
    pub(crate) async fn maybe_rotate(&self) -> Result<bool, AuditError> {
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

        // H1: Read the tail hash before rotation
        // SECURITY (R18-AUDIT-1): If load fails, skip rotation to avoid creating
        // a corrupt manifest with empty tail_hash. Keep writing to current file.
        let entries = match self.load_entries().await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %self.log_path.display(),
                    "Failed to load audit entries for rotation — skipping rotation to preserve chain integrity"
                );
                return Ok(false);
            }
        };
        // SECURITY (R19-AUDIT-1): Strict tail hash computation.
        // - If entries is empty (first rotation), use empty string (valid first rotation).
        // - If entries exist but last entry has no hash, this is a data integrity error.
        //   Skip rotation to avoid creating a manifest with incorrect/missing tail_hash.
        let tail_hash = if entries.is_empty() {
            // First rotation — no previous entries, empty tail hash is valid
            String::new()
        } else {
            match entries.last().and_then(|e| e.entry_hash.clone()) {
                Some(hash) => hash,
                None => {
                    tracing::error!(
                        path = %self.log_path.display(),
                        entry_count = entries.len(),
                        "Last audit entry has no hash — skipping rotation to preserve chain integrity"
                    );
                    return Ok(false);
                }
            }
        };
        // Use loaded entry count (file is source of truth; in-memory counter is for optimization)
        let entry_count = entries.len();

        let rotated_path = self.rotated_path();
        tokio::fs::rename(&self.log_path, &rotated_path).await?;

        // Rename the Merkle leaf file alongside the rotated log, then reset the tree
        if let Some(ref merkle) = self.merkle_tree {
            let leaf_path = self.merkle_leaf_path();
            if leaf_path.exists() {
                let rotated_leaf_path = {
                    let rotated_stem = rotated_path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let rotated_parent = rotated_path.parent().unwrap_or(std::path::Path::new("."));
                    rotated_parent.join(format!("{rotated_stem}.merkle-leaves"))
                };
                if let Err(e) = tokio::fs::rename(&leaf_path, &rotated_leaf_path).await {
                    tracing::warn!(
                        error = %e,
                        "Failed to rename Merkle leaf file during rotation"
                    );
                }
            }
            let mut tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {}", e)))?;
            tree.reset();
        }

        // H1: Append rotation manifest entry
        // SECURITY (R9-1): Sign the manifest entry with Ed25519 when a signing
        // key is configured. Without signatures, an attacker with file write
        // access can forge manifest entries to hide deleted rotated files.
        // SECURITY (R14-AUDIT-2): Store only the filename component in the
        // manifest to prevent path traversal. The rotated file is always in
        // the same directory as the audit log, so a bare filename suffices.
        let rotated_filename = rotated_path
            .file_name()
            .ok_or_else(|| {
                AuditError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rotated path has no filename component",
                ))
            })?
            .to_string_lossy();
        // SECURITY (FIND-R42-017): Record chain segment start hash for cross-rotation
        // linking. The start_hash is the prev_hash of the first entry (None for the first segment).
        let start_hash = entries
            .first()
            .and_then(|e| e.prev_hash.clone())
            .unwrap_or_default();

        // SECURITY (FIND-R46-ROT-003): Hash-chain manifest entries.
        // Compute `previous_hash` as SHA-256(last manifest line) to chain each
        // entry to its predecessor. This detects deletion, reordering, or
        // replacement of individual manifest entries.
        let manifest_path = self.rotation_manifest_path();
        let previous_hash = match tokio::fs::read_to_string(&manifest_path).await {
            Ok(content) => {
                // Find the last non-empty line
                match content.lines().rev().find(|l| !l.trim().is_empty()) {
                    Some(last_line) => {
                        let mut hasher = Sha256::new();
                        hasher.update(last_line.as_bytes());
                        hex::encode(hasher.finalize())
                    }
                    None => "genesis".to_string(),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "genesis".to_string(),
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut manifest_entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "rotated_file": rotated_filename,
            "tail_hash": tail_hash,
            "start_hash": start_hash,
            "entry_count": entry_count,
            "previous_hash": previous_hash,
        });
        if let Some(signing_key) = &self.signing_key {
            // Sign the canonical JSON of the manifest entry (before adding signature)
            let canonical = Self::canonical_json(&manifest_entry)?;
            let mut hasher = Sha256::new();
            hasher.update(&canonical);
            let digest = hasher.finalize();
            let signature = signing_key.sign(&digest);
            manifest_entry["signature"] =
                serde_json::Value::String(hex::encode(signature.to_bytes()));
            manifest_entry["verifying_key"] =
                serde_json::Value::String(hex::encode(signing_key.verifying_key().as_bytes()));
        }
        let mut manifest_line =
            serde_json::to_string(&manifest_entry).map_err(AuditError::Serialization)?;
        manifest_line.push('\n');

        let mut manifest_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&manifest_path)
            .await?;
        manifest_file.write_all(manifest_line.as_bytes()).await?;
        manifest_file.sync_data().await?;

        tracing::info!(
            "Rotated audit log {} -> {} ({} bytes, {} entries, tail_hash={})",
            self.log_path.display(),
            rotated_path.display(),
            metadata.len(),
            entry_count,
            &tail_hash[..tail_hash.len().min(16)],
        );

        // SECURITY (FIND-041-007): Prune oldest rotated files beyond MAX_ROTATED_FILES
        // to prevent unbounded disk exhaustion.
        if let Err(e) = self.prune_rotated_files().await {
            tracing::warn!(
                error = %e,
                "Failed to prune old rotated audit log files"
            );
        }

        Ok(true)
    }

    /// Verify chain integrity across rotated log files (H1).
    ///
    /// Loads the rotation manifest, verifies each rotated file's internal
    /// hash chain, and checks that the recorded tail hashes match.
    /// Detects missing files, tampered files, and manifest forgery.
    pub async fn verify_across_rotations(&self) -> Result<RotationVerification, AuditError> {
        let manifest_path = self.rotation_manifest_path();
        // SECURITY (R33-SUP-5): Check manifest file size before reading to prevent
        // OOM from a corrupted or adversarially large manifest file.
        const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024; // 10MB
        match tokio::fs::metadata(&manifest_path).await {
            Ok(meta) => {
                if meta.len() > MAX_MANIFEST_SIZE {
                    return Err(AuditError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Rotation manifest file exceeds maximum size ({} > {})",
                            meta.len(),
                            MAX_MANIFEST_SIZE
                        ),
                    )));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RotationVerification {
                    valid: true,
                    files_checked: 0,
                    first_failure: None,
                });
            }
            Err(e) => return Err(AuditError::Io(e)),
        }
        let manifest_content = match tokio::fs::read_to_string(&manifest_path).await {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RotationVerification {
                    valid: true,
                    files_checked: 0,
                    first_failure: None,
                });
            }
            Err(e) => return Err(AuditError::Io(e)),
        };

        let mut files_checked = 0;
        // SECURITY (FIND-R46-ROT-003): Track previous manifest line for hash-chain verification.
        let mut previous_manifest_line: Option<String> = None;
        // SECURITY (FIND-R46-013): Track previous segment's tail hash for
        // cross-rotation start_hash verification. The start_hash of each
        // segment should match the tail_hash of the preceding segment.
        let mut previous_tail_hash: Option<String> = None;

        for (i, line) in manifest_content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: serde_json::Value = serde_json::from_str(line)?;

            // SECURITY (FIND-R46-ROT-003): Verify manifest entry hash chain.
            // Each entry must reference the SHA-256 hash of the previous entry's
            // serialized line, or "genesis" for the first entry. This detects
            // deletion, reordering, or replacement of individual entries.
            let claimed_previous = entry
                .get("previous_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_previous = match &previous_manifest_line {
                Some(prev_line) => {
                    let mut hasher = Sha256::new();
                    hasher.update(prev_line.as_bytes());
                    hex::encode(hasher.finalize())
                }
                None => "genesis".to_string(),
            };
            if claimed_previous != expected_previous {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Manifest entry {} hash chain broken: expected previous_hash {}, got {}",
                        i, expected_previous, claimed_previous
                    )),
                });
            }

            // SECURITY (R9-1): Verify manifest entry signature when present.
            // If a trusted verifying key is configured, ALL manifest entries
            // MUST be signed. Without a trusted key, signed entries are still
            // verified (opportunistic verification).
            if let Some(sig_hex) = entry.get("signature").and_then(|v| v.as_str()) {
                let vk_hex = entry
                    .get("verifying_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                // Key pinning: if trusted key is configured, manifest must match
                if let Some(trusted) = &self.trusted_verifying_key {
                    if vk_hex != trusted.as_str() {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} signed by untrusted key",
                                i
                            )),
                        });
                    }
                }

                // Reconstruct the unsigned entry for signature verification
                let mut unsigned = entry.clone();
                if let Some(obj) = unsigned.as_object_mut() {
                    obj.remove("signature");
                    obj.remove("verifying_key");
                }
                // SECURITY (R33-SUP-1): Fail-closed on malformed signatures.
                // Previously, failures in canonical_json, hex::decode, try_from,
                // or VerifyingKey::from_bytes silently fell through, allowing
                // entries with corrupted/truncated signatures to pass verification.
                let canonical = match Self::canonical_json(&unsigned) {
                    Ok(c) => c,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} failed to canonicalize",
                                i
                            )),
                        });
                    }
                };
                let vk_bytes = match hex::decode(vk_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} has invalid verifying key hex",
                                i
                            )),
                        });
                    }
                };
                let sig_bytes = match hex::decode(sig_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} has invalid signature hex",
                                i
                            )),
                        });
                    }
                };
                let mut hasher = Sha256::new();
                hasher.update(&canonical);
                let digest = hasher.finalize();
                let vk_arr: [u8; 32] = match vk_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} verifying key wrong length",
                                i
                            )),
                        });
                    }
                };
                let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} signature wrong length",
                                i
                            )),
                        });
                    }
                };
                let vk = match VerifyingKey::from_bytes(&vk_arr) {
                    Ok(k) => k,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {} has invalid verifying key",
                                i
                            )),
                        });
                    }
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                if vk.verify(&digest, &sig).is_err() {
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!("Manifest entry {} signature invalid", i)),
                    });
                }
            } else if self.trusted_verifying_key.is_some() {
                // Trusted key is configured but manifest entry is unsigned
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Manifest entry {} is unsigned but signing is required",
                        i
                    )),
                });
            }

            // SECURITY (FIND-R46-013): Verify cross-rotation start_hash linkage.
            // The start_hash field records the prev_hash of the first entry in
            // the rotated segment. When non-empty, it must match the tail_hash
            // of the preceding segment (indicating a continuous chain). An empty
            // start_hash indicates a fresh chain segment (normal after rotation).
            // If start_hash is non-empty but doesn't match, a segment was deleted
            // or reordered.
            let claimed_start_hash = entry
                .get("start_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !claimed_start_hash.is_empty() {
                if let Some(ref prev_tail) = previous_tail_hash {
                    if claimed_start_hash != prev_tail {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Cross-rotation linkage broken at segment {}: start_hash '{}' does not match previous tail_hash '{}'",
                                i, claimed_start_hash, prev_tail
                            )),
                        });
                    }
                }
            }

            let rotated_file = entry
                .get("rotated_file")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_tail_hash = entry
                .get("tail_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_count = entry
                .get("entry_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;

            // SECURITY (R14-AUDIT-2): Validate rotated_file before constructing
            // any path from it. Reject path traversal attempts:
            // 1. Must not contain ".." components
            // 2. Must not be an absolute path
            // 3. Must be a bare filename (no directory separators)
            let rotated_file_path = Path::new(rotated_file);
            let has_traversal = rotated_file_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir));
            let is_absolute = rotated_file_path.is_absolute();
            let is_bare_filename = rotated_file_path
                .file_name()
                .map(|f| f == rotated_file)
                .unwrap_or(false);

            if has_traversal || is_absolute || !is_bare_filename || rotated_file.is_empty() {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Rotated file path traversal detected: {}",
                        rotated_file
                    )),
                });
            }

            // Resolve the filename relative to the audit log's directory
            let log_dir = self.log_path.parent().unwrap_or(Path::new("."));
            let rotated_path = log_dir.join(rotated_file);

            // SECURITY (FIND-R46-008): Track whether we've seen an existing file.
            // Once we encounter a file that exists, all subsequent manifest entries
            // MUST have their files present. Missing files after existing ones
            // indicate undetected deletion (not pruning, which removes oldest first).
            //
            // SECURITY (FIND-R43-017): Pruning removes the oldest files first, so
            // missing files are only acceptable at the start of the manifest (contiguous
            // prefix of missing files). Once we see a file that exists, we've passed
            // the prune boundary.
            if !rotated_path.exists() {
                if files_checked > 0 {
                    // We've already seen existing files — this is NOT a prune.
                    // A non-oldest file is missing, indicating undetected deletion.
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!(
                            "Rotated file missing (not pruned — gap in sequence): {}",
                            rotated_path.display()
                        )),
                    });
                }
                tracing::info!(
                    path = %rotated_path.display(),
                    "Rotated file referenced in manifest no longer exists (likely pruned) — skipping"
                );
                // SECURITY (FIND-R46-013): Still update previous_tail_hash for
                // pruned files so cross-rotation linkage remains consistent.
                previous_tail_hash = Some(expected_tail_hash.to_string());
                previous_manifest_line = Some(line.to_string());
                continue;
            }

            // SECURITY (R38-SUP-1): Check rotated file size before reading
            // to prevent OOM from an adversarially large replacement file.
            let rotated_meta = tokio::fs::metadata(&rotated_path).await?;
            if rotated_meta.len() > Self::MAX_AUDIT_LOG_SIZE {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Rotated file exceeds size limit ({} bytes, max {} bytes): {}",
                        rotated_meta.len(),
                        Self::MAX_AUDIT_LOG_SIZE,
                        rotated_path.display()
                    )),
                });
            }

            // Load and verify the rotated file's chain
            let content = tokio::fs::read_to_string(&rotated_path).await?;
            let mut entries = Vec::new();
            for file_line in content.lines() {
                if file_line.trim().is_empty() {
                    continue;
                }
                if let Ok(ae) = serde_json::from_str::<AuditEntry>(file_line) {
                    entries.push(ae);
                }
            }

            // Verify entry count
            if entries.len() != expected_count {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Entry count mismatch in {}: expected {}, got {}",
                        rotated_path.display(),
                        expected_count,
                        entries.len()
                    )),
                });
            }

            // Verify tail hash
            let actual_tail_hash = entries
                .last()
                .and_then(|e| e.entry_hash.as_deref())
                .unwrap_or_default();
            if actual_tail_hash != expected_tail_hash {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Tail hash mismatch in {}: expected {}, got {}",
                        rotated_path.display(),
                        expected_tail_hash,
                        actual_tail_hash
                    )),
                });
            }

            // Verify internal hash chain
            let mut prev_hash: Option<String> = None;
            for (j, ae) in entries.iter().enumerate() {
                if ae.prev_hash != prev_hash {
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!(
                            "Internal chain broken at entry {} in {}",
                            j,
                            rotated_path.display()
                        )),
                    });
                }
                if let Some(ref eh) = ae.entry_hash {
                    let computed = Self::compute_entry_hash(ae)?;
                    if *eh != computed {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Hash mismatch at entry {} in {} (tampering detected)",
                                j,
                                rotated_path.display()
                            )),
                        });
                    }
                    prev_hash = Some(eh.clone());
                }
            }

            // SECURITY (FIND-R46-013): Update previous tail hash for next iteration.
            previous_tail_hash = Some(expected_tail_hash.to_string());
            previous_manifest_line = Some(line.to_string());
            files_checked += 1;
        }

        Ok(RotationVerification {
            valid: true,
            files_checked,
            first_failure: None,
        })
    }

    /// Build the destination path for a rotated log file.
    ///
    /// Format: `<stem>.<timestamp>.<ext>` where timestamp uses hyphens
    /// (filesystem-safe) e.g. `audit.2026-02-02T12-00-00.log`.
    /// If a file with that name already exists (multiple rotations in the
    /// same second), a counter suffix is appended.
    pub(crate) fn rotated_path(&self) -> PathBuf {
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
                // SECURITY (FIND-R43-005): Exclude companion files from rotated file list.
                // Merkle leaf files and manifest files should never be pruned as rotated logs.
                if name.ends_with(".merkle-leaves") || name.ends_with(".rotation-manifest.jsonl") {
                    continue;
                }

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

    /// Remove the oldest rotated log files when the count exceeds `MAX_ROTATED_FILES`.
    ///
    /// Files are sorted by modification time (oldest first) and the excess
    /// oldest files are deleted. Errors on individual file deletions are
    /// logged but do not abort the pruning of remaining files.
    async fn prune_rotated_files(&self) -> Result<(), AuditError> {
        let mut rotated = self.list_rotated_files()?;

        if rotated.len() <= MAX_ROTATED_FILES {
            return Ok(());
        }

        // Sort by modification time (oldest first) for deterministic pruning.
        // Fall back to epoch on metadata errors so those files sort first and
        // get pruned preferentially.
        rotated.sort_by(|a, b| {
            let time_a = std::fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let time_b = std::fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            time_a.cmp(&time_b)
        });

        let excess = rotated.len() - MAX_ROTATED_FILES;
        for path in rotated.iter().take(excess) {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {
                    tracing::info!(
                        path = %path.display(),
                        "Pruned old rotated audit log file (FIND-041-007)"
                    );

                    // SECURITY (FIND-R43-005): Also remove companion merkle-leaves file.
                    let merkle_path = path.with_extension("merkle-leaves");
                    if merkle_path.exists() {
                        if let Err(e) = std::fs::remove_file(&merkle_path) {
                            tracing::warn!(
                                path = %merkle_path.display(),
                                error = %e,
                                "Failed to remove companion merkle-leaves file during pruning"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "Failed to prune rotated audit log file"
                    );
                }
            }
        }

        Ok(())
    }
}
