use crate::logger::AuditLogger;
use crate::types::{AuditEntry, AuditError, AuditReport, ChainVerification};
use sentinel_types::Verdict;

impl AuditLogger {
    /// Maximum audit log file size for load operations (100 MB).
    ///
    /// Prevents memory DoS (Exploit #10) where an attacker grows the audit log
    /// and then triggers `verify_chain()` to OOM the server.
    pub(crate) const MAX_AUDIT_LOG_SIZE: u64 = 100 * 1024 * 1024;

    /// Maximum audit log line size (1 MB). Prevents memory exhaustion from
    /// maliciously crafted audit files with extremely long lines.
    /// SECURITY (R33-002): A valid audit entry should be under 100 KB (including
    /// large metadata), so 1 MB is generous while still preventing abuse.
    const MAX_AUDIT_LINE_SIZE: usize = 1024 * 1024;

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
            // SECURITY (R33-002): Reject oversized lines to prevent memory exhaustion.
            if line.len() > Self::MAX_AUDIT_LINE_SIZE {
                skipped += 1;
                tracing::warn!(
                    line_num = line_num + 1,
                    line_len = line.len(),
                    max_len = Self::MAX_AUDIT_LINE_SIZE,
                    "Skipping oversized audit line in {:?}",
                    self.log_path
                );
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

    /// Detect entries with duplicate IDs in the audit log.
    ///
    /// Returns a list of IDs that appear more than once, along with their
    /// occurrence counts. Duplicate IDs may indicate a replay attack or
    /// log corruption.
    pub async fn detect_duplicate_ids(&self) -> Result<Vec<(String, usize)>, AuditError> {
        let entries = self.load_entries().await?;
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        for entry in &entries {
            *counts.entry(entry.id.as_str()).or_insert(0) += 1;
        }

        let mut duplicates: Vec<(String, usize)> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(id, count)| (id.to_string(), count))
            .collect();

        duplicates.sort_by(|a, b| b.1.cmp(&a.1)); // Most duplicated first
        Ok(duplicates)
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
                // Handle future variants - count as deny (fail-closed)
                _ => deny_count += 1,
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
}
