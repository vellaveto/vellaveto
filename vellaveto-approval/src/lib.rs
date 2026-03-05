// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use vellaveto_types::unicode::normalize_homoglyphs;
use vellaveto_types::Action;

#[derive(Error, Debug)]
pub enum ApprovalError {
    /// The requested approval ID does not exist in the store.
    #[error("Approval not found: {0}")]
    NotFound(String),
    /// The approval has already been approved, denied, or expired and cannot be
    /// resolved again.
    #[error("Approval already resolved: {0}")]
    AlreadyResolved(String),
    /// The approval's TTL has elapsed. It was marked as expired atomically
    /// and can no longer be approved or denied.
    #[error("Approval expired: {0}")]
    Expired(String),
    /// The store has reached `max_pending` capacity. The caller should treat
    /// this as a Deny verdict (fail-closed).
    #[error("Approval store at capacity ({0} max pending)")]
    CapacityExceeded(usize),
    /// Input validation failed (e.g., identity too long, self-approval attempt,
    /// reason exceeding max length).
    #[error("Validation error: {0}")]
    Validation(String),
    /// File system I/O error during persistence operations.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Status of an approval request through its lifecycle.
///
/// State transitions:
/// ```text
/// Pending --> Approved  (via approve())
/// Pending --> Denied    (via deny())
/// Pending --> Expired   (via expire_stale() or on-access TTL check)
/// ```
/// Once resolved (Approved/Denied/Expired), the status is terminal and
/// cannot be changed. Attempting to resolve an already-resolved approval
/// returns `ApprovalError::AlreadyResolved`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum ApprovalStatus {
    /// The approval is awaiting resolution by a human reviewer.
    /// This is the initial state after `create()`.
    Pending,
    /// The approval was approved by a reviewer. The `resolved_by` and
    /// `resolved_at` fields on `PendingApproval` are populated.
    Approved,
    /// The approval was denied by a reviewer. The `resolved_by` and
    /// `resolved_at` fields on `PendingApproval` are populated.
    Denied,
    /// The approval's TTL elapsed before resolution. Set either by
    /// `expire_stale()` during periodic cleanup or by `approve()`/`deny()`
    /// when they detect the TTL has passed.
    Expired,
}

// SECURITY (FIND-R122-002): deny_unknown_fields prevents field injection via JSONL persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Maximum length of identity strings (resolved_by, requested_by) at the store level.
///
/// SECURITY (R39-SUP-6): Prevents unbounded memory usage from arbitrarily long
/// identity strings passed by direct consumers of the store API. The server layer
/// adds its own check, but the store must be safe independently.
pub const MAX_IDENTITY_LEN: usize = 512;

/// Maximum length of the approval reason string.
///
/// SECURITY (FIND-R46-011): Prevents unbounded memory usage from arbitrarily long
/// reason strings passed to the approval store.
pub const MAX_REASON_LEN: usize = 4096;

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
fn compute_dedup_key(
    action: &Action,
    reason: &str,
    requested_by: Option<&str>,
) -> Result<String, ApprovalError> {
    // SECURITY (R33-SUP-4): Include resolved_ips in the dedup key. Without this,
    // two actions targeting the same domain but resolving to different IPs (e.g.,
    // due to DNS rebinding) would incorrectly deduplicate, and approving one
    // would effectively approve the other.
    //
    // SECURITY (R40-SUP-4): Sort resolved_ips, target_paths, and target_domains
    // before hashing. Without sorting, identical actions whose Vec fields arrive
    // in different order (e.g., DNS round-robin) produce different hashes,
    // bypassing deduplication.
    let mut sorted_ips = action.resolved_ips.clone();
    sorted_ips.sort();
    let mut sorted_paths = action.target_paths.clone();
    sorted_paths.sort();
    let mut sorted_domains = action.target_domains.clone();
    sorted_domains.sort();
    // R230-APPR-1: Normalize tool/function names through NFKC + lowercase +
    // homoglyph mapping to prevent Unicode variants from bypassing dedup.
    // E.g., "ﬁle_read" (fi ligature) and "file_read" must hash the same.
    let norm_tool = vellaveto_types::unicode::normalize_identity(&action.tool);
    let norm_func = vellaveto_types::unicode::normalize_identity(&action.function);
    let canonical = serde_json::json!({
        "tool": norm_tool,
        "function": norm_func,
        "parameters": action.parameters,
        "target_paths": sorted_paths,
        "target_domains": sorted_domains,
        "resolved_ips": sorted_ips,
    });
    // SECURITY (R37-SUP-6): Fail-closed on serialization failure instead of
    // falling back to empty string. With unwrap_or_default(), all actions
    // that fail serialization would hash to the same dedup key, causing
    // unrelated approval requests to collide.
    let canonical_str = serde_json::to_string(&canonical)?;
    // SECURITY (FIND-R122-003): Use a distinct sentinel for None to avoid
    // collision with Some(""). The NUL byte cannot appear in valid identities
    // (control chars are rejected), guaranteeing no false collisions.
    let rb_component = requested_by.unwrap_or("\x00NONE\x00");
    let input = format!("{canonical_str}||{reason}||{rb_component}");
    let hash = Sha256::digest(input.as_bytes());
    Ok(format!("{hash:x}"))
}

/// In-memory approval store with file-based persistence.
///
/// Manages the lifecycle of pending tool-call approvals: creation, deduplication,
/// resolution (approve/deny), and expiration. State is persisted to an append-only
/// JSONL file for crash recovery.
pub struct ApprovalStore {
    /// Map of approval ID to `PendingApproval`. Contains both pending and
    /// recently-resolved entries (resolved entries older than 1 hour are evicted
    /// by `expire_stale()`).
    pending: RwLock<HashMap<String, PendingApproval>>,
    /// Maps dedup_key (SHA-256 of action+reason+requested_by) to approval_id
    /// for pending entries only. Enables O(1) deduplication of identical
    /// approval requests.
    dedup_index: RwLock<HashMap<String, String>>,
    /// Path to the append-only JSONL persistence file.
    log_path: PathBuf,
    /// Default time-to-live for new approvals. Pending approvals that exceed
    /// this TTL are marked as expired during `expire_stale()`.
    default_ttl: std::time::Duration,
    /// Maximum number of pending approvals allowed. When reached, new
    /// `create()` calls return `CapacityExceeded` (fail-closed).
    max_pending: usize,
}

impl ApprovalStore {
    /// Create a new approval store.
    ///
    /// `default_ttl` is the time-to-live for new approvals (default: 15 minutes).
    pub fn new(log_path: PathBuf, default_ttl: std::time::Duration) -> Self {
        // SECURITY (R240-APPR-1): Reject path traversal in log_path.
        // A malicious config could write the approval JSONL file to a sensitive
        // location via ".." components. persist_approval() creates parent dirs.
        for component in log_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                tracing::error!(
                    "SECURITY: Approval log_path contains '..' path traversal — rejecting: {:?}",
                    log_path
                );
                // Use /dev/null as a safe sink — all persists will succeed but write nothing.
                return Self {
                    pending: RwLock::new(HashMap::new()),
                    dedup_index: RwLock::new(HashMap::new()),
                    log_path: PathBuf::from("/dev/null"),
                    default_ttl,
                    max_pending: DEFAULT_MAX_PENDING,
                };
            }
        }
        Self {
            pending: RwLock::new(HashMap::new()),
            dedup_index: RwLock::new(HashMap::new()),
            log_path,
            default_ttl,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }

    /// Create a new approval store with a custom maximum capacity.
    ///
    /// If `max_pending` is 0, it is clamped to 1 with an error-level log
    /// message. A zero-capacity store can never accept any pending approvals,
    /// which is almost certainly a misconfiguration.
    ///
    /// SECURITY (FIND-R111-003): Rejecting 0 at construction time surfaces the
    /// bug immediately rather than silently producing an unusable store that
    /// denies every approval request.
    ///
    /// SECURITY (FIND-R116-CA-002): Replaced `assert!` with clamping to avoid
    /// panicking in library code (violates "no panics in library code" rule).
    pub fn with_max_pending(
        log_path: PathBuf,
        default_ttl: std::time::Duration,
        max_pending: usize,
    ) -> Self {
        let effective_max = if max_pending == 0 {
            tracing::error!(
                "ApprovalStore::with_max_pending called with 0; clamping to 1. \
                 A zero-capacity store can never accept pending approvals."
            );
            1
        } else {
            max_pending
        };
        Self {
            pending: RwLock::new(HashMap::new()),
            dedup_index: RwLock::new(HashMap::new()),
            log_path,
            default_ttl,
            max_pending: effective_max,
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
                    // SECURITY (R36-SUP-2): Use char-boundary-aware truncation to
                    // prevent panic when byte position 200 falls mid-character in
                    // multi-byte UTF-8 content.
                    let max = 200.min(line.len());
                    let mut end = max;
                    while end > 0 && !line.is_char_boundary(end) {
                        end -= 1;
                    }
                    tracing::warn!(
                        "Skipping malformed approval entry at line {}: {} (content: {})",
                        line_num + 1,
                        e,
                        &line[..end]
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

        // SECURITY (FIND-R122-004): Evict stale resolved entries on load to
        // prevent false CapacityExceeded errors on restart.  This mirrors the
        // same retention logic in expire_stale() (line 753).
        let retention_cutoff = Utc::now() - Duration::hours(1);
        let before = pending.len();
        // SECURITY (FIND-R126-001): Use resolved_at (if available) for retention
        // comparison, not created_at.  An approval created 2h ago but resolved
        // 30min ago should still be retained, while one resolved 2h ago should not.
        pending.retain(|_, a| {
            a.status == ApprovalStatus::Pending
                || a.resolved_at.unwrap_or(a.created_at) > retention_cutoff
        });
        let evicted = before.saturating_sub(pending.len());
        if evicted > 0 {
            tracing::info!(
                "Evicted {} stale resolved entries on load (retention cutoff: 1h)",
                evicted
            );
        }

        // Rebuild the dedup index for entries that are still pending
        let mut dedup = self.dedup_index.write().await;
        dedup.clear();
        for approval in pending.values() {
            if approval.status == ApprovalStatus::Pending {
                let key = compute_dedup_key(
                    &approval.action,
                    &approval.reason,
                    approval.requested_by.as_deref(),
                )?;
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
        // SECURITY (FIND-R46-011): Validate reason length at the store level.
        if reason.len() > MAX_REASON_LEN {
            return Err(ApprovalError::Validation(format!(
                "reason exceeds maximum length of {MAX_REASON_LEN} bytes ({} bytes)",
                reason.len()
            )));
        }
        // SECURITY (FIND-R116-CA-001): Validate reason content for control characters
        // and Unicode format characters. Parity with Redis backend (redis_backend.rs
        // lines 313-325) which already validates both.
        if reason.chars().any(|c| c.is_control()) {
            return Err(ApprovalError::Validation(
                "reason contains control characters".to_string(),
            ));
        }
        if reason.chars().any(vellaveto_types::is_unicode_format_char) {
            return Err(ApprovalError::Validation(
                "reason contains Unicode format characters".to_string(),
            ));
        }
        // SECURITY (R39-SUP-6): Validate requested_by identity length at the store level.
        // SECURITY (FIND-R112-008): Also reject control chars and Unicode format chars
        // in requested_by to prevent identity spoofing via invisible characters.
        if let Some(ref rb) = requested_by {
            // SECURITY (FIND-R143-004): Reject empty requested_by. When requested_by
            // is Some(""), the self-approval check's `!req_final.is_empty()` guard
            // evaluates to false, skipping the check entirely and allowing self-approval.
            if rb.is_empty() {
                return Err(ApprovalError::Validation(
                    "requested_by must not be empty".to_string(),
                ));
            }
            if rb.len() > MAX_IDENTITY_LEN {
                return Err(ApprovalError::Validation(format!(
                    "requested_by exceeds maximum length of {MAX_IDENTITY_LEN} bytes"
                )));
            }
            if rb.chars().any(|c| c.is_control()) {
                return Err(ApprovalError::Validation(
                    "requested_by contains control characters".to_string(),
                ));
            }
            if rb.chars().any(vellaveto_types::is_unicode_format_char) {
                return Err(ApprovalError::Validation(
                    "requested_by contains Unicode format characters".to_string(),
                ));
            }
        }

        let dedup_key = compute_dedup_key(&action, &reason, requested_by.as_deref())?;

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
        // SECURITY (R241-APPR-1): Log TTL conversion failure instead of silent fallback.
        let ttl = Duration::from_std(self.default_ttl).unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                default_ttl = ?self.default_ttl,
                fallback_secs = 900,
                "chrono::Duration conversion failed — using fallback TTL"
            );
            Duration::seconds(900)
        });

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

        // SECURITY (FIND-029/FIND-030): Acquire both locks in consistent order
        // (pending -> dedup_index) and hold them through the double-check, capacity
        // check, and insert. Previously, the double-check used a READ lock on
        // dedup_index, creating a theoretical window where expire_stale() could
        // desynchronize the dedup index between the check and the insert.
        // This now matches the lock order used by expire_stale().
        let mut pending = self.pending.write().await;
        let mut dedup = self.dedup_index.write().await;

        // Double-check dedup under both write locks to handle races
        if let Some(existing_id) = dedup.get(&dedup_key) {
            if let Some(existing) = pending.get(existing_id) {
                if existing.status == ApprovalStatus::Pending {
                    return Ok(existing_id.clone());
                }
            }
        }

        // Check capacity before inserting (Finding #26: prevents unbounded growth)
        if pending.len() >= self.max_pending {
            return Err(ApprovalError::CapacityExceeded(self.max_pending));
        }

        // Insert into both maps atomically while holding both write locks
        pending.insert(id.clone(), approval.clone());
        dedup.insert(dedup_key.clone(), id.clone());

        // Release locks before I/O
        drop(dedup);
        drop(pending);

        // Persist to disk; rollback on failure
        // SECURITY (FIND-R212-005): Acquire both locks atomically for rollback
        // in consistent order (pending → dedup_index) to prevent TOCTOU where a
        // concurrent reader sees a stale dedup entry pointing to a removed approval.
        if let Err(e) = self.persist_approval(&approval).await {
            let mut pending = self.pending.write().await;
            let mut dedup = self.dedup_index.write().await;
            // SECURITY (FIND-R218-002): Only rollback if the entry is still Pending.
            // A concurrent approve()/deny() may have resolved it between insert and
            // persist_approval failure — removing an already-resolved entry would
            // discard a valid resolution.
            if pending
                .get(&id)
                .is_some_and(|a| a.status == ApprovalStatus::Pending)
            {
                pending.remove(&id);
                dedup.remove(&dedup_key);
            }
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
        // SECURITY (FIND-R143-005): Reject empty resolver identity. An empty `by`
        // string would create an approval with `resolved_by: Some("")`, providing
        // no audit accountability. It also bypasses the self-approval check because
        // the normalized empty string hits the `!req_final.is_empty()` guard.
        if by.is_empty() {
            return Err(ApprovalError::Validation(
                "resolved_by must not be empty".to_string(),
            ));
        }
        // SECURITY (R39-SUP-6): Validate identity length at the store level.
        // The server adds its own check, but direct API consumers must also
        // be protected from arbitrarily long identity strings.
        if by.len() > MAX_IDENTITY_LEN {
            return Err(ApprovalError::Validation(format!(
                "resolved_by exceeds maximum length of {MAX_IDENTITY_LEN} bytes"
            )));
        }
        // SECURITY (FIND-R112-008): Reject control characters and Unicode format
        // characters in the `by` identity string. Without this check, an attacker
        // can inject zero-width or bidi override characters to make log entries
        // appear to have been approved by a different principal.
        if by.chars().any(|c| c.is_control()) {
            return Err(ApprovalError::Validation(
                "resolved_by contains control characters".to_string(),
            ));
        }
        if by.chars().any(vellaveto_types::is_unicode_format_char) {
            return Err(ApprovalError::Validation(
                "resolved_by contains Unicode format characters".to_string(),
            ));
        }

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
            // SECURITY (R36-SUP-4): Apply Unicode NFKC normalization before
            // comparison to prevent bypass via confusable characters (e.g.,
            // fullwidth Latin vs ASCII). NFKC maps compatibility equivalents
            // to their canonical forms.
            // SECURITY (R38-SUP-3): Use full Unicode case folding instead of
            // ASCII-only `eq_ignore_ascii_case`. Non-ASCII letters like Turkish
            // İ (U+0130) must case-fold correctly to detect self-approval.
            // SECURITY (R42-SUP-1): Apply homoglyph normalization AFTER NFKC
            // and case folding. NFKC does NOT convert cross-script confusables
            // like Cyrillic 'а' (U+0430) to Latin 'a' (U+0061). This explicit
            // mapping prevents self-approval bypass via visually identical but
            // technically different Unicode characters (P0 fix).
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
            // Apply homoglyph normalization to catch Cyrillic/Greek/etc spoofing
            let req_final = normalize_homoglyphs(&req_lower);
            let app_final = normalize_homoglyphs(&app_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == app_final {
                return Err(ApprovalError::Validation(format!(
                    "Self-approval denied: requester '{requester_base}' cannot approve their own request"
                )));
            }
        }

        // Compute dedup key before mutating the approval
        let dedup_key = compute_dedup_key(
            &approval.action,
            &approval.reason,
            approval.requested_by.as_deref(),
        )?;

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            // Remove from dedup index since it's no longer pending
            let mut dedup = self.dedup_index.write().await;
            dedup.remove(&dedup_key);
            drop(dedup);
            // SECURITY (FIND-R224-001): Rollback in-memory state on persist failure.
            // Without this, the approval is Expired in memory but Pending on disk.
            // On restart, it reloads as Pending, and the removed dedup key allows
            // a duplicate approval to be created.
            if let Err(e) = self.persist_approval(&result).await {
                approval.status = ApprovalStatus::Pending;
                let mut dedup = self.dedup_index.write().await;
                dedup.insert(dedup_key, id.to_string());
                return Err(e);
            }
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

        // SECURITY (FIND-R222-002): Rollback in-memory state on persist failure.
        // Without this, a failed disk write leaves the approval as Approved in memory
        // but Pending on disk. On restart, the approval reverts to Pending — allowing
        // a second resolution by a different principal.
        if let Err(e) = self.persist_approval(&result).await {
            approval.status = ApprovalStatus::Pending;
            approval.resolved_by = None;
            approval.resolved_at = None;
            let mut dedup = self.dedup_index.write().await;
            dedup.insert(dedup_key, id.to_string());
            return Err(e);
        }
        Ok(result)
    }

    /// Deny a pending approval.
    ///
    /// SECURITY (R9-2): When `requested_by` is set on the approval, the
    /// resolver identity (`by`) must differ from the requester. This prevents
    /// an agent from denying its own tool calls — a separation-of-privilege
    /// requirement for meaningful human-in-the-loop approval flows.
    pub async fn deny(&self, id: &str, by: &str) -> Result<PendingApproval, ApprovalError> {
        // SECURITY (FIND-R143-005): Reject empty resolver identity (parity with approve()).
        if by.is_empty() {
            return Err(ApprovalError::Validation(
                "resolved_by must not be empty".to_string(),
            ));
        }
        // SECURITY (R39-SUP-6): Validate identity length at the store level.
        if by.len() > MAX_IDENTITY_LEN {
            return Err(ApprovalError::Validation(format!(
                "resolved_by exceeds maximum length of {MAX_IDENTITY_LEN} bytes"
            )));
        }
        // SECURITY (FIND-R112-008): Reject control characters and Unicode format
        // characters in the `by` identity string (parity with approve()).
        if by.chars().any(|c| c.is_control()) {
            return Err(ApprovalError::Validation(
                "resolved_by contains control characters".to_string(),
            ));
        }
        if by.chars().any(vellaveto_types::is_unicode_format_char) {
            return Err(ApprovalError::Validation(
                "resolved_by contains Unicode format characters".to_string(),
            ));
        }

        let mut pending = self.pending.write().await;
        let approval = pending
            .get_mut(id)
            .ok_or_else(|| ApprovalError::NotFound(id.to_string()))?;

        if approval.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyResolved(id.to_string()));
        }

        // SECURITY (R9-2): Prevent self-denial. If the approval was
        // requested by a known principal, the denier must be different.
        // Compare the base principal (before any "(note: ...)" suffix).
        // SECURITY (R23-SUP-1): Also reject principals that contain the
        // `" (note:"` separator themselves — an attacker could inject a
        // crafted `requested_by` like `"victim (note:real_id"` so the
        // split produces a different base than their actual identity.
        if let Some(requester) = &approval.requested_by {
            let requester_base = requester.split(" (note:").next().unwrap_or(requester);
            let denier_base = by.split(" (note:").next().unwrap_or(by);

            // Reject if the base principal contains parentheses — indicates
            // an attempt to embed a fake note separator in the identity.
            if requester_base.contains('(') || denier_base.contains('(') {
                return Err(ApprovalError::Validation(
                    "Self-denial denied: principal contains invalid characters".to_string(),
                ));
            }

            // SECURITY (R28-SUP-10): Case-insensitive comparison to prevent
            // self-denial bypass via casing variations (e.g., "Admin@Corp.com"
            // vs "admin@corp.com").
            // SECURITY (R36-SUP-4): Apply Unicode NFKC normalization before
            // comparison to prevent bypass via confusable characters (e.g.,
            // Cyrillic 'a' U+0430 vs Latin 'a' U+0061). NFKC maps compatibility
            // equivalents to their canonical forms.
            // SECURITY (R38-SUP-3): Use full Unicode case folding instead of
            // ASCII-only `eq_ignore_ascii_case`. Non-ASCII letters like Turkish
            // İ (U+0130) must case-fold correctly to detect self-denial.
            // SECURITY (FIND-R46-001): Apply full normalization pipeline matching
            // approve() — NFKC + Unicode case folding + homoglyph normalization.
            // Previously deny() was missing the homoglyph step, allowing an attacker
            // to deny someone else's approval using a Cyrillic/Greek homoglyph.
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
            // Apply homoglyph normalization to catch Cyrillic/Greek/etc spoofing
            let req_final = normalize_homoglyphs(&req_lower);
            let den_final = normalize_homoglyphs(&den_lower);
            if !req_final.is_empty() && req_final != "anonymous" && req_final == den_final {
                return Err(ApprovalError::Validation(format!(
                    "Self-denial denied: requester '{requester_base}' cannot deny their own request"
                )));
            }
        }

        // Compute dedup key before mutating the approval
        let dedup_key = compute_dedup_key(
            &approval.action,
            &approval.reason,
            approval.requested_by.as_deref(),
        )?;

        if Utc::now() > approval.expires_at {
            approval.status = ApprovalStatus::Expired;
            let result = approval.clone();
            // Remove from dedup index since it's no longer pending
            let mut dedup = self.dedup_index.write().await;
            dedup.remove(&dedup_key);
            drop(dedup);
            // SECURITY (FIND-R224-001): Rollback in-memory state on persist failure.
            // Parity with approve() expiry path rollback.
            if let Err(e) = self.persist_approval(&result).await {
                approval.status = ApprovalStatus::Pending;
                let mut dedup = self.dedup_index.write().await;
                dedup.insert(dedup_key, id.to_string());
                return Err(e);
            }
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

        // SECURITY (FIND-R222-002): Rollback in-memory state on persist failure.
        // Parity with approve() rollback. Without this, a failed disk write
        // leaves the denial as Denied in memory but Pending on disk.
        if let Err(e) = self.persist_approval(&result).await {
            approval.status = ApprovalStatus::Pending;
            approval.resolved_by = None;
            approval.resolved_at = None;
            let mut dedup = self.dedup_index.write().await;
            dedup.insert(dedup_key, id.to_string());
            return Err(e);
        }
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
    ///
    /// SECURITY (FIND-R212-010, FIND-R216-004): Caps the returned collection at
    /// `self.max_pending` to bound clone allocation. Primary capacity enforcement
    /// is in `create()`, but this defends against HashMap growth via persistence
    /// replay or config changes after construction.
    pub async fn list_pending(&self) -> Vec<PendingApproval> {
        let pending = self.pending.read().await;
        pending
            .values()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .take(self.max_pending)
            .cloned()
            .collect()
    }

    /// Count pending (not yet resolved) approvals without cloning.
    ///
    /// SECURITY (R34-SRV-1): Avoids expensive full-clone of all pending approvals
    /// on every Prometheus scrape request.
    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.read().await;
        pending
            .values()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .count()
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
        let mut expired_count: usize = 0;
        let mut to_persist = Vec::new();

        for approval in pending.values_mut() {
            if approval.status == ApprovalStatus::Pending && now > approval.expires_at {
                // Remove dedup key atomically while both locks are held
                // SECURITY (R37-SUP-6): Handle serialization failure gracefully
                // in non-Result context — log warning but still expire the approval.
                match compute_dedup_key(
                    &approval.action,
                    &approval.reason,
                    approval.requested_by.as_deref(),
                ) {
                    Ok(dedup_key) => {
                        dedup.remove(&dedup_key);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to compute dedup key during expiry: {}", e);
                    }
                }
                approval.status = ApprovalStatus::Expired;
                expired_count += 1;
                to_persist.push(approval.clone());
            }
        }

        // Remove resolved entries older than 1 hour to prevent memory leaks
        let retention_cutoff = now - Duration::hours(1);
        // SECURITY (FIND-R126-001): Use resolved_at for retention comparison.
        pending.retain(|_, a| {
            a.status == ApprovalStatus::Pending
                || a.resolved_at.unwrap_or(a.created_at) > retention_cutoff
        });

        // Drop both locks before I/O operations
        drop(dedup);
        drop(pending);

        // SECURITY (FIND-R224-005): Track which approvals failed to persist and
        // rollback their in-memory state. Without this, approvals that fail to
        // persist as Expired remain Expired in memory but Pending on disk. On
        // restart they reload as Pending and can be resolved — creating ghost
        // approvals that bypass the expiry system.
        let mut failed_ids = Vec::new();
        for approval in &to_persist {
            if let Err(e) = self.persist_approval(approval).await {
                tracing::warn!("Failed to persist expired approval {}: {}", approval.id, e);
                failed_ids.push(approval.id.clone());
            }
        }
        if !failed_ids.is_empty() {
            let mut pending = self.pending.write().await;
            let mut dedup = self.dedup_index.write().await;
            for id in &failed_ids {
                if let Some(approval) = pending.get_mut(id) {
                    if approval.status == ApprovalStatus::Expired {
                        approval.status = ApprovalStatus::Pending;
                        expired_count = expired_count.saturating_sub(1);
                        // Restore dedup key so duplicates are still rejected
                        if let Ok(key) = compute_dedup_key(
                            &approval.action,
                            &approval.reason,
                            approval.requested_by.as_deref(),
                        ) {
                            dedup.insert(key, id.clone());
                        }
                    }
                }
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
            "Expected Expired error, got: {err:?}"
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
        assert!(loaded >= 2, "Should load at least 2 entries, got {loaded}");

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

    // -- R36-SUP-2: Multi-byte UTF-8 boundary safety in load logging --

    #[tokio::test]
    async fn test_r36_sup_2_multibyte_utf8_truncation_no_panic() {
        // Write a JSONL file with a malformed line containing multi-byte UTF-8
        // characters. When truncated at byte 200, the boundary might fall
        // mid-character. This must not panic.
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");

        // Create a line with emoji (4 bytes each) that exceeds 200 bytes
        // 60 emoji = 240 bytes, so byte 200 falls inside an emoji
        let emoji_line = "\u{1F600}".repeat(60); // 240 bytes, not valid JSON
        tokio::fs::write(&log_path, format!("{emoji_line}\n"))
            .await
            .unwrap();

        let store = ApprovalStore::new(log_path, std::time::Duration::from_secs(900));
        // This must not panic despite the mid-character truncation
        let result = store.load_from_file().await;
        assert!(result.is_ok());
        // The malformed line should be skipped (count = 0)
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_r36_sup_2_ascii_truncation_still_works() {
        // Ensure normal ASCII lines longer than 200 bytes are still truncated
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");

        let long_ascii = "x".repeat(300); // 300 bytes, not valid JSON
        tokio::fs::write(&log_path, format!("{long_ascii}\n"))
            .await
            .unwrap();

        let store = ApprovalStore::new(log_path, std::time::Duration::from_secs(900));
        let result = store.load_from_file().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    // -- R36-SUP-4: Unicode confusable self-approval prevention --

    #[tokio::test]
    async fn test_r36_sup_4_unicode_confusable_self_approval_blocked_fullwidth() {
        // Fullwidth Latin 'A' (U+FF21) is normalized to 'A' by NFKC.
        // An attacker could use fullwidth characters to bypass case-insensitive
        // comparison of the original strings.
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Requester uses normal Latin characters
        let requester = "Admin@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Approver uses fullwidth Latin 'A' (U+FF21) + normal "dmin@corp.com"
        // NFKC normalizes U+FF21 to 'A', so this should match "Admin@corp.com"
        let approver_fullwidth = "\u{FF21}dmin@corp.com";
        let result = store.approve(&id, approver_fullwidth).await;
        assert!(
            result.is_err(),
            "Fullwidth Unicode self-approval should be denied"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("Self-approval denied"),
                    "Expected self-approval denial, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r36_sup_4_unicode_confusable_self_approval_blocked_roman_numeral() {
        // Roman numeral 'I' (U+2160) is NFKC-normalized to 'I'.
        // Test that an identity containing compatibility characters is caught.
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let requester = "Id-1@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Approver uses Roman numeral I (U+2160) which NFKC-normalizes to 'I'
        let approver = "\u{2160}d-1@corp.com";
        let result = store.approve(&id, approver).await;
        assert!(
            result.is_err(),
            "Roman numeral confusable self-approval should be denied"
        );
    }

    #[tokio::test]
    async fn test_r36_sup_4_legitimate_different_users_allowed() {
        // Ensure NFKC normalization does not block legitimate different users
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(
                test_action(),
                "needs review".to_string(),
                Some("alice@corp.com".to_string()),
            )
            .await
            .unwrap();

        let result = store.approve(&id, "bob@corp.com").await;
        assert!(
            result.is_ok(),
            "Different users should be able to approve: {:?}",
            result.err()
        );
    }

    // SECURITY (R42-SUP-1): P0 FIX — Cyrillic homoglyph self-approval bypass prevention.
    // NFKC normalization does NOT convert Cyrillic confusables to Latin equivalents.
    // An attacker using "аdmin" (Cyrillic U+0430) vs "admin" (Latin) could bypass
    // self-approval checks without explicit homoglyph normalization.
    #[tokio::test]
    async fn test_r42_sup_1_cyrillic_homoglyph_self_approval_blocked() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Requester uses Latin "admin"
        let requester = "admin@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Attacker tries to self-approve using Cyrillic 'а' (U+0430) instead of Latin 'a'
        let cyrillic_a = '\u{0430}'; // Cyrillic lowercase а
        let spoofed_approver = format!("{cyrillic_a}dmin@corp.com");
        let result = store.approve(&id, &spoofed_approver).await;
        assert!(
            result.is_err(),
            "P0 FIX: Cyrillic homoglyph 'а' (U+0430) vs Latin 'a' must be caught as \
             self-approval. Without homoglyph normalization, NFKC would NOT catch this."
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("Self-approval denied"),
                    "Error should indicate self-approval denial: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r42_sup_1_cyrillic_mixed_homoglyphs_self_approval_blocked() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Requester uses Latin "password"
        let requester = "password@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Attacker uses multiple Cyrillic confusables: р(U+0440), а(U+0430), о(U+043E)
        // "раssword" with Cyrillic р and а
        let spoofed = "р\u{0430}ssword@corp.com"; // Cyrillic р + Cyrillic а + Latin ssword
        let result = store.approve(&id, spoofed).await;
        assert!(
            result.is_err(),
            "P0 FIX: Multiple Cyrillic homoglyphs in 'password' must be caught"
        );
    }

    #[tokio::test]
    async fn test_r42_sup_1_greek_homoglyph_self_approval_blocked() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Requester uses Latin "alpha"
        let requester = "alpha@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Attacker uses Greek alpha (U+03B1) which NFKC does NOT normalize to Latin 'a'
        let spoofed = "\u{03B1}lpha@corp.com"; // Greek α + Latin lpha
        let result = store.approve(&id, spoofed).await;
        assert!(
            result.is_err(),
            "P0 FIX: Greek alpha (U+03B1) homoglyph must be caught as self-approval"
        );
    }

    // SECURITY (R38-SUP-3): Non-ASCII case folding for self-approval check.
    // Greek Sigma (U+03A3) uppercase vs sigma (U+03C3) lowercase are the same
    // principal. ASCII-only eq_ignore_ascii_case misses this because it only
    // folds A-Z. Full Unicode to_lowercase catches it.
    #[tokio::test]
    async fn test_r38_sup_3_greek_sigma_self_approval_blocked() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Requester uses uppercase Greek Sigma
        let requester = "\u{03A3}igma@corp.com".to_string();
        let id = store
            .create(test_action(), "needs review".to_string(), Some(requester))
            .await
            .unwrap();

        // Approver uses lowercase Greek sigma — same principal
        let result = store.approve(&id, "\u{03C3}igma@corp.com").await;
        assert!(
            result.is_err(),
            "Greek Sigma uppercase vs lowercase should be caught as self-approval \
             under Unicode case folding (was missed by ASCII-only folding)"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("Self-approval denied"),
                    "Expected self-approval denial, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    // Regression: ASCII case folding must still work after the Unicode change
    #[tokio::test]
    async fn test_r38_sup_3_ascii_case_folding_still_works() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(
                test_action(),
                "needs review".to_string(),
                Some("Admin@Corp.com".to_string()),
            )
            .await
            .unwrap();

        let result = store.approve(&id, "admin@corp.com").await;
        assert!(
            result.is_err(),
            "ASCII case-insensitive self-approval should still be caught"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("Self-approval denied"),
                    "Expected self-approval denial, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    // The "anonymous" exclusion must still work with Unicode folding
    #[tokio::test]
    async fn test_r38_sup_3_anonymous_exclusion_preserved() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(
                test_action(),
                "needs review".to_string(),
                Some("Anonymous".to_string()),
            )
            .await
            .unwrap();

        // "Anonymous" requester should NOT be blocked from approval by "anonymous"
        let result = store.approve(&id, "anonymous").await;
        assert!(
            result.is_ok(),
            "Anonymous principal should be excluded from self-approval check: {:?}",
            result.err()
        );
    }

    // --- R39-SUP-6: Identity length validation tests ---

    #[tokio::test]
    async fn test_r39_sup_6_approve_rejects_long_identity() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        // Identity exceeding MAX_IDENTITY_LEN should be rejected
        let long_identity = "x".repeat(MAX_IDENTITY_LEN + 1);
        let result = store.approve(&id, &long_identity).await;
        assert!(
            result.is_err(),
            "Long identity in approve() should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("resolved_by") && msg.contains("maximum length"),
                    "Error message should mention resolved_by length, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r39_sup_6_approve_accepts_identity_at_limit() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        // Identity exactly at MAX_IDENTITY_LEN should be accepted
        let exact_identity = "x".repeat(MAX_IDENTITY_LEN);
        let result = store.approve(&id, &exact_identity).await;
        assert!(
            result.is_ok(),
            "Identity at exactly MAX_IDENTITY_LEN should be accepted: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_r39_sup_6_deny_rejects_long_identity() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        let long_identity = "y".repeat(MAX_IDENTITY_LEN + 1);
        let result = store.deny(&id, &long_identity).await;
        assert!(
            result.is_err(),
            "Long identity in deny() should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("resolved_by") && msg.contains("maximum length"),
                    "Error message should mention resolved_by length, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r39_sup_6_deny_accepts_identity_at_limit() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id = store
            .create(test_action(), "needs review".to_string(), None)
            .await
            .unwrap();

        let exact_identity = "y".repeat(MAX_IDENTITY_LEN);
        let result = store.deny(&id, &exact_identity).await;
        assert!(
            result.is_ok(),
            "Identity at exactly MAX_IDENTITY_LEN should be accepted: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_r39_sup_6_create_rejects_long_requested_by() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let long_requester = "z".repeat(MAX_IDENTITY_LEN + 1);
        let result = store
            .create(
                test_action(),
                "needs review".to_string(),
                Some(long_requester),
            )
            .await;
        assert!(
            result.is_err(),
            "Long requested_by in create() should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("requested_by") && msg.contains("maximum length"),
                    "Error message should mention requested_by length, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r39_sup_6_create_accepts_requested_by_at_limit() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let exact_requester = "z".repeat(MAX_IDENTITY_LEN);
        let result = store
            .create(
                test_action(),
                "needs review".to_string(),
                Some(exact_requester),
            )
            .await;
        assert!(
            result.is_ok(),
            "requested_by at exactly MAX_IDENTITY_LEN should be accepted: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_r39_sup_6_create_accepts_none_requested_by() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // None requested_by should always pass the length check
        let result = store
            .create(test_action(), "needs review".to_string(), None)
            .await;
        assert!(
            result.is_ok(),
            "None requested_by should be accepted: {:?}",
            result.err()
        );
    }

    // -- R40-SUP-4: Dedup key ordering invariance tests --

    #[tokio::test]
    async fn test_r40_sup_4_dedup_key_same_ips_different_order() {
        // Two actions with the same resolved_ips in different orders must
        // produce the same dedup key (i.e., deduplicate correctly).
        let mut action_a = test_action();
        action_a.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];

        let mut action_b = test_action();
        action_b.resolved_ips = vec!["10.0.0.2".to_string(), "10.0.0.1".to_string()];

        let key_a = compute_dedup_key(&action_a, "test reason", Some("user@corp.com")).unwrap();
        let key_b = compute_dedup_key(&action_b, "test reason", Some("user@corp.com")).unwrap();
        assert_eq!(
            key_a, key_b,
            "Dedup keys should match regardless of resolved_ips order"
        );
    }

    #[tokio::test]
    async fn test_r40_sup_4_dedup_key_same_paths_different_order() {
        // Two actions with the same target_paths in different orders must
        // produce the same dedup key.
        let mut action_a = test_action();
        action_a.target_paths = vec!["/etc/passwd".to_string(), "/etc/shadow".to_string()];

        let mut action_b = test_action();
        action_b.target_paths = vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()];

        let key_a = compute_dedup_key(&action_a, "test reason", Some("user@corp.com")).unwrap();
        let key_b = compute_dedup_key(&action_b, "test reason", Some("user@corp.com")).unwrap();
        assert_eq!(
            key_a, key_b,
            "Dedup keys should match regardless of target_paths order"
        );
    }

    #[tokio::test]
    async fn test_r40_sup_4_dedup_key_same_domains_different_order() {
        // Two actions with the same target_domains in different orders must
        // produce the same dedup key.
        let mut action_a = test_action();
        action_a.target_domains = vec!["evil.com".to_string(), "bad.com".to_string()];

        let mut action_b = test_action();
        action_b.target_domains = vec!["bad.com".to_string(), "evil.com".to_string()];

        let key_a = compute_dedup_key(&action_a, "test reason", Some("user@corp.com")).unwrap();
        let key_b = compute_dedup_key(&action_b, "test reason", Some("user@corp.com")).unwrap();
        assert_eq!(
            key_a, key_b,
            "Dedup keys should match regardless of target_domains order"
        );
    }

    #[tokio::test]
    async fn test_r40_sup_4_dedup_key_different_ips_still_differ() {
        // Actions with genuinely different resolved_ips must NOT deduplicate.
        let mut action_a = test_action();
        action_a.resolved_ips = vec!["10.0.0.1".to_string()];

        let mut action_b = test_action();
        action_b.resolved_ips = vec!["10.0.0.2".to_string()];

        let key_a = compute_dedup_key(&action_a, "test reason", Some("user@corp.com")).unwrap();
        let key_b = compute_dedup_key(&action_b, "test reason", Some("user@corp.com")).unwrap();
        assert_ne!(
            key_a, key_b,
            "Dedup keys should differ when resolved_ips are actually different"
        );
    }

    #[tokio::test]
    async fn test_r40_sup_4_dedup_integration_same_ips_different_order() {
        // End-to-end: creating two approvals with same IPs in different order
        // should return the same approval ID (deduplication).
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let mut action_a = test_action();
        action_a.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];

        let mut action_b = test_action();
        action_b.resolved_ips = vec!["10.0.0.2".to_string(), "10.0.0.1".to_string()];

        let id_a = store
            .create(
                action_a,
                "needs review".to_string(),
                Some("user@corp.com".to_string()),
            )
            .await
            .unwrap();
        let id_b = store
            .create(
                action_b,
                "needs review".to_string(),
                Some("user@corp.com".to_string()),
            )
            .await
            .unwrap();

        assert_eq!(
            id_a, id_b,
            "Same action with reordered IPs should deduplicate to same approval ID"
        );
    }

    // IMP-R126-008: Verify load_from_file() evicts stale resolved entries
    // so they don't count toward the capacity limit.
    #[tokio::test]
    async fn test_load_from_file_evicts_stale_resolved() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("approvals.jsonl");

        // Create store, add entries, resolve one with an old timestamp
        let store = ApprovalStore::new(log_path.clone(), std::time::Duration::from_secs(900));
        let id_pending = store
            .create(test_action(), "still pending".to_string(), None)
            .await
            .unwrap();
        let id_old_resolved = store
            .create(
                Action::new(
                    "network".to_string(),
                    "http_request".to_string(),
                    json!({"url": "https://example.com"}),
                ),
                "old resolved".to_string(),
                None,
            )
            .await
            .unwrap();
        // Approve the second one (sets resolved_at to now)
        store.approve(&id_old_resolved, "admin").await.unwrap();

        // Manually rewrite the file so the resolved entry has a very old resolved_at
        // (3 hours ago, well past the 1h retention cutoff)
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let old_ts = (Utc::now() - Duration::hours(3)).to_rfc3339();
        let mut new_lines = Vec::new();
        for line in content.lines() {
            if line.contains(&id_old_resolved) {
                // Replace the resolved_at timestamp with an old one
                if let Ok(mut entry) = serde_json::from_str::<PendingApproval>(line) {
                    if entry.status != ApprovalStatus::Pending {
                        entry.resolved_at = Some(
                            chrono::DateTime::parse_from_rfc3339(&old_ts)
                                .unwrap()
                                .with_timezone(&Utc),
                        );
                        // Also backdate created_at so it's clearly old
                        entry.created_at = chrono::DateTime::parse_from_rfc3339(&old_ts)
                            .unwrap()
                            .with_timezone(&Utc);
                        new_lines.push(serde_json::to_string(&entry).unwrap());
                        continue;
                    }
                }
            }
            new_lines.push(line.to_string());
        }
        tokio::fs::write(&log_path, new_lines.join("\n") + "\n")
            .await
            .unwrap();

        // Load into a fresh store — the old resolved entry should be evicted
        let store2 = ApprovalStore::new(log_path, std::time::Duration::from_secs(900));
        let loaded = store2.load_from_file().await.unwrap();
        // Only the pending entry should survive
        assert!(loaded >= 1, "Should load at least 1 entry, got {loaded}");

        // Pending entry must still be accessible
        let pending = store2.get(&id_pending).await;
        assert!(
            pending.is_ok(),
            "Pending entry should survive retention cleanup"
        );

        // Old resolved entry should have been evicted
        let old = store2.get(&id_old_resolved).await;
        assert!(
            old.is_err(),
            "Resolved entry with 3h-old resolved_at should be evicted on load"
        );
    }

    // --- FIND-R116-CA-001: Reason control/format char validation in create() ---

    #[tokio::test]
    async fn test_r116_ca_001_create_rejects_reason_with_control_chars() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let result = store
            .create(
                test_action(),
                "reason with \x01 control char".to_string(),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "Reason with control chars should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("reason contains control characters"),
                    "Expected control char rejection, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r116_ca_001_create_rejects_reason_with_null_byte() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let result = store
            .create(test_action(), "reason with \0 null byte".to_string(), None)
            .await;
        assert!(result.is_err(), "Reason with null byte should be rejected");
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("reason contains control characters"),
                    "got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r116_ca_001_create_rejects_reason_with_unicode_format_chars() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Zero-width space U+200B
        let result = store
            .create(
                test_action(),
                "reason with \u{200B} zero-width space".to_string(),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "Reason with Unicode format chars should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("reason contains Unicode format characters"),
                    "Expected Unicode format char rejection, got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r116_ca_001_create_rejects_reason_with_bidi_override() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        // Right-to-left override U+202E
        let result = store
            .create(
                test_action(),
                "reason with \u{202E} bidi override".to_string(),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "Reason with bidi override should be rejected"
        );
        match result.unwrap_err() {
            ApprovalError::Validation(msg) => {
                assert!(
                    msg.contains("reason contains Unicode format characters"),
                    "got: {msg}"
                );
            }
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_r116_ca_001_create_accepts_clean_reason() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let result = store
            .create(
                test_action(),
                "Clean reason with normal text and numbers 123".to_string(),
                None,
            )
            .await;
        assert!(
            result.is_ok(),
            "Clean reason should be accepted: {:?}",
            result.err()
        );
    }

    // --- FIND-R116-CA-002: with_max_pending(0) clamps instead of panicking ---

    #[tokio::test]
    async fn test_r116_ca_002_with_max_pending_zero_clamps_to_one() {
        // Previously this would panic with assert!. Now it should clamp to 1.
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::with_max_pending(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
            0,
        );

        // The store should work — it should accept exactly 1 pending approval
        let id = store
            .create(test_action(), "should work".to_string(), None)
            .await
            .unwrap();
        assert!(!id.is_empty());

        // Second create with different action should hit capacity (max_pending = 1)
        let action2 = Action::new(
            "network".to_string(),
            "http_request".to_string(),
            json!({"url": "https://example.com"}),
        );
        let result = store
            .create(action2, "should fail capacity".to_string(), None)
            .await;
        assert!(
            matches!(result, Err(ApprovalError::CapacityExceeded(1))),
            "Expected CapacityExceeded(1) after clamping from 0, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_r116_ca_002_with_max_pending_normal_value_unchanged() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::with_max_pending(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
            5,
        );

        // Should accept 5 distinct approvals
        for i in 0..5 {
            let action = Action::new(format!("tool_{i}"), "exec".to_string(), json!({}));
            let result = store.create(action, format!("reason_{i}"), None).await;
            assert!(
                result.is_ok(),
                "Should accept approval {i}: {:?}",
                result.err()
            );
        }

        // 6th should fail
        let action6 = Action::new("tool_overflow".to_string(), "exec".to_string(), json!({}));
        let result = store.create(action6, "overflow".to_string(), None).await;
        assert!(
            matches!(result, Err(ApprovalError::CapacityExceeded(5))),
            "Expected CapacityExceeded(5), got: {result:?}"
        );
    }

    // SECURITY (FIND-R143-004): Empty requested_by must be rejected
    #[tokio::test]
    async fn test_r143_create_empty_requested_by_rejected() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let action = Action::new("tool".to_string(), "func".to_string(), json!({}));
        let result = store
            .create(action, "reason".to_string(), Some(String::new()))
            .await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("must not be empty"), "Got: {err_msg}");
    }

    // SECURITY (FIND-R143-005): Empty by must be rejected in approve()
    #[tokio::test]
    async fn test_r143_approve_empty_by_rejected() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let action = Action::new("tool".to_string(), "func".to_string(), json!({}));
        let id = store
            .create(action, "reason".to_string(), Some("requester".to_string()))
            .await
            .expect("create should succeed");
        let result = store.approve(&id, "").await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("must not be empty"), "Got: {err_msg}");
    }

    // SECURITY (FIND-R143-005): Empty by must be rejected in deny()
    #[tokio::test]
    async fn test_r143_deny_empty_by_rejected() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let action = Action::new("tool".to_string(), "func".to_string(), json!({}));
        let id = store
            .create(action, "reason".to_string(), Some("requester".to_string()))
            .await
            .expect("create should succeed");
        let result: Result<PendingApproval, ApprovalError> = store.deny(&id, "").await;
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("must not be empty"), "Got: {err_msg}");
    }

    // ─────────────────────────────────────────────────────────────────────
    // compute_dedup_key tests
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_dedup_key_deterministic() {
        let action = test_action();
        let key1 = compute_dedup_key(&action, "reason", None).unwrap();
        let key2 = compute_dedup_key(&action, "reason", None).unwrap();
        assert_eq!(key1, key2, "Same inputs should produce the same dedup key");
    }

    #[test]
    fn test_compute_dedup_key_different_reasons_differ() {
        let action = test_action();
        let key1 = compute_dedup_key(&action, "reason-a", None).unwrap();
        let key2 = compute_dedup_key(&action, "reason-b", None).unwrap();
        assert_ne!(
            key1, key2,
            "Different reasons should produce different keys"
        );
    }

    #[test]
    fn test_compute_dedup_key_different_requested_by_differ() {
        let action = test_action();
        let key1 = compute_dedup_key(&action, "reason", Some("alice")).unwrap();
        let key2 = compute_dedup_key(&action, "reason", Some("bob")).unwrap();
        assert_ne!(
            key1, key2,
            "Different requested_by should produce different keys"
        );
    }

    #[test]
    fn test_compute_dedup_key_none_vs_some_requested_by_differ() {
        let action = test_action();
        let key_none = compute_dedup_key(&action, "reason", None).unwrap();
        let key_some = compute_dedup_key(&action, "reason", Some("alice")).unwrap();
        assert_ne!(
            key_none, key_some,
            "None vs Some(requested_by) should produce different keys"
        );
    }

    #[test]
    fn test_compute_dedup_key_case_normalization() {
        // normalize_identity lowercases and normalizes homoglyphs.
        let action1 = Action::new("File_System".to_string(), "Read".to_string(), json!({}));
        let action2 = Action::new("file_system".to_string(), "read".to_string(), json!({}));
        let key1 = compute_dedup_key(&action1, "reason", None).unwrap();
        let key2 = compute_dedup_key(&action2, "reason", None).unwrap();
        assert_eq!(
            key1, key2,
            "Case-different tool names should produce the same dedup key via normalize_identity"
        );
    }

    #[test]
    fn test_compute_dedup_key_homoglyph_normalization() {
        // Cyrillic 'а' (U+0430) should normalize to Latin 'a' via normalize_identity
        let action1 = Action::new(
            "\u{0430}gent".to_string(), // Cyrillic 'а' + "gent"
            "read".to_string(),
            json!({}),
        );
        let action2 = Action::new("agent".to_string(), "read".to_string(), json!({}));
        let key1 = compute_dedup_key(&action1, "reason", None).unwrap();
        let key2 = compute_dedup_key(&action2, "reason", None).unwrap();
        assert_eq!(
            key1, key2,
            "Homoglyph-equivalent tool names should produce the same dedup key"
        );
    }

    #[test]
    fn test_compute_dedup_key_sorted_ips() {
        let mut action1 = test_action();
        action1.resolved_ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let mut action2 = test_action();
        action2.resolved_ips = vec!["5.6.7.8".to_string(), "1.2.3.4".to_string()];
        let key1 = compute_dedup_key(&action1, "reason", None).unwrap();
        let key2 = compute_dedup_key(&action2, "reason", None).unwrap();
        assert_eq!(
            key1, key2,
            "Same IPs in different order should produce the same key"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // pending_count tests
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pending_count_empty_store() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        assert_eq!(store.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_pending_count_excludes_resolved() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let id1 = store
            .create(test_action(), "first".to_string(), None)
            .await
            .unwrap();
        store
            .create(test_action(), "second".to_string(), None)
            .await
            .unwrap();

        assert_eq!(store.pending_count().await, 2);

        store.approve(&id1, "admin").await.unwrap();
        assert_eq!(
            store.pending_count().await,
            1,
            "Approved entries should not be counted as pending"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // with_max_pending capacity enforcement tests
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_with_max_pending_capacity_exceeded() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::with_max_pending(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
            2,
        );

        store
            .create(test_action(), "first".to_string(), None)
            .await
            .unwrap();
        store
            .create(test_action(), "second".to_string(), None)
            .await
            .unwrap();

        // Third should fail with CapacityExceeded
        let result = store.create(test_action(), "third".to_string(), None).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ApprovalError::CapacityExceeded(2)),
            "Should fail with CapacityExceeded(2)"
        );
    }

    #[tokio::test]
    async fn test_with_max_pending_one_allows_single_approval() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::with_max_pending(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
            1,
        );

        let id = store
            .create(test_action(), "only one".to_string(), None)
            .await
            .unwrap();
        assert!(!id.is_empty());

        // Second should fail
        let result = store
            .create(test_action(), "overflow".to_string(), None)
            .await;
        assert!(matches!(
            result.unwrap_err(),
            ApprovalError::CapacityExceeded(1)
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // reason validation edge case tests
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_rejects_reason_exceeding_max_length() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let long_reason = "x".repeat(MAX_REASON_LEN + 1);
        let result = store.create(test_action(), long_reason, None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApprovalError::Validation(_)),
            "Expected Validation error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_create_accepts_reason_at_max_length() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );

        let max_reason = "y".repeat(MAX_REASON_LEN);
        let result = store.create(test_action(), max_reason, None).await;
        assert!(
            result.is_ok(),
            "Reason at exact max length should be accepted"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // approve/deny identity validation edge case tests
    // ─────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_approve_rejects_control_chars_in_by() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let id = store
            .create(test_action(), "test".to_string(), None)
            .await
            .unwrap();
        let result = store.approve(&id, "admin\x00injected").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApprovalError::Validation(_)),
            "Expected Validation error for control chars, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_deny_rejects_control_chars_in_by() {
        let dir = TempDir::new().unwrap();
        let store = ApprovalStore::new(
            dir.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        );
        let id = store
            .create(test_action(), "test".to_string(), None)
            .await
            .unwrap();
        let result = store.deny(&id, "admin\ttab").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ApprovalError::Validation(_)),
            "Expected Validation error for control chars, got: {err:?}"
        );
    }
}
