//! Centralized audit store types — query parameters, results, and backend selection.
//!
//! Phase 43: These types define the query interface for structured audit log search.
//! They live in `vellaveto-types` (leaf crate) so both `vellaveto-audit` and
//! `vellaveto-server` can reference them without circular dependencies.

use serde::{Deserialize, Serialize};

/// Maximum number of entries returned per query (prevents OOM on large result sets).
pub const MAX_QUERY_LIMIT: u64 = 1_000;

/// Maximum text search length (bytes) to prevent ReDoS / excessive scan time.
pub const MAX_TEXT_SEARCH_LEN: usize = 512;

/// Maximum length of agent_id / tool filter strings.
pub const MAX_FILTER_STRING_LEN: usize = 256;

/// Maximum query offset to prevent DoS via astronomical skip values.
pub const MAX_QUERY_OFFSET: u64 = 1_000_000;

/// Maximum length of `tenant_id` filter string (bytes).
///
/// SECURITY (FIND-R203-003): Named constant replaces magic number 64 in validate().
pub const MAX_TENANT_ID_LEN: usize = 64;

/// Supported audit store backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditStoreBackend {
    /// Local JSONL file (default, always active).
    #[default]
    File,
    /// PostgreSQL database (requires `postgres-store` feature).
    Postgres,
}

/// Verdict filter for audit queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictFilter {
    Allow,
    Deny,
    RequireApproval,
}

/// Query parameters for searching audit entries.
///
/// All fields are optional — omitted fields are not filtered.
/// `limit` is capped at [`MAX_QUERY_LIMIT`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryParams {
    /// ISO 8601 start time (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// ISO 8601 end time (exclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,

    /// Filter by agent ID (exact match on metadata.agent_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Filter by tool name (exact match on action.tool).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,

    /// Filter by verdict type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<VerdictFilter>,

    /// Substring text search across tool, function, and metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_search: Option<String>,

    /// Minimum sequence number (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_sequence: Option<u64>,

    /// Maximum sequence number (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_sequence: Option<u64>,

    /// Maximum number of entries to return (default 100, max 1000).
    #[serde(default = "default_limit")]
    pub limit: u64,

    /// Number of entries to skip for pagination.
    #[serde(default)]
    pub offset: u64,

    /// Filter by tenant ID (exact match on entry.tenant_id). Phase 44.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

fn default_limit() -> u64 {
    100
}

impl Default for AuditQueryParams {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            agent_id: None,
            tool: None,
            verdict: None,
            text_search: None,
            from_sequence: None,
            to_sequence: None,
            limit: default_limit(),
            offset: 0,
            tenant_id: None,
        }
    }
}

impl AuditQueryParams {
    /// Validate query parameters. Returns an error describing the first violation.
    pub fn validate(&self) -> Result<(), String> {
        // Cap limit
        if self.limit > MAX_QUERY_LIMIT {
            return Err(format!(
                "limit {} exceeds maximum {}",
                self.limit, MAX_QUERY_LIMIT
            ));
        }
        if self.limit == 0 {
            return Err("limit must be > 0".to_string());
        }

        // SECURITY (FIND-R200-004): Cap offset to prevent DoS via astronomical skip values
        // that force the backend to scan/skip huge numbers of rows.
        if self.offset > MAX_QUERY_OFFSET {
            return Err(format!(
                "offset {} exceeds maximum {}",
                self.offset, MAX_QUERY_OFFSET
            ));
        }

        // Validate filter string lengths
        if let Some(ref agent_id) = self.agent_id {
            // SECURITY (IMP-R198-013): Reject empty filter strings — they are
            // semantically meaningless and likely caller errors.
            if agent_id.is_empty() {
                return Err("agent_id filter must not be empty".to_string());
            }
            if agent_id.len() > MAX_FILTER_STRING_LEN {
                return Err(format!(
                    "agent_id length {} exceeds maximum {}",
                    agent_id.len(),
                    MAX_FILTER_STRING_LEN
                ));
            }
            if crate::has_dangerous_chars(agent_id) {
                return Err(
                    "agent_id contains control or format characters".to_string(),
                );
            }
        }

        if let Some(ref tool) = self.tool {
            // SECURITY (IMP-R198-013): Reject empty filter strings.
            if tool.is_empty() {
                return Err("tool filter must not be empty".to_string());
            }
            if tool.len() > MAX_FILTER_STRING_LEN {
                return Err(format!(
                    "tool length {} exceeds maximum {}",
                    tool.len(),
                    MAX_FILTER_STRING_LEN
                ));
            }
            if crate::has_dangerous_chars(tool) {
                return Err(
                    "tool contains control or format characters".to_string(),
                );
            }
        }

        if let Some(ref text_search) = self.text_search {
            if text_search.is_empty() {
                return Err("text_search must not be empty".to_string());
            }
            if text_search.len() > MAX_TEXT_SEARCH_LEN {
                return Err(format!(
                    "text_search length {} exceeds maximum {}",
                    text_search.len(),
                    MAX_TEXT_SEARCH_LEN
                ));
            }
            if crate::has_dangerous_chars(text_search) {
                return Err(
                    "text_search contains control or format characters".to_string(),
                );
            }
            // SECURITY (FIND-R198-007): Reject text_search consisting solely of
            // SQL LIKE wildcards (% and _). Such patterns match everything and
            // could be used for data exfiltration or DoS via full-table scan.
            if text_search.chars().all(|c| c == '%' || c == '_') {
                return Err(
                    "text_search must not consist solely of SQL wildcard characters".to_string(),
                );
            }
        }

        // Phase 44: Validate tenant_id filter
        if let Some(ref tenant_id) = self.tenant_id {
            if tenant_id.is_empty() {
                return Err("tenant_id filter must not be empty".to_string());
            }
            // SECURITY (FIND-R203-003): Use named constant instead of magic number 64.
            if tenant_id.len() > MAX_TENANT_ID_LEN {
                return Err(format!(
                    "tenant_id length {} exceeds maximum {}",
                    tenant_id.len(),
                    MAX_TENANT_ID_LEN
                ));
            }
            if crate::has_dangerous_chars(tenant_id) {
                return Err(
                    "tenant_id contains control or format characters".to_string(),
                );
            }
        }

        // Validate sequence range ordering
        if let (Some(from), Some(to)) = (self.from_sequence, self.to_sequence) {
            if from > to {
                return Err(format!(
                    "from_sequence ({}) must be <= to_sequence ({})",
                    from, to
                ));
            }
        }

        // SECURITY (FIND-R198-006): Validate timestamps with full ISO 8601 parsing
        // at validation time rather than deferring to query time. Malformed timestamps
        // could bypass time-range filters or cause unexpected query behavior.
        if let Some(ref since) = self.since {
            if since.len() > 64 {
                return Err("since timestamp too long".to_string());
            }
            if crate::has_dangerous_chars(since) {
                return Err("since contains control or format characters".to_string());
            }
            crate::time_util::parse_iso8601_secs(since)
                .map_err(|e| format!("since is not valid ISO 8601: {}", e))?;
        }
        if let Some(ref until) = self.until {
            if until.len() > 64 {
                return Err("until timestamp too long".to_string());
            }
            if crate::has_dangerous_chars(until) {
                return Err("until contains control or format characters".to_string());
            }
            crate::time_util::parse_iso8601_secs(until)
                .map_err(|e| format!("until is not valid ISO 8601: {}", e))?;
        }

        // SECURITY (FIND-R200-005, FIND-R202-001): Validate temporal ordering using parsed
        // epoch seconds, not lexicographic string comparison. Lexicographic ordering can
        // disagree with chronological ordering on edge cases (sub-second precision, timezone
        // suffixes). Both timestamps were already parsed above, so re-parse is infallible.
        if let (Some(ref since), Some(ref until)) = (&self.since, &self.until) {
            let since_epoch = crate::time_util::parse_iso8601_secs(since)
                .map_err(|e| format!("since is not valid ISO 8601: {}", e))?;
            let until_epoch = crate::time_util::parse_iso8601_secs(until)
                .map_err(|e| format!("until is not valid ISO 8601: {}", e))?;
            if since_epoch >= until_epoch {
                return Err(format!(
                    "since ({}) must be before until ({})",
                    since, until
                ));
            }
        }

        Ok(())
    }
}

/// Result of an audit query.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryResult {
    /// Matching entries for this page.
    pub entries: Vec<serde_json::Value>,
    /// Total number of matching entries (across all pages).
    pub total: u64,
    /// Current offset.
    pub offset: u64,
    /// Page size used.
    pub limit: u64,
}

/// Status of the audit store backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStoreStatus {
    /// Which backend is active.
    pub backend: AuditStoreBackend,
    /// Whether the centralized store is enabled.
    pub enabled: bool,
    /// Whether the sink is healthy (for dual-write backends).
    pub sink_healthy: bool,
    /// Number of entries pending flush to the centralized store.
    pub pending_count: usize,
}
