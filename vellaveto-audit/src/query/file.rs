//! File-based audit query implementation (Phase 43).
//!
//! Wraps the existing `AuditLogger::load_entries()` to provide in-memory
//! filtering and pagination. This is the default query backend when no
//! centralized store is configured.
//!
//! Performance note: this loads all entries into memory for each query.
//! For large audit logs, the PostgreSQL backend is recommended.

use super::{AuditQueryService, QueryError};
use crate::types::AuditEntry;
use crate::AuditLogger;
use std::sync::Arc;
use vellaveto_types::audit_store::{AuditQueryParams, AuditQueryResult, VerdictFilter};

/// File-based audit query service.
///
/// Reads entries from the JSONL audit log file and applies filters in memory.
pub struct FileAuditQuery {
    logger: Arc<AuditLogger>,
}

impl std::fmt::Debug for FileAuditQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAuditQuery")
            .field("log_path", &self.logger.log_path)
            .finish()
    }
}

impl FileAuditQuery {
    /// Create a new file-based query service wrapping the given logger.
    pub fn new(logger: Arc<AuditLogger>) -> Self {
        Self { logger }
    }
}

/// Maximum entries loaded from file to prevent OOM.
const MAX_LOADED_ENTRIES: usize = 500_000;

#[async_trait::async_trait]
impl AuditQueryService for FileAuditQuery {
    async fn search(&self, params: &AuditQueryParams) -> Result<AuditQueryResult, QueryError> {
        params
            .validate()
            .map_err(QueryError::Validation)?;

        let entries = self
            .logger
            .load_entries()
            .await
            .map_err(|e| QueryError::Io(std::io::Error::other(e.to_string())))?;

        // Cap loaded entries
        let entries: Vec<AuditEntry> = if entries.len() > MAX_LOADED_ENTRIES {
            entries.into_iter().take(MAX_LOADED_ENTRIES).collect()
        } else {
            entries
        };

        let filtered = filter_entries(&entries, params);
        let total = filtered.len() as u64;

        let offset = params.offset as usize;
        let limit = params.limit as usize;

        let page: Vec<serde_json::Value> = filtered
            .into_iter()
            .skip(offset)
            .take(limit)
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        Ok(AuditQueryResult {
            entries: page,
            total,
            offset: params.offset,
            limit: params.limit,
        })
    }

    async fn count(&self, params: &AuditQueryParams) -> Result<u64, QueryError> {
        params
            .validate()
            .map_err(QueryError::Validation)?;

        let entries = self
            .logger
            .load_entries()
            .await
            .map_err(|e| QueryError::Io(std::io::Error::other(e.to_string())))?;

        let entries: Vec<AuditEntry> = if entries.len() > MAX_LOADED_ENTRIES {
            entries.into_iter().take(MAX_LOADED_ENTRIES).collect()
        } else {
            entries
        };

        let filtered = filter_entries(&entries, params);
        Ok(filtered.len() as u64)
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<serde_json::Value>, QueryError> {
        if id.is_empty() || id.len() > 256 {
            return Err(QueryError::Validation("invalid entry ID".to_string()));
        }
        // SECURITY (FIND-R200-003): Reject control/format characters in entry IDs.
        if vellaveto_types::has_dangerous_chars(id) {
            return Err(QueryError::Validation(
                "entry ID contains control or format characters".to_string(),
            ));
        }

        let entries = self
            .logger
            .load_entries()
            .await
            .map_err(|e| QueryError::Io(std::io::Error::other(e.to_string())))?;

        for entry in entries {
            if entry.id == id {
                return Ok(serde_json::to_value(&entry).ok());
            }
        }
        Ok(None)
    }

    async fn recent(&self, limit: u64) -> Result<Vec<serde_json::Value>, QueryError> {
        let capped_limit = limit.min(vellaveto_types::audit_store::MAX_QUERY_LIMIT) as usize;
        if capped_limit == 0 {
            return Ok(vec![]);
        }

        let entries = self
            .logger
            .load_entries()
            .await
            .map_err(|e| QueryError::Io(std::io::Error::other(e.to_string())))?;

        let start = entries.len().saturating_sub(capped_limit);
        let recent: Vec<serde_json::Value> = entries[start..]
            .iter()
            .filter_map(|e| serde_json::to_value(e).ok())
            .collect();

        Ok(recent)
    }
}

/// Apply all filters from `AuditQueryParams` to a slice of entries.
/// Returns references to matching entries in order.
fn filter_entries<'a>(
    entries: &'a [AuditEntry],
    params: &AuditQueryParams,
) -> Vec<&'a AuditEntry> {
    entries
        .iter()
        .filter(|e| {
            // Time range filter
            if let Some(ref since) = params.since {
                if e.timestamp.as_str() < since.as_str() {
                    return false;
                }
            }
            if let Some(ref until) = params.until {
                if e.timestamp.as_str() >= until.as_str() {
                    return false;
                }
            }

            // Tool filter
            if let Some(ref tool) = params.tool {
                if e.action.tool != *tool {
                    return false;
                }
            }

            // Agent ID filter (check metadata.agent_id)
            if let Some(ref agent_id) = params.agent_id {
                let entry_agent = e
                    .metadata
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if entry_agent != agent_id.as_str() {
                    return false;
                }
            }

            // Verdict filter
            if let Some(ref verdict_filter) = params.verdict {
                let matches = match verdict_filter {
                    VerdictFilter::Allow => matches!(e.verdict, vellaveto_types::Verdict::Allow),
                    VerdictFilter::Deny => {
                        matches!(e.verdict, vellaveto_types::Verdict::Deny { .. })
                    }
                    VerdictFilter::RequireApproval => {
                        matches!(e.verdict, vellaveto_types::Verdict::RequireApproval { .. })
                    }
                };
                if !matches {
                    return false;
                }
            }

            // Sequence range filter
            if let Some(from) = params.from_sequence {
                if e.sequence < from {
                    return false;
                }
            }
            if let Some(to) = params.to_sequence {
                if e.sequence > to {
                    return false;
                }
            }

            // Phase 44: Tenant ID filter (exact match on entry.tenant_id)
            if let Some(ref tid) = params.tenant_id {
                let entry_tenant = e.tenant_id.as_deref().unwrap_or("");
                if entry_tenant != tid.as_str() {
                    return false;
                }
            }

            // Text search (substring match across tool, function, and metadata)
            if let Some(ref text) = params.text_search {
                let text_lower = text.to_lowercase();
                let in_tool = e.action.tool.to_lowercase().contains(&text_lower);
                let in_function = e.action.function.to_lowercase().contains(&text_lower);
                let in_metadata = e.metadata.to_string().to_lowercase().contains(&text_lower);
                if !in_tool && !in_function && !in_metadata {
                    return false;
                }
            }

            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::{Action, Verdict};

    /// Build a test entry with the given tool, verdict, sequence, and timestamp.
    fn make_entry(
        tool: &str,
        function: &str,
        verdict: Verdict,
        sequence: u64,
        timestamp: &str,
        agent_id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> AuditEntry {
        let mut metadata = serde_json::Map::new();
        if let Some(aid) = agent_id {
            metadata.insert("agent_id".to_string(), serde_json::Value::String(aid.to_string()));
        }
        AuditEntry {
            id: format!("entry-{}", sequence),
            action: Action {
                tool: tool.to_string(),
                function: function.to_string(),
                parameters: serde_json::Value::Object(serde_json::Map::new()),
                target_paths: vec![],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict,
            timestamp: timestamp.to_string(),
            metadata: serde_json::Value::Object(metadata),
            sequence,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: tenant_id.map(|t| t.to_string()),
        }
    }

    fn sample_entries() -> Vec<AuditEntry> {
        vec![
            make_entry("file_read", "read", Verdict::Allow, 1, "2026-01-01T00:00:00Z", Some("agent-a"), Some("tenant-1")),
            make_entry("file_write", "write", Verdict::Deny { reason: "blocked".to_string() }, 2, "2026-01-02T00:00:00Z", Some("agent-b"), Some("tenant-1")),
            make_entry("http_request", "get", Verdict::Allow, 3, "2026-01-03T00:00:00Z", Some("agent-a"), Some("tenant-2")),
            make_entry("file_read", "read_secret", Verdict::RequireApproval { reason: "sensitive".to_string() }, 4, "2026-01-04T00:00:00Z", None, None),
            make_entry("db_query", "select", Verdict::Allow, 5, "2026-01-05T00:00:00Z", Some("agent-c"), Some("tenant-1")),
        ]
    }

    #[test]
    fn test_filter_entries_no_filters_returns_all() {
        let entries = sample_entries();
        let params = AuditQueryParams::default();
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_filter_entries_tool_filter() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            tool: Some("file_read".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|e| e.action.tool == "file_read"));
    }

    #[test]
    fn test_filter_entries_agent_id_filter() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            agent_id: Some("agent-a".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_entries_agent_id_missing_metadata_excluded() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            agent_id: Some("agent-a".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        // Entry 4 has no agent_id metadata — should be excluded
        assert!(result.iter().all(|e| e.sequence != 4));
    }

    #[test]
    fn test_filter_entries_verdict_allow() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            verdict: Some(VerdictFilter::Allow),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_filter_entries_verdict_deny() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            verdict: Some(VerdictFilter::Deny),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sequence, 2);
    }

    #[test]
    fn test_filter_entries_verdict_require_approval() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            verdict: Some(VerdictFilter::RequireApproval),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sequence, 4);
    }

    #[test]
    fn test_filter_entries_since_timestamp() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            since: Some("2026-01-03T00:00:00Z".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3); // entries 3, 4, 5
    }

    #[test]
    fn test_filter_entries_until_timestamp() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            until: Some("2026-01-03T00:00:00Z".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 2); // entries 1, 2 (until is exclusive)
    }

    #[test]
    fn test_filter_entries_since_and_until_range() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            since: Some("2026-01-02T00:00:00Z".to_string()),
            until: Some("2026-01-04T00:00:00Z".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 2); // entries 2, 3
    }

    #[test]
    fn test_filter_entries_sequence_range() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            from_sequence: Some(2),
            to_sequence: Some(4),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3); // entries 2, 3, 4
    }

    #[test]
    fn test_filter_entries_text_search_in_tool() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            text_search: Some("file".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3); // file_read (x2) + file_write
    }

    #[test]
    fn test_filter_entries_text_search_in_function() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            text_search: Some("secret".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 1); // read_secret
        assert_eq!(result[0].sequence, 4);
    }

    #[test]
    fn test_filter_entries_text_search_case_insensitive() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            text_search: Some("FILE".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_filter_entries_tenant_id_filter() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            tenant_id: Some("tenant-1".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 3); // entries 1, 2, 5
    }

    #[test]
    fn test_filter_entries_tenant_id_excludes_none() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            tenant_id: Some("tenant-1".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        // Entry 4 has tenant_id=None, should be excluded
        assert!(result.iter().all(|e| e.sequence != 4));
    }

    #[test]
    fn test_filter_entries_combined_filters() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            tool: Some("file_read".to_string()),
            verdict: Some(VerdictFilter::Allow),
            tenant_id: Some("tenant-1".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert_eq!(result.len(), 1); // Only entry 1
        assert_eq!(result[0].sequence, 1);
    }

    #[test]
    fn test_filter_entries_empty_input() {
        let entries: Vec<AuditEntry> = vec![];
        let params = AuditQueryParams::default();
        let result = filter_entries(&entries, &params);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_entries_no_match() {
        let entries = sample_entries();
        let params = AuditQueryParams {
            tool: Some("nonexistent_tool".to_string()),
            ..Default::default()
        };
        let result = filter_entries(&entries, &params);
        assert!(result.is_empty());
    }
}
