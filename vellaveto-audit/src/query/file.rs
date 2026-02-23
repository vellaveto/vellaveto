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
