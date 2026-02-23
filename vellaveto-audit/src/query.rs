//! Audit query service abstraction (Phase 43).
//!
//! Provides a trait for structured audit log search and a file-based
//! implementation that wraps the existing `AuditLogger::load_entries()`.

use thiserror::Error;
use vellaveto_types::audit_store::{AuditQueryParams, AuditQueryResult};

pub mod file;

#[cfg(feature = "postgres-store")]
pub mod postgres;

/// Errors from audit query operations.
#[derive(Error, Debug)]
pub enum QueryError {
    /// I/O error reading the audit log.
    #[error("query I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Query execution failed.
    #[error("query error: {0}")]
    Query(String),

    /// Invalid query parameters.
    #[error("query validation error: {0}")]
    Validation(String),

    /// The query backend is not available.
    #[error("query backend not available: {0}")]
    NotAvailable(String),
}

/// Trait for querying audit log entries.
///
/// Implementations provide structured search over audit data, whether
/// from local files or a centralized database.
#[async_trait::async_trait]
pub trait AuditQueryService: Send + Sync + std::fmt::Debug {
    /// Search audit entries matching the given parameters.
    ///
    /// Returns paginated results with total count for the query.
    async fn search(&self, params: &AuditQueryParams) -> Result<AuditQueryResult, QueryError>;

    /// Count entries matching the given parameters (without fetching data).
    async fn count(&self, params: &AuditQueryParams) -> Result<u64, QueryError>;

    /// Look up a single entry by its UUID.
    async fn get_by_id(&self, id: &str) -> Result<Option<serde_json::Value>, QueryError>;

    /// Get the N most recent entries.
    async fn recent(&self, limit: u64) -> Result<Vec<serde_json::Value>, QueryError>;
}
