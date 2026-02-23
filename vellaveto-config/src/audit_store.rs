//! Centralized audit store configuration (Phase 43).
//!
//! Controls optional dual-write to PostgreSQL and query backend selection.

use serde::{Deserialize, Serialize};
use vellaveto_types::AuditStoreBackend;

/// Maximum connection pool size.
pub const MAX_POOL_SIZE: u32 = 100;

/// Maximum sink buffer (mpsc channel capacity).
pub const MAX_SINK_BUFFER_SIZE: usize = 10_000;

/// Maximum flush interval (1 minute).
pub const MAX_FLUSH_INTERVAL_MS: u64 = 60_000;

/// Maximum batch insert size.
pub const MAX_BATCH_INSERT_SIZE: usize = 1_000;

/// Maximum connect timeout (seconds).
pub const MAX_CONNECT_TIMEOUT_SECS: u64 = 60;

/// Maximum table name length (SQL identifier).
const MAX_TABLE_NAME_LEN: usize = 128;

/// Configuration for the centralized audit store.
///
/// When `enabled` is false (default), no centralized store is used and
/// all audit data is read from the local JSONL file. When enabled with
/// `backend: postgres`, entries are dual-written to PostgreSQL via an
/// async mpsc channel for structured querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStoreConfig {
    /// Whether the centralized audit store is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Backend type for the centralized store.
    #[serde(default)]
    pub backend: AuditStoreBackend,

    /// PostgreSQL connection URL (required when backend is `postgres`).
    /// Must start with `postgres://` or `postgresql://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_url: Option<String>,

    /// Connection pool size (1–100, default 5).
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// PostgreSQL table name (alphanumeric + underscore only, default `vellaveto_audit_entries`).
    #[serde(default = "default_table_name")]
    pub table_name: String,

    /// Whether to auto-create the table on startup (default true).
    #[serde(default = "crate::default_true")]
    pub auto_migrate: bool,

    /// mpsc channel buffer size for the background writer (1–10000, default 1000).
    #[serde(default = "default_sink_buffer_size")]
    pub sink_buffer_size: usize,

    /// Flush interval in milliseconds for the background writer (1–60000, default 1000).
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,

    /// Batch insert size for the background writer (1–1000, default 100).
    #[serde(default = "default_batch_insert_size")]
    pub batch_insert_size: usize,

    /// Connection timeout in seconds (1–60, default 5).
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Whether sink write failures are fatal (deny the request).
    /// Default false — file log is source of truth, sink failures are logged as warnings.
    #[serde(default)]
    pub sink_failure_fatal: bool,
}

fn default_pool_size() -> u32 {
    5
}

fn default_table_name() -> String {
    "vellaveto_audit_entries".to_string()
}

fn default_sink_buffer_size() -> usize {
    1_000
}

fn default_flush_interval_ms() -> u64 {
    1_000
}

fn default_batch_insert_size() -> usize {
    100
}

fn default_connect_timeout_secs() -> u64 {
    5
}

impl Default for AuditStoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuditStoreBackend::default(),
            database_url: None,
            pool_size: default_pool_size(),
            table_name: default_table_name(),
            auto_migrate: true,
            sink_buffer_size: default_sink_buffer_size(),
            flush_interval_ms: default_flush_interval_ms(),
            batch_insert_size: default_batch_insert_size(),
            connect_timeout_secs: default_connect_timeout_secs(),
            sink_failure_fatal: false,
        }
    }
}

impl AuditStoreConfig {
    /// Validate configuration. Skips most checks when disabled.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Backend-specific validation
        if self.backend == AuditStoreBackend::Postgres {
            // Database URL is required for postgres backend
            match &self.database_url {
                None => {
                    return Err(
                        "audit_store.database_url is required when backend is postgres".to_string(),
                    );
                }
                Some(url) => {
                    let trimmed = url.trim();
                    if trimmed.is_empty() {
                        return Err("audit_store.database_url must not be empty".to_string());
                    }
                    if !trimmed.starts_with("postgres://") && !trimmed.starts_with("postgresql://")
                    {
                        return Err(
                            "audit_store.database_url must start with postgres:// or postgresql://"
                                .to_string(),
                        );
                    }
                    // SECURITY: Reject control characters in URL
                    if vellaveto_types::has_dangerous_chars(trimmed) {
                        return Err(
                            "audit_store.database_url contains control or format characters"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Pool size bounds
        if self.pool_size == 0 || self.pool_size > MAX_POOL_SIZE {
            return Err(format!(
                "audit_store.pool_size must be in [1, {}], got {}",
                MAX_POOL_SIZE, self.pool_size
            ));
        }

        // Table name: alphanumeric + underscore only (prevents SQL injection)
        if self.table_name.is_empty() {
            return Err("audit_store.table_name must not be empty".to_string());
        }
        if self.table_name.len() > MAX_TABLE_NAME_LEN {
            return Err(format!(
                "audit_store.table_name length {} exceeds maximum {}",
                self.table_name.len(),
                MAX_TABLE_NAME_LEN
            ));
        }
        if !self
            .table_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(
                "audit_store.table_name must contain only alphanumeric characters and underscores"
                    .to_string(),
            );
        }
        // SECURITY: Reject table names starting with digits (invalid SQL identifier)
        if self
            .table_name
            .chars()
            .next()
            .map_or(false, |c| c.is_ascii_digit())
        {
            return Err(
                "audit_store.table_name must not start with a digit".to_string(),
            );
        }

        // Sink buffer size bounds
        if self.sink_buffer_size == 0 || self.sink_buffer_size > MAX_SINK_BUFFER_SIZE {
            return Err(format!(
                "audit_store.sink_buffer_size must be in [1, {}], got {}",
                MAX_SINK_BUFFER_SIZE, self.sink_buffer_size
            ));
        }

        // Flush interval bounds
        if self.flush_interval_ms == 0 || self.flush_interval_ms > MAX_FLUSH_INTERVAL_MS {
            return Err(format!(
                "audit_store.flush_interval_ms must be in [1, {}], got {}",
                MAX_FLUSH_INTERVAL_MS, self.flush_interval_ms
            ));
        }

        // Batch insert size bounds
        if self.batch_insert_size == 0 || self.batch_insert_size > MAX_BATCH_INSERT_SIZE {
            return Err(format!(
                "audit_store.batch_insert_size must be in [1, {}], got {}",
                MAX_BATCH_INSERT_SIZE, self.batch_insert_size
            ));
        }

        // Connect timeout bounds
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > MAX_CONNECT_TIMEOUT_SECS {
            return Err(format!(
                "audit_store.connect_timeout_secs must be in [1, {}], got {}",
                MAX_CONNECT_TIMEOUT_SECS, self.connect_timeout_secs
            ));
        }

        Ok(())
    }
}
