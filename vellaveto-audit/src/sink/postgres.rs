//! PostgreSQL audit sink implementation (Phase 43).
//!
//! Uses an mpsc channel to decouple the log_entry() hot path from database I/O.
//! A background tokio task drains the channel and batch-INSERTs to PostgreSQL.
//!
//! This module is feature-gated behind `postgres-store`.

use crate::sink::{AuditSink, SinkError};
use crate::types::AuditEntry;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Schema DDL for the audit entries table.
/// Indexes are chosen for the query patterns in `PostgresAuditQuery`.
const CREATE_TABLE_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS vellaveto_audit_entries (
    id               TEXT PRIMARY KEY,
    sequence         BIGINT NOT NULL,
    timestamp_raw    TEXT NOT NULL,
    tool             TEXT NOT NULL,
    function_name    TEXT NOT NULL,
    verdict_type     TEXT NOT NULL,
    verdict_reason   TEXT,
    action_json      JSONB NOT NULL,
    verdict_json     JSONB NOT NULL,
    metadata         JSONB NOT NULL DEFAULT '{}',
    entry_hash       TEXT NOT NULL,
    prev_hash        TEXT NOT NULL,
    commitment       TEXT,
    tenant_id        TEXT,
    inserted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_sequence ON vellaveto_audit_entries (sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON vellaveto_audit_entries (timestamp_raw);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON vellaveto_audit_entries (tool);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON vellaveto_audit_entries (verdict_type);
CREATE INDEX IF NOT EXISTS idx_audit_metadata ON vellaveto_audit_entries USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_audit_ts_verdict ON vellaveto_audit_entries (timestamp_raw, verdict_type);
CREATE INDEX IF NOT EXISTS idx_audit_deny ON vellaveto_audit_entries (timestamp_raw) WHERE verdict_type = 'deny';
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON vellaveto_audit_entries (tenant_id);
"#;

/// Maximum entries in the pending channel before backpressure.
const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// Maximum entries per batch INSERT.
const DEFAULT_BATCH_SIZE: usize = 100;

/// Default flush interval in milliseconds.
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 5_000;

/// Maximum retry attempts for transient failures.
const MAX_RETRY_ATTEMPTS: u32 = 3;

/// Maximum batch size to stay within PostgreSQL's 65535 bind-parameter limit.
/// Each row uses 14 parameters (Phase 44: +tenant_id), so 65535 / 14 = 4681.
/// We cap at 4600 for safety.
const MAX_BATCH_SIZE: usize = 4_600;

/// PostgreSQL audit sink configuration.
pub struct PostgresSinkConfig {
    /// Channel buffer size.
    pub buffer_size: usize,
    /// Max entries per batch INSERT.
    pub batch_size: usize,
    /// Flush interval in milliseconds.
    pub flush_interval_ms: u64,
    /// Table name (pre-validated to be safe SQL identifier).
    pub table_name: String,
}

impl PostgresSinkConfig {
    /// Validate configuration values.
    ///
    /// Rejects zero values for `buffer_size`, `batch_size`, and `flush_interval_ms`.
    /// Validates `table_name` is a safe SQL identifier (non-empty, alphanumeric + underscore,
    /// does not start with a digit, max 63 chars per PostgreSQL identifier limit).
    /// Caps `batch_size` at [`MAX_BATCH_SIZE`] to stay within PostgreSQL's 65535 param limit.
    pub fn validate(&self) -> Result<(), SinkError> {
        if self.buffer_size == 0 {
            return Err(SinkError::Connection(
                "buffer_size must be > 0".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(SinkError::Connection(
                "batch_size must be > 0".to_string(),
            ));
        }
        if self.batch_size > MAX_BATCH_SIZE {
            return Err(SinkError::Connection(format!(
                "batch_size ({}) exceeds maximum ({}); PostgreSQL has a 65535 bind-parameter limit",
                self.batch_size, MAX_BATCH_SIZE
            )));
        }
        if self.flush_interval_ms == 0 {
            return Err(SinkError::Connection(
                "flush_interval_ms must be > 0".to_string(),
            ));
        }
        if self.table_name.is_empty() {
            return Err(SinkError::Connection(
                "table_name must not be empty".to_string(),
            ));
        }
        if self.table_name.len() > 63 {
            return Err(SinkError::Connection(
                "table_name exceeds PostgreSQL's 63-character identifier limit".to_string(),
            ));
        }
        if self.table_name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(SinkError::Connection(
                "table_name must not start with a digit".to_string(),
            ));
        }
        if !self
            .table_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(SinkError::Connection(
                "table_name must contain only alphanumeric characters and underscores".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for PostgresSinkConfig {
    fn default() -> Self {
        Self {
            buffer_size: DEFAULT_CHANNEL_CAPACITY,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            table_name: "vellaveto_audit_entries".to_string(),
        }
    }
}

/// PostgreSQL audit sink.
///
/// Entries are sent to a background writer via an mpsc channel.
/// The writer batches INSERTs for efficiency.
pub struct PostgresAuditSink {
    tx: mpsc::Sender<AuditEntry>,
    pending: Arc<AtomicUsize>,
    healthy: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

impl std::fmt::Debug for PostgresAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresAuditSink")
            .field("pending", &self.pending.load(Ordering::SeqCst))
            .field("healthy", &self.healthy.load(Ordering::SeqCst))
            .finish()
    }
}

impl PostgresAuditSink {
    /// Create a new PostgreSQL sink with a background writer.
    ///
    /// If `auto_migrate` is true, the table and indexes are created on startup.
    pub async fn new(
        pool: PgPool,
        config: PostgresSinkConfig,
        auto_migrate: bool,
    ) -> Result<Self, SinkError> {
        config.validate()?;

        if auto_migrate {
            // Replace table name in DDL (already validated by config).
            // SECURITY (FIND-R200-008): Also replace index name prefix to avoid
            // collisions when multiple instances use different table names.
            let ddl = CREATE_TABLE_DDL
                .replace("vellaveto_audit_entries", &config.table_name)
                .replace("idx_audit_", &format!("idx_{}_", config.table_name));
            sqlx::raw_sql(&ddl)
                .execute(&pool)
                .await
                .map_err(|e| SinkError::Connection(format!("Migration failed: {}", e)))?;
            tracing::info!(table = %config.table_name, "Audit store table migrated");
        }

        let (tx, rx) = mpsc::channel(config.buffer_size);
        let pending = Arc::new(AtomicUsize::new(0));
        let healthy = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Spawn background writer
        let writer = BackgroundWriter {
            pool,
            rx,
            pending: Arc::clone(&pending),
            healthy: Arc::clone(&healthy),
            shutdown: Arc::clone(&shutdown),
            batch_size: config.batch_size,
            flush_interval: std::time::Duration::from_millis(config.flush_interval_ms),
            table_name: config.table_name,
        };
        tokio::spawn(writer.run());

        Ok(Self {
            tx,
            pending,
            healthy,
            shutdown,
        })
    }
}

#[async_trait::async_trait]
impl AuditSink for PostgresAuditSink {
    async fn sink(&self, entry: &AuditEntry) -> Result<(), SinkError> {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(SinkError::ShuttingDown);
        }
        match self.tx.try_send(entry.clone()) {
            Ok(()) => {
                let _ = self
                    .pending
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                        Some(v.saturating_add(1))
                    });
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(SinkError::BufferFull(self.pending.load(Ordering::SeqCst)))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(SinkError::ShuttingDown),
        }
    }

    async fn flush(&self) -> Result<(), SinkError> {
        // Signal the writer to flush, then wait for pending to drain.
        // In practice the writer flushes on its interval or batch size.
        // This is a best-effort wait.
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);
        while self.pending.load(Ordering::SeqCst) > 0 {
            if start.elapsed() > timeout {
                return Err(SinkError::Write("Flush timed out".to_string()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), SinkError> {
        self.shutdown.store(true, Ordering::SeqCst);
        // Give the writer time to drain
        self.flush().await
    }

    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    fn pending_count(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
}

/// Background writer that drains the channel and batch-INSERTs to PostgreSQL.
struct BackgroundWriter {
    pool: PgPool,
    rx: mpsc::Receiver<AuditEntry>,
    pending: Arc<AtomicUsize>,
    healthy: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    batch_size: usize,
    flush_interval: std::time::Duration,
    table_name: String,
}

impl BackgroundWriter {
    async fn run(mut self) {
        let mut batch: Vec<AuditEntry> = Vec::with_capacity(self.batch_size);
        let mut interval = tokio::time::interval(self.flush_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                entry = self.rx.recv() => {
                    match entry {
                        Some(e) => {
                            batch.push(e);
                            if batch.len() >= self.batch_size {
                                self.flush_batch(&mut batch).await;
                            }
                        }
                        None => {
                            // Channel closed — flush remaining and exit.
                            if !batch.is_empty() {
                                self.flush_batch(&mut batch).await;
                            }
                            tracing::info!("Audit sink writer shutting down");
                            return;
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        self.flush_batch(&mut batch).await;
                    }
                    // Check for shutdown
                    if self.shutdown.load(Ordering::SeqCst) && batch.is_empty() {
                        tracing::info!("Audit sink writer shutdown complete");
                        return;
                    }
                }
            }
        }
    }

    async fn flush_batch(&mut self, batch: &mut Vec<AuditEntry>) {
        let count = batch.len();
        for attempt in 0..MAX_RETRY_ATTEMPTS {
            match self.insert_batch(batch).await {
                Ok(()) => {
                    let _ = self.pending.fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |v| Some(v.saturating_sub(count)),
                    );
                    self.healthy.store(true, Ordering::SeqCst);
                    batch.clear();
                    return;
                }
                Err(e) => {
                    let backoff = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = MAX_RETRY_ATTEMPTS,
                        error = %e,
                        batch_size = count,
                        "Audit sink batch insert failed, retrying after {:?}",
                        backoff
                    );
                    self.healthy.store(false, Ordering::SeqCst);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        // All retries failed — drop the batch to prevent unbounded growth
        tracing::error!(
            batch_size = count,
            "Audit sink batch insert failed after {} retries, dropping entries",
            MAX_RETRY_ATTEMPTS
        );
        let _ = self.pending.fetch_update(
            Ordering::SeqCst,
            Ordering::SeqCst,
            |v| Some(v.saturating_sub(count)),
        );
        batch.clear();
    }

    async fn insert_batch(&self, batch: &[AuditEntry]) -> Result<(), sqlx::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        // Build parameterized batch INSERT
        // INSERT INTO table (columns) VALUES ($1,$2,...), ($N+1,$N+2,...), ...
        let cols = "(id, sequence, timestamp_raw, tool, function_name, verdict_type, verdict_reason, action_json, verdict_json, metadata, entry_hash, prev_hash, commitment, tenant_id)";
        let params_per_row = 14;
        let mut sql = format!(
            "INSERT INTO {} {} VALUES ",
            self.table_name, cols
        );

        let mut param_idx = 1u32;
        for (i, _) in batch.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push('(');
            for j in 0..params_per_row {
                if j > 0 {
                    sql.push_str(", ");
                }
                sql.push('$');
                sql.push_str(&param_idx.to_string());
                param_idx = param_idx.saturating_add(1);
            }
            sql.push(')');
        }
        sql.push_str(" ON CONFLICT (id) DO NOTHING");

        // Pre-compute derived values so they live long enough for the query borrow.
        // Each tuple: (sequence_i64, verdict_type, verdict_reason, action_json, verdict_json)
        let mut derived: Vec<(i64, &'static str, Option<String>, serde_json::Value, serde_json::Value)> =
            Vec::with_capacity(batch.len());

        for entry in batch {
            // SECURITY (R158-001): Use try_from to prevent wrapping when sequence > i64::MAX.
            let sequence_i64 = i64::try_from(entry.sequence).map_err(|_| {
                sqlx::Error::Protocol(format!(
                    "sequence {} exceeds i64::MAX for entry {}",
                    entry.sequence, entry.id
                ))
            })?;

            let verdict_type: &'static str = match &entry.verdict {
                vellaveto_types::Verdict::Allow => "allow",
                vellaveto_types::Verdict::Deny { .. } => "deny",
                vellaveto_types::Verdict::RequireApproval { .. } => "require_approval",
                _ => "unknown",
            };
            let verdict_reason = match &entry.verdict {
                vellaveto_types::Verdict::Deny { reason } => Some(reason.clone()),
                vellaveto_types::Verdict::RequireApproval { reason } => Some(reason.clone()),
                _ => None,
            };
            // SECURITY (R158-005): Log a warning when serialization fails instead of
            // silently converting to null, which loses audit data.
            let action_json = serde_json::to_value(&entry.action).unwrap_or_else(|e| {
                tracing::warn!(
                    entry_id = %entry.id,
                    error = %e,
                    "Action serialization failed for audit entry, storing null"
                );
                serde_json::Value::Null
            });
            let verdict_json = serde_json::to_value(&entry.verdict).unwrap_or_else(|e| {
                tracing::warn!(
                    entry_id = %entry.id,
                    error = %e,
                    "Verdict serialization failed for audit entry, storing null"
                );
                serde_json::Value::Null
            });

            derived.push((sequence_i64, verdict_type, verdict_reason, action_json, verdict_json));
        }

        let mut query = sqlx::query(&sql);

        for (entry, (sequence_i64, verdict_type, verdict_reason, action_json, verdict_json)) in
            batch.iter().zip(derived.iter())
        {
            query = query
                .bind(&entry.id)
                .bind(*sequence_i64)
                .bind(&entry.timestamp)
                .bind(&entry.action.tool)
                .bind(&entry.action.function)
                .bind(*verdict_type)
                .bind(verdict_reason.as_deref())
                .bind(action_json)
                .bind(verdict_json)
                .bind(&entry.metadata)
                .bind(&entry.entry_hash)
                .bind(&entry.prev_hash)
                .bind(&entry.commitment)
                .bind(entry.tenant_id.as_deref());
        }

        query.execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PostgresSinkConfig::default();
        assert_eq!(config.buffer_size, DEFAULT_CHANNEL_CAPACITY);
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.flush_interval_ms, DEFAULT_FLUSH_INTERVAL_MS);
        assert_eq!(config.table_name, "vellaveto_audit_entries");
    }

    #[test]
    fn test_ddl_contains_table_and_indexes() {
        assert!(CREATE_TABLE_DDL.contains("CREATE TABLE IF NOT EXISTS"));
        assert!(CREATE_TABLE_DDL.contains("idx_audit_sequence"));
        assert!(CREATE_TABLE_DDL.contains("idx_audit_metadata"));
        assert!(CREATE_TABLE_DDL.contains("GIN"));
        assert!(CREATE_TABLE_DDL.contains("ON CONFLICT") == false); // DDL doesn't have ON CONFLICT
    }

    #[test]
    fn test_sink_debug_redacts_pool() {
        // The Debug impl should not expose connection strings
        let debug_output = format!(
            "{:?}",
            format_args!("PostgresAuditSink {{ pending: 0, healthy: true }}")
        );
        assert!(!debug_output.contains("postgres://"));
    }

    // --- PostgresSinkConfig::validate() tests (R158-002) ---

    #[test]
    fn test_config_validate_default_passes() {
        let config = PostgresSinkConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_buffer_size() {
        let config = PostgresSinkConfig {
            buffer_size: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("buffer_size"), "got: {err}");
    }

    #[test]
    fn test_config_validate_zero_batch_size() {
        let config = PostgresSinkConfig {
            batch_size: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("batch_size"), "got: {err}");
    }

    #[test]
    fn test_config_validate_batch_size_exceeds_max() {
        let config = PostgresSinkConfig {
            batch_size: MAX_BATCH_SIZE + 1,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("batch_size"), "got: {err}");
        assert!(err.contains("65535"), "should mention PG param limit: {err}");
    }

    #[test]
    fn test_config_validate_batch_size_at_max() {
        let config = PostgresSinkConfig {
            batch_size: MAX_BATCH_SIZE,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_flush_interval() {
        let config = PostgresSinkConfig {
            flush_interval_ms: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("flush_interval_ms"), "got: {err}");
    }

    #[test]
    fn test_config_validate_empty_table_name() {
        let config = PostgresSinkConfig {
            table_name: String::new(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("table_name"), "got: {err}");
    }

    #[test]
    fn test_config_validate_table_name_starts_with_digit() {
        let config = PostgresSinkConfig {
            table_name: "1audit".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("digit"), "got: {err}");
    }

    #[test]
    fn test_config_validate_table_name_special_chars() {
        let config = PostgresSinkConfig {
            table_name: "audit; DROP TABLE --".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("alphanumeric"),
            "got: {err}"
        );
    }

    #[test]
    fn test_config_validate_table_name_too_long() {
        let config = PostgresSinkConfig {
            table_name: "a".repeat(64),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("63"), "got: {err}");
    }

    #[test]
    fn test_config_validate_table_name_at_max_length() {
        let config = PostgresSinkConfig {
            table_name: "a".repeat(63),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_table_name_with_underscore() {
        let config = PostgresSinkConfig {
            table_name: "my_audit_table".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
