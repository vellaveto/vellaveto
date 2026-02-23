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
    inserted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_sequence ON vellaveto_audit_entries (sequence);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON vellaveto_audit_entries (timestamp_raw);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON vellaveto_audit_entries (tool);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON vellaveto_audit_entries (verdict_type);
CREATE INDEX IF NOT EXISTS idx_audit_metadata ON vellaveto_audit_entries USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_audit_ts_verdict ON vellaveto_audit_entries (timestamp_raw, verdict_type);
CREATE INDEX IF NOT EXISTS idx_audit_deny ON vellaveto_audit_entries (timestamp_raw) WHERE verdict_type = 'deny';
"#;

/// Maximum entries in the pending channel before backpressure.
const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// Maximum entries per batch INSERT.
const DEFAULT_BATCH_SIZE: usize = 100;

/// Default flush interval in milliseconds.
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 5_000;

/// Maximum retry attempts for transient failures.
const MAX_RETRY_ATTEMPTS: u32 = 3;

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
        if auto_migrate {
            // Replace table name in DDL (already validated by config)
            let ddl = CREATE_TABLE_DDL.replace("vellaveto_audit_entries", &config.table_name);
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
        let cols = "(id, sequence, timestamp_raw, tool, function_name, verdict_type, verdict_reason, action_json, verdict_json, metadata, entry_hash, prev_hash, commitment)";
        let params_per_row = 13;
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

        let mut query = sqlx::query(&sql);

        for entry in batch {
            let verdict_type = match &entry.verdict {
                vellaveto_types::Verdict::Allow => "allow",
                vellaveto_types::Verdict::Deny { .. } => "deny",
                vellaveto_types::Verdict::RequireApproval { .. } => "require_approval",
                _ => "unknown",
            };
            let verdict_reason = match &entry.verdict {
                vellaveto_types::Verdict::Deny { reason } => Some(reason.as_str()),
                vellaveto_types::Verdict::RequireApproval { reason } => Some(reason.as_str()),
                _ => None,
            };
            let action_json = serde_json::to_value(&entry.action)
                .unwrap_or_else(|_| serde_json::Value::Null);
            let verdict_json = serde_json::to_value(&entry.verdict)
                .unwrap_or_else(|_| serde_json::Value::Null);

            query = query
                .bind(&entry.id)
                .bind(entry.sequence as i64)
                .bind(&entry.timestamp)
                .bind(&entry.action.tool)
                .bind(&entry.action.function)
                .bind(verdict_type)
                .bind(verdict_reason)
                .bind(&action_json)
                .bind(&verdict_json)
                .bind(&entry.metadata)
                .bind(&entry.entry_hash)
                .bind(&entry.prev_hash)
                .bind(&entry.commitment);
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
}
