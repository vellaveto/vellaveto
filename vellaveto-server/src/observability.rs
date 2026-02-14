//! Background observability export manager.
//!
//! This module provides non-blocking export of security spans to AI observability
//! platforms (Langfuse, Arize, Helicone) via a background task.
//!
//! ## Architecture
//!
//! ```text
//! Route Handler
//!     |
//!     v
//! submit(span) --> [MPSC Channel] --> Background Task
//!                                          |
//!                                          v
//!                                     SpanSampler
//!                                          |
//!                                          v
//!                                     Exporters[]
//! ```
//!
//! ## Non-Blocking Design
//!
//! The `submit()` method is non-blocking and returns immediately. Spans are
//! buffered in an MPSC channel and processed by a background task. This ensures
//! the hot path (policy evaluation) is not affected by export latency.
//!
//! ## Feature Gate
//!
//! This module is always compiled but exporters are only created when the
//! `observability-exporters` feature is enabled in vellaveto-audit.

use vellaveto_audit::observability::{ObservabilityError, RedactionConfig, SecuritySpan};
use vellaveto_config::observability::ObservabilityConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::warn;

#[cfg(feature = "observability-exporters")]
use vellaveto_audit::observability::{ObservabilityExporter, SamplingConfig, SpanSampler};
#[cfg(feature = "observability-exporters")]
use tokio::sync::mpsc;
#[cfg(feature = "observability-exporters")]
use tracing::{debug, error, info};

/// Statistics for observability exports.
#[derive(Debug, Default)]
pub struct ObservabilityStats {
    /// Total spans submitted.
    pub spans_submitted: AtomicU64,
    /// Spans sampled (passed sampling).
    pub spans_sampled: AtomicU64,
    /// Spans dropped (failed sampling).
    pub spans_dropped: AtomicU64,
    /// Spans exported successfully.
    pub spans_exported: AtomicU64,
    /// Export failures.
    pub export_failures: AtomicU64,
}

impl ObservabilityStats {
    /// Create a snapshot of current stats.
    pub fn snapshot(&self) -> ObservabilityStatsSnapshot {
        ObservabilityStatsSnapshot {
            spans_submitted: self.spans_submitted.load(Ordering::Relaxed),
            spans_sampled: self.spans_sampled.load(Ordering::Relaxed),
            spans_dropped: self.spans_dropped.load(Ordering::Relaxed),
            spans_exported: self.spans_exported.load(Ordering::Relaxed),
            export_failures: self.export_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of observability statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObservabilityStatsSnapshot {
    pub spans_submitted: u64,
    pub spans_sampled: u64,
    pub spans_dropped: u64,
    pub spans_exported: u64,
    pub export_failures: u64,
}

/// Information about a configured exporter.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExporterInfo {
    /// Exporter name (e.g., "langfuse", "arize").
    pub name: String,
    /// Whether the exporter is enabled.
    pub enabled: bool,
    /// Last health check result.
    pub healthy: bool,
    /// Batch size configuration.
    pub batch_size: usize,
    /// Flush interval in seconds.
    pub flush_interval_secs: u64,
}

// ============================================================================
// Feature-gated implementation
// ============================================================================

#[cfg(feature = "observability-exporters")]
mod enabled {
    use super::*;

    /// Background observability export manager.
    ///
    /// Manages non-blocking export of security spans to observability platforms.
    pub struct ObservabilityManager {
        /// Channel sender for submitting spans.
        tx: mpsc::Sender<SecuritySpan>,
        /// Span sampler for filtering.
        sampler: SpanSampler,
        /// Redaction config for sensitive data.
        redaction: RedactionConfig,
        /// Export statistics.
        stats: Arc<ObservabilityStats>,
        /// Configured exporters info (for status reporting).
        exporter_info: Vec<ExporterInfo>,
        /// Whether observability is enabled.
        enabled: bool,
    }

    impl ObservabilityManager {
        /// Create a new observability manager and spawn background task.
        ///
        /// Returns `None` if observability is disabled or no exporters are enabled.
        pub fn new(config: &ObservabilityConfig) -> Result<Option<Self>, ObservabilityError> {
            if !config.enabled || !config.has_enabled_exporters() {
                debug!("Observability disabled or no exporters configured");
                return Ok(None);
            }

            // Build exporters
            let mut exporters: Vec<Arc<dyn ObservabilityExporter>> = Vec::new();
            let mut exporter_info = Vec::new();

            // Langfuse
            if config.langfuse.enabled {
                let langfuse_config = Self::build_langfuse_config(&config.langfuse)?;
                let exporter = vellaveto_audit::observability::langfuse::LangfuseExporter::new(
                    langfuse_config,
                )?;
                exporter_info.push(ExporterInfo {
                    name: "langfuse".to_string(),
                    enabled: true,
                    healthy: true,
                    batch_size: config.langfuse.batch_size,
                    flush_interval_secs: config.langfuse.flush_interval_secs,
                });
                exporters.push(Arc::new(exporter));
                info!("Langfuse exporter enabled");
            }

            // Arize
            if config.arize.enabled {
                let arize_config = Self::build_arize_config(&config.arize)?;
                let exporter =
                    vellaveto_audit::observability::arize::ArizeExporter::new(arize_config)?;
                exporter_info.push(ExporterInfo {
                    name: "arize".to_string(),
                    enabled: true,
                    healthy: true,
                    batch_size: config.arize.batch_size,
                    flush_interval_secs: config.arize.flush_interval_secs,
                });
                exporters.push(Arc::new(exporter));
                info!("Arize exporter enabled");
            }

            // Helicone
            if config.helicone.enabled {
                let helicone_config = Self::build_helicone_config(&config.helicone)?;
                let exporter = vellaveto_audit::observability::helicone::HeliconeExporter::new(
                    helicone_config,
                )?;
                exporter_info.push(ExporterInfo {
                    name: "helicone".to_string(),
                    enabled: true,
                    healthy: true,
                    batch_size: config.helicone.batch_size,
                    flush_interval_secs: config.helicone.flush_interval_secs,
                });
                exporters.push(Arc::new(exporter));
                info!("Helicone exporter enabled");
            }

            // Webhook
            if config.webhook.enabled {
                let webhook_config = Self::build_webhook_config(&config.webhook)?;
                let exporter =
                    vellaveto_audit::observability::webhook::WebhookExporter::new(webhook_config)?;
                exporter_info.push(ExporterInfo {
                    name: "webhook".to_string(),
                    enabled: true,
                    healthy: true,
                    batch_size: config.webhook.batch_size,
                    flush_interval_secs: config.webhook.flush_interval_secs,
                });
                exporters.push(Arc::new(exporter));
                info!("Webhook exporter enabled");
            }

            if exporters.is_empty() {
                return Ok(None);
            }

            // Create channel with bounded capacity
            let (tx, rx) = mpsc::channel::<SecuritySpan>(1000);

            // Build sampler
            let sampling_config = SamplingConfig {
                sample_rate: config.sample_rate,
                always_sample_denies: config.always_sample_denies,
                always_sample_detections: config.always_sample_detections,
                min_severity_to_sample: config.min_severity_to_sample,
            };
            let sampler = SpanSampler::new(sampling_config);

            // Build redaction config
            let mut redacted_fields = vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "api_key".to_string(),
                "apikey".to_string(),
                "authorization".to_string(),
                "bearer".to_string(),
                "credential".to_string(),
                "private_key".to_string(),
            ];
            redacted_fields.extend(config.redacted_fields.clone());

            let redaction = RedactionConfig {
                enabled: config.mask_sensitive_data,
                max_body_size: config.max_body_size,
                redacted_fields,
                redaction_text: "[REDACTED]".to_string(),
            };

            let stats = Arc::new(ObservabilityStats::default());

            // Spawn background export task
            let task_stats = stats.clone();
            let flush_interval = std::time::Duration::from_secs(
                config
                    .langfuse
                    .flush_interval_secs
                    .max(config.arize.flush_interval_secs)
                    .max(config.helicone.flush_interval_secs)
                    .max(config.webhook.flush_interval_secs)
                    .max(1),
            );
            let batch_size = config
                .langfuse
                .batch_size
                .min(config.arize.batch_size)
                .min(config.helicone.batch_size)
                .min(config.webhook.batch_size)
                .max(1);

            tokio::spawn(Self::export_task(
                rx,
                exporters,
                task_stats,
                batch_size,
                flush_interval,
            ));

            info!(
                "Observability manager started with {} exporter(s)",
                exporter_info.len()
            );

            Ok(Some(Self {
                tx,
                sampler,
                redaction,
                stats,
                exporter_info,
                enabled: true,
            }))
        }

        /// Submit a span for export (non-blocking).
        ///
        /// Returns immediately. The span will be sampled and exported by the
        /// background task if it passes sampling.
        pub fn submit(&self, span: SecuritySpan) {
            if !self.enabled {
                return;
            }

            self.stats.spans_submitted.fetch_add(1, Ordering::Relaxed);

            // Check sampling
            if !self.sampler.should_sample(&span) {
                self.stats.spans_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }

            self.stats.spans_sampled.fetch_add(1, Ordering::Relaxed);

            // Try to send (non-blocking)
            if let Err(e) = self.tx.try_send(span) {
                warn!("Observability channel full, dropping span: {}", e);
                self.stats.spans_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

        /// Get current statistics.
        pub fn stats(&self) -> ObservabilityStatsSnapshot {
            self.stats.snapshot()
        }

        /// Get exporter information.
        pub fn exporters(&self) -> &[ExporterInfo] {
            &self.exporter_info
        }

        /// Get redaction config (for use by routes).
        pub fn redaction(&self) -> &RedactionConfig {
            &self.redaction
        }

        /// Check if request body capture is enabled.
        pub fn capture_request_body(&self) -> bool {
            self.redaction.enabled
        }

        /// Background export task.
        async fn export_task(
            mut rx: mpsc::Receiver<SecuritySpan>,
            exporters: Vec<Arc<dyn ObservabilityExporter>>,
            stats: Arc<ObservabilityStats>,
            batch_size: usize,
            flush_interval: std::time::Duration,
        ) {
            let mut batch = Vec::with_capacity(batch_size);
            let mut interval = tokio::time::interval(flush_interval);

            loop {
                tokio::select! {
                    // Receive span
                    span = rx.recv() => {
                        match span {
                            Some(s) => {
                                batch.push(s);
                                if batch.len() >= batch_size {
                                    Self::flush_batch(&mut batch, &exporters, &stats).await;
                                }
                            }
                            None => {
                                // Channel closed, flush remaining and exit
                                if !batch.is_empty() {
                                    Self::flush_batch(&mut batch, &exporters, &stats).await;
                                }
                                info!("Observability export task shutting down");
                                break;
                            }
                        }
                    }
                    // Periodic flush
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::flush_batch(&mut batch, &exporters, &stats).await;
                        }
                    }
                }
            }
        }

        /// Flush a batch to all exporters.
        async fn flush_batch(
            batch: &mut Vec<SecuritySpan>,
            exporters: &[Arc<dyn ObservabilityExporter>],
            stats: &Arc<ObservabilityStats>,
        ) {
            let span_count = batch.len() as u64;

            for exporter in exporters {
                match exporter.export_batch(batch).await {
                    Ok(()) => {
                        debug!(
                            exporter = exporter.name(),
                            count = span_count,
                            "Exported spans successfully"
                        );
                        stats
                            .spans_exported
                            .fetch_add(span_count, Ordering::Relaxed);
                    }
                    Err(e) => {
                        error!(
                            exporter = exporter.name(),
                            error = %e,
                            count = span_count,
                            "Failed to export spans"
                        );
                        stats.export_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            batch.clear();
        }

        // Config builders
        fn build_langfuse_config(
            config: &vellaveto_config::observability::LangfuseConfig,
        ) -> Result<
            vellaveto_audit::observability::langfuse::LangfuseExporterConfig,
            ObservabilityError,
        > {
            let mut exporter_config =
                vellaveto_audit::observability::langfuse::LangfuseExporterConfig::from_env(
                    &config.endpoint,
                    &config.public_key_env,
                    &config.secret_key_env,
                )?;

            if let Some(release) = &config.release {
                exporter_config = exporter_config.with_release(release);
            }

            for (key, value) in &config.metadata {
                exporter_config = exporter_config.with_metadata(key, value.clone());
            }

            exporter_config.common.batch_size = config.batch_size;
            exporter_config.common.flush_interval_secs = config.flush_interval_secs;
            exporter_config.common.max_retries = config.max_retries;
            exporter_config.common.timeout_secs = config.timeout_secs;

            Ok(exporter_config)
        }

        fn build_arize_config(
            config: &vellaveto_config::observability::ArizeConfig,
        ) -> Result<vellaveto_audit::observability::arize::ArizeExporterConfig, ObservabilityError>
        {
            let mut exporter_config =
                vellaveto_audit::observability::arize::ArizeExporterConfig::from_env(
                    &config.endpoint,
                    &config.space_key_env,
                    &config.api_key_env,
                )?;

            exporter_config = exporter_config.with_model_id(&config.model_id);

            if let Some(version) = &config.model_version {
                exporter_config = exporter_config.with_model_version(version);
            }

            exporter_config.common.batch_size = config.batch_size;
            exporter_config.common.flush_interval_secs = config.flush_interval_secs;
            exporter_config.common.max_retries = config.max_retries;
            exporter_config.common.timeout_secs = config.timeout_secs;

            Ok(exporter_config)
        }

        fn build_helicone_config(
            config: &vellaveto_config::observability::HeliconeConfig,
        ) -> Result<
            vellaveto_audit::observability::helicone::HeliconeExporterConfig,
            ObservabilityError,
        > {
            let mut exporter_config =
                vellaveto_audit::observability::helicone::HeliconeExporterConfig::from_env(
                    &config.endpoint,
                    &config.api_key_env,
                )?;

            for (key, value) in &config.custom_properties {
                exporter_config = exporter_config.with_property(key, value);
            }

            exporter_config.common.batch_size = config.batch_size;
            exporter_config.common.flush_interval_secs = config.flush_interval_secs;
            exporter_config.common.max_retries = config.max_retries;
            exporter_config.common.timeout_secs = config.timeout_secs;

            Ok(exporter_config)
        }

        fn build_webhook_config(
            config: &vellaveto_config::observability::WebhookExporterConfig,
        ) -> Result<vellaveto_audit::observability::webhook::WebhookExporterConfig, ObservabilityError>
        {
            let mut exporter_config =
                vellaveto_audit::observability::webhook::WebhookExporterConfig::new(
                    &config.endpoint,
                );

            if let Some(auth_env) = &config.auth_header_env {
                if let Ok(auth_value) = std::env::var(auth_env) {
                    exporter_config = exporter_config.with_auth(auth_value);
                }
            }

            for (key, value) in &config.headers {
                exporter_config = exporter_config.with_header(key, value);
            }

            exporter_config.compress = config.compress;
            exporter_config.common.batch_size = config.batch_size;
            exporter_config.common.flush_interval_secs = config.flush_interval_secs;
            exporter_config.common.max_retries = config.max_retries;
            exporter_config.common.timeout_secs = config.timeout_secs;

            Ok(exporter_config)
        }
    }
}

// Re-export when feature is enabled
#[cfg(feature = "observability-exporters")]
pub use enabled::ObservabilityManager;

// ============================================================================
// Stub implementation when feature is disabled
// ============================================================================

#[cfg(not(feature = "observability-exporters"))]
pub struct ObservabilityManager {
    stats: Arc<ObservabilityStats>,
    exporter_info: Vec<ExporterInfo>,
    redaction: RedactionConfig,
}

#[cfg(not(feature = "observability-exporters"))]
impl ObservabilityManager {
    /// Create a disabled manager (feature not enabled).
    pub fn new(_config: &ObservabilityConfig) -> Result<Option<Self>, ObservabilityError> {
        if _config.enabled {
            warn!("Observability is enabled in config but observability-exporters feature is not compiled");
        }
        Ok(None)
    }

    /// Submit is a no-op when feature is disabled.
    pub fn submit(&self, _span: SecuritySpan) {}

    /// Get current statistics.
    pub fn stats(&self) -> ObservabilityStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get exporter information.
    pub fn exporters(&self) -> &[ExporterInfo] {
        &self.exporter_info
    }

    /// Get redaction config.
    pub fn redaction(&self) -> &RedactionConfig {
        &self.redaction
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_snapshot() {
        let stats = ObservabilityStats::default();
        stats.spans_submitted.store(100, Ordering::Relaxed);
        stats.spans_sampled.store(50, Ordering::Relaxed);
        stats.spans_dropped.store(50, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.spans_submitted, 100);
        assert_eq!(snapshot.spans_sampled, 50);
        assert_eq!(snapshot.spans_dropped, 50);
    }

    #[test]
    fn test_exporter_info() {
        let info = ExporterInfo {
            name: "langfuse".to_string(),
            enabled: true,
            healthy: true,
            batch_size: 100,
            flush_interval_secs: 5,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("langfuse"));
    }
}
