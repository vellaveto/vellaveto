//! Prometheus metrics integration for Sentinel.
//!
//! Provides a `/metrics` endpoint exposing operational counters and gauges
//! in Prometheus text exposition format (text/plain; version=0.0.4).
//!
//! Metrics registered:
//! - `sentinel_evaluations_total` (counter, labels: verdict)
//! - `sentinel_evaluation_duration_seconds` (histogram)
//! - `sentinel_policies_loaded` (gauge)
//! - `sentinel_dlp_findings_total` (counter)
//! - `sentinel_audit_entries_total` (counter)
//! - `sentinel_active_sessions` (gauge)
//! - `sentinel_uptime_seconds` (gauge)
//! - `sentinel_rate_limit_rejections_total` (counter)

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Initialize the Prometheus metrics recorder and return a handle for rendering.
///
/// This installs a global metrics recorder. It should be called exactly once
/// at startup. Returns `None` if the recorder cannot be installed (e.g., if
/// another recorder is already installed, which happens in tests).
pub fn init_prometheus() -> Option<PrometheusHandle> {
    let builder = PrometheusBuilder::new();
    match builder.install_recorder() {
        Ok(handle) => {
            // Register metric descriptions so they appear in /metrics output
            // even before the first observation.
            metrics::describe_counter!(
                "sentinel_evaluations_total",
                "Total number of policy evaluations"
            );
            metrics::describe_histogram!(
                "sentinel_evaluation_duration_seconds",
                "Policy evaluation latency in seconds"
            );
            metrics::describe_gauge!(
                "sentinel_policies_loaded",
                "Number of policies currently loaded"
            );
            metrics::describe_counter!(
                "sentinel_dlp_findings_total",
                "Total number of DLP findings detected"
            );
            metrics::describe_counter!(
                "sentinel_audit_entries_total",
                "Total number of audit log entries written"
            );
            metrics::describe_gauge!(
                "sentinel_active_sessions",
                "Number of currently active sessions"
            );
            metrics::describe_gauge!("sentinel_uptime_seconds", "Server uptime in seconds");
            metrics::describe_counter!(
                "sentinel_rate_limit_rejections_total",
                "Total number of requests rejected by rate limiting"
            );

            tracing::info!("Prometheus metrics recorder installed");
            Some(handle)
        }
        Err(e) => {
            tracing::warn!("Failed to install Prometheus metrics recorder: {}", e);
            None
        }
    }
}

/// Record an evaluation verdict in the Prometheus counter.
pub fn record_evaluation_verdict(verdict_label: &str) {
    metrics::counter!("sentinel_evaluations_total", "verdict" => verdict_label.to_string())
        .increment(1);
}

/// Record evaluation duration in the Prometheus histogram.
pub fn record_evaluation_duration(duration_secs: f64) {
    metrics::histogram!("sentinel_evaluation_duration_seconds").record(duration_secs);
}

/// Update the policies_loaded gauge.
pub fn set_policies_loaded(count: f64) {
    metrics::gauge!("sentinel_policies_loaded").set(count);
}

/// Increment the audit entries counter.
pub fn increment_audit_entries() {
    metrics::counter!("sentinel_audit_entries_total").increment(1);
}

/// Increment the DLP findings counter by the given count.
pub fn increment_dlp_findings(count: u64) {
    metrics::counter!("sentinel_dlp_findings_total").increment(count);
}

/// Update the active sessions gauge.
pub fn set_active_sessions(count: f64) {
    metrics::gauge!("sentinel_active_sessions").set(count);
}

/// Increment the rate-limit rejections counter.
pub fn increment_rate_limit_rejections() {
    metrics::counter!("sentinel_rate_limit_rejections_total").increment(1);
}

/// Update the uptime gauge.
pub fn set_uptime_seconds(secs: f64) {
    metrics::gauge!("sentinel_uptime_seconds").set(secs);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: We cannot test init_prometheus() in unit tests because the global
    // recorder can only be set once per process, and test ordering is
    // non-deterministic. Instead, we test the helper functions which are
    // safe to call even without a recorder installed (metrics crate uses a
    // no-op recorder by default).

    #[test]
    fn test_record_evaluation_verdict_does_not_panic() {
        // Should not panic even without a recorder installed
        record_evaluation_verdict("allow");
        record_evaluation_verdict("deny");
        record_evaluation_verdict("require_approval");
        record_evaluation_verdict("error");
    }

    #[test]
    fn test_record_evaluation_duration_does_not_panic() {
        record_evaluation_duration(0.001);
        record_evaluation_duration(0.0);
        record_evaluation_duration(5.0);
    }

    #[test]
    fn test_set_policies_loaded_does_not_panic() {
        set_policies_loaded(0.0);
        set_policies_loaded(42.0);
    }

    #[test]
    fn test_increment_audit_entries_does_not_panic() {
        increment_audit_entries();
    }

    #[test]
    fn test_set_uptime_seconds_does_not_panic() {
        set_uptime_seconds(0.0);
        set_uptime_seconds(3600.0);
    }

    #[test]
    fn test_increment_dlp_findings_does_not_panic() {
        increment_dlp_findings(0);
        increment_dlp_findings(3);
    }

    #[test]
    fn test_set_active_sessions_does_not_panic() {
        set_active_sessions(0.0);
        set_active_sessions(10.0);
    }

    #[test]
    fn test_increment_rate_limit_rejections_does_not_panic() {
        increment_rate_limit_rejections();
    }
}
