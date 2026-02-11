//! Sentinel MCP HTTP Proxy library.
//!
//! Re-exports proxy, session, and OAuth modules for use by both the binary
//! and integration tests.

pub mod oauth;
pub mod proxy;
pub mod session;

/// Metrics instrumentation for the HTTP proxy.
pub mod proxy_metrics {
    /// Record a DLP finding with pattern type.
    /// IMPROVEMENT_PLAN 1.1: DLP findings should be metered for observability.
    pub fn record_dlp_finding(pattern_type: &str) {
        metrics::counter!(
            "sentinel_dlp_findings_total",
            "pattern_type" => pattern_type.to_string()
        )
        .increment(1);
    }

    /// Record DLP scan latency in seconds.
    pub fn record_dlp_scan_latency(seconds: f64) {
        metrics::histogram!("sentinel_dlp_scan_duration_seconds").record(seconds);
    }

    /// Record a DPoP validation failure with a stable reason code.
    pub fn record_dpop_failure(reason: &str) {
        metrics::counter!(
            "sentinel_oauth_dpop_failures_total",
            "reason" => reason.to_string()
        )
        .increment(1);
    }

    /// Record that a DPoP replay (`jti` reuse) was detected.
    pub fn record_dpop_replay_detected() {
        metrics::counter!("sentinel_oauth_dpop_replay_total").increment(1);
    }
}
