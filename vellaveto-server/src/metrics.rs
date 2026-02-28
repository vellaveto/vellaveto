// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Prometheus metrics integration for Vellaveto.
//!
//! Provides a `/metrics` endpoint exposing operational counters and gauges
//! in Prometheus text exposition format (text/plain; version=0.0.4).
//!
//! ## Core Metrics
//! - `vellaveto_evaluations_total` (counter, labels: verdict, tool, tenant_id)
//! - `vellaveto_evaluation_duration_seconds` (histogram)
//! - `vellaveto_policies_loaded` (gauge)
//! - `vellaveto_uptime_seconds` (gauge)
//!
//! ## Security Metrics
//! - `vellaveto_dlp_findings_total` (counter, labels: pattern_type)
//! - `vellaveto_injection_detections_total` (counter, labels: injection_type)
//! - `vellaveto_rug_pull_detections_total` (counter)
//! - `vellaveto_squatting_detections_total` (counter)
//! - `vellaveto_anomaly_detections_total` (counter)
//! - `vellaveto_forwarded_header_rejections_total` (counter, labels: header)
//!
//! ## Session & Auth Metrics
//! - `vellaveto_active_sessions` (gauge)
//! - `vellaveto_auth_failures_total` (counter, labels: reason)
//! - `vellaveto_rate_limit_rejections_total` (counter)
//!
//! ## Policy Metrics
//! - `vellaveto_policy_matches_total` (counter, labels: policy_id)
//! - `vellaveto_policy_compilation_errors_total` (counter)
//!
//! ## Audit Metrics
//! - `vellaveto_audit_entries_total` (counter)
//! - `vellaveto_audit_checkpoint_total` (counter)
//! - `vellaveto_audit_rotation_total` (counter)
//!
//! ## Network Metrics
//! - `vellaveto_dns_resolutions_total` (counter, labels: status)
//! - `vellaveto_dns_resolution_duration_seconds` (histogram)
//! - `vellaveto_blocked_ips_total` (counter)
//!
//! ## SIEM Export Metrics
//! - `vellaveto_siem_exports_total` (counter, labels: exporter, status)
//! - `vellaveto_siem_export_duration_seconds` (histogram, labels: exporter)
//! - `vellaveto_siem_export_batch_size` (histogram, labels: exporter)
//!
//! ## Cluster Metrics
//! - `vellaveto_cluster_backend_latency_seconds` (histogram, labels: operation)
//! - `vellaveto_opa_queries_total` (counter, labels: result)
//! - `vellaveto_opa_query_duration_seconds` (histogram)
//! - `vellaveto_opa_fail_closed_denials_total` (counter)

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
            register_metric_descriptions();
            tracing::info!("Prometheus metrics recorder installed with 25 metrics");
            Some(handle)
        }
        Err(e) => {
            tracing::warn!("Failed to install Prometheus metrics recorder: {}", e);
            None
        }
    }
}

/// Register all metric descriptions so they appear in /metrics output
/// even before the first observation.
fn register_metric_descriptions() {
    // Core metrics
    metrics::describe_counter!(
        "vellaveto_evaluations_total",
        "Total number of policy evaluations"
    );
    metrics::describe_histogram!(
        "vellaveto_evaluation_duration_seconds",
        "Policy evaluation latency in seconds"
    );
    metrics::describe_gauge!(
        "vellaveto_policies_loaded",
        "Number of policies currently loaded"
    );
    metrics::describe_gauge!("vellaveto_uptime_seconds", "Server uptime in seconds");

    // Security metrics
    metrics::describe_counter!(
        "vellaveto_dlp_findings_total",
        "Total number of DLP findings detected"
    );
    metrics::describe_counter!(
        "vellaveto_injection_detections_total",
        "Total number of injection attempts detected"
    );
    metrics::describe_counter!(
        "vellaveto_rug_pull_detections_total",
        "Total number of rug-pull attacks detected"
    );
    metrics::describe_counter!(
        "vellaveto_squatting_detections_total",
        "Total number of tool squatting attempts detected"
    );
    metrics::describe_counter!(
        "vellaveto_anomaly_detections_total",
        "Total number of behavioral anomalies detected"
    );
    metrics::describe_counter!(
        "vellaveto_forwarded_header_rejections_total",
        "Total number of untrusted forwarded headers ignored by security checks"
    );

    // Session & auth metrics
    metrics::describe_gauge!(
        "vellaveto_active_sessions",
        "Number of currently active sessions"
    );
    metrics::describe_counter!(
        "vellaveto_auth_failures_total",
        "Total number of authentication failures"
    );
    metrics::describe_counter!(
        "vellaveto_rate_limit_rejections_total",
        "Total number of requests rejected by rate limiting"
    );

    // Policy metrics
    metrics::describe_counter!(
        "vellaveto_policy_matches_total",
        "Total number of policy matches"
    );
    metrics::describe_counter!(
        "vellaveto_policy_compilation_errors_total",
        "Total number of policy compilation errors"
    );

    // Audit metrics
    metrics::describe_counter!(
        "vellaveto_audit_entries_total",
        "Total number of audit log entries written"
    );
    metrics::describe_counter!(
        "vellaveto_audit_checkpoint_total",
        "Total number of audit checkpoints created"
    );
    metrics::describe_counter!(
        "vellaveto_audit_rotation_total",
        "Total number of audit log rotations"
    );

    // Network metrics
    metrics::describe_counter!(
        "vellaveto_dns_resolutions_total",
        "Total number of DNS resolutions performed"
    );
    metrics::describe_histogram!(
        "vellaveto_dns_resolution_duration_seconds",
        "DNS resolution latency in seconds"
    );
    metrics::describe_counter!(
        "vellaveto_blocked_ips_total",
        "Total number of blocked IP addresses"
    );

    // SIEM export metrics
    metrics::describe_counter!(
        "vellaveto_siem_exports_total",
        "Total number of SIEM export operations"
    );
    metrics::describe_histogram!(
        "vellaveto_siem_export_duration_seconds",
        "SIEM export latency in seconds"
    );
    metrics::describe_histogram!(
        "vellaveto_siem_export_batch_size",
        "Number of entries per SIEM export batch"
    );

    // Cluster metrics
    metrics::describe_histogram!(
        "vellaveto_cluster_backend_latency_seconds",
        "Cluster backend operation latency in seconds"
    );

    // OPA runtime metrics
    metrics::describe_counter!(
        "vellaveto_opa_queries_total",
        "Total number of OPA runtime queries"
    );
    metrics::describe_histogram!(
        "vellaveto_opa_query_duration_seconds",
        "OPA query latency in seconds"
    );
    metrics::describe_counter!(
        "vellaveto_opa_fail_closed_denials_total",
        "Total number of requests denied due to OPA fail-closed behavior"
    );
}

/// Record an evaluation verdict in the Prometheus counter.
pub fn record_evaluation_verdict(verdict_label: &str) {
    metrics::counter!("vellaveto_evaluations_total", "verdict" => verdict_label.to_string())
        .increment(1);
}

/// Record evaluation duration in the Prometheus histogram.
pub fn record_evaluation_duration(duration_secs: f64) {
    metrics::histogram!("vellaveto_evaluation_duration_seconds").record(duration_secs);
}

/// Update the policies_loaded gauge.
pub fn set_policies_loaded(count: f64) {
    metrics::gauge!("vellaveto_policies_loaded").set(count);
}

/// Increment the audit entries counter.
pub fn increment_audit_entries() {
    metrics::counter!("vellaveto_audit_entries_total").increment(1);
}

/// Increment the DLP findings counter by the given count.
pub fn increment_dlp_findings(count: u64) {
    metrics::counter!("vellaveto_dlp_findings_total").increment(count);
}

/// Update the active sessions gauge.
pub fn set_active_sessions(count: f64) {
    metrics::gauge!("vellaveto_active_sessions").set(count);
}

/// Increment the rate-limit rejections counter.
pub fn increment_rate_limit_rejections() {
    metrics::counter!("vellaveto_rate_limit_rejections_total").increment(1);
}

/// Update the uptime gauge.
pub fn set_uptime_seconds(secs: f64) {
    metrics::gauge!("vellaveto_uptime_seconds").set(secs);
}

// ============================================================================
// Enhanced metrics helper functions (Phase 4)
// ============================================================================

/// Record an evaluation with tool and tenant context.
pub fn record_evaluation(verdict: &str, tool: &str, tenant_id: &str) {
    metrics::counter!(
        "vellaveto_evaluations_total",
        "verdict" => verdict.to_string(),
        "tool" => tool.to_string(),
        "tenant_id" => tenant_id.to_string()
    )
    .increment(1);
}

/// Record an injection detection.
pub fn record_injection_detection(injection_type: &str) {
    metrics::counter!(
        "vellaveto_injection_detections_total",
        "injection_type" => injection_type.to_string()
    )
    .increment(1);
}

/// Record an untrusted forwarded header rejection.
pub fn increment_forwarded_header_rejections(header: &str) {
    metrics::counter!(
        "vellaveto_forwarded_header_rejections_total",
        "header" => header.to_string()
    )
    .increment(1);
}

/// Record a rug-pull detection.
pub fn record_rug_pull_detection() {
    metrics::counter!("vellaveto_rug_pull_detections_total").increment(1);
}

/// Record a tool squatting detection.
pub fn record_squatting_detection() {
    metrics::counter!("vellaveto_squatting_detections_total").increment(1);
}

/// Record a behavioral anomaly detection.
pub fn record_anomaly_detection() {
    metrics::counter!("vellaveto_anomaly_detections_total").increment(1);
}

/// Record an authentication failure.
pub fn record_auth_failure(reason: &str) {
    metrics::counter!(
        "vellaveto_auth_failures_total",
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record a policy match.
pub fn record_policy_match(policy_id: &str) {
    metrics::counter!(
        "vellaveto_policy_matches_total",
        "policy_id" => policy_id.to_string()
    )
    .increment(1);
}

/// Record a policy compilation error.
pub fn record_policy_compilation_error() {
    metrics::counter!("vellaveto_policy_compilation_errors_total").increment(1);
}

/// Record an audit checkpoint creation.
pub fn record_audit_checkpoint() {
    metrics::counter!("vellaveto_audit_checkpoint_total").increment(1);
}

/// Record an audit log rotation.
pub fn record_audit_rotation() {
    metrics::counter!("vellaveto_audit_rotation_total").increment(1);
}

/// Record a DNS resolution result.
pub fn record_dns_resolution(status: &str, duration_secs: f64) {
    metrics::counter!(
        "vellaveto_dns_resolutions_total",
        "status" => status.to_string()
    )
    .increment(1);
    metrics::histogram!("vellaveto_dns_resolution_duration_seconds").record(duration_secs);
}

/// Record a blocked IP.
pub fn record_blocked_ip() {
    metrics::counter!("vellaveto_blocked_ips_total").increment(1);
}

/// Record a DLP finding with pattern type.
pub fn record_dlp_finding(pattern_type: &str) {
    metrics::counter!(
        "vellaveto_dlp_findings_total",
        "pattern_type" => pattern_type.to_string()
    )
    .increment(1);
}

/// Record a SIEM export operation.
pub fn record_siem_export(exporter: &str, status: &str, duration_secs: f64, batch_size: u64) {
    metrics::counter!(
        "vellaveto_siem_exports_total",
        "exporter" => exporter.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
    metrics::histogram!(
        "vellaveto_siem_export_duration_seconds",
        "exporter" => exporter.to_string()
    )
    .record(duration_secs);
    metrics::histogram!(
        "vellaveto_siem_export_batch_size",
        "exporter" => exporter.to_string()
    )
    .record(batch_size as f64);
}

/// Record a cluster backend operation latency.
pub fn record_cluster_backend_latency(operation: &str, duration_secs: f64) {
    metrics::histogram!(
        "vellaveto_cluster_backend_latency_seconds",
        "operation" => operation.to_string()
    )
    .record(duration_secs);
}

/// Record an OPA query result and latency.
pub fn record_opa_query(result: &str, duration_secs: f64) {
    metrics::counter!("vellaveto_opa_queries_total", "result" => result.to_string()).increment(1);
    metrics::histogram!("vellaveto_opa_query_duration_seconds").record(duration_secs);
}

/// Record a fail-closed denial due to OPA unavailability/error.
pub fn increment_opa_fail_closed_denial() {
    metrics::counter!("vellaveto_opa_fail_closed_denials_total").increment(1);
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

    // Phase 4: Enhanced metrics tests

    #[test]
    fn test_record_evaluation_with_labels_does_not_panic() {
        record_evaluation("allow", "file_read", "tenant-1");
        record_evaluation("deny", "shell_exec", "tenant-2");
    }

    #[test]
    fn test_record_injection_detection_does_not_panic() {
        record_injection_detection("sql");
        record_injection_detection("command");
        record_injection_detection("path_traversal");
    }

    #[test]
    fn test_record_rug_pull_detection_does_not_panic() {
        record_rug_pull_detection();
    }

    #[test]
    fn test_record_squatting_detection_does_not_panic() {
        record_squatting_detection();
    }

    #[test]
    fn test_record_anomaly_detection_does_not_panic() {
        record_anomaly_detection();
    }

    #[test]
    fn test_record_auth_failure_does_not_panic() {
        record_auth_failure("invalid_token");
        record_auth_failure("expired");
        record_auth_failure("wrong_scope");
    }

    #[test]
    fn test_record_policy_match_does_not_panic() {
        record_policy_match("policy-001");
        record_policy_match("default-deny");
    }

    #[test]
    fn test_record_policy_compilation_error_does_not_panic() {
        record_policy_compilation_error();
    }

    #[test]
    fn test_record_audit_checkpoint_does_not_panic() {
        record_audit_checkpoint();
    }

    #[test]
    fn test_record_audit_rotation_does_not_panic() {
        record_audit_rotation();
    }

    #[test]
    fn test_record_dns_resolution_does_not_panic() {
        record_dns_resolution("success", 0.015);
        record_dns_resolution("failure", 5.0);
        record_dns_resolution("timeout", 30.0);
    }

    #[test]
    fn test_record_blocked_ip_does_not_panic() {
        record_blocked_ip();
    }

    #[test]
    fn test_record_dlp_finding_does_not_panic() {
        record_dlp_finding("credit_card");
        record_dlp_finding("ssn");
        record_dlp_finding("api_key");
    }

    #[test]
    fn test_record_siem_export_does_not_panic() {
        record_siem_export("splunk", "success", 0.5, 100);
        record_siem_export("datadog", "failure", 5.0, 50);
        record_siem_export("elasticsearch", "success", 0.2, 200);
    }

    #[test]
    fn test_record_cluster_backend_latency_does_not_panic() {
        record_cluster_backend_latency("get_approval", 0.01);
        record_cluster_backend_latency("set_approval", 0.02);
        record_cluster_backend_latency("sync", 0.5);
    }

    #[test]
    fn test_record_opa_query_does_not_panic() {
        record_opa_query("allow", 0.01);
        record_opa_query("deny", 0.02);
        record_opa_query("error", 0.5);
        record_opa_query("timeout", 1.0);
    }

    #[test]
    fn test_increment_opa_fail_closed_denial_does_not_panic() {
        increment_opa_fail_closed_denial();
    }
}
