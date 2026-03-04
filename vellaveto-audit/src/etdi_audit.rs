// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::logger::AuditLogger;
use crate::types::AuditError;
use vellaveto_types::{Action, Verdict};

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 8: ETDI Cryptographic Tool Security Audit Helpers
// ═══════════════════════════════════════════════════════════════════════════════

impl AuditLogger {
    /// Log a successful ETDI signature verification.
    pub async fn log_etdi_signature_verified(
        &self,
        tool: &str,
        signer: &str,
        trusted: bool,
    ) -> Result<(), AuditError> {
        let action = Action::new(
            "vellaveto",
            "etdi_signature_verified",
            serde_json::json!({
                "tool": tool,
                "signer": signer,
                "trusted": trusted,
            }),
        );
        let verdict = if trusted {
            Verdict::Allow
        } else {
            Verdict::Deny {
                reason: "Signer not in trusted list".to_string(),
            }
        };
        self.log_entry(
            &action,
            &verdict,
            serde_json::json!({
                "source": "etdi",
                "event": "signature_verified",
            }),
        )
        .await
    }

    /// Log a failed ETDI signature verification.
    pub async fn log_etdi_signature_failed(
        &self,
        tool: &str,
        reason: &str,
    ) -> Result<(), AuditError> {
        let action = Action::new(
            "vellaveto",
            "etdi_signature_verification",
            serde_json::json!({
                "tool": tool,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Signature verification failed: {reason}"),
        };
        self.log_entry(
            &action,
            &verdict,
            serde_json::json!({
                "source": "etdi",
                "event": "signature_failed",
                "failure_reason": reason,
            }),
        )
        .await
    }

    /// Log an unsigned tool detection (blocked or allowed based on config).
    pub async fn log_etdi_unsigned_tool(
        &self,
        tool: &str,
        blocked: bool,
    ) -> Result<(), AuditError> {
        let action = Action::new(
            "vellaveto",
            "etdi_unsigned_tool",
            serde_json::json!({
                "tool": tool,
            }),
        );
        let verdict = if blocked {
            Verdict::Deny {
                reason: "Tool has no ETDI signature".to_string(),
            }
        } else {
            Verdict::Allow
        };
        self.log_entry(
            &action,
            &verdict,
            serde_json::json!({
                "source": "etdi",
                "event": if blocked { "unsigned_tool_blocked" } else { "unsigned_tool_allowed" },
            }),
        )
        .await
    }

    /// Log a version drift detection.
    pub async fn log_etdi_version_drift(
        &self,
        alert: &vellaveto_types::VersionDriftAlert,
    ) -> Result<(), AuditError> {
        let action = Action::new(
            "vellaveto",
            "etdi_version_drift",
            serde_json::json!({
                "tool": alert.tool,
                "expected": alert.expected_version,
                "actual": alert.actual_version,
                "drift_type": alert.drift_type,
            }),
        );
        let verdict = if alert.blocking {
            Verdict::Deny {
                reason: format!(
                    "Version drift detected: expected {}, got {}",
                    alert.expected_version, alert.actual_version
                ),
            }
        } else {
            Verdict::Allow
        };
        self.log_entry(
            &action,
            &verdict,
            serde_json::json!({
                "source": "etdi",
                "event": "version_drift",
                "blocking": alert.blocking,
                "detected_at": alert.detected_at,
            }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_logger() -> (AuditLogger, TempDir) {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);
        (logger, tmp)
    }

    #[tokio::test]
    async fn test_log_etdi_signature_verified_trusted_allow() {
        let (logger, _tmp) = make_logger();
        logger
            .log_etdi_signature_verified("my_tool", "trusted_signer", true)
            .await
            .expect("sig verified");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.function, "etdi_signature_verified");
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert_eq!(entries[0].metadata["source"], "etdi");
        assert_eq!(entries[0].metadata["event"], "signature_verified");
    }

    #[tokio::test]
    async fn test_log_etdi_signature_verified_untrusted_deny() {
        let (logger, _tmp) = make_logger();
        logger
            .log_etdi_signature_verified("my_tool", "unknown_signer", false)
            .await
            .expect("sig verified");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = &entries[0].verdict {
            assert!(reason.contains("not in trusted list"));
        }
    }

    #[tokio::test]
    async fn test_log_etdi_signature_failed_produces_deny() {
        let (logger, _tmp) = make_logger();
        logger
            .log_etdi_signature_failed("evil_tool", "invalid signature bytes")
            .await
            .expect("sig failed");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.function, "etdi_signature_verification");
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = &entries[0].verdict {
            assert!(reason.contains("Signature verification failed"));
            assert!(reason.contains("invalid signature bytes"));
        }
        assert_eq!(entries[0].metadata["event"], "signature_failed");
        assert_eq!(
            entries[0].metadata["failure_reason"],
            "invalid signature bytes"
        );
    }

    #[tokio::test]
    async fn test_log_etdi_unsigned_tool_blocked_deny() {
        let (logger, _tmp) = make_logger();
        logger
            .log_etdi_unsigned_tool("unsigned_tool", true)
            .await
            .expect("unsigned blocked");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = &entries[0].verdict {
            assert!(reason.contains("no ETDI signature"));
        }
        assert_eq!(entries[0].metadata["event"], "unsigned_tool_blocked");
    }

    #[tokio::test]
    async fn test_log_etdi_unsigned_tool_allowed() {
        let (logger, _tmp) = make_logger();
        logger
            .log_etdi_unsigned_tool("legacy_tool", false)
            .await
            .expect("unsigned allowed");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Allow));
        assert_eq!(entries[0].metadata["event"], "unsigned_tool_allowed");
    }

    #[tokio::test]
    async fn test_log_etdi_version_drift_blocking_deny() {
        let (logger, _tmp) = make_logger();
        let alert = vellaveto_types::VersionDriftAlert {
            tool: "my_tool".to_string(),
            expected_version: "1.0.0".to_string(),
            actual_version: "2.0.0".to_string(),
            drift_type: "version_mismatch".to_string(),
            blocking: true,
            detected_at: "2026-03-01T00:00:00Z".to_string(),
        };
        logger
            .log_etdi_version_drift(&alert)
            .await
            .expect("version drift");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Deny { .. }));
        if let Verdict::Deny { reason } = &entries[0].verdict {
            assert!(reason.contains("expected 1.0.0"));
            assert!(reason.contains("got 2.0.0"));
        }
        assert_eq!(entries[0].metadata["event"], "version_drift");
        assert_eq!(entries[0].metadata["blocking"], true);
    }

    #[tokio::test]
    async fn test_log_etdi_version_drift_non_blocking_allow() {
        let (logger, _tmp) = make_logger();
        let alert = vellaveto_types::VersionDriftAlert {
            tool: "my_tool".to_string(),
            expected_version: "1.0.0".to_string(),
            actual_version: "1.0.1".to_string(),
            drift_type: "version_mismatch".to_string(),
            blocking: false,
            detected_at: "2026-03-01T00:00:00Z".to_string(),
        };
        logger
            .log_etdi_version_drift(&alert)
            .await
            .expect("version drift");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].verdict, Verdict::Allow));
    }

    #[tokio::test]
    async fn test_log_etdi_version_drift_records_action_params() {
        let (logger, _tmp) = make_logger();
        let alert = vellaveto_types::VersionDriftAlert {
            tool: "drifter".to_string(),
            expected_version: "abc123".to_string(),
            actual_version: "def456".to_string(),
            drift_type: "hash_mismatch".to_string(),
            blocking: false,
            detected_at: "2026-03-01T12:00:00Z".to_string(),
        };
        logger
            .log_etdi_version_drift(&alert)
            .await
            .expect("version drift");
        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries[0].action.function, "etdi_version_drift");
        // Parameters should contain the tool info (may be redacted but keys present)
        let params = &entries[0].action.parameters;
        assert!(params.get("tool").is_some());
        assert!(params.get("drift_type").is_some());
    }
}
