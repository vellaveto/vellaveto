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
            reason: format!("Signature verification failed: {}", reason),
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
