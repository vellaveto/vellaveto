// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::logger::AuditLogger;
use crate::types::AuditError;
use vellaveto_types::{Action, Verdict};

/// Reserved metadata keys that must not be overwritten by user-supplied details.
/// SECURITY (FIND-R46-007): Prevents callers from injecting fake event_type,
/// timestamp, sequence, or hash values into audit metadata.
const RESERVED_METADATA_KEYS: &[&str] = &[
    "event",
    "event_type",
    "timestamp",
    "sequence",
    "hash",
    "entry_hash",
    "prev_hash",
    "id",
    "entry_id",
    "signature",
    "merkle_root",
    "chain_head_hash",
];

/// Merge `details` into `metadata`, skipping any reserved keys.
/// SECURITY (FIND-R46-007): Prevents details from overwriting reserved metadata keys.
fn merge_details_safe(metadata: &mut serde_json::Value, details: serde_json::Value) {
    if let serde_json::Value::Object(ref mut map) = metadata {
        if let serde_json::Value::Object(d) = details {
            for (k, v) in d {
                if RESERVED_METADATA_KEYS.contains(&k.as_str()) {
                    tracing::warn!(
                        key = %k,
                        "Rejected attempt to overwrite reserved metadata key in event details"
                    );
                    continue;
                }
                map.insert(k, v);
            }
        }
    }
}

impl AuditLogger {
    // ═══════════════════════════════════════════════════
    // HEARTBEAT ENTRIES (Phase 10.6)
    // ═══════════════════════════════════════════════════

    /// Write a heartbeat entry to the audit log.
    ///
    /// Heartbeat entries are lightweight vellaveto entries that maintain hash chain
    /// continuity. When the audit log has gaps in timestamps exceeding an expected
    /// heartbeat interval, it indicates potential truncation or tampering.
    ///
    /// The entry uses `tool: "vellaveto"`, `function: "heartbeat"` with an `Allow`
    /// verdict and metadata recording the heartbeat interval and sequence number.
    pub async fn log_heartbeat(&self, interval_secs: u64, sequence: u64) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "heartbeat", serde_json::json!({}));
        let verdict = Verdict::Allow;
        let metadata = serde_json::json!({
            "event": "heartbeat",
            "interval_secs": interval_secs,
            "sequence": sequence,
        });
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // Security Event Logging Helpers (Phase 3.1 - Runtime Integration)
    // =========================================================================

    /// Log a circuit breaker state change event.
    ///
    /// Circuit breaker events track when tools transition between open/closed/half-open
    /// states, helping detect cascading failures and service degradation.
    pub async fn log_circuit_breaker_event(
        &self,
        event_type: &str,
        tool: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "circuit_breaker", serde_json::json!({}));
        let verdict = if event_type == "rejected" {
            Verdict::Deny {
                reason: format!("Circuit breaker open for tool: {}", tool),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("circuit_breaker.{}", event_type),
            "tool": tool,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a deputy validation event.
    ///
    /// Deputy events track delegation registration, validation failures, and
    /// depth limit violations for confused deputy attack prevention.
    pub async fn log_deputy_event(
        &self,
        event_type: &str,
        session: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "deputy", serde_json::json!({}));
        let verdict = if event_type == "validation_failed" || event_type == "depth_exceeded" {
            Verdict::Deny {
                reason: format!("Deputy validation failed for session: {}", session),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("deputy.{}", event_type),
            "session": session,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a shadow agent detection event.
    ///
    /// Shadow agent events track agent registration, impersonation detection,
    /// and trust level changes.
    pub async fn log_shadow_agent_event(
        &self,
        event_type: &str,
        agent_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "shadow_agent", serde_json::json!({}));
        let verdict = if event_type == "detected" {
            Verdict::Deny {
                reason: format!("Shadow agent detected impersonating: {}", agent_id),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("shadow_agent.{}", event_type),
            "agent_id": agent_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a schema poisoning event.
    ///
    /// Schema events track mutation detection, poisoning alerts, and trust resets
    /// for tool schema integrity monitoring.
    pub async fn log_schema_event(
        &self,
        event_type: &str,
        tool: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "schema", serde_json::json!({}));
        let verdict = if event_type == "poisoning_alert" {
            Verdict::Deny {
                reason: format!("Schema poisoning detected for tool: {}", tool),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("schema.{}", event_type),
            "tool": tool,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a task lifecycle event.
    ///
    /// Task events track async MCP task creation, status changes, cancellation,
    /// expiration, and session limit violations.
    pub async fn log_task_event(
        &self,
        event_type: &str,
        task_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "task", serde_json::json!({}));
        let verdict = if event_type == "limit_exceeded" {
            Verdict::Deny {
                reason: format!("Task limit exceeded for task: {}", task_id),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("task.{}", event_type),
            "task_id": task_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a task lifecycle state transition event.
    ///
    /// Records MCP 2025-11-25 task state transitions for audit visibility.
    /// Unlike `log_task_event` which covers enforcement events (limit exceeded),
    /// this helper covers the full lifecycle: creation, status transitions,
    /// and terminal states.
    ///
    /// Event types:
    /// - `created` -- task registered via `tasks/create`
    /// - `working` -- task transitioned to running/working state
    /// - `input_required` -- task requires additional input from the client
    /// - `completed` -- task completed successfully
    /// - `failed` -- task execution failed
    /// - `cancelled` -- task cancelled by agent or system
    pub async fn log_task_lifecycle_event(
        &self,
        event_type: &str,
        task_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "task_lifecycle", serde_json::json!({}));
        let verdict = match event_type {
            "failed" | "cancelled" => Verdict::Deny {
                reason: format!("Task {} for task: {}", event_type, task_id),
            },
            _ => Verdict::Allow,
        };
        let mut metadata = serde_json::json!({
            "event": format!("task_lifecycle.{}", event_type),
            "task_id": task_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log an authentication level event.
    ///
    /// Auth events track step-up authentication requirements, level upgrades,
    /// and level expirations.
    pub async fn log_auth_event(
        &self,
        event_type: &str,
        session: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "auth", serde_json::json!({}));
        let verdict = if event_type == "step_up_required" {
            Verdict::Deny {
                reason: format!("Step-up authentication required for session: {}", session),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("auth.{}", event_type),
            "session": session,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a sampling detection event.
    ///
    /// Sampling events track rate limit violations, prompt length violations,
    /// sensitive content detection, and model denials.
    pub async fn log_sampling_event(
        &self,
        event_type: &str,
        session: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "sampling", serde_json::json!({}));
        let verdict = Verdict::Deny {
            reason: format!("Sampling request denied for session: {}", session),
        };
        let mut metadata = serde_json::json!({
            "event": format!("sampling.{}", event_type),
            "session": session,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // Governance Event Logging Helpers (Phase 26)
    // =========================================================================

    /// Log a shadow AI discovery event.
    ///
    /// Shadow AI events track detection of unregistered agents, unapproved tools,
    /// and unknown MCP servers in the traffic flow.
    ///
    /// Event types:
    /// - `shadow_ai.unregistered_agent` — new agent observed outside registration list
    /// - `shadow_ai.unapproved_tool` — tool used that is not in approved list
    /// - `shadow_ai.unknown_server` — MCP server observed that is not in known list
    pub async fn log_shadow_ai_discovery_event(
        &self,
        event_type: &str,
        entity_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "shadow_ai_discovery", serde_json::json!({}));
        let verdict = Verdict::Deny {
            reason: format!(
                "Shadow AI discovery: {} for entity '{}'",
                event_type, entity_id
            ),
        };
        let mut metadata = serde_json::json!({
            "event": format!("shadow_ai.{}", event_type),
            "entity_id": entity_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a least agency enforcement event.
    ///
    /// Least agency events track permission usage reports and auto-revocation
    /// actions for governance visibility.
    ///
    /// Event types:
    /// - `least_agency.report` — periodic usage ratio report
    /// - `least_agency.auto_revoke` — permission auto-revoked due to inactivity
    pub async fn log_least_agency_event(
        &self,
        event_type: &str,
        agent_id: &str,
        session_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "least_agency", serde_json::json!({}));
        let verdict = if event_type == "auto_revoke" {
            Verdict::Deny {
                reason: format!(
                    "Least agency auto-revoke for agent '{}' session '{}'",
                    agent_id, session_id
                ),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("least_agency.{}", event_type),
            "agent_id": agent_id,
            "session_id": session_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // Deployment Event Logging Helpers (Phase 27)
    // =========================================================================

    /// Log a leader election lifecycle event.
    ///
    /// Leader election events track acquisition, renewal, release, and failure
    /// of the leader lease for cluster coordination visibility.
    ///
    /// Event types:
    /// - `leader_election.acquired` — instance became the leader
    /// - `leader_election.renewed` — lease successfully renewed
    /// - `leader_election.released` — leader voluntarily released the lease
    /// - `leader_election.lost` — lease lost (expired or backend unreachable)
    /// - `leader_election.failed` — acquisition or renewal failed
    pub async fn log_leader_election_event(
        &self,
        event_type: &str,
        instance_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "leader_election", serde_json::json!({}));
        let verdict = if event_type == "lost" || event_type == "failed" {
            Verdict::Deny {
                reason: format!(
                    "Leader election {} for instance '{}'",
                    event_type, instance_id
                ),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("leader_election.{}", event_type),
            "instance_id": instance_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a service discovery lifecycle event.
    ///
    /// Service discovery events track endpoint additions, removals, and
    /// refresh failures for operational visibility.
    ///
    /// Event types:
    /// - `service_discovery.endpoint_added` — new endpoint discovered
    /// - `service_discovery.endpoint_removed` — endpoint no longer resolved
    /// - `service_discovery.endpoint_updated` — endpoint health or metadata changed
    /// - `service_discovery.refresh_failed` — periodic refresh encountered an error
    pub async fn log_service_discovery_event(
        &self,
        event_type: &str,
        endpoint_id: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "service_discovery", serde_json::json!({}));
        let verdict = if event_type == "refresh_failed" {
            Verdict::Deny {
                reason: format!(
                    "Service discovery refresh failed for endpoint '{}'",
                    endpoint_id
                ),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("service_discovery.{}", event_type),
            "endpoint_id": endpoint_id,
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // Projector Event Logging Helpers (Phase 35.3)
    // =========================================================================

    /// Log a projector event.
    ///
    /// Projector events track schema transformations, model family lookups,
    /// and registry operations for observability.
    ///
    /// Event types:
    /// - `projector.transform` — schema projected to a model-specific format
    /// - `projector.models_listed` — model family list requested
    /// - `projector.error` — projection or registry error occurred
    pub async fn log_projector_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "projector", serde_json::json!({}));
        let verdict = if event_type == "error" {
            Verdict::Deny {
                reason: "Projector operation failed".to_string(),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("projector.{}", event_type),
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // ZK Audit Event Logging Helpers (Phase 37)
    // =========================================================================

    /// Log a zero-knowledge audit event.
    ///
    /// ZK audit events track commitment creation, batch proving, and proof
    /// verification for zero-knowledge audit trail observability.
    ///
    /// Event types:
    /// - `zk_audit.commitment_created` — Pedersen commitment computed for an entry
    /// - `zk_audit.batch_proved` — batch Groth16 proof generated
    /// - `zk_audit.proof_verified` — batch proof verification completed
    /// - `zk_audit.scheduler_started` — background batch scheduler started
    /// - `zk_audit.scheduler_stopped` — background batch scheduler stopped
    /// - `zk_audit.error` — ZK operation error occurred
    pub async fn log_zk_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "zk_audit", serde_json::json!({}));
        let verdict = if event_type == "error" {
            Verdict::Deny {
                reason: "ZK audit operation failed".to_string(),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("zk_audit.{}", event_type),
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    // =========================================================================
    // Access Review Event Logging Helpers (Phase 38)
    // =========================================================================

    /// Log an access review lifecycle event.
    ///
    /// Access review events track report generation, scheduling, export,
    /// and errors for SOC 2 Type II compliance audit trail visibility.
    ///
    /// Event types:
    /// - `access_review.generated` — report generated (manual or scheduled)
    /// - `access_review.scheduled` — scheduled report generation triggered
    /// - `access_review.exported` — report exported in a specific format
    /// - `access_review.error` — report generation or export error
    pub async fn log_access_review_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "access_review", serde_json::json!({}));
        let verdict = if event_type == "error" {
            Verdict::Deny {
                reason: "Access review operation failed".to_string(),
            }
        } else {
            Verdict::Allow
        };
        let mut metadata = serde_json::json!({
            "event": format!("access_review.{}", event_type),
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Check whether the audit log has a heartbeat gap — a period longer than
    /// `max_gap_secs` between consecutive entries (heartbeat or otherwise).
    ///
    /// Returns the first detected gap as `(gap_start_timestamp, gap_end_timestamp, gap_seconds)`
    /// or `None` if the log has no gaps exceeding the threshold.
    pub async fn detect_heartbeat_gap(
        &self,
        max_gap_secs: u64,
    ) -> Result<Option<(String, String, u64)>, AuditError> {
        let entries = self.load_entries().await?;
        if entries.len() < 2 {
            return Ok(None);
        }

        for window in entries.windows(2) {
            let prev_ts = chrono::DateTime::parse_from_rfc3339(&window[0].timestamp).ok();
            let curr_ts = chrono::DateTime::parse_from_rfc3339(&window[1].timestamp).ok();

            if let (Some(prev), Some(curr)) = (prev_ts, curr_ts) {
                let gap = (curr - prev).num_seconds().unsigned_abs();
                if gap > max_gap_secs {
                    return Ok(Some((
                        window[0].timestamp.clone(),
                        window[1].timestamp.clone(),
                        gap,
                    )));
                }
            }
        }

        Ok(None)
    }

    // =========================================================================
    // Tool Discovery Event Logging Helpers (Phase 34)
    // =========================================================================

    // =========================================================================
    // Federation Event Logging Helpers (Phase 39)
    // =========================================================================

    /// Log a federation identity event.
    ///
    /// Records federation-related events including identity validation,
    /// JWKS cache operations, and validation failures.
    ///
    /// Event types:
    /// - `identity_validated` — successful federated identity resolution
    /// - `validation_failed` — JWT validation failed for matched anchor
    /// - `jwks_refreshed` — JWKS cache refreshed for an anchor
    /// - `jwks_fetch_failed` — JWKS endpoint unreachable
    /// - `token_expired` — federated token expired
    /// - `anchor_removed` — trust anchor removed from configuration
    pub async fn log_federation_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "federation", serde_json::json!({}));
        // SECURITY (FIND-R56-AUDIT-005): Federation failure events must use Deny
        // verdict so they are flagged in audit trails and compliance reports.
        let verdict = match event_type {
            "validation_failed" | "jwks_fetch_failed" | "token_expired" | "anchor_removed" => {
                Verdict::Deny {
                    reason: format!("Federation event: {}", event_type),
                }
            }
            _ => Verdict::Allow,
        };
        let mut metadata = serde_json::json!({
            "event": format!("federation.{}", event_type),
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }

    /// Log a tool discovery query event.
    ///
    /// Records when an agent performs a discovery search, including the query,
    /// number of results returned, and any policy-filtered tools.
    pub async fn log_discovery_event(
        &self,
        event_type: &str,
        details: serde_json::Value,
    ) -> Result<(), AuditError> {
        let action = Action::new("vellaveto", "discovery", serde_json::json!({}));
        let verdict = Verdict::Allow;
        let mut metadata = serde_json::json!({
            "event": format!("discovery.{}", event_type),
        });
        merge_details_safe(&mut metadata, details);
        self.log_entry(&action, &verdict, metadata).await
    }
}
