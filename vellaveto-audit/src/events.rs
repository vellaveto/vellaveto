use crate::logger::AuditLogger;
use crate::types::AuditError;
use vellaveto_types::{Action, Verdict};

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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
        if let serde_json::Value::Object(ref mut map) = metadata {
            if let serde_json::Value::Object(d) = details {
                for (k, v) in d {
                    map.insert(k, v);
                }
            }
        }
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
}
