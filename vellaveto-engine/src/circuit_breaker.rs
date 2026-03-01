// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Circuit breaker for cascading failure protection (OWASP ASI08).
//!
//! Implements the circuit breaker pattern to prevent cascading failures when
//! tools become unreliable. When a tool fails repeatedly, requests are blocked
//! until the tool recovers.
//!
//! # Circuit States
//!
//! - **Closed**: Normal operation, requests are allowed
//! - **Open**: Tool is failing, requests are blocked
//! - **HalfOpen**: Testing recovery, limited requests allowed
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
//!
//! let manager = CircuitBreakerManager::new(5, 3, 30);
//!
//! // Check before calling tool
//! if let Err(reason) = manager.can_proceed("my_tool") {
//!     println!("Circuit open: {}", reason);
//!     return;
//! }
//!
//! // Call the tool...
//!
//! // Record result
//! if success {
//!     manager.record_success("my_tool");
//! } else {
//!     manager.record_failure("my_tool");
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use vellaveto_types::{CircuitState, CircuitStats};

/// Maximum number of tracked circuits to bound memory (FIND-R44-032).
/// Beyond this limit, new tools are treated as Open (fail-closed).
const MAX_TRACKED_CIRCUITS: usize = 10_000;

/// Manages circuit breakers for tool calls.
///
/// Thread-safe via `RwLock` for concurrent access.
#[derive(Debug)]
pub struct CircuitBreakerManager {
    /// Circuit states by tool name.
    circuits: RwLock<HashMap<String, CircuitStats>>,

    /// Number of failures before opening the circuit.
    failure_threshold: u32,

    /// Number of successes in half-open state to close the circuit.
    success_threshold: u32,

    /// Duration in seconds the circuit stays open before half-open.
    open_duration_secs: u64,

    /// Maximum requests allowed in half-open state.
    half_open_max_requests: u32,
}

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager.
    ///
    /// # Arguments
    /// * `failure_threshold` - Number of consecutive failures before opening
    /// * `success_threshold` - Number of consecutive successes to close
    /// * `open_duration_secs` - Seconds before transitioning to half-open
    pub fn new(failure_threshold: u32, success_threshold: u32, open_duration_secs: u64) -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            failure_threshold,
            success_threshold,
            open_duration_secs,
            half_open_max_requests: 1,
        }
    }

    /// Create with full configuration.
    pub fn with_config(
        failure_threshold: u32,
        success_threshold: u32,
        open_duration_secs: u64,
        half_open_max_requests: u32,
    ) -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            failure_threshold,
            success_threshold,
            open_duration_secs,
            half_open_max_requests,
        }
    }

    /// Create a shareable reference to this manager.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Get the current timestamp as Unix seconds.
    ///
    /// SECURITY: Returns Result to enable fail-closed behavior when system time
    /// is unavailable. Callers should deny requests when this returns Err.
    fn now() -> Result<u64, String> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| format!("System time error (fail-closed): {e}"))
    }

    /// Fallback timestamp for non-critical paths where we can't propagate errors.
    /// Uses 0 as a safe default that keeps circuits in their current state.
    fn now_or_zero() -> u64 {
        Self::now().unwrap_or_else(|e| {
            tracing::error!("CRITICAL: {e}");
            0
        })
    }

    /// Compute effective open duration with exponential backoff.
    ///
    /// Each HalfOpen→Open transition (trip) doubles the duration, capped at 32x.
    /// Resets to base duration when circuit fully recovers (HalfOpen→Closed).
    fn effective_open_duration(&self, stats: &CircuitStats) -> u64 {
        let multiplier = 1u64 << stats.trip_count.min(5); // 2^trip_count, max 32x
        self.open_duration_secs.saturating_mul(multiplier)
    }

    /// Check if a request can proceed for the given tool.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
    ///
    /// SECURITY: This method is fail-closed. If the RwLock is poisoned or
    /// system time is unavailable, requests are denied to prevent cascading
    /// failures from bypassing circuit breaker protection.
    ///
    /// # Metrics (GAP-011)
    ///
    /// - `vellaveto_circuit_breaker_check_duration_seconds`: Histogram of check latency
    /// - `vellaveto_circuit_breaker_rejections_total`: Counter of rejected requests
    pub fn can_proceed(&self, tool: &str) -> Result<(), String> {
        let start = std::time::Instant::now();
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name to prevent
        // case-variation and homoglyph (Cyrillic/fullwidth) bypass.
        let tool_lower = crate::normalize::normalize_full(tool);

        // SECURITY: Fail-closed on RwLock poisoning instead of recovering stale state.
        let circuits = self.circuits.read().map_err(|_| {
            tracing::error!(
                "CRITICAL: Circuit breaker RwLock poisoned — failing closed for tool '{tool}'"
            );
            let reason = format!(
                "Circuit breaker unavailable for tool '{tool}' (internal error — failing closed)"
            );
            // GAP-011: Record rejection metric
            metrics::counter!(
                "vellaveto_circuit_breaker_rejections_total",
                "tool" => tool_lower.clone(),
                "reason" => "rwlock_poisoned"
            )
            .increment(1);
            reason
        })?;

        let stats = match circuits.get(&tool_lower) {
            Some(s) => s,
            None => {
                // GAP-011: Record successful check latency
                metrics::histogram!("vellaveto_circuit_breaker_check_duration_seconds")
                    .record(start.elapsed().as_secs_f64());
                return Ok(()); // No circuit = closed
            }
        };

        let result = match stats.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if it's time to transition to half-open
                // SECURITY: Fail-closed on system time error.
                let now = Self::now()?;
                let eff_duration = self.effective_open_duration(stats);
                if now >= stats.last_state_change + eff_duration {
                    // SECURITY (FIND-078): Upgrade to write lock and transition to HalfOpen.
                    // Double-check locking prevents TOCTOU: re-verify state after acquiring write lock.
                    drop(circuits);
                    let mut circuits_w = self.circuits.write().map_err(|_| {
                        format!("Circuit breaker unavailable for tool '{tool}' (internal error — failing closed)")
                    })?;
                    if let Some(stats_w) = circuits_w.get_mut(&tool_lower) {
                        if stats_w.state == CircuitState::Open {
                            let now = Self::now()?;
                            let eff_duration = self.effective_open_duration(stats_w);
                            if now >= stats_w.last_state_change + eff_duration {
                                stats_w.state = CircuitState::HalfOpen;
                                stats_w.success_count = 0;
                                stats_w.last_state_change = now;
                                metrics::counter!(
                                    "vellaveto_circuit_breaker_state_changes_total",
                                    "from_state" => "open",
                                    "to_state" => "half_open"
                                )
                                .increment(1);
                                tracing::info!(
                                    tool = %tool,
                                    "Circuit breaker transitioning to half-open in can_proceed"
                                );
                            }
                        }
                        // Now check HalfOpen limit
                        if stats_w.state == CircuitState::HalfOpen {
                            if stats_w.success_count < self.half_open_max_requests {
                                metrics::histogram!(
                                    "vellaveto_circuit_breaker_check_duration_seconds"
                                )
                                .record(start.elapsed().as_secs_f64());
                                return Ok(());
                            } else {
                                let reason = format!(
                                    "Circuit breaker half-open for tool '{tool}' (testing recovery)"
                                );
                                metrics::counter!(
                                    "vellaveto_circuit_breaker_rejections_total",
                                    "tool" => tool_lower,
                                    "reason" => "half_open_limit"
                                )
                                .increment(1);
                                metrics::histogram!(
                                    "vellaveto_circuit_breaker_check_duration_seconds"
                                )
                                .record(start.elapsed().as_secs_f64());
                                return Err(reason);
                            }
                        }
                    }
                    // No entry found after write lock (race: removed between locks) — allow
                    metrics::histogram!("vellaveto_circuit_breaker_check_duration_seconds")
                        .record(start.elapsed().as_secs_f64());
                    return Ok(());
                } else {
                    // R230-ENG-4: Log internal details only; don't expose counts/timing to clients
                    let opens_in = (stats.last_state_change + eff_duration).saturating_sub(now);
                    tracing::debug!(tool = %tool, failures = stats.failure_count, opens_in_secs = opens_in, "Circuit breaker open (internal)");
                    let reason = format!("Circuit breaker open for tool '{tool}'");
                    // GAP-011: Record rejection metric
                    metrics::counter!(
                        "vellaveto_circuit_breaker_rejections_total",
                        "tool" => tool_lower,
                        "reason" => "circuit_open"
                    )
                    .increment(1);
                    Err(reason)
                }
            }
            CircuitState::HalfOpen => {
                // In half-open, allow limited requests
                if stats.success_count < self.half_open_max_requests {
                    Ok(())
                } else {
                    let reason =
                        format!("Circuit breaker half-open for tool '{tool}' (testing recovery)");
                    // GAP-011: Record rejection metric
                    metrics::counter!(
                        "vellaveto_circuit_breaker_rejections_total",
                        "tool" => tool_lower,
                        "reason" => "half_open_limit"
                    )
                    .increment(1);
                    Err(reason)
                }
            }
        };

        // GAP-011: Record check latency
        metrics::histogram!("vellaveto_circuit_breaker_check_duration_seconds")
            .record(start.elapsed().as_secs_f64());

        result
    }

    /// Record a successful call.
    ///
    /// Note: If RwLock is poisoned, logs a critical error but does not panic.
    /// This is acceptable because record_success is not on the security-critical
    /// path (can_proceed is). However, persistent poisoning will be visible in logs.
    ///
    /// FIND-R44-032: If the circuit map is at capacity and this is a new tool,
    /// the insert is skipped silently.
    pub fn record_success(&self, tool: &str) {
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name to prevent
        // case-variation and homoglyph (Cyrillic/fullwidth) bypass.
        let tool_lower = crate::normalize::normalize_full(tool);
        let mut circuits = match self.circuits.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in record_success for '{}': {}",
                    tool,
                    e
                );
                return;
            }
        };

        // FIND-R44-032: Bound circuit map size to prevent memory exhaustion.
        if circuits.len() >= MAX_TRACKED_CIRCUITS && !circuits.contains_key(&tool_lower) {
            tracing::warn!(
                tool = %tool,
                max = MAX_TRACKED_CIRCUITS,
                "Circuit breaker map at capacity — skipping record_success for new tool"
            );
            return;
        }

        let now = Self::now_or_zero();

        let stats = circuits.entry(tool_lower).or_insert_with(|| CircuitStats {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_state_change: now,
            trip_count: 0,
        });

        match stats.state {
            CircuitState::Closed => {
                // Reset failure count on success
                stats.failure_count = 0;
            }
            CircuitState::Open => {
                // Check if transitioning to half-open
                let eff_duration = self.effective_open_duration(stats);
                if now >= stats.last_state_change + eff_duration {
                    stats.state = CircuitState::HalfOpen;
                    stats.success_count = 1;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "vellaveto_circuit_breaker_state_changes_total",
                        "from_state" => "open",
                        "to_state" => "half_open"
                    )
                    .increment(1);
                    tracing::info!(
                        tool = %tool,
                        "Circuit breaker transitioning to half-open after timeout"
                    );
                }
            }
            CircuitState::HalfOpen => {
                stats.success_count = stats.success_count.saturating_add(1);

                // Check if we've reached success threshold to close
                if stats.success_count >= self.success_threshold {
                    stats.state = CircuitState::Closed;
                    stats.failure_count = 0;
                    stats.success_count = 0;
                    // SECURITY (FIND-079): Reset trip_count on full recovery.
                    stats.trip_count = 0;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "vellaveto_circuit_breaker_state_changes_total",
                        "from_state" => "half_open",
                        "to_state" => "closed"
                    )
                    .increment(1);
                    tracing::info!(
                        tool = %tool,
                        "Circuit breaker closed after recovery"
                    );
                }
            }
        }
    }

    /// Record a failure. Returns the new circuit state.
    ///
    /// Note: If RwLock is poisoned, logs a critical error and returns Open
    /// (fail-closed behavior for the returned state).
    ///
    /// FIND-R44-032: If the circuit map is at capacity and this is a new tool,
    /// the insert is skipped and `Open` is returned (fail-closed).
    pub fn record_failure(&self, tool: &str) -> CircuitState {
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name to prevent
        // case-variation and homoglyph (Cyrillic/fullwidth) bypass.
        let tool_lower = crate::normalize::normalize_full(tool);
        let mut circuits = match self.circuits.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in record_failure for '{}': {}",
                    tool,
                    e
                );
                // Return Open as fail-closed behavior
                return CircuitState::Open;
            }
        };

        // FIND-R44-032: Bound circuit map size to prevent memory exhaustion.
        if circuits.len() >= MAX_TRACKED_CIRCUITS && !circuits.contains_key(&tool_lower) {
            tracing::warn!(
                tool = %tool,
                max = MAX_TRACKED_CIRCUITS,
                "Circuit breaker map at capacity — treating new tool as Open (fail-closed)"
            );
            return CircuitState::Open;
        }

        let now = Self::now_or_zero();

        let stats = circuits.entry(tool_lower).or_insert_with(|| CircuitStats {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_state_change: now,
            trip_count: 0,
        });

        stats.last_failure = Some(now);

        match stats.state {
            CircuitState::Closed => {
                stats.failure_count = stats.failure_count.saturating_add(1);

                // Check if we've reached failure threshold
                if stats.failure_count >= self.failure_threshold {
                    stats.state = CircuitState::Open;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "vellaveto_circuit_breaker_state_changes_total",
                        "from_state" => "closed",
                        "to_state" => "open"
                    )
                    .increment(1);
                    tracing::warn!(
                        tool = %tool,
                        failures = stats.failure_count,
                        "Circuit breaker opened due to repeated failures"
                    );
                }
            }
            CircuitState::Open => {
                // Already open, just update failure count
                stats.failure_count = stats.failure_count.saturating_add(1);
            }
            CircuitState::HalfOpen => {
                // Failure in half-open means we go back to open
                stats.state = CircuitState::Open;
                stats.failure_count = stats.failure_count.saturating_add(1);
                stats.success_count = 0;
                // SECURITY (FIND-079): Increment trip_count for exponential backoff.
                stats.trip_count = stats.trip_count.saturating_add(1);
                stats.last_state_change = now;
                // IMPROVEMENT_PLAN 1.3: Record state change metric
                metrics::counter!(
                    "vellaveto_circuit_breaker_state_changes_total",
                    "from_state" => "half_open",
                    "to_state" => "open"
                )
                .increment(1);
                tracing::warn!(
                    tool = %tool,
                    trip_count = stats.trip_count,
                    "Circuit breaker reopened after half-open failure (backoff trip #{})",
                    stats.trip_count
                );
            }
        }

        stats.state
    }

    /// Get the current state for a tool.
    ///
    /// Note: If RwLock is poisoned, returns Open (fail-closed behavior).
    pub fn get_state(&self, tool: &str) -> CircuitState {
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name with homoglyphs.
        let tool_lower = crate::normalize::normalize_full(tool);
        let circuits = match self.circuits.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in get_state for '{}': {}",
                    tool,
                    e
                );
                // Return Open as fail-closed behavior
                return CircuitState::Open;
            }
        };

        circuits
            .get(&tool_lower)
            .map(|s| {
                // Check for automatic transition to half-open
                if s.state == CircuitState::Open {
                    let now = Self::now_or_zero();
                    let eff_duration = self.effective_open_duration(s);
                    if now >= s.last_state_change + eff_duration {
                        return CircuitState::HalfOpen;
                    }
                }
                s.state
            })
            .unwrap_or(CircuitState::Closed)
    }

    /// Get full statistics for a tool.
    ///
    /// Note: If RwLock is poisoned, returns None and logs error.
    pub fn get_stats(&self, tool: &str) -> Option<CircuitStats> {
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name with homoglyphs.
        let tool_lower = crate::normalize::normalize_full(tool);
        let circuits = match self.circuits.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in get_stats for '{}': {}",
                    tool,
                    e
                );
                return None;
            }
        };
        circuits.get(&tool_lower).cloned()
    }

    /// Manually reset a circuit to closed state.
    ///
    /// FIND-R44-034: Rejects resets while the circuit is Open and the open
    /// duration has not yet elapsed, to prevent abuse that bypasses backoff.
    /// Returns `Ok(())` on success, `Err(reason)` if the reset is rejected.
    ///
    /// Note: If RwLock is poisoned, logs error and returns an error.
    pub fn reset(&self, tool: &str) -> Result<(), String> {
        // SECURITY (FIND-077, FIND-R211-001): Normalize tool name with homoglyphs.
        let tool_lower = crate::normalize::normalize_full(tool);
        let mut circuits = match self.circuits.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in reset for '{}': {}",
                    tool,
                    e
                );
                return Err(format!(
                    "Circuit breaker unavailable for tool '{tool}' (internal error)"
                ));
            }
        };

        // FIND-R44-034: Reject reset if circuit is Open and cooldown has not elapsed.
        if let Some(stats) = circuits.get(&tool_lower) {
            if stats.state == CircuitState::Open {
                let now = Self::now_or_zero();
                let eff_duration = self.effective_open_duration(stats);
                if now < stats.last_state_change + eff_duration {
                    let remaining = (stats.last_state_change + eff_duration).saturating_sub(now);
                    tracing::warn!(
                        tool = %tool,
                        remaining_secs = remaining,
                        "Circuit breaker reset rejected — open cooldown has not elapsed"
                    );
                    return Err(format!(
                        "Circuit breaker reset rejected for tool '{tool}': \
                         open cooldown has {remaining}s remaining"
                    ));
                }
            }
        }

        circuits.remove(&tool_lower);
        tracing::warn!(
            tool = %tool,
            "Circuit breaker manually reset"
        );
        Ok(())
    }

    /// Check if a tool's circuit is attempting recovery (half-open).
    pub fn is_recovering(&self, tool: &str) -> bool {
        self.get_state(tool) == CircuitState::HalfOpen
    }

    /// Get all tracked tools.
    ///
    /// Note: If RwLock is poisoned, returns empty vec and logs error.
    pub fn tracked_tools(&self) -> Vec<String> {
        let circuits = match self.circuits.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in tracked_tools: {}",
                    e
                );
                return Vec::new();
            }
        };
        circuits.keys().cloned().collect()
    }

    /// Get summary statistics for all circuits.
    ///
    /// Note: If RwLock is poisoned, returns empty summary and logs error.
    pub fn summary(&self) -> CircuitSummary {
        let circuits = match self.circuits.read() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in summary: {}",
                    e
                );
                return CircuitSummary {
                    total: 0,
                    closed: 0,
                    open: 0,
                    half_open: 0,
                };
            }
        };
        let now = Self::now_or_zero();

        let mut closed: usize = 0;
        let mut open: usize = 0;
        let mut half_open: usize = 0;

        for stats in circuits.values() {
            match stats.state {
                // SECURITY (FIND-R58-ENG-003): Saturating arithmetic per Trap 9.
                CircuitState::Closed => closed = closed.saturating_add(1),
                CircuitState::Open => {
                    let eff_duration = self.effective_open_duration(stats);
                    if now >= stats.last_state_change + eff_duration {
                        half_open = half_open.saturating_add(1);
                    } else {
                        open = open.saturating_add(1);
                    }
                }
                CircuitState::HalfOpen => half_open = half_open.saturating_add(1),
            }
        }

        CircuitSummary {
            total: circuits.len(),
            closed,
            open,
            half_open,
        }
    }
}

/// Summary of circuit breaker states.
#[derive(Debug, Clone, Default)]
pub struct CircuitSummary {
    pub total: usize,
    pub closed: usize,
    pub open: usize,
    pub half_open: usize,
}

impl CircuitSummary {
    /// Record current state counts as gauge metrics (GAP-011).
    ///
    /// Call this periodically (e.g., every 10 seconds) to keep gauge values current.
    ///
    /// # Metrics
    ///
    /// - `vellaveto_circuit_breaker_circuits_total`: Total circuits tracked
    /// - `vellaveto_circuit_breaker_state_current`: Current count by state
    pub fn record_metrics(&self) {
        metrics::gauge!("vellaveto_circuit_breaker_circuits_total").set(self.total as f64);
        metrics::gauge!("vellaveto_circuit_breaker_state_current", "state" => "closed")
            .set(self.closed as f64);
        metrics::gauge!("vellaveto_circuit_breaker_state_current", "state" => "open")
            .set(self.open as f64);
        metrics::gauge!("vellaveto_circuit_breaker_state_current", "state" => "half_open")
            .set(self.half_open as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_starts_closed() {
        let manager = CircuitBreakerManager::new(5, 3, 30);
        assert_eq!(manager.get_state("my_tool"), CircuitState::Closed);
        assert!(manager.can_proceed("my_tool").is_ok());
    }

    #[test]
    fn test_circuit_trips_after_failures() {
        let manager = CircuitBreakerManager::new(3, 2, 30);

        // Record failures up to threshold
        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::Closed);

        // Third failure trips the circuit
        let state = manager.record_failure("my_tool");
        assert_eq!(state, CircuitState::Open);
        assert!(manager.can_proceed("my_tool").is_err());
    }

    #[test]
    fn test_success_resets_failure_count() {
        let manager = CircuitBreakerManager::new(3, 2, 30);

        manager.record_failure("my_tool");
        manager.record_failure("my_tool");

        // Success resets failures
        manager.record_success("my_tool");

        // Need 3 more failures to trip
        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::Closed);

        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::Open);
    }

    #[test]
    fn test_manual_reset() {
        // Use 0-sec open duration so reset is never blocked by cooldown
        let manager = CircuitBreakerManager::new(2, 2, 0);

        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::HalfOpen); // 0-sec → HalfOpen

        assert!(manager.reset("my_tool").is_ok());
        assert_eq!(manager.get_state("my_tool"), CircuitState::Closed);
        assert!(manager.can_proceed("my_tool").is_ok());
    }

    #[test]
    fn test_tracked_tools() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        manager.record_failure("tool_a");
        manager.record_success("tool_b");

        let tools = manager.tracked_tools();
        assert!(tools.contains(&"tool_a".to_string()));
        assert!(tools.contains(&"tool_b".to_string()));
    }

    #[test]
    fn test_summary() {
        let manager = CircuitBreakerManager::new(2, 2, 30);

        manager.record_success("closed_tool");

        manager.record_failure("open_tool");
        manager.record_failure("open_tool");

        let summary = manager.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.open, 1);
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let manager = CircuitBreakerManager::with_config(2, 2, 0, 2); // 0 duration for immediate transition

        // Trip the circuit
        manager.record_failure("my_tool");
        let state = manager.record_failure("my_tool");
        // record_failure returns the state immediately after setting it
        assert_eq!(state, CircuitState::Open);

        // With 0 duration, get_state returns HalfOpen because enough time has passed
        assert_eq!(manager.get_state("my_tool"), CircuitState::HalfOpen);

        // Record a success to transition to half-open state in internal storage
        manager.record_success("my_tool");

        // Now a failure in half-open should reopen
        let state = manager.record_failure("my_tool");
        assert_eq!(state, CircuitState::Open);
    }

    // ========================================
    // GAP-011: Circuit Breaker Metrics Tests
    // ========================================

    #[test]
    fn test_summary_record_metrics_does_not_panic() {
        let manager = CircuitBreakerManager::new(2, 2, 30);

        manager.record_success("closed_tool");
        manager.record_failure("open_tool");
        manager.record_failure("open_tool");

        let summary = manager.summary();

        // Should not panic when recording metrics
        summary.record_metrics();
    }

    #[test]
    fn test_can_proceed_rejection_contains_tool_name() {
        let manager = CircuitBreakerManager::new(2, 2, 30);

        manager.record_failure("my_flaky_tool");
        manager.record_failure("my_flaky_tool");

        let result = manager.can_proceed("my_flaky_tool");
        assert!(result.is_err());
        let reason = result.unwrap_err();
        assert!(
            reason.contains("my_flaky_tool"),
            "rejection reason should contain tool name"
        );
        assert!(
            reason.contains("Circuit breaker open"),
            "rejection reason should indicate circuit is open"
        );
    }

    #[test]
    fn test_can_proceed_success_does_not_panic() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        // Multiple successful can_proceed calls should work fine
        for _ in 0..100 {
            assert!(manager.can_proceed("healthy_tool").is_ok());
        }
    }

    // ════════════════════════════════════════════════════════
    // FIND-044: HalfOpen-to-Closed recovery path
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_half_open_success_threshold_closes_circuit() {
        // success_threshold = 2, open_duration = 0 (immediate transition)
        let manager = CircuitBreakerManager::with_config(2, 2, 0, 2);

        // Trip the circuit
        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::HalfOpen); // 0-sec open → HalfOpen

        // First success in half-open transitions internal state to HalfOpen
        manager.record_success("my_tool");

        // Second success reaches success_threshold (2) → should close
        manager.record_success("my_tool");
        assert_eq!(
            manager.get_state("my_tool"),
            CircuitState::Closed,
            "Circuit should close after reaching success_threshold in HalfOpen"
        );

        // Verify it's fully operational again
        assert!(manager.can_proceed("my_tool").is_ok());
    }

    #[test]
    fn test_can_proceed_allows_after_open_duration_expires() {
        // open_duration = 0 → circuit immediately allows probing
        let manager = CircuitBreakerManager::new(2, 2, 0);

        // Trip the circuit
        manager.record_failure("my_tool");
        manager.record_failure("my_tool");

        // Even though circuit is "Open", 0-second duration means it should allow
        assert!(
            manager.can_proceed("my_tool").is_ok(),
            "can_proceed should allow after open_duration expires"
        );
    }

    #[test]
    fn test_half_open_full_lifecycle() {
        // Test the complete lifecycle: Closed → Open → HalfOpen → Closed
        let manager = CircuitBreakerManager::with_config(3, 2, 0, 2);

        // Phase 1: Closed
        assert_eq!(manager.get_state("tool"), CircuitState::Closed);
        assert!(manager.can_proceed("tool").is_ok());

        // Phase 2: Trip to Open
        manager.record_failure("tool");
        manager.record_failure("tool");
        manager.record_failure("tool");
        // get_state with 0-sec open returns HalfOpen immediately
        assert_eq!(manager.get_state("tool"), CircuitState::HalfOpen);

        // Phase 3: Enter HalfOpen via record_success (internal state update)
        manager.record_success("tool");
        // Not yet at success_threshold (2)

        // Phase 4: Second success closes the circuit
        manager.record_success("tool");
        assert_eq!(manager.get_state("tool"), CircuitState::Closed);

        // Phase 5: Verify clean state — failure counts should be reset
        manager.record_failure("tool");
        manager.record_failure("tool");
        assert_eq!(
            manager.get_state("tool"),
            CircuitState::Closed,
            "After recovery, failure_count should be 0 so 2 failures < threshold(3)"
        );
    }

    #[test]
    fn test_half_open_single_failure_reopens_and_requires_full_recovery() {
        let manager = CircuitBreakerManager::with_config(2, 3, 0, 3);

        // Trip circuit
        manager.record_failure("tool");
        manager.record_failure("tool");

        // Enter half-open
        manager.record_success("tool");
        // 1 success, need 3

        // Failure in half-open → back to open
        let state = manager.record_failure("tool");
        assert_eq!(state, CircuitState::Open);

        // Re-enter half-open
        manager.record_success("tool");
        // Now need full 3 successes again
        manager.record_success("tool");
        manager.record_success("tool");
        assert_eq!(
            manager.get_state("tool"),
            CircuitState::Closed,
            "Should close after full success_threshold from scratch"
        );
    }

    #[test]
    fn test_is_recovering_reflects_half_open_state() {
        let manager = CircuitBreakerManager::with_config(2, 2, 0, 2);

        assert!(
            !manager.is_recovering("tool"),
            "No circuit = not recovering"
        );

        // Trip
        manager.record_failure("tool");
        manager.record_failure("tool");

        // With 0-sec open duration, get_state returns HalfOpen
        assert!(
            manager.is_recovering("tool"),
            "Should be recovering after open_duration expires"
        );

        // Complete recovery
        manager.record_success("tool");
        manager.record_success("tool");
        assert!(
            !manager.is_recovering("tool"),
            "Should not be recovering after circuit closes"
        );
    }

    #[test]
    fn test_summary_shows_half_open_with_expired_duration() {
        let manager = CircuitBreakerManager::with_config(2, 2, 0, 2);

        manager.record_success("closed_tool");

        // Trip a circuit with 0-sec duration → appears as half_open in summary
        manager.record_failure("recovering_tool");
        manager.record_failure("recovering_tool");

        let summary = manager.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.closed, 1);
        assert_eq!(
            summary.half_open, 1,
            "Open circuit with expired duration should show as half_open"
        );
        assert_eq!(summary.open, 0);
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-032: Bounded circuit map size
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_circuit_map_bounded_record_failure() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        // Fill to capacity
        for i in 0..MAX_TRACKED_CIRCUITS {
            manager.record_failure(&format!("tool_{}", i));
        }

        // Next new tool should be rejected (fail-closed → Open)
        let state = manager.record_failure("overflow_tool");
        assert_eq!(
            state,
            CircuitState::Open,
            "New tool at capacity should be treated as Open (fail-closed)"
        );

        // Existing tool should still be tracked
        let state = manager.record_failure("tool_0");
        assert_eq!(
            state,
            CircuitState::Closed,
            "Existing tool should still be updatable"
        );
    }

    #[test]
    fn test_circuit_map_bounded_record_success() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        // Fill to capacity
        for i in 0..MAX_TRACKED_CIRCUITS {
            manager.record_success(&format!("tool_{}", i));
        }

        // New tool success should be silently skipped
        manager.record_success("overflow_tool");

        // overflow_tool should not be tracked
        assert_eq!(
            manager.get_state("overflow_tool"),
            CircuitState::Closed,
            "Untracked tool returns Closed (no entry)"
        );

        let tools = manager.tracked_tools();
        assert!(
            !tools.contains(&"overflow_tool".to_string()),
            "Overflow tool should not appear in tracked tools"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R44-034: Reset rate limiting
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_reset_rejected_during_open_cooldown() {
        // 30-second open duration → reset should be rejected while Open
        let manager = CircuitBreakerManager::new(2, 2, 30);

        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::Open);

        let result = manager.reset("my_tool");
        assert!(
            result.is_err(),
            "Reset should be rejected while open cooldown has not elapsed"
        );
        let err = result.err().unwrap_or_default();
        assert!(
            err.contains("cooldown"),
            "Error message should mention cooldown: {err}"
        );

        // Circuit should still be Open
        assert_eq!(manager.get_state("my_tool"), CircuitState::Open);
    }

    #[test]
    fn test_reset_allowed_after_cooldown_expires() {
        // 0-second open duration → cooldown expires immediately
        let manager = CircuitBreakerManager::new(2, 2, 0);

        manager.record_failure("my_tool");
        manager.record_failure("my_tool");

        // With 0-sec duration, reset should succeed
        let result = manager.reset("my_tool");
        assert!(
            result.is_ok(),
            "Reset should succeed after cooldown expires"
        );
        assert_eq!(manager.get_state("my_tool"), CircuitState::Closed);
    }

    #[test]
    fn test_reset_allowed_for_closed_circuit() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        manager.record_failure("my_tool");
        // Not enough failures to open

        let result = manager.reset("my_tool");
        assert!(result.is_ok(), "Reset should succeed for a Closed circuit");
    }

    #[test]
    fn test_reset_allowed_for_nonexistent_circuit() {
        let manager = CircuitBreakerManager::new(5, 3, 30);

        let result = manager.reset("nonexistent_tool");
        assert!(
            result.is_ok(),
            "Reset should succeed for a nonexistent circuit"
        );
    }
}
