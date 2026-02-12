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
//! use sentinel_engine::circuit_breaker::CircuitBreakerManager;
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

use sentinel_types::{CircuitState, CircuitStats};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

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
    /// - `sentinel_circuit_breaker_check_duration_seconds`: Histogram of check latency
    /// - `sentinel_circuit_breaker_rejections_total`: Counter of rejected requests
    pub fn can_proceed(&self, tool: &str) -> Result<(), String> {
        let start = std::time::Instant::now();

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
                "sentinel_circuit_breaker_rejections_total",
                "tool" => tool.to_string(),
                "reason" => "rwlock_poisoned"
            )
            .increment(1);
            reason
        })?;

        let stats = match circuits.get(tool) {
            Some(s) => s,
            None => {
                // GAP-011: Record successful check latency
                metrics::histogram!("sentinel_circuit_breaker_check_duration_seconds")
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
                if now >= stats.last_state_change + self.open_duration_secs {
                    // Would transition to half-open, allow one request
                    Ok(())
                } else {
                    let opens_in =
                        (stats.last_state_change + self.open_duration_secs).saturating_sub(now);
                    let failure_count = stats.failure_count;
                    let reason = format!(
                        "Circuit breaker open for tool '{tool}' (failures: {failure_count}, opens in {opens_in}s)"
                    );
                    // GAP-011: Record rejection metric
                    metrics::counter!(
                        "sentinel_circuit_breaker_rejections_total",
                        "tool" => tool.to_string(),
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
                        "sentinel_circuit_breaker_rejections_total",
                        "tool" => tool.to_string(),
                        "reason" => "half_open_limit"
                    )
                    .increment(1);
                    Err(reason)
                }
            }
        };

        // GAP-011: Record check latency
        metrics::histogram!("sentinel_circuit_breaker_check_duration_seconds")
            .record(start.elapsed().as_secs_f64());

        result
    }

    /// Record a successful call.
    ///
    /// Note: If RwLock is poisoned, logs a critical error but does not panic.
    /// This is acceptable because record_success is not on the security-critical
    /// path (can_proceed is). However, persistent poisoning will be visible in logs.
    pub fn record_success(&self, tool: &str) {
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
        let now = Self::now_or_zero();

        let stats = circuits
            .entry(tool.to_string())
            .or_insert_with(|| CircuitStats {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure: None,
                last_state_change: now,
            });

        match stats.state {
            CircuitState::Closed => {
                // Reset failure count on success
                stats.failure_count = 0;
            }
            CircuitState::Open => {
                // Check if transitioning to half-open
                if now >= stats.last_state_change + self.open_duration_secs {
                    stats.state = CircuitState::HalfOpen;
                    stats.success_count = 1;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "sentinel_circuit_breaker_state_changes_total",
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
                stats.success_count += 1;

                // Check if we've reached success threshold to close
                if stats.success_count >= self.success_threshold {
                    stats.state = CircuitState::Closed;
                    stats.failure_count = 0;
                    stats.success_count = 0;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "sentinel_circuit_breaker_state_changes_total",
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
    pub fn record_failure(&self, tool: &str) -> CircuitState {
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
        let now = Self::now_or_zero();

        let stats = circuits
            .entry(tool.to_string())
            .or_insert_with(|| CircuitStats {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure: None,
                last_state_change: now,
            });

        stats.last_failure = Some(now);

        match stats.state {
            CircuitState::Closed => {
                stats.failure_count += 1;

                // Check if we've reached failure threshold
                if stats.failure_count >= self.failure_threshold {
                    stats.state = CircuitState::Open;
                    stats.last_state_change = now;
                    // IMPROVEMENT_PLAN 1.3: Record state change metric
                    metrics::counter!(
                        "sentinel_circuit_breaker_state_changes_total",
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
                stats.failure_count += 1;
            }
            CircuitState::HalfOpen => {
                // Failure in half-open means we go back to open
                stats.state = CircuitState::Open;
                stats.failure_count += 1;
                stats.success_count = 0;
                stats.last_state_change = now;
                // IMPROVEMENT_PLAN 1.3: Record state change metric
                metrics::counter!(
                    "sentinel_circuit_breaker_state_changes_total",
                    "from_state" => "half_open",
                    "to_state" => "open"
                )
                .increment(1);
                tracing::warn!(
                    tool = %tool,
                    "Circuit breaker reopened after half-open failure"
                );
            }
        }

        stats.state
    }

    /// Get the current state for a tool.
    ///
    /// Note: If RwLock is poisoned, returns Open (fail-closed behavior).
    pub fn get_state(&self, tool: &str) -> CircuitState {
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
            .get(tool)
            .map(|s| {
                // Check for automatic transition to half-open
                if s.state == CircuitState::Open {
                    let now = Self::now_or_zero();
                    if now >= s.last_state_change + self.open_duration_secs {
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
        circuits.get(tool).cloned()
    }

    /// Manually reset a circuit to closed state.
    ///
    /// Note: If RwLock is poisoned, logs error and does nothing.
    pub fn reset(&self, tool: &str) {
        let mut circuits = match self.circuits.write() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    "CRITICAL: Circuit breaker RwLock poisoned in reset for '{}': {}",
                    tool,
                    e
                );
                return;
            }
        };
        circuits.remove(tool);
        tracing::info!(
            tool = %tool,
            "Circuit breaker manually reset"
        );
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

        let mut closed = 0;
        let mut open = 0;
        let mut half_open = 0;

        for stats in circuits.values() {
            match stats.state {
                CircuitState::Closed => closed += 1,
                CircuitState::Open => {
                    if now >= stats.last_state_change + self.open_duration_secs {
                        half_open += 1;
                    } else {
                        open += 1;
                    }
                }
                CircuitState::HalfOpen => half_open += 1,
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
    /// - `sentinel_circuit_breaker_circuits_total`: Total circuits tracked
    /// - `sentinel_circuit_breaker_state_current`: Current count by state
    pub fn record_metrics(&self) {
        metrics::gauge!("sentinel_circuit_breaker_circuits_total").set(self.total as f64);
        metrics::gauge!("sentinel_circuit_breaker_state_current", "state" => "closed")
            .set(self.closed as f64);
        metrics::gauge!("sentinel_circuit_breaker_state_current", "state" => "open")
            .set(self.open as f64);
        metrics::gauge!("sentinel_circuit_breaker_state_current", "state" => "half_open")
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
        let manager = CircuitBreakerManager::new(2, 2, 30);

        manager.record_failure("my_tool");
        manager.record_failure("my_tool");
        assert_eq!(manager.get_state("my_tool"), CircuitState::Open);

        manager.reset("my_tool");
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

        assert!(!manager.is_recovering("tool"), "No circuit = not recovering");

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
}
