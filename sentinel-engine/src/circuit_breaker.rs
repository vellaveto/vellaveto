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
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Check if a request can proceed for the given tool.
    ///
    /// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
    pub fn can_proceed(&self, tool: &str) -> Result<(), String> {
        let circuits = self.circuits.read().unwrap_or_else(|p| p.into_inner());

        let stats = match circuits.get(tool) {
            Some(s) => s,
            None => return Ok(()), // No circuit = closed
        };

        match stats.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if it's time to transition to half-open
                let now = Self::now();
                if now >= stats.last_state_change + self.open_duration_secs {
                    // Would transition to half-open, allow one request
                    Ok(())
                } else {
                    Err(format!(
                        "Circuit breaker open for tool '{}' (failures: {}, opens in {}s)",
                        tool,
                        stats.failure_count,
                        (stats.last_state_change + self.open_duration_secs).saturating_sub(now)
                    ))
                }
            }
            CircuitState::HalfOpen => {
                // In half-open, allow limited requests
                if stats.success_count < self.half_open_max_requests {
                    Ok(())
                } else {
                    Err(format!(
                        "Circuit breaker half-open for tool '{}' (testing recovery)",
                        tool
                    ))
                }
            }
        }
    }

    /// Record a successful call.
    pub fn record_success(&self, tool: &str) {
        let mut circuits = self.circuits.write().unwrap_or_else(|p| p.into_inner());
        let now = Self::now();

        let stats = circuits.entry(tool.to_string()).or_insert_with(|| CircuitStats {
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
                    tracing::info!(
                        tool = %tool,
                        "Circuit breaker closed after recovery"
                    );
                }
            }
        }
    }

    /// Record a failure. Returns the new circuit state.
    pub fn record_failure(&self, tool: &str) -> CircuitState {
        let mut circuits = self.circuits.write().unwrap_or_else(|p| p.into_inner());
        let now = Self::now();

        let stats = circuits.entry(tool.to_string()).or_insert_with(|| CircuitStats {
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
                tracing::warn!(
                    tool = %tool,
                    "Circuit breaker reopened after half-open failure"
                );
            }
        }

        stats.state
    }

    /// Get the current state for a tool.
    pub fn get_state(&self, tool: &str) -> CircuitState {
        let circuits = self.circuits.read().unwrap_or_else(|p| p.into_inner());

        circuits
            .get(tool)
            .map(|s| {
                // Check for automatic transition to half-open
                if s.state == CircuitState::Open {
                    let now = Self::now();
                    if now >= s.last_state_change + self.open_duration_secs {
                        return CircuitState::HalfOpen;
                    }
                }
                s.state
            })
            .unwrap_or(CircuitState::Closed)
    }

    /// Get full statistics for a tool.
    pub fn get_stats(&self, tool: &str) -> Option<CircuitStats> {
        let circuits = self.circuits.read().unwrap_or_else(|p| p.into_inner());
        circuits.get(tool).cloned()
    }

    /// Manually reset a circuit to closed state.
    pub fn reset(&self, tool: &str) {
        let mut circuits = self.circuits.write().unwrap_or_else(|p| p.into_inner());
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
    pub fn tracked_tools(&self) -> Vec<String> {
        let circuits = self.circuits.read().unwrap_or_else(|p| p.into_inner());
        circuits.keys().cloned().collect()
    }

    /// Get summary statistics for all circuits.
    pub fn summary(&self) -> CircuitSummary {
        let circuits = self.circuits.read().unwrap_or_else(|p| p.into_inner());
        let now = Self::now();

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
}
