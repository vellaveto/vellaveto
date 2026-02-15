//! Per-transport circuit breaker for cross-transport fallback (Phase 29).
//!
//! Mirrors the `CircuitBreakerManager` pattern (Closed/Open/HalfOpen state machine)
//! but keyed by `(upstream_id, TransportProtocol)` instead of tool name.
//! Used by `SmartFallbackChain` to skip transports that are known to be down.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use vellaveto_types::TransportProtocol;

/// Per-transport circuit breaker state, mirroring `CircuitState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportCircuitState {
    /// Normal operation, transport available.
    #[default]
    Closed,
    /// Transport marked down, requests blocked until open duration expires.
    Open,
    /// Testing recovery, limited requests allowed.
    HalfOpen,
}

/// Statistics for a single (upstream, transport) circuit.
#[derive(Debug, Clone)]
struct TransportCircuitStats {
    state: TransportCircuitState,
    failure_count: u32,
    success_count: u32,
    last_state_change: u64,
    trip_count: u32,
}

impl TransportCircuitStats {
    fn new() -> Self {
        Self {
            state: TransportCircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_state_change: now_secs(),
            trip_count: 0,
        }
    }
}

/// Summary snapshot of transport health tracker state.
#[derive(Debug, Clone, Serialize)]
pub struct TransportHealthSummary {
    /// Total number of tracked (upstream, transport) pairs.
    pub total: usize,
    /// Number in Closed state.
    pub closed: usize,
    /// Number in Open state.
    pub open: usize,
    /// Number in HalfOpen state.
    pub half_open: usize,
}

/// Maximum number of tracked (upstream_id, transport) pairs.
/// Prevents unbounded memory growth (FIND-R41-003).
const MAX_TRACKED_CIRCUITS: usize = 10_000;

/// Per-transport circuit breaker tracker.
///
/// Tracks health of each `(upstream_id, TransportProtocol)` pair using a
/// Closed/Open/HalfOpen state machine with exponential backoff.
pub struct TransportHealthTracker {
    states: RwLock<HashMap<(String, TransportProtocol), TransportCircuitStats>>,
    failure_threshold: u32,
    success_threshold: u32,
    open_duration_secs: u64,
}

impl std::fmt::Debug for TransportHealthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportHealthTracker")
            .field("failure_threshold", &self.failure_threshold)
            .field("success_threshold", &self.success_threshold)
            .field("open_duration_secs", &self.open_duration_secs)
            .finish()
    }
}

impl TransportHealthTracker {
    /// Create a new tracker with the given thresholds.
    pub fn new(failure_threshold: u32, success_threshold: u32, open_duration_secs: u64) -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
            failure_threshold: failure_threshold.max(1),
            success_threshold: success_threshold.max(1),
            open_duration_secs: open_duration_secs.max(1),
        }
    }

    /// Calculate effective open duration with exponential backoff (2^trip_count, max 32x).
    fn effective_open_duration(&self, stats: &TransportCircuitStats) -> u64 {
        let multiplier = 1u64 << stats.trip_count.min(5);
        self.open_duration_secs.saturating_mul(multiplier)
    }

    /// Check whether a transport can be used for the given upstream.
    ///
    /// Returns `Ok(())` if available, `Err(reason)` if the circuit is open.
    /// SECURITY: Fail-closed on RwLock poisoning.
    pub fn can_use(&self, upstream_id: &str, protocol: TransportProtocol) -> Result<(), String> {
        let key = (upstream_id.to_string(), protocol);

        // Read-lock first for common path (Closed).
        let needs_transition = {
            let states = self.states.read().map_err(|e| {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in can_use(): {}",
                    e
                );
                "transport health tracker unavailable (poisoned)".to_string()
            })?;

            match states.get(&key) {
                None => return Ok(()), // Unknown = assume available (Closed).
                Some(stats) => match stats.state {
                    TransportCircuitState::Closed => return Ok(()),
                    TransportCircuitState::HalfOpen => return Ok(()),
                    TransportCircuitState::Open => {
                        let now = now_secs();
                        let effective_dur = self.effective_open_duration(stats);
                        if now.saturating_sub(stats.last_state_change) >= effective_dur {
                            true // needs transition to HalfOpen
                        } else {
                            metrics::counter!(
                                "vellaveto_transport_health_rejections_total",
                                "upstream_id" => upstream_id.to_string(),
                                "transport" => format!("{:?}", protocol),
                            )
                            .increment(1);
                            return Err(format!(
                                "transport {:?} circuit open for upstream '{}'",
                                protocol, upstream_id
                            ));
                        }
                    }
                },
            }
        };

        // Double-check locking: transition Open → HalfOpen under write lock.
        if needs_transition {
            let mut states = self.states.write().map_err(|e| {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in can_use() (write): {}",
                    e
                );
                "transport health tracker unavailable (poisoned)".to_string()
            })?;

            if let Some(stats) = states.get_mut(&key) {
                if stats.state == TransportCircuitState::Open {
                    let now = now_secs();
                    let effective_dur = self.effective_open_duration(stats);
                    if now.saturating_sub(stats.last_state_change) >= effective_dur {
                        tracing::info!(
                            upstream_id = upstream_id,
                            transport = ?protocol,
                            "transport circuit Open → HalfOpen"
                        );
                        metrics::counter!(
                            "vellaveto_transport_health_state_changes_total",
                            "upstream_id" => upstream_id.to_string(),
                            "transport" => format!("{:?}", protocol),
                            "from" => "open",
                            "to" => "half_open",
                        )
                        .increment(1);
                        stats.state = TransportCircuitState::HalfOpen;
                        stats.success_count = 0;
                        stats.failure_count = 0;
                        stats.last_state_change = now;
                    }
                }
            }
        }

        Ok(())
    }

    /// Record a successful use of a transport.
    pub fn record_success(&self, upstream_id: &str, protocol: TransportProtocol) {
        let key = (upstream_id.to_string(), protocol);

        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in record_success(): {}",
                    e
                );
                return;
            }
        };

        // SECURITY (FIND-R41-003): Bound capacity. Only insert if entry exists
        // or we're under the limit. If over limit, silently skip (don't track).
        if !states.contains_key(&key) && states.len() >= MAX_TRACKED_CIRCUITS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRACKED_CIRCUITS,
                "Transport health tracker capacity reached — skipping new entry"
            );
            return;
        }
        let stats = states.entry(key).or_insert_with(TransportCircuitStats::new);
        stats.failure_count = 0;

        match stats.state {
            TransportCircuitState::Closed => {
                // Already healthy, nothing to do.
            }
            TransportCircuitState::Open => {
                // Unexpected success while open — treat as recovery start.
                stats.state = TransportCircuitState::HalfOpen;
                stats.success_count = 1;
                stats.last_state_change = now_secs();
            }
            TransportCircuitState::HalfOpen => {
                stats.success_count += 1;
                if stats.success_count >= self.success_threshold {
                    tracing::info!(
                        upstream_id = upstream_id,
                        transport = ?protocol,
                        "transport circuit HalfOpen → Closed (recovered)"
                    );
                    metrics::counter!(
                        "vellaveto_transport_health_state_changes_total",
                        "upstream_id" => upstream_id.to_string(),
                        "transport" => format!("{:?}", protocol),
                        "from" => "half_open",
                        "to" => "closed",
                    )
                    .increment(1);
                    stats.state = TransportCircuitState::Closed;
                    stats.success_count = 0;
                    stats.trip_count = 0; // Reset backoff on full recovery.
                    stats.last_state_change = now_secs();
                }
            }
        }
    }

    /// Record a failed use of a transport. Returns the new circuit state.
    pub fn record_failure(
        &self,
        upstream_id: &str,
        protocol: TransportProtocol,
    ) -> TransportCircuitState {
        let key = (upstream_id.to_string(), protocol);

        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in record_failure(): {}",
                    e
                );
                return TransportCircuitState::Open; // fail-closed
            }
        };

        // SECURITY (FIND-R41-003): Bound capacity. Fail-closed: treat as Open.
        if !states.contains_key(&key) && states.len() >= MAX_TRACKED_CIRCUITS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRACKED_CIRCUITS,
                "Transport health tracker capacity reached — treating as Open (fail-closed)"
            );
            return TransportCircuitState::Open;
        }
        let stats = states.entry(key).or_insert_with(TransportCircuitStats::new);
        stats.success_count = 0;

        match stats.state {
            TransportCircuitState::Closed => {
                stats.failure_count += 1;
                if stats.failure_count >= self.failure_threshold {
                    tracing::warn!(
                        upstream_id = upstream_id,
                        transport = ?protocol,
                        failures = stats.failure_count,
                        "transport circuit Closed → Open"
                    );
                    metrics::counter!(
                        "vellaveto_transport_health_state_changes_total",
                        "upstream_id" => upstream_id.to_string(),
                        "transport" => format!("{:?}", protocol),
                        "from" => "closed",
                        "to" => "open",
                    )
                    .increment(1);
                    stats.state = TransportCircuitState::Open;
                    stats.last_state_change = now_secs();
                }
                stats.state
            }
            TransportCircuitState::Open => {
                stats.failure_count += 1;
                TransportCircuitState::Open
            }
            TransportCircuitState::HalfOpen => {
                tracing::warn!(
                    upstream_id = upstream_id,
                    transport = ?protocol,
                    "transport circuit HalfOpen → Open (recovery failed)"
                );
                metrics::counter!(
                    "vellaveto_transport_health_state_changes_total",
                    "upstream_id" => upstream_id.to_string(),
                    "transport" => format!("{:?}", protocol),
                    "from" => "half_open",
                    "to" => "open",
                )
                .increment(1);
                stats.state = TransportCircuitState::Open;
                stats.trip_count = stats.trip_count.saturating_add(1);
                stats.failure_count = 0;
                stats.last_state_change = now_secs();
                TransportCircuitState::Open
            }
        }
    }

    /// Return a list of available transports for the given upstream,
    /// filtering out Open circuits and preserving priority order.
    pub fn available_transports(
        &self,
        upstream_id: &str,
        priorities: &[TransportProtocol],
    ) -> Vec<TransportProtocol> {
        priorities
            .iter()
            .copied()
            .filter(|proto| self.can_use(upstream_id, *proto).is_ok())
            .collect()
    }

    /// Return a summary of all tracked transport circuit states.
    pub fn summary(&self) -> TransportHealthSummary {
        let states = match self.states.read() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in summary(): {}",
                    e
                );
                return TransportHealthSummary {
                    total: 0,
                    closed: 0,
                    open: 0,
                    half_open: 0,
                };
            }
        };

        let now = now_secs();
        let mut closed = 0usize;
        let mut open = 0usize;
        let mut half_open = 0usize;

        for stats in states.values() {
            match stats.state {
                TransportCircuitState::Closed => closed += 1,
                TransportCircuitState::Open => {
                    let effective_dur = self.effective_open_duration(stats);
                    if now.saturating_sub(stats.last_state_change) >= effective_dur {
                        half_open += 1; // Would transition on next can_use()
                    } else {
                        open += 1;
                    }
                }
                TransportCircuitState::HalfOpen => half_open += 1,
            }
        }

        TransportHealthSummary {
            total: states.len(),
            closed,
            open,
            half_open,
        }
    }

    /// Manually reset a transport circuit to Closed state.
    pub fn reset(&self, upstream_id: &str, protocol: TransportProtocol) {
        let key = (upstream_id.to_string(), protocol);
        let mut states = match self.states.write() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::error!(
                    "TransportHealthTracker RwLock poisoned in reset(): {}",
                    e
                );
                return;
            }
        };
        states.remove(&key);
    }
}

/// Current Unix timestamp in seconds. Returns 0 on system clock error (fail-safe).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_health_tracker_new_defaults() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        assert_eq!(tracker.failure_threshold, 3);
        assert_eq!(tracker.success_threshold, 2);
        assert_eq!(tracker.open_duration_secs, 30);
    }

    #[test]
    fn test_transport_health_tracker_new_clamps_minimums() {
        let tracker = TransportHealthTracker::new(0, 0, 0);
        assert_eq!(tracker.failure_threshold, 1);
        assert_eq!(tracker.success_threshold, 1);
        assert_eq!(tracker.open_duration_secs, 1);
    }

    #[test]
    fn test_can_use_unknown_transport_allowed() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        assert!(tracker.can_use("upstream-1", TransportProtocol::Http).is_ok());
    }

    #[test]
    fn test_can_use_closed_circuit_allowed() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        tracker.record_success("upstream-1", TransportProtocol::Grpc);
        assert!(tracker.can_use("upstream-1", TransportProtocol::Grpc).is_ok());
    }

    #[test]
    fn test_record_failure_opens_circuit_after_threshold() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let proto = TransportProtocol::Http;

        // First two failures don't open the circuit.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Closed
        );
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Closed
        );
        assert!(tracker.can_use("up", proto).is_ok());

        // Third failure opens it.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
        assert!(tracker.can_use("up", proto).is_err());
    }

    #[test]
    fn test_record_success_resets_failure_count() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let proto = TransportProtocol::WebSocket;

        tracker.record_failure("up", proto);
        tracker.record_failure("up", proto);
        // Two failures, then a success should reset.
        tracker.record_success("up", proto);
        // Two more failures should not open (count was reset).
        tracker.record_failure("up", proto);
        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_half_open_recovers_on_successes() {
        let tracker = TransportHealthTracker::new(1, 2, 0); // 0 → clamped to 1s
        let proto = TransportProtocol::Http;

        // Open the circuit.
        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_err());

        // Wait for open duration to expire (1 second, practically instant in test).
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Should transition to HalfOpen.
        assert!(tracker.can_use("up", proto).is_ok());

        // Succeed twice to close.
        tracker.record_success("up", proto);
        tracker.record_success("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());

        // Summary should show closed.
        let summary = tracker.summary();
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.open, 0);
    }

    #[test]
    fn test_half_open_failure_reopens_circuit() {
        let tracker = TransportHealthTracker::new(1, 2, 0); // clamped to 1s
        let proto = TransportProtocol::Grpc;

        // Open the circuit.
        tracker.record_failure("up", proto);
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Transition to HalfOpen.
        assert!(tracker.can_use("up", proto).is_ok());

        // Fail in HalfOpen → back to Open.
        assert_eq!(
            tracker.record_failure("up", proto),
            TransportCircuitState::Open
        );
        assert!(tracker.can_use("up", proto).is_err());
    }

    #[test]
    fn test_available_transports_filters_open() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let priorities = vec![
            TransportProtocol::Grpc,
            TransportProtocol::WebSocket,
            TransportProtocol::Http,
        ];

        // Open gRPC circuit.
        tracker.record_failure("up", TransportProtocol::Grpc);

        let available = tracker.available_transports("up", &priorities);
        assert_eq!(available.len(), 2);
        assert!(!available.contains(&TransportProtocol::Grpc));
        assert!(available.contains(&TransportProtocol::WebSocket));
        assert!(available.contains(&TransportProtocol::Http));
    }

    #[test]
    fn test_available_transports_preserves_order() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let priorities = vec![
            TransportProtocol::Http,
            TransportProtocol::Grpc,
            TransportProtocol::WebSocket,
        ];

        let available = tracker.available_transports("up", &priorities);
        assert_eq!(available, priorities);
    }

    #[test]
    fn test_summary_empty_tracker() {
        let tracker = TransportHealthTracker::new(3, 2, 30);
        let summary = tracker.summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.closed, 0);
        assert_eq!(summary.open, 0);
        assert_eq!(summary.half_open, 0);
    }

    #[test]
    fn test_summary_mixed_states() {
        let tracker = TransportHealthTracker::new(1, 2, 300);

        // Closed (via success).
        tracker.record_success("up", TransportProtocol::Http);
        // Open (via failure).
        tracker.record_failure("up", TransportProtocol::Grpc);

        let summary = tracker.summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.open, 1);
    }

    #[test]
    fn test_reset_removes_circuit() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let proto = TransportProtocol::WebSocket;

        tracker.record_failure("up", proto);
        assert!(tracker.can_use("up", proto).is_err());

        tracker.reset("up", proto);
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_independent_upstreams() {
        let tracker = TransportHealthTracker::new(1, 2, 300);
        let proto = TransportProtocol::Http;

        tracker.record_failure("up-a", proto);
        assert!(tracker.can_use("up-a", proto).is_err());
        assert!(tracker.can_use("up-b", proto).is_ok());
    }

    #[test]
    fn test_independent_transports_same_upstream() {
        let tracker = TransportHealthTracker::new(1, 2, 300);

        tracker.record_failure("up", TransportProtocol::Grpc);
        assert!(tracker.can_use("up", TransportProtocol::Grpc).is_err());
        assert!(tracker.can_use("up", TransportProtocol::Http).is_ok());
    }

    #[test]
    fn test_exponential_backoff_increases_open_duration() {
        let tracker = TransportHealthTracker::new(1, 1, 1);
        let proto = TransportProtocol::Http;

        // First trip: 1s open duration.
        tracker.record_failure("up", proto);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(tracker.can_use("up", proto).is_ok()); // HalfOpen

        // Fail in HalfOpen → trip_count=1, open_duration=2s.
        tracker.record_failure("up", proto);

        // After 1.1s, should still be open (need 2s).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(tracker.can_use("up", proto).is_err());

        // After another 1.1s (total ~2.2s), should transition to HalfOpen.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(tracker.can_use("up", proto).is_ok());
    }

    #[test]
    fn test_trip_count_resets_on_full_recovery() {
        let tracker = TransportHealthTracker::new(1, 1, 1);
        let proto = TransportProtocol::Http;

        // Trip once.
        tracker.record_failure("up", proto);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        tracker.can_use("up", proto).ok(); // HalfOpen
        tracker.record_failure("up", proto); // trip_count=1

        // Recover.
        std::thread::sleep(std::time::Duration::from_millis(2200));
        tracker.can_use("up", proto).ok(); // HalfOpen
        tracker.record_success("up", proto); // Closed, trip_count=0

        // Next trip should use base duration (1s) again.
        tracker.record_failure("up", proto);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(tracker.can_use("up", proto).is_ok()); // Would fail if trip_count wasn't reset.
    }

    #[test]
    fn test_circuit_state_serde_roundtrip() {
        for state in [
            TransportCircuitState::Closed,
            TransportCircuitState::Open,
            TransportCircuitState::HalfOpen,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deser: TransportCircuitState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, deser);
        }
    }

    #[test]
    fn test_transport_health_summary_serialize() {
        let summary = TransportHealthSummary {
            total: 5,
            closed: 3,
            open: 1,
            half_open: 1,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total\":5"));
    }
}
