//! Adaptive rate limiting — adjusts thresholds based on behavioral patterns.
//!
//! Phase 71: Per-entity rate limiting with anomaly detection. When an anomaly
//! is signalled for an entity, their allowed rate is reduced. The rate
//! recovers automatically after a configurable recovery period.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for the adaptive rate limiter.
#[derive(Debug, Clone)]
pub struct AdaptiveRateConfig {
    /// Base allowed requests per window. Default: 100.
    pub base_rate_per_minute: u64,
    /// Multiplier for burst threshold above current rate. Default: 2.0.
    /// Requests above `current_rate * burst_multiplier` are denied.
    pub burst_multiplier: f64,
    /// Factor to reduce rate on anomaly detection. Default: 0.5 (halves rate).
    /// Clamped to [0.0, 1.0].
    pub anomaly_reduction_factor: f64,
    /// How long the reduced rate persists after anomaly. Default: 5 minutes.
    pub recovery_period: Duration,
    /// Size of the sliding window. Default: 1 minute.
    pub window_size: Duration,
}

impl Default for AdaptiveRateConfig {
    fn default() -> Self {
        Self {
            base_rate_per_minute: 100,
            burst_multiplier: 2.0,
            anomaly_reduction_factor: 0.5,
            recovery_period: Duration::from_secs(300),
            window_size: Duration::from_secs(60),
        }
    }
}

impl AdaptiveRateConfig {
    /// SECURITY (R229-ENG-3): Validate configuration values at construction time.
    ///
    /// Ensures f64 fields are finite and in valid ranges, and duration fields
    /// are non-zero. Without this, NaN/Infinity values bypass threshold checks.
    pub fn validate(&self) -> Result<(), String> {
        if self.base_rate_per_minute == 0 {
            return Err("base_rate_per_minute must be > 0".to_string());
        }
        if !self.burst_multiplier.is_finite() || self.burst_multiplier <= 0.0 {
            return Err(format!(
                "burst_multiplier must be finite and > 0.0, got {}",
                self.burst_multiplier
            ));
        }
        if !self.anomaly_reduction_factor.is_finite()
            || self.anomaly_reduction_factor < 0.0
            || self.anomaly_reduction_factor > 1.0
        {
            return Err(format!(
                "anomaly_reduction_factor must be in [0.0, 1.0], got {}",
                self.anomaly_reduction_factor
            ));
        }
        if self.recovery_period.is_zero() {
            return Err("recovery_period must be > 0".to_string());
        }
        if self.window_size.is_zero() {
            return Err("window_size must be > 0".to_string());
        }
        Ok(())
    }
}

/// Per-entity rate state.
#[derive(Debug, Clone)]
pub struct RateState {
    /// Current allowed rate per window.
    pub current_rate: u64,
    /// Requests counted in the current window.
    pub request_count: u64,
    /// Start of the current window.
    pub window_start: Instant,
    /// Whether an anomaly is currently active.
    pub anomaly_detected: bool,
    /// When the anomaly penalty expires.
    pub anomaly_expires: Option<Instant>,
    /// Lifetime total requests for this entity.
    pub total_requests: u64,
    /// Lifetime total denied requests for this entity.
    pub total_denied: u64,
}

/// Rate limit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// Request is within normal limits.
    Allow,
    /// Request exceeds burst threshold and is rejected.
    Deny,
    /// Request exceeds base rate but below burst threshold.
    Throttle,
}

/// Aggregated statistics across all tracked entities.
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub active_entities: usize,
    pub total_requests: u64,
    pub total_denied: u64,
    pub anomaly_count: usize,
}

/// Maximum number of tracked entities to bound memory (R228-ENG-7).
/// Beyond this limit, new entities are denied (fail-closed).
const MAX_TRACKED_ENTITIES: usize = 100_000;

/// Adaptive rate limiter that adjusts per-entity thresholds.
///
/// Entities are identified by string key (e.g., agent_id, tenant_id, tool name).
/// Rate limits are per-window and automatically reset when the window expires.
/// Anomaly signals temporarily reduce an entity's allowed rate.
pub struct AdaptiveRateLimiter {
    config: AdaptiveRateConfig,
    states: HashMap<String, RateState>,
}

impl AdaptiveRateLimiter {
    /// Create a new limiter with the given configuration.
    pub fn new(config: AdaptiveRateConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
        }
    }

    /// Check whether a request from `entity_id` should be allowed.
    ///
    /// Returns `Allow`, `Throttle`, or `Deny` based on the entity's
    /// current rate and anomaly state.
    pub fn check(&mut self, entity_id: &str) -> RateDecision {
        let now = Instant::now();
        let base_rate = self.config.base_rate_per_minute;
        let window_size = self.config.window_size;

        // SECURITY (R228-ENG-7): Bound the number of tracked entities to prevent
        // memory exhaustion from attacker-controlled entity_id proliferation.
        // Fail-closed: new unknown entities are denied when at capacity.
        if !self.states.contains_key(entity_id) && self.states.len() >= MAX_TRACKED_ENTITIES {
            return RateDecision::Deny;
        }

        let state = self
            .states
            .entry(entity_id.to_string())
            .or_insert_with(|| RateState {
                current_rate: base_rate,
                request_count: 0,
                window_start: now,
                anomaly_detected: false,
                anomaly_expires: None,
                total_requests: 0,
                total_denied: 0,
            });

        // Check if the current window has expired and reset
        if now.duration_since(state.window_start) >= window_size {
            state.window_start = now;
            state.request_count = 0;
        }

        // Check if anomaly has expired and restore rate
        if state.anomaly_detected {
            if let Some(expires) = state.anomaly_expires {
                if now >= expires {
                    state.anomaly_detected = false;
                    state.anomaly_expires = None;
                    state.current_rate = base_rate;
                }
            }
        }

        // Increment counters (saturating to prevent overflow)
        state.request_count = state.request_count.saturating_add(1);
        state.total_requests = state.total_requests.saturating_add(1);

        // Compute burst ceiling. Clamp multiplier to avoid NaN/Infinity.
        let burst_multiplier = clamp_f64(self.config.burst_multiplier, 0.0, 100.0);
        let burst_ceiling = (state.current_rate as f64 * burst_multiplier) as u64;
        // Ensure burst_ceiling is at least current_rate to maintain ordering
        let burst_ceiling = burst_ceiling.max(state.current_rate);

        if state.request_count > burst_ceiling {
            state.total_denied = state.total_denied.saturating_add(1);
            RateDecision::Deny
        } else if state.request_count > state.current_rate {
            RateDecision::Throttle
        } else {
            RateDecision::Allow
        }
    }

    /// Signal an anomaly for an entity, reducing their allowed rate.
    ///
    /// The rate is reduced by the configured `anomaly_reduction_factor`.
    /// The reduction expires after `recovery_period`.
    pub fn signal_anomaly(&mut self, entity_id: &str) {
        let now = Instant::now();
        let base_rate = self.config.base_rate_per_minute;
        let reduction = clamp_f64(self.config.anomaly_reduction_factor, 0.0, 1.0);
        let recovery = self.config.recovery_period;

        let state = self
            .states
            .entry(entity_id.to_string())
            .or_insert_with(|| RateState {
                current_rate: base_rate,
                request_count: 0,
                window_start: now,
                anomaly_detected: false,
                anomaly_expires: None,
                total_requests: 0,
                total_denied: 0,
            });

        state.anomaly_detected = true;
        state.anomaly_expires = Some(now + recovery);
        // Reduce rate: multiply by reduction factor, ensure at least 1
        let reduced = (base_rate as f64 * reduction) as u64;
        state.current_rate = reduced.max(1);
    }

    /// Clear anomaly state for an entity, restoring their base rate.
    pub fn clear_anomaly(&mut self, entity_id: &str) {
        if let Some(state) = self.states.get_mut(entity_id) {
            state.anomaly_detected = false;
            state.anomaly_expires = None;
            state.current_rate = self.config.base_rate_per_minute;
        }
    }

    /// Get current state for an entity (for reporting/inspection).
    pub fn get_state(&self, entity_id: &str) -> Option<&RateState> {
        self.states.get(entity_id)
    }

    /// Remove stale entries not seen within 2x window_size.
    ///
    /// Entities whose window started more than `2 * window_size` ago
    /// and have no active anomaly are pruned.
    pub fn prune_stale(&mut self) {
        let now = Instant::now();
        let staleness_threshold = self.config.window_size * 2;
        self.states.retain(|_, state| {
            // Keep if anomaly is active
            if state.anomaly_detected {
                return true;
            }
            // Keep if window is recent
            now.duration_since(state.window_start) < staleness_threshold
        });
    }

    /// Get aggregated statistics across all tracked entities.
    pub fn stats(&self) -> RateLimiterStats {
        let mut total_requests: u64 = 0;
        let mut total_denied: u64 = 0;
        let mut anomaly_count: usize = 0;

        for state in self.states.values() {
            total_requests = total_requests.saturating_add(state.total_requests);
            total_denied = total_denied.saturating_add(state.total_denied);
            if state.anomaly_detected {
                anomaly_count = anomaly_count.saturating_add(1);
            }
        }

        RateLimiterStats {
            active_entities: self.states.len(),
            total_requests,
            total_denied,
            anomaly_count,
        }
    }
}

/// Clamp an f64 to a range, handling NaN by returning `min`.
fn clamp_f64(val: f64, min: f64, max: f64) -> f64 {
    if val.is_nan() || val.is_infinite() {
        return min;
    }
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limiter() -> AdaptiveRateLimiter {
        AdaptiveRateLimiter::new(AdaptiveRateConfig::default())
    }

    fn fast_limiter(base_rate: u64) -> AdaptiveRateLimiter {
        AdaptiveRateLimiter::new(AdaptiveRateConfig {
            base_rate_per_minute: base_rate,
            burst_multiplier: 2.0,
            anomaly_reduction_factor: 0.5,
            recovery_period: Duration::from_millis(50),
            window_size: Duration::from_millis(100),
        })
    }

    #[test]
    fn test_adaptive_rate_allow_under_limit() {
        let mut limiter = fast_limiter(10);
        for _ in 0..10 {
            assert_eq!(limiter.check("agent-1"), RateDecision::Allow);
        }
    }

    #[test]
    fn test_adaptive_rate_throttle_above_base() {
        let mut limiter = fast_limiter(5);
        // First 5 are Allow
        for _ in 0..5 {
            assert_eq!(limiter.check("agent-1"), RateDecision::Allow);
        }
        // 6th through 10th should be Throttle (between base and burst=10)
        assert_eq!(limiter.check("agent-1"), RateDecision::Throttle);
    }

    #[test]
    fn test_adaptive_rate_deny_above_burst() {
        let mut limiter = fast_limiter(5);
        // Fill up to burst ceiling (5 * 2.0 = 10)
        for _ in 0..10 {
            let _ = limiter.check("agent-1");
        }
        // 11th should be Deny
        assert_eq!(limiter.check("agent-1"), RateDecision::Deny);
    }

    #[test]
    fn test_adaptive_rate_window_reset() {
        let mut limiter = fast_limiter(5);
        // Fill to base rate
        for _ in 0..5 {
            let _ = limiter.check("agent-1");
        }
        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(120));
        // After window reset, should be Allow again
        assert_eq!(limiter.check("agent-1"), RateDecision::Allow);
    }

    #[test]
    fn test_adaptive_rate_anomaly_reduces_rate() {
        let mut limiter = fast_limiter(10);
        limiter.signal_anomaly("agent-1");
        let state = limiter.get_state("agent-1").unwrap();
        assert!(state.anomaly_detected);
        // Rate reduced to 10 * 0.5 = 5
        assert_eq!(state.current_rate, 5);
    }

    #[test]
    fn test_adaptive_rate_anomaly_expires() {
        let mut limiter = fast_limiter(10);
        limiter.signal_anomaly("agent-1");
        // Wait for recovery
        std::thread::sleep(Duration::from_millis(60));
        // Next check should restore rate
        let _ = limiter.check("agent-1");
        let state = limiter.get_state("agent-1").unwrap();
        assert!(!state.anomaly_detected);
        assert_eq!(state.current_rate, 10);
    }

    #[test]
    fn test_adaptive_rate_clear_anomaly() {
        let mut limiter = fast_limiter(10);
        limiter.signal_anomaly("agent-1");
        assert!(limiter.get_state("agent-1").unwrap().anomaly_detected);
        limiter.clear_anomaly("agent-1");
        let state = limiter.get_state("agent-1").unwrap();
        assert!(!state.anomaly_detected);
        assert_eq!(state.current_rate, 10);
    }

    #[test]
    fn test_adaptive_rate_clear_anomaly_nonexistent() {
        let mut limiter = default_limiter();
        // Should not panic on non-existent entity
        limiter.clear_anomaly("ghost");
        assert!(limiter.get_state("ghost").is_none());
    }

    #[test]
    fn test_adaptive_rate_get_state_none() {
        let limiter = default_limiter();
        assert!(limiter.get_state("unknown").is_none());
    }

    #[test]
    fn test_adaptive_rate_multiple_entities() {
        let mut limiter = fast_limiter(5);
        assert_eq!(limiter.check("a"), RateDecision::Allow);
        assert_eq!(limiter.check("b"), RateDecision::Allow);
        // Each entity has independent counters
        for _ in 0..4 {
            let _ = limiter.check("a");
        }
        // 'a' is now at 5 (base), next should throttle
        assert_eq!(limiter.check("a"), RateDecision::Throttle);
        // 'b' is still at 1, should allow
        assert_eq!(limiter.check("b"), RateDecision::Allow);
    }

    #[test]
    fn test_adaptive_rate_stats_basic() {
        let mut limiter = fast_limiter(100);
        for _ in 0..10 {
            let _ = limiter.check("e1");
        }
        for _ in 0..5 {
            let _ = limiter.check("e2");
        }
        let stats = limiter.stats();
        assert_eq!(stats.active_entities, 2);
        assert_eq!(stats.total_requests, 15);
        assert_eq!(stats.total_denied, 0);
        assert_eq!(stats.anomaly_count, 0);
    }

    #[test]
    fn test_adaptive_rate_stats_with_anomaly() {
        let mut limiter = fast_limiter(100);
        let _ = limiter.check("e1");
        limiter.signal_anomaly("e2");
        let stats = limiter.stats();
        assert_eq!(stats.anomaly_count, 1);
    }

    #[test]
    fn test_adaptive_rate_prune_stale() {
        let mut limiter = fast_limiter(100);
        let _ = limiter.check("stale");
        // Wait for 2x window
        std::thread::sleep(Duration::from_millis(210));
        limiter.prune_stale();
        assert!(limiter.get_state("stale").is_none());
    }

    #[test]
    fn test_adaptive_rate_prune_keeps_anomaly() {
        let mut limiter = fast_limiter(100);
        limiter.signal_anomaly("anomalous");
        std::thread::sleep(Duration::from_millis(210));
        limiter.prune_stale();
        // Entity with active anomaly should be retained
        assert!(limiter.get_state("anomalous").is_some());
    }

    #[test]
    fn test_adaptive_rate_saturating_counters() {
        let mut limiter = fast_limiter(u64::MAX);
        // Force state with near-max counters
        let _ = limiter.check("saturate");
        let state = limiter.states.get_mut("saturate").unwrap();
        state.total_requests = u64::MAX;
        state.request_count = u64::MAX;
        // Next check should not panic (saturating_add prevents overflow)
        let _ = limiter.check("saturate");
        let state = limiter.get_state("saturate").unwrap();
        assert_eq!(state.total_requests, u64::MAX);
    }

    #[test]
    fn test_adaptive_rate_anomaly_minimum_rate_one() {
        // Even with factor 0.0, rate should not go below 1
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateConfig {
            base_rate_per_minute: 10,
            burst_multiplier: 2.0,
            anomaly_reduction_factor: 0.0,
            recovery_period: Duration::from_secs(60),
            window_size: Duration::from_secs(60),
        });
        limiter.signal_anomaly("agent");
        let state = limiter.get_state("agent").unwrap();
        assert_eq!(state.current_rate, 1); // Minimum rate is 1, not 0
    }

    #[test]
    fn test_adaptive_rate_clamp_nan_multiplier() {
        let mut limiter = AdaptiveRateLimiter::new(AdaptiveRateConfig {
            base_rate_per_minute: 10,
            burst_multiplier: f64::NAN,
            anomaly_reduction_factor: 0.5,
            recovery_period: Duration::from_secs(60),
            window_size: Duration::from_secs(60),
        });
        // Should not panic — NaN burst_multiplier is clamped to 0.0
        for _ in 0..10 {
            let _ = limiter.check("agent");
        }
        // With burst_multiplier clamped to 0.0, burst_ceiling = max(0, 10) = 10
        // 11th request should be denied (count 11 > burst_ceiling 10)
        assert_eq!(limiter.check("agent"), RateDecision::Deny);
    }

    #[test]
    fn test_adaptive_rate_default_config() {
        let config = AdaptiveRateConfig::default();
        assert_eq!(config.base_rate_per_minute, 100);
        assert!((config.burst_multiplier - 2.0).abs() < f64::EPSILON);
        assert!((config.anomaly_reduction_factor - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.recovery_period, Duration::from_secs(300));
        assert_eq!(config.window_size, Duration::from_secs(60));
    }
}
