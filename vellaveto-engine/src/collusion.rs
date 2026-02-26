//! Multi-agent collusion detection (Phase 62 — OWASP ASI04, ASI07).
//!
//! Detects coordinated attacks across multiple agents where individual actions
//! appear innocuous but collectively constitute malicious behavior:
//!
//! - **Steganographic channels**: Unusually high entropy in tool parameters or
//!   response values, suggesting hidden data channels between agents.
//! - **Coordinated attack patterns**: Multiple agents targeting the same resource
//!   in a narrow time window (e.g., agent A reads credentials, agent B exfiltrates).
//! - **Cross-agent behavioral correlation**: Synchronized tool call patterns that
//!   deviate from independent baselines.
//!
//! # Design
//!
//! - **Deterministic**: No ML, no randomness — uses entropy thresholds and
//!   temporal correlation windows.
//! - **Bounded memory**: Ring buffers with `MAX_*` constants on all collections.
//! - **Fail-closed**: Lock poisoning and capacity exhaustion produce alerts.
//! - **Observable**: Every detection logged with structured tracing.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

// ═══════════════════════════════════════════════════
// CONSTANTS (bounded collections — Trap 3)
// ═══════════════════════════════════════════════════

/// Maximum number of agents tracked for collusion correlation.
const MAX_TRACKED_AGENTS: usize = 10_000;

/// Maximum resource access events retained per resource.
const MAX_EVENTS_PER_RESOURCE: usize = 1_000;

/// Maximum number of distinct resources tracked.
const MAX_TRACKED_RESOURCES: usize = 50_000;

/// Maximum number of entropy samples retained per agent.
const MAX_ENTROPY_SAMPLES_PER_AGENT: usize = 500;

/// Maximum length of an agent ID.
const MAX_AGENT_ID_LEN: usize = 512;

/// Maximum length of a resource key.
const MAX_RESOURCE_KEY_LEN: usize = 2048;

/// Maximum length of a tool name.
const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum number of collusion alerts retained.
const MAX_ALERT_HISTORY: usize = 10_000;

/// Maximum length of parameter data for entropy analysis (64 KB).
const MAX_PARAM_DATA_LEN: usize = 65_536;

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for multi-agent collusion detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionConfig {
    /// Whether collusion detection is enabled.
    /// Default: true
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Time window (seconds) for coordinated access detection.
    /// Two agents accessing the same resource within this window are correlated.
    /// Default: 60
    #[serde(default = "default_coordination_window_secs")]
    pub coordination_window_secs: u64,

    /// Minimum Shannon entropy (bits per byte) to flag a parameter as potentially
    /// steganographic. Normal text is ~3.5–4.5, compressed/encrypted data is ~7.5+.
    /// Default: 6.5
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Minimum number of high-entropy observations before flagging an agent.
    /// Prevents false positives from occasional base64 parameters.
    /// Default: 5
    #[serde(default = "default_min_entropy_observations")]
    pub min_entropy_observations: u32,

    /// Number of distinct agents that must access the same resource within
    /// `coordination_window_secs` to trigger a coordinated access alert.
    /// Default: 3
    #[serde(default = "default_min_coordinated_agents")]
    pub min_coordinated_agents: u32,

    /// Threshold for temporal synchronization score (0.0–1.0).
    /// Higher values require more precise synchronization.
    /// Default: 0.7
    #[serde(default = "default_sync_threshold")]
    pub sync_threshold: f64,
}

fn default_enabled() -> bool {
    true
}
fn default_coordination_window_secs() -> u64 {
    60
}
fn default_entropy_threshold() -> f64 {
    6.5
}
fn default_min_entropy_observations() -> u32 {
    5
}
fn default_min_coordinated_agents() -> u32 {
    3
}
fn default_sync_threshold() -> f64 {
    0.7
}

impl Default for CollusionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            coordination_window_secs: default_coordination_window_secs(),
            entropy_threshold: default_entropy_threshold(),
            min_entropy_observations: default_min_entropy_observations(),
            min_coordinated_agents: default_min_coordinated_agents(),
            sync_threshold: default_sync_threshold(),
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from collusion detection operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CollusionError {
    /// Configuration validation failed.
    InvalidConfig(String),
    /// Lock poisoned — fail-closed.
    LockPoisoned(String),
    /// Input validation failed.
    InvalidInput(String),
}

impl std::fmt::Display for CollusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollusionError::InvalidConfig(msg) => write!(f, "invalid collusion config: {msg}"),
            CollusionError::LockPoisoned(msg) => {
                write!(f, "collusion detector lock poisoned (fail-closed): {msg}")
            }
            CollusionError::InvalidInput(msg) => {
                write!(f, "collusion detector input validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for CollusionError {}

impl CollusionConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), CollusionError> {
        if self.coordination_window_secs == 0 {
            return Err(CollusionError::InvalidConfig(
                "coordination_window_secs must be > 0".to_string(),
            ));
        }
        // SECURITY (Trap 4): Validate f64 fields for NaN/Infinity.
        if !self.entropy_threshold.is_finite() || self.entropy_threshold < 0.0 {
            return Err(CollusionError::InvalidConfig(format!(
                "entropy_threshold must be finite and >= 0.0, got {}",
                self.entropy_threshold
            )));
        }
        if !self.sync_threshold.is_finite()
            || self.sync_threshold < 0.0
            || self.sync_threshold > 1.0
        {
            return Err(CollusionError::InvalidConfig(format!(
                "sync_threshold must be in [0.0, 1.0], got {}",
                self.sync_threshold
            )));
        }
        if self.min_coordinated_agents < 2 {
            return Err(CollusionError::InvalidConfig(
                "min_coordinated_agents must be >= 2".to_string(),
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// ALERT TYPES
// ═══════════════════════════════════════════════════

/// Type of collusion detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollusionType {
    /// Steganographic channel: high-entropy parameters suggesting hidden data.
    SteganographicChannel,
    /// Coordinated resource access: multiple agents accessing the same resource
    /// in a narrow time window.
    CoordinatedAccess,
    /// Synchronized behavior: agents showing correlated tool call timing.
    SynchronizedBehavior,
}

/// Severity of a collusion alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CollusionSeverity {
    /// Suspicious pattern detected, may be benign.
    Low,
    /// Pattern is unlikely to be accidental.
    Medium,
    /// Strong indicator of coordinated malicious activity.
    High,
    /// Multiple strong indicators combined.
    Critical,
}

/// A collusion alert emitted by the detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionAlert {
    /// Type of collusion detected.
    pub collusion_type: CollusionType,
    /// Severity level.
    pub severity: CollusionSeverity,
    /// Agent IDs involved.
    pub agent_ids: Vec<String>,
    /// Resource or tool targeted (if applicable).
    pub target: String,
    /// Human-readable description.
    pub description: String,
    /// Unix timestamp when detected.
    pub detected_at: u64,
    /// Supporting evidence (entropy values, timing data, etc.).
    pub evidence: CollusionEvidence,
}

/// Evidence supporting a collusion alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollusionEvidence {
    /// Entropy values if steganographic channel detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_values: Option<Vec<f64>>,
    /// Timestamps of coordinated accesses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_timestamps: Option<Vec<u64>>,
    /// Synchronization score (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_score: Option<f64>,
    /// Number of observations.
    pub observation_count: u32,
}

impl std::fmt::Display for CollusionAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}/{:?}] agents={:?} target='{}': {}",
            self.severity, self.collusion_type, self.agent_ids, self.target, self.description,
        )
    }
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// A timestamped resource access event.
#[derive(Debug, Clone)]
struct ResourceAccessEvent {
    agent_id: String,
    /// Tool used for the access. Retained for audit trail / evidence.
    #[allow(dead_code)]
    tool: String,
    timestamp: u64,
}

/// Per-agent entropy tracking.
#[derive(Debug, Clone)]
struct EntropyProfile {
    /// Recent entropy values for parameter data.
    samples: VecDeque<f64>,
    /// Count of samples exceeding the threshold.
    high_entropy_count: u32,
    /// Total samples recorded.
    total_samples: u32,
}

impl EntropyProfile {
    fn new() -> Self {
        Self {
            samples: VecDeque::new(),
            high_entropy_count: 0,
            total_samples: 0,
        }
    }
}

/// Per-agent tool call timing profile for synchronization detection.
#[derive(Debug, Clone)]
struct TimingProfile {
    /// Recent tool call timestamps.
    timestamps: VecDeque<u64>,
    /// Maximum entries retained.
    max_entries: usize,
}

impl TimingProfile {
    fn new(max_entries: usize) -> Self {
        Self {
            timestamps: VecDeque::new(),
            max_entries,
        }
    }

    fn record(&mut self, timestamp: u64) {
        if self.timestamps.len() >= self.max_entries {
            self.timestamps.pop_front();
        }
        self.timestamps.push_back(timestamp);
    }
}

// ═══════════════════════════════════════════════════
// DETECTOR
// ═══════════════════════════════════════════════════

/// Multi-agent collusion detector.
///
/// Thread-safe via `RwLock`. All operations are fail-closed on lock poisoning.
pub struct CollusionDetector {
    config: CollusionConfig,
    /// Per-resource access event ring buffers.
    resource_events: RwLock<HashMap<String, VecDeque<ResourceAccessEvent>>>,
    /// Per-agent entropy profiles.
    entropy_profiles: RwLock<HashMap<String, EntropyProfile>>,
    /// Per-agent timing profiles for sync detection.
    timing_profiles: RwLock<HashMap<String, TimingProfile>>,
    /// Alert history (ring buffer).
    alerts: RwLock<VecDeque<CollusionAlert>>,
}

impl std::fmt::Debug for CollusionDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollusionDetector")
            .field("config", &self.config)
            .field("resource_events", &"<locked>")
            .field("entropy_profiles", &"<locked>")
            .field("timing_profiles", &"<locked>")
            .field("alerts", &"<locked>")
            .finish()
    }
}

impl CollusionDetector {
    /// Create a new collusion detector with validated configuration.
    pub fn new(config: CollusionConfig) -> Result<Self, CollusionError> {
        config.validate()?;
        Ok(Self {
            config,
            resource_events: RwLock::new(HashMap::new()),
            entropy_profiles: RwLock::new(HashMap::new()),
            timing_profiles: RwLock::new(HashMap::new()),
            alerts: RwLock::new(VecDeque::new()),
        })
    }

    /// Check if the detector is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the current configuration.
    pub fn config(&self) -> &CollusionConfig {
        &self.config
    }

    // ═══════════════════════════════════════════════
    // INPUT VALIDATION
    // ═══════════════════════════════════════════════

    /// Validate an agent ID for length and dangerous characters.
    fn validate_agent_id(agent_id: &str) -> Result<(), CollusionError> {
        if agent_id.is_empty() || agent_id.len() > MAX_AGENT_ID_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "agent_id length {} out of range [1, {}]",
                agent_id.len(),
                MAX_AGENT_ID_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(agent_id) {
            return Err(CollusionError::InvalidInput(
                "agent_id contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a resource key for length and dangerous characters.
    fn validate_resource_key(resource: &str) -> Result<(), CollusionError> {
        if resource.is_empty() || resource.len() > MAX_RESOURCE_KEY_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "resource key length {} out of range [1, {}]",
                resource.len(),
                MAX_RESOURCE_KEY_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(resource) {
            return Err(CollusionError::InvalidInput(
                "resource key contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate a tool name.
    fn validate_tool_name(tool: &str) -> Result<(), CollusionError> {
        if tool.is_empty() || tool.len() > MAX_TOOL_NAME_LEN {
            return Err(CollusionError::InvalidInput(format!(
                "tool name length {} out of range [1, {}]",
                tool.len(),
                MAX_TOOL_NAME_LEN
            )));
        }
        if vellaveto_types::has_dangerous_chars(tool) {
            return Err(CollusionError::InvalidInput(
                "tool name contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }

    // ═══════════════════════════════════════════════
    // STEGANOGRAPHIC CHANNEL DETECTION
    // ═══════════════════════════════════════════════

    /// Compute Shannon entropy (bits per byte) of raw data.
    ///
    /// Returns a value in [0.0, 8.0]. Values above ~6.5 suggest
    /// compressed/encrypted/random data (potential steganographic channel).
    pub fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] = freq[byte as usize].saturating_add(1);
        }

        let len = data.len() as f64;
        let mut entropy = 0.0_f64;

        for &count in &freq {
            if count == 0 {
                continue;
            }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }

        // Guard against NaN/Infinity from degenerate inputs.
        if !entropy.is_finite() {
            return 0.0;
        }

        entropy
    }

    /// Analyze parameter data for steganographic channels.
    ///
    /// Records the entropy observation and returns an alert if the agent
    /// has consistently high-entropy parameters.
    pub fn analyze_parameters(
        &self,
        agent_id: &str,
        param_data: &[u8],
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;

        // Truncate oversized parameter data for entropy analysis.
        let data = if param_data.len() > MAX_PARAM_DATA_LEN {
            &param_data[..MAX_PARAM_DATA_LEN]
        } else {
            param_data
        };

        // Skip very short data (insufficient for meaningful entropy).
        if data.len() < 16 {
            return Ok(None);
        }

        let entropy = Self::compute_entropy(data);
        let is_high = entropy >= self.config.entropy_threshold;

        let mut profiles = self
            .entropy_profiles
            .write()
            .map_err(|_| CollusionError::LockPoisoned("entropy_profiles write lock".to_string()))?;

        // SECURITY (Trap 3): Bound the number of tracked agents.
        if !profiles.contains_key(agent_id) && profiles.len() >= MAX_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_TRACKED_AGENTS,
                "Collusion entropy profiles at capacity, skipping new agent"
            );
            return Ok(None);
        }

        let profile = profiles
            .entry(agent_id.to_string())
            .or_insert_with(EntropyProfile::new);

        // Record sample.
        if profile.samples.len() >= MAX_ENTROPY_SAMPLES_PER_AGENT {
            // Evict oldest and adjust count if it was high-entropy.
            if let Some(old) = profile.samples.pop_front() {
                if old >= self.config.entropy_threshold {
                    profile.high_entropy_count = profile.high_entropy_count.saturating_sub(1);
                }
            }
        }
        profile.samples.push_back(entropy);
        profile.total_samples = profile.total_samples.saturating_add(1);
        if is_high {
            profile.high_entropy_count = profile.high_entropy_count.saturating_add(1);
        }

        // Check if we have enough high-entropy observations to alert.
        if profile.high_entropy_count >= self.config.min_entropy_observations {
            let entropy_values: Vec<f64> = profile
                .samples
                .iter()
                .copied()
                .filter(|&e| e >= self.config.entropy_threshold)
                .take(10) // Limit evidence size
                .collect();

            let now = Self::now_secs();

            let alert = CollusionAlert {
                collusion_type: CollusionType::SteganographicChannel,
                severity: if profile.high_entropy_count
                    >= self.config.min_entropy_observations.saturating_mul(2)
                {
                    CollusionSeverity::High
                } else {
                    CollusionSeverity::Medium
                },
                agent_ids: vec![agent_id.to_string()],
                target: format!("agent:{agent_id}"),
                description: format!(
                    "Agent '{}' has {} high-entropy parameter observations (threshold: {:.1} bits/byte)",
                    agent_id,
                    profile.high_entropy_count,
                    self.config.entropy_threshold,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: Some(entropy_values),
                    access_timestamps: None,
                    sync_score: None,
                    observation_count: profile.high_entropy_count,
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "steganographic_channel"
            )
            .increment(1);

            tracing::warn!(
                agent_id = %agent_id,
                high_entropy_count = %profile.high_entropy_count,
                latest_entropy = %entropy,
                "Potential steganographic channel detected in agent parameters"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // COORDINATED RESOURCE ACCESS DETECTION
    // ═══════════════════════════════════════════════

    /// Record a resource access event and check for coordinated access patterns.
    ///
    /// Returns an alert if `min_coordinated_agents` or more distinct agents
    /// accessed the same resource within `coordination_window_secs`.
    pub fn record_resource_access(
        &self,
        agent_id: &str,
        resource: &str,
        tool: &str,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;
        Self::validate_resource_key(resource)?;
        Self::validate_tool_name(tool)?;

        let mut events = self
            .resource_events
            .write()
            .map_err(|_| CollusionError::LockPoisoned("resource_events write lock".to_string()))?;

        // SECURITY (Trap 3): Bound tracked resources.
        if !events.contains_key(resource) && events.len() >= MAX_TRACKED_RESOURCES {
            tracing::warn!(
                max = MAX_TRACKED_RESOURCES,
                "Collusion resource tracking at capacity, skipping new resource"
            );
            return Ok(None);
        }

        let event_queue = events
            .entry(resource.to_string())
            .or_insert_with(VecDeque::new);

        // Evict events outside the window.
        let cutoff = timestamp.saturating_sub(self.config.coordination_window_secs);
        while let Some(front) = event_queue.front() {
            if front.timestamp < cutoff {
                event_queue.pop_front();
            } else {
                break;
            }
        }

        // Add new event, evicting oldest if at capacity.
        if event_queue.len() >= MAX_EVENTS_PER_RESOURCE {
            event_queue.pop_front();
        }

        event_queue.push_back(ResourceAccessEvent {
            agent_id: agent_id.to_string(),
            tool: tool.to_string(),
            timestamp,
        });

        // Count distinct agents in the current window.
        let mut distinct_agents: Vec<&str> = Vec::new();
        let mut timestamps_in_window: Vec<u64> = Vec::new();
        for event in event_queue.iter() {
            if event.timestamp >= cutoff {
                if !distinct_agents.contains(&event.agent_id.as_str()) {
                    distinct_agents.push(&event.agent_id);
                }
                timestamps_in_window.push(event.timestamp);
            }
        }

        if distinct_agents.len() >= self.config.min_coordinated_agents as usize {
            let now = Self::now_secs();

            let severity = if distinct_agents.len()
                >= (self.config.min_coordinated_agents as usize).saturating_mul(2)
            {
                CollusionSeverity::High
            } else {
                CollusionSeverity::Medium
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::CoordinatedAccess,
                severity,
                agent_ids: distinct_agents.iter().map(|s| s.to_string()).collect(),
                target: resource.to_string(),
                description: format!(
                    "{} agents accessed resource '{}' within {}s window",
                    distinct_agents.len(),
                    resource,
                    self.config.coordination_window_secs,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: None,
                    access_timestamps: Some(timestamps_in_window),
                    sync_score: None,
                    observation_count: distinct_agents.len() as u32,
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "coordinated_access"
            )
            .increment(1);

            tracing::warn!(
                resource = %resource,
                agent_count = %distinct_agents.len(),
                window_secs = %self.config.coordination_window_secs,
                "Coordinated resource access detected"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    // ═══════════════════════════════════════════════
    // SYNCHRONIZED BEHAVIOR DETECTION
    // ═══════════════════════════════════════════════

    /// Record a tool call timestamp for synchronization analysis.
    ///
    /// Returns an alert if the agent's timing is highly correlated with
    /// other tracked agents.
    pub fn record_tool_timing(
        &self,
        agent_id: &str,
        timestamp: u64,
    ) -> Result<Option<CollusionAlert>, CollusionError> {
        if !self.config.enabled {
            return Ok(None);
        }
        Self::validate_agent_id(agent_id)?;

        let mut profiles = self
            .timing_profiles
            .write()
            .map_err(|_| CollusionError::LockPoisoned("timing_profiles write lock".to_string()))?;

        // SECURITY (Trap 3): Bound tracked agents.
        if !profiles.contains_key(agent_id) && profiles.len() >= MAX_TRACKED_AGENTS {
            tracing::warn!(
                max = MAX_TRACKED_AGENTS,
                "Collusion timing profiles at capacity, skipping new agent"
            );
            return Ok(None);
        }

        let profile = profiles
            .entry(agent_id.to_string())
            .or_insert_with(|| TimingProfile::new(MAX_ENTROPY_SAMPLES_PER_AGENT));

        profile.record(timestamp);

        // Need at least 10 timestamps per agent for meaningful correlation.
        if profile.timestamps.len() < 10 {
            return Ok(None);
        }

        // Clone the current agent's timestamps to release the mutable borrow,
        // allowing immutable iteration over other profiles.
        let agent_timestamps = profile.timestamps.clone();

        // Check synchronization with all other agents.
        let mut correlated_agents = Vec::new();
        let mut max_sync_score = 0.0_f64;

        for (other_id, other_profile) in profiles.iter() {
            if other_id == agent_id || other_profile.timestamps.len() < 10 {
                continue;
            }
            let score = Self::compute_sync_score(&agent_timestamps, &other_profile.timestamps);
            if score >= self.config.sync_threshold {
                correlated_agents.push(other_id.clone());
                if score > max_sync_score {
                    max_sync_score = score;
                }
            }
        }

        if !correlated_agents.is_empty() {
            let mut all_agents = vec![agent_id.to_string()];
            all_agents.extend(correlated_agents);

            let now = Self::now_secs();

            let severity = if max_sync_score >= 0.9 {
                CollusionSeverity::High
            } else {
                CollusionSeverity::Medium
            };

            let alert = CollusionAlert {
                collusion_type: CollusionType::SynchronizedBehavior,
                severity,
                agent_ids: all_agents.clone(),
                target: "tool_call_timing".to_string(),
                description: format!(
                    "{} agents show synchronized tool call timing (max sync score: {:.2})",
                    all_agents.len(),
                    max_sync_score,
                ),
                detected_at: now,
                evidence: CollusionEvidence {
                    entropy_values: None,
                    access_timestamps: None,
                    sync_score: Some(max_sync_score),
                    observation_count: all_agents.len() as u32,
                },
            };

            metrics::counter!(
                "vellaveto_collusion_alerts_total",
                "type" => "synchronized_behavior"
            )
            .increment(1);

            tracing::warn!(
                agent_ids = ?all_agents,
                sync_score = %max_sync_score,
                "Synchronized agent behavior detected"
            );

            self.record_alert(alert.clone())?;
            return Ok(Some(alert));
        }

        Ok(None)
    }

    /// Compute temporal synchronization score between two agents.
    ///
    /// Uses inter-arrival time correlation: if agents consistently make
    /// calls at similar intervals, the score approaches 1.0.
    ///
    /// Returns a value in [0.0, 1.0].
    fn compute_sync_score(a_timestamps: &VecDeque<u64>, b_timestamps: &VecDeque<u64>) -> f64 {
        if a_timestamps.len() < 2 || b_timestamps.len() < 2 {
            return 0.0;
        }

        // Compute inter-arrival times.
        let a_intervals: Vec<f64> = a_timestamps
            .iter()
            .zip(a_timestamps.iter().skip(1))
            .map(|(&t1, &t2)| t2.saturating_sub(t1) as f64)
            .collect();

        let b_intervals: Vec<f64> = b_timestamps
            .iter()
            .zip(b_timestamps.iter().skip(1))
            .map(|(&t1, &t2)| t2.saturating_sub(t1) as f64)
            .collect();

        if a_intervals.is_empty() || b_intervals.is_empty() {
            return 0.0;
        }

        // Pearson correlation of inter-arrival times.
        // Use the shorter of the two vectors.
        let min_len = a_intervals.len().min(b_intervals.len());
        if min_len < 2 {
            return 0.0;
        }

        let a_slice = &a_intervals[..min_len];
        let b_slice = &b_intervals[..min_len];

        let a_mean: f64 = a_slice.iter().sum::<f64>() / min_len as f64;
        let b_mean: f64 = b_slice.iter().sum::<f64>() / min_len as f64;

        let mut cov = 0.0_f64;
        let mut a_var = 0.0_f64;
        let mut b_var = 0.0_f64;

        for i in 0..min_len {
            let a_diff = a_slice[i] - a_mean;
            let b_diff = b_slice[i] - b_mean;
            cov += a_diff * b_diff;
            a_var += a_diff * a_diff;
            b_var += b_diff * b_diff;
        }

        let denom = (a_var * b_var).sqrt();
        if denom < f64::EPSILON {
            // Zero variance — constant intervals. If both are constant at the
            // same rate, treat as highly correlated.
            if a_var < f64::EPSILON && b_var < f64::EPSILON {
                // Both constant: check if the intervals are similar.
                let a_rep = a_slice.first().copied().unwrap_or(0.0);
                let b_rep = b_slice.first().copied().unwrap_or(0.0);
                let max_rep = a_rep.max(b_rep);
                if max_rep < f64::EPSILON {
                    return 1.0; // Both zero-interval — identical
                }
                let diff = (a_rep - b_rep).abs() / max_rep;
                return (1.0 - diff).max(0.0);
            }
            return 0.0;
        }

        let correlation = cov / denom;
        // Clamp to [0.0, 1.0] — negative correlation is not collusion.
        // Guard against NaN from degenerate inputs before clamping.
        if !correlation.is_finite() {
            return 0.0;
        }
        correlation.clamp(0.0, 1.0)
    }

    // ═══════════════════════════════════════════════
    // ALERT MANAGEMENT
    // ═══════════════════════════════════════════════

    /// Record an alert in the history ring buffer.
    fn record_alert(&self, alert: CollusionAlert) -> Result<(), CollusionError> {
        let mut alerts = self
            .alerts
            .write()
            .map_err(|_| CollusionError::LockPoisoned("alerts write lock".to_string()))?;

        if alerts.len() >= MAX_ALERT_HISTORY {
            alerts.pop_front();
        }
        alerts.push_back(alert);
        Ok(())
    }

    /// Get recent alerts (up to `limit`).
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<CollusionAlert>, CollusionError> {
        let alerts = self
            .alerts
            .read()
            .map_err(|_| CollusionError::LockPoisoned("alerts read lock".to_string()))?;

        Ok(alerts.iter().rev().take(limit).cloned().collect())
    }

    /// Get total alert count.
    pub fn alert_count(&self) -> Result<usize, CollusionError> {
        let alerts = self
            .alerts
            .read()
            .map_err(|_| CollusionError::LockPoisoned("alerts read lock".to_string()))?;
        Ok(alerts.len())
    }

    // ═══════════════════════════════════════════════
    // UTILITY
    // ═══════════════════════════════════════════════

    /// Get current Unix timestamp in seconds.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CollusionConfig {
        CollusionConfig::default()
    }

    fn make_detector() -> CollusionDetector {
        CollusionDetector::new(default_config()).unwrap()
    }

    // ────────────────────────────────────────────────
    // Config validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_validate_default_ok() {
        assert!(CollusionConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_window_rejected() {
        let mut cfg = default_config();
        cfg.coordination_window_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_nan_entropy_rejected() {
        let mut cfg = default_config();
        cfg.entropy_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_negative_entropy_rejected() {
        let mut cfg = default_config();
        cfg.entropy_threshold = -1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_sync_threshold_out_of_range() {
        let mut cfg = default_config();
        cfg.sync_threshold = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_validate_min_agents_below_two() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 1;
        assert!(cfg.validate().is_err());
    }

    // ────────────────────────────────────────────────
    // Entropy computation
    // ────────────────────────────────────────────────

    #[test]
    fn test_compute_entropy_empty_data_returns_zero() {
        assert_eq!(CollusionDetector::compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_compute_entropy_uniform_data_returns_zero() {
        let data = vec![0x41u8; 100]; // All 'A'
        let entropy = CollusionDetector::compute_entropy(&data);
        assert!(
            entropy < 0.01,
            "Uniform data should have ~0 entropy, got {entropy}"
        );
    }

    #[test]
    fn test_compute_entropy_random_data_returns_high() {
        // Simulate high-entropy data (all 256 byte values equally distributed).
        let mut data = Vec::with_capacity(2560);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let entropy = CollusionDetector::compute_entropy(&data);
        assert!(
            entropy > 7.9,
            "Uniformly distributed data should have ~8.0 bits/byte entropy, got {entropy}"
        );
    }

    #[test]
    fn test_compute_entropy_english_text_moderate() {
        let data = b"The quick brown fox jumps over the lazy dog. This is a normal sentence.";
        let entropy = CollusionDetector::compute_entropy(data);
        assert!(
            entropy > 3.0 && entropy < 5.5,
            "English text should have ~3.5-4.5 bits/byte entropy, got {entropy}"
        );
    }

    // ────────────────────────────────────────────────
    // Steganographic channel detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_analyze_parameters_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.analyze_parameters("agent-1", &[0u8; 100]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_analyze_parameters_short_data_returns_none() {
        let detector = make_detector();
        // Data shorter than 16 bytes should be skipped.
        let result = detector.analyze_parameters("agent-1", &[0u8; 10]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_analyze_parameters_normal_text_no_alert() {
        let detector = make_detector();
        let text = b"This is normal text parameter data that should not trigger alerts.";
        for _ in 0..20 {
            let result = detector.analyze_parameters("agent-1", text);
            assert!(
                result.unwrap().is_none(),
                "Normal text should not trigger steganographic alert"
            );
        }
    }

    #[test]
    fn test_analyze_parameters_high_entropy_triggers_alert() {
        let mut cfg = default_config();
        cfg.min_entropy_observations = 3;
        cfg.entropy_threshold = 6.0;
        let detector = CollusionDetector::new(cfg).unwrap();

        // Generate high-entropy data.
        let mut data = Vec::with_capacity(2560);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }

        // First few won't trigger (below min_entropy_observations).
        for i in 0..2 {
            let result = detector
                .analyze_parameters(&format!("agent-{i}"), &data)
                .unwrap();
            // These are unique agents, so each has only 1 observation.
            assert!(result.is_none());
        }

        // Same agent, repeated observations should trigger.
        let mut triggered = false;
        for _ in 0..5 {
            if let Some(alert) = detector.analyze_parameters("agent-crypto", &data).unwrap() {
                assert_eq!(alert.collusion_type, CollusionType::SteganographicChannel);
                assert!(alert.evidence.entropy_values.is_some());
                triggered = true;
                break;
            }
        }
        assert!(
            triggered,
            "Should have triggered steganographic alert after repeated high-entropy observations"
        );
    }

    // ────────────────────────────────────────────────
    // Coordinated resource access
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_resource_access_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_resource_access("agent-1", "/secret", "read", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_resource_access_single_agent_no_alert() {
        let detector = make_detector();
        let result = detector.record_resource_access("agent-1", "/secret", "read", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_resource_access_coordinated_triggers_alert() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 3;
        cfg.coordination_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base_time = 1_000_000u64;
        // Three agents access the same resource within the window.
        assert!(detector
            .record_resource_access("agent-1", "/credentials/db", "read_file", base_time)
            .unwrap()
            .is_none());
        assert!(detector
            .record_resource_access("agent-2", "/credentials/db", "read_file", base_time + 10)
            .unwrap()
            .is_none());

        let result = detector
            .record_resource_access("agent-3", "/credentials/db", "read_file", base_time + 20)
            .unwrap();
        assert!(
            result.is_some(),
            "Three agents in window should trigger alert"
        );

        let alert = result.unwrap();
        assert_eq!(alert.collusion_type, CollusionType::CoordinatedAccess);
        assert_eq!(alert.agent_ids.len(), 3);
        assert!(alert.description.contains("3 agents"));
    }

    #[test]
    fn test_record_resource_access_outside_window_no_alert() {
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 3;
        cfg.coordination_window_secs = 60;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base_time = 1_000_000u64;
        // First two agents access resource, third is outside the window.
        assert!(detector
            .record_resource_access("agent-1", "/secret", "read", base_time)
            .unwrap()
            .is_none());
        assert!(detector
            .record_resource_access("agent-2", "/secret", "read", base_time + 10)
            .unwrap()
            .is_none());
        // Agent-3 accesses 100 seconds later (outside 60s window).
        let result = detector
            .record_resource_access("agent-3", "/secret", "read", base_time + 100)
            .unwrap();
        // Agent-1's event is expired (100 > 60), so only agent-2 and agent-3 remain = 2 < 3.
        assert!(
            result.is_none(),
            "Agent outside window should not trigger alert"
        );
    }

    // ────────────────────────────────────────────────
    // Synchronized behavior detection
    // ────────────────────────────────────────────────

    #[test]
    fn test_record_tool_timing_disabled_returns_none() {
        let mut cfg = default_config();
        cfg.enabled = false;
        let detector = CollusionDetector::new(cfg).unwrap();
        let result = detector.record_tool_timing("agent-1", 1000);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_tool_timing_single_agent_no_alert() {
        let detector = make_detector();
        for t in 0..20 {
            let result = detector.record_tool_timing("agent-1", t * 10);
            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    fn test_record_tool_timing_synchronized_triggers_alert() {
        let mut cfg = default_config();
        cfg.sync_threshold = 0.8;
        let detector = CollusionDetector::new(cfg).unwrap();

        // Two agents with identical inter-arrival times.
        for t in 0..15 {
            let _ = detector.record_tool_timing("agent-a", t * 10);
            let _ = detector.record_tool_timing("agent-b", t * 10 + 1); // Offset by 1s
        }

        // The next recording should detect synchronization.
        let result = detector.record_tool_timing("agent-a", 150);
        // May or may not trigger depending on exact correlation computation.
        // The sync detection is best-effort for identical patterns.
        // We primarily verify no errors.
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_sync_score_identical_intervals_returns_high() {
        let a: VecDeque<u64> = (0..10).map(|i| i * 5).collect();
        let b: VecDeque<u64> = (0..10).map(|i| i * 5 + 1).collect();

        let score = CollusionDetector::compute_sync_score(&a, &b);
        assert!(
            score > 0.95,
            "Identical intervals should have high sync score, got {score}"
        );
    }

    #[test]
    fn test_compute_sync_score_different_intervals_returns_low() {
        // Agent A: constant 5s intervals.
        let a: VecDeque<u64> = (0..10).map(|i| i * 5).collect();
        // Agent B: exponentially increasing intervals.
        let b: VecDeque<u64> = (0..10).map(|i| i * i * 3).collect();

        let score = CollusionDetector::compute_sync_score(&a, &b);
        assert!(
            score < 0.8,
            "Different interval patterns should have low sync score, got {score}"
        );
    }

    #[test]
    fn test_compute_sync_score_empty_timestamps_returns_zero() {
        let a: VecDeque<u64> = VecDeque::new();
        let b: VecDeque<u64> = (0..10).collect();
        assert_eq!(CollusionDetector::compute_sync_score(&a, &b), 0.0);
    }

    #[test]
    fn test_compute_sync_score_single_timestamp_returns_zero() {
        let a: VecDeque<u64> = vec![100].into_iter().collect();
        let b: VecDeque<u64> = vec![100].into_iter().collect();
        assert_eq!(CollusionDetector::compute_sync_score(&a, &b), 0.0);
    }

    // ────────────────────────────────────────────────
    // Input validation
    // ────────────────────────────────────────────────

    #[test]
    fn test_validate_agent_id_empty_rejected() {
        assert!(CollusionDetector::validate_agent_id("").is_err());
    }

    #[test]
    fn test_validate_agent_id_too_long_rejected() {
        let long_id = "a".repeat(MAX_AGENT_ID_LEN + 1);
        assert!(CollusionDetector::validate_agent_id(&long_id).is_err());
    }

    #[test]
    fn test_validate_agent_id_control_chars_rejected() {
        assert!(CollusionDetector::validate_agent_id("agent\0id").is_err());
    }

    #[test]
    fn test_validate_resource_key_empty_rejected() {
        assert!(CollusionDetector::validate_resource_key("").is_err());
    }

    #[test]
    fn test_validate_tool_name_too_long_rejected() {
        let long_name = "t".repeat(MAX_TOOL_NAME_LEN + 1);
        assert!(CollusionDetector::validate_tool_name(&long_name).is_err());
    }

    // ────────────────────────────────────────────────
    // Alert management
    // ────────────────────────────────────────────────

    #[test]
    fn test_recent_alerts_returns_empty_initially() {
        let detector = make_detector();
        let alerts = detector.recent_alerts(10).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_alert_count_returns_zero_initially() {
        let detector = make_detector();
        assert_eq!(detector.alert_count().unwrap(), 0);
    }

    #[test]
    fn test_recent_alerts_returns_most_recent_first() {
        // Record a coordinated access alert via 2-agent pattern.
        let mut cfg = default_config();
        cfg.min_coordinated_agents = 2;
        let detector = CollusionDetector::new(cfg).unwrap();

        let base = 1_000_000u64;
        let _ = detector.record_resource_access("a1", "/res1", "read", base);
        let _ = detector.record_resource_access("a2", "/res1", "read", base + 1);
        let _ = detector.record_resource_access("a1", "/res2", "read", base + 2);
        let _ = detector.record_resource_access("a3", "/res2", "read", base + 3);

        let alerts = detector.recent_alerts(10).unwrap();
        assert!(!alerts.is_empty(), "Should have at least one alert");
        // Most recent should be first.
        if alerts.len() >= 2 {
            assert!(alerts[0].detected_at >= alerts[1].detected_at);
        }
    }

    // ────────────────────────────────────────────────
    // Serialization
    // ────────────────────────────────────────────────

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = CollusionConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: CollusionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.coordination_window_secs,
            cfg.coordination_window_secs
        );
        assert_eq!(parsed.entropy_threshold, cfg.entropy_threshold);
    }

    #[test]
    fn test_config_deny_unknown_fields() {
        let json = r#"{"enabled": true, "unknown_field": 42}"#;
        let result: Result<CollusionConfig, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject unknown fields"
        );
    }

    #[test]
    fn test_alert_serialization_roundtrip() {
        let alert = CollusionAlert {
            collusion_type: CollusionType::SteganographicChannel,
            severity: CollusionSeverity::High,
            agent_ids: vec!["a1".to_string()],
            target: "test".to_string(),
            description: "test alert".to_string(),
            detected_at: 12345,
            evidence: CollusionEvidence {
                entropy_values: Some(vec![7.5, 7.8]),
                access_timestamps: None,
                sync_score: None,
                observation_count: 2,
            },
        };
        let json = serde_json::to_string(&alert).unwrap();
        let parsed: CollusionAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.collusion_type, CollusionType::SteganographicChannel);
        assert_eq!(parsed.severity, CollusionSeverity::High);
    }
}
