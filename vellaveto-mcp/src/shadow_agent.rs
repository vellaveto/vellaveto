//! Shadow agent detection.
//!
//! Detects when an unknown agent claims to be a known agent, indicating
//! potential impersonation or shadow agent attack. Fingerprints agents
//! based on JWT claims, client ID, and IP hash.
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::shadow_agent::ShadowAgentDetector;
//! use vellaveto_types::AgentFingerprint;
//!
//! let detector = ShadowAgentDetector::new(10000);
//!
//! // Register a known agent
//! let fingerprint = AgentFingerprint {
//!     jwt_sub: Some("agent-123".to_string()),
//!     jwt_iss: Some("https://auth.example.com".to_string()),
//!     ..Default::default()
//! };
//! detector.register_agent(fingerprint.clone(), "my-agent");
//!
//! // Later, detect if a different fingerprint claims same identity
//! let fake = AgentFingerprint {
//!     jwt_sub: Some("attacker".to_string()),
//!     ..Default::default()
//! };
//! let result = detector.detect_shadow("my-agent", &fake);
//! assert!(result.is_err()); // Shadow agent detected!
//! ```

use vellaveto_types::{AgentFingerprint, TrustLevel};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

/// Alert severity levels for shadow agent detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Low severity - minor fingerprint variation
    Low,
    /// Medium severity - significant fingerprint mismatch
    Medium,
    /// High severity - completely different fingerprint
    High,
    /// Critical - known malicious pattern
    Critical,
}

/// Alert for shadow agent detection.
#[derive(Debug, Clone)]
pub struct ShadowAgentAlert {
    /// The identity claimed by the agent.
    pub claimed_id: String,
    /// Expected fingerprint for this identity.
    pub expected_fingerprint: AgentFingerprint,
    /// Actual fingerprint received.
    pub actual_fingerprint: AgentFingerprint,
    /// Severity of the alert.
    pub severity: AlertSeverity,
}

impl std::fmt::Display for ShadowAgentAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Shadow agent detected for '{}': expected {}, got {} (severity: {:?})",
            self.claimed_id,
            self.expected_fingerprint.summary(),
            self.actual_fingerprint.summary(),
            self.severity
        )
    }
}

impl std::error::Error for ShadowAgentAlert {}

/// Record of a known agent.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    /// Fingerprint for this agent.
    pub fingerprint: AgentFingerprint,
    /// First time this agent was seen (Unix timestamp).
    pub first_seen: u64,
    /// Last time this agent was seen (Unix timestamp).
    pub last_seen: u64,
    /// Total number of requests from this agent.
    pub request_count: u64,
    /// Trust level for this agent.
    pub trust_level: TrustLevel,
    /// Sessions associated with this agent.
    pub associated_sessions: HashSet<String>,
}

impl AgentRecord {
    /// Create a new agent record.
    pub fn new(fingerprint: AgentFingerprint, now: u64) -> Self {
        Self {
            fingerprint,
            first_seen: now,
            last_seen: now,
            request_count: 1,
            trust_level: TrustLevel::Unknown,
            associated_sessions: HashSet::new(),
        }
    }

    /// Update the record with a new request.
    pub fn touch(&mut self, now: u64) {
        self.last_seen = now;
        self.request_count = self.request_count.saturating_add(1);
    }
}

/// Detects shadow agent attacks.
#[derive(Debug)]
pub struct ShadowAgentDetector {
    /// Known agents by claimed identity.
    known_agents: RwLock<HashMap<String, AgentRecord>>,
    /// Fingerprint to identity mapping for reverse lookup.
    fingerprint_index: RwLock<HashMap<AgentFingerprint, String>>,
    /// Maximum number of known agents to track.
    max_agents: usize,
}

impl ShadowAgentDetector {
    /// Create a new shadow agent detector.
    ///
    /// # Arguments
    /// * `max_agents` - Maximum number of agents to track
    pub fn new(max_agents: usize) -> Self {
        Self {
            known_agents: RwLock::new(HashMap::new()),
            fingerprint_index: RwLock::new(HashMap::new()),
            max_agents,
        }
    }

    /// Create a shareable reference to this detector.
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

    /// Register a new known agent.
    ///
    /// # Arguments
    /// * `fingerprint` - The agent's fingerprint
    /// * `claimed_id` - The identity the agent claims
    pub fn register_agent(&self, fingerprint: AgentFingerprint, claimed_id: &str) {
        let now = Self::now();

        let mut agents = match self.known_agents.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::register_agent (known_agents)");
                return;
            }
        };
        let mut index = match self.fingerprint_index.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::register_agent (fingerprint_index)");
                return;
            }
        };

        // Evict if at capacity
        if agents.len() >= self.max_agents {
            self.evict_oldest_internal(&mut agents, &mut index);
        }

        agents.insert(
            claimed_id.to_string(),
            AgentRecord::new(fingerprint.clone(), now),
        );
        index.insert(fingerprint, claimed_id.to_string());

        tracing::debug!(
            agent_id = %claimed_id,
            "Registered new known agent"
        );
    }

    /// Evict the oldest (least recently seen) agent.
    fn evict_oldest_internal(
        &self,
        agents: &mut HashMap<String, AgentRecord>,
        index: &mut HashMap<AgentFingerprint, String>,
    ) {
        if let Some((oldest_id, oldest_record)) = agents
            .iter()
            .min_by_key(|(_, r)| r.last_seen)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            agents.remove(&oldest_id);
            index.remove(&oldest_record.fingerprint);
            tracing::debug!(
                agent_id = %oldest_id,
                last_seen = oldest_record.last_seen,
                "Evicted oldest agent to make room"
            );
        }
    }

    /// Identify an agent by fingerprint.
    ///
    /// Returns the agent record if the fingerprint matches a known agent.
    pub fn identify_agent(&self, fingerprint: &AgentFingerprint) -> Option<AgentRecord> {
        let index = match self.fingerprint_index.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::identify_agent (fingerprint_index)");
                return None;
            }
        };
        let agents = match self.known_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::identify_agent (known_agents)");
                return None;
            }
        };

        index
            .get(fingerprint)
            .and_then(|id| agents.get(id))
            .cloned()
    }

    /// Detect shadow agent (new fingerprint claiming known identity).
    ///
    /// # Arguments
    /// * `claimed_id` - The identity being claimed
    /// * `fingerprint` - The actual fingerprint of the requester
    ///
    /// # Returns
    /// `Ok(())` if the fingerprint matches or identity is unknown.
    /// `Err(Box<ShadowAgentAlert>)` if shadow agent detected.
    pub fn detect_shadow(
        &self,
        claimed_id: &str,
        fingerprint: &AgentFingerprint,
    ) -> Result<(), Box<ShadowAgentAlert>> {
        let agents = match self.known_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::detect_shadow (known_agents)");
                return Err(Box::new(ShadowAgentAlert {
                    claimed_id: claimed_id.to_string(),
                    expected_fingerprint: AgentFingerprint::default(),
                    actual_fingerprint: fingerprint.clone(),
                    severity: AlertSeverity::Critical,
                }));
            }
        };

        let known_record = match agents.get(claimed_id) {
            Some(r) => r,
            None => return Ok(()), // Unknown identity, not a shadow attack
        };

        // Check if fingerprints match
        if &known_record.fingerprint == fingerprint {
            return Ok(()); // Same fingerprint, legitimate
        }

        // Fingerprint mismatch - shadow agent detected
        let severity = self.calculate_severity(&known_record.fingerprint, fingerprint);

        Err(Box::new(ShadowAgentAlert {
            claimed_id: claimed_id.to_string(),
            expected_fingerprint: known_record.fingerprint.clone(),
            actual_fingerprint: fingerprint.clone(),
            severity,
        }))
    }

    /// Calculate alert severity based on fingerprint differences.
    fn calculate_severity(
        &self,
        expected: &AgentFingerprint,
        actual: &AgentFingerprint,
    ) -> AlertSeverity {
        let mut mismatches = 0;

        // Count mismatched fields
        if expected.jwt_sub != actual.jwt_sub && expected.jwt_sub.is_some() {
            mismatches += 2; // Subject mismatch is serious
        }
        if expected.jwt_iss != actual.jwt_iss && expected.jwt_iss.is_some() {
            mismatches += 2; // Issuer mismatch is serious
        }
        if expected.client_id != actual.client_id && expected.client_id.is_some() {
            mismatches += 1;
        }
        if expected.ip_hash != actual.ip_hash && expected.ip_hash.is_some() {
            mismatches += 1;
        }

        match mismatches {
            0..=1 => AlertSeverity::Low,
            2..=3 => AlertSeverity::Medium,
            4..=5 => AlertSeverity::High,
            _ => AlertSeverity::Critical,
        }
    }

    /// Upgrade the trust level for an agent.
    pub fn upgrade_trust(&self, fingerprint: &AgentFingerprint, level: TrustLevel) {
        let index = match self.fingerprint_index.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::upgrade_trust (fingerprint_index)");
                return;
            }
        };
        let mut agents = match self.known_agents.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::upgrade_trust (known_agents)");
                return;
            }
        };

        if let Some(id) = index.get(fingerprint) {
            if let Some(record) = agents.get_mut(id) {
                record.trust_level = level;
                tracing::info!(
                    agent_id = %id,
                    new_level = %level,
                    "Upgraded agent trust level"
                );
            }
        }
    }

    /// Get the trust level for a fingerprint.
    pub fn get_trust_level(&self, fingerprint: &AgentFingerprint) -> TrustLevel {
        let index = match self.fingerprint_index.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::get_trust_level (fingerprint_index)");
                return TrustLevel::Unknown;
            }
        };
        let agents = match self.known_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::get_trust_level (known_agents)");
                return TrustLevel::Unknown;
            }
        };

        index
            .get(fingerprint)
            .and_then(|id| agents.get(id))
            .map(|r| r.trust_level)
            .unwrap_or(TrustLevel::Unknown)
    }

    /// Record a request from an agent.
    ///
    /// Updates the last_seen timestamp and request count.
    pub fn record_request(&self, claimed_id: &str) {
        let now = Self::now();
        let mut agents = match self.known_agents.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::record_request (known_agents)");
                return;
            }
        };

        if let Some(record) = agents.get_mut(claimed_id) {
            record.touch(now);
        }
    }

    /// Associate a session with an agent.
    pub fn associate_session(&self, claimed_id: &str, session_id: &str) {
        let mut agents = match self.known_agents.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::associate_session (known_agents)");
                return;
            }
        };

        if let Some(record) = agents.get_mut(claimed_id) {
            record.associated_sessions.insert(session_id.to_string());
        }
    }

    /// Get the number of known agents.
    pub fn known_count(&self) -> usize {
        let agents = match self.known_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::known_count (known_agents)");
                return 0;
            }
        };
        agents.len()
    }

    /// Get all known agent IDs.
    pub fn known_ids(&self) -> Vec<String> {
        let agents = match self.known_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in ShadowAgentDetector::known_ids (known_agents)");
                return vec![];
            }
        };
        agents.keys().cloned().collect()
    }
}

impl Default for ShadowAgentDetector {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fingerprint(sub: Option<&str>, iss: Option<&str>) -> AgentFingerprint {
        AgentFingerprint {
            jwt_sub: sub.map(|s| s.to_string()),
            jwt_iss: iss.map(|s| s.to_string()),
            client_id: None,
            ip_hash: None,
        }
    }

    #[test]
    fn test_new_agent_registered() {
        let detector = ShadowAgentDetector::new(100);
        let fp = make_fingerprint(Some("agent-1"), Some("issuer"));

        detector.register_agent(fp.clone(), "my-agent");

        assert_eq!(detector.known_count(), 1);
        assert!(detector.known_ids().contains(&"my-agent".to_string()));
    }

    #[test]
    fn test_known_agent_identified() {
        let detector = ShadowAgentDetector::new(100);
        let fp = make_fingerprint(Some("agent-1"), Some("issuer"));

        detector.register_agent(fp.clone(), "my-agent");

        let record = detector.identify_agent(&fp).unwrap();
        assert_eq!(record.fingerprint, fp);
        assert_eq!(record.trust_level, TrustLevel::Unknown);
    }

    #[test]
    fn test_shadow_agent_detected() {
        let detector = ShadowAgentDetector::new(100);
        let real_fp = make_fingerprint(Some("real-agent"), Some("real-issuer"));
        let fake_fp = make_fingerprint(Some("fake-agent"), Some("fake-issuer"));

        detector.register_agent(real_fp.clone(), "my-agent");

        // Fake fingerprint claiming same identity
        let result = detector.detect_shadow("my-agent", &fake_fp);
        assert!(result.is_err());

        let alert = result.unwrap_err();
        assert_eq!(alert.claimed_id, "my-agent");
        assert_eq!(alert.expected_fingerprint, real_fp);
        assert_eq!(alert.actual_fingerprint, fake_fp);
    }

    #[test]
    fn test_unknown_identity_not_shadow() {
        let detector = ShadowAgentDetector::new(100);
        let fp = make_fingerprint(Some("new-agent"), None);

        // Unknown identity should pass (not a shadow attack)
        let result = detector.detect_shadow("unknown-agent", &fp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_trust_level_upgrade() {
        let detector = ShadowAgentDetector::new(100);
        let fp = make_fingerprint(Some("agent-1"), None);

        detector.register_agent(fp.clone(), "my-agent");
        assert_eq!(detector.get_trust_level(&fp), TrustLevel::Unknown);

        detector.upgrade_trust(&fp, TrustLevel::High);
        assert_eq!(detector.get_trust_level(&fp), TrustLevel::High);
    }

    #[test]
    fn test_severity_calculation() {
        let detector = ShadowAgentDetector::new(100);
        let real = AgentFingerprint {
            jwt_sub: Some("real".to_string()),
            jwt_iss: Some("real-issuer".to_string()),
            client_id: Some("client-1".to_string()),
            ip_hash: Some("hash".to_string()),
        };
        let fake = AgentFingerprint::default();

        let severity = detector.calculate_severity(&real, &fake);
        assert!(matches!(severity, AlertSeverity::Critical));
    }

    #[test]
    fn test_record_request() {
        let detector = ShadowAgentDetector::new(100);
        let fp = make_fingerprint(Some("agent-1"), None);

        detector.register_agent(fp.clone(), "my-agent");

        let record1 = detector.identify_agent(&fp).unwrap();
        assert_eq!(record1.request_count, 1);

        detector.record_request("my-agent");

        let record2 = detector.identify_agent(&fp).unwrap();
        assert_eq!(record2.request_count, 2);
    }

    #[test]
    fn test_max_agents_eviction() {
        let detector = ShadowAgentDetector::new(2); // Small capacity

        let fp1 = make_fingerprint(Some("agent-1"), None);
        let fp2 = make_fingerprint(Some("agent-2"), None);
        let fp3 = make_fingerprint(Some("agent-3"), None);

        detector.register_agent(fp1, "agent-1");
        detector.register_agent(fp2, "agent-2");
        assert_eq!(detector.known_count(), 2);

        // This should evict the oldest
        detector.register_agent(fp3, "agent-3");
        assert_eq!(detector.known_count(), 2);
    }
}
