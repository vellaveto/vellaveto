//! Agent Trust Graph for Multi-Agent Security (Phase 3.2)
//!
//! Tracks trust relationships between agents in multi-agent systems to prevent:
//! - Cross-agent privilege escalation (second-order prompt injection)
//! - Unauthorized delegation chains
//! - Trust boundary violations
//!
//! Reference: OWASP ASI Top 10 (ASI02, ASI04)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Maximum number of request chain entries stored per session.
/// Prevents unbounded memory growth from long-running sessions (FIND-041-006).
const MAX_CHAINS_PER_SESSION: usize = 10_000;

/// Maximum number of tracked sessions in request_chains (FIND-R42-007).
/// Prevents unbounded memory growth from many unique sessions.
const MAX_TRACKED_SESSIONS: usize = 10_000;

/// SECURITY (FIND-R43-006): Maximum registered agents in privilege_levels.
const MAX_REGISTERED_AGENTS: usize = 10_000;

/// SECURITY (FIND-R43-006): Maximum globally trusted agents.
const MAX_TRUSTED_AGENTS: usize = 1_000;

/// SECURITY (FIND-R43-006): Maximum total trust edge source keys.
const MAX_TRUST_EDGES: usize = 50_000;

/// SECURITY (FIND-R44-038): Maximum entries in the last_activity map.
/// Matches MAX_REGISTERED_AGENTS to prevent unbounded memory growth.
const MAX_LAST_ACTIVITY_ENTRIES: usize = 10_000;

/// SECURITY (FIND-R43-006): Maximum trust targets per source agent.
const MAX_TRUST_TARGETS_PER_AGENT: usize = 1_000;

/// Privilege level assigned to an agent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum PrivilegeLevel {
    /// No privileges - can only read public data
    #[default]
    None = 0,
    /// Basic privileges - can execute safe operations
    Basic = 1,
    /// Standard privileges - can execute most operations
    Standard = 2,
    /// Elevated privileges - can execute sensitive operations
    Elevated = 3,
    /// Admin privileges - full access
    Admin = 4,
}

impl PrivilegeLevel {
    /// Check if this level can delegate to another level.
    /// An agent can only delegate to agents with equal or lower privilege.
    pub fn can_delegate_to(&self, target: PrivilegeLevel) -> bool {
        *self >= target
    }
}

/// Entry in the request chain tracking who requested what from whom.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChainEntry {
    /// Agent that made the request
    pub from_agent: String,
    /// Agent that received the request
    pub to_agent: String,
    /// Action being requested (tool:function format)
    pub action: String,
    /// Timestamp of the request
    pub timestamp: u64,
    /// Session ID for the request
    pub session_id: String,
}

/// Alert generated when privilege escalation is detected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationAlert {
    /// Type of escalation detected
    pub alert_type: EscalationAlertType,
    /// Agent that initiated the chain
    pub source_agent: String,
    /// Agent that would gain elevated privileges
    pub target_agent: Option<String>,
    /// The request chain that triggered the alert
    pub chain: Vec<RequestChainEntry>,
    /// Human-readable description
    pub description: String,
    /// Severity level (1-5)
    pub severity: u8,
}

/// Types of privilege escalation alerts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationAlertType {
    /// Agent with lower privilege delegating to higher privilege agent
    UpwardDelegation,
    /// Request chain exceeds maximum allowed depth
    ChainDepthExceeded,
    /// Agent not in trusted list attempting privileged operation
    UntrustedAgent,
    /// Circular delegation detected in trust graph
    CircularDelegation,
    /// Agent attempting to bypass trust boundaries
    TrustBoundaryViolation,
}

/// Tracks trust relationships between agents in multi-agent systems.
pub struct AgentTrustGraph {
    /// Directed edges: agent_a trusts agent_b (agent_a -> Set<agent_b>)
    trust_edges: RwLock<HashMap<String, HashSet<String>>>,
    /// Privilege levels per agent
    privilege_levels: RwLock<HashMap<String, PrivilegeLevel>>,
    /// Request chains: session_id -> chain entries
    request_chains: RwLock<HashMap<String, Vec<RequestChainEntry>>>,
    /// Maximum allowed chain depth
    max_chain_depth: usize,
    /// Trusted agents that can bypass certain checks
    trusted_agents: RwLock<HashSet<String>>,
    /// Last activity timestamp per agent (for cleanup)
    last_activity: RwLock<HashMap<String, Instant>>,
    /// TTL for inactive chains
    chain_ttl: Duration,
    /// SECURITY (FIND-R43-018): Counter for opportunistic cleanup scheduling.
    call_count: AtomicU64,
}

impl AgentTrustGraph {
    /// Create a new agent trust graph with default settings.
    pub fn new() -> Self {
        Self::with_config(5, Duration::from_secs(3600))
    }

    /// Create a new agent trust graph with custom configuration.
    pub fn with_config(max_chain_depth: usize, chain_ttl: Duration) -> Self {
        Self {
            trust_edges: RwLock::new(HashMap::new()),
            privilege_levels: RwLock::new(HashMap::new()),
            request_chains: RwLock::new(HashMap::new()),
            max_chain_depth,
            trusted_agents: RwLock::new(HashSet::new()),
            last_activity: RwLock::new(HashMap::new()),
            chain_ttl,
            call_count: AtomicU64::new(0),
        }
    }

    /// Register an agent with a privilege level.
    pub fn register_agent(&self, agent_id: &str, level: PrivilegeLevel) {
        let mut levels = match self.privilege_levels.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::register_agent (privilege_levels)");
                return;
            }
        };
        // SECURITY (FIND-R43-006): Bound the number of registered agents.
        if !levels.contains_key(agent_id) && levels.len() >= MAX_REGISTERED_AGENTS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_REGISTERED_AGENTS,
                "Registered agent limit reached — dropping new agent"
            );
            return;
        }
        levels.insert(agent_id.to_string(), level);

        let mut activity = match self.last_activity.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::register_agent (last_activity)");
                return;
            }
        };
        // SECURITY (FIND-R44-038): Bound last_activity entries. If at capacity
        // and the key is not already present, skip the insert.
        if activity.len() >= MAX_LAST_ACTIVITY_ENTRIES && !activity.contains_key(agent_id) {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_LAST_ACTIVITY_ENTRIES,
                "Last activity limit reached — dropping new entry"
            );
            return;
        }
        activity.insert(agent_id.to_string(), Instant::now());
    }

    /// Add a trust relationship: `from_agent` trusts `to_agent`.
    pub fn add_trust(&self, from_agent: &str, to_agent: &str) {
        let mut edges = match self.trust_edges.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::add_trust");
                return;
            }
        };
        // SECURITY (FIND-R43-006): Bound the number of trust edge source keys.
        if !edges.contains_key(from_agent) && edges.len() >= MAX_TRUST_EDGES {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRUST_EDGES,
                "Trust edge source limit reached — dropping new edge"
            );
            return;
        }
        let targets = edges.entry(from_agent.to_string()).or_default();
        // SECURITY (FIND-R43-006): Bound the per-agent trust target set.
        if !targets.contains(to_agent) && targets.len() >= MAX_TRUST_TARGETS_PER_AGENT {
            tracing::warn!(
                target: "vellaveto::security",
                from_agent = %from_agent,
                limit = MAX_TRUST_TARGETS_PER_AGENT,
                "Per-agent trust target limit reached — dropping new target"
            );
            return;
        }
        targets.insert(to_agent.to_string());
    }

    /// Remove a trust relationship.
    pub fn remove_trust(&self, from_agent: &str, to_agent: &str) {
        let mut edges = match self.trust_edges.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::remove_trust");
                return;
            }
        };
        if let Some(trusted) = edges.get_mut(from_agent) {
            trusted.remove(to_agent);
        }
    }

    /// Mark an agent as globally trusted.
    pub fn add_trusted_agent(&self, agent_id: &str) {
        let mut trusted = match self.trusted_agents.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::add_trusted_agent");
                return;
            }
        };
        // SECURITY (FIND-R43-006): Bound the number of globally trusted agents.
        if !trusted.contains(agent_id) && trusted.len() >= MAX_TRUSTED_AGENTS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRUSTED_AGENTS,
                "Trusted agent limit reached — dropping new trusted agent"
            );
            return;
        }
        trusted.insert(agent_id.to_string());
    }

    /// Check if agent_a can delegate to agent_b.
    ///
    /// Returns true if:
    /// 1. agent_a explicitly trusts agent_b, OR
    /// 2. agent_b is a globally trusted agent, AND
    /// 3. agent_a's privilege level can delegate to agent_b's level
    pub fn can_delegate(&self, from_agent: &str, to_agent: &str) -> bool {
        // Check if to_agent is globally trusted
        let trusted = match self.trusted_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::can_delegate (trusted_agents)");
                return false;
            }
        };
        if trusted.contains(to_agent) {
            return true;
        }

        // Check explicit trust relationship
        let edges = match self.trust_edges.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::can_delegate (trust_edges)");
                return false;
            }
        };
        let has_trust = edges
            .get(from_agent)
            .map(|t| t.contains(to_agent))
            .unwrap_or(false);

        if !has_trust {
            return false;
        }

        // Check privilege levels
        let levels = match self.privilege_levels.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::can_delegate (privilege_levels)");
                return false;
            }
        };
        let from_level = levels
            .get(from_agent)
            .copied()
            .unwrap_or(PrivilegeLevel::None);
        let to_level = levels
            .get(to_agent)
            .copied()
            .unwrap_or(PrivilegeLevel::None);

        from_level.can_delegate_to(to_level)
    }

    /// Record an inter-agent request.
    pub fn record_request(&self, session_id: &str, from_agent: &str, to_agent: &str, action: &str) {
        let entry = RequestChainEntry {
            from_agent: from_agent.to_string(),
            to_agent: to_agent.to_string(),
            action: action.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            session_id: session_id.to_string(),
        };

        let mut chains = match self.request_chains.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::record_request (request_chains)");
                return;
            }
        };
        // SECURITY (FIND-R42-007): Bound the number of tracked sessions.
        if !chains.contains_key(session_id) && chains.len() >= MAX_TRACKED_SESSIONS {
            tracing::warn!(
                target: "vellaveto::security",
                limit = MAX_TRACKED_SESSIONS,
                "Request chain session limit reached — dropping new session"
            );
            return;
        }
        let session_chains = chains
            .entry(session_id.to_string())
            .or_default();
        if session_chains.len() >= MAX_CHAINS_PER_SESSION {
            tracing::warn!(
                target: "vellaveto::security",
                session_id = %session_id,
                limit = MAX_CHAINS_PER_SESSION,
                "Request chain limit reached for session — dropping new entry"
            );
            return;
        }
        session_chains.push(entry);
        drop(chains);

        let mut activity = match self.last_activity.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::record_request (last_activity)");
                return;
            }
        };
        activity.insert(from_agent.to_string(), Instant::now());
        activity.insert(to_agent.to_string(), Instant::now());
        drop(activity);

        // SECURITY (FIND-R43-018): Opportunistic cleanup every 1000 calls.
        if self.call_count.fetch_add(1, Ordering::Relaxed).is_multiple_of(1000) {
            self.cleanup();
        }
    }

    /// Get the request chain for a session.
    pub fn get_chain(&self, session_id: &str) -> Vec<RequestChainEntry> {
        let chains = match self.request_chains.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::get_chain");
                return vec![];
            }
        };
        chains.get(session_id).cloned().unwrap_or_default()
    }

    /// Check for privilege escalation in a request chain.
    ///
    /// Returns an alert if escalation is detected, None otherwise.
    pub fn detect_privilege_escalation(
        &self,
        chain: &[RequestChainEntry],
    ) -> Option<EscalationAlert> {
        if chain.is_empty() {
            return None;
        }

        // Check chain depth
        if chain.len() > self.max_chain_depth {
            return Some(EscalationAlert {
                alert_type: EscalationAlertType::ChainDepthExceeded,
                source_agent: chain
                    .first()
                    .map(|e| e.from_agent.clone())
                    .unwrap_or_default(),
                target_agent: chain.last().map(|e| e.to_agent.clone()),
                chain: chain.to_vec(),
                description: format!(
                    "Request chain depth {} exceeds maximum allowed depth {}",
                    chain.len(),
                    self.max_chain_depth
                ),
                severity: 4,
            });
        }

        let levels = match self.privilege_levels.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::detect_privilege_escalation (privilege_levels)");
                return Some(EscalationAlert {
                    alert_type: EscalationAlertType::TrustBoundaryViolation,
                    source_agent: chain
                        .first()
                        .map(|e| e.from_agent.clone())
                        .unwrap_or_default(),
                    target_agent: chain.last().map(|e| e.to_agent.clone()),
                    chain: chain.to_vec(),
                    description: "Lock poisoned — fail-closed escalation alert".to_string(),
                    severity: 5,
                });
            }
        };
        let trusted = match self.trusted_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::detect_privilege_escalation (trusted_agents)");
                return Some(EscalationAlert {
                    alert_type: EscalationAlertType::TrustBoundaryViolation,
                    source_agent: chain
                        .first()
                        .map(|e| e.from_agent.clone())
                        .unwrap_or_default(),
                    target_agent: chain.last().map(|e| e.to_agent.clone()),
                    chain: chain.to_vec(),
                    description: "Lock poisoned — fail-closed escalation alert".to_string(),
                    severity: 5,
                });
            }
        };

        // Track visited agents for circular delegation detection
        let mut visited = HashSet::new();

        for entry in chain {
            // SECURITY (FIND-R43-035): Catch self-referential delegation.
            if entry.from_agent == entry.to_agent {
                return Some(EscalationAlert {
                    alert_type: EscalationAlertType::CircularDelegation,
                    source_agent: entry.from_agent.clone(),
                    target_agent: Some(entry.to_agent.clone()),
                    chain: chain.to_vec(),
                    description: format!(
                        "Self-referential delegation detected: agent '{}' delegates to itself",
                        entry.from_agent
                    ),
                    severity: 5,
                });
            }

            // Check for circular delegation
            if visited.contains(&entry.to_agent) {
                return Some(EscalationAlert {
                    alert_type: EscalationAlertType::CircularDelegation,
                    source_agent: entry.from_agent.clone(),
                    target_agent: Some(entry.to_agent.clone()),
                    chain: chain.to_vec(),
                    description: format!(
                        "Circular delegation detected: agent '{}' appears multiple times in chain",
                        entry.to_agent
                    ),
                    severity: 5,
                });
            }
            visited.insert(entry.from_agent.clone());

            // Check for untrusted agent
            let from_level = levels
                .get(&entry.from_agent)
                .copied()
                .unwrap_or(PrivilegeLevel::None);
            let to_level = levels
                .get(&entry.to_agent)
                .copied()
                .unwrap_or(PrivilegeLevel::None);

            // Skip trusted agents
            if trusted.contains(&entry.from_agent) {
                continue;
            }

            // Check for upward delegation (privilege escalation)
            if to_level > from_level {
                return Some(EscalationAlert {
                    alert_type: EscalationAlertType::UpwardDelegation,
                    source_agent: entry.from_agent.clone(),
                    target_agent: Some(entry.to_agent.clone()),
                    chain: chain.to_vec(),
                    description: format!(
                        "Privilege escalation: agent '{}' ({:?}) delegating to '{}' ({:?})",
                        entry.from_agent, from_level, entry.to_agent, to_level
                    ),
                    severity: 5,
                });
            }
        }

        None
    }

    /// Get the transitive trust closure for an agent.
    ///
    /// Returns all agents that the given agent transitively trusts.
    pub fn trust_closure(&self, agent: &str) -> HashSet<String> {
        let edges = match self.trust_edges.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::trust_closure");
                return HashSet::new();
            }
        };
        let mut closure = HashSet::new();
        let mut to_visit = vec![agent.to_string()];

        while let Some(current) = to_visit.pop() {
            if let Some(trusted) = edges.get(&current) {
                for t in trusted {
                    if closure.insert(t.clone()) {
                        to_visit.push(t.clone());
                    }
                }
            }
        }

        closure
    }

    /// Get the privilege level for an agent.
    pub fn get_privilege_level(&self, agent: &str) -> PrivilegeLevel {
        let levels = match self.privilege_levels.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::get_privilege_level");
                return PrivilegeLevel::None;
            }
        };
        levels.get(agent).copied().unwrap_or(PrivilegeLevel::None)
    }

    /// Check if an agent is registered.
    pub fn is_registered(&self, agent: &str) -> bool {
        let levels = match self.privilege_levels.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::is_registered");
                return false;
            }
        };
        levels.contains_key(agent)
    }

    /// Get statistics about the trust graph.
    pub fn stats(&self) -> TrustGraphStats {
        let edges = match self.trust_edges.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::stats (trust_edges)");
                return TrustGraphStats {
                    registered_agents: 0,
                    trusted_agents: 0,
                    total_trust_edges: 0,
                    active_sessions: 0,
                    max_chain_depth: self.max_chain_depth,
                };
            }
        };
        let levels = match self.privilege_levels.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::stats (privilege_levels)");
                return TrustGraphStats {
                    registered_agents: 0,
                    trusted_agents: 0,
                    total_trust_edges: 0,
                    active_sessions: 0,
                    max_chain_depth: self.max_chain_depth,
                };
            }
        };
        let chains = match self.request_chains.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::stats (request_chains)");
                return TrustGraphStats {
                    registered_agents: 0,
                    trusted_agents: 0,
                    total_trust_edges: 0,
                    active_sessions: 0,
                    max_chain_depth: self.max_chain_depth,
                };
            }
        };
        let trusted = match self.trusted_agents.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::stats (trusted_agents)");
                return TrustGraphStats {
                    registered_agents: 0,
                    trusted_agents: 0,
                    total_trust_edges: 0,
                    active_sessions: 0,
                    max_chain_depth: self.max_chain_depth,
                };
            }
        };

        let total_edges: usize = edges.values().map(|s| s.len()).sum();

        TrustGraphStats {
            registered_agents: levels.len(),
            trusted_agents: trusted.len(),
            total_trust_edges: total_edges,
            active_sessions: chains.len(),
            max_chain_depth: self.max_chain_depth,
        }
    }

    /// Clean up expired chains and inactive agents.
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean up old chains
        let mut chains = match self.request_chains.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::cleanup (request_chains)");
                return;
            }
        };
        chains.retain(|_, entries| {
            if let Some(last) = entries.last() {
                let entry_time =
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(last.timestamp);
                if let Ok(elapsed) = std::time::SystemTime::now().duration_since(entry_time) {
                    elapsed < self.chain_ttl
                } else {
                    false
                }
            } else {
                false
            }
        });

        // Clean up inactive agents
        let mut activity = match self.last_activity.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::cleanup (last_activity)");
                return;
            }
        };
        activity.retain(|_, last| now.duration_since(*last) < self.chain_ttl);
    }

    /// Clear all data (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        if let Ok(mut g) = self.trust_edges.write() {
            g.clear();
        } else {
            tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::clear (trust_edges)");
            return;
        }
        if let Ok(mut g) = self.privilege_levels.write() {
            g.clear();
        } else {
            tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::clear (privilege_levels)");
            return;
        }
        if let Ok(mut g) = self.request_chains.write() {
            g.clear();
        } else {
            tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::clear (request_chains)");
            return;
        }
        if let Ok(mut g) = self.trusted_agents.write() {
            g.clear();
        } else {
            tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::clear (trusted_agents)");
            return;
        }
        if let Ok(mut g) = self.last_activity.write() {
            g.clear();
        } else {
            tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentTrustGraph::clear (last_activity)");
        }
    }
}

impl Default for AgentTrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGraphStats {
    pub registered_agents: usize,
    pub trusted_agents: usize,
    pub total_trust_edges: usize,
    pub active_sessions: usize,
    pub max_chain_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_level_ordering() {
        assert!(PrivilegeLevel::Admin > PrivilegeLevel::Elevated);
        assert!(PrivilegeLevel::Elevated > PrivilegeLevel::Standard);
        assert!(PrivilegeLevel::Standard > PrivilegeLevel::Basic);
        assert!(PrivilegeLevel::Basic > PrivilegeLevel::None);
    }

    #[test]
    fn test_can_delegate_to() {
        assert!(PrivilegeLevel::Admin.can_delegate_to(PrivilegeLevel::Basic));
        assert!(PrivilegeLevel::Admin.can_delegate_to(PrivilegeLevel::Admin));
        assert!(!PrivilegeLevel::Basic.can_delegate_to(PrivilegeLevel::Admin));
        assert!(PrivilegeLevel::Basic.can_delegate_to(PrivilegeLevel::None));
    }

    #[test]
    fn test_register_and_trust() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("agent_a", PrivilegeLevel::Admin);
        graph.register_agent("agent_b", PrivilegeLevel::Basic);

        assert!(graph.is_registered("agent_a"));
        assert!(graph.is_registered("agent_b"));
        assert!(!graph.is_registered("agent_c"));

        graph.add_trust("agent_a", "agent_b");
        assert!(graph.can_delegate("agent_a", "agent_b"));
        assert!(!graph.can_delegate("agent_b", "agent_a")); // No reverse trust
    }

    #[test]
    fn test_cannot_delegate_without_trust() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("agent_a", PrivilegeLevel::Admin);
        graph.register_agent("agent_b", PrivilegeLevel::Basic);

        // No trust relationship established
        assert!(!graph.can_delegate("agent_a", "agent_b"));
    }

    #[test]
    fn test_trusted_agents_bypass() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("agent_a", PrivilegeLevel::Basic);
        graph.register_agent("trusted_agent", PrivilegeLevel::Admin);
        graph.add_trusted_agent("trusted_agent");

        // agent_a can delegate to trusted_agent even without explicit trust
        assert!(graph.can_delegate("agent_a", "trusted_agent"));
    }

    #[test]
    fn test_trust_closure() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("a", PrivilegeLevel::Admin);
        graph.register_agent("b", PrivilegeLevel::Standard);
        graph.register_agent("c", PrivilegeLevel::Basic);

        graph.add_trust("a", "b");
        graph.add_trust("b", "c");

        let closure = graph.trust_closure("a");
        assert!(closure.contains("b"));
        assert!(closure.contains("c"));
        assert!(!closure.contains("a")); // Self not included
    }

    #[test]
    fn test_record_request_chain() {
        let graph = AgentTrustGraph::new();

        graph.record_request("session_1", "agent_a", "agent_b", "tool:function");
        graph.record_request("session_1", "agent_b", "agent_c", "tool:other");

        let chain = graph.get_chain("session_1");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].from_agent, "agent_a");
        assert_eq!(chain[1].to_agent, "agent_c");
    }

    #[test]
    fn test_detect_chain_depth_exceeded() {
        let graph = AgentTrustGraph::with_config(2, Duration::from_secs(3600));

        let chain = vec![
            RequestChainEntry {
                from_agent: "a".to_string(),
                to_agent: "b".to_string(),
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
            RequestChainEntry {
                from_agent: "b".to_string(),
                to_agent: "c".to_string(),
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
            RequestChainEntry {
                from_agent: "c".to_string(),
                to_agent: "d".to_string(),
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
        ];

        let alert = graph.detect_privilege_escalation(&chain);
        assert!(alert.is_some());
        assert_eq!(
            alert.unwrap().alert_type,
            EscalationAlertType::ChainDepthExceeded
        );
    }

    #[test]
    fn test_detect_upward_delegation() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("low_priv", PrivilegeLevel::Basic);
        graph.register_agent("high_priv", PrivilegeLevel::Admin);

        let chain = vec![RequestChainEntry {
            from_agent: "low_priv".to_string(),
            to_agent: "high_priv".to_string(),
            action: "sensitive:operation".to_string(),
            timestamp: 0,
            session_id: "s1".to_string(),
        }];

        let alert = graph.detect_privilege_escalation(&chain);
        assert!(alert.is_some());
        assert_eq!(
            alert.unwrap().alert_type,
            EscalationAlertType::UpwardDelegation
        );
    }

    #[test]
    fn test_detect_circular_delegation() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("a", PrivilegeLevel::Standard);
        graph.register_agent("b", PrivilegeLevel::Standard);
        graph.register_agent("c", PrivilegeLevel::Standard);

        let chain = vec![
            RequestChainEntry {
                from_agent: "a".to_string(),
                to_agent: "b".to_string(),
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
            RequestChainEntry {
                from_agent: "b".to_string(),
                to_agent: "c".to_string(),
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
            RequestChainEntry {
                from_agent: "c".to_string(),
                to_agent: "a".to_string(), // Circular!
                action: "tool:fn".to_string(),
                timestamp: 0,
                session_id: "s1".to_string(),
            },
        ];

        let alert = graph.detect_privilege_escalation(&chain);
        assert!(alert.is_some());
        assert_eq!(
            alert.unwrap().alert_type,
            EscalationAlertType::CircularDelegation
        );
    }

    #[test]
    fn test_no_escalation_on_valid_chain() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("admin", PrivilegeLevel::Admin);
        graph.register_agent("user", PrivilegeLevel::Basic);

        let chain = vec![RequestChainEntry {
            from_agent: "admin".to_string(),
            to_agent: "user".to_string(),
            action: "tool:fn".to_string(),
            timestamp: 0,
            session_id: "s1".to_string(),
        }];

        let alert = graph.detect_privilege_escalation(&chain);
        assert!(alert.is_none());
    }

    #[test]
    fn test_stats() {
        let graph = AgentTrustGraph::new();

        graph.register_agent("a", PrivilegeLevel::Admin);
        graph.register_agent("b", PrivilegeLevel::Basic);
        graph.add_trust("a", "b");
        graph.add_trusted_agent("system");
        graph.record_request("s1", "a", "b", "tool:fn");

        let stats = graph.stats();
        assert_eq!(stats.registered_agents, 2);
        assert_eq!(stats.trusted_agents, 1);
        assert_eq!(stats.total_trust_edges, 1);
        assert_eq!(stats.active_sessions, 1);
    }

    // ═══════════════════════════════════════════════════════
    // FIND-R44-038: last_activity bounded at MAX_LAST_ACTIVITY_ENTRIES
    // ═══════════════════════════════════════════════════════

    /// FIND-R44-038: last_activity stops accepting new entries at capacity.
    /// Note: MAX_REGISTERED_AGENTS and MAX_LAST_ACTIVITY_ENTRIES are both 10_000.
    /// Since register_agent also checks MAX_REGISTERED_AGENTS for privilege_levels,
    /// both bounds trigger together. We verify via stats that registration stops.
    #[test]
    fn test_last_activity_bounded() {
        let graph = AgentTrustGraph::new();

        // Fill to capacity (MAX_REGISTERED_AGENTS = 10_000)
        for i in 0..MAX_REGISTERED_AGENTS {
            graph.register_agent(&format!("agent_{}", i), PrivilegeLevel::Basic);
        }

        let stats = graph.stats();
        assert_eq!(stats.registered_agents, MAX_REGISTERED_AGENTS);

        // One more should be dropped
        graph.register_agent("overflow_agent", PrivilegeLevel::Admin);

        let stats_after = graph.stats();
        assert_eq!(
            stats_after.registered_agents, MAX_REGISTERED_AGENTS,
            "Registration beyond MAX_REGISTERED_AGENTS must be rejected"
        );
        assert!(
            !graph.is_registered("overflow_agent"),
            "Overflow agent must not be registered"
        );
    }

    /// FIND-R44-038: Updating an existing agent's last_activity does not fail at capacity.
    #[test]
    fn test_last_activity_existing_agent_updates_at_capacity() {
        let graph = AgentTrustGraph::new();

        // Fill to capacity
        for i in 0..MAX_REGISTERED_AGENTS {
            graph.register_agent(&format!("agent_{}", i), PrivilegeLevel::Basic);
        }

        // Re-registering an existing agent should succeed (updates last_activity)
        graph.register_agent("agent_0", PrivilegeLevel::Admin);

        // Verify the agent is still registered
        assert!(
            graph.is_registered("agent_0"),
            "Re-registering existing agent must succeed at capacity"
        );
    }
}
