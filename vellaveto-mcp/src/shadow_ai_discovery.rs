//! Shadow AI Discovery Engine (Phase 26.1).
//!
//! Passive discovery of unregistered agents, unapproved tools, and unknown
//! MCP servers from traffic patterns. Does NOT scan the network — only observes
//! requests flowing through Vellaveto.
//!
//! Design constraints:
//! - Bounded memory: max 1000 unregistered agents, 500 tools, 100 servers.
//! - Thread-safe: all state behind `RwLock`.
//! - No panics: RwLock poisoning returns empty/default results.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use vellaveto_types::{ShadowAiReport, UnapprovedTool, UnknownMcpServer, UnregisteredAgent};

/// Maximum tracked unregistered agents.
const MAX_UNREGISTERED_AGENTS: usize = 1_000;

/// Maximum tracked unapproved tools.
const MAX_UNAPPROVED_TOOLS: usize = 500;

/// Maximum tracked unknown servers.
const MAX_UNKNOWN_SERVERS: usize = 100;

/// Maximum tools-per-agent tracked (bounds memory within each agent entry).
const MAX_TOOLS_PER_AGENT: usize = 100;

/// Maximum agents-per-tool tracked.
const MAX_AGENTS_PER_TOOL: usize = 100;

/// Maximum tools-per-server tracked.
const MAX_TOOLS_PER_SERVER: usize = 100;

/// Passive discovery engine for unregistered agents, unapproved tools, and unknown MCP servers.
pub struct ShadowAiDiscovery {
    registered_agents: RwLock<HashSet<String>>,
    unregistered: RwLock<HashMap<String, UnregisteredAgent>>,
    approved_tools: RwLock<HashSet<String>>,
    unapproved: RwLock<HashMap<String, UnapprovedTool>>,
    known_servers: RwLock<HashSet<String>>,
    unknown_servers: RwLock<HashMap<String, UnknownMcpServer>>,
    require_registration: bool,
}

impl ShadowAiDiscovery {
    /// Create a new discovery engine from governance configuration.
    pub fn new(
        registered_agents: HashSet<String>,
        approved_tools: HashSet<String>,
        known_servers: HashSet<String>,
        require_registration: bool,
    ) -> Self {
        Self {
            registered_agents: RwLock::new(registered_agents),
            unregistered: RwLock::new(HashMap::new()),
            approved_tools: RwLock::new(approved_tools),
            unapproved: RwLock::new(HashMap::new()),
            known_servers: RwLock::new(known_servers),
            unknown_servers: RwLock::new(HashMap::new()),
            require_registration,
        }
    }

    /// Observe a request and update discovery state.
    ///
    /// Called on every MCP request. Updates unregistered agents, unapproved tools,
    /// and unknown servers based on the request metadata.
    pub fn observe_request(
        &self,
        agent_id: &str,
        tool_name: &str,
        server_id: Option<&str>,
    ) {
        let now = chrono::Utc::now().to_rfc3339();

        // Check if agent is registered
        let agent_registered = self
            .registered_agents
            .read()
            .map(|r| r.contains(agent_id))
            .unwrap_or(false);

        if !agent_registered && !agent_id.is_empty() {
            if let Ok(mut unregistered) = self.unregistered.write() {
                if let Some(entry) = unregistered.get_mut(agent_id) {
                    entry.request_count = entry.request_count.saturating_add(1);
                    entry.last_seen = now.clone();
                    if entry.tools_used.len() < MAX_TOOLS_PER_AGENT {
                        entry.tools_used.insert(tool_name.to_string());
                    }
                    entry.risk_score = Self::compute_risk_score(
                        entry.request_count,
                        entry.tools_used.len(),
                    );
                } else if unregistered.len() < MAX_UNREGISTERED_AGENTS {
                    let mut tools_used = HashSet::new();
                    tools_used.insert(tool_name.to_string());
                    let request_count = 1;
                    let risk_score =
                        Self::compute_risk_score(request_count, tools_used.len());
                    unregistered.insert(
                        agent_id.to_string(),
                        UnregisteredAgent {
                            agent_id: agent_id.to_string(),
                            first_seen: now.clone(),
                            last_seen: now.clone(),
                            request_count,
                            tools_used,
                            risk_score,
                        },
                    );
                }
            }
        }

        // Check if tool is approved (empty approved_tools = all approved)
        let tool_check_needed = self
            .approved_tools
            .read()
            .map(|r| !r.is_empty() && !r.contains(tool_name))
            .unwrap_or(false);

        if tool_check_needed && !tool_name.is_empty() {
            if let Ok(mut unapproved) = self.unapproved.write() {
                if let Some(entry) = unapproved.get_mut(tool_name) {
                    entry.request_count = entry.request_count.saturating_add(1);
                    if entry.requesting_agents.len() < MAX_AGENTS_PER_TOOL {
                        entry
                            .requesting_agents
                            .insert(agent_id.to_string());
                    }
                } else if unapproved.len() < MAX_UNAPPROVED_TOOLS {
                    let mut requesting_agents = HashSet::new();
                    requesting_agents.insert(agent_id.to_string());
                    unapproved.insert(
                        tool_name.to_string(),
                        UnapprovedTool {
                            tool_name: tool_name.to_string(),
                            first_seen: now.clone(),
                            request_count: 1,
                            requesting_agents,
                        },
                    );
                }
            }
        }

        // Check if server is known (empty known_servers = all allowed)
        if let Some(sid) = server_id {
            let server_check_needed = self
                .known_servers
                .read()
                .map(|r| !r.is_empty() && !r.contains(sid))
                .unwrap_or(false);

            if server_check_needed && !sid.is_empty() {
                if let Ok(mut unknown) = self.unknown_servers.write() {
                    if let Some(entry) = unknown.get_mut(sid) {
                        entry.connection_count = entry.connection_count.saturating_add(1);
                        if entry.advertised_tools.len() < MAX_TOOLS_PER_SERVER {
                            entry.advertised_tools.insert(tool_name.to_string());
                        }
                    } else if unknown.len() < MAX_UNKNOWN_SERVERS {
                        let mut advertised_tools = HashSet::new();
                        advertised_tools.insert(tool_name.to_string());
                        unknown.insert(
                            sid.to_string(),
                            UnknownMcpServer {
                                server_id: sid.to_string(),
                                first_seen: now,
                                connection_count: 1,
                                advertised_tools,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Check if an agent is in the registered agent list.
    pub fn is_agent_registered(&self, agent_id: &str) -> bool {
        self.registered_agents
            .read()
            .map(|r| r.contains(agent_id))
            .unwrap_or(false)
    }

    /// Check if a tool is in the approved tools list.
    /// Returns true if the approved list is empty (all tools approved).
    pub fn is_tool_approved(&self, tool_name: &str) -> bool {
        self.approved_tools
            .read()
            .map(|r| r.is_empty() || r.contains(tool_name))
            .unwrap_or(false)
    }

    /// Returns true when the agent should be denied due to being unregistered.
    /// Only returns true when `require_registration` is enabled.
    pub fn should_deny_unregistered(&self, agent_id: &str) -> bool {
        self.require_registration && !self.is_agent_registered(agent_id)
    }

    /// Register an agent at runtime (complements config-defined agents).
    pub fn register_agent(&self, agent_id: &str) {
        if let Ok(mut registered) = self.registered_agents.write() {
            registered.insert(agent_id.to_string());
        }
        // Remove from unregistered if previously observed
        if let Ok(mut unregistered) = self.unregistered.write() {
            unregistered.remove(agent_id);
        }
    }

    /// Generate a full shadow AI discovery report.
    pub fn generate_report(&self) -> ShadowAiReport {
        let unregistered_agents: Vec<UnregisteredAgent> = self
            .unregistered
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default();

        let unapproved_tools: Vec<UnapprovedTool> = self
            .unapproved
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default();

        let unknown_servers: Vec<UnknownMcpServer> = self
            .unknown_servers
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default();

        let total_risk_score: f64 = unregistered_agents
            .iter()
            .map(|a| a.risk_score)
            .sum::<f64>()
            + unapproved_tools.len() as f64 * 0.3
            + unknown_servers.len() as f64 * 0.5;

        ShadowAiReport {
            unregistered_agents,
            unapproved_tools,
            unknown_servers,
            total_risk_score,
        }
    }

    /// Compute risk score for an unregistered agent.
    ///
    /// Heuristic: `min(1.0, request_count * tools_count / 100.0)`
    fn compute_risk_score(request_count: u64, tools_count: usize) -> f64 {
        let raw = request_count as f64 * tools_count as f64 / 100.0;
        raw.min(1.0)
    }

    /// Return the count of unregistered agents observed.
    pub fn unregistered_agent_count(&self) -> usize {
        self.unregistered.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Return the count of unapproved tools observed.
    pub fn unapproved_tool_count(&self) -> usize {
        self.unapproved.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Return the count of unknown servers observed.
    pub fn unknown_server_count(&self) -> usize {
        self.unknown_servers.read().map(|r| r.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_discovery() -> ShadowAiDiscovery {
        ShadowAiDiscovery::new(
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            false,
        )
    }

    fn configured_discovery() -> ShadowAiDiscovery {
        let mut registered = HashSet::new();
        registered.insert("agent-alpha".to_string());
        registered.insert("agent-beta".to_string());

        let mut approved = HashSet::new();
        approved.insert("filesystem".to_string());
        approved.insert("http".to_string());

        let mut servers = HashSet::new();
        servers.insert("server-1".to_string());

        ShadowAiDiscovery::new(registered, approved, servers, true)
    }

    #[test]
    fn test_observe_unregistered_agent() {
        let d = configured_discovery();
        d.observe_request("unknown-agent", "filesystem", None);

        assert_eq!(d.unregistered_agent_count(), 1);

        let report = d.generate_report();
        assert_eq!(report.unregistered_agents.len(), 1);
        assert_eq!(report.unregistered_agents[0].agent_id, "unknown-agent");
        assert_eq!(report.unregistered_agents[0].request_count, 1);
    }

    #[test]
    fn test_registered_agent_not_tracked() {
        let d = configured_discovery();
        d.observe_request("agent-alpha", "filesystem", None);

        assert_eq!(d.unregistered_agent_count(), 0);
    }

    #[test]
    fn test_observe_unapproved_tool() {
        let d = configured_discovery();
        d.observe_request("agent-alpha", "database", None);

        assert_eq!(d.unapproved_tool_count(), 1);

        let report = d.generate_report();
        assert_eq!(report.unapproved_tools.len(), 1);
        assert_eq!(report.unapproved_tools[0].tool_name, "database");
    }

    #[test]
    fn test_approved_tool_not_tracked() {
        let d = configured_discovery();
        d.observe_request("agent-alpha", "filesystem", None);

        assert_eq!(d.unapproved_tool_count(), 0);
    }

    #[test]
    fn test_empty_approved_tools_allows_all() {
        let d = empty_discovery();
        d.observe_request("any-agent", "any-tool", None);

        // With empty approved_tools, all tools are approved
        assert_eq!(d.unapproved_tool_count(), 0);
        assert!(d.is_tool_approved("any-tool"));
    }

    #[test]
    fn test_observe_unknown_server() {
        let d = configured_discovery();
        d.observe_request("agent-alpha", "filesystem", Some("rogue-server"));

        assert_eq!(d.unknown_server_count(), 1);

        let report = d.generate_report();
        assert_eq!(report.unknown_servers.len(), 1);
        assert_eq!(report.unknown_servers[0].server_id, "rogue-server");
    }

    #[test]
    fn test_known_server_not_tracked() {
        let d = configured_discovery();
        d.observe_request("agent-alpha", "filesystem", Some("server-1"));

        assert_eq!(d.unknown_server_count(), 0);
    }

    #[test]
    fn test_should_deny_unregistered_when_required() {
        let d = configured_discovery();
        assert!(d.should_deny_unregistered("unknown-agent"));
        assert!(!d.should_deny_unregistered("agent-alpha"));
    }

    #[test]
    fn test_should_deny_unregistered_when_not_required() {
        let d = empty_discovery();
        assert!(!d.should_deny_unregistered("any-agent"));
    }

    #[test]
    fn test_register_agent_at_runtime() {
        let d = configured_discovery();

        // First observe as unregistered
        d.observe_request("new-agent", "filesystem", None);
        assert_eq!(d.unregistered_agent_count(), 1);
        assert!(d.should_deny_unregistered("new-agent"));

        // Register at runtime
        d.register_agent("new-agent");
        assert_eq!(d.unregistered_agent_count(), 0);
        assert!(!d.should_deny_unregistered("new-agent"));
        assert!(d.is_agent_registered("new-agent"));
    }

    #[test]
    fn test_request_count_increments() {
        let d = configured_discovery();
        d.observe_request("unknown-agent", "filesystem", None);
        d.observe_request("unknown-agent", "filesystem", None);
        d.observe_request("unknown-agent", "http", None);

        let report = d.generate_report();
        assert_eq!(report.unregistered_agents[0].request_count, 3);
        assert_eq!(report.unregistered_agents[0].tools_used.len(), 2);
    }

    #[test]
    fn test_risk_score_computation() {
        // 1 request * 1 tool / 100 = 0.01
        assert!((ShadowAiDiscovery::compute_risk_score(1, 1) - 0.01).abs() < f64::EPSILON);

        // 10 requests * 10 tools / 100 = 1.0
        assert!((ShadowAiDiscovery::compute_risk_score(10, 10) - 1.0).abs() < f64::EPSILON);

        // 100 requests * 100 tools / 100 = 100.0 → capped at 1.0
        assert!((ShadowAiDiscovery::compute_risk_score(100, 100) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_total_risk_score_aggregation() {
        let d = configured_discovery();
        d.observe_request("unknown-1", "database", Some("rogue-srv"));
        d.observe_request("unknown-2", "shell", None);

        let report = d.generate_report();
        // 2 unregistered agents + 2 unapproved tools + 1 unknown server
        assert!(report.total_risk_score > 0.0);
    }

    #[test]
    fn test_bounded_unregistered_agents() {
        let d = empty_discovery();
        // Fill beyond limit — should not panic or grow unbounded
        for i in 0..MAX_UNREGISTERED_AGENTS + 100 {
            d.observe_request(&format!("agent-{}", i), "tool", None);
        }
        // All are unregistered since registered_agents is empty
        // but bounded at MAX_UNREGISTERED_AGENTS
        assert!(d.unregistered_agent_count() <= MAX_UNREGISTERED_AGENTS);
    }

    #[test]
    fn test_empty_agent_id_not_tracked() {
        let d = configured_discovery();
        d.observe_request("", "filesystem", None);
        assert_eq!(d.unregistered_agent_count(), 0);
    }

    #[test]
    fn test_empty_tool_name_not_tracked() {
        let d = configured_discovery();
        d.observe_request("unknown-agent", "", None);
        // Agent tracked but empty tool should not produce unapproved tool
        assert_eq!(d.unapproved_tool_count(), 0);
    }

    #[test]
    fn test_generate_report_empty() {
        let d = empty_discovery();
        let report = d.generate_report();
        assert!(report.unregistered_agents.is_empty());
        assert!(report.unapproved_tools.is_empty());
        assert!(report.unknown_servers.is_empty());
        assert!((report.total_risk_score - 0.0).abs() < f64::EPSILON);
    }
}
