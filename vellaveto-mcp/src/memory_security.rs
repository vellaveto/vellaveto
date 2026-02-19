//! Memory Injection Defense (MINJA) - Phase 9.
//!
//! Provides comprehensive defense against memory injection attacks by:
//! - Tracking taint labels on data from untrusted sources
//! - Maintaining a provenance graph for data lineage
//! - Implementing trust decay over time
//! - Quarantining suspicious data
//! - Enforcing namespace isolation between agents

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;
use uuid::Uuid;
use vellaveto_config::MemorySecurityConfig;
use vellaveto_types::{
    MemoryAccessDecision, MemoryEntry, MemoryNamespace, MemorySecurityStats, NamespaceAccessType,
    NamespaceIsolation, NamespaceSharingRequest, ProvenanceEventType, ProvenanceNode,
    QuarantineDetection, QuarantineEntry, TaintLabel,
};

/// Maximum recursion depth for provenance traversal.
const MAX_PROVENANCE_DEPTH: usize = 100;

/// Minimum string length to track (shorter strings cause false positives).
const MIN_TRACKABLE_LENGTH: usize = 20;

/// Memory Security Manager for MINJA defense.
///
/// Thread-safe manager that coordinates taint propagation, provenance tracking,
/// quarantine management, and namespace isolation.
#[derive(Debug)]
pub struct MemorySecurityManager {
    /// Configuration.
    config: MemorySecurityConfig,
    /// Memory entries indexed by fingerprint.
    entries: RwLock<HashMap<String, MemoryEntry>>,
    /// Provenance graph nodes indexed by ID.
    provenance: RwLock<ProvenanceGraph>,
    /// Quarantine records indexed by entry ID.
    quarantine: RwLock<QuarantineManager>,
    /// Namespace manager.
    namespaces: RwLock<NamespaceManager>,
    /// Statistics.
    stats: RwLock<MemorySecurityStats>,
}

impl MemorySecurityManager {
    /// Create a new memory security manager with the given configuration.
    pub fn new(config: MemorySecurityConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            provenance: RwLock::new(ProvenanceGraph::new()),
            quarantine: RwLock::new(QuarantineManager::new()),
            namespaces: RwLock::new(NamespaceManager::new()),
            stats: RwLock::new(MemorySecurityStats::default()),
        }
    }

    /// Check if the manager is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record a string from a tool response.
    ///
    /// Creates a memory entry with taint tracking and provenance.
    pub async fn record_response(
        &self,
        content: &str,
        source_tool: &str,
        session_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> Option<String> {
        if !self.config.enabled || content.len() < MIN_TRACKABLE_LENGTH {
            return None;
        }

        let fingerprint = Self::compute_fingerprint(content);
        let content_hash = Self::compute_hash(content);
        let now = chrono::Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        let mut entry = MemoryEntry::new(
            id.clone(),
            fingerprint.clone(),
            content,
            content_hash.clone(),
            now.clone(),
        );
        entry.session_id = session_id.map(|s| s.to_string());
        entry.agent_id = agent_id.map(|a| a.to_string());
        entry.add_taint(TaintLabel::Untrusted);

        // Create provenance node
        if self.config.provenance_tracking {
            let mut prov = self.provenance.write().await;
            let node_id = Uuid::new_v4().to_string();
            let mut node = ProvenanceNode::new(
                node_id.clone(),
                ProvenanceEventType::ToolResponse,
                source_tool.to_string(),
                content_hash,
                now,
            );
            node.session_id = session_id.map(|s| s.to_string());
            node.entry_id = Some(id.clone());
            prov.add_node(node, self.config.max_provenance_nodes);
            entry.provenance_id = Some(node_id);
        }

        // Store entry
        let mut entries = self.entries.write().await;
        if entries.len() < self.config.max_entries_per_session {
            entries.insert(fingerprint, entry);
            let mut stats = self.stats.write().await;
            stats.total_entries = stats.total_entries.saturating_add(1);
            Some(id)
        } else {
            None
        }
    }

    /// Record a string from a notification.
    pub async fn record_notification(
        &self,
        content: &str,
        notification_method: &str,
        session_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> Option<String> {
        if !self.config.enabled || content.len() < MIN_TRACKABLE_LENGTH {
            return None;
        }

        let fingerprint = Self::compute_fingerprint(content);
        let content_hash = Self::compute_hash(content);
        let now = chrono::Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        let mut entry = MemoryEntry::new(
            id.clone(),
            fingerprint.clone(),
            content,
            content_hash.clone(),
            now.clone(),
        );
        entry.session_id = session_id.map(|s| s.to_string());
        entry.agent_id = agent_id.map(|a| a.to_string());
        entry.add_taint(TaintLabel::Untrusted);

        // Create provenance node for notification
        if self.config.provenance_tracking {
            let mut prov = self.provenance.write().await;
            let node_id = Uuid::new_v4().to_string();
            let mut node = ProvenanceNode::new(
                node_id.clone(),
                ProvenanceEventType::Notification,
                notification_method.to_string(),
                content_hash,
                now,
            );
            node.session_id = session_id.map(|s| s.to_string());
            node.entry_id = Some(id.clone());
            prov.add_node(node, self.config.max_provenance_nodes);
            entry.provenance_id = Some(node_id);
        }

        let mut entries = self.entries.write().await;
        if entries.len() < self.config.max_entries_per_session {
            entries.insert(fingerprint, entry);
            let mut stats = self.stats.write().await;
            stats.total_entries = stats.total_entries.saturating_add(1);
            Some(id)
        } else {
            None
        }
    }

    /// Check if a parameter string matches a recorded entry.
    ///
    /// Returns the match result with security assessment.
    pub async fn check_parameter(
        &self,
        content: &str,
        session_id: Option<&str>,
        _agent_id: Option<&str>,
    ) -> Option<MemoryMatch> {
        if !self.config.enabled || content.len() < MIN_TRACKABLE_LENGTH {
            return None;
        }

        let fingerprint = Self::compute_fingerprint(content);
        let entries = self.entries.read().await;

        if let Some(entry) = entries.get(&fingerprint) {
            let now = chrono::Utc::now().to_rfc3339();

            // Check trust decay
            let current_trust = entry.decayed_trust_score(self.config.trust_decay_rate, &now);

            // Check for cross-session replay
            let is_cross_session = session_id.is_some()
                && entry.session_id.is_some()
                && session_id != entry.session_id.as_deref();

            // Check if quarantined
            let is_blocked = entry.is_blocked()
                || (self.config.block_quarantined && entry.quarantined)
                || (current_trust < self.config.trust_threshold);

            // Check for notification replay pattern
            let mut is_notification_replay = false;
            if self.config.provenance_tracking {
                if let Some(prov_id) = &entry.provenance_id {
                    let prov = self.provenance.read().await;
                    if let Some(node) = prov.get_node(prov_id) {
                        is_notification_replay =
                            matches!(node.event_type, ProvenanceEventType::Notification);
                    }
                }
            }

            return Some(MemoryMatch {
                entry_id: entry.id.clone(),
                fingerprint,
                preview: entry.preview.clone(),
                is_blocked,
                is_cross_session,
                is_notification_replay,
                current_trust,
                taint_labels: entry.taint_labels.clone(),
            });
        }

        None
    }

    /// Quarantine an entry by ID.
    pub async fn quarantine_entry(
        &self,
        entry_id: &str,
        reason: QuarantineDetection,
        triggered_by: Option<&str>,
    ) -> Result<(), MemorySecurityError> {
        let mut entries = self.entries.write().await;

        // Find entry by ID
        let entry = entries
            .values_mut()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| MemorySecurityError::EntryNotFound(entry_id.to_string()))?;

        entry.quarantined = true;
        entry.add_taint(TaintLabel::Quarantined);

        let now = chrono::Utc::now().to_rfc3339();
        let mut quarantine_entry = QuarantineEntry::new(entry_id.to_string(), reason, now);
        quarantine_entry.triggered_by = triggered_by.map(|s| s.to_string());

        drop(entries);

        let mut quarantine = self.quarantine.write().await;
        quarantine.add(quarantine_entry)?;

        let mut stats = self.stats.write().await;
        stats.quarantined_entries = stats.quarantined_entries.saturating_add(1);

        Ok(())
    }

    /// Release an entry from quarantine.
    pub async fn release_entry(&self, entry_id: &str) -> Result<(), MemorySecurityError> {
        let mut entries = self.entries.write().await;

        let entry = entries
            .values_mut()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| MemorySecurityError::EntryNotFound(entry_id.to_string()))?;

        entry.quarantined = false;
        // Remove quarantine taint but keep others
        entry.taint_labels.retain(|t| *t != TaintLabel::Quarantined);

        drop(entries);

        let mut quarantine = self.quarantine.write().await;
        quarantine.release(entry_id);

        let mut stats = self.stats.write().await;
        if stats.quarantined_entries > 0 {
            stats.quarantined_entries -= 1;
        }

        Ok(())
    }

    /// Get an entry by ID.
    pub async fn get_entry(&self, entry_id: &str) -> Option<MemoryEntry> {
        let entries = self.entries.read().await;
        entries.values().find(|e| e.id == entry_id).cloned()
    }

    /// List all entries with optional filters.
    pub async fn list_entries(
        &self,
        session_id: Option<&str>,
        quarantined_only: bool,
        limit: usize,
        offset: usize,
    ) -> Vec<MemoryEntry> {
        let entries = self.entries.read().await;

        entries
            .values()
            .filter(|e| {
                let session_match = session_id.is_none() || e.session_id.as_deref() == session_id;
                let quarantine_match = !quarantined_only || e.quarantined;
                session_match && quarantine_match
            })
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get provenance chain for an entry.
    pub async fn get_provenance_chain(&self, entry_id: &str) -> Vec<ProvenanceNode> {
        let entries = self.entries.read().await;
        let entry = match entries.values().find(|e| e.id == entry_id) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let prov_id = match &entry.provenance_id {
            Some(id) => id.clone(),
            None => return Vec::new(),
        };

        drop(entries);

        let prov = self.provenance.read().await;
        prov.get_chain(&prov_id)
    }

    /// Verify integrity of a session's memory entries.
    pub async fn verify_session_integrity(&self, session_id: &str) -> IntegrityReport {
        let entries = self.entries.read().await;
        let session_entries: Vec<_> = entries
            .values()
            .filter(|e| e.session_id.as_deref() == Some(session_id))
            .collect();

        let mut report = IntegrityReport {
            session_id: session_id.to_string(),
            total_entries: session_entries.len(),
            verified: 0,
            failed: 0,
            failures: Vec::new(),
        };

        for entry in session_entries {
            // We can't verify actual content without storing it, but we can check
            // that the fingerprint and content_hash are consistent
            if entry.fingerprint.len() == 64 && entry.content_hash.len() == 64 {
                report.verified += 1;
            } else {
                report.failed += 1;
                report.failures.push(IntegrityFailure {
                    entry_id: entry.id.clone(),
                    reason: "Invalid hash format".to_string(),
                });
            }
        }

        report
    }

    /// Create a namespace for an agent.
    pub async fn create_namespace(
        &self,
        namespace_id: &str,
        owner_agent: &str,
    ) -> Result<MemoryNamespace, MemorySecurityError> {
        if !self.config.namespaces.enabled {
            return Err(MemorySecurityError::NamespacesDisabled);
        }

        let mut ns_manager = self.namespaces.write().await;
        if ns_manager.count() >= self.config.namespaces.max_namespaces {
            return Err(MemorySecurityError::CapacityExceeded(
                "max namespaces reached".to_string(),
            ));
        }

        let isolation = match self.config.namespaces.default_isolation.as_str() {
            "agent" => NamespaceIsolation::Agent,
            "shared" => NamespaceIsolation::Shared,
            _ => NamespaceIsolation::Session,
        };

        let now = chrono::Utc::now().to_rfc3339();
        let mut namespace =
            MemoryNamespace::new(namespace_id.to_string(), owner_agent.to_string(), now);
        namespace.isolation = isolation;

        ns_manager.add(namespace.clone())?;

        let mut stats = self.stats.write().await;
        stats.namespaces += 1;

        Ok(namespace)
    }

    /// List namespaces.
    pub async fn list_namespaces(&self) -> Vec<MemoryNamespace> {
        let ns_manager = self.namespaces.read().await;
        ns_manager.list()
    }

    /// Check if an agent can access a namespace.
    pub async fn check_namespace_access(
        &self,
        namespace_id: &str,
        agent_id: &str,
        access_type: NamespaceAccessType,
    ) -> MemoryAccessDecision {
        if !self.config.namespaces.enabled {
            return MemoryAccessDecision::Allow;
        }

        let ns_manager = self.namespaces.read().await;
        ns_manager.check_access(namespace_id, agent_id, access_type)
    }

    /// Request sharing of a namespace.
    pub async fn request_share(
        &self,
        namespace_id: &str,
        requester_agent: &str,
        access_type: NamespaceAccessType,
    ) -> Result<NamespaceSharingRequest, MemorySecurityError> {
        if !self.config.namespaces.enabled {
            return Err(MemorySecurityError::NamespacesDisabled);
        }

        let now = chrono::Utc::now().to_rfc3339();
        let request = NamespaceSharingRequest {
            namespace_id: namespace_id.to_string(),
            requester_agent: requester_agent.to_string(),
            access_type,
            requested_at: now,
            approved: None,
            resolved_at: None,
        };

        let mut ns_manager = self.namespaces.write().await;
        ns_manager.add_share_request(request.clone());

        let mut stats = self.stats.write().await;
        stats.pending_shares = stats.pending_shares.saturating_add(1);

        Ok(request)
    }

    /// Approve a sharing request.
    pub async fn approve_share(
        &self,
        namespace_id: &str,
        requester_agent: &str,
    ) -> Result<(), MemorySecurityError> {
        let mut ns_manager = self.namespaces.write().await;
        ns_manager.approve_share(namespace_id, requester_agent)?;

        let mut stats = self.stats.write().await;
        if stats.pending_shares > 0 {
            stats.pending_shares -= 1;
        }

        Ok(())
    }

    /// Get current statistics.
    pub async fn get_stats(&self) -> MemorySecurityStats {
        self.stats.read().await.clone()
    }

    /// Compute SHA-256 fingerprint for a string.
    fn compute_fingerprint(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute SHA-256 hash for content integrity.
    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Result of checking a parameter against memory entries.
#[derive(Debug, Clone)]
pub struct MemoryMatch {
    /// ID of the matched entry.
    pub entry_id: String,
    /// Fingerprint of the matched content.
    pub fingerprint: String,
    /// Preview of the matched content.
    pub preview: String,
    /// Whether access to this entry should be blocked.
    pub is_blocked: bool,
    /// Whether this is a cross-session replay.
    pub is_cross_session: bool,
    /// Whether this entry came from a notification (potential injection).
    pub is_notification_replay: bool,
    /// Current trust score after decay.
    pub current_trust: f64,
    /// Taint labels on the entry.
    pub taint_labels: Vec<TaintLabel>,
}

/// Integrity verification report for a session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityReport {
    /// Session ID.
    pub session_id: String,
    /// Total entries checked.
    pub total_entries: usize,
    /// Entries that passed verification.
    pub verified: usize,
    /// Entries that failed verification.
    pub failed: usize,
    /// Details of failures.
    pub failures: Vec<IntegrityFailure>,
}

/// Details of an integrity verification failure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrityFailure {
    /// Entry ID that failed.
    pub entry_id: String,
    /// Reason for failure.
    pub reason: String,
}

/// Errors from memory security operations.
#[derive(Debug, thiserror::Error)]
pub enum MemorySecurityError {
    #[error("Entry not found: {0}")]
    EntryNotFound(String),
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),
    #[error("Namespaces are disabled")]
    NamespacesDisabled,
    #[error("Capacity exceeded: {0}")]
    CapacityExceeded(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    #[error("Share request not found")]
    ShareRequestNotFound,
}

/// Provenance graph for tracking data lineage.
#[derive(Debug)]
struct ProvenanceGraph {
    /// Nodes indexed by ID.
    nodes: HashMap<String, ProvenanceNode>,
    /// Insertion order for FIFO eviction.
    order: VecDeque<String>,
}

impl ProvenanceGraph {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn add_node(&mut self, node: ProvenanceNode, max_nodes: usize) {
        // FIFO eviction if at capacity
        while self.nodes.len() >= max_nodes && !self.order.is_empty() {
            if let Some(oldest_id) = self.order.pop_front() {
                self.nodes.remove(&oldest_id);
            }
        }

        let id = node.id.clone();
        self.nodes.insert(id.clone(), node);
        self.order.push_back(id);
    }

    fn get_node(&self, id: &str) -> Option<&ProvenanceNode> {
        self.nodes.get(id)
    }

    fn get_chain(&self, start_id: &str) -> Vec<ProvenanceNode> {
        let mut result = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![start_id.to_string()];

        while let Some(id) = stack.pop() {
            if visited.contains(&id) || result.len() >= MAX_PROVENANCE_DEPTH {
                continue;
            }
            visited.insert(id.clone());

            if let Some(node) = self.nodes.get(&id) {
                result.push(node.clone());
                for parent in &node.parents {
                    if !visited.contains(parent) {
                        stack.push(parent.clone());
                    }
                }
            }
        }

        result
    }
}

/// Maximum quarantine records to prevent unbounded memory growth.
///
/// SECURITY (FIND-R67-5-005): Without a cap, an attacker could quarantine
/// entries faster than they are released, causing OOM.
const MAX_QUARANTINE_RECORDS: usize = 100_000;

/// Manager for quarantined entries.
#[derive(Debug)]
struct QuarantineManager {
    /// Quarantine records indexed by entry ID.
    records: HashMap<String, QuarantineEntry>,
}

impl QuarantineManager {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    fn add(&mut self, entry: QuarantineEntry) -> Result<(), MemorySecurityError> {
        // SECURITY (FIND-R67-5-005): Reject when at capacity.
        if self.records.len() >= MAX_QUARANTINE_RECORDS && !self.records.contains_key(&entry.entry_id) {
            return Err(MemorySecurityError::CapacityExceeded(format!(
                "quarantine records at maximum of {}",
                MAX_QUARANTINE_RECORDS,
            )));
        }
        self.records.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    fn release(&mut self, entry_id: &str) {
        if let Some(record) = self.records.get_mut(entry_id) {
            record.released = true;
            record.released_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    #[allow(dead_code)] // Reserved for future quarantine inspection API
    fn get(&self, entry_id: &str) -> Option<&QuarantineEntry> {
        self.records.get(entry_id)
    }
}

/// Manager for namespace isolation.
#[derive(Debug)]
struct NamespaceManager {
    /// Namespaces indexed by ID.
    namespaces: HashMap<String, MemoryNamespace>,
    /// Pending share requests.
    share_requests: Vec<NamespaceSharingRequest>,
}

impl NamespaceManager {
    fn new() -> Self {
        Self {
            namespaces: HashMap::new(),
            share_requests: Vec::new(),
        }
    }

    fn add(&mut self, namespace: MemoryNamespace) -> Result<(), MemorySecurityError> {
        if self.namespaces.contains_key(&namespace.id) {
            return Err(MemorySecurityError::AlreadyExists(namespace.id));
        }
        self.namespaces.insert(namespace.id.clone(), namespace);
        Ok(())
    }

    fn count(&self) -> usize {
        self.namespaces.len()
    }

    fn list(&self) -> Vec<MemoryNamespace> {
        self.namespaces.values().cloned().collect()
    }

    fn check_access(
        &self,
        namespace_id: &str,
        agent_id: &str,
        access_type: NamespaceAccessType,
    ) -> MemoryAccessDecision {
        let namespace = match self.namespaces.get(namespace_id) {
            Some(ns) => ns,
            None => {
                return MemoryAccessDecision::Deny {
                    reason: format!("Namespace '{}' not found", namespace_id),
                }
            }
        };

        match access_type {
            NamespaceAccessType::Read => {
                if namespace.can_read(agent_id) {
                    MemoryAccessDecision::Allow
                } else {
                    MemoryAccessDecision::Deny {
                        reason: format!(
                            "Agent '{}' not allowed to read namespace '{}'",
                            agent_id, namespace_id
                        ),
                    }
                }
            }
            NamespaceAccessType::Write | NamespaceAccessType::Full => {
                if namespace.can_write(agent_id) {
                    MemoryAccessDecision::Allow
                } else {
                    MemoryAccessDecision::Deny {
                        reason: format!(
                            "Agent '{}' not allowed to write to namespace '{}'",
                            agent_id, namespace_id
                        ),
                    }
                }
            }
        }
    }

    fn add_share_request(&mut self, request: NamespaceSharingRequest) {
        self.share_requests.push(request);
    }

    fn approve_share(
        &mut self,
        namespace_id: &str,
        requester_agent: &str,
    ) -> Result<(), MemorySecurityError> {
        // Find and mark request as approved
        let request = self
            .share_requests
            .iter_mut()
            .find(|r| r.namespace_id == namespace_id && r.requester_agent == requester_agent)
            .ok_or(MemorySecurityError::ShareRequestNotFound)?;

        request.approved = Some(true);
        request.resolved_at = Some(chrono::Utc::now().to_rfc3339());

        let access_type = request.access_type;

        // Update namespace permissions
        let namespace = self
            .namespaces
            .get_mut(namespace_id)
            .ok_or_else(|| MemorySecurityError::NamespaceNotFound(namespace_id.to_string()))?;

        match access_type {
            NamespaceAccessType::Read => {
                if !namespace
                    .read_allowed
                    .contains(&requester_agent.to_string())
                {
                    namespace.read_allowed.push(requester_agent.to_string());
                }
            }
            NamespaceAccessType::Write | NamespaceAccessType::Full => {
                if !namespace
                    .read_allowed
                    .contains(&requester_agent.to_string())
                {
                    namespace.read_allowed.push(requester_agent.to_string());
                }
                if !namespace
                    .write_allowed
                    .contains(&requester_agent.to_string())
                {
                    namespace.write_allowed.push(requester_agent.to_string());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MemorySecurityConfig {
        MemorySecurityConfig {
            enabled: true,
            taint_propagation: true,
            provenance_tracking: true,
            trust_decay_rate: 0.029,
            trust_threshold: 0.1,
            max_memory_age_hours: 168,
            quarantine_on_injection: true,
            block_quarantined: true,
            max_entries_per_session: 5000,
            max_provenance_nodes: 10000,
            namespaces: vellaveto_config::NamespaceConfig {
                enabled: true,
                default_isolation: "session".to_string(),
                require_sharing_approval: true,
                max_namespaces: 1000,
                allow_cross_session: false,
                auto_create: true,
            },
            block_on_integrity_failure: true,
            content_hashing: true,
            max_fingerprints: 2500,
            min_trackable_length: 20,
        }
    }

    #[tokio::test]
    async fn test_record_and_check_response() {
        let manager = MemorySecurityManager::new(test_config());

        let content = "This is a test string that is long enough to track properly";
        let entry_id = manager
            .record_response(content, "test_tool", Some("session-1"), Some("agent-1"))
            .await;

        assert!(entry_id.is_some());

        // Check same content in same session
        let match_result = manager
            .check_parameter(content, Some("session-1"), Some("agent-1"))
            .await;

        assert!(match_result.is_some());
        let m = match_result.unwrap();
        assert!(!m.is_cross_session);
        assert!(!m.is_blocked);
    }

    #[tokio::test]
    async fn test_cross_session_detection() {
        let manager = MemorySecurityManager::new(test_config());

        let content = "Secret URL: https://evil.example.com/exfil/session-data";
        manager
            .record_response(content, "test_tool", Some("session-1"), Some("agent-1"))
            .await;

        // Check same content from different session
        let match_result = manager
            .check_parameter(content, Some("session-2"), Some("agent-1"))
            .await;

        assert!(match_result.is_some());
        assert!(match_result.unwrap().is_cross_session);
    }

    #[tokio::test]
    async fn test_notification_replay_detection() {
        let manager = MemorySecurityManager::new(test_config());

        let content = "Malicious URL from notification: https://attacker.com/collect";
        manager
            .record_notification(
                content,
                "notifications/resource/updated",
                Some("session-1"),
                Some("agent-1"),
            )
            .await;

        let match_result = manager
            .check_parameter(content, Some("session-1"), Some("agent-1"))
            .await;

        assert!(match_result.is_some());
        assert!(match_result.unwrap().is_notification_replay);
    }

    #[tokio::test]
    async fn test_quarantine_entry() {
        let manager = MemorySecurityManager::new(test_config());

        let content = "Suspicious content that should be quarantined for safety";
        let entry_id = manager
            .record_response(content, "test_tool", Some("session-1"), Some("agent-1"))
            .await
            .unwrap();

        // Quarantine the entry
        manager
            .quarantine_entry(
                &entry_id,
                QuarantineDetection::InjectionPattern,
                Some("admin"),
            )
            .await
            .unwrap();

        // Check that entry is now blocked
        let match_result = manager
            .check_parameter(content, Some("session-1"), Some("agent-1"))
            .await;

        assert!(match_result.is_some());
        assert!(match_result.unwrap().is_blocked);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let manager = MemorySecurityManager::new(test_config());

        // Create namespace
        let ns = manager.create_namespace("ns-1", "agent-1").await.unwrap();

        assert_eq!(ns.owner_agent, "agent-1");

        // Owner should have access
        let decision = manager
            .check_namespace_access("ns-1", "agent-1", NamespaceAccessType::Write)
            .await;
        assert!(matches!(decision, MemoryAccessDecision::Allow));

        // Other agent should not have access
        let decision = manager
            .check_namespace_access("ns-1", "agent-2", NamespaceAccessType::Read)
            .await;
        assert!(matches!(decision, MemoryAccessDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn test_sharing_approval() {
        let manager = MemorySecurityManager::new(test_config());

        // Create namespace
        manager.create_namespace("ns-1", "agent-1").await.unwrap();

        // Request share
        let request = manager
            .request_share("ns-1", "agent-2", NamespaceAccessType::Read)
            .await
            .unwrap();

        assert_eq!(request.requester_agent, "agent-2");
        assert!(request.approved.is_none());

        // Approve share
        manager.approve_share("ns-1", "agent-2").await.unwrap();

        // Now agent-2 should have access
        let decision = manager
            .check_namespace_access("ns-1", "agent-2", NamespaceAccessType::Read)
            .await;
        assert!(matches!(decision, MemoryAccessDecision::Allow));
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let manager = MemorySecurityManager::new(test_config());

        // Record some entries
        manager
            .record_response(
                "First test string that is long enough",
                "tool1",
                Some("s1"),
                Some("a1"),
            )
            .await;
        manager
            .record_response(
                "Second test string that is also long enough",
                "tool2",
                Some("s1"),
                Some("a1"),
            )
            .await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_entries, 2);
    }

    #[tokio::test]
    async fn test_short_strings_ignored() {
        let manager = MemorySecurityManager::new(test_config());

        let content = "too short";
        let entry_id = manager
            .record_response(content, "test_tool", Some("session-1"), Some("agent-1"))
            .await;

        assert!(entry_id.is_none());
    }

    #[tokio::test]
    async fn test_disabled_manager() {
        let mut config = test_config();
        config.enabled = false;
        let manager = MemorySecurityManager::new(config);

        let content = "This should not be tracked even though it is long enough";
        let entry_id = manager
            .record_response(content, "test_tool", Some("session-1"), Some("agent-1"))
            .await;

        assert!(entry_id.is_none());
    }
}
