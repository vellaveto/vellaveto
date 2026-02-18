//! Memory Injection Defense (MINJA) types — taint tracking, provenance,
//! quarantine, namespace isolation, and memory security statistics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Taint labels for tracking data provenance and trust level.
///
/// Memory entries are tagged with taint labels to indicate their source
/// and security properties. Taint propagates when derived data is created.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TaintLabel {
    /// Data from an untrusted source (external tool response, notification).
    Untrusted,
    /// Data that has been sanitized or validated.
    Sanitized,
    /// Data that is quarantined due to security concerns.
    Quarantined,
    /// Data that contains sensitive information (PII, secrets).
    Sensitive,
    /// Data that originated from a different agent (cross-agent flow).
    CrossAgent,
    /// Data that has been replayed from a previous session.
    Replayed,
    /// Data derived from multiple sources with mixed trust levels.
    MixedProvenance,
    /// Data that failed integrity verification.
    IntegrityFailed,
}

impl fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaintLabel::Untrusted => write!(f, "untrusted"),
            TaintLabel::Sanitized => write!(f, "sanitized"),
            TaintLabel::Quarantined => write!(f, "quarantined"),
            TaintLabel::Sensitive => write!(f, "sensitive"),
            TaintLabel::CrossAgent => write!(f, "cross_agent"),
            TaintLabel::Replayed => write!(f, "replayed"),
            TaintLabel::MixedProvenance => write!(f, "mixed_provenance"),
            TaintLabel::IntegrityFailed => write!(f, "integrity_failed"),
        }
    }
}

/// Maximum number of taint labels per memory entry.
pub const MAX_TAINT_LABELS: usize = 16;

/// A memory entry with provenance tracking for MINJA defense.
///
/// Represents a notable string or data fragment recorded from tool responses,
/// notifications, or other sources. Tracks access patterns, trust scores,
/// and provenance for detecting memory injection attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryEntry {
    /// Unique identifier for this entry (UUID v4).
    pub id: String,
    /// SHA-256 fingerprint of the content.
    pub fingerprint: String,
    /// Truncated preview of the content (first 100 chars).
    pub preview: String,
    /// ISO 8601 timestamp when the entry was first recorded.
    pub recorded_at: String,
    /// ISO 8601 timestamp when the entry was last accessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accessed: Option<String>,
    /// Number of times this entry has been accessed (matched in parameters).
    #[serde(default)]
    pub access_count: u64,
    /// Taint labels associated with this entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_labels: Vec<TaintLabel>,
    /// Current trust score (0.0 = no trust, 1.0 = full trust).
    /// Decays over time based on trust_decay_rate.
    #[serde(default = "default_trust_score")]
    pub trust_score: f64,
    /// ID of the provenance node that created this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_id: Option<String>,
    /// Whether this entry is currently quarantined.
    #[serde(default)]
    pub quarantined: bool,
    /// Namespace this entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Session ID this entry belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent ID that created this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// SHA-256 hash of the full content for integrity verification.
    pub content_hash: String,
}

fn default_trust_score() -> f64 {
    1.0
}

impl MemoryEntry {
    /// Maximum preview length in characters.
    pub const MAX_PREVIEW_LENGTH: usize = 100;

    /// Validate that all f64 fields are finite (not NaN or Infinity)
    /// and that trust_score is consistent with taint_labels.
    ///
    /// SECURITY (FIND-R46-018): Tainted memory entries (those with non-empty
    /// taint_labels containing security-relevant labels like Untrusted,
    /// Quarantined, IntegrityFailed, or MixedProvenance) must not have a
    /// perfect trust score of 1.0. A trust_score of 1.0 on tainted data
    /// could cause downstream consumers to skip security checks.
    pub fn validate(&self) -> Result<(), String> {
        if !self.trust_score.is_finite() {
            return Err(format!(
                "MemoryEntry '{}' trust_score is not finite: {}",
                self.id, self.trust_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate trust_score is in documented [0.0, 1.0] range.
        if self.trust_score < 0.0 || self.trust_score > 1.0 {
            return Err(format!(
                "MemoryEntry '{}' trust_score must be in [0.0, 1.0], got {}",
                self.id, self.trust_score
            ));
        }

        // Security-relevant taint labels that are incompatible with perfect trust
        let has_security_taint = self.taint_labels.iter().any(|label| {
            matches!(
                label,
                TaintLabel::Untrusted
                    | TaintLabel::Quarantined
                    | TaintLabel::IntegrityFailed
                    | TaintLabel::MixedProvenance
                    | TaintLabel::Replayed
            )
        });

        if has_security_taint && self.trust_score >= 1.0 {
            return Err(format!(
                "MemoryEntry '{}' has security-relevant taint labels {:?} but trust_score is {} (must be < 1.0)",
                self.id, self.taint_labels, self.trust_score
            ));
        }

        Ok(())
    }

    /// Validate that all f64 fields are finite (not NaN or Infinity).
    #[deprecated(
        since = "4.0.1",
        note = "use validate() which also checks taint/trust consistency"
    )]
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.trust_score.is_finite() {
            return Err(format!(
                "MemoryEntry '{}' trust_score is not finite: {}",
                self.id, self.trust_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate trust_score is in documented [0.0, 1.0] range.
        if self.trust_score < 0.0 || self.trust_score > 1.0 {
            return Err(format!(
                "MemoryEntry '{}' trust_score must be in [0.0, 1.0], got {}",
                self.id, self.trust_score
            ));
        }
        Ok(())
    }

    /// Create a new memory entry with default values.
    pub fn new(
        id: String,
        fingerprint: String,
        content: &str,
        content_hash: String,
        recorded_at: String,
    ) -> Self {
        let preview = if content.len() > Self::MAX_PREVIEW_LENGTH {
            let mut end = Self::MAX_PREVIEW_LENGTH;
            while !content.is_char_boundary(end) && end > 0 {
                end -= 1;
            }
            format!("{}...", &content[..end])
        } else {
            content.to_string()
        };

        Self {
            id,
            fingerprint,
            preview,
            recorded_at,
            last_accessed: None,
            access_count: 0,
            taint_labels: vec![TaintLabel::Untrusted],
            // SECURITY (FIND-R46-018): New entries start Untrusted, so trust
            // must be < 1.0 to be consistent with the taint label. 0.5 is a
            // reasonable default for unverified data from external sources.
            trust_score: 0.5,
            provenance_id: None,
            quarantined: false,
            namespace: None,
            session_id: None,
            agent_id: None,
            content_hash,
        }
    }

    /// Check if this entry is tainted with a specific label.
    pub fn has_taint(&self, label: TaintLabel) -> bool {
        self.taint_labels.contains(&label)
    }

    /// Add a taint label if not already present and under the limit.
    pub fn add_taint(&mut self, label: TaintLabel) -> bool {
        if self.taint_labels.len() >= MAX_TAINT_LABELS {
            return false;
        }
        if !self.taint_labels.contains(&label) {
            self.taint_labels.push(label);
            true
        } else {
            false
        }
    }

    /// Check if the entry should be blocked based on quarantine status.
    pub fn is_blocked(&self) -> bool {
        self.quarantined || self.has_taint(TaintLabel::Quarantined)
    }

    /// Calculate the current trust score after decay.
    /// Uses exponential decay: trust(t) = initial_trust * e^(-λ * age_hours)
    ///
    /// SECURITY (FIND-P1-6): Returns `0.0` (minimum trust / fail-closed) when
    /// timestamps cannot be parsed. Previously returned the full undecayed trust
    /// score on parse failure, which meant corrupt timestamps bypassed trust decay.
    pub fn decayed_trust_score(&self, decay_rate: f64, current_time: &str) -> f64 {
        match Self::hours_since(&self.recorded_at, current_time) {
            Some(age_hours) => self.trust_score * (-decay_rate * age_hours).exp(),
            None => {
                // Fail-closed: corrupt/unparseable timestamps → minimum trust
                0.0
            }
        }
    }

    /// Calculate hours between two ISO 8601 timestamps.
    ///
    /// SECURITY (FIND-P1-6): Returns `None` if either timestamp fails to parse,
    /// rather than silently returning `0.0` which would bypass trust decay.
    fn hours_since(start: &str, end: &str) -> Option<f64> {
        let start_secs = Self::parse_timestamp(start)?;
        let end_secs = Self::parse_timestamp(end)?;

        if end_secs > start_secs {
            Some((end_secs - start_secs) as f64 / 3600.0)
        } else {
            // end <= start: zero elapsed time (not negative)
            Some(0.0)
        }
    }

    /// Parse an ISO 8601 timestamp to Unix seconds (approximate).
    ///
    /// SECURITY (FIND-P1-6): Validates that month >= 1, day >= 1, and
    /// year >= 1970 to prevent underflow in the epoch calculation.
    fn parse_timestamp(ts: &str) -> Option<u64> {
        // Simplified parsing: YYYY-MM-DDTHH:MM:SSZ
        if ts.len() < 19 {
            return None;
        }
        let year: u64 = ts.get(0..4)?.parse().ok()?;
        let month: u64 = ts.get(5..7)?.parse().ok()?;
        let day: u64 = ts.get(8..10)?.parse().ok()?;
        let hour: u64 = ts.get(11..13)?.parse().ok()?;
        let min: u64 = ts.get(14..16)?.parse().ok()?;
        let sec: u64 = ts.get(17..19)?.parse().ok()?;

        // SECURITY (FIND-P1-6): Reject invalid month/day/year values that
        // would cause underflow or produce nonsensical results.
        if year < 1970 || month == 0 || month > 12 || day == 0 || day > 31 {
            return None;
        }
        if hour > 23 || min > 59 || sec > 60 {
            // sec == 60 is valid for leap seconds in ISO 8601, but > 60 is not
            return None;
        }

        // Approximate calculation (ignores leap years, etc.)
        let days_since_epoch = (year - 1970) * 365 + (month - 1) * 30 + day;
        Some(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec)
    }
}

/// Event types for provenance tracking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEventType {
    /// Data received from a tool response.
    ToolResponse,
    /// Data received from a notification.
    Notification,
    /// Data derived from other entries (transformation, aggregation).
    Derivation,
    /// Data replayed from a previous request.
    Replay,
    /// Data received from external source (user input, API).
    ExternalInput,
    /// Data created by the agent itself.
    AgentGenerated,
    /// Data received from another agent.
    CrossAgentReceive,
    /// Data sent to another agent.
    CrossAgentSend,
    /// Data restored from persistent storage.
    Restore,
    /// Data sanitized or validated.
    Sanitization,
}

impl fmt::Display for ProvenanceEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvenanceEventType::ToolResponse => write!(f, "tool_response"),
            ProvenanceEventType::Notification => write!(f, "notification"),
            ProvenanceEventType::Derivation => write!(f, "derivation"),
            ProvenanceEventType::Replay => write!(f, "replay"),
            ProvenanceEventType::ExternalInput => write!(f, "external_input"),
            ProvenanceEventType::AgentGenerated => write!(f, "agent_generated"),
            ProvenanceEventType::CrossAgentReceive => write!(f, "cross_agent_receive"),
            ProvenanceEventType::CrossAgentSend => write!(f, "cross_agent_send"),
            ProvenanceEventType::Restore => write!(f, "restore"),
            ProvenanceEventType::Sanitization => write!(f, "sanitization"),
        }
    }
}

/// A node in the provenance graph tracking data lineage.
///
/// Forms a DAG (directed acyclic graph) where edges point from parent
/// entries to derived entries. Used to detect suspicious patterns like
/// notification→replay chains or cross-session data flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceNode {
    /// Unique identifier for this node (UUID v4).
    pub id: String,
    /// Type of event that created this node.
    pub event_type: ProvenanceEventType,
    /// ISO 8601 timestamp when this node was created.
    pub timestamp: String,
    /// Source identifier (tool name, notification method, agent ID).
    pub source: String,
    /// Session ID where this event occurred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Parent node IDs (entries this was derived from).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<String>,
    /// SHA-256 hash of the content at this node.
    pub content_hash: String,
    /// Memory entry ID associated with this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    /// Additional metadata about the provenance event.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl ProvenanceNode {
    /// Maximum number of parent references per node.
    pub const MAX_PARENTS: usize = 64;

    /// Create a new provenance node.
    pub fn new(
        id: String,
        event_type: ProvenanceEventType,
        source: String,
        content_hash: String,
        timestamp: String,
    ) -> Self {
        Self {
            id,
            event_type,
            timestamp,
            source,
            session_id: None,
            parents: Vec::new(),
            content_hash,
            entry_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Maximum number of metadata entries per node.
    pub const MAX_METADATA_ENTRIES: usize = 64;

    /// Maximum length of the `id` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_ID_LEN: usize = 256;

    /// Maximum length of the `source` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_SOURCE_LEN: usize = 1024;

    /// Maximum length of the `content_hash` field.
    ///
    /// SECURITY (FIND-R51-014): Bound string fields to prevent memory exhaustion.
    pub const MAX_CONTENT_HASH_LEN: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-003): MAX_PARENTS was declared but never enforced.
    /// Deserialized payloads can contain arbitrarily many parents/metadata.
    ///
    /// SECURITY (FIND-R51-014): Also validates string field lengths for id,
    /// source, and content_hash to prevent memory exhaustion via crafted payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "ProvenanceNode id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ID_LEN
            ));
        }
        if self.source.len() > Self::MAX_SOURCE_LEN {
            return Err(format!(
                "ProvenanceNode '{}' source length {} exceeds max {}",
                self.id,
                self.source.len(),
                Self::MAX_SOURCE_LEN
            ));
        }
        if self.content_hash.len() > Self::MAX_CONTENT_HASH_LEN {
            return Err(format!(
                "ProvenanceNode '{}' content_hash length {} exceeds max {}",
                self.id,
                self.content_hash.len(),
                Self::MAX_CONTENT_HASH_LEN
            ));
        }
        if self.parents.len() > Self::MAX_PARENTS {
            return Err(format!(
                "ProvenanceNode '{}' has {} parents (max {})",
                self.id,
                self.parents.len(),
                Self::MAX_PARENTS
            ));
        }
        if self.metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(format!(
                "ProvenanceNode '{}' has {} metadata entries (max {})",
                self.id,
                self.metadata.len(),
                Self::MAX_METADATA_ENTRIES
            ));
        }
        Ok(())
    }

    /// Check if this node represents a suspicious pattern.
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self.event_type,
            ProvenanceEventType::Replay | ProvenanceEventType::CrossAgentReceive
        )
    }
}

/// Reason for quarantining a memory entry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineDetection {
    /// Entry matched injection patterns.
    InjectionPattern,
    /// Suspicious data flow pattern detected.
    SuspiciousDataFlow,
    /// Trust score below threshold.
    LowTrust,
    /// Cross-session data replay detected.
    CrossSessionReplay,
    /// Notification→tool_call chain detected.
    NotificationReplay,
    /// Content integrity verification failed.
    IntegrityFailure,
    /// Manual quarantine by administrator.
    ManualQuarantine,
    /// Entry from untrusted source exceeded access threshold.
    ExcessiveAccess,
    /// Entry contains sensitive data patterns.
    SensitiveData,
}

impl fmt::Display for QuarantineDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuarantineDetection::InjectionPattern => write!(f, "injection_pattern"),
            QuarantineDetection::SuspiciousDataFlow => write!(f, "suspicious_data_flow"),
            QuarantineDetection::LowTrust => write!(f, "low_trust"),
            QuarantineDetection::CrossSessionReplay => write!(f, "cross_session_replay"),
            QuarantineDetection::NotificationReplay => write!(f, "notification_replay"),
            QuarantineDetection::IntegrityFailure => write!(f, "integrity_failure"),
            QuarantineDetection::ManualQuarantine => write!(f, "manual_quarantine"),
            QuarantineDetection::ExcessiveAccess => write!(f, "excessive_access"),
            QuarantineDetection::SensitiveData => write!(f, "sensitive_data"),
        }
    }
}

/// Record of a quarantined memory entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineEntry {
    /// ID of the quarantined memory entry.
    pub entry_id: String,
    /// Reason for quarantine.
    pub reason: QuarantineDetection,
    /// ISO 8601 timestamp when quarantine was applied.
    pub quarantined_at: String,
    /// Optional description of the quarantine reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Agent or system that triggered the quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// Whether the quarantine was lifted.
    #[serde(default)]
    pub released: bool,
    /// ISO 8601 timestamp when quarantine was released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
}

impl QuarantineEntry {
    /// Create a new quarantine entry.
    pub fn new(entry_id: String, reason: QuarantineDetection, quarantined_at: String) -> Self {
        Self {
            entry_id,
            reason,
            quarantined_at,
            description: None,
            triggered_by: None,
            released: false,
            released_at: None,
        }
    }
}

/// Memory namespace for agent isolation.
///
/// Namespaces provide logical isolation between agents and sessions.
/// Access control policies determine which agents can read/write to
/// which namespaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryNamespace {
    /// Unique namespace identifier.
    pub id: String,
    /// Agent ID that owns this namespace.
    pub owner_agent: String,
    /// Agent IDs allowed to read from this namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_allowed: Vec<String>,
    /// Agent IDs allowed to write to this namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_allowed: Vec<String>,
    /// ISO 8601 timestamp when namespace was created.
    pub created_at: String,
    /// Isolation level for the namespace.
    #[serde(default)]
    pub isolation: NamespaceIsolation,
    /// Whether this namespace is the default for its owner.
    #[serde(default)]
    pub is_default: bool,
}

impl MemoryNamespace {
    /// Create a new namespace with the given owner.
    ///
    /// FIND-P3-017: Minimized clones — `owner_agent` is cloned once for
    /// `read_allowed`, once for `write_allowed`, and the original is moved
    /// into the `owner_agent` field.
    pub fn new(id: String, owner_agent: String, created_at: String) -> Self {
        let read_allowed = vec![owner_agent.clone()];
        let write_allowed = vec![owner_agent.clone()];
        Self {
            id,
            owner_agent,
            read_allowed,
            write_allowed,
            created_at,
            isolation: NamespaceIsolation::default(),
            is_default: false,
        }
    }

    /// Check if an agent can read from this namespace.
    pub fn can_read(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id || self.read_allowed.iter().any(|a| a == agent_id || a == "*")
    }

    /// Check if an agent can write to this namespace.
    pub fn can_write(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id || self.write_allowed.iter().any(|a| a == agent_id || a == "*")
    }

    /// Maximum ACL entries per namespace.
    pub const MAX_ACL_ENTRIES: usize = 1000;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-008): Unbounded read_allowed/write_allowed from deserialization.
    pub fn validate(&self) -> Result<(), String> {
        if self.read_allowed.len() > Self::MAX_ACL_ENTRIES {
            return Err(format!(
                "MemoryNamespace '{}' has {} read_allowed entries (max {})",
                self.id,
                self.read_allowed.len(),
                Self::MAX_ACL_ENTRIES
            ));
        }
        if self.write_allowed.len() > Self::MAX_ACL_ENTRIES {
            return Err(format!(
                "MemoryNamespace '{}' has {} write_allowed entries (max {})",
                self.id,
                self.write_allowed.len(),
                Self::MAX_ACL_ENTRIES
            ));
        }
        Ok(())
    }
}

/// Namespace isolation level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceIsolation {
    /// Isolated per session (default).
    #[default]
    Session,
    /// Isolated per agent (shared across sessions).
    Agent,
    /// Shared namespace (accessible by allowed agents).
    Shared,
}

impl fmt::Display for NamespaceIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceIsolation::Session => write!(f, "session"),
            NamespaceIsolation::Agent => write!(f, "agent"),
            NamespaceIsolation::Shared => write!(f, "shared"),
        }
    }
}

/// Decision for memory access requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessDecision {
    /// Access is allowed.
    Allow,
    /// Access is denied with a reason.
    Deny { reason: String },
    /// Access requires manual approval.
    RequireApproval { reason: String },
}

impl fmt::Display for MemoryAccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAccessDecision::Allow => write!(f, "allow"),
            MemoryAccessDecision::Deny { reason } => write!(f, "deny: {reason}"),
            MemoryAccessDecision::RequireApproval { reason } => {
                write!(f, "require_approval: {reason}")
            }
        }
    }
}

/// Request to share a namespace with another agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NamespaceSharingRequest {
    /// Namespace ID to share.
    pub namespace_id: String,
    /// Agent ID requesting access.
    pub requester_agent: String,
    /// Requested access type.
    pub access_type: NamespaceAccessType,
    /// ISO 8601 timestamp of the request.
    pub requested_at: String,
    /// Tri-state approval status:
    /// - `None` — pending (not yet reviewed by an operator).
    /// - `Some(true)` — approved (access granted, ACL updated).
    /// - `Some(false)` — denied (access rejected, requester notified).
    #[serde(default)]
    pub approved: Option<bool>,
    /// ISO 8601 timestamp when the request was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

/// Type of namespace access requested.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceAccessType {
    /// Read-only access.
    Read,
    /// Write access (implies read).
    Write,
    /// Full access (read, write, and share).
    Full,
}

impl fmt::Display for NamespaceAccessType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceAccessType::Read => write!(f, "read"),
            NamespaceAccessType::Write => write!(f, "write"),
            NamespaceAccessType::Full => write!(f, "full"),
        }
    }
}

/// Aggregate statistics for MINJA memory security operations.
///
/// Exposed via the `/api/health` and governance endpoints.
/// All counters use `u64` and are incremented with `saturating_add`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemorySecurityStats {
    /// Total [`MemoryEntry`] records currently tracked across all namespaces.
    pub total_entries: u64,
    /// Entries currently in quarantine (blocked from use in tool parameters).
    pub quarantined_entries: u64,
    /// Total [`ProvenanceNode`] records in the provenance DAG.
    pub provenance_nodes: u64,
    /// Number of [`MemoryNamespace`] instances created (including defaults).
    pub namespaces: u64,
    /// Cumulative count of injection patterns detected in memory content
    /// (matched by Aho-Corasick + NFKC normalization).
    pub injections_detected: u64,
    /// Cumulative count of cross-session data replays blocked by the
    /// session guard (prevents data exfiltration via session pivoting).
    pub cross_session_blocked: u64,
    /// Cumulative count of access denials due to trust score below the
    /// configured `trust_threshold` after time-based decay.
    pub low_trust_denials: u64,
    /// Number of [`NamespaceSharingRequest`] records awaiting operator approval.
    pub pending_shares: u64,
}
