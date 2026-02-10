use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub mod json_rpc;
pub use json_rpc::*;

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 COMPLIANCE TYPES
// ═══════════════════════════════════════════════════

/// Status of an async MCP task for lifecycle tracking.
///
/// MCP 2025-11-25 introduces async tasks that run in the background.
/// This enum tracks the current state for policy enforcement and audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task has been accepted but not yet started.
    #[default]
    Pending,
    /// Task is currently executing.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task failed with an error.
    Failed { reason: String },
    /// Task was cancelled by request.
    Cancelled,
    /// Task expired due to timeout.
    Expired,
}


impl fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::Running => write!(f, "running"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed { reason } => write!(f, "failed: {}", reason),
            TaskStatus::Cancelled => write!(f, "cancelled"),
            TaskStatus::Expired => write!(f, "expired"),
        }
    }
}

/// A tracked async MCP task for lifecycle management.
///
/// Sentinel tracks task state to enforce policies on:
/// - Maximum concurrent tasks per session/agent
/// - Task duration limits
/// - Cancellation authorization (self-cancel only vs. any agent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrackedTask {
    /// Unique task identifier from the MCP server.
    pub task_id: String,
    /// Tool that created this task.
    pub tool: String,
    /// Function that created this task.
    pub function: String,
    /// Current task status.
    pub status: TaskStatus,
    /// ISO 8601 timestamp when the task was created.
    pub created_at: String,
    /// ISO 8601 timestamp when the task expires (if set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Agent ID that created this task (for cancellation authorization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Session ID this task belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl TrackedTask {
    /// Returns true if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed | TaskStatus::Failed { .. } | TaskStatus::Cancelled | TaskStatus::Expired
        )
    }

    /// Returns true if the task is active (pending or running).
    pub fn is_active(&self) -> bool {
        matches!(self.status, TaskStatus::Pending | TaskStatus::Running)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 11: MCP Tasks Primitive Security Types
// ═══════════════════════════════════════════════════════════════════════════════

/// A state transition in a task's hash chain for tamper detection.
///
/// Each transition records the previous hash, new state, and produces
/// a new hash, forming an append-only chain that detects tampering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskStateTransition {
    /// Sequence number in the hash chain (0-indexed).
    pub sequence: u64,
    /// SHA-256 hash of the previous transition (empty string for first).
    pub prev_hash: String,
    /// The new task status after this transition.
    pub new_status: TaskStatus,
    /// ISO 8601 timestamp of this transition.
    pub timestamp: String,
    /// Agent ID that triggered this transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    /// SHA-256 hash of this transition (computed from prev_hash + new_status + timestamp).
    pub hash: String,
}

/// A secure task with encryption and integrity protection.
///
/// Extends TrackedTask with:
/// - Encrypted state data (ChaCha20-Poly1305)
/// - Hash chain for tamper detection
/// - Resume token for authenticated task resumption
/// - Replay protection via nonces
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecureTask {
    /// The underlying tracked task.
    pub task: TrackedTask,
    /// Encrypted task state/result data (base64-encoded ciphertext).
    /// Only present when task has state to protect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_state: Option<String>,
    /// Nonce used for encryption (base64-encoded, 12 bytes for ChaCha20-Poly1305).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_nonce: Option<String>,
    /// Hash chain of state transitions for tamper detection.
    #[serde(default)]
    pub state_chain: Vec<TaskStateTransition>,
    /// HMAC-SHA256 resume token (hex-encoded) for authenticated resumption.
    /// Generated on task creation, verified on resume requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Nonces seen for replay protection (hex-encoded).
    /// Prevents replaying old task resume/cancel requests.
    #[serde(default)]
    pub seen_nonces: Vec<String>,
    /// Maximum number of nonces to track (FIFO eviction).
    #[serde(default = "default_max_nonces")]
    pub max_nonces: usize,
}

fn default_max_nonces() -> usize {
    1000
}

impl SecureTask {
    /// Create a new secure task from a tracked task.
    pub fn new(task: TrackedTask) -> Self {
        Self {
            task,
            encrypted_state: None,
            encryption_nonce: None,
            state_chain: Vec::new(),
            resume_token: None,
            seen_nonces: Vec::new(),
            max_nonces: default_max_nonces(),
        }
    }

    /// Check if a nonce has been seen (replay detection).
    pub fn is_nonce_seen(&self, nonce: &str) -> bool {
        self.seen_nonces.iter().any(|n| n == nonce)
    }

    /// Record a nonce as seen.
    pub fn record_nonce(&mut self, nonce: String) {
        if self.seen_nonces.len() >= self.max_nonces {
            self.seen_nonces.remove(0); // FIFO eviction
        }
        self.seen_nonces.push(nonce);
    }

    /// Get the latest hash in the state chain.
    pub fn latest_hash(&self) -> Option<&str> {
        self.state_chain.last().map(|t| t.hash.as_str())
    }

    /// Get the current sequence number.
    pub fn current_sequence(&self) -> u64 {
        self.state_chain.last().map(|t| t.sequence).unwrap_or(0)
    }
}

/// A checkpoint of task state for verification.
///
/// Checkpoints are signed snapshots that can be used to verify
/// task state integrity at a specific point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskCheckpoint {
    /// Unique checkpoint identifier.
    pub checkpoint_id: String,
    /// Task ID this checkpoint belongs to.
    pub task_id: String,
    /// Sequence number in the state chain at checkpoint time.
    pub sequence: u64,
    /// Hash of the state chain at checkpoint time.
    pub state_hash: String,
    /// ISO 8601 timestamp of checkpoint creation.
    pub created_at: String,
    /// Ed25519 signature of the checkpoint (hex-encoded).
    pub signature: String,
    /// Public key used to sign (hex-encoded).
    pub public_key: String,
}

/// Request to resume a task with authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResumeRequest {
    /// Task ID to resume.
    pub task_id: String,
    /// Resume token for authentication.
    pub resume_token: String,
    /// Unique nonce for replay protection (hex-encoded).
    pub nonce: String,
    /// Agent ID requesting the resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// Result of a task resume attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResumeResult {
    /// Whether the resume was authorized.
    pub authorized: bool,
    /// The task if authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<SecureTask>,
    /// Decrypted state data if authorized and available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decrypted_state: Option<serde_json::Value>,
    /// Reason for denial if not authorized.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

/// Result of validating a task's state chain integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskIntegrityResult {
    /// Whether the state chain is valid.
    pub valid: bool,
    /// Number of transitions verified.
    pub transitions_verified: u64,
    /// First broken transition index if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_broken_at: Option<u64>,
    /// Reason for failure if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Statistics about secure task management.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecureTaskStats {
    /// Total secure tasks tracked.
    pub total_tasks: usize,
    /// Tasks with encrypted state.
    pub encrypted_tasks: usize,
    /// Total state transitions recorded.
    pub total_transitions: u64,
    /// Checkpoints created.
    pub checkpoints_created: u64,
    /// Resume attempts.
    pub resume_attempts: u64,
    /// Successful resumes.
    pub resume_successes: u64,
    /// Replay attacks blocked.
    pub replay_attacks_blocked: u64,
    /// Integrity violations detected.
    pub integrity_violations: u64,
}

/// Authentication level for step-up authentication policies.
///
/// Step-up auth allows policies to require stronger authentication
/// for sensitive operations. Levels are ordered by strength.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AuthLevel {
    /// No authentication.
    #[default]
    None = 0,
    /// Basic authentication (API key, simple token).
    Basic = 1,
    /// OAuth 2.0/2.1 authentication.
    OAuth = 2,
    /// OAuth with MFA (multi-factor authentication).
    OAuthMfa = 3,
    /// Hardware key authentication (WebAuthn, FIDO2).
    HardwareKey = 4,
}


impl fmt::Display for AuthLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthLevel::None => write!(f, "none"),
            AuthLevel::Basic => write!(f, "basic"),
            AuthLevel::OAuth => write!(f, "oauth"),
            AuthLevel::OAuthMfa => write!(f, "oauth_mfa"),
            AuthLevel::HardwareKey => write!(f, "hardware_key"),
        }
    }
}

impl AuthLevel {
    /// Convert from u8 to AuthLevel, defaulting to None for unknown values.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => AuthLevel::None,
            1 => AuthLevel::Basic,
            2 => AuthLevel::OAuth,
            3 => AuthLevel::OAuthMfa,
            4 => AuthLevel::HardwareKey,
            _ => AuthLevel::None,
        }
    }

    /// Returns true if this level meets or exceeds the required level.
    pub fn satisfies(&self, required: AuthLevel) -> bool {
        *self >= required
    }
}

/// An MCP capability declaration for CIMD (Capability-Indexed Message Dispatch).
///
/// MCP 2025-11-25 introduces capability negotiation. Clients declare their
/// capabilities, and policies can require or block specific capabilities.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpCapability {
    /// Capability name (e.g., "tools", "resources", "sampling").
    pub name: String,
    /// Optional version string for the capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Sub-capabilities (e.g., for "tools": ["read", "write", "execute"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_capabilities: Vec<String>,
}

impl McpCapability {
    /// Create a new capability with just a name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            sub_capabilities: Vec::new(),
        }
    }

    /// Create a capability with a version.
    pub fn with_version(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: Some(version.into()),
            sub_capabilities: Vec::new(),
        }
    }

    /// Check if this capability has a specific sub-capability.
    pub fn has_sub(&self, sub: &str) -> bool {
        self.sub_capabilities.iter().any(|s| s == sub)
    }
}

// ═══════════════════════════════════════════════════
// PHASE 2: ADVANCED THREAT DETECTION TYPES
// ═══════════════════════════════════════════════════

/// State of a circuit breaker for cascading failure protection.
///
/// Circuit breakers prevent cascading failures by temporarily blocking
/// requests to failing tools. Aligned with OWASP ASI08.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Circuit is operating normally, requests are allowed.
    #[default]
    Closed,
    /// Circuit is tripped due to failures, requests are blocked.
    Open,
    /// Circuit is testing recovery, limited requests allowed.
    HalfOpen,
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Statistics for a circuit breaker instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CircuitStats {
    /// Current state of the circuit.
    pub state: CircuitState,
    /// Number of consecutive failures.
    pub failure_count: u32,
    /// Number of consecutive successes (used in half-open state).
    pub success_count: u32,
    /// Unix timestamp of the last failure, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<u64>,
    /// Unix timestamp of the last state change.
    pub last_state_change: u64,
}

impl Default for CircuitStats {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_state_change: 0,
        }
    }
}

/// Fingerprint for agent identity detection (shadow agent prevention).
///
/// Used to detect when an unknown agent claims to be a known agent,
/// indicating potential shadow agent attack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct AgentFingerprint {
    /// JWT subject claim, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_sub: Option<String>,
    /// JWT issuer claim, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_iss: Option<String>,
    /// OAuth client ID, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Hashed IP address for privacy-preserving fingerprinting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_hash: Option<String>,
}

impl AgentFingerprint {
    /// Returns true if this fingerprint has any identifying information.
    pub fn is_populated(&self) -> bool {
        self.jwt_sub.is_some()
            || self.jwt_iss.is_some()
            || self.client_id.is_some()
            || self.ip_hash.is_some()
    }

    /// Returns a summary string for logging (no sensitive data).
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(sub) = &self.jwt_sub {
            parts.push(format!("sub:{}", truncate_for_log(sub, 20)));
        }
        if let Some(iss) = &self.jwt_iss {
            parts.push(format!("iss:{}", truncate_for_log(iss, 20)));
        }
        if let Some(cid) = &self.client_id {
            parts.push(format!("cid:{}", truncate_for_log(cid, 20)));
        }
        if self.ip_hash.is_some() {
            parts.push("ip:*".to_string());
        }
        if parts.is_empty() {
            "empty".to_string()
        } else {
            parts.join(",")
        }
    }
}

/// Truncate a string for logging, adding "..." if truncated.
fn truncate_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Trust level for known agents (shadow agent detection).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Unknown agent, no trust established.
    #[default]
    Unknown = 0,
    /// Low trust, recently seen but not verified.
    Low = 1,
    /// Medium trust, consistent behavior observed.
    Medium = 2,
    /// High trust, extended consistent behavior.
    High = 3,
    /// Verified trust, administratively confirmed.
    Verified = 4,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Unknown => write!(f, "unknown"),
            TrustLevel::Low => write!(f, "low"),
            TrustLevel::Medium => write!(f, "medium"),
            TrustLevel::High => write!(f, "high"),
            TrustLevel::Verified => write!(f, "verified"),
        }
    }
}

impl TrustLevel {
    /// Convert from u8, defaulting to Unknown for invalid values.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => TrustLevel::Unknown,
            1 => TrustLevel::Low,
            2 => TrustLevel::Medium,
            3 => TrustLevel::High,
            4 => TrustLevel::Verified,
            _ => TrustLevel::Unknown,
        }
    }
}

/// Record of a tool's schema for lineage tracking (schema poisoning detection).
///
/// Tracks schema changes over time to detect malicious mutations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaRecord {
    /// Name of the tool this schema belongs to.
    pub tool_name: String,
    /// SHA-256 hash of the current schema.
    pub schema_hash: String,
    /// Unix timestamp when this schema was first seen.
    pub first_seen: u64,
    /// Unix timestamp when this schema was last seen.
    pub last_seen: u64,
    /// History of schema hashes (oldest first, max 10 entries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub version_history: Vec<String>,
    /// Trust score based on schema stability (0.0-1.0).
    pub trust_score: f32,
    /// SECURITY (R33-006): Actual schema content for field-level diff detection.
    /// Only stored if schema is under 64KB to prevent memory exhaustion.
    /// Enables real similarity calculation instead of heuristics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_content: Option<serde_json::Value>,
}

impl SchemaRecord {
    /// Maximum schema size to store in memory (64 KB).
    /// Larger schemas fall back to hash-only comparison.
    pub const MAX_SCHEMA_SIZE: usize = 64 * 1024;

    /// Create a new schema record with initial observation.
    pub fn new(tool_name: impl Into<String>, schema_hash: impl Into<String>, now: u64) -> Self {
        Self {
            tool_name: tool_name.into(),
            schema_hash: schema_hash.into(),
            first_seen: now,
            last_seen: now,
            version_history: Vec::new(),
            trust_score: 0.0, // Start with no trust
            schema_content: None,
        }
    }

    /// Create a new schema record with content stored (if under size limit).
    pub fn new_with_content(
        tool_name: impl Into<String>,
        schema_hash: impl Into<String>,
        schema: &serde_json::Value,
        now: u64,
    ) -> Self {
        let content = serde_json::to_string(schema)
            .ok()
            .filter(|s| s.len() <= Self::MAX_SCHEMA_SIZE)
            .map(|_| schema.clone());

        Self {
            tool_name: tool_name.into(),
            schema_hash: schema_hash.into(),
            first_seen: now,
            last_seen: now,
            version_history: Vec::new(),
            trust_score: 0.0,
            schema_content: content,
        }
    }

    /// Returns the number of schema versions observed.
    pub fn version_count(&self) -> usize {
        self.version_history.len() + 1 // Current + history
    }

    /// Returns true if the schema has been stable (no changes in history).
    pub fn is_stable(&self) -> bool {
        self.version_history.is_empty()
            || self.version_history.iter().all(|h| h == &self.schema_hash)
    }
}

/// Principal context for confused deputy prevention.
///
/// Tracks the delegation chain to prevent unauthorized tool access
/// via confused deputy attacks (OWASP ASI02).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub struct PrincipalContext {
    /// The original principal that initiated the request.
    pub original_principal: String,
    /// The principal the original delegated to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_to: Option<String>,
    /// Depth of the delegation chain (0 = direct, 1+ = delegated).
    pub delegation_depth: u8,
    /// Tools the delegate is allowed to access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<String>,
    /// Unix timestamp when the delegation expires, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_expires: Option<u64>,
}


impl PrincipalContext {
    /// Create a new context for a direct (non-delegated) principal.
    pub fn direct(principal: impl Into<String>) -> Self {
        Self {
            original_principal: principal.into(),
            delegated_to: None,
            delegation_depth: 0,
            allowed_tools: Vec::new(),
            delegation_expires: None,
        }
    }

    /// Returns true if this context represents a delegated request.
    pub fn is_delegated(&self) -> bool {
        self.delegated_to.is_some()
    }

    /// Returns true if the delegation has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        self.delegation_expires.is_some_and(|exp| now >= exp)
    }
}

/// Statistics for sampling request rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SamplingStats {
    /// Number of sampling requests in the current window.
    pub request_count: u32,
    /// Unix timestamp of the last sampling request.
    pub last_request: u64,
    /// Unix timestamp when the current window started.
    pub window_start: u64,
    /// Patterns flagged in recent requests (for monitoring).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flagged_patterns: Vec<String>,
}

impl SamplingStats {
    /// Create new stats starting now.
    pub fn new(now: u64) -> Self {
        Self {
            request_count: 0,
            last_request: now,
            window_start: now,
            flagged_patterns: Vec::new(),
        }
    }

    /// Reset the window, keeping flagged patterns.
    pub fn reset_window(&mut self, now: u64) {
        self.request_count = 0;
        self.window_start = now;
    }

    /// Record a request and return the new count.
    pub fn record_request(&mut self, now: u64) -> u32 {
        self.last_request = now;
        self.request_count += 1;
        self.request_count
    }
}

/// Maximum length for tool and function names (bytes).
const MAX_NAME_LEN: usize = 256;

/// Maximum length for individual path or domain strings (bytes).
const MAX_TARGET_LEN: usize = 4096;

/// Maximum number of combined target_paths + target_domains entries.
const MAX_TARGETS: usize = 256;

/// Validation errors for Action fields.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// Tool or function name is empty.
    EmptyField { field: &'static str },
    /// Tool or function name contains a null byte.
    NullByte { field: &'static str },
    /// Tool or function name contains a control character (tab, newline, etc.).
    ControlCharacter { field: &'static str },
    /// Tool or function name exceeds the maximum length.
    TooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    /// Too many target_paths + target_domains entries.
    TooManyTargets { count: usize, max: usize },
    /// A target path or domain string is too long.
    TargetTooLong {
        field: &'static str,
        index: usize,
        len: usize,
        max: usize,
    },
    /// A target path or domain contains a null byte.
    TargetNullByte { field: &'static str, index: usize },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::EmptyField { field } => {
                write!(f, "Action {} must not be empty", field)
            }
            ValidationError::NullByte { field } => {
                write!(f, "Action {} contains null byte", field)
            }
            ValidationError::ControlCharacter { field } => {
                write!(f, "Action {} contains control character", field)
            }
            ValidationError::TooLong { field, len, max } => {
                write!(f, "Action {} too long: {} bytes (max {})", field, len, max)
            }
            ValidationError::TooManyTargets { count, max } => {
                write!(f, "Too many targets: {} (max {})", count, max)
            }
            ValidationError::TargetTooLong {
                field,
                index,
                len,
                max,
            } => {
                write!(
                    f,
                    "Target {}[{}] too long: {} bytes (max {})",
                    field, index, len, max
                )
            }
            ValidationError::TargetNullByte { field, index } => {
                write!(f, "Target {}[{}] contains null byte", field, index)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Action {
    pub tool: String,
    pub function: String,
    pub parameters: serde_json::Value,
    /// File paths targeted by this action (e.g. from `file://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    /// Domains targeted by this action (e.g. from `https://` URIs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
    /// IP addresses resolved from target_domains (populated by proxy layer).
    /// Used by the engine for DNS rebinding protection when `IpRules` are configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_ips: Vec<String>,
}

/// Validate a single name field (tool or function).
fn validate_name(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    if value.contains('\0') {
        return Err(ValidationError::NullByte { field });
    }
    if value.len() > MAX_NAME_LEN {
        return Err(ValidationError::TooLong {
            field,
            len: value.len(),
            max: MAX_NAME_LEN,
        });
    }
    // SECURITY (R12-TYPES-1): Reject names with control characters or
    // that are whitespace-only. Prevents homoglyph/invisible-char bypass
    // and log confusion.
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    // SECURITY (R16-TYPES-1): Use distinct variant for control characters
    // so error messages accurately describe the issue.
    if value.chars().any(|c| c.is_control() && c != '\0') {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(())
}

impl Action {
    /// Create an Action with only tool, function, and parameters.
    /// `target_paths` and `target_domains` default to empty.
    ///
    /// Does NOT validate inputs — use [`Action::validated`] or [`Action::validate`]
    /// at trust boundaries (MCP extractor, HTTP proxy).
    pub fn new(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            tool: tool.into(),
            function: function.into(),
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        }
    }

    /// Create an Action with validation on tool and function names.
    ///
    /// Rejects empty names, null bytes, and names exceeding 256 bytes.
    /// Use this at trust boundaries where inputs come from external sources.
    pub fn validated(
        tool: impl Into<String>,
        function: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Result<Self, ValidationError> {
        let tool = tool.into();
        let function = function.into();
        validate_name(&tool, "tool")?;
        validate_name(&function, "function")?;
        Ok(Self {
            tool,
            function,
            parameters,
            target_paths: Vec::new(),
            target_domains: Vec::new(),
            resolved_ips: Vec::new(),
        })
    }

    /// Validate an existing Action's fields.
    ///
    /// Checks tool/function names, and target_paths/target_domains for
    /// null bytes, excessive length, and total count.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.tool, "tool")?;
        validate_name(&self.function, "function")?;

        // Check combined target count (R39-ENG-4: include resolved_ips)
        let total_targets =
            self.target_paths.len() + self.target_domains.len() + self.resolved_ips.len();
        if total_targets > MAX_TARGETS {
            return Err(ValidationError::TooManyTargets {
                count: total_targets,
                max: MAX_TARGETS,
            });
        }

        // Validate individual target_paths
        for (i, path) in self.target_paths.iter().enumerate() {
            if path.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_paths",
                    index: i,
                });
            }
            if path.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_paths",
                    index: i,
                    len: path.len(),
                    max: MAX_TARGET_LEN,
                });
            }
        }

        // Validate individual target_domains
        for (i, domain) in self.target_domains.iter().enumerate() {
            if domain.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "target_domains",
                    index: i,
                });
            }
            if domain.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "target_domains",
                    index: i,
                    len: domain.len(),
                    max: MAX_TARGET_LEN,
                });
            }
        }

        // SECURITY (R42-TYPES-1): Validate resolved_ips contents (null bytes, length).
        // Previously only counted toward MAX_TARGETS but contents were not checked,
        // unlike target_paths and target_domains which validate null bytes and length.
        for (i, ip) in self.resolved_ips.iter().enumerate() {
            if ip.contains('\0') {
                return Err(ValidationError::TargetNullByte {
                    field: "resolved_ips",
                    index: i,
                });
            }
            if ip.len() > MAX_TARGET_LEN {
                return Err(ValidationError::TargetTooLong {
                    field: "resolved_ips",
                    index: i,
                    len: ip.len(),
                    max: MAX_TARGET_LEN,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum PolicyType {
    Allow,
    Deny,
    Conditional { conditions: serde_json::Value },
}

/// Path-based access control rules for file system operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PathRules {
    /// Glob patterns for allowed paths. If non-empty, only matching paths are allowed.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Glob patterns for blocked paths. Any match results in denial.
    #[serde(default)]
    pub blocked: Vec<String>,
}

/// Network-based access control rules for outbound connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NetworkRules {
    /// Domain patterns for allowed destinations. If non-empty, only matching domains are allowed.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Domain patterns for blocked destinations. Any match results in denial.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// IP-level access control for DNS rebinding protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_rules: Option<IpRules>,
}

/// IP-level access control rules (DNS rebinding protection).
///
/// When configured, the proxy layer resolves target domains to IP addresses
/// and the engine checks them against these rules. This prevents attacks
/// where an allowed domain's DNS record changes to point at a private IP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IpRules {
    /// Block connections to private/reserved IPs (RFC 1918, loopback, link-local).
    #[serde(default)]
    pub block_private: bool,
    /// CIDR ranges to block (e.g. "10.0.0.0/8").
    #[serde(default)]
    pub blocked_cidrs: Vec<String>,
    /// CIDR ranges to allow. If non-empty, only matching IPs are allowed.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub priority: i32,
    /// Optional path-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<PathRules>,
    /// Optional network-based access control rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<NetworkRules>,
}

// ═══════════════════════════════════════════════════
// EVALUATION TRACE TYPES (Phase 10.4)
// ═══════════════════════════════════════════════════

/// Full evaluation trace for a single action evaluation.
///
/// Returned by `PolicyEngine::evaluate_action_traced()` when callers need
/// OPA-style decision explanations (e.g. `?trace=true` on the HTTP proxy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationTrace {
    pub action_summary: ActionSummary,
    pub policies_checked: usize,
    pub policies_matched: usize,
    pub matches: Vec<PolicyMatch>,
    pub verdict: Verdict,
    pub duration_us: u64,
}

/// Summary of the action being evaluated (no raw parameter values for security).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    pub tool: String,
    pub function: String,
    pub param_count: usize,
    pub param_keys: Vec<String>,
}

/// Per-policy evaluation result within a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatch {
    pub policy_id: String,
    pub policy_name: String,
    pub policy_type: String,
    pub priority: i32,
    pub tool_matched: bool,
    pub constraint_results: Vec<ConstraintResult>,
    pub verdict_contribution: Option<Verdict>,
}

/// Individual constraint evaluation result within a policy match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintResult {
    pub constraint_type: String,
    pub param: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
}

// ═══════════════════════════════════════════════════
// ETDI: ENHANCED TOOL DEFINITION INTERFACE
// Cryptographic verification of MCP tool definitions
// Based on arxiv:2506.01333
// ═══════════════════════════════════════════════════

/// Signature algorithm for tool definitions (ETDI).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Ed25519 signatures (recommended, default).
    #[default]
    Ed25519,
    /// ECDSA with P-256 curve.
    EcdsaP256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::Ed25519 => write!(f, "ed25519"),
            SignatureAlgorithm::EcdsaP256 => write!(f, "ecdsa_p256"),
        }
    }
}

/// A cryptographic signature on a tool definition.
///
/// Part of the ETDI (Enhanced Tool Definition Interface) system.
/// Tool providers sign their tool definitions, and Sentinel verifies
/// these signatures before allowing tool registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSignature {
    /// Unique identifier for this signature.
    pub signature_id: String,
    /// Hex-encoded cryptographic signature.
    pub signature: String,
    /// Algorithm used to create the signature.
    pub algorithm: SignatureAlgorithm,
    /// Hex-encoded public key of the signer.
    pub public_key: String,
    /// Optional fingerprint of the public key (for key management).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    /// ISO 8601 timestamp when the signature was created.
    pub signed_at: String,
    /// ISO 8601 timestamp when the signature expires (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// SPIFFE ID of the signer for workload identity (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_spiffe_id: Option<String>,
}

impl ToolSignature {
    /// Returns true if the signature has expired.
    pub fn is_expired(&self, now: &str) -> bool {
        self.expires_at.as_ref().is_some_and(|exp| now >= exp.as_str())
    }
}

/// Verification result for a tool signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignatureVerification {
    /// Whether the cryptographic signature is valid.
    pub valid: bool,
    /// Whether the signer is in the trusted signers list.
    pub signer_trusted: bool,
    /// Whether the signature has expired.
    pub expired: bool,
    /// Human-readable message about the verification result.
    pub message: String,
}

impl SignatureVerification {
    /// Returns true if the signature passes all checks.
    pub fn is_fully_verified(&self) -> bool {
        self.valid && self.signer_trusted && !self.expired
    }
}

/// An attestation record in a tool's provenance chain.
///
/// Attestations form a chain of custody for tool definitions,
/// allowing verification that a tool has not been modified
/// since it was first registered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolAttestation {
    /// Unique identifier for this attestation.
    pub attestation_id: String,
    /// Type of attestation (e.g., "initial", "version_update", "security_audit").
    pub attestation_type: String,
    /// Entity that created this attestation.
    pub attester: String,
    /// ISO 8601 timestamp when the attestation was created.
    pub timestamp: String,
    /// SHA-256 hash of the tool definition at attestation time.
    pub tool_hash: String,
    /// ID of the previous attestation in the chain (None for first attestation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_attestation: Option<String>,
    /// Cryptographic signature on this attestation.
    pub signature: ToolSignature,
    /// Optional reference to a transparency log entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_log_entry: Option<String>,
}

impl ToolAttestation {
    /// Returns true if this is the first attestation in the chain.
    pub fn is_initial(&self) -> bool {
        self.previous_attestation.is_none()
    }
}

/// Version pinning record for a tool.
///
/// Pins allow administrators to lock tools to specific versions
/// or version constraints, preventing unauthorized updates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolVersionPin {
    /// Name of the tool being pinned.
    pub tool_name: String,
    /// Exact version to pin to (e.g., "1.2.3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<String>,
    /// Semver constraint (e.g., "^1.2.0", ">=1.0,<2.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_constraint: Option<String>,
    /// SHA-256 hash of the pinned tool definition.
    pub definition_hash: String,
    /// ISO 8601 timestamp when the pin was created.
    pub pinned_at: String,
    /// Identity of who created this pin.
    pub pinned_by: String,
}

impl ToolVersionPin {
    /// Returns true if the pin uses an exact version match.
    pub fn is_exact(&self) -> bool {
        self.pinned_version.is_some()
    }

    /// Returns true if the pin uses a constraint.
    pub fn is_constraint(&self) -> bool {
        self.version_constraint.is_some()
    }
}

/// Result of version drift detection.
///
/// Generated when a tool's version or definition changes
/// from the pinned state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionDriftAlert {
    /// Name of the tool with drift.
    pub tool: String,
    /// Expected version or hash from the pin.
    pub expected_version: String,
    /// Actual version or hash observed.
    pub actual_version: String,
    /// Type of drift detected (e.g., "version_mismatch", "hash_mismatch").
    pub drift_type: String,
    /// Whether this drift should block the tool from being used.
    pub blocking: bool,
    /// ISO 8601 timestamp when the drift was detected.
    pub detected_at: String,
}

impl VersionDriftAlert {
    /// Create a version mismatch alert.
    pub fn version_mismatch(
        tool: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
        blocking: bool,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            expected_version: expected.into(),
            actual_version: actual.into(),
            drift_type: "version_mismatch".to_string(),
            blocking,
            detected_at: detected_at.into(),
        }
    }

    /// Create a hash mismatch alert.
    pub fn hash_mismatch(
        tool: impl Into<String>,
        expected_hash: impl Into<String>,
        actual_hash: impl Into<String>,
        blocking: bool,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            tool: tool.into(),
            expected_version: expected_hash.into(),
            actual_version: actual_hash.into(),
            drift_type: "hash_mismatch".to_string(),
            blocking,
            detected_at: detected_at.into(),
        }
    }
}

/// Cryptographically attested agent identity from a signed JWT.
///
/// This type represents a validated identity extracted from the `X-Agent-Identity`
/// header. Unlike the simple `agent_id` string, this provides cryptographic
/// attestation of the agent's identity via JWT signature verification.
///
/// # Security (OWASP ASI07 - Agent Identity Attestation)
///
/// - All claims are extracted from a signature-verified JWT
/// - The proxy validates the JWT before populating this struct
/// - Policies can match on issuer, subject, and custom claims
/// - This provides stronger identity guarantees than the legacy `agent_id` field
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AgentIdentity {
    /// JWT issuer (`iss` claim). Identifies the identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// JWT subject (`sub` claim). Identifies the specific agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// JWT audience (`aud` claim). May be a single string or array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Additional custom claims from the JWT payload.
    /// Common claims: `role`, `team`, `environment`, `permissions`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub claims: HashMap<String, serde_json::Value>,
}

impl AgentIdentity {
    /// Returns true if this identity has any populated fields.
    pub fn is_populated(&self) -> bool {
        self.issuer.is_some()
            || self.subject.is_some()
            || !self.audience.is_empty()
            || !self.claims.is_empty()
    }

    /// Get a claim value as a string, if present and is a string.
    pub fn claim_str(&self, key: &str) -> Option<&str> {
        self.claims.get(key).and_then(|v| v.as_str())
    }

    /// Get a claim value as an array of strings, if present and is an array.
    pub fn claim_str_array(&self, key: &str) -> Option<Vec<&str>> {
        self.claims.get(key).and_then(|v| {
            v.as_array()
                .map(|arr| arr.iter().filter_map(|item| item.as_str()).collect())
        })
    }
}

/// An entry in a multi-agent call chain, tracking the path of a request
/// through multiple agents in a multi-hop MCP scenario.
///
/// OWASP ASI08: Multi-agent communication monitoring requires tracking
/// the full chain of tool calls to detect privilege escalation patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallChainEntry {
    /// The agent that made this call (from X-Upstream-Agent header or OAuth subject).
    pub agent_id: String,
    /// The tool being called.
    pub tool: String,
    /// The function being called.
    pub function: String,
    /// ISO 8601 timestamp when the call was made.
    pub timestamp: String,
    /// HMAC-SHA256 signature over the entry content (FIND-015).
    /// Present when the entry was signed by a Sentinel instance with a configured HMAC key.
    /// Hex-encoded. Omitted from serialization when `None` for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
    /// Whether the HMAC on this entry has been verified (FIND-015).
    /// `None` = not checked (no key configured or entry has no HMAC).
    /// `Some(true)` = HMAC verified successfully.
    /// `Some(false)` = HMAC verification failed (entry marked as unverified).
    /// Excluded from serialization — this is local verification state only.
    #[serde(skip)]
    pub verified: Option<bool>,
}

/// Session-level context for policy evaluation.
///
/// Separate from [`Action`] because Action = "what to do" (from the agent),
/// while Context = "session state" (from the proxy). This security boundary
/// ensures agents don't control context fields like call counts or timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvaluationContext {
    /// ISO 8601 timestamp for the evaluation. When `None`, the engine uses
    /// the current wall-clock time. Providing an explicit timestamp enables
    /// deterministic testing of time-window policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Identity of the agent making the request (e.g., OAuth subject, API key hash).
    /// This is the legacy identity field — prefer `agent_identity` for stronger guarantees.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Cryptographically attested agent identity from a signed JWT (OWASP ASI07).
    ///
    /// When present, this provides stronger identity guarantees than `agent_id`.
    /// Populated from the `X-Agent-Identity` header after JWT signature verification.
    /// Policies can use `agent_identity` context conditions to match on claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<AgentIdentity>,
    /// Per-tool call counts for the current session (tool_name → count).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub call_counts: HashMap<String, u64>,
    /// History of tool names called in this session (most recent last).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_actions: Vec<String>,
    /// OWASP ASI08: Call chain for multi-agent communication monitoring.
    /// Records the path of the current request through multiple agents.
    /// The first entry is the originating agent, subsequent entries are
    /// intermediary agents in multi-hop scenarios.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_chain: Vec<CallChainEntry>,
    /// Tenant identifier for multi-tenancy support.
    /// When set, policies are scoped to this tenant. Extracted from:
    /// 1. JWT claims (`tenant_id` or `org_id`)
    /// 2. Request header (`X-Tenant-ID`)
    /// 3. Subdomain (`{tenant}.sentinel.example.com`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl EvaluationContext {
    /// Returns true if any context field is populated with meaningful data.
    /// Used by the engine to decide whether falling back to the legacy path
    /// (which cannot evaluate context conditions) is safe.
    // SECURITY (R16-TYPES-2): Include timestamp so time-window policies
    // fail-closed when compiled policies are unavailable, rather than
    // silently falling back to the legacy path that ignores time constraints.
    pub fn has_any_meaningful_fields(&self) -> bool {
        self.timestamp.is_some()
            || self.agent_id.is_some()
            || self
                .agent_identity
                .as_ref()
                .is_some_and(|id| id.is_populated())
            || !self.call_counts.is_empty()
            || !self.previous_actions.is_empty()
            || !self.call_chain.is_empty()
            || self.tenant_id.is_some()
    }

    /// Returns the depth of the current call chain (number of agents in the chain).
    /// A depth of 0 means no multi-hop scenario (direct call).
    /// A depth of 1 means there is one upstream agent.
    pub fn call_chain_depth(&self) -> usize {
        self.call_chain.len()
    }

    /// Returns the originating agent ID if this is a multi-hop request.
    /// This is the first agent in the call chain (the one that initiated the request).
    pub fn originating_agent(&self) -> Option<&str> {
        self.call_chain.first().map(|e| e.agent_id.as_str())
    }
}

// ═══════════════════════════════════════════════════
// PHASE 9: MEMORY INJECTION DEFENSE (MINJA) TYPES
// ═══════════════════════════════════════════════════

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
            trust_score: 1.0,
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
    pub fn decayed_trust_score(&self, decay_rate: f64, current_time: &str) -> f64 {
        let age_hours = Self::hours_since(&self.recorded_at, current_time);
        self.trust_score * (-decay_rate * age_hours).exp()
    }

    /// Calculate hours between two ISO 8601 timestamps.
    /// Returns 0.0 if parsing fails.
    fn hours_since(start: &str, end: &str) -> f64 {
        // Simple parsing: extract the timestamp portion and compute difference
        // For robustness, we'd use chrono but keep dependencies minimal
        use std::time::Duration;

        // Try to parse as Unix timestamp or ISO 8601
        let start_secs = Self::parse_timestamp(start).unwrap_or(0);
        let end_secs = Self::parse_timestamp(end).unwrap_or(0);

        if end_secs > start_secs {
            Duration::from_secs(end_secs - start_secs).as_secs_f64() / 3600.0
        } else {
            0.0
        }
    }

    /// Parse an ISO 8601 timestamp to Unix seconds (approximate).
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
    pub fn new(id: String, owner_agent: String, created_at: String) -> Self {
        Self {
            id,
            owner_agent: owner_agent.clone(),
            read_allowed: vec![owner_agent.clone()],
            write_allowed: vec![owner_agent],
            created_at,
            isolation: NamespaceIsolation::default(),
            is_default: false,
        }
    }

    /// Check if an agent can read from this namespace.
    pub fn can_read(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id
            || self.read_allowed.iter().any(|a| a == agent_id || a == "*")
    }

    /// Check if an agent can write to this namespace.
    pub fn can_write(&self, agent_id: &str) -> bool {
        self.owner_agent == agent_id
            || self.write_allowed.iter().any(|a| a == agent_id || a == "*")
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
            MemoryAccessDecision::Deny { reason } => write!(f, "deny: {}", reason),
            MemoryAccessDecision::RequireApproval { reason } => {
                write!(f, "require_approval: {}", reason)
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
    /// Whether the request has been approved.
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

/// Statistics for memory security operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemorySecurityStats {
    /// Total entries tracked.
    pub total_entries: u64,
    /// Entries currently quarantined.
    pub quarantined_entries: u64,
    /// Total provenance nodes.
    pub provenance_nodes: u64,
    /// Namespaces created.
    pub namespaces: u64,
    /// Injection patterns detected.
    pub injections_detected: u64,
    /// Cross-session replays blocked.
    pub cross_session_blocked: u64,
    /// Low-trust access denials.
    pub low_trust_denials: u64,
    /// Sharing approvals pending.
    pub pending_shares: u64,
}

// ═══════════════════════════════════════════════════
// PHASE 10: NON-HUMAN IDENTITY (NHI) LIFECYCLE TYPES
// ═══════════════════════════════════════════════════

/// Attestation type for agent identity verification.
///
/// Determines how an agent proves its identity to Sentinel.
/// Different attestation types offer varying levels of security.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum NhiAttestationType {
    /// JWT-based attestation (signed identity claims).
    #[default]
    Jwt,
    /// Mutual TLS with client certificate.
    Mtls,
    /// SPIFFE/SPIRE workload identity.
    Spiffe,
    /// DPoP (Demonstration of Proof-of-Possession) per RFC 9449.
    DPoP,
    /// API key authentication (lowest security).
    ApiKey,
}

impl fmt::Display for NhiAttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NhiAttestationType::Jwt => write!(f, "jwt"),
            NhiAttestationType::Mtls => write!(f, "mtls"),
            NhiAttestationType::Spiffe => write!(f, "spiffe"),
            NhiAttestationType::DPoP => write!(f, "dpop"),
            NhiAttestationType::ApiKey => write!(f, "api_key"),
        }
    }
}

/// Status of an agent identity in the NHI lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum NhiIdentityStatus {
    /// Identity is active and valid.
    #[default]
    Active,
    /// Identity is suspended pending review.
    Suspended,
    /// Identity has been revoked.
    Revoked,
    /// Identity has expired.
    Expired,
    /// Identity is in a probationary period (new or recently restored).
    Probationary,
}

impl fmt::Display for NhiIdentityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NhiIdentityStatus::Active => write!(f, "active"),
            NhiIdentityStatus::Suspended => write!(f, "suspended"),
            NhiIdentityStatus::Revoked => write!(f, "revoked"),
            NhiIdentityStatus::Expired => write!(f, "expired"),
            NhiIdentityStatus::Probationary => write!(f, "probationary"),
        }
    }
}

/// Registered agent identity for NHI lifecycle management.
///
/// Tracks the full lifecycle of a non-human identity, including:
/// - Attestation type and credentials
/// - Behavioral baseline for continuous authentication
/// - Credential rotation and expiration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub struct NhiAgentIdentity {
    /// Unique agent identifier.
    pub id: String,
    /// Human-readable name for the agent.
    pub name: String,
    /// Attestation type used for verification.
    pub attestation_type: NhiAttestationType,
    /// Current identity status.
    pub status: NhiIdentityStatus,
    /// SPIFFE ID if using SPIFFE attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// Public key for signature verification (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Key algorithm (e.g., "Ed25519", "ES256", "RS256").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    /// ISO 8601 timestamp when the identity was issued.
    pub issued_at: String,
    /// ISO 8601 timestamp when the identity expires.
    pub expires_at: String,
    /// ISO 8601 timestamp of last credential rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotation: Option<String>,
    /// Number of successful authentications.
    #[serde(default)]
    pub auth_count: u64,
    /// ISO 8601 timestamp of last successful authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_auth: Option<String>,
    /// Tags for categorization (e.g., "production", "internal").
    #[serde(default)]
    pub tags: Vec<String>,
    /// Custom metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}


/// Behavioral baseline for continuous agent authentication.
///
/// Tracks typical behavior patterns to detect anomalies that might
/// indicate credential theft or impersonation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiBehavioralBaseline {
    /// Agent ID this baseline belongs to.
    pub agent_id: String,
    /// Tool call frequency distribution (tool:function → calls per hour).
    #[serde(default)]
    pub tool_call_patterns: HashMap<String, f64>,
    /// Average interval between requests in seconds.
    #[serde(default)]
    pub avg_request_interval_secs: f64,
    /// Standard deviation of request intervals.
    #[serde(default)]
    pub request_interval_stddev: f64,
    /// Typical session duration in seconds.
    #[serde(default)]
    pub typical_session_duration_secs: f64,
    /// Number of observations used to build this baseline.
    #[serde(default)]
    pub observation_count: u64,
    /// ISO 8601 timestamp when the baseline was first created.
    pub created_at: String,
    /// ISO 8601 timestamp when the baseline was last updated.
    pub last_updated: String,
    /// Confidence score (0.0 - 1.0) based on observation count.
    #[serde(default)]
    pub confidence: f64,
    /// Typical IP addresses or ranges.
    #[serde(default)]
    pub typical_source_ips: Vec<String>,
    /// Typical time windows (hour of day, 0-23).
    #[serde(default)]
    pub active_hours: Vec<u8>,
}

impl Default for NhiBehavioralBaseline {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            tool_call_patterns: HashMap::new(),
            avg_request_interval_secs: 0.0,
            request_interval_stddev: 0.0,
            typical_session_duration_secs: 0.0,
            observation_count: 0,
            created_at: String::new(),
            last_updated: String::new(),
            confidence: 0.0,
            typical_source_ips: Vec::new(),
            active_hours: Vec::new(),
        }
    }
}

/// Result of behavioral attestation check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiBehavioralCheckResult {
    /// Whether the behavior is within acceptable bounds.
    pub within_baseline: bool,
    /// Anomaly score (0.0 = normal, 1.0 = highly anomalous).
    pub anomaly_score: f64,
    /// Specific deviations detected.
    #[serde(default)]
    pub deviations: Vec<NhiBehavioralDeviation>,
    /// Recommended action.
    pub recommendation: NhiBehavioralRecommendation,
}

/// A specific behavioral deviation from the baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiBehavioralDeviation {
    /// Type of deviation.
    pub deviation_type: String,
    /// Observed value.
    pub observed: String,
    /// Expected value or range.
    pub expected: String,
    /// Severity (0.0 - 1.0).
    pub severity: f64,
}

/// Recommended action based on behavioral analysis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NhiBehavioralRecommendation {
    /// Allow the request normally.
    Allow,
    /// Allow but log for review.
    AllowWithLogging,
    /// Require additional authentication.
    StepUpAuth,
    /// Suspend the identity pending review.
    Suspend,
    /// Revoke the identity immediately.
    Revoke,
}

impl fmt::Display for NhiBehavioralRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NhiBehavioralRecommendation::Allow => write!(f, "allow"),
            NhiBehavioralRecommendation::AllowWithLogging => write!(f, "allow_with_logging"),
            NhiBehavioralRecommendation::StepUpAuth => write!(f, "step_up_auth"),
            NhiBehavioralRecommendation::Suspend => write!(f, "suspend"),
            NhiBehavioralRecommendation::Revoke => write!(f, "revoke"),
        }
    }
}

/// A link in a delegation chain for NHI accountability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiDelegationLink {
    /// Agent delegating permissions.
    pub from_agent: String,
    /// Agent receiving permissions.
    pub to_agent: String,
    /// Permissions being delegated.
    pub permissions: Vec<String>,
    /// Scope constraints (e.g., "tools:read_file", "domains:*.internal").
    #[serde(default)]
    pub scope_constraints: Vec<String>,
    /// ISO 8601 timestamp when the delegation was created.
    pub created_at: String,
    /// ISO 8601 timestamp when the delegation expires.
    pub expires_at: String,
    /// Whether the delegation is currently active.
    #[serde(default = "default_true_nhi")]
    pub active: bool,
    /// Reason for the delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_true_nhi() -> bool {
    true
}

/// Full delegation chain for audit and accountability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiDelegationChain {
    /// Ordered list of delegation links from origin to current agent.
    pub chain: Vec<NhiDelegationLink>,
    /// Maximum allowed chain depth.
    pub max_depth: usize,
    /// ISO 8601 timestamp when this chain was resolved.
    pub resolved_at: String,
}

impl NhiDelegationChain {
    /// Returns the current depth of the chain.
    pub fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Returns true if the chain exceeds the maximum allowed depth.
    pub fn exceeds_max_depth(&self) -> bool {
        self.chain.len() > self.max_depth
    }

    /// Returns the originating agent (first in chain).
    pub fn origin(&self) -> Option<&str> {
        self.chain.first().map(|link| link.from_agent.as_str())
    }

    /// Returns the final delegated agent (last to_agent in chain).
    pub fn terminus(&self) -> Option<&str> {
        self.chain.last().map(|link| link.to_agent.as_str())
    }
}

/// DPoP (Demonstration of Proof-of-Possession) proof for RFC 9449 compliance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiDpopProof {
    /// The DPoP proof JWT.
    pub proof: String,
    /// HTTP method (e.g., "POST").
    pub htm: String,
    /// HTTP URI.
    pub htu: String,
    /// Access token hash (ath claim) if binding to an access token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Nonce from the server (if required).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// ISO 8601 timestamp of proof creation.
    pub iat: String,
    /// Unique identifier for replay prevention (jti claim).
    pub jti: String,
}

/// Result of DPoP proof verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiDpopVerificationResult {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Public key thumbprint (JWK thumbprint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbprint: Option<String>,
    /// Error message if verification failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Nonce to return for retry (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_nonce: Option<String>,
}

/// Statistics for NHI lifecycle management.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NhiStats {
    /// Total registered agent identities.
    pub total_identities: u64,
    /// Active identities.
    pub active_identities: u64,
    /// Suspended identities.
    pub suspended_identities: u64,
    /// Revoked identities.
    pub revoked_identities: u64,
    /// Expired identities.
    pub expired_identities: u64,
    /// Identities with behavioral baselines.
    pub with_baselines: u64,
    /// Authentications in the last hour.
    pub auths_last_hour: u64,
    /// Behavioral anomalies detected in the last hour.
    pub anomalies_last_hour: u64,
    /// Active delegations.
    pub active_delegations: u64,
    /// DPoP proofs verified in the last hour.
    pub dpop_verifications_last_hour: u64,
}

/// Credential rotation event for audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhiCredentialRotation {
    /// Agent ID.
    pub agent_id: String,
    /// Previous key thumbprint (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_thumbprint: Option<String>,
    /// New key thumbprint.
    pub new_thumbprint: String,
    /// ISO 8601 timestamp of rotation.
    pub rotated_at: String,
    /// Rotation trigger (scheduled, manual, security_event).
    pub trigger: String,
    /// New expiration time.
    pub new_expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn test_action_serialization_roundtrip() {
        let action = Action::new("file_system", "read_file", json!({"path": "/tmp/test.txt"}));
        let json_str = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&json_str).unwrap();
        assert_eq!(action, deserialized);
    }

    #[test]
    fn test_verdict_all_variants() {
        let variants = vec![
            Verdict::Allow,
            Verdict::Deny {
                reason: "blocked".to_string(),
            },
            Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
        ];
        for v in variants {
            let json_str = serde_json::to_string(&v).unwrap();
            let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
            assert_eq!(v, deserialized);
        }
    }

    #[test]
    fn test_policy_type_conditional_with_value() {
        let pt = PolicyType::Conditional {
            conditions: json!({"tool_pattern": "bash", "forbidden_parameters": ["force"]}),
        };
        let json_str = serde_json::to_string(&pt).unwrap();
        let deserialized: PolicyType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pt, deserialized);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = Policy {
            id: "bash:*".to_string(),
            name: "Block bash".to_string(),
            policy_type: PolicyType::Deny,
            priority: 100,
            path_rules: None,
            network_rules: None,
        };
        let json_str = serde_json::to_string(&policy).unwrap();
        let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, "bash:*");
        assert_eq!(deserialized.priority, 100);
    }

    // --- Action validation tests (M2) ---

    #[test]
    fn test_validated_accepts_valid_input() {
        let action = Action::validated("read_file", "execute", json!({}));
        assert!(action.is_ok());
        let action = action.unwrap();
        assert_eq!(action.tool, "read_file");
        assert_eq!(action.function, "execute");
    }

    #[test]
    fn test_validated_rejects_empty_tool() {
        let result = Action::validated("", "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::EmptyField { field: "tool" })
        ));
    }

    #[test]
    fn test_validated_rejects_empty_function() {
        let result = Action::validated("read_file", "", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::EmptyField { field: "function" })
        ));
    }

    #[test]
    fn test_validated_rejects_null_bytes_in_tool() {
        let result = Action::validated("read\0file", "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::NullByte { field: "tool" })
        ));
    }

    #[test]
    fn test_validated_rejects_null_bytes_in_function() {
        let result = Action::validated("read_file", "exec\0ute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::NullByte { field: "function" })
        ));
    }

    #[test]
    fn test_validated_rejects_too_long_tool() {
        let long_name = "a".repeat(257);
        let result = Action::validated(long_name, "execute", json!({}));
        assert!(matches!(
            result,
            Err(ValidationError::TooLong { field: "tool", .. })
        ));
    }

    #[test]
    fn test_validated_accepts_max_length_tool() {
        let name = "a".repeat(256);
        let result = Action::validated(name, "execute", json!({}));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_existing_action() {
        let action = Action::new("read_file", "execute", json!({}));
        assert!(action.validate().is_ok());

        let bad = Action::new("", "execute", json!({}));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_new_still_works_without_validation() {
        // Backward compatibility: new() doesn't validate
        let action = Action::new("", "", json!({}));
        assert_eq!(action.tool, "");
        assert_eq!(action.function, "");
    }

    #[test]
    fn test_validation_error_display() {
        let e = ValidationError::EmptyField { field: "tool" };
        assert!(e.to_string().contains("tool"));
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn test_validated_rejects_control_chars_with_correct_variant() {
        // Tab character should produce ControlCharacter, not NullByte
        let result = Action::validated("read\tfile", "execute", json!({}));
        assert!(
            matches!(
                result,
                Err(ValidationError::ControlCharacter { field: "tool" })
            ),
            "Tab should produce ControlCharacter variant, got: {:?}",
            result
        );

        // Newline in function
        let result = Action::validated("tool", "exec\nute", json!({}));
        assert!(
            matches!(
                result,
                Err(ValidationError::ControlCharacter { field: "function" })
            ),
            "Newline should produce ControlCharacter variant, got: {:?}",
            result
        );
    }

    #[test]
    fn test_control_character_error_display() {
        let e = ValidationError::ControlCharacter { field: "tool" };
        let msg = e.to_string();
        assert!(
            msg.contains("control character"),
            "Error message should say 'control character', got: {}",
            msg
        );
        assert!(!msg.contains("null byte"), "Should NOT mention null byte");
    }

    // --- Target validation tests ---

    #[test]
    fn test_validate_rejects_null_byte_in_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/tmp/foo\0bar".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_paths",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_rejects_null_byte_in_target_domain() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_domains = vec!["evil\0.com".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_domains",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_rejects_too_long_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["a".repeat(4097)];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetTooLong {
                field: "target_paths",
                index: 0,
                ..
            })
        ));
    }

    #[test]
    fn test_validate_accepts_max_length_target_path() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["a".repeat(4096)];
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_too_many_targets() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..200).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
        // 200 + 100 = 300 > 256
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets {
                count: 300,
                max: 256
            })
        ));
    }

    #[test]
    fn test_validate_accepts_max_targets() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..128).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..128).map(|i| format!("d{}.com", i)).collect();
        // 128 + 128 = 256 == MAX_TARGETS
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_too_many_resolved_ips_r39_eng_4() {
        // R39-ENG-4: resolved_ips must be counted in total_targets.
        // 300 resolved_ips alone should exceed MAX_TARGETS=256.
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = (0..300)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets {
                count: 300,
                max: 256
            })
        ));
    }

    #[test]
    fn test_validate_resolved_ips_combined_with_paths_domains_r39_eng_4() {
        // R39-ENG-4: Combination of paths + domains + IPs exceeding MAX_TARGETS
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..100).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..100).map(|i| format!("d{}.com", i)).collect();
        action.resolved_ips = (0..57).map(|i| format!("10.0.0.{}", i)).collect();
        // 100 + 100 + 57 = 257 > 256
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TooManyTargets {
                count: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn test_validate_resolved_ips_at_boundary_r39_eng_4() {
        // R39-ENG-4: paths + domains + IPs exactly at MAX_TARGETS should pass
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = (0..85).map(|i| format!("/path/{}", i)).collect();
        action.target_domains = (0..85).map(|i| format!("d{}.com", i)).collect();
        action.resolved_ips = (0..86).map(|i| format!("10.0.0.{}", i)).collect();
        // 85 + 85 + 86 = 256 == MAX_TARGETS
        assert!(action.validate().is_ok());
    }

    // --- R42-TYPES-1: resolved_ips content validation tests ---

    #[test]
    fn test_r42_types_1_resolved_ips_null_byte_rejected() {
        // R42-TYPES-1: resolved_ips with null byte must be rejected
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.\0.2".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "resolved_ips",
                index: 1
            })
        ));
    }

    #[test]
    fn test_r42_types_1_resolved_ips_oversized_rejected() {
        // R42-TYPES-1: resolved_ips with oversized string must be rejected
        let mut action = Action::new("tool", "func", json!({}));
        let oversized = "A".repeat(4097); // MAX_TARGET_LEN is 4096
        action.resolved_ips = vec![oversized];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetTooLong {
                field: "resolved_ips",
                index: 0,
                len: 4097,
                max: 4096
            })
        ));
    }

    #[test]
    fn test_r42_types_1_resolved_ips_valid_entries_pass() {
        // R42-TYPES-1: Valid resolved_ips should pass validation
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec![
            "10.0.0.1".to_string(),
            "192.168.1.1".to_string(),
            "::1".to_string(),
        ];
        assert!(action.validate().is_ok());
    }

    #[test]
    fn test_r42_types_1_resolved_ips_null_byte_first_entry() {
        // R42-TYPES-1: null byte at index 0
        let mut action = Action::new("tool", "func", json!({}));
        action.resolved_ips = vec!["\0".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "resolved_ips",
                index: 0
            })
        ));
    }

    #[test]
    fn test_validate_null_byte_second_target() {
        let mut action = Action::new("tool", "func", json!({}));
        action.target_paths = vec!["/ok".to_string(), "/bad\0path".to_string()];
        assert!(matches!(
            action.validate(),
            Err(ValidationError::TargetNullByte {
                field: "target_paths",
                index: 1
            })
        ));
    }

    #[test]
    fn test_target_validation_error_display() {
        let e = ValidationError::TooManyTargets {
            count: 500,
            max: 256,
        };
        assert!(e.to_string().contains("500"));
        assert!(e.to_string().contains("256"));

        let e = ValidationError::TargetNullByte {
            field: "target_paths",
            index: 3,
        };
        assert!(e.to_string().contains("target_paths[3]"));
        assert!(e.to_string().contains("null byte"));

        let e = ValidationError::TargetTooLong {
            field: "target_domains",
            index: 0,
            len: 5000,
            max: 4096,
        };
        assert!(e.to_string().contains("5000"));
        assert!(e.to_string().contains("4096"));
    }

    // ═══════════════════════════════════════════════════
    // PROPERTY-BASED TESTS: Action Validation
    // ═══════════════════════════════════════════════════

    proptest! {
        // PROPERTY: validated() succeeds iff validate() succeeds on the same inputs
        #[test]
        fn validated_ok_iff_validate_ok(
            tool in "[a-z_]{0,260}",
            function in "[a-z_]{0,260}",
        ) {
            let validated_result = Action::validated(&tool, &function, json!({}));
            let new_action = Action::new(&tool, &function, json!({}));
            let validate_result = new_action.validate();

            prop_assert_eq!(
                validated_result.is_ok(),
                validate_result.is_ok(),
                "validated() and validate() must agree for tool={:?} function={:?}\n\
                 validated: {:?}\n\
                 validate:  {:?}",
                tool, function, validated_result, validate_result
            );
        }

        // PROPERTY: Any name containing a null byte is always rejected
        #[test]
        fn null_byte_always_rejected(
            prefix in "[a-z]{1,10}",
            suffix in "[a-z]{1,10}",
        ) {
            let tool_with_null = format!("{}\0{}", prefix, suffix);

            // Null in tool
            let result = Action::validated(&tool_with_null, "func", json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::NullByte { field: "tool" })),
                "Null byte in tool must be rejected. Got: {:?}", result
            );

            // Null in function
            let result = Action::validated("tool", &tool_with_null, json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::NullByte { field: "function" })),
                "Null byte in function must be rejected. Got: {:?}", result
            );
        }

        // PROPERTY: Empty tool or function name is always rejected
        #[test]
        fn empty_name_always_rejected(
            other in "[a-z]{1,10}",
        ) {
            let result = Action::validated("", &other, json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::EmptyField { field: "tool" })),
                "Empty tool must be rejected. Got: {:?}", result
            );

            let result = Action::validated(&other, "", json!({}));
            prop_assert!(
                matches!(result, Err(ValidationError::EmptyField { field: "function" })),
                "Empty function must be rejected. Got: {:?}", result
            );
        }

        // PROPERTY: 256-byte name is accepted, 257-byte name is rejected
        #[test]
        fn max_length_boundary(
            ch in "[a-z]",
        ) {
            let at_max = ch.repeat(256);
            let over_max = ch.repeat(257);

            let ok_result = Action::validated(&at_max, "func", json!({}));
            prop_assert!(ok_result.is_ok(),
                "256-byte name must be accepted. Got: {:?}", ok_result);

            let err_result = Action::validated(&over_max, "func", json!({}));
            prop_assert!(
                matches!(err_result, Err(ValidationError::TooLong { field: "tool", .. })),
                "257-byte name must be rejected. Got: {:?}", err_result
            );
        }

        // PROPERTY: Valid actions roundtrip through serde unchanged
        #[test]
        fn valid_names_roundtrip_serde(
            tool in "[a-z_]{1,20}",
            function in "[a-z_]{1,20}",
        ) {
            let action = Action::validated(&tool, &function, json!({"key": "value"})).unwrap();
            let serialized = serde_json::to_string(&action).unwrap();
            let deserialized: Action = serde_json::from_str(&serialized).unwrap();
            prop_assert_eq!(&action, &deserialized,
                "Valid action must roundtrip through serde unchanged");
        }
    }

    // SECURITY (R16-TYPES-2): EvaluationContext.has_any_meaningful_fields()
    // must include timestamp so time-window policies fail-closed.
    #[test]
    fn test_context_timestamp_only_is_meaningful() {
        let ctx = EvaluationContext {
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with only timestamp should be meaningful"
        );
    }

    #[test]
    fn test_context_empty_is_not_meaningful() {
        let ctx = EvaluationContext::default();
        assert!(
            !ctx.has_any_meaningful_fields(),
            "Default context should not be meaningful"
        );
    }

    // --- Call chain tests (OWASP ASI08) ---

    #[test]
    fn test_call_chain_entry_serialization() {
        let entry = CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        };
        let json_str = serde_json::to_string(&entry).unwrap();
        let deserialized: CallChainEntry = serde_json::from_str(&json_str).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_context_call_chain_is_meaningful() {
        let ctx = EvaluationContext {
            call_chain: vec![CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "read_file".to_string(),
                function: "execute".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            }],
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with call_chain should be meaningful"
        );
    }

    #[test]
    fn test_call_chain_depth() {
        let empty_ctx = EvaluationContext::default();
        assert_eq!(empty_ctx.call_chain_depth(), 0);

        let single_hop_ctx = EvaluationContext {
            call_chain: vec![CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            }],
            ..Default::default()
        };
        assert_eq!(single_hop_ctx.call_chain_depth(), 1);

        let multi_hop_ctx = EvaluationContext {
            call_chain: vec![
                CallChainEntry {
                    agent_id: "agent-a".to_string(),
                    tool: "tool1".to_string(),
                    function: "func1".to_string(),
                    timestamp: "2026-01-01T12:00:00Z".to_string(),
                    hmac: None,
                    verified: None,
                },
                CallChainEntry {
                    agent_id: "agent-b".to_string(),
                    tool: "tool2".to_string(),
                    function: "func2".to_string(),
                    timestamp: "2026-01-01T12:00:01Z".to_string(),
                    hmac: None,
                    verified: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(multi_hop_ctx.call_chain_depth(), 2);
    }

    #[test]
    fn test_originating_agent() {
        let empty_ctx = EvaluationContext::default();
        assert!(empty_ctx.originating_agent().is_none());

        let ctx = EvaluationContext {
            call_chain: vec![
                CallChainEntry {
                    agent_id: "origin-agent".to_string(),
                    tool: "tool1".to_string(),
                    function: "func1".to_string(),
                    timestamp: "2026-01-01T12:00:00Z".to_string(),
                    hmac: None,
                    verified: None,
                },
                CallChainEntry {
                    agent_id: "proxy-agent".to_string(),
                    tool: "tool2".to_string(),
                    function: "func2".to_string(),
                    timestamp: "2026-01-01T12:00:01Z".to_string(),
                    hmac: None,
                    verified: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(ctx.originating_agent(), Some("origin-agent"));
    }

    // --- AgentIdentity tests (OWASP ASI07) ---

    #[test]
    fn test_agent_identity_serialization_roundtrip() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        claims.insert("permissions".to_string(), json!(["read", "write"]));

        let identity = AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            subject: Some("agent-123".to_string()),
            audience: vec!["mcp-server".to_string()],
            claims,
        };

        let json_str = serde_json::to_string(&identity).unwrap();
        let deserialized: AgentIdentity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(identity, deserialized);
    }

    #[test]
    fn test_agent_identity_is_populated() {
        let empty = AgentIdentity::default();
        assert!(!empty.is_populated());

        let with_issuer = AgentIdentity {
            issuer: Some("https://auth.example.com".to_string()),
            ..Default::default()
        };
        assert!(with_issuer.is_populated());

        let with_subject = AgentIdentity {
            subject: Some("agent-123".to_string()),
            ..Default::default()
        };
        assert!(with_subject.is_populated());

        let with_audience = AgentIdentity {
            audience: vec!["server".to_string()],
            ..Default::default()
        };
        assert!(with_audience.is_populated());

        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        let with_claims = AgentIdentity {
            claims,
            ..Default::default()
        };
        assert!(with_claims.is_populated());
    }

    #[test]
    fn test_agent_identity_claim_str() {
        let mut claims = HashMap::new();
        claims.insert("role".to_string(), json!("admin"));
        claims.insert("count".to_string(), json!(42));

        let identity = AgentIdentity {
            claims,
            ..Default::default()
        };

        assert_eq!(identity.claim_str("role"), Some("admin"));
        assert_eq!(identity.claim_str("count"), None); // Not a string
        assert_eq!(identity.claim_str("missing"), None);
    }

    #[test]
    fn test_agent_identity_claim_str_array() {
        let mut claims = HashMap::new();
        claims.insert("permissions".to_string(), json!(["read", "write"]));
        claims.insert("role".to_string(), json!("admin")); // Not an array
        claims.insert("mixed".to_string(), json!(["str", 42])); // Mixed types

        let identity = AgentIdentity {
            claims,
            ..Default::default()
        };

        assert_eq!(
            identity.claim_str_array("permissions"),
            Some(vec!["read", "write"])
        );
        assert_eq!(identity.claim_str_array("role"), None); // Not an array
                                                            // Mixed array should only contain strings
        assert_eq!(identity.claim_str_array("mixed"), Some(vec!["str"]));
        assert_eq!(identity.claim_str_array("missing"), None);
    }

    #[test]
    fn test_context_with_agent_identity_is_meaningful() {
        let identity = AgentIdentity {
            subject: Some("agent-123".to_string()),
            ..Default::default()
        };
        let ctx = EvaluationContext {
            agent_identity: Some(identity),
            ..Default::default()
        };
        assert!(
            ctx.has_any_meaningful_fields(),
            "Context with agent_identity should be meaningful"
        );
    }

    #[test]
    fn test_context_with_empty_agent_identity_is_not_meaningful() {
        let ctx = EvaluationContext {
            agent_identity: Some(AgentIdentity::default()),
            ..Default::default()
        };
        assert!(
            !ctx.has_any_meaningful_fields(),
            "Context with empty agent_identity should not be meaningful"
        );
    }

    // ═══════════════════════════════════════════════════
    // MCP 2025-11-25 TYPES TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_task_status_serialization() {
        let statuses = vec![
            TaskStatus::Pending,
            TaskStatus::Running,
            TaskStatus::Completed,
            TaskStatus::Failed { reason: "timeout".to_string() },
            TaskStatus::Cancelled,
            TaskStatus::Expired,
        ];
        for status in statuses {
            let json_str = serde_json::to_string(&status).unwrap();
            let deserialized: TaskStatus = serde_json::from_str(&json_str).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_task_status_display() {
        assert_eq!(TaskStatus::Pending.to_string(), "pending");
        assert_eq!(TaskStatus::Running.to_string(), "running");
        assert_eq!(TaskStatus::Completed.to_string(), "completed");
        assert_eq!(
            TaskStatus::Failed { reason: "error".to_string() }.to_string(),
            "failed: error"
        );
        assert_eq!(TaskStatus::Cancelled.to_string(), "cancelled");
        assert_eq!(TaskStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_tracked_task_terminal_states() {
        let pending = TrackedTask {
            task_id: "1".to_string(),
            tool: "tool".to_string(),
            function: "func".to_string(),
            status: TaskStatus::Pending,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            created_by: None,
            session_id: None,
        };
        assert!(!pending.is_terminal());
        assert!(pending.is_active());

        let running = TrackedTask {
            status: TaskStatus::Running,
            ..pending.clone()
        };
        assert!(!running.is_terminal());
        assert!(running.is_active());

        let completed = TrackedTask {
            status: TaskStatus::Completed,
            ..pending.clone()
        };
        assert!(completed.is_terminal());
        assert!(!completed.is_active());

        let failed = TrackedTask {
            status: TaskStatus::Failed { reason: "error".to_string() },
            ..pending.clone()
        };
        assert!(failed.is_terminal());
        assert!(!failed.is_active());

        let cancelled = TrackedTask {
            status: TaskStatus::Cancelled,
            ..pending.clone()
        };
        assert!(cancelled.is_terminal());
        assert!(!cancelled.is_active());

        let expired = TrackedTask {
            status: TaskStatus::Expired,
            ..pending
        };
        assert!(expired.is_terminal());
        assert!(!expired.is_active());
    }

    #[test]
    fn test_tracked_task_serialization() {
        let task = TrackedTask {
            task_id: "task-123".to_string(),
            tool: "background_job".to_string(),
            function: "execute".to_string(),
            status: TaskStatus::Running,
            created_at: "2026-01-01T12:00:00Z".to_string(),
            expires_at: Some("2026-01-01T13:00:00Z".to_string()),
            created_by: Some("agent-1".to_string()),
            session_id: Some("session-abc".to_string()),
        };
        let json_str = serde_json::to_string(&task).unwrap();
        let deserialized: TrackedTask = serde_json::from_str(&json_str).unwrap();
        assert_eq!(task, deserialized);
    }

    #[test]
    fn test_auth_level_ordering() {
        assert!(AuthLevel::None < AuthLevel::Basic);
        assert!(AuthLevel::Basic < AuthLevel::OAuth);
        assert!(AuthLevel::OAuth < AuthLevel::OAuthMfa);
        assert!(AuthLevel::OAuthMfa < AuthLevel::HardwareKey);
    }

    #[test]
    fn test_auth_level_satisfies() {
        assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::None));
        assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::Basic));
        assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuth));
        assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuthMfa));
        assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::HardwareKey));

        assert!(!AuthLevel::None.satisfies(AuthLevel::Basic));
        assert!(!AuthLevel::OAuth.satisfies(AuthLevel::OAuthMfa));
    }

    #[test]
    fn test_auth_level_from_u8() {
        assert_eq!(AuthLevel::from_u8(0), AuthLevel::None);
        assert_eq!(AuthLevel::from_u8(1), AuthLevel::Basic);
        assert_eq!(AuthLevel::from_u8(2), AuthLevel::OAuth);
        assert_eq!(AuthLevel::from_u8(3), AuthLevel::OAuthMfa);
        assert_eq!(AuthLevel::from_u8(4), AuthLevel::HardwareKey);
        assert_eq!(AuthLevel::from_u8(255), AuthLevel::None); // Unknown defaults to None
    }

    #[test]
    fn test_auth_level_display() {
        assert_eq!(AuthLevel::None.to_string(), "none");
        assert_eq!(AuthLevel::Basic.to_string(), "basic");
        assert_eq!(AuthLevel::OAuth.to_string(), "oauth");
        assert_eq!(AuthLevel::OAuthMfa.to_string(), "oauth_mfa");
        assert_eq!(AuthLevel::HardwareKey.to_string(), "hardware_key");
    }

    #[test]
    fn test_mcp_capability_new() {
        let cap = McpCapability::new("tools");
        assert_eq!(cap.name, "tools");
        assert!(cap.version.is_none());
        assert!(cap.sub_capabilities.is_empty());
    }

    #[test]
    fn test_mcp_capability_with_version() {
        let cap = McpCapability::with_version("sampling", "1.0");
        assert_eq!(cap.name, "sampling");
        assert_eq!(cap.version, Some("1.0".to_string()));
    }

    #[test]
    fn test_mcp_capability_has_sub() {
        let mut cap = McpCapability::new("tools");
        cap.sub_capabilities = vec!["read".to_string(), "write".to_string()];

        assert!(cap.has_sub("read"));
        assert!(cap.has_sub("write"));
        assert!(!cap.has_sub("execute"));
    }

    #[test]
    fn test_mcp_capability_serialization() {
        let cap = McpCapability {
            name: "resources".to_string(),
            version: Some("2.0".to_string()),
            sub_capabilities: vec!["list".to_string(), "read".to_string()],
        };
        let json_str = serde_json::to_string(&cap).unwrap();
        let deserialized: McpCapability = serde_json::from_str(&json_str).unwrap();
        assert_eq!(cap, deserialized);
    }

    // ═══════════════════════════════════════════════════
    // PHASE 2: ADVANCED THREAT DETECTION TYPES TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    #[test]
    fn test_circuit_state_serialization() {
        let states = vec![CircuitState::Closed, CircuitState::Open, CircuitState::HalfOpen];
        for state in states {
            let json_str = serde_json::to_string(&state).unwrap();
            let deserialized: CircuitState = serde_json::from_str(&json_str).unwrap();
            assert_eq!(state, deserialized);
        }
    }

    #[test]
    fn test_circuit_stats_default() {
        let stats = CircuitStats::default();
        assert_eq!(stats.state, CircuitState::Closed);
        assert_eq!(stats.failure_count, 0);
        assert_eq!(stats.success_count, 0);
        assert!(stats.last_failure.is_none());
    }

    #[test]
    fn test_circuit_stats_serialization() {
        let stats = CircuitStats {
            state: CircuitState::Open,
            failure_count: 5,
            success_count: 0,
            last_failure: Some(1704067200),
            last_state_change: 1704067200,
        };
        let json_str = serde_json::to_string(&stats).unwrap();
        let deserialized: CircuitStats = serde_json::from_str(&json_str).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_agent_fingerprint_is_populated() {
        let empty = AgentFingerprint::default();
        assert!(!empty.is_populated());

        let with_sub = AgentFingerprint {
            jwt_sub: Some("agent-123".to_string()),
            ..Default::default()
        };
        assert!(with_sub.is_populated());

        let with_iss = AgentFingerprint {
            jwt_iss: Some("https://auth.example.com".to_string()),
            ..Default::default()
        };
        assert!(with_iss.is_populated());
    }

    #[test]
    fn test_agent_fingerprint_summary() {
        let empty = AgentFingerprint::default();
        assert_eq!(empty.summary(), "empty");

        let fp = AgentFingerprint {
            jwt_sub: Some("agent-123".to_string()),
            jwt_iss: Some("https://auth.example.com".to_string()),
            client_id: Some("client-456".to_string()),
            ip_hash: Some("abc123".to_string()),
        };
        let summary = fp.summary();
        assert!(summary.contains("sub:agent-123"));
        assert!(summary.contains("iss:"));
        assert!(summary.contains("cid:client-456"));
        assert!(summary.contains("ip:*"));
    }

    #[test]
    fn test_agent_fingerprint_serialization() {
        let fp = AgentFingerprint {
            jwt_sub: Some("sub".to_string()),
            jwt_iss: Some("iss".to_string()),
            client_id: Some("cid".to_string()),
            ip_hash: Some("hash".to_string()),
        };
        let json_str = serde_json::to_string(&fp).unwrap();
        let deserialized: AgentFingerprint = serde_json::from_str(&json_str).unwrap();
        assert_eq!(fp, deserialized);
    }

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Unknown < TrustLevel::Low);
        assert!(TrustLevel::Low < TrustLevel::Medium);
        assert!(TrustLevel::Medium < TrustLevel::High);
        assert!(TrustLevel::High < TrustLevel::Verified);
    }

    #[test]
    fn test_trust_level_from_u8() {
        assert_eq!(TrustLevel::from_u8(0), TrustLevel::Unknown);
        assert_eq!(TrustLevel::from_u8(1), TrustLevel::Low);
        assert_eq!(TrustLevel::from_u8(2), TrustLevel::Medium);
        assert_eq!(TrustLevel::from_u8(3), TrustLevel::High);
        assert_eq!(TrustLevel::from_u8(4), TrustLevel::Verified);
        assert_eq!(TrustLevel::from_u8(255), TrustLevel::Unknown);
    }

    #[test]
    fn test_trust_level_display() {
        assert_eq!(TrustLevel::Unknown.to_string(), "unknown");
        assert_eq!(TrustLevel::Low.to_string(), "low");
        assert_eq!(TrustLevel::Medium.to_string(), "medium");
        assert_eq!(TrustLevel::High.to_string(), "high");
        assert_eq!(TrustLevel::Verified.to_string(), "verified");
    }

    #[test]
    fn test_schema_record_new() {
        let record = SchemaRecord::new("my_tool", "abc123", 1704067200);
        assert_eq!(record.tool_name, "my_tool");
        assert_eq!(record.schema_hash, "abc123");
        assert_eq!(record.first_seen, 1704067200);
        assert_eq!(record.last_seen, 1704067200);
        assert!(record.version_history.is_empty());
        assert_eq!(record.trust_score, 0.0);
    }

    #[test]
    fn test_schema_record_version_count() {
        let mut record = SchemaRecord::new("tool", "hash1", 1000);
        assert_eq!(record.version_count(), 1);

        record.version_history.push("hash0".to_string());
        assert_eq!(record.version_count(), 2);

        record.version_history.push("hash_prev".to_string());
        assert_eq!(record.version_count(), 3);
    }

    #[test]
    fn test_schema_record_is_stable() {
        let record = SchemaRecord::new("tool", "hash", 1000);
        assert!(record.is_stable()); // No history = stable

        let mut record_same = record.clone();
        record_same.version_history.push("hash".to_string());
        assert!(record_same.is_stable()); // Same hash in history = stable

        let mut record_diff = record.clone();
        record_diff.version_history.push("different_hash".to_string());
        assert!(!record_diff.is_stable()); // Different hash in history = unstable
    }

    #[test]
    fn test_schema_record_serialization() {
        let record = SchemaRecord {
            tool_name: "my_tool".to_string(),
            schema_hash: "hash123".to_string(),
            first_seen: 1000,
            last_seen: 2000,
            version_history: vec!["hash0".to_string(), "hash1".to_string()],
            trust_score: 0.75,
            schema_content: Some(serde_json::json!({"type": "object"})),
        };
        let json_str = serde_json::to_string(&record).unwrap();
        let deserialized: SchemaRecord = serde_json::from_str(&json_str).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_schema_record_new_with_content() {
        let schema = serde_json::json!({"type": "object", "properties": {"name": {"type": "string"}}});
        let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
        assert_eq!(record.tool_name, "test_tool");
        assert_eq!(record.schema_hash, "hash123");
        assert_eq!(record.schema_content, Some(schema));
    }

    #[test]
    fn test_schema_record_large_schema_not_stored() {
        // Create a schema larger than MAX_SCHEMA_SIZE
        let large_value = "x".repeat(SchemaRecord::MAX_SCHEMA_SIZE + 1000);
        let schema = serde_json::json!({"data": large_value});
        let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
        // Schema content should be None because it's too large
        assert!(record.schema_content.is_none());
    }

    #[test]
    fn test_principal_context_direct() {
        let ctx = PrincipalContext::direct("user-123");
        assert_eq!(ctx.original_principal, "user-123");
        assert!(!ctx.is_delegated());
        assert_eq!(ctx.delegation_depth, 0);
    }

    #[test]
    fn test_principal_context_is_delegated() {
        let direct = PrincipalContext::direct("user");
        assert!(!direct.is_delegated());

        let delegated = PrincipalContext {
            original_principal: "user".to_string(),
            delegated_to: Some("agent".to_string()),
            delegation_depth: 1,
            allowed_tools: vec!["read_file".to_string()],
            delegation_expires: None,
        };
        assert!(delegated.is_delegated());
    }

    #[test]
    fn test_principal_context_is_expired() {
        let no_expiry = PrincipalContext::direct("user");
        assert!(!no_expiry.is_expired(1000));

        let not_expired = PrincipalContext {
            delegation_expires: Some(2000),
            ..PrincipalContext::direct("user")
        };
        assert!(!not_expired.is_expired(1000));

        let expired = PrincipalContext {
            delegation_expires: Some(1000),
            ..PrincipalContext::direct("user")
        };
        assert!(expired.is_expired(1000));
        assert!(expired.is_expired(2000));
    }

    #[test]
    fn test_principal_context_serialization() {
        let ctx = PrincipalContext {
            original_principal: "user".to_string(),
            delegated_to: Some("agent".to_string()),
            delegation_depth: 2,
            allowed_tools: vec!["tool1".to_string(), "tool2".to_string()],
            delegation_expires: Some(1704067200),
        };
        let json_str = serde_json::to_string(&ctx).unwrap();
        let deserialized: PrincipalContext = serde_json::from_str(&json_str).unwrap();
        assert_eq!(ctx, deserialized);
    }

    #[test]
    fn test_sampling_stats_new() {
        let stats = SamplingStats::new(1000);
        assert_eq!(stats.request_count, 0);
        assert_eq!(stats.last_request, 1000);
        assert_eq!(stats.window_start, 1000);
        assert!(stats.flagged_patterns.is_empty());
    }

    #[test]
    fn test_sampling_stats_record_request() {
        let mut stats = SamplingStats::new(1000);
        assert_eq!(stats.record_request(1001), 1);
        assert_eq!(stats.record_request(1002), 2);
        assert_eq!(stats.last_request, 1002);
        assert_eq!(stats.request_count, 2);
    }

    #[test]
    fn test_sampling_stats_reset_window() {
        let mut stats = SamplingStats::new(1000);
        stats.record_request(1001);
        stats.record_request(1002);
        stats.flagged_patterns.push("pattern1".to_string());

        stats.reset_window(2000);
        assert_eq!(stats.request_count, 0);
        assert_eq!(stats.window_start, 2000);
        // Flagged patterns are preserved
        assert!(!stats.flagged_patterns.is_empty());
    }

    #[test]
    fn test_sampling_stats_serialization() {
        let stats = SamplingStats {
            request_count: 5,
            last_request: 1005,
            window_start: 1000,
            flagged_patterns: vec!["sensitive".to_string()],
        };
        let json_str = serde_json::to_string(&stats).unwrap();
        let deserialized: SamplingStats = serde_json::from_str(&json_str).unwrap();
        assert_eq!(stats, deserialized);
    }

    // ═══════════════════════════════════════════════════
    // ETDI (Enhanced Tool Definition Interface) TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_signature_algorithm_display() {
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(SignatureAlgorithm::EcdsaP256.to_string(), "ecdsa_p256");
    }

    #[test]
    fn test_signature_algorithm_default() {
        assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_signature_algorithm_serialization() {
        for alg in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::EcdsaP256] {
            let json_str = serde_json::to_string(&alg).unwrap();
            let deserialized: SignatureAlgorithm = serde_json::from_str(&json_str).unwrap();
            assert_eq!(alg, deserialized);
        }
    }

    #[test]
    fn test_tool_signature_serialization_roundtrip() {
        let sig = ToolSignature {
            signature_id: "sig-123".to_string(),
            signature: "deadbeef".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "cafe0123".to_string(),
            key_fingerprint: Some("fp:abc".to_string()),
            signed_at: "2026-01-15T12:00:00Z".to_string(),
            expires_at: Some("2027-01-15T12:00:00Z".to_string()),
            signer_spiffe_id: Some("spiffe://example.org/agent".to_string()),
        };
        let json_str = serde_json::to_string(&sig).unwrap();
        let deserialized: ToolSignature = serde_json::from_str(&json_str).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn test_tool_signature_is_expired() {
        let sig = ToolSignature {
            signature_id: "sig-1".to_string(),
            signature: "abc".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "key".to_string(),
            key_fingerprint: None,
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: Some("2026-06-01T00:00:00Z".to_string()),
            signer_spiffe_id: None,
        };

        // Before expiry
        assert!(!sig.is_expired("2026-05-01T00:00:00Z"));
        // At expiry
        assert!(sig.is_expired("2026-06-01T00:00:00Z"));
        // After expiry
        assert!(sig.is_expired("2026-12-01T00:00:00Z"));
    }

    #[test]
    fn test_tool_signature_no_expiry_never_expires() {
        let sig = ToolSignature {
            signature_id: "sig-1".to_string(),
            signature: "abc".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "key".to_string(),
            key_fingerprint: None,
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            signer_spiffe_id: None,
        };
        assert!(!sig.is_expired("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn test_signature_verification_is_fully_verified() {
        let valid_and_trusted = SignatureVerification {
            valid: true,
            signer_trusted: true,
            expired: false,
            message: "OK".to_string(),
        };
        assert!(valid_and_trusted.is_fully_verified());

        let invalid = SignatureVerification {
            valid: false,
            signer_trusted: true,
            expired: false,
            message: "bad sig".to_string(),
        };
        assert!(!invalid.is_fully_verified());

        let untrusted = SignatureVerification {
            valid: true,
            signer_trusted: false,
            expired: false,
            message: "unknown signer".to_string(),
        };
        assert!(!untrusted.is_fully_verified());

        let expired = SignatureVerification {
            valid: true,
            signer_trusted: true,
            expired: true,
            message: "expired".to_string(),
        };
        assert!(!expired.is_fully_verified());
    }

    #[test]
    fn test_signature_verification_serialization() {
        let verification = SignatureVerification {
            valid: true,
            signer_trusted: true,
            expired: false,
            message: "Verified successfully".to_string(),
        };
        let json_str = serde_json::to_string(&verification).unwrap();
        let deserialized: SignatureVerification = serde_json::from_str(&json_str).unwrap();
        assert_eq!(verification, deserialized);
    }

    #[test]
    fn test_tool_attestation_is_initial() {
        let sig = ToolSignature {
            signature_id: "sig-1".to_string(),
            signature: "abc".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "key".to_string(),
            key_fingerprint: None,
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            signer_spiffe_id: None,
        };

        let initial = ToolAttestation {
            attestation_id: "att-1".to_string(),
            attestation_type: "initial".to_string(),
            attester: "admin".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            tool_hash: "hash123".to_string(),
            previous_attestation: None,
            signature: sig.clone(),
            transparency_log_entry: None,
        };
        assert!(initial.is_initial());

        let chained = ToolAttestation {
            attestation_id: "att-2".to_string(),
            attestation_type: "version_update".to_string(),
            attester: "admin".to_string(),
            timestamp: "2026-02-01T00:00:00Z".to_string(),
            tool_hash: "hash456".to_string(),
            previous_attestation: Some("att-1".to_string()),
            signature: sig,
            transparency_log_entry: Some("log-entry-123".to_string()),
        };
        assert!(!chained.is_initial());
    }

    #[test]
    fn test_tool_attestation_serialization() {
        let sig = ToolSignature {
            signature_id: "sig-1".to_string(),
            signature: "abc".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: "key".to_string(),
            key_fingerprint: None,
            signed_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            signer_spiffe_id: None,
        };
        let attestation = ToolAttestation {
            attestation_id: "att-1".to_string(),
            attestation_type: "initial".to_string(),
            attester: "admin".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            tool_hash: "hash123".to_string(),
            previous_attestation: None,
            signature: sig,
            transparency_log_entry: None,
        };
        let json_str = serde_json::to_string(&attestation).unwrap();
        let deserialized: ToolAttestation = serde_json::from_str(&json_str).unwrap();
        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_tool_version_pin_exact_vs_constraint() {
        let exact = ToolVersionPin {
            tool_name: "my_tool".to_string(),
            pinned_version: Some("1.2.3".to_string()),
            version_constraint: None,
            definition_hash: "hash123".to_string(),
            pinned_at: "2026-01-01T00:00:00Z".to_string(),
            pinned_by: "admin".to_string(),
        };
        assert!(exact.is_exact());
        assert!(!exact.is_constraint());

        let constraint = ToolVersionPin {
            tool_name: "my_tool".to_string(),
            pinned_version: None,
            version_constraint: Some("^1.2.0".to_string()),
            definition_hash: "hash456".to_string(),
            pinned_at: "2026-01-01T00:00:00Z".to_string(),
            pinned_by: "admin".to_string(),
        };
        assert!(!constraint.is_exact());
        assert!(constraint.is_constraint());
    }

    #[test]
    fn test_tool_version_pin_serialization() {
        let pin = ToolVersionPin {
            tool_name: "tool".to_string(),
            pinned_version: Some("1.0.0".to_string()),
            version_constraint: None,
            definition_hash: "hash".to_string(),
            pinned_at: "2026-01-01T00:00:00Z".to_string(),
            pinned_by: "admin".to_string(),
        };
        let json_str = serde_json::to_string(&pin).unwrap();
        let deserialized: ToolVersionPin = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pin, deserialized);
    }

    #[test]
    fn test_version_drift_alert_version_mismatch() {
        let alert = VersionDriftAlert::version_mismatch(
            "my_tool",
            "1.0.0",
            "1.1.0",
            true,
            "2026-02-01T00:00:00Z",
        );
        assert_eq!(alert.tool, "my_tool");
        assert_eq!(alert.expected_version, "1.0.0");
        assert_eq!(alert.actual_version, "1.1.0");
        assert_eq!(alert.drift_type, "version_mismatch");
        assert!(alert.blocking);
    }

    #[test]
    fn test_version_drift_alert_hash_mismatch() {
        let alert = VersionDriftAlert::hash_mismatch(
            "my_tool",
            "abc123",
            "def456",
            false,
            "2026-02-01T00:00:00Z",
        );
        assert_eq!(alert.drift_type, "hash_mismatch");
        assert!(!alert.blocking);
    }

    #[test]
    fn test_version_drift_alert_serialization() {
        let alert = VersionDriftAlert {
            tool: "tool".to_string(),
            expected_version: "1.0".to_string(),
            actual_version: "2.0".to_string(),
            drift_type: "version_mismatch".to_string(),
            blocking: true,
            detected_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json_str = serde_json::to_string(&alert).unwrap();
        let deserialized: VersionDriftAlert = serde_json::from_str(&json_str).unwrap();
        assert_eq!(alert, deserialized);
    }

    // ═══════════════════════════════════════════════════
    // PHASE 10: NHI LIFECYCLE TYPES TESTS
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_nhi_attestation_type_serialization() {
        let types = vec![
            NhiAttestationType::Jwt,
            NhiAttestationType::Mtls,
            NhiAttestationType::Spiffe,
            NhiAttestationType::DPoP,
            NhiAttestationType::ApiKey,
        ];
        for atype in types {
            let json_str = serde_json::to_string(&atype).unwrap();
            let deserialized: NhiAttestationType = serde_json::from_str(&json_str).unwrap();
            assert_eq!(atype, deserialized);
        }
    }

    #[test]
    fn test_nhi_attestation_type_display() {
        assert_eq!(NhiAttestationType::Jwt.to_string(), "jwt");
        assert_eq!(NhiAttestationType::Mtls.to_string(), "mtls");
        assert_eq!(NhiAttestationType::Spiffe.to_string(), "spiffe");
        assert_eq!(NhiAttestationType::DPoP.to_string(), "dpop");
        assert_eq!(NhiAttestationType::ApiKey.to_string(), "api_key");
    }

    #[test]
    fn test_nhi_identity_status_serialization() {
        let statuses = vec![
            NhiIdentityStatus::Active,
            NhiIdentityStatus::Suspended,
            NhiIdentityStatus::Revoked,
            NhiIdentityStatus::Expired,
            NhiIdentityStatus::Probationary,
        ];
        for status in statuses {
            let json_str = serde_json::to_string(&status).unwrap();
            let deserialized: NhiIdentityStatus = serde_json::from_str(&json_str).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_nhi_identity_status_display() {
        assert_eq!(NhiIdentityStatus::Active.to_string(), "active");
        assert_eq!(NhiIdentityStatus::Suspended.to_string(), "suspended");
        assert_eq!(NhiIdentityStatus::Revoked.to_string(), "revoked");
        assert_eq!(NhiIdentityStatus::Expired.to_string(), "expired");
        assert_eq!(NhiIdentityStatus::Probationary.to_string(), "probationary");
    }

    #[test]
    fn test_nhi_agent_identity_serialization() {
        let identity = NhiAgentIdentity {
            id: "agent-123".to_string(),
            name: "Test Agent".to_string(),
            attestation_type: NhiAttestationType::Spiffe,
            status: NhiIdentityStatus::Active,
            spiffe_id: Some("spiffe://example.org/agent/test".to_string()),
            public_key: Some("abc123".to_string()),
            key_algorithm: Some("Ed25519".to_string()),
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            last_rotation: Some("2026-06-01T00:00:00Z".to_string()),
            auth_count: 42,
            last_auth: Some("2026-02-01T12:00:00Z".to_string()),
            tags: vec!["production".to_string(), "internal".to_string()],
            metadata: {
                let mut m = HashMap::new();
                m.insert("team".to_string(), "platform".to_string());
                m
            },
        };
        let json_str = serde_json::to_string(&identity).unwrap();
        let deserialized: NhiAgentIdentity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(identity, deserialized);
    }

    #[test]
    fn test_nhi_behavioral_baseline_serialization() {
        let baseline = NhiBehavioralBaseline {
            agent_id: "agent-123".to_string(),
            tool_call_patterns: {
                let mut m = HashMap::new();
                m.insert("file:read".to_string(), 10.5);
                m.insert("http:get".to_string(), 5.2);
                m
            },
            avg_request_interval_secs: 2.5,
            request_interval_stddev: 0.8,
            typical_session_duration_secs: 3600.0,
            observation_count: 1000,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            last_updated: "2026-02-01T00:00:00Z".to_string(),
            confidence: 0.95,
            typical_source_ips: vec!["10.0.0.0/8".to_string()],
            active_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17],
        };
        let json_str = serde_json::to_string(&baseline).unwrap();
        let deserialized: NhiBehavioralBaseline = serde_json::from_str(&json_str).unwrap();
        assert_eq!(baseline, deserialized);
    }

    #[test]
    fn test_nhi_behavioral_recommendation_display() {
        assert_eq!(NhiBehavioralRecommendation::Allow.to_string(), "allow");
        assert_eq!(NhiBehavioralRecommendation::AllowWithLogging.to_string(), "allow_with_logging");
        assert_eq!(NhiBehavioralRecommendation::StepUpAuth.to_string(), "step_up_auth");
        assert_eq!(NhiBehavioralRecommendation::Suspend.to_string(), "suspend");
        assert_eq!(NhiBehavioralRecommendation::Revoke.to_string(), "revoke");
    }

    #[test]
    fn test_nhi_delegation_chain_depth() {
        let chain = NhiDelegationChain {
            chain: vec![
                NhiDelegationLink {
                    from_agent: "agent-a".to_string(),
                    to_agent: "agent-b".to_string(),
                    permissions: vec!["read".to_string()],
                    scope_constraints: vec!["tools:file_*".to_string()],
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    expires_at: "2026-02-01T00:00:00Z".to_string(),
                    active: true,
                    reason: Some("Temporary delegation".to_string()),
                },
                NhiDelegationLink {
                    from_agent: "agent-b".to_string(),
                    to_agent: "agent-c".to_string(),
                    permissions: vec!["read".to_string()],
                    scope_constraints: vec![],
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    expires_at: "2026-02-01T00:00:00Z".to_string(),
                    active: true,
                    reason: None,
                },
            ],
            max_depth: 5,
            resolved_at: "2026-01-15T00:00:00Z".to_string(),
        };
        assert_eq!(chain.depth(), 2);
        assert!(!chain.exceeds_max_depth());
        assert_eq!(chain.origin(), Some("agent-a"));
        assert_eq!(chain.terminus(), Some("agent-c"));
    }

    #[test]
    fn test_nhi_delegation_chain_exceeds_max() {
        let chain = NhiDelegationChain {
            chain: vec![
                NhiDelegationLink {
                    from_agent: "a".to_string(),
                    to_agent: "b".to_string(),
                    permissions: vec![],
                    scope_constraints: vec![],
                    created_at: "".to_string(),
                    expires_at: "".to_string(),
                    active: true,
                    reason: None,
                },
            ],
            max_depth: 0, // Max depth of 0 means no delegation allowed
            resolved_at: "".to_string(),
        };
        assert!(chain.exceeds_max_depth());
    }

    #[test]
    fn test_nhi_dpop_proof_serialization() {
        let proof = NhiDpopProof {
            proof: "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...".to_string(),
            htm: "POST".to_string(),
            htu: "https://api.example.com/resource".to_string(),
            ath: Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo".to_string()),
            nonce: Some("server-nonce-123".to_string()),
            iat: "2026-02-01T12:00:00Z".to_string(),
            jti: "unique-id-456".to_string(),
        };
        let json_str = serde_json::to_string(&proof).unwrap();
        let deserialized: NhiDpopProof = serde_json::from_str(&json_str).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_nhi_stats_default() {
        let stats = NhiStats::default();
        assert_eq!(stats.total_identities, 0);
        assert_eq!(stats.active_identities, 0);
        assert_eq!(stats.active_delegations, 0);
    }

    #[test]
    fn test_nhi_credential_rotation_serialization() {
        let rotation = NhiCredentialRotation {
            agent_id: "agent-123".to_string(),
            previous_thumbprint: Some("old-thumb".to_string()),
            new_thumbprint: "new-thumb".to_string(),
            rotated_at: "2026-02-01T00:00:00Z".to_string(),
            trigger: "scheduled".to_string(),
            new_expires_at: "2027-02-01T00:00:00Z".to_string(),
        };
        let json_str = serde_json::to_string(&rotation).unwrap();
        let deserialized: NhiCredentialRotation = serde_json::from_str(&json_str).unwrap();
        assert_eq!(rotation, deserialized);
    }
}
