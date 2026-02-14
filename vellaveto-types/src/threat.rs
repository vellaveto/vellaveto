//! Advanced threat detection types — auth levels, circuit breakers, fingerprints,
//! trust levels, schema records, principal context, and sampling stats.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Authentication level for step-up authentication policies.
///
/// Step-up auth allows policies to require stronger authentication
/// for sensitive operations. Levels are ordered by strength.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
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
    /// Hardware key authentication (`WebAuthn`, `FIDO2`).
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
    /// Convert from `u8` to `AuthLevel`, defaulting to `None` for unknown values.
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
    /// Number of times the circuit has tripped (HalfOpen→Open transitions).
    /// Used for exponential backoff of open duration. Capped at 5 (32x max).
    #[serde(default)]
    pub trip_count: u32,
}

impl Default for CircuitStats {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_state_change: 0,
            trip_count: 0,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    /// Too many `target_paths` + `target_domains` entries.
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
                write!(f, "Action {field} must not be empty")
            }
            ValidationError::NullByte { field } => {
                write!(f, "Action {field} contains null byte")
            }
            ValidationError::ControlCharacter { field } => {
                write!(f, "Action {field} contains control character")
            }
            ValidationError::TooLong { field, len, max } => {
                write!(f, "Action {field} too long: {len} bytes (max {max})")
            }
            ValidationError::TooManyTargets { count, max } => {
                write!(f, "Too many targets: {count} (max {max})")
            }
            ValidationError::TargetTooLong {
                field,
                index,
                len,
                max,
            } => {
                write!(
                    f,
                    "Target {field}[{index}] too long: {len} bytes (max {max})"
                )
            }
            ValidationError::TargetNullByte { field, index } => {
                write!(f, "Target {field}[{index}] contains null byte")
            }
        }
    }
}

impl std::error::Error for ValidationError {}
