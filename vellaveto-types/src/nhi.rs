//! Non-Human Identity (NHI) lifecycle types — attestation, behavioral baselines,
//! delegation chains, DPoP proofs, and credential rotation.

use crate::verification::{AccountabilityAttestation, VerificationTier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Attestation type for agent identity verification.
///
/// Determines how an agent proves its identity to Vellaveto.
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
    Active,
    /// Identity is suspended pending review.
    Suspended,
    /// Identity has been revoked.
    Revoked,
    /// Identity has expired.
    Expired,
    /// Identity is in a probationary period (new or recently restored).
    /// SECURITY (FIND-R46-014): Default to Probationary for fail-closed behavior.
    /// New identities should start with restricted privileges until explicitly
    /// promoted to Active after verification. Prevents newly registered agents
    /// from immediately gaining full access.
    #[default]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    /// Verification tier for this identity.
    #[serde(default)]
    pub verification_tier: VerificationTier,
    /// DID:PLC identifier (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_plc: Option<String>,
    /// Accountability attestations signed by this identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AccountabilityAttestation>,
}

impl NhiAgentIdentity {
    /// Maximum tags per identity.
    pub const MAX_TAGS: usize = 100;
    /// Maximum metadata entries per identity.
    pub const MAX_METADATA_ENTRIES: usize = 100;
    /// Maximum attestations per identity.
    pub const MAX_ATTESTATIONS: usize = 100;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-005): Unbounded tags, metadata, attestations from deserialization.
    pub fn validate(&self) -> Result<(), String> {
        if self.tags.len() > Self::MAX_TAGS {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} tags (max {})",
                self.id,
                self.tags.len(),
                Self::MAX_TAGS
            ));
        }
        if self.metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} metadata entries (max {})",
                self.id,
                self.metadata.len(),
                Self::MAX_METADATA_ENTRIES
            ));
        }
        if self.attestations.len() > Self::MAX_ATTESTATIONS {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} attestations (max {})",
                self.id,
                self.attestations.len(),
                Self::MAX_ATTESTATIONS
            ));
        }
        Ok(())
    }
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

impl NhiBehavioralBaseline {
    /// Maximum tool call pattern entries.
    pub const MAX_TOOL_CALL_PATTERNS: usize = 10_000;
    /// Maximum typical source IPs.
    pub const MAX_SOURCE_IPS: usize = 1000;

    /// Validate that all f64 fields are finite (not NaN or Infinity)
    /// and collection sizes are bounded.
    ///
    /// SECURITY (FIND-R48-009): Also check collection size bounds.
    pub fn validate_finite(&self) -> Result<(), String> {
        if self.tool_call_patterns.len() > Self::MAX_TOOL_CALL_PATTERNS {
            return Err(format!(
                "NhiBehavioralBaseline has {} tool_call_patterns (max {})",
                self.tool_call_patterns.len(),
                Self::MAX_TOOL_CALL_PATTERNS
            ));
        }
        if self.typical_source_ips.len() > Self::MAX_SOURCE_IPS {
            return Err(format!(
                "NhiBehavioralBaseline has {} typical_source_ips (max {})",
                self.typical_source_ips.len(),
                Self::MAX_SOURCE_IPS
            ));
        }
        for (key, val) in &self.tool_call_patterns {
            if !val.is_finite() {
                return Err(format!(
                    "NhiBehavioralBaseline tool_call_patterns['{key}'] is not finite: {val}"
                ));
            }
        }
        if !self.avg_request_interval_secs.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline avg_request_interval_secs is not finite: {}",
                self.avg_request_interval_secs
            ));
        }
        if !self.request_interval_stddev.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline request_interval_stddev is not finite: {}",
                self.request_interval_stddev
            ));
        }
        if !self.typical_session_duration_secs.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline typical_session_duration_secs is not finite: {}",
                self.typical_session_duration_secs
            ));
        }
        if !self.confidence.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline confidence is not finite: {}",
                self.confidence
            ));
        }
        Ok(())
    }
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

impl NhiBehavioralCheckResult {
    /// Validate that all f64 fields are finite (not NaN or Infinity).
    ///
    /// SECURITY (FIND-P2-007): Non-finite anomaly_score could bypass
    /// threshold comparisons that determine whether to allow or block.
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.anomaly_score.is_finite() {
            return Err(format!(
                "NhiBehavioralCheckResult has non-finite anomaly_score: {}",
                self.anomaly_score
            ));
        }
        for dev in &self.deviations {
            if !dev.severity.is_finite() {
                return Err(format!(
                    "NhiBehavioralDeviation '{}' has non-finite severity: {}",
                    dev.deviation_type, dev.severity
                ));
            }
        }
        Ok(())
    }
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

impl NhiDelegationLink {
    /// Maximum permissions per delegation link.
    pub const MAX_PERMISSIONS: usize = 256;
    /// Maximum scope constraints per delegation link.
    pub const MAX_SCOPE_CONSTRAINTS: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-006): Unbounded permissions and scope_constraints.
    pub fn validate(&self) -> Result<(), String> {
        if self.permissions.len() > Self::MAX_PERMISSIONS {
            return Err(format!(
                "NhiDelegationLink has {} permissions (max {})",
                self.permissions.len(),
                Self::MAX_PERMISSIONS
            ));
        }
        if self.scope_constraints.len() > Self::MAX_SCOPE_CONSTRAINTS {
            return Err(format!(
                "NhiDelegationLink has {} scope_constraints (max {})",
                self.scope_constraints.len(),
                Self::MAX_SCOPE_CONSTRAINTS
            ));
        }
        Ok(())
    }
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
