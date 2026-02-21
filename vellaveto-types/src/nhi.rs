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
///
/// SECURITY (IMP-R104-003): Custom Debug impl redacts public_key.
#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
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

/// SECURITY (IMP-R104-003): Custom Debug redacts `public_key` to prevent
/// cryptographic material from leaking into logs. Follows the ToolSignature pattern.
impl std::fmt::Debug for NhiAgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NhiAgentIdentity")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("attestation_type", &self.attestation_type)
            .field("status", &self.status)
            .field("spiffe_id", &self.spiffe_id)
            .field("public_key", &self.public_key.as_ref().map(|_| "[REDACTED]"))
            .field("key_algorithm", &self.key_algorithm)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("last_rotation", &self.last_rotation)
            .field("auth_count", &self.auth_count)
            .field("last_auth", &self.last_auth)
            .field("tags", &self.tags)
            .field("metadata", &self.metadata)
            .field("verification_tier", &self.verification_tier)
            .field("did_plc", &self.did_plc)
            .field("attestations", &self.attestations)
            .finish()
    }
}

impl NhiAgentIdentity {
    /// Maximum tags per identity.
    pub const MAX_TAGS: usize = 100;
    /// Maximum metadata entries per identity.
    pub const MAX_METADATA_ENTRIES: usize = 100;
    /// Maximum attestations per identity.
    pub const MAX_ATTESTATIONS: usize = 100;
    /// Maximum length for a single tag.
    pub const MAX_TAG_LEN: usize = 256;
    /// Maximum length for a metadata key.
    pub const MAX_METADATA_KEY_LEN: usize = 256;
    /// Maximum length for a metadata value.
    pub const MAX_METADATA_VALUE_LEN: usize = 4096;
    /// Maximum length for the `id` field.
    pub const MAX_ID_LEN: usize = 256;
    /// Maximum length for the `name` field.
    pub const MAX_NAME_LEN: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-005): Unbounded tags, metadata, attestations from deserialization.
    /// SECURITY (FIND-R112-007): Per-entry tag/metadata content validation.
    /// SECURITY (FIND-R112-011): id and name field validation.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (FIND-R112-011): Validate id field.
        if self.id.is_empty() {
            return Err("NhiAgentIdentity id must not be empty".to_string());
        }
        if self.id.len() > Self::MAX_ID_LEN {
            return Err(format!(
                "NhiAgentIdentity id length {} exceeds max {}",
                self.id.len(),
                Self::MAX_ID_LEN
            ));
        }
        if self.id.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiAgentIdentity id contains control or format characters".to_string());
        }

        // SECURITY (FIND-R112-011): Validate name field.
        if self.name.len() > Self::MAX_NAME_LEN {
            return Err(format!(
                "NhiAgentIdentity '{}' name length {} exceeds max {}",
                self.id,
                self.name.len(),
                Self::MAX_NAME_LEN
            ));
        }
        if self.name.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err(format!(
                "NhiAgentIdentity '{}' name contains control or format characters",
                self.id
            ));
        }

        if self.tags.len() > Self::MAX_TAGS {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} tags (max {})",
                self.id,
                self.tags.len(),
                Self::MAX_TAGS
            ));
        }
        // SECURITY (FIND-R112-007): Per-entry tag validation.
        for (i, tag) in self.tags.iter().enumerate() {
            if tag.len() > Self::MAX_TAG_LEN {
                return Err(format!(
                    "NhiAgentIdentity '{}' tag[{i}] length {} exceeds max {}",
                    self.id,
                    tag.len(),
                    Self::MAX_TAG_LEN
                ));
            }
            if tag.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err(format!(
                    "NhiAgentIdentity '{}' tag[{i}] contains control or format characters",
                    self.id
                ));
            }
        }

        if self.metadata.len() > Self::MAX_METADATA_ENTRIES {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} metadata entries (max {})",
                self.id,
                self.metadata.len(),
                Self::MAX_METADATA_ENTRIES
            ));
        }
        // SECURITY (FIND-R112-007): Per-entry metadata key/value validation.
        for (key, value) in &self.metadata {
            if key.len() > Self::MAX_METADATA_KEY_LEN {
                return Err(format!(
                    "NhiAgentIdentity '{}' metadata key length {} exceeds max {}",
                    self.id,
                    key.len(),
                    Self::MAX_METADATA_KEY_LEN
                ));
            }
            if key.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err(format!(
                    "NhiAgentIdentity '{}' metadata key contains control or format characters",
                    self.id
                ));
            }
            if value.len() > Self::MAX_METADATA_VALUE_LEN {
                return Err(format!(
                    "NhiAgentIdentity '{}' metadata value length {} exceeds max {}",
                    self.id,
                    value.len(),
                    Self::MAX_METADATA_VALUE_LEN
                ));
            }
            if value.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err(format!(
                    "NhiAgentIdentity '{}' metadata value contains control or format characters",
                    self.id
                ));
            }
        }

        if self.attestations.len() > Self::MAX_ATTESTATIONS {
            return Err(format!(
                "NhiAgentIdentity '{}' has {} attestations (max {})",
                self.id,
                self.attestations.len(),
                Self::MAX_ATTESTATIONS
            ));
        }

        // SECURITY (IMP-R122-009): Validate ISO 8601 timestamp fields.
        // Malformed timestamps can bypass is_expired() checks.
        crate::time_util::parse_iso8601_secs(&self.issued_at).map_err(|e| {
            format!(
                "NhiAgentIdentity '{}' issued_at is not valid ISO 8601: {}",
                self.id, e
            )
        })?;
        crate::time_util::parse_iso8601_secs(&self.expires_at).map_err(|e| {
            format!(
                "NhiAgentIdentity '{}' expires_at is not valid ISO 8601: {}",
                self.id, e
            )
        })?;
        if let Some(ref lr) = self.last_rotation {
            crate::time_util::parse_iso8601_secs(lr).map_err(|e| {
                format!(
                    "NhiAgentIdentity '{}' last_rotation is not valid ISO 8601: {}",
                    self.id, e
                )
            })?;
        }
        if let Some(ref la) = self.last_auth {
            crate::time_util::parse_iso8601_secs(la).map_err(|e| {
                format!(
                    "NhiAgentIdentity '{}' last_auth is not valid ISO 8601: {}",
                    self.id, e
                )
            })?;
        }

        Ok(())
    }
}

/// Behavioral baseline for continuous agent authentication.
///
/// Tracks typical behavior patterns to detect anomalies that might
/// indicate credential theft or impersonation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
    /// Maximum entries in `active_hours`.
    pub const MAX_ACTIVE_HOURS: usize = 24;

    /// Validate structural invariants: finite scores, range checks, collection bounds,
    /// and active hour validity.
    ///
    /// SECURITY (FIND-R48-009): Also check collection size bounds.
    pub fn validate(&self) -> Result<(), String> {
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
        if self.active_hours.len() > Self::MAX_ACTIVE_HOURS {
            return Err(format!(
                "NhiBehavioralBaseline has {} active_hours (max {})",
                self.active_hours.len(),
                Self::MAX_ACTIVE_HOURS
            ));
        }
        for (i, &hour) in self.active_hours.iter().enumerate() {
            if hour > 23 {
                return Err(format!(
                    "NhiBehavioralBaseline active_hours[{}] value {} is not a valid hour (0-23)",
                    i, hour
                ));
            }
        }
        for (key, val) in &self.tool_call_patterns {
            if !val.is_finite() {
                return Err(format!(
                    "NhiBehavioralBaseline tool_call_patterns['{key}'] is not finite: {val}"
                ));
            }
            // SECURITY (FIND-R53-P3-006): Negative call frequency is nonsensical.
            if *val < 0.0 {
                return Err(format!(
                    "NhiBehavioralBaseline tool_call_patterns['{key}'] must be >= 0.0, got {val}"
                ));
            }
        }
        if !self.avg_request_interval_secs.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline avg_request_interval_secs is not finite: {}",
                self.avg_request_interval_secs
            ));
        }
        // SECURITY (FIND-R53-P3-006): Negative timing values are nonsensical and could
        // cause unexpected comparisons (e.g., negative interval always < any threshold).
        if self.avg_request_interval_secs < 0.0 {
            return Err(format!(
                "NhiBehavioralBaseline avg_request_interval_secs must be >= 0.0, got {}",
                self.avg_request_interval_secs
            ));
        }
        if !self.request_interval_stddev.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline request_interval_stddev is not finite: {}",
                self.request_interval_stddev
            ));
        }
        if self.request_interval_stddev < 0.0 {
            return Err(format!(
                "NhiBehavioralBaseline request_interval_stddev must be >= 0.0, got {}",
                self.request_interval_stddev
            ));
        }
        if !self.typical_session_duration_secs.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline typical_session_duration_secs is not finite: {}",
                self.typical_session_duration_secs
            ));
        }
        if self.typical_session_duration_secs < 0.0 {
            return Err(format!(
                "NhiBehavioralBaseline typical_session_duration_secs must be >= 0.0, got {}",
                self.typical_session_duration_secs
            ));
        }
        if !self.confidence.is_finite() {
            return Err(format!(
                "NhiBehavioralBaseline confidence is not finite: {}",
                self.confidence
            ));
        }
        // SECURITY (FIND-R51-001): Validate confidence is in documented [0.0, 1.0] range.
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(format!(
                "NhiBehavioralBaseline confidence must be in [0.0, 1.0], got {}",
                self.confidence
            ));
        }
        Ok(())
    }

    /// Deprecated alias for [`NhiBehavioralBaseline::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
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
#[serde(deny_unknown_fields)]
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
    /// Validate structural invariants: finite scores, range checks, deviation bounds.
    ///
    /// SECURITY (FIND-P2-007): Non-finite anomaly_score could bypass
    /// threshold comparisons that determine whether to allow or block.
    pub fn validate(&self) -> Result<(), String> {
        if !self.anomaly_score.is_finite() {
            return Err(format!(
                "NhiBehavioralCheckResult has non-finite anomaly_score: {}",
                self.anomaly_score
            ));
        }
        // SECURITY (FIND-R51-001): Validate anomaly_score is in documented [0.0, 1.0] range.
        if self.anomaly_score < 0.0 || self.anomaly_score > 1.0 {
            return Err(format!(
                "NhiBehavioralCheckResult anomaly_score must be in [0.0, 1.0], got {}",
                self.anomaly_score
            ));
        }
        // SECURITY (FIND-R52-002): Bound deviations collection size.
        const MAX_DEVIATIONS: usize = 256;
        if self.deviations.len() > MAX_DEVIATIONS {
            return Err(format!(
                "NhiBehavioralCheckResult deviations count {} exceeds max {}",
                self.deviations.len(),
                MAX_DEVIATIONS,
            ));
        }
        for dev in &self.deviations {
            if !dev.severity.is_finite() || dev.severity < 0.0 || dev.severity > 1.0 {
                return Err(format!(
                    "NhiBehavioralDeviation '{}' severity must be in [0.0, 1.0], got {}",
                    dev.deviation_type, dev.severity
                ));
            }
        }
        Ok(())
    }

    /// Deprecated alias for [`NhiBehavioralCheckResult::validate()`].
    #[deprecated(since = "4.0.1", note = "renamed to validate()")]
    pub fn validate_finite(&self) -> Result<(), String> {
        self.validate()
    }
}

/// A specific behavioral deviation from the established baseline.
///
/// Describes a single anomalous observation relative to an agent's
/// [`NhiBehavioralBaseline`]. Multiple deviations may be reported
/// in a single [`NhiBehavioralCheckResult`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NhiBehavioralDeviation {
    /// Category of deviation (e.g., `"request_interval"`, `"tool_frequency"`,
    /// `"source_ip"`, `"active_hours"`).
    pub deviation_type: String,
    /// The actual value observed during the current request/session
    /// (e.g., `"1200ms"`, `"10.0.0.1"`, `"23"`).
    pub observed: String,
    /// The expected value or range from the baseline
    /// (e.g., `"300-500ms"`, `"192.168.1.0/24"`, `"9-17"`).
    pub expected: String,
    /// How severe this deviation is, from 0.0 (negligible) to 1.0 (extreme).
    /// Validated to be in `[0.0, 1.0]` by [`NhiBehavioralCheckResult::validate()`].
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
#[serde(deny_unknown_fields)]
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
        // SECURITY (FIND-R114-015): Reject control/format characters in from_agent
        // and to_agent BEFORE self-delegation check, preventing Unicode format char
        // bypass (e.g., "admin" vs "admin\u{200B}").
        if self
            .from_agent
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "NhiDelegationLink from_agent contains control or Unicode format characters"
                    .to_string(),
            );
        }
        if self
            .to_agent
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err(
                "NhiDelegationLink to_agent contains control or Unicode format characters"
                    .to_string(),
            );
        }
        // SECURITY (FIND-R51-009): Reject self-delegation to prevent
        // privilege escalation loops. Case-insensitive comparison.
        if self.from_agent.eq_ignore_ascii_case(&self.to_agent) {
            return Err("self-delegation is not allowed".to_string());
        }
        // SECURITY (FIND-R51-012): Validate temporal ordering.
        // For ISO 8601 timestamps, lexicographic comparison preserves chronological order.
        // Only check when both fields are non-empty (empty fields caught elsewhere).
        if !self.created_at.is_empty()
            && !self.expires_at.is_empty()
            && self.expires_at <= self.created_at
        {
            return Err(format!(
                "NhiDelegationLink expires_at '{}' must be after created_at '{}'",
                self.expires_at, self.created_at,
            ));
        }
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
#[serde(deny_unknown_fields)]
pub struct NhiDelegationChain {
    /// Ordered list of delegation links from origin to current agent.
    pub chain: Vec<NhiDelegationLink>,
    /// Maximum allowed chain depth.
    pub max_depth: usize,
    /// ISO 8601 timestamp when this chain was resolved.
    pub resolved_at: String,
}

impl NhiDelegationChain {
    pub const MAX_DELEGATION_DEPTH: usize = 20;

    /// Returns the current depth of the chain.
    pub fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Returns true if the chain exceeds the maximum allowed depth.
    pub fn exceeds_max_depth(&self) -> bool {
        let effective_max = self.max_depth.min(Self::MAX_DELEGATION_DEPTH);
        self.chain.len() > effective_max
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.max_depth > Self::MAX_DELEGATION_DEPTH {
            return Err(format!(
                "NhiDelegationChain max_depth {} exceeds maximum allowed {} (capped internally)",
                self.max_depth,
                Self::MAX_DELEGATION_DEPTH
            ));
        }
        for link in &self.chain {
            link.validate()?;
        }
        Ok(())
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
///
/// SECURITY (IMP-R104-004): Custom Debug impl redacts `proof` JWT and `ath` hash.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl std::fmt::Debug for NhiDpopProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NhiDpopProof")
            .field("proof", &"[REDACTED]")
            .field("htm", &self.htm)
            .field("htu", &self.htu)
            .field("ath", &self.ath.as_ref().map(|_| "[REDACTED]"))
            .field("nonce", &self.nonce)
            .field("iat", &self.iat)
            .field("jti", &self.jti)
            .finish()
    }
}

impl NhiDpopProof {
    /// Maximum length for the `proof` JWT field.
    const MAX_PROOF_LEN: usize = 16_384;
    /// Maximum length for `htm`, `htu`, `ath`, `nonce`, `iat`, and `jti` fields.
    const MAX_FIELD_LEN: usize = 1024;

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (FIND-R71-002): Prevents memory exhaustion via oversized DPoP proofs.
    pub fn validate(&self) -> Result<(), String> {
        if self.proof.len() > Self::MAX_PROOF_LEN {
            return Err(format!(
                "NhiDpopProof proof length {} exceeds max {}",
                self.proof.len(),
                Self::MAX_PROOF_LEN,
            ));
        }
        if self.htm.len() > Self::MAX_FIELD_LEN {
            return Err(format!(
                "NhiDpopProof htm length {} exceeds max {}",
                self.htm.len(),
                Self::MAX_FIELD_LEN,
            ));
        }
        // SECURITY (FIND-R104-005): Reject Unicode format characters in htm/htu/iat/jti
        // to prevent bidi-override and zero-width character injection.
        if self
            .htm
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err("NhiDpopProof htm contains control or format characters".to_string());
        }
        if self.htu.len() > Self::MAX_FIELD_LEN {
            return Err(format!(
                "NhiDpopProof htu length {} exceeds max {}",
                self.htu.len(),
                Self::MAX_FIELD_LEN,
            ));
        }
        if self
            .htu
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err("NhiDpopProof htu contains control or format characters".to_string());
        }
        if let Some(ref ath) = self.ath {
            if ath.len() > Self::MAX_FIELD_LEN {
                return Err(format!(
                    "NhiDpopProof ath length {} exceeds max {}",
                    ath.len(),
                    Self::MAX_FIELD_LEN,
                ));
            }
            // SECURITY (FIND-R112-008): Reject control and format characters in ath.
            if ath.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err("NhiDpopProof ath contains control or format characters".to_string());
            }
        }
        if let Some(ref nonce) = self.nonce {
            if nonce.len() > Self::MAX_FIELD_LEN {
                return Err(format!(
                    "NhiDpopProof nonce length {} exceeds max {}",
                    nonce.len(),
                    Self::MAX_FIELD_LEN,
                ));
            }
            // SECURITY (FIND-R112-008): Reject control and format characters in nonce.
            if nonce.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err("NhiDpopProof nonce contains control or format characters".to_string());
            }
        }
        if self.iat.len() > Self::MAX_FIELD_LEN {
            return Err(format!(
                "NhiDpopProof iat length {} exceeds max {}",
                self.iat.len(),
                Self::MAX_FIELD_LEN,
            ));
        }
        if self
            .iat
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err("NhiDpopProof iat contains control or format characters".to_string());
        }
        if self.jti.len() > Self::MAX_FIELD_LEN {
            return Err(format!(
                "NhiDpopProof jti length {} exceeds max {}",
                self.jti.len(),
                Self::MAX_FIELD_LEN,
            ));
        }
        if self
            .jti
            .chars()
            .any(|c| c.is_control() || crate::core::is_unicode_format_char(c))
        {
            return Err("NhiDpopProof jti contains control or format characters".to_string());
        }
        Ok(())
    }
}

/// Result of DPoP proof verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl NhiDpopVerificationResult {
    /// Maximum length for thumbprint strings.
    const MAX_THUMBPRINT_LEN: usize = 512;
    /// Maximum length for error messages.
    const MAX_ERROR_LEN: usize = 1024;
    /// Maximum length for nonce strings.
    const MAX_NONCE_LEN: usize = 256;

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (IMP-R122-011): Unbounded thumbprint/error/nonce fields from
    /// external input could cause memory exhaustion or log injection.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref t) = self.thumbprint {
            if t.len() > Self::MAX_THUMBPRINT_LEN {
                return Err(format!(
                    "NhiDpopVerificationResult thumbprint length {} exceeds max {}",
                    t.len(),
                    Self::MAX_THUMBPRINT_LEN
                ));
            }
            if crate::core::has_dangerous_chars(t) {
                return Err(
                    "NhiDpopVerificationResult thumbprint contains control or format characters"
                        .to_string(),
                );
            }
        }
        if let Some(ref e) = self.error {
            if e.len() > Self::MAX_ERROR_LEN {
                return Err(format!(
                    "NhiDpopVerificationResult error length {} exceeds max {}",
                    e.len(),
                    Self::MAX_ERROR_LEN
                ));
            }
            if crate::core::has_dangerous_chars(e) {
                return Err(
                    "NhiDpopVerificationResult error contains control or format characters"
                        .to_string(),
                );
            }
        }
        if let Some(ref n) = self.new_nonce {
            if n.len() > Self::MAX_NONCE_LEN {
                return Err(format!(
                    "NhiDpopVerificationResult new_nonce length {} exceeds max {}",
                    n.len(),
                    Self::MAX_NONCE_LEN
                ));
            }
            if crate::core::has_dangerous_chars(n) {
                return Err(
                    "NhiDpopVerificationResult new_nonce contains control or format characters"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// Statistics for NHI lifecycle management.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl NhiStats {
    /// Validate structural invariants.
    ///
    /// Currently a no-op since all fields are bounded integer types,
    /// but provided for forward-compatibility with future string fields.
    pub fn validate(&self) -> Result<(), String> {
        // All fields are u64 — no string bounds to check.
        // total_identities should be >= sum of sub-counts, but this is
        // a consistency check rather than a security bound, so we only
        // enforce it as a warning-level audit finding, not a hard reject.
        Ok(())
    }
}

/// Credential rotation event for audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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

impl NhiCredentialRotation {
    /// Maximum length for `agent_id`.
    const MAX_AGENT_ID_LEN: usize = 256;
    /// Maximum length for thumbprint strings.
    const MAX_THUMBPRINT_LEN: usize = 512;
    /// Maximum length for ISO 8601 timestamp strings.
    const MAX_TIMESTAMP_LEN: usize = 64;
    /// Maximum length for `trigger`.
    const MAX_TRIGGER_LEN: usize = 128;

    /// Validate structural bounds on string fields.
    ///
    /// SECURITY (FIND-R112-009): Control and Unicode format character validation on all string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.agent_id.len() > Self::MAX_AGENT_ID_LEN {
            return Err(format!(
                "NhiCredentialRotation agent_id length {} exceeds max {}",
                self.agent_id.len(),
                Self::MAX_AGENT_ID_LEN,
            ));
        }
        if self.agent_id.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiCredentialRotation agent_id contains control or format characters".to_string());
        }

        if let Some(ref pt) = self.previous_thumbprint {
            if pt.len() > Self::MAX_THUMBPRINT_LEN {
                return Err(format!(
                    "NhiCredentialRotation previous_thumbprint length {} exceeds max {}",
                    pt.len(),
                    Self::MAX_THUMBPRINT_LEN,
                ));
            }
            if pt.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
                return Err("NhiCredentialRotation previous_thumbprint contains control or format characters".to_string());
            }
        }

        if self.new_thumbprint.len() > Self::MAX_THUMBPRINT_LEN {
            return Err(format!(
                "NhiCredentialRotation new_thumbprint length {} exceeds max {}",
                self.new_thumbprint.len(),
                Self::MAX_THUMBPRINT_LEN,
            ));
        }
        if self.new_thumbprint.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiCredentialRotation new_thumbprint contains control or format characters".to_string());
        }

        if self.rotated_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "NhiCredentialRotation rotated_at length {} exceeds max {}",
                self.rotated_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if self.rotated_at.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiCredentialRotation rotated_at contains control or format characters".to_string());
        }

        if self.trigger.len() > Self::MAX_TRIGGER_LEN {
            return Err(format!(
                "NhiCredentialRotation trigger length {} exceeds max {}",
                self.trigger.len(),
                Self::MAX_TRIGGER_LEN,
            ));
        }
        if self.trigger.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiCredentialRotation trigger contains control or format characters".to_string());
        }

        if self.new_expires_at.len() > Self::MAX_TIMESTAMP_LEN {
            return Err(format!(
                "NhiCredentialRotation new_expires_at length {} exceeds max {}",
                self.new_expires_at.len(),
                Self::MAX_TIMESTAMP_LEN,
            ));
        }
        if self.new_expires_at.chars().any(|c| c.is_control() || crate::core::is_unicode_format_char(c)) {
            return Err("NhiCredentialRotation new_expires_at contains control or format characters".to_string());
        }

        Ok(())
    }
}
