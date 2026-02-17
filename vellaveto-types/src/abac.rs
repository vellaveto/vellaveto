//! ABAC (Attribute-Based Access Control) types — Cedar-style policies,
//! entity store, risk scores, federation, and least-agency tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// ABAC POLICY TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// ABAC policy effect — Cedar-style permit/forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AbacEffect {
    Permit,
    Forbid,
}

/// Principal constraint — who is performing the action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PrincipalConstraint {
    /// Principal type (e.g., "Agent", "Service", "User"). None = any.
    #[serde(default)]
    pub principal_type: Option<String>,
    /// Glob patterns for principal ID (e.g., "code-agent", "team-*").
    #[serde(default)]
    pub id_patterns: Vec<String>,
    /// Required JWT claims (key → glob value pattern).
    #[serde(default)]
    pub claims: HashMap<String, String>,
}

/// Action constraint — what operation is being performed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ActionConstraint {
    /// Tool:function patterns the action must match (e.g., ["filesystem:read_*"]).
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Resource constraint — what is being acted upon.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceConstraint {
    /// Path glob patterns the resource must match.
    #[serde(default)]
    pub path_patterns: Vec<String>,
    /// Domain patterns the resource must match.
    #[serde(default)]
    pub domain_patterns: Vec<String>,
    /// Required resource tags (all must be present).
    #[serde(default)]
    pub tags: Vec<String>,
}

/// ABAC condition — additional constraints on the evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbacCondition {
    /// Field path to evaluate (e.g., "context.verified", "principal.team").
    pub field: String,
    /// Comparison operator.
    pub op: AbacOp,
    /// Value to compare against.
    pub value: serde_json::Value,
}

impl AbacCondition {
    /// Maximum serialized size of `value` in bytes.
    pub const MAX_VALUE_SIZE: usize = 8192;

    pub fn validate(&self) -> Result<(), String> {
        let size = serde_json::to_string(&self.value)
            .map_err(|e| format!("AbacCondition value serialization failed: {e}"))?
            .len();
        if size > Self::MAX_VALUE_SIZE {
            return Err(format!(
                "AbacCondition field '{}' value serialized size {} exceeds max {}",
                self.field,
                size,
                Self::MAX_VALUE_SIZE
            ));
        }
        Ok(())
    }
}

/// ABAC comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbacOp {
    Eq,
    Ne,
    In,
    NotIn,
    Contains,
    StartsWith,
    Gt,
    Lt,
    Gte,
    Lte,
}

/// A Cedar-style ABAC policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbacPolicy {
    pub id: String,
    pub description: String,
    pub effect: AbacEffect,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub principal: PrincipalConstraint,
    #[serde(default)]
    pub action: ActionConstraint,
    #[serde(default)]
    pub resource: ResourceConstraint,
    #[serde(default)]
    pub conditions: Vec<AbacCondition>,
}

impl AbacPolicy {
    /// Maximum number of conditions per policy.
    pub const MAX_CONDITIONS: usize = 256;

    /// SECURITY (FIND-R49-005): Validate AbacPolicy bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.conditions.len() > Self::MAX_CONDITIONS {
            return Err(format!(
                "AbacPolicy conditions count {} exceeds max {}",
                self.conditions.len(),
                Self::MAX_CONDITIONS
            ));
        }
        for (i, cond) in self.conditions.iter().enumerate() {
            cond.validate()
                .map_err(|e| format!("conditions[{}]: {}", i, e))?;
        }
        self.principal.validate()?;
        self.action.validate()?;
        self.resource.validate()?;
        Ok(())
    }
}

impl PrincipalConstraint {
    /// Maximum number of ID patterns per principal constraint.
    pub const MAX_ID_PATTERNS: usize = 64;
    /// Maximum number of required claims per principal constraint.
    pub const MAX_CLAIMS: usize = 64;

    /// SECURITY (FIND-R49-005): Validate PrincipalConstraint bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.id_patterns.len() > Self::MAX_ID_PATTERNS {
            return Err(format!(
                "PrincipalConstraint id_patterns count {} exceeds max {}",
                self.id_patterns.len(),
                Self::MAX_ID_PATTERNS
            ));
        }
        if self.claims.len() > Self::MAX_CLAIMS {
            return Err(format!(
                "PrincipalConstraint claims count {} exceeds max {}",
                self.claims.len(),
                Self::MAX_CLAIMS
            ));
        }
        Ok(())
    }
}

impl ActionConstraint {
    /// Maximum number of patterns per action constraint.
    pub const MAX_PATTERNS: usize = 256;

    /// SECURITY (FIND-R49-005): Validate ActionConstraint bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.patterns.len() > Self::MAX_PATTERNS {
            return Err(format!(
                "ActionConstraint patterns count {} exceeds max {}",
                self.patterns.len(),
                Self::MAX_PATTERNS
            ));
        }
        Ok(())
    }
}

impl ResourceConstraint {
    /// Maximum number of path patterns per resource constraint.
    pub const MAX_PATH_PATTERNS: usize = 256;
    /// Maximum number of domain patterns per resource constraint.
    pub const MAX_DOMAIN_PATTERNS: usize = 256;
    /// Maximum number of tags per resource constraint.
    pub const MAX_TAGS: usize = 64;

    /// SECURITY (FIND-R49-005): Validate ResourceConstraint bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.path_patterns.len() > Self::MAX_PATH_PATTERNS {
            return Err(format!(
                "ResourceConstraint path_patterns count {} exceeds max {}",
                self.path_patterns.len(),
                Self::MAX_PATH_PATTERNS
            ));
        }
        if self.domain_patterns.len() > Self::MAX_DOMAIN_PATTERNS {
            return Err(format!(
                "ResourceConstraint domain_patterns count {} exceeds max {}",
                self.domain_patterns.len(),
                Self::MAX_DOMAIN_PATTERNS
            ));
        }
        if self.tags.len() > Self::MAX_TAGS {
            return Err(format!(
                "ResourceConstraint tags count {} exceeds max {}",
                self.tags.len(),
                Self::MAX_TAGS
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTITY STORE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Entity in the ABAC entity store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbacEntity {
    /// Entity type (e.g., "Agent", "Service", "Resource", "Group").
    pub entity_type: String,
    /// Unique entity identifier.
    pub id: String,
    /// Arbitrary attributes for condition evaluation.
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
    /// Parent entity IDs (for group membership: Agent in Group).
    #[serde(default)]
    pub parents: Vec<String>,
}

impl AbacEntity {
    /// Maximum parents per entity.
    pub const MAX_PARENTS: usize = 256;
    /// Maximum attributes per entity.
    pub const MAX_ATTRIBUTES: usize = 256;

    /// Validate bounds on deserialized data.
    ///
    /// SECURITY (FIND-R48-004): Unbounded parents and attributes from deserialization.
    pub fn validate(&self) -> Result<(), String> {
        if self.parents.len() > Self::MAX_PARENTS {
            return Err(format!(
                "AbacEntity '{}::{}' has {} parents (max {})",
                self.entity_type,
                self.id,
                self.parents.len(),
                Self::MAX_PARENTS
            ));
        }
        if self.attributes.len() > Self::MAX_ATTRIBUTES {
            return Err(format!(
                "AbacEntity '{}::{}' has {} attributes (max {})",
                self.entity_type,
                self.id,
                self.attributes.len(),
                Self::MAX_ATTRIBUTES
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTINUOUS AUTHORIZATION (21.4)
// ═══════════════════════════════════════════════════════════════════════════════

/// Risk score for continuous authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskScore {
    /// Risk score from 0.0 (safe) to 1.0 (critical).
    pub score: f64,
    /// Contributing risk factors.
    #[serde(default)]
    pub factors: Vec<RiskFactor>,
    /// ISO 8601 timestamp of last update.
    pub updated_at: String,
}

/// A single contributing factor to the overall risk score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskFactor {
    /// Factor name (e.g., "anomaly_score", "threat_intel", "failed_auth").
    pub name: String,
    /// Weight of this factor in the composite score.
    pub weight: f64,
    /// Current value of this factor.
    pub value: f64,
}

impl RiskScore {
    /// Validate that all f64 fields are finite (not NaN or Infinity).
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.score.is_finite() {
            return Err(format!("RiskScore::score is not finite: {}", self.score));
        }
        for factor in &self.factors {
            factor.validate_finite()?;
        }
        Ok(())
    }
}

impl RiskFactor {
    /// Validate that all f64 fields are finite (not NaN or Infinity).
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.weight.is_finite() {
            return Err(format!(
                "RiskFactor '{}' weight is not finite: {}",
                self.name, self.weight
            ));
        }
        if !self.value.is_finite() {
            return Err(format!(
                "RiskFactor '{}' value is not finite: {}",
                self.name, self.value
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY FEDERATION (21.3)
// ═══════════════════════════════════════════════════════════════════════════════

/// Federation trust anchor for cross-org identity mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationTrustAnchor {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name for the trust anchor.
    pub display_name: String,
    /// Optional JWKS URI for verifying federated tokens.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Glob pattern for trusted JWT issuers.
    pub issuer_pattern: String,
    /// Identity claim-to-principal mappings.
    #[serde(default)]
    pub identity_mappings: Vec<IdentityMapping>,
    /// Trust level for this federated organization.
    /// Injected as `federation.trust_level` claim in mapped identity.
    /// ABAC policies can condition on this value.
    /// Valid values: "full", "limited", "read_only".
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
}

fn default_trust_level() -> String {
    "limited".to_string()
}

/// Allowed trust level values for federation trust anchors.
const VALID_TRUST_LEVELS: &[&str] = &["full", "limited", "read_only"];

impl FederationTrustAnchor {
    /// Maximum number of identity mappings per trust anchor.
    pub const MAX_IDENTITY_MAPPINGS: usize = 64;

    /// Maximum length for issuer_pattern.
    pub const MAX_ISSUER_PATTERN_LEN: usize = 2048;

    /// Validate the trust anchor configuration.
    ///
    /// Checks: org_id non-empty, issuer_pattern non-empty and bounded,
    /// issuer_pattern not bare wildcard, jwks_uri scheme and SSRF safety,
    /// trust_level enum, identity_mappings bounds and individual validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.org_id.is_empty() {
            return Err("FederationTrustAnchor org_id must not be empty".to_string());
        }
        if self.org_id.chars().any(|c| c.is_control()) {
            return Err(format!(
                "FederationTrustAnchor '{}' org_id contains control characters",
                self.org_id
            ));
        }
        if self.issuer_pattern.is_empty() {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern must not be empty",
                self.org_id
            ));
        }
        // SECURITY (FIND-R50-009): Bound issuer_pattern length.
        if self.issuer_pattern.len() > Self::MAX_ISSUER_PATTERN_LEN {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern length {} exceeds max {}",
                self.org_id,
                self.issuer_pattern.len(),
                Self::MAX_ISSUER_PATTERN_LEN
            ));
        }
        // SECURITY (FIND-R50-009): Reject bare `*` wildcard — it would match
        // any issuer, which is almost certainly a misconfiguration.
        if self.issuer_pattern.trim() == "*" {
            return Err(format!(
                "FederationTrustAnchor '{}' issuer_pattern must not be a bare '*' wildcard",
                self.org_id
            ));
        }
        if let Some(ref uri) = self.jwks_uri {
            // SECURITY (FIND-R50-010): Require https:// scheme for JWKS URIs
            // in production. http:// is only allowed for testing.
            if !uri.starts_with("https://") && !uri.starts_with("http://") {
                return Err(format!(
                    "FederationTrustAnchor '{}' jwks_uri must use http(s) scheme, got: {}",
                    self.org_id, uri
                ));
            }
            // SECURITY (FIND-R50-010): Validate jwks_uri against SSRF —
            // reject localhost, loopback, link-local, and private IP ranges.
            Self::validate_jwks_uri_ssrf(uri)
                .map_err(|e| format!("FederationTrustAnchor '{}' jwks_uri {}", self.org_id, e))?;
        }
        if !VALID_TRUST_LEVELS.contains(&self.trust_level.as_str()) {
            return Err(format!(
                "FederationTrustAnchor '{}' trust_level must be one of {:?}, got: {}",
                self.org_id, VALID_TRUST_LEVELS, self.trust_level
            ));
        }
        if self.identity_mappings.len() > Self::MAX_IDENTITY_MAPPINGS {
            return Err(format!(
                "FederationTrustAnchor '{}' identity_mappings count {} exceeds max {}",
                self.org_id,
                self.identity_mappings.len(),
                Self::MAX_IDENTITY_MAPPINGS
            ));
        }
        for (i, mapping) in self.identity_mappings.iter().enumerate() {
            mapping.validate().map_err(|e| {
                format!(
                    "FederationTrustAnchor '{}' identity_mappings[{}]: {}",
                    self.org_id, i, e
                )
            })?;
        }
        Ok(())
    }

    /// SECURITY (FIND-R50-010): Validate a JWKS URI against SSRF vectors.
    ///
    /// Rejects localhost, loopback, link-local, and private IP ranges in the
    /// host portion of the URI. Follows the same pattern as
    /// `validate_agent_card_base_url` in vellaveto-mcp.
    fn validate_jwks_uri_ssrf(uri: &str) -> Result<(), String> {
        // Extract the scheme-relative portion
        let after_scheme = if let Some(rest) = uri.strip_prefix("https://") {
            rest
        } else if let Some(rest) = uri.strip_prefix("http://") {
            rest
        } else {
            return Err("must use http(s) scheme".to_string());
        };

        // Extract authority (before first '/')
        let authority = after_scheme
            .find('/')
            .map_or(after_scheme, |i| &after_scheme[..i]);

        // Strip userinfo before '@'
        let host_portion = match authority.rfind('@') {
            Some(at) => &authority[at + 1..],
            None => authority,
        };

        // Extract host (handle IPv6 brackets and port)
        let host = if host_portion.starts_with('[') {
            if let Some(bracket_end) = host_portion.find(']') {
                host_portion[1..bracket_end].to_lowercase()
            } else {
                return Err("malformed IPv6 address (missing ']')".to_string());
            }
        } else {
            let host_end = host_portion
                .find([':', '/', '?', '#'])
                .unwrap_or(host_portion.len());
            host_portion[..host_end].to_lowercase()
        };

        if host.is_empty() {
            return Err("has no host".to_string());
        }

        // Reject localhost/loopback hostnames
        let loopbacks = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
        if loopbacks.iter().any(|lb| host == *lb) {
            return Err(format!(
                "must not target localhost/loopback, got '{}'",
                host
            ));
        }

        // Reject private IPv4 ranges
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            let is_private = ip.is_loopback()
                || ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && (ip.octets()[1] & 0xf0) == 16)
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
                || (ip.octets()[0] == 169 && ip.octets()[1] == 254)
                || ip.octets()[0] == 0;
            if is_private {
                return Err(format!(
                    "must not target private/internal IPs, got '{}'",
                    host
                ));
            }
        }

        // Reject private IPv6 ranges
        if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
            let segs = ip6.segments();
            let is_private = ip6.is_loopback()
                || ip6.is_unspecified()
                || (segs[0] & 0xfe00) == 0xfc00
                || (segs[0] & 0xffc0) == 0xfe80;
            if is_private {
                return Err(format!(
                    "must not target private/internal IPv6 ranges, got '{}'",
                    host
                ));
            }
        }

        Ok(())
    }
}

/// Maps external identity claims to an internal Vellaveto principal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityMapping {
    /// JWT claim to read (e.g., "sub", "email").
    pub external_claim: String,
    /// Internal principal type to map to.
    pub internal_principal_type: String,
    /// Template for the internal principal ID: "{org_id}:{claim_value}".
    pub id_template: String,
}

impl IdentityMapping {
    /// Validate the identity mapping configuration.
    ///
    /// Checks: external_claim non-empty, id_template contains `{claim_value}`,
    /// no control characters in any field.
    pub fn validate(&self) -> Result<(), String> {
        if self.external_claim.is_empty() {
            return Err("external_claim must not be empty".to_string());
        }
        if self.external_claim.chars().any(|c| c.is_control()) {
            return Err(format!(
                "external_claim '{}' contains control characters",
                self.external_claim
            ));
        }
        if !self.id_template.contains("{claim_value}") {
            return Err(format!(
                "id_template '{}' must contain '{{claim_value}}' placeholder",
                self.id_template
            ));
        }
        if self.id_template.chars().any(|c| c.is_control()) {
            return Err(format!(
                "id_template '{}' contains control characters",
                self.id_template
            ));
        }
        if self.internal_principal_type.is_empty() {
            return Err("internal_principal_type must not be empty".to_string());
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION STATUS TYPES (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

/// Federation status returned by GET /api/federation/status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationStatus {
    /// Whether federation is enabled.
    pub enabled: bool,
    /// Number of configured trust anchors.
    pub trust_anchor_count: usize,
    /// Per-anchor status.
    pub anchors: Vec<FederationAnchorStatus>,
}

/// Per-anchor status with JWKS cache info.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationAnchorStatus {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Issuer glob pattern.
    pub issuer_pattern: String,
    /// Trust level.
    pub trust_level: String,
    /// JWKS URI if configured.
    pub jwks_uri: Option<String>,
    /// Whether JWKS keys are currently cached.
    pub jwks_cached: bool,
    /// ISO 8601 timestamp of last JWKS fetch.
    pub jwks_last_fetched: Option<String>,
    /// Number of identity mappings.
    pub identity_mapping_count: usize,
    /// Successful validation count.
    pub successful_validations: u64,
    /// Failed validation count.
    pub failed_validations: u64,
}

/// Abbreviated anchor info for API listing (excludes JWKS keys).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FederationAnchorInfo {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Issuer glob pattern.
    pub issuer_pattern: String,
    /// Trust level.
    pub trust_level: String,
    /// Whether a JWKS URI is configured.
    pub has_jwks_uri: bool,
    /// Number of identity mappings.
    pub identity_mapping_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEAST-AGENCY TRACKING (21.2)
// ═══════════════════════════════════════════════════════════════════════════════

/// Permission usage record for least-agency tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionUsage {
    /// Tool pattern from the granting policy.
    pub tool_pattern: String,
    /// Function pattern from the granting policy.
    pub function_pattern: String,
    /// Number of times this permission has been exercised.
    pub used_count: u64,
    /// ISO 8601 timestamp of last usage.
    #[serde(default)]
    pub last_used: Option<String>,
}

/// Least-agency compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeastAgencyReport {
    /// Agent identifier.
    pub agent_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Total number of permissions granted.
    pub granted_permissions: usize,
    /// Number of permissions actually exercised.
    pub used_permissions: usize,
    /// Policy IDs that were never exercised.
    pub unused_permissions: Vec<String>,
    /// Ratio of used to granted permissions (0.0–1.0).
    ///
    /// When `granted_permissions == 0`, this is `1.0` (not `0.0`) to avoid
    /// division by zero and to indicate that no permissions were wasted — an
    /// agent with zero grants has no unused permissions, so it is trivially
    /// "optimal" from a least-agency perspective.
    pub usage_ratio: f64,
    /// Recommended action based on usage ratio.
    pub recommendation: AgencyRecommendation,
}

impl LeastAgencyReport {
    /// Validate that all f64 fields are finite (not NaN or Infinity).
    ///
    /// SECURITY (FIND-P2-007): Non-finite floats can propagate through
    /// calculations and comparisons unpredictably, potentially bypassing
    /// threshold checks (e.g., NaN < 0.5 is false, NaN > 0.5 is also false).
    pub fn validate_finite(&self) -> Result<(), String> {
        if !self.usage_ratio.is_finite() {
            return Err(format!(
                "LeastAgencyReport for agent '{}' session '{}' has non-finite usage_ratio: {}",
                self.agent_id, self.session_id, self.usage_ratio
            ));
        }
        Ok(())
    }
}

/// Recommendation for adjusting an agent's permission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgencyRecommendation {
    /// >80% usage — permissions are well-calibrated.
    Optimal,
    /// 50–80% usage — consider reviewing grants.
    ReviewGrants,
    /// 20–50% usage — scope should be narrowed.
    NarrowScope,
    /// <20% usage — severely over-permissioned.
    Critical,
}
