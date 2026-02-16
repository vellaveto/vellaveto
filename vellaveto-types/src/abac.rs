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
    pub usage_ratio: f64,
    /// Recommended action based on usage ratio.
    pub recommendation: AgencyRecommendation,
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
