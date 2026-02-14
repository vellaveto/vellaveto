//! ABAC (Attribute-Based Access Control) configuration.
//!
//! Defines the configuration structure for Cedar-style ABAC policies,
//! entity stores, least-agency enforcement, identity federation, and
//! continuous authorization.

use sentinel_types::{AbacEntity, AbacPolicy, FederationTrustAnchor};
use serde::{Deserialize, Serialize};

/// Maximum number of ABAC policies allowed in config.
pub const MAX_ABAC_POLICIES: usize = 512;

/// Maximum number of entities allowed in the ABAC entity store.
pub const MAX_ENTITIES: usize = 4096;

/// Maximum number of conditions per ABAC policy.
pub const MAX_CONDITIONS_PER_POLICY: usize = 16;

/// Maximum number of patterns per constraint (principal/action/resource).
pub const MAX_PATTERNS_PER_CONSTRAINT: usize = 32;

/// Maximum number of federation trust anchors.
pub const MAX_TRUST_ANCHORS: usize = 64;

fn default_unused_alert_after_secs() -> u64 {
    300
}

fn default_narrow_threshold() -> f64 {
    0.5
}

fn default_risk_threshold() -> f64 {
    0.7
}

fn default_degradation_threshold() -> f64 {
    0.5
}

fn default_reevaluation_interval_secs() -> u64 {
    60
}

/// Top-level ABAC configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AbacConfig {
    /// When false (default), ABAC evaluation is skipped entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Cedar-style ABAC policies.
    #[serde(default)]
    pub policies: Vec<AbacPolicy>,
    /// Entity store for principal/resource attributes and group membership.
    #[serde(default)]
    pub entities: Vec<AbacEntity>,
    /// Least-agency enforcement configuration.
    #[serde(default)]
    pub least_agency: LeastAgencyConfig,
    /// Identity federation configuration.
    #[serde(default)]
    pub federation: FederationConfig,
    /// Continuous authorization configuration.
    #[serde(default)]
    pub continuous_auth: ContinuousAuthConfig,
}

/// Least-agency enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LeastAgencyConfig {
    /// When false (default), least-agency tracking is disabled.
    #[serde(default)]
    pub enabled: bool,
    /// Seconds after which unused permissions trigger an alert.
    #[serde(default = "default_unused_alert_after_secs")]
    pub unused_alert_after_secs: u64,
    /// Usage ratio below which narrowing is recommended.
    #[serde(default = "default_narrow_threshold")]
    pub narrow_threshold: f64,
}

impl Default for LeastAgencyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unused_alert_after_secs: default_unused_alert_after_secs(),
            narrow_threshold: default_narrow_threshold(),
        }
    }
}

/// Identity federation configuration for cross-org identity mapping.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FederationConfig {
    /// When false (default), federation is disabled.
    #[serde(default)]
    pub enabled: bool,
    /// Trust anchors for federated identity providers.
    #[serde(default)]
    pub trust_anchors: Vec<FederationTrustAnchor>,
}

/// Continuous authorization configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContinuousAuthConfig {
    /// When false (default), continuous authorization is disabled.
    #[serde(default)]
    pub enabled: bool,
    /// Risk score threshold above which requests are denied (0.0–1.0).
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: f64,
    /// Risk score threshold above which requests trigger degraded mode (0.0–1.0).
    #[serde(default = "default_degradation_threshold")]
    pub degradation_threshold: f64,
    /// Interval in seconds between risk score re-evaluations.
    #[serde(default = "default_reevaluation_interval_secs")]
    pub reevaluation_interval_secs: u64,
}

impl Default for ContinuousAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            risk_threshold: default_risk_threshold(),
            degradation_threshold: default_degradation_threshold(),
            reevaluation_interval_secs: default_reevaluation_interval_secs(),
        }
    }
}

impl AbacConfig {
    /// Validate the ABAC configuration. Returns an error describing the first
    /// violation found.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        // Policy count bounds
        if self.policies.len() > MAX_ABAC_POLICIES {
            return Err(format!(
                "abac.policies has {} entries, max is {}",
                self.policies.len(),
                MAX_ABAC_POLICIES
            ));
        }

        // Entity count bounds
        if self.entities.len() > MAX_ENTITIES {
            return Err(format!(
                "abac.entities has {} entries, max is {}",
                self.entities.len(),
                MAX_ENTITIES
            ));
        }

        // Validate each policy
        let mut seen_ids = std::collections::HashSet::new();
        for (i, policy) in self.policies.iter().enumerate() {
            if policy.id.is_empty() {
                return Err(format!("abac.policies[{}].id must not be empty", i));
            }
            if policy.description.is_empty() {
                return Err(format!(
                    "abac.policies[{}].description must not be empty",
                    i
                ));
            }
            if !seen_ids.insert(&policy.id) {
                return Err(format!("abac.policies has duplicate id '{}'", policy.id));
            }
            if policy.conditions.len() > MAX_CONDITIONS_PER_POLICY {
                return Err(format!(
                    "abac.policies[{}] has {} conditions, max is {}",
                    i,
                    policy.conditions.len(),
                    MAX_CONDITIONS_PER_POLICY
                ));
            }
            if policy.principal.id_patterns.len() > MAX_PATTERNS_PER_CONSTRAINT {
                return Err(format!(
                    "abac.policies[{}].principal.id_patterns has {} entries, max is {}",
                    i,
                    policy.principal.id_patterns.len(),
                    MAX_PATTERNS_PER_CONSTRAINT
                ));
            }
            if policy.action.patterns.len() > MAX_PATTERNS_PER_CONSTRAINT {
                return Err(format!(
                    "abac.policies[{}].action.patterns has {} entries, max is {}",
                    i,
                    policy.action.patterns.len(),
                    MAX_PATTERNS_PER_CONSTRAINT
                ));
            }
            if policy.resource.path_patterns.len() > MAX_PATTERNS_PER_CONSTRAINT {
                return Err(format!(
                    "abac.policies[{}].resource.path_patterns has {} entries, max is {}",
                    i,
                    policy.resource.path_patterns.len(),
                    MAX_PATTERNS_PER_CONSTRAINT
                ));
            }
            if policy.resource.domain_patterns.len() > MAX_PATTERNS_PER_CONSTRAINT {
                return Err(format!(
                    "abac.policies[{}].resource.domain_patterns has {} entries, max is {}",
                    i,
                    policy.resource.domain_patterns.len(),
                    MAX_PATTERNS_PER_CONSTRAINT
                ));
            }
        }

        // Validate entity uniqueness
        let mut seen_entity_keys = std::collections::HashSet::new();
        for (i, entity) in self.entities.iter().enumerate() {
            let key = format!("{}::{}", entity.entity_type, entity.id);
            if !seen_entity_keys.insert(key.clone()) {
                return Err(format!(
                    "abac.entities has duplicate key '{}' at index {}",
                    key, i
                ));
            }
        }

        // Validate continuous auth thresholds
        if self.continuous_auth.enabled {
            if !self.continuous_auth.risk_threshold.is_finite()
                || self.continuous_auth.risk_threshold < 0.0
                || self.continuous_auth.risk_threshold > 1.0
            {
                return Err(format!(
                    "abac.continuous_auth.risk_threshold must be in [0.0, 1.0], got {}",
                    self.continuous_auth.risk_threshold
                ));
            }
            if !self.continuous_auth.degradation_threshold.is_finite()
                || self.continuous_auth.degradation_threshold < 0.0
                || self.continuous_auth.degradation_threshold > 1.0
            {
                return Err(format!(
                    "abac.continuous_auth.degradation_threshold must be in [0.0, 1.0], got {}",
                    self.continuous_auth.degradation_threshold
                ));
            }
        }

        // Validate least-agency threshold
        if self.least_agency.enabled
            && (!self.least_agency.narrow_threshold.is_finite()
                || self.least_agency.narrow_threshold < 0.0
                || self.least_agency.narrow_threshold > 1.0)
        {
            return Err(format!(
                "abac.least_agency.narrow_threshold must be in [0.0, 1.0], got {}",
                self.least_agency.narrow_threshold
            ));
        }

        // Validate federation trust anchors
        if self.federation.enabled {
            if self.federation.trust_anchors.len() > MAX_TRUST_ANCHORS {
                return Err(format!(
                    "abac.federation.trust_anchors has {} entries, max is {}",
                    self.federation.trust_anchors.len(),
                    MAX_TRUST_ANCHORS
                ));
            }
            for (i, anchor) in self.federation.trust_anchors.iter().enumerate() {
                if anchor.org_id.is_empty() {
                    return Err(format!(
                        "abac.federation.trust_anchors[{}].org_id must not be empty",
                        i
                    ));
                }
                if anchor.issuer_pattern.is_empty() {
                    return Err(format!(
                        "abac.federation.trust_anchors[{}].issuer_pattern must not be empty",
                        i
                    ));
                }
            }
        }

        Ok(())
    }
}
