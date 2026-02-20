use serde::{Deserialize, Serialize};

use crate::default_true;

// ═══════════════════════════════════════════════════
// PHASE 9: MEMORY INJECTION DEFENSE (MINJA) CONFIGURATION
// ═══════════════════════════════════════════════════

/// Memory security configuration for MINJA defense (Phase 9).
///
/// Controls taint propagation, provenance tracking, trust decay, quarantine,
/// and namespace isolation for memory injection defense.
///
/// # TOML Example
///
/// ```toml
/// [memory_security]
/// enabled = true
/// taint_propagation = true
/// provenance_tracking = true
/// trust_decay_rate = 0.029
/// trust_threshold = 0.1
/// max_memory_age_hours = 168
/// quarantine_on_injection = true
/// block_quarantined = true
/// max_entries_per_session = 5000
///
/// [memory_security.namespaces]
/// enabled = true
/// default_isolation = "session"
/// require_sharing_approval = true
/// max_namespaces = 1000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityConfig {
    /// Enable memory security tracking. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enable taint label propagation to derived entries. Default: true.
    #[serde(default = "default_true")]
    pub taint_propagation: bool,

    /// Enable provenance graph tracking. Default: true.
    #[serde(default = "default_true")]
    pub provenance_tracking: bool,

    /// Trust decay rate (lambda) for exponential decay.
    /// Default: 0.029 (24-hour half-life).
    /// Formula: trust(t) = initial_trust * e^(-λ * age_hours)
    #[serde(default = "default_trust_decay_rate")]
    pub trust_decay_rate: f64,

    /// Trust threshold below which entries are flagged.
    /// Default: 0.1 (10% of initial trust).
    #[serde(default = "default_trust_threshold_mem")]
    pub trust_threshold: f64,

    /// Maximum age in hours for memory entries before eviction.
    /// Default: 168 (7 days).
    #[serde(default = "default_max_memory_age")]
    pub max_memory_age_hours: u64,

    /// Automatically quarantine entries matching injection patterns.
    /// Default: true.
    #[serde(default = "default_true")]
    pub quarantine_on_injection: bool,

    /// Block access to quarantined entries. Default: true.
    #[serde(default = "default_true")]
    pub block_quarantined: bool,

    /// Maximum memory entries per session. Default: 5000.
    #[serde(default = "default_max_entries_per_session")]
    pub max_entries_per_session: usize,

    /// Maximum provenance nodes tracked. Default: 10000.
    #[serde(default = "default_max_provenance_nodes")]
    pub max_provenance_nodes: usize,

    /// Namespace isolation configuration.
    #[serde(default)]
    pub namespaces: NamespaceConfig,

    /// Block entries that fail integrity verification. Default: true.
    #[serde(default = "default_true")]
    pub block_on_integrity_failure: bool,

    /// Compute content hashes for integrity verification. Default: true.
    #[serde(default = "default_true")]
    pub content_hashing: bool,

    /// Maximum fingerprints to track per session for memory poisoning detection.
    /// Default: 2500 (~80KB memory per session).
    #[serde(default = "default_max_fingerprints")]
    pub max_fingerprints: usize,

    /// Minimum string length to track for memory poisoning detection.
    /// Shorter strings cause too many false positives. Default: 20.
    #[serde(default = "default_min_trackable_length")]
    pub min_trackable_length: usize,
}

fn default_trust_decay_rate() -> f64 {
    0.029 // 24-hour half-life: ln(2) / 24 ≈ 0.029
}

fn default_trust_threshold_mem() -> f64 {
    0.1
}

fn default_max_memory_age() -> u64 {
    168 // 7 days
}

fn default_max_entries_per_session() -> usize {
    5000
}

fn default_max_provenance_nodes() -> usize {
    10000
}

fn default_max_fingerprints() -> usize {
    2500
}

fn default_min_trackable_length() -> usize {
    20
}

impl MemorySecurityConfig {
    /// Validate memory security configuration (FIND-R58-CFG-019).
    ///
    /// Ensures float thresholds are finite and within valid ranges.
    pub fn validate(&self) -> Result<(), String> {
        if !self.trust_decay_rate.is_finite()
            || self.trust_decay_rate <= 0.0
            || self.trust_decay_rate > 10.0
        {
            return Err(format!(
                "memory.trust_decay_rate must be in (0.0, 10.0], got {}",
                self.trust_decay_rate
            ));
        }
        if !self.trust_threshold.is_finite()
            || self.trust_threshold < 0.0
            || self.trust_threshold > 1.0
        {
            return Err(format!(
                "memory.trust_threshold must be in [0.0, 1.0], got {}",
                self.trust_threshold
            ));
        }
        // SECURITY (FIND-R71-CFG-014): Validate namespace default_isolation is
        // a recognized value. Unrecognized values could silently fail-open.
        let valid_isolations = ["session", "agent", "shared"];
        if !valid_isolations.contains(&self.namespaces.default_isolation.as_str()) {
            return Err(format!(
                "memory.namespaces.default_isolation must be one of {:?}, got '{}'",
                valid_isolations, self.namespaces.default_isolation
            ));
        }
        Ok(())
    }
}

impl Default for MemorySecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            taint_propagation: true,
            provenance_tracking: true,
            trust_decay_rate: default_trust_decay_rate(),
            trust_threshold: default_trust_threshold_mem(),
            max_memory_age_hours: default_max_memory_age(),
            quarantine_on_injection: true,
            block_quarantined: true,
            max_entries_per_session: default_max_entries_per_session(),
            max_provenance_nodes: default_max_provenance_nodes(),
            namespaces: NamespaceConfig::default(),
            block_on_integrity_failure: true,
            content_hashing: true,
            max_fingerprints: default_max_fingerprints(),
            min_trackable_length: default_min_trackable_length(),
        }
    }
}

/// Namespace isolation configuration for memory security.
///
/// Controls agent-level namespace isolation and access control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceConfig {
    /// Enable namespace isolation. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default isolation level for new namespaces.
    /// Options: "session", "agent", "shared". Default: "session".
    #[serde(default = "default_namespace_isolation")]
    pub default_isolation: String,

    /// Require approval for namespace sharing. Default: true.
    #[serde(default = "default_true")]
    pub require_sharing_approval: bool,

    /// Maximum namespaces per session. Default: 1000.
    #[serde(default = "default_max_namespaces")]
    pub max_namespaces: usize,

    /// Allow cross-session namespace access. Default: false.
    #[serde(default)]
    pub allow_cross_session: bool,

    /// Auto-create namespace for new agents. Default: true.
    #[serde(default = "default_true")]
    pub auto_create: bool,
}

fn default_namespace_isolation() -> String {
    "session".to_string()
}

fn default_max_namespaces() -> usize {
    1000
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_isolation: default_namespace_isolation(),
            require_sharing_approval: true,
            max_namespaces: default_max_namespaces(),
            allow_cross_session: false,
            auto_create: true,
        }
    }
}

// ═══════════════════════════════════════════════════
// PHASE 10: NHI (NON-HUMAN IDENTITY) CONFIGURATION
// ═══════════════════════════════════════════════════

/// Non-Human Identity (NHI) lifecycle management configuration.
///
/// Provides identity management for machine identities (agents, services,
/// bots) including registration, attestation, behavioral monitoring,
/// and credential lifecycle management.
///
/// # TOML Example
///
/// ```toml
/// [nhi]
/// enabled = true
/// credential_ttl_secs = 3600
/// max_credential_ttl_secs = 86400
/// require_attestation = true
/// attestation_types = ["jwt", "mtls", "spiffe", "dpop"]
/// auto_revoke_on_anomaly = true
/// anomaly_threshold = 0.3
/// baseline_learning_period_hours = 168
///
/// [nhi.dpop]
/// require_nonce = true
/// max_clock_skew_secs = 300
/// allowed_algorithms = ["ES256", "RS256"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NhiConfig {
    /// Enable NHI lifecycle management. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Default credential TTL in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_nhi_credential_ttl")]
    pub credential_ttl_secs: u64,

    /// Maximum allowed credential TTL in seconds. Default: 86400 (24 hours).
    #[serde(default = "default_nhi_max_credential_ttl")]
    pub max_credential_ttl_secs: u64,

    /// Require attestation for all agent registrations. Default: true.
    #[serde(default = "default_true")]
    pub require_attestation: bool,

    /// Allowed attestation types. Default: ["jwt", "mtls", "spiffe", "dpop", "api_key"].
    #[serde(default = "default_nhi_attestation_types")]
    pub attestation_types: Vec<String>,

    /// Automatically revoke identity on behavioral anomaly. Default: false.
    /// When true, identities with anomaly scores above threshold are suspended.
    #[serde(default)]
    pub auto_revoke_on_anomaly: bool,

    /// Anomaly threshold (0.0 - 1.0) for behavioral alerts. Default: 0.3.
    /// Scores above this trigger alerts or suspension (if auto_revoke enabled).
    #[serde(default = "default_nhi_anomaly_threshold")]
    pub anomaly_threshold: f64,

    /// Learning period for behavioral baselines in hours. Default: 168 (7 days).
    /// During this period, behavior is observed but not enforced.
    #[serde(default = "default_nhi_baseline_period")]
    pub baseline_learning_period_hours: u64,

    /// Minimum observations before baseline is active. Default: 100.
    #[serde(default = "default_nhi_min_observations")]
    pub min_baseline_observations: u64,

    /// Maximum registered identities. Default: 10000.
    #[serde(default = "default_nhi_max_identities")]
    pub max_identities: usize,

    /// Maximum active delegations. Default: 5000.
    #[serde(default = "default_nhi_max_delegations")]
    pub max_delegations: usize,

    /// Maximum delegation chain depth. Default: 5.
    #[serde(default = "default_nhi_max_chain_depth")]
    pub max_delegation_chain_depth: usize,

    /// Require explicit delegation approval. Default: true.
    #[serde(default = "default_true")]
    pub require_delegation_approval: bool,

    /// Credential rotation warning threshold in hours. Default: 24.
    /// Alerts are generated when credentials expire within this window.
    #[serde(default = "default_nhi_rotation_warning")]
    pub rotation_warning_hours: u64,

    /// Identity verification configuration.
    #[serde(default)]
    pub verification: VerificationConfig,

    /// DPoP (Demonstration of Proof-of-Possession) configuration.
    #[serde(default)]
    pub dpop: DpopConfig,

    /// SPIFFE trust domains to accept (in addition to main trust domain).
    #[serde(default)]
    pub additional_trust_domains: Vec<String>,

    /// Tags that mark identities as privileged (bypasses some checks).
    #[serde(default)]
    pub privileged_tags: Vec<String>,

    /// Enable continuous authentication scoring. Default: true.
    #[serde(default = "default_true")]
    pub continuous_auth: bool,

    /// Session timeout in seconds for behavioral tracking. Default: 3600.
    #[serde(default = "default_nhi_session_timeout")]
    pub session_timeout_secs: u64,
}

fn default_nhi_credential_ttl() -> u64 {
    3600 // 1 hour
}

fn default_nhi_max_credential_ttl() -> u64 {
    86400 // 24 hours
}

fn default_nhi_attestation_types() -> Vec<String> {
    vec![
        "jwt".to_string(),
        "mtls".to_string(),
        "spiffe".to_string(),
        "dpop".to_string(),
        "api_key".to_string(),
    ]
}

fn default_nhi_anomaly_threshold() -> f64 {
    0.3
}

fn default_nhi_baseline_period() -> u64 {
    168 // 7 days
}

fn default_nhi_min_observations() -> u64 {
    100
}

fn default_nhi_max_identities() -> usize {
    10000
}

fn default_nhi_max_delegations() -> usize {
    5000
}

fn default_nhi_max_chain_depth() -> usize {
    5
}

fn default_nhi_rotation_warning() -> u64 {
    24 // 24 hours before expiration
}

fn default_nhi_session_timeout() -> u64 {
    3600 // 1 hour
}

/// Maximum allowed attestation types in NHI config.
const MAX_NHI_ATTESTATION_TYPES: usize = 20;
/// Maximum allowed additional trust domains in NHI config.
const MAX_NHI_ADDITIONAL_TRUST_DOMAINS: usize = 50;
/// Maximum allowed privileged tags in NHI config.
const MAX_NHI_PRIVILEGED_TAGS: usize = 50;
/// Maximum length for string fields in NHI config.
const MAX_NHI_STRING_FIELD_LEN: usize = 256;
/// Maximum credential TTL cap in seconds (7 days).
const MAX_NHI_CREDENTIAL_TTL_CAP: u64 = 7 * 86_400;
/// Maximum delegation chain depth cap.
const MAX_NHI_CHAIN_DEPTH_CAP: usize = 50;
/// Maximum identities cap.
const MAX_NHI_IDENTITIES_CAP: usize = 1_000_000;
/// Maximum delegations cap.
const MAX_NHI_DELEGATIONS_CAP: usize = 100_000;

impl NhiConfig {
    /// Validate NHI configuration bounds.
    ///
    /// SECURITY (IMP-R100-005): Ensures anomaly_threshold is within [0.0, 1.0],
    /// Vec fields are bounded, TTL consistency is checked, and string fields
    /// reject control/Unicode format characters.
    pub fn validate(&self) -> Result<(), String> {
        // Float range validation
        if !self.anomaly_threshold.is_finite()
            || self.anomaly_threshold < 0.0
            || self.anomaly_threshold > 1.0
        {
            return Err(format!(
                "nhi.anomaly_threshold must be in [0.0, 1.0], got {}",
                self.anomaly_threshold
            ));
        }

        // TTL consistency: credential_ttl must not exceed max_credential_ttl
        if self.credential_ttl_secs > self.max_credential_ttl_secs {
            return Err(format!(
                "nhi.credential_ttl_secs ({}) must be <= max_credential_ttl_secs ({})",
                self.credential_ttl_secs, self.max_credential_ttl_secs
            ));
        }
        // TTL upper bound
        if self.max_credential_ttl_secs > MAX_NHI_CREDENTIAL_TTL_CAP {
            return Err(format!(
                "nhi.max_credential_ttl_secs must be <= {}, got {}",
                MAX_NHI_CREDENTIAL_TTL_CAP, self.max_credential_ttl_secs
            ));
        }

        // Delegation chain depth cap
        if self.max_delegation_chain_depth > MAX_NHI_CHAIN_DEPTH_CAP {
            return Err(format!(
                "nhi.max_delegation_chain_depth must be <= {}, got {}",
                MAX_NHI_CHAIN_DEPTH_CAP, self.max_delegation_chain_depth
            ));
        }

        // Identity/delegation count caps
        if self.max_identities > MAX_NHI_IDENTITIES_CAP {
            return Err(format!(
                "nhi.max_identities must be <= {}, got {}",
                MAX_NHI_IDENTITIES_CAP, self.max_identities
            ));
        }
        if self.max_delegations > MAX_NHI_DELEGATIONS_CAP {
            return Err(format!(
                "nhi.max_delegations must be <= {}, got {}",
                MAX_NHI_DELEGATIONS_CAP, self.max_delegations
            ));
        }

        // Vec bounds
        if self.attestation_types.len() > MAX_NHI_ATTESTATION_TYPES {
            return Err(format!(
                "nhi.attestation_types has {} entries, max is {}",
                self.attestation_types.len(),
                MAX_NHI_ATTESTATION_TYPES
            ));
        }
        if self.additional_trust_domains.len() > MAX_NHI_ADDITIONAL_TRUST_DOMAINS {
            return Err(format!(
                "nhi.additional_trust_domains has {} entries, max is {}",
                self.additional_trust_domains.len(),
                MAX_NHI_ADDITIONAL_TRUST_DOMAINS
            ));
        }
        if self.privileged_tags.len() > MAX_NHI_PRIVILEGED_TAGS {
            return Err(format!(
                "nhi.privileged_tags has {} entries, max is {}",
                self.privileged_tags.len(),
                MAX_NHI_PRIVILEGED_TAGS
            ));
        }

        // Per-string validation for Vec<String> fields
        for (i, at) in self.attestation_types.iter().enumerate() {
            if at.is_empty() {
                return Err(format!("nhi.attestation_types[{}] must not be empty", i));
            }
            if at.len() > MAX_NHI_STRING_FIELD_LEN {
                return Err(format!(
                    "nhi.attestation_types[{}] length {} exceeds maximum {}",
                    i,
                    at.len(),
                    MAX_NHI_STRING_FIELD_LEN
                ));
            }
            if at.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "nhi.attestation_types[{}] contains control characters",
                    i
                ));
            }
        }
        for (i, td) in self.additional_trust_domains.iter().enumerate() {
            if td.is_empty() {
                return Err(format!(
                    "nhi.additional_trust_domains[{}] must not be empty",
                    i
                ));
            }
            if td.len() > MAX_NHI_STRING_FIELD_LEN {
                return Err(format!(
                    "nhi.additional_trust_domains[{}] length {} exceeds maximum {}",
                    i,
                    td.len(),
                    MAX_NHI_STRING_FIELD_LEN
                ));
            }
            if td.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "nhi.additional_trust_domains[{}] contains control characters",
                    i
                ));
            }
        }
        for (i, tag) in self.privileged_tags.iter().enumerate() {
            if tag.is_empty() {
                return Err(format!("nhi.privileged_tags[{}] must not be empty", i));
            }
            if tag.len() > MAX_NHI_STRING_FIELD_LEN {
                return Err(format!(
                    "nhi.privileged_tags[{}] length {} exceeds maximum {}",
                    i,
                    tag.len(),
                    MAX_NHI_STRING_FIELD_LEN
                ));
            }
            if tag.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "nhi.privileged_tags[{}] contains control characters",
                    i
                ));
            }
        }

        // Delegate to sub-config validation
        self.verification.validate()?;
        self.dpop.validate()?;

        Ok(())
    }
}

impl Default for NhiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            credential_ttl_secs: default_nhi_credential_ttl(),
            max_credential_ttl_secs: default_nhi_max_credential_ttl(),
            require_attestation: true,
            attestation_types: default_nhi_attestation_types(),
            auto_revoke_on_anomaly: false,
            anomaly_threshold: default_nhi_anomaly_threshold(),
            baseline_learning_period_hours: default_nhi_baseline_period(),
            min_baseline_observations: default_nhi_min_observations(),
            max_identities: default_nhi_max_identities(),
            max_delegations: default_nhi_max_delegations(),
            max_delegation_chain_depth: default_nhi_max_chain_depth(),
            require_delegation_approval: true,
            rotation_warning_hours: default_nhi_rotation_warning(),
            verification: VerificationConfig::default(),
            dpop: DpopConfig::default(),
            additional_trust_domains: Vec::new(),
            privileged_tags: Vec::new(),
            continuous_auth: true,
            session_timeout_secs: default_nhi_session_timeout(),
        }
    }
}

/// Identity verification configuration.
///
/// Controls verification tier enforcement, DID:PLC generation, and
/// accountability attestation settings.
///
/// # TOML Example
///
/// ```toml
/// [nhi.verification]
/// enabled = true
/// default_tier = "unverified"
/// global_minimum_tier = "unverified"
/// did_plc_enabled = true
/// plc_directory_url = "https://plc.directory"
/// max_attestations_per_identity = 100
/// attestation_ttl_secs = 86400
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerificationConfig {
    /// Enable identity verification features. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Default verification tier for new identities. Default: "unverified".
    #[serde(default = "default_verification_tier")]
    pub default_tier: String,

    /// Global minimum verification tier required. Default: "unverified".
    /// Policies can override this with `min_verification_tier` condition.
    #[serde(default = "default_verification_tier")]
    pub global_minimum_tier: String,

    /// Enable DID:PLC generation for agent identities. Default: false.
    #[serde(default)]
    pub did_plc_enabled: bool,

    /// PLC directory URL for DID resolution. Default: "https://plc.directory".
    #[serde(default = "default_plc_directory_url")]
    pub plc_directory_url: String,

    /// Maximum attestations stored per identity. Default: 100.
    #[serde(default = "default_max_attestations")]
    pub max_attestations_per_identity: usize,

    /// Attestation TTL in seconds. Default: 86400 (24 hours).
    #[serde(default = "default_attestation_ttl")]
    pub attestation_ttl_secs: u64,
}

fn default_verification_tier() -> String {
    "unverified".to_string()
}

fn default_plc_directory_url() -> String {
    "https://plc.directory".to_string()
}

fn default_max_attestations() -> usize {
    100
}

fn default_attestation_ttl() -> u64 {
    86400 // 24 hours
}

/// Maximum attestations per identity cap.
const MAX_ATTESTATIONS_CAP: usize = 10_000;
/// Maximum attestation TTL cap in seconds (30 days).
const MAX_ATTESTATION_TTL_CAP: u64 = 30 * 86_400;
/// Maximum PLC directory URL length.
const MAX_PLC_URL_LEN: usize = 2048;

/// Valid verification tier values.
const VALID_VERIFICATION_TIERS: &[&str] = &[
    "unverified",
    "email_verified",
    "phone_verified",
    "did_verified",
    "fully_verified",
];

impl VerificationConfig {
    /// Validate verification configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        // Tier validation (even when disabled, reject nonsensical defaults)
        if !VALID_VERIFICATION_TIERS.contains(&self.default_tier.as_str()) {
            return Err(format!(
                "nhi.verification.default_tier must be one of {:?}, got '{}'",
                VALID_VERIFICATION_TIERS, self.default_tier
            ));
        }
        if !VALID_VERIFICATION_TIERS.contains(&self.global_minimum_tier.as_str()) {
            return Err(format!(
                "nhi.verification.global_minimum_tier must be one of {:?}, got '{}'",
                VALID_VERIFICATION_TIERS, self.global_minimum_tier
            ));
        }
        // Attestation bounds
        if self.max_attestations_per_identity > MAX_ATTESTATIONS_CAP {
            return Err(format!(
                "nhi.verification.max_attestations_per_identity must be <= {}, got {}",
                MAX_ATTESTATIONS_CAP, self.max_attestations_per_identity
            ));
        }
        if self.enabled && self.max_attestations_per_identity == 0 {
            return Err(
                "nhi.verification.max_attestations_per_identity must be > 0 when enabled"
                    .to_string(),
            );
        }
        if self.attestation_ttl_secs > MAX_ATTESTATION_TTL_CAP {
            return Err(format!(
                "nhi.verification.attestation_ttl_secs must be <= {}, got {}",
                MAX_ATTESTATION_TTL_CAP, self.attestation_ttl_secs
            ));
        }
        if self.enabled && self.attestation_ttl_secs == 0 {
            return Err(
                "nhi.verification.attestation_ttl_secs must be > 0 when enabled".to_string(),
            );
        }
        // PLC directory URL validation
        if self.did_plc_enabled {
            if self.plc_directory_url.is_empty() {
                return Err(
                    "nhi.verification.plc_directory_url must not be empty when DID:PLC is enabled"
                        .to_string(),
                );
            }
            if self.plc_directory_url.len() > MAX_PLC_URL_LEN {
                return Err(format!(
                    "nhi.verification.plc_directory_url length {} exceeds maximum {}",
                    self.plc_directory_url.len(),
                    MAX_PLC_URL_LEN
                ));
            }
            if !self.plc_directory_url.starts_with("https://") {
                return Err(
                    "nhi.verification.plc_directory_url must use https:// scheme".to_string(),
                );
            }
            if self.plc_directory_url.chars().any(|c| c.is_control()) {
                return Err(
                    "nhi.verification.plc_directory_url contains control characters".to_string(),
                );
            }
        }
        Ok(())
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_tier: default_verification_tier(),
            global_minimum_tier: default_verification_tier(),
            did_plc_enabled: false,
            plc_directory_url: default_plc_directory_url(),
            max_attestations_per_identity: default_max_attestations(),
            attestation_ttl_secs: default_attestation_ttl(),
        }
    }
}

/// DPoP (Demonstration of Proof-of-Possession) configuration per RFC 9449.
///
/// Controls validation of DPoP proofs for sender-constrained tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DpopConfig {
    /// Require server-issued nonce in DPoP proofs. Default: true.
    #[serde(default = "default_true")]
    pub require_nonce: bool,

    /// Maximum clock skew allowed in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_dpop_clock_skew")]
    pub max_clock_skew_secs: u64,

    /// Allowed signature algorithms. Default: ["ES256", "RS256", "EdDSA"].
    #[serde(default = "default_dpop_algorithms")]
    pub allowed_algorithms: Vec<String>,

    /// Nonce validity period in seconds. Default: 300 (5 minutes).
    #[serde(default = "default_dpop_nonce_ttl")]
    pub nonce_ttl_secs: u64,

    /// Maximum number of active nonces to track. Default: 10000.
    #[serde(default = "default_dpop_max_nonces")]
    pub max_nonces: usize,

    /// Require access token hash (ath) claim when binding to tokens. Default: true.
    #[serde(default = "default_true")]
    pub require_ath: bool,

    /// Maximum DPoP proof lifetime in seconds. Default: 60.
    #[serde(default = "default_dpop_proof_lifetime")]
    pub max_proof_lifetime_secs: u64,
}

fn default_dpop_clock_skew() -> u64 {
    300 // 5 minutes
}

fn default_dpop_algorithms() -> Vec<String> {
    vec![
        "ES256".to_string(),
        "RS256".to_string(),
        "EdDSA".to_string(),
    ]
}

fn default_dpop_nonce_ttl() -> u64 {
    300 // 5 minutes
}

fn default_dpop_max_nonces() -> usize {
    10000
}

fn default_dpop_proof_lifetime() -> u64 {
    60 // 1 minute
}

/// Maximum DPoP algorithms allowed.
const MAX_DPOP_ALGORITHMS: usize = 20;
/// Maximum DPoP algorithm string length.
const MAX_DPOP_ALGORITHM_LEN: usize = 32;
/// Maximum clock skew cap (1 hour).
const MAX_DPOP_CLOCK_SKEW_CAP: u64 = 3_600;
/// Maximum nonces cap.
const MAX_DPOP_NONCES_CAP: usize = 1_000_000;
/// Maximum proof lifetime cap (10 minutes).
const MAX_DPOP_PROOF_LIFETIME_CAP: u64 = 600;

impl DpopConfig {
    /// Validate DPoP configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_clock_skew_secs > MAX_DPOP_CLOCK_SKEW_CAP {
            return Err(format!(
                "nhi.dpop.max_clock_skew_secs must be <= {}, got {}",
                MAX_DPOP_CLOCK_SKEW_CAP, self.max_clock_skew_secs
            ));
        }
        if self.nonce_ttl_secs > MAX_DPOP_CLOCK_SKEW_CAP {
            return Err(format!(
                "nhi.dpop.nonce_ttl_secs must be <= {}, got {}",
                MAX_DPOP_CLOCK_SKEW_CAP, self.nonce_ttl_secs
            ));
        }
        if self.max_nonces > MAX_DPOP_NONCES_CAP {
            return Err(format!(
                "nhi.dpop.max_nonces must be <= {}, got {}",
                MAX_DPOP_NONCES_CAP, self.max_nonces
            ));
        }
        if self.max_proof_lifetime_secs > MAX_DPOP_PROOF_LIFETIME_CAP {
            return Err(format!(
                "nhi.dpop.max_proof_lifetime_secs must be <= {}, got {}",
                MAX_DPOP_PROOF_LIFETIME_CAP, self.max_proof_lifetime_secs
            ));
        }
        if self.max_proof_lifetime_secs == 0 {
            return Err("nhi.dpop.max_proof_lifetime_secs must be > 0".to_string());
        }
        // Algorithm list bounds
        if self.allowed_algorithms.len() > MAX_DPOP_ALGORITHMS {
            return Err(format!(
                "nhi.dpop.allowed_algorithms has {} entries, max is {}",
                self.allowed_algorithms.len(),
                MAX_DPOP_ALGORITHMS
            ));
        }
        for (i, alg) in self.allowed_algorithms.iter().enumerate() {
            if alg.is_empty() {
                return Err(format!(
                    "nhi.dpop.allowed_algorithms[{}] must not be empty",
                    i
                ));
            }
            if alg.len() > MAX_DPOP_ALGORITHM_LEN {
                return Err(format!(
                    "nhi.dpop.allowed_algorithms[{}] length {} exceeds maximum {}",
                    i,
                    alg.len(),
                    MAX_DPOP_ALGORITHM_LEN
                ));
            }
            if alg.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "nhi.dpop.allowed_algorithms[{}] contains control characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            require_nonce: true,
            max_clock_skew_secs: default_dpop_clock_skew(),
            allowed_algorithms: default_dpop_algorithms(),
            nonce_ttl_secs: default_dpop_nonce_ttl(),
            max_nonces: default_dpop_max_nonces(),
            require_ath: true,
            max_proof_lifetime_secs: default_dpop_proof_lifetime(),
        }
    }
}
