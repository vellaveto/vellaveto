//! OWASP AI Vulnerability Scoring System (AIVSS) Integration.
//!
//! Provides severity scoring for AI security findings based on the
//! OWASP AIVSS framework (expected finalization RSA 2026).
//!
//! The scoring system evaluates AI-specific factors:
//! - Attack Complexity (how difficult to exploit)
//! - Privileges Required (what access level is needed)
//! - User Interaction (does attack require user action)
//! - Scope (can attack affect other components)
//! - Confidentiality Impact (data exposure)
//! - Integrity Impact (data/model manipulation)
//! - Availability Impact (service disruption)
//! - AI-Specific Factors (autonomy, persistence, reversibility)
//!
//! References:
//! - OWASP Top 10 for Agentic Applications 2026
//! - OWASP Machine Learning Security Top 10
//! - CVSS v4.0 (base scoring methodology)

use serde::{Deserialize, Serialize};

/// AIVSS score components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AivssScore {
    /// Base score (0.0 - 10.0).
    pub base_score: f32,
    /// Severity rating derived from base score.
    pub severity: AivssSeverity,
    /// Individual metric values.
    pub metrics: AivssMetrics,
    /// Vector string representation.
    pub vector_string: String,
}

/// Severity rating levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AivssSeverity {
    /// 0.0 - No security impact.
    None,
    /// 0.1 - 3.9 - Minor security impact.
    Low,
    /// 4.0 - 6.9 - Moderate security impact.
    Medium,
    /// 7.0 - 8.9 - Significant security impact.
    High,
    /// 9.0 - 10.0 - Maximum security impact.
    Critical,
}

impl AivssSeverity {
    /// Get severity from base score.
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s <= 0.0 => Self::None,
            s if s < 4.0 => Self::Low,
            s if s < 7.0 => Self::Medium,
            s if s < 9.0 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Get color code for display.
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::None => "#808080",     // Gray
            Self::Low => "#2E7D32",      // Green
            Self::Medium => "#F9A825",   // Yellow/Orange
            Self::High => "#E65100",     // Orange
            Self::Critical => "#C62828", // Red
        }
    }
}

impl std::fmt::Display for AivssSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// AIVSS metric values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AivssMetrics {
    // === Exploitability Metrics ===
    /// Attack Vector - How the vulnerability is exploited.
    pub attack_vector: AttackVector,
    /// Attack Complexity - Difficulty of exploitation.
    pub attack_complexity: AttackComplexity,
    /// Privileges Required - Access level needed.
    pub privileges_required: PrivilegesRequired,
    /// User Interaction - Does attack require user action.
    pub user_interaction: UserInteraction,

    // === Impact Metrics ===
    /// Scope - Can attack affect other components.
    pub scope: Scope,
    /// Confidentiality Impact - Data exposure.
    pub confidentiality_impact: Impact,
    /// Integrity Impact - Data/model manipulation.
    pub integrity_impact: Impact,
    /// Availability Impact - Service disruption.
    pub availability_impact: Impact,

    // === AI-Specific Metrics ===
    /// Agent Autonomy - Degree of autonomous action.
    pub agent_autonomy: AgentAutonomy,
    /// Attack Persistence - Does attack persist across sessions.
    pub attack_persistence: AttackPersistence,
    /// Reversibility - Can the damage be undone.
    pub reversibility: Reversibility,
}

impl Default for AivssMetrics {
    fn default() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::None,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
            agent_autonomy: AgentAutonomy::Low,
            attack_persistence: AttackPersistence::Transient,
            reversibility: Reversibility::Reversible,
        }
    }
}

/// Attack Vector - How the vulnerability is exploited.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    /// Requires physical access.
    Physical,
    /// Requires local access.
    Local,
    /// Requires adjacent network access.
    Adjacent,
    /// Exploitable over the network.
    Network,
}

impl AttackVector {
    fn weight(&self) -> f32 {
        match self {
            Self::Physical => 0.20,
            Self::Local => 0.55,
            Self::Adjacent => 0.62,
            Self::Network => 0.85,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Physical => "P",
            Self::Local => "L",
            Self::Adjacent => "A",
            Self::Network => "N",
        }
    }
}

/// Attack Complexity - Difficulty of exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    /// Specialized conditions required.
    High,
    /// No specialized conditions required.
    Low,
}

impl AttackComplexity {
    fn weight(&self) -> f32 {
        match self {
            Self::High => 0.44,
            Self::Low => 0.77,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::High => "H",
            Self::Low => "L",
        }
    }
}

/// Privileges Required - Access level needed for exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    /// High privileges needed (admin).
    High,
    /// Low privileges needed (authenticated user).
    Low,
    /// No privileges needed (unauthenticated).
    None,
}

impl PrivilegesRequired {
    fn weight(&self, scope_changed: bool) -> f32 {
        match (self, scope_changed) {
            (Self::High, false) => 0.27,
            (Self::High, true) => 0.50,
            (Self::Low, false) => 0.62,
            (Self::Low, true) => 0.68,
            (Self::None, _) => 0.85,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::High => "H",
            Self::Low => "L",
            Self::None => "N",
        }
    }
}

/// User Interaction - Does exploitation require user action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    /// User action required.
    Required,
    /// No user action required.
    None,
}

impl UserInteraction {
    fn weight(&self) -> f32 {
        match self {
            Self::Required => 0.62,
            Self::None => 0.85,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Required => "R",
            Self::None => "N",
        }
    }
}

/// Scope - Can the attack affect other components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Impact limited to the vulnerable component.
    Unchanged,
    /// Impact extends to other components.
    Changed,
}

impl Scope {
    fn is_changed(&self) -> bool {
        matches!(self, Self::Changed)
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Unchanged => "U",
            Self::Changed => "C",
        }
    }
}

/// Impact level for C/I/A metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Impact {
    /// No impact.
    None,
    /// Low impact.
    Low,
    /// High impact.
    High,
}

impl Impact {
    fn weight(&self) -> f32 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.22,
            Self::High => 0.56,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::None => "N",
            Self::Low => "L",
            Self::High => "H",
        }
    }
}

/// Agent Autonomy - Degree of autonomous action capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAutonomy {
    /// Agent has minimal autonomous capabilities.
    Low,
    /// Agent has moderate autonomous capabilities.
    Medium,
    /// Agent can take significant autonomous actions.
    High,
}

impl AgentAutonomy {
    fn multiplier(&self) -> f32 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 1.1,
            Self::High => 1.2,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Low => "L",
            Self::Medium => "M",
            Self::High => "H",
        }
    }
}

/// Attack Persistence - Does the attack persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPersistence {
    /// Attack effects are temporary.
    Transient,
    /// Attack effects persist within session.
    Session,
    /// Attack effects persist across sessions.
    Persistent,
}

impl AttackPersistence {
    fn multiplier(&self) -> f32 {
        match self {
            Self::Transient => 1.0,
            Self::Session => 1.05,
            Self::Persistent => 1.15,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Transient => "T",
            Self::Session => "S",
            Self::Persistent => "P",
        }
    }
}

/// Reversibility - Can the damage be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    /// Effects can be easily reversed.
    Reversible,
    /// Effects are difficult to reverse.
    Difficult,
    /// Effects are permanent.
    Irreversible,
}

impl Reversibility {
    fn multiplier(&self) -> f32 {
        match self {
            Self::Reversible => 1.0,
            Self::Difficult => 1.1,
            Self::Irreversible => 1.2,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Reversible => "R",
            Self::Difficult => "D",
            Self::Irreversible => "I",
        }
    }
}

/// AIVSS score calculator.
pub struct AivssCalculator;

impl AivssCalculator {
    /// Calculate AIVSS score from metrics.
    pub fn calculate(metrics: &AivssMetrics) -> AivssScore {
        let scope_changed = metrics.scope.is_changed();

        // Calculate exploitability sub-score
        let exploitability = 8.22
            * metrics.attack_vector.weight()
            * metrics.attack_complexity.weight()
            * metrics.privileges_required.weight(scope_changed)
            * metrics.user_interaction.weight();

        // Calculate impact sub-score
        let isc_base = 1.0
            - (1.0 - metrics.confidentiality_impact.weight())
                * (1.0 - metrics.integrity_impact.weight())
                * (1.0 - metrics.availability_impact.weight());

        let impact = if scope_changed {
            7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02).powf(15.0)
        } else {
            6.42 * isc_base
        };

        // Calculate base score
        let mut base_score = if impact <= 0.0 {
            0.0
        } else if scope_changed {
            (1.08 * (impact + exploitability)).min(10.0)
        } else {
            (impact + exploitability).min(10.0)
        };

        // Apply AI-specific multipliers
        let ai_multiplier = metrics.agent_autonomy.multiplier()
            * metrics.attack_persistence.multiplier()
            * metrics.reversibility.multiplier();

        base_score = (base_score * ai_multiplier).min(10.0);

        // Round to one decimal place
        base_score = (base_score * 10.0).round() / 10.0;

        let severity = AivssSeverity::from_score(base_score);
        let vector_string = Self::build_vector_string(metrics);

        AivssScore {
            base_score,
            severity,
            metrics: metrics.clone(),
            vector_string,
        }
    }

    /// Build the vector string representation.
    fn build_vector_string(metrics: &AivssMetrics) -> String {
        format!(
            "AIVSS:1.0/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}/AU:{}/AP:{}/RV:{}",
            metrics.attack_vector.code(),
            metrics.attack_complexity.code(),
            metrics.privileges_required.code(),
            metrics.user_interaction.code(),
            metrics.scope.code(),
            metrics.confidentiality_impact.code(),
            metrics.integrity_impact.code(),
            metrics.availability_impact.code(),
            metrics.agent_autonomy.code(),
            metrics.attack_persistence.code(),
            metrics.reversibility.code(),
        )
    }

    /// Parse a vector string into metrics.
    pub fn parse_vector_string(vector: &str) -> Option<AivssMetrics> {
        if !vector.starts_with("AIVSS:1.0/") {
            return None;
        }

        let mut metrics = AivssMetrics::default();

        for part in vector[10..].split('/') {
            let (key, value) = part.split_once(':')?;
            match key {
                "AV" => {
                    metrics.attack_vector = match value {
                        "P" => AttackVector::Physical,
                        "L" => AttackVector::Local,
                        "A" => AttackVector::Adjacent,
                        "N" => AttackVector::Network,
                        _ => return None,
                    }
                }
                "AC" => {
                    metrics.attack_complexity = match value {
                        "H" => AttackComplexity::High,
                        "L" => AttackComplexity::Low,
                        _ => return None,
                    }
                }
                "PR" => {
                    metrics.privileges_required = match value {
                        "H" => PrivilegesRequired::High,
                        "L" => PrivilegesRequired::Low,
                        "N" => PrivilegesRequired::None,
                        _ => return None,
                    }
                }
                "UI" => {
                    metrics.user_interaction = match value {
                        "R" => UserInteraction::Required,
                        "N" => UserInteraction::None,
                        _ => return None,
                    }
                }
                "S" => {
                    metrics.scope = match value {
                        "U" => Scope::Unchanged,
                        "C" => Scope::Changed,
                        _ => return None,
                    }
                }
                "C" => {
                    metrics.confidentiality_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => return None,
                    }
                }
                "I" => {
                    metrics.integrity_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => return None,
                    }
                }
                "A" => {
                    metrics.availability_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => return None,
                    }
                }
                "AU" => {
                    metrics.agent_autonomy = match value {
                        "L" => AgentAutonomy::Low,
                        "M" => AgentAutonomy::Medium,
                        "H" => AgentAutonomy::High,
                        _ => return None,
                    }
                }
                "AP" => {
                    metrics.attack_persistence = match value {
                        "T" => AttackPersistence::Transient,
                        "S" => AttackPersistence::Session,
                        "P" => AttackPersistence::Persistent,
                        _ => return None,
                    }
                }
                "RV" => {
                    metrics.reversibility = match value {
                        "R" => Reversibility::Reversible,
                        "D" => Reversibility::Difficult,
                        "I" => Reversibility::Irreversible,
                        _ => return None,
                    }
                }
                _ => {}
            }
        }

        Some(metrics)
    }
}

/// Security finding with AIVSS scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AivssFinding {
    /// Finding ID.
    pub id: String,
    /// Finding title.
    pub title: String,
    /// Finding description.
    pub description: String,
    /// AIVSS score.
    pub score: AivssScore,
    /// Affected component.
    pub component: String,
    /// Timestamp.
    pub timestamp: String,
    /// Additional metadata.
    pub metadata: serde_json::Value,
}

/// AIVSS finding report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AivssReport {
    /// Report generation timestamp.
    pub generated_at: String,
    /// Total findings.
    pub total_findings: usize,
    /// Findings by severity.
    pub by_severity: SeverityCounts,
    /// Individual findings.
    pub findings: Vec<AivssFinding>,
}

/// Counts by severity level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
}

impl AivssReport {
    /// Create a new report from findings.
    pub fn new(findings: Vec<AivssFinding>) -> Self {
        let mut by_severity = SeverityCounts::default();

        for finding in &findings {
            match finding.score.severity {
                AivssSeverity::Critical => by_severity.critical += 1,
                AivssSeverity::High => by_severity.high += 1,
                AivssSeverity::Medium => by_severity.medium += 1,
                AivssSeverity::Low => by_severity.low += 1,
                AivssSeverity::None => by_severity.none += 1,
            }
        }

        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_findings: findings.len(),
            by_severity,
            findings,
        }
    }

    /// Export to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate summary string.
    pub fn summary(&self) -> String {
        format!(
            "AIVSS Report: {} findings (Critical: {}, High: {}, Medium: {}, Low: {}, None: {})",
            self.total_findings,
            self.by_severity.critical,
            self.by_severity.high,
            self.by_severity.medium,
            self.by_severity.low,
            self.by_severity.none
        )
    }
}

/// Predefined AIVSS profiles for common Sentinel detections.
pub struct AivssProfiles;

impl AivssProfiles {
    /// Get metrics profile for prompt injection.
    pub fn prompt_injection() -> AivssMetrics {
        AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::Low,
            agent_autonomy: AgentAutonomy::Medium,
            attack_persistence: AttackPersistence::Session,
            reversibility: Reversibility::Reversible,
        }
    }

    /// Get metrics profile for tool squatting.
    pub fn tool_squatting() -> AivssMetrics {
        AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::None,
            agent_autonomy: AgentAutonomy::Low,
            attack_persistence: AttackPersistence::Persistent,
            reversibility: Reversibility::Difficult,
        }
    }

    /// Get metrics profile for confused deputy.
    pub fn confused_deputy() -> AivssMetrics {
        AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::Low,
            agent_autonomy: AgentAutonomy::High,
            attack_persistence: AttackPersistence::Session,
            reversibility: Reversibility::Reversible,
        }
    }

    /// Get metrics profile for data exfiltration.
    pub fn data_exfiltration() -> AivssMetrics {
        AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Changed,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
            agent_autonomy: AgentAutonomy::Medium,
            attack_persistence: AttackPersistence::Transient,
            reversibility: Reversibility::Irreversible,
        }
    }

    /// Get metrics profile for memory poisoning.
    pub fn memory_poisoning() -> AivssMetrics {
        AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::Low,
            integrity_impact: Impact::High,
            availability_impact: Impact::Low,
            agent_autonomy: AgentAutonomy::Medium,
            attack_persistence: AttackPersistence::Persistent,
            reversibility: Reversibility::Difficult,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score() {
        assert_eq!(AivssSeverity::from_score(0.0), AivssSeverity::None);
        assert_eq!(AivssSeverity::from_score(2.5), AivssSeverity::Low);
        assert_eq!(AivssSeverity::from_score(5.0), AivssSeverity::Medium);
        assert_eq!(AivssSeverity::from_score(7.5), AivssSeverity::High);
        assert_eq!(AivssSeverity::from_score(9.5), AivssSeverity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", AivssSeverity::Critical), "Critical");
        assert_eq!(format!("{}", AivssSeverity::Low), "Low");
    }

    #[test]
    fn test_calculate_score() {
        let metrics = AivssProfiles::prompt_injection();
        let score = AivssCalculator::calculate(&metrics);

        assert!(score.base_score > 0.0);
        assert!(score.base_score <= 10.0);
        assert!(!score.vector_string.is_empty());
    }

    #[test]
    fn test_vector_string_generation() {
        let metrics = AivssMetrics::default();
        let score = AivssCalculator::calculate(&metrics);

        assert!(score.vector_string.starts_with("AIVSS:1.0/"));
        assert!(score.vector_string.contains("AV:N"));
    }

    #[test]
    fn test_vector_string_parsing() {
        let original = AivssProfiles::prompt_injection();
        let score = AivssCalculator::calculate(&original);

        let parsed = AivssCalculator::parse_vector_string(&score.vector_string);
        assert!(parsed.is_some());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.attack_vector, original.attack_vector);
        assert_eq!(parsed.attack_complexity, original.attack_complexity);
    }

    #[test]
    fn test_invalid_vector_string() {
        assert!(AivssCalculator::parse_vector_string("invalid").is_none());
        assert!(AivssCalculator::parse_vector_string("AIVSS:1.0/AV:X").is_none());
    }

    #[test]
    fn test_report_generation() {
        let findings = vec![
            AivssFinding {
                id: "FINDING-001".to_string(),
                title: "Prompt Injection".to_string(),
                description: "Test finding".to_string(),
                score: AivssCalculator::calculate(&AivssProfiles::prompt_injection()),
                component: "agent".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                metadata: serde_json::json!({}),
            },
            AivssFinding {
                id: "FINDING-002".to_string(),
                title: "Tool Squatting".to_string(),
                description: "Test finding".to_string(),
                score: AivssCalculator::calculate(&AivssProfiles::tool_squatting()),
                component: "tools".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                metadata: serde_json::json!({}),
            },
        ];

        let report = AivssReport::new(findings);

        assert_eq!(report.total_findings, 2);
        assert!(!report.generated_at.is_empty());
    }

    #[test]
    fn test_report_to_json() {
        let report = AivssReport::new(vec![]);
        let json = report.to_json();
        assert!(json.is_ok());
    }

    #[test]
    fn test_report_summary() {
        let report = AivssReport::new(vec![]);
        let summary = report.summary();
        assert!(summary.contains("AIVSS Report"));
    }

    #[test]
    fn test_profiles() {
        // Verify all profiles produce valid scores
        let profiles = [
            AivssProfiles::prompt_injection(),
            AivssProfiles::tool_squatting(),
            AivssProfiles::confused_deputy(),
            AivssProfiles::data_exfiltration(),
            AivssProfiles::memory_poisoning(),
        ];

        for profile in profiles {
            let score = AivssCalculator::calculate(&profile);
            assert!(score.base_score >= 0.0);
            assert!(score.base_score <= 10.0);
        }
    }

    #[test]
    fn test_ai_multipliers_increase_score() {
        let mut base = AivssMetrics::default();
        base.confidentiality_impact = Impact::High;
        base.integrity_impact = Impact::High;

        let base_score = AivssCalculator::calculate(&base);

        // High autonomy should increase score
        let mut high_autonomy = base.clone();
        high_autonomy.agent_autonomy = AgentAutonomy::High;
        let high_score = AivssCalculator::calculate(&high_autonomy);

        assert!(high_score.base_score >= base_score.base_score);
    }

    #[test]
    fn test_zero_impact_zero_score() {
        let metrics = AivssMetrics {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::None,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
            agent_autonomy: AgentAutonomy::Low,
            attack_persistence: AttackPersistence::Transient,
            reversibility: Reversibility::Reversible,
        };

        let score = AivssCalculator::calculate(&metrics);
        assert_eq!(score.base_score, 0.0);
        assert_eq!(score.severity, AivssSeverity::None);
    }
}
