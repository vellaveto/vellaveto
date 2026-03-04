// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Intent taxonomy and classification types for semantic guardrails (Phase 12).
//!
//! Provides a structured taxonomy of action intents and risk categories
//! for LLM-based policy evaluation.
//!
//! # Intent Categories
//!
//! - **Data**: Read, write, delete, export, query operations
//! - **System**: Execute, configure, monitor system actions
//! - **Network**: Fetch, send, connect network operations
//! - **Security**: Credential access, privilege escalation, policy bypass
//! - **Malicious**: Injection, exfiltration, denial of service
//!
//! # Example
//!
//! ```rust
//! use vellaveto_mcp::semantic_guardrails::intent::{Intent, RiskCategory, IntentClassification};
//!
//! let classification = IntentClassification {
//!     primary_intent: Intent::DataRead,
//!     confidence: 0.95,
//!     secondary_intents: vec![(Intent::NetworkFetch, 0.3)],
//!     detected_risks: vec![RiskCategory::DataLeakage],
//!     explanation: None,
//! };
//!
//! assert!(classification.confidence >= 0.6);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════
// INTENT TAXONOMY
// ═══════════════════════════════════════════════════

/// Primary intent categories for tool actions.
///
/// Each action is classified into one of these intent categories
/// to enable semantic policy evaluation beyond pattern matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    // ── Data Operations ─────────────────────────
    /// Reading data from storage, files, or databases.
    DataRead,
    /// Writing/creating data to storage, files, or databases.
    DataWrite,
    /// Deleting data from storage, files, or databases.
    DataDelete,
    /// Exporting data to external systems or formats.
    DataExport,
    /// Querying or searching data.
    DataQuery,

    // ── System Operations ───────────────────────
    /// Executing commands, scripts, or processes.
    SystemExecute,
    /// Configuring system settings or parameters.
    SystemConfigure,
    /// Monitoring system state or metrics.
    SystemMonitor,

    // ── Network Operations ──────────────────────
    /// Fetching data from external URLs or APIs.
    NetworkFetch,
    /// Sending data to external endpoints.
    NetworkSend,
    /// Establishing network connections.
    NetworkConnect,

    // ── Security-Sensitive Operations ───────────
    /// Accessing credentials, secrets, or tokens.
    CredentialAccess,
    /// Attempting privilege escalation.
    PrivilegeEscalation,
    /// Attempting to bypass security policies.
    PolicyBypass,

    // ── Malicious Operations ────────────────────
    /// Prompt injection or code injection attempts.
    Injection,
    /// Data exfiltration attempts.
    Exfiltration,
    /// Denial of service or resource exhaustion.
    DenialOfService,

    // ── Default Categories ──────────────────────
    /// Intent could not be determined.
    #[default]
    Unknown,
    /// No concerning intent detected (benign operation).
    Benign,
}

impl Intent {
    /// Returns the risk level (0-100) associated with this intent.
    ///
    /// Higher values indicate more security-sensitive intents.
    pub fn risk_level(&self) -> u8 {
        match self {
            // Malicious intents: highest risk
            Intent::Injection => 100,
            Intent::Exfiltration => 95,
            Intent::DenialOfService => 90,

            // Security-sensitive: high risk
            Intent::CredentialAccess => 85,
            Intent::PrivilegeEscalation => 90,
            Intent::PolicyBypass => 85,

            // Destructive data ops: medium-high risk
            Intent::DataDelete => 70,
            Intent::DataExport => 60,

            // System/network ops: medium risk
            Intent::SystemExecute => 65,
            Intent::SystemConfigure => 55,
            Intent::NetworkSend => 50,
            Intent::NetworkConnect => 45,

            // Read/query ops: low risk
            Intent::DataRead => 20,
            Intent::DataQuery => 15,
            Intent::NetworkFetch => 30,
            Intent::DataWrite => 40,
            Intent::SystemMonitor => 25,

            // Default: minimal risk
            Intent::Unknown => 50, // Treat unknown as medium risk (fail-closed)
            Intent::Benign => 0,
        }
    }

    /// Returns true if this intent is considered potentially malicious.
    pub fn is_malicious(&self) -> bool {
        matches!(
            self,
            Intent::Injection | Intent::Exfiltration | Intent::DenialOfService
        )
    }

    /// Returns true if this intent involves security-sensitive operations.
    pub fn is_security_sensitive(&self) -> bool {
        matches!(
            self,
            Intent::CredentialAccess | Intent::PrivilegeEscalation | Intent::PolicyBypass
        ) || self.is_malicious()
    }

    /// Returns a human-readable description of this intent.
    pub fn description(&self) -> &'static str {
        match self {
            Intent::DataRead => "Reading data from storage or files",
            Intent::DataWrite => "Writing data to storage or files",
            Intent::DataDelete => "Deleting data from storage or files",
            Intent::DataExport => "Exporting data to external systems",
            Intent::DataQuery => "Querying or searching data",
            Intent::SystemExecute => "Executing commands or processes",
            Intent::SystemConfigure => "Configuring system settings",
            Intent::SystemMonitor => "Monitoring system state",
            Intent::NetworkFetch => "Fetching data from external URLs",
            Intent::NetworkSend => "Sending data to external endpoints",
            Intent::NetworkConnect => "Establishing network connections",
            Intent::CredentialAccess => "Accessing credentials or secrets",
            Intent::PrivilegeEscalation => "Attempting privilege escalation",
            Intent::PolicyBypass => "Attempting to bypass security policies",
            Intent::Injection => "Prompt or code injection attempt",
            Intent::Exfiltration => "Data exfiltration attempt",
            Intent::DenialOfService => "Denial of service attempt",
            Intent::Unknown => "Intent could not be determined",
            Intent::Benign => "No concerning intent detected",
        }
    }
}

// ═══════════════════════════════════════════════════
// RISK CATEGORIES
// ═══════════════════════════════════════════════════

/// Security risk categories detected in requests or responses.
///
/// These are orthogonal to intents — a single action may have multiple
/// detected risks even with a benign primary intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    /// Prompt injection attempt detected.
    PromptInjection,
    /// Jailbreak attempt detected.
    Jailbreak,
    /// Potential data leakage or exfiltration.
    DataLeakage,
    /// Unauthorized access attempt.
    UnauthorizedAccess,
    /// Privilege escalation attempt.
    PrivilegeEscalation,
    /// Malicious payload detected.
    MaliciousPayload,
    /// Social engineering markers present.
    SocialEngineering,
    /// System abuse or resource exhaustion.
    SystemAbuse,
    /// Policy violation detected.
    PolicyViolation,
}

impl RiskCategory {
    /// Returns the severity level (0-100) of this risk category.
    pub fn severity(&self) -> u8 {
        match self {
            RiskCategory::PromptInjection => 90,
            RiskCategory::Jailbreak => 95,
            RiskCategory::DataLeakage => 85,
            RiskCategory::UnauthorizedAccess => 80,
            RiskCategory::PrivilegeEscalation => 90,
            RiskCategory::MaliciousPayload => 100,
            RiskCategory::SocialEngineering => 70,
            RiskCategory::SystemAbuse => 75,
            RiskCategory::PolicyViolation => 60,
        }
    }

    /// Returns a human-readable description of this risk category.
    pub fn description(&self) -> &'static str {
        match self {
            RiskCategory::PromptInjection => "Prompt injection attempt detected",
            RiskCategory::Jailbreak => "Jailbreak attempt detected",
            RiskCategory::DataLeakage => "Potential data leakage or exfiltration",
            RiskCategory::UnauthorizedAccess => "Unauthorized access attempt",
            RiskCategory::PrivilegeEscalation => "Privilege escalation attempt",
            RiskCategory::MaliciousPayload => "Malicious payload detected",
            RiskCategory::SocialEngineering => "Social engineering markers present",
            RiskCategory::SystemAbuse => "System abuse or resource exhaustion",
            RiskCategory::PolicyViolation => "Policy violation detected",
        }
    }
}

// ═══════════════════════════════════════════════════
// INTENT CLASSIFICATION RESULT
// ═══════════════════════════════════════════════════

/// Maximum number of secondary intents in an IntentClassification.
const MAX_SECONDARY_INTENTS: usize = 50;

/// Maximum number of detected risks in an IntentClassification.
const MAX_DETECTED_RISKS: usize = 50;

/// Result of intent classification for an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentClassification {
    /// Primary classified intent.
    pub primary_intent: Intent,
    /// Confidence score for the primary intent (0.0 to 1.0).
    pub confidence: f64,
    /// Secondary intents with their confidence scores.
    #[serde(default)]
    pub secondary_intents: Vec<(Intent, f64)>,
    /// Risk categories detected in the action.
    #[serde(default)]
    pub detected_risks: Vec<RiskCategory>,
    /// Raw explanation from the LLM (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

impl Default for IntentClassification {
    fn default() -> Self {
        Self {
            primary_intent: Intent::Unknown,
            confidence: 0.0,
            secondary_intents: Vec::new(),
            detected_risks: Vec::new(),
            explanation: None,
        }
    }
}

impl IntentClassification {
    /// Creates a new classification with unknown intent.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Creates a classification indicating a benign action.
    ///
    /// SECURITY (FIND-R114-010): NaN/Infinity/negative confidence clamped to [0.0, 1.0].
    pub fn benign(confidence: f64) -> Self {
        let confidence = if confidence.is_finite() {
            confidence.clamp(0.0, 1.0)
        } else {
            0.0
        };
        Self {
            primary_intent: Intent::Benign,
            confidence,
            secondary_intents: Vec::new(),
            detected_risks: Vec::new(),
            explanation: None,
        }
    }

    /// Validates the classification, enforcing collection bounds and numeric ranges.
    ///
    /// SECURITY (FIND-R114-006): Unbounded secondary_intents/detected_risks vectors.
    pub fn validate(&self) -> Result<(), String> {
        if !self.confidence.is_finite() || self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(format!(
                "IntentClassification.confidence must be finite in [0.0, 1.0], got {}",
                self.confidence
            ));
        }
        if self.secondary_intents.len() > MAX_SECONDARY_INTENTS {
            return Err(format!(
                "IntentClassification.secondary_intents exceeds max ({} > {})",
                self.secondary_intents.len(),
                MAX_SECONDARY_INTENTS
            ));
        }
        for (i, (_, conf)) in self.secondary_intents.iter().enumerate() {
            if !conf.is_finite() || *conf < 0.0 || *conf > 1.0 {
                return Err(format!(
                    "IntentClassification.secondary_intents[{}] confidence must be finite in [0.0, 1.0], got {}",
                    i, conf
                ));
            }
        }
        if self.detected_risks.len() > MAX_DETECTED_RISKS {
            return Err(format!(
                "IntentClassification.detected_risks exceeds max ({} > {})",
                self.detected_risks.len(),
                MAX_DETECTED_RISKS
            ));
        }
        Ok(())
    }

    /// Returns true if the classification has high confidence (>= threshold).
    ///
    /// SECURITY (FIND-R64-003): NaN confidence returns false (not high confidence).
    pub fn is_high_confidence(&self, threshold: f64) -> bool {
        self.confidence.is_finite() && self.confidence >= threshold
    }

    /// Returns the maximum risk level across primary intent and detected risks.
    pub fn max_risk_level(&self) -> u8 {
        let intent_risk = self.primary_intent.risk_level();
        let risk_max = self
            .detected_risks
            .iter()
            .map(|r| r.severity())
            .max()
            .unwrap_or(0);
        intent_risk.max(risk_max)
    }

    /// Returns true if any malicious intent or high-severity risk is detected.
    pub fn is_suspicious(&self) -> bool {
        self.primary_intent.is_malicious() || self.detected_risks.iter().any(|r| r.severity() >= 80)
    }
}

// ═══════════════════════════════════════════════════
// INTENT CHAIN TRACKING
// ═══════════════════════════════════════════════════

/// Tracks intent patterns across a session for anomaly detection.
///
/// Maintains a sliding window of recent intents to detect suspicious
/// sequences like: DataRead → DataRead → NetworkSend (potential exfiltration).
#[derive(Debug, Clone, Default)]
pub struct IntentChain {
    /// Recent intents in chronological order.
    intents: Vec<IntentRecord>,
    /// Maximum number of intents to track.
    max_size: usize,
}

/// A single intent record with timestamp.
#[derive(Debug, Clone)]
pub struct IntentRecord {
    /// The classified intent.
    pub intent: Intent,
    /// Tool that triggered this intent.
    pub tool: String,
    /// Timestamp (Unix epoch seconds).
    pub timestamp: u64,
}

impl IntentChain {
    /// Creates a new intent chain with the specified maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            intents: Vec::with_capacity(max_size.min(100)),
            max_size: max_size.min(100),
        }
    }

    /// Adds an intent to the chain, evicting oldest if at capacity.
    pub fn push(&mut self, intent: Intent, tool: String, timestamp: u64) {
        if self.intents.len() >= self.max_size && !self.intents.is_empty() {
            self.intents.remove(0);
        }
        self.intents.push(IntentRecord {
            intent,
            tool,
            timestamp,
        });
    }

    /// Returns the number of tracked intents.
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// Returns true if no intents are tracked.
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Returns the most recent intents (up to n).
    pub fn recent(&self, n: usize) -> &[IntentRecord] {
        let start = self.intents.len().saturating_sub(n);
        &self.intents[start..]
    }

    /// Analyzes the chain for suspicious patterns.
    ///
    /// Returns a list of detected suspicious patterns with descriptions.
    pub fn detect_suspicious_patterns(&self) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();

        // Check for data gathering followed by network send (exfiltration)
        patterns.extend(self.detect_exfiltration_pattern());

        // Check for repeated credential access (brute force)
        patterns.extend(self.detect_repeated_credential_access());

        // Check for privilege escalation sequences
        patterns.extend(self.detect_escalation_sequence());

        patterns
    }

    fn detect_exfiltration_pattern(&self) -> Option<SuspiciousPattern> {
        let recent = self.recent(5);
        if recent.len() < 2 {
            return None;
        }

        let has_data_read = recent
            .iter()
            .any(|r| matches!(r.intent, Intent::DataRead | Intent::DataQuery));
        let ends_with_send = recent
            .last()
            .map(|r| matches!(r.intent, Intent::NetworkSend | Intent::Exfiltration))
            .unwrap_or(false);

        if has_data_read && ends_with_send {
            Some(SuspiciousPattern {
                pattern_type: "exfiltration_chain",
                description: "Data read followed by network send may indicate exfiltration"
                    .to_string(),
                severity: 80,
            })
        } else {
            None
        }
    }

    fn detect_repeated_credential_access(&self) -> Option<SuspiciousPattern> {
        let recent = self.recent(10);
        let cred_count = recent
            .iter()
            .filter(|r| matches!(r.intent, Intent::CredentialAccess))
            .count();

        if cred_count >= 3 {
            Some(SuspiciousPattern {
                pattern_type: "credential_enumeration",
                description: format!(
                    "Multiple credential access attempts ({}) may indicate brute force",
                    cred_count
                ),
                severity: 75,
            })
        } else {
            None
        }
    }

    fn detect_escalation_sequence(&self) -> Option<SuspiciousPattern> {
        let recent = self.recent(5);

        // Look for: SystemConfigure → PrivilegeEscalation or PolicyBypass
        let mut saw_configure = false;
        for record in recent {
            if matches!(record.intent, Intent::SystemConfigure) {
                saw_configure = true;
            } else if saw_configure
                && matches!(
                    record.intent,
                    Intent::PrivilegeEscalation | Intent::PolicyBypass
                )
            {
                return Some(SuspiciousPattern {
                    pattern_type: "privilege_escalation",
                    description: "System configuration followed by privilege escalation attempt"
                        .to_string(),
                    severity: 90,
                });
            }
        }

        None
    }

    /// Returns intent frequency distribution for the session.
    pub fn intent_distribution(&self) -> HashMap<Intent, usize> {
        let mut dist = HashMap::new();
        for record in &self.intents {
            *dist.entry(record.intent).or_insert(0) += 1;
        }
        dist
    }
}

/// A detected suspicious pattern in the intent chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    /// Pattern identifier.
    pub pattern_type: &'static str,
    /// Human-readable description.
    pub description: String,
    /// Severity score (0-100).
    pub severity: u8,
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_risk_levels() {
        assert!(Intent::Injection.risk_level() >= 90);
        assert!(Intent::Benign.risk_level() == 0);
        assert!(Intent::DataRead.risk_level() < Intent::DataDelete.risk_level());
    }

    #[test]
    fn test_intent_is_malicious() {
        assert!(Intent::Injection.is_malicious());
        assert!(Intent::Exfiltration.is_malicious());
        assert!(!Intent::DataRead.is_malicious());
        assert!(!Intent::Unknown.is_malicious());
    }

    #[test]
    fn test_intent_is_security_sensitive() {
        assert!(Intent::CredentialAccess.is_security_sensitive());
        assert!(Intent::Injection.is_security_sensitive());
        assert!(!Intent::DataRead.is_security_sensitive());
    }

    #[test]
    fn test_risk_category_severity() {
        assert!(RiskCategory::MaliciousPayload.severity() == 100);
        assert!(RiskCategory::PolicyViolation.severity() < RiskCategory::Jailbreak.severity());
    }

    #[test]
    fn test_intent_classification_default() {
        let classification = IntentClassification::default();
        assert_eq!(classification.primary_intent, Intent::Unknown);
        assert_eq!(classification.confidence, 0.0);
        assert!(classification.secondary_intents.is_empty());
    }

    #[test]
    fn test_intent_classification_benign() {
        let classification = IntentClassification::benign(0.95);
        assert_eq!(classification.primary_intent, Intent::Benign);
        assert_eq!(classification.confidence, 0.95);
        assert!(!classification.is_suspicious());
    }

    #[test]
    fn test_intent_classification_max_risk() {
        let mut classification = IntentClassification::benign(0.9);
        classification.detected_risks = vec![RiskCategory::DataLeakage];
        assert!(classification.max_risk_level() >= 85);
    }

    #[test]
    fn test_intent_classification_is_suspicious() {
        let mut classification = IntentClassification {
            primary_intent: Intent::Injection,
            ..Default::default()
        };
        assert!(classification.is_suspicious());

        classification.primary_intent = Intent::DataRead;
        classification.detected_risks = vec![RiskCategory::Jailbreak];
        assert!(classification.is_suspicious());
    }

    #[test]
    fn test_intent_chain_push_and_eviction() {
        let mut chain = IntentChain::new(3);
        chain.push(Intent::DataRead, "tool1".to_string(), 1000);
        chain.push(Intent::DataQuery, "tool2".to_string(), 1001);
        chain.push(Intent::NetworkSend, "tool3".to_string(), 1002);
        assert_eq!(chain.len(), 3);

        // Push one more, should evict oldest
        chain.push(Intent::DataWrite, "tool4".to_string(), 1003);
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.intents[0].intent, Intent::DataQuery);
    }

    #[test]
    fn test_intent_chain_recent() {
        let mut chain = IntentChain::new(10);
        for i in 0..5 {
            chain.push(Intent::DataRead, format!("tool{}", i), i as u64);
        }
        let recent = chain.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].tool, "tool2");
    }

    #[test]
    fn test_intent_chain_exfiltration_detection() {
        let mut chain = IntentChain::new(10);
        chain.push(Intent::DataRead, "fs".to_string(), 1000);
        chain.push(Intent::DataQuery, "db".to_string(), 1001);
        chain.push(Intent::NetworkSend, "http".to_string(), 1002);

        let patterns = chain.detect_suspicious_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns
            .iter()
            .any(|p| p.pattern_type == "exfiltration_chain"));
    }

    #[test]
    fn test_intent_chain_credential_enumeration() {
        let mut chain = IntentChain::new(10);
        for i in 0..4 {
            chain.push(Intent::CredentialAccess, format!("vault{}", i), i as u64);
        }

        let patterns = chain.detect_suspicious_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns
            .iter()
            .any(|p| p.pattern_type == "credential_enumeration"));
    }

    #[test]
    fn test_intent_chain_no_patterns_benign() {
        let mut chain = IntentChain::new(10);
        chain.push(Intent::DataRead, "fs".to_string(), 1000);
        chain.push(Intent::DataRead, "fs".to_string(), 1001);
        chain.push(Intent::DataQuery, "db".to_string(), 1002);

        let patterns = chain.detect_suspicious_patterns();
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_intent_chain_distribution() {
        let mut chain = IntentChain::new(10);
        chain.push(Intent::DataRead, "fs".to_string(), 1000);
        chain.push(Intent::DataRead, "fs".to_string(), 1001);
        chain.push(Intent::DataQuery, "db".to_string(), 1002);

        let dist = chain.intent_distribution();
        assert_eq!(dist.get(&Intent::DataRead), Some(&2));
        assert_eq!(dist.get(&Intent::DataQuery), Some(&1));
    }

    #[test]
    fn test_intent_serialization() {
        let intent = Intent::DataRead;
        let json = serde_json::to_string(&intent).expect("serialize");
        assert_eq!(json, "\"data_read\"");

        let parsed: Intent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, Intent::DataRead);
    }

    #[test]
    fn test_risk_category_serialization() {
        let risk = RiskCategory::PromptInjection;
        let json = serde_json::to_string(&risk).expect("serialize");
        assert_eq!(json, "\"prompt_injection\"");

        let parsed: RiskCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, RiskCategory::PromptInjection);
    }

    #[test]
    fn test_intent_classification_serialization() {
        let classification = IntentClassification {
            primary_intent: Intent::DataRead,
            confidence: 0.85,
            secondary_intents: vec![(Intent::NetworkFetch, 0.3)],
            detected_risks: vec![RiskCategory::DataLeakage],
            explanation: Some("Reading sensitive data".to_string()),
        };

        let json = serde_json::to_string(&classification).expect("serialize");
        let parsed: IntentClassification = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.primary_intent, Intent::DataRead);
        assert!((parsed.confidence - 0.85).abs() < f64::EPSILON);
        assert_eq!(parsed.secondary_intents.len(), 1);
        assert_eq!(parsed.detected_risks.len(), 1);
    }

    // ═══════════════════════════════════════════════════
    // IntentClassification::benign() clamping tests (IMP-R116-018)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_benign_nan_confidence_clamped_to_zero() {
        let ic = IntentClassification::benign(f64::NAN);
        assert_eq!(ic.confidence, 0.0);
    }

    #[test]
    fn test_benign_negative_confidence_clamped_to_zero() {
        let ic = IntentClassification::benign(-1.0);
        assert_eq!(ic.confidence, 0.0);
    }

    #[test]
    fn test_benign_over_one_confidence_clamped() {
        let ic = IntentClassification::benign(2.0);
        assert_eq!(ic.confidence, 1.0);
    }

    #[test]
    fn test_benign_infinity_confidence_clamped_to_zero() {
        let ic = IntentClassification::benign(f64::INFINITY);
        assert_eq!(ic.confidence, 0.0);
    }

    #[test]
    fn test_benign_neg_infinity_confidence_clamped_to_zero() {
        let ic = IntentClassification::benign(f64::NEG_INFINITY);
        assert_eq!(ic.confidence, 0.0);
    }

    #[test]
    fn test_benign_valid_confidence_unchanged() {
        let ic = IntentClassification::benign(0.75);
        assert!((ic.confidence - 0.75).abs() < f64::EPSILON);
        assert_eq!(ic.primary_intent, Intent::Benign);
    }

    // ═══════════════════════════════════════════════════
    // Additional coverage: Intent helpers, validation, chain
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_intent_description_returns_non_empty_for_all_variants() {
        let variants = [
            Intent::DataRead,
            Intent::DataWrite,
            Intent::DataDelete,
            Intent::DataExport,
            Intent::DataQuery,
            Intent::SystemExecute,
            Intent::SystemConfigure,
            Intent::SystemMonitor,
            Intent::NetworkFetch,
            Intent::NetworkSend,
            Intent::NetworkConnect,
            Intent::CredentialAccess,
            Intent::PrivilegeEscalation,
            Intent::PolicyBypass,
            Intent::Injection,
            Intent::Exfiltration,
            Intent::DenialOfService,
            Intent::Unknown,
            Intent::Benign,
        ];
        for variant in &variants {
            assert!(
                !variant.description().is_empty(),
                "Intent::{:?} description must be non-empty",
                variant
            );
        }
    }

    #[test]
    fn test_risk_category_description_returns_non_empty_for_all_variants() {
        let variants = [
            RiskCategory::PromptInjection,
            RiskCategory::Jailbreak,
            RiskCategory::DataLeakage,
            RiskCategory::UnauthorizedAccess,
            RiskCategory::PrivilegeEscalation,
            RiskCategory::MaliciousPayload,
            RiskCategory::SocialEngineering,
            RiskCategory::SystemAbuse,
            RiskCategory::PolicyViolation,
        ];
        for variant in &variants {
            assert!(
                !variant.description().is_empty(),
                "RiskCategory::{:?} description must be non-empty",
                variant
            );
        }
    }

    #[test]
    fn test_intent_default_is_unknown() {
        let intent = Intent::default();
        assert_eq!(intent, Intent::Unknown);
        // Unknown treated as medium risk (fail-closed)
        assert_eq!(intent.risk_level(), 50);
    }

    #[test]
    fn test_intent_classification_validate_nan_confidence_rejected() {
        let ic = IntentClassification {
            confidence: f64::NAN,
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_negative_confidence_rejected() {
        let ic = IntentClassification {
            confidence: -0.1,
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_over_one_confidence_rejected() {
        let ic = IntentClassification {
            confidence: 1.01,
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_too_many_secondary_intents() {
        let ic = IntentClassification {
            confidence: 0.5,
            secondary_intents: (0..51).map(|_| (Intent::DataRead, 0.1)).collect(),
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_bad_secondary_confidence() {
        let ic = IntentClassification {
            confidence: 0.5,
            secondary_intents: vec![(Intent::DataRead, f64::INFINITY)],
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_too_many_risks() {
        let ic = IntentClassification {
            confidence: 0.5,
            detected_risks: (0..51)
                .map(|_| RiskCategory::PolicyViolation)
                .collect(),
            ..Default::default()
        };
        assert!(ic.validate().is_err());
    }

    #[test]
    fn test_intent_classification_validate_valid_passes() {
        let ic = IntentClassification {
            primary_intent: Intent::DataRead,
            confidence: 0.8,
            secondary_intents: vec![(Intent::NetworkFetch, 0.3)],
            detected_risks: vec![RiskCategory::DataLeakage],
            explanation: Some("test".to_string()),
        };
        assert!(ic.validate().is_ok());
    }

    #[test]
    fn test_intent_classification_is_high_confidence_nan_returns_false() {
        let ic = IntentClassification {
            confidence: f64::NAN,
            ..Default::default()
        };
        assert!(!ic.is_high_confidence(0.5));
    }

    #[test]
    fn test_intent_classification_is_high_confidence_at_threshold() {
        let ic = IntentClassification {
            confidence: 0.8,
            ..Default::default()
        };
        assert!(ic.is_high_confidence(0.8));
        assert!(!ic.is_high_confidence(0.81));
    }

    #[test]
    fn test_intent_chain_new_caps_at_100() {
        let chain = IntentChain::new(500);
        assert_eq!(chain.max_size, 100);
    }

    #[test]
    fn test_intent_chain_is_empty() {
        let chain = IntentChain::new(10);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_intent_chain_detect_escalation_sequence() {
        let mut chain = IntentChain::new(10);
        chain.push(Intent::SystemConfigure, "config".to_string(), 1000);
        chain.push(Intent::PrivilegeEscalation, "escalate".to_string(), 1001);

        let patterns = chain.detect_suspicious_patterns();
        assert!(patterns
            .iter()
            .any(|p| p.pattern_type == "privilege_escalation"));
    }

    #[test]
    fn test_intent_chain_recent_more_than_available() {
        let mut chain = IntentChain::new(10);
        chain.push(Intent::DataRead, "fs".to_string(), 1000);

        let recent = chain.recent(100);
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_intent_classification_is_suspicious_benign_no_risks() {
        let ic = IntentClassification::benign(0.9);
        assert!(!ic.is_suspicious());
    }

    #[test]
    fn test_intent_classification_max_risk_level_no_risks() {
        let ic = IntentClassification {
            primary_intent: Intent::DataRead,
            confidence: 0.5,
            ..Default::default()
        };
        assert_eq!(ic.max_risk_level(), Intent::DataRead.risk_level());
    }

    #[test]
    fn test_intent_classification_unknown_produces_unknown() {
        let ic = IntentClassification::unknown();
        assert_eq!(ic.primary_intent, Intent::Unknown);
        assert_eq!(ic.confidence, 0.0);
    }
}
