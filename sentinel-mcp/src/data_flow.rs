//! Cross-request data flow tracking for exfiltration detection (P4.2).
//!
//! Tracks DLP findings from tool responses and correlates them with subsequent
//! outbound requests to detect potential data exfiltration chains.
//!
//! # Exfiltration Chain Detection
//!
//! An exfiltration chain occurs when:
//! 1. A tool response contains sensitive data (detected by DLP scanning)
//! 2. A subsequent request targets an external domain
//! 3. The request parameters contain data matching the same DLP pattern
//!
//! This module provides session-level correlation to detect these chains,
//! moving from point-in-time DLP scanning to session-level flow analysis.
//!
//! # Design
//!
//! - **Pattern-level correlation**: Matches response DLP pattern types against
//!   request DLP pattern types (e.g., `aws_access_key` in response then request)
//! - **Fingerprint correlation**: SHA-256 fingerprints of exact matched values
//!   for precise detection of the same secret being exfiltrated
//! - **Bounded memory**: Ring buffer with configurable capacity
//! - **Deterministic**: No ML, no randomness — fully auditable

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::inspection::DlpFinding;

// ═══════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════

/// Configuration for data flow tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowConfig {
    /// Maximum number of response findings to retain per session.
    /// Oldest findings are evicted when capacity is reached.
    /// Default: 500
    #[serde(default = "default_max_findings")]
    pub max_findings: usize,

    /// Maximum number of fingerprints to retain per DLP pattern.
    /// Default: 100
    #[serde(default = "default_max_fingerprints_per_pattern")]
    pub max_fingerprints_per_pattern: usize,

    /// When true, require exact fingerprint match (same secret value) in
    /// addition to pattern-type match. When false, any matching DLP pattern
    /// type triggers an alert. Default: false (pattern-level correlation is
    /// sufficient for most use cases).
    #[serde(default)]
    pub require_exact_match: bool,
}

fn default_max_findings() -> usize {
    500
}
fn default_max_fingerprints_per_pattern() -> usize {
    100
}

impl Default for DataFlowConfig {
    fn default() -> Self {
        Self {
            max_findings: default_max_findings(),
            max_fingerprints_per_pattern: default_max_fingerprints_per_pattern(),
            require_exact_match: false,
        }
    }
}

// ═══════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════

/// Errors from data flow tracking operations.
#[derive(Debug, Clone, PartialEq)]
pub enum DataFlowError {
    /// max_findings must be > 0.
    InvalidMaxFindings,
    /// max_fingerprints_per_pattern must be > 0.
    InvalidMaxFingerprints,
}

impl std::fmt::Display for DataFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataFlowError::InvalidMaxFindings => write!(f, "max_findings must be > 0"),
            DataFlowError::InvalidMaxFingerprints => {
                write!(f, "max_fingerprints_per_pattern must be > 0")
            }
        }
    }
}

impl std::error::Error for DataFlowError {}

impl DataFlowConfig {
    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), DataFlowError> {
        if self.max_findings == 0 {
            return Err(DataFlowError::InvalidMaxFindings);
        }
        if self.max_fingerprints_per_pattern == 0 {
            return Err(DataFlowError::InvalidMaxFingerprints);
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// ALERT TYPE
// ═══════════════════════════════════════════════════

/// An alert indicating potential data exfiltration across requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationAlert {
    /// The DLP pattern type that correlates response and request
    /// (e.g., "aws_access_key", "github_token").
    pub pattern_name: String,
    /// Tool that produced the response containing the sensitive data.
    pub source_tool: String,
    /// Tool making the outbound request.
    pub requesting_tool: String,
    /// Target domain(s) in the outbound request.
    pub target_domains: Vec<String>,
    /// Whether the exact same secret value was detected (fingerprint match).
    pub exact_match: bool,
}

impl std::fmt::Display for ExfiltrationAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Potential exfiltration: '{}' pattern found in response from '{}', \
             now in request from '{}' targeting {:?}{}",
            self.pattern_name,
            self.source_tool,
            self.requesting_tool,
            self.target_domains,
            if self.exact_match {
                " [EXACT MATCH]"
            } else {
                ""
            },
        )
    }
}

// ═══════════════════════════════════════════════════
// EXTENDED DLP FINDING
// ═══════════════════════════════════════════════════

/// A DLP finding enriched with a fingerprint of the matched value.
///
/// Created by [`DlpFindingWithFingerprint::from_finding`] when the caller
/// has access to the matched text. The fingerprint is a SHA-256 hash —
/// the actual secret value is never stored.
#[derive(Debug, Clone)]
pub struct DlpFindingWithFingerprint {
    /// The original DLP finding.
    pub finding: DlpFinding,
    /// SHA-256 fingerprint of the matched secret value.
    /// None if the matched text was not available for fingerprinting.
    pub fingerprint: Option<[u8; 32]>,
}

impl DlpFindingWithFingerprint {
    /// Create from a DLP finding with optional matched text for fingerprinting.
    pub fn from_finding(finding: DlpFinding, matched_text: Option<&str>) -> Self {
        let fingerprint = matched_text.map(|text| {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            let result = hasher.finalize();
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&result);
            fp
        });
        Self {
            finding,
            fingerprint,
        }
    }

    /// Create from a DLP finding without fingerprint.
    pub fn without_fingerprint(finding: DlpFinding) -> Self {
        Self {
            finding,
            fingerprint: None,
        }
    }
}

// ═══════════════════════════════════════════════════
// INTERNAL STATE
// ═══════════════════════════════════════════════════

/// A recorded response DLP finding.
#[derive(Debug, Clone)]
struct ResponseRecord {
    /// DLP pattern name (e.g., "aws_access_key").
    pattern_name: String,
    /// Tool that produced the response.
    source_tool: String,
}

// ═══════════════════════════════════════════════════
// TRACKER
// ═══════════════════════════════════════════════════

/// Tracks sensitive data flow across requests within a session.
///
/// Records DLP findings from tool responses and correlates them with
/// outbound requests to detect potential exfiltration chains.
///
/// # Usage
///
/// ```
/// use sentinel_mcp::data_flow::{DataFlowTracker, DataFlowConfig, DlpFindingWithFingerprint};
/// use sentinel_mcp::inspection::DlpFinding;
///
/// let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).unwrap();
///
/// // Record DLP findings from a tool response
/// let finding = DlpFinding {
///     pattern_name: "aws_access_key".to_string(),
///     location: "result.content[0].text".to_string(),
/// };
/// let enriched = DlpFindingWithFingerprint::from_finding(finding, Some("AKIAIOSFODNN7EXAMPLE"));
/// tracker.record_response_findings("read_secrets", &[enriched]);
///
/// // Check if a subsequent request might be exfiltrating
/// let req_finding = DlpFinding {
///     pattern_name: "aws_access_key".to_string(),
///     location: "$.content".to_string(),
/// };
/// let req_enriched = DlpFindingWithFingerprint::from_finding(req_finding, Some("AKIAIOSFODNN7EXAMPLE"));
/// let alerts = tracker.check_request(
///     "http_request",
///     &[req_enriched],
///     &["evil.example.com".to_string()],
/// );
/// assert!(!alerts.is_empty());
/// ```
pub struct DataFlowTracker {
    config: DataFlowConfig,
    /// Recorded response findings in insertion order.
    records: Vec<ResponseRecord>,
    /// Pattern name → set of fingerprints (for exact match mode).
    fingerprints: HashMap<String, Vec<[u8; 32]>>,
    /// Set of active pattern names for fast O(1) lookup.
    active_patterns: HashSet<String>,
}

impl DataFlowTracker {
    /// Create a new tracker. Returns an error if the configuration is invalid.
    pub fn new(config: DataFlowConfig) -> Result<Self, DataFlowError> {
        config.validate()?;
        Ok(Self {
            config,
            records: Vec::new(),
            fingerprints: HashMap::new(),
            active_patterns: HashSet::new(),
        })
    }

    /// Record DLP findings from a tool response.
    ///
    /// Call this after scanning a tool response with DLP. Only findings with
    /// non-empty pattern names are recorded.
    pub fn record_response_findings(
        &mut self,
        source_tool: &str,
        findings: &[DlpFindingWithFingerprint],
    ) {
        for f in findings {
            if f.finding.pattern_name.is_empty() {
                continue;
            }

            // Enforce capacity limit — evict oldest
            if self.records.len() >= self.config.max_findings {
                self.evict_oldest();
            }

            // Record the finding
            self.active_patterns.insert(f.finding.pattern_name.clone());

            if let Some(fp) = f.fingerprint {
                let fps = self
                    .fingerprints
                    .entry(f.finding.pattern_name.clone())
                    .or_default();
                // Enforce per-pattern fingerprint limit
                if fps.len() >= self.config.max_fingerprints_per_pattern {
                    fps.remove(0); // Remove oldest
                }
                fps.push(fp);
            }

            self.records.push(ResponseRecord {
                pattern_name: f.finding.pattern_name.clone(),
                source_tool: source_tool.to_string(),
            });
        }
    }

    /// Record DLP findings without fingerprints (convenience method).
    ///
    /// Use this when matched text is not available for fingerprinting.
    pub fn record_response_findings_simple(&mut self, source_tool: &str, findings: &[DlpFinding]) {
        let enriched: Vec<DlpFindingWithFingerprint> = findings
            .iter()
            .map(|f| DlpFindingWithFingerprint::without_fingerprint(f.clone()))
            .collect();
        self.record_response_findings(source_tool, &enriched);
    }

    /// Check if an outbound request might be exfiltrating previously-seen secrets.
    ///
    /// Returns alerts when:
    /// 1. A DLP pattern in `request_findings` matches a pattern previously seen
    ///    in a tool response
    /// 2. The request targets one or more external domains
    ///
    /// When `config.require_exact_match` is true, additionally requires that
    /// the exact same secret value (by SHA-256 fingerprint) was seen in the
    /// response.
    pub fn check_request(
        &self,
        requesting_tool: &str,
        request_findings: &[DlpFindingWithFingerprint],
        target_domains: &[String],
    ) -> Vec<ExfiltrationAlert> {
        let mut alerts = Vec::new();

        // No target domains means no exfiltration vector
        if target_domains.is_empty() {
            return alerts;
        }

        // No response findings recorded yet
        if self.records.is_empty() {
            return alerts;
        }

        for req_finding in request_findings {
            let pattern = &req_finding.finding.pattern_name;
            if pattern.is_empty() {
                continue;
            }

            // Check if this pattern was seen in any response
            if !self.active_patterns.contains(pattern) {
                continue;
            }

            // Find the source tool(s) that produced this pattern
            let source_tools: Vec<String> = self
                .records
                .iter()
                .filter(|r| r.pattern_name == *pattern)
                .map(|r| r.source_tool.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if source_tools.is_empty() {
                continue;
            }

            // Check fingerprint match if required
            let exact_match = if let (Some(req_fp), Some(stored_fps)) =
                (&req_finding.fingerprint, self.fingerprints.get(pattern))
            {
                stored_fps.contains(req_fp)
            } else {
                false
            };

            if self.config.require_exact_match && !exact_match {
                continue;
            }

            // Generate an alert for each source tool
            for source_tool in &source_tools {
                alerts.push(ExfiltrationAlert {
                    pattern_name: pattern.clone(),
                    source_tool: source_tool.clone(),
                    requesting_tool: requesting_tool.to_string(),
                    target_domains: target_domains.to_vec(),
                    exact_match,
                });
            }
        }

        alerts
    }

    /// Convenience method: check request using plain DLP findings (no fingerprints).
    pub fn check_request_simple(
        &self,
        requesting_tool: &str,
        request_findings: &[DlpFinding],
        target_domains: &[String],
    ) -> Vec<ExfiltrationAlert> {
        let enriched: Vec<DlpFindingWithFingerprint> = request_findings
            .iter()
            .map(|f| DlpFindingWithFingerprint::without_fingerprint(f.clone()))
            .collect();
        self.check_request(requesting_tool, &enriched, target_domains)
    }

    /// Number of unique DLP pattern types seen in responses.
    pub fn active_pattern_count(&self) -> usize {
        self.active_patterns.len()
    }

    /// Total number of recorded response findings.
    pub fn finding_count(&self) -> usize {
        self.records.len()
    }

    /// Access the current configuration.
    pub fn config(&self) -> &DataFlowConfig {
        &self.config
    }

    /// Evict the oldest record and clean up associated state.
    fn evict_oldest(&mut self) {
        if self.records.is_empty() {
            return;
        }

        let removed = self.records.remove(0);

        // Check if this pattern still has other records
        let pattern_still_active = self
            .records
            .iter()
            .any(|r| r.pattern_name == removed.pattern_name);

        if !pattern_still_active {
            self.active_patterns.remove(&removed.pattern_name);
            self.fingerprints.remove(&removed.pattern_name);
        }
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(pattern: &str, location: &str) -> DlpFinding {
        DlpFinding {
            pattern_name: pattern.to_string(),
            location: location.to_string(),
        }
    }

    fn enriched(pattern: &str, location: &str, text: Option<&str>) -> DlpFindingWithFingerprint {
        DlpFindingWithFingerprint::from_finding(finding(pattern, location), text)
    }

    fn domains(ds: &[&str]) -> Vec<String> {
        ds.iter().map(|s| s.to_string()).collect()
    }

    // ── Config validation ─────────────────────────

    #[test]
    fn test_default_config_valid() {
        assert!(DataFlowConfig::default().validate().is_ok());
    }

    #[test]
    fn test_config_invalid_max_findings() {
        let mut c = DataFlowConfig::default();
        c.max_findings = 0;
        assert!(matches!(
            c.validate(),
            Err(DataFlowError::InvalidMaxFindings)
        ));
    }

    #[test]
    fn test_config_invalid_max_fingerprints() {
        let mut c = DataFlowConfig::default();
        c.max_fingerprints_per_pattern = 0;
        assert!(matches!(
            c.validate(),
            Err(DataFlowError::InvalidMaxFingerprints)
        ));
    }

    // ── Basic detection ───────────────────────────

    #[test]
    fn test_exfiltration_chain_detected() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        // Response contains AWS key
        tracker.record_response_findings(
            "read_secrets",
            &[enriched(
                "aws_access_key",
                "result.content[0].text",
                Some("AKIAIOSFODNN7EXAMPLE"),
            )],
        );

        // Subsequent request also contains AWS key, targeting external domain
        let req_findings = vec![enriched(
            "aws_access_key",
            "$.body",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        let alerts = tracker.check_request(
            "http_request",
            &req_findings,
            &domains(&["evil.example.com"]),
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].pattern_name, "aws_access_key");
        assert_eq!(alerts[0].source_tool, "read_secrets");
        assert_eq!(alerts[0].requesting_tool, "http_request");
        assert_eq!(alerts[0].target_domains, vec!["evil.example.com"]);
        assert!(alerts[0].exact_match);
    }

    #[test]
    fn test_no_alert_without_target_domains() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        tracker.record_response_findings(
            "read_secrets",
            &[enriched("aws_access_key", "text", Some("AKIAKEY"))],
        );

        // Request has matching pattern but no target domains
        let alerts = tracker.check_request(
            "process_data",
            &[enriched("aws_access_key", "$.body", Some("AKIAKEY"))],
            &[],
        );

        assert!(alerts.is_empty(), "No domains = no exfiltration vector");
    }

    #[test]
    fn test_no_alert_without_response_findings() {
        let tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        // Request has findings but no response findings were recorded
        let alerts = tracker.check_request(
            "http_request",
            &[enriched("aws_access_key", "$.body", Some("AKIAKEY"))],
            &domains(&["example.com"]),
        );

        assert!(alerts.is_empty());
    }

    #[test]
    fn test_no_alert_for_different_pattern() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        // Response has AWS key
        tracker.record_response_findings(
            "read_secrets",
            &[enriched("aws_access_key", "text", Some("AKIAKEY"))],
        );

        // Request has GitHub token — different pattern
        let alerts = tracker.check_request(
            "http_request",
            &[enriched("github_token", "$.body", Some("ghp_xxxx"))],
            &domains(&["example.com"]),
        );

        assert!(
            alerts.is_empty(),
            "Different pattern should not trigger alert"
        );
    }

    // ── Pattern-level vs fingerprint matching ─────

    #[test]
    fn test_pattern_level_match_without_fingerprint() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        // Response finding without fingerprint
        tracker.record_response_findings("read_file", &[enriched("aws_access_key", "text", None)]);

        // Request finding without fingerprint — still matches at pattern level
        let alerts = tracker.check_request(
            "send_data",
            &[enriched("aws_access_key", "$.body", None)],
            &domains(&["attacker.com"]),
        );

        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].exact_match);
    }

    #[test]
    fn test_exact_match_mode_rejects_different_values() {
        let config = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        tracker.record_response_findings(
            "read_file",
            &[enriched(
                "aws_access_key",
                "text",
                Some("AKIAIOSFODNN7EXAMPLE"),
            )],
        );

        // Different AWS key value — pattern matches but fingerprint doesn't
        let alerts = tracker.check_request(
            "send_data",
            &[enriched(
                "aws_access_key",
                "$.body",
                Some("AKIADIFFERENTKEY1234"),
            )],
            &domains(&["attacker.com"]),
        );

        assert!(
            alerts.is_empty(),
            "Exact match mode should reject different values"
        );
    }

    #[test]
    fn test_exact_match_mode_accepts_same_value() {
        let config = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        let secret = "AKIAIOSFODNN7EXAMPLE";
        tracker.record_response_findings(
            "read_file",
            &[enriched("aws_access_key", "text", Some(secret))],
        );

        let alerts = tracker.check_request(
            "send_data",
            &[enriched("aws_access_key", "$.body", Some(secret))],
            &domains(&["attacker.com"]),
        );

        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].exact_match);
    }

    #[test]
    fn test_exact_match_mode_rejects_no_fingerprint() {
        let config = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        // Response with fingerprint
        tracker.record_response_findings(
            "read_file",
            &[enriched("aws_access_key", "text", Some("AKIAKEY"))],
        );

        // Request without fingerprint — can't verify exact match
        let alerts = tracker.check_request(
            "send_data",
            &[enriched("aws_access_key", "$.body", None)],
            &domains(&["attacker.com"]),
        );

        assert!(
            alerts.is_empty(),
            "No fingerprint on request = can't confirm exact match"
        );
    }

    // ── Multiple patterns/sources ─────────────────

    #[test]
    fn test_multiple_patterns_detected() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        tracker.record_response_findings(
            "vault_read",
            &[
                enriched("aws_access_key", "text", Some("AKIAKEY")),
                enriched("github_token", "text", Some("ghp_token123")),
            ],
        );

        // Request contains both patterns
        let alerts = tracker.check_request(
            "curl",
            &[
                enriched("aws_access_key", "$.body", Some("AKIAKEY")),
                enriched("github_token", "$.url", Some("ghp_token123")),
            ],
            &domains(&["attacker.com"]),
        );

        assert_eq!(alerts.len(), 2);
        let patterns: HashSet<&str> = alerts.iter().map(|a| a.pattern_name.as_str()).collect();
        assert!(patterns.contains("aws_access_key"));
        assert!(patterns.contains("github_token"));
    }

    #[test]
    fn test_multiple_source_tools_for_same_pattern() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        // Two different tools produced AWS keys
        tracker.record_response_findings(
            "read_env",
            &[enriched("aws_access_key", "text", Some("AKIAKEY1"))],
        );
        tracker.record_response_findings(
            "read_config",
            &[enriched("aws_access_key", "text", Some("AKIAKEY2"))],
        );

        let alerts = tracker.check_request(
            "send",
            &[enriched("aws_access_key", "$.body", None)],
            &domains(&["attacker.com"]),
        );

        // Should get alerts referencing both source tools
        assert_eq!(alerts.len(), 2);
        let sources: HashSet<&str> = alerts.iter().map(|a| a.source_tool.as_str()).collect();
        assert!(sources.contains("read_env"));
        assert!(sources.contains("read_config"));
    }

    #[test]
    fn test_multiple_target_domains() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        tracker.record_response_findings(
            "read_file",
            &[enriched("aws_access_key", "text", Some("AKIAKEY"))],
        );

        let alerts = tracker.check_request(
            "send",
            &[enriched("aws_access_key", "$.body", Some("AKIAKEY"))],
            &domains(&["evil1.com", "evil2.com"]),
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].target_domains,
            vec!["evil1.com".to_string(), "evil2.com".to_string()]
        );
    }

    // ── Eviction ──────────────────────────────────

    #[test]
    fn test_finding_eviction_when_full() {
        let config = DataFlowConfig {
            max_findings: 2,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        tracker
            .record_response_findings("tool-a", &[enriched("pattern_a", "text", Some("secret_a"))]);
        tracker
            .record_response_findings("tool-b", &[enriched("pattern_b", "text", Some("secret_b"))]);
        // This should evict pattern_a (oldest)
        tracker
            .record_response_findings("tool-c", &[enriched("pattern_c", "text", Some("secret_c"))]);

        assert_eq!(tracker.finding_count(), 2);
        assert!(!tracker.active_patterns.contains("pattern_a"));
        assert!(tracker.active_patterns.contains("pattern_b"));
        assert!(tracker.active_patterns.contains("pattern_c"));
    }

    #[test]
    fn test_pattern_survives_partial_eviction() {
        let config = DataFlowConfig {
            max_findings: 2,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        // Two findings for same pattern
        tracker.record_response_findings("tool-a", &[enriched("aws_key", "text1", Some("key1"))]);
        tracker.record_response_findings("tool-b", &[enriched("aws_key", "text2", Some("key2"))]);

        // Evict first, but pattern still has second record
        tracker.record_response_findings("tool-c", &[enriched("other", "text3", Some("xxx"))]);

        assert!(
            tracker.active_patterns.contains("aws_key"),
            "Pattern should survive when other records remain"
        );
    }

    #[test]
    fn test_fingerprint_eviction() {
        let config = DataFlowConfig {
            max_fingerprints_per_pattern: 2,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");

        tracker.record_response_findings("tool", &[enriched("aws_key", "a", Some("secret1"))]);
        tracker.record_response_findings("tool", &[enriched("aws_key", "b", Some("secret2"))]);
        // This should evict fingerprint of "secret1"
        tracker.record_response_findings("tool", &[enriched("aws_key", "c", Some("secret3"))]);

        let fps = tracker.fingerprints.get("aws_key").expect("should exist");
        assert_eq!(fps.len(), 2);

        // secret1's fingerprint should be gone — exact match should fail
        let config2 = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker2 = DataFlowTracker::new(config2).expect("valid config");
        tracker2.record_response_findings("tool", &[enriched("aws_key", "a", Some("secret1"))]);
        tracker2.record_response_findings("tool", &[enriched("aws_key", "b", Some("secret2"))]);
        // Since max_fingerprints is default (100), both should be present
        let alerts = tracker2.check_request(
            "send",
            &[enriched("aws_key", "$.body", Some("secret1"))],
            &domains(&["evil.com"]),
        );
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].exact_match);
    }

    // ── Simple API ────────────────────────────────

    #[test]
    fn test_simple_api_record_and_check() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        let resp_findings = vec![finding("aws_access_key", "result.text")];
        tracker.record_response_findings_simple("tool_a", &resp_findings);

        let req_findings = vec![finding("aws_access_key", "$.body")];
        let alerts =
            tracker.check_request_simple("tool_b", &req_findings, &domains(&["attacker.com"]));

        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].exact_match); // No fingerprints in simple API
    }

    // ── Edge cases ────────────────────────────────

    #[test]
    fn test_empty_pattern_name_ignored() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        tracker.record_response_findings("tool", &[enriched("", "text", Some("data"))]);
        assert_eq!(tracker.finding_count(), 0);
        assert_eq!(tracker.active_pattern_count(), 0);
    }

    #[test]
    fn test_empty_request_findings_no_alert() {
        let mut tracker = DataFlowTracker::new(DataFlowConfig::default()).expect("valid config");

        tracker.record_response_findings("tool", &[enriched("aws_key", "text", Some("AKIAKEY"))]);

        let alerts = tracker.check_request("send", &[], &domains(&["evil.com"]));
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_accessors() {
        let config = DataFlowConfig {
            max_findings: 42,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("valid config");
        assert_eq!(tracker.config().max_findings, 42);
        assert_eq!(tracker.finding_count(), 0);
        assert_eq!(tracker.active_pattern_count(), 0);

        tracker.record_response_findings("tool", &[enriched("aws_key", "text", Some("AKIAKEY"))]);
        assert_eq!(tracker.finding_count(), 1);
        assert_eq!(tracker.active_pattern_count(), 1);
    }

    // ── Display ───────────────────────────────────

    #[test]
    fn test_exfiltration_alert_display() {
        let alert = ExfiltrationAlert {
            pattern_name: "aws_access_key".to_string(),
            source_tool: "read_secrets".to_string(),
            requesting_tool: "http_post".to_string(),
            target_domains: vec!["evil.com".to_string()],
            exact_match: true,
        };
        let display = format!("{}", alert);
        assert!(display.contains("aws_access_key"));
        assert!(display.contains("read_secrets"));
        assert!(display.contains("http_post"));
        assert!(display.contains("evil.com"));
        assert!(display.contains("EXACT MATCH"));
    }

    #[test]
    fn test_exfiltration_alert_display_no_exact() {
        let alert = ExfiltrationAlert {
            pattern_name: "github_token".to_string(),
            source_tool: "list_env".to_string(),
            requesting_tool: "curl".to_string(),
            target_domains: vec!["attacker.com".to_string()],
            exact_match: false,
        };
        let display = format!("{}", alert);
        assert!(!display.contains("EXACT MATCH"));
    }

    #[test]
    fn test_error_display() {
        let e = DataFlowError::InvalidMaxFindings;
        assert!(format!("{}", e).contains("max_findings"));
        let e = DataFlowError::InvalidMaxFingerprints;
        assert!(format!("{}", e).contains("max_fingerprints"));
    }

    // ── Fingerprint determinism ───────────────────

    #[test]
    fn test_fingerprint_deterministic() {
        let f1 =
            DlpFindingWithFingerprint::from_finding(finding("test", "loc"), Some("secret_value"));
        let f2 =
            DlpFindingWithFingerprint::from_finding(finding("test", "loc"), Some("secret_value"));
        assert_eq!(f1.fingerprint, f2.fingerprint);

        let f3 = DlpFindingWithFingerprint::from_finding(
            finding("test", "loc"),
            Some("different_value"),
        );
        assert_ne!(f1.fingerprint, f3.fingerprint);
    }

    #[test]
    fn test_fingerprint_none_when_no_text() {
        let f = DlpFindingWithFingerprint::from_finding(finding("test", "loc"), None);
        assert!(f.fingerprint.is_none());
    }
}
