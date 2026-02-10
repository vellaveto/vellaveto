//! Policy Configuration Validation
//!
//! Provides comprehensive validation for policy configurations including:
//! - Syntax validation (TOML parsing)
//! - Schema validation (required fields, valid types)
//! - Semantic validation (no conflicts, valid references)
//! - Best practice recommendations

use crate::{PolicyConfig, PolicyRule, PolicyType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Severity level for validation findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    /// Informational - best practice recommendations
    Info,
    /// Warning - potential issues that may cause unexpected behavior
    Warning,
    /// Error - configuration is invalid and will fail at runtime
    Error,
}

/// Category of validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCategory {
    /// Syntax errors (TOML parsing)
    Syntax,
    /// Schema errors (required fields, types)
    Schema,
    /// Semantic errors (conflicts, references)
    Semantic,
    /// Security issues
    Security,
    /// Best practices
    BestPractice,
}

/// A single validation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFinding {
    /// Severity of the finding.
    pub severity: ValidationSeverity,
    /// Category of the finding.
    pub category: ValidationCategory,
    /// Error code for programmatic handling.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Location in the config (policy name or path).
    pub location: Option<String>,
    /// Suggested fix.
    pub suggestion: Option<String>,
}

impl ValidationFinding {
    /// Create a new error finding.
    pub fn error(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Error,
            category: ValidationCategory::Schema,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Create a new warning finding.
    pub fn warning(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Warning,
            category: ValidationCategory::Semantic,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Create a new info finding.
    pub fn info(code: &str, message: &str) -> Self {
        ValidationFinding {
            severity: ValidationSeverity::Info,
            category: ValidationCategory::BestPractice,
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            suggestion: None,
        }
    }

    /// Set the location.
    pub fn at(mut self, location: &str) -> Self {
        self.location = Some(location.to_string());
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: ValidationCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the suggestion.
    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestion = Some(suggestion.to_string());
        self
    }
}

/// Result of policy configuration validation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationResult {
    /// All findings from validation.
    pub findings: Vec<ValidationFinding>,
    /// Summary statistics.
    pub summary: ValidationSummary,
}

/// Summary of validation results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationSummary {
    /// Total number of policies.
    pub total_policies: usize,
    /// Number of error findings.
    pub errors: usize,
    /// Number of warning findings.
    pub warnings: usize,
    /// Number of info findings.
    pub infos: usize,
    /// Whether the configuration is valid (no errors).
    pub valid: bool,
}

impl ValidationResult {
    /// Create a new empty validation result.
    pub fn new() -> Self {
        ValidationResult::default()
    }

    /// Add a finding.
    pub fn add(&mut self, finding: ValidationFinding) {
        match finding.severity {
            ValidationSeverity::Error => self.summary.errors += 1,
            ValidationSeverity::Warning => self.summary.warnings += 1,
            ValidationSeverity::Info => self.summary.infos += 1,
        }
        self.findings.push(finding);
    }

    /// Check if there are any errors.
    pub fn has_errors(&self) -> bool {
        self.summary.errors > 0
    }

    /// Check if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        self.summary.warnings > 0
    }

    /// Finalize the result.
    pub fn finalize(mut self) -> Self {
        self.summary.valid = self.summary.errors == 0;
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        self
    }

    /// Get findings by severity.
    pub fn by_severity(&self, severity: ValidationSeverity) -> Vec<&ValidationFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Format as human-readable text.
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        for finding in &self.findings {
            let severity = match finding.severity {
                ValidationSeverity::Error => "ERROR",
                ValidationSeverity::Warning => "WARNING",
                ValidationSeverity::Info => "INFO",
            };

            let location = finding
                .location
                .as_ref()
                .map(|l| format!(" at {}", l))
                .unwrap_or_default();

            output.push_str(&format!(
                "[{}] {}{}: {}\n",
                severity, finding.code, location, finding.message
            ));

            if let Some(ref suggestion) = finding.suggestion {
                output.push_str(&format!("  Suggestion: {}\n", suggestion));
            }
        }

        output.push_str(&format!(
            "\nSummary: {} errors, {} warnings, {} info\n",
            self.summary.errors, self.summary.warnings, self.summary.infos
        ));

        if self.summary.valid {
            output.push_str("Configuration is VALID\n");
        } else {
            output.push_str("Configuration is INVALID\n");
        }

        output
    }
}

/// Policy configuration validator.
pub struct PolicyValidator {
    /// Check for security issues.
    check_security: bool,
    /// Check for best practices.
    check_best_practices: bool,
    /// Strict mode (treat warnings as errors).
    strict: bool,
}

impl Default for PolicyValidator {
    fn default() -> Self {
        PolicyValidator {
            check_security: true,
            check_best_practices: true,
            strict: false,
        }
    }
}

impl PolicyValidator {
    /// Create a new validator.
    pub fn new() -> Self {
        PolicyValidator::default()
    }

    /// Enable/disable security checks.
    pub fn with_security_checks(mut self, enabled: bool) -> Self {
        self.check_security = enabled;
        self
    }

    /// Enable/disable best practice checks.
    pub fn with_best_practices(mut self, enabled: bool) -> Self {
        self.check_best_practices = enabled;
        self
    }

    /// Enable strict mode.
    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Validate a policy configuration.
    pub fn validate(&self, config: &PolicyConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        let policies = &config.policies;

        result.summary.total_policies = policies.len();

        // Check for empty configuration
        if policies.is_empty() {
            result.add(
                ValidationFinding::warning("EMPTY_CONFIG", "No policies defined")
                    .with_suggestion("Add at least one policy rule"),
            );
        }

        // Validate each policy
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut seen_priorities: HashMap<i32, Vec<String>> = HashMap::new();

        for (idx, policy) in policies.iter().enumerate() {
            let location = if policy.name.is_empty() {
                format!("policies[{}]", idx)
            } else {
                policy.name.clone()
            };

            // Check for duplicate IDs
            if let Some(ref id) = policy.id {
                if seen_ids.contains(id) {
                    result.add(
                        ValidationFinding::error(
                            "DUPLICATE_ID",
                            &format!("Duplicate policy ID: {}", id),
                        )
                        .at(&location),
                    );
                }
                seen_ids.insert(id.clone());
            }

            // Track priorities for conflict detection
            let priority = policy.effective_priority();
            seen_priorities
                .entry(priority)
                .or_default()
                .push(location.clone());

            // Validate policy fields
            self.validate_policy(policy, &location, &mut result);
        }

        // Check for priority conflicts
        for (priority, names) in seen_priorities {
            if names.len() > 1 {
                result.add(
                    ValidationFinding::warning(
                        "PRIORITY_CONFLICT",
                        &format!(
                            "Multiple policies with priority {}: {}",
                            priority,
                            names.join(", ")
                        ),
                    )
                    .with_suggestion(
                        "Consider using different priorities to ensure deterministic evaluation",
                    ),
                );
            }
        }

        // Security checks
        if self.check_security {
            self.check_security_issues(config, &mut result);
        }

        // Best practice checks
        if self.check_best_practices {
            self.check_best_practices_fn(config, &mut result);
        }

        // Convert warnings to errors in strict mode
        if self.strict {
            for finding in &mut result.findings {
                if finding.severity == ValidationSeverity::Warning {
                    finding.severity = ValidationSeverity::Error;
                    result.summary.errors += 1;
                    result.summary.warnings -= 1;
                }
            }
        }

        result.finalize()
    }

    /// Validate a single policy.
    fn validate_policy(&self, policy: &PolicyRule, location: &str, result: &mut ValidationResult) {
        // Check tool pattern
        if policy.tool_pattern.is_empty() {
            result
                .add(ValidationFinding::error("EMPTY_PATTERN", "Empty tool pattern").at(location));
        }

        if policy.tool_pattern == "*" && policy.policy_type == PolicyType::Allow {
            result.add(
                ValidationFinding::warning(
                    "WILDCARD_ALLOW",
                    "Policy allows all tools with wildcard",
                )
                .at(location)
                .with_category(ValidationCategory::Security)
                .with_suggestion("Consider using more specific tool patterns"),
            );
        }

        // Check function pattern
        if policy.function_pattern.is_empty() {
            result.add(
                ValidationFinding::error("EMPTY_PATTERN", "Empty function pattern").at(location),
            );
        }

        // Check path rules
        if let Some(ref path_rules) = policy.path_rules {
            if path_rules.allowed.is_empty() && path_rules.blocked.is_empty() {
                result.add(
                    ValidationFinding::warning(
                        "EMPTY_PATH_RULES",
                        "Path rules defined but no patterns specified",
                    )
                    .at(location),
                );
            }

            // Check for overlapping patterns
            for allow_pattern in &path_rules.allowed {
                for block_pattern in &path_rules.blocked {
                    if patterns_overlap(allow_pattern, block_pattern) {
                        result.add(
                            ValidationFinding::warning(
                                "OVERLAPPING_PATHS",
                                &format!(
                                    "Allowed pattern '{}' may overlap with blocked pattern '{}'",
                                    allow_pattern, block_pattern
                                ),
                            )
                            .at(location),
                        );
                    }
                }
            }
        }

        // Check network rules
        if let Some(ref network_rules) = policy.network_rules {
            if network_rules.allowed_domains.is_empty() && network_rules.blocked_domains.is_empty()
            {
                result.add(
                    ValidationFinding::warning(
                        "EMPTY_NETWORK_RULES",
                        "Network rules defined but no domains specified",
                    )
                    .at(location),
                );
            }

            // Check for invalid domain patterns
            for domain in &network_rules.allowed_domains {
                if !is_valid_domain_pattern(domain) {
                    result.add(
                        ValidationFinding::error(
                            "INVALID_DOMAIN",
                            &format!("Invalid domain pattern: {}", domain),
                        )
                        .at(location),
                    );
                }
            }

            for domain in &network_rules.blocked_domains {
                if !is_valid_domain_pattern(domain) {
                    result.add(
                        ValidationFinding::error(
                            "INVALID_DOMAIN",
                            &format!("Invalid domain pattern: {}", domain),
                        )
                        .at(location),
                    );
                }
            }
        }
    }

    /// Check for security issues.
    fn check_security_issues(&self, config: &PolicyConfig, result: &mut ValidationResult) {
        let policies = &config.policies;

        // Check for overly permissive policies
        let has_deny_all = policies
            .iter()
            .any(|p| p.policy_type == PolicyType::Deny && p.tool_pattern == "*");

        if !has_deny_all {
            result.add(
                ValidationFinding::info("NO_DENY_ALL", "No default deny-all policy found")
                    .with_category(ValidationCategory::Security)
                    .with_suggestion(
                        "Consider adding a low-priority deny-all policy as a safety net",
                    ),
            );
        }

        // Check for sensitive path exposure
        for policy in policies {
            if policy.policy_type == PolicyType::Allow {
                if let Some(ref path_rules) = policy.path_rules {
                    for pattern in &path_rules.allowed {
                        if is_sensitive_path(pattern) {
                            result.add(
                                ValidationFinding::warning(
                                    "SENSITIVE_PATH",
                                    &format!("Policy allows access to sensitive path: {}", pattern),
                                )
                                .at(&policy.name)
                                .with_category(ValidationCategory::Security),
                            );
                        }
                    }
                }
            }
        }

        // Check rate limiting
        let has_rate_limits = config.rate_limit.evaluate_rps.is_some()
            || config.rate_limit.admin_rps.is_some()
            || config.rate_limit.per_ip_rps.is_some();

        if !has_rate_limits {
            result.add(
                ValidationFinding::warning("NO_RATE_LIMITS", "No rate limits configured")
                    .with_category(ValidationCategory::Security)
                    .with_suggestion("Consider enabling rate limiting to prevent abuse"),
            );
        }
    }

    /// Check for best practices.
    fn check_best_practices_fn(&self, config: &PolicyConfig, result: &mut ValidationResult) {
        let policies = &config.policies;

        // Check for missing policy names
        for (idx, policy) in policies.iter().enumerate() {
            if policy.name.is_empty() {
                result.add(
                    ValidationFinding::info(
                        "MISSING_NAME",
                        &format!("Policy at index {} has no name", idx),
                    )
                    .with_suggestion("Add descriptive names to policies for easier debugging"),
                );
            }
        }

        // Check for missing policy IDs
        for (idx, policy) in policies.iter().enumerate() {
            if policy.id.is_none() {
                let location = if policy.name.is_empty() {
                    format!("policies[{}]", idx)
                } else {
                    policy.name.clone()
                };
                result.add(
                    ValidationFinding::info("MISSING_ID", "Policy has no ID")
                        .at(&location)
                        .with_suggestion("Add unique IDs for policy management"),
                );
            }
        }

        // Check for injection scanning
        if !config.injection.enabled {
            result.add(
                ValidationFinding::info("INJECTION_DISABLED", "Injection scanning is disabled")
                    .with_suggestion("Consider enabling injection scanning for better security"),
            );
        }
    }
}

/// Check if two glob patterns might overlap.
fn patterns_overlap(pattern1: &str, pattern2: &str) -> bool {
    // Simple overlap detection - check if one is a prefix/suffix of the other
    if pattern1.starts_with(pattern2.trim_end_matches('*'))
        || pattern2.starts_with(pattern1.trim_end_matches('*'))
    {
        return true;
    }

    // Check for common directory prefixes
    let parts1: Vec<&str> = pattern1.split('/').collect();
    let parts2: Vec<&str> = pattern2.split('/').collect();

    let common_len = parts1.len().min(parts2.len());
    for i in 0..common_len {
        if parts1[i] != parts2[i]
            && parts1[i] != "*"
            && parts1[i] != "**"
            && parts2[i] != "*"
            && parts2[i] != "**"
        {
            return false;
        }
    }

    true
}

/// Check if a domain pattern is valid.
fn is_valid_domain_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }

    // Allow wildcards
    if pattern == "*" {
        return true;
    }

    // Allow wildcard prefix
    let check_pattern = pattern.strip_prefix("*.").unwrap_or(pattern);

    // Basic domain validation
    if check_pattern.is_empty() {
        return false;
    }

    // Check for valid characters
    check_pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// Check if a path pattern points to sensitive locations.
fn is_sensitive_path(pattern: &str) -> bool {
    let sensitive_patterns = [
        "~/.ssh",
        "~/.aws",
        "~/.gnupg",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "**/.env",
        "**/credentials",
        "**/secrets",
        "**/private",
        "**/*.pem",
        "**/*.key",
        "**/id_rsa",
        "**/id_ed25519",
    ];

    for sensitive in sensitive_patterns {
        if pattern.contains(sensitive) || glob_matches(sensitive, pattern) {
            return true;
        }
    }

    false
}

/// Simple glob matching for pattern comparison.
fn glob_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("**/") {
        return path.contains(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix);
    }

    pattern == path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_finding_creation() {
        let finding = ValidationFinding::error("TEST_ERROR", "Test error message")
            .at("test_location")
            .with_suggestion("Fix it");

        assert_eq!(finding.severity, ValidationSeverity::Error);
        assert_eq!(finding.code, "TEST_ERROR");
        assert_eq!(finding.location, Some("test_location".to_string()));
        assert_eq!(finding.suggestion, Some("Fix it".to_string()));
    }

    #[test]
    fn test_validation_result_add() {
        let mut result = ValidationResult::new();
        result.add(ValidationFinding::error("E1", "Error 1"));
        result.add(ValidationFinding::warning("W1", "Warning 1"));
        result.add(ValidationFinding::info("I1", "Info 1"));

        assert_eq!(result.summary.errors, 1);
        assert_eq!(result.summary.warnings, 1);
        assert_eq!(result.summary.infos, 1);
    }

    #[test]
    fn test_validation_result_has_errors() {
        let mut result = ValidationResult::new();
        assert!(!result.has_errors());

        result.add(ValidationFinding::error("E1", "Error 1"));
        assert!(result.has_errors());
    }

    #[test]
    fn test_patterns_overlap() {
        assert!(patterns_overlap("/home/*", "/home/user"));
        assert!(patterns_overlap("/var/log/**", "/var/log/app.log"));
        assert!(!patterns_overlap("/home/*", "/etc/*"));
    }

    #[test]
    fn test_is_valid_domain_pattern() {
        assert!(is_valid_domain_pattern("example.com"));
        assert!(is_valid_domain_pattern("*.example.com"));
        assert!(is_valid_domain_pattern("sub.example.com"));
        assert!(is_valid_domain_pattern("*"));
        assert!(!is_valid_domain_pattern(""));
        assert!(!is_valid_domain_pattern("*."));
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("~/.ssh/id_rsa"));
        assert!(is_sensitive_path("~/.aws/credentials"));
        assert!(is_sensitive_path("/etc/shadow"));
        assert!(is_sensitive_path("**/.env"));
        assert!(!is_sensitive_path("/home/user/documents"));
    }

    fn empty_config() -> PolicyConfig {
        PolicyConfig::from_toml("policies = []").unwrap()
    }

    fn minimal_config() -> PolicyConfig {
        PolicyConfig::from_toml(
            r#"
[[policies]]
name = "test"
tool_pattern = "test"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap()
    }

    #[test]
    fn test_validator_empty_config() {
        let config = empty_config();
        let validator = PolicyValidator::new();
        let result = validator.validate(&config);

        assert!(result.has_warnings());
        assert!(result.findings.iter().any(|f| f.code == "EMPTY_CONFIG"));
    }

    #[test]
    fn test_validator_strict_mode() {
        let config = minimal_config();

        let validator = PolicyValidator::new().strict();
        let result = validator.validate(&config);

        // In strict mode, warnings become errors
        assert!(result.summary.warnings == 0);
    }

    #[test]
    fn test_validation_result_to_text() {
        let mut result = ValidationResult::new();
        result.add(ValidationFinding::error("E1", "Error 1").at("policy1"));
        result.add(ValidationFinding::warning("W1", "Warning 1").with_suggestion("Fix it"));

        let result = result.finalize();
        let text = result.to_text();

        assert!(text.contains("[ERROR]"));
        assert!(text.contains("[WARNING]"));
        assert!(text.contains("Suggestion: Fix it"));
    }
}
