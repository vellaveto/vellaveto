//! Natural Language Policy compiler for semantic guardrails (Phase 12).
//!
//! Enables defining security policies in plain English that are compiled
//! into evaluatable rules for the LLM backend.
//!
//! # Policy Format
//!
//! Policies are defined with:
//! - **id**: Unique identifier
//! - **name**: Human-readable name
//! - **statement**: Natural language policy description
//! - **tool_patterns**: Glob patterns for matching tools (e.g., "filesystem:*")
//!
//! # Example
//!
//! ```rust
//! use vellaveto_mcp::semantic_guardrails::nl_policy::{NlPolicy, NlPolicyCompiler};
//!
//! let mut compiler = NlPolicyCompiler::new();
//!
//! compiler.add_policy(NlPolicy {
//!     id: "no-file-delete".to_string(),
//!     name: "Prevent file deletion".to_string(),
//!     statement: "Never allow file deletion outside of /tmp directory".to_string(),
//!     tool_patterns: vec!["filesystem:*".to_string(), "shell:*".to_string()],
//!     enabled: true,
//!     priority: 100,
//! });
//!
//! let matches = compiler.match_policies("filesystem", "delete");
//! assert!(!matches.is_empty());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════
// POLICY DEFINITION
// ═══════════════════════════════════════════════════

/// Maximum NlPolicy ID length.
const MAX_NL_POLICY_ID_LEN: usize = 256;
/// Maximum NlPolicy name length.
const MAX_NL_POLICY_NAME_LEN: usize = 256;
/// Maximum NlPolicy statement length.
const MAX_NL_POLICY_STATEMENT_LEN: usize = 64_000;
/// Maximum number of tool patterns per NlPolicy.
const MAX_NL_POLICY_TOOL_PATTERNS: usize = 100;
/// Maximum length of a single tool pattern.
const MAX_NL_POLICY_PATTERN_LEN: usize = 256;

/// A natural language security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NlPolicy {
    /// Unique policy identifier.
    pub id: String,

    /// Human-readable policy name.
    pub name: String,

    /// Natural language policy statement.
    ///
    /// This is the actual policy text that will be sent to the LLM
    /// for evaluation. Should be clear and unambiguous.
    pub statement: String,

    /// Tool patterns this policy applies to.
    ///
    /// Format: "tool:function" or "tool:*" for all functions.
    /// Examples: ["filesystem:delete", "shell:*", "http:post"]
    #[serde(default)]
    pub tool_patterns: Vec<String>,

    /// Whether this policy is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Priority (higher = evaluated first).
    #[serde(default)]
    pub priority: i32,
}

fn default_true() -> bool {
    true
}

impl NlPolicy {
    /// Creates a new policy with the given ID and statement.
    pub fn new(id: impl Into<String>, statement: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            statement: statement.into(),
            tool_patterns: Vec::new(),
            enabled: true,
            priority: 0,
        }
    }

    /// Sets the policy name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Adds a tool pattern.
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.tool_patterns.push(pattern.into());
        self
    }

    /// Sets the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Disables the policy.
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Validates the policy, enforcing bounds on all string and collection fields.
    ///
    /// SECURITY (FIND-R114-013): Unbounded fields in NlPolicy.
    /// SECURITY (FIND-R116-008): Control character rejection on string fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() || self.id.len() > MAX_NL_POLICY_ID_LEN {
            return Err(format!(
                "NlPolicy.id length must be 1..={}, got {}",
                MAX_NL_POLICY_ID_LEN,
                self.id.len()
            ));
        }
        // SECURITY (FIND-R116-008): Control char validation — statement is interpolated into LLM
        // prompts, so invisible characters could alter prompt interpretation.
        if vellaveto_types::has_dangerous_chars(&self.id)
        {
            return Err("NlPolicy.id contains control or Unicode format characters".to_string());
        }
        if self.name.len() > MAX_NL_POLICY_NAME_LEN {
            return Err(format!(
                "NlPolicy.name exceeds max length ({} > {})",
                self.name.len(),
                MAX_NL_POLICY_NAME_LEN
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.name)
        {
            return Err("NlPolicy.name contains control or Unicode format characters".to_string());
        }
        if self.statement.is_empty() || self.statement.len() > MAX_NL_POLICY_STATEMENT_LEN {
            return Err(format!(
                "NlPolicy.statement length must be 1..={}, got {}",
                MAX_NL_POLICY_STATEMENT_LEN,
                self.statement.len()
            ));
        }
        if self
            .statement
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
        {
            return Err(
                "NlPolicy.statement contains control characters (tab/newline permitted)"
                    .to_string(),
            );
        }
        if self
            .statement
            .chars()
            .any(vellaveto_types::is_unicode_format_char)
        {
            return Err(
                "NlPolicy.statement contains Unicode format characters".to_string(),
            );
        }
        if self.tool_patterns.len() > MAX_NL_POLICY_TOOL_PATTERNS {
            return Err(format!(
                "NlPolicy.tool_patterns exceeds max ({} > {})",
                self.tool_patterns.len(),
                MAX_NL_POLICY_TOOL_PATTERNS
            ));
        }
        for (i, p) in self.tool_patterns.iter().enumerate() {
            if p.len() > MAX_NL_POLICY_PATTERN_LEN {
                return Err(format!(
                    "NlPolicy.tool_patterns[{}] exceeds max length ({} > {})",
                    i,
                    p.len(),
                    MAX_NL_POLICY_PATTERN_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(p)
            {
                return Err(format!(
                    "NlPolicy.tool_patterns[{}] contains control or Unicode format characters",
                    i
                ));
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════
// COMPILED PATTERN
// ═══════════════════════════════════════════════════

/// A compiled tool pattern for efficient matching.
#[derive(Debug, Clone)]
struct CompiledPattern {
    /// The original pattern string.
    pattern: String,
    /// Tool part (before colon).
    tool: String,
    /// Function part (after colon), "*" means any.
    function: String,
    /// Whether tool matches any (glob pattern).
    tool_wildcard: bool,
    /// Whether function matches any.
    function_wildcard: bool,
}

impl CompiledPattern {
    /// Compiles a pattern string into a CompiledPattern.
    fn compile(pattern: &str) -> Option<Self> {
        let parts: Vec<&str> = pattern.splitn(2, ':').collect();
        if parts.is_empty() {
            return None;
        }

        let tool = parts[0].to_string();
        let function = parts.get(1).copied().unwrap_or("*").to_string();

        let tool_wildcard = tool == "*" || tool.contains('*');
        let function_wildcard = function == "*" || function.contains('*');

        Some(Self {
            pattern: pattern.to_string(),
            tool,
            function,
            tool_wildcard,
            function_wildcard,
        })
    }

    /// Checks if this pattern matches the given tool and function.
    fn matches(&self, tool: &str, function: &str) -> bool {
        let tool_matches = if self.tool_wildcard {
            glob_match(&self.tool, tool)
        } else {
            self.tool.eq_ignore_ascii_case(tool)
        };

        if !tool_matches {
            return false;
        }

        if self.function_wildcard {
            glob_match(&self.function, function)
        } else {
            self.function.eq_ignore_ascii_case(function)
        }
    }
}

/// Case-insensitive glob matching (supports `*` and `?` wildcards).
///
/// Lowercases both sides and delegates to the shared `crate::util::glob_match`.
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern_lower = pattern.to_lowercase();
    let text_lower = text.to_lowercase();
    crate::util::glob_match(&pattern_lower, &text_lower)
}

// ═══════════════════════════════════════════════════
// POLICY MATCH RESULT
// ═══════════════════════════════════════════════════

/// Result of matching a tool/function against NL policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NlPolicyMatch {
    /// The matched policy ID.
    pub policy_id: String,

    /// The matched policy name.
    pub policy_name: String,

    /// The policy statement to enforce.
    pub statement: String,

    /// The pattern that matched.
    pub matched_pattern: String,

    /// Policy priority.
    pub priority: i32,
}

// ═══════════════════════════════════════════════════
// POLICY COMPILER
// ═══════════════════════════════════════════════════

/// Maximum number of compiled policies to prevent unbounded growth.
const MAX_COMPILED_POLICIES: usize = 10_000;

/// Compiler and matcher for natural language policies.
///
/// Compiles policy patterns once and efficiently matches against
/// tool/function pairs.
#[derive(Debug, Clone, Default)]
pub struct NlPolicyCompiler {
    /// Policies by ID.
    policies: HashMap<String, NlPolicy>,
    /// Compiled patterns for each policy.
    patterns: HashMap<String, Vec<CompiledPattern>>,
}

impl NlPolicyCompiler {
    /// Creates a new empty compiler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a policy to the compiler.
    ///
    /// If a policy with the same ID exists, it will be replaced.
    /// Returns `false` if the policy could not be added because the
    /// compiler is at capacity (`MAX_COMPILED_POLICIES`).
    pub fn add_policy(&mut self, policy: NlPolicy) -> bool {
        // SECURITY (FIND-R130-003): Validate policy before insertion to prevent
        // oversized statements from consuming memory in the policy map and cache.
        // Previously validate() was optional — callers could skip it.
        if let Err(e) = policy.validate() {
            tracing::warn!(
                policy_id = %policy.id,
                error = %e,
                "NlPolicyCompiler rejecting invalid policy"
            );
            return false;
        }

        // If this is a new policy (not a replacement) and we are at capacity, reject.
        if !self.policies.contains_key(&policy.id) && self.policies.len() >= MAX_COMPILED_POLICIES {
            tracing::warn!(
                policy_id = %policy.id,
                capacity = MAX_COMPILED_POLICIES,
                "NlPolicyCompiler at capacity; rejecting new policy"
            );
            return false;
        }

        // Compile patterns
        let compiled: Vec<CompiledPattern> = policy
            .tool_patterns
            .iter()
            .filter_map(|p| CompiledPattern::compile(p))
            .collect();

        self.patterns.insert(policy.id.clone(), compiled);
        self.policies.insert(policy.id.clone(), policy);
        true
    }

    /// Removes a policy by ID.
    pub fn remove_policy(&mut self, id: &str) -> Option<NlPolicy> {
        self.patterns.remove(id);
        self.policies.remove(id)
    }

    /// Returns a policy by ID.
    pub fn get_policy(&self, id: &str) -> Option<&NlPolicy> {
        self.policies.get(id)
    }

    /// Returns all policies.
    pub fn policies(&self) -> impl Iterator<Item = &NlPolicy> {
        self.policies.values()
    }

    /// Returns the number of policies.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Returns true if there are no policies.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Clears all policies.
    pub fn clear(&mut self) {
        self.policies.clear();
        self.patterns.clear();
    }

    /// Finds all policies that match the given tool and function.
    ///
    /// Returns matches sorted by priority (highest first).
    /// Capped at `MAX_POLICY_MATCHES` to prevent unbounded memory growth.
    pub fn match_policies(&self, tool: &str, function: &str) -> Vec<NlPolicyMatch> {
        // SECURITY (FIND-R205-007): Cap matches to prevent unbounded memory
        // growth (10,000 policies * 64KB statement = 640MB worst case).
        const MAX_POLICY_MATCHES: usize = 100;

        let mut matches: Vec<NlPolicyMatch> = Vec::new();

        for (id, compiled_patterns) in &self.patterns {
            if let Some(policy) = self.policies.get(id) {
                if !policy.enabled {
                    continue;
                }

                for pattern in compiled_patterns {
                    if pattern.matches(tool, function) {
                        matches.push(NlPolicyMatch {
                            policy_id: policy.id.clone(),
                            policy_name: policy.name.clone(),
                            statement: policy.statement.clone(),
                            matched_pattern: pattern.pattern.clone(),
                            priority: policy.priority,
                        });
                        break; // One match per policy is enough
                    }
                }

                if matches.len() >= MAX_POLICY_MATCHES {
                    tracing::warn!(
                        "NlPolicyCompiler match_policies capped at {}",
                        MAX_POLICY_MATCHES
                    );
                    break;
                }
            }
        }

        // Sort by priority (highest first)
        matches.sort_by(|a, b| b.priority.cmp(&a.priority));

        matches
    }

    /// Generates the prompt text for matched policies.
    ///
    /// This text is included in the LLM evaluation prompt.
    pub fn generate_prompt(&self, matches: &[NlPolicyMatch]) -> String {
        if matches.is_empty() {
            return String::new();
        }

        let mut prompt = String::from("The following security policies MUST be enforced:\n\n");

        for (i, m) in matches.iter().enumerate() {
            prompt.push_str(&format!("{}. {}\n", i + 1, m.statement));
        }

        prompt.push_str("\nDeny any action that violates these policies.");

        prompt
    }
}

// ═══════════════════════════════════════════════════
// POLICY BUILDER
// ═══════════════════════════════════════════════════

/// Builder for creating NL policies from TOML config.
pub struct NlPolicyBuilder {
    policies: Vec<NlPolicy>,
}

impl NlPolicyBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Adds a policy to the builder.
    pub fn with_policy(mut self, policy: NlPolicy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Builds the policies into a compiler.
    pub fn build(self) -> NlPolicyCompiler {
        let mut compiler = NlPolicyCompiler::new();
        for policy in self.policies {
            compiler.add_policy(policy);
        }
        compiler
    }
}

impl Default for NlPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_compiler() -> NlPolicyCompiler {
        let mut compiler = NlPolicyCompiler::new();

        compiler.add_policy(NlPolicy {
            id: "no-delete".to_string(),
            name: "No deletion".to_string(),
            statement: "Never delete files".to_string(),
            tool_patterns: vec!["filesystem:delete".to_string()],
            enabled: true,
            priority: 100,
        });

        compiler.add_policy(NlPolicy {
            id: "no-shell".to_string(),
            name: "No shell".to_string(),
            statement: "Never execute shell commands".to_string(),
            tool_patterns: vec!["shell:*".to_string(), "bash:*".to_string()],
            enabled: true,
            priority: 200,
        });

        compiler
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("foo", "foo"));
        assert!(glob_match("foo", "FOO"));
        assert!(!glob_match("foo", "bar"));
    }

    #[test]
    fn test_glob_match_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("*bar", "foobar"));
        assert!(glob_match("foo*bar", "foobazbar"));
        assert!(!glob_match("foo*", "barfoo"));
    }

    #[test]
    fn test_compiled_pattern_exact() {
        let pattern = CompiledPattern::compile("filesystem:delete").unwrap();
        assert!(pattern.matches("filesystem", "delete"));
        assert!(pattern.matches("FILESYSTEM", "DELETE"));
        assert!(!pattern.matches("filesystem", "read"));
    }

    #[test]
    fn test_compiled_pattern_wildcard() {
        let pattern = CompiledPattern::compile("shell:*").unwrap();
        assert!(pattern.matches("shell", "execute"));
        assert!(pattern.matches("shell", "run"));
        assert!(!pattern.matches("bash", "execute"));
    }

    #[test]
    fn test_compiler_add_remove() {
        let mut compiler = NlPolicyCompiler::new();
        assert!(compiler.is_empty());

        compiler.add_policy(NlPolicy::new("test", "test policy"));
        assert_eq!(compiler.len(), 1);

        compiler.remove_policy("test");
        assert!(compiler.is_empty());
    }

    #[test]
    fn test_compiler_match_exact() {
        let compiler = test_compiler();

        let matches = compiler.match_policies("filesystem", "delete");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].policy_id, "no-delete");
    }

    #[test]
    fn test_compiler_match_wildcard() {
        let compiler = test_compiler();

        let matches = compiler.match_policies("shell", "execute");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].policy_id, "no-shell");

        let matches = compiler.match_policies("bash", "run");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].policy_id, "no-shell");
    }

    #[test]
    fn test_compiler_match_priority_order() {
        let compiler = test_compiler();

        // Add a policy that matches shell:* with lower priority
        let mut compiler = compiler;
        compiler.add_policy(NlPolicy {
            id: "shell-audit".to_string(),
            name: "Audit shell".to_string(),
            statement: "Audit all shell commands".to_string(),
            tool_patterns: vec!["shell:*".to_string()],
            enabled: true,
            priority: 50,
        });

        let matches = compiler.match_policies("shell", "execute");
        assert_eq!(matches.len(), 2);
        // Higher priority first
        assert_eq!(matches[0].policy_id, "no-shell");
        assert_eq!(matches[1].policy_id, "shell-audit");
    }

    #[test]
    fn test_compiler_match_no_match() {
        let compiler = test_compiler();

        let matches = compiler.match_policies("filesystem", "read");
        assert!(matches.is_empty());

        let matches = compiler.match_policies("http", "get");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_compiler_disabled_policy() {
        let mut compiler = NlPolicyCompiler::new();
        compiler.add_policy(
            NlPolicy::new("disabled-test", "test policy")
                .with_pattern("test:*")
                .disabled(),
        );

        let matches = compiler.match_policies("test", "function");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_compiler_generate_prompt() {
        let compiler = test_compiler();
        let matches = compiler.match_policies("filesystem", "delete");

        let prompt = compiler.generate_prompt(&matches);
        assert!(prompt.contains("Never delete files"));
        assert!(prompt.contains("security policies"));
    }

    #[test]
    fn test_compiler_generate_prompt_empty() {
        let compiler = test_compiler();
        let matches = compiler.match_policies("http", "get");

        let prompt = compiler.generate_prompt(&matches);
        assert!(prompt.is_empty());
    }

    #[test]
    fn test_policy_builder() {
        let policy = NlPolicy::new("test", "test statement")
            .with_name("Test Policy")
            .with_pattern("tool:*")
            .with_priority(50);

        assert_eq!(policy.id, "test");
        assert_eq!(policy.name, "Test Policy");
        assert_eq!(policy.priority, 50);
        assert!(policy.enabled);
    }

    #[test]
    fn test_nl_policy_builder() {
        let compiler = NlPolicyBuilder::new()
            .with_policy(NlPolicy::new("p1", "policy 1").with_pattern("*:*"))
            .with_policy(NlPolicy::new("p2", "policy 2").with_pattern("*:*"))
            .build();

        assert_eq!(compiler.len(), 2);
    }

    #[test]
    fn test_policy_serialization() {
        let policy = NlPolicy {
            id: "test".to_string(),
            name: "Test".to_string(),
            statement: "Test statement".to_string(),
            tool_patterns: vec!["tool:*".to_string()],
            enabled: true,
            priority: 100,
        };

        let json = serde_json::to_string(&policy).expect("serialize");
        let parsed: NlPolicy = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.id, "test");
        assert_eq!(parsed.priority, 100);
    }

    // ── FIND-R130-003: add_policy validates before insertion ─────────────

    #[test]
    fn test_add_policy_rejects_empty_id() {
        let mut compiler = NlPolicyCompiler::new();
        let policy = NlPolicy {
            id: "".to_string(),
            name: "Test".to_string(),
            statement: "Test statement".to_string(),
            tool_patterns: vec![],
            enabled: true,
            priority: 50,
        };
        assert!(!compiler.add_policy(policy), "should reject empty id");
        assert_eq!(compiler.len(), 0);
    }

    #[test]
    fn test_add_policy_rejects_oversized_statement() {
        let mut compiler = NlPolicyCompiler::new();
        let policy = NlPolicy {
            id: "test".to_string(),
            name: "Test".to_string(),
            statement: "x".repeat(65_000),
            tool_patterns: vec![],
            enabled: true,
            priority: 50,
        };
        assert!(
            !compiler.add_policy(policy),
            "should reject oversized statement"
        );
        assert_eq!(compiler.len(), 0);
    }

    #[test]
    fn test_add_policy_accepts_valid() {
        let mut compiler = NlPolicyCompiler::new();
        let policy = NlPolicy::new("test", "Valid policy statement");
        assert!(compiler.add_policy(policy));
        assert_eq!(compiler.len(), 1);
    }

    #[test]
    fn test_nl_policy_match_serialization() {
        let m = NlPolicyMatch {
            policy_id: "test".to_string(),
            policy_name: "Test".to_string(),
            statement: "Test statement".to_string(),
            matched_pattern: "tool:*".to_string(),
            priority: 100,
        };

        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: NlPolicyMatch = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.policy_id, "test");
    }

    // ═══════════════════════════════════════════════════
    // NlPolicy::validate() TESTS (IMP-R116-016)
    // ═══════════════════════════════════════════════════

    fn make_valid_policy() -> NlPolicy {
        NlPolicy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            statement: "Never allow dangerous operations".to_string(),
            tool_patterns: vec!["filesystem:*".to_string()],
            enabled: true,
            priority: 100,
        }
    }

    #[test]
    fn test_nl_policy_validate_valid() {
        let p = make_valid_policy();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_nl_policy_validate_empty_id() {
        let mut p = make_valid_policy();
        p.id = String::new();
        let err = p.validate().unwrap_err();
        assert!(err.contains("id length must be"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_id_too_long() {
        let mut p = make_valid_policy();
        p.id = "x".repeat(MAX_NL_POLICY_ID_LEN + 1);
        let err = p.validate().unwrap_err();
        assert!(err.contains("id length must be"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_id_at_limit() {
        let mut p = make_valid_policy();
        p.id = "x".repeat(MAX_NL_POLICY_ID_LEN);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_nl_policy_validate_empty_statement() {
        let mut p = make_valid_policy();
        p.statement = String::new();
        let err = p.validate().unwrap_err();
        assert!(err.contains("statement length must be"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_statement_too_long() {
        let mut p = make_valid_policy();
        p.statement = "x".repeat(MAX_NL_POLICY_STATEMENT_LEN + 1);
        let err = p.validate().unwrap_err();
        assert!(err.contains("statement length must be"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_too_many_patterns() {
        let mut p = make_valid_policy();
        p.tool_patterns = (0..=MAX_NL_POLICY_TOOL_PATTERNS)
            .map(|i| format!("tool:{}", i))
            .collect();
        let err = p.validate().unwrap_err();
        assert!(err.contains("tool_patterns exceeds max"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_pattern_too_long() {
        let mut p = make_valid_policy();
        p.tool_patterns = vec!["x".repeat(MAX_NL_POLICY_PATTERN_LEN + 1)];
        let err = p.validate().unwrap_err();
        assert!(err.contains("exceeds max length"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_id_control_chars() {
        let mut p = make_valid_policy();
        p.id = "test\x00policy".to_string();
        let err = p.validate().unwrap_err();
        assert!(err.contains("control"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_id_unicode_format_chars() {
        let mut p = make_valid_policy();
        p.id = "test\u{200B}policy".to_string(); // zero-width space
        let err = p.validate().unwrap_err();
        assert!(err.contains("control or Unicode format"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_statement_control_chars() {
        let mut p = make_valid_policy();
        p.statement = "Never allow\x01dangerous".to_string();
        let err = p.validate().unwrap_err();
        assert!(err.contains("control"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_statement_allows_newlines() {
        let mut p = make_valid_policy();
        p.statement = "Line one\nLine two\r\nLine three\ttabbed".to_string();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_nl_policy_validate_statement_unicode_format_chars() {
        let mut p = make_valid_policy();
        p.statement = "Never allow \u{200B} operations".to_string(); // zero-width space
        let err = p.validate().unwrap_err();
        assert!(err.contains("Unicode format"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_pattern_control_chars() {
        let mut p = make_valid_policy();
        p.tool_patterns = vec!["tool:\x00*".to_string()];
        let err = p.validate().unwrap_err();
        assert!(err.contains("control"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_name_control_chars() {
        let mut p = make_valid_policy();
        p.name = "Test\x07Policy".to_string();
        let err = p.validate().unwrap_err();
        assert!(err.contains("control"), "got: {}", err);
    }

    #[test]
    fn test_nl_policy_validate_name_too_long() {
        let mut p = make_valid_policy();
        p.name = "x".repeat(MAX_NL_POLICY_NAME_LEN + 1);
        let err = p.validate().unwrap_err();
        assert!(err.contains("name exceeds max length"), "got: {}", err);
    }
}
