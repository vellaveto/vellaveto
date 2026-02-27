//! Cedar policy import/export module.
//!
//! Parses a simplified subset of Cedar policy syntax and converts to/from
//! Vellaveto's `Policy` format. This enables interoperability with AWS Bedrock
//! AgentCore and other Cedar-based authorization systems.
//!
//! ## Supported Cedar subset
//!
//! ```text
//! permit(principal, action == Action::"tools/call", resource)
//! when { resource.tool == "read_file" && resource.path like "/tmp/*" };
//!
//! forbid(principal, action, resource)
//! when { resource.domain == "evil.com" };
//! ```
//!
//! ## Mapping
//!
//! | Cedar construct                       | Vellaveto equivalent                        |
//! |---------------------------------------|---------------------------------------------|
//! | `permit`                              | `PolicyType::Allow`                         |
//! | `forbid`                              | `PolicyType::Deny`                          |
//! | `resource.tool == "X"`                | tool pattern `"X"`                          |
//! | `resource.path like "/tmp/*"`         | `PathRules { allowed: ["/tmp/*"] }`         |
//! | `resource.path like "!/secret/*"`     | `PathRules { blocked: ["/secret/*"] }`      |
//! | `resource.domain == "X"`              | `NetworkRules { allowed_domains: ["X"] }`   |
//! | `resource.domain != "evil.com"`       | `NetworkRules { blocked_domains: ["evil.com"] }` |

use vellaveto_types::{NetworkRules, PathRules, Policy, PolicyType};

// ═══════════════════════════════════════════════════════════════════════════════
// BOUNDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of Cedar policies that can be imported in a single call.
pub const MAX_CEDAR_POLICIES: usize = 10_000;

/// Maximum size of Cedar policy text in bytes (1 MiB).
pub const MAX_POLICY_TEXT_SIZE: usize = 1_048_576;

/// Maximum number of conditions (when-clause conjuncts) per policy.
pub const MAX_CONDITIONS_PER_POLICY: usize = 100;

/// Maximum length of a string literal inside Cedar policy text.
const MAX_STRING_LITERAL_LEN: usize = 4096;

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Errors that can occur during Cedar policy import.
#[derive(Debug)]
pub enum CedarImportError {
    /// Parse error at a specific line.
    Parse { line: usize, message: String },
    /// Unsupported Cedar feature encountered.
    UnsupportedFeature { feature: String },
    /// Too many policies in input.
    TooManyPolicies { count: usize, max: usize },
    /// Input text exceeds maximum size.
    InputTooLarge { size: usize, max: usize },
    /// Too many conditions in a single policy.
    TooManyConditions { count: usize, max: usize },
}

impl std::fmt::Display for CedarImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CedarImportError::Parse { line, message } => {
                write!(f, "parse error at line {}: {}", line, message)
            }
            CedarImportError::UnsupportedFeature { feature } => {
                write!(f, "unsupported Cedar feature: {}", feature)
            }
            CedarImportError::TooManyPolicies { count, max } => {
                write!(f, "too many policies: {} exceeds maximum {}", count, max)
            }
            CedarImportError::InputTooLarge { size, max } => {
                write!(
                    f,
                    "input too large: {} bytes exceeds maximum {} bytes",
                    size, max
                )
            }
            CedarImportError::TooManyConditions { count, max } => {
                write!(f, "too many conditions: {} exceeds maximum {}", count, max)
            }
        }
    }
}

impl std::error::Error for CedarImportError {}

/// Errors that can occur during Cedar policy export.
#[derive(Debug)]
pub enum CedarExportError {
    /// A policy has a conditional type that cannot be represented in Cedar subset.
    ConditionalPolicy { policy_id: String },
    /// A policy has no tool pattern (empty id).
    EmptyPolicyId { index: usize },
}

impl std::fmt::Display for CedarExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CedarExportError::ConditionalPolicy { policy_id } => {
                write!(
                    f,
                    "cannot export conditional policy '{}' to Cedar subset",
                    policy_id
                )
            }
            CedarExportError::EmptyPolicyId { index } => {
                write!(f, "policy at index {} has empty id", index)
            }
        }
    }
}

impl std::error::Error for CedarExportError {}

// ═══════════════════════════════════════════════════════════════════════════════
// IMPORT
// ═══════════════════════════════════════════════════════════════════════════════

/// Parse a simplified Cedar policy text and convert to Vellaveto `Policy` structs.
///
/// Supports `permit` and `forbid` statements with optional `when` clauses
/// containing conditions on `resource.tool`, `resource.path`, and `resource.domain`.
///
/// # Errors
///
/// Returns `CedarImportError` if:
/// - Input exceeds `MAX_POLICY_TEXT_SIZE`
/// - More than `MAX_CEDAR_POLICIES` policies found
/// - Syntax errors in the Cedar text
/// - Unsupported Cedar features encountered
pub fn import_cedar_policies(cedar_text: &str) -> Result<Vec<Policy>, CedarImportError> {
    // Validate input size
    if cedar_text.len() > MAX_POLICY_TEXT_SIZE {
        return Err(CedarImportError::InputTooLarge {
            size: cedar_text.len(),
            max: MAX_POLICY_TEXT_SIZE,
        });
    }

    // Validate no control characters (except whitespace)
    for (line_idx, line) in cedar_text.lines().enumerate() {
        for ch in line.chars() {
            if ch.is_control() && ch != '\t' {
                return Err(CedarImportError::Parse {
                    line: line_idx.saturating_add(1),
                    message: "input contains control characters".to_string(),
                });
            }
            if vellaveto_types::is_unicode_format_char(ch) {
                return Err(CedarImportError::Parse {
                    line: line_idx.saturating_add(1),
                    message: "input contains Unicode format characters".to_string(),
                });
            }
        }
    }

    // Split into policy statements by semicolons at the top level.
    // Each statement is `permit(...)` or `forbid(...)` optionally followed by `when { ... }` and `;`.
    let statements = split_statements(cedar_text)?;

    if statements.len() > MAX_CEDAR_POLICIES {
        return Err(CedarImportError::TooManyPolicies {
            count: statements.len(),
            max: MAX_CEDAR_POLICIES,
        });
    }

    let mut policies = Vec::with_capacity(statements.len());

    for (idx, stmt) in statements.iter().enumerate() {
        let policy = parse_statement(stmt, idx)?;
        // SECURITY (R228-CFG-1): Validate each imported policy to enforce bounds
        // (MAX_POLICY_ID_LEN, MAX_POLICY_NAME_LEN, etc.). Without this, Cedar
        // policies with oversized string literals bypass all validation gates.
        if let Err(e) = policy.validate() {
            return Err(CedarImportError::Parse {
                line: stmt.line,
                message: format!("imported policy failed validation: {}", e),
            });
        }
        policies.push(policy);
    }

    Ok(policies)
}

/// A raw statement with its starting line number (1-based) and text content.
struct RawStatement {
    line: usize,
    text: String,
}

/// Split Cedar text into individual policy statements separated by `;`.
fn split_statements(text: &str) -> Result<Vec<RawStatement>, CedarImportError> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape_next = false;
    let mut current_start_line: usize = 1;
    let mut line_number: usize = 1;
    let mut brace_depth: i32 = 0;

    for ch in text.chars() {
        if ch == '\n' {
            line_number = line_number.saturating_add(1);
        }

        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        if ch == '\\' && in_string {
            current.push(ch);
            escape_next = true;
            continue;
        }

        if ch == '"' {
            in_string = !in_string;
            current.push(ch);
            continue;
        }

        if in_string {
            current.push(ch);
            continue;
        }

        // Track brace depth for `when { ... }`
        if ch == '{' {
            brace_depth = brace_depth.saturating_add(1);
        } else if ch == '}' {
            brace_depth = brace_depth.saturating_sub(1);
        }

        // Skip single-line comments
        // We handle this by skipping everything after `//` until newline
        // But since we're iterating char by char, we need a different approach.
        // For simplicity, strip comments in a pre-pass.

        if ch == ';' && brace_depth == 0 {
            let trimmed = current.trim().to_string();
            if !trimmed.is_empty() {
                statements.push(RawStatement {
                    line: current_start_line,
                    text: trimmed,
                });
            }
            current.clear();
            current_start_line = line_number;
            continue;
        }

        if current.is_empty() && ch.is_whitespace() {
            current_start_line = line_number;
            continue;
        }

        current.push(ch);
    }

    // Handle trailing statement without semicolon
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        // Check if it looks like a real statement (not just whitespace/comments)
        let content = strip_line_comments(&trimmed);
        let content = content.trim();
        if !content.is_empty() {
            statements.push(RawStatement {
                line: current_start_line,
                text: trimmed,
            });
        }
    }

    Ok(statements)
}

/// Strip single-line `//` comments from a line.
///
/// SECURITY (R230-TYP-5): Handles backslash-escaped quotes (`\"`) inside
/// string literals to prevent premature string termination.
fn strip_line_comments(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut in_string = false;
    let mut prev_slash = false;
    let mut prev_backslash = false;

    for ch in text.chars() {
        if in_string {
            if ch == '"' && !prev_backslash {
                in_string = false;
            }
            prev_backslash = ch == '\\' && !prev_backslash;
            result.push(ch);
            prev_slash = false;
            continue;
        }

        if ch == '/' && prev_slash {
            // Found `//` outside string — discard rest of this logical line
            // Remove the previously pushed '/'
            result.pop();
            // Skip to next newline
            break;
        }

        if ch == '"' {
            in_string = true;
            prev_backslash = false;
        }

        prev_slash = ch == '/';
        result.push(ch);
    }

    result
}

/// Parsed condition from a Cedar `when` clause.
#[derive(Debug)]
enum Condition {
    /// `resource.tool == "value"`
    ToolEquals(String),
    /// `resource.path like "pattern"`
    PathLike(String),
    /// `resource.domain == "value"`
    DomainEquals(String),
    /// `resource.domain != "value"`
    DomainNotEquals(String),
}

/// Parse a single Cedar statement into a Vellaveto Policy.
fn parse_statement(stmt: &RawStatement, idx: usize) -> Result<Policy, CedarImportError> {
    // Strip comments from each line
    let clean: String = stmt
        .text
        .lines()
        .map(strip_line_comments)
        .collect::<Vec<_>>()
        .join(" ");
    let text = clean.trim();

    // Determine effect: permit or forbid
    let (effect, rest) = if let Some(rest) = text.strip_prefix("permit") {
        (PolicyType::Allow, rest.trim())
    } else if let Some(rest) = text.strip_prefix("forbid") {
        (PolicyType::Deny, rest.trim())
    } else {
        return Err(CedarImportError::Parse {
            line: stmt.line,
            message: "expected 'permit' or 'forbid'".to_string(),
        });
    };

    // Parse the head: (principal, action, resource) or variants
    let rest = parse_head(rest, stmt.line)?;

    // Parse optional `when { ... }` clause
    let conditions = if !rest.is_empty() {
        parse_when_clause(rest, stmt.line)?
    } else {
        Vec::new()
    };

    if conditions.len() > MAX_CONDITIONS_PER_POLICY {
        return Err(CedarImportError::TooManyConditions {
            count: conditions.len(),
            max: MAX_CONDITIONS_PER_POLICY,
        });
    }

    // Build Policy from effect + conditions
    build_policy(effect, &conditions, idx, stmt.line)
}

/// Parse the head `(principal, action, resource)` or `(principal, action == ..., resource)`.
/// Returns the remaining text after the closing `)`.
fn parse_head(text: &str, line: usize) -> Result<&str, CedarImportError> {
    // Must start with `(`
    let text = text
        .strip_prefix('(')
        .ok_or_else(|| CedarImportError::Parse {
            line,
            message: "expected '(' after permit/forbid".to_string(),
        })?;

    // Find the matching closing `)`
    let mut depth = 1i32;
    let mut in_string = false;
    let mut close_pos = None;

    for (i, ch) in text.char_indices() {
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '(' {
            depth = depth.saturating_add(1);
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                close_pos = Some(i);
                break;
            }
        }
    }

    let close_pos = close_pos.ok_or_else(|| CedarImportError::Parse {
        line,
        message: "unmatched '(' in policy head".to_string(),
    })?;

    // Validate the head contents loosely: we accept various forms
    // like (principal, action, resource) or (principal, action == Action::"...", resource)
    let _head_content = &text[..close_pos];

    // We don't need to deeply parse the head for our simplified subset.
    // The conditions in the `when` clause carry the semantics.
    // But we do reject unsupported features like `unless`.
    let remaining = text[close_pos..]
        .strip_prefix(')')
        .ok_or_else(|| CedarImportError::Parse {
            line,
            message: "expected ')' in policy head".to_string(),
        })?;

    let remaining = remaining.trim();

    // Reject `unless` clause (unsupported)
    if remaining.starts_with("unless") {
        return Err(CedarImportError::UnsupportedFeature {
            feature: "unless clause".to_string(),
        });
    }

    Ok(remaining)
}

/// Parse a `when { ... }` clause into a list of conditions.
fn parse_when_clause(text: &str, line: usize) -> Result<Vec<Condition>, CedarImportError> {
    let text = text.trim();

    // Must start with `when`
    let text = text
        .strip_prefix("when")
        .ok_or_else(|| CedarImportError::Parse {
            line,
            message: format!(
                "expected 'when' clause or end of statement, got '{}'",
                truncate_for_error(text, 40),
            ),
        })?;

    let text = text.trim();

    // Must have `{ ... }`
    let text = text
        .strip_prefix('{')
        .ok_or_else(|| CedarImportError::Parse {
            line,
            message: "expected '{' after 'when'".to_string(),
        })?;

    // Find matching `}`
    let mut depth = 1i32;
    let mut in_string = false;
    let mut close_pos = None;

    for (i, ch) in text.char_indices() {
        if ch == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if ch == '{' {
            depth = depth.saturating_add(1);
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                close_pos = Some(i);
                break;
            }
        }
    }

    let close_pos = close_pos.ok_or_else(|| CedarImportError::Parse {
        line,
        message: "unmatched '{' in when clause".to_string(),
    })?;

    let body = text[..close_pos].trim();

    if body.is_empty() {
        return Ok(Vec::new());
    }

    // Split conditions on `&&`
    let condition_strs = split_conditions(body);
    let mut conditions = Vec::with_capacity(condition_strs.len());

    for cond_str in &condition_strs {
        let cond = parse_condition(cond_str.trim(), line)?;
        conditions.push(cond);
    }

    Ok(conditions)
}

/// Split a when-clause body on `&&` outside of string literals.
fn split_conditions(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_string = false;
    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'"' {
            in_string = !in_string;
            i = i.saturating_add(1);
            continue;
        }
        if in_string {
            i = i.saturating_add(1);
            continue;
        }
        if i.saturating_add(1) < len && bytes[i] == b'&' && bytes[i.saturating_add(1)] == b'&' {
            parts.push(&body[start..i]);
            i = i.saturating_add(2);
            start = i;
            continue;
        }
        i = i.saturating_add(1);
    }

    if start < len {
        parts.push(&body[start..]);
    }

    parts
}

/// Parse a single condition like `resource.tool == "read_file"` or `resource.path like "/tmp/*"`.
fn parse_condition(text: &str, line: usize) -> Result<Condition, CedarImportError> {
    let text = text.trim();

    // resource.tool == "value"
    if let Some(rest) = text.strip_prefix("resource.tool") {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix("==") {
            let value = parse_string_literal(rest.trim(), line)?;
            return Ok(Condition::ToolEquals(value));
        }
        return Err(CedarImportError::Parse {
            line,
            message: format!(
                "expected '==' after 'resource.tool', got '{}'",
                truncate_for_error(rest, 40),
            ),
        });
    }

    // resource.path like "pattern"
    if let Some(rest) = text.strip_prefix("resource.path") {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix("like") {
            let value = parse_string_literal(rest.trim(), line)?;
            return Ok(Condition::PathLike(value));
        }
        return Err(CedarImportError::Parse {
            line,
            message: format!(
                "expected 'like' after 'resource.path', got '{}'",
                truncate_for_error(rest, 40),
            ),
        });
    }

    // resource.domain == "value" or resource.domain != "value"
    if let Some(rest) = text.strip_prefix("resource.domain") {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix("!=") {
            let value = parse_string_literal(rest.trim(), line)?;
            return Ok(Condition::DomainNotEquals(value));
        }
        if let Some(rest) = rest.strip_prefix("==") {
            let value = parse_string_literal(rest.trim(), line)?;
            return Ok(Condition::DomainEquals(value));
        }
        return Err(CedarImportError::Parse {
            line,
            message: format!(
                "expected '==' or '!=' after 'resource.domain', got '{}'",
                truncate_for_error(rest, 40),
            ),
        });
    }

    // Unsupported condition
    Err(CedarImportError::UnsupportedFeature {
        feature: format!("condition '{}'", truncate_for_error(text, 60),),
    })
}

/// Parse a double-quoted string literal and return its contents.
fn parse_string_literal(text: &str, line: usize) -> Result<String, CedarImportError> {
    let text = text.trim();

    if !text.starts_with('"') {
        return Err(CedarImportError::Parse {
            line,
            message: format!(
                "expected string literal, got '{}'",
                truncate_for_error(text, 40),
            ),
        });
    }

    let inner = &text[1..]; // skip opening quote
    let mut result = String::new();
    let mut chars = inner.chars();
    let mut closed = false;

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some(other) => {
                    return Err(CedarImportError::Parse {
                        line,
                        message: format!("invalid escape sequence '\\{}'", other),
                    });
                }
                None => {
                    return Err(CedarImportError::Parse {
                        line,
                        message: "unterminated escape sequence".to_string(),
                    });
                }
            }
        } else if ch == '"' {
            closed = true;
            break;
        } else {
            result.push(ch);
        }

        if result.len() > MAX_STRING_LITERAL_LEN {
            return Err(CedarImportError::Parse {
                line,
                message: format!(
                    "string literal exceeds maximum length of {} bytes",
                    MAX_STRING_LITERAL_LEN
                ),
            });
        }
    }

    if !closed {
        return Err(CedarImportError::Parse {
            line,
            message: "unterminated string literal".to_string(),
        });
    }

    // Validate no control/format characters in the extracted value
    if vellaveto_types::has_dangerous_chars(&result) {
        return Err(CedarImportError::Parse {
            line,
            message: "string literal contains control or format characters".to_string(),
        });
    }

    Ok(result)
}

/// Build a Vellaveto `Policy` from an effect and list of conditions.
fn build_policy(
    effect: PolicyType,
    conditions: &[Condition],
    idx: usize,
    line: usize,
) -> Result<Policy, CedarImportError> {
    let mut tool_pattern: Option<String> = None;
    let mut allowed_paths: Vec<String> = Vec::new();
    let mut blocked_paths: Vec<String> = Vec::new();
    let mut allowed_domains: Vec<String> = Vec::new();
    let mut blocked_domains: Vec<String> = Vec::new();

    for cond in conditions {
        match cond {
            Condition::ToolEquals(val) => {
                if tool_pattern.is_some() {
                    return Err(CedarImportError::Parse {
                        line,
                        message: "duplicate resource.tool condition".to_string(),
                    });
                }
                tool_pattern = Some(val.clone());
            }
            Condition::PathLike(val) => {
                // Patterns prefixed with `!` are blocklist entries
                if let Some(blocked) = val.strip_prefix('!') {
                    blocked_paths.push(blocked.to_string());
                } else {
                    allowed_paths.push(val.clone());
                }
            }
            Condition::DomainEquals(val) => {
                allowed_domains.push(val.clone());
            }
            Condition::DomainNotEquals(val) => {
                blocked_domains.push(val.clone());
            }
        }
    }

    let tool = tool_pattern.unwrap_or_else(|| "*".to_string());

    // Validate tool name for dangerous characters
    if vellaveto_types::has_dangerous_chars(&tool) {
        return Err(CedarImportError::Parse {
            line,
            message: "tool name contains control or format characters".to_string(),
        });
    }

    // Build path_rules if any path conditions were present
    let path_rules = if !allowed_paths.is_empty() || !blocked_paths.is_empty() {
        Some(PathRules {
            allowed: allowed_paths,
            blocked: blocked_paths,
        })
    } else {
        None
    };

    // Build network_rules if any domain conditions were present
    let network_rules = if !allowed_domains.is_empty() || !blocked_domains.is_empty() {
        Some(NetworkRules {
            allowed_domains,
            blocked_domains,
            ip_rules: None,
        })
    } else {
        None
    };

    let policy_id = format!("cedar-{}:{}", tool, idx);
    let policy_name = format!("Cedar policy {} (line {})", idx, line);

    Ok(Policy {
        id: policy_id,
        name: policy_name,
        policy_type: effect,
        priority: 0, // Default priority; fail-closed
        path_rules,
        network_rules,
    })
}

/// Truncate a string for inclusion in error messages.
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len).collect();
        format!("{}...", truncated)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

/// Export Vellaveto policies as Cedar policy syntax.
///
/// Converts each `Policy` into a `permit` or `forbid` statement with
/// appropriate `when` conditions for tool, path, and domain rules.
///
/// # Errors
///
/// Returns `CedarExportError` if:
/// - A policy uses `PolicyType::Conditional` (not representable in Cedar subset)
/// - A policy has an empty id
pub fn export_to_cedar(policies: &[Policy]) -> Result<String, CedarExportError> {
    let mut output = String::new();

    for (idx, policy) in policies.iter().enumerate() {
        if policy.id.is_empty() {
            return Err(CedarExportError::EmptyPolicyId { index: idx });
        }

        let effect = match &policy.policy_type {
            PolicyType::Allow => "permit",
            PolicyType::Deny => "forbid",
            PolicyType::Conditional { .. } => {
                return Err(CedarExportError::ConditionalPolicy {
                    policy_id: policy.id.clone(),
                });
            }
            #[allow(unreachable_patterns)] // PolicyType is #[non_exhaustive]
            _ => {
                return Err(CedarExportError::ConditionalPolicy {
                    policy_id: policy.id.clone(),
                });
            }
        };

        // Collect conditions
        let mut conditions: Vec<String> = Vec::new();

        // Tool name condition (skip if wildcard)
        let tool_name = extract_tool_from_id(&policy.id);
        if tool_name != "*" {
            conditions.push(format!(
                "resource.tool == \"{}\"",
                escape_cedar_string(&tool_name)
            ));
        }

        // Path rules
        if let Some(ref pr) = policy.path_rules {
            for path in &pr.allowed {
                conditions.push(format!(
                    "resource.path like \"{}\"",
                    escape_cedar_string(path)
                ));
            }
            for path in &pr.blocked {
                conditions.push(format!(
                    "resource.path like \"!{}\"",
                    escape_cedar_string(path)
                ));
            }
        }

        // Network rules
        if let Some(ref nr) = policy.network_rules {
            for domain in &nr.allowed_domains {
                conditions.push(format!(
                    "resource.domain == \"{}\"",
                    escape_cedar_string(domain)
                ));
            }
            for domain in &nr.blocked_domains {
                conditions.push(format!(
                    "resource.domain != \"{}\"",
                    escape_cedar_string(domain)
                ));
            }
        }

        // Write the policy statement with a comment header
        output.push_str(&format!("// {}\n", policy.name));
        output.push_str(effect);
        output.push_str("(principal, action, resource)");

        if !conditions.is_empty() {
            output.push_str("\nwhen { ");
            output.push_str(&conditions.join(" && "));
            output.push_str(" }");
        }

        output.push_str(";\n");

        // Add blank line between policies
        if idx < policies.len().saturating_sub(1) {
            output.push('\n');
        }
    }

    Ok(output)
}

/// Extract a tool name from the policy ID.
///
/// Policies created by `import_cedar_policies` use `"cedar-TOOL:N"` format.
/// Policies from config use `"tool_pattern:function_pattern"` format.
/// We extract the tool pattern portion from the ID.
fn extract_tool_from_id(id: &str) -> String {
    if let Some(rest) = id.strip_prefix("cedar-") {
        // Cedar-imported: "cedar-TOOL:N"
        if let Some(colon_pos) = rest.rfind(':') {
            let tool = &rest[..colon_pos];
            if tool.is_empty() {
                return "*".to_string();
            }
            return tool.to_string();
        }
        return "*".to_string();
    }
    if let Some(colon_pos) = id.find(':') {
        id[..colon_pos].to_string()
    } else {
        "*".to_string()
    }
}

/// Escape special characters for inclusion in a Cedar string literal.
fn escape_cedar_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_permit_policy() {
        let cedar = r#"permit(principal, action, resource);"#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_type, PolicyType::Allow);
        assert_eq!(policies[0].id, "cedar-*:0");
    }

    #[test]
    fn test_import_forbid_policy() {
        let cedar = r#"forbid(principal, action, resource);"#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_type, PolicyType::Deny);
    }

    #[test]
    fn test_import_with_path_condition() {
        let cedar = r#"
            permit(principal, action == Action::"tools/call", resource)
            when { resource.tool == "read_file" && resource.path like "/tmp/*" };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_type, PolicyType::Allow);

        let pr = policies[0].path_rules.as_ref().unwrap();
        assert_eq!(pr.allowed, vec!["/tmp/*"]);
        assert!(pr.blocked.is_empty());
    }

    #[test]
    fn test_import_with_domain_condition() {
        let cedar = r#"
            forbid(principal, action, resource)
            when { resource.domain == "evil.com" };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_type, PolicyType::Deny);

        let nr = policies[0].network_rules.as_ref().unwrap();
        assert_eq!(nr.allowed_domains, vec!["evil.com"]);
        assert!(nr.blocked_domains.is_empty());
    }

    #[test]
    fn test_import_domain_not_equals() {
        let cedar = r#"
            forbid(principal, action, resource)
            when { resource.domain != "evil.com" };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        let nr = policies[0].network_rules.as_ref().unwrap();
        assert!(nr.allowed_domains.is_empty());
        assert_eq!(nr.blocked_domains, vec!["evil.com"]);
    }

    #[test]
    fn test_import_blocked_path() {
        let cedar = r#"
            forbid(principal, action, resource)
            when { resource.path like "!/secret/*" };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        let pr = policies[0].path_rules.as_ref().unwrap();
        assert!(pr.allowed.is_empty());
        assert_eq!(pr.blocked, vec!["/secret/*"]);
    }

    #[test]
    fn test_import_multiple_conditions() {
        let cedar = r#"
            permit(principal, action, resource)
            when {
                resource.tool == "fetch" &&
                resource.domain == "api.example.com" &&
                resource.path like "/data/*"
            };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);

        let pr = policies[0].path_rules.as_ref().unwrap();
        assert_eq!(pr.allowed, vec!["/data/*"]);

        let nr = policies[0].network_rules.as_ref().unwrap();
        assert_eq!(nr.allowed_domains, vec!["api.example.com"]);
    }

    #[test]
    fn test_import_multiple_policies() {
        let cedar = r#"
            permit(principal, action, resource)
            when { resource.tool == "read_file" };

            forbid(principal, action, resource)
            when { resource.domain == "evil.com" };
        "#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].policy_type, PolicyType::Allow);
        assert_eq!(policies[0].id, "cedar-read_file:0");
        assert_eq!(policies[1].policy_type, PolicyType::Deny);
        assert_eq!(policies[1].id, "cedar-*:1");
    }

    #[test]
    fn test_export_allow_policy() {
        let policy = Policy {
            id: "read_file:*".to_string(),
            name: "Allow read_file".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: Some(PathRules {
                allowed: vec!["/tmp/*".to_string()],
                blocked: vec![],
            }),
            network_rules: None,
        };
        let cedar = export_to_cedar(&[policy]).unwrap();
        assert!(cedar.contains("permit"));
        assert!(cedar.contains("resource.tool == \"read_file\""));
        assert!(cedar.contains("resource.path like \"/tmp/*\""));
    }

    #[test]
    fn test_export_deny_policy() {
        let policy = Policy {
            id: "*:*".to_string(),
            name: "Block evil domain".to_string(),
            policy_type: PolicyType::Deny,
            priority: 0,
            path_rules: None,
            network_rules: Some(NetworkRules {
                allowed_domains: vec![],
                blocked_domains: vec!["evil.com".to_string()],
                ip_rules: None,
            }),
        };
        let cedar = export_to_cedar(&[policy]).unwrap();
        assert!(cedar.contains("forbid"));
        assert!(cedar.contains("resource.domain != \"evil.com\""));
    }

    #[test]
    fn test_roundtrip_import_export() {
        let original = r#"
            permit(principal, action, resource)
            when { resource.tool == "read_file" && resource.path like "/tmp/*" };

            forbid(principal, action, resource)
            when { resource.domain != "evil.com" };
        "#;

        let policies = import_cedar_policies(original).unwrap();
        assert_eq!(policies.len(), 2);

        let exported = export_to_cedar(&policies).unwrap();

        // Re-import the exported text
        let reimported = import_cedar_policies(&exported).unwrap();
        assert_eq!(reimported.len(), 2);
        assert_eq!(reimported[0].policy_type, PolicyType::Allow);
        assert_eq!(reimported[1].policy_type, PolicyType::Deny);

        // Verify path rules survived roundtrip
        let pr = reimported[0].path_rules.as_ref().unwrap();
        assert_eq!(pr.allowed, vec!["/tmp/*"]);

        // Verify network rules survived roundtrip
        let nr = reimported[1].network_rules.as_ref().unwrap();
        assert_eq!(nr.blocked_domains, vec!["evil.com"]);
    }

    #[test]
    fn test_invalid_cedar_syntax() {
        let cedar = r#"allow(principal, action, resource);"#;
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("expected 'permit' or 'forbid'"));
    }

    #[test]
    fn test_unsupported_feature() {
        let cedar = r#"
            permit(principal, action, resource)
            when { resource.custom_attr == "value" };
        "#;
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unsupported Cedar feature"));
    }

    #[test]
    fn test_too_many_policies() {
        // Build a Cedar text with MAX_CEDAR_POLICIES + 1 statements
        let mut cedar = String::new();
        for _ in 0..=MAX_CEDAR_POLICIES {
            cedar.push_str("permit(principal, action, resource);\n");
        }
        let result = import_cedar_policies(&cedar);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("too many policies"));
    }

    #[test]
    fn test_input_too_large() {
        let cedar = "a".repeat(MAX_POLICY_TEXT_SIZE + 1);
        let result = import_cedar_policies(&cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("input too large"));
    }

    #[test]
    fn test_control_chars_rejected() {
        let cedar = "permit(principal, action, resource)\x07;";
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("control characters"));
    }

    #[test]
    fn test_unicode_format_chars_rejected() {
        // Zero-width space in policy text
        let cedar = "permit(principal, action, \u{200B}resource);";
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Unicode format characters"));
    }

    #[test]
    fn test_export_conditional_policy_error() {
        let policy = Policy {
            id: "test".to_string(),
            name: "test".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: serde_json::json!({}),
            },
            priority: 0,
            path_rules: None,
            network_rules: None,
        };
        let result = export_to_cedar(&[policy]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("conditional policy"));
    }

    #[test]
    fn test_export_empty_id_error() {
        let policy = Policy {
            id: "".to_string(),
            name: "test".to_string(),
            policy_type: PolicyType::Allow,
            priority: 0,
            path_rules: None,
            network_rules: None,
        };
        let result = export_to_cedar(&[policy]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("empty id"));
    }

    #[test]
    fn test_unterminated_string() {
        let cedar = r#"permit(principal, action, resource) when { resource.tool == "unclosed };"#;
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
    }

    #[test]
    fn test_escaped_quotes_in_string() {
        let cedar =
            r#"permit(principal, action, resource) when { resource.tool == "say\"hello\"" };"#;
        let policies = import_cedar_policies(cedar).unwrap();
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn test_unmatched_paren() {
        let cedar = "permit(principal, action, resource;";
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unmatched '('"));
    }

    #[test]
    fn test_unless_clause_rejected() {
        let cedar = r#"permit(principal, action, resource) unless { true };"#;
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unless clause"));
    }

    #[test]
    fn test_empty_input() {
        let policies = import_cedar_policies("").unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn test_whitespace_only_input() {
        let policies = import_cedar_policies("   \n\n  \t  ").unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn test_export_empty_policies() {
        let cedar = export_to_cedar(&[]).unwrap();
        assert!(cedar.is_empty());
    }

    #[test]
    fn test_export_wildcard_tool() {
        let policy = Policy {
            id: "*:*".to_string(),
            name: "Deny all".to_string(),
            policy_type: PolicyType::Deny,
            priority: 0,
            path_rules: None,
            network_rules: None,
        };
        let cedar = export_to_cedar(&[policy]).unwrap();
        // Wildcard tool should not generate a resource.tool condition
        assert!(!cedar.contains("resource.tool"));
        assert!(cedar.contains("forbid(principal, action, resource);"));
    }

    #[test]
    fn test_duplicate_tool_condition_rejected() {
        let cedar = r#"
            permit(principal, action, resource)
            when { resource.tool == "a" && resource.tool == "b" };
        "#;
        let result = import_cedar_policies(cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("duplicate resource.tool"));
    }

    #[test]
    fn test_too_many_conditions() {
        let mut conditions = Vec::new();
        for i in 0..=MAX_CONDITIONS_PER_POLICY {
            conditions.push(format!("resource.domain == \"d{}.com\"", i));
        }
        let cedar = format!(
            "permit(principal, action, resource) when {{ {} }};",
            conditions.join(" && ")
        );
        let result = import_cedar_policies(&cedar);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("too many conditions"));
    }
}
