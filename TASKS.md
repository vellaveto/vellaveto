# TASKS.md — Sentinel Implementation Roadmap

> Concrete task list for Claude Code sessions. Check off as you go.

---

## 🚦 Pre-Flight Checklist (Every Session)

```bash
# Run this FIRST, every session
cd /path/to/sentinel
git pull origin main 2>/dev/null || true
cargo check --workspace && cargo test --workspace --no-fail-fast 2>&1 | tail -10
```

**If tests fail:** STOP. Fix failures before proceeding. Log in `.failures/`.

---

## Phase 1: Foundation Fixes (Day 1)

### 1.1 Fix Warnings
```bash
# Check current warnings
cargo clippy --workspace 2>&1 | grep -E "^warning:" | sort -u
```

- [ ] **Fix `strict_mode` unused field**
  - Location: `sentinel-engine/src/lib.rs`
  - Options: (A) Use it in evaluate(), (B) Remove it, (C) Add `#[allow(dead_code)]` with TODO
  - Recommended: Option A — add `if self.strict_mode { /* stricter checks */ }`
  
  ```rust
  // In evaluate_action():
  if self.strict_mode && action.parameters.is_object() {
      // In strict mode, require explicit policy for any tool with parameters
      // (vs. permissive mode where unknown params pass through)
  }
  ```

- [ ] **Run clippy clean**
  ```bash
  cargo clippy --workspace -- -D warnings
  # Must exit 0
  ```

### 1.2 Add CI Workflow
- [ ] **Create `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - uses: Swatinem/rust-cache@v2
      
      - name: Check
        run: cargo check --workspace --all-targets
      
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      
      - name: Format
        run: cargo fmt --all -- --check
      
      - name: Test
        run: cargo test --workspace --no-fail-fast
      
      - name: Doc
        run: cargo doc --workspace --no-deps
```

- [ ] **Commit and push**
  ```bash
  git add .github/
  git commit -m "chore: add CI workflow"
  git push
  ```

### 1.3 Document Canonical Disconnect
- [ ] **Add note to sentinel-canonical/src/lib.rs**

```rust
//! # Canonical Policies
//! 
//! Pre-built policy sets for common scenarios.
//! 
//! ## Important Note
//! 
//! These functions return `Policy` structs with descriptive names and IDs.
//! The current engine matches on `id` pattern (tool:function with wildcards)
//! and `policy_type` only. Fields like "blocks dangerous tools" in the
//! description are implemented via the ID pattern, not semantic inspection.
//! 
//! Example: `block_dangerous_tools()` returns policies with IDs like
//! `bash:*`, `shell:*`, which the engine matches literally.
```

**Checkpoint:** `cargo test --workspace` passes, `cargo clippy --workspace -- -D warnings` passes.

---

## Phase 2: Path/Domain Types (Day 2-3)

### 2.1 Add Types to sentinel-types

- [ ] **Add `NormalizedPath` and `NormalizedDomain`**

Location: `sentinel-types/src/lib.rs`

```rust
use std::path::PathBuf;

/// A normalized, validated filesystem path
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedPath(String);

impl NormalizedPath {
    /// Create from raw string, normalizing and validating
    pub fn new(raw: &str) -> Result<Self, PathError> {
        // Reject null bytes
        if raw.bytes().any(|b| b == 0) {
            return Err(PathError::InvalidCharacter);
        }
        
        // Convert to absolute
        let path = if raw.starts_with('/') {
            PathBuf::from(raw)
        } else {
            return Err(PathError::NotAbsolute);
        };
        
        // Normalize (resolve . and ..)
        let mut normalized = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir => normalized.push("/".to_string()),
                std::path::Component::Normal(c) => {
                    normalized.push(c.to_string_lossy().to_string());
                }
                std::path::Component::CurDir => {} // skip .
                std::path::Component::ParentDir => {
                    if normalized.len() <= 1 {
                        return Err(PathError::TraversalAttempt);
                    }
                    normalized.pop();
                }
                _ => return Err(PathError::InvalidComponent),
            }
        }
        
        let result = if normalized.len() == 1 {
            "/".to_string()
        } else {
            normalized.join("/").replacen("//", "/", 1)
        };
        
        Ok(Self(result))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    /// Check if path matches a glob pattern
    pub fn matches_glob(&self, pattern: &str) -> bool {
        glob_match(pattern, &self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("Path contains invalid character")]
    InvalidCharacter,
    #[error("Path must be absolute")]
    NotAbsolute,
    #[error("Path traversal attempt detected")]
    TraversalAttempt,
    #[error("Invalid path component")]
    InvalidComponent,
}

/// A normalized domain name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedDomain(String);

impl NormalizedDomain {
    pub fn new(raw: &str) -> Result<Self, DomainError> {
        let mut s = raw.to_lowercase();
        
        // Strip port
        if let Some(idx) = s.rfind(':') {
            if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                s = s[..idx].to_string();
            }
        }
        
        // Strip trailing dot
        while s.ends_with('.') {
            s.pop();
        }
        
        // Validate
        if s.is_empty() || s.len() > 253 {
            return Err(DomainError::InvalidLength);
        }
        
        for label in s.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DomainError::InvalidLabel);
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(DomainError::InvalidCharacter);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DomainError::InvalidLabel);
            }
        }
        
        Ok(Self(s))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    /// Check if matches pattern (exact or *.example.com wildcard)
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        let pattern = pattern.to_lowercase();
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // .example.com
            self.0.ends_with(suffix) || self.0 == &pattern[2..]
        } else {
            self.0 == pattern
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("Domain length invalid")]
    InvalidLength,
    #[error("Invalid domain label")]
    InvalidLabel,
    #[error("Invalid character in domain")]
    InvalidCharacter,
}
```

- [ ] **Add glob matching helper**

```rust
/// Simple glob matching for paths
/// Supports: * (single segment), ** (multiple segments), ? (single char)
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    
    glob_match_parts(&pattern_parts, &path_parts)
}

fn glob_match_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            // ** matches zero or more segments
            glob_match_parts(&pattern[1..], path) ||
            (!path.is_empty() && glob_match_parts(pattern, &path[1..]))
        }
        (Some(p), Some(s)) => {
            segment_matches(p, s) && glob_match_parts(&pattern[1..], &path[1..])
        }
        _ => false,
    }
}

fn segment_matches(pattern: &str, segment: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern == segment;
    }
    // Simple wildcard matching
    let mut p_chars = pattern.chars().peekable();
    let mut s_chars = segment.chars().peekable();
    
    while let Some(pc) = p_chars.next() {
        match pc {
            '*' => {
                if p_chars.peek().is_none() {
                    return true; // trailing * matches rest
                }
                // Try matching rest at each position
                while s_chars.peek().is_some() {
                    if segment_matches(&p_chars.clone().collect::<String>(), 
                                       &s_chars.clone().collect::<String>()) {
                        return true;
                    }
                    s_chars.next();
                }
                return false;
            }
            '?' => {
                if s_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                if s_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }
    s_chars.peek().is_none()
}
```

- [ ] **Add tests for normalization**

```rust
#[cfg(test)]
mod path_tests {
    use super::*;
    
    #[test]
    fn test_normalize_simple() {
        let p = NormalizedPath::new("/home/user/file.txt").unwrap();
        assert_eq!(p.as_str(), "/home/user/file.txt");
    }
    
    #[test]
    fn test_normalize_dot_dot() {
        let p = NormalizedPath::new("/home/user/../other/file.txt").unwrap();
        assert_eq!(p.as_str(), "/home/other/file.txt");
    }
    
    #[test]
    fn test_reject_traversal_above_root() {
        let result = NormalizedPath::new("/../etc/passwd");
        assert!(matches!(result, Err(PathError::TraversalAttempt)));
    }
    
    #[test]
    fn test_glob_exact() {
        assert!(glob_match("/home/user", "/home/user"));
        assert!(!glob_match("/home/user", "/home/other"));
    }
    
    #[test]
    fn test_glob_star() {
        assert!(glob_match("/home/*/file", "/home/user/file"));
        assert!(!glob_match("/home/*/file", "/home/user/sub/file"));
    }
    
    #[test]
    fn test_glob_doublestar() {
        assert!(glob_match("/home/**", "/home/user/sub/deep/file"));
        assert!(glob_match("/home/**/file", "/home/user/sub/file"));
    }
}

#[cfg(test)]
mod domain_tests {
    use super::*;
    
    #[test]
    fn test_normalize_lowercase() {
        let d = NormalizedDomain::new("Example.COM").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }
    
    #[test]
    fn test_strip_port() {
        let d = NormalizedDomain::new("example.com:443").unwrap();
        assert_eq!(d.as_str(), "example.com");
    }
    
    #[test]
    fn test_wildcard_match() {
        let d = NormalizedDomain::new("sub.example.com").unwrap();
        assert!(d.matches_pattern("*.example.com"));
        assert!(!d.matches_pattern("*.other.com"));
    }
}
```

- [ ] **Run tests**
  ```bash
  cargo test -p sentinel-types
  ```

### 2.2 Extend Action with Path/Domain Fields

- [ ] **Update Action struct**

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Action {
    pub tool: String,
    pub function: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
    
    // NEW: Extracted from parameters for policy evaluation
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_paths: Vec<String>,
    
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_domains: Vec<String>,
    
    #[serde(default)]
    pub payload_bytes: u64,
}

impl Action {
    /// Extract paths and domains from parameters
    pub fn extract_targets(&mut self) {
        self.target_paths = extract_paths_from_json(&self.parameters);
        self.target_domains = extract_domains_from_json(&self.parameters);
        self.payload_bytes = self.parameters.to_string().len() as u64;
    }
}

fn extract_paths_from_json(value: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    extract_paths_recursive(value, &mut paths);
    paths
}

fn extract_paths_recursive(value: &serde_json::Value, paths: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
                paths.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            // Check known path keys first
            for key in ["path", "file", "filename", "filepath", "directory", "dir"] {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    paths.push(s.clone());
                }
            }
            for v in map.values() {
                extract_paths_recursive(v, paths);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_paths_recursive(v, paths);
            }
        }
        _ => {}
    }
}

fn extract_domains_from_json(value: &serde_json::Value) -> Vec<String> {
    let mut domains = Vec::new();
    extract_domains_recursive(value, &mut domains);
    domains
}

fn extract_domains_recursive(value: &serde_json::Value, domains: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            // Try to extract domain from URL
            if let Ok(url) = url::Url::parse(s) {
                if let Some(host) = url.host_str() {
                    domains.push(host.to_lowercase());
                }
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["url", "uri", "endpoint", "host", "domain", "server"] {
                if let Some(serde_json::Value::String(s)) = map.get(key) {
                    if let Ok(url) = url::Url::parse(s) {
                        if let Some(host) = url.host_str() {
                            domains.push(host.to_lowercase());
                        }
                    } else {
                        // Might be bare domain
                        domains.push(s.to_lowercase());
                    }
                }
            }
            for v in map.values() {
                extract_domains_recursive(v, domains);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                extract_domains_recursive(v, domains);
            }
        }
        _ => {}
    }
}
```

- [ ] **Add `url` dependency to sentinel-types/Cargo.toml**

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
url = "2"
```

- [ ] **Run tests**
  ```bash
  cargo test -p sentinel-types
  cargo test --workspace
  ```

**Checkpoint:** All types compile, extraction works.

---

## Phase 3: Policy Path/Domain Rules (Day 4-5)

### 3.1 Add PathRules and NetworkRules to Policy

- [ ] **Update Policy struct in sentinel-types**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub priority: i32,
    
    // NEW
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rules: Option<PathRules>,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_rules: Option<NetworkRules>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRules {
    /// Glob patterns for allowed paths (empty = allow all)
    #[serde(default)]
    pub allowed: Vec<String>,
    
    /// Glob patterns for blocked paths (checked first)
    #[serde(default)]
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkRules {
    /// Allowed domain patterns (empty = allow all)
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    
    /// Blocked domain patterns (checked first)
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    
    /// Allow connections to private IP ranges (default: false)
    #[serde(default)]
    pub allow_private_ip: bool,
}
```

### 3.2 Update Engine to Evaluate Path/Domain Rules

- [ ] **Modify evaluate_action in sentinel-engine**

```rust
pub fn evaluate_action(&self, action: &Action, policies: &[Policy]) -> Result<Verdict, EngineError> {
    // Find matching policy by tool:function pattern
    let matching_policy = self.find_matching_policy(action, policies)?;
    
    match matching_policy {
        None => {
            // Fail closed
            Ok(Verdict::Deny {
                reason: "No matching policy found".to_string(),
                matched_policy: None,
            })
        }
        Some(policy) => {
            // First check path constraints
            if let Some(ref path_rules) = policy.path_rules {
                if let Some(denial) = self.check_path_rules(action, path_rules, &policy.id)? {
                    return Ok(denial);
                }
            }
            
            // Then check network constraints
            if let Some(ref network_rules) = policy.network_rules {
                if let Some(denial) = self.check_network_rules(action, network_rules, &policy.id)? {
                    return Ok(denial);
                }
            }
            
            // Apply policy type
            match &policy.policy_type {
                PolicyType::Allow => Ok(Verdict::Allow {
                    reason: format!("Allowed by policy: {}", policy.name),
                    matched_policy: Some(policy.id.clone()),
                }),
                PolicyType::Deny => Ok(Verdict::Deny {
                    reason: format!("Denied by policy: {}", policy.name),
                    matched_policy: Some(policy.id.clone()),
                }),
                PolicyType::Conditional { conditions } => Ok(Verdict::RequireApproval {
                    reason: format!("Requires approval per policy: {}", policy.name),
                    conditions: conditions.clone(),
                    matched_policy: Some(policy.id.clone()),
                }),
            }
        }
    }
}

fn check_path_rules(
    &self,
    action: &Action,
    rules: &PathRules,
    policy_id: &str,
) -> Result<Option<Verdict>, EngineError> {
    for path in &action.target_paths {
        // Normalize the path
        let normalized = match NormalizedPath::new(path) {
            Ok(p) => p,
            Err(e) => {
                // Invalid path is suspicious, deny
                return Ok(Some(Verdict::Deny {
                    reason: format!("Invalid path '{}': {}", path, e),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        };
        
        // Check blocked patterns first (deny wins)
        for pattern in &rules.blocked {
            if normalized.matches_glob(pattern) {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path '{}' matches blocked pattern '{}'", path, pattern),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        }
        
        // Check allowed patterns (if any specified)
        if !rules.allowed.is_empty() {
            let allowed = rules.allowed.iter().any(|p| normalized.matches_glob(p));
            if !allowed {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Path '{}' not in allowed list", path),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        }
    }
    
    Ok(None) // All paths OK
}

fn check_network_rules(
    &self,
    action: &Action,
    rules: &NetworkRules,
    policy_id: &str,
) -> Result<Option<Verdict>, EngineError> {
    for domain in &action.target_domains {
        let normalized = match NormalizedDomain::new(domain) {
            Ok(d) => d,
            Err(e) => {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Invalid domain '{}': {}", domain, e),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        };
        
        // Check blocked patterns first
        for pattern in &rules.blocked_domains {
            if normalized.matches_pattern(pattern) {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Domain '{}' matches blocked pattern '{}'", domain, pattern),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        }
        
        // Check allowed patterns
        if !rules.allowed_domains.is_empty() {
            let allowed = rules.allowed_domains.iter().any(|p| normalized.matches_pattern(p));
            if !allowed {
                return Ok(Some(Verdict::Deny {
                    reason: format!("Domain '{}' not in allowed list", domain),
                    matched_policy: Some(policy_id.to_string()),
                }));
            }
        }
    }
    
    Ok(None)
}
```

### 3.3 Update Config Parser

- [ ] **Extend PolicyRule in sentinel-config**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub tool_pattern: String,
    pub function_pattern: String,
    pub policy_type: String,  // "Allow", "Deny", "Conditional"
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub id: Option<String>,
    
    // NEW
    #[serde(default)]
    pub path_rules: Option<PathRulesConfig>,
    #[serde(default)]
    pub network_rules: Option<NetworkRulesConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRulesConfig {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkRulesConfig {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    #[serde(default)]
    pub allow_private_ip: bool,
}
```

- [ ] **Update to_policies() conversion**

```rust
impl PolicyRule {
    pub fn to_policy(&self) -> Policy {
        let id = self.id.clone()
            .unwrap_or_else(|| format!("{}:{}", self.tool_pattern, self.function_pattern));
        
        let policy_type = match self.policy_type.to_lowercase().as_str() {
            "allow" => PolicyType::Allow,
            "deny" => PolicyType::Deny,
            "conditional" => PolicyType::Conditional {
                conditions: HashMap::new(),
            },
            _ => PolicyType::Deny, // fail safe
        };
        
        Policy {
            id,
            name: self.name.clone(),
            policy_type,
            priority: self.priority,
            path_rules: self.path_rules.as_ref().map(|r| PathRules {
                allowed: r.allowed.clone(),
                blocked: r.blocked.clone(),
            }),
            network_rules: self.network_rules.as_ref().map(|r| NetworkRules {
                allowed_domains: r.allowed_domains.clone(),
                blocked_domains: r.blocked_domains.clone(),
                allow_private_ip: r.allow_private_ip,
            }),
        }
    }
}
```

### 3.4 Add Tests for Path/Domain Enforcement

- [ ] **Create comprehensive tests**

```rust
// In sentinel-engine/tests/path_domain_tests.rs

#[test]
fn test_blocked_path_denies_even_when_tool_allowed() {
    let policy = Policy {
        id: "read_file:*".to_string(),
        name: "file_access".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: Some(PathRules {
            allowed: vec!["/home/user/project/**".to_string()],
            blocked: vec!["/home/user/.aws/**".to_string(), "/home/user/.ssh/**".to_string()],
        }),
        network_rules: None,
    };
    
    let engine = PolicyEngine::new();
    
    // Allowed path
    let action = Action {
        tool: "read_file".to_string(),
        function: "read".to_string(),
        target_paths: vec!["/home/user/project/src/main.rs".to_string()],
        ..Default::default()
    };
    let verdict = engine.evaluate_action(&action, &[policy.clone()]).unwrap();
    assert!(matches!(verdict, Verdict::Allow { .. }));
    
    // Blocked path
    let action = Action {
        tool: "read_file".to_string(),
        function: "read".to_string(),
        target_paths: vec!["/home/user/.aws/credentials".to_string()],
        ..Default::default()
    };
    let verdict = engine.evaluate_action(&action, &[policy.clone()]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}

#[test]
fn test_blocked_domain_denies() {
    let policy = Policy {
        id: "http_request:*".to_string(),
        name: "network".to_string(),
        policy_type: PolicyType::Allow,
        priority: 100,
        path_rules: None,
        network_rules: Some(NetworkRules {
            allowed_domains: vec!["api.anthropic.com".to_string(), "*.company.com".to_string()],
            blocked_domains: vec!["*.pastebin.com".to_string()],
            allow_private_ip: false,
        }),
    };
    
    let engine = PolicyEngine::new();
    
    // Allowed domain
    let action = Action {
        tool: "http_request".to_string(),
        function: "post".to_string(),
        target_domains: vec!["api.anthropic.com".to_string()],
        ..Default::default()
    };
    let verdict = engine.evaluate_action(&action, &[policy.clone()]).unwrap();
    assert!(matches!(verdict, Verdict::Allow { .. }));
    
    // Blocked domain
    let action = Action {
        tool: "http_request".to_string(),
        function: "post".to_string(),
        target_domains: vec!["evil.pastebin.com".to_string()],
        ..Default::default()
    };
    let verdict = engine.evaluate_action(&action, &[policy.clone()]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
    
    // Not in allowlist
    let action = Action {
        tool: "http_request".to_string(),
        function: "post".to_string(),
        target_domains: vec!["unknown.com".to_string()],
        ..Default::default()
    };
    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(matches!(verdict, Verdict::Deny { .. }));
}
```

- [ ] **Run all tests**
  ```bash
  cargo test --workspace
  ```

**Checkpoint:** Path/domain enforcement works. This is the CORE SECURITY VALUE.

---

## Phase 4: MCP Transport (Day 6-8)

### 4.1 MCP JSON-RPC Parser

- [ ] **Create `sentinel-mcp/src/parser.rs`**

(See detailed implementation in previous messages)

Key types:
- `JsonRpcRequest`, `JsonRpcResponse`
- `McpMessage::ToolCall`, `McpMessage::ToolResult`
- `parse(line: &str) -> Result<McpMessage, ParseError>`

### 4.2 Action Extractor

- [ ] **Create `sentinel-mcp/src/extractor.rs`**

```rust
pub fn extract_action(tool_call: &ToolCallParams, request_id: &str) -> Action {
    let mut action = Action {
        tool: tool_call.name.clone(),
        function: "call".to_string(),
        parameters: tool_call.arguments.clone(),
        ..Default::default()
    };
    action.extract_targets();
    action
}
```

### 4.3 stdio Proxy

- [ ] **Create `sentinel-mcp/src/proxy.rs`**

Minimal implementation:
- Spawn child process (MCP server)
- Read lines from stdin, parse, evaluate, forward or block
- Read lines from child stdout, forward to our stdout
- Log all decisions

### 4.4 CLI Command

- [ ] **Add `proxy` subcommand to sentinel-server**

```rust
#[derive(Parser)]
enum Commands {
    Serve { ... },
    Evaluate { ... },
    // NEW
    Proxy {
        #[arg(long)]
        config: PathBuf,
        
        #[arg(last = true)]
        command: Vec<String>,
    },
}
```

**Checkpoint:** `sentinel proxy --config policy.toml -- npx @mcp/server-fs /tmp` works.

---

## Phase 5: Approval System (Day 9-10)

### 5.1 PendingStore

- [ ] **Create data structures and storage**

### 5.2 HTTP Endpoints

- [ ] **Add `/api/pending`, `/api/pending/:id/approve`, `/api/pending/:id/deny`**

### 5.3 Proxy Integration

- [ ] **On `RequireApproval`, queue action and return structured response**

**Checkpoint:** Actions can be queued and approved.

---

## Phase 6: Tamper-Evident Audit (Day 11)

### 6.1 Hash Chain

- [ ] **Add `prev_hash` and `entry_hash` to `AuditEntry`**
- [ ] **Implement chain computation in `log_entry()`**

### 6.2 Verify Command

- [ ] **Add `sentinel audit verify <file>`**

**Checkpoint:** Audit log is verifiable.

---

## Phase 7: Demo & Polish (Day 12-14)

### 7.1 Demo Scenario

- [ ] **Create attack script showing credential exfiltration blocked**

### 7.2 Documentation

- [ ] **Update README with quickstart**
- [ ] **Add example policies**

### 7.3 Final Validation

```bash
# Full test suite
cargo test --workspace

# Clippy clean
cargo clippy --workspace -- -D warnings

# Formatted
cargo fmt --check

# Docs build
cargo doc --workspace --no-deps

# Binary size check
cargo build --release
ls -lh target/release/sentinel

# Memory check (if valgrind available)
valgrind --tool=massif target/release/sentinel serve --config example.toml &
# ... exercise endpoints ...
# Check massif output
```

**Checkpoint:** Ready for v0.1.0 release.

---

## 📊 Progress Tracking

> **Note:** This document originally tracked the v0.1→v1.0 implementation tasks.
> All original phases below have been completed or superseded. The project is now
> at **v2.2.1** with 4,300+ tests across 15 phases of implementation. See
> `ROADMAP.md` for the full Phase 1–16+ roadmap and `CHANGELOG.md` for release history.

```
Phase 1: Foundation Fixes     [▓▓▓▓▓▓▓▓▓▓] 100% ✓  (warnings fixed, CI workflow created, clippy clean)
Phase 2: Path/Domain Types    [▓▓▓▓▓▓▓▓▓▓] SUPERSEDED — parameter_constraints approach used instead
Phase 3: Policy Rules         [▓▓▓▓▓▓▓▓▓▓] SUPERSEDED — parameter_constraints approach used instead
Phase 4: MCP Transport        [▓▓▓▓▓▓▓▓▓▓] 100% ✓  (sentinel-mcp parser, extractor, proxy, sentinel-proxy CLI)
Phase 5: Approval System      [▓▓▓▓▓▓▓▓▓▓] 100% ✓  (ApprovalStore, API endpoints, proxy integration, dedup)
Phase 6: Tamper-Evident Audit [▓▓▓▓▓▓▓▓▓▓] 100% ✓  (SHA-256 hash chain, Ed25519 checkpoints, rotation, export)
Phase 7: Demo & Polish        [▓▓▓▓▓▓▓▓▓▓] 100% ✓  (README, examples, v1.0.0 release)

Overall (v0.1 tasks): [▓▓▓▓▓▓▓▓▓▓] 100% ✓
```

### Post-v1.0 phases (tracked in ROADMAP.md)

```
Phase 1:    MCP 2025-11-25 Compliance         ✅ COMPLETE
Phase 2:    Advanced Threat Detection          ✅ COMPLETE
Phase 3.1:  Runtime Integration                ✅ COMPLETE
Phase 3.2:  Cross-Agent Security               ✅ COMPLETE
Phase 3.3:  Advanced Threat Detection          ✅ COMPLETE
Phase 4.1:  Standards Alignment                ✅ COMPLETE
Phase 5:    Enterprise Hardening (Config)      ✅ COMPLETE
Phase 5.5:  Enterprise Hardening (Runtime)     ✅ COMPLETE (FIPS deferred)
Phase 6:    Observability & Tooling            ✅ COMPLETE
Phase 7:    Documentation & Release            ✅ COMPLETE (v2.0.0)
Phase 8:    ETDI Cryptographic Tool Security   ✅ COMPLETE
Phase 9:    Memory Injection Defense           ✅ COMPLETE
Phase 10:   NHI Lifecycle                      ✅ COMPLETE
Phase 11:   MCP Tasks Primitive                ✅ COMPLETE
Phase 12:   Semantic Guardrails                ✅ COMPLETE
Phase 13:   RAG Poisoning Defense              ✅ COMPLETE
Phase 14:   A2A Protocol Security              ✅ COMPLETE
Phase 15:   Observability Platform Integration ✅ COMPLETE (v2.2.1)
Phase 16+:  Future (SDK, marketplace, DX)      🔮 PLANNED
```

### Quality metrics (2026-02-12)

- **4,300+ tests** across all crates, zero failures
- **35 security audit rounds** + **18 adversarial audit rounds** (FIND-043–054 addressed)
- **Zero `unwrap()`** in library code
- **Zero clippy warnings**
- Fuzz targets, Criterion benchmarks, property-based tests

---

*Last updated: 2026-02-12*
