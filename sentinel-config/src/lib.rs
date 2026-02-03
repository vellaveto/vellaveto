use sentinel_types::{Policy, PolicyType};
use serde::{Deserialize, Serialize};

fn default_priority() -> Option<i32> {
    Some(100)
}

/// Configuration for the prompt injection detection scanner.
///
/// Controls which patterns are used for response inspection. The scanner
/// operates as a heuristic pre-filter — it cannot stop all injection attacks
/// but raises alerts for known signatures.
///
/// # TOML Example
///
/// ```toml
/// [injection]
/// enabled = true
/// extra_patterns = ["transfer funds", "send bitcoin", "exfiltrate"]
/// disabled_patterns = ["pretend you are"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    /// Master toggle for injection scanning. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Additional patterns appended to the default set.
    /// Matched case-insensitively after Unicode sanitization.
    #[serde(default)]
    pub extra_patterns: Vec<String>,

    /// Default patterns to remove. Any default pattern whose text matches
    /// an entry here (case-insensitive) will be excluded from scanning.
    #[serde(default)]
    pub disabled_patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            extra_patterns: Vec::new(),
            disabled_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub tool_pattern: String,
    pub function_pattern: String,
    pub policy_type: PolicyType,
    #[serde(default = "default_priority")]
    pub priority: Option<i32>,
    #[serde(default)]
    pub id: Option<String>,
}

impl PolicyRule {
    /// Effective priority (defaults to 100).
    pub fn effective_priority(&self) -> i32 {
        self.priority.unwrap_or(100)
    }

    /// Effective ID (defaults to "tool_pattern:function_pattern").
    pub fn effective_id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", self.tool_pattern, self.function_pattern))
    }
}

/// Rate limiting configuration for the HTTP server.
///
/// All fields are optional — omitted values fall back to environment variable
/// overrides or sensible defaults (rate limiting disabled for that category).
///
/// # TOML Example
///
/// ```toml
/// [rate_limit]
/// evaluate_rps = 1000
/// evaluate_burst = 50
/// admin_rps = 20
/// admin_burst = 5
/// readonly_rps = 200
/// readonly_burst = 20
/// per_ip_rps = 100
/// per_ip_burst = 10
/// per_ip_max_capacity = 100000
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Max sustained requests/sec for `/evaluate` endpoints.
    pub evaluate_rps: Option<u32>,
    /// Burst allowance above `evaluate_rps` (tokens in the bucket beyond 1).
    pub evaluate_burst: Option<u32>,
    /// Max sustained requests/sec for admin/mutating endpoints.
    pub admin_rps: Option<u32>,
    /// Burst allowance above `admin_rps`.
    pub admin_burst: Option<u32>,
    /// Max sustained requests/sec for read-only endpoints.
    pub readonly_rps: Option<u32>,
    /// Burst allowance above `readonly_rps`.
    pub readonly_burst: Option<u32>,
    /// Max sustained requests/sec per unique client IP.
    pub per_ip_rps: Option<u32>,
    /// Burst allowance above `per_ip_rps`.
    pub per_ip_burst: Option<u32>,
    /// Maximum number of unique IPs tracked simultaneously.
    pub per_ip_max_capacity: Option<usize>,
}

/// Audit log configuration.
///
/// # TOML Example
///
/// ```toml
/// [audit]
/// redaction_level = "KeysAndPatterns"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Redaction level for audit log entries.
    /// - `"Off"`: no redaction
    /// - `"KeysOnly"`: redact sensitive keys and value prefixes
    /// - `"KeysAndPatterns"` (default): redact keys, prefixes, and PII patterns
    #[serde(default)]
    pub redaction_level: Option<String>,
}

/// Supply chain verification configuration.
///
/// When enabled, the proxy verifies SHA-256 hashes of MCP server binaries
/// before spawning them.
///
/// # TOML Example
///
/// ```toml
/// [supply_chain]
/// enabled = true
///
/// [supply_chain.allowed_servers]
/// "/usr/local/bin/my-mcp" = "sha256hex..."
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupplyChainConfig {
    /// Master toggle. When false (default), binary verification is skipped.
    #[serde(default)]
    pub enabled: bool,
    /// Map of binary path → expected SHA-256 hex digest.
    #[serde(default)]
    pub allowed_servers: std::collections::HashMap<String, String>,
}

impl SupplyChainConfig {
    /// Verify that a binary at `path` matches its expected SHA-256 hash.
    ///
    /// Returns `Ok(())` if verification passes or is disabled. Returns
    /// `Err(reason)` if the binary is unlisted, missing, or has a hash mismatch.
    pub fn verify_binary(&self, path: &str) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let expected_hash = self
            .allowed_servers
            .get(path)
            .ok_or_else(|| format!("Binary '{}' not in allowed_servers list", path))?;

        let data =
            std::fs::read(path).map_err(|e| format!("Failed to read binary '{}': {}", path, e))?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != *expected_hash {
            return Err(format!(
                "Hash mismatch for '{}': expected {}, got {}",
                path, expected_hash, actual_hash
            ));
        }

        Ok(())
    }
}

/// Tool manifest verification configuration.
///
/// # TOML Example
///
/// ```toml
/// [manifest]
/// enabled = true
/// trusted_keys = ["hex-encoded-ed25519-public-key"]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestConfig {
    /// Enable tool manifest schema pinning. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Trusted Ed25519 public keys (hex-encoded 32-byte) for manifest signatures.
    #[serde(default)]
    pub trusted_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policies: Vec<PolicyRule>,

    /// Optional injection scanning configuration.
    /// When absent, defaults are used (scanning enabled, default patterns only).
    #[serde(default)]
    pub injection: InjectionConfig,

    /// Optional rate limiting configuration.
    /// When absent, all rate limits are unconfigured (env vars or defaults apply).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Optional audit log configuration (redaction level).
    #[serde(default)]
    pub audit: AuditConfig,

    /// Optional supply chain verification configuration.
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,

    /// Optional tool manifest verification configuration.
    #[serde(default)]
    pub manifest: ManifestConfig,
}

impl PolicyConfig {
    /// Parse config from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Parse config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Load config from a file path. Selects parser based on extension.
    pub fn load_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        if path.ends_with(".toml") {
            Ok(Self::from_toml(&content)?)
        } else if path.ends_with(".json") {
            Ok(Self::from_json(&content)?)
        } else {
            Self::from_toml(&content)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        }
    }

    /// Convert PolicyRules into sentinel_types::Policy structs.
    pub fn to_policies(&self) -> Vec<Policy> {
        self.policies
            .iter()
            .map(|rule| {
                let id = rule
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("{}:{}", rule.tool_pattern, rule.function_pattern));
                let priority = rule.priority.unwrap_or(100);
                Policy {
                    id,
                    name: rule.name.clone(),
                    policy_type: rule.policy_type.clone(),
                    priority,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_json_basic() {
        let json = r#"{"policies":[{"name":"test","tool_pattern":"*","function_pattern":"*","policy_type":"Allow"}]}"#;
        let config = PolicyConfig::from_json(json).unwrap();
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].name, "test");
    }

    #[test]
    fn test_from_toml_basic() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert_eq!(config.policies.len(), 1);
    }

    #[test]
    fn test_priority_defaults_to_100() {
        let toml = r#"
[[policies]]
name = "no priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert_eq!(config.policies[0].priority, Some(100));
        let policies = config.to_policies();
        assert_eq!(policies[0].priority, 100);
    }

    #[test]
    fn test_id_defaults_to_pattern_combo() {
        let toml = r#"
[[policies]]
name = "auto id"
tool_pattern = "bash"
function_pattern = "exec"
policy_type = "Deny"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.policies[0].id.is_none());
        let policies = config.to_policies();
        assert_eq!(policies[0].id, "bash:exec");
    }

    #[test]
    fn test_explicit_id_preserved() {
        let toml = r#"
[[policies]]
name = "custom"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
id = "my-custom-id"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        let policies = config.to_policies();
        assert_eq!(policies[0].id, "my-custom-id");
    }

    #[test]
    fn test_to_policies_converts_all() {
        let toml = r#"
[[policies]]
name = "a"
tool_pattern = "t1"
function_pattern = "f1"
policy_type = "Allow"
priority = 10

[[policies]]
name = "b"
tool_pattern = "t2"
function_pattern = "f2"
policy_type = "Deny"
priority = 200
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        let policies = config.to_policies();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].priority, 10);
        assert_eq!(policies[1].priority, 200);
    }

    #[test]
    fn test_injection_config_defaults_when_absent() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.injection.enabled);
        assert!(config.injection.extra_patterns.is_empty());
        assert!(config.injection.disabled_patterns.is_empty());
    }

    #[test]
    fn test_injection_config_custom_patterns() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = true
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.injection.enabled);
        assert_eq!(config.injection.extra_patterns.len(), 2);
        assert_eq!(config.injection.extra_patterns[0], "transfer funds");
        assert_eq!(config.injection.disabled_patterns.len(), 1);
        assert_eq!(config.injection.disabled_patterns[0], "pretend you are");
    }

    #[test]
    fn test_injection_config_disabled() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = false
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(!config.injection.enabled);
    }

    #[test]
    fn test_load_file_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            r#"
[[policies]]
name = "deny bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 20
"#,
        )
        .unwrap();

        let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].name, "deny bash");
        assert_eq!(config.policies[0].tool_pattern, "bash");
    }

    #[test]
    fn test_load_file_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(
            &path,
            r#"{
                "policies": [{
                    "name": "allow read",
                    "tool_pattern": "read_file",
                    "function_pattern": "*",
                    "policy_type": "Allow"
                }]
            }"#,
        )
        .unwrap();

        let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].name, "allow read");
    }

    #[test]
    fn test_load_file_not_found() {
        let result = PolicyConfig::load_file("/nonexistent/path/policy.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_file_invalid_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml {{{").unwrap();

        let result = PolicyConfig::load_file(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_file_invalid_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "{invalid json!}").unwrap();

        let result = PolicyConfig::load_file(path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_file_unknown_extension_tries_toml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("policy.conf");
        std::fs::write(
            &path,
            r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap();

        // Unknown extension should fall back to TOML parsing
        let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
        assert_eq!(config.policies.len(), 1);
    }

    #[test]
    fn test_rate_limit_config_defaults_when_absent() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.rate_limit.evaluate_rps.is_none());
        assert!(config.rate_limit.evaluate_burst.is_none());
        assert!(config.rate_limit.admin_rps.is_none());
        assert!(config.rate_limit.admin_burst.is_none());
        assert!(config.rate_limit.readonly_rps.is_none());
        assert!(config.rate_limit.readonly_burst.is_none());
        assert!(config.rate_limit.per_ip_rps.is_none());
        assert!(config.rate_limit.per_ip_burst.is_none());
        assert!(config.rate_limit.per_ip_max_capacity.is_none());
    }

    #[test]
    fn test_rate_limit_config_parses_values() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[rate_limit]
evaluate_rps = 1000
evaluate_burst = 50
admin_rps = 20
admin_burst = 5
readonly_rps = 200
readonly_burst = 20
per_ip_rps = 100
per_ip_burst = 10
per_ip_max_capacity = 50000
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert_eq!(config.rate_limit.evaluate_rps, Some(1000));
        assert_eq!(config.rate_limit.evaluate_burst, Some(50));
        assert_eq!(config.rate_limit.admin_rps, Some(20));
        assert_eq!(config.rate_limit.admin_burst, Some(5));
        assert_eq!(config.rate_limit.readonly_rps, Some(200));
        assert_eq!(config.rate_limit.readonly_burst, Some(20));
        assert_eq!(config.rate_limit.per_ip_rps, Some(100));
        assert_eq!(config.rate_limit.per_ip_burst, Some(10));
        assert_eq!(config.rate_limit.per_ip_max_capacity, Some(50000));
    }

    #[test]
    fn test_rate_limit_config_partial_values() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[rate_limit]
evaluate_rps = 500
per_ip_rps = 50
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert_eq!(config.rate_limit.evaluate_rps, Some(500));
        assert!(config.rate_limit.evaluate_burst.is_none());
        assert!(config.rate_limit.admin_rps.is_none());
        assert_eq!(config.rate_limit.per_ip_rps, Some(50));
        assert!(config.rate_limit.per_ip_burst.is_none());
        assert!(config.rate_limit.per_ip_max_capacity.is_none());
    }
}
