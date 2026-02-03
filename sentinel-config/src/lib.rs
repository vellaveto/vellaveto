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

/// A pinned tool manifest that records the expected tools and their schema hashes.
///
/// Created from a `tools/list` response, then persisted. On subsequent
/// `tools/list` responses, the live tools are compared against this manifest
/// to detect unexpected changes (new tools, removed tools, schema mutations).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolManifest {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Pinned tool entries with schema hashes.
    pub tools: Vec<ManifestToolEntry>,
    /// Optional Ed25519 signature over the canonical manifest content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A single tool entry in a pinned manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestToolEntry {
    /// Tool name as reported by the MCP server.
    pub name: String,
    /// SHA-256 hex digest of the canonical JSON-serialized `inputSchema`.
    /// If the tool has no inputSchema, this is the hash of the empty string.
    pub input_schema_hash: String,
}

/// Result of manifest verification.
#[derive(Debug, Clone)]
pub struct ManifestVerification {
    /// Whether the manifest matched (no discrepancies).
    pub passed: bool,
    /// Human-readable discrepancy descriptions, empty if passed.
    pub discrepancies: Vec<String>,
}

impl ToolManifest {
    /// Build a manifest from a live `tools/list` JSON-RPC response.
    ///
    /// Expects `response` to contain `result.tools[]` with `name` and
    /// optional `inputSchema` fields per the MCP specification.
    pub fn from_tools_list(response: &serde_json::Value) -> Option<Self> {
        let tools_array = response
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())?;

        let mut entries: Vec<ManifestToolEntry> = tools_array
            .iter()
            .filter_map(|tool| {
                let name = tool.get("name")?.as_str()?.to_string();
                let schema_json = tool
                    .get("inputSchema")
                    .map(|s| serde_json::to_string(s).unwrap_or_default())
                    .unwrap_or_default();

                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(schema_json.as_bytes());
                let hash = hex::encode(hasher.finalize());

                Some(ManifestToolEntry {
                    name,
                    input_schema_hash: hash,
                })
            })
            .collect();

        // Sort by name for deterministic comparison
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Some(ToolManifest {
            schema_version: "1.0".to_string(),
            tools: entries,
            signature: None,
        })
    }

    /// Verify a live `tools/list` response against this pinned manifest.
    pub fn verify(&self, live_response: &serde_json::Value) -> ManifestVerification {
        let live = match Self::from_tools_list(live_response) {
            Some(m) => m,
            None => {
                return ManifestVerification {
                    passed: false,
                    discrepancies: vec![
                        "Failed to parse tools/list response for verification".to_string()
                    ],
                };
            }
        };

        let mut discrepancies = Vec::new();

        // Build lookup maps
        let pinned_map: std::collections::HashMap<&str, &str> = self
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.input_schema_hash.as_str()))
            .collect();

        let live_map: std::collections::HashMap<&str, &str> = live
            .tools
            .iter()
            .map(|t| (t.name.as_str(), t.input_schema_hash.as_str()))
            .collect();

        // Check for removed tools
        for pinned in &self.tools {
            if !live_map.contains_key(pinned.name.as_str()) {
                discrepancies.push(format!("Tool '{}' removed from server", pinned.name));
            }
        }

        // Check for new or changed tools
        for live_tool in &live.tools {
            match pinned_map.get(live_tool.name.as_str()) {
                None => {
                    discrepancies.push(format!(
                        "New tool '{}' not in pinned manifest",
                        live_tool.name
                    ));
                }
                Some(expected_hash) => {
                    if *expected_hash != live_tool.input_schema_hash {
                        discrepancies.push(format!(
                            "Tool '{}' schema changed: expected {}, got {}",
                            live_tool.name, expected_hash, live_tool.input_schema_hash
                        ));
                    }
                }
            }
        }

        ManifestVerification {
            passed: discrepancies.is_empty(),
            discrepancies,
        }
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

impl ManifestConfig {
    /// Verify a live tools/list response against a pinned manifest.
    ///
    /// Returns `Ok(())` if verification passes or is disabled.
    /// Returns `Err(discrepancies)` if the manifest doesn't match.
    pub fn verify_manifest(
        &self,
        pinned: &ToolManifest,
        live_response: &serde_json::Value,
    ) -> Result<(), Vec<String>> {
        if !self.enabled {
            return Ok(());
        }

        let result = pinned.verify(live_response);
        if result.passed {
            Ok(())
        } else {
            Err(result.discrepancies)
        }
    }
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
                    path_rules: None,
                    network_rules: None,
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

    // --- Supply chain verification tests ---

    #[test]
    fn test_supply_chain_disabled_always_passes() {
        let config = SupplyChainConfig {
            enabled: false,
            allowed_servers: std::collections::HashMap::new(),
        };
        assert!(config.verify_binary("/nonexistent/path").is_ok());
    }

    #[test]
    fn test_supply_chain_correct_hash_passes() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("fake-server");
        std::fs::write(&bin_path, b"hello server binary").unwrap();

        // Compute expected hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"hello server binary");
        let expected_hash = hex::encode(hasher.finalize());

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(bin_path.to_string_lossy().to_string(), expected_hash);

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
        };
        assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
    }

    #[test]
    fn test_supply_chain_wrong_hash_fails() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("fake-server");
        std::fs::write(&bin_path, b"hello server binary").unwrap();

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            bin_path.to_string_lossy().to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
        };
        let result = config.verify_binary(&bin_path.to_string_lossy());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hash mismatch"));
    }

    #[test]
    fn test_supply_chain_unlisted_binary_fails() {
        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: std::collections::HashMap::new(),
        };
        let result = config.verify_binary("/usr/bin/something");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowed_servers"));
    }

    #[test]
    fn test_supply_chain_missing_binary_fails() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "/nonexistent/binary".to_string(),
            "abcdef1234567890".to_string(),
        );

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
        };
        let result = config.verify_binary("/nonexistent/binary");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to read"));
    }

    // --- Manifest verification tests ---

    fn make_tools_list_response(tools: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let tool_entries: Vec<serde_json::Value> = tools
            .iter()
            .map(|(name, schema)| {
                serde_json::json!({
                    "name": name,
                    "inputSchema": schema,
                })
            })
            .collect();
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": tool_entries }
        })
    }

    #[test]
    fn test_manifest_from_tools_list() {
        let response = make_tools_list_response(&[
            (
                "read_file",
                serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
            ),
            (
                "write_file",
                serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}),
            ),
        ]);
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert_eq!(manifest.schema_version, "1.0");
        assert_eq!(manifest.tools.len(), 2);
        // Tools should be sorted by name
        assert_eq!(manifest.tools[0].name, "read_file");
        assert_eq!(manifest.tools[1].name, "write_file");
        // Hashes should be non-empty hex strings
        assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
    }

    #[test]
    fn test_manifest_verify_identical_passes() {
        let response = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            (
                "tool_b",
                serde_json::json!({"type": "object", "properties": {}}),
            ),
        ]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = pinned.verify(&response);
        assert!(result.passed);
        assert!(result.discrepancies.is_empty());
    }

    #[test]
    fn test_manifest_verify_new_tool_detected() {
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "object"})),
        ]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("New tool 'tool_b'")));
    }

    #[test]
    fn test_manifest_verify_removed_tool_detected() {
        let original = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "object"})),
        ]);
        let modified =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result.discrepancies.iter().any(|d| d.contains("removed")));
    }

    #[test]
    fn test_manifest_verify_schema_change_detected() {
        let original = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        )]);
        let modified = make_tools_list_response(&[(
            "tool_a",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "force": {"type": "boolean"}}}),
        )]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let result = pinned.verify(&modified);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("schema changed")));
    }

    #[test]
    fn test_manifest_verify_invalid_response() {
        let pinned = ToolManifest {
            schema_version: "1.0".to_string(),
            tools: vec![],
            signature: None,
        };
        let bad_response = serde_json::json!({"error": "something"});
        let result = pinned.verify(&bad_response);
        assert!(!result.passed);
        assert!(result
            .discrepancies
            .iter()
            .any(|d| d.contains("Failed to parse")));
    }

    #[test]
    fn test_manifest_config_disabled_always_passes() {
        let config = ManifestConfig {
            enabled: false,
            trusted_keys: vec![],
        };
        let pinned = ToolManifest {
            schema_version: "1.0".to_string(),
            tools: vec![ManifestToolEntry {
                name: "tool_a".to_string(),
                input_schema_hash: "deadbeef".to_string(),
            }],
            signature: None,
        };
        // Even with a completely wrong response, disabled config passes
        let bad_response = serde_json::json!({"error": "something"});
        assert!(config.verify_manifest(&pinned, &bad_response).is_ok());
    }

    #[test]
    fn test_manifest_config_enabled_detects_mismatch() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
        };
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();

        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("injected_tool", serde_json::json!({"type": "object"})),
        ]);
        let result = config.verify_manifest(&pinned, &modified);
        assert!(result.is_err());
        let discrepancies = result.unwrap_err();
        assert!(discrepancies.iter().any(|d| d.contains("injected_tool")));
    }

    #[test]
    fn test_manifest_tool_without_schema() {
        // Tools without inputSchema should still get a hash (of empty string)
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "simple_tool"}
                ]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "simple_tool");
        // Hash of empty string
        assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
    }
}
