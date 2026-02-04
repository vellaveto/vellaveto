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

    /// When true, injection matches block the response instead of just logging.
    /// Default: `false` (log-only mode, backward compatible).
    #[serde(default)]
    pub block_on_injection: bool,

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
            block_on_injection: false,
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
/// per_principal_rps = 50
/// per_principal_burst = 10
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
    /// Max sustained requests/sec per principal (identified by X-Principal
    /// header, Bearer token, or client IP as fallback).
    pub per_principal_rps: Option<u32>,
    /// Burst allowance above `per_principal_rps`.
    pub per_principal_burst: Option<u32>,
}

/// A custom PII detection pattern for audit log redaction.
///
/// Allows operators to add site-specific patterns beyond the built-in set
/// (email, SSN, phone, credit card, etc.).
///
/// # TOML Example
///
/// ```toml
/// [[audit.custom_pii_patterns]]
/// name = "internal_employee_id"
/// pattern = "EMP-\\d{6}"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPiiPattern {
    /// Human-readable name for this pattern (used in diagnostics).
    pub name: String,
    /// Regex pattern string. Invalid patterns are logged and skipped at startup.
    pub pattern: String,
}

/// Audit log configuration.
///
/// # TOML Example
///
/// ```toml
/// [audit]
/// redaction_level = "KeysAndPatterns"
///
/// [[audit.custom_pii_patterns]]
/// name = "internal_employee_id"
/// pattern = "EMP-\\d{6}"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Redaction level for audit log entries.
    /// - `"Off"`: no redaction
    /// - `"KeysOnly"`: redact sensitive keys and value prefixes
    /// - `"KeysAndPatterns"` (default): redact keys, prefixes, and PII patterns
    #[serde(default)]
    pub redaction_level: Option<String>,
    /// Custom PII detection patterns appended to the built-in set.
    #[serde(default)]
    pub custom_pii_patterns: Vec<CustomPiiPattern>,
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
    /// When true, validate that all paths in `allowed_servers` exist at load time.
    #[serde(default)]
    pub validate_paths_on_load: bool,
}

impl SupplyChainConfig {
    /// Compute the SHA-256 hash of a file at the given path.
    ///
    /// Returns the hex-encoded hash string, or an error if the file cannot be read.
    pub fn compute_hash(path: &str) -> Result<String, String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read '{}': {}", path, e))?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(hex::encode(hasher.finalize()))
    }

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

        let actual_hash = Self::compute_hash(path)?;

        if actual_hash != *expected_hash {
            return Err(format!(
                "Hash mismatch for '{}': expected {}, got {}",
                path, expected_hash, actual_hash
            ));
        }

        Ok(())
    }

    /// Validate that all paths in `allowed_servers` exist on the filesystem.
    ///
    /// Returns `Ok(())` if all paths exist, or `Err(missing_paths)` with a list
    /// of paths that could not be found.
    pub fn validate_paths(&self) -> Result<(), Vec<String>> {
        let missing: Vec<String> = self
            .allowed_servers
            .keys()
            .filter(|path| !std::path::Path::new(path).exists())
            .cloned()
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// A pinned tool manifest that records the expected tools and their schema hashes.
///
/// Created from a `tools/list` response, then persisted. On subsequent
/// `tools/list` responses, the live tools are compared against this manifest
/// to detect unexpected changes (new tools, removed tools, schema mutations).
/// Snapshot of MCP tool annotations at manifest creation time.
///
/// These hints describe behavioral properties of a tool. Changes to annotations
/// between manifest versions may indicate a rug-pull attack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ManifestAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolManifest {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Pinned tool entries with schema hashes.
    pub tools: Vec<ManifestToolEntry>,
    /// Optional Ed25519 signature over the canonical manifest content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// ISO 8601 timestamp when the manifest was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Hex-encoded Ed25519 verifying key (32 bytes) for signature verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<String>,
}

/// A single tool entry in a pinned manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestToolEntry {
    /// Tool name as reported by the MCP server.
    pub name: String,
    /// SHA-256 hex digest of the canonical JSON-serialized `inputSchema`.
    /// If the tool has no inputSchema, this is the hash of the empty string.
    pub input_schema_hash: String,
    /// SHA-256 hex digest of the tool's description string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    /// SHA-256 hex digest of the tool's `title` display field (MCP 2025-06-18).
    /// A changed title could be used for social engineering (rug-pull via UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_hash: Option<String>,
    /// Snapshot of tool annotations at manifest creation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ManifestAnnotations>,
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
                let input_schema_hash = hex::encode(hasher.finalize());

                // Hash the description if present
                let description_hash = tool.get("description").and_then(|d| d.as_str()).map(|d| {
                    let mut h = Sha256::new();
                    h.update(d.as_bytes());
                    hex::encode(h.finalize())
                });

                // Hash the title if present (MCP 2025-06-18)
                let title_hash = tool.get("title").and_then(|t| t.as_str()).map(|t| {
                    let mut h = Sha256::new();
                    h.update(t.as_bytes());
                    hex::encode(h.finalize())
                });

                // Snapshot annotations if present
                let annotations = tool.get("annotations").and_then(|a| {
                    let ann = ManifestAnnotations {
                        read_only_hint: a.get("readOnlyHint").and_then(|v| v.as_bool()),
                        destructive_hint: a.get("destructiveHint").and_then(|v| v.as_bool()),
                        idempotent_hint: a.get("idempotentHint").and_then(|v| v.as_bool()),
                        open_world_hint: a.get("openWorldHint").and_then(|v| v.as_bool()),
                    };
                    // Only include if at least one field is set
                    if ann.read_only_hint.is_some()
                        || ann.destructive_hint.is_some()
                        || ann.idempotent_hint.is_some()
                        || ann.open_world_hint.is_some()
                    {
                        Some(ann)
                    } else {
                        None
                    }
                });

                Some(ManifestToolEntry {
                    name,
                    input_schema_hash,
                    description_hash,
                    title_hash,
                    annotations,
                })
            })
            .collect();

        // Sort by name for deterministic comparison
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        Some(ToolManifest {
            schema_version: "2.0".to_string(),
            tools: entries,
            signature: None,
            created_at: None,
            verifying_key: None,
        })
    }

    /// Load a pinned manifest from a JSON file.
    pub fn load_pinned_manifest(
        path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let manifest: ToolManifest = serde_json::from_str(&content)?;
        Ok(manifest)
    }

    /// Save this manifest to a JSON file.
    pub fn save_manifest(
        &self,
        path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Compute the canonical content that is signed.
    ///
    /// Content = SHA-256(schema_version || created_at || sorted_tools[]).
    /// Each tool: name || input_schema_hash || description_hash || annotations_string.
    /// All fields are length-prefixed with u64 LE to prevent boundary collisions.
    pub fn signing_content(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        Self::hash_field(&mut hasher, self.schema_version.as_bytes());
        Self::hash_field(
            &mut hasher,
            self.created_at.as_deref().unwrap_or("").as_bytes(),
        );

        // Tools are already sorted by name in from_tools_list
        for tool in &self.tools {
            Self::hash_field(&mut hasher, tool.name.as_bytes());
            Self::hash_field(&mut hasher, tool.input_schema_hash.as_bytes());
            Self::hash_field(
                &mut hasher,
                tool.description_hash.as_deref().unwrap_or("").as_bytes(),
            );
            Self::hash_field(
                &mut hasher,
                tool.title_hash.as_deref().unwrap_or("").as_bytes(),
            );
            let ann_str = tool
                .annotations
                .as_ref()
                .map(|a| serde_json::to_string(a).unwrap_or_default())
                .unwrap_or_default();
            Self::hash_field(&mut hasher, ann_str.as_bytes());
        }

        hasher.finalize().to_vec()
    }

    fn hash_field(hasher: &mut sha2::Sha256, data: &[u8]) {
        use sha2::Digest;
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Sign this manifest with an Ed25519 signing key.
    ///
    /// Populates the `signature` and `verifying_key` fields.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let content = self.signing_content();
        let signature = signing_key.sign(&content);
        self.signature = Some(hex::encode(signature.to_bytes()));
        let vk = signing_key.verifying_key();
        self.verifying_key = Some(hex::encode(vk.as_bytes()));
    }

    /// Verify the manifest signature against a trusted public key.
    ///
    /// Returns `Ok(())` if the signature is valid, or `Err(reason)` if verification fails.
    pub fn verify_signature(&self, trusted_key_hex: &str) -> Result<(), String> {
        use ed25519_dalek::{Verifier, VerifyingKey};

        let sig_hex = self
            .signature
            .as_ref()
            .ok_or_else(|| "Manifest has no signature".to_string())?;

        let sig_bytes: [u8; 64] = hex::decode(sig_hex)
            .map_err(|e| format!("Invalid signature hex: {}", e))?
            .try_into()
            .map_err(|_| "Signature must be 64 bytes".to_string())?;

        let key_bytes: [u8; 32] = hex::decode(trusted_key_hex)
            .map_err(|e| format!("Invalid key hex: {}", e))?
            .try_into()
            .map_err(|_| "Verifying key must be 32 bytes".to_string())?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| format!("Invalid verifying key: {}", e))?;

        let content = self.signing_content();
        verifying_key
            .verify(&content, &signature)
            .map_err(|e| format!("Signature verification failed: {}", e))
    }

    /// Verify the manifest signature against any of the given trusted keys.
    ///
    /// Returns `Ok(())` if at least one key verifies the signature.
    pub fn verify_signature_any(&self, trusted_keys: &[String]) -> Result<(), String> {
        if trusted_keys.is_empty() {
            return Err("No trusted keys provided".to_string());
        }
        for key in trusted_keys {
            if self.verify_signature(key).is_ok() {
                return Ok(());
            }
        }
        Err("Signature does not match any trusted key".to_string())
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

        // Build pinned tool lookup for detailed comparison
        let pinned_tools_by_name: std::collections::HashMap<&str, &ManifestToolEntry> =
            self.tools.iter().map(|t| (t.name.as_str(), t)).collect();

        // Check for new or changed tools
        for live_tool in &live.tools {
            match pinned_tools_by_name.get(live_tool.name.as_str()) {
                None => {
                    discrepancies.push(format!(
                        "New tool '{}' not in pinned manifest",
                        live_tool.name
                    ));
                }
                Some(pinned_entry) => {
                    if pinned_entry.input_schema_hash != live_tool.input_schema_hash {
                        discrepancies.push(format!(
                            "Tool '{}' schema changed: expected {}, got {}",
                            live_tool.name,
                            pinned_entry.input_schema_hash,
                            live_tool.input_schema_hash
                        ));
                    }
                    // MCP 2025-06-18: Detect title changes (social engineering vector)
                    if pinned_entry.title_hash != live_tool.title_hash {
                        discrepancies.push(format!(
                            "Tool '{}' title changed (potential social engineering)",
                            live_tool.name
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

/// Enforcement mode for manifest verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ManifestEnforcement {
    /// Log discrepancies but allow the request (default).
    #[default]
    Warn,
    /// Block requests when manifest verification fails.
    Block,
}

/// Tool manifest verification configuration.
///
/// # TOML Example
///
/// ```toml
/// [manifest]
/// enabled = true
/// enforcement = "Warn"
/// require_signature = false
/// manifest_path = "/etc/sentinel/manifest.json"
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
    /// What to do when manifest verification fails. Default: Warn.
    #[serde(default)]
    pub enforcement: ManifestEnforcement,
    /// Optional file path to a pre-signed manifest file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_path: Option<String>,
    /// Require a valid signature on manifests. Default: false.
    #[serde(default)]
    pub require_signature: bool,
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

        // Check signature if required
        if self.require_signature && !self.trusted_keys.is_empty() {
            if let Err(sig_err) = pinned.verify_signature_any(&self.trusted_keys) {
                let msg = format!("Manifest signature verification failed: {}", sig_err);
                if self.enforcement == ManifestEnforcement::Block {
                    return Err(vec![msg]);
                }
                // Warn mode: continue silently (logging happens at server level)
            }
        } else if self.require_signature && self.trusted_keys.is_empty() {
            let msg = "require_signature is set but no trusted_keys configured".to_string();
            if self.enforcement == ManifestEnforcement::Block {
                return Err(vec![msg]);
            }
        }

        let result = pinned.verify(live_response);
        if result.passed {
            Ok(())
        } else if self.enforcement == ManifestEnforcement::Block {
            Err(result.discrepancies)
        } else {
            // Warn mode: schema mismatches are not blocking
            Ok(())
        }
    }

    /// Load a pre-signed manifest from the configured path.
    pub fn load_pinned_manifest(
        &self,
    ) -> Result<Option<ToolManifest>, Box<dyn std::error::Error + Send + Sync>> {
        match &self.manifest_path {
            Some(path) => {
                let manifest = ToolManifest::load_pinned_manifest(path)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
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

/// Maximum number of custom PII patterns allowed in config.
/// Prevents memory exhaustion from excessively large pattern arrays.
pub const MAX_CUSTOM_PII_PATTERNS: usize = 100;

/// Maximum number of extra injection patterns allowed in config.
pub const MAX_EXTRA_INJECTION_PATTERNS: usize = 100;

/// Maximum number of disabled injection patterns allowed in config.
pub const MAX_DISABLED_INJECTION_PATTERNS: usize = 100;

/// Maximum number of policies allowed in a single config file.
pub const MAX_POLICIES: usize = 10_000;

/// Maximum number of trusted keys for manifest verification.
pub const MAX_TRUSTED_KEYS: usize = 50;

impl PolicyConfig {
    /// Parse config from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Parse config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Validate config bounds. Returns an error describing the first violation found.
    ///
    /// Checks that unbounded collection fields do not exceed safe limits,
    /// preventing memory exhaustion from maliciously crafted config files.
    pub fn validate(&self) -> Result<(), String> {
        if self.policies.len() > MAX_POLICIES {
            return Err(format!(
                "policies array has {} entries, max is {}",
                self.policies.len(),
                MAX_POLICIES
            ));
        }
        if self.injection.extra_patterns.len() > MAX_EXTRA_INJECTION_PATTERNS {
            return Err(format!(
                "injection.extra_patterns has {} entries, max is {}",
                self.injection.extra_patterns.len(),
                MAX_EXTRA_INJECTION_PATTERNS
            ));
        }
        if self.injection.disabled_patterns.len() > MAX_DISABLED_INJECTION_PATTERNS {
            return Err(format!(
                "injection.disabled_patterns has {} entries, max is {}",
                self.injection.disabled_patterns.len(),
                MAX_DISABLED_INJECTION_PATTERNS
            ));
        }
        if self.audit.custom_pii_patterns.len() > MAX_CUSTOM_PII_PATTERNS {
            return Err(format!(
                "audit.custom_pii_patterns has {} entries, max is {}",
                self.audit.custom_pii_patterns.len(),
                MAX_CUSTOM_PII_PATTERNS
            ));
        }
        if self.manifest.trusted_keys.len() > MAX_TRUSTED_KEYS {
            return Err(format!(
                "manifest.trusted_keys has {} entries, max is {}",
                self.manifest.trusted_keys.len(),
                MAX_TRUSTED_KEYS
            ));
        }
        Ok(())
    }

    /// Load config from a file path. Selects parser based on extension.
    ///
    /// Validates config bounds after parsing to prevent memory exhaustion
    /// from excessively large arrays.
    pub fn load_file(path: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // SECURITY (R9-5): Check file size before reading to prevent OOM
        // from maliciously large config files. 10 MB is generous for any
        // realistic policy configuration.
        const MAX_CONFIG_FILE_SIZE: u64 = 10 * 1024 * 1024;
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_CONFIG_FILE_SIZE {
            return Err(format!(
                "Config file '{}' is too large ({} bytes, max {} bytes)",
                path,
                metadata.len(),
                MAX_CONFIG_FILE_SIZE
            )
            .into());
        }
        let content = std::fs::read_to_string(path)?;
        let config = if path.ends_with(".toml") {
            Self::from_toml(&content)?
        } else if path.ends_with(".json") {
            Self::from_json(&content)?
        } else {
            Self::from_toml(&content)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        };
        config
            .validate()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        Ok(config)
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
        assert!(!config.injection.block_on_injection);
        assert!(config.injection.extra_patterns.is_empty());
        assert!(config.injection.disabled_patterns.is_empty());
    }

    #[test]
    fn test_injection_config_block_on_injection() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = true
block_on_injection = true
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.injection.enabled);
        assert!(config.injection.block_on_injection);
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
        assert!(config.rate_limit.per_principal_rps.is_none());
        assert!(config.rate_limit.per_principal_burst.is_none());
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
per_principal_rps = 50
per_principal_burst = 10
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
        assert_eq!(config.rate_limit.per_principal_rps, Some(50));
        assert_eq!(config.rate_limit.per_principal_burst, Some(10));
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
        assert!(config.rate_limit.per_principal_rps.is_none());
        assert!(config.rate_limit.per_principal_burst.is_none());
    }

    // --- Supply chain verification tests ---

    #[test]
    fn test_supply_chain_disabled_always_passes() {
        let config = SupplyChainConfig {
            enabled: false,
            allowed_servers: std::collections::HashMap::new(),
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        assert_eq!(manifest.schema_version, "2.0");
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
            created_at: None,
            verifying_key: None,
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
            enforcement: ManifestEnforcement::default(),
            manifest_path: None,
            require_signature: false,
        };
        let pinned = ToolManifest {
            schema_version: "1.0".to_string(),
            tools: vec![ManifestToolEntry {
                name: "tool_a".to_string(),
                input_schema_hash: "deadbeef".to_string(),
                description_hash: None,
                title_hash: None,
                annotations: None,
            }],
            signature: None,
            created_at: None,
            verifying_key: None,
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
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: false,
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

    // ═══════════════════════════════════════════════════
    // MANIFEST SIGNING TESTS (C-17.2)
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_manifest_sign_and_verify_roundtrip() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.created_at = Some("2026-02-04T12:00:00Z".to_string());
        manifest.sign(&signing_key);

        assert!(manifest.signature.is_some());
        assert!(manifest.verifying_key.is_some());
        assert!(manifest.verify_signature(&vk_hex).is_ok());
    }

    #[test]
    fn test_manifest_verify_with_wrong_key_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let other_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let other_vk_hex = hex::encode(other_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        assert!(manifest.verify_signature(&other_vk_hex).is_err());
    }

    #[test]
    fn test_manifest_tampered_manifest_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        // Tamper with the manifest
        manifest.tools.push(ManifestToolEntry {
            name: "injected".to_string(),
            input_schema_hash: "deadbeef".to_string(),
            description_hash: None,
            title_hash: None,
            annotations: None,
        });

        assert!(manifest.verify_signature(&vk_hex).is_err());
    }

    #[test]
    fn test_manifest_unsigned_when_required_fails() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![vk_hex],
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: true,
        };

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        // pinned is NOT signed
        let result = config.verify_manifest(&pinned, &response);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_no_trusted_keys_skips_signature() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::Block,
            manifest_path: None,
            require_signature: false,
        };
        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = config.verify_manifest(&pinned, &response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_manifest_signing_content_deterministic() {
        let response = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("tool_b", serde_json::json!({"type": "string"})),
        ]);
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let c1 = manifest.signing_content();
        let c2 = manifest.signing_content();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_manifest_description_hash_populated() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "tool_a",
                    "description": "A helpful tool",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        assert!(manifest.tools[0].description_hash.is_some());
        assert_eq!(
            manifest.tools[0].description_hash.as_ref().unwrap().len(),
            64
        );
    }

    #[test]
    fn test_manifest_annotations_snapshot() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "tool_a",
                    "inputSchema": {"type": "object"},
                    "annotations": {
                        "readOnlyHint": true,
                        "destructiveHint": false
                    }
                }]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let ann = manifest.tools[0].annotations.as_ref().unwrap();
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, None);
    }

    #[test]
    fn test_manifest_load_save_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("manifest.json");

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&signing_key);

        manifest.save_manifest(path.to_str().unwrap()).unwrap();
        let loaded = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap();
        assert_eq!(manifest, loaded);
    }

    #[test]
    fn test_manifest_backward_compat_v1() {
        // v1 manifests (without new fields) should deserialize fine
        let json = r#"{
            "schema_version": "1.0",
            "tools": [{"name": "tool_a", "input_schema_hash": "abcdef1234567890"}]
        }"#;
        let manifest: ToolManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.schema_version, "1.0");
        assert_eq!(manifest.tools[0].name, "tool_a");
        assert!(manifest.signature.is_none());
        assert!(manifest.created_at.is_none());
        assert!(manifest.verifying_key.is_none());
        assert!(manifest.tools[0].description_hash.is_none());
        assert!(manifest.tools[0].annotations.is_none());
    }

    #[test]
    fn test_manifest_verify_signature_any() {
        let key1 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let key2 = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let vk1 = hex::encode(key1.verifying_key().as_bytes());
        let vk2 = hex::encode(key2.verifying_key().as_bytes());

        let response =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
        manifest.sign(&key1);

        // Should pass with key1 in the list
        assert!(manifest
            .verify_signature_any(&[vk2.clone(), vk1.clone()])
            .is_ok());
        // Should fail with only key2
        assert!(manifest.verify_signature_any(&[vk2]).is_err());
    }

    // --- Custom PII pattern config tests ---

    #[test]
    fn test_custom_pii_patterns_default_empty() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.audit.custom_pii_patterns.is_empty());
    }

    #[test]
    fn test_custom_pii_patterns_parsed() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[[audit.custom_pii_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert_eq!(config.audit.custom_pii_patterns.len(), 1);
        assert_eq!(config.audit.custom_pii_patterns[0].name, "employee_id");
    }

    // --- Supply chain new methods tests ---

    #[test]
    fn test_supply_chain_compute_hash() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("test-binary");
        std::fs::write(&bin_path, b"hello").unwrap();

        let hash = SupplyChainConfig::compute_hash(bin_path.to_str().unwrap()).unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
                                    // Hash of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_supply_chain_validate_paths_all_exist() {
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("server");
        std::fs::write(&bin_path, b"binary").unwrap();

        let mut allowed = std::collections::HashMap::new();
        allowed.insert(bin_path.to_string_lossy().to_string(), "hash".to_string());

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        assert!(config.validate_paths().is_ok());
    }

    #[test]
    fn test_supply_chain_validate_paths_missing() {
        let mut allowed = std::collections::HashMap::new();
        allowed.insert("/nonexistent/server".to_string(), "hash".to_string());

        let config = SupplyChainConfig {
            enabled: true,
            allowed_servers: allowed,
            ..Default::default()
        };
        let result = config.validate_paths();
        assert!(result.is_err());
        let missing = result.unwrap_err();
        assert!(missing.contains(&"/nonexistent/server".to_string()));
    }

    // --- ManifestEnforcement tests ---

    #[test]
    fn test_manifest_enforcement_warn_allows_schema_mismatch() {
        let config = ManifestConfig {
            enabled: true,
            trusted_keys: vec![],
            enforcement: ManifestEnforcement::Warn,
            manifest_path: None,
            require_signature: false,
        };
        let original =
            make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
        let pinned = ToolManifest::from_tools_list(&original).unwrap();
        let modified = make_tools_list_response(&[
            ("tool_a", serde_json::json!({"type": "object"})),
            ("injected_tool", serde_json::json!({"type": "object"})),
        ]);
        // Warn mode: schema mismatches are non-blocking
        let result = config.verify_manifest(&pinned, &modified);
        assert!(result.is_ok());
    }

    // --- Config validation bounds tests ---

    #[test]
    fn test_validate_passes_for_normal_config() {
        let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
        let config = PolicyConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_too_many_custom_pii_patterns() {
        let mut config = PolicyConfig::from_toml(
            r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap();
        config.audit.custom_pii_patterns = (0..=MAX_CUSTOM_PII_PATTERNS)
            .map(|i| CustomPiiPattern {
                name: format!("pat_{}", i),
                pattern: format!("pattern{}", i),
            })
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("custom_pii_patterns"));
        assert!(err.contains(&MAX_CUSTOM_PII_PATTERNS.to_string()));
    }

    #[test]
    fn test_validate_rejects_too_many_extra_injection_patterns() {
        let mut config = PolicyConfig::from_toml(
            r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap();
        config.injection.extra_patterns = (0..=MAX_EXTRA_INJECTION_PATTERNS)
            .map(|i| format!("pattern {}", i))
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("extra_patterns"));
    }

    #[test]
    fn test_validate_rejects_too_many_policies() {
        let mut config = PolicyConfig {
            policies: Vec::new(),
            injection: InjectionConfig::default(),
            rate_limit: RateLimitConfig::default(),
            audit: AuditConfig::default(),
            supply_chain: SupplyChainConfig::default(),
            manifest: ManifestConfig::default(),
        };
        config.policies = (0..=MAX_POLICIES)
            .map(|i| PolicyRule {
                name: format!("p{}", i),
                tool_pattern: "*".to_string(),
                function_pattern: "*".to_string(),
                policy_type: PolicyType::Allow,
                priority: Some(100),
                id: None,
            })
            .collect();
        let err = config.validate().unwrap_err();
        assert!(err.contains("policies"));
        assert!(err.contains(&MAX_POLICIES.to_string()));
    }

    #[test]
    fn test_load_file_validates_bounds() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        // Create a config with way too many PII patterns
        let patterns: Vec<serde_json::Value> = (0..=MAX_CUSTOM_PII_PATTERNS)
            .map(|i| {
                serde_json::json!({
                    "name": format!("p{}", i),
                    "pattern": format!("x{}", i)
                })
            })
            .collect();
        let json = serde_json::json!({
            "policies": [{"name": "t", "tool_pattern": "*", "function_pattern": "*", "policy_type": "Allow"}],
            "audit": {"custom_pii_patterns": patterns}
        });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let result = PolicyConfig::load_file(path.to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("custom_pii_patterns"));
    }

    #[test]
    fn test_validate_at_limit_passes() {
        let mut config = PolicyConfig::from_toml(
            r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
        )
        .unwrap();
        // Exactly at the limit should pass
        config.audit.custom_pii_patterns = (0..MAX_CUSTOM_PII_PATTERNS)
            .map(|i| CustomPiiPattern {
                name: format!("pat_{}", i),
                pattern: format!("pattern{}", i),
            })
            .collect();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_manifest_title_hash_populated_from_tools_list() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search",
                        "title": "Web Search",
                        "description": "Search the web",
                        "inputSchema": {"type": "object"}
                    },
                    {
                        "name": "no_title",
                        "description": "No title field",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        });
        let manifest = ToolManifest::from_tools_list(&response).unwrap();
        let search = manifest.tools.iter().find(|t| t.name == "search").unwrap();
        assert!(search.title_hash.is_some(), "search should have title_hash");

        let no_title = manifest
            .tools
            .iter()
            .find(|t| t.name == "no_title")
            .unwrap();
        assert!(no_title.title_hash.is_none(), "no_title should have None");
    }

    #[test]
    fn test_manifest_title_change_detected_as_drift() {
        // Pin with title "Search"
        let initial = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Web Search",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let pinned = ToolManifest::from_tools_list(&initial).unwrap();

        // Same tool with changed title
        let changed = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Admin Panel Access",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let result = pinned.verify(&changed);
        assert!(!result.passed, "Should detect title change as discrepancy");
        assert!(
            result
                .discrepancies
                .iter()
                .any(|d| d.contains("title changed")),
            "Discrepancy should mention title: {:?}",
            result.discrepancies
        );
    }

    #[test]
    fn test_manifest_same_title_passes() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "title": "Web Search",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                }]
            }
        });
        let pinned = ToolManifest::from_tools_list(&response).unwrap();
        let result = pinned.verify(&response);
        assert!(result.passed, "Identical tools/list should pass");
    }
}
