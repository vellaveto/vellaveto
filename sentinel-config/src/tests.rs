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
    config.opa.endpoint = Some("http://opa.internal:8181/v1/data/sentinel/allow".to_string());
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
    config.opa.endpoint = Some("https://opa.internal/v1/data/sentinel/allow".to_string());
    config.opa.require_https = true;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_opa_http_endpoint_when_require_https_disabled() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://127.0.0.1:8181/v1/data/sentinel/allow".to_string());
    config.opa.require_https = false;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_opa_endpoint_with_userinfo() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("https://user:pass@opa.internal/v1/data/sentinel/allow".to_string());
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
    config.opa.endpoint = Some("https://:443/v1/data/sentinel/allow".to_string());
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
        sentinel_types::SignatureAlgorithm::Ed25519
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
data_path = "/var/lib/sentinel/etdi"

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
        Some("/var/lib/sentinel/etdi".to_string())
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
    let mut config = ExtensionConfig::default();
    config.enabled = true;
    config.default_resource_limits.max_concurrent_requests = 0;
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
    use sentinel_types::TransportProtocol;
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
    let mut config = TransportConfig::default();
    config.max_fallback_retries = 11;
    assert!(config.validate().is_err());

    config.max_fallback_retries = 1;
    config.fallback_timeout_secs = 0;
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
