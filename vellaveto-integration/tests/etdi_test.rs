//! ETDI (Enhanced Tool Definition Interface) Integration Tests
//!
//! Tests the complete ETDI flow:
//! - Keypair generation and signing
//! - Signature verification (valid, invalid, expired)
//! - Attestation chain creation and verification
//! - Version pinning and drift detection
//! - Store persistence

use vellaveto_config::AllowedSignersConfig;
use vellaveto_mcp::etdi::version_pin::PinCheckResult;
use vellaveto_mcp::etdi::{
    AttestationChain, EtdiStore, ToolSignatureVerifier, ToolSigner, VersionPinManager,
};
use vellaveto_types::SignatureAlgorithm;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn test_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "recursive": { "type": "boolean" }
        },
        "required": ["path"]
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNATURE CREATION AND VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_generate_keypair_and_sign() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();

    let signature = signer.sign_tool("read_file", &schema, Some(365));

    assert!(!signature.signature.is_empty());
    assert!(!signature.public_key.is_empty());
    assert_eq!(signature.algorithm, SignatureAlgorithm::Ed25519);
    assert!(signature.key_fingerprint.is_some());
    assert!(signature.expires_at.is_some());
}

#[test]
fn test_signature_roundtrip_verification() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();
    let signature = signer.sign_tool("my_tool", &schema, None);

    // Verify with same signer's key trusted
    let allowed = AllowedSignersConfig {
        fingerprints: vec![signer.fingerprint().to_string()],
        spiffe_ids: vec![],
    };
    let verifier = ToolSignatureVerifier::new(allowed);

    let result = verifier.verify_tool_signature("my_tool", &schema, &signature);
    assert!(result.valid, "Signature should be valid");
    assert!(result.signer_trusted, "Signer should be trusted");
    assert!(!result.expired, "Signature should not be expired");
    assert!(result.is_fully_verified());
}

#[test]
fn test_signature_wrong_schema_fails() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();
    let signature = signer.sign_tool("my_tool", &schema, None);

    let allowed = AllowedSignersConfig {
        fingerprints: vec![signer.fingerprint().to_string()],
        spiffe_ids: vec![],
    };
    let verifier = ToolSignatureVerifier::new(allowed);

    // Try to verify with different schema
    let different_schema = json!({"type": "string"});
    let result = verifier.verify_tool_signature("my_tool", &different_schema, &signature);
    assert!(
        !result.valid,
        "Signature should be invalid for different schema"
    );
}

#[test]
fn test_signature_wrong_tool_name_fails() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();
    let signature = signer.sign_tool("tool_a", &schema, None);

    let allowed = AllowedSignersConfig {
        fingerprints: vec![signer.fingerprint().to_string()],
        spiffe_ids: vec![],
    };
    let verifier = ToolSignatureVerifier::new(allowed);

    // Try to verify with different tool name
    let result = verifier.verify_tool_signature("tool_b", &schema, &signature);
    assert!(
        !result.valid,
        "Signature should be invalid for different tool name"
    );
}

#[test]
fn test_signature_untrusted_signer() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();
    let signature = signer.sign_tool("my_tool", &schema, None);

    // Empty allowed signers
    let verifier = ToolSignatureVerifier::new(AllowedSignersConfig::default());

    let result = verifier.verify_tool_signature("my_tool", &schema, &signature);
    assert!(result.valid, "Cryptographic signature should be valid");
    assert!(!result.signer_trusted, "Signer should not be trusted");
    assert!(!result.is_fully_verified());
}

#[test]
fn test_signature_expired() {
    let signer = ToolSigner::generate().expect("Should generate keypair");
    let schema = test_schema();
    let mut signature = signer.sign_tool("my_tool", &schema, None);

    // Set expiration to the past
    signature.expires_at = Some("2020-01-01T00:00:00Z".to_string());

    let allowed = AllowedSignersConfig {
        fingerprints: vec![signer.fingerprint().to_string()],
        spiffe_ids: vec![],
    };
    let verifier = ToolSignatureVerifier::new(allowed);

    let result = verifier.verify_tool_signature("my_tool", &schema, &signature);
    assert!(result.valid, "Cryptographic signature should be valid");
    assert!(result.signer_trusted, "Signer should be trusted");
    assert!(result.expired, "Signature should be expired");
    assert!(!result.is_fully_verified());
}

#[test]
fn test_spiffe_trust() {
    let signer =
        ToolSigner::generate_with_identity(Some("spiffe://example.org/tool-provider".to_string()))
            .expect("Should generate keypair");
    let schema = test_schema();
    let signature = signer.sign_tool("my_tool", &schema, None);

    // Trust by SPIFFE ID only
    let allowed = AllowedSignersConfig {
        fingerprints: vec![],
        spiffe_ids: vec!["spiffe://example.org/tool-provider".to_string()],
    };
    let verifier = ToolSignatureVerifier::new(allowed);

    let result = verifier.verify_tool_signature("my_tool", &schema, &signature);
    assert!(
        result.is_fully_verified(),
        "Should be trusted via SPIFFE ID"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ETDI STORE PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_store_signature_persistence() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = EtdiStore::new(tmp.path());

        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();
        let signature = signer.sign_tool("test_tool", &schema, None);

        // Save signature
        store
            .save_signature("test_tool", signature.clone())
            .await
            .unwrap();

        // Create new store and load
        let store2 = EtdiStore::new(tmp.path());
        store2.load().await.unwrap();

        let loaded = store2.get_signature("test_tool").await.unwrap();
        assert_eq!(loaded.signature_id, signature.signature_id);
    });
}

#[test]
fn test_store_with_hmac_protection() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let key = [0u8; 32];
        let store = EtdiStore::new(tmp.path()).with_hmac_key(key);

        let signer = ToolSigner::generate().unwrap();
        let signature = signer.sign_tool("test_tool", &test_schema(), None);

        store.save_signature("test_tool", signature).await.unwrap();

        // Load with same key
        let store2 = EtdiStore::new(tmp.path()).with_hmac_key(key);
        store2.load().await.unwrap();
        assert!(store2.get_signature("test_tool").await.is_some());

        // Load with different key should reject
        let wrong_key = [1u8; 32];
        let store3 = EtdiStore::new(tmp.path()).with_hmac_key(wrong_key);
        store3.load().await.unwrap();
        assert!(store3.get_signature("test_tool").await.is_none());
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTESTATION CHAIN
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_attestation_chain_initial() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let chain = AttestationChain::new(store);
        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();

        let attestation = chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        assert_eq!(attestation.attestation_type, "initial");
        assert!(attestation.previous_attestation.is_none());
        assert!(attestation.is_initial());
    });
}

#[test]
fn test_attestation_chain_update() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let chain = AttestationChain::new(store);
        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();

        let initial = chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        // Wait a tiny bit to ensure timestamp difference
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let update = chain
            .create_update("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        assert_eq!(update.attestation_type, "version_update");
        assert_eq!(update.previous_attestation, Some(initial.attestation_id));
        assert!(!update.is_initial());
    });
}

#[test]
fn test_attestation_chain_verification() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let chain = AttestationChain::new(store);
        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();

        chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        chain
            .create_update("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        let result = chain.verify_chain("test_tool").await;
        assert!(result.valid, "Chain should be valid: {:?}", result.issues);
        assert_eq!(result.chain_length, 2);
    });
}

#[test]
fn test_attestation_hash_verification() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let chain = AttestationChain::new(store);
        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();

        chain
            .create_initial("test_tool", &schema, "admin", &signer)
            .await
            .unwrap();

        // Verify matching schema
        assert!(chain.verify_hash("test_tool", &schema).await);

        // Verify non-matching schema
        let different = json!({"type": "string"});
        assert!(!chain.verify_hash("test_tool", &different).await);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// VERSION PINNING
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_version_pin_exact() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let pins = VersionPinManager::new(store, false);

        let schema = test_schema();
        let hash = vellaveto_mcp::etdi::signature::compute_tool_hash("test_tool", &schema);

        pins.pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        // Check matching version
        let result = pins.check_pin("test_tool", Some("1.0.0"), &schema).await;
        assert_eq!(result, PinCheckResult::Matches);

        // Check non-matching version
        let result = pins.check_pin("test_tool", Some("2.0.0"), &schema).await;
        assert!(matches!(result, PinCheckResult::VersionDrift(_)));
    });
}

#[test]
fn test_version_pin_constraint() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let pins = VersionPinManager::new(store, false);

        let schema = test_schema();
        let hash = vellaveto_mcp::etdi::signature::compute_tool_hash("test_tool", &schema);

        pins.pin_constraint("test_tool", "^1.0.0", &hash, "admin")
            .await
            .unwrap();

        // 1.2.3 matches ^1.0.0
        let result = pins.check_pin("test_tool", Some("1.2.3"), &schema).await;
        assert_eq!(result, PinCheckResult::Matches);

        // 2.0.0 does NOT match ^1.0.0
        let result = pins.check_pin("test_tool", Some("2.0.0"), &schema).await;
        assert!(matches!(result, PinCheckResult::VersionDrift(_)));
    });
}

#[test]
fn test_version_pin_hash_drift() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let pins = VersionPinManager::new(store, true); // blocking mode

        let schema = test_schema();
        let hash = vellaveto_mcp::etdi::signature::compute_tool_hash("test_tool", &schema);

        pins.pin_version("test_tool", "1.0.0", &hash, "admin")
            .await
            .unwrap();

        // Same version but different schema
        let different_schema = json!({"type": "string"});
        let result = pins
            .check_pin("test_tool", Some("1.0.0"), &different_schema)
            .await;

        match result {
            PinCheckResult::HashDrift(alert) => {
                assert_eq!(alert.drift_type, "hash_mismatch");
                assert!(alert.blocking);
            }
            _ => panic!("Expected HashDrift, got {:?}", result),
        }
    });
}

#[test]
fn test_version_pin_unpin() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let pins = VersionPinManager::new(store, false);

        pins.pin_version("test_tool", "1.0.0", "hash", "admin")
            .await
            .unwrap();
        assert!(pins.get_pin("test_tool").await.is_some());

        pins.unpin("test_tool").await.unwrap();
        assert!(pins.get_pin("test_tool").await.is_none());
    });
}

#[test]
fn test_version_pin_no_pin_exists() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(EtdiStore::new(tmp.path()));
        let pins = VersionPinManager::new(store, false);

        let result = pins
            .check_pin("unknown_tool", Some("1.0.0"), &test_schema())
            .await;
        assert_eq!(result, PinCheckResult::NoPinExists);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// END-TO-END FLOW
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_e2e_sign_verify_attest_pin() {
    let rt = runtime();
    rt.block_on(async {
        let tmp = TempDir::new().unwrap();

        // 1. Generate key and sign tool
        let signer = ToolSigner::generate().unwrap();
        let schema = test_schema();
        let signature = signer.sign_tool("secure_tool", &schema, Some(365));

        // 2. Store signature
        let store = Arc::new(EtdiStore::new(tmp.path()));
        store
            .save_signature("secure_tool", signature.clone())
            .await
            .unwrap();

        // 3. Verify signature
        let allowed = AllowedSignersConfig {
            fingerprints: vec![signer.fingerprint().to_string()],
            spiffe_ids: vec![],
        };
        let verifier = ToolSignatureVerifier::new(allowed);
        let result = verifier.verify_tool_signature("secure_tool", &schema, &signature);
        assert!(result.is_fully_verified());

        // 4. Create attestation
        let chain = AttestationChain::new(store.clone());
        let attestation = chain
            .create_initial("secure_tool", &schema, "admin", &signer)
            .await
            .unwrap();
        assert!(attestation.is_initial());

        // 5. Pin version
        let pins = VersionPinManager::new(store.clone(), true);
        pins.pin_version(
            "secure_tool",
            "1.0.0",
            &vellaveto_mcp::etdi::signature::compute_tool_hash("secure_tool", &schema),
            "admin",
        )
        .await
        .unwrap();

        // 6. Verify everything holds
        assert!(chain.verify_hash("secure_tool", &schema).await);
        let pin_result = pins.check_pin("secure_tool", Some("1.0.0"), &schema).await;
        assert_eq!(pin_result, PinCheckResult::Matches);
    });
}
