use super::*;
use vellaveto_audit::{CustomPiiPattern, PiiScanner};

// ═══════════════════════════════════════════════════════════════════
// Sanitizer Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_sanitizer_email_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Contact user@example.com").unwrap();
    assert!(!result.contains("user@example.com"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_ssn_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("SSN: 123-45-6789").unwrap();
    assert!(!result.contains("123-45-6789"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_cc_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Card: 4111111111111111").unwrap();
    assert!(!result.contains("4111111111111111"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_phone_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Call 555-123-4567").unwrap();
    assert!(!result.contains("555-123-4567"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_roundtrip() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let original = "Email user@example.com and SSN 123-45-6789 here";
    let sanitized = sanitizer.sanitize(original).unwrap();
    assert!(!sanitized.contains("user@example.com"));
    assert!(!sanitized.contains("123-45-6789"));

    let restored = sanitizer.desanitize(&sanitized).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn test_sanitizer_json_recursive() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = serde_json::json!({
        "name": "test",
        "email": "user@example.com",
        "nested": {
            "ssn": "123-45-6789"
        }
    });
    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_str = serde_json::to_string(&sanitized).unwrap();
    assert!(!sanitized_str.contains("user@example.com"));
    assert!(!sanitized_str.contains("123-45-6789"));

    let restored = sanitizer.desanitize_json(&sanitized).unwrap();
    assert_eq!(restored, input);
}

#[test]
fn test_sanitizer_max_mappings_fail_closed() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    // Fill up mappings (each unique email creates a mapping)
    for i in 0..50_000 {
        let input = format!("user{}@example.com", i);
        let _ = sanitizer.sanitize(&input);
    }
    // Next sanitize should fail
    let result = sanitizer.sanitize("overflow@example.com");
    assert!(result.is_err());
}

#[test]
fn test_sanitizer_custom_patterns() {
    let custom = vec![CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }];
    let scanner = PiiScanner::new(&custom);
    let sanitizer = QuerySanitizer::new(scanner);
    let result = sanitizer.sanitize("Employee EMP-123456 logged in").unwrap();
    assert!(!result.contains("EMP-123456"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_clear() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let _ = sanitizer.sanitize("user@example.com").unwrap();
    assert!(sanitizer.mapping_count() > 0);
    sanitizer.clear();
    assert_eq!(sanitizer.mapping_count(), 0);
}

#[test]
fn test_sanitizer_empty_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_sanitizer_no_pii_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = "Normal text with no PII";
    let result = sanitizer.sanitize(input).unwrap();
    assert_eq!(result, input);
}

// ═══════════════════════════════════════════════════════════════════
// Session Isolator Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_create() {
    let isolator = SessionIsolator::new();
    let result = isolator.sanitize_in_session("s1", "user@example.com");
    assert!(result.is_ok());
    assert_eq!(isolator.session_count(), 1);
}

#[test]
fn test_session_max_fail_closed() {
    let isolator = SessionIsolator::with_limits(2, 100);
    let _ = isolator.sanitize_in_session("s1", "test").unwrap();
    let _ = isolator.sanitize_in_session("s2", "test").unwrap();
    let result = isolator.sanitize_in_session("s3", "test");
    assert!(result.is_err());
}

#[test]
fn test_session_independent_pii_maps() {
    let isolator = SessionIsolator::new();
    let s1_result = isolator.sanitize_in_session("s1", "user1@example.com").unwrap();
    let s2_result = isolator.sanitize_in_session("s2", "user2@example.com").unwrap();

    // Both sessions have PII replaced
    assert!(!s1_result.contains("user1@example.com"));
    assert!(!s2_result.contains("user2@example.com"));

    // Desanitize in the correct session restores the original
    let restored = isolator.desanitize_in_session("s1", &s1_result).unwrap();
    assert_eq!(restored, "user1@example.com");

    // Cross-session desanitization should NOT restore the other session's PII
    let cross_restored = isolator.desanitize_in_session("s2", &s1_result).unwrap();
    assert_ne!(cross_restored, "user1@example.com", "session isolation should prevent cross-session PII restoration");
}

#[test]
fn test_session_end_clears() {
    let isolator = SessionIsolator::new();
    let _ = isolator.sanitize_in_session("s1", "user@example.com").unwrap();
    assert_eq!(isolator.session_count(), 1);
    isolator.end_session("s1");
    assert_eq!(isolator.session_count(), 0);
}

#[test]
fn test_session_history_bounded() {
    let isolator = SessionIsolator::with_limits(10, 3);
    let _ = isolator.sanitize_in_session("s1", "first").unwrap();
    let _ = isolator.sanitize_in_session("s1", "second").unwrap();
    let _ = isolator.sanitize_in_session("s1", "third").unwrap();
    let _ = isolator.sanitize_in_session("s1", "fourth").unwrap();
    // Should not error — old entries evicted
    assert_eq!(isolator.session_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════
// Crypto Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_crypto_encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let plaintext = b"sensitive audit data";
    let encrypted = store.encrypt(plaintext).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_crypto_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "correct-passphrase").unwrap();
    store1.write_encrypted_entry(b"secret data").unwrap();

    let store2 = EncryptedAuditStore::new(path, "wrong-passphrase").unwrap();
    let result = store2.read_all_entries();
    assert!(result.is_err());
}

#[test]
fn test_crypto_empty_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let encrypted = store.encrypt(b"").unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_crypto_large_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase").unwrap();

    let large = vec![0xABu8; 1_000_000];
    let encrypted = store.encrypt(&large).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, large);
}

#[test]
fn test_crypto_salt_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "passphrase").unwrap();
    store1.write_encrypted_entry(b"entry 1").unwrap();

    // Re-open with same passphrase — should read same salt
    let store2 = EncryptedAuditStore::new(path, "passphrase").unwrap();
    let entries = store2.read_all_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], b"entry 1");
}

// ═══════════════════════════════════════════════════════════════════
// Local Audit Tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_local_audit_encrypted_not_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path.clone(), "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager.log_shield_event("test", "sensitive details").await.unwrap();

    // Read raw file — should NOT contain plaintext
    let raw = std::fs::read(&enc_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(!raw_str.contains("sensitive details"));
}

#[tokio::test]
async fn test_local_audit_merkle_proof_valid() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store).with_merkle();

    manager.log_shield_event("event1", "details1").await.unwrap();
    manager.log_shield_event("event2", "details2").await.unwrap();

    let proof = manager.generate_proof(0);
    assert!(proof.is_ok());
    assert!(manager.merkle_root().is_some());
}

#[tokio::test]
async fn test_local_audit_read_decrypts() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager.log_shield_event("test_event", "test_details").await.unwrap();

    let entries = manager.read_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event"], "test_event");
}
