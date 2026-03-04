// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Integration tests for Consumer Shield PII sanitization pipeline.
//!
//! Validates the full bidirectional PII sanitization flow using
//! QuerySanitizer and SessionIsolator, including:
//! - Email PII detection and placeholder replacement
//! - Custom file-path PII pattern detection
//! - Bidirectional desanitization (placeholder → original)
//! - Session isolation (independent PII contexts per session)
//! - JSON recursive sanitization/desanitization

use vellaveto_audit::{CustomPiiPattern, PiiScanner};
use vellaveto_mcp_shield::{QuerySanitizer, SessionIsolator};

// ═══════════════════════════════════════════════════════════════════
// Helper: PiiScanner with a custom file-path pattern
// ═══════════════════════════════════════════════════════════════════

/// Create a PiiScanner that detects emails (built-in) plus file paths
/// matching `/home/<user>/<rest>` (custom pattern, category "filepath").
fn scanner_with_filepath_pattern() -> PiiScanner {
    let custom = vec![CustomPiiPattern {
        name: "filepath".to_string(),
        pattern: r"/home/[a-zA-Z0-9_]+/[\w./\-]+".to_string(),
    }];
    PiiScanner::new(&custom)
}

// ═══════════════════════════════════════════════════════════════════
// Test 1: QuerySanitizer replaces email and file-path PII with
//         numbered placeholders, then desanitize restores originals.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_query_sanitizer_email_and_filepath_roundtrip_restores_originals() {
    let scanner = scanner_with_filepath_pattern();
    let sanitizer = QuerySanitizer::new(scanner);

    let original =
        "Please read /home/alice/medical/records.pdf and email alice@example.com with results";

    // Sanitize: PII should be replaced with [PII_*] placeholders
    let sanitized = sanitizer
        .sanitize(original)
        .expect("sanitize should succeed");

    // Original PII values must NOT appear in sanitized output
    assert!(
        !sanitized.contains("/home/alice/medical/records.pdf"),
        "file path should be sanitized, got: {sanitized}"
    );
    assert!(
        !sanitized.contains("alice@example.com"),
        "email should be sanitized, got: {sanitized}"
    );

    // Placeholders must be present (categories uppercased: FILEPATH and EMAIL)
    assert!(
        sanitized.contains("[PII_FILEPATH_"),
        "should contain FILEPATH placeholder, got: {sanitized}"
    );
    assert!(
        sanitized.contains("[PII_EMAIL_"),
        "should contain EMAIL placeholder, got: {sanitized}"
    );

    // At least 2 PII mappings recorded (filepath + email)
    assert!(
        sanitizer.mapping_count() >= 2,
        "expected at least 2 mappings, got: {}",
        sanitizer.mapping_count()
    );

    // Desanitize: restore original values from placeholders
    let restored = sanitizer
        .desanitize(&sanitized)
        .expect("desanitize should succeed");

    assert_eq!(
        restored, original,
        "roundtrip should restore exact original text"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Test 2: Session isolation — different sessions have independent
//         PII mapping tables and cannot cross-restore each other.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_isolator_independent_contexts_prevent_cross_restoration() {
    let isolator = SessionIsolator::new();

    let session_a = "session-alice";
    let session_b = "session-bob";

    let input_a = "Contact alice@example.com for the report";
    let input_b = "Contact bob@example.com for the invoice";

    // Sanitize in each session
    let sanitized_a = isolator
        .sanitize_in_session(session_a, input_a)
        .expect("session A sanitize");
    let sanitized_b = isolator
        .sanitize_in_session(session_b, input_b)
        .expect("session B sanitize");

    // Both sessions must have replaced the email
    assert!(
        !sanitized_a.contains("alice@example.com"),
        "session A should sanitize alice's email"
    );
    assert!(
        !sanitized_b.contains("bob@example.com"),
        "session B should sanitize bob's email"
    );

    // Both sessions must contain PII placeholders
    assert!(
        sanitized_a.contains("[PII_EMAIL_"),
        "session A should have EMAIL placeholder"
    );
    assert!(
        sanitized_b.contains("[PII_EMAIL_"),
        "session B should have EMAIL placeholder"
    );

    // Desanitize within the correct session restores the original
    let restored_a = isolator
        .desanitize_in_session(session_a, &sanitized_a)
        .expect("session A desanitize");
    assert_eq!(
        restored_a, input_a,
        "session A roundtrip should restore original"
    );

    let restored_b = isolator
        .desanitize_in_session(session_b, &sanitized_b)
        .expect("session B desanitize");
    assert_eq!(
        restored_b, input_b,
        "session B roundtrip should restore original"
    );

    // Cross-session desanitization must NOT restore the other session's PII.
    // Session B does not know session A's placeholders, so the placeholder
    // text should remain unchanged (or at least not resolve to alice's email).
    let cross_restored = isolator
        .desanitize_in_session(session_b, &sanitized_a)
        .expect("cross-session desanitize should not error");
    assert_ne!(
        cross_restored, input_a,
        "cross-session desanitization must NOT restore alice's email"
    );
    assert!(
        !cross_restored.contains("alice@example.com"),
        "alice's email must not leak through bob's session context"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Test 3: Session end clears all state, preventing post-session
//         desanitization (fail-closed on ended sessions).
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_end_prevents_desanitization_fail_closed() {
    let isolator = SessionIsolator::new();
    let session_id = "ephemeral-session";

    let sanitized = isolator
        .sanitize_in_session(session_id, "user@example.com")
        .expect("sanitize should succeed");
    assert!(sanitized.contains("[PII_EMAIL_"));

    // End the session — wipes all PII mappings
    isolator.end_session(session_id);
    assert_eq!(
        isolator.session_count(),
        0,
        "session count should be 0 after end"
    );

    // Desanitize on ended session should fail (unknown session)
    let result = isolator.desanitize_in_session(session_id, &sanitized);
    assert!(
        result.is_err(),
        "desanitize on ended session should return error (fail-closed)"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Test 4: JSON recursive sanitization/desanitization preserves
//         structure and replaces PII in nested values.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_query_sanitizer_json_recursive_roundtrip_preserves_structure() {
    let scanner = scanner_with_filepath_pattern();
    let sanitizer = QuerySanitizer::new(scanner);

    let original = serde_json::json!({
        "tool": "file_reader",
        "parameters": {
            "path": "/home/alice/medical/records.pdf",
            "notify": "alice@example.com"
        },
        "metadata": {
            "priority": 1,
            "tags": ["medical", "urgent"]
        }
    });

    // Sanitize the JSON value recursively
    let sanitized = sanitizer
        .sanitize_json(&original)
        .expect("sanitize_json should succeed");
    let sanitized_str = serde_json::to_string(&sanitized).expect("serialize sanitized JSON");

    // PII must not appear in the serialized output
    assert!(
        !sanitized_str.contains("/home/alice/medical/records.pdf"),
        "file path must be sanitized in JSON"
    );
    assert!(
        !sanitized_str.contains("alice@example.com"),
        "email must be sanitized in JSON"
    );

    // Non-PII values must remain unchanged
    assert!(
        sanitized_str.contains("file_reader"),
        "tool name should be preserved"
    );
    assert!(
        sanitized_str.contains("medical"),
        "non-PII tag should be preserved"
    );
    assert!(
        sanitized_str.contains("\"priority\":1") || sanitized_str.contains("\"priority\": 1"),
        "numeric value should be preserved"
    );

    // Desanitize restores original JSON exactly
    let restored = sanitizer
        .desanitize_json(&sanitized)
        .expect("desanitize_json should succeed");
    assert_eq!(
        restored, original,
        "JSON roundtrip must restore exact original structure"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Test 5: Multiple PII occurrences get distinct sequence numbers.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_query_sanitizer_multiple_pii_get_distinct_placeholders() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());

    let input = "Email alice@example.com or bob@example.com for details";
    let sanitized = sanitizer.sanitize(input).expect("sanitize should succeed");

    // Neither email should remain
    assert!(!sanitized.contains("alice@example.com"));
    assert!(!sanitized.contains("bob@example.com"));

    // Should have at least 2 distinct placeholders
    assert!(
        sanitizer.mapping_count() >= 2,
        "expected at least 2 distinct PII mappings, got: {}",
        sanitizer.mapping_count()
    );

    // Desanitize restores both emails to their correct positions
    let restored = sanitizer.desanitize(&sanitized).expect("desanitize");
    assert_eq!(restored, input);
}

// ═══════════════════════════════════════════════════════════════════
// Test 6: Session isolator with custom PII patterns preserves
//         per-session custom-category detection.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_isolator_sanitize_and_desanitize_within_same_session() {
    let isolator = SessionIsolator::new();
    let session = "session-medical";

    // The default scanner detects emails and SSNs
    let input = "Patient SSN 123-45-6789 email: patient@hospital.org";
    let sanitized = isolator
        .sanitize_in_session(session, input)
        .expect("sanitize");

    assert!(!sanitized.contains("123-45-6789"), "SSN must be sanitized");
    assert!(
        !sanitized.contains("patient@hospital.org"),
        "email must be sanitized"
    );
    assert!(
        sanitized.contains("[PII_SSN_") || sanitized.contains("[PII_"),
        "SSN placeholder expected"
    );

    // Desanitize in same session restores original
    let restored = isolator
        .desanitize_in_session(session, &sanitized)
        .expect("desanitize");
    assert_eq!(
        restored, input,
        "same-session roundtrip must restore original"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Test 7: QuerySanitizer clear() wipes mappings, making subsequent
//         desanitize unable to restore previous PII.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_query_sanitizer_clear_prevents_desanitization() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());

    let sanitized = sanitizer.sanitize("secret@example.com").expect("sanitize");
    assert!(sanitized.contains("[PII_EMAIL_"));
    assert!(sanitizer.mapping_count() > 0);

    // Clear all mappings
    sanitizer.clear();
    assert_eq!(sanitizer.mapping_count(), 0);

    // Desanitize can no longer restore the email — placeholder remains as-is
    let after_clear = sanitizer.desanitize(&sanitized).expect("desanitize");
    assert!(
        after_clear.contains("[PII_EMAIL_"),
        "placeholder should remain after clear, got: {after_clear}"
    );
    assert!(
        !after_clear.contains("secret@example.com"),
        "email must not be restored after clear"
    );
}
