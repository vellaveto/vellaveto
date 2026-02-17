//! Self-tests for the MCPSEC benchmark harness.
//!
//! These tests validate the harness logic itself (scoring, report generation,
//! attack registry) without requiring a running gateway.

use mcpsec::attacks;
use mcpsec::scoring;
use mcpsec::{AttackResult, BenchmarkResult, BenchmarkSummary, PropertyScore};

#[test]
fn test_attack_registry_has_64_tests() {
    let tests = attacks::all_tests();
    assert_eq!(
        tests.len(),
        64,
        "Expected 64 test cases, got {}",
        tests.len()
    );
}

#[test]
fn test_all_attack_ids_unique() {
    let tests = attacks::all_tests();
    let mut ids: Vec<&str> = tests.iter().map(|t| t.id).collect();
    let total = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total, "All test IDs must be unique");
}

#[test]
fn test_attack_ids_follow_format() {
    let tests = attacks::all_tests();
    for test in &tests {
        assert!(
            test.id.starts_with('A'),
            "Test ID must start with 'A': {}",
            test.id
        );
        let parts: Vec<&str> = test.id.split('.').collect();
        assert_eq!(
            parts.len(),
            2,
            "Test ID must have format 'AX.Y': {}",
            test.id
        );
    }
}

#[test]
fn test_all_12_attack_classes_present() {
    let tests = attacks::all_tests();
    let mut classes: Vec<&str> = tests.iter().map(|t| t.class).collect();
    classes.sort();
    classes.dedup();
    assert_eq!(
        classes.len(),
        12,
        "Expected 12 attack classes, got {}: {:?}",
        classes.len(),
        classes
    );
}

#[test]
fn test_scoring_weights_sum_to_one() {
    // Implicitly tested via scoring module, but verify here too
    let attacks: Vec<AttackResult> = attacks::all_tests()
        .iter()
        .map(|t| AttackResult {
            attack_id: t.id.to_string(),
            name: t.name.to_string(),
            class: t.class.to_string(),
            passed: true,
            latency_ns: 0,
            details: String::new(),
        })
        .collect();

    let props = scoring::calculate_property_scores(&attacks);
    let score = scoring::calculate_overall_score(&props);
    assert!(
        (score - 100.0).abs() < 0.01,
        "All-pass should give 100%, got {score}"
    );
}

#[test]
fn test_scoring_all_fail_gives_zero() {
    let attacks: Vec<AttackResult> = attacks::all_tests()
        .iter()
        .map(|t| AttackResult {
            attack_id: t.id.to_string(),
            name: t.name.to_string(),
            class: t.class.to_string(),
            passed: false,
            latency_ns: 0,
            details: String::new(),
        })
        .collect();

    let props = scoring::calculate_property_scores(&attacks);
    let score = scoring::calculate_overall_score(&props);
    assert!(score.abs() < 0.01, "All-fail should give 0%, got {score}");
}

#[test]
fn test_tier_boundaries() {
    assert_eq!(scoring::score_to_tier(0.0), 0);
    assert_eq!(scoring::score_to_tier(19.9), 0);
    assert_eq!(scoring::score_to_tier(20.0), 1);
    assert_eq!(scoring::score_to_tier(39.9), 1);
    assert_eq!(scoring::score_to_tier(40.0), 2);
    assert_eq!(scoring::score_to_tier(59.9), 2);
    assert_eq!(scoring::score_to_tier(60.0), 3);
    assert_eq!(scoring::score_to_tier(79.9), 3);
    assert_eq!(scoring::score_to_tier(80.0), 4);
    assert_eq!(scoring::score_to_tier(94.9), 4);
    assert_eq!(scoring::score_to_tier(95.0), 5);
    assert_eq!(scoring::score_to_tier(100.0), 5);
}

#[test]
fn test_tier_names() {
    assert_eq!(scoring::tier_name(0), "Unsafe");
    assert_eq!(scoring::tier_name(1), "Basic");
    assert_eq!(scoring::tier_name(2), "Moderate");
    assert_eq!(scoring::tier_name(3), "Strong");
    assert_eq!(scoring::tier_name(4), "Comprehensive");
    assert_eq!(scoring::tier_name(5), "Hardened");
}

#[test]
fn test_json_report_roundtrip() {
    let result = BenchmarkResult {
        framework: "MCPSEC".to_string(),
        version: "1.0.0".to_string(),
        timestamp: "2026-02-15T12:00:00Z".to_string(),
        gateway: "test-gateway".to_string(),
        gateway_version: "1.0.0".to_string(),
        overall_score: 97.0,
        tier: 5,
        tier_name: "Hardened".to_string(),
        properties: vec![PropertyScore {
            property_id: "P1".to_string(),
            name: "Tool-Level Access Control".to_string(),
            score: 100.0,
            tests_passed: 6,
            tests_total: 6,
        }],
        attacks: vec![AttackResult {
            attack_id: "A1.1".to_string(),
            name: "Classic injection phrase".to_string(),
            class: "Prompt Injection Evasion".to_string(),
            passed: true,
            latency_ns: 28000,
            details: "Detected".to_string(),
        }],
        summary: BenchmarkSummary {
            total_tests: 64,
            passed: 62,
            failed: 2,
            skipped: 0,
        },
    };

    let json = mcpsec::report::to_json(&result);
    let parsed: BenchmarkResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.framework, "MCPSEC");
    assert_eq!(parsed.overall_score, 97.0);
    assert_eq!(parsed.tier, 5);
}

#[test]
fn test_markdown_report_generation() {
    let result = BenchmarkResult {
        framework: "MCPSEC".to_string(),
        version: "1.0.0".to_string(),
        timestamp: "2026-02-15T12:00:00Z".to_string(),
        gateway: "test-gateway".to_string(),
        gateway_version: "1.0.0".to_string(),
        overall_score: 50.0,
        tier: 2,
        tier_name: "Moderate".to_string(),
        properties: vec![],
        attacks: vec![
            AttackResult {
                attack_id: "A1.1".to_string(),
                name: "Test pass".to_string(),
                class: "Class A".to_string(),
                passed: true,
                latency_ns: 1000,
                details: String::new(),
            },
            AttackResult {
                attack_id: "A1.2".to_string(),
                name: "Test fail".to_string(),
                class: "Class A".to_string(),
                passed: false,
                latency_ns: 2000,
                details: "Not detected".to_string(),
            },
        ],
        summary: BenchmarkSummary {
            total_tests: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
        },
    };

    let md = mcpsec::report::to_markdown(&result);
    assert!(md.contains("MCPSEC Benchmark Report"));
    assert!(md.contains("Overall Score"));
    assert!(md.contains("PASS"));
    assert!(md.contains("**FAIL**"));
    assert!(md.contains("Failed Tests"));
}

#[test]
fn test_every_property_has_tests() {
    let all = attacks::all_tests();
    let attacks: Vec<AttackResult> = all
        .iter()
        .map(|t| AttackResult {
            attack_id: t.id.to_string(),
            name: t.name.to_string(),
            class: t.class.to_string(),
            passed: true,
            latency_ns: 0,
            details: String::new(),
        })
        .collect();

    let props = scoring::calculate_property_scores(&attacks);

    for prop in &props {
        assert!(
            prop.tests_total > 0,
            "Property {} ({}) has no mapped tests",
            prop.property_id,
            prop.name
        );
    }
}

#[test]
fn test_verdict_parsing_vellaveto_format() {
    let deny = serde_json::json!({"verdict": {"Deny": {"reason": "blocked"}}});
    assert!(attacks::is_deny(&deny, 200));
    assert!(!attacks::is_allow(&deny, 200));

    let allow = serde_json::json!({"verdict": "Allow"});
    assert!(attacks::is_allow(&allow, 200));
    assert!(!attacks::is_deny(&allow, 200));
}

#[test]
fn test_verdict_parsing_simple_format() {
    let deny = serde_json::json!({"verdict": "Deny"});
    assert!(attacks::is_deny(&deny, 200));

    let deny_lower = serde_json::json!({"verdict": "deny"});
    assert!(attacks::is_deny(&deny_lower, 200));
}

#[test]
fn test_verdict_parsing_http_status() {
    let body = serde_json::json!({});
    assert!(attacks::is_deny(&body, 403));
    assert!(attacks::is_deny(&body, 429));
    assert!(!attacks::is_deny(&body, 200));
}
