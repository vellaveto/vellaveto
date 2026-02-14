//! CI validation tests for Phase 18: SDK tier declaration.
//!
//! These tests ensure Sentinel maintains at least Standard tier and
//! declares all required capabilities for its Extended tier level.

use sentinel_types::SdkTier;

#[test]
fn test_sdk_tier_minimum_standard() {
    // Sentinel must declare at least Standard tier.
    let tier = sentinel_http_proxy::proxy::discovery::SENTINEL_SDK_TIER;
    assert!(
        tier >= SdkTier::Standard,
        "Sentinel must declare at least Standard SDK tier, got {:?}",
        tier
    );
}

#[test]
fn test_extended_tier_required_capabilities() {
    // Extended tier requires these 8 minimum capabilities.
    let caps = sentinel_http_proxy::proxy::discovery::build_sdk_capabilities();
    let required = [
        "policy-evaluation",
        "audit-logging",
        "dlp-scanning",
        "injection-detection",
        "multi-transport",
        "threat-detection",
        "compliance-evidence",
        "protocol-extensions",
    ];
    for req in &required {
        assert!(
            caps.capabilities.iter().any(|c| c == req),
            "Extended tier requires capability '{}', not found in {:?}",
            req,
            caps.capabilities
        );
    }
}
