//! NHI (Non-Human Identity) Lifecycle Integration Tests
//!
//! Tests the complete NHI flow:
//! - Identity registration with different attestation types
//! - Identity lifecycle (probationary → active → suspended → revoked)
//! - Behavioral baseline tracking and anomaly detection
//! - Delegation chain creation and resolution
//! - Credential rotation
//! - DPoP nonce generation and validation

use sentinel_config::NhiConfig;
use sentinel_mcp::nhi::{NhiError, NhiManager};
use sentinel_types::{
    NhiAttestationType, NhiBehavioralRecommendation, NhiIdentityStatus,
};
use std::collections::HashMap;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn enabled_config() -> NhiConfig {
    NhiConfig {
        enabled: true,
        ..Default::default()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY REGISTRATION AND LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_register_jwt_identity() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "Test JWT Agent",
                NhiAttestationType::Jwt,
                None,
                Some("public-key-pem"),
                Some("Ed25519"),
                Some(3600),
                vec!["production".to_string()],
                HashMap::new(),
            )
            .await
            .expect("Should register identity");

        let identity = manager.get_identity(&id).await.expect("Should find identity");
        assert_eq!(identity.name, "Test JWT Agent");
        assert_eq!(identity.attestation_type, NhiAttestationType::Jwt);
        assert_eq!(identity.status, NhiIdentityStatus::Probationary);
        assert_eq!(identity.public_key, Some("public-key-pem".to_string()));
        assert!(identity.tags.contains(&"production".to_string()));
    });
}

#[test]
fn test_register_spiffe_identity() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "SPIFFE Agent",
                NhiAttestationType::Spiffe,
                Some("spiffe://example.org/service/api"),
                None,
                None,
                None,
                vec![],
                HashMap::new(),
            )
            .await
            .expect("Should register SPIFFE identity");

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.spiffe_id, Some("spiffe://example.org/service/api".to_string()));
    });
}

#[test]
fn test_register_mtls_identity() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity(
                "mTLS Agent",
                NhiAttestationType::Mtls,
                None,
                Some("cert-fingerprint"),
                None,
                None,
                vec!["internal".to_string()],
                HashMap::new(),
            )
            .await
            .expect("Should register mTLS identity");

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.attestation_type, NhiAttestationType::Mtls);
    });
}

#[test]
fn test_identity_lifecycle_probationary_to_active() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity("Lifecycle Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        // Initially probationary
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Probationary);

        // Activate
        manager.activate_identity(&id).await.expect("Should activate");
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Active);
    });
}

#[test]
fn test_identity_lifecycle_suspend_and_revoke() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity("Suspend Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        manager.activate_identity(&id).await.unwrap();

        // Suspend
        manager.update_status(&id, NhiIdentityStatus::Suspended).await.unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Suspended);

        // Revoke
        manager.update_status(&id, NhiIdentityStatus::Revoked).await.unwrap();
        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Revoked);
        assert!(manager.is_revoked(&id).await);
    });
}

#[test]
fn test_cannot_activate_non_probationary() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity("Already Active", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        manager.activate_identity(&id).await.unwrap();

        // Try to activate again
        let result = manager.activate_identity(&id).await;
        assert!(matches!(result, Err(NhiError::InvalidStatusTransition { .. })));
    });
}

#[test]
fn test_record_auth_increments_counter() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity("Auth Counter", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        for _ in 0..5 {
            manager.record_auth(&id).await.unwrap();
        }

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.auth_count, 5);
        assert!(identity.last_auth.is_some());
    });
}

#[test]
fn test_list_identities_with_status_filter() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        // Register multiple agents with different statuses
        let id1 = manager.register_identity("Agent 1", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let id2 = manager.register_identity("Agent 2", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let _id3 = manager.register_identity("Agent 3", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        manager.activate_identity(&id1).await.unwrap();
        manager.update_status(&id2, NhiIdentityStatus::Suspended).await.unwrap();

        let active = manager.list_identities(Some(NhiIdentityStatus::Active)).await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "Agent 1");

        let suspended = manager.list_identities(Some(NhiIdentityStatus::Suspended)).await;
        assert_eq!(suspended.len(), 1);

        let all = manager.list_identities(None).await;
        assert_eq!(all.len(), 3);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// BEHAVIORAL ATTESTATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_behavioral_baseline_creation() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            min_baseline_observations: 10,
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Baseline Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        // No baseline initially
        assert!(manager.get_baseline(&id).await.is_none());

        // Build baseline
        for _ in 0..15 {
            manager.update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1")).await.unwrap();
        }

        let baseline = manager.get_baseline(&id).await.expect("Should have baseline");
        assert_eq!(baseline.observation_count, 15);
        assert!(baseline.confidence >= 1.0);
        assert!(baseline.tool_call_patterns.contains_key("file:read"));
        assert!(baseline.typical_source_ips.contains(&"10.0.0.1".to_string()));
    });
}

#[test]
fn test_behavioral_check_within_baseline() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            min_baseline_observations: 10,
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Check Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        // Build baseline
        for _ in 0..20 {
            manager.update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1")).await.unwrap();
        }

        // Check normal behavior
        let result = manager.check_behavior(&id, "file:read", Some(1.0), Some("10.0.0.1")).await;
        assert!(result.within_baseline);
        assert_eq!(result.recommendation, NhiBehavioralRecommendation::Allow);
    });
}

#[test]
fn test_behavioral_check_anomaly_unknown_tool() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            min_baseline_observations: 10,
            anomaly_threshold: 0.3,
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Anomaly Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        // Build baseline with specific tools
        for _ in 0..20 {
            manager.update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1")).await.unwrap();
        }

        // Use unknown tool
        let result = manager.check_behavior(&id, "bash:execute", Some(1.0), Some("10.0.0.1")).await;
        assert!(!result.deviations.is_empty());
        assert!(result.anomaly_score > 0.0);
    });
}

#[test]
fn test_behavioral_check_during_learning() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            min_baseline_observations: 100, // High threshold
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Learning Test", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await
            .unwrap();

        // Only a few observations (still learning)
        for _ in 0..5 {
            manager.update_baseline(&id, "file:read", Some(1.0), Some("10.0.0.1")).await.unwrap();
        }

        // During learning period, allow anything
        let result = manager.check_behavior(&id, "unknown:tool", Some(100.0), Some("1.2.3.4")).await;
        assert!(result.within_baseline);
        assert_eq!(result.recommendation, NhiBehavioralRecommendation::Allow);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// DELEGATION CHAINS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_delegation() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let agent_a = manager.register_identity("Agent A", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_b = manager.register_identity("Agent B", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        let delegation = manager
            .create_delegation(
                &agent_a,
                &agent_b,
                vec!["read".to_string(), "write".to_string()],
                vec!["tools:file_*".to_string()],
                3600,
                Some("Temporary access".to_string()),
            )
            .await
            .expect("Should create delegation");

        assert_eq!(delegation.from_agent, agent_a);
        assert_eq!(delegation.to_agent, agent_b);
        assert!(delegation.permissions.contains(&"read".to_string()));
        assert!(delegation.scope_constraints.contains(&"tools:file_*".to_string()));
        assert!(delegation.active);
    });
}

#[test]
fn test_delegation_requires_existing_agents() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let agent_a = manager.register_identity("Agent A", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        let result = manager
            .create_delegation(&agent_a, "nonexistent", vec![], vec![], 3600, None)
            .await;

        assert!(matches!(result, Err(NhiError::IdentityNotFound(_))));
    });
}

#[test]
fn test_delegation_chain_resolution() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        // Create chain: A -> B -> C
        let agent_a = manager.register_identity("Agent A", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_b = manager.register_identity("Agent B", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_c = manager.register_identity("Agent C", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        manager.create_delegation(&agent_a, &agent_b, vec!["admin".to_string()], vec![], 3600, None).await.unwrap();
        manager.create_delegation(&agent_b, &agent_c, vec!["read".to_string()], vec![], 3600, None).await.unwrap();

        let chain = manager.resolve_delegation_chain(&agent_c).await;
        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.origin(), Some(agent_a.as_str()));
        assert_eq!(chain.terminus(), Some(agent_c.as_str()));
        assert!(!chain.exceeds_max_depth());
    });
}

#[test]
fn test_revoke_delegation() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let agent_a = manager.register_identity("Agent A", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_b = manager.register_identity("Agent B", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        manager.create_delegation(&agent_a, &agent_b, vec![], vec![], 3600, None).await.unwrap();

        // Revoke
        manager.revoke_delegation(&agent_a, &agent_b).await.unwrap();

        let delegation = manager.get_delegation(&agent_a, &agent_b).await.unwrap();
        assert!(!delegation.active);
    });
}

#[test]
fn test_list_delegations_for_agent() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let agent_a = manager.register_identity("Agent A", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_b = manager.register_identity("Agent B", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let agent_c = manager.register_identity("Agent C", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        manager.create_delegation(&agent_a, &agent_b, vec![], vec![], 3600, None).await.unwrap();
        manager.create_delegation(&agent_a, &agent_c, vec![], vec![], 3600, None).await.unwrap();

        let delegations = manager.list_delegations(&agent_a).await;
        assert_eq!(delegations.len(), 2);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CREDENTIAL ROTATION
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_credential_rotation() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id = manager
            .register_identity("Rotation Test", NhiAttestationType::Jwt, None, Some("old-key"), Some("Ed25519"), None, vec![], HashMap::new())
            .await
            .unwrap();

        let rotation = manager
            .rotate_credentials(&id, "new-key", Some("Ed25519"), "scheduled", Some(7200))
            .await
            .expect("Should rotate credentials");

        assert!(rotation.previous_thumbprint.is_some());
        assert!(!rotation.new_thumbprint.is_empty());
        assert_eq!(rotation.trigger, "scheduled");

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.public_key, Some("new-key".to_string()));
        assert!(identity.last_rotation.is_some());
    });
}

#[test]
fn test_rotation_nonexistent_agent() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let result = manager
            .rotate_credentials("nonexistent", "new-key", None, "manual", None)
            .await;

        assert!(matches!(result, Err(NhiError::IdentityNotFound(_))));
    });
}

#[test]
fn test_get_expiring_identities() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            credential_ttl_secs: 10, // Very short TTL
            rotation_warning_hours: 1,
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Expiring Soon", NhiAttestationType::Jwt, None, None, None, Some(10), vec![], HashMap::new())
            .await
            .unwrap();

        manager.activate_identity(&id).await.unwrap();

        let expiring = manager.get_expiring_identities().await;
        // The identity should be in the expiring list since it expires in 10 seconds
        // and the warning window is 1 hour
        assert!(expiring.iter().any(|i| i.id == id));
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// DPOP NONCE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_dpop_nonce_generation() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let nonce1 = manager.generate_dpop_nonce().await;
        let nonce2 = manager.generate_dpop_nonce().await;

        assert!(!nonce1.is_empty());
        assert!(!nonce2.is_empty());
        assert_ne!(nonce1, nonce2);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATISTICS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_stats_tracking() {
    runtime().block_on(async {
        let manager = NhiManager::new(enabled_config());

        let id1 = manager.register_identity("Agent 1", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        let id2 = manager.register_identity("Agent 2", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        manager.activate_identity(&id1).await.unwrap();
        manager.update_status(&id2, NhiIdentityStatus::Suspended).await.unwrap();

        manager.create_delegation(&id1, &id2, vec![], vec![], 3600, None).await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.total_identities, 2);
        assert_eq!(stats.active_identities, 1);
        assert_eq!(stats.suspended_identities, 1);
        assert_eq!(stats.active_delegations, 1);
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_disabled_manager_rejects_operations() {
    runtime().block_on(async {
        let manager = NhiManager::new(NhiConfig::default()); // Disabled

        let result = manager
            .register_identity("Should Fail", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new())
            .await;

        assert!(matches!(result, Err(NhiError::Disabled)));
    });
}

#[test]
fn test_ttl_exceeds_max_rejected() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            max_credential_ttl_secs: 3600, // 1 hour max
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let result = manager
            .register_identity("Long TTL", NhiAttestationType::Jwt, None, None, None, Some(86400), vec![], HashMap::new())
            .await;

        assert!(matches!(result, Err(NhiError::TtlExceedsMax { .. })));
    });
}

#[test]
fn test_capacity_limits() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            max_identities: 2,
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        manager.register_identity("Agent 1", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();
        manager.register_identity("Agent 2", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await.unwrap();

        let result = manager.register_identity("Agent 3", NhiAttestationType::Jwt, None, None, None, None, vec![], HashMap::new()).await;
        assert!(matches!(result, Err(NhiError::CapacityExceeded(_))));
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_cleanup_expired() {
    runtime().block_on(async {
        let config = NhiConfig {
            enabled: true,
            credential_ttl_secs: 1, // Very short TTL
            ..Default::default()
        };
        let manager = NhiManager::new(config);

        let id = manager
            .register_identity("Expire Soon", NhiAttestationType::Jwt, None, None, None, Some(1), vec![], HashMap::new())
            .await
            .unwrap();

        manager.activate_identity(&id).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        manager.cleanup_expired().await;

        let identity = manager.get_identity(&id).await.unwrap();
        assert_eq!(identity.status, NhiIdentityStatus::Expired);
    });
}
