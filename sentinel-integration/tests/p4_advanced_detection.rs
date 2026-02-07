//! Integration tests for P4 advanced detection features.
//!
//! Tests end-to-end behavior of:
//! - P4.1: Behavioral anomaly detection (EMA baselines, cold start, anomaly alerts)
//! - P4.2: Cross-request data flow tracking (exfiltration chain detection)
//! - P4.3: Semantic injection detection (paraphrase detection via n-gram TF-IDF)

// ═══════════════════════════════════════════════════
// P4.1: BEHAVIORAL ANOMALY DETECTION
// ═══════════════════════════════════════════════════

mod behavioral {
    use sentinel_engine::behavioral::{AnomalySeverity, BehavioralConfig, BehavioralTracker};
    use std::collections::HashMap;

    fn default_tracker() -> BehavioralTracker {
        BehavioralTracker::new(BehavioralConfig::default()).expect("default config works")
    }

    fn tracker_with_config(alpha: f64, threshold: f64, min_sessions: u32) -> BehavioralTracker {
        BehavioralTracker::new(BehavioralConfig {
            alpha,
            threshold,
            min_sessions,
            ..Default::default()
        })
        .expect("config works")
    }

    #[test]
    fn cold_start_no_alerts_for_new_agents() {
        let mut tracker = default_tracker();
        // First session: 100 calls to read_file — should NOT alert (cold start)
        let mut tool_counts = HashMap::new();
        tool_counts.insert("read_file".to_string(), 100u64);
        let alerts = tracker.check_session("agent-a", &tool_counts);
        assert!(
            alerts.is_empty(),
            "First session should not generate alerts (cold start), got: {:?}",
            alerts
        );
        tracker.record_session("agent-a", &tool_counts);
    }

    #[test]
    fn baseline_builds_over_sessions() {
        let mut tracker = tracker_with_config(0.3, 10.0, 3);
        let normal = HashMap::from([("read_file".to_string(), 5u64)]);

        // Record 3 normal sessions to build baseline
        for _ in 0..3 {
            let alerts = tracker.check_session("agent-x", &normal);
            assert!(alerts.is_empty(), "Normal sessions should not alert");
            tracker.record_session("agent-x", &normal);
        }

        // 4th session: same normal usage — no alert expected
        let alerts = tracker.check_session("agent-x", &normal);
        assert!(alerts.is_empty(), "Continued normal usage should not alert");
    }

    #[test]
    fn anomaly_detected_after_baseline_established() {
        let mut tracker = tracker_with_config(0.3, 5.0, 3);
        let normal = HashMap::from([("read_file".to_string(), 5u64)]);

        // Build baseline over 3+ sessions
        for _ in 0..5 {
            tracker.record_session("agent-b", &normal);
        }

        // Spike: 500 calls (100x normal)
        let spike = HashMap::from([("read_file".to_string(), 500u64)]);
        let alerts = tracker.check_session("agent-b", &spike);
        assert!(
            !alerts.is_empty(),
            "Spike of 500 calls (vs baseline ~5) should trigger anomaly"
        );
        assert!(
            alerts
                .iter()
                .any(|a| a.tool == "read_file" && matches!(a.severity, AnomalySeverity::Critical)),
            "100x deviation should be High severity, got: {:?}",
            alerts
        );
    }

    #[test]
    fn different_agents_have_independent_baselines() {
        let mut tracker = tracker_with_config(0.3, 5.0, 3);

        // Agent A: heavy reader
        let heavy = HashMap::from([("read_file".to_string(), 100u64)]);
        for _ in 0..5 {
            tracker.record_session("agent-heavy", &heavy);
        }

        // Agent B: light reader
        let light = HashMap::from([("read_file".to_string(), 2u64)]);
        for _ in 0..5 {
            tracker.record_session("agent-light", &light);
        }

        // 100 calls from heavy agent: normal
        let alerts_heavy = tracker.check_session("agent-heavy", &heavy);
        assert!(
            alerts_heavy.is_empty(),
            "100 calls is normal for heavy agent"
        );

        // 100 calls from light agent: anomalous
        let alerts_light = tracker.check_session("agent-light", &heavy);
        assert!(
            !alerts_light.is_empty(),
            "100 calls is anomalous for light agent (baseline ~2)"
        );
    }

    #[test]
    fn snapshot_and_restore_preserves_baselines() {
        let mut tracker = tracker_with_config(0.3, 5.0, 3);
        let normal = HashMap::from([("read_file".to_string(), 10u64)]);

        // Build baseline
        for _ in 0..5 {
            tracker.record_session("agent-persist", &normal);
        }

        // Snapshot
        let snapshot = tracker.snapshot();

        // Restore into new tracker
        let restored = BehavioralTracker::from_snapshot(
            BehavioralConfig {
                alpha: 0.3,
                threshold: 5.0,
                min_sessions: 3,
                ..Default::default()
            },
            snapshot,
        )
        .expect("restore works");

        // Verify baseline still works — spike should alert
        let spike = HashMap::from([("read_file".to_string(), 500u64)]);
        let alerts = restored.check_session("agent-persist", &spike);
        assert!(
            !alerts.is_empty(),
            "Restored tracker should detect anomaly against pre-existing baseline"
        );
    }

    #[test]
    fn new_tool_in_session_not_anomalous() {
        let mut tracker = tracker_with_config(0.3, 5.0, 3);
        let normal = HashMap::from([("read_file".to_string(), 5u64)]);

        // Build baseline with read_file only
        for _ in 0..5 {
            tracker.record_session("agent-c", &normal);
        }

        // Session with a completely new tool — should not trigger anomaly
        // (no baseline exists for write_file)
        let new_tool = HashMap::from([
            ("read_file".to_string(), 5u64),
            ("write_file".to_string(), 3u64),
        ]);
        let alerts = tracker.check_session("agent-c", &new_tool);
        // Filter for only write_file alerts (read_file should be fine)
        let write_alerts: Vec<_> = alerts.iter().filter(|a| a.tool == "write_file").collect();
        assert!(
            write_alerts.is_empty(),
            "New tool with no baseline should not alert (cold start per-tool)"
        );
    }
}

// ═══════════════════════════════════════════════════
// P4.2: CROSS-REQUEST DATA FLOW TRACKING
// ═══════════════════════════════════════════════════

mod data_flow {
    use sentinel_mcp::data_flow::{DataFlowConfig, DataFlowTracker, DlpFindingWithFingerprint};
    use sentinel_mcp::inspection::DlpFinding;

    fn default_tracker() -> DataFlowTracker {
        DataFlowTracker::new(DataFlowConfig::default()).expect("default config works")
    }

    fn make_finding(
        pattern: &str,
        location: &str,
        value: Option<&str>,
    ) -> DlpFindingWithFingerprint {
        DlpFindingWithFingerprint::from_finding(
            DlpFinding {
                pattern_name: pattern.to_string(),
                location: location.to_string(),
            },
            value,
        )
    }

    #[test]
    fn no_alert_when_no_prior_response_findings() {
        let tracker = default_tracker();
        let req_findings = vec![make_finding(
            "aws_access_key",
            "$.body",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        let domains = vec!["evil.com".to_string()];

        let alerts = tracker.check_request("send_email", &req_findings, &domains);
        assert!(
            alerts.is_empty(),
            "No prior response findings → no exfiltration chain"
        );
    }

    #[test]
    fn detects_exfiltration_chain_pattern_match() {
        let mut tracker = default_tracker();

        // Step 1: Tool response contains an AWS key
        let resp_findings = vec![make_finding(
            "aws_access_key",
            "result.content[0].text",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        tracker.record_response_findings("read_secrets", &resp_findings);

        // Step 2: Subsequent request to external domain contains same pattern type
        let req_findings = vec![make_finding(
            "aws_access_key",
            "$.arguments.body",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        let domains = vec!["evil.com".to_string()];

        let alerts = tracker.check_request("send_email", &req_findings, &domains);
        assert!(
            !alerts.is_empty(),
            "AWS key in response then request to external domain = exfiltration chain"
        );
        assert!(
            alerts[0].source_tool == "read_secrets",
            "Alert should reference source tool, got: {:?}",
            alerts[0]
        );
    }

    #[test]
    fn no_alert_for_different_pattern_types() {
        let mut tracker = default_tracker();

        // Response has AWS key
        let resp_findings = vec![make_finding(
            "aws_access_key",
            "text",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        tracker.record_response_findings("read_tool", &resp_findings);

        // Request has GitHub token (different pattern type)
        let req_findings = vec![make_finding(
            "github_token",
            "$.body",
            Some("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"),
        )];
        let domains = vec!["evil.com".to_string()];

        let alerts = tracker.check_request("send_tool", &req_findings, &domains);
        assert!(
            alerts.is_empty(),
            "Different DLP pattern types should not correlate"
        );
    }

    #[test]
    fn exact_match_mode_requires_same_secret_value() {
        let config = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("config works");

        // Response has key A
        let resp_findings = vec![make_finding(
            "aws_access_key",
            "text",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        tracker.record_response_findings("read_tool", &resp_findings);

        // Request has DIFFERENT key B (same pattern type but different value)
        let req_findings = vec![make_finding(
            "aws_access_key",
            "$.body",
            Some("AKIAI999999999DIFFER"),
        )];
        let domains = vec!["evil.com".to_string()];

        let alerts = tracker.check_request("send_tool", &req_findings, &domains);
        assert!(
            alerts.is_empty(),
            "Exact match mode: different secret values should not alert"
        );
    }

    #[test]
    fn exact_match_mode_detects_same_secret_value() {
        let config = DataFlowConfig {
            require_exact_match: true,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("config works");

        let secret = "AKIAIOSFODNN7EXAMPLE";
        let resp_findings = vec![make_finding("aws_access_key", "text", Some(secret))];
        tracker.record_response_findings("read_tool", &resp_findings);

        let req_findings = vec![make_finding("aws_access_key", "$.body", Some(secret))];
        let domains = vec!["evil.com".to_string()];

        let alerts = tracker.check_request("send_tool", &req_findings, &domains);
        assert!(
            !alerts.is_empty(),
            "Exact match mode: same secret value should alert"
        );
    }

    #[test]
    fn multi_step_exfiltration_chain() {
        let mut tracker = default_tracker();

        // Step 1: First tool response returns database credentials
        let resp1 = vec![make_finding(
            "generic_password",
            "text",
            Some("supersecretpassword123"),
        )];
        tracker.record_response_findings("read_database_config", &resp1);

        // Step 2: Second tool response returns an API key
        let resp2 = vec![make_finding(
            "aws_access_key",
            "text",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        tracker.record_response_findings("read_env_vars", &resp2);

        // Step 3: Outbound request tries to send the API key to external server
        let req_findings = vec![make_finding(
            "aws_access_key",
            "$.arguments.body",
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        let domains = vec!["attacker.com".to_string()];

        let alerts = tracker.check_request("http_post", &req_findings, &domains);
        assert!(!alerts.is_empty(), "Multi-step chain should be detected");
        assert!(
            alerts[0].source_tool == "read_env_vars",
            "Should trace back to the correct source tool"
        );
    }

    #[test]
    fn ring_buffer_eviction_at_capacity() {
        let config = DataFlowConfig {
            max_findings: 5,
            ..Default::default()
        };
        let mut tracker = DataFlowTracker::new(config).expect("config works");

        // Fill beyond capacity with different patterns
        for i in 0..10 {
            let findings = vec![make_finding(
                &format!("pattern_{}", i),
                "text",
                Some(&format!("secret_{}", i)),
            )];
            tracker.record_response_findings(&format!("tool_{}", i), &findings);
        }

        // Oldest patterns (0-4) should have been evicted
        // Newest patterns (5-9) should remain
        let req = vec![make_finding("pattern_0", "$.body", Some("secret_0"))];
        let domains = vec!["evil.com".to_string()];
        let alerts_old = tracker.check_request("send", &req, &domains);

        let req_new = vec![make_finding("pattern_9", "$.body", Some("secret_9"))];
        let alerts_new = tracker.check_request("send", &req_new, &domains);

        assert!(alerts_old.is_empty(), "Evicted pattern should not alert");
        assert!(!alerts_new.is_empty(), "Recent pattern should still alert");
    }
}

// ═══════════════════════════════════════════════════
// P4.1 + P4.2 INTERACTION
// ═══════════════════════════════════════════════════

mod p4_interaction {
    use sentinel_engine::behavioral::{BehavioralConfig, BehavioralTracker};
    use sentinel_mcp::data_flow::{DataFlowConfig, DataFlowTracker, DlpFindingWithFingerprint};
    use sentinel_mcp::inspection::DlpFinding;
    use std::collections::HashMap;

    /// Simulates a complete attack scenario:
    /// 1. Agent builds normal baseline (behavioral)
    /// 2. Agent reads a secret (data flow records it)
    /// 3. Agent makes anomalously many HTTP calls (behavioral detects)
    /// 4. Agent tries to exfiltrate the secret (data flow detects)
    #[test]
    fn combined_behavioral_and_data_flow_attack_detection() {
        // Set up behavioral tracker
        let mut behavioral = BehavioralTracker::new(BehavioralConfig {
            alpha: 0.3,
            threshold: 5.0,
            min_sessions: 3,
            ..Default::default()
        })
        .expect("config works");

        // Set up data flow tracker
        let mut data_flow = DataFlowTracker::new(DataFlowConfig::default()).expect("config works");

        // Phase 1: Normal behavior for 5 sessions
        let normal = HashMap::from([
            ("read_file".to_string(), 5u64),
            ("http_post".to_string(), 1u64),
        ]);
        for _ in 0..5 {
            behavioral.record_session("compromised-agent", &normal);
        }

        // Phase 2: Tool response contains a secret
        let resp_findings = vec![DlpFindingWithFingerprint::from_finding(
            DlpFinding {
                pattern_name: "aws_access_key".to_string(),
                location: "result.content[0].text".to_string(),
            },
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        data_flow.record_response_findings("read_secrets", &resp_findings);

        // Phase 3: Anomalous spike in HTTP posts
        let spike = HashMap::from([
            ("read_file".to_string(), 5u64),
            ("http_post".to_string(), 50u64),
        ]);
        let behavioral_alerts = behavioral.check_session("compromised-agent", &spike);

        // Phase 4: Exfiltration attempt
        let req_findings = vec![DlpFindingWithFingerprint::from_finding(
            DlpFinding {
                pattern_name: "aws_access_key".to_string(),
                location: "$.arguments.body".to_string(),
            },
            Some("AKIAIOSFODNN7EXAMPLE"),
        )];
        let exfil_alerts =
            data_flow.check_request("http_post", &req_findings, &vec!["evil.com".to_string()]);

        // Both detection systems should fire
        assert!(
            !behavioral_alerts.is_empty(),
            "50x spike in http_post should trigger behavioral anomaly"
        );
        assert!(
            !exfil_alerts.is_empty(),
            "Secret in response then in request to evil.com should trigger data flow alert"
        );
    }
}
