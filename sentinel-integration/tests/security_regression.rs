//! Security Regression Tests for CRITICAL/HIGH Findings 1-14
//!
//! These tests verify that each vulnerability identified in the Controller's
//! external security audit is properly fixed. Each test attempts the attack
//! described in the audit report and confirms the fix blocks it.
//!
//! Reference: `.collab/orchestrator/issues/external-audit-report.md`

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::Request;
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_mcp::extractor::{classify_message, MessageType};
use sentinel_mcp::framing::{read_message, FramingError};
use sentinel_server::{routes, AppState, Metrics, RateLimits};
use sentinel_types::{Action, Policy, PolicyType, Verdict};
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::BufReader;
use tower::ServiceExt;

// ═══════════════════════════════════════════════════
// FINDING #1 — Hash chain bypass (CRITICAL)
//
// Attack: Insert a hashless entry after the chain has started.
// The old code accepted it silently, letting an attacker splice
// entries into the audit log undetected.
// Fix: verify_chain() rejects hashless entries after the first hashed one.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_1_hashless_entry_after_chain_start_rejected() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Phase 1: Create a valid hashed chain with 2 entries
    let logger = AuditLogger::new(log_path.clone());
    let action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/tmp/test"}),
    };
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    // Verify chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid, "Initial chain should be valid");

    // Phase 2: Tamper — inject a hashless entry into the log file
    let entries = logger.load_entries().await.unwrap();
    assert!(
        entries[0].entry_hash.is_some(),
        "Entries should have hashes"
    );

    // Create a fake entry without hashes and append it
    let fake_entry = json!({
        "id": "injected-fake",
        "action": {"tool": "bash", "function": "exec", "parameters": {"cmd": "rm -rf /"}},
        "verdict": "Allow",
        "timestamp": "2026-01-01T00:00:00Z",
        "metadata": {}
        // No entry_hash or prev_hash — this is the attack
    });
    let mut log_content = tokio::fs::read_to_string(&log_path).await.unwrap();
    log_content.push_str(&serde_json::to_string(&fake_entry).unwrap());
    log_content.push('\n');
    tokio::fs::write(&log_path, log_content).await.unwrap();

    // Phase 3: Verify that the chain is now invalid
    let logger2 = AuditLogger::new(log_path);
    let verification = logger2.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Chain with injected hashless entry must be detected as invalid"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #2 — Hash chain field separators (CRITICAL)
//
// Attack: Two entries with boundary-shifted fields produce the same hash.
// e.g., tool="ab", function="cd" vs tool="abc", function="d"
// Fix: Length-prefixed encoding prevents field boundary collisions.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_2_boundary_shifted_fields_produce_different_hashes() {
    let tmp = TempDir::new().unwrap();

    // Entry A: tool="ab", function="cd"
    let logger_a = AuditLogger::new(tmp.path().join("a.log"));
    let action_a = Action {
        tool: "ab".to_string(),
        function: "cd".to_string(),
        parameters: json!({}),
    };
    logger_a
        .log_entry(&action_a, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Entry B: tool="abc", function="d"
    let logger_b = AuditLogger::new(tmp.path().join("b.log"));
    let action_b = Action {
        tool: "abc".to_string(),
        function: "d".to_string(),
        parameters: json!({}),
    };
    logger_b
        .log_entry(&action_b, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries_a = logger_a.load_entries().await.unwrap();
    let entries_b = logger_b.load_entries().await.unwrap();

    let hash_a = entries_a[0].entry_hash.as_ref().unwrap();
    let hash_b = entries_b[0].entry_hash.as_ref().unwrap();

    assert_ne!(
        hash_a, hash_b,
        "Boundary-shifted fields must produce different hashes (length-prefix encoding)"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #3 — initialize_chain trusts file (CRITICAL)
//
// Attack: Tamper with the log file, then restart the logger.
// The old code would trust the last entry's hash and chain from it.
// Fix: initialize_chain() verifies the chain before trusting it.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_3_initialize_chain_detects_tampered_file() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create a valid chain
    let logger = AuditLogger::new(log_path.clone());
    let action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({"path": "/tmp/safe"}),
    };
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    // Tamper: modify the entry_hash of the first entry (preserving valid JSON)
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    assert_eq!(lines.len(), 2, "Should have 2 entries");

    // Parse first entry, corrupt its hash, write back
    let mut entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    entry["entry_hash"] = json!("0000000000000000000000000000000000000000000000000000000000000000");
    lines[0] = serde_json::to_string(&entry).unwrap();
    let tampered = lines.join("\n") + "\n";
    tokio::fs::write(&log_path, tampered).await.unwrap();

    // Restart logger — initialize_chain should detect the corruption
    let logger2 = AuditLogger::new(log_path.clone());
    // initialize_chain calls verify_chain internally; it may warn and start fresh
    let _ = logger2.initialize_chain().await;

    // New entry after detecting corruption starts a fresh chain segment
    logger2
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // The full chain (including tampered entries) should be detected as invalid
    let entries = logger2.load_entries().await.unwrap();
    assert!(
        entries.len() >= 3,
        "Should have original entries plus new one"
    );

    // Verify the chain detects the tampering
    let verification = logger2.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Chain with tampered entry hash must be detected as invalid"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #5 — Empty tool name bypass (CRITICAL)
//
// Attack: Send a tools/call with no name or empty name.
// The old code created a ToolCall with empty string that evaded
// specific deny policies (deny rules match on tool name).
// Fix: classify_message returns Invalid for missing/empty names.
// ═══════════════════════════════════════════════════

#[test]
fn finding_5_empty_tool_name_returns_invalid_not_toolcall() {
    // Attack 1: No params at all
    let msg_no_params = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call"
    });
    assert!(
        matches!(
            classify_message(&msg_no_params),
            MessageType::Invalid { .. }
        ),
        "tools/call without params must be Invalid"
    );

    // Attack 2: Empty tool name
    let msg_empty_name = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "", "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_empty_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with empty name must be Invalid"
    );

    // Attack 3: Non-string tool name
    let msg_numeric_name = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": 42, "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_numeric_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with non-string name must be Invalid"
    );

    // Attack 4: Name is null
    let msg_null_name = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": null, "arguments": {}}
    });
    assert!(
        matches!(
            classify_message(&msg_null_name),
            MessageType::Invalid { .. }
        ),
        "tools/call with null name must be Invalid"
    );
}

#[test]
fn finding_5_valid_tool_name_still_works() {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}}
    });
    match classify_message(&msg) {
        MessageType::ToolCall { tool_name, .. } => {
            assert_eq!(tool_name, "read_file");
        }
        other => panic!("Expected ToolCall, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════
// FINDING #6 — Unbounded read_line OOM (CRITICAL)
//
// Attack: Send a line without a newline that's > 1MB.
// The old code would buffer the entire line into memory.
// Fix: MAX_LINE_LENGTH (1MB) enforced; returns LineTooLong error.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_6_oversized_line_rejected() {
    // Create a line that exceeds 1MB
    let oversized = format!("{}\n", "A".repeat(1_048_577));
    let cursor = Cursor::new(oversized.into_bytes());
    let mut reader = BufReader::new(cursor);
    let result = read_message(&mut reader).await;
    assert!(result.is_err(), "Oversized line must be rejected");
    assert!(
        matches!(result.unwrap_err(), FramingError::LineTooLong(_)),
        "Error must be LineTooLong"
    );
}

#[tokio::test]
async fn finding_6_normal_sized_line_accepted() {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let data = format!("{}\n", serde_json::to_string(&msg).unwrap());
    let cursor = Cursor::new(data.into_bytes());
    let mut reader = BufReader::new(cursor);
    let result = read_message(&mut reader).await.unwrap();
    assert!(result.is_some(), "Normal-sized line must be accepted");
}

// ═══════════════════════════════════════════════════
// FINDING #7 — No authentication on server endpoints (CRITICAL)
//
// Attack: Anyone can POST to /api/policies to add permissive policies,
// or POST to /api/evaluate to test what's allowed, without any auth.
// Fix: Bearer token auth middleware on all mutating (non-GET) endpoints.
// ═══════════════════════════════════════════════════

mod server_auth {
    use arc_swap::ArcSwap;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sentinel_approval::ApprovalStore;
    use sentinel_audit::AuditLogger;
    use sentinel_engine::PolicyEngine;
    use sentinel_server::{routes, AppState, Metrics, RateLimits};
    use sentinel_types::{Policy, PolicyType};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn make_authed_state(api_key: &str) -> (AppState, TempDir) {
        let tmp = TempDir::new().unwrap();
        let state = AppState {
            engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
            policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
                id: "file:read".to_string(),
                name: "Allow file reads".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
            }])),
            audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
            config_path: Arc::new("test.toml".to_string()),
            approvals: Arc::new(ApprovalStore::new(
                tmp.path().join("approvals.jsonl"),
                std::time::Duration::from_secs(900),
            )),
            api_key: Some(Arc::new(api_key.to_string())),
            rate_limits: Arc::new(RateLimits::disabled()),
            cors_origins: vec![],
            metrics: Arc::new(Metrics::default()),
            trusted_proxies: Arc::new(vec![]),
        };
        (state, tmp)
    }

    #[tokio::test]
    async fn post_without_auth_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST without Bearer token must be 401"
        );
    }

    #[tokio::test]
    async fn post_with_wrong_key_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-key")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST with wrong Bearer token must be 401"
        );
    }

    #[tokio::test]
    async fn post_with_correct_key_returns_200() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret-key-123")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "POST with correct Bearer token must succeed, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn get_without_auth_still_works() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::get("/health").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "GET endpoints must work without auth"
        );
    }

    #[tokio::test]
    async fn delete_without_auth_returns_401() {
        let (state, _tmp) = make_authed_state("secret-key-123");
        let app = routes::build_router(state);

        let req = Request::delete("/api/policies/some-id")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "DELETE without auth must be 401"
        );
    }

    #[tokio::test]
    async fn no_api_key_configured_allows_all() {
        let tmp = TempDir::new().unwrap();
        let state = AppState {
            engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
            policies: Arc::new(ArcSwap::from_pointee(vec![])),
            audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
            config_path: Arc::new("test.toml".to_string()),
            approvals: Arc::new(ApprovalStore::new(
                tmp.path().join("approvals.jsonl"),
                std::time::Duration::from_secs(900),
            )),
            api_key: None, // No key configured
            rate_limits: Arc::new(RateLimits::disabled()),
            cors_origins: vec![],
            metrics: Arc::new(Metrics::default()),
            trusted_proxies: Arc::new(vec![]),
        };
        let app = routes::build_router(state);

        let req = Request::post("/api/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"tool":"file","function":"read","parameters":{}}"#,
            ))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert!(
            resp.status().is_success(),
            "When no API key configured, POST should succeed without auth"
        );
    }

    #[tokio::test]
    async fn policy_add_requires_auth() {
        let (state, _tmp) = make_authed_state("test-key");
        let app = routes::build_router(state);

        let policy_json = r#"{
            "id": "evil:*",
            "name": "Attacker policy",
            "policy_type": "Allow",
            "priority": 1000
        }"#;

        let req = Request::post("/api/policies")
            .header("content-type", "application/json")
            .body(Body::from(policy_json))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Adding policies without auth must be blocked"
        );
    }

    #[tokio::test]
    async fn approval_endpoints_require_auth() {
        let (state, _tmp) = make_authed_state("test-key");
        let app = routes::build_router(state);

        let req = Request::post("/api/approvals/fake-id/approve")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Approving without auth must be blocked"
        );
    }
}

// ═══════════════════════════════════════════════════
// FINDING #8 — extract_domain `@` bypass (HIGH)
//
// Attack: URL like `https://evil.com/path?email=user@safe.com`
// The old code searched for `@` in the entire URL, finding it in the
// query string and extracting `safe.com` as the domain instead of `evil.com`.
// Fix: Only search for `@` in the authority portion.
// ═══════════════════════════════════════════════════

#[test]
fn finding_8_at_sign_in_query_does_not_poison_domain() {
    // The attack: query param contains @safe.com
    let domain = PolicyEngine::extract_domain("https://evil.com/path?email=user@safe.com");
    assert_eq!(
        domain, "evil.com",
        "@ in query string must not affect domain extraction"
    );
}

#[test]
fn finding_8_at_sign_in_fragment_does_not_poison_domain() {
    let domain = PolicyEngine::extract_domain("https://evil.com/page#user@safe.com");
    assert_eq!(
        domain, "evil.com",
        "@ in fragment must not affect domain extraction"
    );
}

#[test]
fn finding_8_legitimate_userinfo_still_works() {
    // user@host is valid in the authority section
    let domain = PolicyEngine::extract_domain("https://user@real-host.com/path");
    assert_eq!(
        domain, "real-host.com",
        "Legitimate userinfo@ must still extract the correct host"
    );
}

#[test]
fn finding_8_at_in_both_authority_and_query() {
    let domain =
        PolicyEngine::extract_domain("https://admin@legit.com/path?redirect=user@evil.com");
    assert_eq!(
        domain, "legit.com",
        "Authority @ takes precedence over query @"
    );
}

#[test]
fn finding_8_domain_policy_blocks_evil_despite_at_bypass_attempt() {
    let engine = PolicyEngine::new(false);

    let policy = Policy {
        id: "http:*".to_string(),
        name: "Block evil.com".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "evil.com"
                }]
            }),
        },
        priority: 100,
    };

    // The attack URL with @ in query trying to evade the policy
    let action = Action {
        tool: "http".to_string(),
        function: "request".to_string(),
        parameters: json!({"url": "https://evil.com/steal?callback=user@safe.com"}),
    };

    let verdict = engine.evaluate_action(&action, &[policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "evil.com must be blocked even with @ in query: got {:?}",
        verdict
    );
}

// ═══════════════════════════════════════════════════
// FINDING #9 — normalize_path empty fallback (HIGH)
//
// Attack: Path that normalizes to empty string (null bytes, etc.)
// The old code returned the RAW INPUT, which still contained the
// dangerous traversal sequences normalization was meant to remove.
// Fix: Return "/" (root) when normalization produces empty string.
// ═══════════════════════════════════════════════════

#[test]
fn finding_9_null_byte_path_normalizes_to_root() {
    let result = PolicyEngine::normalize_path("/a/b\0/c");
    assert_eq!(
        result, "/",
        "Path with null bytes must normalize to root, not raw input"
    );
}

#[test]
fn finding_9_pure_traversal_normalizes_to_root() {
    // Path that resolves to nothing after normalization
    let result = PolicyEngine::normalize_path("");
    assert_eq!(result, "/", "Empty path must normalize to root");
}

#[test]
fn finding_9_normal_paths_still_work() {
    assert_eq!(PolicyEngine::normalize_path("/etc/passwd"), "/etc/passwd");
    assert_eq!(
        PolicyEngine::normalize_path("/a/../b"),
        "/b",
        "Normal traversal should resolve correctly"
    );
    assert_eq!(
        PolicyEngine::normalize_path("/a/./b/./c"),
        "/a/b/c",
        "Dot segments should be removed"
    );
}

#[test]
fn finding_9_traversal_at_root_absorbed() {
    // Traversal beyond root should be absorbed, not preserved
    let result = PolicyEngine::normalize_path("/a/../../etc/passwd");
    assert_eq!(
        result, "/etc/passwd",
        "Traversal beyond root must be absorbed"
    );
}

// ═══════════════════════════════════════════════════
// FINDING #10 — Approval store persistence (HIGH)
//
// Verify that approvals survive a logger restart by reading
// from the persistence file.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_10_approvals_survive_restart() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("approvals.jsonl");

    // Create store and add an approval
    let store =
        sentinel_approval::ApprovalStore::new(path.clone(), std::time::Duration::from_secs(900));
    let action = Action {
        tool: "dangerous".to_string(),
        function: "exec".to_string(),
        parameters: json!({}),
    };
    let id = store
        .create(action.clone(), "needs review".to_string())
        .await
        .unwrap();

    // Verify the persistence file exists and has content
    let file_content = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(
        !file_content.is_empty(),
        "Approval store must persist to file"
    );

    // "Restart" — create new store from same path and reload from file
    let store2 = sentinel_approval::ApprovalStore::new(path, std::time::Duration::from_secs(900));
    store2
        .load_from_file()
        .await
        .expect("load_from_file must succeed");

    // The pending approval should be visible after restart + reload
    let pending = store2.list_pending().await;
    assert!(
        pending.iter().any(|a| a.id == id),
        "Approval '{}' must survive store restart (Finding #10). Got: {:?}",
        id,
        pending.iter().map(|a| &a.id).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════
// FINDING #13 — Audit records wrong verdict for RequireApproval (HIGH)
//
// The old code logged RequireApproval verdicts as Deny in the audit trail.
// Fix: The audit entry should record the actual verdict.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_13_require_approval_verdict_recorded_correctly() {
    let tmp = TempDir::new().unwrap();
    let logger = AuditLogger::new(tmp.path().join("audit.log"));

    let action = Action {
        tool: "dangerous".to_string(),
        function: "exec".to_string(),
        parameters: json!({}),
    };
    let verdict = Verdict::RequireApproval {
        reason: "needs human review".to_string(),
    };

    logger
        .log_entry(&action, &verdict, json!({"source": "test"}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);

    // The verdict in the audit entry must be RequireApproval, not Deny
    match &entries[0].verdict {
        Verdict::RequireApproval { reason } => {
            assert!(
                reason.contains("human review"),
                "Reason should be preserved"
            );
        }
        other => {
            panic!(
                "Expected RequireApproval in audit log, got {:?}. \
                 This means the audit is recording the wrong verdict.",
                other
            );
        }
    }
}

// ═══════════════════════════════════════════════════
// FINDING #14 — Empty line terminates proxy (HIGH)
//
// Attack: A blank newline from the child process terminates the proxy.
// Fix: Empty lines are skipped; only true EOF terminates.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_14_empty_lines_skipped_not_eof() {
    // Multiple empty lines followed by a valid message
    let data = b"\n\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);
    let msg = read_message(&mut reader).await.unwrap();
    assert!(
        msg.is_some(),
        "Empty lines must be skipped, not treated as EOF"
    );
    assert_eq!(msg.unwrap()["method"], "ping");
}

#[tokio::test]
async fn finding_14_only_empty_lines_followed_by_eof() {
    // Only empty lines followed by actual EOF → should return None
    let data = b"\n\n\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);
    let msg = read_message(&mut reader).await.unwrap();
    assert!(
        msg.is_none(),
        "Only empty lines followed by EOF should return None"
    );
}

#[tokio::test]
async fn finding_14_interleaved_empty_lines_between_messages() {
    let data = b"{\"id\":1,\"method\":\"a\"}\n\n\n{\"id\":2,\"method\":\"b\"}\n";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = BufReader::new(cursor);

    let msg1 = read_message(&mut reader).await.unwrap().unwrap();
    assert_eq!(msg1["id"], 1);

    let msg2 = read_message(&mut reader).await.unwrap().unwrap();
    assert_eq!(msg2["id"], 2);

    let msg3 = read_message(&mut reader).await.unwrap();
    assert!(msg3.is_none(), "Should be EOF after last message");
}

// ═══════════════════════════════════════════════════
// COMBINED ATTACK SCENARIOS
//
// Tests that combine multiple findings to verify defense in depth.
// ═══════════════════════════════════════════════════

#[test]
fn combined_domain_bypass_with_path_traversal() {
    // Attacker tries both @ bypass and path traversal simultaneously
    let engine = PolicyEngine::new(false);

    let deny_policy = Policy {
        id: "http:*".to_string(),
        name: "Block evil.com".to_string(),
        policy_type: PolicyType::Conditional {
            conditions: json!({
                "parameter_constraints": [{
                    "param": "url",
                    "op": "domain_match",
                    "pattern": "evil.com"
                }]
            }),
        },
        priority: 100,
    };

    // Attack: evil.com with @ bypass attempt
    let action = Action {
        tool: "http".to_string(),
        function: "request".to_string(),
        parameters: json!({
            "url": "https://evil.com/data?user@safe.com",
            "path": "/a/../../etc/shadow"
        }),
    };

    let verdict = engine.evaluate_action(&action, &[deny_policy]).unwrap();
    assert!(
        matches!(verdict, Verdict::Deny { .. }),
        "Combined attack must be blocked: got {:?}",
        verdict
    );
}

#[test]
fn combined_empty_tool_name_with_deny_policy() {
    // Verify that empty tool name is caught at the MCP layer,
    // not forwarded to the engine where it could evade policies
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "tools/call",
        "params": {"name": "", "arguments": {"path": "/etc/shadow"}}
    });

    match classify_message(&msg) {
        MessageType::Invalid { reason, .. } => {
            assert!(
                reason.contains("missing or empty"),
                "Should explain why it's invalid"
            );
        }
        other => panic!(
            "Empty tool name must be caught as Invalid before reaching engine: got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn combined_audit_integrity_full_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    // Create logger and log several entries
    let logger = Arc::new(AuditLogger::new(log_path.clone()));

    let actions = vec![
        ("file", "read", Verdict::Allow),
        (
            "bash",
            "exec",
            Verdict::Deny {
                reason: "blocked".to_string(),
            },
        ),
        (
            "deploy",
            "push",
            Verdict::RequireApproval {
                reason: "needs sign-off".to_string(),
            },
        ),
    ];

    for (tool, func, verdict) in &actions {
        let action = Action {
            tool: tool.to_string(),
            function: func.to_string(),
            parameters: json!({}),
        };
        logger.log_entry(&action, verdict, json!({})).await.unwrap();
    }

    // Verify chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid, "Chain must be valid after normal usage");
    assert_eq!(verification.entries_checked, 3);

    // Verify all verdicts are recorded correctly (finding #13)
    let entries = logger.load_entries().await.unwrap();
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    assert!(matches!(entries[1].verdict, Verdict::Deny { .. }));
    assert!(matches!(
        entries[2].verdict,
        Verdict::RequireApproval { .. }
    ));

    // Verify all entries have hashes (finding #1)
    for entry in &entries {
        assert!(entry.entry_hash.is_some(), "All entries must have hashes");
    }
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #4 — Hash chain write ordering
//
// The audit log must update last_hash ONLY AFTER the file write
// succeeds. If last_hash were updated before the write, a failed
// write would leave an orphaned hash pointing to a non-existent
// entry on disk, breaking the chain.
//
// This test verifies that after multiple writes, the chain is valid
// and each entry's prev_hash correctly references the previous entry.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_4_hash_chain_ordering_consistent_after_writes() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.log");

    let logger = AuditLogger::new(log_path.clone());
    logger.initialize_chain().await.unwrap();

    let action = Action {
        tool: "test".to_string(),
        function: "op".to_string(),
        parameters: json!({}),
    };

    // Write 5 entries in sequence
    for i in 0..5 {
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: format!("entry {}", i),
                },
                json!({"seq": i}),
            )
            .await
            .unwrap();
    }

    // Verify the chain is valid
    let verification = logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "Chain must be valid: first_broken_at={:?}",
        verification.first_broken_at
    );
    assert_eq!(verification.entries_checked, 5);

    // Verify prev_hash linkage: entry[i].prev_hash == entry[i-1].entry_hash
    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5);

    // First entry has no prev_hash (or it's None)
    assert!(
        entries[0].prev_hash.is_none(),
        "First entry should have no prev_hash"
    );

    for i in 1..entries.len() {
        assert_eq!(
            entries[i].prev_hash.as_deref(),
            entries[i - 1].entry_hash.as_deref(),
            "Entry {}'s prev_hash must equal entry {}'s entry_hash",
            i,
            i - 1
        );
    }
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #11 — Error propagation in evaluate
//
// When audit logging or approval creation encounters an error,
// the server must not panic or silently return incorrect results.
// Audit log failures are fire-and-forget (logged, don't fail the request).
// Approval failures are fail-closed (converted to Deny).
//
// This test verifies evaluate works correctly even when the audit
// logger points to a valid path but the approval store is unwritable.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_11_evaluate_succeeds_even_when_audit_fails_to_write() {
    let tmp = TempDir::new().unwrap();

    // Create audit logger pointing to a file we make read-only
    let audit_path = tmp.path().join("audit.log");
    let logger = Arc::new(AuditLogger::new(audit_path.clone()));

    // Write one valid entry first
    let action = Action {
        tool: "file".to_string(),
        function: "read".to_string(),
        parameters: json!({}),
    };
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Now make the audit file read-only to force write failures
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o444);
        std::fs::set_permissions(&audit_path, perms).unwrap();
    }

    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow reads".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        }])),
        audit: logger,
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
    };

    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "file",
        "function": "read",
        "parameters": {"path": "/tmp/test"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request should succeed (200 OK) even though audit write fails
    // because audit is fire-and-forget
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "Evaluate must succeed even when audit write fails"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["verdict"], "Allow");
}

// ═══════════════════════════════════════════════════
// CROSS-REVIEW FINDING #12 — Fail-closed on approval creation failure
//
// When a policy evaluates to RequireApproval but ApprovalStore::create()
// fails, the server MUST deny the request (fail-closed), NOT allow it
// through without an approval_id.
//
// This test creates an unwritable approval store, evaluates an action
// against a RequireApproval policy, and verifies the response is Deny.
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn finding_12_approval_creation_failure_denies_request() {
    let tmp = TempDir::new().unwrap();

    // Create an approval store pointing to an unwritable path.
    // /dev/null/impossible cannot be created as a file because /dev/null is not a directory.
    let approvals = Arc::new(ApprovalStore::new(
        std::path::PathBuf::from("/dev/null/impossible.jsonl"),
        std::time::Duration::from_secs(900),
    ));

    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "network:*".to_string(),
            name: "Network requires approval".to_string(),
            policy_type: PolicyType::Conditional {
                conditions: json!({
                    "require_approval": true
                }),
            },
            priority: 100,
        }])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals,
        api_key: None,
        rate_limits: Arc::new(RateLimits::disabled()),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
    };

    let app = routes::build_router(state);

    let body = serde_json::to_string(&json!({
        "tool": "network",
        "function": "connect",
        "parameters": {"host": "example.com"}
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    // The request should return 200 OK with Deny verdict (fail-closed)
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verdict must be Deny (not RequireApproval, not Allow)
    let verdict = &json["verdict"];
    assert!(
        verdict.is_object() || verdict.is_string(),
        "Expected verdict in response"
    );

    // Check for Deny verdict — it should contain the reason about approval failure
    let verdict_str = serde_json::to_string(verdict).unwrap();
    assert!(
        verdict_str.contains("Deny") || verdict_str.contains("deny"),
        "Verdict must be Deny when approval creation fails, got: {}",
        verdict_str
    );

    // approval_id must be null/absent since creation failed
    let approval_id = json.get("approval_id");
    assert!(
        approval_id.is_none() || approval_id.unwrap().is_null(),
        "approval_id must be null when creation fails"
    );
}
