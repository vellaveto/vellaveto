//! Security regression tests for per-IP rate limiting.
//!
//! Originally written as adversary exploit demonstrations (Phase 6).
//! Now converted to regression tests that verify the fixes remain in place.
//!
//! Findings addressed:
//! - #18 (HIGH): XFF spoofing bypass → Fixed: proxy headers ignored without trusted_proxies
//! - #19 (MEDIUM): Unbounded DashMap → Fixed: max_capacity with fail-closed
//! - #20 (LOW): Localhost collapse → Fixed: ConnectInfo used instead of header fallback
//! - #21 (HIGH): IP impersonation → Fixed: proxy headers ignored without trusted_proxies
//! - #22 (LOW): Verify exits 0 on duplicates → Fixed: exit code 2 on duplicate IDs
//! - #23 (LOW): XFF leftmost attacker-controlled → Fixed: rightmost-untrusted with trusted_proxies
//! - #24 (LOW): Error leaks rate limit type → Fixed: unified error message

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sentinel_approval::ApprovalStore;
use sentinel_audit::AuditLogger;
use sentinel_engine::PolicyEngine;
use sentinel_server::{routes, AppState, Metrics, PerIpRateLimiter, RateLimits};
use sentinel_types::{Policy, PolicyType};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

fn per_ip_state(rps: u32) -> (AppState, TempDir) {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(sentinel_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
        })),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(
            RateLimits::new(None, None, None).with_per_ip(std::num::NonZeroU32::new(rps).unwrap()),
        ),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
    };
    (state, tmp)
}

// =============================================================================
// Finding #18 FIXED: XFF spoofing no longer bypasses rate limiting.
//
// With trusted_proxies empty (default), proxy headers are ignored entirely.
// All requests are attributed to the connection IP (127.0.0.1 in tests),
// so spoofing X-Forwarded-For has no effect on rate limiting.
// =============================================================================

#[tokio::test]
async fn regression_18_xff_spoofing_blocked_without_trusted_proxies() {
    // Per-IP limit of 1 req/s, no trusted proxies
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds (new bucket for connection IP)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First request should succeed");

    // Second request with DIFFERENT spoofed XFF — still rate-limited because
    // without trusted_proxies, the XFF header is ignored. Both requests use
    // the same connection IP (127.0.0.1).
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.2")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "XFF spoofing must not bypass rate limiting when trusted_proxies is empty"
    );
}

#[tokio::test]
async fn regression_18_xri_spoofing_blocked_without_trusted_proxies() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-real-ip", "192.168.1.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Second request with different X-Real-IP — still rate-limited
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-real-ip", "192.168.1.2")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "X-Real-IP spoofing must not bypass rate limiting when trusted_proxies is empty"
    );
}

// =============================================================================
// Finding #19 FIXED: DashMap growth is bounded by max_capacity.
//
// When the limiter reaches max_capacity, new IPs are denied (fail-closed)
// instead of creating unbounded entries.
// =============================================================================

#[test]
fn regression_19_dashmap_growth_bounded() {
    // Create limiter with a small max capacity for testing
    let limiter = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 100);

    // Fill to capacity
    for i in 0..100u32 {
        let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167772160)).into();
        let _ = limiter.check(ip);
    }
    assert_eq!(limiter.len(), 100, "Should have 100 entries at capacity");

    // Attempt to add more — should be denied, not inserted
    let new_ip: std::net::IpAddr = std::net::Ipv4Addr::from(200_000_000u32).into();
    let result = limiter.check(new_ip);
    assert!(
        result.is_some(),
        "New IPs must be denied when at max capacity (fail-closed)"
    );
    assert_eq!(
        limiter.len(),
        100,
        "No new entries should be inserted when at max capacity"
    );

    // Existing IPs still work (not locked out)
    let existing_ip: std::net::IpAddr = std::net::Ipv4Addr::from(167772160u32).into();
    let result = limiter.check(existing_ip);
    assert!(
        result.is_none(),
        "Existing IPs should still be allowed when at capacity"
    );
}

#[test]
fn regression_19_cleanup_frees_capacity() {
    let limiter = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 50);

    // Fill to capacity
    for i in 0..50u32 {
        let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167772160)).into();
        let _ = limiter.check(ip);
    }
    assert_eq!(limiter.len(), 50);

    // Cleanup with 0 duration removes all entries
    limiter.cleanup(std::time::Duration::from_secs(0));
    assert_eq!(limiter.len(), 0, "Cleanup should free all entries");

    // New IPs can now be admitted
    let new_ip: std::net::IpAddr = std::net::Ipv4Addr::from(200_000_000u32).into();
    let result = limiter.check(new_ip);
    assert!(
        result.is_none(),
        "New IPs should be allowed after cleanup frees capacity"
    );
}

// =============================================================================
// Finding #20 FIXED: Without proxy headers, connection IP is used.
//
// In test environments without real TCP connections, ConnectInfo isn't set
// so the fallback is 127.0.0.1. This is correct behavior — all test
// requests from the same process share one bucket, as they should.
// In production with real connections, each TCP connection has its own IP.
// =============================================================================

#[tokio::test]
async fn regression_20_direct_clients_use_connection_ip() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds — uses connection IP (127.0.0.1 in test)
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First direct request succeeds");

    // Second request is properly rate-limited on the same connection IP.
    // This is correct behavior — in production, different clients have
    // different connection IPs via ConnectInfo<SocketAddr>.
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Second request from same connection IP is properly rate-limited"
    );
}

// =============================================================================
// Finding #21 FIXED: IP impersonation blocked.
//
// Without trusted_proxies, X-Forwarded-For is ignored. An attacker cannot
// consume another user's rate limit bucket by spoofing their IP.
// =============================================================================

#[tokio::test]
async fn regression_21_ip_impersonation_blocked() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    let victim_ip = "203.0.113.42";

    // Attacker tries to impersonate victim via X-Forwarded-For
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", victim_ip)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "First request succeeds");

    // Attacker's second request is rate-limited on THEIR connection IP (127.0.0.1),
    // not on the victim's IP. The spoofed header is ignored.
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", victim_ip)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Attacker is rate-limited on their own connection IP, not the victim's"
    );
}

// =============================================================================
// Finding #23 FIXED: XFF leftmost entry is ignored without trusted_proxies.
//
// With the empty trusted_proxies default, ALL proxy headers are ignored.
// When trusted_proxies is configured, the rightmost untrusted entry is used.
// =============================================================================

#[tokio::test]
async fn regression_23_xff_ignored_without_trusted_proxies() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request with crafted XFF chain — succeeds
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "1.2.3.4, 10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Second request with DIFFERENT leftmost XFF entry — still rate-limited
    // because XFF is completely ignored without trusted_proxies
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "5.6.7.8, 10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Changing leftmost XFF entry must not bypass rate limiting"
    );
}

// =============================================================================
// Finding #24 FIXED: Error responses use the same generic message.
//
// Both per-IP and global rate limit responses now say:
//   "Rate limit exceeded. Try again later."
// No architectural details are leaked.
// =============================================================================

#[tokio::test]
async fn regression_24_error_message_does_not_leak_architecture() {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(sentinel_server::PolicySnapshot {
            engine: PolicyEngine::new(false),
            policies: vec![Policy {
                id: "file:read".to_string(),
                name: "Allow".to_string(),
                policy_type: PolicyType::Allow,
                priority: 10,
                path_rules: None,
                network_rules: None,
            }],
        })),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(
            RateLimits::new(Some(100), None, None)
                .with_per_ip(std::num::NonZeroU32::new(1).unwrap()),
        ),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
        trusted_proxies: Arc::new(vec![]),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle: None,
        tool_registry: None,
    };

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds
    let app = routes::build_router(state.clone());
    let _ = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    // Second request triggers rate limit
    let app = routes::build_router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error_msg = body_json["error"].as_str().unwrap();

    // Must NOT contain "Per-IP" or any architecture-revealing text
    assert!(
        !error_msg.contains("Per-IP") && !error_msg.contains("per-ip"),
        "Error message '{}' must not reveal which rate limiter triggered",
        error_msg
    );
    assert_eq!(
        error_msg, "Rate limit exceeded. Try again later.",
        "Error message should be generic"
    );
}

// =============================================================================
// Additional regression: max_capacity accessor works correctly
// =============================================================================

#[test]
fn regression_max_capacity_accessor() {
    let limiter = PerIpRateLimiter::new(std::num::NonZeroU32::new(10).unwrap());
    assert_eq!(
        limiter.max_capacity(),
        sentinel_server::DEFAULT_MAX_IP_CAPACITY
    );

    let custom = PerIpRateLimiter::with_max_capacity(std::num::NonZeroU32::new(10).unwrap(), 500);
    assert_eq!(custom.max_capacity(), 500);
}
