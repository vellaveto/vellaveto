//! Adversarial tests for per-IP rate limiting.
//!
//! Findings from adversary instance audit of uncommitted per-IP rate limiter.
//! These tests demonstrate exploitable vulnerabilities in the current implementation.

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
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        }])),
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
    };
    (state, tmp)
}

// =============================================================================
// Finding #18: Per-IP Rate Limit Bypass via X-Forwarded-For Spoofing (HIGH)
//
// The extract_client_ip() function trusts client-provided X-Forwarded-For
// headers. An attacker can bypass per-IP rate limiting entirely by rotating
// the header value on each request. Each request appears to come from a
// unique IP, so each gets a fresh rate limit bucket.
//
// Attack: Send N requests that exceed the per-IP limit, each with a unique
// X-Forwarded-For value. All succeed because each "IP" is a fresh bucket.
// =============================================================================

#[tokio::test]
async fn exploit_18_xff_spoofing_bypasses_per_ip_rate_limit() {
    // Set per-IP limit to 1 request/second — extremely restrictive
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // Send 20 requests rapidly, each with a different spoofed X-Forwarded-For.
    // Without spoofing, only the 1st would succeed (1 req/s limit).
    // With spoofing, ALL succeed — the rate limiter is fully bypassed.
    let mut success_count = 0;

    for i in 0..20u8 {
        let app = routes::build_router(state.clone());
        let spoofed_ip = format!("10.{}.{}.{}", i / 100, (i / 10) % 10, i % 10);
        let resp = app
            .oneshot(
                Request::post("/api/evaluate")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", &spoofed_ip)
                    .body(Body::from(body_str))
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status().is_success() {
            success_count += 1;
        }
    }

    // EXPLOIT DEMONSTRATED: All 20 requests succeed despite 1 req/s limit.
    // A correct implementation would use the actual connection IP, not headers.
    assert_eq!(
        success_count, 20,
        "All 20 requests bypassed rate limiting via X-Forwarded-For spoofing. \
         The per-IP rate limiter trusts client-provided headers, making it trivially bypassable."
    );
}

#[tokio::test]
async fn exploit_18_xff_spoofing_also_works_with_x_real_ip() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    let mut success_count = 0;
    for i in 0..10u8 {
        let app = routes::build_router(state.clone());
        let spoofed_ip = format!("192.168.1.{}", i);
        let resp = app
            .oneshot(
                Request::post("/api/evaluate")
                    .header("content-type", "application/json")
                    .header("x-real-ip", &spoofed_ip)
                    .body(Body::from(body_str))
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status().is_success() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 10,
        "X-Real-IP spoofing also bypasses per-IP rate limiting"
    );
}

// =============================================================================
// Finding #19: Unbounded DashMap Growth / Memory Exhaustion (MEDIUM)
//
// Each unique spoofed IP creates a new entry in the DashMap. There is no
// maximum capacity. Cleanup only runs every 10 minutes (and only removes
// entries >1 hour old). Between cleanups, an attacker can fill memory.
//
// At 10,000 unique IPs: ~1.5MB of rate limiter state
// At 1,000,000 unique IPs: ~150MB of rate limiter state
// At 10,000,000 unique IPs (10min @ 16k req/s): ~1.5GB
//
// The DashMap will never refuse to insert. There is no cap.
// =============================================================================

#[test]
fn exploit_19_unbounded_dashmap_growth() {
    let limiter = PerIpRateLimiter::new(std::num::NonZeroU32::new(10).unwrap());

    // Simulate an attacker sending requests with 10,000 unique IPs.
    // Every single one creates a new entry.
    for i in 0..10_000u32 {
        let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167772160)).into(); // 10.x.x.x
        let _ = limiter.check(ip);
    }

    // All 10,000 entries are stored — no cap, no eviction.
    assert_eq!(
        limiter.len(),
        10_000,
        "DashMap grew unbounded to 10,000 entries with no capacity limit. \
         An attacker can exhaust memory by sending requests with unique spoofed IPs."
    );

    // Cleanup only removes entries older than the max_age threshold.
    // Since we just created all entries, cleanup with 1-hour threshold removes nothing.
    limiter.cleanup(std::time::Duration::from_secs(3600));
    assert_eq!(
        limiter.len(),
        10_000,
        "Cleanup with 1-hour threshold doesn't help — all entries are fresh"
    );
}

// =============================================================================
// Finding #20: Localhost Rate Limit Collapse (LOW)
//
// When no proxy headers are present, extract_client_ip() falls back to
// 127.0.0.1 for ALL clients. This means:
//
// - All clients without proxy headers share ONE rate limit bucket
// - One client's requests consume quota for ALL other direct clients
// - Per-IP rate limiting degrades to a GLOBAL rate limiter for direct connections
//
// This affects deployments where sentinel-server is exposed directly
// (not behind a reverse proxy), which is supported via --bind.
// =============================================================================

#[tokio::test]
async fn exploit_20_all_direct_clients_share_one_bucket() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request with NO proxy headers — succeeds, attributed to 127.0.0.1
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

    // Second request with NO proxy headers — throttled because it shares
    // the same 127.0.0.1 bucket, even though it could be a different client.
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
        "Second direct request is throttled — all headerless clients collapse to 127.0.0.1. \
         A different real client making a legitimate request would be denied."
    );
}

// =============================================================================
// Finding #21: IP Impersonation / Rate Limit Exhaustion Attack (HIGH)
//
// An attacker can consume another user's rate limit quota by setting
// X-Forwarded-For to the victim's IP. The victim's subsequent requests
// are then throttled.
//
// This is a denial-of-service against specific IPs.
// =============================================================================

#[tokio::test]
async fn exploit_21_attacker_exhausts_victim_rate_limit() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    let victim_ip = "203.0.113.42"; // The victim's real IP

    // ATTACKER: sends request with X-Forwarded-For set to victim's IP.
    // This consumes the victim's rate limit bucket.
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
    assert!(
        resp.status().is_success(),
        "Attacker's request succeeds using victim's IP"
    );

    // VICTIM: makes a legitimate request. Gets 429 because their
    // bucket was already consumed by the attacker.
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
        "Victim is rate-limited because the attacker consumed their bucket. \
         This is a targeted DoS attack against specific users."
    );
}

// =============================================================================
// Finding #22: Verify Command Exits 0 on Duplicate IDs (LOW)
//
// The `sentinel verify` command reports duplicate entry IDs as a warning
// but exits with code 0 ("VERIFIED (with warnings)"). Automated monitoring
// and CI/CD pipelines checking exit codes will miss replay attacks.
//
// Duplicate IDs indicate either:
// - Replay attack (entries copied from one log to another)
// - UUID collision (code bug)
// - Log corruption
//
// None of these should pass verification silently.
//
// (This finding requires a CLI test — see test_cli_verify or inline below.)
// =============================================================================

// Note: The duplicate ID finding is verified structurally by reading the
// cmd_verify code. The `has_duplicates` flag affects the display message
// but NOT the exit code. The process returns 0 when `all_valid` is true,
// regardless of duplicates. This cannot be tested without a process spawn
// or refactoring the verify command into a testable function.

// =============================================================================
// Finding #23: X-Forwarded-For Injection via Comma (LOW)
//
// An attacker can inject additional IPs into the X-Forwarded-For header.
// The code takes the FIRST comma-separated value, but a real proxy APPENDS
// the real client IP to the END of the chain. If an attacker sends:
//
//   X-Forwarded-For: 1.2.3.4, attacker-real-ip
//
// The code uses 1.2.3.4 (attacker-chosen), not attacker-real-ip (real).
// This is the classic XFF rightmost-proxy problem.
// =============================================================================

#[tokio::test]
async fn exploit_23_xff_leftmost_ip_is_attacker_controlled() {
    let (state, _tmp) = per_ip_state(1);
    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // Attacker sends request with crafted XFF chain.
    // The real proxy will append the attacker's actual IP at the end,
    // but the code takes the FIRST value — which the attacker controls.
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

    // The code used 1.2.3.4 (attacker-controlled first entry), not 10.0.0.1
    // Attacker now sends with a different first entry to bypass rate limiting
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
    assert!(
        resp.status().is_success(),
        "Attacker bypasses rate limit by changing the leftmost XFF entry. \
         The real client IP (10.0.0.1, appended by proxy) is ignored."
    );
}

// =============================================================================
// Finding #24: Error Response Leaks Rate Limit Architecture (LOW)
//
// The 429 error response from per-IP rate limiting says:
//   "Per-IP rate limit exceeded"
// while the global rate limiter says:
//   "Rate limit exceeded"
//
// This tells an attacker which layer they hit, helping them calibrate
// their evasion strategy (spoof IPs for per-IP, vs. throttle for global).
// =============================================================================

#[tokio::test]
async fn exploit_24_error_response_distinguishes_rate_limit_type() {
    let tmp = TempDir::new().unwrap();
    let state = AppState {
        engine: Arc::new(ArcSwap::from_pointee(PolicyEngine::new(false))),
        policies: Arc::new(ArcSwap::from_pointee(vec![Policy {
            id: "file:read".to_string(),
            name: "Allow".to_string(),
            policy_type: PolicyType::Allow,
            priority: 10,
        }])),
        audit: Arc::new(AuditLogger::new(tmp.path().join("audit.log"))),
        config_path: Arc::new("test.toml".to_string()),
        approvals: Arc::new(ApprovalStore::new(
            tmp.path().join("approvals.jsonl"),
            std::time::Duration::from_secs(900),
        )),
        api_key: None,
        rate_limits: Arc::new(
            RateLimits::new(Some(100), None, None) // high global limit
                .with_per_ip(std::num::NonZeroU32::new(1).unwrap()), // strict per-IP
        ),
        cors_origins: vec![],
        metrics: Arc::new(Metrics::default()),
    };

    let body_str = r#"{"tool":"file","function":"read","parameters":{}}"#;

    // First request succeeds
    let app = routes::build_router(state.clone());
    let _ = app
        .oneshot(
            Request::post("/api/evaluate")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.1")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    // Second request triggers per-IP rate limit
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

    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let error_msg = body_json["error"].as_str().unwrap();

    // The error message reveals which rate limiter triggered.
    // An attacker can use this to determine: "I need to spoof XFF to bypass"
    assert!(
        error_msg.contains("Per-IP"),
        "Error message '{}' reveals it was the per-IP rate limiter, \
         giving the attacker information to calibrate their evasion strategy",
        error_msg
    );
}
