//! Benchmarks for the HTTP proxy hot path: origin validation, call chain HMAC,
//! evaluation context building, and privilege escalation detection.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::net::SocketAddr;

use axum::http::HeaderMap;
use vellaveto_http_proxy::proxy::call_chain;
use vellaveto_http_proxy::proxy::origin;

// ---------- Origin Validation ----------

fn bench_origin(c: &mut Criterion) {
    let mut group = c.benchmark_group("origin");

    // is_loopback_addr — micro-benchmark baseline
    let loopback_v4: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    let loopback_v6: SocketAddr = "[::1]:3000".parse().unwrap();
    let non_loopback: SocketAddr = "10.0.0.1:3000".parse().unwrap();

    group.bench_function("is_loopback_v4", |b| {
        b.iter(|| origin::is_loopback_addr(black_box(&loopback_v4)))
    });
    group.bench_function("is_loopback_v6", |b| {
        b.iter(|| origin::is_loopback_addr(black_box(&loopback_v6)))
    });
    group.bench_function("is_loopback_non", |b| {
        b.iter(|| origin::is_loopback_addr(black_box(&non_loopback)))
    });

    // build_loopback_origins
    group.bench_function("build_loopback_origins", |b| {
        b.iter(|| origin::build_loopback_origins(black_box(3000)))
    });

    // extract_authority_from_origin
    group.bench_function("extract_authority_simple", |b| {
        b.iter(|| origin::extract_authority_from_origin(black_box("http://localhost:3000")))
    });
    group.bench_function("extract_authority_https", |b| {
        b.iter(|| origin::extract_authority_from_origin(black_box("https://example.com")))
    });
    group.bench_function("extract_authority_ipv6", |b| {
        b.iter(|| origin::extract_authority_from_origin(black_box("http://[::1]:3000")))
    });
    group.bench_function("extract_authority_with_path", |b| {
        b.iter(|| {
            origin::extract_authority_from_origin(black_box(
                "https://example.com/path?query=1#frag",
            ))
        })
    });
    group.bench_function("extract_authority_with_userinfo", |b| {
        b.iter(|| origin::extract_authority_from_origin(black_box("http://user@example.com:8080")))
    });

    // validate_origin — full CSRF/DNS-rebinding check
    let bind_loopback: SocketAddr = "127.0.0.1:3000".parse().unwrap();

    // No Origin header (common fast path for API clients)
    let empty_headers = HeaderMap::new();
    group.bench_function("validate_no_origin", |b| {
        b.iter(|| {
            origin::validate_origin(
                black_box(&empty_headers),
                black_box(&bind_loopback),
                black_box(&[]),
            )
        })
    });

    // Loopback with matching localhost origin
    let mut loopback_headers = HeaderMap::new();
    loopback_headers.insert("origin", "http://localhost:3000".parse().unwrap());
    group.bench_function("validate_loopback_match", |b| {
        b.iter(|| {
            origin::validate_origin(
                black_box(&loopback_headers),
                black_box(&bind_loopback),
                black_box(&[]),
            )
        })
    });

    // Explicit allowlist with matching origin
    let allowed = vec!["http://app.example.com".to_string()];
    let mut allowed_headers = HeaderMap::new();
    allowed_headers.insert("origin", "http://app.example.com".parse().unwrap());
    group.bench_function("validate_allowlist_match", |b| {
        b.iter(|| {
            origin::validate_origin(
                black_box(&allowed_headers),
                black_box(&bind_loopback),
                black_box(&allowed),
            )
        })
    });

    // DNS rebinding attack — loopback bind with non-localhost origin
    let mut evil_headers = HeaderMap::new();
    evil_headers.insert("origin", "http://evil.com".parse().unwrap());
    group.bench_function("validate_rebinding_reject", |b| {
        b.iter(|| {
            let _ = origin::validate_origin(
                black_box(&evil_headers),
                black_box(&bind_loopback),
                black_box(&[]),
            );
        })
    });

    group.finish();
}

// ---------- Call Chain HMAC ----------

fn bench_call_chain_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("call_chain_hmac");

    let key: [u8; 32] = [0x42u8; 32];

    // call_chain_entry_signing_content
    let entry = vellaveto_types::CallChainEntry {
        agent_id: "agent-alpha".to_string(),
        tool: "read_file".to_string(),
        function: "read".to_string(),
        timestamp: "2026-02-14T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    };
    group.bench_function("signing_content", |b| {
        b.iter(|| call_chain::call_chain_entry_signing_content(black_box(&entry)))
    });

    // compute_call_chain_hmac — small payload
    let small_data = call_chain::call_chain_entry_signing_content(&entry);
    group.bench_function("compute_hmac_small", |b| {
        b.iter(|| call_chain::compute_call_chain_hmac(black_box(&key), black_box(&small_data)))
    });

    // compute_call_chain_hmac — large payload (multi-hop chain)
    let large_data = vec![0u8; 4096];
    group.bench_function("compute_hmac_4kb", |b| {
        b.iter(|| call_chain::compute_call_chain_hmac(black_box(&key), black_box(&large_data)))
    });

    // verify_call_chain_hmac — valid
    let valid_hmac = call_chain::compute_call_chain_hmac(&key, &small_data).unwrap();
    group.bench_function("verify_hmac_valid", |b| {
        b.iter(|| {
            call_chain::verify_call_chain_hmac(
                black_box(&key),
                black_box(&small_data),
                black_box(&valid_hmac),
            )
        })
    });

    // verify_call_chain_hmac — invalid (tampered data)
    let tampered_data = vec![0xFFu8; small_data.len()];
    group.bench_function("verify_hmac_invalid", |b| {
        b.iter(|| {
            call_chain::verify_call_chain_hmac(
                black_box(&key),
                black_box(&tampered_data),
                black_box(&valid_hmac),
            )
        })
    });

    // build_current_agent_entry — without HMAC
    group.bench_function("build_entry_no_hmac", |b| {
        b.iter(|| {
            call_chain::build_current_agent_entry(
                black_box(Some("agent-1")),
                black_box("read_file"),
                black_box("read"),
                black_box(None),
            )
        })
    });

    // build_current_agent_entry — with HMAC signing
    group.bench_function("build_entry_with_hmac", |b| {
        b.iter(|| {
            call_chain::build_current_agent_entry(
                black_box(Some("agent-1")),
                black_box("read_file"),
                black_box("read"),
                black_box(Some(&key)),
            )
        })
    });

    group.finish();
}

// ---------- Call Chain Header Parsing ----------

fn bench_call_chain_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("call_chain_parsing");

    let limits = vellaveto_config::LimitsConfig::default();

    // jsonrpc_id_key — string id
    let string_id = serde_json::json!("req-12345");
    group.bench_function("id_key_string", |b| {
        b.iter(|| call_chain::jsonrpc_id_key(black_box(&string_id)))
    });

    // jsonrpc_id_key — number id
    let number_id = serde_json::json!(42);
    group.bench_function("id_key_number", |b| {
        b.iter(|| call_chain::jsonrpc_id_key(black_box(&number_id)))
    });

    // validate_call_chain_header — no header (fast path)
    let empty_headers = HeaderMap::new();
    group.bench_function("validate_header_absent", |b| {
        b.iter(|| {
            call_chain::validate_call_chain_header(black_box(&empty_headers), black_box(&limits))
        })
    });

    // validate_call_chain_header — single entry
    let single_entry = serde_json::to_string(&vec![vellaveto_types::CallChainEntry {
        agent_id: "agent-1".to_string(),
        tool: "read_file".to_string(),
        function: "read".to_string(),
        timestamp: "2026-02-14T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    }])
    .unwrap();
    let mut single_headers = HeaderMap::new();
    single_headers.insert("x-upstream-agents", single_entry.parse().unwrap());
    group.bench_function("validate_header_1_entry", |b| {
        b.iter(|| {
            call_chain::validate_call_chain_header(black_box(&single_headers), black_box(&limits))
        })
    });

    // validate_call_chain_header — 5 entries (multi-hop)
    let five_entries: Vec<vellaveto_types::CallChainEntry> = (0..5)
        .map(|i| vellaveto_types::CallChainEntry {
            agent_id: format!("agent-{i}"),
            tool: "tool".to_string(),
            function: "fn".to_string(),
            timestamp: "2026-02-14T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect();
    let five_str = serde_json::to_string(&five_entries).unwrap();
    let mut five_headers = HeaderMap::new();
    five_headers.insert("x-upstream-agents", five_str.parse().unwrap());
    group.bench_function("validate_header_5_entries", |b| {
        b.iter(|| {
            call_chain::validate_call_chain_header(black_box(&five_headers), black_box(&limits))
        })
    });

    // extract_call_chain_from_headers — no header
    group.bench_function("extract_chain_absent", |b| {
        b.iter(|| {
            call_chain::extract_call_chain_from_headers(
                black_box(&empty_headers),
                black_box(None),
                black_box(&limits),
            )
        })
    });

    // extract_call_chain_from_headers — 1 entry, no HMAC
    group.bench_function("extract_chain_1_no_hmac", |b| {
        b.iter(|| {
            call_chain::extract_call_chain_from_headers(
                black_box(&single_headers),
                black_box(None),
                black_box(&limits),
            )
        })
    });

    // extract_call_chain_from_headers — 5 entries, no HMAC
    group.bench_function("extract_chain_5_no_hmac", |b| {
        b.iter(|| {
            call_chain::extract_call_chain_from_headers(
                black_box(&five_headers),
                black_box(None),
                black_box(&limits),
            )
        })
    });

    // extract_call_chain_from_headers — 1 entry, with HMAC verification
    let key: [u8; 32] = [0x42u8; 32];
    let signed_entry =
        call_chain::build_current_agent_entry(Some("agent-1"), "read_file", "read", Some(&key));
    let signed_str = serde_json::to_string(&vec![signed_entry]).unwrap();
    let mut signed_headers = HeaderMap::new();
    signed_headers.insert("x-upstream-agents", signed_str.parse().unwrap());
    group.bench_function("extract_chain_1_with_hmac", |b| {
        b.iter(|| {
            call_chain::extract_call_chain_from_headers(
                black_box(&signed_headers),
                black_box(Some(&key)),
                black_box(&limits),
            )
        })
    });

    group.finish();
}

// ---------- Privilege Escalation Detection ----------

fn bench_privilege_escalation(c: &mut Criterion) {
    use vellaveto_engine::PolicyEngine;
    use vellaveto_types::{Action, Policy};

    let mut group = c.benchmark_group("privilege_escalation");

    // Build a simple policy engine
    let engine = PolicyEngine::new(false);
    let policies: Vec<Policy> = vec![
        serde_json::from_value(serde_json::json!({
            "id": "deny-exec",
            "name": "deny-exec",
            "policy_type": "Deny",
            "priority": 100,
            "tool_patterns": ["exec*"],
            "conditions": [{"agent_identity_match": {"agent_id_pattern": "restricted-*"}}]
        }))
        .unwrap(),
        serde_json::from_value(serde_json::json!({
            "id": "allow-all",
            "name": "allow-all",
            "policy_type": "Allow",
            "priority": 1,
            "tool_patterns": ["*"]
        }))
        .unwrap(),
    ];

    let action = Action {
        tool: "exec_command".to_string(),
        function: "shell".to_string(),
        parameters: Default::default(),
        target_paths: vec![],
        target_domains: vec![],
        resolved_ips: vec![],
    };

    // No call chain — fast path
    group.bench_function("no_chain", |b| {
        b.iter(|| {
            call_chain::check_privilege_escalation(
                black_box(&engine),
                black_box(&policies),
                black_box(&action),
                black_box(&[]),
                black_box(Some("current-agent")),
            )
        })
    });

    // 1-hop call chain
    let chain_1 = vec![vellaveto_types::CallChainEntry {
        agent_id: "restricted-agent".to_string(),
        tool: "exec_command".to_string(),
        function: "shell".to_string(),
        timestamp: "2026-02-14T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    }];
    group.bench_function("1_hop_chain", |b| {
        b.iter(|| {
            call_chain::check_privilege_escalation(
                black_box(&engine),
                black_box(&policies),
                black_box(&action),
                black_box(&chain_1),
                black_box(Some("current-agent")),
            )
        })
    });

    // 5-hop call chain — measures scaling
    let chain_5: Vec<vellaveto_types::CallChainEntry> = (0..5)
        .map(|i| vellaveto_types::CallChainEntry {
            agent_id: format!("agent-{i}"),
            tool: "exec_command".to_string(),
            function: "shell".to_string(),
            timestamp: "2026-02-14T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect();
    group.bench_function("5_hop_chain", |b| {
        b.iter(|| {
            call_chain::check_privilege_escalation(
                black_box(&engine),
                black_box(&policies),
                black_box(&action),
                black_box(&chain_5),
                black_box(Some("current-agent")),
            )
        })
    });

    // 10-hop call chain
    let chain_10: Vec<vellaveto_types::CallChainEntry> = (0..10)
        .map(|i| vellaveto_types::CallChainEntry {
            agent_id: format!("agent-{i}"),
            tool: "exec_command".to_string(),
            function: "shell".to_string(),
            timestamp: "2026-02-14T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect();
    group.bench_function("10_hop_chain", |b| {
        b.iter(|| {
            call_chain::check_privilege_escalation(
                black_box(&engine),
                black_box(&policies),
                black_box(&action),
                black_box(&chain_10),
                black_box(Some("current-agent")),
            )
        })
    });

    group.finish();
}

// ---------- Audit Context Building ----------

fn bench_audit_context(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_context");

    use vellaveto_http_proxy::proxy::call_chain::{
        build_audit_context, build_audit_context_with_chain,
    };

    // build_audit_context — minimal
    group.bench_function("build_minimal", |b| {
        b.iter(|| {
            build_audit_context(
                black_box("sess-1234"),
                black_box(serde_json::json!({})),
                black_box(&None),
            )
        })
    });

    // build_audit_context — with OAuth claims
    let claims: vellaveto_http_proxy::oauth::OAuthClaims =
        serde_json::from_value(serde_json::json!({
            "sub": "user@example.com",
            "scope": "tool:read tool:write",
            "exp": 9999999999u64
        }))
        .unwrap();
    group.bench_function("build_with_oauth", |b| {
        b.iter(|| {
            build_audit_context(
                black_box("sess-1234"),
                black_box(serde_json::json!({"method": "tools/call"})),
                black_box(&Some(claims.clone())),
            )
        })
    });

    // build_audit_context_with_chain — 3-hop chain
    let chain: Vec<vellaveto_types::CallChainEntry> = (0..3)
        .map(|i| vellaveto_types::CallChainEntry {
            agent_id: format!("agent-{i}"),
            tool: "tool".to_string(),
            function: "fn".to_string(),
            timestamp: "2026-02-14T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        })
        .collect();
    group.bench_function("build_with_chain_3_hops", |b| {
        b.iter(|| {
            build_audit_context_with_chain(
                black_box("sess-1234"),
                black_box(serde_json::json!({})),
                black_box(&Some(claims.clone())),
                black_box(&chain),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_origin,
    bench_call_chain_hmac,
    bench_call_chain_parsing,
    bench_privilege_escalation,
    bench_audit_context,
);
criterion_main!(benches);
