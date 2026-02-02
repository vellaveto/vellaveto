# Tasks for Instance A — Directive C-9 (Production Hardening)

## READ THIS FIRST

Controller Directive C-9 is active. All C-8 work is complete. Focus on security headers (quick win), then rate limit polish, then OWASP test completion, then benchmarks.

Update `.collab/instance-a.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (all previous directives)
- CI workflow, integration tests, approval flow tests
- S-A1 (auth), S-A2 (bind address), security regression tests (32)
- C7-A1: Rate limiting (#31), proptest (8 property tests), ArcSwap migration fixes
- C8-A1: OWASP MCP Top 10 test coverage (39 tests)

---

## Task C9-A1: API Security Headers Middleware
**Priority: HIGH — Quick win, outsized value**
**Directive:** C-9.1
**Reference:** `controller/research/rate-limiting-cors-headers.md` §4

Add standard security response headers to all API responses. This is expected of any security-critical API server.

**Implementation:**
1. In `sentinel-server/src/routes.rs`, add an async middleware function:

```rust
async fn security_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    if path == "/health" {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=5"));
    } else {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    headers.remove("server");
    response
}
```

2. Apply in `build_router()` via `.layer(middleware::from_fn(security_headers))`
3. Add tests verifying headers are present on responses

---

## Task C9-A2: Rate Limit Polish
**Priority: HIGH**
**Directive:** C-9.1

1. **Exempt `/health` from rate limiting:** In the `categorize_rate_limit` function, return `None` for `/health` path (load balancer probes must never be throttled)
2. **Add `Retry-After` header to 429 responses:** When `limiter.check()` returns `Err(not_until)`, extract wait time and set `Retry-After: <seconds>` header
3. **Add `max_age` to CORS:** Add `.max_age(Duration::from_secs(3600))` to the CORS layer to cache preflight for 1 hour

---

## Task C9-A3: Complete OWASP Placeholder Tests
**Priority: MEDIUM — Now unblocked by C-8.2/C-8.3 completion**
**Directive:** C-9.4

Instance B has completed tool annotation awareness (C8-B1) and response inspection (C8-B2). Replace the placeholder tests:

**MCP03 (Tool Poisoning):**
- Replace placeholder with real test exercising rug-pull detection
- Test that `ToolAnnotations` are extracted from `tools/list` responses
- Test that tool definition changes between calls trigger warning
- Test that annotations are logged in audit metadata

**MCP06 (Prompt Injection):**
- Replace placeholder with real test exercising response injection scanning
- Test that `inspect_response_for_injection()` detects known patterns
- Test that clean responses pass through without warnings
- Test audit logging of suspicious responses

**File:** `sentinel-integration/tests/owasp_mcp_top10.rs`
**Reference:** Instance B's tests in `sentinel-mcp/src/proxy.rs` (60+ tests total)

---

## Task C9-A4: Criterion Benchmarks (Phase 7.2)
**Priority: MEDIUM**
**Directive:** C-9.1

Create performance benchmarks to validate <5ms evaluation latency target.

1. Add `criterion = "0.5"` as dev-dependency to `sentinel-engine/Cargo.toml`
2. Create `sentinel-engine/benches/evaluation.rs`:
   - Benchmark single policy evaluation (1 policy, exact match)
   - Benchmark 100-policy evaluation (mixed allow/deny, wildcards)
   - Benchmark 1000-policy evaluation (stress test)
   - Benchmark `normalize_path()` with various inputs
   - Benchmark `extract_domain()` with various URLs
   - Benchmark regex constraint matching
3. Add `[[bench]]` section to Cargo.toml

---

## Work Order
1. C9-A1 (security headers) — do first, highest value/effort ratio
2. C9-A2 (rate limit polish) — do second, pairs naturally with C9-A1
3. C9-A3 (OWASP placeholders) — do third, unblocked by C-8 completion
4. C9-A4 (benchmarks) — do last, important but less urgent

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `.github/`, `sentinel-integration/tests/`, `sentinel-server/src/routes.rs` (security headers only — coordinate with Instance B if touching engine)
