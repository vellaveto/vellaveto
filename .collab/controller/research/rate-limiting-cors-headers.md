# Rate Limiting, CORS, and API Security Headers for Sentinel

**Date:** 2026-02-02
**Author:** Controller Instance (Research Agent a7a4cb8)
**Sources:** governor crate docs, tower-http docs, Axum examples, OWASP API Security

---

## 1. Rate Limiting Crate Comparison

### Governor (Current — Recommended)

Sentinel already uses `governor` v0.6 directly. It implements GCRA (Generic Cell Rate Algorithm):
- Smooth, jitter-free rate limiting (no burst-at-window-boundary)
- Lock-free via `AtomicU64` — zero contention in hot path
- Minimal memory (a few bytes per limiter instance)

Current usage in `sentinel-server/src/lib.rs` uses `DefaultDirectRateLimiter` (global, not per-IP).

### tower-governor

Tower middleware wrapper around `governor`:
- Built-in per-IP via `PeerIpKeyExtractor`
- Standard `429 Too Many Requests` response generation
- `Retry-After` header support

**When to use:** When primary dimension is per-IP rate limiting.

### tower::limit::RateLimit

- Simple fixed-window limiting from the tower crate
- No per-key support, no GCRA, no burst config
- Only suitable for simple global concurrency limiting

### Recommendation

| Crate | Per-IP | Per-Category | Algorithm | Burst Config | Recommendation |
|-------|--------|-------------|-----------|-------------|----------------|
| `governor` (direct) | Manual | Yes (current) | GCRA | Yes | **Keep for per-category** |
| `tower-governor` | Built-in | Manual | GCRA | Yes | **Add for per-IP** |
| `tower::limit` | No | No | Fixed window | No | **Concurrency only** |

---

## 2. Per-Endpoint Rate Limiting

### Current Implementation Assessment

The categorize function in `sentinel-server/src/routes.rs` lines 445-481 is well-designed, mapping (method, path) to rate limiter categories.

### Recommended Configuration Values

| Category | Endpoints | RPS | Burst | Rationale |
|----------|-----------|-----|-------|-----------|
| `evaluate` | `POST /api/evaluate` | 500-1000/s | 50 | Hot path, agents send bursts |
| `admin` | `POST /api/policies`, `DELETE`, approvals | 10-20/s | 5 | Mutating, infrequent |
| `readonly` | `GET /health`, policies, audit, approvals | 100-200/s | 20 | Monitoring/dashboards |
| `health` | `GET /health` | Unlimited | N/A | Load balancer probes must never be throttled |

### Improvement: Exempt Health from Rate Limiting

```rust
fn categorize_rate_limit<'a>(...) -> Option<&'a governor::DefaultDirectRateLimiter> {
    if path == "/health" { return None; }
    // ... existing logic
}
```

### Improvement: Burst Configuration

```rust
// Instead of: Quota::per_second(r)
// Use: Quota::per_second(r).allow_burst(NonZeroU32::new(burst_size).unwrap_or(r))
```

### Improvement: Retry-After Header

```rust
if let Err(not_until) = limiter.check() {
    let wait = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
    let retry_after = wait.as_secs().max(1);
    return (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after.to_string())],
        Json(json!({"error": "Rate limit exceeded", "retry_after_seconds": retry_after})),
    ).into_response();
}
```

---

## 3. CORS Security

### Current Implementation Assessment

`sentinel-server/src/routes.rs` lines 49-70:
- Strict default: localhost only when no origins configured
- Explicitly lists allowed methods and headers
- Warning logged when `*` origin is used

### Recommendations

**Issue 1: `max_age` for preflight caching**

Without `max_age`, browsers may send a preflight for every request, doubling latency:

```rust
.max_age(Duration::from_secs(3600)) // Cache preflight for 1 hour
```

**Issue 2: `expose_headers`**

If browser clients need `Retry-After` or `X-Request-Id`:

```rust
.expose_headers([header::RETRY_AFTER, HeaderName::from_static("x-request-id")])
```

**Issue 3: Localhost with ports**

Use `AllowOrigin::predicate` for dynamic localhost matching:

```rust
AllowOrigin::predicate(|origin: &HeaderValue, _req: &Parts| {
    let origin_str = origin.to_str().unwrap_or("");
    origin_str.starts_with("http://localhost")
        || origin_str.starts_with("http://127.0.0.1")
        || origin_str.starts_with("http://[::1]")
})
```

---

## 4. API Security Headers

For a security-critical API server, add via Tower middleware:

| Header | Value | Rationale |
|--------|-------|-----------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing, blocks XSS vectors |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Belt-and-suspenders for JSON API |
| `Cache-Control` | `no-store` | Prevents caching of sensitive responses |
| `Referrer-Policy` | `no-referrer` | Prevents API URLs leaking via Referer |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables browser features |

**Headers NOT to set:**
- `Strict-Transport-Security (HSTS)` — Only if Sentinel terminates TLS itself
- `X-XSS-Protection` — Deprecated, can introduce vulnerabilities

**Selective caching:** `/health` can use `public, max-age=5`; everything else `no-store`.

### Implementation

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

---

## 5. Per-IP Rate Limiting

### The Problem

Current rate limiting is global — a single misbehaving client exhausts the limit for all clients.

### Solution: Layered Approach

1. **Global rate limiting** (keep): Protects server from total overload
2. **Per-IP rate limiting** (add): Prevents single-client monopolization

### Implementation with governor

```rust
use governor::state::keyed::DashMapStateStore;
use std::net::IpAddr;

type KeyedRateLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

pub struct RateLimits {
    pub evaluate: Option<governor::DefaultDirectRateLimiter>,
    pub admin: Option<governor::DefaultDirectRateLimiter>,
    pub readonly: Option<governor::DefaultDirectRateLimiter>,
    pub per_ip: Option<KeyedRateLimiter>,
}
```

### IP Extraction: Security Critical

**Direct connection:** Use `axum::extract::ConnectInfo<SocketAddr>`

**Behind proxy:** Walk `X-Forwarded-For` **right-to-left**, skipping trusted proxies:

```rust
impl TrustedProxies {
    fn extract_client_ip(&self, request: &Request) -> Option<IpAddr> {
        let conn_ip = request.extensions()
            .get::<ConnectInfo<SocketAddr>>()?.0.ip();

        if self.trusted.contains(&conn_ip) {
            if let Some(xff) = request.headers().get("x-forwarded-for") {
                for ip_str in xff.to_str().ok()?.rsplit(',') {
                    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                        if !self.trusted.contains(&ip) { return Some(ip); }
                    }
                }
            }
        }
        Some(conn_ip)
    }
}
```

**WARNING:** `X-Forwarded-For` is client-spoofable. Only trust it when connection comes from a known proxy.

### Memory Management

`governor`'s `DashMapStateStore` grows unboundedly. Add periodic cleanup:

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        limiter.retain_recent();
    }
});
```

### Configurable Strategy

```rust
pub enum ClientIpStrategy {
    ConnectInfo,     // Direct connection
    XForwardedFor,   // Behind trusted proxy
    XRealIp,         // Nginx
    Disabled,        // No per-IP limiting
}
```

---

## Summary: Actionable Recommendations

### High Priority (Security)
1. **Add security response headers** — `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `Cache-Control`
2. **Add `Retry-After` header** to 429 responses
3. **Exempt `/health` from rate limiting**

### Medium Priority (Robustness)
4. **Add burst configuration** to `governor::Quota`
5. **Add `max_age` to CORS preflight** — 3600 seconds
6. **Consider per-IP rate limiting** with `DashMapStateStore<IpAddr>`

### Low Priority (Polish)
7. **Use `AllowOrigin::predicate`** for localhost CORS matching
8. **Add `axum-client-ip`** crate if per-IP + proxy support needed
9. **Add periodic `retain_recent()`** cleanup for keyed rate limiters

---

*Last updated: 2026-02-02*
