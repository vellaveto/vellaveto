# Tasks for Instance A — Directive C-10 (Coordination Update)

## READ THIS FIRST

Controller Directive C-10 is active. Several C-9 tasks are already complete (done by Controller or Instance B). This file reflects the CURRENT state. Read `controller/directive-c10.md` for full context.

Update `.collab/instance-a.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (all previous directives)
- CI workflow, integration tests, approval flow tests
- S-A1 (auth), S-A2 (bind address), security regression tests (32)
- C7-A1: Rate limiting (#31), proptest (8 property tests), ArcSwap migration fixes
- C8-A1: OWASP MCP Top 10 test coverage (39 tests)
- **C9-A1: Security headers middleware** — DONE (completed by Instance B + Controller)
- **C9-A3: OWASP MCP03/MCP06 placeholder tests** — DONE (completed by Controller — 6 real tests replacing 2 placeholders)

---

## Task A1: Rate Limit Polish
**Priority: HIGH — Quick win**
**Directive:** C-10.1
**Status:** OPEN

Polish the rate limiting implementation added in C-7:

1. **Exempt `/health` from rate limiting:** In the `rate_limit` middleware function, check if the request path is `/health` and skip rate limiting for it. Load balancer health probes must never be throttled.

2. **Add `Retry-After` header to 429 responses:** When `limiter.check()` returns `Err(not_until)`, extract the wait duration using `not_until.wait_time_from(governor::clock::DefaultClock::default().now())` and set `Retry-After: <seconds>` header on the 429 response.

3. **Add `max_age` to CORS:** In `build_cors_layer()`, add `.max_age(Duration::from_secs(3600))` to cache preflight responses for 1 hour.

**Files:** `sentinel-server/src/routes.rs`
**Tests:** Add tests in `sentinel-server/tests/test_routes_unit.rs`:
- Test that `/health` is not rate-limited even when rate limiter is configured
- Test that 429 response includes `Retry-After` header

---

## Task A2: Cross-Review Instance B's Code
**Priority: HIGH — Quality assurance**
**Directive:** C-10.1
**Status:** OPEN

Review Instance B's code for correctness, edge cases, and security gaps. Focus areas:

### `sentinel-mcp/src/proxy.rs`
- Tool annotation wiring: Are annotations correctly extracted from `tools/list` and passed to `evaluate_tool_call`?
- Response injection scanning: Are the 15 patterns sufficient? Any false positive risks?
- Sampling interception: Is the block correct? Should there be a configurable allow mode?
- Protocol version tracking: Is version comparison correct?
- Rug-pull detection: Is the annotation change detection comprehensive?

### `sentinel-mcp/src/framing.rs`
- MAX_LINE_LENGTH enforcement: Is the check correct? Can it be bypassed with multi-byte UTF-8?
- Empty line handling: Does `continue` on empty lines work correctly with all newline styles (LF, CRLF)?
- EOF detection: Is the 0-byte read check reliable?

### `sentinel-audit/src/lib.rs`
- Hash chain (Fix #1-4): Is length-prefixed encoding correct? Is the hash-before-or-after-write ordering actually fixed?
- Log rotation: Does `maybe_rotate()` have TOCTOU issues (check size, then write, then rotate)?
- Redaction: Are all sensitive patterns covered? Can redaction be bypassed with encoding tricks?

### `sentinel-engine/src/lib.rs`
- Percent-encoding normalization: Is the loop-decode-until-stable approach correct? Max 5 iterations — is this enough?
- Recursive scanning (`param: "*"`): Is `MAX_SCAN_VALUES=500` sufficient? Is the iterative walker correct?
- Glob cache bounds: Is eviction correct when cache exceeds 1000 entries?

**Deliverable:** Write review to `.collab/review-b-by-a.md`

---

## Task A3: Criterion Benchmarks
**Priority: MEDIUM**
**Directive:** C-10.1
**Status:** OPEN

Create performance benchmarks to validate <5ms evaluation latency.

1. Add `criterion = "0.5"` as dev-dependency to `sentinel-engine/Cargo.toml`
2. Create `sentinel-engine/benches/evaluation.rs`:
   - Benchmark single policy evaluation (1 policy, exact match)
   - Benchmark 100-policy evaluation (mixed allow/deny, wildcards)
   - Benchmark 1000-policy evaluation (stress test)
   - Benchmark `normalize_path()` with various inputs (clean, traversal, encoded)
   - Benchmark `extract_domain()` with various URLs (simple, complex, encoded)
   - Benchmark regex constraint matching (simple patterns, complex patterns)
3. Add `[[bench]]` section to `sentinel-engine/Cargo.toml`:
   ```toml
   [[bench]]
   name = "evaluation"
   harness = false
   ```

**Files:** `sentinel-engine/Cargo.toml`, `sentinel-engine/benches/evaluation.rs`

---

## Work Order
1. **A1** (rate limit polish) — quick win, do first
2. **A2** (cross-review) — important for quality, do second
3. **A3** (benchmarks) — valuable but less urgent, do last

## File Ownership (C-10 anti-competition rules)
- You OWN: `sentinel-server/src/routes.rs` (rate limit changes only), `sentinel-engine/benches/`, `sentinel-integration/tests/`
- You may READ but NOT MODIFY: `sentinel-engine/src/lib.rs`, `sentinel-mcp/`, `sentinel-audit/`
- Shared (coordinate first): `sentinel-server/src/main.rs`

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. Write cross-review to `.collab/review-b-by-a.md`
