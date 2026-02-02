# Controller Directives

## Completed Directives

**CONTROLLER ACTIVATED: 2026-02-02**
**Authority:** These directives override all orchestrator task assignments per hierarchy rules (Controller > Orchestrator > Instance A/B).

**STATUS: ALL DIRECTIVES EXECUTED — Improvement plan Phases 3+ now unblocked.**

---

### Directive C-1: STOP ALL FEATURE WORK — Fix Security-Breaking Bugs — COMPLETE
**Priority:** CRITICAL
**Affects:** All
**Date:** 2026-02-02
**Completed:** 2026-02-02

- [x] ALL instances: Read the external audit report immediately
- [x] Orchestrator: Halt improvement plan execution (Phases 1-6 are paused)
- [x] Instance B: Fix findings 1-6 (your code, you know it best) — see Directive C-2
- [x] Instance A: Fix finding 7 (server auth) and write regression tests — see Directive C-3

---

### Directive C-2: Instance B — Fix CRITICAL Audit/Engine/MCP Bugs — COMPLETE
**Priority:** CRITICAL
**Affects:** Instance B
**Date:** 2026-02-02
**Completed:** 2026-02-02

All 9 fixes implemented and verified:

- [x] **Fix #1 — Hash chain bypass:** Hashless entries rejected after first hashed entry
- [x] **Fix #2 — Hash chain field separators:** Length-prefixed encoding added
- [x] **Fix #3 — initialize_chain trusts file:** Chain verified on init
- [x] **Fix #4 — last_hash before file write:** Hash update moved after flush
- [x] **Fix #5 — Empty tool name bypass:** Returns `MessageType::Invalid`
- [x] **Fix #6 — Unbounded read_line:** MAX_LINE_LENGTH (1MB) enforced
- [x] **Fix #8 — extract_domain `@` bypass:** Authority-only `@` search
- [x] **Fix #9 — normalize_path empty fallback:** Returns `/` on empty
- [x] **Fix #14 — Empty line kills proxy:** Continue loop on empty lines

---

### Directive C-3: Instance A — Server Auth + Regression Tests — COMPLETE
**Priority:** CRITICAL
**Affects:** Instance A
**Date:** 2026-02-02
**Completed:** 2026-02-02

- [x] **Fix #7 — Server authentication:** Bearer token auth middleware via `route_layer`, CORS replaced with explicit config, `SENTINEL_API_KEY` env var
- [x] **Fix #26 — Default bind to 127.0.0.1:** Default changed, `--bind` flag added
- [x] **32 regression tests** in `sentinel-integration/tests/security_regression.rs` covering all 14 CRITICAL/HIGH findings

---

### Directive C-4: Orchestrator — Validate Fixes, Update Status — COMPLETE
**Priority:** HIGH
**Affects:** Orchestrator
**Date:** 2026-02-02
**Completed:** 2026-02-02

- [x] After Instance B submits fixes: run full test suite, verify each CRITICAL finding is addressed
- [x] After Instance A submits auth + tests: review the auth middleware design, verify tests are comprehensive
- [x] Update `orchestrator/status.md` to reflect the security audit findings
- [x] Resume improvement plan execution ONLY after all CRITICAL/HIGH findings are fixed
- [x] Update the external audit report with fix status

---

### Directive C-5: Orchestrator Improvement Plan — Corrections — COMPLETE
**Priority:** MEDIUM
**Affects:** Orchestrator
**Date:** 2026-02-02
**Completed:** 2026-02-02

- [x] Add "Phase 0: Security Hardening" to improvement plan with findings 1-14
- [x] Mark completed items (kill_on_drop, regex cache, globset, pre-sort, deep param inspection, resource read)
- [x] Defer Merkle tree until hash chain is correct (marked DEFERRED in plan)
- [x] Acknowledge the gap in the original orchestrator audit (in orchestrator/status.md)

---

### Directive C-6: MCP Protocol Compliance — COMPLETE
**Priority:** MEDIUM
**Affects:** Instance B
**Date:** 2026-02-02
**Completed:** 2026-02-02

- [x] **Fix #27:** `McpRequest.id` changed to `serde_json::Value`
- [x] **Fix #28:** `"jsonrpc": "2.0"` field added to `McpResponse`
- [x] **Fix #29:** Error codes changed to `-32001` (policy denial) / `-32002` (evaluation error)
- [x] **Fix #30:** Child process reaped after kill (+ `kill_on_drop(true)` by Orchestrator)

---

### Directive C-7: Remaining MEDIUM Fixes — Phase 3 — COMPLETE
**Priority:** MEDIUM
**Affects:** All instances
**Date:** 2026-02-02
**Completed:** 2026-02-02

**ALL 16 MEDIUM FINDINGS RESOLVED:**

Controller fixed 12 directly: #15/16, #18, #20, #21, #22, #23, #24, #25, #33, #34, #35, #37, plus normalize_path idempotency bug.

Instance B fixed 3: #31 (rate limiting), #32 (CORS), #36 (log rotation).

Instance A contributed: Property-based tests (8 proptests covering evaluate determinism, normalize_path idempotency, extract_domain consistency/lowercase, traversal stripping, path safety).

**Test status: 1,499 tests, 0 failures, 0 clippy warnings.**

---

### Directive C-8: MCP Spec Alignment & Strategic Features (Research-Based) — COMPLETE
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02
**Completed:** 2026-02-02

All C-8 sub-directives executed:
- [x] **C-8.1** Orchestrator updated improvement plan with Phases 8-9
- [x] **C-8.2** Instance B implemented tool annotation awareness + rug-pull detection (4 tests)
- [x] **C-8.3** Instance B implemented response injection scanning (5 tests)
- [x] **C-8.4** Instance A added OWASP MCP Top 10 test matrix (39 tests)
- [x] **C-8.5** Orchestrator reviewed research, updated plan, added Phases 8-9

**Test status at C-8 close: 1,512 tests, 0 failures, 0 clippy warnings.**

---

### Directive C-9: Production Hardening & Architecture (Research-Based)
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02
**Source:** Controller research — `controller/research/policy-engine-patterns.md`, `controller/research/rate-limiting-cors-headers.md`, `controller/research/audit-log-rotation.md`

C-8 delivered strong MCP spec alignment. C-9 focuses on **production hardening** (security headers, performance, observability) and **architecture improvements** (pre-compiled policies, signed audit checkpoints) derived from Cedar/OPA/CT research. These items close the gap between "working prototype" and "production-deployable security product."

---

#### C-9.1 — Instance A: API Security Headers & Rate Limit Polish
**Priority:** HIGH — Quick wins with outsized security value
**Source:** `controller/research/rate-limiting-cors-headers.md` §4, §2

Add API security response headers and polish rate limiting. These are standard hardening measures expected of any security-critical API server.

**Security Headers Middleware:**
- [ ] Add `security_headers` middleware function (axum middleware `from_fn`)
- [ ] Set `X-Content-Type-Options: nosniff` on all responses
- [ ] Set `X-Frame-Options: DENY` on all responses
- [ ] Set `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on all responses
- [ ] Set `Cache-Control: no-store` on all responses EXCEPT `/health` (use `public, max-age=5` for health)
- [ ] Set `Referrer-Policy: no-referrer` on all responses
- [ ] Strip `Server` header from all responses
- [ ] Apply middleware in `build_router()` via `.layer(middleware::from_fn(security_headers))`

**Rate Limit Polish:**
- [ ] Exempt `/health` endpoint from rate limiting (load balancer probes must never be throttled)
- [ ] Add `Retry-After` header to 429 responses with wait time from governor's `NotUntil`
- [ ] Add `max_age(Duration::from_secs(3600))` to CORS layer for preflight caching

**Criterion Benchmarks (I-A2):**
- [ ] Create `sentinel-engine/benches/evaluation.rs` with criterion benchmarks
- [ ] Benchmark: single policy evaluation, 100-policy evaluation, 1000-policy evaluation
- [ ] Benchmark: path normalization, domain extraction, regex constraint matching
- [ ] Verify <5ms P99 for policy evaluation under load

**Files:** `sentinel-server/src/routes.rs` (middleware), `sentinel-server/src/main.rs`, `sentinel-engine/benches/`
**Reference:** `controller/research/rate-limiting-cors-headers.md` §4 has exact implementation code

---

#### C-9.2 — Instance B: Pre-Compiled Policies & Protocol Awareness
**Priority:** HIGH — Eliminates hot-path lock contention, enables policy validation
**Source:** `controller/research/policy-engine-patterns.md` §2.1, §1.3, §3.1

The current engine uses `Mutex<HashMap<String, Regex>>` and `Mutex<HashMap<String, GlobMatcher>>` caches that introduce lock contention on every evaluation. Cedar and OPA both compile policies at load time. This is the single highest-impact performance improvement remaining.

**Pre-Compiled Policies (Phase 10.1):**
- [ ] Add `CompiledPolicy` struct that holds pre-compiled regex and glob matchers alongside the raw `Policy`
- [ ] Compile all regex patterns, glob patterns, and tool matchers at policy load time
- [ ] Replace `regex_cache` and `glob_cache` Mutex fields with direct compiled references in `CompiledPolicy`
- [ ] `PolicyEngine::new()` and `PolicyEngine::reload()` perform compilation, returning errors for invalid patterns
- [ ] Policy validation: reject policies with invalid regex, invalid glob, conflicting constraints at load time
- [ ] Zero Mutex acquisitions in the evaluate hot path

**Implementation approach:**
```rust
pub struct CompiledPolicy {
    pub policy: Policy,
    pub tool_matcher: CompiledToolMatcher,   // pre-compiled glob or exact match
    pub constraints: Vec<CompiledConstraint>, // pre-compiled regex/glob per constraint
}

pub enum CompiledToolMatcher {
    Exact(String, String),           // tool, function
    ToolWildcard(String),            // tool:*
    FunctionWildcard(GlobMatcher),   // *:function or glob
    Universal,                        // *
}
```

**Protocol Version Awareness (Phase 8.4):**
- [ ] In `sentinel-mcp/src/proxy.rs`, intercept `initialize` request/response
- [ ] Extract and store `protocolVersion` from the `initialize` result
- [ ] Log protocol version in audit entries
- [ ] Warn if version is < 2024-11-05 (earliest stable spec)

**`sampling/createMessage` Interception (Phase 8.5):**
- [ ] In `sentinel-mcp/src/extractor.rs`, add `MessageType::SamplingRequest` for `sampling/createMessage`
- [ ] In proxy, intercept sampling requests from server → client direction
- [ ] Log all sampling requests in audit trail (these are server-initiated LLM calls — potential exfiltration vector)
- [ ] Apply policy evaluation to sampling requests (reuse tool evaluation with `tool="sampling"`, `function="createMessage"`)

**Files:** `sentinel-engine/src/lib.rs` (compiled policies), `sentinel-mcp/src/proxy.rs` (protocol + sampling), `sentinel-mcp/src/extractor.rs`
**Reference:** `controller/research/policy-engine-patterns.md` §2.1 and §3.1

---

#### C-9.3 — Orchestrator: Architecture Design & Plan Updates
**Priority:** MEDIUM — Planning for next major features
**Source:** All 4 controller research files

**Signed Audit Checkpoints Design:**
- [ ] Review `controller/research/audit-log-rotation.md` §2 (Sigstore patterns) and §5 (verification)
- [ ] Design `ChainCheckpoint` struct: timestamp, entry_count, segment_id, chain_head_hash, Ed25519 signature
- [ ] Plan: write checkpoint entry every 1000 entries or 5 minutes (whichever comes first)
- [ ] Plan: `verify_since_checkpoint()` API for incremental verification
- [ ] Add to improvement plan as Phase 10.3

**Evaluation Trace Design:**
- [ ] Review `controller/research/policy-engine-patterns.md` §2.2 (OPA decision logging)
- [ ] Design `EvaluationTrace` struct: policies_checked, first_match, all matches with constraint results, duration
- [ ] Plan: optional `?trace=true` query param on `/api/evaluate` endpoint
- [ ] Add to improvement plan as Phase 10.4

**Streamable HTTP Architecture (Phase 9):**
- [ ] Review `controller/research/mcp-spec-and-landscape.md` §Streamable HTTP
- [ ] Design reverse proxy architecture: single `/mcp` endpoint, POST handler, SSE streaming
- [ ] Plan session management: `Mcp-Session-Id` header → per-session policy state
- [ ] Plan OAuth 2.1 token validation flow
- [ ] Document architecture in improvement plan Phase 9 (expand from current outline)

**Update Improvement Plan:**
- [ ] Add Phase 10: Production Hardening
  - 10.1 Pre-compiled policies (C-9.2)
  - 10.2 API security headers (C-9.1)
  - 10.3 Signed audit checkpoints
  - 10.4 Evaluation trace/explanation
  - 10.5 Policy index by tool name (O(matching) instead of O(all))
- [ ] Mark C-8 items as complete in Phases 8.1, 8.2, 8.3
- [ ] Update completed items summary

---

#### C-9.4 — Instance A: Complete OWASP Placeholder Tests
**Priority:** MEDIUM — Now unblocked by C-8.2/C-8.3 completion
**Depends on:** C-8.2 and C-8.3 (tool annotations + response inspection — both DONE)

Instance A's OWASP test matrix has two placeholder tests that were blocked on Instance B's C-8 work:

- [ ] **MCP03 (Tool Poisoning):** Replace placeholder test with real test exercising rug-pull detection from C8-B1. Test that tool definition changes between `tools/list` calls are detected and audited.
- [ ] **MCP06 (Prompt Injection):** Replace placeholder test with real test exercising response inspection from C8-B2. Test that injection patterns in tool results are detected and logged.

**Files:** `sentinel-integration/tests/owasp_mcp_top10.rs`

---

#### Priority Order
1. **C-9.1** (Instance A) — Security headers are a quick win, immediate production value
2. **C-9.2** (Instance B) — Pre-compiled policies eliminate the last hot-path bottleneck
3. **C-9.4** (Instance A) — Unblock OWASP test completion
4. **C-9.3** (Orchestrator) — Architecture planning for next cycle
