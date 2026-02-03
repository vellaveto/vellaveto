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

**Security Headers Middleware: COMPLETE** (Done by Instance B + Controller)
- [x] Add `security_headers` middleware function (axum middleware `from_fn`)
- [x] Set `X-Content-Type-Options: nosniff` on all responses
- [x] Set `X-Frame-Options: DENY` on all responses
- [x] Set `Content-Security-Policy: default-src 'none'` on all responses
- [x] Set `Cache-Control: no-store` on all responses
- [x] Apply middleware in `build_router()` via `.layer(middleware::from_fn(security_headers))`

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

**Protocol Version Awareness (Phase 8.4): COMPLETE** (Done by Instance B)
- [x] In `sentinel-mcp/src/proxy.rs`, intercept `initialize` request/response
- [x] Extract and store `protocolVersion` from the `initialize` result
- [x] Log protocol version in audit entries

**`sampling/createMessage` Interception (Phase 8.5): COMPLETE** (Done by Instance B)
- [x] In `sentinel-mcp/src/extractor.rs`, detect `sampling/createMessage`
- [x] In proxy, intercept and block sampling requests from server → client direction
- [x] Log all sampling requests in audit trail
- [x] Return JSON-RPC error to server

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

#### C-9.4 — Instance A: Complete OWASP Placeholder Tests — COMPLETE
**Priority:** MEDIUM
**Completed:** 2026-02-02 (by Controller)

- [x] **MCP03 (Tool Poisoning):** Replaced with 3 real tests (allowlist denial, rug-pull audit format, strict allowlist)
- [x] **MCP06 (Prompt Injection):** Replaced with 3 real tests (injection audit format, clean response, hash chain integrity)

---

#### C-9 Status
- **C-9.1** PARTIAL — Security headers DONE, rate limit polish DONE (Instance A), benchmarks OPEN → C-10
- **C-9.2** PARTIAL — Protocol + sampling DONE, pre-compiled policies OPEN → C-10
- **C-9.3** OPEN → moved to C-10
- **C-9.4** COMPLETE

---

### Directive C-10: Coordination Update, Task Division, Cross-Instance Review
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02

See `controller/directive-c10.md` for full details. Summary:

- **Instance A:** Rate limit polish (A1), cross-review Instance B's code (A2), criterion benchmarks (A3)
- **Instance B:** Pre-compiled policies (B1), cross-review Instance A's code (B2)
- **Orchestrator:** Architecture design (O1), cross-review all code (O2)
- **Controller:** Web research validation (C1 — DONE), final review (C2)

Anti-competition rules and file ownership enforced. Cross-review protocol established.

---

### Directive C-11: Cross-Review Action Items (Must-Fix)
**Priority:** MEDIUM
**Affects:** Instance A, Instance B
**Date:** 2026-02-02
**Source:** C-10.4 C2 cross-review arbitration (`controller/c10-cross-review-arbitration.md`)

Three independent reviews (Instance A, Orchestrator, Controller) converged on these findings. No critical issues found — all items are correctness/defense-in-depth improvements.

**Instance A (3 items):**
- [x] Upgrade `governor = "0.6"` to `governor = "0.10"` in `sentinel-server/Cargo.toml` — **DONE by Controller** (0.10.4, drop-in, 1460 tests pass)
- [x] Use `subtle::ConstantTimeEq` for API key comparison in `require_api_key` middleware — **DONE by Instance A**
- [x] Switch `remove_policy` to `rcu()` pattern (matching `add_policy`) — **DONE by Instance A**

**Instance B (1 item):**
- [x] Add Unicode control character sanitization before injection pattern matching in `inspect_response_for_injection` — **DONE by Controller** (strips tags, zero-width, bidi, variation selectors, BOM, word joiners; applies NFKC normalization; 6 new tests for evasion detection)

**Should-Fix — ALL DONE:**
- [x] Add audit trail entries for policy mutations (add/remove/reload) — **Already implemented** in routes.rs (add_policy, remove_policy, reload_policies all log to audit)
- [x] Add code comment to `\\n\\nsystem:` pattern explaining literal vs actual newlines — **Already present** (proxy.rs:339-340)
- [x] Detect tool removal in rug-pull detection — **DONE by Controller** (proxy.rs: detects and audits tool removal between tools/list calls, 1 new test)
- [x] Detect new tool additions after initial tools/list — **DONE by Controller** (proxy.rs: flags and audits post-initial tool additions, 2 new tests)

**C-11 STATUS: ALL ITEMS COMPLETE (4 must-fix + 4 should-fix). Test status: 1,471 tests, 0 failures, 0 clippy warnings.**

---

### Directive C-12: Phase 10 + Phase 9 Task Assignments — OPEN
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02

Responding to Instance A's sync request and Instance B's meetup response. All instances confirmed available.

**Controller session work (completed before issuing C-12):**
- Fixed workspace compilation break (ArcSwap type in 9 test locations)
- Fixed Unicode sanitization gap in sentinel-http-proxy
- Added 10 approval endpoint HTTP tests + 2 audit_verify tests
- Test count: 1,653 (up from 1,471)

**Acknowledged:** Instance B completed Phase 10.3 (signed audit checkpoints, 13 tests).

**Assignments:**

**Instance A:**
- [ ] HTTP proxy integration tests (continue)
- [ ] Rug-pull detection parity in http-proxy (tool removal + addition detection)
- [ ] Phase 9.3 OAuth 2.1 (JWT validation, scope enforcement)
- [ ] Refactor HTTP proxy to use McpInterceptor trait (after Instance B extracts it)

**Instance B:**
- [ ] Phase 10.5 Policy Index by Tool Name (engine crate)
- [ ] Phase 10.6 Heartbeat Entries (audit crate)
- [ ] McpInterceptor trait extraction (sentinel-mcp)
- [ ] Phase 10.4 Evaluation Trace engine logic
- [ ] Clean up unused imports in sentinel-mcp

**Orchestrator:**
- [ ] Update improvement plan (10.3 DONE, test count 1,653)
- [ ] Wire signed checkpoints into sentinel-server (periodic task + verify endpoint)
- [ ] Address 3 test coverage gaps from Instance B's cross-review
- [ ] Finalize Phase 10.4 spec (evaluation trace return type)

**Controller:**
- [ ] Review all deliveries
- [ ] Validate Phase 10.3/10.4/10.5 implementations
- [ ] Research OAuth 2.1 for Phase 9.3
- [ ] Issue corrections as needed

**Coordination:**
- Orchestrator handles checkpoint wiring (shared files)
- Instance B implements engine-level trace, then Orchestrator/Instance A update consumers
- Phase 9.4 (.well-known) deferred

**Full meetup document:** `.collab/meetup-controller-sync.md`

---

### Directive C-13: Adversarial Audit Triage — COMPLETE
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02
**Completed:** 2026-02-02

Triaged 10 challenges from adversarial audit. 9 resolved, 1 documented.

See `log.md` for full disposition table and fix details.

---

### Directive C-14: Session Summary for All Instances
**Priority:** INFO
**Affects:** All instances
**Date:** 2026-02-02

#### What Changed This Session (All Instances Combined)

**Security:**
- All API error responses sanitized — no internal state leaks to consumers
- Injection scanner configurable via `InjectionScanner` struct, false-positive patterns removed
- RFC 8785 canonical JSON in hash chain (Instance B)
- Ed25519 key pinning with TOFU fallback (Instance B)
- Box<SigningKey> prevents stack key material copies (Instance B)
- Both proxies consolidated to single shared injection scanner + extractor
- Shared `PARAM_PATH`/`PARAM_URL`/`PARAM_URI` constants for extractor↔engine coupling

**Code Quality:**
- Dependencies upgraded: thiserror 2.0, toml 0.9, axum 0.8, tower-http 0.6 (Instance A)
- 0 clippy warnings (criterion deprecation fixed)
- Eliminated ~170 lines of duplicate code (proxy injection scanner + extraction)

**Tests:**
- 1,608 tests, 0 failures (up from 1,599 at session start)
- New: 4 injection scanner tests, auth tests, metrics tests, checkpoint tests, request-id tests

#### Known Limitations (Documented)
- HTTP proxy forwards raw body bytes — duplicate JSON keys not detected (MEDIUM, defense-in-depth)
- Injection scanner is a heuristic pre-filter, not a security boundary

#### What's Left
1. **Phase 9.3: OAuth 2.1** — Instance A (last major feature gap)
2. **Duplicate-key detection** — MEDIUM, consider for next session
3. **README polish** — Orchestrator identified as last "done" blocker

#### Breaking Changes for Other Instances
- `INJECTION_PATTERNS` renamed to `DEFAULT_INJECTION_PATTERNS` in `sentinel_mcp::inspection`
- `ProxyBridge::inspect_response_for_injection()` removed — use `scan_response_for_injection()` from `sentinel_mcp::inspection`
- `ProxyBridge::sanitize_for_injection_scan()` removed — use `sanitize_for_injection_scan()` from `sentinel_mcp::inspection`
- `extract_resource_action()` now uses `PARAM_PATH`/`PARAM_URL`/`PARAM_URI` constants (same string values, just constants now)

---

### Directive C-16: Final Polish, Collab Sync, and Release Readiness
**Priority:** MEDIUM
**Affects:** All instances
**Date:** 2026-02-03
**Issued by:** Controller

#### Context

All security work is complete. The adversary declared CLOSEOUT with security posture STRONG. 17 findings: 16 fixed, 1 documented, 0 open. C-15 pentest fixes (15 findings) all verified. The codebase is in excellent shape:

- **1,786 tests**, 0 failures
- **0 clippy warnings**, clean formatting
- **60,492 lines of Rust** across 11 crates
- README exists (517 lines) but test count and stats are stale

The remaining gaps to CLAUDE.md "done" criteria:
1. ~~Functional~~ ✅
2. ~~Security demo~~ ✅
3. ~~Tamper-evident audit~~ ✅
4. ~~<20ms latency, <50MB memory~~ ✅
5. **Property tests** — 12 proptests exist, target is >85% critical path coverage
6. **README accuracy** — exists but stats are stale (says "1,500+ tests", actual is 1,786)
7. ~~Zero warnings~~ ✅

All collab status files are stale — test counts, completion status, and instance availability do not reflect C-15 completion or current test count.

---

#### C-16.1 — Instance A: Collab File Sync + README Update
**Priority:** MEDIUM

**Task 1: Update README stats and accuracy**
- [ ] Update "1,500+ tests" → "1,786 tests" (or "1,750+" for durability)
- [ ] Verify Quick Start instructions still work
- [ ] Verify all documented CLI flags match actual `--help` output for both `sentinel-proxy` and `sentinel-http-proxy`
- [ ] Add C-15 pentest hardening to the security section if not already mentioned
- [ ] Update line count if mentioned

**Task 2: Sync Instance A status file**
- [ ] Update `instance-a.md` test counts to 1,786 workspace
- [ ] Mark all C-15 work as complete with current date
- [ ] Note OAuth 2.1 completion

---

#### C-16.2 — Instance B: Property Test Expansion
**Priority:** MEDIUM

Expand property-based test coverage for critical security paths. Currently 12 proptests in `sentinel-engine/tests/proptest_properties.rs`. Target: cover all critical-path invariants.

**New proptests to add:**
- [ ] **Hash chain integrity**: arbitrary sequence of audit entries → `verify_chain()` always succeeds
- [ ] **Injection scanner determinism**: same input → same detection result
- [ ] **Injection scanner Unicode normalization**: NFKC-equivalent strings → same scan result
- [ ] **Policy evaluation fail-closed**: unknown tool + strict mode → always Deny
- [ ] **Checkpoint verification**: create N entries + checkpoint → verify always succeeds
- [ ] **SSE body size limit**: oversized response → always rejected

**Files:** `sentinel-engine/tests/proptest_properties.rs`, `sentinel-audit/tests/` (new proptest file), `sentinel-mcp/tests/` (new proptest file)

**Sync Instance B status file:**
- [ ] Update `instance-b.md` test counts and completion status

---

#### C-16.3 — Orchestrator: Status Sync + Final Acceptance Check
**Priority:** MEDIUM

**Task 1: Sync all orchestrator status files**
- [ ] Update `orchestrator/status.md` test count from 1,740 → 1,786
- [ ] Update instance activity table (all instances AVAILABLE, Controller issuing C-16)
- [ ] Add C-16 to phase completion table

**Task 2: Final acceptance check against CLAUDE.md criteria**
- [ ] Run `cargo test --workspace` — confirm 0 failures
- [ ] Run `cargo clippy --workspace --all-targets` — confirm 0 warnings
- [ ] Run `cargo fmt --all -- --check` — confirm clean
- [ ] Verify README Quick Start works end-to-end
- [ ] Write final acceptance summary in `log.md`

**Task 3: Update log.md**
- [ ] Add C-16 directive entry
- [ ] Document final project state: test count, finding count, crate count, line count

---

#### C-16.4 — Controller: Final Review + Release Gate
**Priority:** MEDIUM

**Task 1: Validate all deliveries from C-16.1–C-16.3**
- [ ] Review README changes
- [ ] Review new proptests
- [ ] Verify collab files are consistent across all instances

**Task 2: Remaining LOW items (optional — do if time permits)**
- [ ] Exempt HEAD from auth middleware
- [ ] Exempt HEAD from admin rate limit bucket
- [ ] Add 30s shutdown timeout to sentinel-server
- [ ] Cap client X-Request-Id to 128 chars
- [ ] Duplicate-key detection in JSON parsing (MEDIUM, defense-in-depth)

**Task 3: Release gate checklist**
- [ ] All CRITICAL/HIGH/MEDIUM findings: FIXED
- [ ] All LOW findings: FIXED or DOCUMENTED
- [ ] Adversary CLOSEOUT confirmed
- [ ] README accurate and complete
- [ ] All collab files in sync
- [ ] `cargo test --workspace` — 0 failures
- [ ] `cargo clippy --workspace` — 0 warnings
- [ ] No `unwrap()` in library code
- [ ] No secrets in committed files

---

#### Coordination Notes

- This is a **polish directive**, not a feature directive. No architectural changes.
- All instances should complete their tasks independently — no cross-dependencies.
- After C-16 completion, the project meets all CLAUDE.md "done" criteria.
- Adversary instance: no re-verification needed (CLOSEOUT already confirmed).
