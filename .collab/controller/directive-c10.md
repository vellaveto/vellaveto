# Directive C-10: Coordination Update, Task Division, and Cross-Instance Review

**Date:** 2026-02-02
**Authority:** Controller (highest authority)
**Priority:** HIGH
**Affects:** All instances

---

## Context

C-9 is partially complete. Several tasks were completed ahead of schedule by Controller and Instance B. The task files for instances A and B are stale and must be updated. This directive:

1. Marks completed C-9 items
2. Assigns remaining work with non-overlapping ownership
3. Establishes cross-instance code review assignments

---

## C-9 Status: What's Done

| Task | Assigned To | Status | Completed By |
|------|-------------|--------|--------------|
| C9-A1: Security headers middleware | Instance A | **DONE** | Instance B + Controller |
| C9-A2: Rate limit polish | Instance A | OPEN | — |
| C9-A3: OWASP placeholder tests | Instance A | **DONE** | Controller |
| C9-A4: Criterion benchmarks | Instance A | OPEN | — |
| C9-B1: Pre-compiled policies | Instance B | OPEN | — |
| C9-B2: Protocol version awareness | Instance B | **DONE** | Instance B |
| C9-B3: sampling/createMessage | Instance B | **DONE** | Instance B |
| C9-3: Orchestrator architecture | Orchestrator | OPEN | — |

---

## C-10.1 — Instance A: Rate Limit Polish + Benchmarks + Cross-Review

**Priority:** HIGH
**Files owned:** `sentinel-server/src/routes.rs` (rate limit only), `sentinel-engine/benches/`, `sentinel-integration/tests/`

### Task A1: Rate Limit Polish (from C9-A2)
1. Exempt `/health` from rate limiting — load balancer probes must never be throttled
2. Add `Retry-After` header to 429 responses with wait duration from governor's `NotUntil`
3. Add `max_age(Duration::from_secs(3600))` to CORS layer for preflight caching

### Task A2: Criterion Benchmarks (from C9-A4)
1. Add `criterion = "0.5"` as dev-dependency to `sentinel-engine/Cargo.toml`
2. Create `sentinel-engine/benches/evaluation.rs`
3. Benchmark: single policy exact match, 100-policy wildcard, 1000-policy stress
4. Benchmark: `normalize_path()`, `extract_domain()`, regex constraint matching
5. Add `[[bench]]` section to `sentinel-engine/Cargo.toml`

### Task A3: Cross-Review Instance B's Code
Review the following files for correctness, edge cases, and security gaps:
- `sentinel-mcp/src/proxy.rs` — focus on: tool annotation wiring, response injection scanning logic, sampling interception, protocol version tracking
- `sentinel-mcp/src/framing.rs` — focus on: MAX_LINE_LENGTH enforcement, empty line handling, EOF detection
- `sentinel-audit/src/lib.rs` — focus on: hash chain integrity (Fix #1-4), log rotation, sensitive value redaction
- `sentinel-engine/src/lib.rs` — focus on: percent-encoding normalization, recursive parameter scanning (`param: "*"`), glob cache bounds

**Deliverable:** Write findings to `.collab/review-b-by-a.md`. For each file, note: (1) bugs found, (2) edge cases missed, (3) security concerns, (4) improvements suggested.

### Work Order
1. A1 (rate limit polish) — quick win
2. A3 (cross-review) — important for quality
3. A2 (benchmarks) — last

---

## C-10.2 — Instance B: Pre-Compiled Policies + Cross-Review

**Priority:** HIGH
**Files owned:** `sentinel-engine/src/lib.rs`, `sentinel-mcp/`, `sentinel-audit/`, `sentinel-approval/`

### Task B1: Pre-Compiled Policies (from C9-B1 — unchanged, still highest priority)
This is the single most impactful remaining performance improvement. See `orchestrator/tasks-instance-b.md` for full specification.

Key requirements:
1. Add `CompiledPolicy` struct with pre-compiled regex/glob matchers
2. Compile at load time in `PolicyEngine::new()`
3. Remove `regex_cache` and `glob_cache` Mutex fields
4. Zero Mutex acquisitions in `evaluate_action()` hot path
5. Invalid patterns rejected at compile time with descriptive errors
6. All existing tests must pass (behavioral parity)

### Task B2: Cross-Review Instance A's Code
Review the following files for correctness, edge cases, and security gaps:
- `sentinel-server/src/routes.rs` — focus on: auth middleware (bearer token extraction, skip logic for GET/OPTIONS), rate_limit middleware, request_id middleware, security_headers middleware, CORS configuration
- `sentinel-server/src/main.rs` — focus on: env var parsing, bind address, graceful shutdown, approval store initialization
- `sentinel-integration/tests/security_regression.rs` — focus on: coverage completeness (are all 14 findings tested?), test quality (are edge cases covered?)
- `sentinel-integration/tests/owasp_mcp_top10.rs` — focus on: MCP03/MCP06 tests (are they exercising real functionality or just formatting?), coverage gaps

**Deliverable:** Write findings to `.collab/review-a-by-b.md`. For each file, note: (1) bugs found, (2) edge cases missed, (3) security concerns, (4) improvements suggested.

### Work Order
1. B1 (pre-compiled policies) — highest impact, do first
2. B2 (cross-review) — do after B1

---

## C-10.3 — Orchestrator: Architecture Design

**Priority:** MEDIUM
**Files owned:** `.collab/orchestrator/`

### Task O1: Architecture Design Documents (from C9-3)
1. Signed audit checkpoints design (Ed25519, every 1000 entries)
2. Evaluation trace design (OPA-style `?trace=true` on evaluate endpoint)
3. Streamable HTTP transport architecture (Phase 9 detailed design)
4. Update improvement plan with Phase 10

### Task O2: Cross-Review All Instance Code
As the coordinator, review both instances' work since the last audit:
- Verify all test files compile and exercise real functionality
- Check for any regressions from the Controller's MEDIUM fixes
- Validate that ArcSwap migration hasn't introduced race conditions

**Deliverable:** Update `orchestrator/status.md` with review findings.

---

## C-10.4 — Controller: Web Research Validation + Final Review

**Priority:** HIGH

### Task C1: Validate Architectural Decisions via Web Research
Research current best practices for:
1. `arc-swap` for lock-free reads — still recommended?
2. SHA-256 linear hash chain — sufficient, or should we consider BLAKE3?
3. `governor` for rate limiting in Axum — still standard?
4. Prompt injection detection patterns — are 15 patterns enough?
5. MCP protocol — any spec updates since 2025-11-25?

### Task C2: Final Cross-Review
Review all cross-review reports from instances A and B. Arbitrate any disagreements. Issue corrections if needed.

---

## Anti-Competition Rules

To prevent instances from stepping on each other:

| File/Area | Owner | Others MUST NOT Touch |
|-----------|-------|----------------------|
| `sentinel-engine/src/lib.rs` | Instance B | Instance A may only read for review |
| `sentinel-engine/benches/` | Instance A | Instance B must not create benchmarks |
| `sentinel-mcp/` | Instance B | Instance A may only read for review |
| `sentinel-audit/src/lib.rs` | Instance B | Instance A may only read for review |
| `sentinel-server/src/routes.rs` | Instance A (rate limit only) | Instance B may only read for review |
| `sentinel-server/src/main.rs` | Shared | Coordinate via log.md before touching |
| `sentinel-integration/tests/` | Instance A | Instance B may only read for review |
| `.collab/orchestrator/` | Orchestrator | Instances may read, not write |
| `.collab/controller/` | Controller | All others read-only |

---

## Cross-Review Protocol

1. Each instance writes their review to `.collab/review-{reviewed}-by-{reviewer}.md`
2. Reviews must cover: bugs, edge cases, security gaps, and suggested improvements
3. Reviews are informational — the code owner decides whether to act on them
4. Use web search to validate any uncertain findings (e.g., "is this hash chain pattern secure?")
5. After reviews are written, Controller reviews all reports and issues corrections if needed

---

## Timeline

1. Instance A: Start A1 immediately, then A3, then A2
2. Instance B: Start B1 immediately, then B2
3. Orchestrator: Start O1, then O2
4. Controller: C1 (in progress), then C2 after reviews are submitted
