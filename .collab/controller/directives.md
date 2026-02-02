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

### Directive C-8: MCP Spec Alignment & Strategic Features (Research-Based)
**Priority:** HIGH
**Affects:** All instances
**Date:** 2026-02-02
**Source:** Controller web research — see `controller/research/mcp-spec-and-landscape.md`

The MCP specification has evolved to version 2025-11-25 with major new features. The competitive landscape is rapidly forming around "MCP gateways." Sentinel has strong differentiators (tamper-evident audit, parameter constraints, Rust performance) but critical gaps vs. market expectations. OWASP published an MCP Top 10 that identifies gaps in Sentinel's coverage.

**Research findings at:** `controller/research/mcp-spec-and-landscape.md`

#### C-8.1 — Orchestrator: Update Improvement Plan with New Phases
Add the following to the improvement plan based on research:

**New Phase 8: MCP Spec Alignment (HIGH — Market Relevance)**
- 8.1 Tool annotation awareness — Intercept `tools/list` responses, extract annotations, use for default policy decisions (destructiveHint=true → require approval). Per MCP spec: "annotations MUST be considered untrusted unless from trusted servers."
- 8.2 Response inspection — Scan tool results flowing from child to agent for prompt injection patterns. Currently Sentinel only inspects outgoing requests, not responses. Maps to OWASP MCP06.
- 8.3 Tool definition pinning — Detect when tool schemas/descriptions change between sessions (rug-pull detection). Maps to OWASP MCP03.
- 8.4 Protocol version awareness — Log and verify the MCP protocol version during `initialize` handshake.
- 8.5 `sampling/createMessage` interception — Monitor server-to-client LLM requests to prevent exfiltration via sampling.

**New Phase 9: Streamable HTTP Transport (HIGH — Market Relevance)**
- 9.1 HTTP reverse proxy mode — Act as Streamable HTTP proxy between client and remote MCP server. Single endpoint, POST handling, optional SSE streaming.
- 9.2 Session management — Handle `Mcp-Session-Id` headers, per-session policy evaluation.
- 9.3 OAuth 2.1 pass-through — Verify and forward Bearer tokens for HTTP transport.
- 9.4 `.well-known` server discovery — Support MCP server metadata for auto-configuration.

#### C-8.2 — Instance B: Implement Tool Annotation Awareness (Priority: HIGH)
This is the highest-value, lowest-effort improvement:
- [ ] Intercept `tools/list` responses in the proxy relay path (currently passthrough)
- [ ] Extract tool annotations from each tool definition
- [ ] Store annotations per tool name in `McpProxy` state
- [ ] Make annotations available during `evaluate_tool_call()` as context
- [ ] Log tool annotations in audit entries as metadata
- [ ] Detect and alert if tool definitions change between `tools/list` calls (rug-pull detection)

**Implementation hint:** In `sentinel-mcp/src/proxy.rs`, the child-to-agent relay currently passes all responses through without inspection. Add a check: if the response is a `tools/list` result, parse and store the tool definitions.

#### C-8.3 — Instance B: Add Response Inspection (Priority: HIGH)
- [ ] Inspect tool result content flowing from child to agent
- [ ] Scan for common prompt injection patterns (e.g., "IGNORE ALL PREVIOUS INSTRUCTIONS", "system prompt", known injection prefixes)
- [ ] Configurable response inspection rules (regex patterns for suspicious content)
- [ ] Log suspicious responses in audit trail with warning level
- [ ] Option to block responses matching injection patterns (fail-safe: log-only by default)

#### C-8.4 — Instance A: Add OWASP MCP Top 10 Test Coverage
- [ ] Add integration tests for OWASP MCP01 (token/secret exposure in audit logs — already covered by redaction, add test)
- [ ] Add integration tests for OWASP MCP05 (command injection — extend parameter constraint tests)
- [ ] Add integration tests for OWASP MCP07 (auth — already covered, verify completeness)
- [ ] Add integration tests for OWASP MCP08 (audit telemetry — already covered, verify completeness)
- [ ] Document OWASP MCP Top 10 coverage matrix in tests

#### C-8.5 — Orchestrator: Competitive Positioning
- [ ] Review research report at `controller/research/mcp-spec-and-landscape.md`
- [ ] Update improvement plan with Phases 8-9
- [ ] Prioritize: Tool annotations (8.1) and response inspection (8.2) should be next after current C-7 work
- [ ] Streamable HTTP transport (Phase 9) is the single biggest market-relevance gap — plan architecture
