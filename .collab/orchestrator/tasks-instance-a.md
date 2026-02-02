# Tasks for Instance A — Directive C-8 (OWASP Coverage) + Remaining

## READ THIS FIRST

Controller Directive C-8 is active. Finish any in-progress C-7 work, then proceed to C-8.4.

Update `.collab/instance-a.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (previous work)
- CI workflow, integration tests, approval flow tests
- S-A1 (auth), S-A2 (bind address)
- Fixed compile breaks from Instance B changes

---

## Task C7-A1: Finish C-7 Items (if incomplete)
**Priority: HIGH**

- [ ] Fix #31 — Rate limiting (if not done)
- [ ] Property-based tests with proptest (I-A1)

---

## Task C8-A1: OWASP MCP Top 10 Test Coverage Matrix (Phase 8)
**Priority: HIGH**
**Directive:** C-8.4

Create a test suite mapping to the OWASP MCP Top 10 risks.

**Implementation:**
1. Create `sentinel-integration/tests/owasp_mcp_top10.rs`
2. Add tests for each OWASP risk where Sentinel has coverage:

| OWASP Risk | Coverage | Test |
|------------|----------|------|
| MCP01 Token Mismanagement | GOOD (redaction) | Verify secrets redacted in audit |
| MCP02 Tool Access Control | GOOD (policy engine) | Verify deny rules enforced |
| MCP03 Tool Poisoning | PARTIAL (C8-B1 adds detection) | Verify tool definition change detection |
| MCP04 Privilege Escalation | GOOD (priority deny-override) | Verify deny overrides allow |
| MCP05 Command Injection | GOOD (param constraints) | Verify injection blocked by constraints |
| MCP06 Prompt Injection | PARTIAL (C8-B2 adds detection) | Verify response inspection |
| MCP07 Auth | GOOD (Bearer token) | Verify auth on mutating endpoints |
| MCP08 Audit & Telemetry | EXCELLENT (tamper-evident) | Verify hash chain + rotation |
| MCP09 Insufficient Logging | GOOD (comprehensive audit) | Verify all verdicts logged |
| MCP10 Denial of Service | GOOD (line limits, body limits, rate limiting) | Verify DoS protections |

3. Document coverage gaps (MCP03 partial, MCP06 partial) with TODO comments
4. Each test should reference the OWASP risk ID in its name (e.g., `test_owasp_mcp01_token_not_in_audit`)

**Files:** `sentinel-integration/tests/owasp_mcp_top10.rs`

---

## Task I-A2: Criterion Benchmarks (Phase 7.2)
**Priority: MEDIUM**

Create benchmarks to validate <5ms evaluation target. See previous task file for details.

---

## Task I-A3: Structured Logging with `tracing` (Phase 7.3)
**Priority: MEDIUM**

Add tracing spans/events at key decision points. See previous task file for details.

---

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `.github/`, `sentinel-integration/tests/`, TASKS.md
4. Coordinate with Instance B for C8-B1/B2 tests (MCP03, MCP06 tests depend on their implementation)
5. Work order: C7 items first, then C8-A1, then I-A2/I-A3
