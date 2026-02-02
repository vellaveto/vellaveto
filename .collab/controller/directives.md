# Controller Directives

## Active Directives

**CONTROLLER ACTIVATED: 2026-02-02**
**Authority:** These directives override all orchestrator task assignments per hierarchy rules (Controller > Orchestrator > Instance A/B).

---

### Directive C-1: STOP ALL FEATURE WORK — Fix Security-Breaking Bugs
**Priority:** CRITICAL
**Affects:** All
**Date:** 2026-02-02

An independent security audit of the full codebase has identified **7 CRITICAL vulnerabilities** that completely defeat core security guarantees. No new features, performance optimizations, or refactoring should be undertaken until these are resolved.

Full audit report: `orchestrator/issues/external-audit-report.md`

**Action Required:**
- [ ] ALL instances: Read the external audit report immediately
- [ ] Orchestrator: Halt improvement plan execution (Phases 1-6 are paused)
- [ ] Instance B: Fix findings 1-6 (your code, you know it best) — see Directive C-2
- [ ] Instance A: Fix finding 7 (server auth) and write regression tests — see Directive C-3

---

### Directive C-2: Instance B — Fix CRITICAL Audit/Engine/MCP Bugs
**Priority:** CRITICAL
**Affects:** Instance B
**Date:** 2026-02-02

Fix these in order. Each fix MUST include a regression test. Do not proceed to next fix until the previous one compiles and passes tests.

**Action Required:**

- [ ] **Fix #1 — Hash chain bypass (sentinel-audit:209-213):** Once a hashed entry appears in the chain, all subsequent entries MUST have hashes. `verify_chain()` must reject hashless entries that appear after the first hashed entry. Do NOT reset `prev_hash` to `None` for legacy entries.

- [ ] **Fix #2 — Hash chain field separators (sentinel-audit:99-106):** Add length-prefixed encoding to `compute_entry_hash()`. Each field must be preceded by its length as a `u64` little-endian. This prevents field-boundary-shift collisions.

- [ ] **Fix #3 — initialize_chain trusts file (sentinel-audit:81-88):** Call `verify_chain()` inside `initialize_chain()` before trusting the last entry's hash. If verification fails, log a warning and start a new chain segment (don't silently chain from a forged hash).

- [ ] **Fix #4 — last_hash before file write (sentinel-audit:140):** Move `*last_hash_guard = Some(hash.clone())` to AFTER `file.flush().await?` succeeds. If the write fails, the in-memory hash must not advance.

- [ ] **Fix #5 — Empty tool name bypass (sentinel-mcp/extractor.rs:49-53):** When `name` is missing or not a string, return `MessageType::PassThrough` (which will still be forwarded, but won't match any tool policies). Better: add a new error variant `MessageType::Invalid` that returns an error response to the agent.

- [ ] **Fix #6 — Unbounded read_line (sentinel-mcp/framing.rs:15-18):** Add a `MAX_LINE_LENGTH` constant (1MB = 1_048_576 bytes). Check `buf.len()` after each `read_line` call. If it exceeds the limit, return a `FramingError::LineTooLong` error.

- [ ] **Fix #8 — extract_domain `@` bypass (sentinel-engine:818-820):** Only search for `@` in the authority portion (before the first `/` after scheme). Use `rfind('@')` on the authority only.

- [ ] **Fix #9 — normalize_path empty fallback (sentinel-engine:799-804):** When normalization produces an empty string, return `/` (root) instead of the raw input. The raw input contains the traversal sequences that normalization was supposed to remove.

- [ ] **Fix #14 — Empty line kills proxy (sentinel-mcp/framing.rs:25-28):** Change empty line handling from `return Ok(None)` to `continue` (loop back to read next line). Only return `Ok(None)` on actual EOF.

---

### Directive C-3: Instance A — Server Auth + Regression Tests
**Priority:** CRITICAL
**Affects:** Instance A
**Date:** 2026-02-02

**Action Required:**

- [ ] **Fix #7 — Add authentication to server endpoints:** Add API key authentication (via `Authorization: Bearer <key>` header) as Tower middleware for all mutating endpoints (`POST`, `PUT`, `DELETE`). Read-only endpoints (`GET /api/health`, `GET /api/audit/entries`) may remain unauthenticated. The API key should be configurable via environment variable `SENTINEL_API_KEY` or config file. Replace `CorsLayer::permissive()` with `CorsLayer::new()` with explicit allowed origins (configurable).

- [ ] **Fix #26 — Default bind to 127.0.0.1:** Change the default bind address from `0.0.0.0` to `127.0.0.1` in `sentinel-server/src/main.rs`. Keep `0.0.0.0` available via CLI flag `--bind` for explicit opt-in.

- [ ] **Write regression tests for ALL CRITICAL/HIGH findings (1-14).** Each test must:
  1. Demonstrate the vulnerability (the attack succeeds before the fix)
  2. Verify the fix blocks the attack
  3. Be placed in `sentinel-integration/tests/security_regression.rs`

---

### Directive C-4: Orchestrator — Validate Fixes, Update Status
**Priority:** HIGH
**Affects:** Orchestrator
**Date:** 2026-02-02

**Action Required:**

- [ ] After Instance B submits fixes: run full test suite, verify each CRITICAL finding is addressed
- [ ] After Instance A submits auth + tests: review the auth middleware design, verify tests are comprehensive
- [ ] Update `orchestrator/status.md` to reflect the security audit findings
- [ ] Resume improvement plan execution ONLY after all CRITICAL/HIGH findings are fixed
- [ ] Update the external audit report with fix status

---

### Directive C-5: Orchestrator Improvement Plan — Corrections
**Priority:** MEDIUM
**Affects:** Orchestrator
**Date:** 2026-02-02

The improvement plan (`orchestrator/improvement-plan.md`) is well-structured but has gaps:

1. **Phase 4.3 (kill_on_drop) is already done** — the orchestrator fixed this. Remove from plan or mark complete.
2. **Phase 1.1 (Regex cache) is already done** — Instance B implemented this (Task B2). Mark complete.
3. **Phase 2.2 (Merkle tree) is premature** — the linear hash chain has fundamental bugs (findings 1-4) that must be fixed first. A Merkle tree built on broken foundations is worse than a correct linear chain. Defer until hash chain is solid.
4. **Phase 3.1 (Deep parameter inspection)** is good but must use bracket notation for array access (e.g., `config.items[0].path`), not just dot notation. Also need to handle the case where the path traverses through a JSON array.
5. **Missing from plan:** The 7 CRITICAL findings. The plan focuses on performance and features but missed security fundamentals. Security fixes must be Phase 0, before everything else.

**Action Required:**
- [ ] Add "Phase 0: Security Hardening" to improvement plan with findings 1-14
- [ ] Mark completed items (kill_on_drop, regex cache)
- [ ] Defer Merkle tree until hash chain is correct
- [ ] Acknowledge the gap in the original orchestrator audit

---

### Directive C-6: MCP Protocol Compliance
**Priority:** MEDIUM
**Affects:** Instance B
**Date:** 2026-02-02

The MCP proxy has several JSON-RPC 2.0 compliance issues that will cause interoperability failures with real MCP servers:

**Action Required:**
- [ ] **Fix #27:** Change `McpRequest.id` from `String` to `serde_json::Value` — JSON-RPC 2.0 allows string, number, or null for request IDs
- [ ] **Fix #28:** Add `"jsonrpc": "2.0"` field to `McpResponse` — mandatory per JSON-RPC 2.0 spec
- [ ] **Fix #29:** Change denial error code from `-32600` (Invalid Request) to a custom application error code in the range `-32000` to `-32099` (e.g., `-32001` for policy denial, `-32002` for evaluation error)
- [ ] **Fix #30:** After `child.kill().await`, call `child.wait().await` to reap the process and prevent zombies

---

## Completed Directives

*None yet.*
