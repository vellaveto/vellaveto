# Sentinel Improvement Plan

**Author:** Orchestrator
**Date:** 2026-02-02
**Last Updated:** 2026-02-02 (post-Controller security audit)
**Based on:** Controller security audit (39 findings), deep research into MCP protocol, policy engine best practices (Cedar, OPA), tamper-evident logging (Trillian, Certificate Transparency), and Rust async patterns.

---

## Executive Summary

The Sentinel codebase is functional and well-tested (1,385 tests passing). Both instances have delivered solid features. However, the Controller's independent security audit identified **7 CRITICAL and 7 HIGH vulnerabilities** that defeat core security guarantees. This plan has been **reordered per Controller Directive C-5** to prioritize security correctness before performance optimization.

**Priority order for a security product:**
1. Security correctness — the tool actually blocks what it claims
2. Reliability — the tool doesn't crash or lose state
3. Protocol compliance — the tool works with real MCP servers
4. Performance — the tool is fast enough
5. Features — the tool does more things

---

## Phase 0: Security Hardening (CRITICAL -- Fix Immediately)

**Status: ACTIVE -- All feature work halted per Directive C-1.**

This phase addresses all 7 CRITICAL and 7 HIGH vulnerabilities found by the Controller's security audit. No other work proceeds until these are resolved.

### 0.1 Hash Chain Bypass -- Hashless Entries Accepted (CRITICAL #1)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-audit/src/lib.rs:209-213`
**Problem:** Once a hashed entry appears in the chain, all subsequent entries MUST have hashes. Currently `verify_chain()` accepts hashless entries after the chain starts, allowing an attacker to insert undetectable tampered entries.
**Fix:** `verify_chain()` must reject hashless entries that appear after the first hashed entry. Do NOT reset `prev_hash` to `None` for legacy entries.

### 0.2 Hash Chain No Field Separators (CRITICAL #2)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-audit/src/lib.rs:99-106`
**Problem:** `compute_entry_hash()` concatenates fields without separators, enabling boundary-shift collision attacks (e.g., tool="ab", function="cd" == tool="a", function="bcd").
**Fix:** Add length-prefixed encoding. Each field must be preceded by its length as `u64` little-endian.

### 0.3 initialize_chain Trusts Unverified File (CRITICAL #3)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-audit/src/lib.rs:81-88`
**Problem:** `initialize_chain()` reads the last entry from disk and trusts its hash without verifying the chain. A tampered file poisons all future entries.
**Fix:** Call `verify_chain()` inside `initialize_chain()` before trusting the last entry's hash. If verification fails, log warning and start new chain segment.

### 0.4 last_hash Updated Before File Write (CRITICAL #4)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-audit/src/lib.rs:140`
**Problem:** `*last_hash_guard = Some(hash.clone())` executes before `file.flush().await?`. If the write fails, in-memory hash diverges from disk.
**Fix:** Move hash update to AFTER `file.flush().await?` succeeds.

### 0.5 Empty Tool Name Bypasses Policy (CRITICAL #5)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-mcp/src/extractor.rs:49-53`
**Problem:** Missing `name` field creates a ToolCall with empty string that evades specific deny rules.
**Fix:** When `name` is missing or not a string, return `MessageType::PassThrough` or a new `MessageType::Invalid` variant.

### 0.6 Unbounded read_line -- OOM DoS (CRITICAL #6)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-mcp/src/framing.rs:15-18`
**Problem:** `read_line` with no limit. A single malicious message without a newline can OOM the process.
**Fix:** Add `MAX_LINE_LENGTH` constant (1MB). Check `buf.len()` after each call. Return `FramingError::LineTooLong` on violation.

### 0.7 No Authentication on Server Endpoints (CRITICAL #7)
**Assigned to:** Instance A (Directive C-3)
**File:** `sentinel-server/src/routes.rs`, `lib.rs`, `main.rs`
**Problem:** All endpoints are unauthenticated with permissive CORS. Any network-adjacent process can modify policies.
**Fix:** Add Bearer token auth as Tower middleware for mutating endpoints. Configure via `SENTINEL_API_KEY` env var or config. Replace `CorsLayer::permissive()` with explicit allowed origins.

### 0.8 extract_domain `@` Bypass (HIGH #8)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-engine/src/lib.rs:818-820`
**Problem:** `?email=user@safe.com` in a URL extracts `safe.com` instead of the actual host, bypassing domain allowlists.
**Fix:** Only search for `@` in the authority portion (before the first `/` after scheme). Use `rfind('@')` on the authority only.

### 0.9 normalize_path Empty Fallback (HIGH #9)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-engine/src/lib.rs:799-804`
**Problem:** When normalization produces an empty string, raw input is returned — containing the traversal sequences normalization was supposed to remove.
**Fix:** Return `/` (root) instead of raw input when result is empty.

### 0.10 Approval Store Persistence Is Write-Only (HIGH #10)
**Assigned to:** TBD
**Problem:** Approval state is persisted via JSONL but never reloaded on restart. All pending approvals are lost.
**Fix:** Load existing JSONL on startup, rebuild in-memory state.

### 0.11 unwrap_or_default Swallows Errors (HIGH #11)
**Assigned to:** TBD
**Problem:** 5 route handlers use `unwrap_or_default()` which silently swallows parse errors.
**Fix:** Return 400 Bad Request with error context.

### 0.12 Evaluate Not Fail-Closed on Approval Creation Failure (HIGH #12)
**Assigned to:** TBD
**Problem:** If creating an approval entry fails, the evaluate handler may not deny the request.
**Fix:** Ensure approval creation failure results in Deny verdict.

### 0.13 Audit Records Wrong Verdict for RequireApproval (HIGH #13)
**Assigned to:** TBD
**Problem:** RequireApproval decisions are logged as Deny in audit trail.
**Fix:** Record actual verdict (RequireApproval) in audit entry.

### 0.14 Empty Line Terminates Proxy (HIGH #14)
**Assigned to:** Instance B (Directive C-2)
**File:** `sentinel-mcp/src/framing.rs:25-28`
**Problem:** A blank `\n` from either agent or child terminates the proxy session.
**Fix:** Change empty line handling from `return Ok(None)` to `continue`. Only return `Ok(None)` on actual EOF.

### 0.15 Default Bind to 127.0.0.1 (HIGH — from Directive C-3)
**Assigned to:** Instance A (Directive C-3)
**File:** `sentinel-server/src/main.rs`
**Problem:** Default bind address is `0.0.0.0`, exposing the server to all interfaces.
**Fix:** Default to `127.0.0.1`. Keep `0.0.0.0` available via `--bind` flag.

### 0.16 Regression Test Suite (Required)
**Assigned to:** Instance A (Directive C-3)
**File:** `sentinel-integration/tests/security_regression.rs`
**Requirement:** Write regression tests for ALL CRITICAL/HIGH findings (1-14). Each test must demonstrate the vulnerability and verify the fix blocks it.

---

## Phase 1: Protocol Compliance (HIGH -- After Phase 0)

**Status: BLOCKED by Phase 0**

### 1.1 MCP JSON-RPC 2.0 Compliance (Directive C-6)
**Assigned to:** Instance B

- **Fix #27:** Change `McpRequest.id` from `String` to `serde_json::Value` (JSON-RPC 2.0 allows string, number, or null)
- **Fix #28:** Add `"jsonrpc": "2.0"` field to `McpResponse` (mandatory per spec)
- **Fix #29:** Change denial error code from `-32600` to custom app error in `-32000` to `-32099` range
- **Fix #30:** After `child.kill().await`, call `child.wait().await` to reap the process

---

## Phase 2: Performance Hot Path (MEDIUM -- After Security Is Correct)

**Status: BLOCKED by Phase 0**

### 2.1 Cache Compiled Regex Patterns -- COMPLETE
Instance B implemented bounded HashMap cache (max 1000 entries) in Task B2.

### 2.2 Replace `glob` with `globset` for Multi-Pattern Matching
**Assigned to:** Instance B
**Problem:** The `glob` crate compiles patterns on every call. `globset` pre-compiles and uses Aho-Corasick internally.
**Solution:** Replace `glob = "0.3"` with `globset = "0.4"` in `sentinel-engine/Cargo.toml`. Refactor `eval_glob_constraint()` and `eval_not_glob_constraint()`.
**Impact:** 10-100x speedup for glob matching

### 2.3 Pre-Sort Policies Once, Not Per Evaluation
**Assigned to:** Instance B
**Problem:** `evaluate_action()` sorts policies on every call — O(n log n) per request.
**Solution:** Sort once at load/reload time. Store pre-sorted `Vec<Policy>`.

---

## Phase 3: Audit Hardening (MEDIUM -- After Security Is Correct)

**Status: BLOCKED by Phase 0 (hash chain must be correct first)**

### 3.1 Decouple Audit Logging from Request Path
**Problem:** Audit logging is in the evaluate handler's hot path. File I/O adds 5-10ms to P99.
**Solution:** Use `tokio::sync::mpsc` channel to background writer task.
**Impact:** Reduces P99 evaluate latency by 5-10ms

### 3.2 Merkle Tree for O(log n) Verification -- DEFERRED
**Reason for deferral:** Per Controller Directive C-5, the linear hash chain has fundamental bugs (findings 1-4) that must be fixed first. A Merkle tree built on broken foundations is worse than a correct linear chain. Resume this item ONLY after Phase 0 hash chain fixes are verified.

### 3.3 Sensitive Value Redaction in Audit Logs
**Problem:** Full Action parameters (potentially containing API keys, passwords) are logged.
**Solution:** Configurable redaction for known-sensitive patterns (`sk-`, `AKIA`, `ghp_`) and parameter names (`password`, `secret`, `token`).

---

## Phase 4: Security Depth (MEDIUM -- Parallel with Phase 3)

### 4.1 Deep Parameter Inspection (JSON Path Traversal) -- COMPLETE
Instance B implemented `get_param_by_path()` with dot-separated JSON path traversal. 9 constraint operators working.
**Note per Controller:** Must also support bracket notation for array access (e.g., `config.items[0].path`) and handle JSON array traversal.

### 4.2 Unicode/Encoding Normalization for Paths
**Problem:** `normalize_path()` handles `..` and `.` but not percent-encoding or Unicode tricks.
**Solution:** Add percent-decoding and NFC normalization before path component resolution.

### 4.3 Recursive Parameter Scanning
**Problem:** All string values in parameters should be scanned for dangerous content beyond explicit constraints.
**Solution:** Add `scan_all_values` mode that recursively walks all string values.

---

## Phase 5: MCP Proxy Hardening (MEDIUM)

### 5.1 Request ID Tracking and Timeout
**Problem:** Proxy doesn't track pending request IDs. Hanging child servers block indefinitely.
**Solution:** `HashMap<Value, Instant>` with configurable timeout (30s default).

### 5.2 Resource Read Interception
**Problem:** Proxy only intercepts `tools/call`. `resources/read` can also access files/URIs.
**Solution:** Extend `classify_message()` to recognize `resources/read` and evaluate URI.

### 5.3 `kill_on_drop` for Child Process -- COMPLETE
Orchestrator added `.kill_on_drop(true)` to `sentinel-proxy/src/main.rs`.

---

## Phase 6: Architecture Improvements (LOW -- Future)

### 6.1 Lock-Free Policy Reads with `arc-swap`
**Problem:** `tokio::sync::RwLock` has scheduler overhead even uncontended.
**Solution:** Use `arc-swap` for lock-free reads.

### 6.2 Session-Aware Evaluation
**Problem:** Stateless evaluation can't detect multi-step attack patterns.
**Solution:** `SessionContext` tracking recent calls per session.

### 6.3 Rate Limiting per Tool
**Solution:** Per-tool rate limits as Tower middleware.

---

## Phase 7: Testing & Observability (Ongoing)

### 7.1 Property-Based Tests with `proptest`
Test critical invariants: deterministic evaluation, fail-closed, path normalization idempotency.

### 7.2 Performance Benchmarks with `criterion`
Benchmark evaluation at scale, regex cache, glob matching, audit throughput.

### 7.3 Structured Logging with `tracing`
Ensure all decisions are traced with structured fields.

---

## Dependency Budget

| Phase | Crate | Size | Purpose |
|-------|-------|------|---------|
| 2.2 | `globset` (replaces `glob`) | Small | Multi-pattern glob matching |
| 4.2 | `percent-encoding` | Tiny | URL decoding for paths |
| 4.2 | `unicode-normalization` | Small | NFC normalization |
| 6.1 | `arc-swap` | Tiny | Lock-free reads |
| 7.1 | `proptest` (dev only) | Medium | Property-based testing |
| 7.2 | `criterion` (dev only) | Medium | Benchmarking |

Total new runtime dependencies: 3-4 small crates. Acceptable.

---

## Completed Items Summary

| Item | Completed By | Phase |
|------|-------------|-------|
| Regex cache (bounded HashMap, max 1000) | Instance B | 2.1 |
| Deep parameter inspection (JSON path) | Instance B | 4.1 |
| `kill_on_drop(true)` on child process | Orchestrator | 5.3 |
| `is_sorted` deny-override bug fix | Orchestrator | (security) |
| unwrap() removal in library code | Orchestrator | (quality) |

---

*This plan will be updated as security fixes are validated.*
