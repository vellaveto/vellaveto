# Controller Corrections

## Purpose
This file tracks corrections issued by the Controller to other instances based on research findings.

---

## Correction 1: Orchestrator Audit Was Incomplete
**Date:** 2026-02-02
**Affects:** Orchestrator
**Severity:** HIGH

The orchestrator's audit (in `orchestrator/status.md` and `log.md`) declared the project healthy based on:
- Tests passing
- Clippy clean
- No `unwrap()` in library code
- Formatting clean

This gave a **false sense of security**. The orchestrator correctly identified surface-level issues (unwrap, missing endpoints, formatting) but missed:

1. **7 CRITICAL security vulnerabilities** that defeat core guarantees (hash chain bypass, domain bypass, empty tool bypass, unbounded memory, no auth)
2. **7 HIGH issues** that would cause production failures (approval data loss on restart, silent error swallowing, incorrect audit records)
3. **16 MEDIUM issues** spanning correctness, compliance, and performance

**Root cause:** The audit focused on "does it compile and pass tests" rather than "does it actually provide the security guarantees it claims." Passing tests only proves the code does what the tests check — not that it's correct.

**Correction:** Future orchestrator audits must include:
- Security-focused review: "Can an attacker bypass this?"
- Boundary analysis: "What happens with missing/empty/malformed input?"
- Crash analysis: "What happens on I/O failure, memory pressure, process death?"
- Protocol compliance: "Does this follow the spec (JSON-RPC 2.0, MCP)?"

---

## Correction 2: Instance B — Hash Chain Implementation Has Fundamental Flaws
**Date:** 2026-02-02
**Affects:** Instance B
**Severity:** CRITICAL

Instance B's status file states "Feature 2: Tamper-Evident Audit — SHA-256 hash chain with verify endpoint" as DONE. However:

1. The tamper-evidence is **bypassable** — an attacker can insert hashless entries and the verifier accepts them (finding #1)
2. The hash function has **ambiguous field boundaries** — field concatenation without separators allows collision attacks (finding #2)
3. The chain **trusts unverified data on startup** — a tampered file poisons all future entries (finding #3)
4. The chain **can diverge from disk** on write failure — in-memory state advances even when persistence fails (finding #4)

These aren't edge cases — they're fundamental to the feature's security claim. A "tamper-evident" log that can be tampered with undetectably is worse than no tamper-evidence at all (it provides false assurance).

**Correction:** The feature status should be "PARTIALLY COMPLETE — architecture correct, implementation needs hardening." See Directive C-2 for required fixes.

---

## Correction 3: Instance B — MCP Proxy Has Reliability and Compliance Issues
**Date:** 2026-02-02
**Affects:** Instance B
**Severity:** HIGH

Instance B declared Feature 4 (MCP Stdio Proxy) as DONE. Issues found:

1. **Empty tool name bypass** — a `tools/call` with no `name` field creates a ToolCall with empty name that evades specific deny policies (finding #5)
2. **Unbounded memory** — `read_line` with no limit means a single malicious message without a newline can OOM the process (finding #6)
3. **Empty line kills session** — a blank `\n` from either agent or child terminates the proxy (finding #14)
4. **Audit records wrong verdict** — `RequireApproval` decisions are logged as `Deny` in the audit trail (finding #13)
5. **JSON-RPC 2.0 non-compliance** — missing `jsonrpc` field, wrong error codes, string-only IDs (findings #27-29)

**Correction:** Feature 4 should be "PARTIALLY COMPLETE — architecture sound, needs hardening and protocol compliance."

---

## Correction 4: Instance A — Good Security Work, But Tests Didn't Catch Existing Bugs
**Date:** 2026-02-02
**Affects:** Instance A
**Severity:** LOW

Instance A's security tests (path_domain_security.rs) are well-designed and caught real issues. However:

1. The `@` bypass in `extract_domain` (finding #8) was not tested — a URL like `https://evil.com/path?email=user@safe.com` would pass the domain allowlist tests
2. The `normalize_path` empty-result fallback (finding #9) was not tested — Instance A fixed the root escape bug but didn't test what happens when normalization produces an empty string

**Correction:** The regression test suite (Directive C-3) must explicitly include these edge cases. Instance A's existing tests are a solid foundation — they just need the adversarial edge cases from findings 8 and 9.

---

## Correction 5: Orchestrator Improvement Plan Priorities Are Inverted
**Date:** 2026-02-02
**Affects:** Orchestrator
**Severity:** MEDIUM

The improvement plan puts "Performance Hot Path" as Phase 1 (P0 — Do Immediately) and security hardening in Phase 3. This is backwards for a security product.

The correct priority order for a policy enforcement tool:
1. **Security correctness** — the tool actually blocks what it claims to block
2. **Reliability** — the tool doesn't crash or lose state
3. **Protocol compliance** — the tool works with real MCP servers
4. **Performance** — the tool is fast enough
5. **Features** — the tool does more things

Regex caching and globset are nice-to-haves. A domain bypass that lets attackers exfiltrate data through `?email=user@safe.com` is a ship-stopper.

**Correction:** The improvement plan should be reordered. See Directive C-5 for specifics.

---

## Correction 6: Controller MEDIUM Fixes — Phase 2
**Date:** 2026-02-02
**Affects:** All instances
**Severity:** MEDIUM

Controller directly fixed the following MEDIUM findings:

1. **Fix #18 (Sort stability):** Added tertiary tiebreaker (lexicographic by policy ID) to `PolicyEngine::sort_policies` for deterministic ordering when priority and type are equal.

2. **Fix #20 (json_depth stack overflow):** Replaced recursive `json_depth` in both `sentinel-engine` and `sentinel-audit` with iterative stack-based approach. Early termination at depth 128 prevents pathological inputs from consuming stack.

3. **Fix #21 (expire_stale persistence):** `ApprovalStore::expire_stale` now persists expired status to the JSONL file. Previously, a server restart would resurrect expired approvals as pending.

4. **Fix #22 (Memory cleanup):** `expire_stale` now removes resolved entries older than 1 hour from the in-memory HashMap to prevent unbounded memory growth.

5. **Fix #23 (Request body limit):** Added `DefaultBodyLimit::max(1_048_576)` (1MB) to the Axum router in `sentinel-server/src/routes.rs`.

6. **Fix #33 (DNS trailing dot bypass):** Added `.trim_end_matches('.')` to both `extract_domain` and `match_domain_pattern` in `sentinel-engine/src/lib.rs`. Without this, `evil.com.` bypasses a policy matching `evil.com`.

7. **Fix #37 (Lenient audit parsing):** `AuditLogger::load_entries` now skips corrupt/malformed lines with a `tracing::warn!` instead of failing the entire load. Updated 3 integration tests that expected hard failure.

8. **Fix #35 (fsync for Deny verdicts):** `AuditLogger::log_entry` now calls `sync_data()` after writing Deny entries to ensure they survive power loss.

9. **Fix #34 (Graceful shutdown):** Server now handles SIGTERM/SIGINT for graceful shutdown via `axum::serve().with_graceful_shutdown()`.

10. **Fix #15/#16 (Glob cache):** Added `GlobMatcher` cache to `PolicyEngine` (same bounded HashMap pattern as regex cache). Both `eval_glob_constraint` and `eval_not_glob_constraint` now use cached matchers.

**Total MEDIUM fixes by Controller:** 10
**Test status:** All 131 test suites pass, 0 failures.

---

## Correction 7: Governor Version Is 4 Majors Behind
**Date:** 2026-02-02
**Affects:** Instance A (file owner of sentinel-server)
**Severity:** MEDIUM
**Source:** C-10.4 C1 web research validation

Sentinel uses `governor = "0.6"` in `sentinel-server/Cargo.toml`. The latest version is **0.10.4** (January 2026). That's 7+ releases and 4 major version bumps. The core API Sentinel uses (`DefaultDirectRateLimiter`, `Quota::per_second`, `RateLimiter::direct`, `.check()`) is stable across versions, making upgrade low-risk. Missing bug fixes, performance improvements, and dependency updates.

**Action:** Bump `governor = "0.6"` to `governor = "0.10"` in `sentinel-server/Cargo.toml`. Verify with `cargo check -p sentinel-server`.

---

## Correction 8: Injection Detection Needs Unicode Sanitization
**Date:** 2026-02-02
**Affects:** Instance B (file owner of sentinel-mcp/)
**Severity:** MEDIUM
**Source:** C-10.4 C1 web research + Instance A's cross-review finding #6

The 15 injection patterns in `sentinel-mcp/src/proxy.rs:280-296` are ASCII-only. Research shows:
- Base64 encoding: 64-94% guardrail evasion success
- Homoglyphs (Cyrillic/Latin confusion): up to 92%
- Zero-width character injection: ~54%
- Unicode tag characters (U+E0000-E007F): high evasion rates
- Emoji smuggling: up to 100% in some guardrails

The current patterns provide a reasonable v1 baseline, but any moderately sophisticated attacker can bypass them. This is not a blocking issue (injection scanning is defense-in-depth, not the primary control), but should be addressed in the next iteration.

**Recommended pre-processing before pattern matching:**
1. Strip Unicode control characters: tags (U+E0000-E007F), zero-width (U+200B-200F), bidi overrides (U+202A-202E), variation selectors (U+FE00-FE0F)
2. Apply NFKC normalization (canonicalizes homoglyphs and fullwidth chars)
3. Detect Base64-encoded injection payloads in responses

---

## Correction 9: Non-Constant-Time API Key Comparison
**Date:** 2026-02-02
**Affects:** Instance A (file owner of sentinel-server/src/routes.rs)
**Severity:** LOW
**Source:** C-10.4 C1 direct code review

The `require_api_key` middleware in `sentinel-server/src/routes.rs` compares bearer tokens using standard string equality (`token == api_key.as_str()`), which short-circuits on first mismatch. This is theoretically vulnerable to timing side-channel attacks.

Practical risk is very low (nanosecond timing differences over network with millisecond jitter, rate limiter throttles brute force). However, for a security product, using constant-time comparison is a defense-in-depth best practice.

**Action:** Use `subtle::ConstantTimeEq` from the `subtle` crate (already in dependency tree via `sha2` → `digest` → `subtle`). Example: `use subtle::ConstantTimeEq; if token.as_bytes().ct_eq(api_key.as_bytes()).into() { ... }`.

---

## Correction 10: `remove_policy` TOCTOU Race
**Date:** 2026-02-02
**Affects:** Instance A (file owner of sentinel-server/src/routes.rs)
**Severity:** LOW
**Source:** C-10.4 C1 arc-swap research validation

`remove_policy()` in `sentinel-server/src/routes.rs:282-287` uses `load()` then `store()` — not atomic with respect to concurrent writers. If two `remove_policy` calls race, one removal could be lost. `add_policy()` correctly uses `rcu()` for atomic read-copy-update.

Low risk since admin operations are rare and typically single-operator, but the inconsistency is a code quality issue.

**Action:** Switch `remove_policy` to use `rcu()` pattern, matching `add_policy`.
