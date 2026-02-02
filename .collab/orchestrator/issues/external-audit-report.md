# External Security Audit Report — Sentinel Project

**Auditor:** External review instance (Opus 4.5)
**Date:** 2026-02-02
**Scope:** Full codebase review of all work by Instance A, Instance B, and Orchestrator
**Method:** 5 parallel audit agents + direct code review + best practices research

---

## Build Status: PASS

- `cargo check --workspace` -- clean
- `cargo test --workspace` -- ALL PASS (214+ tests, 0 failures)
- `cargo clippy --workspace --all-targets` -- clean (0 warnings)
- `cargo fmt --all -- --check` -- PASS
- No `unsafe` code found
- No `unwrap()` in library (non-test) code (the orchestrator's fix for line 294 was effective)

---

## CRITICAL FINDINGS (Fix Before Any Deployment)

### 1. Hash Chain Tamper-Evidence Is Bypassable (sentinel-audit)

**Location:** `sentinel-audit/src/lib.rs:209-213`
**Owner:** Instance B

The `verify_chain()` function silently skips any entry whose `entry_hash` is `None` and resets `prev_hash` to `None`. This means an attacker who can modify the log file can:
- **Insert arbitrary entries** by omitting the `entry_hash` field
- **Delete entries** by inserting a hashless "legacy bridge" entry between chain segments
- The entire tamper-evidence guarantee is defeated

**Fix:** Once the first hashed entry appears, all subsequent entries MUST have hashes. Flag hashless entries after the transition as invalid.

### 2. Hash Chain Has No Field Separators (sentinel-audit)

**Location:** `sentinel-audit/src/lib.rs:99-106`
**Owner:** Instance B

Hash input is `SHA256(id || action_json || verdict_json || timestamp || metadata_json || prev_hash)` with fields directly concatenated. This allows hash collisions where field boundaries shift (e.g., `id="abc"` + `action="def..."` hashes the same as `id="abcd"` + `action="ef..."`).

**Fix:** Use length-prefixed encoding for each field before hashing:
```rust
fn hash_field(hasher: &mut Sha256, data: &[u8]) {
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
}
```

### 3. `initialize_chain` Trusts File Without Verification (sentinel-audit)

**Location:** `sentinel-audit/src/lib.rs:81-88`
**Owner:** Instance B

The method reads the last entry's `entry_hash` from disk and uses it as the chain head without verifying the chain. If the file was tampered with, the logger chains from a falsified hash.

**Fix:** Call `verify_chain()` inside `initialize_chain()`, or at minimum recompute the last entry's hash.

### 4. `last_hash` Updated Before File Write (sentinel-audit)

**Location:** `sentinel-audit/src/lib.rs:140` (before lines 146-166)
**Owner:** Instance B

If the file write fails after the in-memory `last_hash` is updated, the chain head diverges from disk. The next successful write chains from a hash that was never persisted.

**Fix:** Move `*last_hash_guard = Some(hash)` to AFTER `file.flush().await?`.

### 5. Empty Tool Name Bypasses Policy (sentinel-mcp)

**Location:** `sentinel-mcp/src/extractor.rs:49-53`
**Owner:** Instance B

A `tools/call` with missing/non-string `name` creates a `ToolCall` with empty tool name. This passes through most specific deny policies (like `"bash:*"`). Must reject as invalid.

**Fix:** Return `PassThrough` or a new error variant when tool name is missing/empty.

### 6. Unbounded `read_line` in Framing (sentinel-mcp)

**Location:** `sentinel-mcp/src/framing.rs:15-18`
**Owner:** Instance B

No limit on line length. A malicious stream without newlines causes unbounded memory allocation (OOM DoS).

**Fix:** Add a maximum line length check (e.g., 1MB) before accumulating.

### 7. No Authentication on Server Endpoints (sentinel-server)

**Location:** `sentinel-server/src/routes.rs:16-34`
**Owner:** Instance B

All endpoints including `approve_approval`, `deny_approval`, `add_policy`, `remove_policy` are completely unauthenticated. Combined with `CorsLayer::permissive()` (line 32), any webpage can manipulate the policy engine.

**Fix:** Add authentication middleware (API key/bearer token) for all mutating endpoints. Replace `CorsLayer::permissive()` with explicit origin allowlist. Default bind to `127.0.0.1` instead of `0.0.0.0`.

---

## HIGH FINDINGS (Fix Before Production)

### 8. `extract_domain` `@` Bypass (sentinel-engine)

**Location:** `sentinel-engine/src/lib.rs:818-820`
**Owner:** Instance B

`find('@')` matches `@` in query parameters, not just userinfo. URL `https://evil.com/path?email=user@safe.com` extracts domain as `safe.com` instead of `evil.com`, completely bypassing domain allowlists.

**Fix:** Only search for `@` in the authority portion (before the first `/`):
```rust
let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
let host_part = if let Some(pos) = authority.rfind('@') { &authority[pos + 1..] } else { authority };
```

### 9. `normalize_path` Returns Raw Input on Empty Result (sentinel-engine)

**Location:** `sentinel-engine/src/lib.rs:799-804`
**Owner:** Instance B

When normalization produces an empty path, the function falls back to returning the raw unnormalized input, defeating path traversal prevention.

**Fix:** Return an empty string consistently, or deny outright.

### 10. Approval Store Persistence Is Write-Only (sentinel-approval)

**Location:** `sentinel-approval/src/lib.rs` (entire crate)
**Owner:** Instance B

The store persists every state change to JSONL but has NO `load_from_disk()` method. After restart, all pending approvals are lost. The persistence file is never read back.

**Fix:** Implement `load_from_file()` that reconstructs state from JSONL (deduplicate by ID, last-writer-wins).

### 11. `unwrap_or_default()` Silently Swallows Errors (sentinel-server)

**Location:** `sentinel-server/src/routes.rs:203, 219, 242, 283, 310`
**Owner:** Instance B

Five handlers use `serde_json::to_value(...).unwrap_or_default()`, returning `null` with HTTP 200 on serialization failure. For `audit_verify`, this means a failed verification could appear as success.

**Fix:** Replace with proper error mapping that returns HTTP 500.

### 12. Evaluate Handler Not Fail-Closed on Approval Creation Failure (sentinel-server)

**Location:** `sentinel-server/src/routes.rs:82-93`
**Owner:** Instance B

When `RequireApproval` verdict fires but approval creation fails, the handler returns `RequireApproval` with `approval_id: null`. Should fail closed (return error or deny).

### 13. Audit Always Records Deny for Blocked MCP Calls (sentinel-mcp)

**Location:** `sentinel-mcp/src/proxy.rs:118-134`
**Owner:** Instance B

Proxy audit logging always records `Verdict::Deny` even when the actual decision was `RequireApproval`. Audit trail is inaccurate.

### 14. Empty Line Terminates Proxy Session (sentinel-mcp)

**Location:** `sentinel-mcp/src/framing.rs:25-28`
**Owner:** Instance B

Empty lines return `Ok(None)` (same as EOF), which causes the proxy to shut down. A single blank `\n` from agent or child kills the session.

**Fix:** Skip empty lines (loop/continue) instead of returning None.

---

## MEDIUM FINDINGS

| # | Finding | Location | Owner |
|---|---------|----------|-------|
| 15 | Regex cache clears all 1000 entries at once (burst latency) | engine:886-888 | B |
| 16 | Glob patterns compiled on every call (no cache like regex) | engine:395-398 | B |
| 17 | `conditions.to_string().len()` allocates full JSON for size check | engine:157-158 | B |
| 18 | Sort stability: equal-priority same-type policies need tertiary tiebreaker | engine:67-77 | B |
| 19 | `to_string_lossy()` silently corrupts non-UTF8 paths | engine:799 | B |
| 20 | `json_depth` recursive with no early termination | engine:912-922 | B |
| 21 | `expire_stale` doesn't persist expiration status | approval:166-179 | B |
| 22 | Resolved approvals never removed from memory (leak) | approval:166-179 | B |
| 23 | No request body size limit on server endpoints | routes.rs | B |
| 24 | No pagination on audit entries or pending approvals endpoints | routes.rs:174,224 | B |
| 25 | `resolved_by` is self-reported (no identity verification) | routes.rs:245-253 | B |
| 26 | Server binds to 0.0.0.0 by default | main.rs:130 | B |
| 27 | MCP `McpRequest.id` typed as String (rejects integer IDs) | mcp/lib.rs:27 | B |
| 28 | MCP `McpResponse` missing `"jsonrpc": "2.0"` field | mcp/lib.rs:32-37 | B |
| 29 | Denial response uses `-32600` (Invalid Request) instead of app error code | extractor.rs:81-90 | B |
| 30 | Child process not reaped after kill (zombie risk) | proxy main.rs | B |

---

## LOW FINDINGS

| # | Finding | Location |
|---|---------|----------|
| 31 | `*.example.com` matches multi-level subdomains (unexpected) | engine:851-861 |
| 32 | `match_domain_pattern` allocates `format!` string per check | engine:857 |
| 33 | `extract_domain` doesn't strip trailing dots | engine:810-848 |
| 34 | IPv6 addresses extracted with brackets | engine:833-835 |
| 35 | `anyhow` dependency unused in sentinel-engine | engine Cargo.toml:11 |
| 36 | Audit `flush()` doesn't guarantee durability (need `sync_data()`) | audit:165-166 |
| 37 | Single corrupt audit line makes entire log unreadable | audit:179-188 |
| 38 | `relay_handle.abort()` without graceful drain | proxy.rs:172 |
| 39 | Audit metadata includes full parameters (may contain secrets) | proxy.rs:128 |

---

## WHAT THE ORCHESTRATOR GOT RIGHT

The orchestrator's original audit was solid:
- Correctly identified the `unwrap()` on line 294 (now fixed)
- Correctly identified missing approval endpoints (now wired)
- Correctly identified regex compilation performance issue (now cached)
- Correctly assigned file ownership and prevented conflicts
- Formatting issues were addressed

However, the orchestrator missed the deeper security issues listed above. The claim "Build Status: PASS" and "What's Working" section gave a false sense of security.

## WHAT INSTANCE A GOT RIGHT

- The `normalize_path()` root escape bug fix was critical and correct
- The 66 unit tests significantly improved coverage
- The security integration tests (path_domain_security.rs) were well-designed
- The security finding about narrow globs was valid and documented

## WHAT INSTANCE B GOT RIGHT

- Fail-closed default semantics are correctly implemented everywhere
- All 9 constraint operators are logically sound
- The hash chain concept is architecturally correct (implementation needs hardening)
- The approval state machine correctly rejects double-approve and expired
- MCP proxy architecture (bidirectional, separate relay task) is sound
- No `unwrap()` in library code after orchestrator fix

## RECOMMENDATIONS FOR ORCHESTRATOR

### Immediate (assign to workers):
1. Fix items 1-7 (CRITICAL) -- these are security-breaking
2. Fix item 8 (domain `@` bypass) -- exploitable in production
3. Fix item 14 (empty line kills proxy) -- reliability issue

### Short-term:
4. Fix items 9-13 (HIGH) -- needed for production readiness
5. Add authentication middleware to server
6. Implement approval store reload from disk

### Task Assignment Suggestion:
- **Instance B** should fix: 1-6 (audit/engine/mcp -- their code, they know it best)
- **Instance A** should fix: 7 (server auth -- .github/ and server ownership overlap)
- **Instance A** should write: regression tests for every CRITICAL/HIGH finding

---

*External audit complete. 39 findings total: 7 CRITICAL, 7 HIGH, 16 MEDIUM, 9 LOW.*
