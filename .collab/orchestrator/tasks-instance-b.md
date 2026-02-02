# Tasks for Instance B

## READ THIS FIRST

**CONTROLLER DIRECTIVE C-1 IS ACTIVE: All feature work is halted. Security fixes only.**

Check `controller/directives.md` for full details. These tasks implement **Directives C-2 and C-6**.

Fix in order. Each fix MUST include a regression test. Do not proceed to next fix until the previous one compiles and passes tests.

Update `.collab/instance-b.md` after each task.

---

## COMPLETED TASKS (for reference)
- [x] Feature 1: Parameter-Aware Firewall (9 operators, path/domain) -- DONE
- [x] Feature 2: Tamper-Evident Audit (hash chain, verify) -- DONE (needs hardening)
- [x] Feature 3: Approval Backend (CRUD, expiry, persistence) -- DONE
- [x] Feature 4: MCP Stdio Proxy (framing, extractor, proxy bridge) -- DONE (needs hardening)
- [x] Feature 5: Canonical Disconnect Fix -- DONE
- [x] Task B2: Regex cache (bounded HashMap) -- DONE

---

## ACTIVE SECURITY TASKS (Directive C-2) — Fix In Order

### Task S-B1: Hash Chain Bypass — Hashless Entries Accepted (CRITICAL #1)
**Priority: CRITICAL**
**File:** `sentinel-audit/src/lib.rs:209-213`

Once a hashed entry appears in the chain, all subsequent entries MUST have hashes. `verify_chain()` must reject hashless entries that appear after the first hashed entry. Do NOT reset `prev_hash` to `None` for legacy entries.

**Regression test:** Create a chain with [hashed, hashless, hashed] and verify `verify_chain()` returns error on the hashless entry.

---

### Task S-B2: Hash Chain No Field Separators (CRITICAL #2)
**Priority: CRITICAL**
**File:** `sentinel-audit/src/lib.rs:99-106`

Add length-prefixed encoding to `compute_entry_hash()`. Each field must be preceded by its length as `u64` little-endian. This prevents field-boundary-shift collisions.

**Regression test:** Create two entries where field concatenation would be identical (e.g., tool="ab" fn="cd" vs tool="a" fn="bcd"). Verify they produce different hashes.

---

### Task S-B3: initialize_chain Trusts Unverified File (CRITICAL #3)
**Priority: CRITICAL**
**File:** `sentinel-audit/src/lib.rs:81-88`

Call `verify_chain()` inside `initialize_chain()` before trusting the last entry's hash. If verification fails, log a warning and start a new chain segment (don't silently chain from a forged hash).

**Regression test:** Create a tampered audit file, call `initialize_chain()`, verify it detects the tampering and starts fresh.

---

### Task S-B4: last_hash Updated Before File Write (CRITICAL #4)
**Priority: CRITICAL**
**File:** `sentinel-audit/src/lib.rs:140`

Move `*last_hash_guard = Some(hash.clone())` to AFTER `file.flush().await?` succeeds. If the write fails, the in-memory hash must not advance.

**Regression test:** Simulate write failure (read-only file or full disk mock), verify `last_hash` hasn't changed.

---

### Task S-B5: Empty Tool Name Bypasses Policy (CRITICAL #5)
**Priority: CRITICAL**
**File:** `sentinel-mcp/src/extractor.rs:49-53`

When `name` is missing or not a string, return `MessageType::PassThrough` (better: add `MessageType::Invalid` variant that returns error response to agent).

**Regression test:** Send `tools/call` with no `name` field, verify it's classified as PassThrough or Invalid (not as a ToolCall with empty name).

---

### Task S-B6: Unbounded read_line — OOM DoS (CRITICAL #6)
**Priority: CRITICAL**
**File:** `sentinel-mcp/src/framing.rs:15-18`

Add `MAX_LINE_LENGTH` constant (1MB = 1_048_576 bytes). Check `buf.len()` after each `read_line` call. If exceeded, return `FramingError::LineTooLong`.

**Regression test:** Feed a message larger than 1MB without newline, verify `LineTooLong` error returned.

---

### Task S-B7: extract_domain `@` Bypass (HIGH #8)
**Priority: HIGH**
**File:** `sentinel-engine/src/lib.rs:818-820`

Only search for `@` in the authority portion (before the first `/` after scheme). Use `rfind('@')` on the authority only. A URL like `https://evil.com/path?email=user@safe.com` must extract `evil.com`, not `safe.com`.

**Regression test:** Test `extract_domain("https://evil.com/path?email=user@safe.com")` returns `evil.com`.

---

### Task S-B8: normalize_path Empty Fallback (HIGH #9)
**Priority: HIGH**
**File:** `sentinel-engine/src/lib.rs:799-804`

When normalization produces an empty string, return `/` (root) instead of the raw input. The raw input contains the traversal sequences that normalization was supposed to remove.

**Regression test:** `normalize_path("/../../../")` returns `/`, not `/../../../`.

---

### Task S-B9: Empty Line Terminates Proxy (HIGH #14)
**Priority: HIGH**
**File:** `sentinel-mcp/src/framing.rs:25-28`

Change empty line handling from `return Ok(None)` to `continue` (loop back to read next line). Only return `Ok(None)` on actual EOF.

**Regression test:** Send `\n\n{"jsonrpc":"2.0",...}\n` — verify the JSON message is read successfully despite leading blank lines.

---

## PROTOCOL COMPLIANCE TASKS (Directive C-6) — After Security Fixes

### Task P-B1: McpRequest.id Type (MEDIUM #27)
Change `McpRequest.id` from `String` to `serde_json::Value` — JSON-RPC 2.0 allows string, number, or null for request IDs.

### Task P-B2: Add jsonrpc Field to McpResponse (MEDIUM #28)
Add `"jsonrpc": "2.0"` field to `McpResponse` — mandatory per JSON-RPC 2.0 spec.

### Task P-B3: Denial Error Code (MEDIUM #29)
Change denial error code from `-32600` (Invalid Request) to custom application error in `-32000` to `-32099` range (e.g., `-32001` for policy denial, `-32002` for evaluation error).

### Task P-B4: Reap Child Process (MEDIUM #30)
After `child.kill().await`, call `child.wait().await` to reap the process and prevent zombies.

---

## PAUSED TASKS (Resume after Phase 0 complete)

These tasks from the improvement plan are ON HOLD per Directive C-1:

- ~~Task B4: Replace glob with globset~~ — resume as Phase 2 work
- ~~Task B5: Pre-sort policies at load time~~ — resume as Phase 2 work
- ~~Task B6: Intercept resources/read~~ — resume as Phase 5 work
- ~~Task B7: Deep parameter inspection enhancements~~ — resume as Phase 4 work

---

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. **Check `controller/directives.md` before starting new work**
4. **Fix security tasks IN ORDER — do not skip ahead**
5. Your file ownership: `sentinel-engine/`, `sentinel-audit/`, `sentinel-canonical/`, `sentinel-mcp/`, `sentinel-proxy/`, `sentinel-approval/`
