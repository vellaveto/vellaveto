# Tasks for Instance B — Improvement Plan (Phase 3+)

## READ THIS FIRST

Phase 0 (Security) and Phases 1-2 (Protocol + Performance) are **COMPLETE**. Feature work resumes.

Your focus: **audit hardening, security depth, and proxy improvements** — your owned crates.

Update `.collab/instance-b.md` and append to `.collab/log.md` after completing each task.

---

## Task I-B1: Async Audit Writer — Channel Decoupling (Phase 3.1)
**Priority: HIGH — Biggest remaining latency win**

Audit logging is in the evaluate handler's hot path. File I/O adds 5-10ms to P99.

**Implementation:**
1. Create `AsyncAuditWriter` wrapping `AuditLogger` with `tokio::sync::mpsc` channel
2. Background task drains the channel and calls `logger.write_entry()`
3. Configurable buffer size (default 1000 entries)
4. On channel full: log warning, drop entry (don't block hot path)
5. On shutdown: flush remaining entries before exit
6. Expose `AsyncAuditWriter` from `sentinel-audit/src/lib.rs`
7. Update `sentinel-server` to use the async writer instead of direct `AuditLogger`

**Files:** `sentinel-audit/src/lib.rs`, `sentinel-server/src/lib.rs`, `sentinel-server/src/routes.rs`, `sentinel-server/src/main.rs`
**Test:** Verify entries are written asynchronously, verify buffer backpressure behavior

---

## Task I-B2: Sensitive Value Redaction in Audit Logs (Phase 3.3)
**Priority: MEDIUM — Production safety**

Parameters may contain API keys, passwords, SSH keys, or PII. These must not appear in audit logs.

**Implementation:**
1. Add `RedactionConfig` struct with:
   - `sensitive_patterns`: regex list for value patterns (e.g., `sk-`, `AKIA`, `ghp_`, `-----BEGIN`)
   - `sensitive_keys`: parameter name list (e.g., `password`, `secret`, `token`, `api_key`, `credentials`)
2. Add `redact_parameters(params: &Value, config: &RedactionConfig) -> Value` function
3. Call redaction before writing audit entry
4. Configurable via server config (opt-in, with sensible defaults)

**Files:** `sentinel-audit/src/lib.rs` (or new `sentinel-audit/src/redaction.rs`), config integration
**Test:** Verify sensitive patterns and keys are replaced with `[REDACTED]`, verify non-sensitive values pass through

---

## Task I-B3: Unicode/Encoding Normalization for Paths (Phase 4.2)
**Priority: MEDIUM — Defense in depth**

`normalize_path()` handles `..` and `.` but not percent-encoding (`%2e%2e`) or Unicode tricks.

**Implementation:**
1. Add `percent-encoding` crate to `sentinel-engine/Cargo.toml`
2. Add percent-decoding step BEFORE path component resolution in `normalize_path()`
3. Optionally add `unicode-normalization` crate for NFC normalization
4. Handle double-encoding (`%252e%252e`)

**Files:** `sentinel-engine/Cargo.toml`, `sentinel-engine/src/lib.rs`
**Test:** Verify `%2e%2e/etc/passwd`, `%252e%252e`, and Unicode confusables are normalized before evaluation

---

## Task I-B4: Recursive Parameter Scanning (Phase 4.3)
**Priority: MEDIUM — Defense in depth**

All string values in parameters should be scanned for dangerous content, not just explicitly constrained fields.

**Implementation:**
1. Add `scan_all_string_values(params: &Value, checker: &dyn Fn(&str) -> bool) -> Vec<String>` to engine
2. Recursively walk Object/Array/String nodes
3. Integrate with policy evaluation — new `scan_mode: "all_values"` option in constraints
4. Return matched values for audit logging

**Files:** `sentinel-engine/src/lib.rs`
**Test:** Verify nested paths like `{"options": {"target": "https://evil.com"}}` are caught

---

## Task I-B5: Request ID Tracking and Timeout (Phase 5.1)
**Priority: MEDIUM — Reliability**

The proxy doesn't track pending request IDs. Hanging child servers block indefinitely.

**Implementation:**
1. Add `HashMap<Value, Instant>` for pending requests in `ProxyBridge`
2. Configurable timeout (default 30s) via CLI flag `--timeout`
3. On timeout: send JSON-RPC error response to agent, remove from tracking
4. Check timeouts on each loop iteration (or use `tokio::time::interval`)

**Files:** `sentinel-mcp/src/proxy.rs`, `sentinel-proxy/src/main.rs`
**Test:** Verify timeout error returned when child doesn't respond

---

## Task I-B6: Lock-Free Policy Reads with `arc-swap` (Phase 6.1)
**Priority: LOW — Performance under contention**

`state.policies.read().await` uses `tokio::sync::RwLock`. Even uncontended, there's scheduler overhead.

**Implementation:**
1. Add `arc-swap = "1"` to `sentinel-server/Cargo.toml`
2. Replace `Arc<RwLock<Vec<Policy>>>` with `Arc<ArcSwap<Vec<Policy>>>`
3. Readers use `policies.load()` (lock-free)
4. Writers use `policies.store(Arc::new(new_policies))` (atomic swap)
5. Update all read/write sites in `routes.rs`

**Files:** `sentinel-server/Cargo.toml`, `sentinel-server/src/lib.rs`, `sentinel-server/src/routes.rs`
**Test:** Verify concurrent reads don't block during writes

---

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `sentinel-engine/`, `sentinel-audit/`, `sentinel-canonical/`, `sentinel-mcp/`, `sentinel-proxy/`, `sentinel-approval/`
4. Instance A owns: `.github/`, `sentinel-integration/tests/`, TASKS.md
5. Work in order (I-B1 first — highest impact)
