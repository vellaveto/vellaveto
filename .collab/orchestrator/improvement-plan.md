# Sentinel Improvement Plan

**Author:** Orchestrator
**Date:** 2026-02-02
**Based on:** Deep research into MCP protocol, policy engine best practices (Cedar, OPA), tamper-evident logging (Trillian, Certificate Transparency), and Rust async patterns.

---

## Executive Summary

The Sentinel codebase is functional and well-tested (1,359 tests passing). Both instances have delivered solid P1-P3 features. This plan identifies **high-impact, specific improvements** to bring the project from "working prototype" to "production-ready." Items are ordered by impact/effort ratio.

---

## Phase 1: Performance Hot Path (P0 -- Do Immediately)

### 1.1 Cache Compiled Regex Patterns

**Problem:** `eval_regex_constraint()` in `sentinel-engine/src/lib.rs` calls `Regex::new()` on every evaluation. Regex compilation costs 10-100us per pattern. For the <5ms evaluation target, this is the biggest bottleneck.

**Solution:** Add a bounded `regex_cache` to `PolicyEngine`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use regex::Regex;

pub struct PolicyEngine {
    strict_mode: bool,
    regex_cache: Mutex<HashMap<String, Regex>>,
}

impl PolicyEngine {
    fn get_or_compile_regex(&self, pattern: &str) -> Result<Regex, EngineError> {
        let mut cache = self.regex_cache.lock()
            .map_err(|_| EngineError::InternalError("Regex cache poisoned".into()))?;
        if let Some(re) = cache.get(pattern) {
            return Ok(re.clone());
        }
        if cache.len() >= 1000 {
            // Evict oldest (simplest: clear all; better: LRU)
            cache.clear();
        }
        let re = Regex::new(pattern)
            .map_err(|e| EngineError::InvalidPattern(format!("Invalid regex '{}': {}", pattern, e)))?;
        cache.insert(pattern.to_string(), re.clone());
        Ok(re)
    }
}
```

**Assigned to:** Instance B (Task B2 -- already assigned, not yet done)
**Impact:** 10-100x speedup for regex constraint evaluation
**Effort:** Low (< 50 lines)

### 1.2 Replace `glob` with `globset` for Multi-Pattern Matching

**Problem:** The `glob` crate compiles patterns on every call. The `globset` crate (by BurntSushi/ripgrep author) pre-compiles and uses Aho-Corasick internally for simultaneous multi-pattern matching.

**Solution:** In `sentinel-engine/Cargo.toml`, replace `glob = "0.3"` with `globset = "0.4"`. Refactor `eval_glob_constraint()` and `eval_not_glob_constraint()` to use `globset::Glob::new().compile_matcher()`.

**Assigned to:** Instance B
**Impact:** 10-100x speedup for glob matching, especially with many patterns
**Effort:** Low (Cargo.toml change + ~20 lines in engine)

### 1.3 Pre-Sort Policies Once, Not Per Evaluation

**Problem:** `evaluate_action()` calls `.sort_by(|a, b| b.priority.cmp(&a.priority))` on every evaluation (line ~57-68 of engine). This is O(n log n) per request.

**Solution:** Sort policies once at load time. Store a pre-sorted `Vec<Policy>` (or `Arc<[Policy]>`) that never needs re-sorting. Policy add/remove/reload should maintain sort order.

**Assigned to:** Instance B
**Impact:** Eliminates O(n log n) overhead per evaluation
**Effort:** Low

---

## Phase 2: Audit Hardening (P1 -- Next Sprint)

### 2.1 Decouple Audit Logging from Request Path

**Problem:** In `sentinel-server/src/routes.rs` (line 96-106), audit logging is in the evaluate handler's hot path. File I/O adds 5-10ms to P99 latency.

**Solution:** Use a `tokio::sync::mpsc` channel to send audit entries to a background writer task:

```rust
pub struct AsyncAuditWriter {
    sender: tokio::sync::mpsc::Sender<AuditEntry>,
}

impl AsyncAuditWriter {
    pub fn new(logger: AuditLogger, buffer_size: usize) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel(buffer_size);
        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                if let Err(e) = logger.write_entry(&entry).await {
                    tracing::error!("Audit write failed: {}", e);
                }
            }
        });
        Self { sender: tx }
    }
}
```

**Impact:** Reduces P99 evaluate latency by 5-10ms
**Effort:** Medium (~100 lines, touches audit + server)

### 2.2 Merkle Tree for O(log n) Verification

**Problem:** Current `verify_chain()` reads every entry sequentially -- O(n). For a production system with millions of entries, this becomes impractical.

**Solution:** Replace the linear hash chain with an incremental Merkle tree. This enables:
- **O(log n) inclusion proofs** (prove a specific entry exists)
- **O(log n) consistency proofs** (prove the log only appended)

Consider the `rs-merkle` crate or a custom ~200-line implementation.

**Impact:** Scalable verification, enables external auditing
**Effort:** High (~300 lines, replaces audit internals)
**Recommendation:** Keep existing hash chain as fallback; add Merkle tree as optional enhancement.

### 2.3 Sensitive Value Redaction in Audit Logs

**Problem:** The full `Action` (including all parameters) is logged. Parameters may contain API keys, passwords, SSH keys, or PII.

**Solution:** Add a configurable redaction layer that replaces known-sensitive patterns (e.g., keys starting with `sk-`, `AKIA`, `ghp_`) and sensitive parameter names (e.g., `password`, `secret`, `token`) with `[REDACTED]`.

**Impact:** Prevents credential leakage via audit logs
**Effort:** Low (~50 lines)

---

## Phase 3: Security Depth (P1 -- Parallel with Phase 2)

### 3.1 Deep Parameter Inspection (JSON Path Traversal)

**Problem:** Current constraint system only checks top-level parameter keys:
```rust
let param_value = action.parameters.get(param_name);
```

Attackers can hide paths/domains in nested parameters like `{"config": {"output": {"path": "/etc/shadow"}}}`.

**Solution:** Support dot-separated JSON paths in `param` field:
```json
{"param": "config.output.path", "op": "glob", "pattern": "/etc/**"}
```

```rust
fn get_param_by_path<'a>(params: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = params;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}
```

**Impact:** Prevents parameter-hiding attacks
**Effort:** Medium (~40 lines in engine + tests)

### 3.2 Unicode/Encoding Normalization for Paths

**Problem:** `normalize_path()` handles `..` and `.` but not percent-encoding or Unicode tricks. Attackers can use `%2e%2e` or Unicode look-alikes to bypass glob patterns.

**Solution:** Add percent-decoding and NFC normalization before path component resolution. Consider the `percent-encoding` and `unicode-normalization` crates.

**Impact:** Prevents encoding-based bypass attacks
**Effort:** Low (~20 lines + 2 small dependencies)

### 3.3 Recursive Parameter Scanning

**Problem:** Beyond explicit path constraints, all string values in parameters should be scanned for dangerous content (URLs, file paths, credential patterns).

**Solution:** Add a `scan_all_values` mode that recursively walks all string values in the JSON parameter tree and applies pattern checks:

```rust
fn scan_all_string_values(params: &Value, checker: &dyn Fn(&str) -> bool) -> Vec<String> {
    // Recursively walk Object/Array/String nodes
}
```

This catches parameters like `{"options": {"target": "https://evil.com"}}`.

**Impact:** Defense in depth against parameter pollution
**Effort:** Medium (~60 lines)

---

## Phase 4: MCP Proxy Hardening (P2)

### 4.1 Request ID Tracking and Timeout

**Problem:** The proxy forwards requests but doesn't track pending request IDs. If a child server hangs, the proxy has no way to timeout individual requests.

**Solution:** Add a `HashMap<Value, Instant>` tracking pending request IDs and a configurable timeout (e.g., 30s). If a response doesn't arrive in time, send a timeout error to the client.

**Impact:** Prevents proxy hangs from unresponsive servers
**Effort:** Medium

### 4.2 Resource Read Interception

**Problem:** The proxy only intercepts `tools/call`. MCP also has `resources/read` which can access files and URIs. These should also be policy-checked.

**Solution:** Extend `classify_message()` in `extractor.rs` to recognize `resources/read` and extract the resource URI for path/domain checking.

**Impact:** Closes a bypass vector
**Effort:** Low (~30 lines)

### 4.3 `kill_on_drop` for Child Process

**Problem:** In `sentinel-proxy/src/main.rs`, the child process is spawned without `kill_on_drop(true)`. If the proxy crashes, the child may become orphaned.

**Solution:** Add `.kill_on_drop(true)` to the `Command` builder.

**Impact:** Prevents orphaned processes
**Effort:** Trivial (1 line)

---

## Phase 5: Architecture Improvements (P3 -- Future)

### 5.1 Lock-Free Policy Reads with `arc-swap`

**Problem:** `state.policies.read().await` uses `tokio::sync::RwLock`. Even uncontended async RwLock has scheduler overhead.

**Solution:** Use `arc-swap` crate for lock-free reads. Policy updates create a new `Arc<[CompiledPolicy]>` and atomically swap:

```rust
use arc_swap::ArcSwap;
policies: Arc<ArcSwap<Vec<Policy>>>
```

Readers never block, even during updates.

**Impact:** Eliminates read contention under load
**Effort:** Medium (touches AppState and all readers)

### 5.2 Session-Aware Evaluation

**Problem:** Policy evaluation is stateless -- each request is independent. Multi-step attacks (write a script, then execute it) are invisible.

**Solution:** Add a `SessionContext` that tracks recent tool calls per session, with configurable sequence policies:

```rust
pub struct SessionContext {
    recent_calls: VecDeque<(Action, Verdict, Instant)>,
    max_window: Duration,
}
```

**Impact:** Detects chained attack patterns
**Effort:** High (new module, integration across proxy and server)

### 5.3 Rate Limiting per Tool

**Solution:** Add per-tool rate limiting (e.g., max 10 bash calls per minute). Implementable as Tower middleware layer.

**Impact:** Abuse prevention for high-risk tools
**Effort:** Low if using Tower middleware

---

## Phase 6: Testing & Observability (Ongoing)

### 6.1 Property-Based Tests with `proptest`

Add property-based tests for critical invariants:
- Evaluation is deterministic (same input -> same output)
- Blocked paths always deny regardless of encoding tricks
- Empty policies always deny (fail-closed)

### 6.2 Performance Benchmarks with `criterion`

Add benchmarks for:
- Policy evaluation with 10/100/1000 policies
- Regex compilation vs cached evaluation
- Glob matching with globset vs glob
- Audit log write throughput

### 6.3 Structured Logging with `tracing`

Ensure all decisions are traced with structured fields:
```rust
tracing::info!(tool = %action.tool, verdict = %verdict, latency_us = elapsed.as_micros(), "Policy evaluated");
```

---

## Dependency Budget

New dependencies required (ordered by phase):

| Phase | Crate | Size | Purpose |
|-------|-------|------|---------|
| 1.2 | `globset` (replaces `glob`) | Small | Multi-pattern glob matching |
| 2.2 | `rs-merkle` (optional) | Small | Merkle tree for audit |
| 3.2 | `percent-encoding` | Tiny | URL decoding for paths |
| 3.2 | `unicode-normalization` | Small | NFC normalization |
| 5.1 | `arc-swap` | Tiny | Lock-free reads |
| 6.1 | `proptest` (dev only) | Medium | Property-based testing |
| 6.2 | `criterion` (dev only) | Medium | Benchmarking |

Total new runtime dependencies: 3-4 small crates. Acceptable.

---

## Instance Assignments

### Instance A (Focus: Testing, CI, Benchmarks)
1. Add property-based tests (Phase 6.1)
2. Add criterion benchmarks (Phase 6.2)
3. Integration tests for MCP proxy flow
4. Update TASKS.md

### Instance B (Focus: Engine Performance, Security)
1. **Immediate:** Regex caching (Phase 1.1) -- Task B2
2. Replace `glob` with `globset` (Phase 1.2)
3. Pre-sort policies at load time (Phase 1.3)
4. Deep parameter inspection (Phase 3.1)
5. Add `kill_on_drop(true)` to proxy (Phase 4.3)
6. Intercept `resources/read` in proxy (Phase 4.2)

### Orchestrator (Focus: Code Quality, Coordination)
1. Fix remaining `unwrap()` / `unwrap_or_default()` issues
2. Audit channel decoupling design (Phase 2.1)
3. Review PRs from both instances
4. Update status and coordination files

---

*This plan will be updated as work progresses.*
