# Tasks for Instance A — Improvement Plan (Phase 3+)

## READ THIS FIRST

Phase 0 (Security) and Phases 1-2 (Protocol + Performance) are **COMPLETE**. Feature work resumes.

Your focus: **testing, observability, and middleware** — testing infrastructure and cross-cutting concerns.

Finish S-A3 (regression tests) first if not done, then proceed to these tasks.

Update `.collab/instance-a.md` and append to `.collab/log.md` after completing each task.

---

## Task S-A3: Security Regression Test Suite (if not complete)
**Priority: HIGH — Validates all security fixes**

If not already done, finish `sentinel-integration/tests/security_regression.rs` with tests for all 14 CRITICAL/HIGH findings. See previous task file for details.

---

## Task I-A1: Property-Based Tests with `proptest` (Phase 7.1)
**Priority: HIGH — Critical for security assurance**

Add property-based tests to verify invariants hold for arbitrary inputs.

**Implementation:**
1. Add `proptest = "1"` as dev-dependency to `sentinel-engine/Cargo.toml`
2. Create `sentinel-engine/tests/proptests.rs` with:
   - **Evaluation is deterministic:** same input always produces same output
   - **Fail-closed invariant:** empty policy list always denies
   - **Path normalization is idempotent:** `normalize(normalize(x)) == normalize(x)`
   - **Domain extraction never panics:** arbitrary strings don't crash `extract_domain()`
   - **Blocked paths always deny:** any path matching a block pattern is denied regardless of encoding
   - **Deny overrides allow at equal priority:** property holds for any policy combination

**Files:** `sentinel-engine/Cargo.toml`, `sentinel-engine/tests/proptests.rs`

---

## Task I-A2: Performance Benchmarks with `criterion` (Phase 7.2)
**Priority: MEDIUM — Baseline performance metrics**

Create benchmarks to validate the <5ms evaluation target and catch regressions.

**Implementation:**
1. Add to `sentinel-engine/Cargo.toml`:
   ```toml
   [dev-dependencies]
   criterion = { version = "0.5", features = ["html_reports"] }

   [[bench]]
   name = "evaluation"
   harness = false
   ```
2. Create `sentinel-engine/benches/evaluation.rs` benchmarking:
   - Policy evaluation with 10/100/1000 policies
   - Regex cache hit vs miss
   - Glob matching (globset) speed
   - Path normalization throughput
   - Domain extraction throughput
   - Parameter constraint evaluation with nested JSON

**Files:** `sentinel-engine/Cargo.toml`, `sentinel-engine/benches/evaluation.rs`

---

## Task I-A3: Structured Logging with `tracing` (Phase 7.3)
**Priority: MEDIUM — Observability**

Ensure all decision points emit structured trace events for debugging and monitoring.

**Implementation:**
1. Add `tracing` as dependency to `sentinel-engine` and `sentinel-server` (if not already)
2. Add structured spans/events at key decision points:
   - `tracing::info!(tool = %action.tool, verdict = %verdict, latency_us = elapsed.as_micros(), "Policy evaluated")`
   - `tracing::warn!(tool = %tool_name, reason = %reason, "Tool call denied")`
   - `tracing::debug!(policy_id = %id, "Policy matched")`
3. Add `tracing-subscriber` setup in `sentinel-server/src/main.rs` with env filter (`RUST_LOG`)
4. Ensure no sensitive parameter values are logged (coordinate with Instance B's redaction work)

**Files:** `sentinel-engine/Cargo.toml`, `sentinel-engine/src/lib.rs`, `sentinel-server/Cargo.toml`, `sentinel-server/src/main.rs`

---

## Task I-A4: Rate Limiting per Tool (Phase 6.3)
**Priority: LOW — Abuse prevention**

Add per-tool rate limiting as Tower middleware.

**Implementation:**
1. Add `tower` rate-limiting layer or custom middleware
2. Configurable limits per tool (e.g., `bash: 10/min`, `read_file: 100/min`)
3. Return 429 Too Many Requests when exceeded
4. Configuration via server config file

**Files:** `sentinel-server/src/routes.rs` or new `sentinel-server/src/middleware.rs`
**Test:** Verify rate limit enforced and resets after window

---

## Task I-A5: Bracket Notation for JSON Path (Phase 4.1 enhancement)
**Priority: LOW — Completeness**

Per Controller note: `get_param_by_path()` needs bracket notation for array access.

**Implementation:**
1. Extend `get_param_by_path()` in `sentinel-engine/src/lib.rs` to parse `[N]` segments
2. `config.items[0].path` should traverse into JSON arrays
3. Handle out-of-bounds gracefully (return None)

**Files:** `sentinel-engine/src/lib.rs`
**Test:** Verify `items[0].path`, `data[2].name`, mixed dot+bracket notation

**Note:** This touches Instance B's code. Coordinate via log if needed.

---

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. Your file ownership: `.github/`, `sentinel-integration/tests/`, TASKS.md
4. Instance B owns engine/audit/MCP crates — coordinate via log for shared changes
5. Work in order (S-A3 first if incomplete, then I-A1)
