# Tasks for Instance A

## READ THIS FIRST
Updated task list. The Controller instance (when active) may override these. Check `controller/directives.md` first.

Update `.collab/instance-a.md` after each task.

---

## COMPLETED TASKS (for reference)
- [x] Task A1: Create CI workflow -- DONE (.github/workflows/ci.yml)
- [x] Path/domain integration tests -- DONE (15 tests in sentinel-integration)

---

## Task A2: Integration Tests for MCP Proxy Flow
**Priority: HIGH -- No E2E test coverage for the proxy**

Create `sentinel-integration/tests/proxy_integration.rs` that tests the proxy flow:
1. Create a mock MCP server that responds to tools/call
2. Send a tools/call message through the ProxyBridge
3. Verify allowed calls forward correctly
4. Verify denied calls return proper JSON-RPC error
5. Verify audit entries are created for denials

Use the ProxyBridge directly (no need to spawn actual processes):
```rust
use sentinel_mcp::proxy::ProxyBridge;
use sentinel_mcp::extractor::{classify_message, MessageType};
use sentinel_mcp::framing::{read_message, write_message};
```

---

## Task A3: Property-Based Tests with `proptest`
**Priority: MEDIUM -- Critical for security assurance**

Add `proptest` as a dev-dependency to `sentinel-engine` and write property tests:

1. **Evaluation is deterministic**: same input always produces same output
2. **Fail-closed invariant**: empty policy list always denies
3. **Path normalization is idempotent**: normalize(normalize(x)) == normalize(x)
4. **Domain extraction handles arbitrary URLs**: never panics on any input
5. **Blocked paths always deny**: any path matching a block pattern is denied regardless of encoding

Add to `sentinel-engine/Cargo.toml`:
```toml
[dev-dependencies]
proptest = "1"
```

---

## Task A4: Criterion Benchmarks
**Priority: LOW -- Nice to have for performance validation**

Create `sentinel-engine/benches/evaluation.rs` with criterion:

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "evaluation"
harness = false
```

Benchmark:
- Policy evaluation with 10/100/1000 policies
- Regex cache hit vs miss
- Glob matching speed
- Path normalization throughput
- Domain extraction throughput

---

## Task A5: Update TASKS.md Progress
**Priority: LOW**

Update the project TASKS.md with accurate progress. Current state:
- P0: 100% (CI, warnings, tests all done)
- P1: 100% (path/domain constraints, parameter-aware firewall)
- P2: 100% (MCP proxy functional)
- P3: 100% (approval store, endpoints, expiry)
- P4: 100% (hash chain audit, verify endpoint)
- P5: ~30% (improvement plan exists, example configs exist, README needs update)

---

## Communication Protocol
1. After completing each task, update `.collab/instance-a.md`
2. Append completion message to `.collab/log.md`
3. **Check `controller/directives.md` before starting new work**
4. Instance B is NOT modifying your files. Safe to proceed.
5. Your file ownership: `.github/`, `sentinel-integration/tests/`, TASKS.md
