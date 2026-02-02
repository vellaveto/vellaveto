# Orchestrator Status

## Identity
I am the orchestrator instance (Opus 4.5). I audit, coordinate, and assign work to Instance A and Instance B. I also fix issues directly when needed. I report to the Controller instance.

## Current State: AUDIT UPDATE 2
Timestamp: 2026-02-02

---

## Codebase Health Assessment

### Build Status: ALL PASS
- `cargo check --workspace` -- clean
- `cargo clippy --workspace` -- clean (zero warnings)
- `cargo test --workspace` -- ALL 1,359 TESTS PASS
- `cargo fmt --check` -- PASS (fixed in previous session)

### Test Count Summary
| Crate | Tests |
|---|---|
| sentinel-engine | ~145 (71 unit + 74 integration) |
| sentinel-audit | ~46 |
| sentinel-approval | ~9 |
| sentinel-canonical | ~5 |
| sentinel-config | ~6 |
| sentinel-types | ~4 |
| sentinel-mcp | ~21 (3 server + 8 extractor + 5 framing + 5 proxy) |
| sentinel-integration | ~15 |
| sentinel-server (tower/adversarial/unit) | ~1000+ |
| **Total** | **~1,359** |

### Workspace Crates (10)
1. sentinel-types (leaf)
2. sentinel-canonical (types)
3. sentinel-engine (types, canonical)
4. sentinel-audit (types, engine)
5. sentinel-config (types)
6. sentinel-approval (types)
7. sentinel-mcp (types, engine, audit) -- now includes proxy.rs, extractor.rs, framing.rs
8. sentinel-server (all above)
9. sentinel-integration (all above, test only)
10. sentinel-proxy (binary, uses mcp/engine/audit/config)

---

## What's Working (Complete Feature List)

1. **Parameter-Aware Firewall** (9 constraint operators, path normalization, domain extraction)
2. **Tamper-Evident Audit** (SHA-256 hash chain, verify_chain(), backward compat)
3. **Approval Store** (create/approve/deny/expire/persist with JSONL)
4. **Canonical Disconnect Fix** (policies rewritten to use parameter_constraints)
5. **Server Integration** (all endpoints wired: evaluate, audit, approval CRUD, policy CRUD)
6. **MCP Stdio Proxy** (bidirectional relay, tools/call interception, policy enforcement)
7. **CI Workflow** (.github/workflows/ci.yml: check, clippy, fmt, test, doc)

---

## Issues Found in Latest Audit

### RESOLVED (this session)
1. ~~**Compile error in benchmark example**~~ -- `priority: i` was `usize`, needed `i32` cast. Fixed.
2. ~~**`unwrap()` in sentinel-proxy/src/main.rs:74**~~ -- Replaced with `.context()`. Fixed.
3. ~~**Missing `kill_on_drop(true)` on child process**~~ -- Added. Fixed.

### STILL OPEN

#### HIGH
1. **Regex compiled on every evaluation call** (Task B2 -- assigned to Instance B, NOT DONE)
   - `eval_regex_constraint()` calls `Regex::new()` per invocation
   - See improvement plan Phase 1.1 for solution

#### MEDIUM
2. **`glob` crate should be replaced with `globset`** -- See improvement plan Phase 1.2
3. **Policies re-sorted on every evaluation** -- See improvement plan Phase 1.3
4. **No integration tests for MCP proxy flow** -- Need end-to-end test
5. **`resources/read` not intercepted by proxy** -- Only `tools/call` is checked

#### LOW
6. **No property-based tests** -- Important for security-critical code
7. **No performance benchmarks** -- Have benchmark example but no criterion setup
8. **Audit logging in request hot path** -- See improvement plan Phase 2.1

---

## Work Assignment Summary

### Instance A
- CI workflow: DONE
- Integration tests: PARTIAL (15 path/domain tests, need proxy flow tests)
- Property-based tests: NOT STARTED
- Benchmarks: NOT STARTED

### Instance B
- Features 1-5: DONE
- Approval endpoints: DONE
- MCP proxy: DONE (proxy.rs, extractor.rs, framing.rs, sentinel-proxy binary)
- Regex caching (B2): NOT DONE
- `globset` migration: NOT STARTED
- Pre-sort policies: NOT STARTED

### Orchestrator (me)
- Initial audit: DONE
- unwrap fix: DONE
- Test name fix: DONE
- Formatting fix: DONE
- Benchmark example fix: DONE
- Proxy unwrap fix: DONE
- kill_on_drop fix: DONE
- Improvement plan: DONE
- Controller infrastructure: DONE

### Controller
- AWAITING ACTIVATION
- Infrastructure set up at `.collab/controller/`

---

## Monitoring
Tailing instance status files and log.md for updates.
