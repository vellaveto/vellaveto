# Instance B Status

## 2026-02-02 — Instance B (Opus 4.5)

### What I've read
I read your `log.md`. Good findings about the two codebases.

### What I've done so far
I'm implementing the full 5-feature plan from the approved plan document. I chose **option 2** (same as your preference) — port features into root crates, keeping the existing 940+ tests intact.

### Completed Features

**Feature 1: Parameter-Aware Firewall (sentinel-engine)** — DONE
- Added `glob = "0.3"` and `regex = "1"` to sentinel-engine/Cargo.toml
- Added ~300 lines to sentinel-engine/src/lib.rs:
  - `evaluate_parameter_constraints()` dispatches to per-operator functions
  - 9 operators: `glob`, `not_glob`, `domain_match`, `domain_not_in`, `regex`, `eq`, `ne`, `one_of`, `none_of`
  - `normalize_path()` — resolves `..`, `.`, rejects null bytes
  - `extract_domain()` — strips scheme/port/path
  - `match_domain_pattern()` — supports `*.example.com` wildcards
  - `make_constraint_verdict()` — converts `on_match` string to Verdict
  - Fail-closed: missing param → deny, `on_missing: "skip"` override available
- Added `parameter_constraints` to known keys in strict mode
- Created `sentinel-engine/tests/parameter_constraints.rs` with 31 tests — all pass
- All 96 engine tests pass (5 unit + 60 existing + 31 new)
- Updated `sentinel-server/example-config.toml` with constraint examples

**Feature 5: Canonical Disconnect Fix (sentinel-canonical)** — DONE
- Rewrote `block_dangerous_tools()` → uses `PolicyType::Deny` with proper IDs (`bash:*`, `shell:*`, `exec:*`)
- Rewrote `network_security()` → uses `Conditional` with `parameter_constraints` for domain allowlisting
- Rewrote `development_environment()` → uses `Conditional` with `not_glob` constraints for project directory
- `deny_all()` / `allow_all()` left as-is (already correct)
- 5 tests pass

### ALL FEATURES COMPLETE

**Feature 2: Tamper-Evident Audit (sentinel-audit)** — DONE
- Added SHA-256 hash chain (sha2 + hex dependencies)
- Added `entry_hash` and `prev_hash` fields to `AuditEntry` (backward-compatible via `#[serde(default)]`)
- Added `ChainVerification` struct, `verify_chain()`, `initialize_chain()`, `compute_entry_hash()`
- Added `GET /api/audit/verify` endpoint to sentinel-server
- 46 audit tests pass

**Feature 3: Approval Backend (sentinel-approval)** — DONE
- Created new crate with `ApprovalStore`, `PendingApproval`, `ApprovalStatus`, `ApprovalError`
- Methods: `create()`, `approve()`, `deny()`, `get()`, `list_pending()`, `expire_stale()`
- Wired into server: `AppState.approvals`, evaluation creates pending approvals on RequireApproval
- 4 approval REST endpoints: list pending, get, approve, deny
- Periodic expiry task (60s interval, 15min TTL)
- 8 approval tests pass, all server tests pass

**Feature 4: MCP Stdio Proxy (sentinel-proxy)** — DONE
- Added `sentinel-mcp/src/framing.rs` — newline-delimited JSON-RPC read/write
- Added `sentinel-mcp/src/extractor.rs` — classify messages, extract Action from tool calls
- Added `sentinel-mcp/src/proxy.rs` — ProxyBridge with evaluate_tool_call, bidirectional proxy loop
- Created `sentinel-proxy/` binary crate with clap CLI
- Usage: `sentinel-proxy --config policy.toml -- /path/to/mcp-server [args...]`
- 22 MCP tests pass (framing, extractor, proxy bridge)

**Task B2: Regex Cache** — DONE
- Added bounded `HashMap<String, Regex>` cache to `PolicyEngine` (max 1000 entries)
- `regex_is_match()` method with compile-once semantics and cache eviction

### Final State
- All 5 planned features implemented
- All orchestrator-assigned tasks complete (B0 was done by orchestrator, B1 was already done, B2 done, B3 done)
- Full workspace compiles and tests pass: 128 test suites, 0 failures
- Fixed pre-existing `priority: i` type mismatch in policy_scaling_benchmark.rs example

### Files Modified/Created by Instance B
- `Cargo.toml` (workspace) — added sentinel-approval, sentinel-proxy
- `sentinel-engine/Cargo.toml` — added glob, regex
- `sentinel-engine/src/lib.rs` — parameter constraints + regex cache
- `sentinel-engine/tests/parameter_constraints.rs` (NEW)
- `sentinel-canonical/src/lib.rs` — canonical fix
- `sentinel-audit/Cargo.toml` — added sha2, hex
- `sentinel-audit/src/lib.rs` — hash chain
- `sentinel-mcp/Cargo.toml` — added sentinel-audit, tracing
- `sentinel-mcp/src/lib.rs` — added module declarations
- `sentinel-mcp/src/framing.rs` (NEW)
- `sentinel-mcp/src/extractor.rs` (NEW)
- `sentinel-mcp/src/proxy.rs` (NEW)
- `sentinel-approval/` (NEW CRATE)
- `sentinel-proxy/` (NEW CRATE)
- `sentinel-server/src/lib.rs` — added approvals to AppState
- `sentinel-server/src/routes.rs` — approval endpoints, audit verify endpoint
- `sentinel-server/src/main.rs` — ApprovalStore init, expiry task, audit chain init
- `sentinel-server/example-config.toml` — constraint examples
- `sentinel-server/tests/test_routes_unit.rs` — approvals field
- `sentinel-integration/tests/audit_type_completeness.rs` — new AuditEntry fields
- `sentinel-integration/tests/audit_serialization_roundtrip.rs` — new AuditEntry fields
- `sentinel-integration/examples/policy_scaling_benchmark.rs` — type fix
