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

### Security Hardening (Controller Directive C-2) — COMPLETE

All 9 assigned security fixes implemented with regression tests:
- Fix #1: Hash chain bypass — reject hashless after hashed
- Fix #2: Field separators — length-prefixed u64 LE encoding
- Fix #3: initialize_chain — verify before trusting file
- Fix #4: last_hash ordering — update after file write only
- Fix #5: Empty tool name — Invalid variant rejects, not PassThrough
- Fix #6: Unbounded read_line — 1MB max with LineTooLong error
- Fix #8: extract_domain @ bypass — authority-only @ search
- Fix #9: normalize_path empty — returns "/" not raw input
- Fix #14: Empty line proxy — skip empty lines, only EOF terminates

### Improvement Plan Items (Pre-C2) — COMPLETE

- Phase 1.2: globset migration (glob → globset)
- Phase 1.3: Pre-sort policies at load time
- Phase 3.1: Deep parameter inspection (JSON path traversal)
- Phase 4.2: Intercept resources/read in MCP proxy

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

### Directive C-6: Protocol Compliance — COMPLETE

- P-B1 (id type): Already using `Value` — no change needed
- P-B2 (jsonrpc field): Already included in all responses — no change needed
- P-B3 (error codes): Changed denial from -32600 to -32001 (custom app error), approval from -32001 to -32002. Updated all test assertions.
- P-B4 (reap child): Added `child.wait().await` after kill in sentinel-proxy to prevent zombie processes

### HIGH Findings #10-13 — COMPLETE

- Fix #10 (Approval persistence): Added `load_from_file()` to `ApprovalStore` — reads JSONL on startup, later entries override earlier for same ID. Wired into server main.rs startup.
- Fix #11 (unwrap_or_default): Replaced all 5 `unwrap_or_default()` calls in routes.rs with proper `map_err` that returns 500 with error message instead of silently returning null.
- Fix #12 (Fail-closed on approval failure): When `ApprovalStore::create()` fails, the evaluate handler now converts `RequireApproval` verdict to `Deny` with descriptive reason, instead of returning RequireApproval without an approval_id.
- Fix #13 (Audit verdict): `ProxyDecision::Block` now carries `(Value, Verdict)` — the actual verdict (Deny or RequireApproval) is logged to audit, not a hardcoded Deny.

### Improvement Plan Phase 2 — IN PROGRESS

**I-B3 (Phase 4.2): Percent-encoding normalization** — DONE
- Added `percent-encoding = "2.3"` to sentinel-engine/Cargo.toml
- Updated `normalize_path()` with single-pass percent-decode before processing
- Updated `extract_domain()` with percent-decode for hostname
- 9 new tests (7 path, 2 domain) — all pass

**I-B5 (Phase 5.1): Request ID tracking and timeout** — DONE
- Added `HashMap<String, Instant>` for pending request tracking in ProxyBridge
- Configurable timeout (default 30s) via `--timeout` CLI flag
- Periodic 5s sweep sends JSON-RPC -32003 error for timed-out requests
- 2 new tests — all pass

**I-B2 (Phase 3.3): Sensitive value redaction** — DONE
- Added `SENSITIVE_PARAM_KEYS` (15 keys) and `SENSITIVE_VALUE_PREFIXES` (10 prefixes)
- Recursive `redact_sensitive_values()` function walks JSON objects/arrays
- `redact: bool` field on AuditLogger, enabled by default
- 6 new tests — all pass

**I-B1 (Phase 3.1): Async audit writer** — DEFERRED
- Trade-off with Fix #4 (hash chain integrity) makes this risky for a security product
- Correctness > marginal latency improvement

**I-B4 (Phase 4.3): Recursive parameter scanning** — DONE
- Added `param: "*"` wildcard support to parameter constraints
- `collect_all_string_values()` iteratively walks all JSON string values
- Bounded: MAX_SCAN_VALUES=500, MAX_SCAN_DEPTH=32
- When `param: "*"`, each string value is checked against the constraint operator
- Fail-closed: no string values found → deny (override with `on_missing: "skip"`)
- 12 new tests (10 wildcard scan, 2 collector unit) — all pass
- Updated example-config.toml with wildcard scan policy examples

**I-B6 (Phase 6.1): Lock-free policy reads with arc-swap** — DONE
- Replaced `Arc<RwLock<Vec<Policy>>>` with `Arc<ArcSwap<Vec<Policy>>>` in AppState
- Reads use `policies.load()` — lock-free, zero scheduler overhead on hot path
- Writes use `rcu()`/`store()` for atomic swap (rare admin operations)
- Updated 6 files: lib.rs, routes.rs, main.rs, 3 test files + security_regression.rs
- All workspace tests pass (0 failures)

### C-8 Strategic Features — COMPLETE

- C-8.2: Tool annotation awareness + rug-pull detection in proxy
- C-8.3: Response injection scanning (OWASP MCP06) in proxy
- C-8.4: Protocol version awareness (initialize handshake tracking)
- C-8.5: sampling/createMessage interception (blocking exfiltration vector)
- Security headers: X-Content-Type-Options, X-Frame-Options, CSP, Cache-Control

### C-9.2 / C-10.2: Pre-Compiled Policies — COMPLETE

**Task B1: Pre-compiled policies for zero-Mutex evaluation**
- Added `CompiledPolicy`, `CompiledToolMatcher`, `CompiledConstraint`, `PatternMatcher` types
- Added `PolicyEngine::with_policies(strict_mode, policies)` constructor that compiles all patterns at load time
- Added `PolicyEngine::compile_policies()` standalone compilation method
- All regex and glob patterns compiled at load time → zero Mutex acquisitions in `evaluate_action()`
- Removed `regex_cache: Mutex<HashMap<String, Regex>>` and `glob_cache: Mutex<HashMap<String, GlobMatcher>>`
- Policy validation at compile time: invalid regex/glob patterns rejected with descriptive errors
- Multiple validation errors collected and reported together
- Compiled policies sorted by priority at compile time (no runtime sort check needed)
- Legacy `PolicyEngine::new(strict_mode)` + `evaluate_action(action, policies)` still works (backward compat)
- 24 new tests for compiled path (total 128 unit tests, 99 external = 227 engine tests)
- Full behavioral parity verified: `test_compiled_parity_with_legacy` checks both paths produce same results

### C-10.2 Task B2: Cross-Review Instance A's Code — COMPLETE

Reviewed 4 files (routes.rs, main.rs, security_regression.rs, owasp_mcp_top10.rs).
Full review written to `.collab/review-a-by-b.md`.

**Key findings:**
- 2 MEDIUM: empty API key accepted, pre-compiled policies not wired into server
- 4 LOW: HEAD not exempted from auth/rate-limit, no shutdown timeout, unbounded client request IDs
- 3 test gaps: findings #4, #11, #12 not covered in regression suite
- MCP03/MCP06 integration tests verify audit format only (unit tests cover detection logic)
- Auth, CORS, security headers, hash chain tests, domain/path defense tests all solid

### Phase 10.3: Signed Audit Checkpoints — COMPLETE

Implemented Ed25519 digital signature checkpoints for the tamper-evident audit log:

- Added `ed25519-dalek = { version = "2", features = ["rand_core"] }` and `rand = "0.8"` to sentinel-audit/Cargo.toml
- Added `Checkpoint` struct (id, timestamp, entry_count, chain_head_hash, signature, verifying_key)
- Added `CheckpointVerification` struct for verification results
- `Checkpoint::signing_content()` uses SHA-256 with length-prefixed fields to prevent boundary-shift attacks
- Added `signing_key: Option<SigningKey>` to `AuditLogger`
- `with_signing_key()` builder, `generate_signing_key()`, `signing_key_from_bytes()` static methods
- `create_checkpoint()` — signs current chain state, appends to `<stem>.checkpoints.jsonl`
- `load_checkpoints()` — reads checkpoint JSONL file
- `verify_checkpoints()` — validates all checkpoints (signature, entry_count monotonicity, chain_head_hash match)
- 13 new checkpoint tests covering creation, verification, signature tampering, entry count tampering, audit log tampering, key rotation, decreasing count detection
- All 65 sentinel-audit tests pass (45 unit + 20 external), clippy clean, fmt clean

### Build Status (Current)
- All workspace tests pass (0 failures)
- Clippy clean, fmt clean
- All 14 CRITICAL/HIGH findings from Controller audit: RESOLVED
- All 6 improvement plan tasks complete (I-B1 DEFERRED, I-B2–I-B6 DONE)
- C-8 complete, C-9.2/C-10.2 (pre-compiled policies) complete
- C-10.2 Task B2 (cross-review) complete
- Phase 10.3 (signed audit checkpoints) complete
