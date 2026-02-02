# Tasks for Instance B — Directive C-10 (Coordination Update)

## READ THIS FIRST

Controller Directive C-10 is active. Several C-9 tasks are already complete. This file reflects the CURRENT state. Read `controller/directive-c10.md` for full context.

Update `.collab/instance-b.md` and append to `.collab/log.md` after completing each task.

---

## COMPLETED (all previous directives)
- All 5 features (parameter firewall, audit, approval, MCP proxy, canonical fix)
- All C-2 security fixes (9/9)
- All C-6 protocol compliance (4/4)
- All C-7 items (CORS, log rotation)
- All C-8 items (tool annotations, rug-pull detection, response inspection)
- All improvement plan items (I-B2 through I-B6)
- **C9-B2: Protocol version awareness** — DONE
- **C9-B3: sampling/createMessage interception** — DONE
- Security headers — DONE (also applied by Controller)

---

## Task B1: Pre-Compiled Policies (from C9-B1)
**Priority: HIGH — Single highest-impact performance improvement remaining**
**Directive:** C-10.2
**Status:** OPEN
**Reference:** `controller/research/policy-engine-patterns.md` §2.1, §1.3, §3.1

### Problem

`sentinel-engine/src/lib.rs` currently uses:
```rust
regex_cache: Mutex<HashMap<String, Regex>>,
glob_cache: Mutex<HashMap<String, GlobMatcher>>,
```

Every evaluation acquires these Mutex locks. Cedar and OPA both compile at load time — zero runtime compilation.

### Implementation

1. **Add `CompiledPolicy` struct:**

```rust
pub struct CompiledPolicy {
    pub policy: Policy,
    pub tool_matcher: CompiledToolMatcher,
    pub constraints: Vec<CompiledConstraint>,
}

pub enum CompiledToolMatcher {
    Exact(String, String),         // tool:function exact
    ToolWildcard(String),          // tool:*
    FunctionWildcard(GlobMatcher), // glob pattern
    Universal,                      // *
}

pub enum CompiledConstraint {
    Glob { param: String, matcher: GlobMatcher, negated: bool },
    Regex { param: String, regex: Regex },
    DomainMatch { param: String, patterns: Vec<String> },
    Eq { param: String, value: String },
    OneOf { param: String, values: Vec<String> },
    // ... other operators from evaluate_parameter_constraints
}
```

2. **Compile at load time:** In `PolicyEngine::new()`, compile each `Policy` into a `CompiledPolicy`. Return `Result<PolicyEngine, Vec<PolicyValidationError>>` — invalid policies are rejected at load time with descriptive errors.

3. **Remove `regex_cache` and `glob_cache`:** Replace with direct references from `CompiledConstraint`. The `Mutex<HashMap>` fields are gone.

4. **Policy validation at compile time:**
   - Regex patterns compile
   - Glob patterns compile
   - Tool ID format is valid (contains `:` separator or is `*`)
   - Constraint operator is recognized

5. **Update `evaluate_action()`:** Use `CompiledPolicy` fields directly instead of cache lookups. Zero Mutex acquisitions in hot path.

6. **Update policy reload:** When policies change via ArcSwap, compile new policies before swapping. If compilation fails, keep old policies and return error.

**Important:** Keep backward compatibility — existing `PolicyEngine::new(strict_mode)` API should still work. Store `Vec<CompiledPolicy>` internally.

**Tests:**
- All existing tests must continue to pass (behavioral parity)
- New: invalid regex rejected at load time
- New: invalid glob rejected at load time
- New: compilation errors are descriptive
- Optional: before/after benchmark

---

## Task B2: Cross-Review Instance A's Code
**Priority: HIGH — Quality assurance**
**Directive:** C-10.2
**Status:** OPEN

Review Instance A's code for correctness, edge cases, and security gaps. Focus areas:

### `sentinel-server/src/routes.rs`
- **Auth middleware (`require_api_key`):** Is the Bearer token extraction correct? Does skipping GET/OPTIONS cover all read-only methods (HEAD?)? Could timing side-channels leak key validity?
- **Rate limit middleware:** Is per-category classification correct? Are there paths that should be rate-limited but aren't?
- **Request ID middleware:** Is the UUID generation cryptographically random enough? Is there an injection risk from client-provided X-Request-Id headers?
- **Security headers middleware:** Are all recommended headers present? Any missing (HSTS, Permissions-Policy)?
- **CORS configuration:** Is `AllowOrigin::Any` safe for a security API? Should credential-bearing requests be blocked?

### `sentinel-server/src/main.rs`
- **Env var parsing:** Are all env vars validated? What happens with invalid values (empty string, negative number)?
- **Bind address:** Is the default 127.0.0.1 enforced correctly? Could a config file override it?
- **Graceful shutdown:** Is the signal handler correct? Does it wait for in-flight requests?
- **Approval store init:** Is `load_from_file()` called before serving requests?

### `sentinel-integration/tests/security_regression.rs`
- Are all 14 CRITICAL/HIGH findings tested?
- Are the tests testing the actual vulnerability, or just the happy path?
- Are there edge cases that should be added?

### `sentinel-integration/tests/owasp_mcp_top10.rs`
- MCP03 tests: Are they testing real rug-pull detection, or just format?
- MCP06 tests: Are they testing real injection detection, or just audit format?
- Coverage gaps: Any OWASP categories that need more depth?

**Deliverable:** Write review to `.collab/review-a-by-b.md`

---

## Work Order
1. **B1** (pre-compiled policies) — highest impact, do first
2. **B2** (cross-review) — do after B1

## File Ownership (C-10 anti-competition rules)
- You OWN: `sentinel-engine/src/lib.rs`, `sentinel-mcp/`, `sentinel-audit/`, `sentinel-approval/`, `sentinel-canonical/`
- You may READ but NOT MODIFY: `sentinel-server/src/routes.rs`, `sentinel-integration/tests/`
- Shared (coordinate first): `sentinel-server/src/main.rs`

## Communication Protocol
1. After completing each task, update `.collab/instance-b.md`
2. Append completion message to `.collab/log.md`
3. Write cross-review to `.collab/review-a-by-b.md`
